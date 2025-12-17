require('dotenv').config();
const express = require('express')
const axios = require('axios')
const NodeCache = require('node-cache')
const bodyParser = require('body-parser')
const cors = require('cors')
const proj4 = require('proj4')
const jwt = require('jsonwebtoken')
const ldap = require('ldapjs');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

const {
  LDAP_URL,
  LDAP_BIND_DN,
  LDAP_BIND_PASSWORD,
  LDAP_SEARCH_BASE,
} = process.env;

const JWT_SECRET = process.env.JWT_SECRET || 'a-very-secret-key-that-you-should-change';

const app = express()

// 1. Security Headers
app.use(helmet());

// 2. Compression
app.use(compression());

// 3. Rate Limiting (1000 reqs / 15 min)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10000,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

app.use(cors())
// accept JSON objects and primitives (we allow a JSON string body containing the SQL)
app.use(bodyParser.json({ strict: false }))

// simple request logger
app.use((req, res, next) => {
  console.log(new Date().toISOString(), req.method, req.originalUrl)
  next()
})

// Authentication middleware removed
// app.use(authenticateToken);

// Add a global error handler for unhandled promise rejections to prevent silent crashes
process.on('unhandledRejection', (reason, promise) => {
  console.error('!!! UNHANDLED REJECTION AT:', promise, 'REASON:', reason);
  // Optionally, you might want to exit the process: process.exit(1);
});

// health
app.get('/health', (req, res) => res.json({ ok: true }))

// Login endpoint
app.post('/login', (req, res) => {
  if (!LDAP_URL || !LDAP_SEARCH_BASE) {
    console.error('LDAP environment variables are not configured for the proxy server.');
    return res.status(500).json({ message: 'Authentication service is not configured.' });
  }

  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  const client = ldap.createClient({
    url: LDAP_URL,
    tlsOptions: {
      // TODO: In production, this should be true and a proper CA certificate provided
      // For development with self-signed certs, this is often necessary.
      rejectUnauthorized: false
    }
  });

  // For 389-DS, we can often bind directly with the user's constructed DN.
  // This is simpler than the search-then-bind pattern needed for Active Directory.
  const userDn = `uid=${username},${LDAP_SEARCH_BASE}`;

  // Attempt to bind with the user's credentials.
  client.bind(userDn, password, (bindErr) => {
    if (bindErr) {
      // This will fail if the user DN is wrong, password is bad, or user doesn't exist.
      console.error(`LDAP auth failed for user: ${username}`, bindErr);
      // Provide a generic message for security.
      return res.status(401).json({ message: 'Invalid credentials or user not found.' });
    }

    // If the bind is successful, authentication is valid.
    console.log(`LDAP auth successful for user: ${username}`);
    const token = jwt.sign({ username: username }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token });
    client.unbind();
  });
});

// --- Coordinate System Definition for Iowa State Plane North (FIPS 1401, Feet) ---
const IOWA_NORTH_NAD83_FTUS = "EPSG:2235";
proj4.defs(IOWA_NORTH_NAD83_FTUS, '+proj=lcc +lat_0=41.5 +lon_0=-93.5 +lat_1=42.04 +lat_2=43.16 +x_0=1500000 +y_0=1000000 +ellps=GRS80 +datum=NAD83 +units=us-ft +no_defs');

// Use an environment variable for the API base URL, with a default for local development.
const API_BASE = process.env.P2C_API_BASE || 'http://localhost:8083/api/Data'
const cache = new NodeCache({ stdTTL: 60 * 60 * 24, checkperiod: 120 }) // 1 day TTL for geocoding

function sanitizeIdentifier(id) {
  if (!id) return ''
  if (/[^a-zA-Z0-9_\.]/.test(id)) throw new Error('Invalid identifier')
  return id
}

// Simple delay function
const sleep = ms => new Promise(r => setTimeout(r, ms));

function cleanAddress(address) {
  if (!address) return '';
  let cleaned = address
    .replace(/^(at|on)\s+/i, '') // Remove leading "at " or "on "
    .replace(/\s+at\s+/gi, ' and ') // " at " -> " and " (intersection)
    .replace(/\s+on\s+/gi, ' ')     // " on " -> " " (remove noise)
    .replace(/-BLK/gi, ' ')      // "100-BLK" -> "100"
    .replace(/\//g, ' and ')     // "ST A / ST B" -> "ST A and ST B"
    .replace(/,(\s*,)+/g, ',')   // Remove double commas
    .trim();

  // Heuristic: If it looks like an intersection with a specific house number, remove the number
  if (/\s+and\s+/i.test(cleaned) && /^\d+\s+/.test(cleaned)) {
    cleaned = cleaned.replace(/^\d+\s+/, '');
  }
  return cleaned;
}

async function geocodeAddress(address) {
  if (!address) return null;

  const cleanedAddress = cleanAddress(address);
  const key = `geo:${cleanedAddress}`;
  const cached = cache.get(key);
  if (cached) return cached;

  const geocoderUrl = process.env.NOMINATIM_URL || 'http://192.168.0.212:8080/search';

  let attempts = 0;
  const maxAttempts = 10; // More aggressive retries for local server

  while (attempts < maxAttempts) {
    try {
      const r = await axios.get(geocoderUrl, {
        params: { q: cleanedAddress, format: 'json', limit: 1, addressdetails: 0 },
        headers: { 'User-Agent': 'p2c-frontend' },
        timeout: 10000 // 10s timeout to allow for queueing
      });
      const out = r.data && r.data[0] ? { lat: Number(r.data[0].lat), lon: Number(r.data[0].lon) } : null;
      cache.set(key, out);
      console.log('geocoded', `"${address}" (as "${cleanedAddress}")`, '=>', out);
      return out;
    } catch (e) {
      attempts++;
      console.error(`Geocoding attempt ${attempts}/${maxAttempts} failed for "${cleanedAddress}":`, e.message);
      if (attempts >= maxAttempts) {
        return null;
      }
      // Back off a little (500ms) but keep retrying
      await sleep(500);
    }
  }
  return null;
}

app.get('/tables', async (req, res) => {
  try {
    console.log('fetching tables from', `${API_BASE}/tables`)
    const r = await axios.get(`${API_BASE}/tables`)
    console.log('tables status', r.status)
    res.json(r.data)
  } catch (e) {
    res.status(502).json({ error: e.message })
  }
})

app.get('/schema', async (req, res) => {
  try {
    const table = req.query.table
    sanitizeIdentifier(table)
    console.log('fetching schema for', table)
    const r = await axios.get(`${API_BASE}/schema?table=${encodeURIComponent(table)}`)
    res.json(r.data)
  } catch (e) {
    res.status(502).json({ error: e.message })
  }
})

// Proxy for the new parameterized /query endpoint
app.get('/query', async (req, res) => {
  try {
    const params = new URLSearchParams(req.query);
    const url = `${API_BASE}/query?${params.toString()}`;
    console.log('forwarding parameterized query to API:', url);
    const r = await axios.get(url);
    console.log('upstream query status', r.status);
    res.status(r.status).json(r.data)
  } catch (e) {
    if (e.response) return res.status(e.response.status).json({ error: e.response.data || e.response.statusText });
    res.status(502).json({ error: e.message });
  }
});

// Proxy for the rawQuery endpoint (used by legacy functions)
app.get('/rawQuery', async (req, res) => {
  try {
    const sql = req.query.sql;
    if (!sql || !sql.trim().toUpperCase().startsWith('SELECT')) {
      return res.status(400).json({ error: 'Only SELECT queries allowed' });
    }
    const url = `${API_BASE}/rawQuery?sql=${encodeURIComponent(sql)}`;
    console.log('forwarding raw query to API. SQL:', sql);
    const r = await axios.get(url);
    res.status(r.status).json(r.data);
  } catch (e) {
    if (e.response) return res.status(e.response.status).json({ error: e.response.data || e.response.statusText });
    res.status(502).json({ error: e.message });
  }
})

// Geocode endpoint using Nominatim with cache
app.get('/geocode', async (req, res) => {
  const q = req.query.q
  if (!q) return res.status(400).json({ error: 'q query required' })
  try {
    const out = await geocodeAddress(q);
    res.json(out)
  } catch (e) {
    res.status(502).json({ error: e.message })
  }
})

// Proximity search endpoint
app.get('/proximity', async (req, res) => {
  const { address, days = 7, distance = 1000, nature } = req.query;
  if (!address) {
    return res.status(400).json({ error: 'Address query parameter is required' });
  }

  try {
    // 1. Geocode address to lat/lon
    const coords = await geocodeAddress(address);

    if (!coords) {
      return res.status(404).json({ error: 'Address could not be geocoded.' });
    }

    // 2. Convert lat/lon to Iowa State Plane coordinates
    const [geox, geoy] = proj4('WGS84', IOWA_NORTH_NAD83_FTUS, [coords.lon, coords.lat]);

    // 3. Calculate start time
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days, 10));
    const startTimeString = startDate.toISOString().slice(0, 19).replace('T', ' ');

    // 4. Construct and execute the SQL query
    const distanceFt = parseInt(distance, 10);
    let whereClauses = [
      `SQRT(POWER(CAST(geox AS FLOAT) - ${geox}, 2) + POWER(CAST(geoy AS FLOAT) - ${geoy}, 2)) <= ${distanceFt}`,
      `starttime >= '${startTimeString}'`
    ];
    if (nature) whereClauses.push(`nature LIKE '%${nature.replace(/'/g, "''")}%'`);

    const sql = `
      SELECT TOP 50 id, starttime, closetime, agency, service, nature, address, geox, geoy,
             SQRT(POWER(CAST(geox AS FLOAT) - ${geox}, 2) + POWER(CAST(geoy AS FLOAT) - ${geoy}, 2)) AS distance_ft
      FROM cadHandler
      WHERE ${whereClauses.join(' AND ')}
      ORDER BY starttime DESC, distance_ft ASC;
    `;

    console.log('Executing proximity query:', sql);
    const url = `${API_BASE}/rawQuery?sql=${encodeURIComponent(sql)}`;
    const r = await axios.get(url);

    // Format distance to 2 decimal places and convert geox/geoy back to lat/lon for the map
    const results = (r.data?.data || []).map(row => ({
      ...row,
      distance_ft: row.distance_ft ? parseFloat(row.distance_ft).toFixed(2) : null,
      ...(() => {
        if (row.geox && row.geoy) {
          const [lon, lat] = proj4(IOWA_NORTH_NAD83_FTUS, 'WGS84', [Number(row.geox), Number(row.geoy)]);
          return { lat, lon };
        }
        return {};
      })()
    }));

    res.status(r.status).json({ data: results });
  } catch (e) {
    if (e.response) return res.status(e.response.status).json({ error: e.response.data || e.response.statusText });
    res.status(502).json({ error: e.message });
  }
});



// Unified Search Endpoint (used by Tab720 / 360 View)
app.get('/searchP2C', async (req, res) => {
  const { q, page = 1, limit = 20, lat, lon, radius } = req.query;
  const pageNum = parseInt(page) || 1;
  const limitNum = parseInt(limit) || 20;

  // Geospatial Filter Setup
  let geoWhereCAD = '1=1';
  let geoWhereDB = '1=1';

  if (lat && lon && radius) {
    try {
      const rFt = parseFloat(radius);
      if (!isNaN(rFt) && rFt > 0) {
        const center = proj4('WGS84', IOWA_NORTH_NAD83_FTUS, [parseFloat(lon), parseFloat(lat)]);
        const cx = center[0];
        const cy = center[1];
        const minX = cx - rFt;
        const maxX = cx + rFt;
        const minY = cy - rFt;
        const maxY = cy + rFt;
        const boxFilter = `(geox BETWEEN ${minX} AND ${maxX} AND geoy BETWEEN ${minY} AND ${maxY})`;
        geoWhereCAD = boxFilter;
        geoWhereDB = boxFilter;
      }
    } catch (e) {
      console.error('[searchP2C] Geo error:', e);
    }
  }

  // Tokenize search term for smarter "First Last" matching
  const searchTerm = q ? q.trim().replace(/'/g, "''") : '';
  const tokens = searchTerm.split(/\s+/).filter(t => t.length > 0);

  console.log(`[searchP2C] Query: "${searchTerm}", Tokens: ${tokens.length}, Page: ${pageNum}`);

  // Base conditions
  let cadWhere = '1=1';
  let dbWhere = '1=1';

  if (tokens.length > 0) {
    // For each token, it must match at least ONE of the target fields.
    // AND the results together.
    // Example: "Amy Nauman" -> (fields match Amy) AND (fields match Nauman)

    // CAD Fields: nature, address, agency
    const cadConditions = tokens.map(t =>
      `(nature LIKE '%${t}%' OR address LIKE '%${t}%' OR agency LIKE '%${t}%')`
    );
    cadWhere = cadConditions.join(' AND ');

    // DB Fields: name, firstname, lastname, charge, location
    const dbConditions = tokens.map(t =>
      `(name LIKE '%${t}%' OR firstname LIKE '%${t}%' OR lastname LIKE '%${t}%' OR charge LIKE '%${t}%' OR location LIKE '%${t}%')`
    );
    dbWhere = dbConditions.join(' AND ');
  } else if (searchTerm) {
    // Fallback if split failed or something weird
    cadWhere = `(nature LIKE '%${searchTerm}%' OR address LIKE '%${searchTerm}%' OR agency LIKE '%${searchTerm}%')`;
    dbWhere = `(name LIKE '%${searchTerm}%' OR firstname LIKE '%${searchTerm}%' OR lastname LIKE '%${searchTerm}%' OR charge LIKE '%${searchTerm}%' OR location LIKE '%${searchTerm}%')`;
  }

  const fetchLimit = pageNum * limitNum; // Fetch more to allow decent sorting/pagination after merge

  const cadSql = `
    SELECT TOP ${fetchLimit}
      id, starttime as event_time, nature as title, address as location, agency,
      geox, geoy, 'CAD' as type, 'Incidents' as source
    FROM cadHandler
    WHERE ${cadWhere} AND ${geoWhereCAD}
    ORDER BY starttime DESC
  `;

  const dbSql = `
    SELECT TOP ${fetchLimit}
      id, event_time, charge as title, name, firstname, lastname, location, [key] as type, 'DB' as source,
      geox, geoy
    FROM dbo.DailyBulletinArrests
    WHERE ${dbWhere} AND ${geoWhereDB}
    ORDER BY event_time DESC
  `;

  try {
    const [cadRes, dbRes] = await Promise.all([
      axios.get(`${API_BASE}/rawQuery?sql=${encodeURIComponent(cadSql)}`),
      axios.get(`${API_BASE}/rawQuery?sql=${encodeURIComponent(dbSql)}`)
    ]);

    let results = [];

    const processRecord = (r, defaultType) => {
      let lat = null, lon = null;
      if (r.geox && r.geoy) {
        try {
          // Convert only if non-zero
          const gx = Number(r.geox);
          const gy = Number(r.geoy);
          if (gx !== 0 && gy !== 0) {
            const coords = proj4(IOWA_NORTH_NAD83_FTUS, 'WGS84', [gx, gy]);
            lon = coords[0];
            lat = coords[1];
          }
        } catch (e) { }
      }

      let typeCode = r.type;
      if (defaultType === 'DB') typeCode = r.type;

      return {
        id: r.id,
        type: typeCode,
        source: defaultType,
        title: r.title,
        subTitle: r.name || '',
        location: r.location,
        event_time: r.event_time,
        agency: r.agency,
        lat,
        lon
      };
    };

    const cadProcessed = (cadRes.data?.data || []).map(r => processRecord(r, 'CAD'));
    const dbProcessed = (dbRes.data?.data || []).map(r => processRecord(r, 'DB'));

    results = [...cadProcessed, ...dbProcessed];

    results.sort((a, b) => new Date(b.event_time) - new Date(a.event_time));

    const start = (pageNum - 1) * limitNum;
    const end = start + limitNum;
    const paginatedResults = results.slice(start, end);

    res.json({
      data: paginatedResults,
      meta: {
        page: pageNum,
        limit: limitNum,
        hasMore: results.length > end
      }
    });

  } catch (e) {
    console.error('[searchP2C] Error:', e.message);
    res.status(502).json({ error: e.message });
  }
});

// Geocode endpoint using Nominatim with cache
app.get('/geocode', async (req, res) => {
  const q = req.query.q
  if (!q) return res.status(400).json({ error: 'q query required' })
  try {
    const out = await geocodeAddress(q);
    res.json(out)
  } catch (e) {
    res.status(502).json({ error: e.message })
  }
})

// Proximity search endpoint
app.get('/proximity', async (req, res) => {
  const { address, days = 7, distance = 1000, nature } = req.query;
  if (!address) {
    return res.status(400).json({ error: 'Address query parameter is required' });
  }

  try {
    // 1. Geocode address to lat/lon
    const coords = await geocodeAddress(address);

    if (!coords) {
      return res.status(404).json({ error: 'Address could not be geocoded.' });
    }

    // 2. Convert lat/lon to Iowa State Plane coordinates
    const [geox, geoy] = proj4('WGS84', IOWA_NORTH_NAD83_FTUS, [coords.lon, coords.lat]);

    // 3. Calculate start time
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days, 10));
    const startTimeString = startDate.toISOString().slice(0, 19).replace('T', ' ');

    // 4. Construct and execute the SQL query
    const distanceFt = parseInt(distance, 10);
    let whereClauses = [
      `SQRT(POWER(CAST(geox AS FLOAT) - ${geox}, 2) + POWER(CAST(geoy AS FLOAT) - ${geoy}, 2)) <= ${distanceFt}`,
      `starttime >= '${startTimeString}'`
    ];
    if (nature) whereClauses.push(`nature LIKE '%${nature.replace(/'/g, "''")}%'`);

    const sql = `
      SELECT TOP 50 id, starttime, closetime, agency, service, nature, address, geox, geoy,
             SQRT(POWER(CAST(geox AS FLOAT) - ${geox}, 2) + POWER(CAST(geoy AS FLOAT) - ${geoy}, 2)) AS distance_ft
      FROM cadHandler
      WHERE ${whereClauses.join(' AND ')}
      ORDER BY starttime DESC, distance_ft ASC;
    `;

    console.log('Executing proximity query:', sql);
    const url = `${API_BASE}/rawQuery?sql=${encodeURIComponent(sql)}`;
    const r = await axios.get(url);

    // Format distance to 2 decimal places and convert geox/geoy back to lat/lon for the map
    const results = (r.data?.data || []).map(row => ({
      ...row,
      distance_ft: row.distance_ft ? parseFloat(row.distance_ft).toFixed(2) : null,
      ...(() => {
        if (row.geox && row.geoy) {
          const [lon, lat] = proj4(IOWA_NORTH_NAD83_FTUS, 'WGS84', [Number(row.geox), Number(row.geoy)]);
          return { lat, lon };
        }
        return {};
      })()
    }));

    res.status(r.status).json({ data: results });
  } catch (e) {
    if (e.response) return res.status(e.response.status).json({ error: e.response.data || e.response.statusText });
    res.status(502).json({ error: e.message });
  }
});

// Search 360 endpoint: searches DailyBulletinArrests, Sex Offenders, and DOC records
app.get('/search360', async (req, res) => {
  const { q, page = 1, limit = 50 } = req.query;
  const pageNum = Math.max(1, parseInt(page));
  const limitNum = parseInt(limit);
  const fetchLimit = pageNum * limitNum;

  const safeQ = q ? q.replace(/'/g, "''").trim() : '';
  if (!safeQ || safeQ.length < 2) return res.json({ data: [] });

  const terms = safeQ.split(/\s+/).filter(t => t.length > 0);
  console.log(`[search360] Searching for: "${safeQ}" Terms: ${JSON.stringify(terms)} Page: ${pageNum}`);

  try {
    // Helper to build multi-term AND condition
    // For each term, it must appear in at least one of the columns
    // (col1 LIKE %term1% OR col2 LIKE %term1%) AND (col1 LIKE %term2% OR col2 LIKE %term2%)
    const buildOrLike = (cols) => terms.map(t => `(${cols.map(c => `${c} LIKE '%${t}%'`).join(' OR ')})`).join(' AND ');
    const buildLike = (col) => terms.map(t => `${col} LIKE '%${t}%'`).join(' AND ');

    // 1. Arrests Query
    const arrestWhere = buildOrLike(['name', 'firstname', 'lastname', 'charge']);
    const arrestSql = `
      SELECT TOP ${fetchLimit}
        id, event_time, charge, name, firstname, lastname, middlename, location, [key],
        geox, geoy
      FROM dbo.DailyBulletinArrests
      WHERE ${arrestWhere}
      ORDER BY event_time DESC
    `;

    // 2. Sex Offenders Query
    const soWhere = buildOrLike(['first_name', 'last_name']);
    const soSql = `
      SELECT TOP ${fetchLimit}
        registrant_id, first_name, last_name, middle_name, gender, tier, address_line_1, city, lat, lon
      FROM dbo.sexoffender_registrants
      WHERE ${soWhere}
    `;

    // 3. DOC (Probation/Parole) Query
    // Join Summary with Charges to get status
    const docWhere = buildLike('s.Name');
    const docSql = `
      SELECT TOP ${fetchLimit}
        s.OffenderNumber, s.Name, s.Gender, s.Age,
        c.SupervisionStatus, c.OffenseClass, c.EndDate
      FROM dbo.Offender_Summary s
      LEFT JOIN dbo.Offender_Charges c ON s.OffenderNumber = c.OffenderNumber
      WHERE ${docWhere}
    `;

    const [arrestRes, soRes, docRes] = await Promise.all([
      axios.get(`${API_BASE}/rawQuery?sql=${encodeURIComponent(arrestSql)}`),
      axios.get(`${API_BASE}/rawQuery?sql=${encodeURIComponent(soSql)}`),
      axios.get(`${API_BASE}/rawQuery?sql=${encodeURIComponent(docSql)}`)
    ]);

    const arrests = arrestRes.data?.data || [];
    const sexOffenders = soRes.data?.data || [];
    const docRecords = docRes.data?.data || [];

    // Normalize Results
    const combined = [];

    // Process Arrests
    arrests.forEach(row => {
      let lat = null, lon = null;
      if (row.geox && row.geoy) {
        try {
          [lon, lat] = proj4(IOWA_NORTH_NAD83_FTUS, 'WGS84', [Number(row.geox), Number(row.geoy)]);
        } catch (e) { }
      }
      combined.push({
        type: 'ARREST',
        id: row.id,
        name: row.name || `${row.firstname} ${row.lastname}`,
        firstname: row.firstname,
        lastname: row.lastname,
        middlename: row.middlename,
        details: row.charge,
        date: row.event_time,
        location: row.location,
        lat, lon,
        raw: row
      });
    });

    // Process Sex Offenders
    sexOffenders.forEach(row => {
      combined.push({
        type: 'SEX_OFFENDER',
        id: row.registrant_id,
        name: `${row.first_name} ${row.last_name}`,
        firstname: row.first_name,
        lastname: row.last_name,
        middlename: row.middle_name,
        details: `Tier ${row.tier} Sex Offender`,
        location: `${row.address_line_1}, ${row.city}`,
        lat: row.lat,
        lon: row.lon,
        raw: row
      });
    });

    // Process DOC
    docRecords.forEach(row => {
      let type = 'DOC';
      const status = (row.SupervisionStatus || '').toUpperCase();
      if (status.includes('PROBATION')) type = 'PROBATION';
      else if (status.includes('PAROLE')) type = 'PAROLE';

      // Attempt split name for DOC
      const nameParts = (row.Name || '').split(' ');
      const fname = nameParts[0] || '';
      const lname = nameParts.length > 1 ? nameParts.slice(1).join(' ') : '';

      combined.push({
        type: type,
        id: row.OffenderNumber,
        name: row.Name,
        firstname: fname,
        lastname: lname,
        details: `${row.SupervisionStatus} - ${row.OffenseClass}`,
        date: row.EndDate, // Use EndDate as a relevant date
        location: 'N/A', // DOC records often lack specific current address in summary
        lat: null, lon: null,
        raw: row,
        OffenderNumbers: row.OffenderNumber // explicit for robust matching
      });
    });

    console.log(`[search360] Found ${arrests.length} arrests, ${sexOffenders.length} sex offenders, ${docRecords.length} DOC records`);

    // Sort combined results - prioritize date if available? Or just mix them? 
    // Usually mix is okay, but sticking to logic of source priority (Arrest > SO > DOC) as implicit in push order.
    // Or we can sort by name?
    // Let's keep implicit order but SLICE for pagination.

    const start = (pageNum - 1) * limitNum;
    const end = start + limitNum;
    const paginated = combined.slice(start, end);

    res.json({
      data: paginated,
      meta: {
        page: pageNum,
        limit: limitNum,
        totalFetched: combined.length,
        hasMore: combined.length > end
      }
    });

  } catch (e) {
    console.error('[search360] Error:', e.message);
    if (e.response) return res.status(e.response.status).json({ error: e.response.data || e.response.statusText });
    res.status(502).json({ error: e.message });
  }
});

// Unified P2C Search endpoint
app.get('/incidents', async (req, res) => {
  try {
    const { cadLimit = 100, arrestLimit = 100, crimeLimit = 100, dateFrom, dateTo, filters, distanceKm, centerLat, centerLng } = req.query;

    // CRITICAL: The 'filters' parameter is a SQL injection vector and has been disabled.
    // Do not re-enable without a safe implementation (e.g., parameterized queries or strict validation).
    const safeFilters = '';
    if (filters) console.warn('[incidents] WARNING: The "filters" query parameter is currently disabled for security reasons.');

    const buildQuery = (table, limit, filters = '', orderBy = 'starttime DESC') => {
      const params = new URLSearchParams({
        table,
        limit: Number(limit) || 100,
      });
      if (filters) params.set('filters', filters);
      if (orderBy) params.set('orderBy', orderBy);

      const url = `${API_BASE}/query?${params.toString()}`;
      console.log(`[incidents] EXECUTING parameterized query for ${table} via GET: ${url}`);
      // The backend API now handles constructing the safe SQL
      return axios.get(url);
    };

    console.log(`[incidents] INFO: Fetching data with filters: "${safeFilters}"`);

    // Build date filters for DailyBulletinArrests table which uses 'event_time'
    let dbDateFilters = [];
    let cadDateFilters = [];

    if (dateFrom) {
      dbDateFilters.push(`event_time >= '${dateFrom.replace(/'/g, "''")}'`);
      cadDateFilters.push(`starttime >= '${dateFrom.replace(/'/g, "''")}'`);
    }
    if (dateTo) {
      dbDateFilters.push(`event_time <= '${dateTo.replace(/'/g, "''")}'`);
      cadDateFilters.push(`starttime <= '${dateTo.replace(/'/g, "''")}'`);
    }
    const dbFilters = dbDateFilters.join(' AND ');
    const cadFilters = cadDateFilters.join(' AND ');

    const results = await Promise.all([
      buildQuery('cadHandler', cadLimit, cadFilters, 'starttime DESC'),
      buildQuery('DailyBulletinArrests', arrestLimit, `[key] <> 'LW'${dbFilters ? ` AND ${dbFilters}` : ''}`, 'event_time DESC'),
      buildQuery('DailyBulletinArrests', crimeLimit, `[key] = 'LW'${dbFilters ? ` AND ${dbFilters}` : ''}`, 'event_time DESC')
    ]);
    const [cadRes, arrestRes, crimeRes] = results;

    console.log(`[incidents] INFO: Received from upstream: ${cadRes.data?.data?.length} CAD, ${arrestRes.data?.data?.length} Arrests, ${crimeRes.data?.data?.length} Crime`);

    const cadRows = cadRes.data?.data || [];
    const arrestRows = arrestRes.data?.data || [];
    const crimeRows = crimeRes.data?.data || [];

    // Tag rows with their source and combine them. Geocoding will now happen on the client.
    const processedCadRows = cadRows.map(r => ({ ...r, _source: 'cadHandler' }));
    const geocodedArrests = arrestRows.map(r => ({ ...r, _source: 'DailyBulletinArrests' }));
    const geocodedCrime = crimeRows.map(r => ({ ...r, _source: 'Crime' }));

    console.log('[incidents] INFO: Combining and filtering results...');
    let combined = []
    combined = combined.concat(processedCadRows);
    combined = combined.concat(geocodedArrests);
    combined = combined.concat(geocodedCrime);

    // --- ENRICHMENT STEP: Attach cached geocodes ---
    let enrichedCount = 0;
    combined = combined.map(row => {
      // If already has lat/lon (e.g. from CAD), keep it
      if (row.lat && row.lon) return row;

      const address = row.location || row.address;
      if (address) {
        const cleaned = cleanAddress(address);
        const key = `geo:${cleaned}`;
        const cached = cache.get(key);
        if (cached) {
          enrichedCount++;
          return { ...row, lat: cached.lat, lon: cached.lon };
        }
      }
      return row;
    });
    console.log(`[incidents] INFO: Enriched ${enrichedCount} records from cache.`);
    // -----------------------------------------------

    // optional server-side distance filtering (if provided)
    if (distanceKm && centerLat && centerLng) {
      const dKm = Number(distanceKm)
      const lat0 = Number(centerLat)
      const lon0 = Number(centerLng)
      const haversineKm = (lat1, lon1, lat2, lon2) => {
        const R = 6371
        const toRad = v => v * Math.PI / 180
        const dLat = toRad(lat2 - lat1)
        const dLon = toRad(lon2 - lon1)
        const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) * Math.sin(dLon / 2)
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a))
        return R * c
      }
      combined = combined.filter(r => {
        const lat = r.lat || r.geoy;
        const lon = r.lon || r.geox;
        return lat != null && lon != null && haversineKm(lat0, lon0, Number(lat), Number(lon)) <= dKm;
      })
    }

    console.log(`[incidents] SUCCESS: Sending ${combined.length} combined records to client.`);
    res.json({ data: combined })
  } catch (e) {
    console.error('[incidents] FATAL: An unexpected error occurred in the /incidents handler:', e);
    res.status(502).json({ error: e.message })
  }
})

const port = process.env.PORT || 9000
app.listen(port, () => console.log('Proxy listening on', port))
