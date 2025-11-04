require('dotenv').config();
const express = require('express')
const axios = require('axios')
const NodeCache = require('node-cache')
const bodyParser = require('body-parser')
const cors = require('cors')
const proj4 = require('proj4')
const jwt = require('jsonwebtoken')
const ldap = require('ldapjs');

const {
  LDAP_URL,
  LDAP_BIND_DN,
  LDAP_BIND_PASSWORD,
  LDAP_SEARCH_BASE,
} = process.env;

const JWT_SECRET = process.env.JWT_SECRET || 'a-very-secret-key-that-you-should-change';

const app = express()
app.use(cors())
// accept JSON objects and primitives (we allow a JSON string body containing the SQL)
app.use(bodyParser.json({ strict: false }))

// simple request logger
app.use((req,res,next)=>{
  console.log(new Date().toISOString(), req.method, req.originalUrl)
  next()
})

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  // Allow health check and login endpoints to pass without a token
  if (req.path === '/health' || req.path === '/login') {
    return next();
  }

  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (token == null) return res.sendStatus(401); // if there isn't any token

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // if token is no longer valid
    req.user = user;
    next(); // proceed to the next middleware
  });
};
app.use(authenticateToken);

// Add a global error handler for unhandled promise rejections to prevent silent crashes
process.on('unhandledRejection', (reason, promise) => {
  console.error('!!! UNHANDLED REJECTION AT:', promise, 'REASON:', reason);
  // Optionally, you might want to exit the process: process.exit(1);
});

// health
app.get('/health', (req,res)=> res.json({ok:true}))

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
const cache = new NodeCache({stdTTL: 60*60*24, checkperiod:120}) // 1 day TTL for geocoding

function sanitizeIdentifier(id){
  if(!id) return ''
  if(/[^a-zA-Z0-9_\.]/.test(id)) throw new Error('Invalid identifier')
  return id
}

async function geocodeAddress(address) {
  if (!address) return null;

  // Clean up address string for better geocoding results
  const cleanedAddress = address
    .replace(/-BLK/gi, ' ')      // "100-BLK" -> "100"
    .replace(/\//g, ' and ')     // "ST A / ST B" -> "ST A and ST B"
    .trim();

  const key = `geo:${cleanedAddress}`;
  const cached = cache.get(key);
  if (cached) return cached;

  try {
    const r = await axios.get('http://192.168.0.212:8080/search', {
      params: { q: cleanedAddress, format: 'json', limit: 1, addressdetails: 0 },
      headers: { 'User-Agent': 'p2c-frontend' }
    });
    const out = r.data && r.data[0] ? { lat: Number(r.data[0].lat), lon: Number(r.data[0].lon) } : null;
    cache.set(key, out);
    console.log('geocoded', `"${address}" (as "${cleanedAddress}")`, '=>', out);
    return out;
  } catch (e) {
    console.error(`Geocoding failed for "${cleanedAddress}":`, e.message);
    return null;
  }
}

app.get('/tables', async (req,res)=>{
  try{
    console.log('fetching tables from', `${API_BASE}/tables`)
    const r = await axios.get(`${API_BASE}/tables`)
    console.log('tables status', r.status)
    res.json(r.data)
  }catch(e){
    res.status(502).json({error: e.message})
  }
})

app.get('/schema', async (req,res)=>{
  try{
    const table = req.query.table
    sanitizeIdentifier(table)
    console.log('fetching schema for', table)
    const r = await axios.get(`${API_BASE}/schema?table=${encodeURIComponent(table)}`)
    res.json(r.data)
  }catch(e){
    res.status(502).json({error: e.message})
  }
})

// Proxy for /query but enforce SELECT only
app.post('/query', async (req,res)=>{
  try{
    // normalize incoming body: accept either a JSON string primitive or an object with { sql: '...' }
    let sql = null
    if(typeof req.body === 'string') sql = req.body
    else if(req.body && typeof req.body.sql === 'string') sql = req.body.sql
    else return res.status(400).json({error:'SQL must be provided as a JSON string or {sql:"..."}'})

    const s = sql.trim().toUpperCase()
    if(!s.startsWith('SELECT')){
      return res.status(400).json({error:'Only SELECT queries allowed'})
    }
    // forward the SQL string to upstream as a JSON string
    console.log('forwarding query to API. SQL:', sql)
    const r = await axios.post(`${API_BASE}/query`, JSON.stringify(sql), {headers:{'Content-Type':'application/json'}})
    console.log('upstream query status', r.status)
    res.status(r.status).json(r.data)
  }catch(e){
    if(e.response) return res.status(e.response.status).json({error:e.response.data || e.response.statusText})
    res.status(502).json({error: e.message})
  }
})

// Geocode endpoint using Nominatim with cache
app.get('/geocode', async (req,res)=>{
  const q = req.query.q
  if(!q) return res.status(400).json({error:'q query required'})
  try{
    const out = await geocodeAddress(q);
    res.json(out)
  }catch(e){
    res.status(502).json({error:e.message})
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
    const r = await axios.post(`${API_BASE}/query`, JSON.stringify(sql), { headers: { 'Content-Type': 'application/json' } });
    
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

// Combined endpoint: fetch both tables, join geocoded coords for DailyBulletinArrests then return combined data
app.get('/incidents', async (req,res)=>{
  try{
    // params: limit, distanceKm, centerLat, centerLng, dateFrom, dateTo, filters
    const {limit=100, distanceKm, centerLat, centerLng, dateFrom, dateTo, filters} = req.query;
  // fetch recent cadHandler and DailyBulletinArrests rows (use provided limit)
  const numLimit = Number(limit) || 100;
  const perTypeLimit = Math.ceil(numLimit / 3);

  // CRITICAL: The 'filters' parameter is a SQL injection vector and has been disabled.
  // Do not re-enable without a safe implementation (e.g., parameterized queries or strict validation).
  const safeFilters = '';
  if (filters) console.warn('[incidents] WARNING: The "filters" query parameter is currently disabled for security reasons.');

  // Create a separate filter for tables that use 'event_time' instead of 'starttime'
  const dbFilters = (filters || '').replace(/starttime/g, 'event_time');

  const buildQuery = (table, where = '', orderBy = 'starttime DESC') => {
    let sql = `SELECT TOP ${perTypeLimit} * FROM ${table}`;
    if (where) sql += ` WHERE ${where}`;
    if (orderBy) sql += ` ORDER BY ${orderBy}`;
    console.log(`[incidents] EXECUTING SQL for ${table}: ${sql}`);
    return axios.post(`${API_BASE}/query`, JSON.stringify(sql), { headers: { 'Content-Type': 'application/json' } })
      .catch(err => {
        // Log errors from individual queries but don't crash. Return a mock success response.
        console.error(`[incidents] ERROR: Upstream query failed for table ${table}. Status: ${err.response?.status}. Data:`, err.response?.data);
        return { data: { data: [] } }; // Return an empty dataset on failure
      });
  };

  console.log(`[incidents] INFO: Fetching data with filters: "${safeFilters}" and dbFilters: "${dbFilters}"`);
  const results = await Promise.all([
    buildQuery('cadHandler', safeFilters, 'starttime DESC'),
    buildQuery('DailyBulletinArrests', dbFilters, 'event_time DESC'),
    buildQuery('DailyBulletinArrests', `[key] = 'LW'${safeFilters ? ` AND (${safeFilters})` : ''}`, 'event_time DESC')
  ]);
  const [cadRes, arrestRes, crimeRes] = results;

  console.log(`[incidents] INFO: Received from upstream: ${cadRes.data?.data?.length} CAD, ${arrestRes.data?.data?.length} Arrests, ${crimeRes.data?.data?.length} Crime`);

  const cadRows = cadRes.data?.data || [];
  const arrestRows = arrestRes.data?.data || [];
  const crimeRows = crimeRes.data?.data || [];

    // geocode dbRows locations (cached)
  const geocodeAndTag = async (row, source) => {
      if(!row.location) return row
      const g = await geocodeAddress(row.location);
    return { ...row, lat: g?.lat, lon: g?.lon, _source: source };
  };

  console.log('[incidents] INFO: Geocoding arrest and crime records...');
  const geocodedArrests = await Promise.all(arrestRows.map(row => geocodeAndTag(row, 'DailyBulletinArrests')));
  const geocodedCrime = await Promise.all(crimeRows.map(row => geocodeAndTag(row, 'Crime')));

    // Process cadRows: convert UTM or geocode address
    console.log('[incidents] INFO: Geocoding CAD records...');
    const processedCadRows = await Promise.all(cadRows.map(async r => {
      // If no UTM, try geocoding the address/location
      const address = r.location || r.address;
      if (address) {
        const g = await geocodeAddress(address);
        return { ...r, lat: g?.lat, lon: g?.lon, _source: 'cadHandler' };
      }
      return { ...r, _source: 'cadHandler' };
    }));

    console.log('[incidents] INFO: Combining and filtering results...');
    let combined = []
    combined = combined.concat(processedCadRows);
    combined = combined.concat(geocodedArrests);
    combined = combined.concat(geocodedCrime);

    // optional server-side distance filtering (if provided)
    if(distanceKm && centerLat && centerLng){
      const dKm = Number(distanceKm)
      const lat0 = Number(centerLat)
      const lon0 = Number(centerLng)
      const haversineKm = (lat1,lon1,lat2,lon2) => {
        const R = 6371
        const toRad = v=> v * Math.PI / 180
        const dLat = toRad(lat2-lat1)
        const dLon = toRad(lon2-lon1)
        const a = Math.sin(dLat/2)*Math.sin(dLat/2) + Math.cos(toRad(lat1))*Math.cos(toRad(lat2))*Math.sin(dLon/2)*Math.sin(dLon/2)
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a))
        return R * c
      }
      combined = combined.filter(r=> {
        const lat = r.lat || r.geoy;
        const lon = r.lon || r.geox;
        return lat != null && lon != null && haversineKm(lat0, lon0, Number(lat), Number(lon)) <= dKm;
      })
    }

    console.log(`[incidents] SUCCESS: Sending ${combined.length} combined records to client.`);
    res.json({data:combined})
  }catch(e){
    console.error('[incidents] FATAL: An unexpected error occurred in the /incidents handler:', e);
    res.status(502).json({error:e.message})
  }
})

const port = process.env.PORT || 9000
app.listen(port, ()=> console.log('Proxy listening on', port))
