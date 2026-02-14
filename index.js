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

// Authentication Middleware
function authenticateToken(req, res, next) {
  // Allow public endpoints
  const publicPaths = ['/login', '/health', '/geocode'];
  if (publicPaths.some(p => req.path.startsWith(p))) return next();

  // Allow OPTIONS (CORS preflight)
  if (req.method === 'OPTIONS') return next();

  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (token == null) return res.sendStatus(401)

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403)
    req.user = user
    next()
  })
}

app.use(authenticateToken);

// Add a global error handler for unhandled promise rejections to prevent silent crashes
process.on('unhandledRejection', (reason, promise) => {
  console.error('!!! UNHANDLED REJECTION AT:', promise, 'REASON:', reason);
  // Optionally, you might want to exit the process: process.exit(1);
});

// health
app.get('/health', (req, res) => res.json({ ok: true }))

// Login endpoint
app.post('/login', (req, res) => {
  // ... (Login logic unchanged)
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
      rejectUnauthorized: false
    }
  });

  const userDn = `uid=${username},${LDAP_SEARCH_BASE}`;

  client.bind(userDn, password, (bindErr) => {
    if (bindErr) {
      console.error(`LDAP auth failed for user: ${username}`, bindErr);
      return res.status(401).json({ message: 'Invalid credentials or user not found.' });
    }

    console.log(`LDAP auth successful for user: ${username}`);
    const token = jwt.sign({ username: username }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token });
    client.unbind();
  });
});

// ... (Proj4 setup unchanged)

// Use an environment variable for the API base URL, with a default for local development.
const API_BASE = process.env.P2C_API_BASE || 'http://localhost:8083/api/Data'
// API Key for upstream
const API_KEY = process.env.API_KEY || 'dev-secret-key';

const cache = new NodeCache({ stdTTL: 60 * 60 * 24, checkperiod: 120 }) // 1 day TTL for geocoding

function sanitizeIdentifier(id) {
  if (!id) return ''
  if (/[^a-zA-Z0-9_\.]/.test(id)) throw new Error('Invalid identifier')
  return id
}

// Simple delay function
const sleep = ms => new Promise(r => setTimeout(r, ms));

function cleanAddress(address) {
  // ... (unchanged)
  if (!address) return '';
  let cleaned = address
    .replace(/^(at|on)\s+/i, '')
    .replace(/\s+at\s+/gi, ' and ')
    .replace(/\s+on\s+/gi, ' ')
    .replace(/-BLK/gi, ' ')
    .replace(/\s+BLK/gi, ' ')
    .replace(/\//g, ' and ')
    .replace(/,(\s*,)+/g, ',')
    .trim();

  if (/\s+and\s+/i.test(cleaned) && /^\d+\s+/.test(cleaned)) {
    cleaned = cleaned.replace(/^\d+\s+/, '');
  }
  return cleaned;
}

const NOMINATIM_URL = process.env.NOMINATIM_URL || 'http://p2cgps.bradfordgroup.local:8007/search';

// Helper to geocode via Internal Nominatim (cached)
async function geocodeAddress(address) {
  if (!address) throw new Error('Address is required');

  // Check cache
  const cached = cache.get(address);
  if (cached) {
    console.log(`[Geocode] HIT: ${address}`);
    return cached;
  }

  console.log(`[Geocode] MISS: ${address} -> ${NOMINATIM_URL}`);

  const url = `${NOMINATIM_URL}?format=json&q=${encodeURIComponent(address)}&limit=1`;

  try {
    const res = await axios.get(url, {
      headers: { 'User-Agent': 'P2C-Proxy/1.0' }
    });

    if (res.data && res.data.length > 0) {
      const match = res.data[0];
      const result = {
        lat: parseFloat(match.lat),
        lon: parseFloat(match.lon),
        display_name: match.display_name
      };

      cache.set(address, result);
      return result;
    } else {
      console.log(`[Geocode] No results for: ${address}`);
      return {};
    }

  } catch (e) {
    console.error(`[Geocode] Error: ${e.message}`);
    throw new Error('Geocoding downstream failed');
  }
}

// Helper to forward requests to the API
async function forwardToApi(req, res, path) {
  try {
    // Construct the URL. Use req.query to rebuild query string.
    const query = new URLSearchParams(req.query).toString();
    const url = `${API_BASE}${path}${query ? '?' + query : ''}`;
    console.log(`[Proxy] Forwarding ${req.method} ${req.originalUrl} -> ${url}`);

    // Forward the request with API Key
    const response = await axios({
      method: req.method,
      url: url,
      data: req.method !== 'GET' ? req.body : undefined,
      headers: {
        'X-API-KEY': API_KEY, // Inject Key
        'Content-Type': 'application/json'
      },
      validateStatus: () => true // Handle status manually
    });

    // Send back response
    res.status(response.status).json(response.data);
  } catch (e) {
    console.error(`[Proxy] Error forwarding to ${path}:`, e.message);
    if (e.response) {
      res.status(e.response.status).json(e.response.data);
    } else {
      res.status(502).json({ error: 'Bad Gateway: Failed to contact upstream API' });
    }
  }
}

app.get('/tables', (req, res) => forwardToApi(req, res, '/tables'));
app.get('/schema', (req, res) => forwardToApi(req, res, '/schema'));
app.get('/Data/sex-offenders', (req, res) => forwardToApi(req, res, '/sex-offenders'));

// --- New Endpoints Forwarding ---
app.get('/stats/*', (req, res) => forwardToApi(req, res, req.path)); // e.g. /stats/probation -> API /stats/probation
app.get('/corrections', (req, res) => forwardToApi(req, res, '/corrections'));
app.get('/dispatch', (req, res) => forwardToApi(req, res, '/dispatch'));
app.get('/traffic', (req, res) => forwardToApi(req, res, '/traffic'));
app.get('/jail/*', (req, res) => forwardToApi(req, res, req.path));
app.get('/search/*', (req, res) => forwardToApi(req, res, req.path));
app.get('/offenders/*', (req, res) => forwardToApi(req, res, req.path));
app.get('/reoffenders', (req, res) => forwardToApi(req, res, '/reoffenders'));
app.get('/premise-history', (req, res) => forwardToApi(req, res, '/premise-history'));

// Forwarding for existing complex routes that are now in API
app.get('/query', (req, res) => forwardToApi(req, res, '/query'));
app.get('/incidents', (req, res) => forwardToApi(req, res, '/incidents'));
app.get('/search360', (req, res) => forwardToApi(req, res, '/search360'));
app.get('/searchP2C', (req, res) => forwardToApi(req, res, '/searchP2C'));
app.get('/proximity', (req, res) => forwardToApi(req, res, '/proximity'));


// Proxy for the rawQuery endpoint - REMOVED/DEPRECATED
app.get('/rawQuery', async (req, res) => {
  console.warn('[Proxy] Blocked call to deprecated /rawQuery');
  res.status(410).json({ error: 'Endpoint Gone: rawQuery is deprecated for security. Please upgrade client.' });
})

// Geocode endpoint using Nominatim with cache (Kept in Proxy as it calls external service)
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

const port = process.env.PORT || 9000
app.listen(port, () => console.log('Proxy listening on', port))
