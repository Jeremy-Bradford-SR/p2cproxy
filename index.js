require('dotenv').config();
const express = require('express');
const axios = require('axios');
const NodeCache = require('node-cache');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const ldap = require('ldapjs');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const cluster = require('cluster');
const os = require('os');
const http = require('http');
const https = require('https');

// --- Configuration ---
const PORT = process.env.PORT || 9000;
const ENABLE_AUTH = process.env.ENABLE_AUTH === 'true';
const API_BASE = process.env.P2C_API_BASE || 'http://localhost:8083/api/Data';
const API_KEY = process.env.API_KEY || 'dev-secret-key';
const JWT_SECRET = process.env.JWT_SECRET || 'a-very-secret-key-that-you-should-change';
const NOMINATIM_URL = process.env.NOMINATIM_URL || 'http://p2cgps.bradfordgroup.local:8007/search';

const {
  LDAP_URL,
  LDAP_BIND_DN,
  LDAP_BIND_PASSWORD,
  LDAP_SEARCH_BASE,
  FALLBACK_USER,
  FALLBACK_PASS
} = process.env;

// --- CLUSTERING DISABLED FOR STABILITY ---
// if (cluster.isPrimary) { ... }
// Running directly as single process
startWorker();


function startWorker() {
  const app = express();

  // Fix for Rate Limit 'X-Forwarded-For' error
  app.set('trust proxy', 1);

  // Axios Instance with Keep-Alive
  const axiosInstance = axios.create({
    httpAgent: new http.Agent({ keepAlive: true }),
    httpsAgent: new https.Agent({ keepAlive: true }),
    timeout: 120000 // Increased to 120s to match backend
  });

  // Cache with limits
  const cache = new NodeCache({ stdTTL: 60 * 60 * 24, checkperiod: 120, maxKeys: 10000 });

  // Relax CSP to allow React/react-window inline styles and scripts
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        "default-src": ["'self'", "*"],
        "script-src": ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:", "https:", "*"],
        "connect-src": ["'self'", "*"],
        "font-src": ["'self'", "data:", "https:", "*"]
      },
    },
    crossOriginEmbedderPolicy: false
  }));
  app.use(compression());

  // Rate Limit (per worker)
  app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 2000,
    standardHeaders: true,
    legacyHeaders: false,
  }));

  app.use(cors());
  app.use(bodyParser.json({ strict: false }));

  // Logger
  app.use((req, res, next) => {
    if (req.originalUrl !== '/health') {
      console.log(`[Worker ${process.pid}] ${req.method} ${req.originalUrl}`);
    }
    next();
  });

  // Public Routes
  app.get('/health', (req, res) => res.json({ ok: true, worker: process.pid }));

  app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password required.' });

    // 1. LDAP
    if (LDAP_URL && LDAP_SEARCH_BASE) {
      const client = ldap.createClient({ url: LDAP_URL, tlsOptions: { rejectUnauthorized: false } });
      const userDn = `uid=${username},${LDAP_SEARCH_BASE}`;

      client.bind(userDn, password, (bindErr) => {
        if (bindErr) {
          console.error(`LDAP auth failed: ${username}`, bindErr);
          client.unbind();
          return res.status(401).json({ message: 'Invalid credentials.' });
        }
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '8h' });
        res.json({ token });
        client.unbind();
      });
      return;
    }

    // 2. Safe Fallback
    if (FALLBACK_USER && FALLBACK_PASS) {
      if (username === FALLBACK_USER && password === FALLBACK_PASS) {
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '8h' });
        return res.json({ token });
      }
    } else {
      // Warn if no auth method available
      console.warn('No Authentication Method Configured (LDAP or Fallback). Login failing.');
    }

    return res.status(401).json({ message: 'Invalid credentials.' });
  });

  // --- PROTECTED ROUTES BELOW ---

  // Auth Middleware
  app.use((req, res, next) => {
    if (!ENABLE_AUTH) return next();
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Authentication required' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ message: 'Invalid token' });
      req.user = user;
      next();
    });
  });

  // --- GEOCODING (Internal) ---
  async function geocodeAddress(address) {
    if (!address) throw new Error('Address required');
    const cached = cache.get(address);
    if (cached) return cached; // Silent hit

    const url = `${NOMINATIM_URL}?format=json&q=${encodeURIComponent(address)}&limit=1`;
    try {
      // Use axiosInstance with keep-alive
      const res = await axiosInstance.get(url);
      if (res.data && res.data.length > 0) {
        const match = res.data[0];
        const result = {
          lat: parseFloat(match.lat),
          lon: parseFloat(match.lon),
          display_name: match.display_name
        };
        cache.set(address, result);
        return result;
      }
      return {};
    } catch (e) {
      console.error(`[Geocode] Error: ${e.message}`);
      throw new Error('Geocoding service unavailable');
    }
  }

  app.get('/geocode', async (req, res) => {
    const q = req.query.q;
    if (!q) return res.status(400).json({ error: 'q required' });
    try {
      const out = await geocodeAddress(q);
      res.json(out);
    } catch (e) {
      res.status(502).json({ error: e.message });
    }
  });

  // --- API PROXY ---
  async function forwardToApi(req, res, path) {
    try {
      const query = new URLSearchParams(req.query).toString();
      const url = `${API_BASE}${path}${query ? '?' + query : ''}`;

      // Forward with Keep-Alive Agent
      const response = await axiosInstance({
        method: req.method,
        url: url,
        data: req.method !== 'GET' ? req.body : undefined,
        headers: {
          'X-API-KEY': API_KEY,
          'Content-Type': 'application/json'
        },
        validateStatus: () => true // We handle status
      });

      // Filter unsafe headers that might confuse Nginx/Client
      const unsafeHeaders = ['content-length', 'content-encoding', 'transfer-encoding', 'connection'];
      const headers = {};
      Object.keys(response.headers).forEach(key => {
        if (!unsafeHeaders.includes(key.toLowerCase())) {
          headers[key] = response.headers[key];
        }
      });

      res.status(response.status).set(headers).send(response.data);
    } catch (e) {
      console.error(`[Proxy] Forward Error (${path}):`, e.message);
      // Standardized Error Response
      if (e.response) {
        res.status(e.response.status).json(e.response.data);
      } else if (e.code === 'ECONNREFUSED' || e.code === 'ETIMEDOUT') {
        res.status(502).json({ error: 'Backend API Unavailable', details: e.message });
      } else {
        res.status(500).json({ error: 'Proxy Internal Error', details: e.message });
      }
    }
  }

  // Direct Mappings
  const routes = [
    '/tables', '/schema', '/corrections', '/dispatch', '/traffic', '/reoffenders',
    '/premise-history', '/query', '/incidents', '/search360', '/searchP2C', '/proximity'
  ];
  routes.forEach(r => app.get(r, (req, res) => forwardToApi(req, res, r)));

  // Wildcard Mappings
  const wildcards = [
    '/stats/*', '/jail/*', '/search/*', '/offenders/*', '/Data/sex-offenders'
  ];
  wildcards.forEach(w => {
    // Express routing matching
    const route = w.replace('*', '*'); // trivial
    app.get(route, (req, res) => {
      // For /Data/sex-offenders manually map to /sex-offenders
      if (req.path === '/Data/sex-offenders') return forwardToApi(req, res, '/sex-offenders');
      forwardToApi(req, res, req.path);
    });
  });

  // Deprecated
  app.get('/rawQuery', (req, res) => res.status(410).json({ error: 'Deprecated' }));

  app.listen(PORT, () => console.log(`[Worker ${process.pid}] Listening on ${PORT} (Auth: ${ENABLE_AUTH ? 'ON' : 'OFF'})`));
}
