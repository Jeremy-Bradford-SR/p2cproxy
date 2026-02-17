require('dotenv').config();
const express = require('express');
const axios = require('axios');
const NodeCache = require('node-cache');
const bodyParser = require('body-parser');
const cors = require('cors');
const proj4 = require('proj4');
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

// --- CLUSTERING ---
if (cluster.isPrimary) {
  const numCPUs = os.cpus().length;
  console.log(`[Master] Primary ${process.pid} is running`);
  console.log(`[Master] Forking ${numCPUs} workers...`);

  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  cluster.on('exit', (worker, code, signal) => {
    console.warn(`[Master] Worker ${worker.process.pid} died. Restarting...`);
    cluster.fork();
  });
} else {
  // --- WORKER PROCESS ---
  startWorker();
}

function startWorker() {
  const app = express();

  // 1. Connection Pooling (Keep-Alive)
  // Reduce TCP overhead by keeping connections open
  const axiosInstance = axios.create({
    httpAgent: new http.Agent({ keepAlive: true }),
    httpsAgent: new https.Agent({ keepAlive: true }),
    timeout: 30000 // 30s timeout
  });

  // 2. Optimized Caching
  // Added maxKeys to prevent OOM
  const cache = new NodeCache({ stdTTL: 60 * 60 * 24, checkperiod: 120, maxKeys: 10000 });

  // 3. Security Headers
  app.use(helmet());

  // 4. Compression
  app.use(compression());

  // 5. Rate Limiting
  // Note: In a cluster, this limit is per-worker (memory store). 
  // For strict global limits, Redis is needed, but this prevents abuse per-core.
  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 2000, // Increased limit per worker slightly
    standardHeaders: true,
    legacyHeaders: false,
  });
  app.use(limiter);

  app.use(cors());
  app.use(bodyParser.json({ strict: false }));

  // Logging
  app.use((req, res, next) => {
    // Reduced logging noise for health checks
    if (req.originalUrl !== '/health') {
      console.log(`[Worker ${process.pid}] ${new Date().toISOString()} ${req.method} ${req.originalUrl}`);
    }
    next();
  });

  // 6. Security: Authentication Middleware
  function authenticateToken(req, res, next) {
    if (!ENABLE_AUTH) {
      // Log once per worker ideally, but here we just pass through
      return next();
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Authentication required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ message: 'Invalid or expired token' });
      req.user = user;
      next();
    });
  }

  app.use(authenticateToken); // Apply to all routes (Login excluded below manually if needed, or put above)

  // Unhandled Rejections
  process.on('unhandledRejection', (reason, promise) => {
    console.error('!!! UNHANDLED REJECTION AT:', promise, 'REASON:', reason);
  });

  // Health Check (Public)
  app.get('/health', (req, res) => res.json({ ok: true, worker: process.pid }));

  // Login Endpoint (Public - bypassed in Middleware? No, middleware is currently Global)
  // Fix: Move Login ABOVE authenticateToken or make generic middleware smarter.
  // For now, let's redefine middleware application.

  // REDEFINING MIDDLEWARE STACK TO EXCLUDE LOGIN FROM AUTH
}

// Rewriting startWorker with correct middleware order for Login
function startWorker() {
  const app = express();

  // Axios Instance with Keep-Alive
  const axiosInstance = axios.create({
    httpAgent: new http.Agent({ keepAlive: true }),
    httpsAgent: new https.Agent({ keepAlive: true }),
    timeout: 30000
  });

  // Cache with limits
  const cache = new NodeCache({ stdTTL: 60 * 60 * 24, checkperiod: 120, maxKeys: 10000 });

  app.use(helmet());
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

      res.status(response.status).json(response.data);
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
