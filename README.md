# P2C Proxy Server

A Node.js Express server acting as a middleware gateway between the frontend and the legacy MSSQL API.

## Responsibilities
- **Authentication**: LDAP integration for user login.
- **Security**: JWT verification, Helmet headers, Rate limiting.
- **CORS**: Handles Cross-Origin Resource Sharing policies.
- **Geocoding & Caching**: 
    - Proxies calls to Nominatim (OpenStreetMap) for geocoding addresses.
    - Caches geocoding results in SQLite/Memory to prevent redundant external API calls.
- **Data Transformation**: Converts raw MSSQL responses into frontend-friendly JSON structures.
- **Coordinate Projection**: Converts state plane coordinates to Lat/Lon using `proj4`.

## Key Endpoints
- `POST /login`: Authenticates against LDAP and issues a JWT.
- `GET /api/incidents`: Aggregates CAD, Arrest, and Crime data.
- `GET /api/traffic`: Fetches traffic citations and accidents.
- `GET /api/jail`: Proxies jail inmate data.
- `GET /api/reoffenders`: Identifies repeat offenders.

## Setup
### Environment Variables
Required in `.env`:
- `LDAP_URL`, `LDAP_BIND_DN`, `LDAP_SEARCH_BASE`
- `JWT_SECRET`
- `API_BASE` (URL of the internal C# API)

### Docker
```bash
docker compose up -d p2cproxy
```
Exposes port `9000`.
