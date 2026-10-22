/**
 * Scudo Fortezza — reverse proxy invisibile con agente guardian.
 * Tutto ciò che non è traffico web legittimo viene scartato in silenzio.
 *
 * Env richieste:
 *   ORIGIN_URL  -> es. http://10.0.0.2:3000  (server nascosto, IP privato)
 *   PORT        -> default 8080 (dietro Caddy)
 *   LOG_DIR     -> default ./logs (security-events.log e flag LOCKDOWN: il volume di docker-compose)
 *
 * Il proxy usa solo i moduli di Node (niente http-proxy-middleware): meno dipendenze,
 * meno falle da rincorrere. Richiede Node >= 22.23.4 (correzioni del 21 ottobre 2026).
 */
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');
const querystring = require('node:querystring');
const express = require('express');
const { guardian } = require('./guardian');

const ORIGIN = process.env.ORIGIN_URL;
if (!ORIGIN) { console.error('ORIGIN_URL mancante'); process.exit(1); }
const target = new URL(ORIGIN);
const client = target.protocol === 'https:' ? https : http;
const basePath = target.pathname.replace(/\/$/, '');
const LOG_DIR = process.env.LOG_DIR || path.join(process.cwd(), 'logs');
require('node:fs').mkdirSync(LOG_DIR, { recursive: true });

// Header "hop-by-hop": valgono per una sola connessione e non si inoltrano (RFC 9110 §7.6.1).
const HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
// Impronte del backend che non devono uscire.
const FINGERPRINT = new Set(['server', 'x-powered-by', 'via']);

function forwardable(headers, drop) {
  const named = String(headers.connection || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
  const out = {};
  for (const [k, v] of Object.entries(headers)) if (!HOP.has(k) && !drop.has(k) && !named.includes(k)) out[k] = v;
  return out;
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // Caddy davanti

// Corpo letto solo per l'ispezione del guardian (limite anti-abuso)
app.use(express.json({ limit: '100kb', strict: false }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

// ── Invisibilità: niente risposte che rivelino il sistema ──
// Metodi non web: connessione chiusa senza risposta (per gli scanner = host morto)
app.use((req, res, next) => {
  const ok = ['GET', 'POST', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
  if (!ok.includes(req.method)) return req.socket.destroy();
  next();
});

// ── Agente guardian: WAF, rate limit, blocklist, lockdown ──
app.use(guardian({
  rateLimit: { windowMs: 60_000, max: 120 },
  strictPaths: ['/login', '/api/auth', '/api/pay'],
  lockdown: { threshold: 50, windowMs: 300_000, unlockAfterMs: 900_000 },
  skipPaths: ['/webhook'],
  // Nel volume montato: il log e il lockdown sopravvivono al riavvio del container.
  logFile: path.join(LOG_DIR, 'security-events.log'),
  lockdownFlagFile: path.join(LOG_DIR, 'LOCKDOWN'),
  // Invisibilità: gli offender non ricevono un 403 "parlante",
  // la connessione viene chiusa e basta (vedi silentMode in guardian.js)
  silentMode: true,
}));

// ── Proxy verso il server nascosto ──
app.use((req, res) => {
  const headers = forwardable(req.headers, new Set());
  headers.host = target.host;
  const ip = req.socket.remoteAddress || '';
  headers['x-forwarded-for'] = req.headers['x-forwarded-for'] ? `${req.headers['x-forwarded-for']}, ${ip}` : ip;
  headers['x-forwarded-proto'] = req.protocol;
  headers['x-forwarded-host'] = req.headers.host || '';

  // express.json/urlencoded hanno già letto il corpo per il guardian: va rimandato com'era,
  // altrimenti ogni POST/PUT con corpo resterebbe appesa. Gli altri tipi passano come flusso.
  let body = null;
  if (req._body) {
    const type = String(req.headers['content-type'] || '');
    body = type.includes('application/x-www-form-urlencoded') ? querystring.stringify(req.body) : JSON.stringify(req.body);
    headers['content-length'] = Buffer.byteLength(body);
  }

  const upstream = client.request({
    protocol: target.protocol, hostname: target.hostname, port: target.port,
    method: req.method, path: basePath + req.originalUrl, headers, timeout: 30_000,
  }, up => {
    res.writeHead(up.statusCode || 502, forwardable(up.headers, FINGERPRINT));
    up.pipe(res);
  });
  upstream.on('timeout', () => upstream.destroy(new Error('timeout')));
  upstream.on('error', () => {
    if (!res.headersSent) { res.writeHead(502); res.end('Servizio non disponibile.'); }
    else res.destroy();
  });
  if (body !== null) upstream.end(body);
  else req.pipe(upstream);
});

app.listen(process.env.PORT || 8080, () => console.log('Scudo attivo'));
