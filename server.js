'use strict';
/*
 * Sealed: a zero-dependency Node.js server.
 *  - serves the website from /public
 *  - JSON API: accounts, time capsules, public wall, reactions, forecaster ranking
 *  - the text of a capsule is NEVER sent to anyone before its unlock time
 *  - data is stored in a JSON file (DATA_DIR/db.json)
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const PORT = process.env.PORT || process.env.WEBSITES_PORT || 3000;
const PUBLIC = path.join(__dirname, 'public');
// On Azure App Service (Linux) only /home survives restarts and redeploys.
const DATA_DIR = process.env.DATA_DIR || (process.env.WEBSITE_SITE_NAME ? '/home/data' : path.join(__dirname, 'data'));
const DB_FILE = path.join(DATA_DIR, 'db.json');
const MIN_LEAD_MS = (Number(process.env.MIN_LEAD_SECONDS) || 60) * 1000;   // lower value is for automated tests only
const MAX_LEAD_MS = 10 * 365 * 864e5;
const SESSION_DAYS = 30, MAX_CAPSULES = 200;
const TYPES = ['letter', 'prediction'], VISIBILITY = ['private', 'public'], OUTCOMES = ['true', 'partly', 'false'];

/* ---------- database (JSON file, written atomically) ---------- */
fs.mkdirSync(DATA_DIR, { recursive: true });
let db = { users: [], capsules: [] };
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { /* first run */ }
db.users = db.users || []; db.capsules = db.capsules || [];
const byId = new Map(), byName = new Map();
db.users.forEach(indexUser);
function indexUser(u) { byId.set(u.id, u); byName.set(u.lower, u); }
function persist() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DB_FILE);
}

/* ---------- sessions (signed cookie) ---------- */
function loadSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  const f = path.join(DATA_DIR, 'secret.key');
  try { return fs.readFileSync(f, 'utf8'); } catch (e) {
    const s = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(f, s, { mode: 0o600 });
    return s;
  }
}
const SECRET = loadSecret();
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
function makeToken(uid) {
  const p = Buffer.from(JSON.stringify({ u: uid, e: Date.now() + SESSION_DAYS * 864e5 })).toString('base64url');
  return p + '.' + sign(p);
}
function readToken(tok) {
  if (!tok) return null;
  const [p, sig] = tok.split('.');
  if (!p || !sig) return null;
  const a = Buffer.from(sig), b = Buffer.from(sign(p));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.e > Date.now() ? o.u : null; } catch (e) { return null; }
}
function parseCookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const i = c.indexOf('=');
    if (i > 0) { try { o[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim()); } catch (e) {} }
  });
  return o;
}
function isHttps(req) { return String(req.headers['x-forwarded-proto'] || '').includes('https') || !!req.socket.encrypted; }
function setCookie(req, res, val, maxAge) {
  res.setHeader('Set-Cookie', 'sealed=' + val + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + maxAge + (isHttps(req) ? '; Secure' : ''));
}

/* ---------- helpers ---------- */
const hits = new Map();
function limited(key, max, ms) {
  const now = Date.now(), arr = (hits.get(key) || []).filter(t => now - t < ms);
  arr.push(now); hits.set(key, arr);
  return arr.length > max;
}
setInterval(() => hits.clear(), 60 * 60 * 1000).unref();
function clientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  const a = (xf ? xf.split(',')[0].trim() : req.socket.remoteAddress) || '';
  return a.replace(/^(\d+\.\d+\.\d+\.\d+):\d+$/, '$1');
}
function httpErr(status, msg) { const e = new Error(msg); e.status = status; return e; }
function send(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0, tooBig = false; const chunks = [];
    req.on('data', c => { size += c.length; if (size > 10000) tooBig = true; else chunks.push(c); });
    req.on('end', () => {
      if (tooBig) return reject(httpErr(413, 'Request too large'));
      if (!chunks.length) return resolve({});
      try { const o = JSON.parse(Buffer.concat(chunks).toString()); resolve(o && typeof o === 'object' ? o : {}); }
      catch (e) { reject(httpErr(400, 'Invalid JSON')); }
    });
    req.on('error', reject);
  });
}
async function hashPassword(pw, salt) { return (await scrypt(pw, salt, 64)).toString('hex'); }
async function checkPassword(pw, u) {
  const a = Buffer.from(await hashPassword(pw, u.salt), 'hex'), b = Buffer.from(u.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const publicUser = u => ({ username: u.username, created: u.created });

/* ---------- capsule views: the text only leaves the server once unlocked ---------- */
function ownerView(c, now) {
  const open = c.unlockAt <= now;
  const v = { id: c.id, title: c.title, type: c.type, visibility: c.visibility, createdAt: c.createdAt, unlockAt: c.unlockAt, hash: c.hash, open, reactions: c.reactions.length };
  if (open) { v.text = c.text; v.salt = c.salt; v.outcome = c.outcome; }
  return v;
}
function wallView(c, me) {
  return { id: c.id, title: c.title, text: c.text, salt: c.salt, hash: c.hash, type: c.type, createdAt: c.createdAt, unlockAt: c.unlockAt, outcome: c.outcome,
    author: byId.has(c.uid) ? byId.get(c.uid).username : 'deleted', reactions: c.reactions.length, mine: !!me && c.reactions.includes(me.id) };
}
function userStats(uid, now) {
  const mine = db.capsules.filter(c => c.uid === uid);
  const resolved = mine.filter(c => c.type === 'prediction' && c.outcome);
  const score = resolved.reduce((s, c) => s + (c.outcome === 'true' ? 1 : c.outcome === 'partly' ? .5 : 0), 0);
  return { sealed: mine.length, opened: mine.filter(c => c.unlockAt <= now).length, resolved: resolved.length, accuracy: resolved.length ? Math.round(score / resolved.length * 100) : null };
}

/* ---------- API ---------- */
async function handleApi(req, res, url) {
  const m = req.method, p = url.pathname, now = Date.now();

  if (m !== 'GET' && m !== 'HEAD') {
    // CSRF protection: custom header + same-origin check
    if (req.headers['x-sealed'] !== '1') throw httpErr(403, 'Missing header');
    const o = req.headers.origin;
    if (o) {
      let host = ''; try { host = new URL(o).host; } catch (e) {}
      if (host !== req.headers.host && host !== req.headers['x-forwarded-host']) throw httpErr(403, 'Bad origin');
    }
  }
  const uid = readToken(parseCookies(req).sealed);
  const me = uid ? byId.get(uid) : null;
  const needUser = () => { if (!me) throw httpErr(401, 'Please log in first'); return me; };
  const findOwn = id => { const c = db.capsules.find(x => x.id === id && x.uid === needUser().id); if (!c) throw httpErr(404, 'Capsule not found.'); return c; };

  if (p === '/api/health' && m === 'GET') return send(res, 200, { ok: true, now });

  if (p === '/api/stats' && m === 'GET') {
    const upcoming = db.capsules.filter(c => c.visibility === 'public' && c.unlockAt > now).map(c => c.unlockAt);
    return send(res, 200, { now, users: db.users.length, sealed: db.capsules.length, opened: db.capsules.filter(c => c.unlockAt <= now).length, nextOpen: upcoming.length ? Math.min(...upcoming) : null });
  }

  if (p === '/api/register' && m === 'POST') {
    if (limited('reg:' + clientIp(req), 10, 10 * 60 * 1000)) throw httpErr(429, 'Too many attempts. Try again later.');
    const b = await readBody(req), name = String(b.username || '').trim(), pw = String(b.password || '');
    if (!/^[A-Za-z0-9_]{3,20}$/.test(name)) throw httpErr(400, 'Username must be 3 to 20 letters, numbers or underscores.');
    if (pw.length < 8 || pw.length > 100) throw httpErr(400, 'Password must be 8 to 100 characters.');
    if (byName.has(name.toLowerCase())) throw httpErr(409, 'That username is taken.');
    const salt = crypto.randomBytes(16).toString('hex');
    const u = { id: crypto.randomUUID(), username: name, lower: name.toLowerCase(), salt, hash: await hashPassword(pw, salt), created: Date.now() };
    if (byName.has(u.lower)) throw httpErr(409, 'That username is taken.');
    db.users.push(u); indexUser(u); persist();
    setCookie(req, res, makeToken(u.id), SESSION_DAYS * 86400);
    return send(res, 201, { user: publicUser(u), stats: userStats(u.id, now), now });
  }

  if (p === '/api/login' && m === 'POST') {
    const b = await readBody(req), name = String(b.username || '').trim().toLowerCase();
    if (limited('login:' + clientIp(req) + ':' + name, 8, 10 * 60 * 1000)) throw httpErr(429, 'Too many attempts. Try again later.');
    const u = byName.get(name);
    if (!u || !(await checkPassword(String(b.password || ''), u))) throw httpErr(401, 'Wrong username or password.');
    setCookie(req, res, makeToken(u.id), SESSION_DAYS * 86400);
    return send(res, 200, { user: publicUser(u), stats: userStats(u.id, now), now });
  }

  if (p === '/api/logout' && m === 'POST') { setCookie(req, res, '', 0); return send(res, 200, { ok: true }); }

  if (p === '/api/me' && m === 'GET') return send(res, 200, me ? { user: publicUser(me), stats: userStats(me.id, now), now } : { user: null, now });

  if (p === '/api/me' && m === 'DELETE') {
    const u = needUser();
    db.capsules = db.capsules.filter(c => c.uid !== u.id);
    db.capsules.forEach(c => { c.reactions = c.reactions.filter(x => x !== u.id); });
    db.users = db.users.filter(x => x.id !== u.id); byId.delete(u.id); byName.delete(u.lower);
    persist(); setCookie(req, res, '', 0);
    return send(res, 200, { ok: true });
  }

  /* --- capsules --- */
  if (p === '/api/capsules' && m === 'GET') {
    const u = needUser();
    const list = db.capsules.filter(c => c.uid === u.id).sort((a, b) => a.unlockAt - b.unlockAt).map(c => ownerView(c, now));
    return send(res, 200, { now, capsules: list, stats: userStats(u.id, now) });
  }

  if (p === '/api/capsules' && m === 'POST') {
    const u = needUser(), b = await readBody(req);
    if (limited('cap:' + u.id, 30, 60 * 60 * 1000)) throw httpErr(429, 'You are sealing too fast. Try again in a while.');
    const title = typeof b.title === 'string' ? b.title.trim() : '', text = typeof b.text === 'string' ? b.text.trim() : '';
    if (title.length < 1 || title.length > 60) throw httpErr(400, 'Title must be 1 to 60 characters.');
    if (text.length < 1 || text.length > 1000) throw httpErr(400, 'Message must be 1 to 1000 characters.');
    if (!TYPES.includes(b.type)) throw httpErr(400, 'Unknown capsule type.');
    if (!VISIBILITY.includes(b.visibility)) throw httpErr(400, 'Unknown visibility.');
    if (!Number.isFinite(b.unlockAt)) throw httpErr(400, 'Pick an unlock time.');
    if (b.unlockAt - now < MIN_LEAD_MS) throw httpErr(400, 'The unlock time must be at least ' + Math.round(MIN_LEAD_MS / 1000) + ' seconds from now.');
    if (b.unlockAt - now > MAX_LEAD_MS) throw httpErr(400, 'The unlock time must be within 10 years.');
    if (db.capsules.filter(c => c.uid === u.id).length >= MAX_CAPSULES) throw httpErr(403, 'You reached the limit of ' + MAX_CAPSULES + ' capsules. Burn some first.');
    const salt = crypto.randomBytes(16).toString('hex');
    const c = { id: crypto.randomUUID(), uid: u.id, title, text, salt, hash: sha256(salt + text), type: b.type, visibility: b.visibility,
      createdAt: now, unlockAt: Math.round(b.unlockAt), outcome: null, reactions: [] };
    db.capsules.push(c); persist();
    return send(res, 201, { capsule: ownerView(c, now), stats: userStats(u.id, now) });
  }

  let mm;
  if ((mm = p.match(/^\/api\/capsules\/([\w-]+)$/)) && m === 'DELETE') {
    const c = findOwn(mm[1]);
    db.capsules = db.capsules.filter(x => x !== c); persist();
    return send(res, 200, { ok: true, stats: userStats(me.id, now) });
  }
  if ((mm = p.match(/^\/api\/capsules\/([\w-]+)\/visibility$/)) && m === 'POST') {
    const c = findOwn(mm[1]), b = await readBody(req);
    if (!VISIBILITY.includes(b.visibility)) throw httpErr(400, 'Unknown visibility.');
    c.visibility = b.visibility; persist();
    return send(res, 200, { capsule: ownerView(c, now) });
  }
  if ((mm = p.match(/^\/api\/capsules\/([\w-]+)\/outcome$/)) && m === 'POST') {
    const c = findOwn(mm[1]), b = await readBody(req);
    if (c.type !== 'prediction') throw httpErr(400, 'Only predictions can be marked.');
    if (c.unlockAt > now) throw httpErr(403, 'This capsule is still sealed.');
    if (c.outcome) throw httpErr(409, 'You already marked this prediction. It cannot be changed.');
    if (!OUTCOMES.includes(b.outcome)) throw httpErr(400, 'Unknown outcome.');
    c.outcome = b.outcome; persist();
    return send(res, 200, { capsule: ownerView(c, now), stats: userStats(me.id, now) });
  }
  if ((mm = p.match(/^\/api\/capsules\/([\w-]+)\/react$/)) && m === 'POST') {
    const u = needUser(), c = db.capsules.find(x => x.id === mm[1]);
    if (!c || c.visibility !== 'public' || c.unlockAt > now) throw httpErr(404, 'Capsule not found.');
    const i = c.reactions.indexOf(u.id);
    if (i >= 0) c.reactions.splice(i, 1); else c.reactions.push(u.id);
    persist();
    return send(res, 200, { reactions: c.reactions.length, mine: i < 0 });
  }

  /* --- public wall and forecasters --- */
  if (p === '/api/wall' && m === 'GET') {
    const offset = Math.max(0, parseInt(url.searchParams.get('offset')) || 0), limit = Math.min(20, Math.max(1, parseInt(url.searchParams.get('limit')) || 8));
    const all = db.capsules.filter(c => c.visibility === 'public' && c.unlockAt <= now).sort((a, b) => b.unlockAt - a.unlockAt);
    return send(res, 200, { now, items: all.slice(offset, offset + limit).map(c => wallView(c, me)), more: offset + limit < all.length });
  }

  if (p === '/api/forecasters' && m === 'GET') {
    const rows = db.users.map(u => ({ username: u.username, ...userStats(u.id, now) })).filter(r => r.resolved >= 3)
      .sort((a, b) => b.accuracy - a.accuracy || b.resolved - a.resolved).slice(0, 10)
      .map((r, i) => ({ rank: i + 1, username: r.username, accuracy: r.accuracy, resolved: r.resolved, me: !!me && me.username === r.username }));
    return send(res, 200, { rows });
  }

  throw httpErr(404, 'Not found');
}

/* ---------- static files ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8' };
function serveStatic(req, res, url) {
  let rel;
  try { rel = decodeURIComponent(url.pathname); } catch (e) { return send(res, 400, { error: 'Bad request' }); }
  if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(PUBLIC, rel));
  if (!file.startsWith(PUBLIC + path.sep)) return send(res, 403, { error: 'Forbidden' });
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Not found'); }
    const ext = path.extname(file).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600' });
    res.end(req.method === 'HEAD' ? undefined : buf);
  });
}

/* ---------- server ---------- */
const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'");
  if (isHttps(req)) res.setHeader('Strict-Transport-Security', 'max-age=15552000');
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) await handleApi(req, res, url);
    else if (req.method === 'GET' || req.method === 'HEAD') serveStatic(req, res, url);
    else send(res, 405, { error: 'Method not allowed' });
  } catch (e) {
    const status = e.status || 500;
    if (status === 500) console.error(e);
    if (!res.headersSent) send(res, status, { error: status === 500 ? 'Server error' : e.message }); else res.end();
  }
});
server.listen(PORT, () => console.log('Sealed listening on port ' + PORT + ' (data: ' + DB_FILE + ')'));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
