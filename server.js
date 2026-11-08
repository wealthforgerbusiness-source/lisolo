'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin');
const createPay = require('./pay');

const isProd = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT) || 10000;
const TERMS_VERSION = String(process.env.TERMS_VERSION || '1');
const SESSION_MS = 14 * 24 * 60 * 60 * 1000;
const DAY = 86400000;
const MIN_AGE = 13;
const MAX_AGE = 110;
const COOKIE = 'lisolo_session';
const PUBLIC_DIR = path.join(__dirname, 'public');

let BASE = String(process.env.APP_BASE_URL || '').trim().replace(/\/+$/, '');
if (BASE && !/^https?:\/\//i.test(BASE)) BASE = 'https://' + BASE;

const ADMIN_EMAILS = new Set(
  String(process.env.ADMIN_EMAILS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
);

['FIREBASE_WEB_API_KEY', 'FIREBASE_AUTH_DOMAIN', 'FIREBASE_APP_ID', 'APP_BASE_URL', 'ADMIN_EMAILS'].forEach((k) => {
  if (!process.env[k]) console.warn('[config] variable manquante:', k);
});

function loadServiceAccount() {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!raw) throw new Error('FIREBASE_SERVICE_ACCOUNT manquant');
  let t = raw.trim();
  if (!t.startsWith('{')) t = Buffer.from(t, 'base64').toString('utf8');
  const sa = JSON.parse(t);
  if (sa.private_key) sa.private_key = sa.private_key.replace(/\\n/g, '\n');
  return sa;
}

let sa;
try {
  sa = loadServiceAccount();
} catch (e) {
  console.error('[boot]', e.message);
  process.exit(1);
}

admin.initializeApp({ credential: admin.credential.cert(sa), projectId: sa.project_id });
const db = admin.firestore();
db.settings({ ignoreUndefinedProperties: true });
const auth = admin.auth();
const FieldValue = admin.firestore.FieldValue;

const SECRET =
  process.env.SESSION_SECRET || crypto.createHash('sha256').update(String(sa.private_key)).digest('hex');

const LIMITS = {
  free: { messagesPerMonth: 30, quizzes: 2, questions: 10, answersPerQuiz: 20, historyDays: 7 },
  premium: { messagesPerMonth: null, quizzes: 100, questions: 30, answersPerQuiz: null, historyDays: null },
};
const isPremium = (u) => Number(u.planExpiresAt || 0) > Date.now();
const limitsFor = (u) => (isPremium(u) ? LIMITS.premium : LIMITS.free);

const USERNAME_RE = /^[a-z0-9_]{3,20}$/;
const ID_RE = /^[A-Za-z0-9]{20}$/;
const UID_RE = /^[A-Za-z0-9_-]{6,128}$/;
const IP_RE = /^[0-9a-fA-F:.]{3,45}$/;
const RESERVED = new Set([
  'admin', 'api', 'app', 'login', 'legal', 'index', 'u', 'q', 'lisolo', 'support', 'help',
  'static', 'images', 'sw', 'manifest', 'root', 'moderator', 'system', 'null', 'undefined',
]);

class HttpError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}
const fail = (status, code) => {
  throw new HttpError(status, code);
};
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

class TTLCache {
  constructor(ttl, max) {
    this.ttl = ttl;
    this.max = max;
    this.map = new Map();
  }
  get(k) {
    const e = this.map.get(k);
    if (!e) return undefined;
    if (e.x < Date.now()) {
      this.map.delete(k);
      return undefined;
    }
    return e.v;
  }
  set(k, v) {
    if (this.map.size >= this.max) this.map.delete(this.map.keys().next().value);
    this.map.set(k, { v, x: Date.now() + this.ttl });
    return v;
  }
  del(k) {
    this.map.delete(k);
  }
}

const userCache = new TTLCache(30000, 3000);
const profileCache = new TTLCache(120000, 2000);
const quizCache = new TTLCache(60000, 1000);
const adminCache = new TTLCache(60000, 10);
const ageCache = new TTLCache(120000, 1);

const clean = (v) =>
  String(v)
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2066-\u2069]/g, '')
    .replace(/\r\n?/g, '\n')
    .trim();

function txt(v, min, max, code) {
  if (typeof v !== 'string' || v.length > max * 4) fail(400, code);
  const s = clean(v).replace(/\n{3,}/g, '\n\n');
  if (s.length < min || s.length > max) fail(400, code);
  return s;
}

function line(v, min, max, code) {
  const s = txt(v, 0, max * 4, code).replace(/\s+/g, ' ').trim();
  if (s.length < min || s.length > max) fail(400, code);
  return s;
}

const body = (req) => (req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {});
const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const shifted = () => new Date(Date.now() + 3600000).toISOString();
const monthKey = () => shifted().slice(0, 7);
const dayKey = () => shifted().slice(0, 10);

const BIRTH_RE = /^\d{4}-\d{2}-\d{2}$/;

function ageFromBirth(raw) {
  const iso = typeof raw === 'string' ? raw.trim() : '';
  if (!BIRTH_RE.test(iso)) return null;
  const y = Number(iso.slice(0, 4));
  const m = Number(iso.slice(5, 7));
  const d = Number(iso.slice(8, 10));
  const dt = new Date(Date.UTC(y, m - 1, d));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) return null;
  const today = shifted().slice(0, 10);
  const ty = Number(today.slice(0, 4));
  const tm = Number(today.slice(5, 7));
  const td = Number(today.slice(8, 10));
  let age = ty - y;
  if (tm < m || (tm === m && td < d)) age -= 1;
  if (age < 0 || age > MAX_AGE) return null;
  return age;
}

function validateBirth(raw) {
  if (raw === undefined || raw === null || raw === '') return { error: 'birth_required' };
  const iso = typeof raw === 'string' ? raw.trim() : '';
  if (!BIRTH_RE.test(iso)) return { error: 'birth_invalid' };
  const age = ageFromBirth(iso);
  if (age === null) return { error: 'birth_invalid' };
  if (age < MIN_AGE) return { error: 'age_too_young' };
  return { iso, age };
}

function getIp(req) {
  const cf = req.get('cf-connecting-ip');
  if (cf && IP_RE.test(cf)) return cf;
  return req.ip || 'unknown';
}

function fingerprint(req) {
  const dev = String(req.get('x-device-id') || '').slice(0, 64);
  const ua = String(req.get('user-agent') || '').slice(0, 200);
  return crypto.createHmac('sha256', SECRET).update(getIp(req) + '|' + ua + '|' + dev).digest('hex').slice(0, 20);
}

const baseUrl = (req) => BASE || `${req.protocol}://${req.get('host')}`;

function withTimeout(promise, ms, fallback) {
  let timer;
  const guard = new Promise((resolve) => {
    timer = setTimeout(() => resolve(fallback), ms);
  });
  return Promise.race([Promise.resolve(promise).catch(() => fallback), guard]).then(
    (v) => {
      clearTimeout(timer);
      return v;
    },
    () => {
      clearTimeout(timer);
      return fallback;
    }
  );
}

function originOk(req) {
  const origin = req.get('origin');
  if (!origin) return true;
  try {
    const h = new URL(origin).host;
    return h === req.get('host') || (BASE !== '' && h === new URL(BASE).host);
  } catch (e) {
    return false;
  }
}

const cookieOpts = () => ({ httpOnly: true, secure: isProd, sameSite: 'lax', path: '/' });
const clearCookie = (res) => res.clearCookie(COOKIE, cookieOpts());

function readCookie(req, name) {
  const h = req.headers.cookie;
  if (!h) return '';
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) {
      try {
        return decodeURIComponent(part.slice(i + 1).trim());
      } catch (e) {
        return '';
      }
    }
  }
  return '';
}

const pending = { global: {}, days: {} };
let flushing = false;

function bump(field, n = 1) {
  pending.global[field] = (pending.global[field] || 0) + n;
  const d = dayKey();
  pending.days[d] = pending.days[d] || {};
  pending.days[d][field] = (pending.days[d][field] || 0) + n;
}

async function flushStats() {
  if (flushing || !Object.keys(pending.global).length) return;
  flushing = true;
  const snap = { global: pending.global, days: pending.days };
  pending.global = {};
  pending.days = {};
  try {
    const inc = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, FieldValue.increment(v)]));
    const batch = db.batch();
    batch.set(db.doc('stats/global'), { ...inc(snap.global), updatedAt: Date.now() }, { merge: true });
    for (const [d, o] of Object.entries(snap.days)) {
      batch.set(db.doc('stats/day_' + d), { ...inc(o), date: d }, { merge: true });
    }
    await batch.commit();
  } catch (e) {
    console.error('[stats]', e.message);
    for (const [k, v] of Object.entries(snap.global)) pending.global[k] = (pending.global[k] || 0) + v;
    for (const [d, o] of Object.entries(snap.days)) {
      pending.days[d] = pending.days[d] || {};
      for (const [k, v] of Object.entries(o)) pending.days[d][k] = (pending.days[d][k] || 0) + v;
    }
  } finally {
    flushing = false;
  }
}
setInterval(flushStats, 30000).unref();

const userRef = (uid) => db.collection('users').doc(uid);

async function getUser(uid) {
  const hit = userCache.get(uid);
  if (hit !== undefined) return hit;
  const s = await userRef(uid).get();
  return userCache.set(uid, s.exists ? { uid, ...s.data() } : null);
}

async function getPublicProfile(raw) {
  const uname = String(raw || '').toLowerCase();
  if (!USERNAME_RE.test(uname)) return null;
  const hit = profileCache.get(uname);
  if (hit !== undefined) return hit;
  const s = await db.doc('usernames/' + uname).get();
  return profileCache.set(uname, s.exists ? { username: uname, ...s.data() } : null);
}

async function getQuiz(id) {
  const hit = quizCache.get(id);
  if (hit !== undefined) return hit;
  const s = await db.collection('quizzes').doc(id).get();
  return quizCache.set(id, s.exists ? { id, ...s.data() } : null);
}

function meView(u) {
  const prem = isPremium(u);
  const used = u.usage && u.usage.month === monthKey() ? u.usage.received : 0;
  return {
    uid: u.uid,
    email: u.email,
    displayName: u.displayName,
    username: u.username,
    photo: u.photo || '',
    birthDate: u.birthDate || '',
    age: ageFromBirth(u.birthDate),
    plan: prem ? 'premium' : 'free',
    planExpiresAt: prem ? u.planExpiresAt : 0,
    limits: prem ? LIMITS.premium : LIMITS.free,
    usage: { messagesThisMonth: used, quizzes: u.quizCount || 0 },
    unread: u.unread || 0,
    isAdmin: ADMIN_EMAILS.has(String(u.email).toLowerCase()),
    price: payments.price,
  };
}

function safePhoto(u) {
  try {
    const x = new URL(String(u));
    return x.protocol === 'https:' && x.hostname.endsWith('.googleusercontent.com') && x.href.length <= 300 ? x.href : '';
  } catch (e) {
    return '';
  }
}

function genUsername(base) {
  let b = String(base || 'user').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 12);
  if (b.length < 3) b = 'user';
  return b + crypto.randomInt(1000, 99999);
}

async function createProfile(decoded, input, birthDate) {
  const uid = decoded.uid;
  const email = String(decoded.email).toLowerCase();
  const displayName = clean(String(decoded.name || email.split('@')[0])).replace(/\s+/g, ' ').slice(0, 40) || 'Utilisateur';
  const photo = safePhoto(decoded.picture);
  const wanted = typeof input.username === 'string' ? input.username.trim().toLowerCase() : '';
  if (wanted && (!USERNAME_RE.test(wanted) || RESERVED.has(wanted))) fail(400, 'username_invalid');
  for (let i = 0; i < 6; i++) {
    const uname = wanted || genUsername(email.split('@')[0]);
    const uRef = db.collection('usernames').doc(uname);
    try {
      return await db.runTransaction(async (tx) => {
        const ps = await tx.get(userRef(uid));
        if (ps.exists) return false;
        const us = await tx.get(uRef);
        if (us.exists) throw new HttpError(409, 'username_taken');
        const now = Date.now();
        tx.create(userRef(uid), {
          email,
          displayName,
          username: uname,
          photo,
          plan: 'free',
          planExpiresAt: 0,
          createdAt: now,
          terms: { version: TERMS_VERSION, at: now },
          birthDate: birthDate || '',
          banned: false,
          unread: 0,
          quizCount: 0,
          usage: { month: '', received: 0 },
          blocked: [],
          lastUsernameChange: 0,
          provider: (decoded.firebase && decoded.firebase.sign_in_provider) || '',
        });
        tx.create(uRef, { uid, displayName, photo });
        return true;
      });
    } catch (e) {
      if (e instanceof HttpError && e.code === 'username_taken' && !wanted) continue;
      throw e;
    }
  }
  return fail(500, 'username_unavailable');
}

const limiter = (windowMs, limit, keyFn) =>
  rateLimit({
    windowMs,
    limit,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: keyFn || getIp,
    handler: (req, res) => res.status(429).json({ error: 'too_many_requests' }),
  });
const byUser = (windowMs, limit) => limiter(windowMs, limit, (req) => (req.user ? req.user.uid : getIp(req)));

const requireAuth = wrap(async (req, res, next) => {
  const c = readCookie(req, COOKIE);
  if (!c) fail(401, 'unauthenticated');
  let decoded;
  try {
    decoded = await auth.verifySessionCookie(c, false);
  } catch (e) {
    clearCookie(res);
    fail(401, 'unauthenticated');
  }
  const u = await getUser(decoded.uid);
  if (!u) {
    clearCookie(res);
    fail(401, 'unauthenticated');
  }
  if (u.banned) {
    clearCookie(res);
    fail(403, 'banned');
  }
  req.user = u;
  next();
});

const requireAdmin = [
  requireAuth,
  (req, res, next) =>
    ADMIN_EMAILS.has(String(req.user.email).toLowerCase()) ? next() : res.status(404).json({ error: 'not_found' }),
];

const pageCache = {};
function loadPage(name) {
  if (pageCache[name] === undefined) {
    try {
      pageCache[name] = fs.readFileSync(path.join(PUBLIC_DIR, name + '.html'), 'utf8');
    } catch (e) {
      pageCache[name] = null;
    }
  }
  return pageCache[name];
}

function injectMeta(html, m) {
  const alt = esc(m.title);
  const tags = [
    '<meta property="og:type" content="website">',
    '<meta property="og:site_name" content="Lisolo">',
    '<meta property="og:locale" content="fr_FR">',
    `<meta property="og:title" content="${esc(m.title)}">`,
    `<meta property="og:description" content="${esc(m.description)}">`,
    `<meta property="og:url" content="${esc(m.url)}">`,
    `<meta property="og:image" content="${esc(m.image)}">`,
    `<meta property="og:image:secure_url" content="${esc(m.image)}">`,
    '<meta property="og:image:type" content="image/png">',
    '<meta property="og:image:width" content="1200">',
    '<meta property="og:image:height" content="630">',
    `<meta property="og:image:alt" content="${alt}">`,
    '<meta name="twitter:card" content="summary_large_image">',
    `<meta name="twitter:title" content="${esc(m.title)}">`,
    `<meta name="twitter:description" content="${esc(m.description)}">`,
    `<meta name="twitter:image" content="${esc(m.image)}">`,
    `<meta name="twitter:image:alt" content="${alt}">`,
    `<meta name="description" content="${esc(m.description)}">`,
    `<link rel="canonical" href="${esc(m.url)}">`,
  ].join('\n');
  return html
    .replace(/<meta\s+(?:property|name)=["'](?:og:[^"']*|twitter:[^"']*|description)["'][^>]*>\s*/gi, '')
    .replace(/<title>[\s\S]*?<\/title>/i, () => `<title>${esc(m.title)}</title>`)
    .replace('</head>', () => `${tags}\n</head>`);
}

function sendPage(res, name, meta) {
  let html = loadPage(name);
  if (!html) return res.status(404).type('text').send('Page introuvable');
  const nonce = res.locals.nonce;
  if (meta) html = injectMeta(html, meta);
  html = html.replace(/<script(?![^>]*\snonce=)/gi, () => `<script nonce="${nonce}"`);
  res.set({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
  if (name === 'admin' || name === 'login') res.set('X-Robots-Tag', 'noindex, nofollow');
  return res.send(html);
}

const defaultMeta = (req) => ({
  title: 'Lisolo',
  description: 'Messages anonymes et quiz. Reçois la vérité, lance des quiz et amuse-toi.',
  image: baseUrl(req) + '/images/og-default.png',
  url: baseUrl(req) + (req.path === '/index' || req.path === '/index.html' ? '/' : req.path),
});

function parseQuestions(raw, max) {
  if (!Array.isArray(raw) || raw.length < 1 || raw.length > max) fail(400, 'questions_invalid');
  return raw.map((q) => {
    if (!q || typeof q !== 'object') fail(400, 'questions_invalid');
    const text = line(q.q, 3, 200, 'questions_invalid');
    if (!Array.isArray(q.options) || q.options.length < 2 || q.options.length > 4) fail(400, 'questions_invalid');
    const options = q.options.map((o) => line(o, 1, 100, 'questions_invalid'));
    const correct = Number.isInteger(q.correct) ? q.correct : -1;
    if (correct < 0 || correct >= options.length) fail(400, 'questions_invalid');
    return { q: text, options, correct };
  });
}

const idToken = (b) =>
  typeof b.idToken === 'string' && b.idToken.length > 100 && b.idToken.length < 4096 ? b.idToken : fail(400, 'bad_request');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

const payments = createPay({ app, db, userRef, userCache, adminCache, bump, requireAuth, limiter, byUser, wrap, fail, HttpError, baseUrl, body, ID_RE, DAY });

app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('hex');
  next();
});

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`, 'https://www.gstatic.com', 'https://apis.google.com'],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
        imgSrc: ["'self'", 'data:', 'blob:', 'https://*.googleusercontent.com'],
        connectSrc: ["'self'", 'https://*.googleapis.com', 'https://*.firebaseapp.com', 'https://www.gstatic.com'],
        frameSrc: ["'self'", 'https://*.firebaseapp.com', 'https://accounts.google.com', 'https://apis.google.com'],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        manifestSrc: ["'self'"],
        workerSrc: ["'self'"],
        ...(isProd ? { upgradeInsecureRequests: [] } : {}),
      },
    },
    crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    hsts: isProd ? undefined : false,
  })
);
app.use(compression());

app.get('/healthz', (req, res) => res.type('text').send('ok'));

payments.mountWebhook();

app.use('/api', limiter(60000, 300));
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    if (req.get('x-requested-with') !== 'lisolo' || !originOk(req)) return res.status(403).json({ error: 'forbidden' });
  }
  return next();
});
app.use('/api', express.json({ limit: '30kb', strict: true }));

app.get('/api/config', limiter(60000, 60), (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=300');
  res.json({
    firebase: {
      apiKey: process.env.FIREBASE_WEB_API_KEY || '',
      authDomain: process.env.FIREBASE_AUTH_DOMAIN || '',
      projectId: process.env.FIREBASE_PROJECT_ID || sa.project_id,
      appId: process.env.FIREBASE_APP_ID || '',
    },
    termsVersion: TERMS_VERSION,
    limits: LIMITS,
  });
});

app.post(
  '/api/auth/session',
  limiter(10 * 60000, 60),
  wrap(async (req, res) => {
    const b = body(req);
    let decoded;
    try {
      decoded = await auth.verifyIdToken(idToken(b));
    } catch (e) {
      if (e instanceof HttpError) throw e;
      fail(401, 'invalid_token');
    }
    if (Date.now() / 1000 - decoded.auth_time > 300) fail(401, 'recent_login_required');
    const provider = decoded.firebase && decoded.firebase.sign_in_provider;
    if (provider !== 'google.com' && provider !== 'password') fail(400, 'provider_not_allowed');
    if (!decoded.email || !decoded.email_verified) fail(403, 'email_not_verified');
    const accepted = b.acceptTerms === true;
    const snap = await userRef(decoded.uid).get();
    let isNew = false;
    if (!snap.exists) {
      if (!accepted) fail(409, 'terms_required');
      const birth = validateBirth(b.birthDate);
      if (birth.error) fail(400, birth.error);
      isNew = await createProfile(decoded, b, birth.iso);
      userCache.del(decoded.uid);
      if (isNew) bump('users');
    } else {
      const u = snap.data();
      if (u.banned) fail(403, 'banned');
      if (ageFromBirth(u.birthDate) === null) {
        const birth = validateBirth(b.birthDate);
        if (birth.error) fail(400, birth.error);
        await userRef(decoded.uid).update({ birthDate: birth.iso });
        userCache.del(decoded.uid);
      }
      if ((u.terms && u.terms.version) !== TERMS_VERSION) {
        if (!accepted) fail(409, 'terms_required');
        await userRef(decoded.uid).update({ terms: { version: TERMS_VERSION, at: Date.now() } });
        userCache.del(decoded.uid);
      }
    }
    const cookie = await auth.createSessionCookie(idToken(b), { expiresIn: SESSION_MS });
    res.cookie(COOKIE, cookie, { ...cookieOpts(), maxAge: SESSION_MS });
    res.json({ ok: true, isNew });
  })
);

app.post(
  '/api/auth/cancel',
  limiter(10 * 60000, 20),
  wrap(async (req, res) => {
    let decoded;
    try {
      decoded = await auth.verifyIdToken(idToken(body(req)));
    } catch (e) {
      if (e instanceof HttpError) throw e;
      fail(401, 'invalid_token');
    }
    const s = await userRef(decoded.uid).get();
    if (!s.exists) await auth.deleteUser(decoded.uid).catch(() => {});
    res.json({ ok: true });
  })
);

app.post('/api/auth/logout', (req, res) => {
  clearCookie(res);
  res.json({ ok: true });
});

app.get('/api/me', limiter(60000, 90), requireAuth, (req, res) => res.json(meView(req.user)));

app.patch(
  '/api/me',
  limiter(60000, 30),
  requireAuth,
  byUser(3600000, 20),
  wrap(async (req, res) => {
    const dn = line(body(req).displayName, 2, 40, 'display_name_invalid');
    const u = req.user;
    const batch = db.batch();
    batch.update(userRef(u.uid), { displayName: dn });
    batch.update(db.doc('usernames/' + u.username), { displayName: dn });
    await batch.commit();
    userCache.del(u.uid);
    profileCache.del(u.username);
    res.json({ ok: true });
  })
);

app.post(
  '/api/me/username',
  limiter(60000, 20),
  requireAuth,
  byUser(3600000, 6),
  wrap(async (req, res) => {
    const b = body(req);
    const next = typeof b.username === 'string' ? b.username.trim().toLowerCase() : '';
    if (!USERNAME_RE.test(next) || RESERVED.has(next)) fail(400, 'username_invalid');
    const old = req.user.username;
    if (next === old) fail(400, 'username_same');
    const uid = req.user.uid;
    await db.runTransaction(async (tx) => {
      const us = await tx.get(userRef(uid));
      const ns = await tx.get(db.doc('usernames/' + next));
      const u = us.data();
      if (Date.now() - (u.lastUsernameChange || 0) < 30 * DAY) throw new HttpError(429, 'username_cooldown');
      if (ns.exists) throw new HttpError(409, 'username_taken');
      tx.create(db.doc('usernames/' + next), { uid, displayName: u.displayName, photo: u.photo || '' });
      tx.delete(db.doc('usernames/' + old));
      tx.update(userRef(uid), { username: next, lastUsernameChange: Date.now() });
    });
    userCache.del(uid);
    profileCache.del(old);
    profileCache.del(next);
    res.json({ ok: true, username: next });
  })
);

app.delete(
  '/api/me',
  limiter(60000, 10),
  requireAuth,
  byUser(3600000, 3),
  wrap(async (req, res) => {
    if (body(req).confirm !== 'SUPPRIMER') fail(400, 'confirm_required');
    const u = req.user;
    const qs = await db.collection('quizzes').where('ownerUid', '==', u.uid).get();
    for (const d of qs.docs) {
      await db.recursiveDelete(d.ref);
      quizCache.del(d.id);
    }
    await db.recursiveDelete(userRef(u.uid));
    await db.doc('usernames/' + u.username).delete();
    await auth.deleteUser(u.uid).catch(() => {});
    userCache.del(u.uid);
    profileCache.del(u.username);
    clearCookie(res);
    res.json({ ok: true });
  })
);

app.get(
  '/api/public/u/:username',
  limiter(60000, 60),
  wrap(async (req, res) => {
    const p = await getPublicProfile(req.params.username);
    if (!p) fail(404, 'not_found');
    res.json({ username: p.username, displayName: p.displayName, photo: p.photo || '' });
  })
);

app.post(
  '/api/public/u/:username/messages',
  limiter(10 * 60000, 120),
  limiter(10 * 60000, 8, (req) => getIp(req) + '|' + String(req.params.username).toLowerCase().slice(0, 20)),
  wrap(async (req, res) => {
    const b = body(req);
    if (typeof b.hp === 'string' && b.hp.length) return res.json({ ok: true });
    const msg = txt(b.text, 2, 500, 'message_invalid');
    const p = await getPublicProfile(req.params.username);
    if (!p) fail(404, 'not_found');
    const fp = fingerprint(req);
    const ref = userRef(p.uid);
    const mref = ref.collection('messages').doc();
    const out = await db.runTransaction(async (tx) => {
      const s = await tx.get(ref);
      if (!s.exists) return 'gone';
      const u = s.data();
      if (u.banned) return 'gone';
      if (Array.isArray(u.blocked) && u.blocked.includes(fp)) return 'silent';
      const key = monthKey();
      const used = u.usage && u.usage.month === key ? u.usage.received : 0;
      const lim = limitsFor(u);
      if (lim.messagesPerMonth !== null && used >= lim.messagesPerMonth) return 'full';
      tx.set(mref, { text: msg, createdAt: Date.now(), from: fp });
      tx.update(ref, { usage: { month: key, received: used + 1 }, unread: FieldValue.increment(1) });
      return 'ok';
    });
    if (out === 'gone') fail(404, 'not_found');
    if (out === 'full') fail(403, 'inbox_full');
    if (out === 'ok') {
      userCache.del(p.uid);
      bump('messages');
    }
    return res.json({ ok: true });
  })
);

app.get(
  '/api/inbox',
  limiter(60000, 90),
  requireAuth,
  wrap(async (req, res) => {
    const u = req.user;
    const lim = limitsFor(u);
    const beforeRaw = Number(req.query.before);
    const before = Number.isFinite(beforeRaw) && beforeRaw > 0 ? beforeRaw : Date.now() + 1;
    const n = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 30);
    let q = userRef(u.uid).collection('messages').orderBy('createdAt', 'desc').where('createdAt', '<', before);
    if (lim.historyDays !== null) q = q.where('createdAt', '>=', Date.now() - lim.historyDays * DAY);
    const snap = await q.limit(n).get();
    const items = snap.docs.map((d) => ({ id: d.id, text: d.data().text, createdAt: d.data().createdAt }));
    res.json({
      items,
      next: snap.size === n ? items[items.length - 1].createdAt : null,
      historyDays: lim.historyDays,
      unread: u.unread || 0,
    });
  })
);

app.post(
  '/api/inbox/read',
  limiter(60000, 60),
  requireAuth,
  wrap(async (req, res) => {
    if ((req.user.unread || 0) > 0) {
      await userRef(req.user.uid).update({ unread: 0 });
      userCache.del(req.user.uid);
    }
    res.json({ ok: true });
  })
);

app.delete(
  '/api/messages/:id',
  limiter(60000, 60),
  requireAuth,
  byUser(60000, 40),
  wrap(async (req, res) => {
    if (!ID_RE.test(req.params.id)) fail(404, 'not_found');
    await userRef(req.user.uid).collection('messages').doc(req.params.id).delete();
    res.json({ ok: true });
  })
);

app.post(
  '/api/messages/:id/block',
  limiter(60000, 60),
  requireAuth,
  byUser(60000, 20),
  wrap(async (req, res) => {
    if (!ID_RE.test(req.params.id)) fail(404, 'not_found');
    const uid = req.user.uid;
    const mref = userRef(uid).collection('messages').doc(req.params.id);
    const s = await mref.get();
    if (!s.exists) fail(404, 'not_found');
    const fp = s.data().from;
    await db.runTransaction(async (tx) => {
      const us = await tx.get(userRef(uid));
      const list = us.data().blocked || [];
      if (list.includes(fp)) return;
      if (list.length >= 300) throw new HttpError(400, 'block_limit');
      tx.update(userRef(uid), { blocked: FieldValue.arrayUnion(fp) });
    });
    await mref.delete();
    userCache.del(uid);
    res.json({ ok: true });
  })
);

app.post(
  '/api/quizzes',
  limiter(60000, 30),
  requireAuth,
  byUser(3600000, 20),
  wrap(async (req, res) => {
    const b = body(req);
    const uid = req.user.uid;
    const title = line(b.title, 3, 80, 'title_invalid');
    const questions = parseQuestions(b.questions, limitsFor(req.user).questions);
    const qref = db.collection('quizzes').doc();
    await db.runTransaction(async (tx) => {
      const s = await tx.get(userRef(uid));
      const u = s.data();
      const l = limitsFor(u);
      if ((u.quizCount || 0) >= l.quizzes) throw new HttpError(403, 'quiz_limit');
      if (questions.length > l.questions) throw new HttpError(403, 'questions_limit');
      tx.create(qref, { ownerUid: uid, ownerName: u.displayName, title, questions, active: true, createdAt: Date.now(), answers: 0 });
      tx.update(userRef(uid), { quizCount: FieldValue.increment(1) });
    });
    userCache.del(uid);
    bump('quizzes');
    res.status(201).json({ id: qref.id });
  })
);

app.get(
  '/api/quizzes/mine',
  limiter(60000, 60),
  requireAuth,
  wrap(async (req, res) => {
    const snap = await db
      .collection('quizzes')
      .where('ownerUid', '==', req.user.uid)
      .where('active', '==', true)
      .limit(100)
      .get();
    const items = snap.docs
      .map((d) => {
        const x = d.data();
        return { id: d.id, title: x.title, answers: x.answers || 0, questions: x.questions.length, createdAt: x.createdAt };
      })
      .sort((a, b) => b.createdAt - a.createdAt);
    res.json({ items });
  })
);

app.delete(
  '/api/quizzes/:id',
  limiter(60000, 60),
  requireAuth,
  byUser(60000, 20),
  wrap(async (req, res) => {
    const id = req.params.id;
    if (!ID_RE.test(id)) fail(404, 'not_found');
    const uid = req.user.uid;
    const qref = db.collection('quizzes').doc(id);
    await db.runTransaction(async (tx) => {
      const s = await tx.get(qref);
      if (!s.exists || s.data().ownerUid !== uid) throw new HttpError(404, 'not_found');
      if (!s.data().active) return;
      tx.update(qref, { active: false });
      tx.update(userRef(uid), { quizCount: FieldValue.increment(-1) });
    });
    quizCache.del(id);
    userCache.del(uid);
    res.json({ ok: true });
  })
);

app.get(
  '/api/quizzes/:id/results',
  limiter(60000, 60),
  requireAuth,
  wrap(async (req, res) => {
    const id = req.params.id;
    if (!ID_RE.test(id)) fail(404, 'not_found');
    const qref = db.collection('quizzes').doc(id);
    const s = await qref.get();
    if (!s.exists || s.data().ownerUid !== req.user.uid) fail(404, 'not_found');
    const answers = s.data().answers || 0;
    if (!isPremium(req.user)) return res.json({ answers, locked: true, items: [], next: null });
    const beforeRaw = Number(req.query.before);
    const before = Number.isFinite(beforeRaw) && beforeRaw > 0 ? beforeRaw : Date.now() + 1;
    const n = 30;
    const snap = await qref.collection('results').orderBy('at', 'desc').where('at', '<', before).limit(n).get();
    const items = snap.docs.map((d) => ({ nickname: d.data().nickname, score: d.data().score, total: d.data().total, at: d.data().at }));
    return res.json({ answers, locked: false, items, next: snap.size === n ? items[items.length - 1].at : null });
  })
);

app.get(
  '/api/public/quizzes/:id',
  limiter(60000, 60),
  wrap(async (req, res) => {
    if (!ID_RE.test(req.params.id)) fail(404, 'not_found');
    const z = await getQuiz(req.params.id);
    if (!z || !z.active) fail(404, 'not_found');
    const owner = z.ownerUid ? await withTimeout(getUser(z.ownerUid), 900, null) : null;
    res.json({
      id: z.id,
      title: z.title,
      ownerName: (owner && owner.displayName) || z.ownerName,
      questions: z.questions.map((q) => ({ q: q.q, options: q.options })),
    });
  })
);

app.post(
  '/api/public/quizzes/:id/answers',
  limiter(10 * 60000, 120),
  limiter(10 * 60000, 4, (req) => getIp(req) + '|' + String(req.params.id).slice(0, 20)),
  wrap(async (req, res) => {
    const id = req.params.id;
    if (!ID_RE.test(id)) fail(404, 'not_found');
    const b = body(req);
    if (typeof b.hp === 'string' && b.hp.length) return res.json({ ok: true });
    const nick = line(b.nickname, 1, 24, 'nickname_invalid');
    const z = await getQuiz(id);
    if (!z || !z.active) fail(404, 'not_found');
    const n = z.questions.length;
    if (!Array.isArray(b.answers) || b.answers.length !== n) fail(400, 'answers_invalid');
    let score = 0;
    b.answers.forEach((a, i) => {
      if (!Number.isInteger(a) || a < 0 || a >= z.questions[i].options.length) fail(400, 'answers_invalid');
      if (a === z.questions[i].correct) score++;
    });
    const qref = db.collection('quizzes').doc(id);
    const rref = qref.collection('results').doc();
    const fp = fingerprint(req);
    const out = await db.runTransaction(async (tx) => {
      const qs = await tx.get(qref);
      if (!qs.exists || !qs.data().active) return 'gone';
      const owner = await tx.get(userRef(qs.data().ownerUid));
      if (!owner.exists || owner.data().banned) return 'gone';
      const lim = limitsFor(owner.data());
      if (lim.answersPerQuiz !== null && (qs.data().answers || 0) >= lim.answersPerQuiz) return 'full';
      tx.create(rref, { nickname: nick, score, total: n, at: Date.now(), from: fp });
      tx.update(qref, { answers: FieldValue.increment(1) });
      return 'ok';
    });
    if (out === 'gone') fail(404, 'not_found');
    if (out === 'full') fail(403, 'quiz_full');
    bump('answers');
    return res.json({ score, total: n, correct: z.questions.map((q) => q.correct) });
  })
);

payments.mountRoutes();

app.get(
  '/api/admin/stats',
  limiter(60000, 30),
  ...requireAdmin,
  wrap(async (req, res) => {
    const hit = adminCache.get('stats');
    if (hit) return res.json(hit);
    await flushStats();
    const days = [];
    for (let i = 13; i >= 0; i--) days.push(new Date(Date.now() + 3600000 - i * DAY).toISOString().slice(0, 10));
    const refs = [db.doc('stats/global'), ...days.map((d) => db.doc('stats/day_' + d))];
    const [snaps, prem] = await Promise.all([
      db.getAll(...refs),
      db.collection('users').where('planExpiresAt', '>', Date.now()).count().get(),
    ]);
    const pick = (x) => ({
      users: x.users || 0,
      messages: x.messages || 0,
      quizzes: x.quizzes || 0,
      answers: x.answers || 0,
      revenue: x.revenue || 0,
    });
    const out = {
      totals: pick(snaps[0].exists ? snaps[0].data() : {}),
      premiumActive: prem.data().count,
      currency: payments.price.currency,
      daily: days.map((d, i) => ({ date: d, ...pick(snaps[i + 1].exists ? snaps[i + 1].data() : {}) })),
      generatedAt: Date.now(),
    };
    adminCache.set('stats', out);
    return res.json(out);
  })
);

const AGE_BUCKETS = [
  { label: '13–17 ans', min: 13, max: 17 },
  { label: '18–24 ans', min: 18, max: 24 },
  { label: '25–34 ans', min: 25, max: 34 },
  { label: '35–44 ans', min: 35, max: 44 },
  { label: '45–54 ans', min: 45, max: 54 },
  { label: '55 ans et +', min: 55, max: MAX_AGE },
];

async function collectAges() {
  const list = [];
  let missing = 0;
  let last = null;
  let truncated = false;
  for (let page = 0; page < 40; page++) {
    let q = db
      .collection('users')
      .orderBy(admin.firestore.FieldPath.documentId())
      .limit(500);
    if (last) q = q.startAfter(last);
    const snap = await q.get();
    snap.docs.forEach((d) => {
      const age = ageFromBirth(d.data().birthDate);
      if (age === null) missing += 1;
      else list.push(age);
    });
    if (snap.size < 500) break;
    last = snap.docs[snap.docs.length - 1];
    if (page === 39) truncated = true;
  }
  const known = list.length;
  const sum = list.reduce((a, b) => a + b, 0);
  const sorted = list.slice().sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  const median = known ? (known % 2 ? sorted[mid] : Math.round(((sorted[mid - 1] + sorted[mid]) / 2) * 10) / 10) : 0;
  const counts = new Map();
  for (const age of list) counts.set(age, (counts.get(age) || 0) + 1);
  return {
    total: known + missing,
    known,
    missing,
    average: known ? Math.round((sum / known) * 10) / 10 : 0,
    median,
    minors: list.filter((a) => a < 18).length,
    buckets: AGE_BUCKETS.map((b) => ({
      label: b.label,
      min: b.min,
      max: b.max,
      count: list.filter((a) => a >= b.min && a <= b.max).length,
    })),
    ages: [...counts.entries()].sort((a, b) => a[0] - b[0]).map(([age, count]) => ({ age, count })),
    truncated,
    generatedAt: Date.now(),
  };
}

app.get(
  '/api/admin/ages',
  limiter(60000, 20),
  ...requireAdmin,
  wrap(async (req, res) => {
    const hit = ageCache.get('ages');
    if (hit) return res.json(hit);
    return res.json(ageCache.set('ages', await collectAges()));
  })
);

app.get(
  '/api/admin/users',
  limiter(60000, 60),
  ...requireAdmin,
  wrap(async (req, res) => {
    const email = typeof req.query.email === 'string' ? req.query.email.trim().toLowerCase().slice(0, 254) : '';
    let q = db.collection('users');
    if (email) {
      q = q.where('email', '==', email).limit(5);
    } else {
      const beforeRaw = Number(req.query.before);
      const before = Number.isFinite(beforeRaw) && beforeRaw > 0 ? beforeRaw : Date.now() + 1;
      q = q.orderBy('createdAt', 'desc').where('createdAt', '<', before).limit(20);
    }
    const snap = await q.get();
    const items = snap.docs.map((d) => {
      const x = d.data();
      return {
        uid: d.id,
        email: x.email,
        displayName: x.displayName,
        username: x.username,
        age: ageFromBirth(x.birthDate),
        plan: isPremium(x) ? 'premium' : 'free',
        planExpiresAt: x.planExpiresAt || 0,
        createdAt: x.createdAt,
        banned: !!x.banned,
      };
    });
    res.json({ items, next: !email && snap.size === 20 ? items[items.length - 1].createdAt : null });
  })
);

app.post(
  '/api/admin/users/:uid/plan',
  limiter(60000, 30),
  ...requireAdmin,
  wrap(async (req, res) => {
    const target = req.params.uid;
    if (!UID_RE.test(target)) fail(400, 'bad_request');
    const days = Number(body(req).days);
    if (!Number.isInteger(days) || days < 0 || days > 3650) fail(400, 'days_invalid');
    await db.runTransaction(async (tx) => {
      const s = await tx.get(userRef(target));
      if (!s.exists) throw new HttpError(404, 'not_found');
      const cur = Number(s.data().planExpiresAt || 0);
      const exp = days === 0 ? 0 : Math.max(Date.now(), cur) + days * DAY;
      tx.update(userRef(target), { plan: days === 0 ? 'free' : 'premium', planExpiresAt: exp });
    });
    userCache.del(target);
    adminCache.del('stats');
    res.json({ ok: true });
  })
);

app.post(
  '/api/admin/users/:uid/ban',
  limiter(60000, 30),
  ...requireAdmin,
  wrap(async (req, res) => {
    const target = req.params.uid;
    if (!UID_RE.test(target)) fail(400, 'bad_request');
    if (target === req.user.uid) fail(400, 'self_ban');
    const banned = body(req).banned === true;
    const s = await userRef(target).get();
    if (!s.exists) fail(404, 'not_found');
    await userRef(target).update({ banned });
    await auth.updateUser(target, { disabled: banned }).catch((e) => console.error('[ban]', e.message));
    if (banned) await auth.revokeRefreshTokens(target).catch(() => {});
    userCache.del(target);
    res.json({ ok: true });
  })
);

app.use('/api', (req, res) => res.status(404).json({ error: 'not_found' }));

for (const name of ['index', 'login', 'app', 'admin', 'legal']) {
  const paths = name === 'index' ? ['/', '/index', '/index.html'] : ['/' + name, '/' + name + '.html'];
  app.get(paths, (req, res) => sendPage(res, name, name === 'index' || name === 'app' ? defaultMeta(req) : null));
}

app.get(
  '/u/:username',
  limiter(60000, 60),
  wrap(async (req, res) => {
    const p = await withTimeout(getPublicProfile(req.params.username), 1500, null);
    const b = baseUrl(req);
    const meta = p
      ? {
          title: `Envoie un message anonyme à ${p.displayName}`,
          description: `${p.displayName} sur Lisolo. Dis ce que tu penses vraiment, personne ne saura que c'est toi.`,
          image: b + '/images/og-message.png',
          url: `${b}/u/${p.username}`,
        }
      : { ...defaultMeta(req), url: `${b}/u/${encodeURIComponent(String(req.params.username).slice(0, 32))}` };
    sendPage(res, 'app', meta);
  })
);

app.get(
  '/q/:id',
  limiter(60000, 60),
  wrap(async (req, res) => {
    const z = ID_RE.test(req.params.id) ? await withTimeout(getQuiz(req.params.id), 1500, null) : null;
    const owner = z && z.active && z.ownerUid ? await withTimeout(getUser(z.ownerUid), 900, null) : null;
    const ownerName = (owner && owner.displayName) || (z && z.ownerName) || '';
    const b = baseUrl(req);
    const meta =
      z && z.active
        ? {
            title: ownerName ? `Quiz de ${ownerName} : ${z.title}` : `Réponds au quiz « ${z.title} »`,
            description: ownerName
              ? `${ownerName} te défie : « ${z.title} ». Tu me connais vraiment ? Teste-toi sur Lisolo.`
              : `${z.title}. Tu me connais vraiment ? Teste-toi sur Lisolo.`,
            image: b + '/images/og-quiz.png',
            url: `${b}/q/${z.id}`,
          }
        : { ...defaultMeta(req), url: `${b}/q/${encodeURIComponent(String(req.params.id).slice(0, 64))}` };
    sendPage(res, 'app', meta);
  })
);

app.use((req, res, next) => (/\.html?$/i.test(req.path) ? res.status(404).type('text').send('Page introuvable') : next()));

app.use(
  express.static(PUBLIC_DIR, {
    index: false,
    dotfiles: 'ignore',
    maxAge: '1d',
    setHeaders(res, p) {
      if (/(sw\.js|manifest\.json)$/i.test(p)) res.setHeader('Cache-Control', 'no-cache');
    },
  })
);

app.use((req, res) => res.status(404).type('text').send('Page introuvable'));

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.code });
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'too_large' });
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'bad_json' });
  console.error('[error]', req.method, req.path, err && err.message);
  return res.status(500).json({ error: 'server_error' });
});

const server = app.listen(PORT, '0.0.0.0', () => console.log('[lisolo] port ' + PORT));
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;

async function shutdown() {
  setTimeout(() => process.exit(0), 8000).unref();
  await flushStats();
  server.close(() => process.exit(0));
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
process.on('unhandledRejection', (e) => console.error('[unhandled]', e && e.message));
