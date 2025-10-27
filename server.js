// server.js
// Replaces your existing server.js with more logging, CORS for socket.io, and a debug endpoint.

const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const sqlite3 = require('sqlite3').verbose();
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const crypto = require('crypto');
const cors = require('cors');
const nodemailer = require('nodemailer');
const validator = require('validator');
const { parseStringPromise } = require('xml2js');

const LIST_URL = process.env.LIST_URL || 'https://learn.microsoft.com/en-us/certifications/';
const SITEMAP_URL = process.env.SITEMAP_URL || 'https://learn.microsoft.com/sitemap.xml';
const POLL_INTERVAL_MS = parseInt(process.env.POLL_INTERVAL_MS || '60000', 10);
const PORT = parseInt(process.env.PORT || '3000', 10);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// SMTP (optional)
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587', 10);
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const EMAIL_FROM = process.env.EMAIL_FROM || 'no-reply@example.com';

const CONFIRMATION_TTL_HOURS = parseInt(process.env.CONFIRMATION_TTL_HOURS || '48', 10);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);

// IMPORTANT: enable CORS for socket.io so client can connect when proxied/hosted
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// SQLite DB
const db = new sqlite3.Database(path.join(__dirname, 'data.db'));

// Promisified DB helpers
function runAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) { if (err) return reject(err); resolve(this); });
  });
}
function allAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => { if (err) return reject(err); resolve(rows || []); });
  });
}
function getAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => { if (err) return reject(err); resolve(row || null); });
  });
}

// Ensure minimal schema
async function ensureSchema() {
  await runAsync(`
    CREATE TABLE IF NOT EXISTS credentials (
      id TEXT PRIMARY KEY,
      title TEXT,
      url TEXT,
      type TEXT,
      first_seen_at TEXT
    )
  `);
  await runAsync(`
    CREATE TABLE IF NOT EXISTS subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT,
      types TEXT,
      confirmed INTEGER DEFAULT 0,
      confirmation_token TEXT,
      unsubscribe_token TEXT,
      created_at TEXT,
      confirmation_sent_at TEXT,
      confirmed_at TEXT,
      unsubscribed_at TEXT
    )
  `);
  await runAsync(`
    CREATE TABLE IF NOT EXISTS meta (
      k TEXT PRIMARY KEY,
      v TEXT
    )
  `);
}
ensureSchema().catch(err => { console.error('DB init error', err); process.exit(1); });

// meta helpers
async function metaSet(k, v) { await runAsync('INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)', [k, String(v)]); }
async function metaGet(k) { const row = await getAsync('SELECT v FROM meta WHERE k = ?', [k]); return row ? row.v : null; }

// utils
function idForUrl(url) { return crypto.createHash('md5').update(url).digest('hex'); }
async function fetchHtml(url) {
  const res = await axios.get(url, { headers: { 'User-Agent': 'ms-credentials-dashboard/1.0' }, timeout: 15000 });
  return res.data;
}
function classifyItem(title = '', url = '') {
  const t = title.toLowerCase();
  const u = url.toLowerCase();
  if (u.includes('/exams/') || t.includes('exam')) return 'exam';
  if (u.includes('/skills/') || t.includes('skill')) return 'skill';
  return 'certification';
}
function extractCredentialsFromHtml(html, baseUrl) {
  const $ = cheerio.load(html);
  const found = new Map();
  $('a[href]').each((i, el) => {
    let href = $(el).attr('href');
    let text = $(el).text().trim() || $(el).attr('aria-label') || $(el).attr('title') || '';
    if (!href || !text) return;
    const lowText = text.toLowerCase();
    if (href.includes('/certifications/') || href.includes('/exams/') || href.includes('/skills/') || lowText.includes('cert') || lowText.includes('exam') || lowText.includes('skill')) {
      let url = href;
      try {
        if (url.startsWith('/')) {
          const parsed = new URL(baseUrl);
          url = `${parsed.protocol}//${parsed.host}${url}`;
        } else if (!url.startsWith('http')) {
          url = new URL(url, baseUrl).toString();
        }
      } catch (e) {}
      if (!found.has(url)) {
        found.set(url, { title: text, url, type: classifyItem(text, url) });
      }
    }
  });
  return Array.from(found.values());
}

// lightweight sitemap fallback
async function extractFromSitemap(limit = 100) {
  try {
    const res = await axios.get(SITEMAP_URL, { headers: { 'User-Agent': 'ms-credentials-dashboard/1.0' }, timeout: 15000 });
    const xml = res.data;
    const obj = await parseStringPromise(xml);
    const urls = [];
    if (obj.urlset && obj.urlset.url) {
      for (const u of obj.urlset.url) if (u.loc && u.loc[0]) urls.push(u.loc[0]);
    } else if (obj.sitemapindex && obj.sitemapindex.sitemap) {
      for (const s of obj.sitemapindex.sitemap) if (s.loc && s.loc[0]) urls.push(s.loc[0]);
    }
    const candidates = urls.filter(u => /certif|certifications|exam|exams|skills?/.test(u)).slice(0, limit);
    const found = [];
    for (const u of candidates) {
      try {
        const html = await axios.get(u, { headers: { 'User-Agent': 'ms-credentials-dashboard/1.0' }, timeout: 15000 }).then(r => r.data);
        const $ = cheerio.load(html);
        const title = $('h1').first().text().trim() || $('title').first().text().trim() || u;
        found.push({ title, url: u, type: classifyItem(title, u) });
      } catch (e) { /* ignore individual fetch errors */ }
    }
    return found;
  } catch (e) {
    console.warn('Sitemap fallback error', e.message || e);
    return [];
  }
}

// DB credential ops
async function dbGetAllCredentials() { return await allAsync('SELECT id, title, url, type, first_seen_at FROM credentials ORDER BY first_seen_at DESC'); }
async function dbInsertCredential(id, title, url, type) { const now = new Date().toISOString(); await runAsync('INSERT INTO credentials (id, title, url, type, first_seen_at) VALUES (?, ?, ?, ?, ?)', [id, title, url, type, now]); return { id, title, url, type, first_seen_at: now }; }

// subscription DB helpers (kept similar)
async function dbAddSubscription(email, typesCsv) {
  const now = new Date().toISOString();
  const confirmationToken = crypto.randomBytes(20).toString('hex');
  const unsubscribeToken = crypto.randomBytes(20).toString('hex');
  await runAsync('INSERT INTO subscriptions (email, types, confirmed, confirmation_token, unsubscribe_token, created_at, confirmation_sent_at) VALUES (?, ?, 0, ?, ?, ?, ?)', [email, typesCsv, confirmationToken, unsubscribeToken, now, now]);
  return await getAsync('SELECT id, email, types, confirmation_token, unsubscribe_token, created_at FROM subscriptions WHERE id = last_insert_rowid()');
}
async function dbFindSubscriptionByEmail(email) { return await getAsync('SELECT * FROM subscriptions WHERE email = ? ORDER BY id DESC LIMIT 1', [email]); }
async function dbSetConfirmationToken(id, token) { const now = new Date().toISOString(); await runAsync('UPDATE subscriptions SET confirmation_token = ?, confirmation_sent_at = ?, created_at = ? WHERE id = ?', [token, now, now, id]); }
async function dbConfirmSubscription(token) {
  const now = new Date().toISOString();
  const row = await getAsync('SELECT id, email, confirmed, confirmation_sent_at, created_at FROM subscriptions WHERE confirmation_token = ?', [token]);
  if (!row) return null;
  if (row.confirmed) return { already: true, id: row.id, email: row.email };
  if (!row.confirmation_sent_at && row.created_at && ((Date.now() - new Date(row.created_at).getTime()) > CONFIRMATION_TTL_HOURS * 3600 * 1000)) return { expired: true, id: row.id, email: row.email };
  await runAsync('UPDATE subscriptions SET confirmed = 1, confirmed_at = ? WHERE id = ?', [now, row.id]);
  return { id: row.id, email: row.email, confirmed_at: now };
}
async function dbUnsubscribe(token) {
  const now = new Date().toISOString();
  const row = await getAsync('SELECT id, email, unsubscribed_at FROM subscriptions WHERE unsubscribe_token = ?', [token]);
  if (!row) return null;
  if (row.unsubscribed_at) return { already: true, id: row.id, email: row.email };
  await runAsync('UPDATE subscriptions SET unsubscribed_at = ? WHERE id = ?', [now, row.id]);
  return { id: row.id, email: row.email, unsubscribed_at: now };
}
async function dbUnsubscribeByEmail(email) {
  const row = await getAsync('SELECT id, email, unsubscribe_token, unsubscribed_at, confirmed FROM subscriptions WHERE email = ? ORDER BY id DESC LIMIT 1', [email]);
  if (!row) return null;
  if (!row.confirmed) return { not_confirmed: true, id: row.id, email: row.email };
  if (row.unsubscribed_at) return { already: true, id: row.id, email: row.email };
  return row;
}
async function dbGetSubscribersForType(itemType) {
  const rows = await allAsync('SELECT email, unsubscribe_token FROM subscriptions WHERE confirmed = 1 AND (unsubscribed_at IS NULL) AND types LIKE ?', [`%${itemType}%`]);
  return (rows || []).map(r => ({ email: r.email, unsubscribe_token: r.unsubscribe_token }));
}

// basic email send (best-effort)
async function sendEmail(to, subject, text, html) {
  if (!SMTP_HOST || !SMTP_USER) { console.warn('SMTP not configured, skipping email to', to); return; }
  const transporter = nodemailer.createTransport({ host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_PORT === 465, auth: { user: SMTP_USER, pass: SMTP_PASS } });
  await transporter.sendMail({ from: EMAIL_FROM, to, subject, text, html });
}
async function sendConfirmationEmail(email, confirmationToken) {
  const confirmLink = `${BASE_URL.replace(/\/$/, '')}/confirm?token=${confirmationToken}`;
  await sendEmail(email, 'Confirm your subscription', `Confirm: ${confirmLink}`, `<a href="${confirmLink}">Confirm</a>`).catch(e => console.error('sendConfirmationEmail error', e && e.message ? e.message : e));
}
async function sendUnsubscribeEmail(email, unsubscribeToken) {
  const link = `${BASE_URL.replace(/\/$/, '')}/unsubscribe?token=${unsubscribeToken}`;
  await sendEmail(email, 'Unsubscribe', `Unsubscribe: ${link}`, `<a href="${link}">Unsubscribe</a>`).catch(e => console.error('sendUnsubscribeEmail error', e && e.message ? e.message : e));
}

// notify subscribers
async function notifySubscribers(newItem) {
  try {
    const subs = await dbGetSubscribersForType(newItem.type);
    if (!subs || subs.length === 0) return;
    const subject = `New ${newItem.type} added: ${newItem.title}`;
    for (const s of subs) {
      const unsubscribeLink = `${BASE_URL.replace(/\/$/, '')}/unsubscribe?token=${s.unsubscribe_token}`;
      const text = `${newItem.title}\n\n${newItem.url}\n\nDiscovered: ${newItem.first_seen_at}\n\nUnsubscribe: ${unsubscribeLink}`;
      const html = `<p><a href="${newItem.url}">${newItem.title}</a></p><p><a href="${unsubscribeLink}">Unsubscribe</a></p>`;
      try { await sendEmail(s.email, subject, text, html); } catch (e) { console.error('Error sending email to', s.email, e && e.message ? e.message : e); }
    }
  } catch (e) { console.error('Error in notifySubscribers:', e && e.message ? e.message : e); }
}

// main scraper / updater
async function checkForUpdates() {
  console.log('Scrape start', new Date().toISOString());
  await metaSet('last_scrape_started', new Date().toISOString());
  try {
    let html = null;
    try { html = await fetchHtml(LIST_URL); } catch (e) { console.warn('Primary LIST_URL fetch failed:', e.message || e); }
    let items = [];
    if (html) {
      items = extractCredentialsFromHtml(html, LIST_URL);
      console.log('Primary extraction found', items.length);
    }
    if (!items || items.length === 0) {
      console.log('Falling back to sitemap extraction');
      items = await extractFromSitemap(200);
      console.log('Sitemap extraction found', items.length);
    }
    let newCount = 0;
    for (const cred of items) {
      const id = idForUrl(cred.url);
      const exists = await getAsync('SELECT 1 FROM credentials WHERE id = ?', [id]);
      if (!exists) {
        const inserted = await dbInsertCredential(id, cred.title, cred.url, cred.type);
        newCount++;
        console.log('New credential:', inserted.title, inserted.url, inserted.type);
        io.emit('new-credential', inserted);
        notifySubscribers(inserted).catch(err => console.error('notify error', err));
      }
    }
    await metaSet('last_scrape', new Date().toISOString());
    await metaSet('last_scrape_new_count', newCount);
    await metaSet('last_scrape_error', '');
    console.log('Scrape finished, new items:', newCount);
  } catch (err) {
    console.error('Error checking updates:', err && err.message ? err.message : err);
    await metaSet('last_scrape_error', String(err && err.message ? err.message : err));
  }
}

// API: credentials and status
app.get('/api/credentials', async (req, res) => {
  try {
    const type = req.query.type;
    if (type) {
      const rows = await allAsync('SELECT id, title, url, type, first_seen_at FROM credentials WHERE type = ? ORDER BY first_seen_at DESC', [type]);
      return res.json({ data: rows });
    }
    const rows = await dbGetAllCredentials();
    res.json({ data: rows });
  } catch (err) {
    console.error('GET /api/credentials error', err && err.message ? err.message : err);
    res.status(500).json({ error: String(err && err.message ? err.message : err) });
  }
});

// Debug endpoint: fetch LIST_URL and return a few items or error (safe to call)
app.get('/api/debug-fetch', async (req, res) => {
  try {
    const info = { list_url: LIST_URL, sitemap_url: SITEMAP_URL, time: new Date().toISOString() };
    let html = null;
    try { html = await fetchHtml(LIST_URL); info.fetched = true; } catch (e) { info.fetch_error = String(e && e.message ? e.message : e); }
    if (html) {
      const items = extractCredentialsFromHtml(html, LIST_URL);
      info.items_found = items.length;
      info.sample = items.slice(0, 10);
    } else {
      const sitemapItems = await extractFromSitemap(100);
      info.sitemap_found = sitemapItems.length;
      info.sample = sitemapItems.slice(0, 10);
    }
    res.json(info);
  } catch (e) {
    console.error('/api/debug-fetch error', e);
    res.status(500).json({ error: String(e && e.message ? e.message : e) });
  }
});

app.get('/api/status', async (req, res) => {
  try {
    const lastScrape = await metaGet('last_scrape') || null;
    const lastScrapeStarted = await metaGet('last_scrape_started') || null;
    const lastError = await metaGet('last_scrape_error') || null;
    const newCount = await metaGet('last_scrape_new_count') || '0';
    const countRow = await getAsync('SELECT COUNT(*) AS c FROM credentials');
    const total = (countRow && countRow.c) ? countRow.c : 0;
    res.json({ last_scrape: lastScrape, last_scrape_started: lastScrapeStarted, last_error: lastError, last_new_count: newCount, total });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// subscription endpoints (kept)
app.post('/api/subscribe', async (req, res) => {
  try {
    const { email, types } = req.body || {};
    if (!email || !validator.isEmail(email)) return res.status(400).json({ error: 'Invalid or missing email' });
    if (!Array.isArray(types) || types.length === 0) return res.status(400).json({ error: 'Missing types' });
    const clean = types.map(t => t.trim().toLowerCase()).filter(t => ['certification','exam','skill'].includes(t));
    if (clean.length === 0) return res.status(400).json({ error: 'Invalid types' });
    const typesCsv = Array.from(new Set(clean)).join(',');
    const inserted = await dbAddSubscription(email, typesCsv);
    if (inserted && inserted.confirmation_token) await sendConfirmationEmail(email, inserted.confirmation_token);
    res.json({ success: true, message: 'Subscription created. Check your email to confirm.' });
  } catch (e) {
    console.error('/api/subscribe error', e);
    res.status(500).json({ error: String(e) });
  }
});

app.post('/api/resend-confirmation', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email || !validator.isEmail(email)) return res.status(400).json({ error: 'Invalid or missing email' });
    const sub = await dbFindSubscriptionByEmail(email);
    if (!sub) return res.status(404).json({ error: 'No subscription found' });
    if (sub.unsubscribed_at) return res.status(400).json({ error: 'Unsubscribed' });
    if (sub.confirmed) return res.status(400).json({ error: 'Already confirmed' });
    const newToken = crypto.randomBytes(20).toString('hex');
    await dbSetConfirmationToken(sub.id, newToken);
    await sendConfirmationEmail(email, newToken);
    res.json({ success: true, message: 'Confirmation resent' });
  } catch (e) { console.error('/api/resend-confirmation error', e); res.status(500).json({ error: String(e) }); }
});

app.post('/api/request-unsubscribe', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email || !validator.isEmail(email)) return res.status(400).json({ error: 'Invalid or missing email' });
    const sub = await dbUnsubscribeByEmail(email);
    if (!sub) return res.status(404).json({ error: 'No subscription found' });
    if (sub.not_confirmed) return res.status(400).json({ error: 'Not confirmed' });
    if (sub.already) return res.status(400).json({ error: 'Already unsubscribed' });
    await sendUnsubscribeEmail(email, sub.unsubscribe_token);
    res.json({ success: true, message: 'Unsubscribe email sent' });
  } catch (e) { console.error('/api/request-unsubscribe error', e); res.status(500).json({ error: String(e) }); }
});

app.get('/confirm', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.redirect('/confirm.html?status=missing');
  try {
    const result = await dbConfirmSubscription(token);
    if (!result) return res.redirect('/confirm.html?status=invalid');
    if (result.expired) return res.redirect('/confirm.html?status=expired');
    if (result.already) return res.redirect('/confirm.html?status=already');
    return res.redirect('/confirm.html?status=success');
  } catch (e) { console.error('Confirm error', e); return res.redirect('/confirm.html?status=error'); }
});

app.get('/unsubscribe', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.redirect('/unsubscribe.html?status=missing');
  try {
    const result = await dbUnsubscribe(token);
    if (!result) return res.redirect('/unsubscribe.html?status=invalid');
    if (result.already) return res.redirect('/unsubscribe.html?status=already');
    return res.redirect('/unsubscribe.html?status=success');
  } catch (e) { console.error('Unsubscribe error', e); return res.redirect('/unsubscribe.html?status=error'); }
});

// admin listing
app.get('/api/admin/subscriptions', async (req, res) => {
  try {
    const token = req.header('x-admin-token') || req.query.admin_token;
    if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
    const rows = await allAsync('SELECT id, email, types, confirmed, created_at, confirmed_at, confirmation_sent_at, unsubscribed_at FROM subscriptions ORDER BY created_at DESC');
    res.json({ data: rows });
  } catch (e) { console.error('/api/admin/subscriptions error', e); res.status(500).json({ error: String(e) }); }
});

io.on('connection', (socket) => {
  console.log('Socket connected', socket.id);
  socket.on('disconnect', (reason) => { console.log('Socket disconnected', socket.id, reason); });
});

// Start
server.listen(PORT, async () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`LIST_URL=${LIST_URL}  SITEMAP_URL=${SITEMAP_URL}`);
  await checkForUpdates();
  setInterval(checkForUpdates, POLL_INTERVAL_MS);
});
