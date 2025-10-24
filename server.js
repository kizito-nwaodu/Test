
// server.js
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

const LIST_URL = process.env.LIST_URL || 'https://learn.microsoft.com/en-us/certifications/';
const POLL_INTERVAL_MS = parseInt(process.env.POLL_INTERVAL_MS || '60000', 10); // default 60s
const PORT = parseInt(process.env.PORT || '3000', 10);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// SMTP settings
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587', 10);
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const EMAIL_FROM = process.env.EMAIL_FROM || 'no-reply@example.com';

// Confirmation token TTL in hours (default 48)
const CONFIRMATION_TTL_HOURS = parseInt(process.env.CONFIRMATION_TTL_HOURS || '48', 10);

// Admin token to protect admin endpoints (set a random long value in env for production)
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);
const io = new Server(server);

// Simple SQLite DB (file: data.db)
const db = new sqlite3.Database(path.join(__dirname, 'data.db'));

function runAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function allAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

function getAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

async function ensureSchema() {
  // Basic tables
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
      confirmed_at TEXT,
      unsubscribed_at TEXT
    )
  `);

  // Add confirmation_sent_at column if missing
  const cols = await allAsync(`PRAGMA table_info('subscriptions')`);
  const colNames = cols.map(c => c.name);
  if (!colNames.includes('confirmation_sent_at')) {
    await runAsync(`ALTER TABLE subscriptions ADD COLUMN confirmation_sent_at TEXT`);
  }
  // Add other columns if needed (future-proof)
}

ensureSchema().catch(err => {
  console.error('Error ensuring DB schema:', err);
  process.exit(1);
});

function idForUrl(url) {
  return crypto.createHash('md5').update(url).digest('hex');
}

async function fetchHtml(url) {
  const res = await axios.get(url, {
    headers: {
      'User-Agent': 'ms-credentials-dashboard/1.0 (+https://example.com)'
    },
    timeout: 15000
  });
  return res.data;
}

function classifyItem(title, url) {
  const t = (title || '').toLowerCase();
  const u = (url || '').toLowerCase();
  if (u.includes('/exams/') || t.includes('exam') || t.match(/\bms-\w*-exam\b/)) {
    return 'exam';
  }
  if (u.includes('/skills/') || t.includes('skill') || t.includes('skills') || t.includes('applied skill')) {
    return 'skill';
  }
  return 'certification';
}

function extractCredentials(html, baseUrl) {
  const $ = cheerio.load(html);
  const found = new Map();

  $('a[href]').each((i, el) => {
    const href = $(el).attr('href');
    const text = $(el).text().trim();
    if (!href || !text) return;

    if (
      href.includes('/certifications/') ||
      href.includes('/certification/') ||
      href.includes('/exams/') ||
      href.includes('/skills/') ||
      text.toLowerCase().includes('cert') ||
      text.toLowerCase().includes('exam') ||
      text.toLowerCase().includes('skill')
    ) {
      let url = href;
      if (url.startsWith('/')) {
        try {
          const parsed = new URL(baseUrl);
          url = `${parsed.protocol}//${parsed.host}${url}`;
        } catch (e) {}
      } else if (url.startsWith('./') || url.startsWith('../')) {
        try {
          url = new URL(url, baseUrl).toString();
        } catch (e) {}
      }
      if (!found.has(url)) {
        const type = classifyItem(text, url);
        found.set(url, { title: text, url, type });
      }
    }
  });

  return Array.from(found.values());
}

async function dbGetAllCredentials() {
  return await allAsync('SELECT id, title, url, type, first_seen_at FROM credentials ORDER BY first_seen_at DESC');
}

async function dbInsertCredential(id, title, url, type) {
  const now = new Date().toISOString();
  await runAsync('INSERT INTO credentials (id, title, url, type, first_seen_at) VALUES (?, ?, ?, ?, ?)', [id, title, url, type, now]);
  return { id, title, url, type, first_seen_at: now };
}

async function dbAddSubscription(email, typesCsv) {
  const now = new Date().toISOString();
  const confirmationToken = crypto.randomBytes(20).toString('hex');
  const unsubscribeToken = crypto.randomBytes(20).toString('hex');
  await runAsync(
    'INSERT INTO subscriptions (email, types, confirmed, confirmation_token, unsubscribe_token, created_at, confirmation_sent_at) VALUES (?, ?, 0, ?, ?, ?, ?)',
    [email, typesCsv, confirmationToken, unsubscribeToken, now, now]
  );
  const row = await getAsync('SELECT id, email, types, confirmation_token, unsubscribe_token, created_at FROM subscriptions WHERE id = last_insert_rowid()');
  return row;
}

async function dbFindSubscriptionByEmail(email) {
  return await getAsync('SELECT * FROM subscriptions WHERE email = ? ORDER BY id DESC LIMIT 1', [email]);
}

async function dbSetConfirmationToken(id, token) {
  const now = new Date().toISOString();
  await runAsync('UPDATE subscriptions SET confirmation_token = ?, confirmation_sent_at = ?, created_at = ? WHERE id = ?', [token, now, now, id]);
}

async function dbConfirmSubscription(token) {
  const now = new Date().toISOString();
  const row = await getAsync('SELECT id, email, confirmed, confirmation_sent_at FROM subscriptions WHERE confirmation_token = ?', [token]);
  if (!row) return null;
  // Check if already confirmed
  if (row.confirmed) return { already: true, id: row.id, email: row.email };
  // Check TTL
  if (isTokenExpired(row.confirmation_sent_at || row.created_at, CONFIRMATION_TTL_HOURS)) {
    return { expired: true, id: row.id, email: row.email };
  }
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
  // find latest confirmed active subscription
  const row = await getAsync('SELECT id, email, unsubscribe_token, unsubscribed_at, confirmed FROM subscriptions WHERE email = ? ORDER BY id DESC LIMIT 1', [email]);
  if (!row) return null;
  if (!row.confirmed) return { not_confirmed: true, id: row.id, email: row.email };
  if (row.unsubscribed_at) return { already: true, id: row.id, email: row.email };
  // do not immediately mark unsubscribed — send unsubscribe link first
  return row;
}

async function dbGetSubscribersForType(itemType) {
  // Only confirmed and not unsubscribed
  const rows = await allAsync('SELECT email, unsubscribe_token FROM subscriptions WHERE confirmed = 1 AND (unsubscribed_at IS NULL) AND types LIKE ?', [`%${itemType}%`]);
  return (rows || []).map(r => ({ email: r.email, unsubscribe_token: r.unsubscribe_token }));
}

function isTokenExpired(isoDateString, ttlHours) {
  if (!isoDateString) return true;
  const then = new Date(isoDateString).getTime();
  const now = Date.now();
  const diffMs = now - then;
  return diffMs > ttlHours * 3600 * 1000;
}

async function sendEmail(to, subject, text, html) {
  if (!SMTP_HOST || !SMTP_USER) {
    console.warn('SMTP not configured, skipping email to', to);
    return;
  }

  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS
    }
  });

  await transporter.sendMail({
    from: EMAIL_FROM,
    to,
    subject,
    text,
    html
  });
}

async function sendConfirmationEmail(email, confirmationToken) {
  const confirmLink = `${BASE_URL.replace(/\/$/, '')}/confirm?token=${confirmationToken}`;
  const subject = 'Confirm your subscription';
  const text = `Please confirm your subscription by visiting: ${confirmLink}\n\nIf you did not subscribe, ignore this email.`;
  const html = `<p>Please confirm your subscription by clicking the link below:</p><p><a href="${confirmLink}">Confirm subscription</a></p><p>If you did not subscribe, ignore this email.</p>`;
  try {
    await sendEmail(email, subject, text, html);
    console.log('Confirmation email sent to', email);
  } catch (e) {
    console.error('Error sending confirmation email to', email, e && e.message ? e.message : e);
  }
}

async function sendUnsubscribeEmail(email, unsubscribeToken) {
  const unsubscribeLink = `${BASE_URL.replace(/\/$/, '')}/unsubscribe?token=${unsubscribeToken}`;
  const subject = 'Unsubscribe from Microsoft Credentials notifications';
  const text = `Click to unsubscribe: ${unsubscribeLink}\n\nIf you did not request this, ignore the email.`;
  const html = `<p>To unsubscribe from notifications, click the link below:</p><p><a href="${unsubscribeLink}">Unsubscribe</a></p><p>If you did not request this, ignore the email.</p>`;
  try {
    await sendEmail(email, subject, text, html);
    console.log('Unsubscribe email sent to', email);
  } catch (e) {
    console.error('Error sending unsubscribe email to', email, e && e.message ? e.message : e);
  }
}

async function notifySubscribers(newItem) {
  try {
    const subs = await dbGetSubscribersForType(newItem.type);
    if (!subs || subs.length === 0) return;
    const subject = `New ${newItem.type} added: ${newItem.title}`;
    for (const s of subs) {
      const unsubscribeLink = `${BASE_URL.replace(/\/$/, '')}/unsubscribe?token=${s.unsubscribe_token}`;
      const text = `${newItem.title}\n\n${newItem.url}\n\nDiscovered: ${newItem.first_seen_at}\n\nTo unsubscribe: ${unsubscribeLink}`;
      const html = `<p>New <strong>${newItem.type}</strong> added:</p><p><a href="${newItem.url}">${newItem.title}</a></p><p>Discovered: ${newItem.first_seen_at}</p><p><a href="${unsubscribeLink}">Unsubscribe</a></p>`;
      try {
        await sendEmail(s.email, subject, text, html);
        console.log('Notified', s.email, 'about', newItem.title);
      } catch (e) {
        console.error('Error sending email to', s.email, e && e.message ? e.message : e);
      }
    }
  } catch (e) {
    console.error('Error in notifySubscribers:', e && e.message ? e.message : e);
  }
}

async function checkForUpdates() {
  try {
    const html = await fetchHtml(LIST_URL);
    const credentials = extractCredentials(html, LIST_URL);

    for (const cred of credentials) {
      const id = idForUrl(cred.url);
      // check if exists
      const exists = await getAsync('SELECT 1 FROM credentials WHERE id = ?', [id]);
      if (!exists) {
        const inserted = await dbInsertCredential(id, cred.title, cred.url, cred.type);
        console.log('New credential found:', inserted.title, inserted.url, inserted.type);
        io.emit('new-credential', inserted);
        // Send emails to subscribers interested in this type
        notifySubscribers(inserted).catch(err => console.error(err));
      }
    }
  } catch (err) {
    console.error('Error checking updates:', err && err.message ? err.message : err);
  }
}

// API: return all credentials (optionally filter by type query param: ?type=exam)
app.get('/api/credentials', async (req, res) => {
  try {
    const type = req.query.type;
    if (type) {
      const rows = await allAsync('SELECT id, title, url, type, first_seen_at FROM credentials WHERE type = ? ORDER BY first_seen_at DESC', [type]);
      res.json({ data: rows });
      return;
    }
    const rows = await dbGetAllCredentials();
    res.json({ data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// API: subscribe to email notifications
// POST /api/subscribe { email: string, types: ["certification","exam","skill"] }
app.post('/api/subscribe', async (req, res) => {
  try {
    const { email, types } = req.body || {};
    if (!email || !validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid or missing email' });
    }
    if (!Array.isArray(types) || types.length === 0) {
      return res.status(400).json({ error: 'Missing types (choose one or more of certification, exam, skill)' });
    }
    const cleanTypes = types.map(t => t.trim().toLowerCase()).filter(t => ['certification', 'exam', 'skill'].includes(t));
    if (cleanTypes.length === 0) {
      return res.status(400).json({ error: 'Invalid types; allowed: certification, exam, skill' });
    }
    const typesCsv = Array.from(new Set(cleanTypes)).join(',');
    // Insert subscription as unconfirmed with tokens
    const inserted = await dbAddSubscription(email, typesCsv);
    // Send confirmation email (best-effort)
    if (inserted && inserted.confirmation_token) {
      await sendConfirmationEmail(email, inserted.confirmation_token).catch(err => console.error(err));
    }
    res.json({ success: true, message: 'Subscription created. Please check your email and confirm your subscription using the link we sent.' });
  } catch (err) {
    res.status(500).json({ error: err.message || err });
  }
});

// POST /api/resend-confirmation { email }
app.post('/api/resend-confirmation', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email || !validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid or missing email' });
    }
    const sub = await dbFindSubscriptionByEmail(email);
    if (!sub) return res.status(404).json({ error: 'No subscription found for that email' });
    if (sub.unsubscribed_at) return res.status(400).json({ error: 'Subscription was unsubscribed' });
    if (sub.confirmed) return res.status(400).json({ error: 'Subscription already confirmed' });
    // Generate a fresh confirmation token and update
    const newToken = crypto.randomBytes(20).toString('hex');
    await dbSetConfirmationToken(sub.id, newToken);
    await sendConfirmationEmail(email, newToken).catch(err => console.error(err));
    res.json({ success: true, message: 'Confirmation email resent. Check your inbox.' });
  } catch (err) {
    res.status(500).json({ error: err.message || err });
  }
});

// POST /api/request-unsubscribe { email }
app.post('/api/request-unsubscribe', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email || !validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid or missing email' });
    }
    const sub = await dbUnsubscribeByEmail(email);
    if (!sub) return res.status(404).json({ error: 'No subscription found for that email' });
    if (sub.not_confirmed) return res.status(400).json({ error: 'Subscription is not confirmed' });
    if (sub.already) return res.status(400).json({ error: 'Subscription already unsubscribed' });
    // send the unsubscribe email with token (don't mark unsubscribed yet)
    await sendUnsubscribeEmail(email, sub.unsubscribe_token).catch(err => console.error(err));
    res.json({ success: true, message: 'An unsubscribe email was sent. Click the link in that email to complete unsubscription.' });
  } catch (err) {
    res.status(500).json({ error: err.message || err });
  }
});

// API: admin listing of subscriptions (protected by ADMIN_TOKEN header)
app.get('/api/admin/subscriptions', async (req, res) => {
  try {
    const token = req.header('x-admin-token') || req.query.admin_token;
    if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const rows = await allAsync('SELECT id, email, types, confirmed, created_at, confirmed_at, confirmation_sent_at, unsubscribed_at, confirmation_token, unsubscribe_token FROM subscriptions ORDER BY created_at DESC');
    res.json({ data: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// API: to list subscriptions (public debug - kept but less detailed)
app.get('/api/subscriptions', (req, res) => {
  db.all('SELECT id, email, types, confirmed, created_at, confirmed_at, unsubscribed_at FROM subscriptions ORDER BY created_at DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ data: rows || [] });
  });
});

// Confirm endpoint - used by confirmation link in email
app.get('/confirm', async (req, res) => {
  const token = req.query.token;
  if (!token) {
    return res.redirect('/confirm.html?status=missing');
  }
  try {
    const result = await dbConfirmSubscription(token);
    if (!result) return res.redirect('/confirm.html?status=invalid');
    if (result.expired) return res.redirect('/confirm.html?status=expired');
    if (result.already) return res.redirect('/confirm.html?status=already');
    return res.redirect('/confirm.html?status=success');
  } catch (e) {
    console.error('Error confirming subscription:', e && e.message ? e.message : e);
    return res.redirect('/confirm.html?status=error');
  }
});

// Unsubscribe endpoint - used by unsubscribe link in emails
app.get('/unsubscribe', async (req, res) => {
  const token = req.query.token;
  if (!token) {
    return res.redirect('/unsubscribe.html?status=missing');
  }
  try {
    const result = await dbUnsubscribe(token);
    if (!result) return res.redirect('/unsubscribe.html?status=invalid');
    if (result.already) return res.redirect('/unsubscribe.html?status=already');
    return res.redirect('/unsubscribe.html?status=success');
  } catch (e) {
    console.error('Error unsubscribing:', e && e.message ? e.message : e);
    return res.redirect('/unsubscribe.html?status=error');
  }
});

// Serve index.html for root (static served from /public)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// Start server
server.listen(PORT, async () => {
  console.log(`Server listening on port ${PORT}`);
  console.log(`BASE_URL is ${BASE_URL}`);
  console.log(`Confirmation token TTL is ${CONFIRMATION_TTL_HOURS} hours`);
  // On startup, load initial data by scraping once and inserting any new items
  await checkForUpdates();
  // Set interval for polling
  setInterval(checkForUpdates, POLL_INTERVAL_MS);
});
