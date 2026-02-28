require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const sqlite3 = require('sqlite3').verbose();
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'chartcharcha-secret-key-change-in-production';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'chartcharcha123';

// ─── Database Setup ───────────────────────────────────────────
const db = new sqlite3.Database('./chartcharcha.db', (err) => {
  if (err) console.error('DB Error:', err);
  else console.log('✅ Database connected');
});

db.serialize(() => {
  // Subscribers table
  db.run(`CREATE TABLE IF NOT EXISTS subscribers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    subscribed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    active INTEGER DEFAULT 1
  )`);

  // Updates/Posts table
  db.run(`CREATE TABLE IF NOT EXISTS updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    summary TEXT,
    published INTEGER DEFAULT 0,
    published_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Analytics table
  db.run(`CREATE TABLE IF NOT EXISTS analytics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,
    data TEXT,
    ip TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// ─── Middleware ───────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.static('public'));

// Rate limiter for subscribe endpoint
const subscribeLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: { error: 'Too many attempts, try again later.' } });
const emailLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 3 });

// ─── Auth Middleware ──────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ─── Email Setup ──────────────────────────────────────────────
function createTransporter() {
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS  // Gmail App Password
    }
  });
}

// ─── PUBLIC ROUTES ────────────────────────────────────────────

// Subscribe
app.post('/api/subscribe', subscribeLimiter, (req, res) => {
  const { email, name } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required' });

  db.run('INSERT OR IGNORE INTO subscribers (email, name) VALUES (?, ?)', [email.toLowerCase(), name || ''], function(err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (this.changes === 0) return res.status(409).json({ error: 'Email already subscribed!' });

    // Log analytics
    db.run('INSERT INTO analytics (event, data, ip) VALUES (?, ?, ?)', ['subscribe', email, req.ip]);

    // Send welcome email
    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      const transporter = createTransporter();
      transporter.sendMail({
        from: `"Chartcharcha by Sumeet" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: '🎉 Welcome to Chartcharcha!',
        html: `
          <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:32px;background:#0a0d0f;color:#e8eaed;border-radius:12px;">
            <h1 style="color:#f0b429;font-size:1.8rem;margin-bottom:8px;">Welcome to Chartcharcha! 📈</h1>
            <p style="color:#9ca3af;margin-bottom:24px;">Hi ${name || 'there'},</p>
            <p style="line-height:1.7;">You're now subscribed to India's sharpest daily market updates by <strong>Sumeet</strong>.</p>
            <p style="line-height:1.7;margin-top:16px;">Every trading day at <strong>8 AM IST</strong>, you'll get:</p>
            <ul style="color:#9ca3af;line-height:2;">
              <li>📊 NIFTY & SENSEX breakdown</li>
              <li>🔦 Sector spotlight</li>
              <li>💡 Sumeet's Take</li>
              <li>📅 Key events to watch</li>
            </ul>
            <p style="margin-top:24px;color:#9ca3af;font-size:13px;">To unsubscribe at any time, reply with "unsubscribe".</p>
          </div>
        `
      }).catch(console.error);
    }

    res.json({ success: true, message: 'Successfully subscribed! Welcome to Chartcharcha 🎉' });
  });
});

// Unsubscribe
app.post('/api/unsubscribe', (req, res) => {
  const { email } = req.body;
  db.run('UPDATE subscribers SET active = 0 WHERE email = ?', [email?.toLowerCase()], function(err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ success: true, message: 'You have been unsubscribed.' });
  });
});

// Get published updates (for website)
app.get('/api/updates', (req, res) => {
  db.all('SELECT id, title, summary, published_at FROM updates WHERE published = 1 ORDER BY published_at DESC LIMIT 10', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

// Get single update
app.get('/api/updates/:id', (req, res) => {
  db.get('SELECT * FROM updates WHERE id = ? AND published = 1', [req.params.id], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Not found' });
    res.json(row);
  });
});

// Track page visit
app.post('/api/track', (req, res) => {
  const { page } = req.body;
  db.run('INSERT INTO analytics (event, data, ip) VALUES (?, ?, ?)', ['pageview', page || '/', req.ip]);
  res.json({ ok: true });
});

// ─── ADMIN ROUTES ─────────────────────────────────────────────

// Admin login
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

// Get all subscribers
app.get('/api/admin/subscribers', authMiddleware, (req, res) => {
  db.all('SELECT id, email, name, subscribed_at, active FROM subscribers ORDER BY subscribed_at DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

// Get analytics
app.get('/api/admin/analytics', authMiddleware, (req, res) => {
  db.all(`SELECT 
    (SELECT COUNT(*) FROM subscribers WHERE active=1) as total_subscribers,
    (SELECT COUNT(*) FROM analytics WHERE event='pageview') as total_pageviews,
    (SELECT COUNT(*) FROM analytics WHERE event='pageview' AND date(created_at) = date('now')) as today_pageviews,
    (SELECT COUNT(*) FROM updates WHERE published=1) as total_posts
  `, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows[0]);
  });
});

// Create/Save update
app.post('/api/admin/updates', authMiddleware, (req, res) => {
  const { title, content, summary } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'Title and content required' });
  db.run('INSERT INTO updates (title, content, summary) VALUES (?, ?, ?)', [title, content, summary || ''], function(err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ success: true, id: this.lastID });
  });
});

// Get all updates (admin)
app.get('/api/admin/updates', authMiddleware, (req, res) => {
  db.all('SELECT * FROM updates ORDER BY created_at DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

// Publish update + send newsletter
app.post('/api/admin/updates/:id/publish', authMiddleware, emailLimiter, (req, res) => {
  const { id } = req.params;

  db.get('SELECT * FROM updates WHERE id = ?', [id], (err, update) => {
    if (err || !update) return res.status(404).json({ error: 'Update not found' });

    // Mark as published
    db.run('UPDATE updates SET published = 1, published_at = CURRENT_TIMESTAMP WHERE id = ?', [id]);

    // Send to all active subscribers
    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      db.all('SELECT email, name FROM subscribers WHERE active = 1', (err, subscribers) => {
        if (err || !subscribers.length) return;

        const transporter = createTransporter();
        subscribers.forEach(sub => {
          transporter.sendMail({
            from: `"Chartcharcha by Sumeet" <${process.env.EMAIL_USER}>`,
            to: sub.email,
            subject: `📈 ${update.title}`,
            html: `
              <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:32px;background:#0a0d0f;color:#e8eaed;border-radius:12px;">
                <div style="background:#f0b429;color:#000;padding:4px 12px;border-radius:20px;display:inline-block;font-size:12px;font-weight:600;margin-bottom:16px;">CHARTCHARCHA DAILY</div>
                <h1 style="color:#f0b429;font-size:1.6rem;margin-bottom:16px;">${update.title}</h1>
                <div style="color:#e8eaed;line-height:1.8;font-size:15px;">${update.content.replace(/\n/g, '<br/>')}</div>
                <hr style="border-color:#1e2428;margin:24px 0;"/>
                <p style="color:#6b7280;font-size:12px;">You're receiving this because you subscribed to Chartcharcha.<br/>
                <a href="${process.env.SITE_URL || 'https://sumeet-patel999.github.io/chartcharcha'}/unsubscribe?email=${sub.email}" style="color:#f0b429;">Unsubscribe</a></p>
              </div>
            `
          }).catch(console.error);
        });

        res.json({ success: true, sent_to: subscribers.length });
      });
    } else {
      res.json({ success: true, message: 'Published (email not configured)' });
    }
  });
});

// Delete update
app.delete('/api/admin/updates/:id', authMiddleware, (req, res) => {
  db.run('DELETE FROM updates WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ success: true });
  });
});

// ─── Serve Admin Panel ────────────────────────────────────────
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/admin/index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Chartcharcha backend running on port ${PORT}`);
  console.log(`📊 Admin panel: http://localhost:${PORT}/admin`);
});
