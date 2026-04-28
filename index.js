// index.js - Main Express server (Vercel entry point)
const express = require('express');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { getConnection } = require('./lib/db');

const app = express();

// ─── Middleware ───────────────────────────────────────────────
const allowedOrigin = process.env.FRONTEND_URL || 'http://localhost';

app.use(cors({
  origin: allowedOrigin,
  credentials: false // No need for credentials with JWT
}));

app.use(express.json());

// ─── Auth Middleware ──────────────────────────────────────────
function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const token = authHeader.substring(7);
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'change-this-secret');
    req.admin = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ─── Routes ──────────────────────────────────────────────────

// Health check
app.get('/api', (req, res) => {
  res.json({ status: 'ok', message: 'Portfolio API is running' });
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const adminUsername = process.env.ADMIN_USERNAME || 'admin';
  const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';

  const usernameMatch = username === adminUsername;
  // Support both plain text and bcrypt hashed passwords
  const passwordMatch = adminPassword.startsWith('$2')
    ? await bcrypt.compare(password, adminPassword)
    : password === adminPassword;

  if (usernameMatch && passwordMatch) {
    const token = jwt.sign({ username }, process.env.JWT_SECRET || 'change-this-secret', { expiresIn: '1h' });
    return res.json({ success: true, token, username });
  }

  return res.status(401).json({ error: 'Invalid username or password' });
});

// POST /api/logout
app.post('/api/logout', (req, res) => {
  // For JWT, logout is handled on client side by removing token
  res.json({ success: true });
});

// GET /api/auth/check
app.get('/api/auth/check', requireAdmin, (req, res) => {
  res.json({ loggedIn: true, username: req.admin.username });
});

// GET /api/data  — list all entries
app.get('/api/data', requireAdmin, async (req, res) => {
  try {
    const db = await getConnection();
    const [rows] = await db.execute(
      'SELECT * FROM admin_data ORDER BY created_at DESC'
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/data  — create entry
app.post('/api/data', requireAdmin, async (req, res) => {
  const { title, description, status } = req.body;

  if (!title?.trim()) {
    return res.status(400).json({ error: 'Title is required' });
  }

  try {
    const db = await getConnection();
    const [result] = await db.execute(
      'INSERT INTO admin_data (title, description, status) VALUES (?, ?, ?)',
      [title.trim(), description?.trim() || '', status || 'active']
    );
    res.json({ success: true, id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/data/:id  — update entry
app.put('/api/data/:id', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  const { title, description, status } = req.body;

  if (!title?.trim()) {
    return res.status(400).json({ error: 'Title is required' });
  }

  try {
    const db = await getConnection();
    await db.execute(
      'UPDATE admin_data SET title=?, description=?, status=?, updated_at=NOW() WHERE id=?',
      [title.trim(), description?.trim() || '', status || 'active', id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/data/:id  — delete entry
app.delete('/api/data/:id', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);

  try {
    const db = await getConnection();
    await db.execute('DELETE FROM admin_data WHERE id=?', [id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/data/:id  — single entry
app.get('/api/data/:id', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);

  try {
    const db = await getConnection();
    const [rows] = await db.execute('SELECT * FROM admin_data WHERE id=?', [id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Start ────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`API running on port ${PORT}`));

module.exports = app;
