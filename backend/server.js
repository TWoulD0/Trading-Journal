const express    = require('express');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');

const app = express();

// ─── CORS ─────────────────────────────────────────────────────────────────────
// Allow your GitHub Pages domain + localhost for dev
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// Always allow localhost in dev
if (process.env.NODE_ENV !== 'production') {
  ALLOWED_ORIGINS.push('http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5500');
}

app.use(cors({
  origin: (origin, cb) => {
    // allow no-origin (e.g. Render health checks, mobile)
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.some(o => origin.startsWith(o))) return cb(null, true);
    return cb(new Error(`CORS blocked: ${origin}`));
  },
  credentials: true
}));

app.use(express.json({ limit: '2mb' }));

// ─── MongoDB ──────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/trading_journal')
  .then(() => console.log('✅  MongoDB connected'))
  .catch(err => { console.error('❌  MongoDB error:', err.message); process.exit(1); });

// ─── SCHEMAS ──────────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  email:        { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  createdAt:    { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Vision config (sliders + journal settings)
const visionCfgSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', unique: true },
  startCap:  { type: Number, default: 5 },
  target:    { type: Number, default: 1000 },
  skipWE:    { type: String, default: '1' },
  gain:      { type: Number, default: 3 },
  loss:      { type: Number, default: 2 },
  winrate:   { type: Number, default: 60 },
  trades:    { type: Number, default: 1 },
  updatedAt: { type: Date, default: Date.now }
});
const VisionCfg = mongoose.model('VisionCfg', visionCfgSchema);

// RT config (journal settings)
const rtCfgSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', unique: true },
  startCap:  { type: Number, default: 5 },
  target:    { type: Number, default: 1000 },
  startDate: { type: String, default: '2026-03-31' },
  skipWE:    { type: String, default: '1' },
  updatedAt: { type: Date, default: Date.now }
});
const RTCfg = mongoose.model('RTCfg', rtCfgSchema);

// RT rows (trading log)
const rtRowSchema = new mongoose.Schema({
  userId:     { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  rows:       { type: Array, default: [] },   // [{pnl, instrument}]
  updatedAt:  { type: Date, default: Date.now }
});
const RTRows = mongoose.model('RTRows', rtRowSchema);

// ─── HELPERS ──────────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret_in_production';

function signToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const exists = await User.findOne({ email: email.toLowerCase().trim() });
    if (exists) return res.status(409).json({ error: 'Email already registered' });

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ email: email.toLowerCase().trim(), passwordHash });
    const token = signToken(user._id);
    res.status(201).json({ token, email: user.email });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

    const token = signToken(user._id);
    res.json({ token, email: user.email });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/auth/me  — validate token and return user info
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('email createdAt');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ email: user.email, createdAt: user.createdAt });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── VISION CONFIG ────────────────────────────────────────────────────────────

// GET /api/vision/config
app.get('/api/vision/config', authMiddleware, async (req, res) => {
  try {
    const cfg = await VisionCfg.findOne({ userId: req.user.userId });
    res.json(cfg || {});
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// PUT /api/vision/config
app.put('/api/vision/config', authMiddleware, async (req, res) => {
  try {
    const data = { ...req.body, userId: req.user.userId, updatedAt: new Date() };
    const cfg = await VisionCfg.findOneAndUpdate(
      { userId: req.user.userId }, data, { upsert: true, new: true }
    );
    res.json(cfg);
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// ─── RT CONFIG ────────────────────────────────────────────────────────────────

// GET /api/rt/config
app.get('/api/rt/config', authMiddleware, async (req, res) => {
  try {
    const cfg = await RTCfg.findOne({ userId: req.user.userId });
    res.json(cfg || {});
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// PUT /api/rt/config
app.put('/api/rt/config', authMiddleware, async (req, res) => {
  try {
    const data = { ...req.body, userId: req.user.userId, updatedAt: new Date() };
    const cfg = await RTCfg.findOneAndUpdate(
      { userId: req.user.userId }, data, { upsert: true, new: true }
    );
    res.json(cfg);
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// ─── RT ROWS ──────────────────────────────────────────────────────────────────

// GET /api/rt/rows
app.get('/api/rt/rows', authMiddleware, async (req, res) => {
  try {
    const doc = await RTRows.findOne({ userId: req.user.userId });
    res.json(doc ? doc.rows : []);
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// PUT /api/rt/rows  — replace entire rows array
app.put('/api/rt/rows', authMiddleware, async (req, res) => {
  try {
    const { rows } = req.body;
    if (!Array.isArray(rows)) return res.status(400).json({ error: 'rows must be an array' });
    const doc = await RTRows.findOneAndUpdate(
      { userId: req.user.userId },
      { userId: req.user.userId, rows, updatedAt: new Date() },
      { upsert: true, new: true }
    );
    res.json(doc.rows);
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// ─── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', ts: Date.now() }));

// ─── START ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`🚀  Server running on port ${PORT}`));
