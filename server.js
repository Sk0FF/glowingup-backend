require('dotenv').config();
const express = require('express');
const cors = require('cors');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app = express();
const db = new Database('glowingup.db');

// Init DB
db.exec(`
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service TEXT,
    platform TEXT,
    link TEXT,
    quantity INTEGER,
    amount REAL,
    status TEXT DEFAULT 'pending',
    email TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT
  );
`);

// Create admin if not exists
const adminExists = db.prepare('SELECT * FROM admin WHERE email = ?').get(process.env.ADMIN_EMAIL);
if (!adminExists) {
  const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
  db.prepare('INSERT INTO admin (email, password) VALUES (?, ?)').run(process.env.ADMIN_EMAIL, hash);
}

app.use(cors());
app.use(express.json());

// ── AUTH ──
app.post('/api/admin/login', (req, res) => {
  const { email, password } = req.body;
  const admin = db.prepare('SELECT * FROM admin WHERE email = ?').get(email);
  if (!admin || !bcrypt.compareSync(password, admin.password)) {
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }
  const token = jwt.sign({ id: admin.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Non autorisé' });
  try {
    req.admin = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
}

// ── STRIPE CHECKOUT ──
app.post('/api/create-checkout', async (req, res) => {
  const { service, platform, link, quantity, amount, email } = req.body;
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'eur',
          product_data: { name: `${service} — ${quantity} unités`, description: `Lien: ${link}` },
          unit_amount: Math.round(amount * 100),
        },
        quantity: 1,
      }],
      mode: 'payment',
      customer_email: email,
      success_url: `${process.env.FRONTEND_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}/services.html`,
      metadata: { service, platform, link, quantity: String(quantity), amount: String(amount), email }
    });
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── STRIPE WEBHOOK ──
app.post('/api/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  if (event.type === 'checkout.session.completed') {
    const s = event.data.object;
    const m = s.metadata;
    db.prepare('INSERT INTO orders (service, platform, link, quantity, amount, email, status) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
      m.service, m.platform, m.link, parseInt(m.quantity), parseFloat(m.amount), m.email, 'pending'
    );
  }
  res.json({ received: true });
});

// ── ADMIN ROUTES ──
app.get('/api/admin/orders', authMiddleware, (req, res) => {
  const orders = db.prepare('SELECT * FROM orders ORDER BY created_at DESC').all();
  res.json(orders);
});

app.patch('/api/admin/orders/:id', authMiddleware, (req, res) => {
  const { status } = req.body;
  db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(status, req.params.id);
  res.json({ success: true });
});

app.delete('/api/admin/orders/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM orders WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.get('/api/admin/stats', authMiddleware, (req, res) => {
  const total = db.prepare('SELECT COUNT(*) as count, SUM(amount) as revenue FROM orders').get();
  const pending = db.prepare("SELECT COUNT(*) as count FROM orders WHERE status = 'pending'").get();
  const delivered = db.prepare("SELECT COUNT(*) as count FROM orders WHERE status = 'delivered'").get();
  res.json({ total: total.count, revenue: total.revenue || 0, pending: pending.count, delivered: delivered.count });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
