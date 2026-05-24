require('dotenv').config();
const express = require('express');
const cors = require('cors');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');


// ── TELEGRAM NOTIFICATIONS ──
async function sendTelegramNotif(message){
  try {
    const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
    const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
    if(!TELEGRAM_TOKEN || !TELEGRAM_CHAT_ID) return;
    // Send to all chat IDs (comma separated)
    const chatIds = TELEGRAM_CHAT_ID.split(',').map(id => id.trim());
    await Promise.all(chatIds.map(chatId =>
      fetch(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ chat_id: chatId, text: message, parse_mode: 'HTML' })
      })
    ));
  } catch(e) { console.log('Telegram error:', e.message); }
}

const app = express();

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('railway.internal') 
    ? false 
    : { rejectUnauthorized: false }
});

// Init tables
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      service TEXT, platform TEXT, link TEXT,
      quantity INTEGER, amount REAL,
      status TEXT DEFAULT 'pending',
      email TEXT, user_id INTEGER,
      promo_code TEXT,
      id_service TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS id_service TEXT;
    CREATE TABLE IF NOT EXISTS admin (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE, password TEXT
    );
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE, password TEXT, name TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS promo_codes (
      id SERIAL PRIMARY KEY,
      code TEXT UNIQUE,
      discount INTEGER,
      max_uses INTEGER DEFAULT 9999,
      uses INTEGER DEFAULT 0,
      active INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS promo_uses (
      id SERIAL PRIMARY KEY,
      code TEXT, email TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Create admin if not exists
  const adminRes = await pool.query('SELECT * FROM admin WHERE email = $1', [process.env.ADMIN_EMAIL]);
  if (adminRes.rows.length === 0) {
    const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
    await pool.query('INSERT INTO admin (email, password) VALUES ($1, $2)', [process.env.ADMIN_EMAIL, hash]);
    console.log('Admin created');
  }

  // Create default promo code
  const promoRes = await pool.query('SELECT * FROM promo_codes WHERE code = $1', ['GLOW20']);
  if (promoRes.rows.length === 0) {
    await pool.query('INSERT INTO promo_codes (code, discount, max_uses) VALUES ($1, $2, $3)', ['GLOW20', 20, 9999]);
  }

  console.log('Database initialized');
}

initDB().catch(console.error);

app.use(cors());
app.use((req, res, next) => {
  if(req.originalUrl === '/api/webhook') {
    express.raw({type: '*/*'})(req, res, next);
  } else {
    express.json()(req, res, next);
  }
});

// ── ADMIN AUTH ──
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM admin WHERE email = $1', [email]);
  const admin = result.rows[0];
  if (!admin || !bcrypt.compareSync(password, admin.password)) return res.status(401).json({ error: 'Identifiants incorrects' });
  const token = jwt.sign({ id: admin.id, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

function adminMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Non autorisé' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
    req.admin = decoded;
    next();
  } catch { res.status(401).json({ error: 'Token invalide' }); }
}

// ── CLIENT AUTH ──
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name) return res.status(400).json({ error: 'Champs manquants' });
  const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  if (existing.rows.length > 0) return res.status(400).json({ error: 'Email déjà utilisé' });
  const hash = bcrypt.hashSync(password, 10);
  const result = await pool.query('INSERT INTO users (email, password, name) VALUES ($1, $2, $3) RETURNING id', [email, hash, name]);
  const token = jwt.sign({ id: result.rows[0].id, role: 'user' }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: result.rows[0].id, email, name } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  const token = jwt.sign({ id: user.id, role: 'user' }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
});

function userMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Non autorisé' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token invalide' }); }
}

// ── CLIENT ROUTES ──
app.get('/api/user/orders', userMiddleware, async (req, res) => {
  const result = await pool.query('SELECT * FROM orders WHERE user_id = $1 OR email = (SELECT email FROM users WHERE id = $1) ORDER BY created_at DESC', [req.user.id]);
  res.json(result.rows);
});

app.get('/api/user/me', userMiddleware, async (req, res) => {
  const result = await pool.query('SELECT id, email, name, created_at FROM users WHERE id = $1', [req.user.id]);
  res.json(result.rows[0]);
});

// ── PROMO CODES ──
app.post('/api/promo/check', async (req, res) => {
  const { code, email } = req.body;
  if (!code) return res.status(400).json({ error: 'Code manquant' });
  const result = await pool.query('SELECT * FROM promo_codes WHERE code = $1 AND active = 1', [code.toUpperCase()]);
  const promo = result.rows[0];
  if (!promo) return res.status(404).json({ error: 'Code invalide ou expiré' });
  if (promo.uses >= promo.max_uses) return res.status(400).json({ error: 'Code épuisé' });
  if (email) {
    const used = await pool.query('SELECT * FROM promo_uses WHERE code = $1 AND email = $2', [code.toUpperCase(), email]);
    if (used.rows.length > 0) return res.status(400).json({ error: 'Tu as déjà utilisé ce code' });
  }
  res.json({ valid: true, discount: promo.discount, code: promo.code });
});

// ── STRIPE CHECKOUT ──
app.post('/api/create-checkout', async (req, res) => {
  const { service, platform, link, quantity, amount, email, user_id, promo_code, original_amount } = req.body;
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{ price_data: { currency: 'eur', product_data: { name: `${service} — ${quantity} unités`, description: `Lien: ${link}` }, unit_amount: Math.round(amount * 100) }, quantity: 1 }],
      mode: 'payment',
      customer_email: email,
      success_url: `${process.env.FRONTEND_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}/services.html`,
      metadata: { service, platform, link, quantity: String(quantity), amount: String(amount), email, user_id: String(user_id||''), promo_code: promo_code||'' }
    });
    res.json({ url: session.url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── STRIPE WEBHOOK ──
app.post('/api/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET); }
  catch (err) { return res.status(400).send(`Webhook Error: ${err.message}`); }
  if (event.type === 'checkout.session.completed') {
    const s = event.data.object;
    const m = s.metadata;
    const userId = m.user_id ? parseInt(m.user_id) : null;
    await pool.query('INSERT INTO orders (service, platform, link, quantity, amount, email, status, user_id, promo_code, id_service) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      [m.service, m.platform, m.link, parseInt(m.quantity), parseFloat(m.amount), m.email, 'pending', userId, m.promo_code||null, m.id_service||null]);
    
    // Send Telegram notification
    const msg = `🛒 <b>NOUVELLE COMMANDE !</b>\n\n` +
      `📦 <b>Service :</b> ${m.service}\n` +
      `📱 <b>Plateforme :</b> ${m.platform}\n` +
      `🔢 <b>Quantité :</b> ${parseInt(m.quantity).toLocaleString()}\n` +
      `💰 <b>Montant :</b> ${parseFloat(m.amount).toFixed(2)}€\n` +
      `${m.promo_code ? '🎟 <b>Code promo :</b> ' + m.promo_code + '\n' : ''}` +
      `📧 <b>Email :</b> ${m.email}\n` +
      `🔗 <b>Lien :</b> ${m.link}\n\n` +
      `⏰ ${new Date().toLocaleString('fr-FR')}`;
    await sendTelegramNotif(msg);
    if (m.promo_code) {
      await pool.query('UPDATE promo_codes SET uses = uses + 1 WHERE code = $1', [m.promo_code]);
      await pool.query('INSERT INTO promo_uses (code, email) VALUES ($1, $2)', [m.promo_code, m.email]);
    }
  }
  res.json({ received: true });
});

// ── ADMIN ROUTES ──
app.get('/api/admin/orders', adminMiddleware, async (req, res) => {
  const result = await pool.query('SELECT * FROM orders ORDER BY created_at DESC');
  res.json(result.rows);
});

app.patch('/api/admin/orders/:id', adminMiddleware, async (req, res) => {
  await pool.query('UPDATE orders SET status = $1 WHERE id = $2', [req.body.status, req.params.id]);
  res.json({ success: true });
});

app.delete('/api/admin/orders/:id', adminMiddleware, async (req, res) => {
  await pool.query('DELETE FROM orders WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

app.get('/api/admin/stats', adminMiddleware, async (req, res) => {
  const total = await pool.query('SELECT COUNT(*) as count, SUM(amount) as revenue FROM orders');
  const pending = await pool.query("SELECT COUNT(*) as count FROM orders WHERE status = 'pending'");
  const delivered = await pool.query("SELECT COUNT(*) as count FROM orders WHERE status = 'delivered'");
  const users = await pool.query('SELECT COUNT(*) as count FROM users');
  res.json({ total: parseInt(total.rows[0].count), revenue: parseFloat(total.rows[0].revenue)||0, pending: parseInt(pending.rows[0].count), delivered: parseInt(delivered.rows[0].count), users: parseInt(users.rows[0].count) });
});

app.get('/api/admin/users', adminMiddleware, async (req, res) => {
  const result = await pool.query('SELECT id, email, name, created_at FROM users ORDER BY created_at DESC');
  res.json(result.rows);
});

app.patch('/api/admin/users/:id/password', adminMiddleware, async (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: 'Mot de passe trop court' });
  const hash = bcrypt.hashSync(password, 10);
  await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hash, req.params.id]);
  res.json({ success: true });
});

app.delete('/api/admin/users/:id', adminMiddleware, async (req, res) => {
  await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

app.get('/api/admin/promos', adminMiddleware, async (req, res) => {
  const result = await pool.query('SELECT * FROM promo_codes ORDER BY created_at DESC');
  res.json(result.rows);
});

app.post('/api/admin/promos', adminMiddleware, async (req, res) => {
  const { code, discount, max_uses } = req.body;
  try {
    await pool.query('INSERT INTO promo_codes (code, discount, max_uses) VALUES ($1, $2, $3)', [code.toUpperCase(), discount, max_uses||9999]);
    res.json({ success: true });
  } catch { res.status(400).json({ error: 'Code déjà existant' }); }
});

app.patch('/api/admin/promos/:id', adminMiddleware, async (req, res) => {
  await pool.query('UPDATE promo_codes SET active = $1 WHERE id = $2', [req.body.active, req.params.id]);
  res.json({ success: true });
});

app.delete('/api/admin/promos/:id', adminMiddleware, async (req, res) => {
  await pool.query('DELETE FROM promo_codes WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});


// ── STRIPE PAYMENTS HISTORY ──
app.get('/api/admin/payments', adminMiddleware, async (req, res) => {
  try {
    const charges = await stripe.checkout.sessions.list({ limit: 50 });
    const payments = charges.data.map(p => ({
      id: p.id,
      amount: p.amount / 100,
      currency: p.currency,
      status: p.status,
      email: p.receipt_email || p.metadata?.email || '—',
      description: p.description || p.metadata?.service || '—',
      created: new Date(p.created * 1000).toISOString(),
      receipt_url: p.charges?.data[0]?.receipt_url || null
    }));
    res.json(payments);
  } catch(err) { res.status(500).json({ error: err.message }); }
});


// Test Telegram
app.get('/api/test-telegram', async (req, res) => {
  try {
    const token = process.env.TELEGRAM_TOKEN;
    const chatIds = (process.env.TELEGRAM_CHAT_ID || '').split(',').map(id => id.trim());
    const results = [];
    for(const chatId of chatIds){
      const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ chat_id: chatId, text: '🧪 Test GlowingUp — Telegram fonctionne !', parse_mode: 'HTML' })
      });
      const data = await r.json();
      results.push({ chatId, ok: data.ok, error: data.description });
    }
    res.json({ token_set: !!token, chat_ids: chatIds, results });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Test order
app.post('/api/test-order', async (req, res) => {
  await pool.query('INSERT INTO orders (service, platform, link, quantity, amount, email, status) VALUES ($1,$2,$3,$4,$5,$6,$7)',
    ['Abonnés Instagram', 'Instagram', 'https://instagram.com/test', 1000, 9.75, 'test@gmail.com', 'pending']);
  
  // Send Telegram notification
  const msg = `🛒 <b>NOUVELLE COMMANDE !</b>\n\n` +
    `📦 <b>Service :</b> Abonnés Instagram\n` +
    `📱 <b>Plateforme :</b> Instagram\n` +
    `🔢 <b>Quantité :</b> 1 000\n` +
    `💰 <b>Montant :</b> 9.75€\n` +
    `📧 <b>Email :</b> test@gmail.com\n` +
    `🔗 <b>Lien :</b> https://instagram.com/test\n\n` +
    `⏰ ${new Date().toLocaleString('fr-FR')}`;
  await sendTelegramNotif(msg);
  
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));