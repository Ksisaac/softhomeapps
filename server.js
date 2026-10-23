const express = require('express');
const session = require('express-session');
const SQLiteStore = require('better-sqlite3-session-store')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const uploadDir = path.join(ROOT, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const db = new Database(path.join(ROOT, 'data', 'shop.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  price TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  image TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const defaultEmail = process.env.ADMIN_EMAIL || 'admin@softhomeappliances.com';
const defaultPassword = process.env.ADMIN_PASSWORD || 'ChangeMe123!';
if (!db.prepare('SELECT id FROM admins WHERE email = ?').get(defaultEmail)) {
  const hash = bcrypt.hashSync(defaultPassword, 12);
  db.prepare('INSERT INTO admins (email, password_hash) VALUES (?, ?)').run(defaultEmail, hash);
}

app.set('view engine', 'ejs');
app.set('views', path.join(ROOT, 'views'));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(ROOT, 'public')));
app.use('/uploads', express.static(uploadDir));
app.use(session({
  secret: process.env.SESSION_SECRET || 'replace-this-session-secret-before-production',
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStore({ client: db, expired: { clear: true, intervalMs: 900000 } }),
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 }
}));

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2, 9)}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    cb(null, allowed.includes(file.mimetype));
  }
});

function requireAdmin(req, res, next) {
  if (!req.session.adminId) return res.redirect('/admin/login');
  next();
}
function deleteImage(filename) {
  if (!filename) return;
  const file = path.join(uploadDir, path.basename(filename));
  if (fs.existsSync(file)) fs.unlinkSync(file);
}
function clean(value) { return String(value || '').trim(); }

app.get('/', (req, res) => {
  const products = db.prepare('SELECT * FROM products ORDER BY id DESC').all();
  const categories = [...new Set(products.map(p => p.category).filter(Boolean))];
  res.render('index', { products, categories, whatsapp: '256743537202' });
});

app.get('/product/:id', (req, res) => {
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!product) return res.status(404).send('Product not found');
  res.render('product', { product, whatsapp: '256743537202' });
});

app.get('/admin/login', (req, res) => {
  if (req.session.adminId) return res.redirect('/admin');
  res.render('login', { error: '' });
});

app.post('/admin/login', (req, res) => {
  const email = clean(req.body.email).toLowerCase();
  const password = String(req.body.password || '');
  const admin = db.prepare('SELECT * FROM admins WHERE email = ?').get(email);
  if (!admin || !bcrypt.compareSync(password, admin.password_hash)) {
    return res.status(401).render('login', { error: 'Incorrect email or password.' });
  }
  req.session.adminId = admin.id;
  req.session.adminEmail = admin.email;
  res.redirect('/admin');
});

app.post('/admin/logout', requireAdmin, (req, res) => {
  req.session.destroy(() => res.redirect('/admin/login'));
});

app.get('/admin', requireAdmin, (req, res) => {
  const products = db.prepare('SELECT * FROM products ORDER BY id DESC').all();
  res.render('admin', { products, adminEmail: req.session.adminEmail, message: req.query.message || '' });
});

app.post('/admin/products', requireAdmin, upload.single('image'), (req, res) => {
  const name = clean(req.body.name);
  const category = clean(req.body.category) || 'Other';
  const price = clean(req.body.price);
  const description = clean(req.body.description);
  if (!name || !req.file) return res.status(400).send('Product name and image are required.');
  db.prepare('INSERT INTO products (name, category, price, description, image) VALUES (?, ?, ?, ?, ?)')
    .run(name, category, price, description, req.file.filename);
  res.redirect('/admin?message=Product+added');
});

app.post('/admin/products/:id/update', requireAdmin, upload.single('image'), (req, res) => {
  const existing = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).send('Product not found');
  const name = clean(req.body.name);
  const category = clean(req.body.category) || 'Other';
  const price = clean(req.body.price);
  const description = clean(req.body.description);
  const image = req.file ? req.file.filename : existing.image;
  db.prepare('UPDATE products SET name=?, category=?, price=?, description=?, image=?, updated_at=CURRENT_TIMESTAMP WHERE id=?')
    .run(name, category, price, description, image, req.params.id);
  if (req.file) deleteImage(existing.image);
  res.redirect('/admin?message=Product+updated');
});

app.post('/admin/products/:id/delete', requireAdmin, (req, res) => {
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (product) { deleteImage(product.image); db.prepare('DELETE FROM products WHERE id = ?').run(req.params.id); }
  res.redirect('/admin?message=Product+deleted');
});

app.get('/admin/change-password', requireAdmin, (req, res) => res.render('password', { error: '', success: '' }));
app.post('/admin/change-password', requireAdmin, (req, res) => {
  const current = String(req.body.current || '');
  const next = String(req.body.next || '');
  const confirm = String(req.body.confirm || '');
  const admin = db.prepare('SELECT * FROM admins WHERE id=?').get(req.session.adminId);
  if (!bcrypt.compareSync(current, admin.password_hash)) return res.render('password', { error: 'Current password is incorrect.', success: '' });
  if (next.length < 8) return res.render('password', { error: 'New password must be at least 8 characters.', success: '' });
  if (next !== confirm) return res.render('password', { error: 'New passwords do not match.', success: '' });
  db.prepare('UPDATE admins SET password_hash=? WHERE id=?').run(bcrypt.hashSync(next, 12), admin.id);
  res.render('password', { error: '', success: 'Password changed successfully.' });
});

app.use((err, req, res, next) => {
  console.error(err);
  if (err instanceof multer.MulterError || err.message) return res.status(400).send('Upload error: ' + err.message);
  res.status(500).send('Server error');
});

app.listen(PORT, () => console.log(`Soft Home Appliances running at http://localhost:${PORT}`));
