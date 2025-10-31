// Lightweight SQLite helper using better-sqlite3
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs-extra');

const dataDir = path.join(__dirname, '..', 'data');
fs.ensureDirSync(dataDir);

const dbPath = path.join(dataDir, 'forangex.db');
const db = new Database(dbPath);

// Initialize schema if not exists
db.exec(`
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE IF NOT EXISTS rates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  symbol TEXT UNIQUE,
  usd REAL,
  ngn REAL,
  updated_at TEXT
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id TEXT,
  created_at TEXT,
  type TEXT,
  crypto TEXT,
  crypto_amount REAL,
  fiat_amount REAL,
  name TEXT,
  whatsapp_number TEXT,
  status TEXT,
  rate_source TEXT,
  rate_used TEXT
);
CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password_hash TEXT
);
`);

// helpers
function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? JSON.parse(row.value) : null;
}
function setSetting(key, value) {
  const s = JSON.stringify(value);
  const exists = db.prepare('SELECT 1 FROM settings WHERE key = ?').get(key);
  if (exists) db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(s, key);
  else db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run(key, s);
}
module.exports = {
  db,
  getSetting,
  setSetting
};
