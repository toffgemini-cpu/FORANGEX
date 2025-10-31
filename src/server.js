// FORANGEX server with SQLite persistence, admin auth, editable margin, and quotes
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const axios = require('axios');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const qrcode = require('qrcode');
const qrcodeTerminal = require('qrcode-terminal');
const { Client, LocalAuth } = require('whatsapp-web.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

dotenv.config();

const { db, getSetting, setSetting } = require('./db');

const APP_NAME = 'FORANGEX';
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || null;
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || 'changeme';

// default margin (10%)
if (getSetting('margin') === null) setSetting('margin', 0.10);

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// ensure admin user exists (simple single admin)
(async () => {
  if (!ADMIN_PASSWORD) {
    console.warn(`[${APP_NAME}] WARNING: ADMIN_PASSWORD not set in .env. Please set it before production.`);
  } else {
    const row = db.prepare('SELECT * FROM admin WHERE username = ?').get('admin');
    if (!row) {
      const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
      db.prepare('INSERT INTO admin (username, password_hash) VALUES (?, ?)').run('admin', hash);
      console.log(`[${APP_NAME}] Admin user initialized.`);
    }
  }
})();

// --------- helper functions ----------
function toWhatsappId(e164) {
  if (!e164) return null;
  const digits = e164.replace(/\D/g, '');
  return digits + '@c.us';
}

async function fetchCryptoPriceNGN(cryptoId = 'bitcoin') {
  const url = `https://api.coingecko.com/api/v3/simple/price`;
  const res = await axios.get(url, {
    params: { ids: cryptoId, vs_currencies: 'ngn,usd' },
    timeout: 8000
  });
  const data = res.data;
  if (!data || !data[cryptoId]) throw new Error('Price fetch failed');
  return data[cryptoId];
}

// read manual rates from DB; returns object {usd, ngn} or null
function readManualRate(symbol) {
  const row = db.prepare('SELECT usd, ngn FROM rates WHERE symbol = ?').get(symbol);
  if (!row) return null;
  return { usd: row.usd, ngn: row.ngn };
}
function saveManualRate(symbol, usd, ngn) {
  const now = new Date().toISOString();
  const exists = db.prepare('SELECT 1 FROM rates WHERE symbol = ?').get(symbol);
  if (exists) {
    db.prepare('UPDATE rates SET usd = ?, ngn = ?, updated_at = ? WHERE symbol = ?').run(usd, ngn, now, symbol);
  } else {
    db.prepare('INSERT INTO rates (symbol, usd, ngn, updated_at) VALUES (?, ?, ?, ?)').run(symbol, usd, ngn, now);
  }
}
function readAllManualRates() {
  const rows = db.prepare('SELECT symbol, usd, ngn, updated_at FROM rates').all();
  const out = { btc: null, eth: null, usdt: null };
  rows.forEach(r => out[r.symbol] = { usd: r.usd, ngn: r.ngn, updated_at: r.updated_at });
  return out;
}
function saveOrderToDb(order) {
  const stmt = db.prepare(`INSERT INTO orders (order_id, created_at, type, crypto, crypto_amount, fiat_amount,
    name, whatsapp_number, status, rate_source, rate_used) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  stmt.run(order.id, order.created_at, order.type, order.crypto, order.cryptoAmount, order.fiatAmount,
    order.name, order.whatsappNumber, order.status, order.rate_source, JSON.stringify(order.rate_used));
}

// get margin setting
function getMargin() {
  const m = getSetting('margin');
  return typeof m === 'number' ? m : 0.10;
}

// get price: prefer manual DB rate, else CoinGecko
async function getRateForCrypto(crypto) {
  const c = (crypto || '').toLowerCase();
  if (c === 'btc' || c === 'bitcoin') {
    const manual = readManualRate('btc');
    if (manual && manual.usd != null && manual.ngn != null) return { usd: manual.usd, ngn: manual.ngn, source: 'manual' };
    const cg = await fetchCryptoPriceNGN('bitcoin');
    return { usd: cg.usd, ngn: cg.ngn, source: 'coingecko' };
  } else if (c === 'eth' || c === 'ethereum') {
    const manual = readManualRate('eth');
    if (manual && manual.usd != null && manual.ngn != null) return { usd: manual.usd, ngn: manual.ngn, source: 'manual' };
    const cg = await fetchCryptoPriceNGN('ethereum');
    return { usd: cg.usd, ngn: cg.ngn, source: 'coingecko' };
  } else if (c === 'usdt' || c === 'tether') {
    const manual = readManualRate('usdt');
    if (manual && manual.usd != null && manual.ngn != null) return { usd: manual.usd, ngn: manual.ngn, source: 'manual' };
    const cg = await fetchCryptoPriceNGN('tether');
    return { usd: cg.usd, ngn: cg.ngn, source: 'coingecko' };
  } else {
    // try coingecko generic id
    const cg = await fetchCryptoPriceNGN(c);
    return { usd: cg.usd, ngn: cg.ngn, source: 'coingecko' };
  }
}

async function getQuoteForCrypto(crypto) {
  const base = await getRateForCrypto(crypto);
  const margin = getMargin();
  const buy = { usd: Number(base.usd) * (1 + margin), ngn: Number(base.ngn) * (1 + margin) };
  const sell = { usd: Number(base.usd) * (1 - margin), ngn: Number(base.ngn) * (1 - margin) };
  return {
    crypto: (crypto || '').toLowerCase(),
    base: { usd: Number(base.usd), ngn: Number(base.ngn) },
    buy, sell,
    source: base.source,
    margin
  };
}

// ---------- WhatsApp client ----------
const phoneToSocket = new Map();
const socketToPhone = new Map();

const waClient = new Client({
  authStrategy: new LocalAuth({ clientId: "forangex-client" }),
  puppeteer: { headless: true }
});

waClient.on('qr', async (qr) => {
  console.log(`[${APP_NAME}] QR received - scan with WhatsApp mobile app.`);
  qrcodeTerminal.generate(qr, { small: true });
  try {
    const dataUrl = await qrcode.toDataURL(qr);
    io.emit('qr', { qr, dataUrl });
  } catch (e) {
    console.warn(`[${APP_NAME}] Failed to create QR data URL:`, e.message);
  }
});

waClient.on('ready', () => {
  console.log(`[${APP_NAME}] WhatsApp client ready.`);
  io.emit('wa_ready', { ready: true });
});

waClient.on('authenticated', () => {
  console.log(`[${APP_NAME}] WhatsApp authenticated and session saved (LocalAuth).`);
});

waClient.on('auth_failure', (msg) => {
  console.error(`[${APP_NAME}] Auth failure:`, msg);
});

waClient.on('disconnected', (reason) => {
  console.warn(`[${APP_NAME}] Disconnected:`, reason);
});

waClient.on('message', async (message) => {
  try {
    const fromId = message.from;
    const phoneDigits = fromId.split('@')[0];
    const normalized = '+' + phoneDigits;
    const socketId = phoneToSocket.get(normalized);
    const text = message.body || '';

    console.log(`[${APP_NAME}] Incoming from ${normalized}: ${text}`);

    const payload = {
      from: normalized,
      body: text,
      id: message.id._serialized,
      timestamp: message.timestamp
    };

    if (socketId) {
      io.to(socketId).emit('incoming', payload);
    } else {
      console.log(`[${APP_NAME}] No active socket for ${normalized}`);
      if (process.env.ADMIN_WHATSAPP_NUMBER) {
        try {
          const adminId = toWhatsappId(process.env.ADMIN_WHATSAPP_NUMBER);
          await waClient.sendMessage(adminId, `Incoming message from ${normalized}: ${text}`);
        } catch (e) {
          console.warn(`[${APP_NAME}] Failed to notify admin:`, e.message);
        }
      }
    }
  } catch (err) {
    console.error(`[${APP_NAME}] Error handling incoming message:`, err);
  }
});

waClient.initialize().catch(err => {
  console.error(`[${APP_NAME}] Failed to initialize WhatsApp client:`, err);
});

// ---------- API endpoints ----------

// public quote endpoint (live)
app.get('/api/quote', async (req, res) => {
  try {
    const crypto = (req.query.crypto || 'btc').toLowerCase();
    const quote = await getQuoteForCrypto(crypto);
    res.json({ success: true, quote });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// admin: login -> JWT
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username = 'admin', password } = req.body;
    const row = db.prepare('SELECT * FROM admin WHERE username = ?').get(username);
    if (!row) return res.status(401).json({ success: false, error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ success: false, error: 'Invalid credentials' });
    const token = jwt.sign({ username }, ADMIN_JWT_SECRET, { expiresIn: '8h' });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// middleware to verify admin JWT
function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return res.status(401).json({ success: false, error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, ADMIN_JWT_SECRET);
    req.admin = payload;
    next();
  } catch (e) {
    res.status(401).json({ success: false, error: 'Invalid token' });
  }
}

// get manual rates
app.get('/api/rates', async (req, res) => {
  try {
    const rates = readAllManualRates();
    res.json({ success: true, rates });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// update manual rates (admin only)
app.post('/api/rates', requireAdmin, async (req, res) => {
  try {
    const incoming = req.body || {};
    ['btc', 'eth', 'usdt'].forEach(sym => {
      const r = incoming[sym];
      if (r && (r.usd != null || r.ngn != null)) {
        const usd = (r.usd != null) ? Number(r.usd) : null;
        const ngn = (r.ngn != null) ? Number(r.ngn) : null;
        saveManualRate(sym, usd, ngn);
      }
    });
    const saved = readAllManualRates();
    res.json({ success: true, rates: saved });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// get/set margin (admin)
app.get('/api/settings/margin', requireAdmin, (req, res) => {
  const margin = getMargin();
  res.json({ success: true, margin });
});
app.post('/api/settings/margin', requireAdmin, (req, res) => {
  const { margin } = req.body;
  const m = Number(margin);
  if (isNaN(m) || m < 0 || m > 1) return res.status(400).json({ success: false, error: 'margin must be a number between 0 and 1' });
  setSetting('margin', m);
  res.json({ success: true, margin: m });
});

// list orders (admin)
app.get('/api/orders', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM orders ORDER BY id DESC').all();
  res.json({ success: true, orders: rows });
});

// create order (public) - server recalculates amounts and validates
app.post('/api/order', async (req, res) => {
  try {
    const { type = 'sell', crypto = 'btc', cryptoAmount, fiatAmount, name, whatsappNumber } = req.body;
    if (!whatsappNumber) return res.status(400).json({ success: false, error: 'whatsappNumber required' });

    const quote = await getQuoteForCrypto(crypto);
    const buyNgn = Number(quote.buy.ngn);
    const sellNgn = Number(quote.sell.ngn);

    let fiat = fiatAmount;
    let cryptoAmt = cryptoAmount;

    if (type === 'buy') {
      if (cryptoAmt && !fiat) fiat = Number(cryptoAmt) * buyNgn;
      else if (fiat && !cryptoAmt) cryptoAmt = Number(fiat) / buyNgn;
    } else {
      if (cryptoAmt && !fiat) fiat = Number(cryptoAmt) * sellNgn;
      else if (fiat && !cryptoAmt) cryptoAmt = Number(fiat) / sellNgn;
    }

    if (!fiat || !cryptoAmt) return res.status(400).json({ success: false, error: 'cryptoAmount or fiatAmount required' });

    const cryptoRounded = Number(Number(cryptoAmt).toFixed(8));
    const fiatRounded = Number(Number(fiat).toFixed(2));

    const recomputedFiat = (type === 'buy') ? cryptoRounded * buyNgn : cryptoRounded * sellNgn;
    if (Math.abs(recomputedFiat - fiatRounded) / Math.max(1, recomputedFiat) > 0.001) {
      return res.status(400).json({ success: false, error: 'Price mismatch - please refresh and try again' });
    }

    const order = {
      id: `forangex_ord_${Date.now()}`,
      created_at: new Date().toISOString(),
      type,
      crypto,
      cryptoAmount: cryptoRounded,
      fiatAmount: fiatRounded,
      name: name || '',
      whatsappNumber,
      status: 'pending',
      rate_source: quote.source,
      rate_used: { base: quote.base, buy: quote.buy, sell: quote.sell, margin: quote.margin }
    };

    saveOrderToDb(order);

    const waId = toWhatsappId(whatsappNumber);
    const priceUsed = (type === 'buy') ? quote.buy.ngn : quote.sell.ngn;
    const bodyMessage = `Hello ${order.name || ''}.
This is ${APP_NAME}.
Your order ${order.id} is pending.
${order.type.toUpperCase()}: ${order.cryptoAmount} ${order.crypto} → ₦${order.fiatAmount.toLocaleString()}
Rate used: ₦${Number(priceUsed).toLocaleString()} per ${order.crypto} (source: ${quote.source}, margin ${Math.round(quote.margin*100)}%).
We will contact you here on WhatsApp with payment instructions.`;

    try {
      await waClient.sendMessage(waId, bodyMessage);
      console.log(`[${APP_NAME}] Sent order confirmation to ${whatsappNumber}`);
    } catch (e) {
      console.warn(`[${APP_NAME}] Failed to send WhatsApp message to ${whatsappNumber}:`, e.message);
    }

    res.json({ success: true, order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// WhatsApp status
app.get('/api/wa-status', (req, res) => {
  res.json({ ready: waClient.info && waClient.info.wid ? true : false });
});

// Socket.io
io.on('connection', (socket) => {
  console.log(`[${APP_NAME}] socket connected`, socket.id);

  socket.on('join', (data) => {
    if (!data || !data.whatsappNumber) return;
    const phone = data.whatsappNumber.startsWith('+') ? data.whatsappNumber : '+' + data.whatsappNumber.replace(/\D/g, '');
    phoneToSocket.set(phone, socket.id);
    socketToPhone.set(socket.id, phone);
    console.log(`[${APP_NAME}] Mapped ${phone} -> ${socket.id}`);
  });

  socket.on('send_message', async (data) => {
    try {
      let phone = data.whatsappNumber;
      if (!phone) phone = socketToPhone.get(socket.id);
      if (!phone) {
        socket.emit('error', { error: 'whatsappNumber not provided and not joined' });
        return;
      }
      const text = data.text || '';
      const waId = toWhatsappId(phone);
      try {
        await waClient.sendMessage(waId, text);
      } catch (e) {
        socket.emit('error', { error: 'Failed to send message via WhatsApp: ' + e.message });
        return;
      }
      socket.emit('outgoing', { to: phone, body: text, sent_at: new Date().toISOString() });
    } catch (err) {
      console.error('send_message error', err);
      socket.emit('error', { error: err.message });
    }
  });

  socket.on('disconnect', () => {
    const phone = socketToPhone.get(socket.id);
    if (phone) {
      phoneToSocket.delete(phone);
      socketToPhone.delete(socket.id);
      console.log(`[${APP_NAME}] Socket ${socket.id} disconnected - removed mapping for ${phone}`);
    } else {
      console.log(`[${APP_NAME}] Socket disconnected`, socket.id);
    }
  });
});

server.listen(PORT, () => {
  console.log(`${APP_NAME} server listening on port ${PORT}`);
  console.log(`Open http://localhost:${PORT}`);
});
