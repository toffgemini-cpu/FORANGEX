```markdown
# FORANGEX - Crypto ↔ NGN exchange (WhatsApp Web backend)

This is a demo implementation of FORANGEX:
- Live prices (CoinGecko fallback)
- Manual admin rates for BTC/ETH/USDT (USD + NGN)
- Automatic platform margin (editable from admin UI)
- Orders persisted in SQLite
- WhatsApp messaging via whatsapp-web.js (scan QR once)
- Web UI: order flow + chat; Admin UI for rates, margin, orders

Important:
- This uses WhatsApp Web (unofficial). Use for small/personal testing only; Meta may restrict accounts used with automated clients. For production use the official WhatsApp Business API provider.
- Do NOT commit `.wwebjs_auth/`, `.env`, SQLite DB or the session files. `.gitignore` is provided.

Quick start
1. Install:
   npm install

2. Create .env from .env.example and set values (ADMIN_PASSWORD is required for admin login).
   cp .env.example .env
   # Edit .env

3. Start:
   npm start

4. On first run you'll see a QR in terminal (or in the web UI). Scan with WhatsApp:
   WhatsApp -> Linked devices -> Link a device -> scan QR.

5. Open http://localhost:3000
   - Use the live price widget and order form to get automatic NGN/crypto calculations (10% margin default).
   - Admin: open /admin.html to login and set rates and margin, and view orders.

DB & files
- SQLite DB: data/forangex.db (auto-created)
- Orders and rates are persisted to the DB.
- settings.json is not required; margin is stored in DB.

Security & next steps
- Add HTTPS, input sanitization, logging, and rate limiting before going public.
- Add stronger admin auth (2FA or integrate OAuth) if used by real admins.
- Consider migrating to Postgres and add role-based access, audit logs.
- For production messaging use WhatsApp Business API + webhook signature validation.

If you'd like, I can:
- push these files into repo once you create the remote, or
- provide a zip/patch for local application.
```