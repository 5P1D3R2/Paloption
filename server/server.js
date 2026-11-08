// paloption.site - demo/real Even-Odd game. Same fair odds on both accounts.
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(__dirname));

const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const PAYOUT = 1.952;          // pays 1.952x on a 50% chance (disclosed in the UI)
const WIN_CHANCE = 0.5;
const users = new Map();       // in-memory; swap for MongoDB in production

let price = 9500;
function nextTick() {
  price += (crypto.randomInt(-100, 101) / 100) * 4;
  const digit = crypto.randomInt(0, 10);
  const p = Math.floor(price * 10) / 10 + digit / 100;
  return { price: +p.toFixed(2), digit, t: Date.now() };
}
let lastTick = nextTick();
setInterval(() => { lastTick = nextTick(); }, 1000);

function auth(req, res, next) {
  try {
    const d = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    req.user = users.get(d.email);
    if (!req.user) throw 0;
    next();
  } catch { res.status(401).json({ error: 'Unauthorized' }); }
}
const pub = u => ({ name: u.name, email: u.email, demo: +u.demo.toFixed(2), real: +u.real.toFixed(2), history: u.history.slice(0, 50) });

app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !/^\S+@\S+\.\S+$/.test(email || '') || (password || '').length < 6)
    return res.status(400).json({ error: 'Check your details (password min 6 chars)' });
  if (users.has(email.toLowerCase())) return res.status(409).json({ error: 'Email already registered' });
  const u = { name, email: email.toLowerCase(), hash: await bcrypt.hash(password, 10), demo: 10000, real: 0, history: [] };
  users.set(u.email, u);
  res.json({ token: jwt.sign({ email: u.email }, SECRET, { expiresIn: '7d' }), user: pub(u) });
});

app.post('/api/login', async (req, res) => {
  const u = users.get(((req.body || {}).email || '').toLowerCase());
  if (!u || !(await bcrypt.compare(req.body.password || '', u.hash))) return res.status(401).json({ error: 'Invalid email or password' });
  res.json({ token: jwt.sign({ email: u.email }, SECRET, { expiresIn: '7d' }), user: pub(u) });
});

app.get('/api/me', auth, (req, res) => res.json(pub(req.user)));
app.get('/api/tick', (req, res) => res.json(lastTick));
app.get('/api/odds', (req, res) => res.json({ winChance: WIN_CHANCE, payout: PAYOUT, note: 'Same odds for demo and real accounts.' }));

app.post('/api/trade', auth, (req, res) => {
  const { account, stake, pick } = req.body || {};
  const s = Number(stake);
  if (!['demo', 'real'].includes(account) || !['even', 'odd'].includes(pick) || !(s >= 1 && s <= 100))
    return res.status(400).json({ error: 'Invalid trade (stake $1-$100)' });
  const u = req.user;
  if (u[account] < s) return res.status(400).json({ error: 'Insufficient balance' });
  const tick = nextTick(); lastTick = tick;
  const win = (tick.digit % 2 === 0) === (pick === 'even');
  const profit = win ? +(s * PAYOUT - s).toFixed(2) : -s;
  u[account] = +(u[account] + profit).toFixed(2);
  u.history.unshift({ account, pick, stake: s, digit: tick.digit, win, profit, t: Date.now() });
  res.json({ win, profit, digit: tick.digit, tick, user: pub(u) });
});

// Payments: integrate M-Pesa (Daraja STK push) here. Credit only on the verified callback.
// ---------- TinyPesa deposits (M-Pesa STK push) ----------
// Env vars: TINYPESA_API_KEY, TINYPESA_ACCOUNT_NO, WEBHOOK_SECRET, KES_PER_USD (default 129)
// In your TinyPesa dashboard set the callback URL to:
//   https://paloption.site/api/tinypesa/callback/<WEBHOOK_SECRET>
const KES_PER_USD = Number(process.env.KES_PER_USD || 129);
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const deposits = new Map();     // id -> {email, usd, kes, phone, status, requestId}
const seenReceipts = new Set(); // idempotency

const normPhone = p => { p = String(p || '').replace(/\D/g, ''); if (/^0[17]\d{8}$/.test(p)) p = '254' + p.slice(1); else if (/^[17]\d{8}$/.test(p)) p = '254' + p; return /^254[17]\d{8}$/.test(p) ? p : null; };

app.post('/api/deposit/mpesa', auth, async (req, res) => {
  if (!process.env.TINYPESA_API_KEY) return res.status(501).json({ error: 'TinyPesa not configured (set TINYPESA_API_KEY)' });
  const usd = Number(req.body.amount), phone = normPhone(req.body.phone);
  if (!(usd >= 1 && usd <= 1900)) return res.status(400).json({ error: 'Amount must be $1 - $1,900' });
  if (!phone) return res.status(400).json({ error: 'Enter a valid Safaricom number' });
  const kes = Math.ceil(usd * KES_PER_USD);
  const id = crypto.randomUUID();
  try {
    const r = await fetch('https://tinypesa.com/api/v1/express/initialize', {
      method: 'POST',
      headers: { Apikey: process.env.TINYPESA_API_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ amount: String(kes), msisdn: phone, account_no: process.env.TINYPESA_ACCOUNT_NO || id }).toString()
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.success === false) return res.status(502).json({ error: j.message || 'Could not start payment' });
    deposits.set(id, { email: req.user.email, usd, kes, phone, status: 'pending', requestId: j.request_id || null, t: Date.now() });
    res.json({ id, kes });
  } catch (e) { res.status(502).json({ error: 'Payment provider unreachable' }); }
});

app.get('/api/deposit/status/:id', auth, (req, res) => {
  const d = deposits.get(req.params.id);
  if (!d || d.email !== req.user.email) return res.status(404).json({ error: 'Not found' });
  res.json({ status: d.status, user: pub(req.user) });
});

// Callback format: handles Daraja-style (Body.stkCallback) and flat payloads. Check a real
// callback in your TinyPesa dashboard/logs and adjust field names if needed.
app.post('/api/tinypesa/callback/:secret', (req, res) => {
  res.sendStatus(200);
  if (!WEBHOOK_SECRET || req.params.secret !== WEBHOOK_SECRET) return;
  const b = req.body || {}, cb = (b.Body && b.Body.stkCallback) || b;
  const items = Object.fromEntries(((cb.CallbackMetadata || {}).Item || []).map(i => [i.Name, i.Value]));
  const code = cb.ResultCode ?? cb.result_code ?? (String(b.status || '').toLowerCase() === 'success' ? 0 : 1);
  const reqId = cb.CheckoutRequestID || cb.request_id || b.request_id || b.TinyPesaID || null;
  const phone = String(items.PhoneNumber || cb.Msisdn || b.msisdn || '');
  const amount = Number(items.Amount ?? cb.Amount ?? b.amount);
  const receipt = items.MpesaReceiptNumber || cb.MpesaReceiptNumber || b.mpesa_receipt || reqId;
  let hit = null;
  for (const [id, d] of deposits) {
    if (d.status !== 'pending') continue;
    if ((reqId && d.requestId === reqId) || (!reqId && d.phone === phone && d.kes === amount)) { hit = d; break; }
  }
  if (!hit) return;
  if (Number(code) !== 0) { hit.status = 'failed'; return; }
  if (amount && amount < hit.kes) { hit.status = 'failed'; return; }
  if (receipt && seenReceipts.has(receipt)) return;
  if (receipt) seenReceipts.add(receipt);
  const u = users.get(hit.email);
  if (u) { u.real = +(u.real + hit.usd).toFixed(2); hit.status = 'paid'; }
});

app.post('/api/withdraw/mpesa', auth, (req, res) => res.status(501).json({ error: 'Withdrawals not configured yet.' }));

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.listen(process.env.PORT || 3000, () => console.log('paloption.site running'));
