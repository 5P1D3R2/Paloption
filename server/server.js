// paloption.site API - same fair odds for demo and real accounts.
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
const ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
app.use((req, res, next) => {
  const o = req.headers.origin;
  if (o && (ORIGINS.includes(o) || ORIGINS.includes('*'))) {
    res.setHeader('Access-Control-Allow-Origin', o);
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json());
app.use(express.static(__dirname));

const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const RTP = 0.976;              // payout multiplier = RTP / win probability (same for every contract)
const users = new Map();        // in-memory; swap for MongoDB in production

// ---------- markets ----------
const DEFS = [
  ['R_10_1s', 'Volatility 10 (1s) Index', 'Vol 10 (1s)', 10, 1, 9500],
  ['R_10', 'Volatility 10 Index', 'Vol 10', 10, 2, 6200],
  ['R_15_1s', 'Volatility 15 (1s) Index', 'Vol 15 (1s)', 15, 1, 3300],
  ['R_25_1s', 'Volatility 25 (1s) Index', 'Vol 25 (1s)', 25, 1, 2100],
  ['R_25', 'Volatility 25 Index', 'Vol 25', 25, 2, 5400],
  ['R_30_1s', 'Volatility 30 (1s) Index', 'Vol 30 (1s)', 30, 1, 1200],
  ['R_50_1s', 'Volatility 50 (1s) Index', 'Vol 50 (1s)', 50, 1, 7800],
  ['R_50', 'Volatility 50 Index', 'Vol 50', 50, 2, 4100],
  ['R_75_1s', 'Volatility 75 (1s) Index', 'Vol 75 (1s)', 75, 1, 3900],
  ['R_75', 'Volatility 75 Index', 'Vol 75', 75, 2, 640],
  ['R_90_1s', 'Volatility 90 (1s) Index', 'Vol 90 (1s)', 90, 1, 8800],
  ['R_100_1s', 'Volatility 100 (1s) Index', 'Vol 100 (1s)', 100, 1, 5200],
  ['R_100', 'Volatility 100 Index', 'Vol 100', 100, 2, 2300]
];
const SYMS = DEFS.map(([id, name, short, vol, sec, base]) => ({ id, name, short, vol, sec, price: base, step: base * vol * 0.00004, ticks: [] }));
const bySym = Object.fromEntries(SYMS.map(s => [s.id, s]));
function makeTick(s, t) {
  s.price = Math.max(10, s.price + (crypto.randomInt(-1000, 1001) / 1000) * s.step);
  const digit = crypto.randomInt(0, 10);   // fair, independent digit for every tick
  return { price: +(Math.floor(s.price * 10) / 10 + digit / 100).toFixed(2), digit, t, sym: s.id };
}
const push = (s, t) => { s.ticks.push(t); if (s.ticks.length > 500) s.ticks.shift(); };
SYMS.forEach(s => { const now = Date.now(); for (let i = 500; i > 0; i--) push(s, makeTick(s, now - i * s.sec * 1000)); });
let beat = 0;
setInterval(() => { beat++; SYMS.forEach(s => { if (s.sec === 1 || beat % 2 === 0) push(s, makeTick(s, Date.now())); }); }, 1000);
const pickSym = q => bySym[q] || SYMS[0];

// ---------- auth ----------
function auth(req, res, next) {
  try {
    const d = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    req.user = users.get(d.email);
    if (!req.user) throw 0;
    next();
  } catch { res.status(401).json({ error: 'Unauthorized' }); }
}
const pub = u => ({ name: u.name, email: u.email, demo: +u.demo.toFixed(2), real: +u.real.toFixed(2), history: u.history.slice(0, 100), tx: (u.tx || []).slice(0, 50) });

app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !/^\S+@\S+\.\S+$/.test(email || '') || (password || '').length < 6)
    return res.status(400).json({ error: 'Check your details (password min 6 chars)' });
  if (users.has(email.toLowerCase())) return res.status(409).json({ error: 'Email already registered' });
  const u = { name, email: email.toLowerCase(), hash: await bcrypt.hash(password, 10), demo: 10000, real: 0, history: [], tx: [] };
  users.set(u.email, u);
  res.json({ token: jwt.sign({ email: u.email }, SECRET, { expiresIn: '7d' }), user: pub(u) });
});
app.post('/api/login', async (req, res) => {
  const u = users.get(((req.body || {}).email || '').toLowerCase());
  if (!u || !(await bcrypt.compare(req.body.password || '', u.hash))) return res.status(401).json({ error: 'Invalid email or password' });
  res.json({ token: jwt.sign({ email: u.email }, SECRET, { expiresIn: '7d' }), user: pub(u) });
});
app.post('/api/account/name', auth, (req, res) => {
  const n = String((req.body || {}).name || '').trim().slice(0, 60);
  if (n.length < 2) return res.status(400).json({ error: 'Name too short' });
  req.user.name = n; res.json({ user: pub(req.user) });
});
app.post('/api/account/password', auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!(await bcrypt.compare(oldPassword || '', req.user.hash))) return res.status(401).json({ error: 'Current password is wrong' });
  if ((newPassword || '').length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
  req.user.hash = await bcrypt.hash(newPassword, 10); res.json({ ok: true });
});
app.get('/api/me', auth, (req, res) => res.json(pub(req.user)));

// ---------- market data ----------
app.get('/api/symbols', (req, res) => res.json(SYMS.map(({ id, name, short }) => ({ id, name, short }))));
app.get('/api/tick', (req, res) => { const s = pickSym(req.query.symbol); res.json(s.ticks[s.ticks.length - 1]); });
app.get('/api/ticks', (req, res) => res.json(pickSym(req.query.symbol).ticks));
app.get('/api/odds', (req, res) => res.json({ rtp: RTP, note: 'Same odds for demo and real accounts.' }));

// ---------- trading ----------
function contract(kind, pick, digit) {
  const b = Number(digit);
  if (kind === 'eo' && (pick === 'even' || pick === 'odd'))
    return { p: 0.5, label: pick === 'even' ? 'Even' : 'Odd', win: d => (d % 2 === 0) === (pick === 'even') };
  if (kind === 'ou' && Number.isInteger(b)) {
    if (pick === 'over' && b >= 0 && b <= 8) return { p: (9 - b) / 10, label: 'Over ' + b, win: d => d > b };
    if (pick === 'under' && b >= 1 && b <= 9) return { p: b / 10, label: 'Under ' + b, win: d => d < b };
  }
  if (kind === 'md' && Number.isInteger(b) && b >= 0 && b <= 9) {
    if (pick === 'match') return { p: 0.1, label: 'Match ' + b, win: d => d === b };
    if (pick === 'differ') return { p: 0.9, label: 'Differ ' + b, win: d => d !== b };
  }
  return null;
}
app.post('/api/trade', auth, (req, res) => {
  const { account, stake, kind, pick, digit, symbol } = req.body || {};
  const s = Math.round(Number(stake) * 100) / 100;
  const c = contract(kind, pick, digit);
  if (!['demo', 'real'].includes(account) || !c || !(s >= 0.1 && s <= 100))
    return res.status(400).json({ error: 'Invalid trade (stake $0.10 - $100)' });
  const u = req.user;
  if (u[account] < s) return res.status(400).json({ error: 'Insufficient balance' });
  const sy = pickSym(symbol);
  const tick = makeTick(sy, Date.now()); push(sy, tick);
  const win = c.win(tick.digit);
  const payoutIfWin = +(s * RTP / c.p).toFixed(4);
  const balStake = +(u[account] - s).toFixed(4);
  const payout = win ? payoutIfWin : 0;
  u[account] = +(balStake + payout).toFixed(4);
  const profit = +(payout - s).toFixed(4);
  u.history.unshift({ id: crypto.randomUUID(), account, sym: sy.id, kind, label: c.label, stake: s, potential: payoutIfWin, payout, profit, win, digit: tick.digit, balStake, balAfter: u[account], t: tick.t });
  if (u.history.length > 300) u.history.pop();
  res.json({ win, profit, digit: tick.digit, tick, user: pub(u) });
});

// ---------- TinyPesa deposits (M-Pesa STK push) ----------
// Env: TINYPESA_API_KEY, TINYPESA_SLUG (sent as account_no), TINYPESA_TARGET (optional TinyPesa endpoint URL),
//      WEBHOOK_SECRET, KES_PER_USD (default 129).  TINYPESA_ACCOUNT_NO still works as a fallback for TINYPESA_SLUG.
// TinyPesa callback URL: https://YOUR-SERVER/api/tinypesa/callback/<WEBHOOK_SECRET>
const KES_PER_USD = Number(process.env.KES_PER_USD || 129);
const DEFAULT_TARGET = 'https://tinypesa.com/api/v1/express/initialize';
const T = (process.env.TINYPESA_TARGET || '').trim();
// Only accept TINYPESA_TARGET as the API endpoint if it is a tinypesa.com URL; otherwise use the default.
const TINYPESA_URL = /^https:\/\/([a-z0-9-]+\.)*tinypesa\.com\//i.test(T) ? T : DEFAULT_TARGET;
if (T && TINYPESA_URL === DEFAULT_TARGET) console.log('TINYPESA_TARGET is not a tinypesa.com URL, using the default endpoint');
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const deposits = new Map();
const seenReceipts = new Set();
const normPhone = p => { p = String(p || '').replace(/\D/g, ''); if (/^0[17]\d{8}$/.test(p)) p = '254' + p.slice(1); else if (/^[17]\d{8}$/.test(p)) p = '254' + p; return /^254[17]\d{8}$/.test(p) ? p : null; };

app.post('/api/deposit/mpesa', auth, async (req, res) => {
  if (!process.env.TINYPESA_API_KEY) return res.status(501).json({ error: 'TinyPesa not configured (set TINYPESA_API_KEY)' });
  const usd = Number(req.body.amount), phone = normPhone(req.body.phone);
  if (!(usd >= 1 && usd <= 1900)) return res.status(400).json({ error: 'Amount must be $1 - $1,900' });
  if (!phone) return res.status(400).json({ error: 'Enter a valid Safaricom number' });
  const kes = Math.ceil(usd * KES_PER_USD);
  const id = crypto.randomUUID();
  try {
    const r = await fetch(TINYPESA_URL, {
      method: 'POST',
      headers: { Apikey: process.env.TINYPESA_API_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ amount: String(kes), msisdn: phone, account_no: process.env.TINYPESA_SLUG || process.env.TINYPESA_ACCOUNT_NO || id }).toString()
    });
    const raw = await r.text();
    let j = {}; try { j = JSON.parse(raw); } catch {}
    console.log('TinyPesa initialize ->', r.status, new URL(TINYPESA_URL).pathname, raw.slice(0, 300));
    if (!r.ok || j.success === false || j.success === 'false') {
      const why = j.message || j.error || (Array.isArray(j.errors) ? j.errors.join(', ') : j.errors) || raw.slice(0, 120).replace(/<[^>]*>/g, '').trim();
      return res.status(502).json({ error: 'TinyPesa (' + r.status + '): ' + (why || 'no details') });
    }
    deposits.set(id, { email: req.user.email, usd, kes, phone, status: 'pending', requestId: j.request_id || null, t: Date.now() });
    res.json({ id, kes });
  } catch (e) { console.log('TinyPesa request failed:', e.message); res.status(502).json({ error: 'Payment provider unreachable' }); }
});
app.get('/api/deposit/status/:id', auth, (req, res) => {
  const d = deposits.get(req.params.id);
  if (!d || d.email !== req.user.email) return res.status(404).json({ error: 'Not found' });
  res.json({ status: d.status, user: pub(req.user) });
});
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
  for (const [, d] of deposits) {
    if (d.status !== 'pending') continue;
    if ((reqId && d.requestId === reqId) || (!reqId && d.phone === phone && d.kes === amount)) { hit = d; break; }
  }
  if (!hit) return;
  if (Number(code) !== 0) { hit.status = 'failed'; return; }
  if (amount && amount < hit.kes) { hit.status = 'failed'; return; }
  if (receipt && seenReceipts.has(receipt)) return;
  if (receipt) seenReceipts.add(receipt);
  const u = users.get(hit.email);
  if (u) { u.real = +(u.real + hit.usd).toFixed(4); hit.status = 'paid'; u.tx.unshift({ type: 'Deposit (M-Pesa)', usd: hit.usd, t: Date.now() }); }
});
app.post('/api/withdraw/mpesa', auth, (req, res) => res.status(501).json({ error: 'Withdrawals not configured yet.' }));

const INDEX = path.join(__dirname, 'index.html');
app.get('/', (req, res) => fs.existsSync(INDEX) ? res.sendFile(INDEX) : res.json({ ok: true, service: 'paloption.site API' }));
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api/') && fs.existsSync(INDEX)) return res.sendFile(INDEX);
  res.status(404).json({ error: 'Not found' });
});
app.listen(process.env.PORT || 3000, () => console.log('paloption.site running'));
