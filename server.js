'use strict';
require('dotenv').config();
const express = require('express');
const fetch   = require('node-fetch');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID      = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET  = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI   = process.env.DISCORD_REDIRECT_URI || `http://localhost:${PORT}/auth/callback`;
const OWNER_IDS      = (process.env.OWNER_IDS || '').split(',').map(s => s.trim()).filter(Boolean);
const BOT_API_URL    = (process.env.BOT_API_URL || '').replace(/\/$/, '');
const BOT_API_SECRET = process.env.BOT_API_SECRET || '';
const TOKEN_SECRET   = process.env.JWT_SECRET || process.env.SESSION_SECRET || 'snx_fallback_set_SESSION_SECRET';
const TOKEN_TTL      = 24 * 60 * 60;

const HTML_PATH = path.join(__dirname, 'public', 'index.html');
function getHTML() {
  try   { return fs.readFileSync(HTML_PATH, 'utf8'); }
  catch { return '<h1>index.html not found in public/</h1>'; }
}

app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── HMAC signed token (stateless, survives Render restarts) ──────────────────
function signToken(data) {
  const payload = Buffer.from(
    JSON.stringify({ ...data, exp: Math.floor(Date.now() / 1000) + TOKEN_TTL })
  ).toString('base64url');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function verifyToken(token) {
  try {
    const dot = (token || '').lastIndexOf('.');
    if (dot < 1) return null;
    const payload  = token.slice(0, dot);
    const sig      = token.slice(dot + 1);
    const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
    if (sig.length !== expected.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (data.exp && data.exp < Math.floor(Date.now() / 1000)) return null;
    return data;
  } catch { return null; }
}

// ── One-time exchange code store ──────────────────────────────────────────────
// FIX for HTTP 414: the full guilds array is too large for a URL.
// After OAuth we store the signed token behind a short 64-char code.
// The browser receives /?snx_code=CODE (tiny URL), calls GET /api/exchange?c=CODE,
// gets the real token back, saves it in localStorage, cleans the URL.
// Codes expire after 2 minutes and are deleted on first use.
const exchangeCodes = new Map();
function createExchangeCode(tokenString) {
  const code = crypto.randomBytes(32).toString('hex');
  exchangeCodes.set(code, { token: tokenString, ts: Date.now() });
  for (const [k, v] of exchangeCodes.entries())
    if (Date.now() - v.ts > 2 * 60 * 1000) exchangeCodes.delete(k);
  return code;
}
function consumeExchangeCode(code) {
  const entry = exchangeCodes.get(code);
  if (!entry) return null;
  exchangeCodes.delete(code);
  if (Date.now() - entry.ts > 2 * 60 * 1000) return null;
  return entry.token;
}

// ── Auth guard ────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth  = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  const data  = token ? verifyToken(token) : null;
  if (!data) return res.status(401).json({ error: 'Not authenticated' });
  req.auth = data;
  next();
}

// ── Bot API proxy ─────────────────────────────────────────────────────────────
async function botApi(apiPath, body, method) {
  if (!BOT_API_URL || !BOT_API_SECRET) return null;
  try {
    const opts = {
      method:  method || (body ? 'POST' : 'GET'),
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + BOT_API_SECRET },
    };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(BOT_API_URL + apiPath, opts);
    if (!r.ok) return null;
    return r.json();
  } catch (e) {
    console.error('[Dashboard] Bot API error:', e.message);
    return null;
  }
}

// ── Discord OAuth ─────────────────────────────────────────────────────────────
app.get('/auth/login', (req, res) => {
  const prompt = req.query.switch === '1' ? 'consent' : 'none';
  const p = new URLSearchParams({
    client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
    response_type: 'code', scope: 'identify guilds', prompt,
  });
  res.redirect('https://discord.com/api/oauth2/authorize?' + p);
});

app.get('/auth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.send(`<h2>Discord error: ${error}</h2><a href="/">Back</a>`);
  if (!code)  return res.send('<h2>No code from Discord</h2><a href="/">Back</a>');
  try {
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
        grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI,
      }),
    });
    const t = await tokenRes.json();
    if (!t.access_token)
      return res.send(`<h2>Token exchange failed</h2><pre>${JSON.stringify(t,null,2)}</pre><a href="/">Back</a>`);

    const [u, guilds] = await Promise.all([
      fetch('https://discord.com/api/users/@me',        { headers: { Authorization: 'Bearer ' + t.access_token } }).then(r => r.json()),
      fetch('https://discord.com/api/users/@me/guilds', { headers: { Authorization: 'Bearer ' + t.access_token } }).then(r => r.json()),
    ]);

    const fullToken = signToken({
      user:   { id: u.id, username: u.username, avatar: u.avatar },
      guilds: Array.isArray(guilds) ? guilds : [],
    });

    // Short code in URL (64 chars) — no more HTTP 414
    const xcode = createExchangeCode(fullToken);
    res.redirect(`/?snx_code=${xcode}`);
  } catch (e) {
    res.send(`<h2>OAuth crash: ${e.message}</h2><a href="/">Back</a>`);
  }
});

// Browser calls this to swap the short code for the real session token
app.get('/api/exchange', (req, res) => {
  const token = consumeExchangeCode((req.query.c || '').trim());
  if (!token) return res.status(400).json({ error: 'Invalid or expired code — please log in again.' });
  res.json({ token });
});

app.get('/auth/logout', (req, res) => {
  const sw = req.query.switch === '1' ? '&switch=1' : '';
  res.redirect(`/?logout=1${sw}`);
});

// ── API ───────────────────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, (req, res) =>
  res.json({ user: req.auth.user, isOwner: OWNER_IDS.includes(req.auth.user.id) })
);
app.get('/api/guilds', requireAuth, async (req, res) => {
  const uid  = req.auth.user.id;
  const isGO = OWNER_IDS.includes(uid);
  const checks = await Promise.all(
    (req.auth.guilds || []).map(async g => {
      const r = await botApi('/guild-access', { guild_id: g.id, user_id: uid, is_owner: isGO });
      return r?.allowed ? { id: g.id, name: g.name, icon: g.icon } : null;
    })
  );
  res.json(checks.filter(Boolean));
});
app.get ('/api/guild/:gid',                        requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}`) || { prefix:'!', warnings:0, modcases:0, antinuke_enabled:false, automod_enabled:false }); });
app.post('/api/guild/:gid/prefix',                 requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/prefix`, req.body) || { error:'Bot API unreachable' }); });
app.get ('/api/guild/:gid/welcome',                requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/welcome`) || {}); });
app.post('/api/guild/:gid/welcome',                requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/welcome`, req.body) || { error:'Bot API unreachable' }); });
app.get ('/api/guild/:gid/leave',                  requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/leave`) || {}); });
app.post('/api/guild/:gid/leave',                  requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/leave`, req.body) || { error:'Bot API unreachable' }); });
app.get ('/api/guild/:gid/logging',                requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/logging`) || {}); });
app.post('/api/guild/:gid/logging',                requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/logging`, req.body) || { error:'Bot API unreachable' }); });
app.get ('/api/guild/:gid/automod',                requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/automod`) || {}); });
app.post('/api/guild/:gid/automod',                requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/automod`, req.body) || { error:'Bot API unreachable' }); });
app.get ('/api/guild/:gid/antinuke',               requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/antinuke`) || {}); });
app.post('/api/guild/:gid/antinuke',               requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/antinuke`, req.body) || { error:'Bot API unreachable' }); });
app.get ('/api/guild/:gid/leveling',               requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/leveling`) || {}); });
app.post('/api/guild/:gid/leveling',               requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/leveling`, req.body) || { error:'Bot API unreachable' }); });
app.get ('/api/guild/:gid/tickets',                requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/tickets`) || {}); });
app.post('/api/guild/:gid/tickets',                requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/tickets`, req.body) || { error:'Bot API unreachable' }); });
app.get ('/api/guild/:gid/moderation',             requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/moderation`) || { warnings:[], cases:[] }); });
app.get ('/api/guild/:gid/permits',                requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/permits`) || { perms:[], permits:[] }); });
app.post('/api/guild/:gid/permits/add',            requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/permits/add`, req.body) || { error:'Bot API unreachable' }); });
app.post('/api/guild/:gid/permits/remove',         requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/permits/remove`, req.body) || { error:'Bot API unreachable' }); });
app.get ('/api/guild/:gid/joinrole',               requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/joinrole`) || []); });
app.post('/api/guild/:gid/joinrole/add',           requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/joinrole/add`, req.body) || { error:'Bot API unreachable' }); });
app.post('/api/guild/:gid/joinrole/remove',        requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/joinrole/remove`, req.body) || { error:'Bot API unreachable' }); });
app.get ('/api/guild/:gid/autoresponder',          requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/autoresponder`) || []); });
app.get ('/api/guild/:gid/permit-groups',          requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/permit-groups`) || { groups:[], perms:[] }); });
app.post('/api/guild/:gid/permit-groups/save',     requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/permit-groups/save`, req.body) || { error:'Bot API unreachable' }); });
app.post('/api/guild/:gid/permit-groups/delete',   requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/permit-groups/delete`, req.body) || { error:'Bot API unreachable' }); });
app.post('/api/guild/:gid/permit-groups/set-perm', requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/permit-groups/set-perm`, req.body) || { error:'Bot API unreachable' }); });
app.get ('/api/guild/:gid/music-state',            requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/music-state`) || { in_vc:false, queue:[] }); });
app.post('/api/guild/:gid/music-cmd',              requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/music-cmd`, req.body) || { error:'Bot API unreachable' }); });
app.post('/api/guild/:gid/music-search',           requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/music-search`, req.body) || { error:'Bot API unreachable' }); });
app.get ('/api/guild/:gid/music-search',           requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/music-search`) || { ready:false, results:[] }); });
app.get ('/api/guild/:gid/vc-list',                requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/vc-list`) || []); });
app.get ('/api/guild/:gid/overview-extra',         requireAuth, async (req,res) => { res.json(await botApi(`/guild/${req.params.gid}/overview-extra`) || {}); });

app.get('/ping', (req, res) => res.json({ status: 'ok', ts: Date.now() }));
app.get('*',     (req, res) => res.send(getHTML()));

app.listen(PORT, '0.0.0.0', () => {
  console.log('[Dashboard] Running on port', PORT);
  const selfUrl = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
  setInterval(async () => {
    try   { await fetch(selfUrl + '/ping'); console.log('[Dashboard] Self-ping ok'); }
    catch (e) { console.log('[Dashboard] Self-ping failed:', e.message); }
  }, 14 * 60 * 1000);
});
