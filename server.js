'use strict';
require('dotenv').config();
const express  = require('express');
const session  = require('express-session');
const fetch    = require('node-fetch');
const path     = require('path');
const fs       = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID      = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET  = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI   = process.env.DISCORD_REDIRECT_URI || `http://localhost:${PORT}/auth/callback`;
const OWNER_IDS      = (process.env.OWNER_IDS || '').split(',').map(s => s.trim()).filter(Boolean);
const BOT_API_URL    = (process.env.BOT_API_URL || '').replace(/\/$/, '');
const BOT_API_SECRET = process.env.BOT_API_SECRET || '';

const HTML = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');


app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'sentrax-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    secure: false,
    sameSite: 'lax',
    httpOnly: true
  }
}));

// ── Bot API proxy ─────────────────────────────────────────────────────────────
async function botApi(apiPath, body, method) {
  if (!BOT_API_URL || !BOT_API_SECRET) {
    console.error('[Dashboard] BOT_API_URL or BOT_API_SECRET not set');
    return null;
  }
  try {
    const opts = {
      method: method || (body ? 'POST' : 'GET'),
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + BOT_API_SECRET }
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

// ── Auth guard ────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session.user) return next();
  return res.status(401).json({ error: 'Not authenticated' });
}

// ── Discord OAuth ─────────────────────────────────────────────────────────────
app.get('/auth/login', (req, res) => {
  const p = new URLSearchParams({
    client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
    response_type: 'code', scope: 'identify guilds', prompt: 'none'
  });
  res.redirect('https://discord.com/api/oauth2/authorize?' + p);
});

app.get('/auth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.send('<h2>Discord OAuth Error: ' + error + '</h2><a href="/">Back</a>');
  if (!code) return res.send('<h2>No code received from Discord</h2><a href="/">Back</a>');
  console.log('[OAuth] Got code, exchanging... CLIENT_ID:', CLIENT_ID ? 'SET' : 'MISSING', 'REDIRECT_URI:', REDIRECT_URI);
  try {
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI })
    });
    const t = await tokenRes.json();
    console.log('[OAuth] Token response status:', tokenRes.status, 'has access_token:', !!t.access_token, 'error:', t.error || 'none');
    if (!t.access_token) return res.send('<h2>Token exchange failed</h2><pre>' + JSON.stringify(t, null, 2) + '</pre><a href="/">Back</a>');
    const [u, guilds] = await Promise.all([
      fetch('https://discord.com/api/users/@me', { headers: { Authorization: 'Bearer ' + t.access_token } }).then(r => r.json()),
      fetch('https://discord.com/api/users/@me/guilds', { headers: { Authorization: 'Bearer ' + t.access_token } }).then(r => r.json())
    ]);
    console.log('[OAuth] Logged in as:', u.username, 'guilds:', guilds.length);
    req.session.user   = { id: u.id, username: u.username, avatar: u.avatar };
    req.session.guilds = guilds;
    req.session.save(err => {
      if (err) { console.error('[Session save error]', err); return res.send('<h2>Session save failed: ' + err.message + '</h2>'); }
      console.log('[OAuth] Session saved, redirecting to /dashboard');
      res.redirect('/dashboard');
    });
  } catch (e) { console.error('[OAuth crash]', e); res.send('<h2>OAuth crash: ' + e.message + '</h2><a href="/">Back</a>'); }
});

app.get('/auth/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// ── API ───────────────────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, (req, res) =>
  res.json({ user: req.session.user, isOwner: OWNER_IDS.includes(req.session.user.id) })
);

app.get('/api/guilds', requireAuth, async (req, res) => {
  const uid  = req.session.user.id;
  const isGO = OWNER_IDS.includes(uid);
  const checks = await Promise.all(
    (req.session.guilds || []).map(async g => {
      const r = await botApi('/guild-access', { guild_id: g.id, user_id: uid, is_owner: isGO });
      return r?.allowed ? { id: g.id, name: g.name, icon: g.icon } : null;
    })
  );
  res.json(checks.filter(Boolean));
});

app.get('/api/guild/:gid',                 requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}`) || { prefix: '!', warnings: 0, modcases: 0, antinuke_enabled: false, automod_enabled: false }); });
app.post('/api/guild/:gid/prefix',         requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/prefix`, req.body) || { error: 'Bot API unreachable' }); });
app.get('/api/guild/:gid/welcome',         requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/welcome`) || {}); });
app.post('/api/guild/:gid/welcome',        requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/welcome`, req.body) || { error: 'Bot API unreachable' }); });
app.get('/api/guild/:gid/leave',           requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/leave`) || {}); });
app.post('/api/guild/:gid/leave',          requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/leave`, req.body) || { error: 'Bot API unreachable' }); });
app.get('/api/guild/:gid/logging',         requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/logging`) || {}); });
app.post('/api/guild/:gid/logging',        requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/logging`, req.body) || { error: 'Bot API unreachable' }); });
app.get('/api/guild/:gid/automod',         requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/automod`) || {}); });
app.post('/api/guild/:gid/automod',        requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/automod`, req.body) || { error: 'Bot API unreachable' }); });
app.get('/api/guild/:gid/antinuke',        requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/antinuke`) || {}); });
app.post('/api/guild/:gid/antinuke',       requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/antinuke`, req.body) || { error: 'Bot API unreachable' }); });
app.get('/api/guild/:gid/leveling',        requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/leveling`) || {}); });
app.post('/api/guild/:gid/leveling',       requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/leveling`, req.body) || { error: 'Bot API unreachable' }); });
app.get('/api/guild/:gid/tickets',         requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/tickets`) || {}); });
app.post('/api/guild/:gid/tickets',        requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/tickets`, req.body) || { error: 'Bot API unreachable' }); });
app.get('/api/guild/:gid/moderation',      requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/moderation`) || { warnings: [], cases: [] }); });
app.get('/api/guild/:gid/permits',         requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/permits`) || { perms: [], permits: [] }); });
app.post('/api/guild/:gid/permits/add',    requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/permits/add`, req.body) || { error: 'Bot API unreachable' }); });
app.post('/api/guild/:gid/permits/remove', requireAuth, async (req, res) => { res.json(await botApi(`/guild/${req.params.gid}/permits/remove`, req.body) || { error: 'Bot API unreachable' }); });

// ── Serve HTML ────────────────────────────────────────────────────────────────
app.get('*', (req, res) => res.send(HTML));
app.listen(PORT, '0.0.0.0', () => console.log('[Dashboard] Running on port', PORT));
