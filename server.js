const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────
// CONFIG — All settings in one place
// ─────────────────────────────────────────
const CONFIG = {
  freshservice_url: 'https://nive-959766391470843394.myfreshworks.com',

  // OIDC Redirect URL from Freshservice → Admin → Security → SSO with JWT
  redirect_uri: 'https://nive-959766391470843394.myfreshworks.com/sp/OIDC/964246980516603282/implicit',

  // Agents: email → { password, workspace, given_name, family_name }
  agents: {
    'niveditha@oskloud.com': { password: 'Nivedemo@1234', workspace: 'amazon', given_name: 'Niveditha', family_name: 'Agent' },
    'nivetestfw@gmail.com':  { password: 'Nivedemo@1234', workspace: 'netflix', given_name: 'Nive', family_name: 'Test' }
  }
};

// Load RSA private key
let PRIVATE_KEY;
try {
  PRIVATE_KEY = process.env.PRIVATE_KEY
    ? process.env.PRIVATE_KEY.replace(/\\n/g, '\n')
    : fs.readFileSync(path.join(__dirname, 'private.key'), 'utf8');
  console.log('✅ Private key loaded successfully');
} catch (err) {
  console.error('❌ Private key not found!');
  process.exit(1);
}

// ─────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────

// Agent visits /amazon directly → no OIDC params → redirect to Freshservice
// Freshservice sees SSO configured → bounces back to /amazon WITH state & nonce
// Agent sees login page → enters credentials → lands in dashboard
// The bounce is instant — agent just sees the login page appear.

app.get('/', (req, res) => {
  if (req.query.state && req.query.nonce) {
    return res.sendFile(path.join(__dirname, 'public', 'amazon.html'));
  }
  res.redirect(CONFIG.freshservice_url);
});

app.get('/amazon', (req, res) => {
  if (req.query.state && req.query.nonce) {
    return res.sendFile(path.join(__dirname, 'public', 'amazon.html'));
  }
  // No OIDC params — redirect to Freshservice to get them
  console.log('📌 /amazon direct access → bouncing through Freshservice for OIDC params');
  res.redirect(CONFIG.freshservice_url);
});

app.get('/netflix', (req, res) => {
  if (req.query.state && req.query.nonce) {
    return res.sendFile(path.join(__dirname, 'public', 'netflix.html'));
  }
  console.log('📌 /netflix direct access → bouncing through Freshservice for OIDC params');
  res.redirect(CONFIG.freshservice_url);
});

// ─────────────────────────────────────────
// LOGIN — JWT Generation + Portal Restriction
// ─────────────────────────────────────────
app.post('/login', (req, res) => {
  const { email, password, portal, state, nonce } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'Email and password are required.' });
  }

  if (!state || !nonce) {
    return res.status(400).json({ success: false, error: 'Session expired. Please refresh and try again.' });
  }

  const agentKey = email.toLowerCase().trim();
  const agent = CONFIG.agents[agentKey];

  // Agent does not exist
  if (!agent) {
    return res.status(401).json({ success: false, error: 'Invalid email or password.' });
  }

  // Wrong password
  if (agent.password !== password) {
    return res.status(401).json({ success: false, error: 'Invalid email or password.' });
  }

  // ✅ PORTAL RESTRICTION — Netflix agent cannot login via Amazon page
  if (portal && agent.workspace !== portal) {
    return res.status(403).json({
      success: false,
      error: `Access denied. You are not an agent for the ${portal} portal.`
    });
  }

  // Build JWT — per Freshworks OIDC spec
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: agentKey,
    email: agentKey,
    given_name: agent.given_name,
    family_name: agent.family_name,
    iat: now,
    exp: now + 300,
    nonce: nonce       // MUST be the nonce Freshservice sent — not self-generated
  };

  // Sign JWT
  let token;
  try {
    token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });
  } catch (err) {
    console.error('JWT signing error:', err.message);
    return res.status(500).json({ success: false, error: 'Authentication error. Please contact admin.' });
  }

  // ✅ OIDC implicit flow — redirect to Freshworks with state + id_token
  const redirectUrl = `${CONFIG.redirect_uri}?state=${encodeURIComponent(state)}&id_token=${token}`;

  console.log(`✅ Login success: ${agentKey} → ${portal} portal`);
  return res.json({ success: true, redirectUrl });
});

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
✅ Freshservice SSO Portal running!
🟠 Amazon → http://localhost:${PORT}/amazon
🔴 Netflix → http://localhost:${PORT}/netflix
📌 OIDC Redirect: ${CONFIG.redirect_uri}
  `);
});
