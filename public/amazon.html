const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ═══════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════
const CONFIG = {
  // The OIDC Redirect URL from Freshservice SSO config
  redirect_uri: 'https://nive-959766391470843394.myfreshworks.com/sp/OIDC/964246980516603282/implicit',

  agents: {
    'niveditha@oskloud.com': {
      password: 'Nivedemo@1234',
      workspace: 'amazon',
      given_name: 'Niveditha',
      family_name: 'Agent'
    },
    'nivetestfw@gmail.com': {
      password: 'Nivedemo@1234',
      workspace: 'netflix',
      given_name: 'Nive',
      family_name: 'Test'
    }
  }
};

// ═══════════════════════════════════════════════════
// LOAD PRIVATE KEY
// ═══════════════════════════════════════════════════
let PRIVATE_KEY;
try {
  if (process.env.PRIVATE_KEY) {
    PRIVATE_KEY = process.env.PRIVATE_KEY.replace(/\\n/g, '\n');
    console.log('✅ Private key loaded from ENV');
  } else {
    PRIVATE_KEY = fs.readFileSync(path.join(__dirname, 'private.key'), 'utf8');
    console.log('✅ Private key loaded from file');
  }
} catch (err) {
  console.error('❌ Private key not found!');
  process.exit(1);
}

// ═══════════════════════════════════════════════════
// ROUTES — Serve login pages
// ═══════════════════════════════════════════════════
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'amazon.html')));
app.get('/amazon', (req, res) => res.sendFile(path.join(__dirname, 'public', 'amazon.html')));
app.get('/netflix', (req, res) => res.sendFile(path.join(__dirname, 'public', 'netflix.html')));

// ═══════════════════════════════════════════════════
// LOGIN — Authenticate and redirect via OIDC implicit flow
// ═══════════════════════════════════════════════════
app.post('/login', (req, res) => {
  const { email, password, portal, state, nonce } = req.body;

  console.log('📥 Login attempt:', { email, portal, hasState: !!state, hasNonce: !!nonce });

  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'Email and password are required.' });
  }

  if (!state || !nonce) {
    console.warn('⚠️  Missing state or nonce — SSO flow may have been started directly, not from Freshservice');
  }

  const agentKey = email.toLowerCase().trim();
  const agent = CONFIG.agents[agentKey];

  if (!agent) {
    return res.status(401).json({ success: false, error: 'Invalid email or password.' });
  }

  if (agent.password !== password) {
    return res.status(401).json({ success: false, error: 'Invalid email or password.' });
  }

  if (portal && agent.workspace !== portal) {
    return res.status(403).json({
      success: false,
      error: `Access denied. You are not an agent for the ${portal} portal.`
    });
  }

  // ─── Build JWT payload per Freshworks OIDC spec ───
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: agentKey,                    // Required — unique user ID
    email: agentKey,                  // Required — must match agent email in Freshservice
    given_name: agent.given_name,     // Required — first name
    family_name: agent.family_name,   // Required — last name
    iat: now,                         // Required — issued at (unix timestamp)
    nonce: nonce || ''                // Required — MUST be the nonce Freshservice sent
  };

  let token;
  try {
    token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256', expiresIn: '5m' });
    console.log('✅ JWT signed successfully');
  } catch (err) {
    console.error('❌ JWT signing error:', err.message);
    return res.status(500).json({ success: false, error: 'Authentication error.' });
  }

  // ─── Redirect to Freshworks OIDC implicit endpoint ───
  // Format: {redirect_uri}?state={state}&id_token={jwt}
  const redirectUrl = `${CONFIG.redirect_uri}?state=${encodeURIComponent(state || '')}&id_token=${token}`;

  console.log(`✅ Login: ${agentKey} → redirecting to OIDC endpoint`);

  return res.json({ success: true, redirectUrl });
});

// ═══════════════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════════════
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
✅ Freshservice JWT SSO Portal running on port ${PORT}
🟠 Amazon → http://localhost:${PORT}/amazon
🔴 Netflix → http://localhost:${PORT}/netflix
📌 OIDC Redirect URI: ${CONFIG.redirect_uri}
  `);
});
