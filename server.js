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
  freshservice_url: 'https://nive-959766391470843394.myfreshworks.com',
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

// Freshservice redirects here with: ?client_id=xxx&state=xxx&nonce=xxx
// We capture those params and pass them to the login page
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'amazon.html')));

app.get('/amazon', (req, res) => {
  // Freshservice sends: /amazon?client_id=xxx&state=xxx&nonce=xxx&grant_type=implicit&scope=...
  // The HTML page needs to capture state + nonce and send them with the login POST
  res.sendFile(path.join(__dirname, 'public', 'amazon.html'));
});

app.get('/netflix', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'netflix.html'));
});

// ═══════════════════════════════════════════════════
// LOGIN — Authenticate and redirect with OIDC implicit flow
// ═══════════════════════════════════════════════════
app.post('/login', (req, res) => {
  const { email, password, portal, state, nonce, redirect_uri } = req.body;

  console.log('📥 Login request:', { email, portal, state: state?.substring(0, 20) + '...', nonce });

  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'Email and password are required.' });
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

  // ─── Build JWT payload per Freshworks spec ───
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: agentKey,
    email: agentKey,
    given_name: agent.given_name,
    family_name: agent.family_name,
    iat: now,
    nonce: nonce || ''   // MUST be the nonce Freshservice sent, not self-generated
  };

  let token;
  try {
    token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256', expiresIn: '5m' });
  } catch (err) {
    console.error('❌ JWT signing error:', err.message);
    return res.status(500).json({ success: false, error: 'Authentication error.' });
  }

  // ─── Build redirect URL ───
  // Freshworks expects: {redirect_uri}?state={state}&id_token={jwt}
  // The redirect_uri comes from Freshservice SSO config page (the "Redirect URL" field)
  // If the frontend didn't pass redirect_uri, fall back to the known OIDC endpoint
  let redirectUrl;
  if (redirect_uri) {
    // Use the redirect_uri passed from Freshservice
    redirectUrl = `${redirect_uri}?state=${encodeURIComponent(state || '')}&id_token=${token}`;
  } else {
    // Fallback: use /login/jwt (old method) — but this likely won't work
    // You MUST get the Redirect URL from Freshservice SSO config page
    redirectUrl = `${CONFIG.freshservice_url}/login/jwt?jwt=${token}`;
    console.warn('⚠️  No redirect_uri provided — using fallback /login/jwt. This may not work!');
  }

  console.log(`✅ Login success: ${agentKey} → redirecting`);
  console.log(`🔗 Redirect URL: ${redirectUrl.substring(0, 120)}...`);

  return res.json({ success: true, redirectUrl });
});

// ═══════════════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════════════
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
✅ Freshservice SSO Portal running on port ${PORT}
🟠 Amazon → http://localhost:${PORT}/amazon
🔴 Netflix → http://localhost:${PORT}/netflix

⚠️  IMPORTANT: Your login HTML pages must capture these URL params from Freshservice:
   - state  (pass back unchanged)
   - nonce  (include in JWT payload)
   - client_id (identifies the Freshservice account)
   
   And the Redirect URL from Freshservice SSO config must be sent as redirect_uri.
  `);
});
