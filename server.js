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
  freshservice_redirect_url: 'https://nive-959766391470843394.myfreshworks.com/sp/OIDC/963808191442391342/implicit',

  // Agents: email → { password, workspace }
  agents: {
    'niveditha@oskloud.com': { password: 'Nivedemo@1234', workspace: 'amazon' },
    'nivetestfw@gmail.com':  { password: 'Nivedemo@1234', workspace: 'netflix' }
  }
};

// Load RSA private key from env variable or file
let PRIVATE_KEY;
try {
  if (process.env.PRIVATE_KEY_CONTENT) {
    PRIVATE_KEY = process.env.PRIVATE_KEY_CONTENT.replace(/\\n/g, '\n');
    console.log('✅ Private key loaded from environment variable');
  } else {
    PRIVATE_KEY = fs.readFileSync(path.join(__dirname, 'private.key'), 'utf8');
    console.log('✅ Private key loaded from file');
  }
} catch (err) {
  console.error('❌ private.key not found! Make sure private.key is in the same folder as server.js');
  process.exit(1);
}

// ─────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'amazon.html')));
app.get('/amazon', (req, res) => res.sendFile(path.join(__dirname, 'public', 'amazon.html')));
app.get('/netflix', (req, res) => res.sendFile(path.join(__dirname, 'public', 'netflix.html')));

// ─────────────────────────────────────────
// LOGIN — JWT Generation
// ─────────────────────────────────────────
app.post('/login', (req, res) => {
  const { email, password, portal } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const agentKey = email.toLowerCase().trim();
  const agent = CONFIG.agents[agentKey];

  // Check if agent exists
  if (!agent) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  // Check password
  if (agent.password !== password) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  // Check they are using the correct portal
  if (portal && agent.workspace !== portal) {
    return res.status(403).json({
      error: `Access denied. You are not an agent for the ${portal} portal.`
    });
  }

  // Build JWT
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: agentKey,
    email: agentKey,
    iat: now,
    exp: now + 300,
    nonce: uuidv4()
  };

  // Sign JWT
  let token;
  try {
    token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });
  } catch (err) {
    console.error('JWT signing error:', err.message);
    return res.status(500).json({ error: 'Authentication error. Please contact admin.' });
  }

  // Redirect URL for Freshservice
  const redirectUrl = `${CONFIG.freshservice_redirect_url}?id_token=${token}&state=${req.query.state || portal}&nonce=${payload.nonce}`;
  return res.json({ success: true, redirectUrl });
});

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
  ✅ Freshservice SSO Portal running!
  🟠 Amazon  → http://localhost:${PORT}/amazon
  🔴 Netflix → http://localhost:${PORT}/netflix
  `);
});
