const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const CONFIG = {
  freshservice_redirect_url: 'https://nive-959766391470843394.myfreshworks.com/sp/OIDC/963808191442391342/implicit',
  agents: {
    'niveditha@oskloud.com': { password: 'Nivedemo@1234', workspace: 'amazon' },
    'nivetestfw@gmail.com':  { password: 'Nivedemo@1234', workspace: 'netflix' }
  }
};

let PRIVATE_KEY;
try {
  PRIVATE_KEY = fs.readFileSync(path.join(__dirname, 'private.key'), 'utf8');
  console.log('✅ Private key loaded');
} catch (err) {
  console.error('❌ private.key not found!');
  process.exit(1);
}

// ── ROUTES ──────────────────────────────────────
app.get('/', (req, res) => res.redirect('/amazon'));

app.get('/amazon', (req, res) => {
  const state = req.query.state || '';
  const nonce = req.query.nonce || '';
  let html = fs.readFileSync(path.join(__dirname, 'public', 'amazon.html'), 'utf8');
  // Inject state + nonce into the form as hidden fields
  html = html.replace(
    '<input type="hidden" name="portal" value="amazon"/>',
    `<input type="hidden" name="portal" value="amazon"/>
     <input type="hidden" name="state" value="${state}"/>
     <input type="hidden" name="nonce" value="${nonce}"/>`
  );
  res.send(html);
});

app.get('/netflix', (req, res) => {
  const state = req.query.state || '';
  const nonce = req.query.nonce || '';
  let html = fs.readFileSync(path.join(__dirname, 'public', 'netflix.html'), 'utf8');
  html = html.replace(
    '<input type="hidden" name="portal" value="netflix"/>',
    `<input type="hidden" name="portal" value="netflix"/>
     <input type="hidden" name="state" value="${state}"/>
     <input type="hidden" name="nonce" value="${nonce}"/>`
  );
  res.send(html);
});

// ── LOGIN ────────────────────────────────────────
app.post('/login', (req, res) => {
  const { email, password, portal, state, nonce } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required.' });

  const agentKey = email.toLowerCase().trim();
  const agent = CONFIG.agents[agentKey];

  if (!agent)
    return res.status(401).json({ error: 'Invalid email or password.' });

  if (agent.password !== password)
    return res.status(401).json({ error: 'Invalid email or password.' });

  if (portal && agent.workspace !== portal)
    return res.status(403).json({ error: `Access denied. You are not an agent for the ${portal} portal.` });

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: agentKey,
    email: agentKey,
    iat: now,
    exp: now + 300,
    nonce: nonce || uuidv4()
  };

  let token;
  try {
    token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });
  } catch (err) {
    console.error('JWT signing error:', err.message);
    return res.status(500).json({ error: 'Authentication error. Please contact admin.' });
  }

  const redirectUrl = `${CONFIG.freshservice_redirect_url}?id_token=${token}&state=${state}&nonce=${payload.nonce}`;
  return res.json({ success: true, redirectUrl });
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ SSO Portal running on port ${PORT}`);
});
