const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

const CONFIG = {
  freshservice_redirect_url: 'https://nive-959766391470843394.myfreshworks.com/sp/OIDC/963808191442391342/implicit',
  agents: {
    'niveditha@oskloud.com': { password: 'Nivedemo@1234', workspace: 'amazon' },
    'nivetestfw@gmail.com':  { password: 'Nivedemo@1234', workspace: 'netflix' }
  }
};

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
  console.error('❌ private.key not found!');
  process.exit(1);
}

app.get('/', (req, res) => serve(res, 'amazon', req.query));
app.get('/amazon', (req, res) => serve(res, 'amazon', req.query));
app.get('/netflix', (req, res) => serve(res, 'netflix', req.query));

function serve(res, portal, query) {
  const state = query.state || '';
  const nonce = query.nonce || '';
  let html = fs.readFileSync(path.join(__dirname, `${portal}.html`), 'utf8');
  const qs = `?state=${encodeURIComponent(state)}&nonce=${encodeURIComponent(nonce)}&portal=${portal}`;
  html = html.replace(/action=["']\/login["']/gi, `action="/login${qs}"`);
  res.send(html);
}

app.post('/login', (req, res) => {
  const state  = req.query.state  || '';
  const nonce  = req.query.nonce  || '';
  const portal = req.query.portal || 'amazon';
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required.' });

  const agentKey = email.toLowerCase().trim();
  const agent = CONFIG.agents[agentKey];

  if (!agent || agent.password !== password)
    return res.status(401).json({ error: 'Invalid email or password.' });

  if (agent.workspace !== portal)
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
    return res.status(500).json({ error: 'Authentication error.' });
  }

  const redirectUrl = `${CONFIG.freshservice_redirect_url}?id_token=${token}&state=${encodeURIComponent(state)}&nonce=${encodeURIComponent(payload.nonce)}`;
  return res.json({ success: true, redirectUrl });
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ SSO Portal running on port ${PORT}`));
const PORTAL_AGENTS = {
  amazon: ['niveditha@oskloud.com'],
  netflix: ['nivetestfw@gmail.com']
};

app.post('/login', (req, res) => {
  const { email, portal } = req.body;
  const allowed = (PORTAL_AGENTS[portal] || []).map(e => e.toLowerCase());
  if (!allowed.includes(email.toLowerCase())) {
    return res.json({ success: false, error: 'You are not authorized for this portal.' });
  }
  // rest of your JWT code...
});
