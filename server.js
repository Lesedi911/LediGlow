/**
 * Minimal Express server stub for demo auth flow.
 * Run: npm init -y
 *       npm i express bcrypt cookie-parser cors body-parser
 * Run server: node server.js
 *
 * Notes:
 * - This is a demo in-memory store. Replace with a persistent DB (Postgres/Mongo) and a proper session store (Redis).
 * - Ensure HTTPS in production and set cookie.secure = true.
 * - Add rate limiting, captcha, and account lockout for security.
 */
const express = require('express');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: true, credentials: true })); // adjust in prod
app.use(bodyParser.json());
app.use(cookieParser());

/**
 * In-memory stores (demo only)
 * users: { email: { id, email, passwordHash, createdAt } }
 * sessions: { sid: email }
 */
const users = Object.create(null);
const sessions = Object.create(null);

// helper: create session id (very small demo)
function createSid() { return 's' + Math.random().toString(36).slice(2); }

/* POST /api/signup
   Expect: { email, password }
   - validate input
   - hash password (bcrypt)
   - store user
   - (stub) send verification email
*/
app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body || {};
  if(!email || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ ok:false, field:'email', message:'Invalid email' });
  if(!password || password.length < 8) return res.status(400).json({ ok:false, field:'password', message:'Password too short' });
  if(users[email]) return res.status(409).json({ ok:false, field:'email', message:'Email already registered' });

  try {
    const hash = await bcrypt.hash(password, 12);
    users[email] = { id: Date.now().toString(), email, passwordHash: hash, createdAt: new Date().toISOString() };
    // stub: send verification email (replace with real email provider)
    console.log('[stub] send verification email to', email);
    // create session and set cookie
    const sid = createSid();
    sessions[sid] = email;
    res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax' /* set secure:true in prod */ });
    return res.json({ ok:true, redirect:'/dashboard.html' });
  } catch(err) {
    console.error(err);
    return res.status(500).json({ ok:false, message:'Server error' });
  }
});

/* POST /api/login
   Expect: { email, password }
   - verify email exists
   - compare password via bcrypt.compare
   - create session cookie (HttpOnly)
*/
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if(!email || !password) return res.status(400).json({ ok:false, message:'Missing fields' });
  const user = users[email];
  if(!user) return res.status(401).json({ ok:false, field:'email', message:'Invalid credentials' });

  try {
    const ok = await bcrypt.compare(password, user.passwordHash);
    if(!ok) return res.status(401).json({ ok:false, field:'password', message:'Invalid credentials' });
    const sid = createSid();
    sessions[sid] = email;
    res.cookie('sid', sid, { httpOnly:true, sameSite: 'lax' }); // secure:true in prod with HTTPS
    return res.json({ ok:true, redirect:'/dashboard.html' });
  } catch(err) {
    console.error(err);
    return res.status(500).json({ ok:false, message:'Server error' });
  }
});

/* GET /api/me
   - returns { email } when session valid
*/
app.get('/api/me', (req, res) => {
  const sid = req.cookies && req.cookies.sid;
  if(!sid || !sessions[sid]) return res.status(401).json({ ok:false, message:'Not authenticated' });
  const email = sessions[sid];
  const user = users[email];
  if(!user) return res.status(401).json({ ok:false, message:'Not authenticated' });
  return res.json({ ok:true, email: user.email, id: user.id });
});

/* POST /api/logout
   - destroy session cookie
*/
app.post('/api/logout', (req, res) => {
  const sid = req.cookies && req.cookies.sid;
  if(sid) {
    delete sessions[sid];
    res.clearCookie('sid');
  }
  res.json({ ok:true });
});

/* static files for demo (serve front-end) */
app.use(express.static(__dirname)); // serves index.html, signup.html, login.html, dashboard.html

app.listen(PORT, () => {
  console.log(`LediGlow demo server listening on http://localhost:${PORT}`);
});
