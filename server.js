require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static('public', {
  // Cache images/icons aggressively (they rarely change); HTML always revalidates
  // so content edits from the dashboard show up immediately for everyone.
  setHeaders: (res, filePath) => {
    if (/\.(jpg|jpeg|png|webp|svg|ico)$/i.test(filePath)) {
      res.setHeader('Cache-Control', 'public, max-age=2592000, immutable'); // 30 days
    } else if (/\.html$/i.test(filePath)) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));

// Lets people open /admin (no .html needed) and still get the dashboard.
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

const BOT_TOKEN = process.env.BOT_TOKEN;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');

// The 3 channels students must be subscribed to.
// Use @username for public channels. For private channels use the numeric chat id (e.g. -1001234567890).
const CHANNELS = [
  '@islamicwezary',
  '@FrancaisAA',
  '@wezaryataa',
];

if (!BOT_TOKEN) {
  console.warn('⚠️  BOT_TOKEN is missing — the Telegram subscription check will not work until you set it in .env. The dashboard and site content will still work.');
}
if (!ADMIN_PASSWORD) {
  console.warn('⚠️  ADMIN_PASSWORD is missing — set it in .env or the dashboard at /admin will refuse every login.');
}

/* =================== CONTENT STORAGE (subjects & topics) =================== */
function readContent() {
  if (!fs.existsSync(DATA_FILE)) {
    return { subjects: [], topics: [] };
  }
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}

function writeContent(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// Anyone can read the current content — this is what the public site loads on every visit.
app.get('/api/content', (req, res) => {
  try {
    res.json(readContent());
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

// Simple shared-password auth for the dashboard. Not meant for multi-admin/enterprise use —
// good enough for one or a few trusted people managing this site's content.
function requireAdmin(req, res, next) {
  if (!ADMIN_PASSWORD) {
    return res.status(500).json({ error: 'admin_password_not_configured' });
  }
  const key = req.get('x-admin-key');
  if (key !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

// Basic in-memory rate limit for login attempts, keyed by IP.
// Good enough to stop casual password guessing; for real protection at scale,
// put this behind Cloudflare or a proper rate-limiting service too.
const loginAttempts = new Map(); // ip -> { count, resetAt }
const MAX_ATTEMPTS = 8;
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes

function rateLimitLogin(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now > entry.resetAt) {
    loginAttempts.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return next();
  }
  if (entry.count >= MAX_ATTEMPTS) {
    const waitMin = Math.ceil((entry.resetAt - now) / 60000);
    return res.status(429).json({ error: 'too_many_attempts', retry_after_minutes: waitMin });
  }
  entry.count++;
  next();
}

app.post('/api/admin/login', rateLimitLogin, (req, res) => {
  if (!ADMIN_PASSWORD) {
    return res.status(500).json({ error: 'admin_password_not_configured' });
  }
  const { password } = req.body || {};
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'wrong_password' });
  }
  res.json({ ok: true });
});

// Replaces the whole content file. The dashboard edits everything client-side
// and saves the complete {subjects, topics} object back in one shot.
app.put('/api/admin/content', requireAdmin, (req, res) => {
  const { subjects, topics } = req.body || {};
  if (!Array.isArray(subjects) || !Array.isArray(topics)) {
    return res.status(400).json({ error: 'invalid_payload' });
  }
  try {
    writeContent({ subjects, topics });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

/* =================== TELEGRAM SUBSCRIPTION CHECK =================== */

/**
 * Verifies that the login payload really came from Telegram and wasn't forged.
 * https://core.telegram.org/widgets/login#checking-authorization
 */
function verifyTelegramAuth(data) {
  const { hash, ...fields } = data;
  if (!hash) return false;

  const checkString = Object.keys(fields)
    .filter((k) => fields[k] !== undefined)
    .sort()
    .map((k) => `${k}=${fields[k]}`)
    .join('\n');

  const secretKey = crypto.createHash('sha256').update(BOT_TOKEN).digest();
  const computedHash = crypto
    .createHmac('sha256', secretKey)
    .update(checkString)
    .digest('hex');

  if (computedHash !== hash) return false;

  // Reject stale logins (older than 24h) as an extra safety margin.
  const authAge = Math.floor(Date.now() / 1000) - Number(fields.auth_date);
  if (authAge > 86400) return false;

  return true;
}

/**
 * Asks Telegram directly whether userId is a member/admin/creator of the given channel.
 * The bot MUST be added to the channel (as admin is safest) for this to work reliably.
 */
async function isChannelMember(userId, channel) {
  const url = `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(
    channel
  )}&user_id=${userId}`;

  const res = await fetch(url);
  const data = await res.json();

  if (!data.ok) {
    console.warn(`⚠️ getChatMember failed for ${channel}:`, data.description);
    return false;
  }

  const status = data.result.status;
  return ['member', 'administrator', 'creator'].includes(status);
}

app.post('/api/check-subscription', async (req, res) => {
  if (!BOT_TOKEN) {
    return res.status(500).json({ error: 'bot_token_not_configured' });
  }
  try {
    const authData = req.body;

    if (!verifyTelegramAuth(authData)) {
      return res.status(401).json({ error: 'auth_invalid' });
    }

    const userId = authData.id;
    const results = await Promise.all(
      CHANNELS.map((ch) => isChannelMember(userId, ch))
    );
    const missing = CHANNELS.filter((_, i) => !results[i]);

    res.json({ subscribed: missing.length === 0, missing });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
