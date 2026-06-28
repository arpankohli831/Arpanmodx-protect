import crypto from 'crypto';

// Simple in-memory rate limiter
const ipRequests = new Map();

function isRateLimited(ip) {
  const now = Date.now();
  const windowMs = 60 * 1000;
  const maxRequests = 5;

  if (!ipRequests.has(ip)) ipRequests.set(ip, []);
  const timestamps = ipRequests.get(ip).filter(t => now - t < windowMs);
  timestamps.push(now);
  ipRequests.set(ip, timestamps);
  return timestamps.length > maxRequests;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';

  // Rate limit check
  if (isRateLimited(ip)) {
    return res.status(429).json({ error: '🚫 Too many requests! Try again in 1 minute.' });
  }

  const { captcha_token, link_token, page_token } = req.body;

  if (!captcha_token || !link_token || !page_token) {
    return res.status(400).json({ error: '❌ Missing required tokens.' });
  }

  try {
    // ✅ STEP 1: Verify server-signed page token (bot cannot fake this!)
    const decodedPage = Buffer.from(page_token, 'base64url').toString('utf8');
    const [timestamp, receivedHmac] = decodedPage.split(':');

    const expectedHmac = crypto
      .createHmac('sha256', process.env.ENCRYPTION_KEY)
      .update(timestamp)
      .digest('hex');

    // Check signature is valid
    if (receivedHmac !== expectedHmac) {
      return res.status(400).json({ error: '🤖 Invalid session! Bot detected.' });
    }

    const pageOpenTime = parseInt(timestamp);
    const timeSpent = Date.now() - pageOpenTime;

    // Check minimum time (must spend at least 5 seconds on page)
    if (timeSpent < 5000) {
      return res.status(400).json({ error: '🤖 Too fast! You are a bot.' });
    }

    // Check page session not expired (max 15 minutes)
    if (timeSpent > 15 * 60 * 1000) {
      return res.status(400).json({ error: '⏰ Session expired. Please refresh the page.' });
    }

    // ✅ STEP 2: Verify Cloudflare Turnstile CAPTCHA
    const captchaRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret:   process.env.TURNSTILE_SECRET,
        response: captcha_token
      })
    });

    const captchaData = await captchaRes.json();

    if (!captchaData.success) {
      return res.status(400).json({ error: '❌ CAPTCHA failed. Please try again.' });
    }

    // ✅ STEP 3: Decrypt link token
    const decoded = Buffer.from(link_token, 'base64url').toString('utf8');
    const [ivHex, encrypted] = decoded.split(':');

    const key      = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
    const iv       = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    const payload = JSON.parse(decrypted);

    // Check link token not expired (15 minutes)
    if (Date.now() - payload.created_at > 15 * 60 * 1000) {
      return res.status(400).json({ error: '⏰ This link expired! Generate a new protected link.' });
    }

    return res.status(200).json({ url: payload.url });

  } catch (err) {
    return res.status(400).json({ error: '❌ Invalid or expired link.' });
  }
}
