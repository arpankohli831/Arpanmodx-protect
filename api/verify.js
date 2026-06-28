import crypto from 'crypto';

// Rate limiter
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

  if (isRateLimited(ip)) {
    return res.status(429).json({ error: '🚫 Too many requests! Try again in 1 minute.' });
  }

  const { captcha_token, link_token, page_token } = req.body;

  if (!captcha_token || !link_token || !page_token) {
    return res.status(400).json({ error: '❌ Missing required tokens.' });
  }

  try {
    // ✅ STEP 1: Verify server-signed page token
    const decodedPage = Buffer.from(page_token, 'base64url').toString('utf8');
    const [timestamp, receivedHmac] = decodedPage.split(':');

    const expectedHmac = crypto
      .createHmac('sha256', process.env.ENCRYPTION_KEY)
      .update(timestamp)
      .digest('hex');

    if (receivedHmac !== expectedHmac) {
      return res.status(400).json({ error: '🤖 Invalid session! Bot detected.' });
    }

    const timeSpent = Date.now() - parseInt(timestamp);

    if (timeSpent < 5000) {
      return res.status(400).json({ error: '🤖 Too fast! You are a bot.' });
    }

    if (timeSpent > 15 * 60 * 1000) {
      return res.status(400).json({ error: '⏰ Session expired. Please refresh.' });
    }

    // ✅ STEP 2: Verify Cloudflare Turnstile
    const captchaRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: process.env.TURNSTILE_SECRET,
        response: captcha_token
      })
    });

    const captchaData = await captchaRes.json();

    if (!captchaData.success) {
      return res.status(400).json({ error: '❌ CAPTCHA failed. Please try again.' });
    }

    // ✅ STEP 3: Get link from Redis using short ID
    const redisRes = await fetch(process.env.KV_REST_API_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.KV_REST_API_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(['GET', `link:${link_token}`])
    });

    const redisData = await redisRes.json();

    if (!redisData.result) {
      return res.status(400).json({ error: '⏰ Link expired or invalid! Generate a new one.' });
    }

    const payload = JSON.parse(redisData.result);

    return res.status(200).json({ url: payload.url });

  } catch (err) {
    return res.status(400).json({ error: '❌ Something went wrong.' });
  }
}
