import crypto from 'crypto';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { captcha_token, link_token } = req.body;

  if (!captcha_token || !link_token) {
    return res.status(400).json({ error: 'Missing tokens' });
  }

  try {
    // Step 1: Verify Cloudflare Turnstile CAPTCHA
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
      return res.status(400).json({ error: 'CAPTCHA failed. Please try again.' });
    }

    // Step 2: Decrypt the link token
    const decoded = Buffer.from(link_token, 'base64url').toString('utf8');
    const [ivHex, encrypted] = decoded.split(':');

    const key      = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
    const iv       = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

    let url = decipher.update(encrypted, 'hex', 'utf8');
    url += decipher.final('utf8');

    // Step 3: Return the real URL
    return res.status(200).json({ url });

  } catch (err) {
    return res.status(400).json({ error: 'Invalid or expired link.' });
  }
}
