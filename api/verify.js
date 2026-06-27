export default async function handler(req, res) {
  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'No token provided' });
  }

  try {
    // Verify CAPTCHA token with Cloudflare
    const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: process.env.TURNSTILE_SECRET,
        response: token
      })
    });

    const verifyData = await verifyRes.json();

    if (verifyData.success) {
      // ✅ CAPTCHA passed — return the protected link
      return res.status(200).json({ url: process.env.PROTECTED_URL });
    } else {
      // ❌ CAPTCHA failed
      return res.status(400).json({ error: 'CAPTCHA verification failed' });
    }
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
}
