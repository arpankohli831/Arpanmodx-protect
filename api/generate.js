import crypto from 'crypto';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { url, password } = req.body;

  if (password !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Wrong password' });
  }

  if (!url) {
    return res.status(400).json({ error: 'No URL provided' });
  }

  try {
    // Generate short 8-character ID
    const shortId = crypto.randomBytes(4).toString('hex');

    // Store link in Upstash Redis with 15 min expiry
    const payload = JSON.stringify({ url, created_at: Date.now() });

    const redisRes = await fetch(process.env.KV_REST_API_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.KV_REST_API_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(['SET', `link:${shortId}`, payload, 'EX', '900'])
    });

    const redisData = await redisRes.json();

    if (redisData.result !== 'OK') {
      return res.status(500).json({ error: 'Failed to store link' });
    }

    const siteUrl = process.env.SITE_URL || 'https://arpanmodx-protect.vercel.app';
    const protected_url = `${siteUrl}/go?t=${shortId}`;

    return res.status(200).json({ protected_url });

  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
}
