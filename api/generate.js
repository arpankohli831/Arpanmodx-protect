import crypto from 'crypto';

export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { url, password } = req.body;

  // Check admin password
  if (password !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Wrong password' });
  }

  if (!url) {
    return res.status(400).json({ error: 'No URL provided' });
  }

  try {
    // Encrypt the URL using AES-256-CBC
    const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
    const iv  = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

    let encrypted = cipher.update(url, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Combine IV + encrypted into a base64url token
    const token = Buffer.from(iv.toString('hex') + ':' + encrypted).toString('base64url');

    const siteUrl = process.env.SITE_URL || 'https://arpanmodx-protect.vercel.app';
    const protected_url = `${siteUrl}/go?t=${token}`;

    return res.status(200).json({ protected_url });

  } catch (err) {
    return res.status(500).json({ error: 'Encryption failed' });
  }
}
