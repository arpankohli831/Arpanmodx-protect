import crypto from 'crypto';

export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Create a server-signed timestamp (bot cannot fake this!)
  const timestamp = Date.now().toString();
  const hmac = crypto
    .createHmac('sha256', process.env.ENCRYPTION_KEY)
    .update(timestamp)
    .digest('hex');

  // Combine timestamp + signature into a page token
  const page_token = Buffer.from(timestamp + ':' + hmac).toString('base64url');

  return res.status(200).json({ page_token });
}
