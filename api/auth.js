import crypto from 'crypto';

const COOKIE_NAME = 'vault_session';

function signToken(payloadB64, secret) {
  return crypto.createHmac('sha256', secret).update(payloadB64).digest('base64url');
}

export function createSessionCookie(username, secret) {
  const payload = JSON.stringify({
    u: username,
    exp: Date.now() + 1000 * 60 * 60 * 24 * 7, // 7 giorni
  });
  const payloadB64 = Buffer.from(payload).toString('base64url');
  const sig = signToken(payloadB64, secret);
  return `${COOKIE_NAME}=${payloadB64}.${sig}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=604800`;
}

export function clearSessionCookie() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0`;
}

export function isAuthenticated(req) {
  const secret = process.env.ADMIN_SECRET;
  if (!secret) return false;

  const rawCookie = req.headers.cookie || '';
  const match = rawCookie.split(';').map((s) => s.trim()).find((s) => s.startsWith(`${COOKIE_NAME}=`));
  if (!match) return false;

  const token = match.slice(COOKIE_NAME.length + 1);
  const parts = token.split('.');
  if (parts.length !== 2) return false;

  const [payloadB64, sig] = parts;
  const expectedSig = signToken(payloadB64, secret);
  if (sig.length !== expectedSig.length) return false;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) return false;

  try {
    const data = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
    return Boolean(data && data.exp && Date.now() < data.exp);
  } catch {
    return false;
  }
}

export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'GET') {
    return res.status(200).json({ authenticated: isAuthenticated(req) });
  }

  if (req.method === 'POST') {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const user = String(body.username || '').trim();
    const pass = String(body.password || '');

    const expectedUser = process.env.ADMIN_USER || 'admin';
    const expectedPass = process.env.ADMIN_PASSWORD || '';
    const secret = process.env.ADMIN_SECRET || '';

    if (!expectedPass || !secret) {
      return res.status(500).json({ ok: false, error: 'Configura ADMIN_PASSWORD e ADMIN_SECRET su Vercel' });
    }

    if (user === expectedUser && pass === expectedPass) {
      res.setHeader('Set-Cookie', createSessionCookie(user, secret));
      return res.status(200).json({ ok: true, authenticated: true, user });
    }

    return res.status(401).json({ ok: false, error: 'Credenziali non valide' });
  }

  if (req.method === 'DELETE') {
    res.setHeader('Set-Cookie', clearSessionCookie());
    return res.status(200).json({ ok: true, authenticated: false });
  }

  return res.status(405).json({ error: 'Metodo non consentito' });
}