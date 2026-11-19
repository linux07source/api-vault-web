import { redis, KEYS_HASH } from './_redis.js';

export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  if (req.method !== 'POST') {
    return res.status(405).json({ authorized: false, message: 'Metodo non consentito' });
  }

  const headerKey = (req.headers['x-api-key'] || '').toString().trim();
  const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
  const providedKey = (headerKey || body.apiKey || '').toString().trim();

  if (!providedKey) {
    return res.status(401).json({ authorized: false, message: 'API Key mancante' });
  }

  const raw = await redis.hget(KEYS_HASH, providedKey);
  if (!raw) {
    return res.status(401).json({ authorized: false, message: 'API Key non valida' });
  }

  const record = typeof raw === 'string' ? JSON.parse(raw) : raw;

  if (record.active === false) {
    return res.status(403).json({ authorized: false, message: 'API Key disattivata' });
  }

  if (record.expiresAt) {
    const expMs = new Date(record.expiresAt).getTime();
    if (!Number.isNaN(expMs) && Date.now() >= expMs) {
      return res.status(403).json({
        authorized: false,
        expired: true,
        expiresAt: record.expiresAt,
        message: `Accesso in pausa per update (scaduta il ${record.expiresAt})`
      });
    }
  }

  record.hits = (record.hits || 0) + 1;
  record.lastUsed = new Date().toISOString();
  await redis.hset(KEYS_HASH, { [providedKey]: JSON.stringify(record) });

  return res.status(200).json({
    authorized: true,
    apiName: record.name,
    scope: record.scope,
    message: 'Verifica OK'
  });
}