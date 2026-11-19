import crypto from 'crypto';
import { redis, KEYS_HASH } from './_redis.js';
import { isAuthenticated } from './auth.js';

export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: 'Non autorizzato: effettua il login' });
  }

  if (req.method === 'GET') {
    const raw = (await redis.hgetall(KEYS_HASH)) || {};
    const list = Object.values(raw).map((item) =>
      typeof item === 'string' ? JSON.parse(item) : item
    );
    list.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    return res.status(200).json({ keys: list });
  }

  if (req.method === 'POST') {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const name = String(body.name || 'App CLI').trim();
    const scope = String(body.scope || 'cli:exec').trim();
    const expiresAt = body.expiresAt ? String(body.expiresAt).trim() : null;

    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') || 'cli';
    const apiKey = `vault_${slug}_${crypto.randomBytes(8).toString('hex')}`;

    const record = {
      apiKey,
      name,
      scope,
      active: true,
      expiresAt,
      hits: 0,
      createdAt: Date.now(),
    };

    await redis.hset(KEYS_HASH, { [apiKey]: JSON.stringify(record) });
    return res.status(201).json({ ok: true, key: record });
  }

  if (req.method === 'PATCH') {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const apiKey = String(body.apiKey || '').trim();
    if (!apiKey) return res.status(400).json({ error: 'apiKey mancante' });

    const existingRaw = await redis.hget(KEYS_HASH, apiKey);
    if (!existingRaw) return res.status(404).json({ error: 'Chiave non trovata' });

    const record = typeof existingRaw === 'string' ? JSON.parse(existingRaw) : existingRaw;

    if (typeof body.active === 'boolean') {
      record.active = body.active;
    }
    if ('expiresAt' in body) {
      record.expiresAt = body.expiresAt ? String(body.expiresAt).trim() : null;
    }
    if (typeof body.name === 'string' && body.name.trim()) {
      record.name = body.name.trim();
    }

    await redis.hset(KEYS_HASH, { [apiKey]: JSON.stringify(record) });
    return res.status(200).json({ ok: true, key: record });
  }

  if (req.method === 'DELETE') {
    const apiKey = String(req.query.apiKey || '').trim();
    if (!apiKey) return res.status(400).json({ error: 'apiKey mancante' });

    await redis.hdel(KEYS_HASH, apiKey);
    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: 'Metodo non consentito' });
}