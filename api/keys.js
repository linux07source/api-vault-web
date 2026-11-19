import crypto from 'crypto';
import { isAuthenticated } from './auth.js';

function getSupabaseConfig() {
  const url = String(process.env.SUPABASE_URL || '').trim().replace(/\/+$/, '');
  const serviceKey = String(process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();

  if (!url || !serviceKey) {
    throw new Error('Variabili SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY mancanti');
  }

  return {
    baseUrl: `${url}/rest/v1/api_keys`,
    headers: {
      'Content-Type': 'application/json',
      apikey: serviceKey,
      Authorization: `Bearer ${serviceKey}`,
    },
  };
}

function mapRowToKey(row) {
  return {
    apiKey: row.api_key,
    name: row.name,
    scope: row.scope,
    active: Boolean(row.active),
    expiresAt: row.expires_at ?? null,
    hits: Number(row.hits ?? 0),
    createdAt: Number(row.created_at ?? 0),
  };
}

function mapKeyToRow(record) {
  return {
    api_key: record.apiKey,
    name: record.name,
    scope: record.scope,
    active: record.active,
    expires_at: record.expiresAt,
    hits: record.hits,
    created_at: record.createdAt,
  };
}

export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: 'Non autorizzato: effettua il login' });
  }

  let sb;
  try {
    sb = getSupabaseConfig();
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }

  try {
    if (req.method === 'GET') {
      const response = await fetch(`${sb.baseUrl}?select=*&order=created_at.desc`, {
        method: 'GET',
        headers: sb.headers,
      });

      const data = await response.json();
      if (!response.ok) {
        return res.status(response.status).json({
          error: data?.message || 'Errore durante la lettura delle chiavi da Supabase',
        });
      }

      const list = Array.isArray(data) ? data.map(mapRowToKey) : [];
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

      const response = await fetch(sb.baseUrl, {
        method: 'POST',
        headers: {
          ...sb.headers,
          Prefer: 'return=representation',
        },
        body: JSON.stringify(mapKeyToRow(record)),
      });

      const data = await response.json();
      if (!response.ok) {
        return res.status(response.status).json({
          error: data?.message || 'Errore durante il salvataggio della chiave su Supabase',
        });
      }

      const created = Array.isArray(data) && data[0] ? mapRowToKey(data[0]) : record;
      return res.status(201).json({ ok: true, key: created });
    }

    if (req.method === 'PATCH') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
      const apiKey = String(body.apiKey || '').trim();
      if (!apiKey) return res.status(400).json({ error: 'apiKey mancante' });

      const getRes = await fetch(
        `${sb.baseUrl}?api_key=eq.${encodeURIComponent(apiKey)}&select=*`,
        {
          method: 'GET',
          headers: sb.headers,
        }
      );

      const existingRows = await getRes.json();
      if (!getRes.ok) {
        return res.status(getRes.status).json({
          error: existingRows?.message || 'Errore durante la ricerca della chiave',
        });
      }

      if (!Array.isArray(existingRows) || existingRows.length === 0) {
        return res.status(404).json({ error: 'Chiave non trovata' });
      }

      const record = mapRowToKey(existingRows[0]);

      if (typeof body.active === 'boolean') {
        record.active = body.active;
      }
      if ('expiresAt' in body) {
        record.expiresAt = body.expiresAt ? String(body.expiresAt).trim() : null;
      }
      if (typeof body.name === 'string' && body.name.trim()) {
        record.name = body.name.trim();
      }

      const patchRes = await fetch(
        `${sb.baseUrl}?api_key=eq.${encodeURIComponent(apiKey)}`,
        {
          method: 'PATCH',
          headers: {
            ...sb.headers,
            Prefer: 'return=representation',
          },
          body: JSON.stringify(mapKeyToRow(record)),
        }
      );

      const updatedData = await patchRes.json();
      if (!patchRes.ok) {
        return res.status(patchRes.status).json({
          error: updatedData?.message || 'Errore durante l\'aggiornamento della chiave',
        });
      }

      const updated = Array.isArray(updatedData) && updatedData[0] ? mapRowToKey(updatedData[0]) : record;
      return res.status(200).json({ ok: true, key: updated });
    }

    if (req.method === 'DELETE') {
      const apiKey = String(req.query.apiKey || '').trim();
      if (!apiKey) return res.status(400).json({ error: 'apiKey mancante' });

      const delRes = await fetch(
        `${sb.baseUrl}?api_key=eq.${encodeURIComponent(apiKey)}`,
        {
          method: 'DELETE',
          headers: sb.headers,
        }
      );

      if (!delRes.ok) {
        const errData = await delRes.json().catch(() => ({}));
        return res.status(delRes.status).json({
          error: errData?.message || 'Errore durante l\'eliminazione della chiave',
        });
      }

      return res.status(200).json({ ok: true });
    }

    return res.status(405).json({ error: 'Metodo non consentito' });
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Errore interno del server' });
  }
}