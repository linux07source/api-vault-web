export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  if (req.method !== 'POST') {
    return res.status(405).json({
      authorized: false,
      message: 'Metodo non consentito'
    });
  }

  const supabaseUrl = (process.env.SUPABASE_URL || '').trim().replace(/\/+$/, '');
  const serviceRoleKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();

  if (!supabaseUrl || !serviceRoleKey) {
    return res.status(500).json({
      authorized: false,
      message: 'Variabili SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY mancanti'
    });
  }

  let body = {};
  try {
    if (typeof req.body === 'string') {
      body = req.body.trim() ? JSON.parse(req.body) : {};
    } else if (req.body && typeof req.body === 'object') {
      body = req.body;
    }
  } catch {
    return res.status(400).json({
      authorized: false,
      message: 'Corpo JSON non valido'
    });
  }

  const headerKey = (req.headers['x-api-key'] || '').toString().trim();
  const providedKey = (
    headerKey ||
    body.apiKey ||
    body.api_key ||
    body.key ||
    ''
  )
    .toString()
    .trim();

  if (!providedKey) {
    return res.status(401).json({
      authorized: false,
      message: 'API Key mancante'
    });
  }

  const supabaseHeaders = {
    apikey: serviceRoleKey,
    Authorization: `Bearer ${serviceRoleKey}`,
    'Content-Type': 'application/json'
  };

  try {
    const queryUrl =
      `${supabaseUrl}/rest/v1/api_keys` +
      `?api_key=eq.${encodeURIComponent(providedKey)}` +
      `&select=api_key,name,scope,active,expires_at,hits,last_used,created_at`;

    const selectRes = await fetch(queryUrl, {
      method: 'GET',
      headers: supabaseHeaders
    });

    if (!selectRes.ok) {
      const errText = await selectRes.text();
      return res.status(500).json({
        authorized: false,
        message: `Errore Supabase (${selectRes.status}): ${errText}`
      });
    }

    const rows = await selectRes.json();
    const record = Array.isArray(rows) ? rows[0] : null;

    if (!record) {
      return res.status(401).json({
        authorized: false,
        message: 'API Key non valida'
      });
    }

    if (record.active === false) {
      return res.status(403).json({
        authorized: false,
        message: 'API Key disattivata'
      });
    }

    if (record.expires_at) {
      const expMs = new Date(record.expires_at).getTime();
      if (!Number.isNaN(expMs) && Date.now() >= expMs) {
        return res.status(403).json({
          authorized: false,
          expired: true,
          expiresAt: record.expires_at,
          message: `Accesso in pausa per update (scaduta il ${record.expires_at})`
        });
      }
    }

    const nextHits = Number(record.hits || 0) + 1;
    const nowIso = new Date().toISOString();

    const patchUrl =
      `${supabaseUrl}/rest/v1/api_keys` +
      `?api_key=eq.${encodeURIComponent(providedKey)}`;

    const patchRes = await fetch(patchUrl, {
      method: 'PATCH',
      headers: {
        ...supabaseHeaders,
        Prefer: 'return=minimal'
      },
      body: JSON.stringify({
        hits: nextHits,
        last_used: nowIso
      })
    });

    if (!patchRes.ok) {
      const patchErr = await patchRes.text();
      return res.status(500).json({
        authorized: false,
        message: `Errore aggiornamento statistiche (${patchRes.status}): ${patchErr}`
      });
    }

    return res.status(200).json({
      authorized: true,
      apiName: record.name,
      scope: record.scope,
      message: 'Verifica OK'
    });
  } catch (err) {
    return res.status(500).json({
      authorized: false,
      message: err?.message || 'Errore interno del server'
    });
  }
}