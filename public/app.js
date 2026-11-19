const loginView = document.getElementById('loginView');
const dashView = document.getElementById('dashView');
const keysList = document.getElementById('keysList');

async function checkSession() {
  const res = await fetch('/api/auth');
  const data = await res.json();
  if (data.authenticated) {
    loginView.style.display = 'none';
    dashView.style.display = 'block';
    loadKeys();
  } else {
    loginView.style.display = 'block';
    dashView.style.display = 'none';
  }
}

document.getElementById('btnLogin').addEventListener('click', async () => {
  const username = document.getElementById('loginUser').value;
  const password = document.getElementById('loginPass').value;
  const res = await fetch('/api/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json();
  if (data.ok) {
    document.getElementById('loginMsg').textContent = '';
    checkSession();
  } else {
    document.getElementById('loginMsg').textContent = data.error || 'Errore login';
  }
});

document.getElementById('btnLogout').addEventListener('click', async () => {
  await fetch('/api/auth', { method: 'DELETE' });
  checkSession();
});

document.getElementById('btnCreate').addEventListener('click', async () => {
  const name = document.getElementById('newName').value;
  const expVal = document.getElementById('newExp').value;
  const expiresAt = expVal ? new Date(expVal).toISOString() : null;

  const res = await fetch('/api/keys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, expiresAt }),
  });
  if (res.ok) {
    document.getElementById('newName').value = '';
    document.getElementById('newExp').value = '';
    loadKeys();
  }
});

async function setExpiration(apiKey, expiresAt) {
  await fetch('/api/keys', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ apiKey, expiresAt }),
  });
  loadKeys();
}

async function toggleActive(apiKey, active) {
  await fetch('/api/keys', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ apiKey, active }),
  });
  loadKeys();
}

async function deleteKey(apiKey) {
  await fetch(`/api/keys?apiKey=${encodeURIComponent(apiKey)}`, { method: 'DELETE' });
  loadKeys();
}

async function loadKeys() {
  const res = await fetch('/api/keys');
  if (!res.ok) return;
  const data = await res.json();
  const list = data.keys || [];

  keysList.innerHTML = list.map((k) => {
    const expired = k.expiresAt && Date.now() >= new Date(k.expiresAt).getTime();
    const statusLabel = !k.active ? 'DISATTIVA' : expired ? 'SCADUTA (BLOCCATA PER UPDATE)' : 'ATTIVA';
    return `
      <div class="card">
        <div style="display:flex; justify-content:space-between; gap:8px; flex-wrap:wrap;">
          <strong>${k.name}</strong>
          <span class="muted">${statusLabel} • Avvii: ${k.hits || 0}</span>
        </div>
        <div style="margin:8px 0;"><code>${k.apiKey}</code></div>
        <div class="muted" style="margin-bottom:10px;">
          Scadenza: ${k.expiresAt ? new Date(k.expiresAt).toLocaleString('it-IT') : 'Nessuna'}
        </div>
        <div class="row" style="margin-bottom:0;">
          <button class="ghost" onclick="toggleActive('${k.apiKey}', ${!k.active})">
            ${k.active ? 'Disattiva' : 'Riattiva'}
          </button>
          <button class="ghost" onclick="setExpiration('${k.apiKey}', new Date(Date.now() + 60000).toISOString())">
            Scade tra 1 min (Test Update)
          </button>
          <button class="ghost" onclick="setExpiration('${k.apiKey}', null)">
            Rimuovi scadenza
          </button>
          <button class="danger" onclick="deleteKey('${k.apiKey}')">Elimina</button>
        </div>
      </div>
    `;
  }).join('') || '<p class="muted">Nessuna API Key creata.</p>';
}

checkSession();