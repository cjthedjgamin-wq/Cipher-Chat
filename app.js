// =============================================================
// Cipher — a minimal, local-first, end-to-end encrypted 1:1 chat
// =============================================================
// Security model, in short:
//  - Each device generates its own ECDH (P-256) keypair on first run.
//    The private key is stored non-extractable in IndexedDB — it can
//    be USED by this browser, but never read out or exported again.
//  - Adding a friend = scanning each other's public key via QR, in
//    person. No account system, no server-side directory of who
//    knows whom.
//  - Both sides independently derive the same AES-256 key from
//    (my private key + their public key) via ECDH + HKDF. This key
//    is never transmitted anywhere.
//  - The relay server (see relay_server.py) only ever forwards
//    already-encrypted bytes between a room ID derived from both
//    public keys. It cannot read messages and doesn't log/store them.
//  - Message history is OFF by default. If you turn it on in
//    Settings, history is kept only in this browser's local storage —
//    never uploaded anywhere.

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------------------------------------------------------------
// IndexedDB
// ---------------------------------------------------------------
const DB_NAME = 'cipher-db';
const DB_VERSION = 1;

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('identity')) db.createObjectStore('identity', { keyPath: 'id' });
      if (!db.objectStoreNames.contains('contacts')) db.createObjectStore('contacts', { keyPath: 'id' });
      if (!db.objectStoreNames.contains('settings')) db.createObjectStore('settings', { keyPath: 'key' });
      if (!db.objectStoreNames.contains('messages')) {
        const s = db.createObjectStore('messages', { keyPath: 'msgId', autoIncrement: true });
        s.createIndex('byContact', 'contactId');
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet(store, key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

async function idbPut(store, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).put(value);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function idbGetAll(store) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}

async function idbGetByIndex(store, indexName, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).index(indexName).getAll(value);
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}

async function idbClearAll() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(['identity', 'contacts', 'settings', 'messages'], 'readwrite');
    tx.objectStore('identity').clear();
    tx.objectStore('contacts').clear();
    tx.objectStore('settings').clear();
    tx.objectStore('messages').clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---------------------------------------------------------------
// base64 helpers
// ---------------------------------------------------------------
function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64ToBuf(b64) {
  const norm = b64.replace(/-/g, '+').replace(/_/g, '/');
  const pad = norm.length % 4 === 0 ? '' : '='.repeat(4 - (norm.length % 4));
  const bin = atob(norm + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

// ---------------------------------------------------------------
// Identity (my own long-term ECDH keypair)
// ---------------------------------------------------------------
let myIdentity = null; // { privateKey: CryptoKey (non-extractable), publicKeyRaw: base64 }

async function ensureIdentity() {
  const existing = await idbGet('identity', 'me');
  if (existing) {
    myIdentity = existing;
    return;
  }
  // generate fresh, extractable=true JUST long enough to export + re-import non-extractable
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  );
  const pubRaw = await crypto.subtle.exportKey('raw', pair.publicKey);
  const privPkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  const nonExtractablePriv = await crypto.subtle.importKey(
    'pkcs8', privPkcs8, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']
  );
  myIdentity = { id: 'me', privateKey: nonExtractablePriv, publicKeyRaw: bufToB64(pubRaw) };
  await idbPut('identity', myIdentity);
}

// ---------------------------------------------------------------
// Crypto: derive shared AES key + room id + safety number from a peer's public key
// ---------------------------------------------------------------
async function importPeerPublicKey(pubRawB64) {
  return crypto.subtle.importKey(
    'raw', b64ToBuf(pubRawB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
}

async function deriveSharedBits(peerPublicKey) {
  return crypto.subtle.deriveBits({ name: 'ECDH', public: peerPublicKey }, myIdentity.privateKey, 256);
}

async function deriveAesKey(sharedBits) {
  const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('cipher-app-v1') },
    hkdfKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function roomIdFor(myPubB64, peerPubB64) {
  const sorted = [myPubB64, peerPubB64].sort().join('|');
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(sorted));
  return bufToB64(digest).replace(/[^a-zA-Z0-9]/g, '').slice(0, 32);
}

async function safetyNumberFor(sharedBits) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', sharedBits));
  const groups = [];
  for (let i = 0; i < 8; i += 2) {
    const n = ((digest[i] << 8) | digest[i + 1]) % 10000;
    groups.push(String(n).padStart(4, '0'));
  }
  return groups.join('  ');
}

async function encryptMessage(aesKey, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, enc.encode(plaintext));
  const blob = new Uint8Array(iv.length + ct.byteLength);
  blob.set(iv, 0);
  blob.set(new Uint8Array(ct), iv.length);
  return bufToB64(blob.buffer);
}

async function decryptMessage(aesKey, token) {
  const blob = new Uint8Array(b64ToBuf(token));
  const iv = blob.slice(0, 12);
  const ct = blob.slice(12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
  return dec.decode(pt);
}

// ---------------------------------------------------------------
// Settings
// ---------------------------------------------------------------
async function getSetting(key, fallback) {
  const rec = await idbGet('settings', key);
  return rec ? rec.value : fallback;
}
async function setSetting(key, value) {
  await idbPut('settings', { key, value });
}

// ---------------------------------------------------------------
// UI navigation
// ---------------------------------------------------------------
function show(screenId) {
  document.querySelectorAll('.screen').forEach(el => el.classList.add('hidden'));
  document.getElementById(screenId).classList.remove('hidden');
}
document.querySelectorAll('[data-back]').forEach(btn => {
  btn.addEventListener('click', () => {
    stopScanLoop();
    disconnectChat();
    show(btn.dataset.back);
    renderContacts();
  });
});

// ---------------------------------------------------------------
// Contacts list
// ---------------------------------------------------------------
async function renderContacts() {
  const list = document.getElementById('contact-list');
  const contacts = await idbGetAll('contacts');
  list.innerHTML = '';
  if (contacts.length === 0) {
    list.innerHTML = `<div class="empty-state">
      <div class="glyph">◎</div>
      <h3>No contacts yet</h3>
      <p>Tap the + button and scan QR codes with a friend, in person, to start an encrypted chat.</p>
    </div>`;
    return;
  }
  contacts.forEach(c => {
    const row = document.createElement('div');
    row.className = 'contact-row';
    row.innerHTML = `<div class="avatar">${(c.nickname || '?').slice(0,1).toUpperCase()}</div>
      <div><div class="contact-name">${escapeHtml(c.nickname)}</div>
      <div class="contact-meta">${c.roomId.slice(0,12)}…</div></div>`;
    row.addEventListener('click', () => openChat(c));
    list.appendChild(row);
  });
}
function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

// ---------------------------------------------------------------
// Add friend flow
// ---------------------------------------------------------------
let pendingPeer = null; // { publicKeyRaw, sharedBits, aesKey, roomId, safetyNumber }

document.getElementById('btn-add-friend').addEventListener('click', () => {
  document.getElementById('qr-canvas-holder').innerHTML = '';
  new QRCode(document.getElementById('qr-canvas-holder'), {
    text: JSON.stringify({ t: 'cipher-pubkey', k: myIdentity.publicKeyRaw }),
    width: 220, height: 220, colorDark: '#0B0E11', colorLight: '#ffffff'
  });
  show('screen-show-qr');
});

document.getElementById('btn-goto-scan').addEventListener('click', () => {
  show('screen-scan');
  startScanLoop();
});

let scanStream = null;
let scanRAF = null;

async function startScanLoop() {
  const video = document.getElementById('scan-video');
  const statusEl = document.getElementById('scan-status');
  statusEl.textContent = 'Requesting camera access…';
  try {
    scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
  } catch (e) {
    statusEl.textContent = 'Camera access denied. Enable it in Settings > Safari to scan.';
    return;
  }
  video.srcObject = scanStream;
  statusEl.textContent = 'Scanning…';
  const canvas = document.getElementById('scan-canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });

  const tick = () => {
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height);
      if (code) {
        handleScanResult(code.data);
        return;
      }
    }
    scanRAF = requestAnimationFrame(tick);
  };
  scanRAF = requestAnimationFrame(tick);
}

function stopScanLoop() {
  if (scanRAF) cancelAnimationFrame(scanRAF);
  scanRAF = null;
  if (scanStream) {
    scanStream.getTracks().forEach(t => t.stop());
    scanStream = null;
  }
}

async function handleScanResult(raw) {
  stopScanLoop();
  let payload;
  try { payload = JSON.parse(raw); } catch { payload = null; }
  if (!payload || payload.t !== 'cipher-pubkey' || !payload.k) {
    document.getElementById('scan-status').textContent = 'That QR code isn\'t a Cipher contact code.';
    startScanLoop();
    return;
  }
  const peerPublicKey = await importPeerPublicKey(payload.k);
  const sharedBits = await deriveSharedBits(peerPublicKey);
  const aesKey = await deriveAesKey(sharedBits);
  const roomId = await roomIdFor(myIdentity.publicKeyRaw, payload.k);
  const safetyNumber = await safetyNumberFor(sharedBits);
  pendingPeer = { publicKeyRaw: payload.k, aesKey, roomId, safetyNumber };
  document.getElementById('fingerprint-display').textContent = safetyNumber;
  document.getElementById('nickname-input').value = '';
  show('screen-confirm');
}

document.getElementById('btn-save-contact').addEventListener('click', async () => {
  const nickname = document.getElementById('nickname-input').value.trim() || 'Friend';
  const contact = {
    id: pendingPeer.roomId,
    nickname,
    publicKeyRaw: pendingPeer.publicKeyRaw,
    roomId: pendingPeer.roomId,
    safetyNumber: pendingPeer.safetyNumber,
    createdAt: Date.now(),
  };
  await idbPut('contacts', contact);
  pendingPeer = null;
  show('screen-contacts');
  renderContacts();
});

// ---------------------------------------------------------------
// Chat
// ---------------------------------------------------------------
let activeContact = null;
let activeSocket = null;
let activeAesKey = null;
let keepHistory = false;

async function openChat(contact) {
  activeContact = contact;
  document.getElementById('chat-name').textContent = contact.nickname;
  document.getElementById('chat-avatar').textContent = contact.nickname.slice(0, 1).toUpperCase();
  document.getElementById('messages').innerHTML = '';
  setChatStatus('connecting');
  show('screen-chat');

  const peerPublicKey = await importPeerPublicKey(contact.publicKeyRaw);
  const sharedBits = await deriveSharedBits(peerPublicKey);
  activeAesKey = await deriveAesKey(sharedBits);

  keepHistory = await getSetting('keepHistory', false);
  if (keepHistory) {
    const history = await idbGetByIndex('messages', 'byContact', contact.id);
    history.sort((a, b) => a.ts - b.ts);
    history.forEach(m => addBubble(m.mine ? 'mine' : 'theirs', m.text));
  }

  connectChat(contact.roomId);
}

async function connectChat(roomId) {
  const relayUrl = await getSetting('relayUrl', '');
  if (!relayUrl) {
    addBubble('system', 'No relay server set. Add one in Settings first.');
    setChatStatus('');
    return;
  }
  try {
    activeSocket = new WebSocket(relayUrl);
  } catch (e) {
    addBubble('system', 'Could not connect: ' + e.message);
    return;
  }
  activeSocket.onopen = () => {
    activeSocket.send('JOIN:' + roomId);
  };
  activeSocket.onmessage = async (ev) => {
    const data = ev.data;
    if (data.startsWith('ROLE:')) {
      setChatStatus('connected');
      addBubble('system', 'Encrypted session ready.');
      return;
    }
    if (data.startsWith('MSG:')) {
      const token = data.slice(4);
      try {
        const plaintext = await decryptMessage(activeAesKey, token);
        addBubble('theirs', plaintext);
        if (keepHistory) {
          await idbPut('messages', { contactId: activeContact.id, mine: false, text: plaintext, ts: Date.now() });
        }
      } catch (e) {
        addBubble('system', 'Received a message that failed to decrypt.');
      }
    }
  };
  activeSocket.onclose = () => setChatStatus('');
  activeSocket.onerror = () => setChatStatus('');
}

function disconnectChat() {
  if (activeSocket) {
    try { activeSocket.close(); } catch {}
    activeSocket = null;
  }
  activeContact = null;
  activeAesKey = null;
}

function setChatStatus(state) {
  const dot = document.getElementById('chat-dot');
  const label = document.getElementById('chat-status');
  dot.className = 'status-dot' + (state ? ' ' + state : '');
  label.lastChild && (label.lastChild.textContent = ' ' + (state || 'offline'));
}

function addBubble(kind, text) {
  const wrap = document.getElementById('messages');
  const el = document.createElement('div');
  el.className = 'msg ' + kind;
  el.textContent = text;
  wrap.appendChild(el);
  wrap.scrollTop = wrap.scrollHeight;
}

document.getElementById('btn-send').addEventListener('click', sendCurrentMessage);
document.getElementById('msg-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') sendCurrentMessage();
});

async function sendCurrentMessage() {
  const input = document.getElementById('msg-input');
  const text = input.value.trim();
  if (!text || !activeSocket || activeSocket.readyState !== WebSocket.OPEN) return;
  const token = await encryptMessage(activeAesKey, text);
  activeSocket.send('MSG:' + token);
  addBubble('mine', text);
  if (keepHistory) {
    await idbPut('messages', { contactId: activeContact.id, mine: true, text, ts: Date.now() });
  }
  input.value = '';
}

// ---------------------------------------------------------------
// Settings screen
// ---------------------------------------------------------------
document.getElementById('btn-open-settings').addEventListener('click', async () => {
  document.getElementById('relay-input').value = await getSetting('relayUrl', '');
  document.getElementById('toggle-history').checked = await getSetting('keepHistory', false);
  document.getElementById('my-pubkey-display').textContent = myIdentity.publicKeyRaw;
  show('screen-settings');
});

document.getElementById('btn-save-relay').addEventListener('click', async () => {
  const val = document.getElementById('relay-input').value.trim();
  await setSetting('relayUrl', val);
  document.getElementById('btn-save-relay').textContent = 'Saved ✓';
  setTimeout(() => { document.getElementById('btn-save-relay').textContent = 'Save'; }, 1200);
});

document.getElementById('toggle-history').addEventListener('change', async (e) => {
  await setSetting('keepHistory', e.target.checked);
});

document.getElementById('btn-wipe').addEventListener('click', async () => {
  if (!confirm('This deletes your identity, contacts, settings, and any local history on THIS device. Your friends will need to re-pair with you afterward. This cannot be undone. Continue?')) return;
  await idbClearAll();
  location.reload();
});

// ---------------------------------------------------------------
// Boot
// ---------------------------------------------------------------
(async function boot() {
  await ensureIdentity();
  await renderContacts();
  show('screen-contacts');

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
})();
