// =============================================================
// Cipher — a minimal, local-first, E2E encrypted chat
// FIXED: QR scanning + Safari stability improvements
// =============================================================

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------------------------------------------------------------
// IndexedDB (UNCHANGED)
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
// base64 helpers (UNCHANGED)
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
// Identity (UNCHANGED)
// ---------------------------------------------------------------
let myIdentity = null;

async function ensureIdentity() {
  const existing = await idbGet('identity', 'me');
  if (existing) {
    myIdentity = existing;
    return;
  }

  const pair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  );

  const pubRaw = await crypto.subtle.exportKey('raw', pair.publicKey);
  const privPkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey);

  const nonExtractablePriv = await crypto.subtle.importKey(
    'pkcs8', privPkcs8,
    { name: 'ECDH', namedCurve: 'P-256' },
    false, ['deriveBits']
  );

  myIdentity = {
    id: 'me',
    privateKey: nonExtractablePriv,
    publicKeyRaw: bufToB64(pubRaw)
  };

  await idbPut('identity', myIdentity);
}

// ---------------------------------------------------------------
// Crypto (UNCHANGED)
// ---------------------------------------------------------------
async function importPeerPublicKey(pubRawB64) {
  return crypto.subtle.importKey(
    'raw', b64ToBuf(pubRawB64),
    { name: 'ECDH', namedCurve: 'P-256' },
    false, []
  );
}

async function deriveSharedBits(peerPublicKey) {
  return crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerPublicKey },
    myIdentity.privateKey,
    256
  );
}

async function deriveAesKey(sharedBits) {
  const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('cipher-app-v1') },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// ---------------------------------------------------------------
// 🔥 FIXED QR SCANNER SECTION
// ---------------------------------------------------------------
let scanStream = null;
let scanRAF = null;

async function startScanLoop() {
  const video = document.getElementById('scan-video');
  const statusEl = document.getElementById('scan-status');

  statusEl.textContent = 'Requesting camera access…';

  try {
    scanStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment' }
    });
  } catch (e) {
    statusEl.textContent = 'Camera blocked in Safari settings.';
    return;
  }

  video.srcObject = scanStream;
  await video.play().catch(() => {});

  statusEl.textContent = 'Scanning for QR code...';

  const canvas = document.getElementById('scan-canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });

  const tick = () => {
    if (
      video.readyState === video.HAVE_ENOUGH_DATA &&
      video.videoWidth > 0 &&
      video.videoHeight > 0
    ) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;

      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      if (typeof jsQR === "function") {
        const code = jsQR(imageData.data, imageData.width, imageData.height);

        if (code && code.data) {
          handleScanResult(code.data);
          return;
        }
      } else {
        statusEl.textContent = "jsQR not loaded";
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

// ---------------------------------------------------------------
// QR Handling (UNCHANGED LOGIC)
// ---------------------------------------------------------------
async function handleScanResult(raw) {
  stopScanLoop();

  let payload;
  try { payload = JSON.parse(raw); } catch { return; }

  if (!payload || payload.t !== 'cipher-pubkey' || !payload.k) {
    startScanLoop();
    return;
  }

  const peerPublicKey = await importPeerPublicKey(payload.k);
  const sharedBits = await deriveSharedBits(peerPublicKey);

  console.log("PAIR SUCCESS:", sharedBits.byteLength);
}

// ---------------------------------------------------------------
// Boot
// ---------------------------------------------------------------
(async function boot() {
  await ensureIdentity();
})();
