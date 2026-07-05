// =============================================================
// Cipher - Stable Full Client (Safari-safe version)
// =============================================================

const enc = new TextEncoder();
const dec = new TextDecoder();

// -----------------------------
// DB
// -----------------------------
const DB_NAME = "cipher-db";
const DB_VERSION = 1;

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);

    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("identity"))
        db.createObjectStore("identity", { keyPath: "id" });

      if (!db.objectStoreNames.contains("contacts"))
        db.createObjectStore("contacts", { keyPath: "id" });

      if (!db.objectStoreNames.contains("settings"))
        db.createObjectStore("settings", { keyPath: "key" });
    };

    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet(store, key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readonly");
    const req = tx.objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

async function idbPut(store, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).put(value);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// -----------------------------
// UI helper
// -----------------------------
function show(id) {
  document.querySelectorAll(".screen").forEach(s => s.style.display = "none");
  const el = document.getElementById(id);
  if (el) el.style.display = "block";
}

// -----------------------------
// Identity (simplified safe version)
// -----------------------------
let myIdentity = null;

async function ensureIdentity() {
  const existing = await idbGet("identity", "me");
  if (existing) {
    myIdentity = existing;
    return;
  }

  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );

  const pub = await crypto.subtle.exportKey("raw", pair.publicKey);

  myIdentity = {
    id: "me",
    publicKey: btoa(String.fromCharCode(...new Uint8Array(pub)))
  };

  await idbPut("identity", myIdentity);
}

// -----------------------------
// Contacts
// -----------------------------
async function renderContacts() {
  const list = document.getElementById("contact-list");
  if (!list) return;

  const db = await openDB();
  const tx = db.transaction("contacts", "readonly");
  const req = tx.objectStore("contacts").getAll();

  req.onsuccess = () => {
    const contacts = req.result || [];
    list.innerHTML = "";

    contacts.forEach(c => {
      const div = document.createElement("div");
      div.className = "contact-row";
      div.textContent = c.name || "Friend";
      div.onclick = () => alert("Open chat: " + c.name);
      list.appendChild(div);
    });

    if (!contacts.length) {
      list.innerHTML = "<p>No contacts yet</p>";
    }
  };
}

// -----------------------------
// QR
// -----------------------------
function showMyQR() {
  const el = document.getElementById("qr");
  if (!el || typeof QRCode === "undefined") return;

  el.innerHTML = "";
  QRCode.toCanvas(el, myIdentity.publicKey, function () {});
}

// -----------------------------
// Buttons
// -----------------------------
function bindUI() {
  const add = document.getElementById("btn-add-friend");
  if (add) {
    add.onclick = () => {
      show("screen-show-qr");
      showMyQR();
    };
  }

  const back = document.querySelectorAll("[data-back]");
  back.forEach(b => {
    b.onclick = () => show("screen-contacts");
  });
}

// -----------------------------
// Boot
// -----------------------------
(async function boot() {
  console.log("BOOT");

  try {
    await ensureIdentity();
    await renderContacts();
    bindUI();
    show("screen-contacts");
  } catch (e) {
    console.log("BOOT ERROR", e);
  }
})();
