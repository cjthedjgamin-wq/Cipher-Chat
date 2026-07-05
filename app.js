// =============================================================
// Cipher - Stable UI Core (no black screen version)
// =============================================================

console.log("APP JS LOADED");

// -----------------------------
// SAFE SCREEN SWITCHER
// -----------------------------
function show(id) {
  console.log("Switching to:", id);

  document.querySelectorAll(".screen").forEach(s => {
    s.style.display = "none";
  });

  const el = document.getElementById(id);

  if (!el) {
    console.warn("Missing screen:", id);
    document.getElementById("screen-contacts").style.display = "block";
    return;
  }

  el.style.display = "block";
}

// -----------------------------
// BOOT
// -----------------------------
(function boot() {
  console.log("BOOT START");

  try {
    show("screen-contacts");
  } catch (e) {
    console.error("BOOT ERROR:", e);
  }

  bindUI();

  console.log("BOOT DONE");
})();

// -----------------------------
// UI BUTTON BINDING
// -----------------------------
function bindUI() {
  const addBtn = document.getElementById("btn-add-friend");
  if (addBtn) {
    addBtn.onclick = () => {
      alert("add friend worked");

      // IMPORTANT: safe navigation
      show("screen-show-qr");

      renderQR();
    };
  }

  const backBtns = document.querySelectorAll("[data-back]");
  backBtns.forEach(btn => {
    btn.onclick = () => {
      show("screen-contacts");
    };
  });

  const scanBtn = document.getElementById("btn-goto-scan");
  if (scanBtn) {
    scanBtn.onclick = () => {
      alert("scan opened");
      show("screen-scan");
    };
  }

  const settingsBtn = document.getElementById("btn-open-settings");
  if (settingsBtn) {
    settingsBtn.onclick = () => {
      alert("settings opened");
      show("screen-settings");
    };
  }
}

// -----------------------------
// QR (SAFE)
// -----------------------------
function renderQR() {
  const container = document.getElementById("qr");

  if (!container) {
    console.warn("QR container missing");
    return;
  }

  container.innerHTML = "";

  if (typeof QRCode === "undefined") {
    container.innerText = "QRCode library not loaded";
    return;
  }

  const data = "cipher-test-pairing";

  try {
    QRCode.toCanvas(document.createElement("canvas"), data, function (err, canvas) {
      if (err) {
        console.error(err);
        return;
      }
      container.appendChild(canvas);
    });
  } catch (e) {
    console.error("QR error:", e);
  }
}
