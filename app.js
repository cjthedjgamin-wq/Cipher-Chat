console.log("APP JS LOADED");

// -----------------------------
// SAFE UI TEST VERSION
// -----------------------------

function show(id) {
  document.querySelectorAll('.screen').forEach(s => s.style.display = 'none');
  const el = document.getElementById(id);
  if (el) el.style.display = 'block';
}

// Boot test
(function boot() {
  console.log("BOOT START");

  show('screen-contacts');

  console.log("BOOT DONE");
})();

// -----------------------------
// BUTTON TESTS
// -----------------------------

document.addEventListener("DOMContentLoaded", () => {
  console.log("DOM READY");

  const addBtn = document.getElementById("btn-add-friend");
  if (addBtn) {
    addBtn.onclick = () => {
      alert("ADD FRIEND CLICK WORKS");
      show("screen-show-qr");
    };
  }

  const scanBtn = document.getElementById("btn-goto-scan");
  if (scanBtn) {
    scanBtn.onclick = () => {
      alert("SCAN CLICK WORKS");
      show("screen-scan");
    };
  }

  const settingsBtn = document.getElementById("btn-open-settings");
  if (settingsBtn) {
    settingsBtn.onclick = () => {
      alert("SETTINGS CLICK WORKS");
      show("screen-settings");
    };
  }
});
