/* ===========================
   SECURE VAULT STORAGE ENGINE
   =========================== */

const systemKey = "vault-system-secret";

let vaultMemory = null;   // decrypted in RAM only
let vaultKey = null;      // crypto key in session

/* ===== KEY DERIVATION ===== */
async function deriveKey(pin, salt) {
 const enc = new TextEncoder();

 const baseKey = await crypto.subtle.importKey(
  "raw",
  enc.encode(pin + systemKey),
  "PBKDF2",
  false,
  ["deriveKey"]
 );

 return crypto.subtle.deriveKey(
  {
   name: "PBKDF2",
   salt: salt,
   iterations: 100000,
   hash: "SHA-256"
  },
  baseKey,
  { name: "AES-GCM", length: 256 },
  false,
  ["encrypt", "decrypt"]
 );
}

/* ===== CREATE NEW VAULT ===== */
async function createVault(pin) {
 const salt = crypto.getRandomValues(new Uint8Array(16));
 vaultKey = await deriveKey(pin, salt);

 vaultMemory = {
  entries: []
 };

 await saveVault();

 localStorage.setItem("vaultSalt", JSON.stringify(Array.from(salt)));
}

/* ===== UNLOCK VAULT ===== */
async function unlockVault(pin) {

 const saltStored = localStorage.getItem("vaultSalt");
 const vaultStored = localStorage.getItem("vaultSecure");

 if (!saltStored || !vaultStored) return false;

 const salt = new Uint8Array(JSON.parse(saltStored));
 vaultKey = await deriveKey(pin, salt);

 try {
  const vaultObj = JSON.parse(vaultStored);

  const iv = new Uint8Array(vaultObj.iv);
  const data = new Uint8Array(vaultObj.data);

  const decrypted = await crypto.subtle.decrypt(
   { name: "AES-GCM", iv: iv },
   vaultKey,
   data
  );

  const dec = new TextDecoder();
  vaultMemory = JSON.parse(dec.decode(decrypted));

  return true;

 } catch (e) {
  return false;
 }
}

/* ===== SAVE VAULT ===== */
async function saveVault() {

 if (!vaultKey || !vaultMemory) return;

 const enc = new TextEncoder();
 const iv = crypto.getRandomValues(new Uint8Array(12));

 const encrypted = await crypto.subtle.encrypt(
  { name: "AES-GCM", iv: iv },
  vaultKey,
  enc.encode(JSON.stringify(vaultMemory))
 );

 const payload = {
  iv: Array.from(iv),
  data: Array.from(new Uint8Array(encrypted))
 };

 localStorage.setItem("vaultSecure", JSON.stringify(payload));
}

/* ===== RESET VAULT ===== */
function resetVault() {
 localStorage.removeItem("vaultSecure");
 localStorage.removeItem("vaultSalt");
 vaultMemory = null;
 vaultKey = null;
 alert("Vault reset. Create new PIN.");
 location.reload();
}

/* ===== LOCK VAULT ===== */
function lockVault() {
 vaultMemory = null;
 vaultKey = null;
}

/* ===== AUTO LOCK EVENTS ===== */
window.addEventListener("beforeunload", lockVault);

document.addEventListener("visibilitychange", () => {
 if (document.hidden) {
  lockVault();
 }
});
