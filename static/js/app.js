
async function fetchOnlineUsers() {
  const room = el("room").value || "general";
  const res = await fetch(`/api/online-users?room=${encodeURIComponent(room)}`);
  const data = await res.json();
  const list = document.getElementById("onlineUsers");
  if (!list) return;
  list.innerHTML = "";
  data.users.forEach(user => {
    const li = document.createElement("li");
    li.textContent = user;
    list.appendChild(li);
  });
}

// Utility: base64
function toBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function fromBase64(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// Derive AES-GCM key from passphrase + room (salt = room bytes)
async function deriveKey(passphrase, room) {
  const enc = new TextEncoder();
  const passBytes = enc.encode(passphrase);
  const salt = enc.encode(room);
  const keyMaterial = await crypto.subtle.importKey(
    "raw", passBytes, { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function aesEncrypt(plaintext, passphrase, room) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, room);
  const enc = new TextEncoder();
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
  return { ciphertext: toBase64(ct), iv: toBase64(iv) };
}

async function aesDecrypt(ciphertextB64, ivB64, passphrase, room) {
  try {
    const key = await deriveKey(passphrase, room);
    const iv = fromBase64(ivB64);
    const ct = fromBase64(ciphertextB64);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return new TextDecoder().decode(pt);
  } catch (e) {
    return "[Erreur de déchiffrement AES-GCM]";
  }
}

// Caesar (demo only)
function caesarShift(str, shift) {
  const a = "a".charCodeAt(0), z = "z".charCodeAt(0);
  const A = "A".charCodeAt(0), Z = "Z".charCodeAt(0);
  return Array.from(str).map(ch => {
    const c = ch.charCodeAt(0);
    if (c>=a && c<=z) return String.fromCharCode(((c-a+shift)%26+a));
    if (c>=A && c<=Z) return String.fromCharCode(((c-A+shift)%26+A));
    return ch;
  }).join("");
}

async function encryptMessage(algo, text, passphrase, room) {
  if (algo === "AES-GCM") {
    const {ciphertext, iv} = await aesEncrypt(text, passphrase, room);
    return {algo, ciphertext, iv};
  } else { // CAESAR
    const shift = (passphrase || "key").length % 26;
    const ct = caesarShift(text, shift);
    return {algo: "CAESAR", ciphertext: btoa(unescape(encodeURIComponent(ct))), iv: ""};
  }
}

async function decryptMessage(msg, passphrase, room) {
  if (msg.algo === "AES-GCM") {
    return await aesDecrypt(msg.ciphertext, msg.iv, passphrase, room);
  } else {
    try {
      const ct = decodeURIComponent(escape(atob(msg.ciphertext)));
      const shift = (passphrase || "key").length % 26;
      // reverse shift
      return caesarShift(ct, (26 - shift)%26);
    } catch {
      return "[Erreur de déchiffrement César]";
    }
  }
}

// State
let authToken = null;
let lastId = 0;

function el(id){ return document.getElementById(id); }

async function registerOrLogin(kind) {
  const username = el("username").value.trim();
  if (!username) { alert("Entrez un nom d'utilisateur"); return; }
  const url = kind === "register" ? "/api/register" : "/api/login";
  const res = await fetch(url, {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({username})
  });
  const data = await res.json();
  if (!res.ok) { alert(data.error || "Erreur"); return; }
  authToken = data.token;
  localStorage.setItem("authToken", authToken);
  localStorage.setItem("username", data.username);
  alert(`${kind==="register"?"Compte créé":"Connecté"} en tant que ${data.username}`);
}

async function sendMessage() {
  if (!authToken) { alert("Connectez-vous d'abord."); return; }
  const text = el("message").value;
  const room = el("room").value || "general";
  const passphrase = el("passphrase").value || "";
  const algo = el("algo").value;

  if (!text) return;
  const payload = await encryptMessage(algo, text, passphrase, room);

  const res = await fetch("/api/message", {
    method: "POST",
    headers: {
      "Content-Type":"application/json",
      "Authorization": "Bearer " + authToken
    },
    body: JSON.stringify({room, ...payload})
  });
  const data = await res.json();
  if (!res.ok) {
    alert(data.error || "Erreur d'envoi");
    return;
  }
  el("message").value = "";
}

async function fetchMessages() {
  const room = el("room").value || "general";
  const res = await fetch(`/api/messages?room=${encodeURIComponent(room)}&after_id=${lastId||0}`);
  const data = await res.json();
  const passphrase = el("passphrase").value || "";
  const container = el("messages");

  for (const msg of data.messages) {
    lastId = Math.max(lastId, msg.id);
    const div = document.createElement("div");
    div.className = "msg";
    const meta = document.createElement("div");
    meta.className = "meta";
    const dt = new Date(msg.created_at);
    meta.textContent = `${msg.sender} • ${msg.algo} • ${dt.toLocaleString()}`;
    const body = document.createElement("div");
    body.className = "body";
    const plaintext = await decryptMessage(msg, passphrase, room);
    body.textContent = plaintext;
    div.appendChild(meta);
    div.appendChild(body);
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
  }
}

function restoreSession() {
  const tok = localStorage.getItem("authToken");
  const user = localStorage.getItem("username");
  if (tok && user) {
    authToken = tok;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  restoreSession();
  el("btnRegister").addEventListener("click", () => registerOrLogin("register"));
  el("btnLogin").addEventListener("click", () => registerOrLogin("login"));
  el("btnSend").addEventListener("click", sendMessage);
  setInterval(fetchMessages, 2000);
  setInterval(fetchOnlineUsers, 2000);
});
