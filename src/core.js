'use strict';

// ── Constants ──────────────────────────────────────────────────────────────

// PBKDF2 iteration counts by purpose.
//
//   ITER_DERIVE   — used once per password generation; the primary security function.
//   ITER_INTERNAL — used per entry when saving to localStorage; runs multiple times per
//                   save, but the master password is the real secret so 100k is fine here.
//   ITER_EXPORT   — used once per export/import to derive a session key; can be high
//                   because it's a single call regardless of vault size.
const ITER_DERIVE   = 1_000_000;
const ITER_INTERNAL =   100_000;
const ITER_EXPORT   = 1_500_000;

// Named character sets used in both password derivation and guaranteed-char logic.
const CHARS_UPPER   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const CHARS_LOWER   = 'abcdefghijklmnopqrstuvwxyz';
const CHARS_DIGITS  = '0123456789';
const CHARS_SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?';

// ── Text encoder singleton ─────────────────────────────────────────────────

const enc = new TextEncoder();

// ── String utilities ───────────────────────────────────────────────────────

// Escapes user-supplied text before inserting into innerHTML to prevent XSS.
function escHtml(str) {
  return str
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#x27;');
}

// ── Base64 helpers ─────────────────────────────────────────────────────────
// Used in the export file to keep binary blobs human-readable and compact.

function toBase64(bytes) {
  // Spread into String.fromCharCode in chunks to avoid call-stack limits on
  // large arrays (the default spread can hit the argument limit).
  const CHUNK = 0x8000;
  let binary  = '';
  for (let i = 0; i < bytes.length; i += CHUNK)
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  return btoa(binary);
}

function fromBase64(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

// ── Crypto: site hash ──────────────────────────────────────────────────────
// HMAC-SHA256 keyed on the full master password.
// Using HMAC (rather than a plain hash) means an attacker cannot enumerate
// which services someone uses without knowing the full master password.

async function siteHash(site, master) {
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(master),
    { name: 'HMAC', hash: 'SHA-256' },
    /* extractable */ false, ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, enc.encode('vaultless:site:' + site));
  const hex = Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  return hex.slice(0, 16);
}

// ── Crypto: password derivation ────────────────────────────────────────────
// Derives a deterministic password from master + site + username + version.
// The same inputs always produce the same output — nothing is stored.
//
// How it works:
//   1. PBKDF2-SHA256 (ITER_DERIVE iterations) turns the master password into
//      512 bits of cryptographic material.  The salt encodes site, username
//      and version so every credential is unique even with the same master.
//   2. We walk through the derived bytes with a sequential cursor to pick
//      characters and to drive the Fisher-Yates shuffle.  Sequential access
//      avoids index-aliasing that strided access (i*3+7) can cause.

async function derivePassword(master, site, username, version, len, upper, lower, digits, symbols) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(master), 'PBKDF2', /* extractable */ false, ['deriveBits']
  );

  // Username is normalised so "You@Example.com" and "you@example.com" are identical.
  const saltStr = `vaultless:${site}:${username.trim().toLowerCase()}:${version}`;

  const rawBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(saltStr), iterations: ITER_DERIVE },
    keyMaterial, 512
  );
  const bytes = new Uint8Array(rawBits);   // 64 bytes to draw from

  // Build the full character pool from whichever classes are enabled.
  let pool = '';
  if (upper)   pool += CHARS_UPPER;
  if (lower)   pool += CHARS_LOWER;
  if (digits)  pool += CHARS_DIGITS;
  if (symbols) pool += CHARS_SYMBOLS;
  if (!pool)   pool  = CHARS_UPPER + CHARS_LOWER + CHARS_DIGITS;   // safe fallback

  let cursor = 0;   // advances sequentially through `bytes`

  // Pick one guaranteed character per enabled class so the password satisfies
  // common composition requirements (e.g. "must contain a digit").
  let guaranteed = '';
  if (upper)   guaranteed += CHARS_UPPER  [bytes[cursor++] % CHARS_UPPER.length];
  if (lower)   guaranteed += CHARS_LOWER  [bytes[cursor++] % CHARS_LOWER.length];
  if (digits)  guaranteed += CHARS_DIGITS [bytes[cursor++] % CHARS_DIGITS.length];
  if (symbols) guaranteed += CHARS_SYMBOLS[bytes[cursor++] % CHARS_SYMBOLS.length];

  // Fill the remaining slots from the full pool.
  let body = '';
  for (let i = 0; i < len - guaranteed.length; i++) {
    body += pool[bytes[cursor % bytes.length] % pool.length];
    cursor++;
  }

  // Shuffle guaranteed + body together with Fisher-Yates so the guaranteed
  // characters don't predictably cluster at the front of the password.
  const chars = (guaranteed + body).split('');
  for (let i = chars.length - 1; i > 0; i--) {
    const j = bytes[cursor % bytes.length] % (i + 1);
    cursor++;
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.slice(0, len).join('');
}

// ── Crypto: AES-GCM encrypt / decrypt ─────────────────────────────────────
// Used for alias and site-name storage in localStorage, and for export files.
// Each encrypt() call generates a fresh random salt and IV.
// The iteration count is written into the payload so decrypt() never needs
// to guess it — safe even if the default changes in a future version.

async function deriveAesKey(password, salt, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', /* extractable */ false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    /* extractable */ false, ['encrypt', 'decrypt']
  );
}

async function encrypt(data, password, iterations = ITER_INTERNAL) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveAesKey(password, salt, iterations);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(data))
  );
  return { v: 2, iter: iterations, salt: [...salt], iv: [...iv], ct: [...new Uint8Array(ciphertext)] };
}

async function decrypt(payload, password) {
  const iterations = payload.iter ?? ITER_INTERNAL;
  const key = await deriveAesKey(password, new Uint8Array(payload.salt), iterations);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(payload.iv) }, key, new Uint8Array(payload.ct)
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

// ── Crypto: export session key ─────────────────────────────────────────────
// Derives a single AES-GCM key from the master password using PBKDF2.
// Called once per export or import; each individual entry is then encrypted
// with this key and a fresh random IV (no PBKDF2 per entry).
// The salt is persisted in db._export so the same key is reused across exports,
// making unchanged entries produce identical ciphertext (diff-stable vault).

async function deriveExportKey(master, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(master), 'PBKDF2', /* extractable */ false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITER_EXPORT, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    /* extractable */ false, ['encrypt', 'decrypt']
  );
}

// ── Export / import ───────────────────────────────────────────────────────
//
// Export file format (v3):
//   {
//     "vaultless": 3,
//     "iter": <ITER_EXPORT>,
//     "kdf_salt": "<base64>",          ← persisted salt for export key derivation
//     "entries": {
//       "<16-char-hash>": {
//         "iv":  "<base64>",           ← per-entry IV, cached across exports
//         "ct":  "<base64>"            ← AES-GCM ciphertext
//       }, ...
//     }
//   }
//
// Each entry decrypts to: { site, alias, len, counter, upper, lower, digits, symbols }
//
// One PBKDF2 call derives the export key; each entry then uses only AES-GCM.
// This means: changing one site entry changes exactly one "ct" value in the file.

// Returns the keys of db that represent site entries (excludes _ prefixed metadata).
function siteHashes(db) {
  return Object.keys(db).filter(k => !k.startsWith('_'));
}

// Builds and returns the export payload object. Mutates db to persist the
// export salt (db._export) and per-entry IV/CT cache (entry.exportIv/exportCt)
// so subsequent exports produce identical ciphertext for unchanged entries.
async function buildExportPayload(db, master) {
  if (!db._export) db._export = { salt: Array.from(crypto.getRandomValues(new Uint8Array(16))) };
  const kdfSalt   = new Uint8Array(db._export.salt);
  const exportKey = await deriveExportKey(master, kdfSalt);

  const entries = {};
  let skipped   = 0;

  for (const hash of siteHashes(db)) {
    const entry = db[hash];

    // Reuse cached ciphertext if the entry hasn't changed since last export.
    if (entry.exportIv && entry.exportCt) {
      entries[hash] = { iv: entry.exportIv, ct: entry.exportCt };
      continue;
    }

    let site     = '';
    let alias    = '';
    let username = '';
    // Fall back to legacy plaintext fields for entries saved before encryption was added.
    let cfg      = { len: entry.len, counter: entry.counter,
                     upper: entry.upper, lower: entry.lower, digits: entry.digits, symbols: entry.symbols };
    try { site = await decrypt(entry.encSite, master); }
    catch { skipped++; continue; }
    try { if (entry.encAlias)  alias    = await decrypt(entry.encAlias,  master); } catch {}
    try { if (entry.encUser)   username = await decrypt(entry.encUser,   master); } catch {}
    try { if (entry.encConfig) cfg      = await decrypt(entry.encConfig, master); } catch {}

    const payload = {
      site, alias: alias || null, username: username || null,
      len: cfg.len, counter: cfg.counter,
      upper: cfg.upper, lower: cfg.lower, digits: cfg.digits, symbols: cfg.symbols,
    };

    const iv         = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, exportKey, enc.encode(JSON.stringify(payload))
    );
    entry.exportIv = toBase64(iv);
    entry.exportCt = toBase64(new Uint8Array(ciphertext));
    entries[hash] = { iv: entry.exportIv, ct: entry.exportCt };
  }

  return {
    payload: { vaultless: 3, iter: ITER_EXPORT, kdf_salt: toBase64(kdfSalt), entries },
    skipped,
  };
}

// Decrypts a v3 export payload and merges entries into db.
// Also restores db._export and per-entry IV/CT cache so re-exporting from
// this device produces the same file for unchanged entries.
// Returns { imported, failed }.
async function applyImport(db, raw, master) {
  const exportKey = await deriveExportKey(master, fromBase64(raw.kdf_salt));
  let imported = 0, failed = 0;

  for (const [hash, blob] of Object.entries(raw.entries)) {
    try {
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromBase64(blob.iv) },
        exportKey,
        fromBase64(blob.ct)
      );
      const data = JSON.parse(new TextDecoder().decode(plaintext));

      const encSite   = await encrypt(data.site, master);
      const encAlias  = data.alias    ? await encrypt(data.alias,    master) : null;
      const encUser   = data.username ? await encrypt(data.username, master) : null;
      const encConfig = await encrypt(
        { len: data.len, counter: data.counter,
          upper: data.upper, lower: data.lower, digits: data.digits, symbols: data.symbols },
        master
      );

      db[hash] = { hash, encConfig, encSite, encAlias, encUser };
      imported++;
    } catch { failed++; }
  }

  // Restore export salt and per-entry cache so re-exporting from this device
  // produces the same ciphertext for unchanged entries.
  db._export = { salt: Array.from(fromBase64(raw.kdf_salt)) };
  for (const [hash, encEntry] of Object.entries(raw.entries)) {
    if (db[hash]) { db[hash].exportIv = encEntry.iv; db[hash].exportCt = encEntry.ct; }
  }

  return { imported, failed };
}

// ── Master password strength scorer ───────────────────────────────────────
// Returns { score: 0-4, label: string, warning: string }.
// Pure function — no DOM access.

const COMMON_PASSWORDS = [
  'password', '123456', 'qwerty', 'abc123', 'letmein', 'monkey', 'iloveyou',
  'admin', 'welcome', 'login', 'master', 'secret', 'passw0rd', 'password1',
  '111111', 'sunshine', 'princess', 'dragon', 'shadow', 'mustang', 'football', 'baseball',
];
const KEYBOARD_WALKS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', 'qwerty', 'asdf', 'zxcv'];

function scorePassword(value) {
  if (!value) return { score: 0, label: '', warning: '' };

  const lower = value.toLowerCase();

  if (COMMON_PASSWORDS.includes(lower))
    return { score: 0, label: 'very weak', warning: 'extremely common password' };

  for (const walk of KEYBOARD_WALKS)
    if (lower.includes(walk.slice(0, 5)))
      return { score: 1, label: 'weak', warning: 'keyboard pattern detected' };

  if (/(.)\1{3,}/.test(value))
    return { score: 1, label: 'weak', warning: 'too many repeated characters' };

  if (/^(.{1,4})\1+$/.test(value))
    return { score: 1, label: 'weak', warning: 'repeated pattern detected' };

  // Estimate entropy from the character space actually used.
  let charsetSize = 0;
  if (/[a-z]/.test(value))        charsetSize += 26;
  if (/[A-Z]/.test(value))        charsetSize += 26;
  if (/[0-9]/.test(value))        charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(value)) charsetSize += 32;
  const entropyBits = value.length * Math.log2(charsetSize || 1);

  let score, label, warning = '';
  if      (entropyBits < 28) { score = 0; label = 'very weak';  warning = 'too short or too simple'; }
  else if (entropyBits < 40) { score = 1; label = 'weak'; }
  else if (entropyBits < 55) { score = 2; label = 'fair'; }
  else if (entropyBits < 70) { score = 3; label = 'strong'; }
  else                       { score = 4; label = 'very strong'; }

  if (score >= 2 && !/[^a-zA-Z0-9]/.test(value))
    warning = 'add symbols to strengthen';
  else if (score >= 1 && !/[A-Z]/.test(value) && !/[^a-zA-Z0-9]/.test(value))
    warning = 'add uppercase or symbols';

  return { score, label, warning };
}
