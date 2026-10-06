// Encryption for the offline copy of the codes. A passcode the user chooses is
// stretched with PBKDF2 into an AES-256-GCM key; the passcode and key never leave
// the device. Pure Web Crypto, no DOM, so it can be tested in Node.
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// OWASP's current guidance for PBKDF2-HMAC-SHA256.
export const DEFAULT_ITERATIONS = 600000;

export const toBase64 = (bytes) => btoa(String.fromCharCode(...bytes));
export const fromBase64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));

export const newSalt = () => crypto.getRandomValues(new Uint8Array(16));

// The returned key cannot be exported, so a script cannot read its raw bytes.
export const deriveKey = async (passcode, salt, iterations = DEFAULT_ITERATIONS) => {
  const material = await crypto.subtle.importKey('raw', encoder.encode(passcode), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
};

export const encryptJson = async (key, value) => {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(JSON.stringify(value)));
  return { iv: toBase64(iv), data: toBase64(new Uint8Array(data)) };
};

// Throws if the key is wrong or the data was altered.
export const decryptJson = async (key, { iv, data }) => {
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(iv) }, key, fromBase64(data));
  return JSON.parse(decoder.decode(plain));
};
