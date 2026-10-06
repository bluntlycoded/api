// The offline copy of the user's authenticator entries: encrypted with a passcode-
// derived key and kept in IndexedDB. It exists only if the user turns it on. While
// unlocked the key lives in memory; it locks after a few idle minutes or on request.
import { profile } from './api.js';
import { deriveKey, newSalt, encryptJson, decryptJson, toBase64, fromBase64, DEFAULT_ITERATIONS } from './localCrypto.js';

const DB_NAME = 'fraudshield-offline';
const STORE = 'vault';
const RECORD = `vault:${profile}`;
const IDLE_MS = 5 * 60 * 1000;
export const MIN_PASSCODE = 8;

let key = null;
let data = null;
let salt = null;
let iterations = DEFAULT_ITERATIONS;
let idleTimer = null;
const listeners = new Set();

const open = () =>
  new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

const run = async (mode, action) => {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, mode);
    const request = action(tx.objectStore(STORE));
    tx.oncomplete = () => resolve(request?.result);
    tx.onerror = () => reject(tx.error);
  });
};

const read = () => run('readonly', (store) => store.get(RECORD));
const write = (record) => run('readwrite', (store) => store.put(record, RECORD));

const notify = () => listeners.forEach((listener) => listener(isUnlocked()));

// Returns a function that stops listening.
export const onLockChange = (listener) => {
  listeners.add(listener);
  return () => listeners.delete(listener);
};

// The decrypted contents, or null while locked. Held only in memory.
export const getData = () => data;

export const isUnlocked = () => key !== null;

export const hasVault = async () => {
  try {
    return Boolean(await read());
  } catch {
    return false;
  }
};

// Call on user activity so an open app does not lock mid-use.
export const touch = () => {
  clearTimeout(idleTimer);
  if (key) idleTimer = setTimeout(lock, IDLE_MS);
};

export const lock = () => {
  const wasUnlocked = key !== null;
  key = null;
  data = null;
  clearTimeout(idleTimer);
  if (wasUnlocked) notify();
};

const seal = async (contents) => ({ v: 1, salt: toBase64(salt), iterations, ...(await encryptJson(key, contents)) });

// Turns the offline copy on with a new passcode.
export const enable = async (passcode, contents) => {
  salt = newSalt();
  iterations = DEFAULT_ITERATIONS;
  key = await deriveKey(passcode, salt, iterations);
  data = contents;
  await write(await seal(contents));
  touch();
  notify();
};

// Returns the stored data, or throws if the passcode is wrong.
export const unlock = async (passcode) => {
  const record = await read();
  if (!record) throw new Error('There is no offline copy on this device.');
  const candidate = await deriveKey(passcode, fromBase64(record.salt), record.iterations);
  let contents;
  try {
    contents = await decryptJson(candidate, record);
  } catch {
    throw new Error('Wrong passcode.');
  }
  key = candidate;
  data = contents;
  salt = fromBase64(record.salt);
  iterations = record.iterations;
  touch();
  notify();
  return contents;
};

// Only works while unlocked.
export const save = async (contents) => {
  if (!key) throw new Error('Unlock the offline copy first.');
  data = contents;
  await write(await seal(contents));
};

// Deletes the offline copy, for example on logout or when the server revokes this device.
export const wipe = async () => {
  try {
    await run('readwrite', (store) => store.delete(RECORD));
  } catch {
    /* nothing stored */
  }
  // Locking last, so anything reacting to the lock already sees the copy gone.
  lock();
};
