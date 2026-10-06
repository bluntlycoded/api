import { h, toast, guarded } from './dom.js';
import { api, isNetworkError } from './api.js';
import { codeFor, secondsRemaining } from './otp.js';
import * as vault from './vault.js';

const group = (otp) => (otp.length === 6 ? `${otp.slice(0, 3)} ${otp.slice(3)}` : otp.length === 8 ? `${otp.slice(0, 4)} ${otp.slice(4)}` : otp);

// One account with a live code, computed on this device. TOTP codes renew on their
// own; HOTP codes are made on request because each one uses up a counter value.
const entryCard = (entry, nextHotp) => {
  const code = h('div', { class: 'code' }, '······');
  const fill = h('div', { class: 'bar-fill' });
  const period = entry.period || 30;
  const title = entry.issuer || entry.appName;
  const subtitle = entry.account && entry.account !== title ? entry.account : '';
  let step = -1;

  const tick = async (now) => {
    const current = Math.floor(now / 1000 / period);
    fill.style.width = `${(secondsRemaining(period, now) / period) * 100}%`;
    if (current === step) return;
    step = current;
    fill.style.transition = 'none';
    requestAnimationFrame(() => { fill.style.transition = ''; });
    code.textContent = group(await codeFor(entry, now));
  };

  const head = h('div', { class: 'row space' }, h('div', {}, h('strong', {}, title), subtitle ? h('div', { class: 'muted' }, subtitle) : ''));
  if (entry.type === 'hotp') {
    const button = h('button', {}, 'Generate next code');
    button.addEventListener('click', async () => {
      button.disabled = true;
      try {
        code.textContent = group(await nextHotp(entry));
      } catch (err) {
        toast(err.message);
      } finally {
        button.disabled = false;
      }
    });
    return { el: h('div', { class: 'card' }, head, code, button), tick: () => {} };
  }
  return { el: h('div', { class: 'card' }, head, code, h('div', { class: 'bar-track' }, fill)), tick };
};

const addForm = (reload) => {
  const label = h('input', { type: 'text', placeholder: 'Account name (for a plain secret)' });
  const secret = h('input', { type: 'text', placeholder: 'Secret key or otpauth:// link', autocomplete: 'off', required: true });
  const error = h('div', { class: 'error', role: 'alert' });
  const button = h('button', { class: 'primary', type: 'submit' }, 'Add');

  const submit = guarded(button, error, async () => {
    const value = secret.value.trim();
    if (/^otpauth(-migration)?:/i.test(value)) {
      const { imported, skipped } = await api('POST', '/api/addapp/import', { data: value });
      if (!imported) throw new Error(`Nothing could be imported (${skipped} skipped).`);
      toast(`Imported ${imported} account${imported === 1 ? '' : 's'}`);
    } else {
      if (!label.value.trim()) throw new Error('Give the account a name.');
      await api('POST', '/api/addapp', { appName: label.value.trim(), secretKey: value });
      toast('Account added');
    }
    secret.value = '';
    label.value = '';
    reload();
  });

  return h('details', { class: 'card' }, h('summary', {}, 'Add an account'),
    h('form', { class: 'stack', onsubmit: submit }, label, secret, error, button));
};

const unlockForm = (message, onUnlocked) => {
  const passcode = h('input', { type: 'password', placeholder: 'Offline passcode', autocomplete: 'current-password', required: true });
  const error = h('div', { class: 'error', role: 'alert' });
  const button = h('button', { class: 'primary', type: 'submit' }, 'Unlock');
  const submit = guarded(button, error, async () => {
    onUnlocked(await vault.unlock(passcode.value));
    passcode.value = '';
  });
  return h('form', { class: 'card stack', onsubmit: submit }, h('p', { class: 'muted' }, message), passcode, error, button);
};

export const mountCodes = (container, { offline = false } = {}) => {
  const banner = h('div', {});
  const list = h('div', {});
  const addArea = h('div', {});
  let cards = [];
  let entries = [];
  let working = offline;

  const tickAll = () => {
    const now = Date.now();
    cards.forEach((card) => card.tick(now));
  };
  const timer = setInterval(tickAll, 1000);

  const show = (items) => {
    entries = items;
    list.replaceChildren();
    cards = entries.map((entry) => entryCard(entry, nextHotp));
    if (!cards.length) list.append(h('p', { class: 'muted' }, working ? 'No accounts in the offline copy.' : 'No accounts yet. Add one below.'));
    cards.forEach((card) => list.append(card.el));
    tickAll();
  };

  const showLocked = (message) => {
    cards = [];
    list.replaceChildren(unlockForm(message, (data) => show(data.entries)));
  };

  // HOTP: online, the server owns the counter. Offline, the device advances it,
  // remembers it, and sends it back later (the server only ever moves it forward).
  async function nextHotp(entry) {
    if (!working) {
      try {
        const { otp, counter } = await api('GET', `/api/addapp/${entry.id}/otp`);
        entry.counter = counter + 1;
        if (vault.isUnlocked()) await vault.save({ ...vault.getData(), entries });
        return otp;
      } catch (err) {
        if (!isNetworkError(err)) throw err;
      }
    }
    if (!vault.isUnlocked()) throw new Error('Unlock your offline copy first.');
    const otp = await codeFor(entry);
    entry.counter += 1;
    const data = vault.getData();
    await vault.save({ ...data, entries, pendingCounters: { ...data.pendingCounters, [entry.id]: entry.counter } });
    return otp;
  }

  const flushCounters = async () => {
    const pending = Object.entries(vault.getData()?.pendingCounters ?? {});
    if (!pending.length) return;
    await api('PUT', '/api/addapp/counters', { counters: pending.map(([id, counter]) => ({ id, counter })) });
    await vault.save({ ...vault.getData(), pendingCounters: {} });
  };

  // Offline mode: codes come from the encrypted copy, so it has to be unlocked.
  const loadOffline = () => {
    working = true;
    banner.replaceChildren(h('div', { class: 'notice' }, 'You are offline. Codes are generated on this device, so they depend on its clock being right.'));
    addArea.replaceChildren();
    if (vault.isUnlocked()) show(vault.getData().entries);
    else showLocked('Enter your offline passcode to see your codes.');
  };

  const loadOnline = async () => {
    working = false;
    banner.replaceChildren();
    try {
      if (vault.isUnlocked()) await flushCounters();
      const items = await api('GET', '/api/addapp');
      show(items);
      addArea.replaceChildren(addForm(loadOnline));
      if (vault.isUnlocked()) await vault.save({ entries: items, pendingCounters: {} });
      else if (await vault.hasVault()) {
        banner.replaceChildren(unlockForm('Unlock your offline copy to keep it up to date.', () => loadOnline()));
      }
    } catch (err) {
      if (!isNetworkError(err)) {
        list.replaceChildren(h('div', { class: 'error' }, err.message));
        return;
      }
      if (await vault.hasVault()) loadOffline();
      else list.replaceChildren(h('div', { class: 'error' }, 'You are offline. Turn on offline access in Security (while online) to use your codes without a connection.'));
    }
  };

  const stopWatching = vault.onLockChange(async (unlocked) => {
    if (unlocked || !working) return;
    if (await vault.hasVault()) showLocked('Locked. Enter your passcode to see your codes.');
    else {
      cards = [];
      list.replaceChildren(h('p', { class: 'muted' }, 'The offline copy on this device was removed. Reconnect and sign in again.'));
    }
  });

  container.append(h('h2', {}, 'Your codes'), banner, list, addArea);
  if (offline) loadOffline();
  else loadOnline();

  return () => {
    clearInterval(timer);
    stopWatching();
  };
};
