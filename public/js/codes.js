import { h, toast, guarded } from './dom.js';
import { api } from './api.js';

const group = (otp) => (otp.length === 6 ? `${otp.slice(0, 3)} ${otp.slice(3)}` : otp.length === 8 ? `${otp.slice(0, 4)} ${otp.slice(4)}` : otp);

// One account with a live code. TOTP codes renew themselves; HOTP codes are
// generated on request because each one uses up a counter value.
const entryCard = (app, timers) => {
  const code = h('div', { class: 'code' }, '······');
  const fill = h('div', { class: 'bar-fill' });
  const period = app.period || 30;
  const title = app.issuer || app.appName;
  const subtitle = app.account && app.account !== title ? app.account : '';

  const load = async () => {
    try {
      const { otp, expiresInSeconds } = await api('GET', `/api/addapp/${app.id}/otp`);
      code.textContent = group(otp);
      if (expiresInSeconds === undefined) return;
      fill.style.transition = 'none';
      fill.style.width = `${(expiresInSeconds / period) * 100}%`;
      requestAnimationFrame(() => {
        fill.style.transition = `width ${expiresInSeconds}s linear`;
        fill.style.width = '0%';
      });
      timers.push(setTimeout(load, expiresInSeconds * 1000 + 300));
    } catch (err) {
      code.textContent = '—';
      toast(err.message);
    }
  };

  const body = [h('div', { class: 'row space' }, h('div', {}, h('strong', {}, title), subtitle ? h('div', { class: 'muted' }, subtitle) : ''))];
  if (app.type === 'hotp') body.push(code, h('button', { onclick: load }, 'Generate next code'));
  else {
    body.push(code, h('div', { class: 'bar-track' }, fill));
    load();
  }
  return h('div', { class: 'card' }, body);
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

export const mountCodes = (container) => {
  let timers = [];
  const list = h('div', {});

  const load = async () => {
    timers.forEach(clearTimeout);
    timers = [];
    list.replaceChildren();
    try {
      const apps = await api('GET', '/api/addapp');
      if (!apps.length) list.append(h('p', { class: 'muted' }, 'No accounts yet. Add one below.'));
      apps.forEach((app) => list.append(entryCard(app, timers)));
    } catch (err) {
      list.append(h('div', { class: 'error' }, err.message));
    }
  };

  container.append(h('h2', {}, 'Your codes'), list, addForm(load));
  load();
  return () => timers.forEach(clearTimeout);
};
