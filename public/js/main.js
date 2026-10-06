import { h, clear } from './dom.js';
import { api, profile, hasRefreshToken, refresh, clearSession, isNetworkError } from './api.js';
import * as vault from './vault.js';
import { showAuth } from './auth.js';
import { mountApprovals } from './approvals.js';
import { mountCodes } from './codes.js';
import { mountSecurity } from './security.js';

const root = document.getElementById('app');

const showHome = () => {
  let unmount = () => {};
  let current = 'approvals';

  const countBadge = h('span', { class: 'badge count', hidden: true });
  const body = h('main', {});
  const tabs = h('nav', { class: 'tabs', role: 'tablist' });

  const logout = async () => {
    unmount();
    // A logged-out device keeps nothing secret behind.
    await vault.wipe();
    const token = localStorage.getItem(`fs:${profile}:refresh`);
    if (token) await fetch('/api/auth/logout', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ refreshToken: token }) }).catch(() => {});
    clearSession();
    showAuth(root, { onSession: showHome });
  };

  const views = {
    approvals: ['Approve', (el) => mountApprovals(el, { onCount: (n) => { countBadge.textContent = n; countBadge.hidden = n === 0; } })],
    codes: ['Codes', (el) => mountCodes(el)],
    security: ['Security', (el) => mountSecurity(el, { onLogoutAll: logout })],
  };

  const select = (name) => {
    unmount();
    current = name;
    clear(body);
    unmount = views[name][1](body);
    for (const button of tabs.children) button.setAttribute('aria-selected', String(button.dataset.view === name));
  };

  for (const [name, [label]] of Object.entries(views)) {
    const button = h('button', { role: 'tab', 'data-view': name, onclick: () => select(name) }, label);
    if (name === 'approvals') button.append(countBadge);
    tabs.append(button);
  }

  clear(root);
  root.append(
    h('header', { class: 'bar' },
      h('strong', {}, 'FraudShield'),
      h('div', { class: 'row' }, profile !== 'default' ? h('span', { class: 'badge' }, `profile: ${profile}`) : '', h('button', { onclick: logout }, 'Log out'))
    ),
    tabs,
    body
  );
  select(current);
};

// No connection (or the server is down) but this device has an offline copy.
const showOffline = () => {
  const body = h('main', {});
  clear(root);
  root.append(
    h('header', { class: 'bar' },
      h('strong', {}, 'FraudShield'),
      h('div', { class: 'row' },
        h('span', { class: 'badge' }, 'Offline'),
        h('button', { onclick: () => vault.lock() }, 'Lock'),
        h('button', { onclick: () => location.reload() }, 'Reconnect')
      )
    ),
    body
  );
  mountCodes(body, { offline: true });
};

const registerWorker = () => {
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/app/sw.js').catch(() => {});
};

const boot = async () => {
  registerWorker();
  if (hasRefreshToken()) {
    try {
      await refresh();
      await api('GET', '/api/devices');
      return showHome();
    } catch (err) {
      if (isNetworkError(err)) {
        if (await vault.hasVault()) return showOffline();
        return showAuth(root, { onSession: showHome, notice: 'You are offline. Connect to the internet to continue.' });
      }
      clearSession();
    }
  }
  showAuth(root, { onSession: showHome });
};

// Keep the offline copy from locking while the app is in use, and delete it if the
// server tells us this device is no longer allowed.
for (const event of ['pointerdown', 'keydown']) addEventListener(event, () => vault.touch());
addEventListener('session-revoked', () => vault.wipe());

boot();
