import { h, clear } from './dom.js';
import { api, profile, hasRefreshToken, refresh, clearSession } from './api.js';
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

const boot = async () => {
  if (hasRefreshToken()) {
    try {
      await refresh();
      await api('GET', '/api/devices');
      return showHome();
    } catch {
      clearSession();
    }
  }
  showAuth(root, { onSession: showHome });
};

boot();
