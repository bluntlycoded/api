import { h, toast, guarded } from './dom.js';
import { api } from './api.js';
import * as vault from './vault.js';

const when = (iso) => new Date(iso).toLocaleString();

const devicesSection = () => {
  const list = h('div', {});
  const load = async () => {
    list.replaceChildren();
    const devices = await api('GET', '/api/devices');
    devices.forEach((d) =>
      list.append(
        h('div', { class: 'card' },
          h('div', { class: 'row space' },
            h('strong', {}, d.name, d.current ? h('span', { class: 'badge' }, 'this device') : ''),
            h('span', { class: 'badge' }, d.trusted ? 'trusted' : 'not trusted')
          ),
          h('p', { class: 'muted' }, `Last seen ${when(d.lastSeen)}${d.lastIp ? ` from ${d.lastIp}` : ''}`),
          h('button', {
            class: 'danger',
            onclick: async () => {
              if (!confirm(`Remove ${d.name}? It will be signed out and treated as new next time.`)) return;
              try {
                await api('DELETE', `/api/devices/${d.id}`);
                toast('Device removed');
                load();
              } catch (err) {
                toast(err.message);
              }
            },
          }, 'Remove')
        )
      )
    );
  };
  load().catch((err) => list.append(h('div', { class: 'error' }, err.message)));
  return h('section', {}, h('h2', {}, 'Devices'), list);
};

const recoverySection = () => {
  const output = h('div', {});
  const remaining = h('p', { class: 'muted' }, '');
  const password = h('input', { type: 'password', placeholder: 'Your password', autocomplete: 'current-password', required: true });
  const error = h('div', { class: 'error', role: 'alert' });
  const button = h('button', { type: 'submit' }, 'Generate new codes');

  const refreshCount = () =>
    api('GET', '/api/recovery').then(({ remaining: n }) => { remaining.textContent = `${n} unused code${n === 1 ? '' : 's'}.`; }).catch(() => {});

  const submit = guarded(button, error, async () => {
    if (!confirm('This replaces any codes you already have. Continue?')) return;
    const { codes } = await api('POST', '/api/recovery', { password: password.value });
    password.value = '';
    output.replaceChildren(
      h('div', { class: 'notice' }, 'Save these now. Each works once and they will not be shown again.'),
      h('div', { class: 'recovery card' }, codes.map((c) => h('div', {}, c))),
      h('button', { onclick: () => navigator.clipboard.writeText(codes.join('\n')).then(() => toast('Copied')) }, 'Copy all')
    );
    refreshCount();
  });

  refreshCount();
  return h('section', {}, h('h2', {}, 'Recovery codes'),
    h('p', { class: 'muted' }, 'Lose every trusted device and these are the only way back in.'), remaining,
    h('form', { class: 'stack', onsubmit: submit }, password, error, button), output);
};

const activitySection = () => {
  const list = h('div', {});
  api('GET', '/api/security/logins')
    .then((events) => {
      if (!events.length) list.append(h('p', { class: 'muted' }, 'Nothing yet.'));
      events.slice(0, 15).forEach((e) =>
        list.append(
          h('div', { class: 'card' },
            h('div', { class: 'row space' }, h('strong', {}, e.outcome.replace('_', ' ')), h('span', { class: 'muted' }, when(e.at))),
            h('div', { class: 'muted' }, [e.ip, e.location, e.riskScore != null ? `risk ${e.riskScore}` : ''].filter(Boolean).join(' · ')),
            e.reasons.length ? h('ul', { class: 'reasons' }, e.reasons.map((r) => h('li', {}, r))) : ''
          )
        )
      );
    })
    .catch((err) => list.append(h('div', { class: 'error' }, err.message)));
  return h('section', {}, h('h2', {}, 'Recent sign-ins'), list);
};

// Opt-in: keeps an encrypted copy of the codes on this device so they work with no
// connection. Without it, nothing secret is ever written to disk here.
const offlineSection = () => {
  const box = h('div', {});

  const enableForm = () => {
    const passcode = h('input', { type: 'password', placeholder: `New passcode (at least ${vault.MIN_PASSCODE} characters)`, autocomplete: 'new-password', required: true });
    const again = h('input', { type: 'password', placeholder: 'Repeat the passcode', autocomplete: 'new-password', required: true });
    const error = h('div', { class: 'error', role: 'alert' });
    const button = h('button', { class: 'primary', type: 'submit' }, 'Turn on offline access');
    const submit = guarded(button, error, async () => {
      if (passcode.value.length < vault.MIN_PASSCODE) throw new Error(`Use at least ${vault.MIN_PASSCODE} characters.`);
      if (passcode.value !== again.value) throw new Error('The passcodes do not match.');
      const entries = await api('GET', '/api/addapp');
      await vault.enable(passcode.value, { entries, pendingCounters: {} });
      toast('Offline access is on');
      render();
    });
    return h('form', { class: 'stack', onsubmit: submit }, passcode, again, error, button);
  };

  const manage = () => {
    const unlocked = vault.isUnlocked();
    const passcode = h('input', { type: 'password', placeholder: 'Offline passcode', autocomplete: 'current-password' });
    const error = h('div', { class: 'error', role: 'alert' });
    const update = h('button', { type: 'button' }, unlocked ? 'Update now' : 'Unlock and update');
    update.addEventListener('click', guarded(update, error, async () => {
      if (!vault.isUnlocked()) await vault.unlock(passcode.value);
      const entries = await api('GET', '/api/addapp');
      await vault.save({ entries, pendingCounters: vault.getData()?.pendingCounters ?? {} });
      toast('Offline copy updated');
      render();
    }));
    const off = h('button', { class: 'danger', type: 'button' }, 'Turn off and delete the copy');
    off.addEventListener('click', async () => {
      if (!confirm('Delete the offline copy from this device? Your accounts stay safe on the server.')) return;
      await vault.wipe();
      toast('Offline copy deleted');
      render();
    });
    return h('div', { class: 'stack' },
      h('div', { class: 'row space' }, h('strong', {}, 'Offline access is on'), h('span', { class: 'badge' }, unlocked ? 'unlocked' : 'locked')),
      unlocked ? '' : passcode, error,
      h('div', { class: 'row' }, update, unlocked ? h('button', { type: 'button', onclick: () => { vault.lock(); render(); } }, 'Lock now') : '', off));
  };

  const render = async () => {
    box.replaceChildren(await vault.hasVault() ? manage() : enableForm());
  };
  render();

  return h('section', {}, h('h2', {}, 'Offline access'),
    h('p', { class: 'muted' }, 'Keep an encrypted copy of your codes on this device so they work with no connection. Only a passcode you choose opens it. It locks after 5 idle minutes, and it is deleted if you log out or this device is removed. If you forget the passcode, turn it off and on again while online.'),
    h('div', { class: 'card' }, box));
};

export const mountSecurity = (container, { onLogoutAll }) => {
  container.append(
    offlineSection(),
    devicesSection(),
    recoverySection(),
    activitySection(),
    h('h2', {}, 'Sessions'),
    h('button', {
      class: 'danger',
      onclick: async () => {
        if (!confirm('Sign out on every device?')) return;
        await api('POST', '/api/auth/logout-all').catch(() => {});
        onLogoutAll();
      },
    }, 'Sign out everywhere')
  );
  return () => {};
};
