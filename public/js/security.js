import { h, toast, guarded } from './dom.js';
import { api } from './api.js';

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

export const mountSecurity = (container, { onLogoutAll }) => {
  container.append(
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
