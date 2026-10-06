import { h, toast } from './dom.js';
import { api, ApiError } from './api.js';
import { connectApprover } from './realtime.js';

const SITE_LABEL = {
  'origin-header': '',
  'client-claimed': ' (claimed by the app, not verified)',
  none: '',
};

const riskClass = (score) => (score >= 70 ? 'high' : score >= 40 ? 'mid' : '');

const card = (request, { onDone }) => {
  const trust = h('input', { type: 'checkbox', id: `trust-${request.id}` });
  const error = h('div', { class: 'error', role: 'alert' });
  const timeLeft = h('span', {});
  let busy = false;

  const act = async (body, success) => {
    if (busy) return;
    busy = true;
    error.textContent = '';
    try {
      await api('POST', `/api/approval/${request.id}/${body.report ? 'report' : 'respond'}`, body.report ? undefined : body);
      toast(success);
      onDone(request.id);
    } catch (err) {
      error.textContent = err.body?.attemptsLeft !== undefined ? `${err.message}. ${err.body.attemptsLeft} attempt left.` : err.message;
      if (err instanceof ApiError && [403, 404].includes(err.status)) onDone(request.id);
    } finally {
      busy = false;
    }
  };

  const tick = () => {
    const left = Math.round((new Date(request.expiresAt) - Date.now()) / 1000);
    if (left <= 0) return onDone(request.id);
    timeLeft.textContent = `${left}s left`;
  };
  tick();
  const timer = setInterval(tick, 1000);

  const el = h('div', { class: 'card', 'data-request': request.id },
    h('div', { class: 'row space' },
      h('strong', {}, 'Someone is trying to sign in'),
      h('span', { class: 'muted' }, timeLeft)
    ),
    h('dl', { class: 'facts' },
      h('dt', {}, 'Site'),
      h('dd', {}, request.site ? `${request.site}${SITE_LABEL[request.siteSource] ?? ''}` : 'No website (direct app sign-in)'),
      h('dt', {}, 'Device'), h('dd', {}, request.deviceName),
      h('dt', {}, 'Location'), h('dd', {}, request.location),
      h('dt', {}, 'IP address'), h('dd', {}, request.ip),
      h('dt', {}, 'Risk'), h('dd', { class: `risk ${riskClass(request.riskScore)}` }, `${request.riskScore} / 100`)
    ),
    request.reasons.length ? h('ul', { class: 'reasons' }, request.reasons.map((r) => h('li', {}, r))) : '',
    h('p', {}, 'Choose the number shown on the screen that is signing in:'),
    h('div', { class: 'choices' },
      request.options.map((n) => h('button', { onclick: () => act({ action: 'approve', choice: n, trustDevice: trust.checked }, 'Approved') }, n))
    ),
    h('label', { for: `trust-${request.id}` }, trust, ' Trust that device from now on'),
    error,
    h('div', { class: 'row space' },
      h('button', { onclick: () => act({ action: 'deny' }, 'Denied') }, 'Deny'),
      h('button', {
        class: 'danger',
        onclick: () => {
          if (confirm('Report this as not you? Its IP address will be blocked and your account locked until you reset your password.')) {
            act({ report: true }, 'Reported. Your account is locked until you reset your password.');
          }
        },
      }, "This wasn't me")
    )
  );
  el.dispose = () => clearInterval(timer);
  return el;
};

export const mountApprovals = (container, { onCount }) => {
  const list = h('div', {});
  const empty = h('p', { class: 'muted' }, 'No sign-in requests right now. New ones appear here instantly.');
  const status = h('div', {});
  const cards = new Map();

  const update = () => {
    empty.hidden = cards.size > 0;
    onCount(cards.size);
  };
  const remove = (id) => {
    cards.get(id)?.dispose();
    cards.get(id)?.remove();
    cards.delete(id);
    update();
  };
  const add = (request) => {
    if (cards.has(request.id)) return;
    const el = card(request, { onDone: remove });
    cards.set(request.id, el);
    list.prepend(el);
    update();
  };

  container.append(h('h2', {}, 'Sign-in requests'), status, empty, list);

  let closeSocket = () => {};
  api('GET', '/api/approval/pending')
    .then((items) => {
      items.forEach(add);
      closeSocket = connectApprover({ onRequest: add, onClosed: ({ id }) => remove(id) });
    })
    .catch((err) => {
      empty.hidden = true;
      status.append(
        err.status === 403
          ? h('div', { class: 'notice' }, 'This device is not trusted, so it cannot approve sign-ins. Open FraudShield on a trusted device, or ask it to trust this one when it approves your login.')
          : h('div', { class: 'error' }, err.message)
      );
    });
  update();

  return () => {
    closeSocket();
    cards.forEach((el) => el.dispose());
  };
};
