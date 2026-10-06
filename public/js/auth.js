import { h, clear, field, guarded, toast } from './dom.js';
import { publicCall, deviceId, deviceName, setSession } from './api.js';
import { watchChallenge } from './realtime.js';

const POLL_MS = 2000;

// Shown on the new device while a trusted device decides. The number is the
// only thing that links this screen to the prompt on the other device.
const showWaiting = (root, challenge, { onSession, onBack }) => {
  const { challengeId, pollSecret, displayNumber, expiresInSeconds } = challenge;
  const deadline = Date.now() + expiresInSeconds * 1000;
  const timeLeft = h('span', {}, '');
  let done = false;

  const finish = async (status) => {
    if (done) return;
    done = true;
    stop();
    if (status === 'approved') {
      try {
        const { data } = await publicCall('POST', '/api/auth/login/complete', { challengeId, pollSecret, deviceId });
        setSession(data);
        return onSession();
      } catch (err) {
        return onBack(err.message);
      }
    }
    onBack(status === 'denied' ? 'The request was denied on your trusted device.' : 'The request expired. Try again.');
  };

  const stopSocket = watchChallenge(challengeId, pollSecret, finish);
  const poll = setInterval(async () => {
    if (Date.now() > deadline) return finish('expired');
    try {
      const { data } = await publicCall('POST', `/api/approval/${challengeId}/status`, { pollSecret });
      if (data.status !== 'pending') finish(data.status);
    } catch {
      /* try again on the next tick */
    }
  }, POLL_MS);
  const tick = setInterval(() => {
    timeLeft.textContent = `${Math.max(0, Math.round((deadline - Date.now()) / 1000))}s`;
  }, 500);
  const stop = () => {
    stopSocket();
    clearInterval(poll);
    clearInterval(tick);
  };

  clear(root);
  root.append(
    h('main', {},
      h('h1', {}, 'Approve this sign-in'),
      h('p', { class: 'muted' }, 'Open FraudShield on a device you already trust and choose this number:'),
      h('div', { class: 'card' },
        h('div', { class: 'number', 'aria-label': `Number ${displayNumber}` }, displayNumber),
        h('p', { class: 'pulse' }, 'Waiting for approval · ', timeLeft)
      ),
      h('button', { onclick: () => { done = true; stop(); onBack(); } }, 'Cancel')
    )
  );
};

const loginForm = ({ onSession, onWaiting, show }) => {
  const email = h('input', { type: 'email', autocomplete: 'username', required: true });
  const password = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const totp = h('input', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 6 });
  const totpRow = field('Authenticator code', totp);
  totpRow.hidden = true;
  const error = h('div', { class: 'error', role: 'alert' });
  const button = h('button', { class: 'primary', type: 'submit' }, 'Log in');

  const submit = guarded(button, error, async () => {
    try {
      const body = { email: email.value, password: password.value, deviceId, deviceName };
      if (!totpRow.hidden) body.totp = totp.value;
      const { status, data } = await publicCall('POST', '/api/auth/login', body);
      if (status === 202) return onWaiting(data);
      setSession(data);
      onSession();
    } catch (err) {
      if (err.code === 'TOTP_REQUIRED') {
        totpRow.hidden = false;
        totp.focus();
        throw new Error('Enter the 6-digit code from your authenticator app.');
      }
      throw err;
    }
  });

  return h('form', { class: 'card stack', onsubmit: submit },
    field('Email', email), field('Password', password), totpRow, error, button,
    h('div', { class: 'row space' },
      h('button', { class: 'link', type: 'button', onclick: () => show('forgot') }, 'Forgot password?'),
      h('button', { class: 'link', type: 'button', onclick: () => show('recover') }, 'Lost your devices?')
    )
  );
};

const registerForm = ({ onSession }) => {
  const name = h('input', { type: 'text', autocomplete: 'name', required: true });
  const email = h('input', { type: 'email', autocomplete: 'username', required: true });
  const password = h('input', { type: 'password', autocomplete: 'new-password', required: true });
  const error = h('div', { class: 'error', role: 'alert' });
  const button = h('button', { class: 'primary', type: 'submit' }, 'Create account');

  const submit = guarded(button, error, async () => {
    const { data } = await publicCall('POST', '/api/auth/register', {
      name: name.value, email: email.value, password: password.value, deviceId, deviceName,
    });
    setSession(data);
    onSession();
  });

  return h('form', { class: 'card stack', onsubmit: submit },
    field('Name', name), field('Email', email), field('Password', password),
    h('p', { class: 'muted' }, 'At least 8 characters with a letter and a number. This device becomes your first trusted device.'),
    error, button
  );
};

const forgotForm = ({ show }) => {
  const email = h('input', { type: 'email', required: true });
  const token = h('input', { type: 'text', autocomplete: 'off' });
  const password = h('input', { type: 'password', autocomplete: 'new-password' });
  const resetRow = h('div', { class: 'stack' }, field('Reset code from the email', token), field('New password', password));
  resetRow.hidden = true;
  const error = h('div', { class: 'error', role: 'alert' });
  const button = h('button', { class: 'primary', type: 'submit' }, 'Send reset email');

  const submit = guarded(button, error, async () => {
    if (resetRow.hidden) {
      await publicCall('POST', '/api/auth/forgot-password', { email: email.value });
      resetRow.hidden = false;
      button.textContent = 'Set new password';
      toast('If that email is registered, a message is on its way.');
      return;
    }
    await publicCall('POST', '/api/auth/reset-password', { token: token.value.trim(), password: password.value });
    toast('Password updated. Log in with it now.');
    show('login');
  });

  return h('form', { class: 'card stack', onsubmit: submit }, field('Email', email), resetRow, error, button,
    h('button', { class: 'link', type: 'button', onclick: () => show('login') }, 'Back to log in'));
};

const recoverForm = ({ onSession, show }) => {
  const email = h('input', { type: 'email', required: true });
  const password = h('input', { type: 'password', required: true });
  const code = h('input', { type: 'text', autocomplete: 'off', placeholder: 'XXXX-XXXX-XXXX', required: true });
  const error = h('div', { class: 'error', role: 'alert' });
  const button = h('button', { class: 'primary', type: 'submit' }, 'Recover account');

  const submit = guarded(button, error, async () => {
    const { data } = await publicCall('POST', '/api/auth/recover', {
      email: email.value, password: password.value, recoveryCode: code.value, deviceId, deviceName,
    });
    setSession(data);
    toast(`Signed in. ${data.remainingCodes} recovery codes left.`);
    onSession();
  });

  return h('form', { class: 'card stack', onsubmit: submit },
    h('div', { class: 'notice' }, 'Use this only if you cannot reach any trusted device. This device becomes the only trusted one and every other device is signed out.'),
    field('Email', email), field('Password', password), field('Recovery code', code), error, button,
    h('button', { class: 'link', type: 'button', onclick: () => show('login') }, 'Back to log in'));
};

export const showAuth = (root, { onSession, notice }) => {
  let mode = 'login';
  const render = () => {
    const forms = { login: loginForm, register: registerForm, forgot: forgotForm, recover: recoverForm };
    const ctx = {
      onSession,
      show: (next) => { mode = next; render(); },
      onWaiting: (challenge) => showWaiting(root, challenge, {
        onSession,
        onBack: (message) => { render(); if (message) toast(message); },
      }),
    };
    clear(root);
    root.append(
      h('main', {},
        h('h1', {}, 'FraudShield Authenticator'),
        h('p', { class: 'muted' }, 'Sign-ins that look unusual need approval from a device you trust.'),
        notice ? h('div', { class: 'notice' }, notice) : '',
        h('div', { class: 'row' },
          ['login', 'register'].map((m) =>
            h('button', { class: mode === m ? 'primary' : '', onclick: () => ctx.show(m) }, m === 'login' ? 'Log in' : 'Register')
          )
        ),
        forms[mode](ctx)
      )
    );
  };
  render();
};
