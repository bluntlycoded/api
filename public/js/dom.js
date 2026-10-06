// Builds elements with text nodes only. Server data (site names, device names,
// user agents) can be attacker-controlled, so nothing here builds markup from strings.
export const h = (tag, props = {}, ...children) => {
  const el = document.createElement(tag);
  for (const [name, value] of Object.entries(props)) {
    if (name === 'class') el.className = value;
    else if (name.startsWith('on')) el.addEventListener(name.slice(2), value);
    else if (value === true) el.setAttribute(name, '');
    else if (value !== false && value != null) el.setAttribute(name, value);
  }
  for (const child of children.flat()) el.append(child instanceof Node ? child : String(child ?? ''));
  return el;
};

export const clear = (el) => el.replaceChildren();

let toastTimer;
export const toast = (message) => {
  const el = document.getElementById('toast');
  el.textContent = message;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 3500);
};

export const field = (label, input) => h('div', {}, h('label', {}, label), input);

// Runs `task` with the button disabled and shows any error in `errorEl`.
export const guarded = (button, errorEl, task) => async (event) => {
  event?.preventDefault();
  errorEl.textContent = '';
  button.disabled = true;
  try {
    await task();
  } catch (err) {
    errorEl.textContent = err.message;
  } finally {
    button.disabled = false;
  }
};
