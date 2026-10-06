// Browser profile: ?profile=laptop keeps a separate device identity and session,
// so one browser can play several devices when trying the approval flow.
const profile = new URLSearchParams(location.search).get('profile') || 'default';
const key = (name) => `fs:${profile}:${name}`;

const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

// A random secret generated once per install; the server stores only its hash.
const deviceId = (() => {
  let id = localStorage.getItem(key('device'));
  if (!id) {
    id = hex(crypto.getRandomValues(new Uint8Array(24)));
    localStorage.setItem(key('device'), id);
  }
  return id;
})();

const describeBrowser = () => {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Linux/.test(ua) ? 'Linux' : 'unknown OS';
  return `${profile === 'default' ? '' : `${profile}: `}${browser} on ${os}`;
};
const deviceName = describeBrowser();

class ApiError extends Error {
  constructor(status, body) {
    super(body?.message || `Request failed (${status})`);
    this.status = status;
    this.body = body || {};
    this.code = body?.code;
  }
}

let accessToken = null;
let refreshing = null;

const send = async (method, path, body, token) => {
  const res = await fetch(path, {
    method,
    headers: { 'content-type': 'application/json', ...(token && { authorization: `Bearer ${token}` }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => null);
  // 202 is a normal answer to login: approval required.
  if (!res.ok && res.status !== 202) throw new ApiError(res.status, data);
  return { status: res.status, data };
};

// fetch() itself rejects (instead of returning a status) when there is no connection.
const isNetworkError = (err) => !(err instanceof ApiError);

const hasRefreshToken = () => Boolean(localStorage.getItem(key('refresh')));
const getToken = () => accessToken;

const setSession = (session) => {
  accessToken = session.token;
  localStorage.setItem(key('refresh'), session.refreshToken);
};

const clearSession = () => {
  accessToken = null;
  localStorage.removeItem(key('refresh'));
};

// One refresh at a time; the server rotates the token, so parallel calls would
// look like token theft.
const refresh = () => {
  refreshing ??= send('POST', '/api/auth/refresh', { refreshToken: localStorage.getItem(key('refresh')) })
    .then(({ data }) => {
      setSession(data);
      return data;
    })
    .catch((err) => {
      // Only a rejection from the server ends the session. A network failure must not
      // sign the user out, since that is exactly when they are working offline.
      if (err instanceof ApiError) {
        clearSession();
        if (err.code === 'REFRESH_INVALID') window.dispatchEvent(new Event('session-revoked'));
      }
      throw err;
    })
    .finally(() => {
      refreshing = null;
    });
  return refreshing;
};

// Authenticated call. An expired access token triggers one silent refresh and retry.
const api = async (method, path, body) => {
  try {
    return (await send(method, path, body, accessToken)).data;
  } catch (err) {
    if (err instanceof ApiError && [401, 403].includes(err.status) && /token/i.test(err.message) && hasRefreshToken()) {
      await refresh();
      return (await send(method, path, body, accessToken)).data;
    }
    throw err;
  }
};

// Calls that happen before there is a session (login, recovery, polling).
const publicCall = (method, path, body) => send(method, path, body);

export { profile, deviceId, deviceName, ApiError, isNetworkError, api, publicCall, setSession, clearSession, hasRefreshToken, getToken, refresh };
