// Lets the web client open with no connection. It caches only the app's own files;
// API calls and live updates are never cached, so no account data is stored here.
const VERSION = 'v1';
const CACHE = `fraudshield-shell-${VERSION}`;
const SHELL = [
  '/app/',
  '/app/app.css',
  '/app/js/main.js',
  '/app/js/api.js',
  '/app/js/approvals.js',
  '/app/js/auth.js',
  '/app/js/codes.js',
  '/app/js/dom.js',
  '/app/js/localCrypto.js',
  '/app/js/otp.js',
  '/app/js/realtime.js',
  '/app/js/security.js',
  '/app/js/vault.js',
];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((names) => Promise.all(names.filter((n) => n !== CACHE).map((n) => caches.delete(n))))
      .then(() => self.clients.claim())
  );
});

// Serve from the cache straight away and refresh it in the background, so a deploy
// reaches users on their next visit.
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== location.origin || !url.pathname.startsWith('/app/')) return;
  if (url.pathname === '/app/sw.js') return;

  event.respondWith(
    caches.open(CACHE).then(async (cache) => {
      const cached = await cache.match(request, { ignoreSearch: true });
      const network = fetch(request)
        .then((response) => {
          if (response.ok) cache.put(request.mode === 'navigate' ? '/app/' : request, response.clone());
          return response;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});
