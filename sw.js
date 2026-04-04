// AthleteOS Service Worker v5 - Always Fresh
// Network-only for HTML, cache-first for assets

const CACHE = 'athleteos-v7';
const APP_SHELL = [
  '/AthleteOS/manifest.json',
  '/AthleteOS/icon-192.png',
  '/AthleteOS/icon-512.png',
];

self.addEventListener('install', e => {
  self.skipWaiting(); // activate immediately
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(APP_SHELL))
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    // Delete ALL old caches immediately
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
      .then(() => {
        // Force all open tabs/windows to reload
        return self.clients.matchAll({ type: 'window' });
      })
      .then(clients => {
        clients.forEach(client => client.navigate(client.url));
      })
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // ALWAYS network for the main HTML - never serve from cache
  if (url.pathname === '/AthleteOS/' || 
      url.pathname === '/AthleteOS/index.html' ||
      url.pathname.endsWith('/AthleteOS/')) {
    e.respondWith(
      fetch(e.request, { cache: 'no-store' }).catch(() => 
        caches.match('/AthleteOS/index.html')
      )
    );
    return;
  }

  // Pass through all API/CDN requests
  if (!url.hostname.includes('github.io')) return;

  // Cache-first for icons/manifest
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(res => {
        if (res && res.status === 200) {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return res;
      });
    })
  );
});
