// AthleteOS Service Worker v3 - Network First Strategy
const CACHE = 'athleteos-v4';

self.addEventListener('install', e => {
  self.skipWaiting(); // Take over immediately
});

self.addEventListener('activate', e => {
  // Delete ALL old caches
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // Always network-first for the app HTML
  if (url.pathname.includes('index.html') || url.pathname.endsWith('/AthleteOS/')) {
    e.respondWith(
      fetch(e.request, { cache: 'no-cache' })
        .catch(() => caches.match(e.request))
    );
    return;
  }

  // Let API calls go through normally
  if (url.hostname.includes('supabase.co') ||
      url.hostname.includes('workers.dev') ||
      url.hostname.includes('groq') ||
      url.hostname.includes('unpkg') ||
      url.hostname.includes('jsdelivr') ||
      url.hostname.includes('fonts.googleapis')) {
    return;
  }

  // Cache-first for other static assets
  e.respondWith(
    caches.match(e.request).then(cached => {
      const network = fetch(e.request).then(res => {
        if (res && res.status === 200) {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return res;
      });
      return cached || network;
    })
  );
});
