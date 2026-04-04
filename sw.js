// AthleteOS Service Worker v1
const CACHE = 'athleteos-v1';
const OFFLINE_ASSETS = [
  '/AthleteOS/',
  '/AthleteOS/index.html',
  '/AthleteOS/manifest.json',
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(cache => cache.addAll(OFFLINE_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  // Network first for API calls (Supabase, Groq)
  if (e.request.url.includes('supabase.co') ||
      e.request.url.includes('groq') ||
      e.request.url.includes('workers.dev') ||
      e.request.url.includes('unpkg') ||
      e.request.url.includes('jsdelivr') ||
      e.request.url.includes('fonts.googleapis')) {
    return; // Let these go through normally
  }

  // Cache first for app shell
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(res => {
        if (res && res.status === 200 && res.type === 'basic') {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return res;
      }).catch(() => caches.match('/AthleteOS/index.html'));
    })
  );
});
