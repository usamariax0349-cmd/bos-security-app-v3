const CACHE = 'bos-v76';
const SHELL = ['/', '/index.html'];
const STATIC = [...SHELL, '/manifest.json', '/icon.svg', '/img/login-hero.jpg'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(STATIC)));
  self.skipWaiting();
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
  ));
  self.clients.claim();
});
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // Network-first for API and uploads
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/uploads/') || url.pathname === '/logo') {
    e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
    return;
  }
  // Network-first for the app shell itself: any full-page navigation (this
  // covers every SPA entry point server.py serves index.html for — /,
  // /verify/<token>, /apply, /privacy — not just '/') plus '/index.html'
  // directly. This is what actually changes on every deploy and isn't
  // versioned/hashed the way a normal cache-busted bundle would be, so
  // serving it cache-first meant an installed PWA could get stuck showing
  // an old build indefinitely even after a newer service worker had
  // already activated. Falls back to the cached shell only when genuinely
  // offline.
  if (e.request.mode === 'navigate' || SHELL.includes(url.pathname)) {
    e.respondWith(
      fetch(e.request).then(res => {
        if (res.ok) {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return res;
      }).catch(() => caches.match(e.request).then(cached => cached || caches.match('/index.html')))
    );
    return;
  }
  // Cache-first for static assets
  e.respondWith(
    caches.match(e.request).then(cached => cached || fetch(e.request).then(res => {
      if (res.ok) {
        const clone = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, clone));
      }
      return res;
    }))
  );
});

// ── Push notifications (guard messages, new shifts published) ──────────────
self.addEventListener('push', e => {
  let data = {title: 'Brown Owl Security', body: 'You have a new notification', url: '/'};
  try { if (e.data) data = {...data, ...e.data.json()}; } catch(err) {}
  e.waitUntil(self.registration.showNotification(data.title, {
    body: data.body, icon: '/icon.svg', badge: '/icon.svg', data: {url: data.url}
  }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || '/';
  e.waitUntil(
    self.clients.matchAll({type: 'window', includeUncontrolled: true}).then(clientsArr => {
      const existing = clientsArr.find(c => 'focus' in c);
      if (existing) return existing.focus();
      return self.clients.openWindow(url);
    })
  );
});
