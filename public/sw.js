'use strict';

const OFFLINE_PAGE =
  '<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">' +
  '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">' +
  '<meta name="theme-color" content="#F85A03"><title>Hors connexion – Lisolo</title>' +
  '<style>*{box-sizing:border-box;margin:0}body{min-height:100vh;display:grid;place-items:center;padding:24px;' +
  'background:#F85A03;color:#fff;font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;text-align:center}' +
  'main{max-width:340px}h1{font-size:28px;font-weight:800;margin-bottom:10px}p{font-size:16px;line-height:1.5;opacity:.95;margin-bottom:24px}' +
  'a{display:inline-block;background:#fff;color:#B53E00;font-weight:800;text-decoration:none;padding:15px 28px;border-radius:15px}</style></head>' +
  '<body><main><h1>Pas de connexion</h1><p>Lisolo a besoin d’internet. Vérifie ton réseau, puis réessaie.</p>' +
  '<a href="/app">Réessayer</a></main></body></html>';

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== 'lisolo-badge').map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.mode !== 'navigate') return;
  event.respondWith(
    fetch(req).catch(
      () =>
        new Response(OFFLINE_PAGE, {
          status: 503,
          headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
        })
    )
  );
});

// Compteur sur l'icône de l'app installée (+1 à chaque notification reçue)
async function bumpBadge() {
  try {
    const c = await caches.open('lisolo-badge');
    const r = await c.match('/__badge');
    const n = (r ? parseInt(await r.text(), 10) || 0 : 0) + 1;
    await c.put('/__badge', new Response(String(n)));
    if (self.navigator && typeof self.navigator.setAppBadge === 'function') await self.navigator.setAppBadge(n);
  } catch (e) {}
}

async function tellClients() {
  try {
    const list = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    list.forEach((c) => c.postMessage({ type: 'push' }));
  } catch (e) {}
}

self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = { body: event.data ? event.data.text() : '' };
  }
  const title = String(data.title || 'Lisolo').slice(0, 80);
  const options = {
    body: String(data.body || '').slice(0, 240),
    icon: '/images/icon-192.png',
    badge: '/images/favicon-48.png',
    tag: data.tag ? String(data.tag) : undefined,
    data: { url: typeof data.url === 'string' && data.url ? data.url : '/app' },
  };
  event.waitUntil(Promise.all([self.registration.showNotification(title, options), bumpBadge(), tellClients()]));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const raw = (event.notification.data && event.notification.data.url) || '/app';
  let target;
  try {
    target = new URL(raw, self.location.origin).href;
  } catch (e) {
    target = self.location.origin + '/app';
  }
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      const sameOrigin = target.startsWith(self.location.origin);
      if (sameOrigin) {
        for (const c of list) {
          if ('focus' in c && 'navigate' in c) return c.navigate(target).then((w) => (w || c).focus());
        }
      }
      return self.clients.openWindow(target);
    })
  );
});
