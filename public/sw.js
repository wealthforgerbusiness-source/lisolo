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
      .then((keys) => Promise.all(keys.map((k) => caches.delete(k))))
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
