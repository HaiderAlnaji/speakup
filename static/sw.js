// sw.js — minimal service worker.
//
// Its only real job is to satisfy PWA installability (Chrome/Android
// require a registered service worker with a fetch handler before they'll
// offer "Add to Home Screen"). It is deliberately NETWORK-FIRST everywhere:
// it never prefers a cached response over a live one, so it can't cause
// the "my changes did nothing" staleness bug that index.html's own
// Cache-Control: no-store headers already guard against. The cache is
// only ever used as a fallback when there is genuinely no network.
//
// It also never touches /api/ requests — those must always be live,
// authenticated, and fresh; caching them would be actively wrong.
const CACHE_NAME = "speakup-shell-v1";
const SHELL_ASSETS = ["/manifest.json", "/icon-192.png", "/icon-512.png"];

self.addEventListener("install", (event) => {
  self.skipWaiting();
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS)));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (url.pathname.startsWith("/api/")) return;   // never cache API calls
  if (event.request.method !== "GET") return;

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const copy = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy)).catch(() => {});
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
