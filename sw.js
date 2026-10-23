/* 한마당 챗 서비스 워커 — 푸시 수신 → 시스템 알림 표시 */
self.addEventListener('install', (e) => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch(err){ d = {}; }
  const icon = d.icon || undefined;
  e.waitUntil(self.registration.showNotification(d.title || '한마당 챗 [SW기본]', {
    body: d.body || '본문없음(SW ' + '3.11.1)',
    tag: d.tag || 'hmc-msg',
    renotify: true,
    icon: icon,
    badge: icon,
    vibrate: [120, 60, 120],
    data: { url: d.url || './' }
  }));
});
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((cs) => {
    for (const c of cs) { if ('focus' in c) return c.focus(); }
    return self.clients.openWindow((e.notification.data && e.notification.data.url) || './');
  }));
});
