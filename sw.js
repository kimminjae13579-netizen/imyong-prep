/* 임용 준비 — 인터넷이 없어도 앱이 열리게 해 주는 파일 (서비스워커)
   · 이 사이트 파일(HTML·아이콘 등): 인터넷 먼저 → 고친 내용이 바로 반영, 끊기면 담아 둔 것으로 열기
   · 라이브러리(pdf.js 등)·글꼴: 담아 둔 것 먼저 (주소에 버전이 있어 바뀌지 않음)
   · 서버(workers.dev)·구글 로그인·AI 요청은 손대지 않음 */
const CACHE = 'imy-v1';
const CORE = ['./', 'index.html', '교과서 분석 학습자.html', 'manifest.json', 'imyong-icon-192.png', 'imyong-icon-512.png'];
const CDN = /^https:\/\/(cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|fonts\.googleapis\.com|fonts\.gstatic\.com)\//;

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => Promise.all(CORE.map(u => c.add(u).catch(() => {})))).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const r = e.request; if (r.method !== 'GET') return;
  const u = new URL(r.url), same = u.origin === location.origin;
  if (!same && !CDN.test(r.url)) return;   // 서버·로그인·AI는 그냥 통과
  if (same) {   // 이 사이트 파일: 인터넷 먼저 (고친 내용이 바로 보이게)
    e.respondWith(fetch(r).then(res => { if (res.ok) { const cp = res.clone(); caches.open(CACHE).then(c => c.put(r, cp)); } return res; })
      .catch(() => caches.match(r, {ignoreSearch: true}).then(m => m || (r.mode === 'navigate' ? caches.match('index.html') : Response.error()))));
    return;
  }
  e.respondWith(caches.match(r).then(m => m || fetch(r).then(res => {
    if (res.ok || res.type === 'opaque') { const cp = res.clone(); caches.open(CACHE).then(c => c.put(r, cp)); }
    return res;
  })));
});
