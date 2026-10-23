/* 한마당 챗 푸시 중계 — 브라우저 CORS 제한 우회 (Netlify Functions 무료 티어)
   클라이언트가 암호화 본문을 base64 JSON으로 보내면 서버가 바이너리로 복원해 FCM에 전송 */
const ALLOWED = [/\.googleapis\.com$/, /push\.services\.mozilla\.com$/];
exports.handler = async (event) => {
  const json = (code, msg) => ({ statusCode: code, headers: { 'Content-Type': 'text/plain; charset=utf-8' }, body: msg });
  if (event.httpMethod === 'GET') return json(405, 'POST only');
  if (event.httpMethod !== 'POST') return json(405, 'POST only');
  let ep = '';
  try { ep = decodeURIComponent((event.queryStringParameters || {}).endpoint || ''); } catch (e) { ep = ''; }
  let host = '';
  try { host = new URL(ep).host; } catch (e) { host = ''; }
  if (!/^https:/.test(ep) || !ALLOWED.some((re) => re.test(host))) return json(400, 'bad endpoint: ' + (host || 'none'));
  let raw;
  try {
    const parsed = JSON.parse(event.body || '{}');
    if (!parsed || typeof parsed.b64 !== 'string') return json(400, 'no b64');
        raw = Buffer.from(parsed.b64.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    if (!raw.length) return json(400, 'empty body');
  } catch (e) { return json(400, 'bad json: ' + String((e && e.message) || e).slice(0, 80)); }
  const H = event.headers || {};
  const get = (k) => H[k] || H[k.toLowerCase()] || H[k.replace(/(^|-)(\w)/g, (m) => m.toUpperCase())] || '';
  const ttl = get('ttl'), urg = get('urgency'), enc = get('content-encoding'), auth = get('authorization');
  if (!auth) return json(400, 'missing authorization');
  if (!ttl || isNaN(Number(ttl))) ttl = '3600';
  const fwd = {};
  if (ttl) fwd['TTL'] = ttl;
  if (urg) fwd['Urgency'] = urg;
  if (enc) fwd['Content-Encoding'] = enc;
  fwd['Authorization'] = auth;
  try {
    const r = await fetch(ep, { method: 'POST', headers: fwd, body: raw });
    const txt = (await r.text()).slice(0, 200);
    return json(r.status, r.status + (txt ? ' ' + txt : ''));
  } catch (e) {
    return json(502, 'relay error: ' + String((e && e.message) || e).slice(0, 120));
  }
};
