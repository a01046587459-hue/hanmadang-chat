/* 한마당 챗 푸시 중계 v2 — 서버사이드 암호화+서명 (바이너리 전달 없음) */
const crypto = require('crypto');
const ALLOWED = [/\.googleapis\.com$/, /push\.services\.mozilla\.com$/];

function b64uToBuf(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}
function bufToB64u(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* RFC 8291 암호화: aes128gcm */
function encryptPayload(subKeyBuf, authBuf, payloadBytes) {
  const salt = crypto.randomBytes(16);
  const eph = crypto.createECDH('prime256v1');
  eph.generateKeys();
  const ephPub = eph.getPublicKey();           /* 65B uncompressed */
  const ecdhSecret = eph.computeSecret(subKeyBuf); /* 32B */
  /* ikm = ecdh_secret || auth_secret */
  const ikm = Buffer.concat([ecdhSecret, authBuf]);
  const cekInfo = Buffer.concat([Buffer.from('Content-Encoding: aes128gcm\0'), Buffer.from('P-256'), Buffer.from([0, 0, 0, 1]), ephPub, subKeyBuf]);
  const cek = crypto.hkdfSync('sha256', ikm, salt, cekInfo, 16);
  const nonceInfo = Buffer.concat([Buffer.from('Content-Encoding: nonce\0'), Buffer.from('P-256'), Buffer.from([0, 0, 0, 1]), ephPub, subKeyBuf]);
  const nonce = crypto.hkdfSync('sha256', ikm, salt, nonceInfo, 12);
  /* record: payload + delimiter 0x02 (minimal padding) */
  const record = Buffer.concat([payloadBytes, Buffer.from([0x02])]);
  const cipher = crypto.createCipheriv('aes-128-gcm', Buffer.from(cek), Buffer.from(nonce), { authTagLength: 16 });
  const ct = Buffer.concat([cipher.update(record), cipher.final(), cipher.getAuthTag()]);
  /* header: salt(16) + rs(4)=4096 + idlen(1)=65 + keyid(65) */
  const header = Buffer.concat([salt, Buffer.from([0, 0, 16, 0]), Buffer.from([65]), ephPub]);
  return Buffer.concat([header, ct]);
}

/* VAPID JWT (ES256) */
function makeVapidJwt(aud, privJwk) {
  const header = { typ: 'JWT', alg: 'ES256' };
  const p = { aud, exp: Math.floor(Date.now() / 1000) + 43200, sub: 'mailto:hanmadang-chat@example.com' };
  const hB = bufToB64u(Buffer.from(JSON.stringify(header)));
  const pB = bufToB64u(Buffer.from(JSON.stringify(p)));
  const signInput = hB + '.' + pB;
  const jwk = privJwk;
  const keyObj = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  const sig = crypto.sign('sha256', Buffer.from(signInput), keyObj); /* 64B raw r||s */
  return signInput + '.' + bufToB64u(sig);
}

const json = (code, msg) => ({ statusCode: code, headers: { 'Content-Type': 'text/plain; charset=utf-8' }, body: msg });

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, 'POST only');
  let d;
  try { d = JSON.parse(event.body || '{}'); } catch (e) { return json(400, 'bad json'); }
  const ep = d.endpoint || '';
  let host = '';
  try { host = new URL(ep).host; } catch (e) {}
  if (!/^https:/.test(ep) || !ALLOWED.some((re) => re.test(host))) return json(400, 'bad endpoint: ' + (host || 'none'));
  const keys = d.keys || {};
  if (!keys.p256dh || !keys.auth) return json(400, 'missing keys');
  if (!d.vapidPrivJwk) return json(400, 'missing vapid key');
  let payloadBytes;
  try { payloadBytes = Buffer.from(JSON.stringify(d.payload || {}), 'utf8'); } catch (e) { return json(400, 'bad payload'); }
  let subKey, authBuf, privJwk;
  try {
    subKey = b64uToBuf(keys.p256dh);
    authBuf = b64uToBuf(keys.auth);
    privJwk = JSON.parse(d.vapidPrivJwk);
  } catch (e) { return json(400, 'bad key format: ' + String((e && e.message) || e).slice(0, 60)); }
  if (!Buffer.isBuffer(subKey) || subKey.length < 65 || subKey[0] !== 0x04) return json(400, 'bad p256dh: len=' + (subKey ? subKey.length : 0) + ' first=' + (subKey ? subKey[0] : '-'));
  try {
    const body = encryptPayload(subKey, authBuf, payloadBytes);
    const jwt = makeVapidJwt(new URL(ep).origin, privJwk);
    const r = await fetch(ep, { method: 'POST', headers: { TTL: '3600', Urgency: 'normal', 'Content-Encoding': 'aes128gcm', Authorization: 'vapid t=' + jwt + ', k=' + d.vapidPub }, body });
    const txt = (await r.text()).slice(0, 150);
    return json(r.status, r.status + (txt ? ' ' + txt : ''));
  } catch (e) {
    return json(502, 'encrypt/send error: ' + String((e && e.message) || e).slice(0, 120));
  }
};
