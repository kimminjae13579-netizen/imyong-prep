/* =========================================================
   임용 준비 저장소 문지기 (Cloudflare Worker + R2)
   · 로그인: 구글 로그인(ID 토큰)을 확인하고, 30일짜리 로그인 표(세션)를 줌
   · 팀(스터디): 누구나 만들고, 초대 링크로 들어옴. 팀원만 그 팀 폴더를 읽고 씀
   · 공통 Q&A: 로그인한 사람은 모두 읽고, 관리자만 씀
   R2 안의 모양
     public/qna.json              공통 Q&A
     users/<이메일>.json           {teams: [팀 id…]}
     teams/<id>/team.json         {id, name, leader, members, names, invite, used, byMember, created, updated}
     teams/<id>/doc/<이름>.json    data(임용 준비 기록) · textbook(교과서 분석 기록)
     teams/<id>/files/<키>         영상 · PDF · 사진 · 메모장 (customMetadata.by = 올린 사람)
   환경 값 (wrangler.toml): CLIENT_ID, ADMIN_EMAILS, ORIGINS / 비밀 값: SESSION_SECRET
   ========================================================= */

const SESSION_DAYS = 30;
// 제한 (0 = 제한 없음). 나중에 필요하면 숫자만 바꾸면 됨
const TEAM_QUOTA_BYTES = 0;      // 팀당 용량
const TEAMS_PER_USER = 0;        // 한 사람이 만들 수 있는 팀 수
const DOC_NAMES = new Set(['data', 'textbook']);
const KEY_RE = /^[\w:.\-\/]{1,200}$/;

export default {
  async fetch(req, env) {
    const cors = corsHeaders(req, env);
    if (req.method === 'OPTIONS') return new Response(null, {status: 204, headers: cors});
    let res;
    try { res = await handle(req, env); }
    catch (e) { res = e instanceof Response ? e : json({error: '서버 오류: ' + (e.message || e)}, 500); }
    const h = new Headers(res.headers);
    for (const [k, v] of Object.entries(cors)) h.set(k, v);
    return new Response(res.body, {status: res.status, headers: h});
  }
};

function corsHeaders(req, env) {
  const o = req.headers.get('Origin') || '', ok = (env.ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  return ok.includes(o) ? {
    'Access-Control-Allow-Origin': o, 'Vary': 'Origin',
    'Access-Control-Allow-Methods': 'GET, PUT, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, If-Match',
    'Access-Control-Expose-Headers': 'X-Etag, X-Size, X-Type',
    'Access-Control-Max-Age': '86400'
  } : {'Vary': 'Origin'};
}
const json = (o, status = 200, headers = {}) => new Response(JSON.stringify(o), {status, headers: {'Content-Type': 'application/json; charset=utf-8', ...headers}});
const fail = (msg, status = 400) => { throw json({error: msg}, status); };

async function handle(req, env) {
  const url = new URL(req.url), p = url.pathname.replace(/\/+$/, '').split('/').slice(1).map(decodeURIComponent), m = req.method;
  if (p[0] === 'auth' && m === 'POST') return auth(req, env);
  if (p[0] === '' || p.length === 0) return json({ok: true});
  const me = await session(req, env);
  if (p[0] === 'me' && m === 'GET') return json(await meInfo(env, me));
  if (p[0] === 'qna') return qna(req, env, me, p.slice(1));
  if (p[0] === 'req') return requests(req, env, me, p.slice(1));
  if (p[0] === 'admin' && p[1] === 'teams' && m === 'GET') return adminTeams(env, me);
  if (p[0] === 'teams' && m === 'POST' && p.length === 1) return createTeam(req, env, me);
  if (p[0] === 'join' && m === 'POST') return joinTeam(req, env, me);
  if (p[0] === 't' && p[1]) return teamRoute(req, env, me, p.slice(1), url);
  fail('없는 주소예요.', 404);
}

/* ---------- 로그인 ---------- */
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));
const enc = new TextEncoder(), dec = new TextDecoder();
let googleKeys = null, googleKeysAt = 0;
async function googleKey(kid) {
  if (!googleKeys || Date.now() - googleKeysAt > 3600e3 || !googleKeys[kid]) {
    const j = await (await fetch('https://www.googleapis.com/oauth2/v3/certs')).json();
    googleKeys = {}; googleKeysAt = Date.now();
    for (const k of j.keys) googleKeys[k.kid] = await crypto.subtle.importKey('jwk', k, {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}, false, ['verify']);
  }
  return googleKeys[kid];
}
async function verifyGoogle(token, env) {
  const [h, b, s] = String(token || '').split('.'); if (!s) fail('로그인 정보가 이상해요.', 401);
  const head = JSON.parse(dec.decode(unb64u(h))), body = JSON.parse(dec.decode(unb64u(b)));
  const key = await googleKey(head.kid); if (!key) fail('로그인 정보를 확인하지 못했어요.', 401);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, unb64u(s), enc.encode(h + '.' + b));
  if (!ok) fail('로그인 정보가 이상해요.', 401);
  if (body.aud !== env.CLIENT_ID) fail('이 앱의 로그인이 아니에요.', 401);
  if (!['accounts.google.com', 'https://accounts.google.com'].includes(body.iss)) fail('구글 로그인이 아니에요.', 401);
  if (body.exp * 1000 < Date.now()) fail('로그인 시간이 지났어요. 다시 로그인해 주세요.', 401);
  if (!body.email || body.email_verified === false) fail('이메일이 확인된 구글 계정만 쓸 수 있어요.', 401);
  return {email: body.email.toLowerCase(), name: body.name || body.email.split('@')[0]};
}
async function hmac(env, data) {
  if (!env.SESSION_SECRET) fail('서버 설정(SESSION_SECRET)이 없어요.', 500);
  const k = await crypto.subtle.importKey('raw', enc.encode(env.SESSION_SECRET), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
  return b64u(await crypto.subtle.sign('HMAC', k, enc.encode(data)));
}
async function auth(req, env) {
  const {credential} = await req.json().catch(() => ({}));
  const u = await verifyGoogle(credential, env);
  const payload = b64u(enc.encode(JSON.stringify({e: u.email, n: u.name, x: Date.now() + SESSION_DAYS * 864e5})));
  const token = payload + '.' + await hmac(env, payload);
  return json({token, ...(await meInfo(env, u))});
}
async function session(req, env) {
  const t = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, ''), [payload, sig] = t.split('.');
  if (!payload || !sig || sig !== await hmac(env, payload)) fail('로그인이 필요해요.', 401);
  const o = JSON.parse(dec.decode(unb64u(payload)));
  if (o.x < Date.now()) fail('로그인한 지 오래돼서 다시 로그인해야 해요.', 401);
  return {email: o.e, name: o.n};
}
const isAdmin = (env, email) => (env.ADMIN_EMAILS || '').toLowerCase().split(',').map(s => s.trim()).includes(email);

/* ---------- R2 도우미 ---------- */
const getJSON = async (env, key) => { const o = await env.BUCKET.get(key); return o ? {v: await o.json(), etag: o.etag} : null; };
// 읽고 고쳐서 쓰기: 그사이 다른 사람이 고쳤으면 다시 읽어서 다시 고침
async function mutate(env, key, fn) {
  for (let i = 0; i < 8; i++) {
    const cur = await getJSON(env, key), nv = await fn(cur ? cur.v : null);
    if (nv === undefined) return cur ? cur.v : null;
    if (nv === null) { await env.BUCKET.delete(key); return null; }
    const r = await env.BUCKET.put(key, JSON.stringify(nv), {httpMetadata: {contentType: 'application/json'}, ...(cur ? {onlyIf: {etagMatches: cur.etag}} : {})});
    if (r) return nv;
  }
  fail('동시에 고치는 사람이 많아요. 잠시 뒤 다시 해 주세요.', 409);
}
const userKey = email => `users/${email}.json`;
const teamKey = id => `teams/${id}/team.json`;
const rid = n => { const a = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789', r = crypto.getRandomValues(new Uint8Array(n)); return Array.from(r, x => a[x % a.length]).join(''); };
const addUserTeam = (env, email, id) => mutate(env, userKey(email), u => { u = u || {teams: []}; if (u.teams.includes(id)) return undefined; u.teams.push(id); return u; });
const delUserTeam = (env, email, id) => mutate(env, userKey(email), u => { if (!u || !u.teams.includes(id)) return undefined; u.teams = u.teams.filter(x => x !== id); return u; });
const teamView = (t, me) => ({id: t.id, name: t.name, leader: t.leader, members: t.members, names: t.names || {}, used: t.used || 0, byMember: t.byMember || {},
  quota: TEAM_QUOTA_BYTES, created: t.created, updated: t.updated, invite: t.id + '.' + t.invite, isLeader: t.leader === me.email});

async function meInfo(env, me) {
  const u = (await getJSON(env, userKey(me.email)))?.v || {teams: []}, teams = [];
  for (const id of u.teams) { const t = (await getJSON(env, teamKey(id)))?.v; if (t && t.members.includes(me.email)) teams.push({id, name: t.name, leader: t.leader}); }
  return {email: me.email, name: me.name, admin: isAdmin(env, me.email), teams};
}

/* ---------- 팀 ---------- */
async function createTeam(req, env, me) {
  const {name} = await req.json().catch(() => ({}));
  const nm = String(name || '').trim().slice(0, 40); if (!nm) fail('스터디 이름을 써 주세요.');
  if (TEAMS_PER_USER) {
    const u = (await getJSON(env, userKey(me.email)))?.v || {teams: []}; let mine = 0;
    for (const id of u.teams) if ((await getJSON(env, teamKey(id)))?.v?.leader === me.email) mine++;
    if (mine >= TEAMS_PER_USER) fail(`한 사람이 만들 수 있는 스터디는 ${TEAMS_PER_USER}개까지예요.`);
  }
  const id = rid(10), now = Date.now();
  const t = {id, name: nm, leader: me.email, members: [me.email], names: {[me.email]: me.name}, invite: rid(16), used: 0, byMember: {}, created: now, updated: now};
  await env.BUCKET.put(teamKey(id), JSON.stringify(t), {httpMetadata: {contentType: 'application/json'}});
  await addUserTeam(env, me.email, id);
  return json(teamView(t, me));
}
async function joinTeam(req, env, me) {
  const {invite} = await req.json().catch(() => ({}));
  const [id, code] = String(invite || '').split('.');
  if (!id || !code) fail('초대 링크가 이상해요. 다시 받아 주세요.');
  let bad = false;
  const t = await mutate(env, teamKey(id), t => {
    if (!t || t.invite !== code) { bad = true; return undefined; }
    if (t.members.includes(me.email)) return undefined;
    t.members.push(me.email); t.names = {...(t.names || {}), [me.email]: me.name}; t.updated = Date.now(); return t;
  });
  if (bad || !t) fail('초대 링크가 바뀌었거나 없어진 스터디예요. 팀장에게 새 링크를 받아 주세요.', 404);
  await addUserTeam(env, me.email, id);
  return json(teamView(t, me));
}
async function loadTeam(env, id, me) {
  const t = (await getJSON(env, teamKey(id)))?.v;
  if (!t) fail('없는 스터디예요.', 404);
  if (!t.members.includes(me.email)) fail('이 스터디의 팀원이 아니에요.', 403);
  return t;
}
async function deleteTeam(env, t) {
  let cursor;
  do {
    const l = await env.BUCKET.list({prefix: `teams/${t.id}/`, cursor, limit: 1000});
    if (l.objects.length) await env.BUCKET.delete(l.objects.map(o => o.key));
    cursor = l.truncated ? l.cursor : undefined;
  } while (cursor);
  for (const e of t.members) await delUserTeam(env, e, t.id);
}

async function teamRoute(req, env, me, p, url) {
  const id = p[0], m = req.method, what = p[1] || '';
  if (!/^[\w]{6,20}$/.test(id)) fail('없는 스터디예요.', 404);
  // 팀 삭제는 관리자도 할 수 있음 (팀원이 아니어도)
  if (!what && m === 'DELETE') {
    const t = (await getJSON(env, teamKey(id)))?.v; if (!t) fail('없는 스터디예요.', 404);
    if (t.leader !== me.email && !isAdmin(env, me.email)) fail('팀장만 스터디를 지울 수 있어요.', 403);
    await deleteTeam(env, t); return json({ok: true});
  }
  const t = await loadTeam(env, id, me), leader = t.leader === me.email;
  if (!what && m === 'GET') return json(teamView(t, me));
  if (m === 'POST' && ['invite', 'kick', 'leader', 'rename', 'leave'].includes(what)) {
    const body = await req.json().catch(() => ({}));
    if (what === 'leave') {
      if (leader && t.members.length > 1) fail('팀장은 먼저 다른 팀원에게 팀장을 넘겨야 나갈 수 있어요.');
      if (leader) { await deleteTeam(env, t); return json({ok: true, deleted: true}); }
      await mutate(env, teamKey(id), t => { t.members = t.members.filter(e => e !== me.email); t.updated = Date.now(); return t; });
      await delUserTeam(env, me.email, id); return json({ok: true});
    }
    if (!leader) fail('팀장만 할 수 있어요.', 403);
    const who = String(body.email || '').toLowerCase();
    const nt = await mutate(env, teamKey(id), t => {
      if (what === 'invite') t.invite = rid(16);
      if (what === 'rename') { const nm = String(body.name || '').trim().slice(0, 40); if (!nm) fail('스터디 이름을 써 주세요.'); t.name = nm; }
      if (what === 'kick') { if (who === t.leader) fail('팀장은 내보낼 수 없어요.'); t.members = t.members.filter(e => e !== who); }
      if (what === 'leader') { if (!t.members.includes(who)) fail('팀원에게만 넘길 수 있어요.'); t.leader = who; }
      t.updated = Date.now(); return t;
    });
    if (what === 'kick') await delUserTeam(env, who, id);
    return json(teamView(nt, me));
  }
  if (what === 'doc') return teamDoc(req, env, t, p[2]);
  if (what === 'f') return teamFile(req, env, me, t, p.slice(2).join('/'));
  if (what === 'mp') return teamMultipart(req, env, me, t, p.slice(2).join('/'), url);
  fail('없는 주소예요.', 404);
}

/* ---------- 팀 기록 (data.json · textbook.json): 내가 읽은 뒤로 안 바뀌었을 때만 저장 ---------- */
async function teamDoc(req, env, t, name) {
  if (!DOC_NAMES.has(name)) fail('없는 기록이에요.', 404);
  const key = `teams/${t.id}/doc/${name}.json`;
  if (req.method === 'GET') {
    const o = await env.BUCKET.get(key);
    if (!o) return new Response('{}', {headers: {'Content-Type': 'application/json', 'X-Etag': ''}});
    return new Response(o.body, {headers: {'Content-Type': 'application/json', 'X-Etag': o.etag}});
  }
  if (req.method === 'PUT') {
    const want = req.headers.get('If-Match') || '', body = await req.arrayBuffer();
    if (body.byteLength > 20e6) fail('기록이 너무 커요.', 413);
    let r;
    if (want) r = await env.BUCKET.put(key, body, {httpMetadata: {contentType: 'application/json'}, onlyIf: {etagMatches: want}});
    else { if (await env.BUCKET.head(key)) return json({error: 'changed'}, 412); r = await env.BUCKET.put(key, body, {httpMetadata: {contentType: 'application/json'}}); }
    if (!r) return json({error: 'changed'}, 412);
    return json({etag: r.etag}, 200, {'X-Etag': r.etag});
  }
  fail('없는 주소예요.', 405);
}

/* ---------- 큰 파일 ---------- */
const fileKey = (t, k) => { if (!KEY_RE.test(k) || k.includes('..')) fail('파일 이름이 이상해요.'); return `teams/${t.id}/files/${k}`; };
// 용량 기록: 사람별로 더하고 빼기
async function account(env, t, addBy, addSize, subBy, subSize) {
  if (!addSize && !subSize) return;
  await mutate(env, teamKey(t.id), x => {
    if (!x) return undefined;
    const b = x.byMember = x.byMember || {};
    if (subBy && subSize) b[subBy] = Math.max(0, (b[subBy] || 0) - subSize);
    if (addBy && addSize) b[addBy] = (b[addBy] || 0) + addSize;
    for (const k of Object.keys(b)) if (!b[k]) delete b[k];
    x.used = Math.max(0, (x.used || 0) + (addSize || 0) - (subSize || 0)); return x;
  });
}
const quotaCheck = (t, more) => { if (TEAM_QUOTA_BYTES && (t.used || 0) + more > TEAM_QUOTA_BYTES) fail('스터디 저장 공간이 가득 찼어요. 필요 없는 영상을 지워 주세요.', 413); };
async function teamFile(req, env, me, t, k) {
  const key = fileKey(t, k), m = req.method;
  if (m === 'GET') {
    const o = await env.BUCKET.get(key); if (!o) fail('파일이 없어요.', 404);
    return new Response(o.body, {headers: {'Content-Type': o.httpMetadata?.contentType || 'application/octet-stream', 'Content-Length': String(o.size), 'X-Size': String(o.size), 'X-Type': o.customMetadata?.type || ''}});
  }
  if (m === 'PUT') {
    const size = +req.headers.get('Content-Length') || 0; quotaCheck(t, size);
    const old = await env.BUCKET.head(key), type = req.headers.get('Content-Type') || 'application/octet-stream';
    const r = await env.BUCKET.put(key, req.body, {httpMetadata: {contentType: type}, customMetadata: {by: me.email, type}});
    await account(env, t, me.email, r.size, old?.customMetadata?.by, old?.size || 0);
    return json({size: r.size});
  }
  if (m === 'DELETE') {
    const old = await env.BUCKET.head(key); if (!old) return json({ok: true});
    await env.BUCKET.delete(key); await account(env, t, null, 0, old.customMetadata?.by, old.size);
    return json({ok: true});
  }
  fail('없는 주소예요.', 405);
}
// 100MB가 넘는 영상: 나눠서 올리기 (Worker는 한 번에 100MB까지만 받음)
async function teamMultipart(req, env, me, t, k, url) {
  const key = fileKey(t, k), a = url.searchParams.get('a'), up = url.searchParams.get('u');
  if (a === 'create') {
    const {type, size} = await req.json().catch(() => ({})); quotaCheck(t, +size || 0);
    const mp = await env.BUCKET.createMultipartUpload(key, {httpMetadata: {contentType: type || 'application/octet-stream'}, customMetadata: {by: me.email, type: type || ''}});
    return json({uploadId: mp.uploadId});
  }
  if (!up) fail('올리기 정보가 없어요.');
  const mp = env.BUCKET.resumeMultipartUpload(key, up);
  if (a === 'part') { const part = await mp.uploadPart(+url.searchParams.get('n'), req.body); return json(part); }
  if (a === 'done') {
    const {parts} = await req.json(), old = await env.BUCKET.head(key);
    const o = await mp.complete(parts);
    await account(env, t, me.email, o.size, old?.customMetadata?.by, old?.size || 0);
    return json({size: o.size});
  }
  if (a === 'abort') { await mp.abort(); return json({ok: true}); }
  fail('없는 주소예요.', 404);
}

/* ---------- 관리자에게 요청: 보낸 사람과 관리자만 봄 (admin/requests.json) ---------- */
const REQ_KEY = 'admin/requests.json', REQ_MAX = 30;
async function requests(req, env, me, sub) {
  const m = req.method, what = sub[0] || '', adm = isAdmin(env, me.email);
  const mineView = ({id, text, at, reply, repliedAt}) => ({id, text, at, reply: reply || '', repliedAt: repliedAt || 0});
  if (what === 'mine' && m === 'GET') return json(((await getJSON(env, REQ_KEY))?.v || []).filter(x => x.by === me.email).map(mineView));
  if (what === 'mine' && m === 'POST') {
    const {id, text} = await req.json().catch(() => ({})), t = String(text || '').trim().slice(0, 4000);
    if (!t) fail('요청 내용을 써 주세요.');
    const rqid = /^[\w-]{4,40}$/.test(String(id || '')) ? String(id) : rid(12);
    await mutate(env, REQ_KEY, L => {
      L = L || [];
      if (L.some(x => x.id === rqid)) return undefined;
      if (L.filter(x => x.by === me.email && !x.reply).length >= REQ_MAX) fail(`답을 기다리는 요청이 ${REQ_MAX}개예요. 답이 온 뒤에 더 보내 주세요.`, 429);
      L.push({id: rqid, text: t, by: me.email, name: me.name || '', at: Date.now(), reply: '', repliedAt: 0}); return L;
    });
    return json({id: rqid});
  }
  if (what === 'mine' && m === 'DELETE' && sub[1]) {   // 내 요청 지우기
    await mutate(env, REQ_KEY, L => L && L.some(x => x.id === sub[1] && x.by === me.email) ? L.filter(x => !(x.id === sub[1] && x.by === me.email)) : undefined);
    return json({ok: true});
  }
  if (what === 'all') {
    if (!adm) fail('관리자만 볼 수 있어요.', 403);
    if (m === 'GET') return json((await getJSON(env, REQ_KEY))?.v || []);
    if (m === 'DELETE' && sub[1]) { await mutate(env, REQ_KEY, L => L && L.some(x => x.id === sub[1]) ? L.filter(x => x.id !== sub[1]) : undefined); return json({ok: true}); }
  }
  if (what === 'reply' && m === 'POST') {
    if (!adm) fail('관리자만 답할 수 있어요.', 403);
    const {id, reply} = await req.json().catch(() => ({})), r = String(reply || '').trim().slice(0, 8000);
    if (!r) fail('답을 써 주세요.');
    let found = false;
    await mutate(env, REQ_KEY, L => { const x = (L || []).find(y => y.id === id); if (!x) return undefined; found = true; x.reply = r; x.repliedAt = Date.now(); x.repliedBy = me.email; return L; });
    if (!found) fail('지워졌거나 없는 요청이에요.', 404);
    return json({ok: true});
  }
  fail('없는 주소예요.', 404);
}

/* ---------- 공통 Q&A ---------- */
// 관리자에게 묻기: 질문함(public/qna-inbox.json)에 쌓이고, 관리자가 답하면 공통 Q&A로 옮겨 모두에게 (익명으로) 보임
const INBOX = 'public/qna-inbox.json', ASK_MAX = 20;
async function qna(req, env, me, sub = []) {
  const m = req.method, what = sub[0] || '';
  if (what === 'ask' && m === 'POST') {
    const {id, q} = await req.json().catch(() => ({})), text = String(q || '').trim().slice(0, 2000);
    if (!text) fail('질문을 써 주세요.');
    const qid = /^[\w-]{4,40}$/.test(String(id || '')) ? String(id) : rid(12);
    await mutate(env, INBOX, L => {
      L = L || [];
      if (L.some(x => x.id === qid)) return undefined;
      if (L.filter(x => x.by === me.email).length >= ASK_MAX) fail(`답변을 기다리는 질문이 ${ASK_MAX}개예요. 답이 달린 뒤에 더 물어봐 주세요.`, 429);
      L.push({id: qid, q: text, by: me.email, name: me.name || '', at: Date.now()}); return L;
    });
    return json({id: qid});
  }
  if (what === 'mine' && m === 'GET') {
    const L = (await getJSON(env, INBOX))?.v || [];
    return json(L.filter(x => x.by === me.email).map(({id, q, at}) => ({id, q, at})));
  }
  if (what === 'mine' && m === 'DELETE' && sub[1]) {   // 내 질문 거두기 (답이 달리기 전)
    await mutate(env, INBOX, L => { if (!L || !L.some(x => x.id === sub[1] && x.by === me.email)) return undefined; return L.filter(x => !(x.id === sub[1] && x.by === me.email)); });
    return json({ok: true});
  }
  if (what === 'inbox') {
    if (!isAdmin(env, me.email)) fail('관리자만 볼 수 있어요.', 403);
    if (m === 'GET') return json((await getJSON(env, INBOX))?.v || []);
    if (m === 'DELETE' && sub[1]) { await mutate(env, INBOX, L => L && L.some(x => x.id === sub[1]) ? L.filter(x => x.id !== sub[1]) : undefined); return json({ok: true}); }
  }
  if (what === 'answer' && m === 'POST') {
    if (!isAdmin(env, me.email)) fail('관리자만 답할 수 있어요.', 403);
    const {id, q, a} = await req.json().catch(() => ({})), ans = String(a || '').trim();
    if (!ans) fail('답변을 써 주세요.');
    let item = null;
    await mutate(env, INBOX, L => { item = (L || []).find(x => x.id === id) || null; return item ? L.filter(x => x.id !== id) : undefined; });
    if (!item) fail('이미 답했거나 지워진 질문이에요.', 404);
    const qa = {id: item.id, q: String(q || item.q).trim().slice(0, 2000), a: ans.slice(0, 20000), asked: true, at: Date.now()};
    await mutate(env, 'public/qna.json', L => { L = L || []; return L.some(x => x.id === qa.id) ? undefined : [...L, qa]; });
    return json(qa);
  }
  if (what) fail('없는 주소예요.', 404);
  if (req.method === 'GET') { const o = await getJSON(env, 'public/qna.json'); return json(o?.v || []); }
  if (req.method === 'PUT') {
    if (!isAdmin(env, me.email)) fail('공통 Q&A는 관리자만 고칠 수 있어요.', 403);
    const list = await req.json(); if (!Array.isArray(list)) fail('Q&A 목록이 이상해요.');
    await env.BUCKET.put('public/qna.json', JSON.stringify(list), {httpMetadata: {contentType: 'application/json'}});
    return json({ok: true});
  }
  fail('없는 주소예요.', 405);
}

/* ---------- 관리자: 모든 팀 ---------- */
async function adminTeams(env, me) {
  if (!isAdmin(env, me.email)) fail('관리자만 볼 수 있어요.', 403);
  const out = []; let cursor, total = 0;
  do {
    const l = await env.BUCKET.list({prefix: 'teams/', delimiter: '/', cursor});
    for (const pre of l.delimitedPrefixes) {
      const t = (await getJSON(env, pre + 'team.json'))?.v; if (!t) continue;
      out.push({id: t.id, name: t.name, leader: t.leader, members: t.members.length,
        people: t.members.map(e => ({email: e, name: (t.names || {})[e] || '', used: (t.byMember || {})[e] || 0, leader: e === t.leader})), used: t.used || 0, created: t.created, updated: t.updated});
      total += t.used || 0;
    }
    cursor = l.truncated ? l.cursor : undefined;
  } while (cursor);
  return json({teams: out, total});
}
