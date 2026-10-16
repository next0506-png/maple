// 단풍숲 모험 서버: 정적 파일 + 계정/저장 REST + WebSocket 실시간 접속
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const PUBLIC = path.join(__dirname, 'public');
fs.mkdirSync(DATA_DIR, { recursive: true });

/* ---------- 저장소 (JSON 파일, 변경 시 디바운스 기록) ---------- */
let db = { users: {}, tokens: {} };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))); } catch (e) {}
let dirty = false;
function markDirty() { dirty = true; }
function flush() {
  if (!dirty) return;
  dirty = false;
  const tmp = DB_FILE + '.tmp';
  try { fs.writeFileSync(tmp, JSON.stringify(db)); fs.renameSync(tmp, DB_FILE); } catch (e) { dirty = true; console.error('save fail', e.message); }
}
setInterval(flush, 3000);
process.on('SIGTERM', () => { flush(); process.exit(0); });
process.on('SIGINT', () => { flush(); process.exit(0); });

function hashPw(pw, salt) { return crypto.scryptSync(pw, salt, 32).toString('hex'); }
function newToken(name) {
  const t = crypto.randomBytes(24).toString('hex');
  db.tokens[t] = { name, t: Date.now() };
  markDirty();
  return t;
}
function userOf(token) {
  const r = token && db.tokens[token];
  return r && db.users[r.name] ? r.name : null;
}

/* ---------- 간단한 요청 제한 ---------- */
const hits = new Map();
function limited(ip, max, ms) {
  const now = Date.now();
  const a = (hits.get(ip) || []).filter(t => now - t < ms);
  a.push(now); hits.set(ip, a);
  return a.length > max;
}
setInterval(() => hits.clear(), 600000);

/* ---------- HTTP ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml', '.webmanifest': 'application/manifest+json' };
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}
function readBody(req, max = 400000) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', c => { n += c.length; if (n > max) { reject(new Error('big')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
const NAME_OK = n => typeof n === 'string' && n.length >= 2 && n.length <= 10 && !/[<>&"'\\\/\s]/.test(n);

const server = http.createServer(async (req, res) => {
  const ip = req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : req.socket.remoteAddress;
  const url = new URL(req.url, 'http://x');
  try {
    if (url.pathname === '/api/ping') return send(res, 200, { ok: true, v: 1, online: wss.clients.size });
    if (url.pathname === '/api/register' && req.method === 'POST') {
      if (limited(ip, 15, 600000)) return send(res, 429, { err: '잠시 후 다시 시도해 주세요.' });
      const b = await readBody(req);
      if (!NAME_OK(b.name)) return send(res, 400, { err: '아이디는 2~10자로 입력해 주세요.' });
      if (typeof b.pw !== 'string' || b.pw.length < 4 || b.pw.length > 60) return send(res, 400, { err: '비밀번호는 4자 이상이어야 해요.' });
      if (db.users[b.name]) return send(res, 409, { err: '이미 있는 아이디예요. 로그인을 눌러 주세요.' });
      const salt = crypto.randomBytes(8).toString('hex');
      db.users[b.name] = { salt, hash: hashPw(b.pw, salt), save: null, created: Date.now() };
      markDirty();
      return send(res, 200, { token: newToken(b.name), name: b.name, save: null });
    }
    if (url.pathname === '/api/login' && req.method === 'POST') {
      if (limited(ip, 30, 600000)) return send(res, 429, { err: '잠시 후 다시 시도해 주세요.' });
      const b = await readBody(req);
      const u = typeof b.name === 'string' && db.users[b.name];
      if (!u) return send(res, 404, { err: '없는 아이디예요. "새로 시작"으로 만들 수 있어요.' });
      const h = hashPw(String(b.pw || ''), u.salt);
      if (!crypto.timingSafeEqual(Buffer.from(h), Buffer.from(u.hash))) return send(res, 401, { err: '비밀번호가 맞지 않아요.' });
      return send(res, 200, { token: newToken(b.name), name: b.name, save: u.save });
    }
    if (url.pathname === '/api/me' && req.method === 'GET') {
      const name = userOf(req.headers['x-token']);
      if (!name) return send(res, 401, { err: '로그인이 필요해요.' });
      return send(res, 200, { name, save: db.users[name].save });
    }
    if (url.pathname === '/api/save' && req.method === 'PUT') {
      const name = userOf(req.headers['x-token']);
      if (!name) return send(res, 401, { err: '로그인이 필요해요.' });
      const b = await readBody(req);
      if (!b || typeof b.save !== 'string' || b.save.length > 300000) return send(res, 400, { err: '저장 데이터가 올바르지 않아요.' });
      db.users[name].save = b.save; db.users[name].saved = Date.now();
      markDirty();
      return send(res, 200, { ok: true });
    }
    if (url.pathname === '/api/logout' && req.method === 'POST') {
      const t = req.headers['x-token'];
      if (t && db.tokens[t]) { delete db.tokens[t]; markDirty(); }
      return send(res, 200, { ok: true });
    }
    // 정적 파일
    let p = url.pathname === '/' ? '/index.html' : url.pathname;
    const file = path.normalize(path.join(PUBLIC, p));
    if (!file.startsWith(PUBLIC)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (err, data) => {
      if (err) { res.writeHead(404); return res.end('Not found'); }
      res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
      res.end(data);
    });
  } catch (e) {
    send(res, 400, { err: '요청이 올바르지 않아요.' });
  }
});

/* ---------- WebSocket (의존성 없는 최소 구현, RFC 6455) ---------- */
class Sock {
  constructor(socket) {
    this.socket = socket; this.buf = Buffer.alloc(0); this.readyState = 1; this.handlers = {};
    socket.on('data', d => { this.buf = Buffer.concat([this.buf, d]); this.parse(); });
    socket.on('close', () => this.finish());
    socket.on('error', () => this.finish());
  }
  on(ev, fn) { this.handlers[ev] = fn; }
  emit(ev, a) { if (this.handlers[ev]) this.handlers[ev](a); }
  finish() { if (this.readyState === 3) return; this.readyState = 3; this.emit('close'); }
  frame(op, payload) {
    const len = payload.length; let h;
    if (len < 126) h = Buffer.from([0x80 | op, len]);
    else if (len < 65536) { h = Buffer.alloc(4); h[0] = 0x80 | op; h[1] = 126; h.writeUInt16BE(len, 2); }
    else { h = Buffer.alloc(10); h[0] = 0x80 | op; h[1] = 127; h.writeBigUInt64BE(BigInt(len), 2); }
    return Buffer.concat([h, payload]);
  }
  send(str) { if (this.readyState === 1) try { this.socket.write(this.frame(1, Buffer.from(str))); } catch (e) {} }
  ping() { if (this.readyState === 1) try { this.socket.write(this.frame(9, Buffer.alloc(0))); } catch (e) {} }
  close(code, reason) {
    if (this.readyState !== 1) return;
    this.readyState = 2;
    const r = Buffer.from(reason || '');
    const p = Buffer.alloc(2 + r.length); p.writeUInt16BE(code || 1000, 0); r.copy(p, 2);
    try { this.socket.write(this.frame(8, p)); } catch (e) {}
    setTimeout(() => { try { this.socket.destroy(); } catch (e) {} }, 300);
  }
  parse() {
    for (;;) {
      const b = this.buf; if (b.length < 2) return;
      const op = b[0] & 0x0f, masked = !!(b[1] & 0x80); let len = b[1] & 0x7f, off = 2;
      if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (b.length < 10) return; len = Number(b.readBigUInt64BE(2)); off = 10; }
      if (len > 4096 || !masked) { this.close(1009, 'bad'); this.buf = Buffer.alloc(0); return; }
      if (b.length < off + 4 + len) return;
      const mask = b.slice(off, off + 4); const data = Buffer.from(b.slice(off + 4, off + 4 + len));
      for (let i = 0; i < data.length; i++) data[i] ^= mask[i & 3];
      this.buf = b.slice(off + 4 + len);
      if (op === 1) this.emit('message', data);
      else if (op === 8) { this.close(1000); return; }
      else if (op === 9) { try { this.socket.write(this.frame(10, data)); } catch (e) {} }
    }
  }
}
const wss = { clients: new Set() };
server.on('upgrade', (req, socket) => {
  const url = new URL(req.url, 'http://x');
  const key = req.headers['sec-websocket-key'];
  if (url.pathname !== '/ws' || !key) { socket.destroy(); return; }
  const accept = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  socket.setNoDelay(true);
  onConnection(new Sock(socket), url);
});

let nextId = 1;
const clients = new Map(); // sock -> {id,name,presence}

function clean(s, n) { return String(s == null ? '' : s).replace(/[<>]/g, '').slice(0, n); }
function sanitizePres(p) {
  if (!p || typeof p !== 'object') return null;
  if (!p.n) return { m: null, n: null, s: null };
  const o = {
    n: clean(p.n, 12), j: clean(p.j, 12), h: clean(p.h, 12), wp: +p.wp | 0, l: +p.l | 0,
    m: clean(p.m, 40), x: +p.x || 0, y: +p.y || 0, d: p.d < 0 ? -1 : 1, w: p.w ? 1 : 0, a: p.a ? 1 : 0, k: +p.k | 0, dd: p.dd ? 1 : 0
  };
  if (p.s && typeof p.s === 'object') o.s = { i: clean(p.s.i, 24), t: clean(p.s.t, 40) };
  return o;
}
function snapshot() {
  const list = [];
  for (const c of clients.values()) if (c.presence && c.presence.n) list.push({ peer: c.id, presence: c.presence });
  return list;
}
function broadcast(msg, except) {
  const s = JSON.stringify(msg);
  for (const w of clients.keys()) if (w !== except) w.send(s);
}
function onConnection(ws, url) {
  const name = userOf(url.searchParams.get('token'));
  if (!name) { ws.close(4001, 'auth'); return; }
  for (const [w, c] of clients) if (c.name === name) w.close(4002, 'dup');
  const me = { id: 'p' + (nextId++), name, presence: null };
  clients.set(ws, me); wss.clients.add(ws);
  ws.send(JSON.stringify({ t: 'hello', id: me.id, peers: snapshot() }));
  ws.on('message', buf => {
    let m; try { m = JSON.parse(buf.toString()); } catch (e) { return; }
    if (m.t === 'pres') {
      const p = sanitizePres(m.p);
      if (!p) return;
      if (p.n) p.n = me.name; // 이름 위조 방지
      me.presence = p;
      broadcast({ t: 'pres', peer: me.id, p }, ws);
    }
  });
  ws.on('close', () => {
    clients.delete(ws); wss.clients.delete(ws);
    broadcast({ t: 'left', peer: me.id });
  });
}
setInterval(() => { for (const w of clients.keys()) w.ping(); }, 30000);

server.listen(PORT, () => console.log('단풍숲 서버 실행 중: http://localhost:' + PORT));
