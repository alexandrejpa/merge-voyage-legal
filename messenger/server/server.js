// Voyage Messenger — servidor: estáticos + API REST + WebSocket em tempo real.
// Todo conteúdo de mensagem chega e sai como ciphertext; a criptografia é feita no cliente.
import http from 'node:http';
import { createReadStream, existsSync, statSync } from 'node:fs';
import { join, extname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { WebSocketServer } from 'ws';
import { openDb } from './db.js';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const PUBLIC_DIR = join(__dirname, '..', 'public');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.webmanifest': 'application/manifest+json',
  '.json': 'application/json',
};

const USERNAME_RE = /^[a-z0-9_.]{3,24}$/i;
const MAX_BODY = 256 * 1024;
const MAX_CIPHERTEXT = 64 * 1024;

// -------- utilidades --------
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function scryptHash(authKey) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(authKey, salt, 32);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}
function scryptVerify(authKey, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const hash = crypto.scryptSync(authKey, Buffer.from(saltHex, 'hex'), 32);
  return crypto.timingSafeEqual(hash, Buffer.from(hashHex, 'hex'));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch { reject(new Error('invalid JSON')); }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}

export function createApp({ dbPath = ':memory:' } = {}) {
  const store = openDb(dbPath);
  // Segredo por instância para gerar sais falsos determinísticos (anti-enumeração de usuários).
  const enumSecret = crypto.randomBytes(32);

  /** userId -> Set<WebSocket> (múltiplos dispositivos por usuário) */
  const sockets = new Map();

  const isOnline = (userId) => sockets.has(userId);

  function sendTo(userId, payload) {
    const set = sockets.get(userId);
    if (!set) return;
    const data = JSON.stringify(payload);
    for (const ws of set) if (ws.readyState === ws.OPEN) ws.send(data);
  }
  function broadcastToConvo(convoId, payload, exceptUserId = null) {
    for (const m of store.convoMembers(convoId)) {
      if (m.id !== exceptUserId) sendTo(m.id, payload);
    }
  }

  function publicUser(u) {
    return { id: u.id, username: u.username, pubKey: u.pub_key };
  }

  function convoPayload(convo, forUserId) {
    const members = store.convoMembers(convo.id).map((m) => ({
      id: m.id, username: m.username, pubKey: m.pub_key, online: isOnline(m.id),
    }));
    const payload = {
      id: convo.id, kind: convo.kind, name: convo.name, members,
      lastTs: convo.last_ts ?? null, unread: convo.unread ?? 0,
      readMarks: store.readMarks(convo.id),
    };
    if (convo.kind === 'group') {
      const wk = store.wrappedKeyFor(convo.id, forUserId);
      if (wk) payload.wrappedKey = { wrapped: wk.wrapped_key, iv: wk.iv, wrapperPub: wk.wrapper_pub };
    }
    return payload;
  }

  // -------- REST --------
  async function handleApi(req, res, url) {
    const route = `${req.method} ${url.pathname}`;

    if (route === 'POST /api/register') {
      const b = await readBody(req);
      const { username, authKey, saltAuth, saltKek, pubKey, encPriv, encPrivIv } = b;
      if (!USERNAME_RE.test(username || '')) return sendJson(res, 400, { error: 'Nome de usuário inválido (3–24 caracteres: letras, números, _ ou .)' });
      for (const [k, v] of Object.entries({ authKey, saltAuth, saltKek, pubKey, encPriv, encPrivIv })) {
        if (typeof v !== 'string' || !v || v.length > 8192) return sendJson(res, 400, { error: `Campo inválido: ${k}` });
      }
      if (store.userByName(username)) return sendJson(res, 409, { error: 'Esse nome de usuário já existe' });
      const id = store.createUser({
        username, authHash: scryptHash(authKey), saltAuth, saltKek, pubKey, encPriv, encPrivIv,
      });
      return sendJson(res, 201, { ok: true, userId: id });
    }

    if (route === 'GET /api/salt') {
      const username = url.searchParams.get('username') || '';
      const u = store.userByName(username);
      // Usuário inexistente recebe um sal falso, porém estável — evita enumeração de contas.
      const saltAuth = u ? u.salt_auth
        : crypto.createHmac('sha256', enumSecret).update(username.toLowerCase()).digest('base64').slice(0, 22);
      return sendJson(res, 200, { saltAuth });
    }

    if (route === 'POST /api/login') {
      const { username, authKey } = await readBody(req);
      const u = username && store.userByName(username);
      if (!u || typeof authKey !== 'string' || !scryptVerify(authKey, u.auth_hash)) {
        return sendJson(res, 401, { error: 'Usuário ou senha incorretos' });
      }
      const token = crypto.randomBytes(32).toString('base64url');
      store.saveToken(sha256(token), u.id);
      return sendJson(res, 200, {
        token,
        user: {
          id: u.id, username: u.username, pubKey: u.pub_key,
          saltKek: u.salt_kek, encPriv: u.enc_priv, encPrivIv: u.enc_priv_iv,
        },
      });
    }

    // Rotas autenticadas
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    const me = token && store.userByToken(sha256(token));
    if (!me) return sendJson(res, 401, { error: 'Não autenticado' });

    if (route === 'POST /api/logout') {
      store.deleteToken(sha256(token));
      return sendJson(res, 200, { ok: true });
    }
    if (route === 'GET /api/users') {
      const q = (url.searchParams.get('q') || '').trim();
      if (q.length < 2) return sendJson(res, 200, { users: [] });
      const users = store.searchUsers(q, me.id).map((u) => ({
        id: u.id, username: u.username, pubKey: u.pub_key, online: isOnline(u.id),
      }));
      return sendJson(res, 200, { users });
    }

    return sendJson(res, 404, { error: 'Rota não encontrada' });
  }

  // -------- estáticos --------
  function handleStatic(req, res, url) {
    let path = normalize(url.pathname).replace(/^(\.\.[/\\])+/, '');
    if (path === '/' || path === '') path = '/index.html';
    const file = join(PUBLIC_DIR, path);
    if (!file.startsWith(PUBLIC_DIR) || !existsSync(file) || !statSync(file).isFile()) {
      // SPA fallback
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      createReadStream(join(PUBLIC_DIR, 'index.html')).pipe(res);
      return;
    }
    res.writeHead(200, {
      'Content-Type': MIME[extname(file)] || 'application/octet-stream',
      'Cache-Control': path.startsWith('/js/') || path.startsWith('/css/') ? 'no-cache' : 'no-cache',
    });
    createReadStream(file).pipe(res);
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    try {
      if (url.pathname.startsWith('/api/')) await handleApi(req, res, url);
      else handleStatic(req, res, url);
    } catch (err) {
      sendJson(res, 400, { error: err.message || 'Erro' });
    }
  });

  // -------- WebSocket --------
  const wss = new WebSocketServer({ server, path: '/ws' });

  wss.on('connection', (ws) => {
    let user = null;

    const fail = (message) => ws.send(JSON.stringify({ type: 'error', message }));

    ws.on('message', (raw) => {
      let msg;
      try { msg = JSON.parse(raw.toString()); } catch { return fail('JSON inválido'); }

      try {
        if (msg.type === 'auth') {
          const u = typeof msg.token === 'string' && store.userByToken(sha256(msg.token));
          if (!u) { fail('Token inválido'); ws.close(); return; }
          user = u;
          if (!sockets.has(u.id)) sockets.set(u.id, new Set());
          sockets.get(u.id).add(ws);
          const convos = store.convosForUser(u.id).map((c) => convoPayload(c, u.id));
          ws.send(JSON.stringify({ type: 'ready', me: publicUser(u), convos }));
          // avisa contatos que este usuário ficou online
          const notified = new Set();
          for (const c of convos) for (const m of c.members) {
            if (m.id !== u.id && !notified.has(m.id)) {
              notified.add(m.id);
              sendTo(m.id, { type: 'presence', userId: u.id, online: true });
            }
          }
          return;
        }

        if (!user) return fail('Autentique-se primeiro');

        switch (msg.type) {
          case 'send': {
            const { ciphertext, iv, replyTo, tempId } = msg;
            if (typeof ciphertext !== 'string' || !ciphertext || ciphertext.length > MAX_CIPHERTEXT
              || typeof iv !== 'string' || !iv) return fail('Mensagem inválida');

            let convoId = msg.convoId;
            let isNew = false;
            if (!convoId && msg.toUserId) {
              if (!store.userById(msg.toUserId)) return fail('Usuário não existe');
              const existing = store.directConvo(user.id, msg.toUserId);
              convoId = store.createDirectConvo(user.id, msg.toUserId);
              isNew = !existing;
            }
            if (!convoId || !store.isMember(convoId, user.id)) return fail('Conversa inválida');
            if (replyTo) {
              const orig = store.messageById(replyTo);
              if (!orig || orig.convo_id !== convoId) return fail('Resposta inválida');
            }

            const { id, ts } = store.saveMessage({ convoId, senderId: user.id, ciphertext, iv, replyTo });
            store.markRead(convoId, user.id, ts);
            ws.send(JSON.stringify({ type: 'ack', tempId, id, ts, convoId }));

            const convo = store.convoById(convoId);
            const out = {
              type: 'message',
              msg: { id, convoId, senderId: user.id, ts, ciphertext, iv, replyTo: replyTo ?? null },
            };
            for (const m of store.convoMembers(convoId)) {
              if (m.id === user.id) {
                // outras abas/dispositivos do próprio remetente
                for (const s of sockets.get(user.id) || []) {
                  if (s !== ws && s.readyState === s.OPEN) s.send(JSON.stringify(out));
                }
                continue;
              }
              const payload = isNew || msg.toUserId
                ? { ...out, convo: convoPayload({ ...convo, unread: 0 }, m.id) }
                : out;
              sendTo(m.id, payload);
            }
            return;
          }

          case 'history': {
            const { convoId, beforeTs, limit } = msg;
            if (!store.isMember(convoId, user.id)) return fail('Conversa inválida');
            const messages = store.history(convoId, beforeTs, Math.min(limit || 50, 100));
            const reactions = store.reactionsFor(messages.map((m) => m.id));
            ws.send(JSON.stringify({
              type: 'history', convoId, beforeTs: beforeTs ?? null,
              messages: messages.map((m) => ({
                id: m.id, convoId: m.convo_id, senderId: m.sender_id, ts: m.ts,
                ciphertext: m.ciphertext, iv: m.iv, replyTo: m.reply_to,
                editedTs: m.edited_ts, deleted: !!m.deleted,
              })),
              reactions,
            }));
            return;
          }

          case 'typing': {
            if (!store.isMember(msg.convoId, user.id)) return;
            broadcastToConvo(msg.convoId, { type: 'typing', convoId: msg.convoId, userId: user.id }, user.id);
            return;
          }

          case 'read': {
            const { convoId, ts } = msg;
            if (!store.isMember(convoId, user.id) || typeof ts !== 'number') return;
            store.markRead(convoId, user.id, ts);
            broadcastToConvo(convoId, { type: 'read', convoId, userId: user.id, ts }, user.id);
            return;
          }

          case 'react': {
            const m = store.messageById(msg.messageId);
            if (!m || !store.isMember(m.convo_id, user.id)) return fail('Mensagem inválida');
            const emoji = String(msg.emoji || '').slice(0, 8);
            if (!emoji) return;
            const added = store.toggleReaction(m.id, user.id, emoji);
            broadcastToConvo(m.convo_id, {
              type: 'react', convoId: m.convo_id, messageId: m.id, userId: user.id, emoji, added,
            });
            return;
          }

          case 'edit': {
            const m = store.messageById(msg.messageId);
            if (!m || m.sender_id !== user.id || m.deleted) return fail('Não é possível editar');
            if (typeof msg.ciphertext !== 'string' || msg.ciphertext.length > MAX_CIPHERTEXT
              || typeof msg.iv !== 'string') return fail('Mensagem inválida');
            store.editMessage(m.id, msg.ciphertext, msg.iv);
            broadcastToConvo(m.convo_id, {
              type: 'edit', convoId: m.convo_id, messageId: m.id,
              ciphertext: msg.ciphertext, iv: msg.iv, editedTs: Date.now(),
            });
            return;
          }

          case 'delete': {
            const m = store.messageById(msg.messageId);
            if (!m || m.sender_id !== user.id) return fail('Não é possível apagar');
            store.deleteMessage(m.id);
            broadcastToConvo(m.convo_id, { type: 'delete', convoId: m.convo_id, messageId: m.id });
            return;
          }

          case 'createGroup': {
            const { name, memberIds, wrappedKeys } = msg;
            const cleanName = String(name || '').trim().slice(0, 64);
            if (!cleanName || !Array.isArray(memberIds) || !memberIds.length) return fail('Grupo inválido');
            for (const uid of memberIds) if (!store.userById(uid)) return fail('Membro não existe');
            const convoId = store.createGroup(cleanName, user.id, memberIds);
            for (const [uidStr, wk] of Object.entries(wrappedKeys || {})) {
              const uid = Number(uidStr);
              if (store.isMember(convoId, uid) && wk?.wrapped && wk?.iv) {
                store.saveWrappedKey(convoId, uid, wk.wrapped, wk.iv, user.id);
              }
            }
            const convo = store.convoById(convoId);
            for (const m of store.convoMembers(convoId)) {
              sendTo(m.id, { type: 'convo', convo: convoPayload(convo, m.id) });
            }
            return;
          }

          case 'addMembers': {
            const { convoId, members } = msg;
            const convo = store.convoById(convoId);
            if (!convo || convo.kind !== 'group' || !store.isMember(convoId, user.id)) return fail('Grupo inválido');
            for (const [uidStr, wk] of Object.entries(members || {})) {
              const uid = Number(uidStr);
              if (!store.userById(uid) || !wk?.wrapped || !wk?.iv) continue;
              store.addMember(convoId, uid);
              store.saveWrappedKey(convoId, uid, wk.wrapped, wk.iv, user.id);
            }
            for (const m of store.convoMembers(convoId)) {
              sendTo(m.id, { type: 'convo', convo: convoPayload({ ...convo }, m.id) });
            }
            return;
          }

          case 'leave': {
            const convo = store.convoById(msg.convoId);
            if (!convo || convo.kind !== 'group' || !store.isMember(convo.id, user.id)) return;
            store.removeMember(convo.id, user.id);
            sendTo(user.id, { type: 'left', convoId: convo.id });
            for (const m of store.convoMembers(convo.id)) {
              sendTo(m.id, { type: 'convo', convo: convoPayload(convo, m.id) });
            }
            return;
          }

          default:
            return fail(`Tipo desconhecido: ${msg.type}`);
        }
      } catch (err) {
        fail(err.message || 'Erro interno');
      }
    });

    ws.on('close', () => {
      if (!user) return;
      const set = sockets.get(user.id);
      if (set) {
        set.delete(ws);
        if (!set.size) {
          sockets.delete(user.id);
          const notified = new Set();
          for (const c of store.convosForUser(user.id)) {
            for (const m of store.convoMembers(c.id)) {
              if (m.id !== user.id && !notified.has(m.id)) {
                notified.add(m.id);
                sendTo(m.id, { type: 'presence', userId: user.id, online: false });
              }
            }
          }
        }
      }
    });
  });

  return { server, store };
}

// Execução direta
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 3000);
  const dbPath = process.env.DB_PATH || join(__dirname, '..', 'data', 'voyage.db');
  const { server } = createApp({ dbPath });
  server.listen(port, () => {
    console.log(`Voyage Messenger rodando em http://localhost:${port}`);
  });
}
