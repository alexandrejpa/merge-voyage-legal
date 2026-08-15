// Voyage Messenger — lógica do aplicativo (SPA sem framework, sem build).
import * as vc from './crypto.js';
import { api, Socket } from './net.js';

const $ = (id) => document.getElementById(id);

const state = {
  token: null,
  me: null,          // { id, username, pubKey }
  priv: null,        // CryptoKey (identidade ECDH)
  socket: null,
  convos: new Map(), // convoId -> convo
  msgs: new Map(),   // convoId -> [msg] ordenado por ts
  plain: new Map(),  // msgId -> { text } decifrado
  keys: new Map(),   // convoId -> Promise<CryptoKey>
  historyDone: new Set(),
  active: null,      // convo ativo (pode ser rascunho { draft: true })
  replyTo: null,
  editing: null,
  pending: new Map(), // tempId -> msg otimista
  typingTimers: new Map(),
  lastTypingSent: 0,
};

// ---------------------------------------------------------------- utilidades
const AVATAR_COLORS = ['#e05d5d', '#d9822b', '#b1a12c', '#3ba55d', '#2f9e9e', '#2080c0', '#7a5cd6', '#c65cba'];
const colorFor = (name) => AVATAR_COLORS[[...name].reduce((a, c) => a + c.charCodeAt(0), 0) % AVATAR_COLORS.length];

function setAvatar(el, name, online = false) {
  el.textContent = (name || '?').slice(0, 2).toUpperCase();
  el.style.background = colorFor(name || '?');
  el.classList.toggle('online', !!online);
}
const fmtTime = (ts) => new Date(ts).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
function fmtDay(ts) {
  const d = new Date(ts), today = new Date();
  const yest = new Date(today); yest.setDate(today.getDate() - 1);
  if (d.toDateString() === today.toDateString()) return 'Hoje';
  if (d.toDateString() === yest.toDateString()) return 'Ontem';
  return d.toLocaleDateString('pt-BR', { day: 'numeric', month: 'long', year: 'numeric' });
}
function toast(text, ms = 3000) {
  const t = $('toast');
  t.textContent = text;
  t.hidden = false;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.hidden = true; }, ms);
}
const debounce = (fn, ms) => {
  let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
};

function convoTitle(c) {
  if (c.kind === 'group') return c.name;
  const other = c.members.find((m) => m.id !== state.me.id);
  return other ? other.username : c.members[0]?.username || '?';
}
function otherMember(c) {
  return c.members.find((m) => m.id !== state.me.id);
}
function memberName(c, userId) {
  if (userId === state.me.id) return 'Você';
  return c?.members.find((m) => m.id === userId)?.username
    || [...state.convos.values()].flatMap((x) => x.members).find((m) => m.id === userId)?.username
    || '?';
}

// ---------------------------------------------------------------- criptografia por conversa
function keyFor(convo) {
  const cacheId = convo.draft ? `draft:${otherMember(convo).id}` : convo.id;
  if (!state.keys.has(cacheId)) {
    let p;
    if (convo.kind === 'direct') {
      const other = otherMember(convo);
      p = vc.directKey(state.priv, other.pubKey, state.me.id, other.id);
    } else {
      const wk = convo.wrappedKey;
      if (!wk) return Promise.reject(new Error('sem chave de grupo'));
      p = vc.unwrapGroupKey(wk.wrapped, wk.iv, state.priv, wk.wrapperPub);
    }
    state.keys.set(cacheId, p);
  }
  return state.keys.get(cacheId);
}

async function decryptInto(convo, msg) {
  if (msg.deleted) return;
  if (state.plain.has(msg.id)) return;
  try {
    const key = await keyFor(convo);
    state.plain.set(msg.id, await vc.decryptMessage(key, msg.ciphertext, msg.iv));
  } catch {
    state.plain.set(msg.id, { text: '⚠️ não foi possível decifrar' });
  }
}
const plainText = (msgId) => state.plain.get(msgId)?.text ?? '…';

// ---------------------------------------------------------------- sessão
const SESSION_KEY = 'voyage.session';

function saveSession(privJwk) {
  localStorage.setItem(SESSION_KEY, JSON.stringify({ token: state.token, me: state.me, privJwk }));
}
async function loadSession() {
  const raw = localStorage.getItem(SESSION_KEY);
  if (!raw) return false;
  try {
    const s = JSON.parse(raw);
    state.token = s.token;
    state.me = s.me;
    state.priv = await crypto.subtle.importKey('jwk', s.privJwk,
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    return true;
  } catch { return false; }
}
function clearSession() {
  localStorage.removeItem(SESSION_KEY);
}

async function doLogin(username, password) {
  const { saltAuth } = await api(`/api/salt?username=${encodeURIComponent(username)}`);
  const authKey = await vc.deriveAuthKey(password, saltAuth);
  const { token, user } = await api('/api/login', { method: 'POST', body: { username, authKey } });
  const kek = await vc.deriveKek(password, user.saltKek);
  let priv;
  try {
    priv = await vc.decryptPrivateKey(user.encPriv, user.encPrivIv, kek);
  } catch {
    throw new Error('Não foi possível decifrar sua chave privada');
  }
  state.token = token;
  state.me = { id: user.id, username: user.username, pubKey: user.pubKey };
  state.priv = priv;
  saveSession(await crypto.subtle.exportKey('jwk', priv));
}

async function doRegister(username, password) {
  const saltAuth = vc.randomB64();
  const saltKek = vc.randomB64();
  const [authKey, kek, keyPair] = await Promise.all([
    vc.deriveAuthKey(password, saltAuth),
    vc.deriveKek(password, saltKek),
    vc.generateIdentity(),
  ]);
  const pubKey = await vc.exportPublicKey(keyPair);
  const { encPriv, encPrivIv } = await vc.encryptPrivateKey(keyPair, kek);
  await api('/api/register', {
    method: 'POST',
    body: { username, authKey, saltAuth, saltKek, pubKey, encPriv, encPrivIv },
  });
  await doLogin(username, password);
}

// ---------------------------------------------------------------- WebSocket
function connect() {
  state.socket = new Socket(state.token, {
    ready(msg) {
      $('conn-status').textContent = '🔒 conectado · criptografia de ponta a ponta ativa';
      $('conn-status').className = 'conn-status online';
      state.me = msg.me;
      for (const c of msg.convos) upsertConvo(c);
      renderConvoList();
      if (state.active && !state.active.draft) {
        state.historyDone.delete(state.active.id);
        loadHistory(state.active);
      }
    },
    _offline() {
      $('conn-status').textContent = 'reconectando…';
      $('conn-status').className = 'conn-status offline';
    },
    error(msg) { toast(msg.message); },

    async message(m) {
      if (m.convo) upsertConvo(m.convo);
      const convo = state.convos.get(m.msg.convoId);
      if (!convo) return;
      pushMsg(m.msg);
      await decryptInto(convo, m.msg);
      convo.lastTs = m.msg.ts;
      if (isActive(convo.id) && document.visibilityState === 'visible') {
        markRead(convo, m.msg.ts);
        renderMessages();
      } else if (m.msg.senderId !== state.me.id) {
        convo.unread = (convo.unread || 0) + 1;
        notify(convo, m.msg);
      }
      renderConvoList();
    },

    ack(msg) {
      const pend = state.pending.get(msg.tempId);
      if (!pend) return;
      state.pending.delete(msg.tempId);
      const plain = state.plain.get(msg.tempId);
      state.plain.delete(msg.tempId);
      state.plain.set(msg.id, plain);
      pend.id = msg.id; pend.ts = msg.ts; pend.pending = false;

      // Primeiro DM: o rascunho vira conversa real
      if (pend.convoId == null) {
        pend.convoId = msg.convoId;
        const draft = state.active;
        if (draft?.draft) {
          const real = {
            id: msg.convoId, kind: 'direct', name: null, members: draft.members,
            lastTs: msg.ts, unread: 0, readMarks: [],
          };
          upsertConvo(real);
          const list = state.msgs.get('draft') || [];
          state.msgs.set(msg.convoId, list);
          state.msgs.delete('draft');
          state.historyDone.add(msg.convoId);
          state.active = state.convos.get(msg.convoId);
        }
      }
      const convo = state.convos.get(msg.convoId);
      if (convo) convo.lastTs = msg.ts;
      renderConvoList();
      if (isActive(msg.convoId)) renderMessages();
    },

    async history(msg) {
      const convo = state.convos.get(msg.convoId);
      if (!convo) return;
      const list = state.msgs.get(msg.convoId) || [];
      const known = new Set(list.map((m) => m.id));
      const fresh = msg.messages.filter((m) => !known.has(m.id));
      for (const m of fresh) await decryptInto(convo, m);
      state.msgs.set(msg.convoId, [...fresh, ...list].sort((a, b) => a.ts - b.ts));
      applyReactions(msg.reactions || []);
      if (msg.messages.length < 50) state.historyDone.add(msg.convoId);
      if (isActive(msg.convoId)) renderMessages(!msg.beforeTs);
      renderConvoList();
    },

    typing(msg) {
      if (!isActive(msg.convoId)) return;
      const name = memberName(state.active, msg.userId);
      const el = $('typing');
      el.textContent = `${name} está digitando…`;
      el.hidden = false;
      clearTimeout(state.typingTimers.get(msg.userId));
      state.typingTimers.set(msg.userId, setTimeout(() => { el.hidden = true; }, 3000));
    },

    read(msg) {
      const convo = state.convos.get(msg.convoId);
      if (!convo) return;
      const mark = convo.readMarks.find((r) => r.user_id === msg.userId);
      if (mark) mark.last_read_ts = Math.max(mark.last_read_ts, msg.ts);
      else convo.readMarks.push({ user_id: msg.userId, last_read_ts: msg.ts });
      if (isActive(msg.convoId)) renderMessages();
    },

    react(msg) {
      const list = state.msgs.get(msg.convoId) || [];
      const m = list.find((x) => x.id === msg.messageId);
      if (!m) return;
      m.reactions = m.reactions || [];
      if (msg.added) m.reactions.push({ userId: msg.userId, emoji: msg.emoji });
      else m.reactions = m.reactions.filter((r) => !(r.userId === msg.userId && r.emoji === msg.emoji));
      if (isActive(msg.convoId)) renderMessages();
    },

    async edit(msg) {
      const list = state.msgs.get(msg.convoId) || [];
      const m = list.find((x) => x.id === msg.messageId);
      if (!m) return;
      m.ciphertext = msg.ciphertext; m.iv = msg.iv; m.editedTs = msg.editedTs;
      state.plain.delete(m.id);
      await decryptInto(state.convos.get(msg.convoId), m);
      if (isActive(msg.convoId)) renderMessages();
      renderConvoList();
    },

    delete(msg) {
      const list = state.msgs.get(msg.convoId) || [];
      const m = list.find((x) => x.id === msg.messageId);
      if (!m) return;
      m.deleted = true; m.ciphertext = ''; m.iv = '';
      state.plain.delete(m.id);
      if (isActive(msg.convoId)) renderMessages();
      renderConvoList();
    },

    convo(msg) {
      upsertConvo(msg.convo);
      renderConvoList();
      if (isActive(msg.convo.id)) renderChatHeader();
    },

    left(msg) {
      state.convos.delete(msg.convoId);
      if (isActive(msg.convoId)) closeChat();
      renderConvoList();
    },

    presence(msg) {
      for (const c of state.convos.values()) {
        const m = c.members.find((x) => x.id === msg.userId);
        if (m) m.online = msg.online;
      }
      renderConvoList();
      if (state.active) renderChatHeader();
    },
  });
}

function upsertConvo(c) {
  const prev = state.convos.get(c.id);
  if (prev) {
    Object.assign(prev, c, { unread: c.unread ?? prev.unread });
  } else {
    state.convos.set(c.id, c);
  }
  // chave pode ter mudado de wrapper (novo grupo etc.)
  if (c.wrappedKey && !prev?.wrappedKey) state.keys.delete(c.id);
}

function pushMsg(m) {
  const list = state.msgs.get(m.convoId) || [];
  if (!list.some((x) => x.id === m.id)) {
    list.push(m);
    list.sort((a, b) => a.ts - b.ts);
  }
  state.msgs.set(m.convoId, list);
}

function applyReactions(rows) {
  for (const r of rows) {
    for (const list of state.msgs.values()) {
      const m = list.find((x) => x.id === r.message_id);
      if (m) {
        m.reactions = m.reactions || [];
        if (!m.reactions.some((x) => x.userId === r.user_id && x.emoji === r.emoji)) {
          m.reactions.push({ userId: r.user_id, emoji: r.emoji });
        }
      }
    }
  }
}

const isActive = (convoId) => state.active && !state.active.draft && state.active.id === convoId;

function markRead(convo, ts) {
  convo.unread = 0;
  state.socket.send({ type: 'read', convoId: convo.id, ts });
}

function notify(convo, msg) {
  if (document.visibilityState === 'visible' || Notification?.permission !== 'granted') return;
  const sender = memberName(convo, msg.senderId);
  const title = convo.kind === 'group' ? `${sender} em ${convo.name}` : sender;
  new Notification(title, { body: plainText(msg.id), icon: '/icon.svg', tag: `convo-${convo.id}` });
}

// ---------------------------------------------------------------- envio
async function sendCurrent() {
  const input = $('input');
  const text = input.value.trim();
  if (!text || !state.active) return;
  const convo = state.active;

  try {
    const key = await keyFor(convo);

    if (state.editing) {
      const { ciphertext, iv } = await vc.encryptMessage(key, { text });
      state.socket.send({ type: 'edit', messageId: state.editing.id, ciphertext, iv });
      cancelEdit();
      input.value = '';
      autosize();
      return;
    }

    const { ciphertext, iv } = await vc.encryptMessage(key, { text });
    const tempId = `t${Date.now()}${Math.random().toString(36).slice(2, 7)}`;
    const optimistic = {
      id: tempId, convoId: convo.draft ? null : convo.id, senderId: state.me.id,
      ts: Date.now(), ciphertext, iv, replyTo: state.replyTo?.id ?? null, pending: true,
    };
    state.plain.set(tempId, { text });
    state.pending.set(tempId, optimistic);
    const listKey = convo.draft ? 'draft' : convo.id;
    const list = state.msgs.get(listKey) || [];
    list.push(optimistic);
    state.msgs.set(listKey, list);

    state.socket.send({
      type: 'send',
      ...(convo.draft ? { toUserId: otherMember(convo).id } : { convoId: convo.id }),
      ciphertext, iv,
      replyTo: state.replyTo?.id ?? undefined,
      tempId,
    });
    cancelReply();
    input.value = '';
    autosize();
    renderMessages();
  } catch (err) {
    toast(`Erro ao enviar: ${err.message}`);
  }
}

// ---------------------------------------------------------------- renderização
function renderConvoList() {
  const nav = $('convo-list');
  nav.innerHTML = '';
  const convos = [...state.convos.values()]
    .sort((a, b) => (b.lastTs || 0) - (a.lastTs || 0));
  for (const c of convos) {
    const btn = document.createElement('button');
    btn.className = 'convo' + (isActive(c.id) ? ' active' : '');
    const av = document.createElement('span');
    av.className = 'avatar';
    const other = c.kind === 'direct' ? otherMember(c) : null;
    setAvatar(av, c.kind === 'group' ? c.name : other?.username, other?.online);

    const body = document.createElement('div');
    body.className = 'convo-body';
    const top = document.createElement('div');
    top.className = 'convo-top';
    const nameEl = document.createElement('span');
    nameEl.className = 'convo-name';
    nameEl.textContent = (c.kind === 'group' ? '👥 ' : '') + convoTitle(c);
    const timeEl = document.createElement('span');
    timeEl.className = 'convo-time';
    timeEl.textContent = c.lastTs ? fmtTime(c.lastTs) : '';
    top.append(nameEl, timeEl);

    const bottom = document.createElement('div');
    bottom.className = 'convo-bottom';
    const preview = document.createElement('span');
    preview.className = 'convo-preview';
    const list = state.msgs.get(c.id) || [];
    const last = list[list.length - 1];
    preview.textContent = last
      ? (last.deleted ? '🚫 mensagem apagada' : plainText(last.id))
      : (c.lastTs ? '🔒 mensagem cifrada' : 'Conversa nova');
    bottom.append(preview);
    if (c.unread > 0) {
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.textContent = c.unread > 99 ? '99+' : c.unread;
      bottom.append(badge);
    }
    body.append(top, bottom);
    btn.append(av, body);
    btn.onclick = () => openConvo(c);
    nav.append(btn);
  }
}

function renderChatHeader() {
  const c = state.active;
  if (!c) return;
  const other = c.kind === 'direct' ? otherMember(c) : null;
  setAvatar($('chat-avatar'), c.kind === 'group' ? c.name : other?.username, other?.online);
  $('chat-title').textContent = convoTitle(c);
  if (c.kind === 'group') {
    $('chat-subtitle').textContent =
      `${c.members.length} membros · ${c.members.filter((m) => m.online).length} online`;
    $('btn-add-member').hidden = false;
    $('btn-leave').hidden = false;
  } else {
    $('chat-subtitle').textContent = other?.online ? 'online' : 'offline';
    $('btn-add-member').hidden = true;
    $('btn-leave').hidden = true;
  }
}

function readByAll(convo, msg) {
  const others = convo.members.filter((m) => m.id !== state.me.id);
  if (!others.length) return false;
  return others.every((o) =>
    (convo.readMarks || []).some((r) => r.user_id === o.id && r.last_read_ts >= msg.ts));
}

function renderMessages(scrollToEnd = true) {
  const box = $('messages');
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 120;
  box.innerHTML = '';
  const c = state.active;
  if (!c) return;
  const list = state.msgs.get(c.draft ? 'draft' : c.id) || [];
  let lastDay = '';

  for (const m of list) {
    const day = new Date(m.ts).toDateString();
    if (day !== lastDay) {
      lastDay = day;
      const sep = document.createElement('div');
      sep.className = 'day-sep';
      sep.textContent = fmtDay(m.ts);
      box.append(sep);
    }

    const mine = m.senderId === state.me.id;
    const el = document.createElement('div');
    el.className = `msg ${mine ? 'mine' : 'theirs'}` + (m.deleted ? ' deleted' : '');
    el.dataset.id = m.id;

    if (!mine && c.kind === 'group' && !m.deleted) {
      const a = document.createElement('div');
      a.className = 'author';
      a.style.color = colorFor(memberName(c, m.senderId));
      a.textContent = memberName(c, m.senderId);
      el.append(a);
    }

    if (m.replyTo && !m.deleted) {
      const orig = list.find((x) => x.id === m.replyTo);
      const q = document.createElement('span');
      q.className = 'reply-quote';
      const qa = document.createElement('b');
      qa.textContent = orig ? memberName(c, orig.senderId) : 'mensagem';
      q.append(qa, document.createTextNode(orig ? (orig.deleted ? '🚫 apagada' : plainText(orig.id)) : '…'));
      q.onclick = () => {
        const target = box.querySelector(`[data-id="${m.replyTo}"]`);
        target?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      };
      el.append(q);
    }

    const body = document.createElement('span');
    body.textContent = m.deleted ? '🚫 Mensagem apagada' : plainText(m.id);
    el.append(body);

    if (!m.deleted) {
      const meta = document.createElement('span');
      meta.className = 'meta';
      if (m.editedTs) {
        const ed = document.createElement('span');
        ed.textContent = 'editada';
        meta.append(ed);
      }
      const t = document.createElement('span');
      t.textContent = fmtTime(m.ts);
      meta.append(t);
      if (mine) {
        const ticks = document.createElement('span');
        ticks.className = 'ticks';
        if (m.pending) ticks.textContent = '🕓';
        else if (readByAll(c, m)) { ticks.textContent = '✓✓'; ticks.classList.add('read'); }
        else ticks.textContent = '✓✓';
        if (!m.pending && !readByAll(c, m)) ticks.textContent = '✓';
        meta.append(ticks);
      }
      el.append(meta);

      // reações existentes
      if (m.reactions?.length) {
        const rx = document.createElement('div');
        rx.className = 'reactions';
        const grouped = new Map();
        for (const r of m.reactions) {
          if (!grouped.has(r.emoji)) grouped.set(r.emoji, []);
          grouped.get(r.emoji).push(r.userId);
        }
        for (const [emoji, users] of grouped) {
          const chip = document.createElement('button');
          chip.className = 'reaction-chip' + (users.includes(state.me.id) ? ' mine' : '');
          chip.textContent = `${emoji} ${users.length}`;
          chip.title = users.map((u) => memberName(c, u)).join(', ');
          chip.onclick = () => state.socket.send({ type: 'react', messageId: m.id, emoji });
          rx.append(chip);
        }
        el.append(rx);
      }

      // barra de ações
      if (!m.pending) {
        const actions = document.createElement('div');
        actions.className = 'actions';
        for (const emoji of ['👍', '❤️', '😂']) {
          const b = document.createElement('button');
          b.textContent = emoji;
          b.title = 'Reagir';
          b.onclick = (e) => { e.stopPropagation(); state.socket.send({ type: 'react', messageId: m.id, emoji }); };
          actions.append(b);
        }
        const reply = document.createElement('button');
        reply.textContent = '↩';
        reply.title = 'Responder';
        reply.onclick = (e) => { e.stopPropagation(); startReply(m); };
        actions.append(reply);
        if (mine) {
          const edit = document.createElement('button');
          edit.textContent = '✏️';
          edit.title = 'Editar';
          edit.onclick = (e) => { e.stopPropagation(); startEdit(m); };
          const del = document.createElement('button');
          del.textContent = '🗑';
          del.title = 'Apagar';
          del.onclick = (e) => {
            e.stopPropagation();
            if (confirm('Apagar esta mensagem para todos?')) {
              state.socket.send({ type: 'delete', messageId: m.id });
            }
          };
          actions.append(edit, del);
        }
        el.append(actions);
        el.onclick = () => {
          document.querySelectorAll('.msg.actions-open').forEach((x) => x !== el && x.classList.remove('actions-open'));
          el.classList.toggle('actions-open');
        };
      }
    }
    box.append(el);
  }

  if (scrollToEnd || nearBottom) box.scrollTop = box.scrollHeight;
}

// ---------------------------------------------------------------- abrir conversas
function openConvo(convo) {
  state.active = convo;
  cancelReply(); cancelEdit();
  $('chat-empty').hidden = true;
  $('chat-view').hidden = false;
  $('app').classList.add('chat-open');
  $('typing').hidden = true;
  renderChatHeader();
  if (!convo.draft) {
    loadHistory(convo);
    const list = state.msgs.get(convo.id) || [];
    const last = list[list.length - 1];
    markRead(convo, last?.ts ?? Date.now());
  }
  renderMessages();
  renderConvoList();
  $('input').focus();
}

function openDraftWith(user) {
  // já existe conversa direta com essa pessoa?
  for (const c of state.convos.values()) {
    if (c.kind === 'direct' && c.members.some((m) => m.id === user.id)) return openConvo(c);
  }
  state.msgs.set('draft', []);
  openConvo({
    draft: true, kind: 'direct', name: null,
    members: [ { ...state.me, online: true }, { ...user } ],
    readMarks: [],
  });
}

function loadHistory(convo, beforeTs = null) {
  if (state.historyDone.has(convo.id) && !beforeTs) return;
  state.socket.send({ type: 'history', convoId: convo.id, beforeTs, limit: 50 });
}

function closeChat() {
  state.active = null;
  $('chat-view').hidden = true;
  $('chat-empty').hidden = false;
  $('app').classList.remove('chat-open');
  renderConvoList();
}

// ---------------------------------------------------------------- responder / editar
function startReply(m) {
  cancelEdit();
  state.replyTo = m;
  $('reply-author').textContent = memberName(state.active, m.senderId);
  $('reply-preview').textContent = plainText(m.id);
  $('reply-bar').hidden = false;
  $('input').focus();
}
function cancelReply() {
  state.replyTo = null;
  $('reply-bar').hidden = true;
}
function startEdit(m) {
  cancelReply();
  state.editing = m;
  $('edit-bar').hidden = false;
  $('input').value = plainText(m.id);
  autosize();
  $('input').focus();
}
function cancelEdit() {
  state.editing = null;
  $('edit-bar').hidden = true;
}

// ---------------------------------------------------------------- grupos
const groupSel = new Map(); // userId -> user
let groupMode = 'create';   // 'create' | 'add'

function openGroupModal(mode) {
  groupMode = mode;
  groupSel.clear();
  $('group-modal-title').textContent = mode === 'create' ? 'Novo grupo' : 'Adicionar pessoas';
  $('group-name-label').hidden = mode === 'add';
  $('group-create').textContent = mode === 'create' ? 'Criar' : 'Adicionar';
  $('group-name').value = '';
  $('group-search').value = '';
  $('group-search-results').innerHTML = '';
  renderGroupChips();
  $('group-modal').showModal();
}

function renderGroupChips() {
  const box = $('group-selected');
  box.innerHTML = '';
  for (const u of groupSel.values()) {
    const chip = document.createElement('span');
    chip.className = 'member-chip';
    chip.textContent = u.username;
    const x = document.createElement('button');
    x.textContent = '✕';
    x.onclick = () => { groupSel.delete(u.id); renderGroupChips(); };
    chip.append(x);
    box.append(chip);
  }
}

const searchGroupUsers = debounce(async () => {
  const q = $('group-search').value.trim();
  const box = $('group-search-results');
  box.innerHTML = '';
  if (q.length < 2) return;
  try {
    const { users } = await api(`/api/users?q=${encodeURIComponent(q)}`, { token: state.token });
    const existing = groupMode === 'add' ? new Set(state.active.members.map((m) => m.id)) : new Set();
    for (const u of users.filter((x) => !groupSel.has(x.id) && !existing.has(x.id))) {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'result';
      const av = document.createElement('span');
      av.className = 'avatar';
      setAvatar(av, u.username, u.online);
      b.append(av, document.createTextNode(u.username));
      b.onclick = () => {
        groupSel.set(u.id, u);
        renderGroupChips();
        b.remove();
      };
      box.append(b);
    }
  } catch { /* silencioso */ }
}, 300);

async function submitGroup(e) {
  e.preventDefault();
  try {
    if (groupMode === 'create') {
      const name = $('group-name').value.trim();
      if (!name) return toast('Dê um nome ao grupo');
      if (!groupSel.size) return toast('Adicione pelo menos uma pessoa');
      const groupKey = await vc.generateGroupKey();
      const wrappedKeys = {};
      wrappedKeys[state.me.id] = await vc.wrapGroupKey(groupKey, state.priv, state.me.pubKey);
      for (const u of groupSel.values()) {
        wrappedKeys[u.id] = await vc.wrapGroupKey(groupKey, state.priv, u.pubKey);
      }
      state.socket.send({
        type: 'createGroup', name,
        memberIds: [...groupSel.keys()], wrappedKeys,
      });
    } else {
      if (!groupSel.size) return toast('Escolha alguém para adicionar');
      const groupKey = await keyFor(state.active);
      const members = {};
      for (const u of groupSel.values()) {
        members[u.id] = await vc.wrapGroupKey(groupKey, state.priv, u.pubKey);
      }
      state.socket.send({ type: 'addMembers', convoId: state.active.id, members });
    }
    $('group-modal').close();
  } catch (err) {
    toast(`Erro: ${err.message}`);
  }
}

// ---------------------------------------------------------------- busca da sidebar
const searchUsers = debounce(async () => {
  const q = $('search-input').value.trim();
  const box = $('search-results');
  box.innerHTML = '';
  if (q.length < 2) { box.hidden = true; renderConvoList(); return; }
  box.hidden = false;

  // filtra conversas existentes
  renderConvoList();
  for (const btn of $('convo-list').children) {
    const name = btn.querySelector('.convo-name')?.textContent || '';
    btn.style.display = name.toLowerCase().includes(q.toLowerCase()) ? '' : 'none';
  }

  try {
    const { users } = await api(`/api/users?q=${encodeURIComponent(q)}`, { token: state.token });
    if (!users.length) {
      const hint = document.createElement('div');
      hint.className = 'hint';
      hint.textContent = 'Nenhum usuário novo encontrado';
      box.append(hint);
      return;
    }
    const hint = document.createElement('div');
    hint.className = 'hint';
    hint.textContent = 'Pessoas';
    box.append(hint);
    for (const u of users) {
      const b = document.createElement('button');
      b.className = 'result';
      const av = document.createElement('span');
      av.className = 'avatar';
      setAvatar(av, u.username, u.online);
      b.append(av, document.createTextNode(u.username));
      b.onclick = () => {
        $('search-input').value = '';
        box.hidden = true;
        renderConvoList();
        openDraftWith(u);
      };
      box.append(b);
    }
  } catch { /* silencioso */ }
}, 300);

// ---------------------------------------------------------------- boot / eventos de UI
function autosize() {
  const input = $('input');
  input.style.height = 'auto';
  input.style.height = `${Math.min(input.scrollHeight, 140)}px`;
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem('voyage.theme', theme);
}

function enterApp() {
  $('auth-screen').hidden = true;
  $('app').hidden = false;
  $('me-name').textContent = state.me.username;
  setAvatar($('me-avatar'), state.me.username, true);
  connect();
  if ('Notification' in window && Notification.permission === 'default') {
    setTimeout(() => Notification.requestPermission(), 2000);
  }
}

function bindEvents() {
  // login/registro
  let mode = 'login';
  const setMode = (m) => {
    mode = m;
    $('tab-login').classList.toggle('active', m === 'login');
    $('tab-register').classList.toggle('active', m === 'register');
    $('auth-submit').textContent = m === 'login' ? 'Entrar' : 'Criar conta';
    $('auth-note-register').hidden = m === 'login';
    $('auth-password').autocomplete = m === 'login' ? 'current-password' : 'new-password';
    $('auth-error').hidden = true;
  };
  $('tab-login').onclick = () => setMode('login');
  $('tab-register').onclick = () => setMode('register');
  $('auth-form').onsubmit = async (e) => {
    e.preventDefault();
    const btn = $('auth-submit');
    btn.disabled = true;
    btn.textContent = 'Gerando chaves…';
    $('auth-error').hidden = true;
    try {
      const username = $('auth-username').value.trim();
      const password = $('auth-password').value;
      if (mode === 'register') await doRegister(username, password);
      else await doLogin(username, password);
      enterApp();
    } catch (err) {
      $('auth-error').textContent = err.message;
      $('auth-error').hidden = false;
    } finally {
      btn.disabled = false;
      setMode(mode);
    }
  };

  // composer
  $('btn-send').onclick = sendCurrent;
  $('input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendCurrent(); }
    if (e.key === 'Escape') { cancelReply(); cancelEdit(); $('input').value = ''; autosize(); }
  });
  $('input').addEventListener('input', () => {
    autosize();
    if (state.active && !state.active.draft && Date.now() - state.lastTypingSent > 2500) {
      state.lastTypingSent = Date.now();
      state.socket.send({ type: 'typing', convoId: state.active.id });
    }
  });

  $('reply-cancel').onclick = cancelReply;
  $('edit-cancel').onclick = () => { cancelEdit(); $('input').value = ''; autosize(); };
  $('btn-back').onclick = closeChat;

  // rolagem para cima carrega histórico
  $('messages').addEventListener('scroll', () => {
    const box = $('messages');
    const c = state.active;
    if (!c || c.draft || box.scrollTop > 40) return;
    const list = state.msgs.get(c.id) || [];
    if (list.length) loadHistory(c, list[0].ts);
  });

  // sidebar
  $('search-input').addEventListener('input', searchUsers);
  $('btn-theme').onclick = () => {
    const cur = document.documentElement.dataset.theme || 'light';
    applyTheme(cur === 'light' ? 'dark' : 'light');
  };
  $('btn-logout').onclick = async () => {
    try { await api('/api/logout', { method: 'POST', token: state.token }); } catch { /* ok */ }
    clearSession();
    location.reload();
  };

  // grupos
  $('btn-new-group').onclick = () => openGroupModal('create');
  $('btn-add-member').onclick = () => openGroupModal('add');
  $('group-cancel').onclick = () => $('group-modal').close();
  $('group-form').onsubmit = submitGroup;
  $('group-search').addEventListener('input', searchGroupUsers);
  $('btn-leave').onclick = () => {
    if (confirm(`Sair do grupo "${state.active?.name}"?`)) {
      state.socket.send({ type: 'leave', convoId: state.active.id });
    }
  };

  // marcar como lida ao voltar para a aba
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && state.active && !state.active.draft) {
      const list = state.msgs.get(state.active.id) || [];
      const last = list[list.length - 1];
      if (last) markRead(state.active, last.ts);
      renderConvoList();
    }
  });
}

async function boot() {
  const savedTheme = localStorage.getItem('voyage.theme');
  applyTheme(savedTheme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
  bindEvents();
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
  if (await loadSession()) enterApp();
}

boot();
