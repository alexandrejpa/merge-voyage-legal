// Testes de integração: REST + WebSocket com dois usuários reais.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { WebSocket } from 'ws';
import { createApp } from '../server/server.js';

let server, base, wsBase;

before(async () => {
  ({ server } = createApp({ dbPath: ':memory:' }));
  await new Promise((r) => server.listen(0, r));
  const { port } = server.address();
  base = `http://127.0.0.1:${port}`;
  wsBase = `ws://127.0.0.1:${port}/ws`;
});
after(() => server.close());

async function api(path, { method = 'GET', body, token } = {}) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, data: await res.json() };
}

function registerBody(username) {
  return {
    username,
    authKey: `authkey-${username}`,
    saltAuth: 'sa', saltKek: 'sk',
    pubKey: `pub-${username}`, encPriv: 'ep', encPrivIv: 'iv',
  };
}

class Client {
  constructor(token) {
    this.ws = new WebSocket(wsBase);
    this.inbox = [];
    this.waiters = [];
    this.ws.on('message', (raw) => {
      const msg = JSON.parse(raw.toString());
      const i = this.waiters.findIndex((w) => w.pred(msg));
      if (i >= 0) this.waiters.splice(i, 1)[0].resolve(msg);
      else this.inbox.push(msg);
    });
    this.ready = new Promise((resolve) => {
      this.ws.on('open', () => {
        this.ws.send(JSON.stringify({ type: 'auth', token }));
        this.wait((m) => m.type === 'ready').then(resolve);
      });
    });
  }
  send(obj) { this.ws.send(JSON.stringify(obj)); }
  wait(pred, ms = 3000) {
    const i = this.inbox.findIndex(pred);
    if (i >= 0) return Promise.resolve(this.inbox.splice(i, 1)[0]);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('timeout esperando mensagem')), ms);
      this.waiters.push({ pred, resolve: (m) => { clearTimeout(timer); resolve(m); } });
    });
  }
  close() { this.ws.close(); }
}

let tokenAna, tokenBia, anaId, biaId;

test('registro de usuários', async () => {
  const r1 = await api('/api/register', { method: 'POST', body: registerBody('ana') });
  assert.equal(r1.status, 201);
  const r2 = await api('/api/register', { method: 'POST', body: registerBody('bia') });
  assert.equal(r2.status, 201);
  anaId = r1.data.userId; biaId = r2.data.userId;

  const dup = await api('/api/register', { method: 'POST', body: registerBody('ana') });
  assert.equal(dup.status, 409);

  const bad = await api('/api/register', { method: 'POST', body: registerBody('a!') });
  assert.equal(bad.status, 400);
});

test('login devolve token e material de chave', async () => {
  const wrong = await api('/api/login', { method: 'POST', body: { username: 'ana', authKey: 'errada' } });
  assert.equal(wrong.status, 401);

  const ok = await api('/api/login', { method: 'POST', body: { username: 'ana', authKey: 'authkey-ana' } });
  assert.equal(ok.status, 200);
  assert.ok(ok.data.token);
  assert.equal(ok.data.user.encPriv, 'ep');
  tokenAna = ok.data.token;

  const okB = await api('/api/login', { method: 'POST', body: { username: 'bia', authKey: 'authkey-bia' } });
  tokenBia = okB.data.token;
});

test('sal de usuário inexistente é estável (anti-enumeração)', async () => {
  const a = await api('/api/salt?username=naoexiste');
  const b = await api('/api/salt?username=naoexiste');
  assert.equal(a.data.saltAuth, b.data.saltAuth);
  assert.ok(a.data.saltAuth.length > 10);
});

test('busca de usuários exige autenticação', async () => {
  const anon = await api('/api/users?q=bi');
  assert.equal(anon.status, 401);
  const ok = await api('/api/users?q=bi', { token: tokenAna });
  assert.equal(ok.status, 200);
  assert.equal(ok.data.users[0].username, 'bia');
});

test('mensagem direta em tempo real, com ack, entrega e recibo de leitura', async () => {
  const ana = new Client(tokenAna);
  const bia = new Client(tokenBia);
  await ana.ready; await bia.ready;

  ana.send({ type: 'send', toUserId: biaId, ciphertext: 'CT1', iv: 'IV1', tempId: 't1' });
  const ack = await ana.wait((m) => m.type === 'ack' && m.tempId === 't1');
  assert.ok(ack.id > 0);
  const convoId = ack.convoId;

  const recv = await bia.wait((m) => m.type === 'message');
  assert.equal(recv.msg.ciphertext, 'CT1');
  assert.equal(recv.msg.senderId, anaId);
  assert.ok(recv.convo, 'primeira mensagem traz os metadados da conversa');
  assert.equal(recv.convo.kind, 'direct');

  // recibo de leitura chega para a remetente
  bia.send({ type: 'read', convoId, ts: recv.msg.ts });
  const read = await ana.wait((m) => m.type === 'read' && m.convoId === convoId);
  assert.equal(read.userId, biaId);

  // histórico
  ana.send({ type: 'history', convoId });
  const hist = await ana.wait((m) => m.type === 'history' && m.convoId === convoId);
  assert.equal(hist.messages.length, 1);
  assert.equal(hist.messages[0].ciphertext, 'CT1');

  // reação
  bia.send({ type: 'react', messageId: ack.id, emoji: '👍' });
  const react = await ana.wait((m) => m.type === 'react');
  assert.equal(react.emoji, '👍');
  assert.equal(react.added, true);

  // edição só pelo autor
  bia.send({ type: 'edit', messageId: ack.id, ciphertext: 'X', iv: 'X' });
  const err = await bia.wait((m) => m.type === 'error');
  assert.match(err.message, /editar/);

  ana.send({ type: 'edit', messageId: ack.id, ciphertext: 'CT1-editada', iv: 'IV2' });
  const edited = await bia.wait((m) => m.type === 'edit');
  assert.equal(edited.ciphertext, 'CT1-editada');

  // apagar
  ana.send({ type: 'delete', messageId: ack.id });
  const deleted = await bia.wait((m) => m.type === 'delete');
  assert.equal(deleted.messageId, ack.id);

  ana.close(); bia.close();
});

test('grupo: criação distribui chaves embrulhadas e mensagens circulam', async () => {
  const ana = new Client(tokenAna);
  const bia = new Client(tokenBia);
  await ana.ready; await bia.ready;

  ana.send({
    type: 'createGroup', name: 'Tripulação', memberIds: [biaId],
    wrappedKeys: {
      [anaId]: { wrapped: 'wk-ana', iv: 'i' },
      [biaId]: { wrapped: 'wk-bia', iv: 'i' },
    },
  });
  const convoAna = await ana.wait((m) => m.type === 'convo');
  const convoBia = await bia.wait((m) => m.type === 'convo');
  assert.equal(convoAna.convo.kind, 'group');
  assert.equal(convoAna.convo.wrappedKey.wrapped, 'wk-ana');
  assert.equal(convoBia.convo.wrappedKey.wrapped, 'wk-bia');
  assert.equal(convoBia.convo.members.length, 2);

  ana.send({ type: 'send', convoId: convoAna.convo.id, ciphertext: 'G1', iv: 'I', tempId: 'g1' });
  const recv = await bia.wait((m) => m.type === 'message');
  assert.equal(recv.msg.ciphertext, 'G1');

  // quem não é membro não envia
  const cadu = await api('/api/register', { method: 'POST', body: registerBody('cadu') });
  const loginCadu = await api('/api/login', { method: 'POST', body: { username: 'cadu', authKey: 'authkey-cadu' } });
  const c = new Client(loginCadu.data.token);
  await c.ready;
  c.send({ type: 'send', convoId: convoAna.convo.id, ciphertext: 'invasor', iv: 'I', tempId: 'x' });
  const err = await c.wait((m) => m.type === 'error');
  assert.match(err.message, /Conversa inválida/);

  // sair do grupo
  bia.send({ type: 'leave', convoId: convoAna.convo.id });
  const left = await bia.wait((m) => m.type === 'left');
  assert.equal(left.convoId, convoAna.convo.id);

  ana.close(); bia.close(); c.close();
});
