// Camada de dados — SQLite embutido do Node (node:sqlite).
// O servidor só armazena ciphertext: o conteúdo das mensagens é cifrado no cliente.
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export function openDb(path) {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id           INTEGER PRIMARY KEY,
      username     TEXT NOT NULL UNIQUE COLLATE NOCASE,
      auth_hash    TEXT NOT NULL,          -- scrypt(authKey) — authKey já é derivada da senha no cliente
      salt_auth    TEXT NOT NULL,          -- sal usado no cliente para derivar a authKey
      salt_kek     TEXT NOT NULL,          -- sal usado no cliente para derivar a chave que cifra a chave privada
      pub_key      TEXT NOT NULL,          -- chave pública ECDH (base64)
      enc_priv     TEXT NOT NULL,          -- chave privada cifrada no cliente (o servidor não consegue ler)
      enc_priv_iv  TEXT NOT NULL,
      created_at   INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS tokens (
      token_hash  TEXT PRIMARY KEY,
      user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at  INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS convos (
      id          INTEGER PRIMARY KEY,
      kind        TEXT NOT NULL CHECK (kind IN ('direct','group')),
      name        TEXT,
      created_by  INTEGER REFERENCES users(id),
      created_at  INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS members (
      convo_id  INTEGER NOT NULL REFERENCES convos(id) ON DELETE CASCADE,
      user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      joined_at INTEGER NOT NULL,
      PRIMARY KEY (convo_id, user_id)
    );
    CREATE INDEX IF NOT EXISTS idx_members_user ON members(user_id);

    CREATE TABLE IF NOT EXISTS direct_pairs (
      user_lo   INTEGER NOT NULL,
      user_hi   INTEGER NOT NULL,
      convo_id  INTEGER NOT NULL REFERENCES convos(id) ON DELETE CASCADE,
      PRIMARY KEY (user_lo, user_hi)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id          INTEGER PRIMARY KEY,
      convo_id    INTEGER NOT NULL REFERENCES convos(id) ON DELETE CASCADE,
      sender_id   INTEGER NOT NULL REFERENCES users(id),
      ts          INTEGER NOT NULL,
      ciphertext  TEXT NOT NULL,
      iv          TEXT NOT NULL,
      reply_to    INTEGER REFERENCES messages(id),
      edited_ts   INTEGER,
      deleted     INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_messages_convo_ts ON messages(convo_id, ts);

    CREATE TABLE IF NOT EXISTS reactions (
      message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      emoji      TEXT NOT NULL,
      PRIMARY KEY (message_id, user_id, emoji)
    );

    -- Chave simétrica de grupo, embrulhada (ECDH) para cada membro por quem o adicionou.
    CREATE TABLE IF NOT EXISTS convo_keys (
      convo_id     INTEGER NOT NULL REFERENCES convos(id) ON DELETE CASCADE,
      user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      wrapped_key  TEXT NOT NULL,
      iv           TEXT NOT NULL,
      wrapper_id   INTEGER NOT NULL REFERENCES users(id),
      PRIMARY KEY (convo_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS read_marks (
      convo_id     INTEGER NOT NULL REFERENCES convos(id) ON DELETE CASCADE,
      user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      last_read_ts INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (convo_id, user_id)
    );
  `);
  return new Store(db);
}

export class Store {
  constructor(db) { this.db = db; }

  // ---- usuários / sessões ----
  createUser(u) {
    const r = this.db.prepare(
      `INSERT INTO users (username, auth_hash, salt_auth, salt_kek, pub_key, enc_priv, enc_priv_iv, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(u.username, u.authHash, u.saltAuth, u.saltKek, u.pubKey, u.encPriv, u.encPrivIv, Date.now());
    return Number(r.lastInsertRowid);
  }
  userByName(username) {
    return this.db.prepare(`SELECT * FROM users WHERE username = ?`).get(username);
  }
  userById(id) {
    return this.db.prepare(`SELECT * FROM users WHERE id = ?`).get(id);
  }
  searchUsers(q, excludeId, limit = 20) {
    return this.db.prepare(
      `SELECT id, username, pub_key FROM users
       WHERE username LIKE ? AND id != ? ORDER BY username LIMIT ?`
    ).all(`%${q.replaceAll('%', '')}%`, excludeId, limit);
  }
  saveToken(tokenHash, userId) {
    this.db.prepare(`INSERT INTO tokens (token_hash, user_id, created_at) VALUES (?, ?, ?)`)
      .run(tokenHash, userId, Date.now());
  }
  userByToken(tokenHash) {
    return this.db.prepare(
      `SELECT u.* FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?`
    ).get(tokenHash);
  }
  deleteToken(tokenHash) {
    this.db.prepare(`DELETE FROM tokens WHERE token_hash = ?`).run(tokenHash);
  }

  // ---- conversas ----
  directConvo(a, b) {
    const [lo, hi] = a < b ? [a, b] : [b, a];
    return this.db.prepare(`SELECT convo_id FROM direct_pairs WHERE user_lo = ? AND user_hi = ?`)
      .get(lo, hi)?.convo_id;
  }
  createDirectConvo(a, b) {
    const existing = this.directConvo(a, b);
    if (existing) return existing;
    const [lo, hi] = a < b ? [a, b] : [b, a];
    const now = Date.now();
    const r = this.db.prepare(`INSERT INTO convos (kind, created_by, created_at) VALUES ('direct', ?, ?)`)
      .run(a, now);
    const id = Number(r.lastInsertRowid);
    const addMember = this.db.prepare(`INSERT INTO members (convo_id, user_id, joined_at) VALUES (?, ?, ?)`);
    addMember.run(id, lo, now); addMember.run(id, hi, now);
    this.db.prepare(`INSERT INTO direct_pairs (user_lo, user_hi, convo_id) VALUES (?, ?, ?)`).run(lo, hi, id);
    return id;
  }
  createGroup(name, creatorId, memberIds) {
    const now = Date.now();
    const r = this.db.prepare(`INSERT INTO convos (kind, name, created_by, created_at) VALUES ('group', ?, ?, ?)`)
      .run(name, creatorId, now);
    const id = Number(r.lastInsertRowid);
    const addMember = this.db.prepare(`INSERT INTO members (convo_id, user_id, joined_at) VALUES (?, ?, ?)`);
    for (const uid of new Set([creatorId, ...memberIds])) addMember.run(id, uid, now);
    return id;
  }
  convoById(id) {
    return this.db.prepare(`SELECT * FROM convos WHERE id = ?`).get(id);
  }
  convoMembers(convoId) {
    return this.db.prepare(
      `SELECT u.id, u.username, u.pub_key FROM members m JOIN users u ON u.id = m.user_id WHERE m.convo_id = ?`
    ).all(convoId);
  }
  isMember(convoId, userId) {
    return !!this.db.prepare(`SELECT 1 FROM members WHERE convo_id = ? AND user_id = ?`).get(convoId, userId);
  }
  addMember(convoId, userId) {
    this.db.prepare(`INSERT OR IGNORE INTO members (convo_id, user_id, joined_at) VALUES (?, ?, ?)`)
      .run(convoId, userId, Date.now());
  }
  removeMember(convoId, userId) {
    this.db.prepare(`DELETE FROM members WHERE convo_id = ? AND user_id = ?`).run(convoId, userId);
    this.db.prepare(`DELETE FROM convo_keys WHERE convo_id = ? AND user_id = ?`).run(convoId, userId);
  }
  convosForUser(userId) {
    return this.db.prepare(
      `SELECT c.*,
              (SELECT MAX(ts) FROM messages WHERE convo_id = c.id) AS last_ts,
              (SELECT COUNT(*) FROM messages msg
                 WHERE msg.convo_id = c.id AND msg.sender_id != ? AND msg.deleted = 0
                   AND msg.ts > COALESCE((SELECT last_read_ts FROM read_marks
                                          WHERE convo_id = c.id AND user_id = ?), 0)) AS unread
       FROM convos c JOIN members m ON m.convo_id = c.id
       WHERE m.user_id = ?
       ORDER BY COALESCE(last_ts, c.created_at) DESC`
    ).all(userId, userId, userId);
  }

  // ---- chaves de grupo ----
  saveWrappedKey(convoId, userId, wrappedKey, iv, wrapperId) {
    this.db.prepare(
      `INSERT OR REPLACE INTO convo_keys (convo_id, user_id, wrapped_key, iv, wrapper_id)
       VALUES (?, ?, ?, ?, ?)`
    ).run(convoId, userId, wrappedKey, iv, wrapperId);
  }
  wrappedKeyFor(convoId, userId) {
    return this.db.prepare(
      `SELECT ck.wrapped_key, ck.iv, ck.wrapper_id, u.pub_key AS wrapper_pub
       FROM convo_keys ck JOIN users u ON u.id = ck.wrapper_id
       WHERE ck.convo_id = ? AND ck.user_id = ?`
    ).get(convoId, userId);
  }

  // ---- mensagens ----
  saveMessage(m) {
    const ts = Date.now();
    const r = this.db.prepare(
      `INSERT INTO messages (convo_id, sender_id, ts, ciphertext, iv, reply_to)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(m.convoId, m.senderId, ts, m.ciphertext, m.iv, m.replyTo ?? null);
    return { id: Number(r.lastInsertRowid), ts };
  }
  messageById(id) {
    return this.db.prepare(`SELECT * FROM messages WHERE id = ?`).get(id);
  }
  editMessage(id, ciphertext, iv) {
    this.db.prepare(`UPDATE messages SET ciphertext = ?, iv = ?, edited_ts = ? WHERE id = ?`)
      .run(ciphertext, iv, Date.now(), id);
  }
  deleteMessage(id) {
    this.db.prepare(`UPDATE messages SET ciphertext = '', iv = '', deleted = 1 WHERE id = ?`).run(id);
  }
  history(convoId, beforeTs, limit = 50) {
    const rows = this.db.prepare(
      `SELECT * FROM messages WHERE convo_id = ? AND ts < ? ORDER BY ts DESC LIMIT ?`
    ).all(convoId, beforeTs ?? Number.MAX_SAFE_INTEGER, limit);
    return rows.reverse();
  }
  reactionsFor(messageIds) {
    if (!messageIds.length) return [];
    const placeholders = messageIds.map(() => '?').join(',');
    return this.db.prepare(
      `SELECT message_id, user_id, emoji FROM reactions WHERE message_id IN (${placeholders})`
    ).all(...messageIds);
  }
  toggleReaction(messageId, userId, emoji) {
    const existing = this.db.prepare(
      `SELECT 1 FROM reactions WHERE message_id = ? AND user_id = ? AND emoji = ?`
    ).get(messageId, userId, emoji);
    if (existing) {
      this.db.prepare(`DELETE FROM reactions WHERE message_id = ? AND user_id = ? AND emoji = ?`)
        .run(messageId, userId, emoji);
      return false;
    }
    this.db.prepare(`INSERT INTO reactions (message_id, user_id, emoji) VALUES (?, ?, ?)`)
      .run(messageId, userId, emoji);
    return true;
  }

  // ---- recibos de leitura ----
  markRead(convoId, userId, ts) {
    this.db.prepare(
      `INSERT INTO read_marks (convo_id, user_id, last_read_ts) VALUES (?, ?, ?)
       ON CONFLICT (convo_id, user_id) DO UPDATE SET last_read_ts = MAX(last_read_ts, excluded.last_read_ts)`
    ).run(convoId, userId, ts);
  }
  readMarks(convoId) {
    return this.db.prepare(`SELECT user_id, last_read_ts FROM read_marks WHERE convo_id = ?`).all(convoId);
  }
}
