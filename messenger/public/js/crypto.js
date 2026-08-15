// Criptografia de ponta a ponta — roda inteiramente no cliente (Web Crypto API).
//
// Modelo:
// - Cada usuário tem um par de chaves ECDH P-256. A pública fica no servidor;
//   a privada só existe cifrada (AES-GCM com chave derivada da senha via PBKDF2).
// - A senha nunca é enviada ao servidor: o login usa uma "authKey" derivada dela
//   (PBKDF2 com sal próprio), então o servidor não consegue decifrar nada.
// - Conversa direta: chave AES-GCM derivada por ECDH entre os dois usuários + HKDF.
// - Grupo: chave AES-GCM aleatória, "embrulhada" para cada membro via ECDH.

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const b64 = {
  encode: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))),
  decode: (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0)),
};

export function randomB64(bytes = 16) {
  const a = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(a);
  return b64.encode(a);
}

const PBKDF2_ITERS = 310000;

async function pbkdf2Bits(password, salt, info, bits = 256) {
  const base = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(`voyage:${info}:${salt}`), iterations: PBKDF2_ITERS },
    base, bits,
  );
}

// authKey enviada ao servidor no lugar da senha (o servidor aplica scrypt por cima).
export async function deriveAuthKey(password, saltAuth) {
  const bits = await pbkdf2Bits(password, saltAuth, 'auth');
  return b64.encode(bits);
}

// KEK: cifra/decifra a chave privada de identidade. Nunca sai do cliente.
export async function deriveKek(password, saltKek) {
  const bits = await pbkdf2Bits(password, saltKek, 'kek');
  return subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function generateIdentity() {
  return subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
}

export async function exportPublicKey(keyPair) {
  return b64.encode(await subtle.exportKey('raw', keyPair.publicKey));
}

export async function encryptPrivateKey(keyPair, kek) {
  const pkcs8 = await subtle.exportKey('pkcs8', keyPair.privateKey);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, kek, pkcs8);
  return { encPriv: b64.encode(ct), encPrivIv: b64.encode(iv) };
}

export async function decryptPrivateKey(encPriv, encPrivIv, kek) {
  const pkcs8 = await subtle.decrypt(
    { name: 'AES-GCM', iv: b64.decode(encPrivIv) }, kek, b64.decode(encPriv),
  );
  return subtle.importKey('pkcs8', pkcs8, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
}

export async function importPublicKey(pubB64) {
  return subtle.importKey('raw', b64.decode(pubB64), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
}

async function ecdhHkdf(privateKey, publicKey, info) {
  const shared = await subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
  const hkdfKey = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('voyage-messenger'), info: enc.encode(info) },
    hkdfKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );
}

// Chave de uma conversa direta — os dois lados derivam a mesma, sem trocar nada além das públicas.
export async function directKey(myPrivateKey, theirPubB64, userIdA, userIdB) {
  const theirPub = await importPublicKey(theirPubB64);
  const [lo, hi] = userIdA < userIdB ? [userIdA, userIdB] : [userIdB, userIdA];
  return ecdhHkdf(myPrivateKey, theirPub, `dm:${lo}:${hi}`);
}

// ---- grupos ----
export async function generateGroupKey() {
  return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function wrapGroupKey(groupKey, myPrivateKey, memberPubB64) {
  const raw = await subtle.exportKey('raw', groupKey);
  const wrapKey = await ecdhHkdf(myPrivateKey, await importPublicKey(memberPubB64), 'wrap:group');
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, raw);
  return { wrapped: b64.encode(ct), iv: b64.encode(iv) };
}

// Extraível (true): qualquer membro pode re-embrulhar a chave ao adicionar novos membros.
export async function unwrapGroupKey(wrapped, iv, myPrivateKey, wrapperPubB64) {
  const wrapKey = await ecdhHkdf(myPrivateKey, await importPublicKey(wrapperPubB64), 'wrap:group');
  const raw = await subtle.decrypt({ name: 'AES-GCM', iv: b64.decode(iv) }, wrapKey, b64.decode(wrapped));
  return subtle.importKey('raw', raw, 'AES-GCM', true, ['encrypt', 'decrypt']);
}

// ---- mensagens ----
export async function encryptMessage(key, payloadObj) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(payloadObj)));
  return { ciphertext: b64.encode(ct), iv: b64.encode(iv) };
}

export async function decryptMessage(key, ciphertext, iv) {
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: b64.decode(iv) }, key, b64.decode(ciphertext));
  return JSON.parse(dec.decode(pt));
}
