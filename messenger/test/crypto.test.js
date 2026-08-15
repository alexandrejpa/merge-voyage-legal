// Round-trip da criptografia E2E — o mesmo módulo usado no navegador roda no Node 22.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as vc from '../public/js/crypto.js';

test('conversa direta: os dois lados derivam a mesma chave e trocam mensagens', async () => {
  const ana = await vc.generateIdentity();
  const bia = await vc.generateIdentity();
  const pubAna = await vc.exportPublicKey(ana);
  const pubBia = await vc.exportPublicKey(bia);

  const keyAna = await vc.directKey(ana.privateKey, pubBia, 1, 2);
  const keyBia = await vc.directKey(bia.privateKey, pubAna, 2, 1);

  const { ciphertext, iv } = await vc.encryptMessage(keyAna, { text: 'olá, tudo bem? 🚀' });
  const plain = await vc.decryptMessage(keyBia, ciphertext, iv);
  assert.equal(plain.text, 'olá, tudo bem? 🚀');

  // ciphertext não contém o texto
  assert.ok(!ciphertext.includes('olá'));
});

test('grupo: chave embrulhada por membro, novo membro recebe de outro wrapper', async () => {
  const ana = await vc.generateIdentity();
  const bia = await vc.generateIdentity();
  const cadu = await vc.generateIdentity();
  const pubAna = await vc.exportPublicKey(ana);
  const pubBia = await vc.exportPublicKey(bia);
  const pubCadu = await vc.exportPublicKey(cadu);

  // Ana cria o grupo e embrulha para si e para Bia
  const groupKey = await vc.generateGroupKey();
  const wkBia = await vc.wrapGroupKey(groupKey, ana.privateKey, pubBia);

  const keyBia = await vc.unwrapGroupKey(wkBia.wrapped, wkBia.iv, bia.privateKey, pubAna);
  const { ciphertext, iv } = await vc.encryptMessage(groupKey, { text: 'segredo do grupo' });
  const plain = await vc.decryptMessage(keyBia, ciphertext, iv);
  assert.equal(plain.text, 'segredo do grupo');

  // Bia (não a criadora) adiciona Cadu re-embrulhando a chave
  const wkCadu = await vc.wrapGroupKey(keyBia, bia.privateKey, pubCadu);
  const keyCadu = await vc.unwrapGroupKey(wkCadu.wrapped, wkCadu.iv, cadu.privateKey, pubBia);
  const plain2 = await vc.decryptMessage(keyCadu, ciphertext, iv);
  assert.equal(plain2.text, 'segredo do grupo');
});

test('chave privada protegida por senha: cifra, decifra e rejeita senha errada', async () => {
  const id = await vc.generateIdentity();
  const kek = await vc.deriveKek('senha-super-secreta', 'salzinho');
  const { encPriv, encPrivIv } = await vc.encryptPrivateKey(id, kek);

  const recovered = await vc.decryptPrivateKey(encPriv, encPrivIv, kek);
  assert.ok(recovered);

  const kekErrada = await vc.deriveKek('senha-errada', 'salzinho');
  await assert.rejects(() => vc.decryptPrivateKey(encPriv, encPrivIv, kekErrada));
});

test('authKey é determinística por (senha, sal) e diferente da KEK', async () => {
  const a1 = await vc.deriveAuthKey('senha', 'sal');
  const a2 = await vc.deriveAuthKey('senha', 'sal');
  const a3 = await vc.deriveAuthKey('senha', 'outro-sal');
  assert.equal(a1, a2);
  assert.notEqual(a1, a3);
});
