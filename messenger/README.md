# Voyage Messenger

Mensageiro em tempo real do **Merge Voyage** — pensado para ser melhor que WhatsApp e Telegram
nos pontos em que eles falham: privacidade de verdade, sem número de telefone e 100% aberto
e auto-hospedável.

## Por que é melhor?

| | Voyage | WhatsApp | Telegram |
|---|---|---|---|
| Criptografia de ponta a ponta **por padrão** | ✅ em tudo (1:1 e grupos) | ✅ | ❌ só em "chats secretos" |
| Funciona **sem número de telefone** | ✅ só nome de usuário | ❌ | ❌ |
| Servidor **não consegue ler nada** (nem sua senha) | ✅ | parcial (metadados/backups) | ❌ |
| Código aberto e auto-hospedável | ✅ | ❌ | só o cliente |
| Web/desktop **sem depender do celular** | ✅ | parcial | ✅ |
| Instalável como app (PWA, offline) | ✅ | — | — |
| Zero rastreamento, zero anúncios, zero coleta | ✅ | ❌ | parcial |

Recursos: conversas 1:1 e grupos, respostas, reações, edição e exclusão de mensagens,
recibos de leitura (✓ / ✓✓), indicador de digitação, presença online, contador de não lidas,
busca de pessoas, multi-dispositivo, tema claro/escuro, notificações e modo offline (PWA).

## Rodando

Requer Node.js ≥ 22.5 (usa o SQLite embutido do Node — sem dependências nativas).

```bash
cd messenger
npm install        # instala apenas "ws"
npm start          # http://localhost:3000
```

Variáveis: `PORT` (padrão 3000) e `DB_PATH` (padrão `messenger/data/voyage.db`).
Em produção, coloque atrás de um proxy TLS (Caddy/nginx) — o app usa `wss://` automaticamente
quando servido por HTTPS.

```bash
npm test           # testes de integração (REST + WebSocket) e de criptografia
```

## Modelo de segurança

- **Identidade**: cada usuário tem um par de chaves ECDH P-256 gerado no navegador.
  A chave privada nunca sai do dispositivo em claro.
- **Senha nunca é enviada**: o cliente deriva via PBKDF2 (310k iterações) duas chaves
  independentes — a `authKey` (enviada no login; o servidor aplica scrypt por cima) e a
  `KEK`, que cifra a chave privada (AES-GCM) para sincronizar entre dispositivos.
  O servidor não consegue derivar a KEK, logo não consegue decifrar nada.
- **Conversas 1:1**: chave AES-GCM derivada por ECDH entre os dois usuários + HKDF.
- **Grupos**: chave AES-GCM aleatória, "embrulhada" individualmente para cada membro
  via ECDH. Qualquer membro pode adicionar pessoas re-embrulhando a chave.
- **O servidor armazena apenas ciphertext** (mensagens, chave privada). Anti-enumeração
  de contas no endpoint de sal.

Limitações conhecidas (roadmap): forward secrecy por mensagem (double ratchet),
verificação de segurança por QR code, rotação de chave ao remover membro de grupo,
anexos/mídia cifrados e apps nativos.

## Arquitetura

```
messenger/
├── server/
│   ├── server.js    # HTTP estático + API REST + WebSocket (ws)
│   └── db.js        # SQLite (node:sqlite) — só ciphertext e metadados mínimos
├── public/          # cliente sem framework e sem build
│   ├── index.html
│   ├── css/style.css
│   └── js/
│       ├── app.js      # UI e estado
│       ├── crypto.js   # E2E (Web Crypto): ECDH + HKDF + AES-GCM + PBKDF2
│       └── net.js      # REST + WebSocket com reconexão automática
└── test/            # node:test — integração e criptografia
```
