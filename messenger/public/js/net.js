// Camada de rede: REST + WebSocket com reconexão automática.

export async function api(path, { method = 'GET', body, token } = {}) {
  const res = await fetch(path, {
    method,
    headers: {
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Erro ${res.status}`);
  return data;
}

export class Socket {
  constructor(token, handlers) {
    this.token = token;
    this.handlers = handlers;
    this.queue = [];
    this.closed = false;
    this.retry = 0;
    this.connect();
  }

  connect() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    this.ws = new WebSocket(`${proto}://${location.host}/ws`);
    this.ws.onopen = () => {
      this.ws.send(JSON.stringify({ type: 'auth', token: this.token }));
    };
    this.ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (msg.type === 'ready') {
        this.retry = 0;
        for (const q of this.queue.splice(0)) this.ws.send(q);
      }
      this.handlers[msg.type]?.(msg);
    };
    this.ws.onclose = () => {
      this.handlers._offline?.();
      if (this.closed) return;
      const delay = Math.min(30000, 1000 * 2 ** this.retry++);
      setTimeout(() => this.connect(), delay);
    };
    this.ws.onerror = () => this.ws.close();
  }

  send(obj) {
    const data = JSON.stringify(obj);
    if (this.ws.readyState === WebSocket.OPEN) this.ws.send(data);
    else this.queue.push(data);
  }

  close() {
    this.closed = true;
    this.ws.close();
  }
}
