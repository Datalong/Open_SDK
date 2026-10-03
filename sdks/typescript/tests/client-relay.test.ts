import { afterEach, describe, expect, it } from 'vitest';
import { WebSocketServer, WebSocket, type WebSocket as WS } from 'ws';
import { A2NetClient, splitBlobIntoChunks } from '../src/index.js';

/**
 * 自包含的最小中继：实现 register 握手与基于 to 地址的密文盲转，
 * 用于校验客户端与真实中继的协议互通（不依赖私有中继源码）。
 */
function startMiniRelay(): Promise<{ port: number; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const peers = new Map<WS, string>();
    const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });

    wss.on('connection', (ws: WS) => {
      ws.on('message', (buf) => {
        let msg: any;
        try {
          msg = JSON.parse(buf.toString());
        } catch {
          return;
        }
        if (msg.type === 'register') {
          peers.set(ws, msg.address);
          ws.send(JSON.stringify({ type: 'register_ack', status: 'success', tier: 'free' }));
          return;
        }
        if (msg.type === 'pong') return;
        const to = msg.to;
        for (const [peer, addr] of peers) {
          if (addr === to && peer !== ws && peer.readyState === WebSocket.OPEN) {
            peer.send(JSON.stringify(msg));
          }
        }
      });
      ws.on('close', () => peers.delete(ws));
    });

    wss.on('listening', () => {
      const addr = wss.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      resolve({
        port,
        close: () =>
          new Promise<void>((res) => {
            for (const p of peers.keys()) p.terminate();
            wss.close(() => res());
          }),
      });
    });
  });
}

const clients: A2NetClient[] = [];
let relayClose: (() => Promise<void>) | null = null;

afterEach(async () => {
  for (const c of clients) c.disconnect();
  clients.length = 0;
  if (relayClose) {
    await relayClose();
    relayClose = null;
  }
});

describe('A2NetClient ↔ Relay interoperability', () => {
  it('registers, performs an E2EE query round-trip, and receives a chunked blob', async () => {
    const { port, close } = await startMiniRelay();
    relayClose = close;
    const url = `ws://127.0.0.1:${port}`;

    let receivedBlob: { name: string; data: Uint8Array } | null = null;

    const responder = new A2NetClient({
      relayUrl: url,
      encryptContent: true,
      permissionPolicy: { defaultAllow: true, whitelist: [], blacklist: [] },
      webSocketImpl: (await import('ws')).WebSocket as any,
    });
    clients.push(responder);
    responder.onQuery(async (q) => `echo: ${q}`);
    responder.onBlob((blob) => {
      receivedBlob = { name: blob.metadata.name, data: blob.data };
    });
    await responder.connect();

    const caller = new A2NetClient({
      relayUrl: url,
      encryptContent: true,
      webSocketImpl: (await import('ws')).WebSocket as any,
    });
    clients.push(caller);
    await caller.connect();

    // 1. 基础请求/响应
    const reply = await caller.query(responder.address, '你好', { timeoutMs: 5000 });
    expect(reply).toBe('echo: 你好');

    // 2. 分块 Blob 传输
    const payload = new Uint8Array(200 * 1024).map((_, i) => (i * 13 + 5) & 0xff);
    const { metadata } = await splitBlobIntoChunks(payload, 'shot.png', 'image/png', 64 * 1024);
    await caller.sendBlob(responder.address, payload, {
      name: 'shot.png',
      mimeType: 'image/png',
      chunkSize: 64 * 1024,
    });

    for (let i = 0; i < 100 && !receivedBlob; i++) {
      await new Promise((r) => setTimeout(r, 50));
    }

    expect(receivedBlob).not.toBeNull();
    expect(receivedBlob!.name).toBe('shot.png');
    expect(receivedBlob!.data.length).toBe(payload.length);
    expect(receivedBlob!.data).toEqual(payload);
    expect(metadata.totalChunks).toBe(4);
  });
});
