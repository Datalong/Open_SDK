import { afterEach, describe, expect, it } from 'vitest';
import { WebSocketServer, WebSocket, type WebSocket as WS } from 'ws';
import { A2NetClient } from '../src/index.js';

/**
 * 流式响应（协议级）
 *
 * 分帧约定：
 *   query { stream: true }
 *     ← response { result: "<增量>", metadata: { seq, done: false } }
 *     ← response { result: "",      metadata: { seq, done: true  } }
 *
 * 终止帧的 result 必须是**空串**：接收侧会把所有带 seq 的帧按序拼接（含终止帧），
 * 若终止帧携带完整文本，拼接结果会把全文再追加一遍 —— 静默产出错误结果。
 *
 * 用自包含的最小中继（不依赖私有中继源码）。
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
        for (const [peer, addr] of peers) {
          if (addr === msg.to && peer !== ws && peer.readyState === WebSocket.OPEN) {
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

const relays: Array<() => Promise<void>> = [];
const clients: A2NetClient[] = [];

afterEach(async () => {
  for (const c of clients.splice(0)) {
    try {
      c.disconnect();
    } catch {
      /* ignore */
    }
  }
  for (const close of relays.splice(0)) await close();
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function mkPair() {
  const relay = await startMiniRelay();
  relays.push(relay.close);
  const url = `ws://127.0.0.1:${relay.port}`;
  const provider = new A2NetClient({
    relayUrl: url,
    webSocketImpl: WebSocket as never,
    encryptContent: true,
    permissionPolicy: { defaultAllow: true },
  });
  const caller = new A2NetClient({
    relayUrl: url,
    webSocketImpl: WebSocket as never,
    encryptContent: true,
    permissionPolicy: { defaultAllow: true },
  });
  clients.push(provider, caller);
  await provider.connect();
  await caller.connect();
  return { caller, provider };
}

describe('协议级流式响应', () => {
  it('分片实时投递：onDelta 在流进行中被调用，而非结束后一次性回调', async () => {
    const { caller, provider } = await mkPair();
    provider.onStreamQuery(async (_q, _s, emit) => {
      for (const piece of ['你', '好', '，', '世界']) {
        await emit(piece);
        await sleep(25);
      }
    });

    const arrivals: Array<{ delta: string; at: number }> = [];
    const t0 = Date.now();
    const full = await caller.query(provider.address, 'go', {
      stream: true,
      onDelta: (d) => arrivals.push({ delta: d, at: Date.now() - t0 }),
    });
    const total = Date.now() - t0;

    expect(full).toBe('你好，世界');
    expect(arrivals.map((a) => a.delta)).toEqual(['你', '好', '，', '世界']);
    // 首片必须显著早于整体完成 —— 这才叫流式
    expect(arrivals[0]!.at).toBeLessThan(total / 2);
  }, 30_000);

  it('拼接恒等式：delta 拼接 === 最终全文（终止帧空 result 不污染拼接）', async () => {
    const { caller, provider } = await mkPair();
    provider.onStreamQuery(async (_q, _s, emit) => {
      await emit('第一段');
      await emit(''); // 空增量应被忽略且不占 seq
      await emit('第二段🎉');
      await emit('第三段');
    });

    const seen: string[] = [];
    const full = await caller.query(provider.address, 'x', {
      stream: true,
      onDelta: (d) => seen.push(d),
    });

    expect(full).toBe('第一段第二段🎉第三段');
    expect(seen.join('')).toBe(full);
    expect(seen).not.toContain('');
  }, 30_000);

  it('空闲超时按帧间隔计，长流不会被总时长上限杀掉', async () => {
    const relay = await startMiniRelay();
    relays.push(relay.close);
    const url = `ws://127.0.0.1:${relay.port}`;
    const provider = new A2NetClient({
      relayUrl: url,
      webSocketImpl: WebSocket as never,
      encryptContent: true,
      permissionPolicy: { defaultAllow: true },
    });
    // 总时长上限故意设得很小（300ms），但流会持续 ~800ms
    const slow = new A2NetClient({
      relayUrl: url,
      webSocketImpl: WebSocket as never,
      encryptContent: true,
      permissionPolicy: { defaultAllow: true },
      requestTimeoutMs: 300,
    });
    clients.push(provider, slow);
    await provider.connect();
    await slow.connect();

    provider.onStreamQuery(async (_q, _s, emit) => {
      for (let i = 0; i < 8; i++) {
        await emit(`${i}`);
        await sleep(100);
      }
    });

    const full = await slow.query(provider.address, 'long', {
      stream: true,
      streamIdleTimeoutMs: 2_000,
    });
    expect(full).toBe('01234567');
  }, 30_000);

  it('中途失败：返回部分内容 + 明确错误，而不是静默成功', async () => {
    const { caller, provider } = await mkPair();
    provider.onStreamQuery(async (_q, _s, emit) => {
      await emit('已生成的部分');
      throw new Error('上游模型连接中断');
    });

    let caught: (Error & { partial?: string }) | null = null;
    try {
      await caller.query(provider.address, 'x', { stream: true, streamIdleTimeoutMs: 5_000 });
    } catch (e) {
      caught = e as Error & { partial?: string };
    }
    expect(caught).not.toBeNull();
    expect(caught!.message).toMatch(/上游模型连接中断/);
    expect(caught!.partial).toBe('已生成的部分');
  }, 30_000);

  it('向后兼容：服务方无流式处理器时自动退化为单帧', async () => {
    const { caller, provider } = await mkPair();
    provider.onQuery(async (q) => `普通:${q}`);
    const full = await caller.query(provider.address, 'hi', { stream: true, onDelta: () => {} });
    expect(full).toBe('普通:hi');
  }, 30_000);

  it('向后兼容：调用方不要求流式时走普通路径', async () => {
    const { caller, provider } = await mkPair();
    let streamUsed = false;
    provider.onStreamQuery(async (_q, _s, emit) => {
      streamUsed = true;
      await emit('不该走这里');
    });
    provider.onQuery(async (q) => `普通:${q}`);
    expect(await caller.query(provider.address, 'x')).toBe('普通:x');
    expect(streamUsed).toBe(false);
  }, 30_000);
});

describe('连接健壮性（协议级能力）', () => {
  it('未连接时 query() 快速失败，而不是静默等到超时', async () => {
    const client = new A2NetClient({
      relayUrl: 'ws://127.0.0.1:1',
      webSocketImpl: WebSocket as never,
      encryptContent: false,
    });
    clients.push(client);
    const t0 = Date.now();
    await expect(client.query('did:key:zNobody', 'hi')).rejects.toThrow(/Not connected/);
    expect(Date.now() - t0).toBeLessThan(500);
  }, 15_000);

  it('非法第三参数立即抛错，而不是被静默忽略', async () => {
    const client = new A2NetClient({
      relayUrl: 'ws://127.0.0.1:1',
      webSocketImpl: WebSocket as never,
      encryptContent: false,
    });
    clients.push(client);
    await expect(client.query('did:key:zX', 'hi', '4000' as never)).rejects.toThrow(TypeError);
  }, 15_000);

  it('isConnected 反映真实连接状态', async () => {
    const { caller } = await mkPair();
    expect(caller.isConnected).toBe(true);
    caller.disconnect();
    expect(caller.isConnected).toBe(false);
  }, 30_000);
});
