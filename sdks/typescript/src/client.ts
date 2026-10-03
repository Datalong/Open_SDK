/**
 * client.ts — A2NetClient：连接中继、收发消息、请求匹配、权限校验与 E2EE 加密
 *
 * 兼容 Node 与浏览器：Node 下用 `ws`，浏览器用原生 WebSocket。
 */
import { EventEmitter } from './emitter.js';
import { generateKeyPair, keyPairFromPrivateKey, type KeyPair } from './crypto.js';
import {
  buildMessage,
  buildPing,
  buildQuery,
  buildError,
  buildResponse,
  buildBlobInit,
  buildBlobChunk,
  buildBlobAck,
  validateMessage,
  ErrorCode,
  type A2Message,
  type QueryContent,
  type ResponseContent,
} from './protocol.js';
import { checkPermission, TokenBucket, type PermissionPolicy } from './permissions.js';
import { decryptFrom, encryptFor, isEncrypted } from './e2ee.js';
import {
  BlobTransferManager,
  splitBlobIntoChunks,
  type BlobMetadata,
  type BlobChunk,
  type CompletedBlob,
} from './multimodal.js';

export type QueryHandler = (
  query: string,
  sender: string,
  msg: A2Message
) => Promise<string | { result: string; metadata?: ResponseContent['metadata'] }>;

export interface A2NetClientConfig {
  relayUrl: string;
  privateKey?: Uint8Array;
  permissionPolicy?: PermissionPolicy;
  /** 商业中继 API Key（若官方中继开启门禁时使用） */
  apiKey?: string;
  /** 端到端加密：开启后消息 content 以密文发送，中继只见密文（默认 false，保持兼容） */
  encryptContent?: boolean;
  /** 重连基础退避毫秒，默认 500，指数退避 + 抖动，上限 30s */
  reconnectBaseMs?: number;
  /** 请求默认超时毫秒 */
  requestTimeoutMs?: number;
  /** 心跳间隔毫秒 */
  heartbeatIntervalMs?: number;
  /** 是否自动重连 */
  autoReconnect?: boolean;
  /** Node 环境下注入 ws 实现 */
  webSocketImpl?: WebSocketConstructor;
}

export type WebSocketConstructor = new (
  url: string,
  protocols?: string | string[]
) => {
  readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: string, listener: (ev: any) => void): void;
  removeEventListener(type: string, listener: (ev: any) => void): void;
  onopen: ((ev: any) => void) | null;
  onclose: ((ev: any) => void) | null;
  onerror: ((ev: any) => void) | null;
  onmessage: ((ev: any) => void) | null;
};

interface PendingRequest {
  resolve: (res: string) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
  chunks?: Map<number, string>;
}

const DEFAULT_POLICY: PermissionPolicy = {
  defaultAllow: true,
  whitelist: [],
  blacklist: [],
};

export class A2NetClient extends EventEmitter {
  private readonly relayUrl: string;
  private readonly keyPair: KeyPair;
  private policy: PermissionPolicy;
  private readonly bucket = new TokenBucket();
  private readonly apiKey?: string;
  private readonly encryptContent: boolean;
  private readonly requestTimeoutMs: number;
  private readonly heartbeatIntervalMs: number;
  private readonly reconnectBaseMs: number;
  private readonly autoReconnect: boolean;
  private readonly webSocketImpl?: WebSocketConstructor;

  private ws: any = null;
  private connected = false;
  private closedExplicitly = false;
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;

  private pending = new Map<string, PendingRequest>();
  private seenIds = new Set<string>();
  private seenOrder: string[] = [];
  private queryHandler: QueryHandler | null = null;
  private readonly blobManager = new BlobTransferManager();
  private blobHandler: ((blob: CompletedBlob, sender: string) => Promise<void> | void) | null = null;

  constructor(config: A2NetClientConfig) {
    super();
    this.relayUrl = config.relayUrl;
    this.keyPair = config.privateKey
      ? keyPairFromPrivateKey(config.privateKey)
      : generateKeyPair();
    this.policy = config.permissionPolicy ?? DEFAULT_POLICY;
    this.apiKey = config.apiKey;
    this.encryptContent = config.encryptContent ?? false;
    this.requestTimeoutMs = config.requestTimeoutMs ?? 30_000;
    this.heartbeatIntervalMs = config.heartbeatIntervalMs ?? 30_000;
    this.reconnectBaseMs = config.reconnectBaseMs ?? 500;
    this.autoReconnect = config.autoReconnect ?? true;
    this.webSocketImpl = config.webSocketImpl;
  }

  get address(): string {
    return this.keyPair.address;
  }

  get isConnected(): boolean {
    return this.connected;
  }

  setPermissionPolicy(policy: PermissionPolicy): void {
    this.policy = policy;
  }

  getPermissionPolicy(): PermissionPolicy {
    return this.policy;
  }

  connect(): Promise<void> {
    if (this.connected) return Promise.resolve();
    this.closedExplicitly = false;

    return new Promise<void>((resolve, reject) => {
      let settled = false;
      const WS =
        this.webSocketImpl ??
        (typeof globalThis.WebSocket !== 'undefined'
          ? (globalThis.WebSocket as unknown as WebSocketConstructor)
          : null);
      if (!WS) {
        reject(new Error('No WebSocket implementation available. In Node, pass webSocketImpl in config.'));
        return;
      }

      try {
        let wsUrl = this.relayUrl;
        if (this.apiKey) {
          const sep = wsUrl.includes('?') ? '&' : '?';
          wsUrl = `${wsUrl}${sep}apiKey=${encodeURIComponent(this.apiKey)}`;
        }
        this.ws = new WS(wsUrl);
      } catch (err) {
        reject(err);
        return;
      }

      this.ws.onopen = () => {
        this.connected = true;
        this.reconnectAttempts = 0;
        this.startHeartbeat();
        this.emit('connected', undefined);

        // 发送注册握手
        const hello = buildPing(this.address, this.address, this.keyPair.privateKey);
        this.sendRaw(hello);

        if (!settled) {
          settled = true;
          resolve();
        }
      };

      this.ws.onclose = (ev: any) => {
        const wasConnected = this.connected;
        this.connected = false;
        this.stopHeartbeat();
        this.emit('disconnected', ev);
        if (!settled) {
          settled = true;
          reject(new Error(`WebSocket closed before open (code ${ev?.code})`));
        }
        if (!this.closedExplicitly && this.autoReconnect) {
          this.scheduleReconnect();
        }
      };

      this.ws.onerror = (err: any) => {
        this.emit('error', err);
      };

      this.ws.onmessage = async (ev: any) => {
        try {
          const raw = typeof ev.data === 'string' ? ev.data : ev.data?.toString?.();
          if (!raw) return;
          const msg = JSON.parse(raw);
          await this.handleMessage(msg);
        } catch (err) {
          this.emit('error', err);
        }
      };
    });
  }

  disconnect(): void {
    this.closedExplicitly = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.stopHeartbeat();
    this.ws?.close();
    this.ws = null;
    this.connected = false;
  }

  async query(
    targetAddress: string,
    queryText: string,
    opts: {
      scope?: QueryContent['scope'];
      sessionId?: string;
      stream?: boolean;
      extensions?: Record<string, unknown>;
      timeoutMs?: number;
    } = {}
  ): Promise<string> {
    if (!this.ws || !this.connected) throw new Error('Not connected');

    const content: Record<string, unknown> = { query: queryText };
    if (opts.scope) content.scope = opts.scope;
    if (opts.sessionId) content.session_id = opts.sessionId;
    if (opts.stream) content.stream = true;

    // 端到端加密
    const finalContent = this.encryptContent
      ? ((await encryptFor(targetAddress, JSON.stringify(content))) as unknown as Record<string, unknown>)
      : content;

    const msg = buildMessage(
      {
        from: this.address,
        to: targetAddress,
        type: 'query',
        content: finalContent,
        extensions: opts.extensions,
      },
      this.keyPair.privateKey
    );
    return this.sendAndWait(msg, opts.timeoutMs ?? this.requestTimeoutMs);
  }

  async ping(targetAddress: string, timeoutMs = 10_000): Promise<string> {
    if (!this.ws || !this.connected) throw new Error('Not connected');
    const msg = buildPing(this.address, targetAddress, this.keyPair.privateKey);
    return this.sendAndWait(msg, timeoutMs);
  }

  onQuery(handler: QueryHandler): void {
    this.queryHandler = handler;
  }

  onBlob(handler: (blob: CompletedBlob, sender: string) => Promise<void> | void): void {
    this.blobHandler = handler;
  }

  async sendBlob(
    targetAddress: string,
    data: Uint8Array,
    options: {
      name?: string;
      mimeType?: string;
      chunkSize?: number;
      onProgress?: (progressPct: number, chunkIndex: number, totalChunks: number) => void;
    } = {}
  ): Promise<BlobMetadata> {
    if (!this.ws || !this.connected) throw new Error('Not connected');

    const name = options.name || 'unnamed.bin';
    const mimeType = options.mimeType || 'application/octet-stream';
    const { metadata, chunks } = await splitBlobIntoChunks(data, name, mimeType, options.chunkSize);

    const initPayload = { metadata };
    const finalInitContent = this.encryptContent
      ? ((await encryptFor(targetAddress, JSON.stringify(initPayload))) as unknown as Record<string, unknown>)
      : initPayload;
    const initMsg = buildBlobInit(this.address, targetAddress, finalInitContent, this.keyPair.privateKey, {
      e2ee: this.encryptContent,
    });
    this.sendRaw(initMsg);

    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i]!;
      const chunkPayload = { chunk };
      const finalChunkContent = this.encryptContent
        ? ((await encryptFor(targetAddress, JSON.stringify(chunkPayload))) as unknown as Record<string, unknown>)
        : chunkPayload;
      const chunkMsg = buildBlobChunk(this.address, targetAddress, finalChunkContent, this.keyPair.privateKey, {
        e2ee: this.encryptContent,
      });
      this.sendRaw(chunkMsg);

      const pct = Math.round(((i + 1) / chunks.length) * 100);
      options.onProgress?.(pct, i, chunks.length);
    }

    return metadata;
  }

  private sendAndWait(msg: A2Message, timeoutMs: number): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(msg.id);
        reject(new Error(`Request timeout (${ErrorCode.TIMEOUT})`));
      }, timeoutMs);
      this.pending.set(msg.id, { resolve, reject, timer });
      this.sendRaw(msg);
    });
  }

  private sendRaw(msg: A2Message): void {
    this.ws?.send(JSON.stringify(msg));
  }

  private async handleMessage(msg: A2Message): Promise<void> {
    const replyTo = (msg.content as any)?.reply_to;
    if (msg.type === 'error' && replyTo && this.pending.has(replyTo)) {
      this.handleReply(msg);
      return;
    }

    const validationError = validateMessage(msg);
    if (validationError !== null) {
      if (validationError === ErrorCode.FORMAT && typeof (msg as any)?.id === 'string' && (msg as any)?.from) {
        const err = await buildError(msg, ErrorCode.FORMAT, 'Invalid format', this.keyPair.privateKey);
        this.sendRaw(err);
      }
      return;
    }

    if (this.seenIds.has(msg.id)) return;
    this.markSeen(msg.id);

    // E2EE 解密
    if (isEncrypted(msg.content)) {
      try {
        const plainJson = await decryptFrom(msg.from, msg.content as any, this.keyPair.privateKey);
        msg.content = JSON.parse(plainJson);
      } catch {
        const err = await buildError(msg, ErrorCode.FORMAT, 'Decryption failed', this.keyPair.privateKey);
        this.sendRaw(err);
        return;
      }
    }

    switch (msg.type) {
      case 'ping':
        this.emit('ping', msg);
        try {
          const pong = buildResponse(msg, 'pong', this.keyPair.privateKey);
          this.sendRaw(pong);
        } catch {}
        break;
      case 'query':
        await this.handleQuery(msg);
        break;
      case 'response':
      case 'error':
        this.handleReply(msg);
        break;
      case 'blob_init':
        await this.handleBlobInit(msg);
        break;
      case 'blob_chunk':
        await this.handleBlobChunk(msg);
        break;
    }
  }

  private markSeen(id: string): void {
    this.seenIds.add(id);
    this.seenOrder.push(id);
    if (this.seenOrder.length > 10_000) {
      const old = this.seenOrder.shift();
      if (old) this.seenIds.delete(old);
    }
  }

  private async handleQuery(msg: A2Message): Promise<void> {
    const scope = (msg.content as unknown as QueryContent).scope?.type
      ? `${(msg.content as unknown as QueryContent).scope!.type}.public`
      : 'knowledge.public';

    const decision = checkPermission(this.policy, { sender: msg.from, scope }, this.bucket);
    if (!decision.allowed) {
      const err = await buildError(
        msg,
        decision.code,
        decision.reason,
        this.keyPair.privateKey,
        Math.ceil((decision.retryAfter ?? 0) / 1000)
      );
      this.sendRaw(err);
      this.emit('denied', { from: msg.from, reason: decision.reason });
      return;
    }

    if (!this.queryHandler) {
      const err = await buildError(msg, ErrorCode.INTERNAL, 'No query handler', this.keyPair.privateKey);
      this.sendRaw(err);
      return;
    }

    const rawQuery = (msg.content as unknown as QueryContent).query;

    try {
      const out = await this.queryHandler(rawQuery, msg.from, msg);
      const result = typeof out === 'string' ? out : out.result;
      const metadata = typeof out === 'string' ? undefined : out.metadata;
      let resp = await buildResponse(msg, result, this.keyPair.privateKey, metadata);

      if (this.encryptContent || msg.extensions?.e2ee === true) {
        const cipher = await encryptFor(msg.from, JSON.stringify(resp.content));
        resp.content = cipher as any;
        resp.extensions = { ...(resp.extensions ?? {}), e2ee: true };
      }

      this.sendRaw(resp);
    } catch (handlerErr) {
      const err = await buildError(
        msg,
        ErrorCode.INTERNAL,
        (handlerErr as Error)?.message ?? 'Handler error',
        this.keyPair.privateKey
      );
      this.sendRaw(err);
    }
  }

  private handleReply(msg: A2Message): void {
    const replyTo =
      (msg.content as unknown as ResponseContent).reply_to ??
      (msg.content as any)?.reply_to;
    if (!replyTo) return;

    const req = this.pending.get(replyTo);
    if (!req) return;

    if (msg.type === 'response') {
      const rc = msg.content as unknown as ResponseContent;
      clearTimeout(req.timer);
      this.pending.delete(replyTo);
      req.resolve(rc.result ?? '');
    } else if (msg.type === 'error') {
      const ec = (msg.content as any).error ?? msg.content;
      clearTimeout(req.timer);
      this.pending.delete(replyTo);
      req.reject(new Error(`${ec.code}: ${ec.message}`));
    }
  }

  private async handleBlobInit(msg: A2Message): Promise<void> {
    const content = msg.content as any;
    if (content?.metadata) {
      this.blobManager.initSession(msg.from, content.metadata);
      this.emit('blob_init', { from: msg.from, metadata: content.metadata });
    }
  }

  private async handleBlobChunk(msg: A2Message): Promise<void> {
    const content = msg.content as any;
    if (content?.chunk) {
      try {
        const { session, completedBlob } = await this.blobManager.handleChunk(msg.from, content.chunk);
        this.emit('blob_progress', {
          from: msg.from,
          blobId: session.metadata.blobId,
          name: session.metadata.name,
          chunkIndex: content.chunk.chunkIndex,
          totalChunks: session.metadata.totalChunks,
          progressPct: session.progressPct,
        });

        if (completedBlob) {
          this.emit('blob_completed', completedBlob);
          if (this.blobHandler) {
            await this.blobHandler(completedBlob, msg.from);
          }
        }
      } catch (err) {
        this.emit('blob_error', { from: msg.from, error: (err as Error).message });
      }
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;
    const delay = Math.min(
      this.reconnectBaseMs * Math.pow(2, this.reconnectAttempts),
      30_000
    );
    this.reconnectAttempts++;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect().catch(() => {});
    }, delay);
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.connected && this.ws) {
        const ping = buildPing(this.address, this.address, this.keyPair.privateKey);
        this.sendRaw(ping);
      }
    }, this.heartbeatIntervalMs);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }
}
