/**
 * client.ts — A2NetClient：连接中继、收发消息、请求匹配、权限校验
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

/**
 * 流式产出一个增量分片。
 *
 * 每次调用立即发一帧 `response`（`metadata.seq` 递增、`done: false`），
 * 因此调用方可以 `for await` 逐个产出 token，接收方实时看到内容。
 */
export type StreamEmit = (delta: string) => Promise<void>;

/**
 * 流式查询处理器。
 *
 * 返回值语义：
 *   · 返回字符串 → 作为**最终帧**的 result（可选；多数情况返回 undefined 即可）
 *   · 返回 undefined → 仅发送终止帧
 *
 * 为什么与 `onQuery` 分开而不是合并：两者契约不同 —— 普通 handler 是
 * 「查询 → 一个完整答复」，流式 handler 是「查询 → 多个增量 + 一个终止」。
 * 合并成一个会让类型与错误处理都变复杂，且难以表达"是否支持流式"。
 */
export type StreamQueryHandler = (
  query: string,
  sender: string,
  emit: StreamEmit,
  msg: A2Message
) => Promise<string | void>;

export interface A2NetClientConfig {
  relayUrl: string;
  privateKey?: Uint8Array;
  permissionPolicy?: PermissionPolicy;
  // 注：企业级 DLP（数据防泄露 / 提示词注入防护）属商业特性，
  //     不在本开源 SDK 中提供。协议级能力（E2EE / 权限 / 流式 / 重试 / 心跳）均已包含。
  /** 端到端加密：开启后消息 content 以密文发送，中继只见密文（默认 false，保持与 v0.1 兼容） */
  encryptContent?: boolean;
  /** 重连基础退避毫秒，默认 500，指数退避 + 抖动，上限 30s */
  reconnectBaseMs?: number;
  /** 请求默认超时毫秒 */
  requestTimeoutMs?: number;
  /** 心跳间隔毫秒 */
  heartbeatIntervalMs?: number;
  /**
   * 心跳失活判定阈值（毫秒）。默认 `heartbeatIntervalMs * 3`。
   *
   * 为什么必须有：WebSocket 在**半开 TCP** 下不会触发 close 事件
   * （中间设备静默丢包、NAT 表项过期、对端断电重启等）。此时客户端
   * `connected` 仍为 true，会一直盲目发送心跳到一个没有接收方的套接字，
   * 所有 query 都要等到 requestTimeoutMs 才失败。
   *
   * 实测证据：故障注入实验中「连上后入站全部静默丢弃」场景下，
   * 修复前客户端永不察觉（connected 恒为 true，心跳空发 22 帧）；
   * 修复后能在阈值内察觉并自动重连。
   *
   * 判定依据是**任意入站帧**（不只 pong）—— 有数据来往即证明链路活着。
   */
  heartbeatTimeoutMs?: number;
  /**
   * 请求超时后的自动重试次数。默认 **0（不重试）**。
   *
   * ⚠️ 默认关闭是刻意的安全选择：A2Net 的 query 是**智能体调用**，
   * 未必幂等。若「请求帧送达并被执行、但响应帧丢失」，重试会导致重复执行
   * （重复扣费、重复副作用）。
   *
   * 开启后重试会**复用同一个消息 id**，从而让下游的去重机制
   * （中继 seenMessages、接收方 seenIds）抑制重复执行。
   * 但端到端的响应去重并不完备，因此仅建议对**幂等能力**开启。
   */
  retryOnTimeout?: number;
  /** 重试间隔毫秒，默认 300 */
  retryDelayMs?: number;
  /** 是否自动重连 */
  autoReconnect?: boolean;
  /** 商业中继 API Key 或凭证（可选，用于解锁高额配额与高级路由） */
  apiKey?: string;
  /** WebSocket 构造器；Node 下传入 `ws`，浏览器可省略 */
  webSocketImpl?: WebSocketConstructor;
}

export type WebSocketConstructor = new (url: string) => WebSocket;

interface PendingRequest {
  /** 流式回调：收到增量分片时实时投递（不设置则仅累积） */
  onDelta?: (delta: string, seq: number) => void;
  /** 是否处于流式接收中（用于切换超时语义） */
  streaming?: boolean;
  /** 已收到的最后一个 seq（用于乱序/丢帧检测） */
  lastSeq?: number;
  /** 流式空闲超时（毫秒）：两帧之间的最大间隔；0 表示沿用固定超时 */
  idleTimeoutMs?: number;
  resolve: (result: string) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
  /** 流式响应累计 */
  chunks?: Map<number, string>;
}

const DEFAULT_POLICY: PermissionPolicy = {
  defaultAllow: false,
  whitelist: [],
  blacklist: [],
};

export class A2NetClient extends EventEmitter {
  readonly relayUrl: string;
  private keyPair: KeyPair;
  private ws: WebSocket | null = null;
  private connected = false;
  private closing = false;
  private reconnectAttempt = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;

  private pending = new Map<string, PendingRequest>();
  private seenIds = new Set<string>();
  private seenOrder: string[] = [];
  /**
   * 入站消息的**串行处理链**。
   *
   * 为什么必须有：`handleMessage` 是异步的（内含 E2EE 解密 await），
   * 若以 `void` 触发（fire-and-forget），多帧会被**并发处理**，
   * 完成顺序不再等于到达顺序 —— 而 WebSocket 本身是**保证有序**的。
   *
   * 实测后果（在并发负载下暴露）：
   *   · 流式分片乱序：拼接出「第一段第三段第二段」
   *   · 流式分片丢失：终止帧先被处理 → 尚未解密完的增量被当作孤儿丢弃
   * 多模态分块走同一条路径，同样受影响。
   *
   * 串行化后，入站帧严格按到达顺序完成处理，SDK 不再破坏传输层保证。
   */
  private inboundChain: Promise<void> = Promise.resolve();
  private queryHandler: QueryHandler | null = null;
  private streamQueryHandler: StreamQueryHandler | null = null;
  private readonly blobManager = new BlobTransferManager();
  private blobHandler: ((blob: CompletedBlob, sender: string) => Promise<void> | void) | null = null;
  private bucket = new TokenBucket();

  private policy: PermissionPolicy;
  readonly apiKey?: string;
  private readonly encryptContent: boolean;
  private readonly requestTimeoutMs: number;
  private readonly heartbeatIntervalMs: number;
  private readonly reconnectBaseMs: number;
  private readonly heartbeatTimeoutMs: number;
  private readonly retryOnTimeout: number;
  private readonly retryDelayMs: number;
  /** 最近一次收到**任意入站帧**的时间，用于半开连接检测 */
  private lastInboundAt = 0;
  private readonly autoReconnect: boolean;
  private readonly webSocketImpl?: WebSocketConstructor;

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
    // 默认取 3 个心跳周期，但**至少 30 秒**。
    //
    // 下限很重要：若心跳间隔被调得很小（例如 500ms），3× = 1.5s 会把
    // 「跨洲 RTT 1.6s 的正常链路」误判为半开连接（故障注入实验 C2 实测暴露）。
    // 30s 的下限保证了任何现实 RTT 都不会误触发。
    this.heartbeatTimeoutMs =
      config.heartbeatTimeoutMs ?? Math.max(this.heartbeatIntervalMs * 3, 30_000);
    this.retryOnTimeout = config.retryOnTimeout ?? 0;
    this.retryDelayMs = config.retryDelayMs ?? 300;
    this.autoReconnect = config.autoReconnect ?? true;
    this.webSocketImpl = config.webSocketImpl;
  }

  get address(): string {
    return this.keyPair.address;
  }

  /**
   * 当前是否已建立可用连接（公开 API）。
   *
   * 内部状态字段 `connected` 是私有的 —— 外部要判断连接状态只能用这个 getter，
   * 不应依赖一次真实调用的 try/catch 去间接推断。
   */
  get isConnected(): boolean {
    return this.connected;
  }

  setPermissionPolicy(policy: PermissionPolicy): void {
    this.policy = policy;
  }

  getPermissionPolicy(): PermissionPolicy {
    return this.policy;
  }

  onQuery(handler: QueryHandler): void {
    this.queryHandler = handler;
  }

  /**
   * 注册**流式**查询处理器。
   *
   * 与 `onQuery` 的关系：两者可同时注册。收到 `stream: true` 的查询时
   * 优先走流式处理器；未注册流式处理器则回落到普通处理器（此时退化为
   * 单帧响应，调用方仍能拿到完整结果 —— **向后兼容**）。
   */
  onStreamQuery(handler: StreamQueryHandler): void {
    this.streamQueryHandler = handler;
  }

  onBlob(handler: (blob: CompletedBlob, sender: string) => Promise<void> | void): void {
    this.blobHandler = handler;
  }

  /**
   * 发送多模态二进制大文件（图片、音频、PDF、向量嵌入），自动分块并支持端到端加密与进度回调
   */
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

    // 1. 发送 blob_init 协商分块元数据
    const initPayload = { metadata };
    const finalInitContent = this.encryptContent
      ? ((await encryptFor(targetAddress, JSON.stringify(initPayload))) as unknown as Record<string, unknown>)
      : initPayload;
    const initMsg = buildBlobInit(this.address, targetAddress, finalInitContent, this.keyPair.privateKey, {
      e2ee: this.encryptContent,
    });
    this.sendRaw(initMsg);

    // 2. 依次管道化发送分片
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

  // -------------------------------------------------------------------------
  // 连接管理
  // -------------------------------------------------------------------------

  async connect(): Promise<void> {
    this.closing = false;
    return new Promise((resolve, reject) => {
      const ws = createWebSocket(this.relayUrl, this.webSocketImpl);
      this.ws = ws;
      let settled = false;

      ws.addEventListener('open', () => {
        ws.send(
          JSON.stringify({
            type: 'register',
            address: this.address,
            apiKey: this.apiKey,
            capabilities: ['a2net.stream.v1', 'a2net.tool_call.v1'],
          })
        );
      });

      ws.addEventListener('message', (ev: MessageEvent) => {
        // 任何入站帧都证明链路存活（不只 pong）—— 这是半开连接检测的依据
        this.lastInboundAt = Date.now();
        const raw = typeof ev.data === 'string' ? ev.data : String(ev.data);
        let msg: Record<string, unknown>;
        try {
          msg = JSON.parse(raw);
        } catch {
          return;
        }
        // 中继控制消息
        if (msg.type === 'register_ack') {
          if (msg.status === 'error') {
            const err = new Error(`Register failed: ${msg.reason ?? 'unknown'}`);
            if (!settled) {
              settled = true;
              reject(err);
            }
            this.emit('error', err);
            return;
          }
          this.connected = true;
          this.reconnectAttempt = 0;
          this.startHeartbeat();
          this.emit('connect');
          if (!settled) {
            settled = true;
            resolve();
          }
          return;
        }
        if (msg.type === 'pong') return;
        // 串行化：保证「到达顺序 === 处理完成顺序」。
        // catch 掉单帧异常，避免一帧失败导致后续帧全部被跳过。
        this.inboundChain = this.inboundChain
          .then(() => this.handleMessage(msg as unknown as A2Message))
          .catch(() => {
            /* 单帧处理异常不应中断后续帧 */
          });
      });

      ws.addEventListener('error', () => {
        if (!settled) {
          settled = true;
          reject(new Error('WebSocket error'));
        }
        this.emit('error', new Error('WebSocket error'));
      });

      ws.addEventListener('close', () => {
        this.connected = false;
        this.stopHeartbeat();
        this.emit('disconnect');
        this.rejectAllPending(new Error('Disconnected'));
        if (!this.closing && this.autoReconnect) this.scheduleReconnect();
      });
    });
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;
    const backoff = Math.min(30_000, this.reconnectBaseMs * 2 ** this.reconnectAttempt);
    const jitter = Math.floor(Math.random() * backoff * 0.3);
    this.reconnectAttempt += 1;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect().catch(() => {
        /* scheduleReconnect 已处理 */
      });
    }, backoff + jitter);
  }

  disconnect(): void {
    this.closing = true;
    this.inboundChain = Promise.resolve();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.stopHeartbeat();
    this.ws?.close();
    this.ws = null;
    this.connected = false;
  }

  // -------------------------------------------------------------------------
  // 收发
  // -------------------------------------------------------------------------

  async query(
    targetAddress: string,
    queryText: string,
    /**
     * 查询选项。
     *
     * 也接受**一个数字**作为 `timeoutMs` 的简写 —— 因为 `query(did, text, 10000)`
     * 是最自然的直觉写法，而早期实现只接受对象。
     *
     * ⚠️ 这个简写不是"锦上添花"，而是修一个真实缺陷：早期实现里传数字**不会报错**，
     * 但 `options.timeoutMs` 求值为 undefined → 静默回落到默认 30s。
     * 调用方以为设了 10 秒，实际拿到 30 秒，且没有任何提示。
     * 仓内就有两处这样写的调用（cross-lang-e2e、verify-seed-agent）。
     */
    opts: number | {
      scope?: QueryContent['scope'];
      sessionId?: string;
      /** 请求对方以**流式**返回（若对方不支持则自动退化为单帧，结果不变） */
      stream?: boolean;
      /**
       * 收到增量分片时实时回调 —— 这是"低延迟体感"的入口：
       * 调用方可以在第一个 token 到达时就开始渲染，而不是等全文拼完。
       *
       * 未提供时仍可配合 `stream: true` 使用，此时分片会被静默累积，
       * 最终一次性返回（与普通查询等价，但传输分段）。
       */
      onDelta?: (delta: string, seq: number) => void;
      /**
       * 流式**空闲**超时（毫秒）：两帧之间的最大允许间隔，默认 30000。
       *
       * 为什么需要它：流式回答可能持续数分钟。若沿用 `timeoutMs`
       * （总时长上限），一个正常的长回答会被中途杀掉。
       * 语义差异：总时长 → 帧间间隔。
       */
      streamIdleTimeoutMs?: number;
      extensions?: Record<string, unknown>;
      timeoutMs?: number;
    } = {}
  ): Promise<string> {
    // 归一化：数字简写 → { timeoutMs }
    const options = typeof opts === 'number' ? { timeoutMs: opts } : opts;
    if (opts !== undefined && typeof opts !== 'number' && (typeof opts !== 'object' || opts === null)) {
      throw new TypeError(
        `query() 第三个参数应为选项对象或超时毫秒数，收到 ${typeof opts}。` +
          `（拒绝静默忽略非法参数 —— 那会让调用方以为超时生效其实没有）`
      );
    }
    if (!this.ws || !this.connected) throw new Error('Not connected');

    const content: Record<string, unknown> = { query: queryText };
    if (options.scope) content.scope = options.scope;
    if (options.sessionId) content.session_id = options.sessionId;
    const wantStream = options.stream === true || typeof options.onDelta === 'function';
    if (wantStream) content.stream = true;
    // 端到端加密：整块 content 换成一个 AEAD 信封
    const finalContent = this.encryptContent
      ? ((await encryptFor(targetAddress, JSON.stringify(content))) as unknown as Record<string, unknown>)
      : content;
    const msg = buildMessage(
      {
        from: this.address,
        to: targetAddress,
        type: 'query',
        content: finalContent,
        extensions: options.extensions,
      },
      this.keyPair.privateKey
    );
    if (!this.canSend()) {
      throw new Error('Not connected: cannot send query');
    }
    return this.sendAndWait(msg, options.timeoutMs ?? this.requestTimeoutMs, {
      onDelta: options.onDelta,
      idleTimeoutMs: wantStream ? (options.streamIdleTimeoutMs ?? 30_000) : undefined,
    });
  }

  async ping(targetAddress: string, timeoutMs = 10_000): Promise<string> {
    if (!this.canSend()) throw new Error('Not connected');
    const msg = buildPing(this.address, targetAddress, this.keyPair.privateKey);
    return this.sendAndWait(msg, timeoutMs);
  }

  private sendAndWait(
    msg: A2Message,
    timeoutMs: number,
    streamOpts: { onDelta?: (delta: string, seq: number) => void; idleTimeoutMs?: number } = {}
  ): Promise<string> {
    return this.sendAndWaitWithRetry(msg, timeoutMs, 0, streamOpts);
  }

  /**
   * 带重试的请求等待。
   *
   * 重试时**复用同一个 msg.id**：这样即使第一次请求其实已送达并执行、
   * 只是响应帧丢失，下游的去重（中继 seenMessages / 接收方 seenIds）
   * 也能抑制重复执行。
   *
   * 但必须诚实说明：**端到端的响应去重并不完备** —— 若接收方已把响应
   * 发出、去重表正好过期，重试仍可能造成重复执行。因此默认
   * `retryOnTimeout = 0`（不重试），由使用方按能力幂等性自行开启。
   */
  private sendAndWaitWithRetry(
    msg: A2Message,
    timeoutMs: number,
    attempt: number,
    streamOpts: { onDelta?: (delta: string, seq: number) => void; idleTimeoutMs?: number } = {}
  ): Promise<string> {
    const promise = new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(msg.id);

        // 仅在「仍处于连接态」且还有重试预算时重试。
        // 若已断连，说明不是单帧丢失，重试也无意义 —— 直接失败。
        if (attempt < this.retryOnTimeout && this.connected) {
          setTimeout(() => {
            if (!this.connected) {
              reject(new Error(`Request timeout (${ErrorCode.TIMEOUT})`));
              return;
            }
            this.sendAndWaitWithRetry(msg, timeoutMs, attempt + 1, streamOpts).then(resolve, reject);
          }, this.retryDelayMs);
          return;
        }

        reject(new Error(`Request timeout (${ErrorCode.TIMEOUT})`));
      }, timeoutMs);
      this.pending.set(msg.id, {
        resolve,
        reject,
        timer,
        onDelta: streamOpts.onDelta,
        idleTimeoutMs: streamOpts.idleTimeoutMs,
      });
      this.sendRaw(msg);
    });

    // 防止「库内部产生的拒绝」打挂宿主进程：
    // 断连时会 rejectAllPending，若调用方没有 await（例如 fire-and-forget 调用，
    // 或已自行超时放弃），该拒绝就会成为 unhandledRejection。
    // 库不应因为调用方的使用方式而影响整个进程 —— 挂一个静默 catch，
    // 同时把原 Promise 返回给调用方（它们仍能正常 await/catch）。
    promise.catch(() => {
      /* 静默：调用方若关心结果会自行 catch */
    });
    return promise;
  }

  private sendRaw(msg: A2Message): void {
    this.ws?.send(JSON.stringify(msg));
  }

  /** 是否处于可发送状态（连接已建立且套接字可写） */
  private canSend(): boolean {
    return this.connected && this.ws !== null && this.ws.readyState === 1; // 1 = OPEN
  }

  private async handleMessage(msg: A2Message): Promise<void> {
    // 中继直接回传的控制平面错误（如 4041 目标离线、4032 配额超限），直接响应匹配的 pending 请求
    const replyTo = (msg.content as any)?.reply_to;
    if (msg.type === 'error' && replyTo && this.pending.has(replyTo)) {
      this.handleReply(msg);
      return;
    }

    const code = validateMessage(msg, { seenIds: this.seenIds });
    if (code !== null) {
      this.emit('invalid-message', { code, msg });
      return;
    }
    this.markSeen(msg.id);

    // 端到端解密：中继转发的 content 可能是密文信封
    if (isEncrypted(msg.content)) {
      try {
        const plain = await decryptFrom(msg.from, msg.content, this.keyPair.privateKey);
        msg.content = JSON.parse(plain) as Record<string, unknown>;
        msg.extensions = { ...(msg.extensions ?? {}), e2ee: true };
        this.emit('decrypted', { from: msg.from });
      } catch (e) {
        this.emit('decrypt-error', { from: msg.from, error: e });
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
    // 简单 LRU：保留最近 10000 条
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

    const wantsStream = (msg.content as unknown as QueryContent).stream === true;

    if (!this.queryHandler && !(wantsStream && this.streamQueryHandler)) {
      const err = await buildError(msg, ErrorCode.INTERNAL, 'No query handler', this.keyPair.privateKey);
      this.sendRaw(err);
      return;
    }

    const rawQuery = (msg.content as unknown as QueryContent).query;

    // ── 流式路径 ──
    // 仅在「对方要求流式」且「本机注册了流式处理器」时启用。
    // 任一不满足则回落到单帧响应 —— 保证对老实现与新实现都兼容。
    if (wantsStream && this.streamQueryHandler) {
      await this.runStreamingQuery(msg, rawQuery);
      return;
    }

    try {
      const out = await this.queryHandler!(rawQuery, msg.from, msg);
      const result = typeof out === 'string' ? out : out.result;
      const metadata = typeof out === 'string' ? undefined : out.metadata;
      let resp = await buildResponse(msg, result, this.keyPair.privateKey, metadata);
      // 对方用了加密就回加密，或本机开启了加密
      if (this.encryptContent || msg.extensions?.e2ee === true) {
        const enc = (await encryptFor(msg.from, JSON.stringify(resp.content))) as unknown as Record<
          string,
          unknown
        >;
        resp = buildMessage(
          { from: resp.from, to: resp.to, type: 'response', content: enc },
          this.keyPair.privateKey
        );
      }
      this.sendRaw(resp);
    } catch (e) {
      const err = await buildError(
        msg,
        ErrorCode.INTERNAL,
        e instanceof Error ? e.message : String(e),
        this.keyPair.privateKey
      );
      this.sendRaw(err);
    }
  }

  /**
   * 执行流式查询：逐块发出 `response`（`metadata.seq` 递增），最后发终止帧。
   *
   * 分帧约定：
   *   · 增量帧：`{ reply_to, result: <本块文本>, metadata: { seq, done: false } }`
   *   · 终止帧：`{ reply_to, result: '',    metadata: { seq, done: true } }`
   *
   * 为什么终止帧的 result 是**空串**而不是完整文本：
   *   接收侧会把所有带 seq 的帧按序拼接（含终止帧）。若终止帧携带完整文本，
   *   拼接结果会把全文追加一遍 —— 静默产出错误结果。空串让拼接恒等式成立：
   *     delta_0 + delta_1 + ... + delta_n + '' === 全文
   *
   * 中途出错：发终止帧并在 metadata 中带 error，而不是发 error 帧 ——
   *   让接收侧能以**确定的方式**结束流（拿到已收到的部分 + 明确失败原因）。
   */
  private async runStreamingQuery(msg: A2Message, rawQuery: string): Promise<void> {
    const useE2ee = this.encryptContent || msg.extensions?.e2ee === true;
    let seq = 0;
    let emitted = 0;

    const sendFrame = async (result: string, done: boolean, error?: string): Promise<void> => {
      const metadata: ResponseContent['metadata'] = { seq, done };
      if (error) (metadata as Record<string, unknown>).error = error;
      let resp = await buildResponse(msg, result, this.keyPair.privateKey, metadata);
      if (useE2ee) {
        const enc = (await encryptFor(msg.from, JSON.stringify(resp.content))) as unknown as Record<string, unknown>;
        resp = buildMessage(
          { from: resp.from, to: resp.to, type: 'response', content: enc },
          this.keyPair.privateKey
        );
      }
      this.sendRaw(resp);
      seq++;
    };

    const emit: StreamEmit = async (delta: string) => {
      if (delta.length === 0) return; // 空增量无意义，且会让 seq 虚增
      await sendFrame(delta, false);
      emitted += delta.length;
    };

    try {
      await this.streamQueryHandler!(rawQuery, msg.from, emit, msg);
      await sendFrame('', true);
      this.emit('stream-complete', { to: msg.from, bytes: emitted });
    } catch (e) {
      const reason = e instanceof Error ? e.message : String(e);
      // 用终止帧而非 error 帧收尾：接收侧已经拿到了部分内容，
      // 发 error 帧会让那些内容被丢弃，且流的结束语义不明确。
      await sendFrame('', true, reason);
      this.emit('stream-error', { to: msg.from, error: reason, bytes: emitted });
    }
  }

  private handleReply(msg: A2Message): void {
    const replyTo = (msg.content as unknown as ResponseContent).reply_to;
    const req = this.pending.get(replyTo);
    if (!req) return;

    if (msg.type === 'response') {
      const rc = msg.content as unknown as ResponseContent;
      const meta = rc.metadata;

      // 流式帧：实时投递增量（这是"低延迟体感"的关键 —— 调用方
      // 能在第一个 token 到达时就渲染，而不是等全文拼完）
      if (meta && typeof meta.seq === 'number' && meta.done !== true) {
        req.chunks = req.chunks ?? new Map();
        req.chunks.set(meta.seq, rc.result);
        req.streaming = true;
        req.lastSeq = meta.seq;

        // 空闲超时：每收到一帧就重置计时。
        // 为什么必须这样：流式响应可以持续数分钟（LLM 长回答），
        // 若沿用固定的 requestTimeoutMs，一个正常的长回答会被中途杀掉。
        // 语义从"总时长上限"改为"两帧之间的最大间隔"。
        if (req.idleTimeoutMs) {
          clearTimeout(req.timer);
          req.timer = setTimeout(() => {
            this.pending.delete(replyTo);
            const partial = req.chunks
              ? [...req.chunks.entries()].sort((a, b) => a[0] - b[0]).map(([, v]) => v).join('')
              : '';
            const e = new Error(
              `Stream idle timeout: 超过 ${req.idleTimeoutMs}ms 未收到新的分片（已收到 ${partial.length} 字符）`
            );
            (e as Error & { partial?: string }).partial = partial;
            req.reject(e);
          }, req.idleTimeoutMs);
        }

        try {
          req.onDelta?.(rc.result, meta.seq);
        } catch {
          // 回调异常不应影响协议流程
        }
        return; // 等待终止帧
      }

      // 终止帧：带 seq 的收尾（含中途失败的 error 标记）
      if (meta && typeof meta.seq === 'number' && req.chunks && req.chunks.size > 0) {
        req.chunks.set(meta.seq, rc.result);
        const sorted = [...req.chunks.entries()].sort((a, b) => a[0] - b[0]).map(([, v]) => v);
        const full = sorted.join('');
        clearTimeout(req.timer);
        this.pending.delete(replyTo);
        const streamErr = (meta as Record<string, unknown>).error;
        if (typeof streamErr === 'string' && streamErr) {
          // 部分内容 + 明确失败原因：两者都给调用方，不静默丢弃已收到的部分
          const e = new Error(`Stream failed after ${full.length} chars: ${streamErr}`);
          (e as Error & { partial?: string }).partial = full;
          req.reject(e);
          return;
        }
        req.resolve(full);
        return;
      }
      clearTimeout(req.timer);
      this.pending.delete(replyTo);
      req.resolve(rc.result);
    } else {
      const ec = msg.content as { code: number; message: string };
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

  private rejectAllPending(err: Error): void {
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(err);
    }
    this.pending.clear();
  }

  // -------------------------------------------------------------------------
  // 心跳
  // -------------------------------------------------------------------------

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.lastInboundAt = Date.now();
    this.heartbeatTimer = setInterval(() => {
      // 半开连接检测：长时间收不到**任何**入站帧即判定链路已死。
      //
      // WebSocket 在半开 TCP 下不会触发 close 事件，若只依赖 close 回调，
      // 客户端会永远以为自己还连着，所有请求都要等 requestTimeoutMs 才失败。
      // 这里主动断开，close 回调会负责 rejectAllPending + scheduleReconnect。
      const idleMs = Date.now() - this.lastInboundAt;
      if (idleMs >= this.heartbeatTimeoutMs) {
        const err = new Error(`Heartbeat timeout: ${idleMs}ms 无任何入站数据（疑似半开连接）`);
        this.emit('error', err);
        try {
          this.ws?.close();
        } catch {
          /* ignore */
        }
        return;
      }
      this.ws?.send(JSON.stringify({ type: 'ping', timestamp: Date.now() }));
    }, this.heartbeatIntervalMs);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }
}

// ---------------------------------------------------------------------------
// WebSocket 适配（Node / 浏览器）
// ---------------------------------------------------------------------------

function createWebSocket(url: string, impl?: WebSocketConstructor): WebSocket {
  if (impl) return new impl(url);
  if (typeof WebSocket !== 'undefined') return new WebSocket(url);
  throw new Error(
    'No WebSocket implementation available; pass `webSocketImpl` (e.g. the `ws` package) in Node'
  );
}
