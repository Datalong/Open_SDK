/**
 * protocol.ts — A2Net 消息协议 v0.1
 *
 * 消息字段：id, from, to, type, content, timestamp, signature, extensions?
 * 签名规范见 crypto.getSignString / canonicalJson。
 */
import { getSignString, signMessage, verifySignature } from './crypto.js';

/** 生成 UUIDv4（浏览器与 Node 18+ 均支持的 crypto.randomUUID） */
function uuidv4(): string {
  return globalThis.crypto.randomUUID();
}

export type MessageType =
  | 'ping'
  | 'query'
  | 'response'
  | 'error'
  | 'blob_init'
  | 'blob_chunk'
  | 'blob_ack';

export const MESSAGE_TYPES: MessageType[] = [
  'ping',
  'query',
  'response',
  'error',
  'blob_init',
  'blob_chunk',
  'blob_ack',
];

/** 时间戳有效窗口：5 分钟 */
export const TIMESTAMP_WINDOW_MS = 5 * 60 * 1000;

export enum ErrorCode {
  FORMAT = 4001,
  SIGNATURE = 4002,
  PERMISSION = 4031,
  RATE_LIMIT = 4032,
  OFFLINE = 4041,
  INTERNAL = 5001,
  TIMEOUT = 5040,
}

export interface A2Message {
  id: string;
  from: string;
  to: string;
  type: MessageType;
  content: Record<string, unknown>;
  timestamp: number;
  signature: string;
  extensions?: Record<string, unknown>;
}

export interface QueryContent {
  query: string;
  scope?: {
    type?: 'knowledge' | 'tool' | 'task';
    max_tokens?: number;
    timeout?: number;
  };
  session_id?: string;
  stream?: boolean;
}

export interface ResponseContent {
  reply_to: string;
  result: string;
  metadata?: {
    source?: 'local_knowledge' | 'model' | 'tool';
    confidence?: number;
    seq?: number;
    done?: boolean;
    usage?: { tokens?: number };
  };
}

export interface ErrorContent {
  reply_to: string;
  code: number;
  message: string;
  retry_after?: number;
}

export class ProtocolError extends Error {
  constructor(public code: ErrorCode, message: string) {
    super(message);
    this.name = 'ProtocolError';
  }
}

export interface BuildMessageParams {
  from: string;
  to: string;
  type: MessageType;
  content: Record<string, unknown>;
  extensions?: Record<string, unknown>;
  /** 允许注入时间戳（测试用） */
  timestamp?: number;
}

/** 构造并签名消息 */
export function buildMessage(params: BuildMessageParams, privateKey: Uint8Array): A2Message {
  if (!MESSAGE_TYPES.includes(params.type)) {
    throw new ProtocolError(ErrorCode.FORMAT, `Invalid message type: ${params.type}`);
  }
  const msg: A2Message = {
    id: uuidv4(),
    from: params.from,
    to: params.to,
    type: params.type,
    content: params.content,
    timestamp: params.timestamp ?? Date.now(),
    signature: '',
  };
  if (params.extensions) msg.extensions = params.extensions;
  msg.signature = signMessage(getSignString(msg as unknown as Record<string, unknown>), privateKey);
  return msg;
}

export interface ValidateOptions {
  /** 已见过的消息 id 集合（重放防护），若提供则检查 */
  seenIds?: Set<string>;
  /** 允许的时间偏差，默认 TIMESTAMP_WINDOW_MS */
  windowMs?: number;
  now?: number;
}

/**
 * 校验消息：字段完整性 → 时间窗 → 签名。
 * 返回 ErrorCode 或 null（通过）。注意：不做重放去重，调用方用 seenIds 决定。
 */
export function validateMessage(msg: unknown, opts: ValidateOptions = {}): ErrorCode | null {
  if (typeof msg !== 'object' || msg === null) return ErrorCode.FORMAT;
  const m = msg as Record<string, unknown>;

  const required = ['id', 'from', 'to', 'type', 'content', 'timestamp', 'signature'];
  for (const f of required) {
    if (!(f in m)) return ErrorCode.FORMAT;
  }
  if (typeof m.id !== 'string' || typeof m.from !== 'string' || typeof m.to !== 'string') {
    return ErrorCode.FORMAT;
  }
  if (typeof m.signature !== 'string' || typeof m.timestamp !== 'number') {
    return ErrorCode.FORMAT;
  }
  if (!MESSAGE_TYPES.includes(m.type as MessageType)) return ErrorCode.FORMAT;
  if (typeof m.content !== 'object' || m.content === null) return ErrorCode.FORMAT;

  const now = opts.now ?? Date.now();
  const windowMs = opts.windowMs ?? TIMESTAMP_WINDOW_MS;
  if (Math.abs(now - m.timestamp) > windowMs) return ErrorCode.SIGNATURE;

  if (opts.seenIds?.has(m.id)) return ErrorCode.SIGNATURE;

  const signStr = getSignString(m);
  const ok = verifySignature(signStr, m.signature, m.from);
  return ok ? null : ErrorCode.SIGNATURE;
}

// ---------------------------------------------------------------------------
// 便捷构造器
// ---------------------------------------------------------------------------

export function buildQuery(
  from: string,
  to: string,
  queryText: string,
  privateKey: Uint8Array,
  opts: { scope?: QueryContent['scope']; sessionId?: string; stream?: boolean; extensions?: Record<string, unknown> } = {}
): A2Message {
  const content: Record<string, unknown> = { query: queryText };
  if (opts.scope) content.scope = opts.scope;
  if (opts.sessionId) content.session_id = opts.sessionId;
  if (opts.stream) content.stream = true;
  return buildMessage({ from, to, type: 'query', content, extensions: opts.extensions }, privateKey);
}

export function buildResponse(
  request: A2Message,
  result: string,
  privateKey: Uint8Array,
  metadata?: ResponseContent['metadata']
): A2Message {
  const content: Record<string, unknown> = { reply_to: request.id, result };
  if (metadata) content.metadata = metadata;
  return buildMessage({ from: request.to, to: request.from, type: 'response', content }, privateKey);
}

export function buildError(
  request: A2Message,
  code: ErrorCode,
  message: string,
  privateKey: Uint8Array,
  retryAfter?: number
): A2Message {
  const content: Record<string, unknown> = { reply_to: request.id, code, message };
  if (retryAfter !== undefined) content.retry_after = retryAfter;
  return buildMessage({ from: request.to, to: request.from, type: 'error', content }, privateKey);
}

export function buildPing(
  from: string,
  to: string,
  privateKey: Uint8Array,
  capabilities: string[] = []
): A2Message {
  return buildMessage(
    { from, to, type: 'ping', content: { nonce: uuidv4(), capabilities } },
    privateKey
  );
}

export function buildBlobInit(
  from: string,
  to: string,
  content: Record<string, unknown>,
  privateKey: Uint8Array,
  extensions?: Record<string, unknown>
): A2Message {
  return buildMessage(
    { from, to, type: 'blob_init', content, extensions },
    privateKey
  );
}

export function buildBlobChunk(
  from: string,
  to: string,
  content: Record<string, unknown>,
  privateKey: Uint8Array,
  extensions?: Record<string, unknown>
): A2Message {
  return buildMessage(
    { from, to, type: 'blob_chunk', content, extensions },
    privateKey
  );
}

export function buildBlobAck(
  from: string,
  to: string,
  ack: Record<string, unknown>,
  privateKey: Uint8Array
): A2Message {
  return buildMessage(
    { from, to, type: 'blob_ack', content: ack },
    privateKey
  );
}
