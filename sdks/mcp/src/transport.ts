/**
 * transport.ts — MCP 传输层（stdio / Streamable HTTP）
 *
 * * stdio：以换行分隔的 JSON-RPC 帧与子进程通信（MCP 规范默认传输）。
 * * http ：Streamable HTTP —— POST JSON-RPC，响应可能为 application/json
 *           或 text/event-stream（SSE），逐事件解析直到拿到匹配 id 的响应。
 */
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import type { JsonRpcMessage } from './types.js';

export interface McpTransportHandlers {
  onMessage: (msg: JsonRpcMessage) => void;
  onError?: (err: Error) => void;
  onClose?: () => void;
}

export interface McpTransport {
  readonly kind: 'stdio' | 'http';
  start(handlers: McpTransportHandlers): Promise<void>;
  send(msg: JsonRpcMessage): Promise<void>;
  close(): Promise<void>;
}

// ---------------------------------------------------------------------------
// stdio
// ---------------------------------------------------------------------------
export interface StdioTransportOptions {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
}

export class StdioTransport implements McpTransport {
  readonly kind = 'stdio' as const;
  private child: ChildProcessWithoutNullStreams | null = null;
  private buffer = '';
  private handlers: McpTransportHandlers | null = null;
  private stderrTail: string[] = [];
  private closed = false;

  constructor(private readonly opts: StdioTransportOptions) {}

  /** 最近若干行 stderr（用于把 MCP server 的启动错误反馈给用户） */
  get recentStderr(): string {
    return this.stderrTail.join('\n');
  }

  async start(handlers: McpTransportHandlers): Promise<void> {
    this.handlers = handlers;

    const child = spawn(this.opts.command, this.opts.args ?? [], {
      cwd: this.opts.cwd,
      env: { ...process.env, ...(this.opts.env ?? {}) },
      stdio: ['pipe', 'pipe', 'pipe'],
    }) as ChildProcessWithoutNullStreams;

    this.child = child;

    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => this.onStdout(chunk));

    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => {
      for (const line of String(chunk).split('\n')) {
        if (!line.trim()) continue;
        this.stderrTail.push(line.trim());
        if (this.stderrTail.length > 50) this.stderrTail.shift();
      }
    });

    child.on('error', (err) => {
      handlers.onError?.(err instanceof Error ? err : new Error(String(err)));
    });

    child.on('close', (code) => {
      this.closed = true;
      if (code !== 0 && code !== null) {
        handlers.onError?.(
          new Error(
            `MCP stdio server exited with code ${code}${this.recentStderr ? `\n${this.recentStderr}` : ''}`
          )
        );
      }
      handlers.onClose?.();
    });

    // 等待进程真正 spawn（或立刻失败，如命令不存在）
    await new Promise<void>((resolve, reject) => {
      const onSpawn = () => {
        child.off('error', onError);
        resolve();
      };
      const onError = (err: Error) => {
        child.off('spawn', onSpawn);
        reject(err);
      };
      child.once('spawn', onSpawn);
      child.once('error', onError);
    });
  }

  private onStdout(chunk: string): void {
    this.buffer += chunk;
    let idx: number;
    while ((idx = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, idx).trim();
      this.buffer = this.buffer.slice(idx + 1);
      if (!line) continue;
      try {
        this.handlers?.onMessage(JSON.parse(line) as JsonRpcMessage);
      } catch {
        // 非 JSON 输出（部分 server 会打印日志到 stdout）——忽略
      }
    }
  }

  async send(msg: JsonRpcMessage): Promise<void> {
    if (!this.child || this.closed) throw new Error('MCP stdio transport is not running');
    this.child.stdin.write(JSON.stringify(msg) + '\n');
  }

  async close(): Promise<void> {
    if (!this.child) return;
    this.closed = true;
    const child = this.child;
    this.child = null;
    try {
      child.stdin.end();
    } catch {
      /* ignore */
    }
    if (!child.killed) {
      child.kill('SIGTERM');
      // 3 秒后仍未退出则强杀
      const timer = setTimeout(() => {
        try {
          child.kill('SIGKILL');
        } catch {
          /* ignore */
        }
      }, 3000);
      timer.unref?.();
    }
  }
}

// ---------------------------------------------------------------------------
// Streamable HTTP
// ---------------------------------------------------------------------------
export interface HttpTransportOptions {
  url: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
}

export class HttpTransport implements McpTransport {
  readonly kind = 'http' as const;
  private handlers: McpTransportHandlers | null = null;
  private sessionId?: string;

  constructor(private readonly opts: HttpTransportOptions) {}

  async start(handlers: McpTransportHandlers): Promise<void> {
    this.handlers = handlers;
  }

  async send(msg: JsonRpcMessage): Promise<void> {
    const isNotification = !('id' in msg);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      ...(this.opts.headers ?? {}),
    };
    if (this.sessionId) headers['Mcp-Session-Id'] = this.sessionId;

    const res = await fetch(this.opts.url, {
      method: 'POST',
      headers,
      body: JSON.stringify(msg),
      signal: AbortSignal.timeout(this.opts.timeoutMs ?? 60_000),
    });

    const sid = res.headers.get('mcp-session-id');
    if (sid) this.sessionId = sid;

    if (isNotification) return;

    if (!res.ok) {
      this.handlers?.onError?.(new Error(`MCP HTTP ${res.status} ${res.statusText}`));
      return;
    }

    const contentType = res.headers.get('content-type') ?? '';

    if (contentType.includes('text/event-stream') && res.body) {
      await this.consumeSse(res.body);
      return;
    }

    const text = await res.text();
    if (!text.trim()) return;
    try {
      this.handlers?.onMessage(JSON.parse(text) as JsonRpcMessage);
    } catch {
      // 有些实现把多条消息包成数组
      try {
        const arr = JSON.parse(text) as JsonRpcMessage[];
        if (Array.isArray(arr)) for (const m of arr) this.handlers?.onMessage(m);
      } catch {
        this.handlers?.onError?.(new Error(`Unparseable MCP HTTP response: ${text.slice(0, 200)}`));
      }
    }
  }

  private async consumeSse(body: ReadableStream<Uint8Array>): Promise<void> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let sep: number;
      // SSE 事件以空行分隔
      while ((sep = buffer.indexOf('\n\n')) !== -1 || (sep = buffer.indexOf('\r\n\r\n')) !== -1) {
        const rawEvent = buffer.slice(0, sep);
        buffer = buffer.slice(sep + (buffer[sep] === '\r' ? 4 : 2));
        for (const line of rawEvent.split(/\r?\n/)) {
          if (!line.startsWith('data:')) continue;
          const payload = line.slice(5).trim();
          if (!payload) continue;
          try {
            this.handlers?.onMessage(JSON.parse(payload) as JsonRpcMessage);
          } catch {
            /* ignore keep-alive / 非 JSON */
          }
        }
      }
    }
  }

  async close(): Promise<void> {
    // 无持久连接，无需处理
    this.handlers = null;
  }
}
