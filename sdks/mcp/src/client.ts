/**
 * client.ts — MCP 客户端：初始化握手、能力协商、工具发现与调用
 */
import {
  HttpTransport,
  StdioTransport,
  type McpTransport,
  type McpTransportHandlers,
} from './transport.js';
import {
  LATEST_PROTOCOL_VERSION,
  JSON_RPC_ERRORS,
  isJsonRpcResponse,
  type JsonRpcMessage,
  type JsonRpcRequest,
  type McpInitializeResult,
  type McpListPromptsResult,
  type McpListResourcesResult,
  type McpListToolsResult,
  type McpPrompt,
  type McpResource,
  type McpServerConfig,
  type McpServerInfo,
  type McpTool,
  type McpToolCallResult,
} from './types.js';

export interface McpClientOptions {
  clientName?: string;
  clientVersion?: string;
  requestTimeoutMs?: number;
}

interface Pending {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

export class McpClient {
  private transport: McpTransport;
  private pending = new Map<string | number, Pending>();
  private nextId = 1;
  private initResult: McpInitializeResult | null = null;
  private notifications: ((method: string, params: unknown) => void)[] = [];
  private cachedTools: McpTool[] | null = null;

  constructor(
    private readonly config: McpServerConfig,
    private readonly options: McpClientOptions = {}
  ) {
    this.transport =
      config.transport === 'stdio'
        ? new StdioTransport({
            command: config.command,
            args: config.args,
            env: config.env,
            cwd: config.cwd,
          })
        : new HttpTransport({ url: config.url, headers: config.headers });
  }

  get serverInfo(): McpServerInfo | null {
    return this.initResult?.serverInfo ?? null;
  }

  get protocolVersion(): string | null {
    return this.initResult?.protocolVersion ?? null;
  }

  get capabilities(): McpInitializeResult['capabilities'] {
    return this.initResult?.capabilities ?? {};
  }

  /** 订阅服务端主动通知（notifications/*） */
  onNotification(handler: (method: string, params: unknown) => void): void {
    this.notifications.push(handler);
  }

  async connect(): Promise<McpInitializeResult> {
    const handlers: McpTransportHandlers = {
      onMessage: (msg) => this.handleMessage(msg),
      onError: (err) => this.failAll(err),
    };
    await this.transport.start(handlers);

    const result = (await this.request('initialize', {
      protocolVersion: LATEST_PROTOCOL_VERSION,
      capabilities: {
        roots: { listChanged: true },
        sampling: {},
      },
      clientInfo: {
        name: this.options.clientName ?? '@a2net/mcp',
        version: this.options.clientVersion ?? '0.1.0',
      },
    })) as McpInitializeResult;

    this.initResult = result;
    await this.notify('notifications/initialized', {});
    return result;
  }

  async listTools(): Promise<McpTool[]> {
    const tools: McpTool[] = [];
    let cursor: string | undefined;
    do {
      const res = (await this.request('tools/list', cursor ? { cursor } : {})) as McpListToolsResult;
      tools.push(...(res.tools ?? []));
      cursor = res.nextCursor;
    } while (cursor);
    this.cachedTools = tools;
    return tools;
  }

  /** 命中缓存时不再往返（tools/list 结果通常静态） */
  async getTools(forceRefresh = false): Promise<McpTool[]> {
    if (!forceRefresh && this.cachedTools) return this.cachedTools;
    return this.listTools();
  }

  async callTool(name: string, args: Record<string, unknown> = {}): Promise<McpToolCallResult> {
    const res = (await this.request('tools/call', {
      name,
      arguments: args,
    })) as McpToolCallResult;
    return res ?? { content: [] };
  }

  async listResources(): Promise<McpResource[]> {
    if (!this.capabilities.resources) return [];
    try {
      const res = (await this.request('resources/list', {})) as McpListResourcesResult;
      return res.resources ?? [];
    } catch {
      return [];
    }
  }

  async listPrompts(): Promise<McpPrompt[]> {
    if (!this.capabilities.prompts) return [];
    try {
      const res = (await this.request('prompts/list', {})) as McpListPromptsResult;
      return res.prompts ?? [];
    } catch {
      return [];
    }
  }

  async close(): Promise<void> {
    this.failAll(new Error('MCP client closed'));
    await this.transport.close();
  }

  // -------------------------------------------------------------------------
  // 内部：JSON-RPC 报文收发
  // -------------------------------------------------------------------------
  private handleMessage(msg: JsonRpcMessage): void {
    if (isJsonRpcResponse(msg)) {
      const pending = this.pending.get(msg.id as string | number);
      if (!pending) return;
      clearTimeout(pending.timer);
      this.pending.delete(msg.id as string | number);
      if (msg.error) {
        pending.reject(new Error(`MCP error ${msg.error.code}: ${msg.error.message}`));
      } else {
        pending.resolve(msg.result);
      }
      return;
    }
    // 服务端通知
    if ('method' in msg && !('id' in msg)) {
      for (const handler of this.notifications) handler(msg.method, msg.params);
    }
  }

  private request(method: string, params: unknown): Promise<unknown> {
    const id = this.nextId++;
    const payload: JsonRpcRequest = { jsonrpc: '2.0', id, method, params };
    const timeoutMs = this.options.requestTimeoutMs ?? 60_000;

    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`MCP request timeout after ${timeoutMs}ms: ${method}`));
      }, timeoutMs);
      timer.unref?.();
      this.pending.set(id, { resolve, reject, timer });
      this.transport.send(payload).catch((err) => {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(err instanceof Error ? err : new Error(String(err)));
      });
    });
  }

  private async notify(method: string, params: unknown): Promise<void> {
    try {
      await this.transport.send({ jsonrpc: '2.0', method, params } as JsonRpcMessage);
    } catch {
      // 通知失败不应中断初始化
    }
  }

  private failAll(err: Error): void {
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(err);
    }
    this.pending.clear();
  }
}

export { JSON_RPC_ERRORS };
