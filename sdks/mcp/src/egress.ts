/**
 * egress.ts — A2Net → MCP 出口服务（A2NetMcpServer）
 *
 * 把 A2Net 去中心化智能体网络暴露为标准 MCP Server，使 Claude Desktop / Cursor /
 * Cline 等任意 MCP 客户端都能直接检索与调用全网 Agent（链路自动 E2EE）。
 *
 * 内置工具：
 *   a2net_identity       查看/获取本机 A2Net 身份与连接状态
 *   a2net_list_agents    检索公开名录（关键词 / 能力 / 仅看企业蓝 V）
 *   a2net_get_agent_card 按 URL 或 DID 拉取并验签 Agent Card
 *   a2net_invoke_agent   向指定 DID 发起 E2EE 查询
 *
 * 可选：exposeAgents=true 时把名录中每个 Agent 动态暴露为一个独立工具。
 */
import readline from 'node:readline';
import WebSocket from 'ws';
import {
  A2NetClient,
  DirectoryClient,
  generateKeyPair,
  keyPairFromPrivateKey,
  resolveAgentCard,
  verifyAgentCard,
  type AgentCard,
  type DirectoryEntry,
  type PermissionPolicy,
} from '@a2net/client';
import {
  JSON_RPC_ERRORS,
  LATEST_PROTOCOL_VERSION,
  type JsonRpcMessage,
  type JsonRpcRequest,
  type McpContent,
  type McpTool,
  type McpToolCallResult,
} from './types.js';

export interface A2NetMcpServerConfig {
  /** A2Net 中继地址 */
  relayUrl: string;
  /** 名录地址（用于 a2net_list_agents） */
  directoryUrl?: string;
  /** 名录 API Key */
  directoryApiKey?: string;
  /** 商业中继 API Key */
  apiKey?: string;
  /** 身份私钥；省略则随机生成（仅本次会话有效，仅用于发起调用） */
  privateKey?: Uint8Array;
  /** 是否开启 E2EE（默认 true） */
  encryptContent?: boolean;
  /** 服务端展示名 */
  serverName?: string;
  /** 是否把名录中的 Agent 动态暴露为独立工具 */
  exposeAgents?: boolean;
  /** 动态工具数量上限 */
  maxExposedAgents?: number;
  /** 默认调用超时（毫秒） */
  invokeTimeoutMs?: number;
  /** 权限策略（本端作为服务端时的入站策略） */
  permissionPolicy?: PermissionPolicy;
}

const TOOLS: McpTool[] = [
  {
    name: 'a2net_identity',
    description:
      '查看本机 A2Net 身份（DID）、中继连接状态与已配置的名录地址。返回本 Agent 的 did:key 地址。',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'a2net_list_agents',
    description:
      '检索 A2Net 全网公开智能体名录。可按关键词、能力标签过滤，或只看已获企业蓝 V / 官方金标认证的 Agent。',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: '对名称与描述的模糊关键词' },
        capability: { type: 'string', description: '能力标签，例如 image.generation.v1' },
        verifiedOnly: { type: 'boolean', description: '仅返回通过组织认证（蓝 V / 金标）的 Agent' },
        limit: { type: 'number', description: '返回条数上限，默认 10' },
      },
      required: [],
    },
  },
  {
    name: 'a2net_get_agent_card',
    description:
      '拉取并密码学验签指定 Agent 的 Agent Card。可传入 .well-known 卡片 URL，或直接传入 did:key 由名录反查。',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'Agent Card 的 .well-known/agent-description.json 地址' },
        did: { type: 'string', description: 'did:key 地址（由名录反查卡片）' },
      },
      required: [],
    },
  },
  {
    name: 'a2net_invoke_agent',
    description:
      '向指定 A2Net Agent 发起端到端加密（X25519-AES-256-GCM）查询并返回其解密响应。中继只转发密文。',
    inputSchema: {
      type: 'object',
      properties: {
        did: { type: 'string', description: '目标 Agent 的 did:key 地址' },
        message: { type: 'string', description: '要发送的查询内容' },
        timeoutMs: { type: 'number', description: '超时毫秒数，默认 30000' },
      },
      required: ['did', 'message'],
    },
  },
];

function text(content: string): McpToolCallResult {
  return { content: [{ type: 'text', text: content }] };
}

function errorText(content: string): McpToolCallResult {
  return { content: [{ type: 'text', text: content }], isError: true };
}

export class A2NetMcpServer {
  private a2net: A2NetClient | null = null;
  private connecting: Promise<A2NetClient> | null = null;
  private directory: DirectoryClient | null = null;
  private dynamicAgents: DirectoryEntry[] = [];
  private closed = false;

  constructor(private readonly cfg: A2NetMcpServerConfig) {
    if (cfg.directoryUrl) {
      this.directory = new DirectoryClient(cfg.directoryUrl, { apiKey: cfg.directoryApiKey });
    }
  }

  // -------------------------------------------------------------------------
  // MCP 协议处理（与传输无关，便于单测）
  // -------------------------------------------------------------------------
  async handleMessage(msg: JsonRpcMessage): Promise<JsonRpcMessage | null> {
    if (!('method' in msg) || !('id' in msg)) return null; // 通知无需响应
    const req = msg as JsonRpcRequest;
    try {
      switch (req.method) {
        case 'initialize':
          return this.ok(req.id, {
            protocolVersion: LATEST_PROTOCOL_VERSION,
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: this.cfg.serverName ?? 'a2net-mcp', version: '0.1.0' },
            instructions:
              'A2Net 是一个去中心化智能体互通网络。使用 a2net_list_agents 发现智能体，' +
              '再用 a2net_invoke_agent 通过端到端加密调用它们。所有消息中继只看到密文。',
          });
        case 'notifications/initialized':
        case 'notifications/cancelled':
          return null;
        case 'ping':
          return this.ok(req.id, {});
        case 'tools/list':
          return this.ok(req.id, { tools: await this.listTools() });
        case 'tools/call':
          return this.ok(req.id, await this.callTool(req.params as never));
        default:
          return this.err(req.id, JSON_RPC_ERRORS.METHOD_NOT_FOUND, `Method not found: ${req.method}`);
      }
    } catch (e) {
      return this.err(req.id, JSON_RPC_ERRORS.INTERNAL_ERROR, (e as Error).message);
    }
  }

  private ok(id: JsonRpcRequest['id'], result: unknown): JsonRpcMessage {
    return { jsonrpc: '2.0', id, result } as JsonRpcMessage;
  }

  private err(id: JsonRpcRequest['id'], code: number, message: string): JsonRpcMessage {
    return { jsonrpc: '2.0', id, error: { code, message } } as JsonRpcMessage;
  }

  async listTools(): Promise<McpTool[]> {
    if (!this.cfg.exposeAgents) return TOOLS;
    await this.refreshDynamicAgents();
    const max = this.cfg.maxExposedAgents ?? 25;
    const dynamic: McpTool[] = this.dynamicAgents.slice(0, max).map((entry) => ({
      name: `a2net_agent_${entry.card.name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 32) || entry.card.did.slice(-8)}`,
      description: `调用 A2Net 智能体「${entry.card.name}」：${entry.card.description ?? ''}`.slice(0, 400),
      inputSchema: {
        type: 'object' as const,
        properties: { message: { type: 'string', description: '发送给该 Agent 的查询内容' } },
        required: ['message'],
      },
    }));
    // 名称去重
    const seen = new Set(TOOLS.map((t) => t.name));
    return [...TOOLS, ...dynamic.filter((t) => !seen.has(t.name))];
  }

  async callTool(params: { name: string; arguments?: Record<string, unknown> }): Promise<McpToolCallResult> {
    const args = params.arguments ?? {};

    if (this.cfg.exposeAgents && params.name.startsWith('a2net_agent_')) {
      const entry = await this.findExposedAgent(params.name);
      if (!entry) return errorText(`未知的已暴露 Agent 工具: ${params.name}`);
      return this.invokeAgent(entry.card.did, String(args.message ?? ''), args.timeoutMs as number);
    }

    switch (params.name) {
      case 'a2net_identity':
        return text(await this.describeIdentity());
      case 'a2net_list_agents':
        return this.listAgents(args);
      case 'a2net_get_agent_card':
        return this.getAgentCard(args);
      case 'a2net_invoke_agent':
        return this.invokeAgent(
          String(args.did ?? ''),
          String(args.message ?? ''),
          args.timeoutMs as number
        );
      default:
        return errorText(`未知工具: ${params.name}`);
    }
  }

  // -------------------------------------------------------------------------
  // 工具实现
  // -------------------------------------------------------------------------
  private async describeIdentity(): Promise<string> {
    const lines: string[] = [];
    try {
      const client = await this.ensureConnected();
      lines.push(`DID: ${client.address}`);
      lines.push(`中继: ${this.cfg.relayUrl}`);
      lines.push(`连接状态: ${client.isConnected ? '已连接' : '未连接'}`);
    } catch (e) {
      lines.push(`连接失败: ${(e as Error).message}`);
      lines.push(`中继: ${this.cfg.relayUrl}`);
    }
    lines.push(`名录: ${this.cfg.directoryUrl ?? '（未配置）'}`);
    lines.push(`E2EE: ${this.cfg.encryptContent ?? true ? '已启用' : '已关闭'}`);
    return lines.join('\n');
  }

  private async listAgents(args: Record<string, unknown>): Promise<McpToolCallResult> {
    if (!this.directory) {
      return errorText('未配置名录地址（directoryUrl），无法检索 Agent。');
    }
    const limit = typeof args.limit === 'number' ? args.limit : 10;
    const res = await this.directory.search({
      q: typeof args.query === 'string' ? args.query : undefined,
      capability: typeof args.capability === 'string' ? args.capability : undefined,
      verifiedOnly: args.verifiedOnly === true,
      limit,
    });
    this.dynamicAgents = res.agents;

    if (res.agents.length === 0) {
      return text('未检索到匹配的 Agent。');
    }
    const lines = res.agents.map((entry) => {
      const c = entry.card;
      const badge = entry.verifiedOrg
        ? ` [${entry.verifiedOrg.badge === 'gold_v' ? '🥇 官方金标' : '🔷 企业蓝V'} ${entry.verifiedOrg.organizationName}]`
        : '';
      const caps = (c.capabilities ?? []).slice(0, 4).join(', ');
      const price = c.pricing ? ` · ${c.pricing.amount} ${c.pricing.unit}/次` : '';
      return `• ${c.name}${badge}\n  DID: ${c.did}\n  能力: ${caps}${price}\n  ${c.description ?? ''}`;
    });
    return text(`共 ${res.agents.length} 个 Agent：\n\n${lines.join('\n\n')}`);
  }

  private async getAgentCard(args: Record<string, unknown>): Promise<McpToolCallResult> {
    let card: AgentCard | null = null;

    if (typeof args.url === 'string' && args.url) {
      try {
        card = await resolveAgentCard(args.url);
      } catch (e) {
        return errorText(`拉取或验签失败: ${(e as Error).message}`);
      }
    } else if (typeof args.did === 'string' && args.did) {
      if (!this.directory) return errorText('未配置名录地址，无法按 DID 反查卡片。');
      const entry = await this.directory.get(args.did);
      if (!entry) return errorText(`名录中未找到 ${args.did}`);
      card = entry.card;
      if (!verifyAgentCard(card)) return errorText('名录返回的卡片签名无效。');
    } else {
      return errorText('请提供 url 或 did 参数之一。');
    }

    return text(JSON.stringify(card, null, 2));
  }

  private async invokeAgent(did: string, message: string, timeoutMs?: number): Promise<McpToolCallResult> {
    if (!did) return errorText('缺少 did 参数。');
    if (!message) return errorText('缺少 message 参数。');
    try {
      const client = await this.ensureConnected();
      const timeout = typeof timeoutMs === 'number' && timeoutMs > 0 ? timeoutMs : this.cfg.invokeTimeoutMs ?? 30_000;
      const reply = await client.query(did, message, { timeoutMs: timeout });
      return text(reply);
    } catch (e) {
      return errorText(`调用 ${did} 失败: ${(e as Error).message}`);
    }
  }

  // -------------------------------------------------------------------------
  // 连接管理
  // -------------------------------------------------------------------------
  private async ensureConnected(): Promise<A2NetClient> {
    if (this.a2net?.isConnected) return this.a2net;
    if (this.connecting) return this.connecting;

    this.connecting = (async () => {
      const keyPair = this.cfg.privateKey
        ? keyPairFromPrivateKey(this.cfg.privateKey)
        : generateKeyPair();
      const client = new A2NetClient({
        relayUrl: this.cfg.relayUrl,
        apiKey: this.cfg.apiKey,
        privateKey: keyPair.privateKey,
        encryptContent: this.cfg.encryptContent ?? true,
        permissionPolicy:
          this.cfg.permissionPolicy ?? { defaultAllow: false, whitelist: [], blacklist: [] },
        webSocketImpl: WebSocket as unknown as typeof globalThis.WebSocket,
      });
      await client.connect();
      this.a2net = client;
      this.connecting = null;
      return client;
    })();

    return this.connecting;
  }

  private async refreshDynamicAgents(): Promise<void> {
    if (!this.directory) return;
    try {
      const res = await this.directory.search({ limit: this.cfg.maxExposedAgents ?? 25 });
      this.dynamicAgents = res.agents;
    } catch {
      /* 名录不可达时保留旧快照 */
    }
  }

  private async findExposedAgent(toolName: string): Promise<DirectoryEntry | undefined> {
    const tools = await this.listTools();
    const idx = tools.findIndex((t) => t.name === toolName);
    if (idx === -1) return undefined;
    const base = TOOLS.length;
    return this.dynamicAgents[idx - base];
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.a2net?.disconnect();
    this.a2net = null;
  }
}

/**
 * 以 stdio 方式运行 A2Net MCP Server（供 Claude Desktop / Cursor 等客户端拉起）。
 * MCP stdio 传输为「换行分隔的 JSON-RPC 2.0」。
 */
export async function serveA2NetMcpStdio(cfg: A2NetMcpServerConfig): Promise<void> {
  const server = new A2NetMcpServer(cfg);
  const rl = readline.createInterface({ input: process.stdin, terminal: false });

  const write = (msg: JsonRpcMessage) => {
    process.stdout.write(JSON.stringify(msg) + '\n');
  };

  // 跟踪在途请求，保证 stdin 关闭时响应能先落盘再退出
  const inflight = new Set<Promise<void>>();

  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let parsed: JsonRpcMessage;
    try {
      parsed = JSON.parse(trimmed) as JsonRpcMessage;
    } catch {
      write({
        jsonrpc: '2.0',
        id: null,
        error: { code: JSON_RPC_ERRORS.PARSE_ERROR, message: 'Invalid JSON' },
      } as JsonRpcMessage);
      return;
    }
    const task = server
      .handleMessage(parsed)
      .then((res) => {
        if (res) write(res);
      })
      .catch((e: unknown) => {
        const id = 'id' in parsed ? (parsed as JsonRpcRequest).id : null;
        write({
          jsonrpc: '2.0',
          id,
          error: { code: JSON_RPC_ERRORS.INTERNAL_ERROR, message: (e as Error).message },
        } as JsonRpcMessage);
      })
      .finally(() => inflight.delete(task));
    inflight.add(task);
  });

  let shuttingDown = false;
  const shutdown = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    // 等待在途请求完成（最多 10s）
    if (inflight.size > 0) {
      await Promise.race([
        Promise.allSettled([...inflight]),
        new Promise((resolve) => setTimeout(resolve, 10_000)),
      ]);
    }
    await server.close().catch(() => undefined);
    process.exit(0);
  };

  process.on('SIGINT', () => void shutdown());
  process.on('SIGTERM', () => void shutdown());
  rl.on('close', () => void shutdown());

  // 保持进程存活
  await new Promise<void>(() => {
    /* 由 stdin 关闭或信号驱动退出 */
  });
}

export { TOOLS as A2NET_MCP_TOOLS, text as mcpText, errorText as mcpErrorText };
