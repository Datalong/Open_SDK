/**
 * ingress.ts — MCP → A2Net 入口网卡（McpIngressAdapter）
 *
 * 把任意 MCP Server（stdio 子进程或 Streamable HTTP 端点）一键挂载为 A2Net Agent：
 *   * 自动派生/复用 did:key 身份，发布带 Ed25519 签名的 Agent Card；
 *   * 将 MCP 工具清单映射为 A2Net 能力标签；
 *   * 收到 A2Net E2EE 查询后路由到对应 MCP tools/call，并把结果规整为文本回传；
 *   * 可选自动登记到 A2Net 目录（Directory）。
 *
 * 入站查询协议（三种形式，见 bridge.parseQueryIntent）：
 *   {"tool":"read_file","arguments":{"path":"/etc/hosts"}}
 *   read_file {"path":"/etc/hosts"}
 *   __tools__          → 返回工具清单
 */
import WebSocket from 'ws';
import {
  A2NetClient,
  DirectoryClient,
  createAgentCard,
  generateKeyPair,
  keyPairFromPrivateKey,
  signAgentCard,
  type AgentCard,
  type KeyPair,
  type PermissionPolicy,
} from '@a2net/client';
import { McpClient } from './client.js';
import {
  mcpResultToText,
  parseQueryIntent,
  toolsToCapabilities,
  toolsToInformation,
  toolsToText,
} from './bridge.js';
import type { McpServerConfig, McpTool } from './types.js';

export interface McpIngressConfig {
  /** 被桥接的 MCP Server 配置 */
  mcp: McpServerConfig;
  /** A2Net 中继地址（ws:// 或 wss://） */
  relayUrl: string;
  /** 身份私钥（32 字节 Ed25519）；省略则每次启动随机生成 */
  privateKey?: Uint8Array;
  /** 商业中继 API Key（可选） */
  apiKey?: string;
  /** 是否开启端到端加密（默认 true） */
  encryptContent?: boolean;
  /** 权限策略（默认对外开放） */
  permissionPolicy?: PermissionPolicy;
  /** Agent 展示名（默认取 MCP serverInfo.name） */
  name?: string;
  /** Agent 描述（默认自动生成） */
  description?: string;
  /** 能力标签前缀（默认 'mcp'） */
  capabilityPrefix?: string;
  /** A2Net 目录地址（提供则自动登记） */
  directoryUrl?: string;
  /** 目录 API Key（可选） */
  directoryApiKey?: string;
  /** 定价策略（展示用） */
  pricing?: { unit: string; amount: number; model?: string };
  /** 单次工具调用超时（毫秒） */
  toolTimeoutMs?: number;
}

export interface McpIngressState {
  address: string;
  serverInfo: { name: string; version: string } | null;
  tools: McpTool[];
  card: AgentCard;
}

export class McpIngressAdapter {
  private mcp: McpClient;
  private a2net: A2NetClient | null = null;
  private keyPair: KeyPair;
  private tools: McpTool[] = [];
  private started = false;

  constructor(private readonly cfg: McpIngressConfig) {
    this.mcp = new McpClient(cfg.mcp, { requestTimeoutMs: cfg.toolTimeoutMs ?? 120_000 });
    this.keyPair = cfg.privateKey ? keyPairFromPrivateKey(cfg.privateKey) : generateKeyPair();
  }

  get address(): string {
    return this.keyPair.address;
  }

  get discoveredTools(): McpTool[] {
    return this.tools;
  }

  /** 启动桥接：连接 MCP → 发现工具 → 接入 A2Net → 可选登记目录 */
  async start(): Promise<McpIngressState> {
    if (this.started) throw new Error('McpIngressAdapter already started');

    const init = await this.mcp.connect();
    this.tools = await this.mcp.listTools();

    const card = this.buildCard();

    this.a2net = new A2NetClient({
      relayUrl: this.cfg.relayUrl,
      apiKey: this.cfg.apiKey,
      privateKey: this.keyPair.privateKey,
      encryptContent: this.cfg.encryptContent ?? true,
      permissionPolicy:
        this.cfg.permissionPolicy ?? { defaultAllow: true, whitelist: [], blacklist: [] },
      webSocketImpl: WebSocket as unknown as typeof globalThis.WebSocket,
    });

    this.a2net.onQuery(async (query, sender) => this.handleQuery(query, sender));
    await this.a2net.connect();

    if (this.cfg.directoryUrl) {
      await this.registerToDirectory(card);
    }

    this.started = true;
    return {
      address: this.keyPair.address,
      serverInfo: init.serverInfo ?? null,
      tools: this.tools,
      card,
    };
  }

  async stop(): Promise<void> {
    this.started = false;
    this.a2net?.disconnect();
    this.a2net = null;
    await this.mcp.close();
  }

  /** 构造（并签名）本 Agent 的 Agent Card */
  buildCard(): AgentCard {
    const serverInfo = this.mcp.serverInfo;
    const name = this.cfg.name ?? `MCP Bridge: ${serverInfo?.name ?? 'unknown'}`;
    const description =
      this.cfg.description ??
      `A2Net ↔ MCP 桥接智能体，暴露 ${this.tools.length} 个 MCP 工具（服务端 ${serverInfo?.name ?? 'unknown'} v${serverInfo?.version ?? '?'}）`;

    return signAgentCard(
      createAgentCard({
        did: this.keyPair.address,
        name,
        description,
        relay: this.cfg.relayUrl,
        capabilities: toolsToCapabilities(this.tools, this.cfg.capabilityPrefix ?? 'mcp'),
        information: toolsToInformation(this.tools),
        interfaces: [{ type: 'StructuredInterface', protocol: 'MCP', url: this.describeMcpEndpoint() }],
        pricing: this.cfg.pricing,
      }),
      this.keyPair
    );
  }

  /** 直接向 MCP 调用某个工具（供本地 CLI / 测试使用） */
  async callTool(name: string, args: Record<string, unknown> = {}): Promise<string> {
    const result = await this.mcp.callTool(name, args);
    return mcpResultToText(result);
  }

  // -------------------------------------------------------------------------
  // 内部
  // -------------------------------------------------------------------------
  private describeMcpEndpoint(): string {
    return this.cfg.mcp.transport === 'stdio'
      ? `stdio://${this.cfg.mcp.command} ${(this.cfg.mcp.args ?? []).join(' ')}`.trim()
      : this.cfg.mcp.url;
  }

  private async handleQuery(query: string, _sender: string): Promise<string> {
    // 工具清单变化时刷新
    const tools = await this.mcp.getTools().catch(() => this.tools);
    this.tools = tools;

    const intent = parseQueryIntent(query, tools);
    switch (intent.kind) {
      case 'list':
        return toolsToText(tools);
      case 'error':
        return intent.message;
      case 'call': {
        const tool = tools.find((t) => t.name === intent.tool);
        if (!tool) {
          return `未知工具 "${intent.tool}"。可用工具:\n${tools.map((t) => t.name).join(', ')}`;
        }
        try {
          const result = await this.mcp.callTool(intent.tool, intent.arguments);
          return mcpResultToText(result);
        } catch (e) {
          return `[MCP 调用失败] ${(e as Error).message}`;
        }
      }
      default:
        return 'Unsupported intent';
    }
  }

  private async registerToDirectory(card: AgentCard): Promise<void> {
    try {
      const client = new DirectoryClient(this.cfg.directoryUrl!, {
        apiKey: this.cfg.directoryApiKey,
      });
      await client.registerCard(card);
    } catch (e) {
      // 登记失败不影响本地桥接运行
      console.warn(`[a2net-mcp] 目录登记失败: ${(e as Error).message}`);
    }
  }
}
