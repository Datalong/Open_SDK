/**
 * langchain.ts — 给 LangChain Agent 加一张 A2Net「网卡」
 *
 * 思路：把 LangChain 的 LLM/Chain 调用包成 A2Net 的 query handler，
 * 让外部 Agent 可以通过网络调用你的 LangChain 能力；同时提供一个
 * A2Net 工具，让你可以在 LangChain 里调用别的 Agent。
 *
 * 依赖：npm i langchain @langchain/core ws
 */
import WebSocket from 'ws';
import { A2NetClient } from '../client.js';

// LangChain 类型（避免强依赖，用最小接口）
export interface RunnableLike {
  invoke(input: string): Promise<string>;
}

export interface LangChainBridgeConfig {
  relayUrl: string;
  privateKey?: Uint8Array;
  /** 本地能力：把入站 query 交给它处理 */
  chain: RunnableLike;
  /** 权限策略 */
  permissionPolicy?: import('../permissions.js').PermissionPolicy;
}

export class LangChainBridge {
  private client: A2NetClient;

  constructor(private cfg: LangChainBridgeConfig) {
    this.client = new A2NetClient({
      relayUrl: cfg.relayUrl,
      privateKey: cfg.privateKey,
      webSocketImpl: WebSocket as unknown as typeof globalThis.WebSocket,
      permissionPolicy: cfg.permissionPolicy,
    });
  }

  get address(): string {
    return this.client.address;
  }

  async start(): Promise<void> {
    await this.client.connect();
    // 入站：外部 Agent 的查询交给 LangChain chain 处理
    this.client.onQuery(async (query) => {
      const out = await this.cfg.chain.invoke(query);
      return typeof out === 'string' ? out : String(out);
    });
  }

  /** 供 LangChain 工具使用：调用网络上另一个 Agent */
  async callAgent(target: string, input: string): Promise<string> {
    return this.client.query(target, input);
  }

  stop(): void {
    this.client.disconnect();
  }
}

/**
 * 用法（伪代码）：
 *
 * const bridge = new LangChainBridge({ relayUrl: 'ws://localhost:8080', chain: myChain });
 * await bridge.start();
 * console.log('我的 Agent 已入网:', bridge.address);
 *
 * // 在 LangChain 里定义工具:
 * const a2netTool = new DynamicTool({
 *   name: 'a2net_call',
 *   description: '调用网络中另一个 Agent，参数 JSON: {"target":"did:key:...","input":"..."}',
 *   func: async (arg) => { const { target, input } = JSON.parse(arg); return bridge.callAgent(target, input); },
 * });
 */
