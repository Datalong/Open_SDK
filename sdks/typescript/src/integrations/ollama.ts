/**
 * ollama.ts — 把本地 Ollama 模型接入 A2Net
 *
 * 外部 Agent 发来查询 → 转发给本地 Ollama → 返回结果。
 * 数据不出本机；只有答复通过网络返回。
 *
 * 依赖：npm i ws（Ollama 需本地运行 http://localhost:11434）
 */
import WebSocket from 'ws';
import { A2NetClient } from '../client.js';

export interface OllamaBridgeConfig {
  relayUrl: string;
  model: string;
  ollamaUrl?: string;
  privateKey?: Uint8Array;
  system?: string;
  permissionPolicy?: import('../permissions.js').PermissionPolicy;
}

export class OllamaBridge {
  private client: A2NetClient;
  private ollamaUrl: string;

  constructor(private cfg: OllamaBridgeConfig) {
    this.ollamaUrl = cfg.ollamaUrl ?? 'http://localhost:11434';
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
    this.client.onQuery(async (query) => this.askOllama(query));
  }

  private async askOllama(prompt: string): Promise<string> {
    const res = await fetch(`${this.ollamaUrl}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: this.cfg.model,
        prompt,
        system: this.cfg.system,
        stream: false,
      }),
    });
    if (!res.ok) throw new Error(`Ollama error: ${res.status}`);
    const data = (await res.json()) as { response: string };
    return data.response;
  }

  stop(): void {
    this.client.disconnect();
  }
}

/**
 * 用法：
 *   const bridge = new OllamaBridge({ relayUrl: 'ws://localhost:8080', model: 'llama3' });
 *   await bridge.start();
 *   console.log('本地 Ollama Agent 已入网:', bridge.address);
 */
