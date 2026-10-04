/**
 * directory.ts — A2Net 目录 / 发现服务的客户端
 *
 * 直连 @a2net/directory 的 HTTP API，用于：
 *   - 检索：按能力标签 / 关键字 / 中继找 Agent
 *   - 登记：提交已签名卡片，或提交 `.well-known` URL 让服务端拉取验签
 *   - 下架：用身份私钥对挑战签名
 *
 * 纯 fetch 实现，浏览器与 Node 均可运行。
 */
import { canonicalJson, signMessage } from './crypto.js';
import type { AgentCard } from './agent-card.js';

export interface DirectoryEntry {
  card: AgentCard;
  registeredAt: number;
  updatedAt: number;
  lastSeen: number;
  sourceUrl?: string;
  tenantId?: string;
  /** 卡片缺硬性字段（登记仍成功，仅打标记）；见 validateAgentCard */
  incomplete?: boolean;
  /** 缺失的硬性字段名 */
  missingFields?: string[];
  verifiedOrg?: {
    organizationName: string;
    organizationDomain: string;
    verifiedLevel: 'official' | 'enterprise' | 'partner';
    badge: 'blue_v' | 'gold_v';
    issuer: string;
    credentialId: string;
  };
}

export interface DirectorySearchQuery {
  capability?: string;
  q?: string;
  relay?: string;
  /** 按归属租户 ID 过滤 */
  tenant?: string;
  /** 是否只查询具有企业蓝 V / 组织认证的 Agent */
  verifiedOnly?: boolean;
  /** 只返回字段完整的卡片（过滤掉缺硬性字段的） */
  completeOnly?: boolean;
  limit?: number;
  offset?: number;
}

export interface DirectorySearchResult {
  total: number;
  agents: DirectoryEntry[];
}

export interface CapabilityCount {
  capability: string;
  count: number;
}

export interface DirectoryHealth {
  ok: boolean;
  service: string;
  agents: number;
  uptimeMs: number;
  billing?: {
    requireApiKey: boolean;
    tenantsCount: number;
  };
}

export interface DirectoryClientOptions {
  apiKey?: string;
  fetchImpl?: typeof fetch;
}

/** 下架挑战的规范字符串；服务端与客户端必须一致 */
export function directoryDelistChallenge(did: string, timestamp: number): string {
  return canonicalJson({ action: 'delist', did, timestamp });
}

export class DirectoryClient {
  private baseUrl: string;
  private apiKey?: string;
  private fetchImpl: typeof fetch;

  constructor(baseUrl: string, optsOrFetch?: DirectoryClientOptions | typeof fetch) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    if (typeof optsOrFetch === 'function') {
      this.fetchImpl = optsOrFetch;
    } else {
      this.apiKey = optsOrFetch?.apiKey;
      this.fetchImpl = optsOrFetch?.fetchImpl ?? fetch;
    }
  }

  private headers(extra?: Record<string, string>): Record<string, string> {
    const h: Record<string, string> = { ...extra };
    if (this.apiKey) {
      h['X-API-Key'] = this.apiKey;
      h['Authorization'] = `Bearer ${this.apiKey}`;
    }
    return h;
  }

  private url(path: string, params?: Record<string, string | number | boolean | undefined>): string {
    const u = new URL(this.baseUrl + path);
    for (const [k, v] of Object.entries(params ?? {})) {
      if (v !== undefined) u.searchParams.set(k, String(v));
    }
    return u.toString();
  }

  private async json<T>(res: Response): Promise<T> {
    if (!res.ok) {
      let detail = '';
      try {
        detail = JSON.stringify(await res.json());
      } catch {
        detail = await res.text().catch(() => '');
      }
      throw new Error(`directory ${res.status}: ${detail}`);
    }
    return (await res.json()) as T;
  }

  /** 按能力 / 关键字 / 中继检索 */
  async search(query: DirectorySearchQuery = {}): Promise<DirectorySearchResult> {
    const res = await this.fetchImpl(this.url('/agents', { ...query }), {
      headers: this.headers(),
    });
    return this.json<DirectorySearchResult>(res);
  }

  /** 取单个条目；不存在返回 null */
  async get(did: string): Promise<DirectoryEntry | null> {
    const res = await this.fetchImpl(this.url(`/agents/${encodeURIComponent(did)}`), {
      headers: this.headers(),
    });
    if (res.status === 404) return null;
    const body = await this.json<{ entry: DirectoryEntry }>(res);
    return body.entry;
  }

  /** 聚合能力标签 */
  async capabilities(): Promise<CapabilityCount[]> {
    const res = await this.fetchImpl(this.url('/capabilities'), {
      headers: this.headers(),
    });
    return (await this.json<{ capabilities: CapabilityCount[] }>(res)).capabilities;
  }

  /** 登记一张已签名卡片 */
  async registerCard(card: AgentCard): Promise<{ entry: DirectoryEntry; created: boolean; tier?: string }> {
    const res = await this.fetchImpl(this.url('/agents'), {
      method: 'POST',
      headers: this.headers({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ card }),
    });
    return this.json(res);
  }

  /** 提交 `.well-known` URL，由服务端拉取并验签 */
  async registerUrl(url: string): Promise<{ entry: DirectoryEntry; created: boolean; tier?: string }> {
    const res = await this.fetchImpl(this.url('/agents'), {
      method: 'POST',
      headers: this.headers({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ url }),
    });
    return this.json(res);
  }

  /** 用身份私钥签名后下架自己的条目 */
  async delist(did: string, privateKey: Uint8Array, timestamp = Date.now()): Promise<boolean> {
    const signature = signMessage(directoryDelistChallenge(did, timestamp), privateKey);
    const res = await this.fetchImpl(this.url(`/agents/${encodeURIComponent(did)}`), {
      method: 'DELETE',
      headers: this.headers({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ timestamp, signature }),
    });
    const body = await this.json<{ delisted?: boolean }>(res);
    return body.delisted === true;
  }

  async healthz(): Promise<DirectoryHealth> {
    const res = await this.fetchImpl(this.url('/healthz'), {
      headers: this.headers(),
    });
    return this.json<DirectoryHealth>(res);
  }

  /** 查询目录用量及配额统计 */
  async getUsage(): Promise<Record<string, unknown>> {
    const res = await this.fetchImpl(this.url('/usage'), {
      headers: this.headers(),
    });
    return this.json<Record<string, unknown>>(res);
  }
}
