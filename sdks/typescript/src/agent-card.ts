/**
 * agent-card.ts — Agent Description（智能体描述文档）+ .well-known 发现
 *
 * 移植自 AgentNetworkProtocol（ANP）：
 *   - ANP-07 Agent Description Protocol（文档结构、proof 签名、interfaces/Information）
 *   - ANP-08 Agent Discovery Protocol（主动发现：GET /.well-known/agent-description.json）
 *
 * 与 ANP 的差异：
 *   - protocolType 用 "A2Net"（ANP 用 "ANP"），并保留 ANP 兼容字段命名
 *   - did 用 A2Net 的 did:key（ANP 用 did:wba / did:web）
 *   - 增加 A2Net 扩展：relay（中继地址）、pricing（Lightning 计价）、capabilities
 *   - proof 复用 A2Net 既有的 canonical JSON + Ed25519 签名（非 JSON-LD）
 */
import { canonicalJson, signMessage, verifySignature, type KeyPair } from './crypto.js';
import type { VerifiableCredential } from './credentials.js';

/** 接口类型：自然语言接口 / 结构化接口（沿用 ANP-07） */
export type InterfaceType = 'NaturalLanguageInterface' | 'StructuredInterface';

export interface AgentInterface {
  type: InterfaceType;
  /** 协议名：A2Net / MCP / openrpc / YAML / WebRTC … */
  protocol: string;
  version?: string;
  /** 接口文档地址（可在本地内联 content 时省略） */
  url?: string;
  /** 需要人类显式授权（沿用 ANP-07） */
  humanAuthorization?: boolean;
  description?: string;
  /** 内联的接口描述（如 OpenRPC 文档） */
  content?: unknown;
}

/** 对外信息/产品/服务（沿用 ANP-07 的 Information 列表） */
export interface AgentInformation {
  /** Product / Information / VideoObject … */
  type: string;
  description: string;
  url?: string;
}

export interface AgentOwner {
  type: string;
  name: string;
  url?: string;
}

/** A2Net 扩展：Lightning 计价 */
/**
 * Agent Card 上的**公示报价**（对外宣告"我收多少"）。
 *
 * 命名说明：曾叫 `AgentPricing`，与 `payment.ts` 里的计费规则类型都带 "Pricing"
 * 字样，含义却完全不同 —— 这是新人极易混淆的点。已改名为 `CardPricing`
 * 以明确它是"卡片上的报价"，与"怎么算钱"（`BillingRule`）区分开。
 *
 * ⚠️ 这是**类型名**变更，不影响线格式：Agent Card 的 JSON 字段仍叫 `pricing`。
 */
export interface CardPricing {
  /** 计价单位，例如 "sat" */
  unit: string;
  /** 每次调用基准价 */
  amount: number;
  /** 收款的 Lightning 节点公钥或 invoice 端点 */
  payee?: string;
}

export interface AgentCardProof {
  type: 'Ed25519Signature2020';
  created: string;
  proofPurpose: 'assertionMethod';
  /** 验证方法，即签名者的 did:key 地址 */
  verificationMethod: string;
  /** base64 编码的 Ed25519 签名 */
  signatureValue: string;
}

export interface AgentCard {
  /** 固定 "A2Net"；解析方应忽略未知 protocolType */
  protocolType: string;
  protocolVersion: string;
  type: 'AgentDescription';
  /** 本卡片的规范 URL */
  url: string;
  name: string;
  did: string;
  owner?: AgentOwner;
  description: string;
  created: string;
  securityDefinitions?: Record<string, { scheme: string; in: string; name: string }>;
  security?: string;
  /** A2Net 扩展：中继服务器地址（wss://） */
  relay?: string;
  /** A2Net 扩展：计价 */
  pricing?: CardPricing;
  /** A2Net 扩展：能力标签，便于检索 */
  capabilities?: string[];
  /** A2Net 扩展：企业组织可验证凭据列表 (W3C Verifiable Credentials) */
  credentials?: VerifiableCredential[];
  information?: AgentInformation[];
  interfaces?: AgentInterface[];
  proof?: AgentCardProof;
}

/** 卡片签名时排除 proof 本身 */
function signablePayload(card: AgentCard): string {
  const { proof: _omit, ...rest } = card;
  return canonicalJson(rest);
}

export interface CreateAgentCardOptions {
  did: string;
  name: string;
  description: string;
  url?: string;
  owner?: AgentOwner;
  relay?: string;
  pricing?: CardPricing;
  capabilities?: string[];
  credentials?: VerifiableCredential[];
  information?: AgentInformation[];
  interfaces?: AgentInterface[];
  protocolVersion?: string;
  created?: string;
}

/** 构造一张（未签名的）Agent Description */
export function createAgentCard(opts: CreateAgentCardOptions): AgentCard {
  return {
    protocolType: 'A2Net',
    protocolVersion: opts.protocolVersion ?? '1.0.0',
    type: 'AgentDescription',
    url: opts.url ?? `a2net://agent/${opts.did}`,
    name: opts.name,
    did: opts.did,
    owner: opts.owner,
    description: opts.description,
    created: opts.created ?? new Date().toISOString(),
    securityDefinitions: {
      a2net_message: { scheme: 'ed25519', in: 'header', name: 'X-A2Net-Signature' },
    },
    security: 'a2net_message',
    relay: opts.relay,
    pricing: opts.pricing,
    capabilities: opts.capabilities,
    credentials: opts.credentials,
    information: opts.information,
    interfaces: opts.interfaces,
  };
}

/** 用私钥对卡片签名，返回带 proof 的新卡片 */
export function signAgentCard(
  card: AgentCard,
  keyPair: KeyPair,
  created = new Date().toISOString()
): AgentCard {
  const signatureValue = signMessage(signablePayload(card), keyPair.privateKey);
  return {
    ...card,
    proof: {
      type: 'Ed25519Signature2020',
      created,
      proofPurpose: 'assertionMethod',
      verificationMethod: keyPair.address,
      signatureValue,
    },
  };
}

/** 快捷工具：一步构造并签名 Agent 卡片 */
export function createSignedAgentCard(
  opts: CreateAgentCardOptions,
  keyPair: KeyPair,
  created = new Date().toISOString()
): AgentCard {
  return signAgentCard(createAgentCard(opts), keyPair, created);
}

/**
 * 校验卡片签名。
 * 注意：did 必须与 proof.verificationMethod 一致，否则签名可被「换主体」重用。
 */
// ────────────────────────────────────────────────────────────────
// Agent Card 字段校验（硬性要求 vs 建议补齐）
// ────────────────────────────────────────────────────────────────
/**
 * 硬性要求：缺失则卡片**不可用于发现与调用**。
 *
 * 注意与 `CreateAgentCardOptions` 的类型约束是**互补而非重复**：
 *   · 类型约束引导**有类型的**调用方（TS 开发者）
 *   · 本函数兜住**无类型的**调用方（JS / Python / 手写 JSON / 第三方实现）
 * 只有两者都在，契约才真正闭合 —— 仅靠类型时，未类型化的调用方能造出
 * 缺字段的卡片并被全网接受（这正是此前的实际状态）。
 */
export const AGENT_CARD_REQUIRED_FIELDS = ['type', 'did', 'name', 'description', 'url', 'created'] as const;

/**
 * 建议补齐：不影响有效性与登记，但影响**可发现性与可用性**。
 *
 * 刻意不设为硬性 —— 收紧已有校验会让既有 Agent 被拒（破坏性变更）。
 * 改为"登记成功但标记不完整"，让问题可见而不制造中断。
 */
export const AGENT_CARD_RECOMMENDED_FIELDS = ['relay', 'capabilities', 'pricing'] as const;

export interface AgentCardValidation {
  /** 硬性字段齐全**且**签名有效 */
  valid: boolean;
  /** 缺失或非法的硬性字段名 */
  missing: string[];
  /** 缺失的建议字段名（不影响 valid） */
  warnings: string[];
  /** 签名是否有效 */
  signed: boolean;
}

/**
 * 校验一张 Agent Card（硬性字段 + 签名 + 建议字段）。
 *
 * 只做**形状与签名**校验，不校验字段语义（如 relay 是否真能连通）——
 * 后者需要真实网络探测，属于另一个层次。
 */
export function validateAgentCard(card: Partial<AgentCard> | null | undefined): AgentCardValidation {
  const missing: string[] = [];
  const warnings: string[] = [];
  if (!card || typeof card !== 'object') {
    return {
      valid: false,
      missing: [...AGENT_CARD_REQUIRED_FIELDS],
      warnings: [...AGENT_CARD_RECOMMENDED_FIELDS],
      signed: false,
    };
  }

  const c = card as Record<string, unknown>;
  for (const f of AGENT_CARD_REQUIRED_FIELDS) {
    const v = c[f];
    if (v === undefined || v === null || (typeof v === 'string' && v.trim() === '')) missing.push(f);
  }
  // type 必须是规范值（上面只查了"非空"）
  if (c.type !== undefined && c.type !== 'AgentDescription') {
    if (!missing.includes('type')) missing.push('type');
  }

  for (const f of AGENT_CARD_RECOMMENDED_FIELDS) {
    const v = c[f];
    if (v === undefined || v === null || (Array.isArray(v) && v.length === 0)) warnings.push(f);
  }

  const signed = typeof c.proof === 'object' && c.proof !== null;
  const structurallyValid = missing.length === 0;

  return {
    valid: structurallyValid && signed && verifyAgentCard(card as AgentCard),
    missing,
    warnings,
    signed,
  };
}

export function verifyAgentCard(card: AgentCard): boolean {
  const proof = card.proof;
  if (!proof || !proof.signatureValue || !proof.verificationMethod) return false;
  if (card.did !== proof.verificationMethod) return false;
  try {
    return verifySignature(signablePayload(card), proof.signatureValue, proof.verificationMethod);
  } catch {
    return false;
  }
}

/** ANP-08 主动发现路径 */
export const AGENT_DESCRIPTION_PATH = '/.well-known/agent-description.json';

/** 由站点 origin 得到描述文档 URL，例如 https://a.example.com → https://a.example.com/.well-known/agent-description.json */
export function agentDescriptionUrl(origin: string): string {
  return origin.replace(/\/+$/, '') + AGENT_DESCRIPTION_PATH;
}

/**
 * 解析并校验远端卡片（ANP-08 主动发现）。
 * @param url 卡片 URL
 * @param fetchImpl 可注入的 fetch（便于测试 / 浏览器环境）
 */
export async function resolveAgentCard(
  url: string,
  fetchImpl: typeof fetch = fetch
): Promise<AgentCard> {
  const res = await fetchImpl(url, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`解析 Agent Description 失败: ${res.status} ${url}`);
  const card = (await res.json()) as AgentCard;
  if (card.type !== 'AgentDescription') throw new Error('不是有效的 Agent Description');
  if (!verifyAgentCard(card)) throw new Error('Agent Description 签名无效');
  return card;
}
