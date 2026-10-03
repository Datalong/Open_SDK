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
export interface AgentPricing {
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
  pricing?: AgentPricing;
  /** A2Net 扩展：能力标签，便于检索 */
  capabilities?: string[];
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
  pricing?: AgentPricing;
  capabilities?: string[];
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
