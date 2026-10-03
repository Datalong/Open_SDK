/**
 * credentials.ts — W3C Verifiable Credentials (VC) 企业组织认证与官方蓝 V 证明
 *
 * 核心设计：
 * 1. 遵循 W3C VC 规范，为匿名 did:key 赋予机构背书能力（组织实名、域名担保、资质评级）；
 * 2. 签发者（Issuer）使用其 Ed25519 私钥为特定 Agent DID 进行不可篡改签名；
 * 3. 任何节点均可在完全离线状态下快速校验组织真实性（RFC 8785 Canonical JSON + Ed25519）；
 * 4. 支持企业蓝 V (blue_v) 与官方黄金认证 (gold_v) 等级与动态吊销列表。
 */

import { canonicalJson, signMessage, verifySignature } from './crypto.js';

function uuidv4(): string {
  return globalThis.crypto.randomUUID();
}

export type VerifiedLevel = 'official' | 'enterprise' | 'partner';
export type VerifiedBadge = 'blue_v' | 'gold_v';

export interface CredentialSubject {
  /** 被认证的智能体自主身份 (did:key) */
  id: string;
  /** 认证的企业/机构法定或公认名称 (如 "Datalong 官方实验室") */
  organizationName: string;
  /** 企业官方验证域名 (如 "datalong.ai") */
  organizationDomain: string;
  /** 认证等级 */
  verifiedLevel: VerifiedLevel;
  /** 授信徽章类型 */
  badge: VerifiedBadge;
  /** 背书认可的专业能力范围标签 */
  capabilitiesEndorsed?: string[];
  /** 额外元数据 */
  metadata?: Record<string, unknown>;
}

export interface CredentialProof {
  type: 'Ed25519Signature2020';
  created: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  proofValue: string;
}

export interface VerifiableCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  expirationDate: string;
  credentialSubject: CredentialSubject;
  proof: CredentialProof;
}

export interface IssueCredentialParams {
  agentDid: string;
  issuerDid: string;
  organizationName: string;
  organizationDomain: string;
  verifiedLevel?: VerifiedLevel;
  badge?: VerifiedBadge;
  capabilitiesEndorsed?: string[];
  validityDays?: number;
  metadata?: Record<string, unknown>;
}

export interface CredentialVerificationResult {
  valid: boolean;
  error?: string;
  issuer?: string;
  subjectDid?: string;
  organizationName?: string;
  organizationDomain?: string;
  badge?: VerifiedBadge;
  verifiedLevel?: VerifiedLevel;
  expiresAt?: number;
}

/** 构造用于签名的不可变声明体规范字符串 */
function getCredentialClaimString(vc: Omit<VerifiableCredential, 'proof'>): string {
  return canonicalJson({
    '@context': vc['@context'],
    id: vc.id,
    type: vc.type,
    issuer: vc.issuer,
    issuanceDate: vc.issuanceDate,
    expirationDate: vc.expirationDate,
    credentialSubject: vc.credentialSubject,
  });
}

/**
 * 签发企业组织凭据 (Verifiable Credential)
 */
export function issueOrganizationCredential(
  params: IssueCredentialParams,
  issuerPrivateKey: Uint8Array
): VerifiableCredential {
  const now = Date.now();
  const validityMs = (params.validityDays ?? 365) * 24 * 60 * 60 * 1000;
  const issuanceDate = new Date(now).toISOString();
  const expirationDate = new Date(now + validityMs).toISOString();

  const claim: Omit<VerifiableCredential, 'proof'> = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://a2net.network/credentials/v1',
    ],
    id: `urn:uuid:${uuidv4()}`,
    type: ['VerifiableCredential', 'AgentOrganizationAffiliationCredential'],
    issuer: params.issuerDid,
    issuanceDate,
    expirationDate,
    credentialSubject: {
      id: params.agentDid,
      organizationName: params.organizationName,
      organizationDomain: params.organizationDomain,
      verifiedLevel: params.verifiedLevel ?? 'enterprise',
      badge: params.badge ?? (params.verifiedLevel === 'official' ? 'gold_v' : 'blue_v'),
      capabilitiesEndorsed: params.capabilitiesEndorsed ?? [],
      metadata: params.metadata,
    },
  };

  const claimStr = getCredentialClaimString(claim);
  const signature = signMessage(claimStr, issuerPrivateKey);

  const proof: CredentialProof = {
    type: 'Ed25519Signature2020',
    created: issuanceDate,
    verificationMethod: `${params.issuerDid}#keys-1`,
    proofPurpose: 'assertionMethod',
    proofValue: signature,
  };

  return {
    ...claim,
    proof,
  };
}

/**
 * 校验企业组织凭据的真实性、签名、有效期与吊销状态
 */
export function verifyOrganizationCredential(
  vc: VerifiableCredential,
  options: {
    now?: number;
    trustedIssuers?: string[];
    revocationList?: Set<string> | string[];
  } = {}
): CredentialVerificationResult {
  if (!vc || typeof vc !== 'object') {
    return { valid: false, error: 'Malformed credential object' };
  }

  // 1. 结构与格式检查
  if (!vc.issuer || !vc.credentialSubject?.id || !vc.proof?.proofValue) {
    return { valid: false, error: 'Missing required credential fields' };
  }

  // 2. 有效期校验
  const now = options.now ?? Date.now();
  const issuedAt = Date.parse(vc.issuanceDate);
  const expiresAt = Date.parse(vc.expirationDate);

  if (isNaN(issuedAt) || isNaN(expiresAt)) {
    return { valid: false, error: 'Invalid date format in credential' };
  }

  if (now < issuedAt - 60_000) {
    return { valid: false, error: 'Credential not yet active' };
  }

  if (now > expiresAt) {
    return { valid: false, error: 'Credential has expired' };
  }

  // 3. 信任签发者白名单校验（若指定）
  if (options.trustedIssuers && options.trustedIssuers.length > 0) {
    if (!options.trustedIssuers.includes(vc.issuer)) {
      return { valid: false, error: `Untrusted issuer: ${vc.issuer}` };
    }
  }

  // 4. 吊销状态检查
  if (options.revocationList) {
    const revSet =
      options.revocationList instanceof Set
        ? options.revocationList
        : new Set(options.revocationList);
    if (revSet.has(vc.id)) {
      return { valid: false, error: `Credential has been revoked: ${vc.id}` };
    }
  }

  // 5. 密码学 Ed25519 签名验证
  const claim: Omit<VerifiableCredential, 'proof'> = {
    '@context': vc['@context'],
    id: vc.id,
    type: vc.type,
    issuer: vc.issuer,
    issuanceDate: vc.issuanceDate,
    expirationDate: vc.expirationDate,
    credentialSubject: vc.credentialSubject,
  };

  const claimStr = getCredentialClaimString(claim);
  const isSignatureValid = verifySignature(claimStr, vc.proof.proofValue, vc.issuer);

  if (!isSignatureValid) {
    return { valid: false, error: 'Cryptographic signature verification failed' };
  }

  return {
    valid: true,
    issuer: vc.issuer,
    subjectDid: vc.credentialSubject.id,
    organizationName: vc.credentialSubject.organizationName,
    organizationDomain: vc.credentialSubject.organizationDomain,
    badge: vc.credentialSubject.badge,
    verifiedLevel: vc.credentialSubject.verifiedLevel,
    expiresAt,
  };
}
