/**
 * recovery.ts — 多层密钥恢复：Shamir 秘密分享（社交恢复）
 *
 * 方案：(k=3, n=5) over GF(256)。
 * - 每个 share 独立分发给一个 guardian。
 * - 恢复时收集 >= k 个 share，拉格朗日插值还原私钥。
 * - < k 个 share 在信息论上不泄露私钥任何信息。
 *
 * 安全说明：GF(256) 逐字节分享。私钥仅 32 字节，安全级别受限于字段大小，
 * 对「防止少数 guardian 串谋」够用；若需更强，可改用 GF(2^32) 或对每字节
 * 做多次随机化。此处实现遵循最小可用与可读性。
 */
import { randomBytes } from '@noble/hashes/utils';

/** GF(256) 乘法，模不可约多项式 0x11b (AES) */
function gfMul(a: number, b: number): number {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p & 0xff;
}

/** 扩展欧几里得求 GF(256) 逆元 */
function gfInv(a: number): number {
  if (a === 0) throw new Error('inverse of 0');
  // a^254 = a^-1 in GF(256)
  let result = 1;
  let base = a;
  let exp = 254;
  while (exp > 0) {
    if (exp & 1) result = gfMul(result, base);
    base = gfMul(base, base);
    exp >>= 1;
  }
  return result;
}

export interface Share {
  /** x 坐标，1..255 */
  x: number;
  /** 与秘密等长的 y 值 */
  y: Uint8Array;
}

/**
 * 将秘密切分为 n 份，任意 k 份可恢复。
 */
export function splitSecret(secret: Uint8Array, k: number, n: number): Share[] {
  if (k < 2 || k > n) throw new Error('require 2 <= k <= n');
  if (n > 255) throw new Error('n must be <= 255');

  const shares: Share[] = [];
  for (let i = 1; i <= n; i++) {
    shares.push({ x: i, y: new Uint8Array(secret.length) });
  }

  // 对每个字节独立构造 k-1 次多项式，常数项 = 该字节
  for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
    const coeffs = new Uint8Array(k);
    coeffs[0] = secret[byteIdx]!;
    for (let c = 1; c < k; c++) {
      coeffs[c] = randomBytes(1)[0]!;
    }
    for (const share of shares) {
      let y = 0;
      let xPow = 1;
      for (let c = 0; c < k; c++) {
        y ^= gfMul(coeffs[c]!, xPow);
        xPow = gfMul(xPow, share.x);
      }
      share.y[byteIdx] = y;
    }
  }
  return shares;
}

/**
 * 用 >= k 个 share 通过拉格朗日插值还原秘密（在 x=0 处求值）。
 */
export function combineShares(shares: Share[]): Uint8Array {
  if (shares.length < 2) throw new Error('need at least 2 shares');
  const len = shares[0]!.y.length;
  for (const s of shares) {
    if (s.y.length !== len) throw new Error('share length mismatch');
  }
  const secret = new Uint8Array(len);

  for (let byteIdx = 0; byteIdx < len; byteIdx++) {
    let acc = 0;
    for (let i = 0; i < shares.length; i++) {
      const xi = shares[i]!.x;
      // 拉格朗日基函数在 x=0 的值：prod_{j!=i} xj / (xj - xi)（GF 中减=异或）
      let num = 1;
      let den = 1;
      for (let j = 0; j < shares.length; j++) {
        if (i === j) continue;
        const xj = shares[j]!.x;
        num = gfMul(num, xj);
        den = gfMul(den, xj ^ xi);
      }
      const basis = gfMul(num, gfInv(den));
      acc ^= gfMul(shares[i]!.y[byteIdx]!, basis);
    }
    secret[byteIdx] = acc;
  }
  return secret;
}

// ---------------------------------------------------------------------------
// Guardian 恢复请求（签名挑战）
// ---------------------------------------------------------------------------

export interface RecoveryRequest {
  /** 新设备身份地址 */
  newAddress: string;
  /** 随机挑战 nonce，防止重放 */
  nonce: string;
  /** 创建时间 */
  createdAt: number;
}

export interface GuardianResponse {
  guardian: string; // guardian 的 did:key
  requestNonce: string;
  share: Share; // guardian 持有的分片
}

export function newRecoveryRequest(newAddress: string): RecoveryRequest {
  return {
    newAddress,
    nonce: randomBytes(16).reduce((s, b) => s + b.toString(16).padStart(2, '0'), ''),
    createdAt: Date.now(),
  };
}

export function shareToJSON(share: Share): { x: number; y: string } {
  return { x: share.x, y: Buffer.from(share.y).toString('base64') };
}

export function shareFromJSON(s: { x: number; y: string }): Share {
  return { x: s.x, y: new Uint8Array(Buffer.from(s.y, 'base64')) };
}
