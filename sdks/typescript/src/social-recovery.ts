/**
 * social-recovery.ts — 社交恢复客户端
 *
 * 把 Shamir 分片分发给若干 guardian，并在需要时从 guardian 收集分片还原私钥。
 * 只依赖全局 fetch，浏览器与 Node 18+ 通用。
 *
 * 安全模型：每个 guardian 只持有 1 片，< k 片在信息论上不泄露私钥。
 * guardian 若被攻陷也拿不到全部；恢复过程带时间锁，给原主人留取消窗口。
 */
import { splitSecret, combineShares, type Share } from './recovery.js';

export interface GuardianEndpoint {
  /** guardian 基础 URL，如 https://guardian.friend.dev:8090 */
  endpoint: string;
  /** 恢复令牌：用户与 guardian 之间共享的密钥，服务端只存其 hash */
  token: string;
  label?: string;
}

export interface Distribution {
  guardian: string;
  shareId: string;
  shareIndex: number;
}

export interface RecoverResult {
  secret: Uint8Array;
  shares: Share[];
  /** 未成功取得分片的 guardian */
  failed: string[];
}

const b64 = (u8: Uint8Array): string =>
  typeof Buffer !== 'undefined'
    ? Buffer.from(u8).toString('base64')
    : globalThis.btoa(String.fromCharCode(...u8));

const fromB64 = (s: string): Uint8Array =>
  typeof Buffer !== 'undefined'
    ? new Uint8Array(Buffer.from(s, 'base64'))
    : Uint8Array.from(globalThis.atob(s), (c) => c.charCodeAt(0));

/** 把 secret 的 n 片分发给 n 个 guardian */
export async function distributeShares(
  secret: Uint8Array,
  k: number,
  guardians: GuardianEndpoint[],
  ownerAddress: string
): Promise<Distribution[]> {
  if (guardians.length < k) throw new Error('guardians fewer than threshold');
  const shares = splitSecret(secret, k, guardians.length);
  const out: Distribution[] = [];
  for (let i = 0; i < shares.length; i++) {
    const g = guardians[i]!;
    const share = shares[i]!;
    const res = await fetch(`${g.endpoint}/shares`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ownerAddress,
        shareIndex: share.x,
        share: b64(share.y),
        token: g.token,
        label: g.label,
      }),
    });
    if (!res.ok) throw new Error(`guardian ${g.endpoint} upload failed: ${res.status}`);
    const data = (await res.json()) as { shareId: string };
    out.push({ guardian: g.endpoint, shareId: data.shareId, shareIndex: share.x });
  }
  return out;
}

async function fetchShare(
  g: GuardianEndpoint,
  ownerAddress: string,
  newDeviceAddress: string,
  opts: { pollMs: number; timeoutMs: number }
): Promise<Share | undefined> {
  const reqRes = await fetch(`${g.endpoint}/recover/request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ownerAddress, token: g.token, newDeviceAddress }),
  });
  if (!reqRes.ok) return undefined;
  const { recoveryId } = (await reqRes.json()) as { recoveryId: string };

  const deadline = Date.now() + opts.timeoutMs;
  while (Date.now() < deadline) {
    const res = await fetch(`${g.endpoint}/recover/${recoveryId}`);
    if (res.ok) {
      const data = (await res.json()) as {
        status: string;
        shareIndex?: number;
        share?: string;
      };
      if (data.status === 'cancelled') return undefined;
      if (data.status === 'ready' && typeof data.shareIndex === 'number' && typeof data.share === 'string') {
        return { x: data.shareIndex, y: fromB64(data.share) };
      }
    }
    await new Promise((r) => setTimeout(r, opts.pollMs));
  }
  return undefined;
}

/** 从 guardian 收集 >= k 片并还原 secret */
export async function recoverSecret(
  ownerAddress: string,
  newDeviceAddress: string,
  guardians: GuardianEndpoint[],
  k: number,
  opts: { pollMs?: number; timeoutMs?: number } = {}
): Promise<RecoverResult> {
  const o = { pollMs: opts.pollMs ?? 500, timeoutMs: opts.timeoutMs ?? 60_000 };
  const shares: Share[] = [];
  const failed: string[] = [];

  for (const g of guardians) {
    try {
      const s = await fetchShare(g, ownerAddress, newDeviceAddress, o);
      if (s) shares.push(s);
      else failed.push(g.endpoint);
    } catch {
      failed.push(g.endpoint);
    }
    if (shares.length >= k) break;
  }

  if (shares.length < k) {
    throw new Error(`insufficient shares: got ${shares.length}, need ${k}`);
  }
  return { secret: combineShares(shares.slice(0, k)), shares, failed };
}
