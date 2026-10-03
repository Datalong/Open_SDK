/**
 * permissions.ts — 本地权限策略 + 令牌桶限流
 *
 * 所有权限校验在接收方本地执行，中继不参与。
 */
export interface RateLimit {
  /** 桶容量（突发上限） */
  max: number;
  /** 补充窗口（秒），refill = max / windowSec 每秒 */
  windowSec: number;
}

export interface PermissionRule {
  /** 主体 did:key，或 '*' */
  subject: string;
  /** 允许的 scope，如 knowledge.public / tool.weather */
  scopes: string[];
  rateLimit?: RateLimit;
  expiresAt?: number;
}

export interface PermissionPolicy {
  defaultAllow: boolean;
  whitelist?: string[];
  blacklist?: string[];
  rules?: PermissionRule[];
  requirePayment?: { amount: number; currency: string };
}

export type PermissionDecision =
  | { allowed: true }
  | { allowed: false; code: 4031 | 4032; reason: string; retryAfter?: number };

// ---------------------------------------------------------------------------
// 令牌桶
// ---------------------------------------------------------------------------

interface Bucket {
  tokens: number;
  lastRefill: number;
}

export class TokenBucket {
  private buckets = new Map<string, Bucket>();

  /** 尝试消费一个令牌；返回 false 表示超限 */
  consume(key: string, limit: RateLimit, now = Date.now()): boolean {
    const refillPerMs = limit.max / (limit.windowSec * 1000);
    let b = this.buckets.get(key);
    if (!b) {
      b = { tokens: limit.max, lastRefill: now };
      this.buckets.set(key, b);
    }
    const elapsed = now - b.lastRefill;
    b.tokens = Math.min(limit.max, b.tokens + elapsed * refillPerMs);
    b.lastRefill = now;
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  /** 距离下一个令牌可用的毫秒数 */
  retryAfterMs(key: string, limit: RateLimit, now = Date.now()): number {
    const b = this.buckets.get(key);
    if (!b) return 0;
    const refillPerMs = limit.max / (limit.windowSec * 1000);
    if (b.tokens >= 1) return 0;
    return Math.ceil((1 - b.tokens) / refillPerMs);
  }

  reset(): void {
    this.buckets.clear();
  }
}

// ---------------------------------------------------------------------------
// 策略校验
// ---------------------------------------------------------------------------

/**
 * 默认入站限流：每个发送方 600 次 / 分钟（10 req/s，突发 600）。
 *
 * 说明：这是接收方本地保护措施（中继不参与）。默认值需高于典型 Agent 服务能力，
 * 否则会先于中继成为瓶颈；需要更高吞吐时可通过 policy.rules 显式放宽。
 */
export const DEFAULT_INBOUND_RATE_LIMIT: RateLimit = { max: 600, windowSec: 60 };

export interface CheckContext {
  sender: string;
  /** 请求 scope，缺省视为 knowledge.public */
  scope: string;
  now?: number;
}

export function checkPermission(
  policy: PermissionPolicy,
  ctx: CheckContext,
  bucket: TokenBucket
): PermissionDecision {
  const now = ctx.now ?? Date.now();

  // 1. 黑名单
  if (policy.blacklist?.includes(ctx.sender)) {
    return { allowed: false, code: 4031, reason: 'blacklisted' };
  }

  // 2. 白名单模式
  if (!policy.defaultAllow && !policy.whitelist?.includes(ctx.sender)) {
    // 仍可能有显式 rule 授权
    const rule = findRule(policy, ctx.sender, ctx.scope, now);
    if (!rule) return { allowed: false, code: 4031, reason: 'not whitelisted' };
  }

  // 3. 匹配规则
  const rule = findRule(policy, ctx.sender, ctx.scope, now);
  if (!policy.defaultAllow && !rule && !policy.whitelist?.includes(ctx.sender)) {
    return { allowed: false, code: 4031, reason: 'scope not granted' };
  }
  if (rule && !scopeMatches(rule, ctx.scope)) {
    return { allowed: false, code: 4031, reason: `scope ${ctx.scope} not granted` };
  }

  // 4. 限流
  const limit = rule?.rateLimit ?? DEFAULT_INBOUND_RATE_LIMIT;
  const key = `${ctx.sender}:${rule ? 'rule' : 'default'}`;
  if (!bucket.consume(key, limit, now)) {
    return {
      allowed: false,
      code: 4032,
      reason: 'rate limit exceeded',
      retryAfter: bucket.retryAfterMs(key, limit, now),
    };
  }

  return { allowed: true };
}

function findRule(
  policy: PermissionPolicy,
  sender: string,
  scope: string,
  now: number
): PermissionRule | undefined {
  const rules = policy.rules ?? [];
  // 精确主体优先于通配
  const candidates = rules.filter(
    (r) => (r.subject === sender || r.subject === '*') && (!r.expiresAt || r.expiresAt > now)
  );
  const exact = candidates.find((r) => r.subject === sender && scopeMatches(r, scope));
  if (exact) return exact;
  return candidates.find((r) => scopeMatches(r, scope));
}

function scopeMatches(rule: PermissionRule, scope: string): boolean {
  return rule.scopes.some((s) => s === '*' || s === scope || scope.startsWith(s + '.'));
}
