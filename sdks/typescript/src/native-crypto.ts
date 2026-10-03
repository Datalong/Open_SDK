/**
 * native-crypto.ts — Node 原生（OpenSSL）曲线运算加速层
 *
 * 背景：纯 JS 的 @noble/curves 使用 BigInt 实现 Edwards/Montgomery 曲线，
 * 单次 Ed25519 验签约 1.1ms、X25519 ECDH 约 0.7ms，成为端点吞吐瓶颈。
 * Node 的 `node:crypto` 直接调用 OpenSSL，实测快 10–30 倍。
 *
 * 设计约束：
 *   * **字节级兼容**：RFC 8032 的 Ed25519 是确定性签名，X25519 是标准 ECDH，
 *     OpenSSL 与 noble 的输出完全一致，因此可无缝替换。
 *   * **浏览器安全**：`node:crypto` 在浏览器被打包器外部化，属性访问会抛错；
 *     所有访问都包在 try/catch 中，任何异常即回退到纯 JS 实现。
 *   * **零行为变化**：所有函数在原生不可用时返回 null，由调用方决定回退。
 */
import * as nodeCryptoNs from 'node:crypto';

/** Ed25519 PKCS8（私钥）与 SPKI（公钥）的固定 DER 前缀 */
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
/** X25519 PKCS8（私钥）与 SPKI（公钥）的固定 DER 前缀 */
const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);
const X25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
]);

type NodeCrypto = typeof import('node:crypto');
type KeyObject = import('node:crypto').KeyObject;

let probe: NodeCrypto | null | undefined;

/** 探测 Node 原生 crypto 是否可用（浏览器下返回 null） */
function nc(): NodeCrypto | null {
  if (probe !== undefined) return probe;
  try {
    const candidate = nodeCryptoNs as unknown as NodeCrypto;
    probe = typeof candidate.createPrivateKey === 'function' && typeof candidate.sign === 'function'
      ? candidate
      : null;
  } catch {
    probe = null;
  }
  return probe;
}

function concat(prefix: Uint8Array, body: Uint8Array): Uint8Array {
  const out = new Uint8Array(prefix.length + body.length);
  out.set(prefix, 0);
  out.set(body, prefix.length);
  return out;
}

// ---------------------------------------------------------------------------
// KeyObject 缓存 —— 身份密钥长期不变，缓存后单次签名开销降至 ~18µs
// ---------------------------------------------------------------------------
const edPrivateCache = new Map<string, KeyObject>();
const edPublicCache = new Map<string, KeyObject>();
const xPrivateCache = new Map<string, KeyObject>();
const xPublicCache = new Map<string, KeyObject>();
const CACHE_LIMIT = 2048;

function cacheGet(cache: Map<string, KeyObject>, key: string): KeyObject | undefined {
  return cache.get(key);
}

function cacheSet(cache: Map<string, KeyObject>, key: string, value: KeyObject): void {
  if (cache.size >= CACHE_LIMIT) {
    const first = cache.keys().next();
    if (!first.done) cache.delete(first.value);
  }
  cache.set(key, value);
}

function hex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, '0');
  return s;
}

function ed25519PrivateKey(seed: Uint8Array): KeyObject | null {
  const crypto = nc();
  if (!crypto || seed.length !== 32) return null;
  const key = hex(seed);
  const cached = cacheGet(edPrivateCache, key);
  if (cached) return cached;
  try {
    const ko = crypto.createPrivateKey({
      key: Buffer.from(concat(ED25519_PKCS8_PREFIX, seed)),
      format: 'der',
      type: 'pkcs8',
    });
    cacheSet(edPrivateCache, key, ko);
    return ko;
  } catch {
    return null;
  }
}

function ed25519PublicKey(pub: Uint8Array): KeyObject | null {
  const crypto = nc();
  if (!crypto || pub.length !== 32) return null;
  const key = hex(pub);
  const cached = cacheGet(edPublicCache, key);
  if (cached) return cached;
  try {
    const ko = crypto.createPublicKey({
      key: Buffer.from(concat(ED25519_SPKI_PREFIX, pub)),
      format: 'der',
      type: 'spki',
    });
    cacheSet(edPublicCache, key, ko);
    return ko;
  } catch {
    return null;
  }
}

function x25519PrivateKey(raw: Uint8Array): KeyObject | null {
  const crypto = nc();
  if (!crypto || raw.length !== 32) return null;
  const key = hex(raw);
  const cached = cacheGet(xPrivateCache, key);
  if (cached) return cached;
  try {
    const ko = crypto.createPrivateKey({
      key: Buffer.from(concat(X25519_PKCS8_PREFIX, raw)),
      format: 'der',
      type: 'pkcs8',
    });
    cacheSet(xPrivateCache, key, ko);
    return ko;
  } catch {
    return null;
  }
}

function x25519PublicKey(raw: Uint8Array): KeyObject | null {
  const crypto = nc();
  if (!crypto || raw.length !== 32) return null;
  const key = hex(raw);
  const cached = cacheGet(xPublicCache, key);
  if (cached) return cached;
  try {
    const ko = crypto.createPublicKey({
      key: Buffer.from(concat(X25519_SPKI_PREFIX, raw)),
      format: 'der',
      type: 'spki',
    });
    cacheSet(xPublicCache, key, ko);
    return ko;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// 对外 API（不可用时返回 null，由调用方回退）
// ---------------------------------------------------------------------------

/** Ed25519 签名；不可用返回 null */
export function nativeEd25519Sign(message: Uint8Array, seed: Uint8Array): Uint8Array | null {
  const crypto = nc();
  if (!crypto) return null;
  const key = ed25519PrivateKey(seed);
  if (!key) return null;
  try {
    return new Uint8Array(crypto.sign(null, Buffer.from(message), key));
  } catch {
    return null;
  }
}

/** Ed25519 验签；不可用返回 null */
export function nativeEd25519Verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean | null {
  const crypto = nc();
  if (!crypto) return null;
  const key = ed25519PublicKey(publicKey);
  if (!key) return null;
  try {
    return crypto.verify(null, Buffer.from(message), key, Buffer.from(signature));
  } catch {
    return null;
  }
}

/** X25519 ECDH；不可用返回 null */
export function nativeX25519(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Uint8Array | null {
  const crypto = nc();
  if (!crypto) return null;
  const priv = x25519PrivateKey(privateKey);
  const pub = x25519PublicKey(publicKey);
  if (!priv || !pub) return null;
  try {
    return new Uint8Array(crypto.diffieHellman({ privateKey: priv, publicKey: pub }));
  } catch {
    return null;
  }
}

/** 由 X25519 私钥推导公钥；不可用返回 null（纯 JS 推导约 600µs，原生约 30µs） */
export function nativeX25519PublicKey(privateKey: Uint8Array): Uint8Array | null {
  const crypto = nc();
  if (!crypto) return null;
  const priv = x25519PrivateKey(privateKey);
  if (!priv) return null;
  try {
    const pub = crypto.createPublicKey(priv);
    const der = new Uint8Array(pub.export({ type: 'spki', format: 'der' }));
    // SPKI 前 12 字节为固定前缀，后 32 字节为原始公钥
    if (der.length !== X25519_SPKI_PREFIX.length + 32) return null;
    return der.slice(X25519_SPKI_PREFIX.length);
  } catch {
    return null;
  }
}

/**
 * 一次性生成 X25519 密钥对（原生约 20–40µs，纯 JS 约 600µs）。
 * 用于 E2EE 每条消息的临时密钥。
 */
export function nativeX25519KeyPair(): { privateKey: Uint8Array; publicKey: Uint8Array } | null {
  const crypto = nc();
  if (!crypto) return null;
  try {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
    const priv = new Uint8Array(privateKey.export({ type: 'pkcs8', format: 'der' }));
    const pub = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }));
    if (priv.length !== X25519_PKCS8_PREFIX.length + 32) return null;
    if (pub.length !== X25519_SPKI_PREFIX.length + 32) return null;
    return {
      privateKey: priv.slice(X25519_PKCS8_PREFIX.length),
      publicKey: pub.slice(X25519_SPKI_PREFIX.length),
    };
  } catch {
    return null;
  }
}

/** 原生加速是否可用（仅用于诊断/基准报告） */
export function isNativeCryptoAvailable(): boolean {
  return nc() !== null;
}

/** 清空 KeyObject 缓存（测试用） */
export function resetNativeCryptoCaches(): void {
  edPrivateCache.clear();
  edPublicCache.clear();
  xPrivateCache.clear();
  xPublicCache.clear();
}
