/**
 * e2ee.ts — 端到端加密（协议 v0.2）
 *
 * 目标：中继只转发密文，看不到消息内容。
 *
 * 设计要点：
 * - **不引入新的密钥**：用身份密钥（Ed25519）通过标准双线性映射转成 X25519，
 *   所以「知道对方 did:key 地址」就等于「知道对方加密公钥」，无需额外分发。
 * - 每条消息用一次性 X25519 临时密钥对（epk）→ ECDH → HKDF-SHA256 → AES-256-GCM。
 *   临时密钥保证前向保密：即使身份私钥日后泄露，也解不开过去的密文。
 * - 密文为 `content` 的整体替换，签名覆盖的是密文，因此中继仍无法伪造，
 *   接收方解密即完成认证（AEAD tag）。
 */
import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { randomBytes } from '@noble/hashes/utils';
import { publicKeyFromAddress } from './crypto.js';
import { nativeX25519, nativeX25519PublicKey, nativeX25519KeyPair } from './native-crypto.js';

export const E2EE_ALG = 'X25519-HKDF-SHA256-AES-256-GCM';
const HKDF_INFO = 'a2net-e2ee-v1';

/** 加密信封：整体替换消息的 content */
/**
 * 明文长度填充的分级桶（字节）。
 *
 * 为什么要填充：密文的**长度**本身会泄露信息。一个 2KB 的查询与一个 200KB 的
 * 应答，即使内容全加密，长度也足以让中继推断出"这是一次长文本生成"而非"一次
 * 短问答"。把明文补齐到固定的几档，可以抹掉大部分长度特征。
 *
 * 为什么用分级桶而非定长：定长（如一律 64KB）会把 100 字节的 ping 放大 640 倍，
 * 带宽代价不可接受。分级桶在"抹平特征"与"控制开销"之间取平衡。
 *
 * **为什么有上限（且这是刻意的）**：
 *   填充的收益随载荷增大而**递减**，代价却线性增长。
 *     · 100B vs 300B 的查询 → 长度差异揭示了"这是短问 vs 长问"，值得抹平
 *     · 64KB vs 64KB-1K 的分片 → 相对差异不到 2%，几乎不泄露信息
 *   而多模态分片本来就是**定长 64KB**（只有末片较短），
 *   若把 64KB 填充到 256KB，会造成 **4 倍带宽膨胀** —— 严重拖慢文件传输，
 *   换来接近为零的隐私收益。
 *   因此超过最大桶的载荷**不填充**（信封不带 `pad` 标记，接收方按原样解码）。
 */
export const PAD_BUCKETS = [256, 1024, 4096, 16384] as const;

/** 长度前缀占用的字节数（大端 uint32，记录**原始明文**长度） */
const PAD_LEN_BYTES = 4;

/** 单次随机填充字节数上限（crypto.getRandomValues 与 noble 都限制为 64KiB） */
const RANDOM_FILL_CHUNK = 65536;

/**
 * 按分级桶计算填充后的目标长度。
 * @returns 目标长度；**返回 0 表示不填充**（载荷已超过最大桶）
 */
export function paddedLength(plaintextBytes: number): number {
  const need = plaintextBytes + PAD_LEN_BYTES;
  for (const b of PAD_BUCKETS) if (need <= b) return b;
  return 0; // 超出最大桶 → 不填充
}

/** 生成 n 字节随机填充（分块以规避 64KiB 单次调用上限） */
function randomFill(n: number): Uint8Array {
  const out = new Uint8Array(n);
  let off = 0;
  while (off < n) {
    const len = Math.min(RANDOM_FILL_CHUNK, n - off);
    out.set(randomBytes(len), off);
    off += len;
  }
  return out;
}

/** 明文 → 填充后字节（[4B 原长][明文][随机填充]）；无需填充时原样返回 */
export function padPlaintext(plaintext: Uint8Array): Uint8Array {
  const target = paddedLength(plaintext.length);
  if (target === 0) return plaintext;
  const out = new Uint8Array(target);
  new DataView(out.buffer).setUint32(0, plaintext.length, false);
  out.set(plaintext, PAD_LEN_BYTES);
  // 随机填充而非零填充：避免在非 AEAD 实现下暴露填充边界
  if (target > plaintext.length + PAD_LEN_BYTES) {
    out.set(randomFill(target - plaintext.length - PAD_LEN_BYTES), plaintext.length + PAD_LEN_BYTES);
  }
  return out;
}

/**
 * 填充后字节 → 明文。**异常输入一律抛错**，绝不返回"看起来像原文"的错数据。
 */
export function unpadPlaintext(padded: Uint8Array): Uint8Array {
  if (padded.length < PAD_LEN_BYTES) throw new Error('填充数据过短，无法解析长度前缀');
  const origLen = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(0, false);
  if (origLen > padded.length - PAD_LEN_BYTES) {
    throw new Error(`填充长度前缀非法: 声称 ${origLen} 字节，但实际只有 ${padded.length - PAD_LEN_BYTES} 字节`);
  }
  return padded.slice(PAD_LEN_BYTES, PAD_LEN_BYTES + origLen);
}

export interface EncryptedEnvelope {
  /** 算法标识 */
  alg: string;
  /**
   * 明文是否经过长度填充。
   *
   * 为什么显式标记而不是"总是解填充"：解填充依赖长度前缀，
   * 而旧版本的信封没有前缀 —— 靠启发式判断（"前 4 字节看起来像长度吗"）
   * 会在小概率下把旧明文误判为填充数据，静默产出错误内容。
   * 显式标记让两种格式**可确定地区分**，新旧实现可混合组网。
   */
  pad?: boolean;
  /** base64：一次性 X25519 公钥 */
  epk: string;
  /** base64：12 字节 GCM nonce */
  iv: string;
  /** base64：密文 + GCM tag */
  ct: string;
}

const P = 2n ** 255n - 19n;

function leToBigInt(b: Uint8Array): bigint {
  let r = 0n;
  for (let i = b.length - 1; i >= 0; i--) r = (r << 8n) | BigInt(b[i]!);
  return r;
}

function bigIntToLe(n: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let x = n;
  for (let i = 0; i < len; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function mod(a: bigint): bigint {
  const r = a % P;
  return r >= 0n ? r : r + P;
}

function powMod(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = mod(result * b);
    b = mod(b * b);
    e >>= 1n;
  }
  return result;
}

/** Ed25519 公钥 → X25519 公钥（Montgomery u = (1+y)/(1-y)） */
export function ed25519PubToX25519(pub: Uint8Array): Uint8Array {
  const y = leToBigInt(pub) & ((1n << 255n) - 1n); // 清掉符号位
  const u = mod(mod(1n + y) * powMod(mod(1n - y), P - 2n));
  return bigIntToLe(u, 32);
}

/** Ed25519 私钥种子 → X25519 私钥（SHA-512 后取前 32 字节并 clamp） */
export function ed25519PrivToX25519(seed: Uint8Array): Uint8Array {
  const h = sha512(seed);
  const a = h.slice(0, 32);
  a[0]! &= 248;
  a[31]! &= 127;
  a[31]! |= 64;
  return a;
}

/**
 * X25519 ECDH：优先走 Node 原生 OpenSSL（约 20µs），否则回退到纯 JS（约 670µs）。
 */
function sharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return nativeX25519(privateKey, publicKey) ?? x25519.getSharedSecret(privateKey, publicKey);
}

/**
 * X25519 公钥推导：优先原生（约 30µs），否则纯 JS（约 600µs）。
 */
function x25519PublicKey(privateKey: Uint8Array): Uint8Array {
  return nativeX25519PublicKey(privateKey) ?? x25519.getPublicKey(privateKey);
}

/** did:key → X25519 公钥的转换结果缓存（纯数学，对同一地址恒定） */
const x25519PubCache = new Map<string, Uint8Array>();
const X25519_PUB_CACHE_LIMIT = 4096;

/** 由 did:key 地址直接得到该 Agent 的 X25519 加密公钥（带缓存） */
export function encryptionPublicKeyFromAddress(address: string): Uint8Array {
  const cached = x25519PubCache.get(address);
  if (cached) return cached;
  const pub = ed25519PubToX25519(publicKeyFromAddress(address));
  if (x25519PubCache.size >= X25519_PUB_CACHE_LIMIT) {
    const first = x25519PubCache.keys().next();
    if (!first.done) x25519PubCache.delete(first.value);
  }
  x25519PubCache.set(address, pub);
  return pub;
}

function toB64(b: Uint8Array): string {
  return btoa(String.fromCharCode(...b));
}

function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function aesGcmEncrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-GCM', false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, k, plaintext as BufferSource);
  return new Uint8Array(ct);
}

async function aesGcmDecrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, k, ciphertext as BufferSource);
  return new Uint8Array(pt);
}

/** 由 ECDH 共享密钥派生 AEAD 密钥 */
function deriveKey(shared: Uint8Array, epk: Uint8Array, recipientPub: Uint8Array): Uint8Array {
  const salt = new Uint8Array(epk.length + recipientPub.length);
  salt.set(epk, 0);
  salt.set(recipientPub, epk.length);
  return hkdf(sha256, shared, salt, HKDF_INFO, 32) as Uint8Array;
}

/**
 * 加密一段明文发给收件人。
 * @param recipientAddress 收件人的 did:key 地址
 * @param plaintext 明文（通常是 JSON 字符串）
 */
export async function encryptFor(
  recipientAddress: string,
  plaintext: string,
  ephemeralSeed?: Uint8Array
): Promise<EncryptedEnvelope> {
  // 参数类型前置校验。
  //
  // 为什么值得专门做：这两个函数都收「地址字符串 + 二进制」，参数序容易记错。
  // 实测把参数顺序写错时，原实现会一路跑到算法判断才报
  //   `不支持的加密算法: undefined`
  // —— 报的是密码学问题，真因却是参数类型不对，排障方向被完全带偏。
  // 这里改为立刻报出**正确的调用形状**。
  if (typeof recipientAddress !== 'string') {
    throw new TypeError(
      `encryptFor 第一个参数必须是收件人地址字符串，收到 ${typeof recipientAddress}。` +
        `调用形状：encryptFor(recipientAddress, plaintext, ephemeralSeed?)`
    );
  }
  const recipientPub = encryptionPublicKeyFromAddress(recipientAddress);
  let ephPriv: Uint8Array;
  let ephPub: Uint8Array;
  if (ephemeralSeed) {
    ephPriv = ed25519PrivToX25519(ephemeralSeed);
    ephPub = x25519PublicKey(ephPriv);
  } else {
    const native = nativeX25519KeyPair();
    if (native) {
      ephPriv = native.privateKey;
      ephPub = native.publicKey;
    } else {
      ephPriv = x25519.utils.randomSecretKey();
      ephPub = x25519.getPublicKey(ephPriv);
    }
  }
  const shared = sharedSecret(ephPriv, recipientPub);
  const key = deriveKey(shared, ephPub, recipientPub);

  const iv = randomBytes(12);
  // 加密前先做长度填充（`pad: true` 标记，接收方据此解填充）
  const raw = new TextEncoder().encode(plaintext);
  const padded = padPlaintext(raw);
  const didPad = padded.length !== raw.length;
  const ct = await aesGcmEncrypt(key, iv, padded);

  // 仅当真的填充过才标记 —— 大载荷不填充，信封也就不带 pad，
  // 接收方据此确定性地选择是否解填充（无需任何启发式判断）
  return didPad
    ? { alg: E2EE_ALG, epk: toB64(ephPub), iv: toB64(iv), ct: toB64(ct), pad: true }
    : { alg: E2EE_ALG, epk: toB64(ephPub), iv: toB64(iv), ct: toB64(ct) };
}

/**
 * 解密来自发件人的信封。
 * @param senderAddress 发件人的 did:key 地址（调用方据此确认发送者身份）
 * @param envelope 密文信封
 * @param recipientPrivateKey 收件人的 Ed25519 私钥种子
 */
export async function decryptFrom(
  senderAddress: string,
  envelope: EncryptedEnvelope,
  recipientPrivateKey: Uint8Array
): Promise<string> {
  // 同上：参数序记错时给出可执行的提示，而不是把方向带向"算法不支持"
  if (typeof senderAddress !== 'string') {
    throw new TypeError(
      `decryptFrom 第一个参数必须是发送方地址字符串，收到 ${typeof senderAddress}。` +
        `调用形状：decryptFrom(senderAddress, envelope, recipientPrivateKey)`
    );
  }
  if (!envelope || typeof envelope !== 'object') {
    throw new TypeError(
      `decryptFrom 第二个参数必须是加密信封对象，收到 ${typeof envelope}。` +
        `调用形状：decryptFrom(senderAddress, envelope, recipientPrivateKey)`
    );
  }
  if (!(recipientPrivateKey instanceof Uint8Array)) {
    throw new TypeError(
      `decryptFrom 第三个参数必须是收件人私钥 Uint8Array，收到 ${typeof recipientPrivateKey}。` +
        `调用形状：decryptFrom(senderAddress, envelope, recipientPrivateKey)`
    );
  }
  if (envelope.alg !== E2EE_ALG) {
    throw new Error(
      `不支持的加密算法: ${String(envelope.alg)}（期望 ${E2EE_ALG}）`
    );
  }
  if (!senderAddress.startsWith('did:key:')) throw new Error('senderAddress 必须是 did:key 地址');
  const recipientPriv = ed25519PrivToX25519(recipientPrivateKey);
  // 收件人自己算 X25519 公钥，保证与发送方的 HKDF salt 一致
  const recipientPub = x25519PublicKey(recipientPriv);
  const epk = fromB64(envelope.epk);
  const shared = sharedSecret(recipientPriv, epk);
  const key = deriveKey(shared, epk, recipientPub);
  const pt = await aesGcmDecrypt(key, fromB64(envelope.iv), fromB64(envelope.ct));
  // 仅当发送方标记了填充才解填充 —— 旧格式（无 pad 字段）按原样解码
  const raw = envelope.pad === true ? unpadPlaintext(pt) : pt;
  return new TextDecoder().decode(raw);
}

/** 判断一个 content 是否为加密信封 */
export function isEncrypted(content: unknown): content is EncryptedEnvelope {
  return (
    typeof content === 'object' &&
    content !== null &&
    (content as EncryptedEnvelope).alg === E2EE_ALG &&
    typeof (content as EncryptedEnvelope).ct === 'string'
  );
}
