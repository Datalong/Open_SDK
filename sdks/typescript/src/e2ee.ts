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
export interface EncryptedEnvelope {
  /** 算法标识 */
  alg: string;
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
  const ct = await aesGcmEncrypt(key, iv, new TextEncoder().encode(plaintext));

  return { alg: E2EE_ALG, epk: toB64(ephPub), iv: toB64(iv), ct: toB64(ct) };
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
  if (envelope.alg !== E2EE_ALG) throw new Error(`不支持的加密算法: ${envelope.alg}`);
  if (!senderAddress.startsWith('did:key:')) throw new Error('senderAddress 必须是 did:key 地址');
  const recipientPriv = ed25519PrivToX25519(recipientPrivateKey);
  // 收件人自己算 X25519 公钥，保证与发送方的 HKDF salt 一致
  const recipientPub = x25519PublicKey(recipientPriv);
  const epk = fromB64(envelope.epk);
  const shared = sharedSecret(recipientPriv, epk);
  const key = deriveKey(shared, epk, recipientPub);
  const pt = await aesGcmDecrypt(key, fromB64(envelope.iv), fromB64(envelope.ct));
  return new TextDecoder().decode(pt);
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
