/**
 * crypto.ts — A2Net 身份与加密核心
 *
 * 设计要点：
 * - 身份 = Ed25519 密钥对，地址 = did:key:z + Base58(公钥)
 * - 私钥永不离开本机；密钥库用 Argon2id + AES-256-GCM 加密
 * - canonicalJson 是签名规范的唯一真源（递归排序键，紧凑序列化）
 */
import { ed25519 } from '@noble/curves/ed25519';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';
import { randomBytes, utf8ToBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { argon2id } from 'hash-wasm';
import bs58 from 'bs58';
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { nativeEd25519Sign, nativeEd25519Verify } from './native-crypto.js';

// AES-GCM 使用 WebCrypto（Node 18+ 与浏览器均可用）
const webcrypto: Crypto = globalThis.crypto;

export const DID_PREFIX = 'did:key:z';

export interface KeyPair {
  /** 32 字节 Ed25519 私钥种子 */
  privateKey: Uint8Array;
  /** 32 字节 Ed25519 公钥 */
  publicKey: Uint8Array;
  /** did:key:z... */
  address: string;
}

// ---------------------------------------------------------------------------
// 密钥生成与地址
// ---------------------------------------------------------------------------

export function generateKeyPair(): KeyPair {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey, address: addressFromPublicKey(publicKey) };
}

export function addressFromPublicKey(publicKey: Uint8Array): string {
  return DID_PREFIX + bs58.encode(publicKey);
}

export function publicKeyFromAddress(address: string): Uint8Array {
  if (!address.startsWith(DID_PREFIX)) {
    throw new Error(`Invalid did:key address: ${address}`);
  }
  const pub = bs58.decode(address.slice(DID_PREFIX.length));
  if (pub.length !== 32) {
    throw new Error(`Invalid public key length: ${pub.length}`);
  }
  return pub;
}

export function keyPairFromPrivateKey(privateKey: Uint8Array): KeyPair {
  if (privateKey.length !== 32) {
    throw new Error('Ed25519 private key must be 32 bytes');
  }
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey, address: addressFromPublicKey(publicKey) };
}

// ---------------------------------------------------------------------------
// BIP39 助记词 + SLIP-0010 (Ed25519) 派生
// ---------------------------------------------------------------------------

const HARDENED_OFFSET = 0x80000000;

/** 生成 12 或 24 词助记词 */
export function generateMnemonicWords(strength: 128 | 256 = 128): string {
  return generateMnemonic(wordlist, strength);
}

export function isValidMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic, wordlist);
}

function ser32(index: number): Uint8Array {
  const out = new Uint8Array(4);
  out[0] = (index >>> 24) & 0xff;
  out[1] = (index >>> 16) & 0xff;
  out[2] = (index >>> 8) & 0xff;
  out[3] = index & 0xff;
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * SLIP-0010 Ed25519 分层派生（所有索引强制 hardened）
 * 路径示例：m/44'/501'/0'/0'
 */
export function deriveEd25519Path(seed: Uint8Array, path: string): Uint8Array {
  const segments = path
    .split('/')
    .filter((s) => s !== 'm' && s.length > 0)
    .map((s) => {
      const hardened = s.endsWith("'") || s.endsWith('h');
      const n = parseInt(hardened ? s.slice(0, -1) : s, 10);
      if (Number.isNaN(n)) throw new Error(`Invalid path segment: ${s}`);
      return n + HARDENED_OFFSET;
    });

  // master: I = HMAC-SHA512(key="ed25519 seed", data=seed)
  const key0 = utf8ToBytes('ed25519 seed');
  let I = hmac(sha512, key0, seed);
  let key = I.slice(0, 32);
  let chainCode = I.slice(32);

  for (const index of segments) {
    // 数据 = 0x00 || key || ser32(index)
    const data = concat(new Uint8Array([0]), key, ser32(index));
    I = hmac(sha512, chainCode, data);
    key = I.slice(0, 32);
    chainCode = I.slice(32);
  }
  return key;
}

/** 助记词 → Ed25519 私钥（默认路径 m/44'/501'/0'/0' 即 Solana 风格） */
export function keyPairFromMnemonic(
  mnemonic: string,
  path = "m/44'/501'/0'/0'",
  passphrase = ''
): KeyPair {
  if (!validateMnemonic(mnemonic, wordlist)) {
    throw new Error('Invalid mnemonic');
  }
  const seed = mnemonicToSeedSync(mnemonic, passphrase);
  const privateKey = deriveEd25519Path(seed, path);
  return keyPairFromPrivateKey(privateKey);
}

// ---------------------------------------------------------------------------
// Canonical JSON（签名规范唯一真源）
// ---------------------------------------------------------------------------

/**
 * 递归按 key 字典序排序后序列化为紧凑 JSON。
 * 拒绝 undefined / 非有限数字，避免不同实现产生不同字符串。
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite number in canonical JSON');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map((v) => canonicalJson(v)).join(',') + ']';
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      if (obj[k] === undefined) continue;
      parts.push(JSON.stringify(k) + ':' + canonicalJson(obj[k]));
    }
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`Unsupported type in canonical JSON: ${typeof value}`);
}

// ---------------------------------------------------------------------------
// 签名 / 验签
// ---------------------------------------------------------------------------

export const SIGN_FIELDS = ['content', 'from', 'id', 'timestamp', 'to', 'type'] as const;

/** 从完整消息构建待签名字符串（只取核心六字段，递归排序） */
export function getSignString(msg: Record<string, unknown>): string {
  const subset: Record<string, unknown> = {};
  for (const f of SIGN_FIELDS) {
    if (!(f in msg)) throw new Error(`Missing field for signing: ${f}`);
    subset[f] = msg[f];
  }
  return canonicalJson(subset);
}

export function signMessage(messageStr: string, privateKey: Uint8Array): string {
  const msg = utf8ToBytes(messageStr);
  // Node 原生 OpenSSL 路径，比纯 JS 快约 14×
  const native = nativeEd25519Sign(msg, privateKey);
  if (native) return bytesToBase64(native);
  return bytesToBase64(ed25519.sign(msg, privateKey));
}

export function verifySignature(messageStr: string, signature: string, address: string): boolean {
  try {
    const pub = publicKeyFromAddress(address);
    const sig = base64ToBytes(signature);
    const msg = utf8ToBytes(messageStr);
    // Node 原生 OpenSSL 路径，比纯 JS 快约 26×
    const native = nativeEd25519Verify(msg, sig, pub);
    if (native !== null) return native;
    // Ed25519 为确定性签名，不需要 lowS 之外的选项
    return ed25519.verify(sig, msg, pub);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// 加密密钥库（Argon2id + AES-256-GCM）
// ---------------------------------------------------------------------------

export interface EncryptedKeystore {
  version: 1;
  kdf: 'argon2id';
  salt: string; // base64
  nonce: string; // base64 (12 bytes)
  ciphertext: string; // base64
  address: string; // did:key，用于校验解密结果
  createdAt: number;
}

const ARGON2_PARAMS = { parallelism: 1, iterations: 3, memorySize: 65536, hashLength: 32, outputType: 'binary' as const };

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(b64, 'base64'));
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToHexStr(b: Uint8Array): string {
  return bytesToHex(b);
}
export function hexStrToBytes(s: string): Uint8Array {
  return hexToBytes(s);
}

async function deriveKeystoreKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const key = await argon2id({ password, salt, ...ARGON2_PARAMS });
  return key as Uint8Array;
}

/** TS 5.7 起 Uint8Array<ArrayBufferLike> 与 BufferSource 不完全兼容，统一转换 */
function toBuf(u8: Uint8Array): BufferSource {
  return u8 as unknown as BufferSource;
}

export async function encryptPrivateKey(
  privateKey: Uint8Array,
  password: string,
  address: string
): Promise<EncryptedKeystore> {
  const salt = randomBytes(16);
  const nonce = randomBytes(12);
  const key = await deriveKeystoreKey(password, salt);
  const cryptoKey = await webcrypto.subtle.importKey('raw', toBuf(key), { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv: toBuf(nonce) }, cryptoKey, toBuf(privateKey));
  return {
    version: 1,
    kdf: 'argon2id',
    salt: bytesToBase64(salt),
    nonce: bytesToBase64(nonce),
    ciphertext: bytesToBase64(new Uint8Array(ct)),
    address,
    createdAt: Date.now(),
  };
}

export async function decryptPrivateKey(
  keystore: EncryptedKeystore,
  password: string
): Promise<Uint8Array> {
  const salt = base64ToBytes(keystore.salt);
  const nonce = base64ToBytes(keystore.nonce);
  const key = await deriveKeystoreKey(password, salt);
  const cryptoKey = await webcrypto.subtle.importKey('raw', toBuf(key), { name: 'AES-GCM' }, false, ['decrypt']);
  let plain: ArrayBuffer;
  try {
    plain = await webcrypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toBuf(nonce) },
      cryptoKey,
      toBuf(base64ToBytes(keystore.ciphertext))
    );
  } catch {
    throw new Error('Wrong password or corrupted keystore');
  }
  const priv = new Uint8Array(plain);
  // 地址校验：解密出的公钥必须与 keystore.address 一致
  if (addressFromPublicKey(ed25519.getPublicKey(priv)) !== keystore.address) {
    throw new Error('Keystore address mismatch');
  }
  return priv;
}
