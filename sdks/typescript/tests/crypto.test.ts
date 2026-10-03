import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  canonicalJson,
  getSignString,
  signMessage,
  verifySignature,
  keyPairFromMnemonic,
  generateMnemonicWords,
  encryptPrivateKey,
  decryptPrivateKey,
  addressFromPublicKey,
  publicKeyFromAddress,
} from '../src/crypto.js';

describe('crypto', () => {
  it('generates valid did:key address', () => {
    const kp = generateKeyPair();
    expect(kp.privateKey.length).toBe(32);
    expect(kp.publicKey.length).toBe(32);
    expect(kp.address.startsWith('did:key:z')).toBe(true);
    const pub = publicKeyFromAddress(kp.address);
    expect(Buffer.from(pub).equals(Buffer.from(kp.publicKey))).toBe(true);
    expect(addressFromPublicKey(pub)).toBe(kp.address);
  });

  it('rejects malformed address', () => {
    expect(() => publicKeyFromAddress('did:web:example.com')).toThrow();
  });

  it('canonicalJson sorts keys recursively', () => {
    const a = canonicalJson({ b: 1, a: { d: 2, c: 3 } });
    const b = canonicalJson({ a: { c: 3, d: 2 }, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":{"c":3,"d":2},"b":1}');
  });

  it('canonicalJson preserves array order', () => {
    expect(canonicalJson([3, 1, 2])).toBe('[3,1,2]');
  });

  it('signs and verifies; tampering fails', () => {
    const kp = generateKeyPair();
    const msg = {
      id: '1',
      from: kp.address,
      to: 'x',
      type: 'query',
      content: { query: 'hi' },
      timestamp: 1,
    };
    const s = getSignString(msg);
    const sig = signMessage(s, kp.privateKey);
    expect(verifySignature(s, sig, kp.address)).toBe(true);

    const tampered = getSignString({ ...msg, content: { query: 'bye' } });
    expect(verifySignature(tampered, sig, kp.address)).toBe(false);
  });

  it('derives deterministic key from mnemonic', () => {
    const m = generateMnemonicWords(128);
    const kp1 = keyPairFromMnemonic(m);
    const kp2 = keyPairFromMnemonic(m);
    expect(kp1.address).toBe(kp2.address);
  });

  it('rejects invalid mnemonic', () => {
    expect(() => keyPairFromMnemonic('not a real mnemonic')).toThrow();
  });

  it('encrypts and decrypts keystore', async () => {
    const kp = generateKeyPair();
    const ks = await encryptPrivateKey(kp.privateKey, 'pw123', kp.address);
    const priv = await decryptPrivateKey(ks, 'pw123');
    expect(Buffer.from(priv).equals(Buffer.from(kp.privateKey))).toBe(true);
  });

  it('rejects wrong password', async () => {
    const kp = generateKeyPair();
    const ks = await encryptPrivateKey(kp.privateKey, 'pw123', kp.address);
    await expect(decryptPrivateKey(ks, 'wrong')).rejects.toThrow();
  });
});
