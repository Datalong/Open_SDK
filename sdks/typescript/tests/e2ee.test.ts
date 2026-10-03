import { describe, it, expect } from 'vitest';
import { x25519 } from '@noble/curves/ed25519';
import { generateKeyPair, publicKeyFromAddress } from '../src/crypto.js';
import {
  E2EE_ALG,
  decryptFrom,
  ed25519PrivToX25519,
  ed25519PubToX25519,
  encryptFor,
  encryptionPublicKeyFromAddress,
  isEncrypted,
} from '../src/e2ee.js';

describe('e2ee', () => {
  it('Ed25519 → X25519 映射自洽（公私钥推导一致）', () => {
    for (let i = 0; i < 20; i++) {
      const kp = generateKeyPair();
      const pubFromPub = ed25519PubToX25519(kp.publicKey);
      const pubFromPriv = x25519.getPublicKey(ed25519PrivToX25519(kp.privateKey));
      expect(Buffer.from(pubFromPriv)).toEqual(Buffer.from(pubFromPub));
      // 与「由地址推导」一致
      expect(Buffer.from(encryptionPublicKeyFromAddress(kp.address))).toEqual(
        Buffer.from(pubFromPriv)
      );
    }
  });

  it('收发双方能正确加解密', async () => {
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const env = await encryptFor(bob.address, '你好，鲍勃');
    expect(env.alg).toBe(E2EE_ALG);
    expect(isEncrypted(env)).toBe(true);
    expect(await decryptFrom(alice.address, env, bob.privateKey)).toBe('你好，鲍勃');
  });

  it('密文不含明文（中继看不到内容）', async () => {
    const bob = generateKeyPair();
    const secret = '银行卡密码是 123456';
    const env = await encryptFor(bob.address, secret);
    const wire = JSON.stringify(env);
    expect(wire).not.toContain('银行卡');
    expect(wire).not.toContain('123456');
  });

  it('用错接收方私钥无法解密', async () => {
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const carol = generateKeyPair();
    const env = await encryptFor(bob.address, '只给鲍勃');
    await expect(decryptFrom(alice.address, env, carol.privateKey)).rejects.toThrow();
  });

  it('密文被篡改则解密失败（AEAD 认证）', async () => {
    const bob = generateKeyPair();
    const alice = generateKeyPair();
    const env = await encryptFor(bob.address, '原文');
    const raw = Buffer.from(env.ct, 'base64');
    raw[0] = raw[0]! ^ 0x01;
    const tampered = { ...env, ct: raw.toString('base64') };
    await expect(decryptFrom(alice.address, tampered, bob.privateKey)).rejects.toThrow();
  });

  it('同一明文两次加密得到不同密文与临时公钥（前向保密）', async () => {
    const bob = generateKeyPair();
    const a = await encryptFor(bob.address, '同样的话');
    const b = await encryptFor(bob.address, '同样的话');
    expect(a.ct).not.toBe(b.ct);
    expect(a.epk).not.toBe(b.epk);
  });

  it('由地址推导的加密公钥与身份一致（无需额外分发密钥）', () => {
    const kp = generateKeyPair();
    expect(publicKeyFromAddress(kp.address)).toEqual(kp.publicKey);
    expect(encryptionPublicKeyFromAddress(kp.address).length).toBe(32);
  });
});
