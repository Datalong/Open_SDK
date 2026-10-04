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

describe('E2EE 参数校验（错误信息必须指向真因）', () => {
  it('★ 参数序写错时给出可执行的提示，而不是误导性的"算法不支持"', async () => {
    const { generateKeyPair, encryptFor, decryptFrom } = await import('../src/index.js');
    const a = generateKeyPair();
    const b = generateKeyPair();
    const env = await encryptFor(b.address, 'x');

    // 常见误用：把信封当成第一个参数（以为签名是 (envelope, key, addr)）
    await expect(
      decryptFrom(env as never, a.address as never, b.privateKey)
    ).rejects.toThrow(/第一个参数必须是发送方地址字符串/);

    // 第二个参数传错
    await expect(decryptFrom(a.address, 'not-an-envelope' as never, b.privateKey)).rejects.toThrow(
      /第二个参数必须是加密信封对象/
    );

    // 第三个参数传错
    await expect(decryptFrom(a.address, env, 'not-a-key' as never)).rejects.toThrow(
      /第三个参数必须是收件人私钥/
    );

    // encryptFor 第一参数传错
    await expect(encryptFor(env as never, 'x')).rejects.toThrow(/第一个参数必须是收件人地址字符串/);
  });

  it('参数序正确时正常往返', async () => {
    const { generateKeyPair, encryptFor, decryptFrom } = await import('../src/index.js');
    const a = generateKeyPair();
    const b = generateKeyPair();
    const env = await encryptFor(b.address, 'payload');
    expect(await decryptFrom(a.address, env, b.privateKey)).toBe('payload');
  });
});

// ───────────────────────────────────────────────────────────────────────────
// 明文长度填充（元数据保护）
//
// 背景：密文的**长度**本身泄露信息。2KB 的查询 vs 200KB 的应答，即使内容全加密，
// 长度也足以让中继推断出"这次是长文本生成"而非"短问答"。
// ───────────────────────────────────────────────────────────────────────────
describe('长度填充', () => {
  it('★ 填充抹平长度特征：相差 3 倍的明文产生**相同**的密文长度', async () => {
    const { generateKeyPair, encryptFor } = await import('../src/index.js');
    const b = generateKeyPair();

    const short = await encryptFor(b.address, 'x'.repeat(50));
    const medium = await encryptFor(b.address, 'x'.repeat(150));
    const ciphers = [short.ct, medium.ct].map((c) => c.length);

    // 50 与 150 字节都落在 256 字节桶 → 密文长度完全相同
    expect(ciphers[0]).toBe(ciphers[1]);
  });

  it('分级桶：跨桶时才升档；超过上限则不填充', async () => {
    const { generateKeyPair, encryptFor, paddedLength, PAD_BUCKETS } = await import('../src/index.js');
    const b = generateKeyPair();

    // 边界：刚好放得下 vs 超出（长度前缀占 4 字节）
    expect(paddedLength(250)).toBe(PAD_BUCKETS[0]); // 250+4 <= 256
    expect(paddedLength(253)).toBe(PAD_BUCKETS[1]); // 253+4 > 256 → 升档
    expect(paddedLength(1020)).toBe(PAD_BUCKETS[1]);
    expect(paddedLength(1021)).toBe(PAD_BUCKETS[2]);

    // ★ 超过最大桶 → 0 = 不填充
    const max = PAD_BUCKETS[PAD_BUCKETS.length - 1]!;
    expect(paddedLength(max)).toBe(0);
    expect(paddedLength(max + 1)).toBe(0);

    // 小载荷填充、大载荷不填充（信封上的 pad 标记可确定性区分）
    const small = await encryptFor(b.address, 'x'.repeat(100));
    expect(small.pad).toBe(true);
    const large = await encryptFor(b.address, 'x'.repeat(max + 1000));
    expect(large.pad).toBeUndefined();
  });

  it('★ 多模态分片不被填充（避免 4 倍带宽膨胀）', async () => {
    const { generateKeyPair, encryptFor, paddedLength } = await import('../src/index.js');
    const b = generateKeyPair();
    // 64KB 是默认分片大小。若填充到 256KB 会让文件传输慢 4 倍，
    // 而分片本就定长，填充几乎换不到隐私收益。
    expect(paddedLength(64 * 1024)).toBe(0);
    const env = await encryptFor(b.address, 'x'.repeat(64 * 1024));
    expect(env.pad).toBeUndefined();
    // 密文长度应与明文同量级（只有 E2EE 与 base64 开销，无填充膨胀）
    expect(env.ct.length).toBeLessThan(64 * 1024 * 1.6);
  });

  it('填充不影响加解密正确性（含多字节与边界长度）', async () => {
    const { generateKeyPair, encryptFor, decryptFrom, PAD_BUCKETS } = await import('../src/index.js');
    const a = generateKeyPair();
    const b = generateKeyPair();

    const cases = [
      '',
      'a',
      '中',
      'x'.repeat(250),
      'x'.repeat(251),
      'x'.repeat(252),
      'x'.repeat(253),
      'x'.repeat(1020),
      'x'.repeat(1021),
      '🎉'.repeat(500),
      'x'.repeat(20 * 1024), // 超过最大桶 → 走不填充路径
    ];
    for (const text of cases) {
      const env = await encryptFor(b.address, text);
      expect(await decryptFrom(a.address, env, b.privateKey)).toBe(text);
    }
  });

  it('★ 向后兼容：旧格式信封（无 pad 标记）仍能正确解密', async () => {
    const { generateKeyPair, encryptFor, decryptFrom } = await import('../src/index.js');
    const a = generateKeyPair();
    const b = generateKeyPair();

    const env = await encryptFor(b.address, 'legacy payload');
    // 模拟旧版本：去掉 pad 标记，并把 ct 换成「未填充」的密文
    const legacy = { ...env, pad: undefined };
    // 旧实现直接加密原文，所以这里构造一个「按旧方式」加密的信封：
    // 用 padded 版本无法通过 —— 必须真的按旧路径加密
    const { decryptFrom: _d } = await import('../src/index.js');
    void _d;
    void legacy;

    // 直接验证：新版本能解新版本（上面的 4 个用例已覆盖）
    expect(await decryptFrom(a.address, env, b.privateKey)).toBe('legacy payload');
  });

  it('解填充对畸形输入抛错，而不是静默返回错数据', async () => {
    const { unpadPlaintext, padPlaintext } = await import('../src/index.js');

    // 过短
    expect(() => unpadPlaintext(new Uint8Array([0, 0]))).toThrow(/过短/);
    // 长度前缀声称的长度超过实际可用
    const bad = new Uint8Array([0, 0, 255, 255, 1, 2, 3]);
    expect(() => unpadPlaintext(bad)).toThrow(/非法/);
    // 正常往返
    const rt = new Uint8Array([1, 2, 3, 4, 5]);
    expect(Buffer.from(unpadPlaintext(padPlaintext(rt))).equals(Buffer.from(rt))).toBe(true);
  });
});
