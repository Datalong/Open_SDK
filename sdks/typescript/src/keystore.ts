/**
 * keystore.ts — 生产级磁盘加密密钥库管理器 (Persistent Encrypted Keystore Manager)
 *
 * 采用环境自适应导入（动态 import node:fs/promises 与 node:path），保证浏览器打包（Vite/Webpack）零冲突，
 * 服务端（Node.js / Bun）运行时提供完整的磁盘安全加密存储。
 */
import {
  encryptPrivateKey,
  decryptPrivateKey,
  keyPairFromPrivateKey,
  type EncryptedKeystore,
  type KeyPair,
} from './crypto.js';

export class FileKeystore {
  private constructor(
    public readonly filePath: string,
    public readonly keystore: EncryptedKeystore
  ) {}

  /** 获取与该密钥库绑定的 DID 标识 */
  get address(): string {
    return this.keystore.address;
  }

  /**
   * 解密并获取可用于初始化的 KeyPair
   */
  async unlock(password: string): Promise<KeyPair> {
    const rawPrivateKey = await decryptPrivateKey(this.keystore, password);
    return keyPairFromPrivateKey(rawPrivateKey);
  }

  /**
   * 从已有的 KeyPair 或新生成身份保存加密密钥库至指定文件路径
   */
  static async save(
    filePath: string,
    keyPair: KeyPair,
    password: string
  ): Promise<FileKeystore> {
    const fs = await import('node:fs/promises');
    const path = await import('node:path');
    const keystore = await encryptPrivateKey(keyPair.privateKey, password, keyPair.address);
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, JSON.stringify(keystore, null, 2), 'utf-8');
    return new FileKeystore(filePath, keystore);
  }

  /**
   * 从磁盘读取加密密钥库
   */
  static async load(filePath: string): Promise<FileKeystore> {
    const fs = await import('node:fs/promises');
    const content = await fs.readFile(filePath, 'utf-8');
    const keystore = JSON.parse(content) as EncryptedKeystore;
    if (!keystore.address || !keystore.ciphertext || keystore.version !== 1) {
      throw new Error(`无效的 A2Net 密钥库文件格式: ${filePath}`);
    }
    return new FileKeystore(filePath, keystore);
  }

  /**
   * 便捷方法：读取并直接使用密码解密
   */
  static async loadAndUnlock(filePath: string, password: string): Promise<KeyPair> {
    const store = await FileKeystore.load(filePath);
    return store.unlock(password);
  }
}
