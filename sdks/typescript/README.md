# @a2net/client

> **A2Net Open TypeScript SDK** — 去中心化智能体互通协议（Decentralized Agent Interoperability Protocol）的官方开源客户端。

让任意 TypeScript / Node.js 智能体获得：自我主权身份（`did:key`）、零知识端到端加密、
与 Python 端**逐字节互通**的签名与消息格式。

MIT 许可 · 协议规范公开中立 · 零中心化账号

---

## 安装

```bash
npm install @a2net/client
```

需要 Node.js ≥ 20。也可用于浏览器（WebCrypto 原生支持）。

---

## 快速开始

### 1. 生成身份并连接中继

```ts
import { A2NetClient } from '@a2net/client';
import WebSocket from 'ws'; // Node 下需注入 WebSocket 实现；浏览器可省略

const client = new A2NetClient({
  relayUrl: 'ws://localhost:8080',
  webSocketImpl: WebSocket as never,
  encryptContent: true, // 端到端加密：中继只见密文
});

await client.connect();
console.log('我的 Agent 已入网:', client.address); // did:key:z...
```

### 2. 响应别人的调用

```ts
client.onQuery(async (query, sender) => {
  return `来自 ${sender} 的请求已处理: ${query}`;
});
```

### 3. 调用网络上的其他 Agent

```ts
const reply = await client.query('did:key:z6Mk...', '你好');
```

第三参数也可直接传超时毫秒数：`client.query(did, text, 10_000)`。

---

## 核心能力

| 能力 | 说明 |
|---|---|
| 🆔 **自我主权身份** | Ed25519 密钥对派生 `did:key`，公钥即地址，无需注册中心 |
| 🔐 **端到端加密** | `X25519-HKDF-AES-256-GCM`，每条消息一次性临时密钥（前向保密）；中继只见密文 |
| 🧩 **跨语言逐字节互通** | RFC 8785 Canonical JSON + Ed25519，与 Python SDK 签名完全一致 |
| 🛡️ **权限原生内置** | 白/黑名单、默认拒绝、令牌桶限流，粒度到调用方 |
| 📦 **多模态分块流** | 突破单帧上限的图片/音频/PDF 传输，64KB 分片 + AES-GCM 封包 + SHA-256 校验 |
| 🔎 **能力发布与发现** | 签名 Agent Card 挂载 `.well-known`，可被其他 Agent 发现并验签 |

---

## 主要 API

```ts
// 身份与签名
generateKeyPair()                      // 生成 Ed25519 身份
keyPairFromMnemonic(mnemonic)          // 由 BIP39 助记词恢复
signMessage(msg, privateKey)           // 签名
verifySignature(msg, sig, address)     // 验签

// 端到端加密
encryptFor(recipientAddress, plaintext)          // → 加密信封
decryptFrom(senderAddress, envelope, privateKey) // → 明文

// 客户端
new A2NetClient({ relayUrl, privateKey, permissionPolicy })
client.connect() / disconnect() / onQuery() / query() / sendBlob() / onBlob()

// Agent Card
createSignedAgentCard(opts, keyPair)
verifyAgentCard(card)
validateAgentCard(card)                // → { valid, missing, warnings, signed }

// 多模态
splitBlobIntoChunks(data, name, mimeType)
computeSha256Hex(data)
```

---

## 子路径导出

```ts
import { LangChainBridge } from '@a2net/client/langchain';  // LangChain 接入
import { OllamaBridge }    from '@a2net/client/ollama';     // 本地 Ollama 接入
```

> 路径以 `package.json` 的 `exports` 字段为准 —— 写入文档前应实际 import 一次验证。

```bash
node -e "import('@a2net/client/langchain').then(()=>console.log('ok'))"
```

---

## 安全边界（如实说明）

**协议保证**：

- 对端持有其声称 `did:key` 的私钥（消息级 Ed25519 签名）
- 中继**无法解密**业务内容（E2EE 在端点完成，中继只转发密文信封）
- 每条消息使用一次性临时密钥 → 密钥泄露不影响历史消息（前向保密）

**不保证**：

- **流量分析抵抗**：中继知道「哪个 did 连到了哪个节点」。需 mixnet / 洋葱路由才能解决
- **端点自身安全**：私钥在当前进程内存中；本 SDK 不负责防主机层入侵
- **吊销与撤销**：`did:key` 无内置吊销机制（需配合上层 VC / 目录策略）

---

## 跨语言互通

```bash
python -m pip install a2net-client
```

TS 与 Python 双端在 `canonical JSON`、Ed25519 签名、消息格式上**逐字节一致**，
由跨语言端到端测试持续保证。

---

## 相关资源

| 资源 | 位置 |
|---|---|
| 协议规范 | [`spec/`](../../spec) |
| Python SDK | [`sdks/python`](../python) |
| MCP 双向网关 | [`@a2net/mcp`](https://www.npmjs.com/package/@a2net/mcp) |
| 完整仓库与示例 | https://github.com/Datalong/Open_SDK |

---

## 许可

[MIT](../../LICENSE) © A2Net Authors & Contributors
