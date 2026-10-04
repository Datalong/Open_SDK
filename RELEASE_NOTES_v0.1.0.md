# A2Net v0.1.0 — Sovereign, End-to-End Encrypted Agent Interoperability

首个公开发布。A2Net 是一套**开放、去中心化的智能体互通协议**：
让任意框架实现的个人智能体都能被全网发现、端到端加密调用、按次结算。

> 协议规范公开中立可自由实现；本仓库为 MIT 许可的参考实现（TypeScript + Python）。

---

## 这是什么

现有 AI Agent 被困在中心化平台孤岛里 —— 不同平台的 Agent 无法互相调用，
用户的数据与能力被锁定在单一厂商。A2Net 把「Agent 之间怎么说话」定义成开放协议：

| 能力 | 说明 |
|---|---|
| 🆔 **自我主权身份** | 基于 W3C `did:key`，Ed25519 公钥即地址。私钥只在本地，网络层永不可见 |
| 🔐 **端到端加密** | `X25519-HKDF-AES-256-GCM`，每条消息一次性临时密钥（前向保密）；中继只见密文 |
| 🧱 **中继不可信** | Relay 只按外层 `to` 转发密文，不解析内容、不验签、不存储、不记日志 |
| 🧩 **跨语言逐字节互通** | RFC 8785 Canonical JSON + Ed25519，TS 与 Python 签名完全一致（有互操作测试保证） |
| 🛡️ **权限原生内置** | 白/黑名单、默认拒绝、令牌桶限流，粒度到调用方 |
| 📦 **多模态分块流** | 突破单帧上限的图片/音频/PDF 传输，64KB 分片 + 密文封包 + SHA-256 校验 |
| 🔎 **能力发布与发现** | 签名 Agent Card 挂载 `.well-known`，可被其他 Agent 发现并验签 |

---

## 本次发布内容

### `@a2net/client` (npm) · TypeScript SDK

```bash
npm install @a2net/client
```

```ts
import { A2NetClient } from '@a2net/client';
import WebSocket from 'ws';

const client = new A2NetClient({
  relayUrl: 'ws://localhost:8080',
  webSocketImpl: WebSocket as never,
  encryptContent: true,          // 中继只见密文
});
client.onQuery(async (q, sender) => `已处理来自 ${sender} 的请求: ${q}`);
await client.connect();
console.log(client.address);      // did:key:z...
```

子路径导出：`@a2net/client/langchain`、`@a2net/client/ollama`

### `a2net-client` (PyPI) · Python SDK

```bash
python -m pip install a2net-client
```

```python
import a2net
kp = a2net.generate_keypair()
card = a2net.sign_agent_card(a2net.create_agent_card(
    did=kp.address, name="MyAgent", description="...",
    url="http://localhost:8000/.well-known/agent-description.json",
), kp)
```

与 TypeScript 端**逐字节互通**（同一套 did:key、canonical JSON、消息格式）。

### `@a2net/mcp` (npm) · MCP 双向网关

把 MCP Server 挂载为 A2Net 节点，或把 A2Net 全网暴露为标准 MCP Server：

```bash
npm install @a2net/mcp
```

### 协议规范

`spec/index.html` — 单页零依赖规范文档。

---

## 质量与验证

本版本在发布前完成了多层验证，并修复了 **31 个真实缺陷**（含若干用户可见的严重问题）：

| 层 | 覆盖 |
|---|---|
| 单元 / 集成 | 380+ 例 |
| 跨语言 E2E | TS ↔ Relay ↔ Python 闭环 |
| 发布产物体检 | pack → 装进干净项目 → 真实使用（本仓库 `npm run preflight`） |

发布产物体检发现的典型问题（均已修复）：
- tarball 曾**不含 README 与 LICENSE** —— 公开包缺许可文件会造成法务歧义
- 子路径导出曾在 `package.json` 声明但实际不可 import

---

## 安全边界（如实说明）

**协议保证**：对端持有其声称 `did:key` 的私钥；中继无法解密业务内容；每条消息一次性临时密钥。

**不保证**：
- **流量分析抵抗** —— 中继知道「哪个 did 连到哪个节点」，需 mixnet / 洋葱路由
- **端点自身安全** —— 私钥在当前进程内存中，本 SDK 不负责防主机层入侵
- **`did:key` 吊销** —— 无内置吊销机制，需配合上层 VC / 目录策略

---

## 后续计划

- 更多框架适配（AutoGen / CrewAI 等）
- 中继联邦的分片与信誉治理细化
- 协议 v0.2 讨论（多轮对话、`did:web`）

---

## 链接

- 协议规范：[`spec/`](./spec)
- 完整仓库：https://github.com/Datalong/Open_SDK
- 问题反馈：https://github.com/Datalong/Open_SDK/issues

**License**: MIT
