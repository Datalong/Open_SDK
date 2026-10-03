# A2Net Open SDK & Protocol Specification

[![Open_SDK CI](https://github.com/Datalong/Open_SDK/actions/workflows/ci.yml/badge.svg)](https://github.com/Datalong/Open_SDK/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![npm @a2net/client](https://img.shields.io/badge/npm-%40a2net%2Fclient-CB3837.svg)](https://www.npmjs.com/package/@a2net/client)
[![PyPI a2net-client](https://img.shields.io/badge/pypi-a2net--client-3776AB.svg)](https://pypi.org/project/a2net-client/)
[![Protocol](https://img.shields.io/badge/Spec-RFC--Standard-green.svg)](./spec/index.html)

> **A2Net (Autonomous Agent Network)** is the open, decentralized interoperability protocol for AI agents.  
> It gives every autonomous agent a cryptographic self-sovereign identity (`did:key`), zero-knowledge end-to-end encryption (E2EE), and cross-language compatibility.

---

## 🌟 Why A2Net Protocol?

Existing AI agents are trapped in centralized API silos. A2Net solves the multi-agent connectivity bottleneck:

1. 🔑 **Self-Sovereign Identity**: No centralized accounts or API keys required. Agents derive identities from Ed25519 keypairs (`did:key:z...`).
2. 🔒 **Zero-Knowledge E2EE**: All agent-to-agent queries and responses are encrypted end-to-end (`X25519-HKDF-AES-256-GCM`). Network relays only see encrypted envelopes and routing headers.
3. 🧩 **Byte-Level Cross-Language Interop**: Built on RFC 8785 Canonical JSON, ensuring identical cryptographic signatures across TypeScript and Python runtimes.
4. 🔎 **Decentralized Discovery**: Standardized ANP-07/08 Agent Cards allow agents to dynamically crawl, verify, and invoke external capabilities.
5. 📦 **Encrypted Multimodal Blobs**: 64KB chunked streaming for images, audio and documents, layered with E2EE and per-chunk + whole-file SHA-256 verification — no single-frame size limits.

---

## 📂 Repository Structure

```
Open_SDK/
├── spec/                 # 📄 A2Net 协议规范全集 (RFC 规范正文 & 交互式静态标准页)
│   ├── index.html        # 规范可读可视化标准文档
│   └── README.md
├── sdks/
│   ├── typescript/       # 💻 开源 TypeScript 客户端 SDK (@a2net/client)
│   └── python/           # 🐍 开源 Python 客户端 SDK (a2net-client)
├── examples/             # 🚀 快速上手演示代码 (TS & Python)
│   ├── typescript-quickstart.ts
│   ├── typescript-multimodal.ts   # 多模态分块加密传输演示
│   ├── python-quickstart.py
│   └── python-multimodal.py
├── LICENSE               # MIT 开源许可证
└── README.md             # 本文档
```

---

## 🚀 5-Minute Quickstart

> 本仓库为 npm workspace monorepo。根目录执行 `npm install` 即可安装 TS SDK 与示例依赖，
> 本地自建中继后可直接跑通示例：`npm run example:ts` / `npm run example:py` /
> `npm run example:ts:multimodal` / `npm run example:py:multimodal`。

### 1. TypeScript / JavaScript

Install the client:
```bash
npm install @a2net/client ws
```

Write an agent in 15 lines of code:
```ts
import WebSocket from 'ws';
import { A2NetClient } from '@a2net/client';

const agent = new A2NetClient({
  relayUrl: 'ws://127.0.0.1:8080', // 本地自建中继，或你的公网 wss:// 中继
  encryptContent: true,                 // 启用原生端到端加密
  webSocketImpl: WebSocket as any,
});

// 处理入站提问
agent.onQuery(async (query, senderDid) => {
  return `Agent 已收到并处理你的提问: "${query}"`;
});

await agent.connect();
console.log('我的 Agent DID 地址:', agent.address);

// 向网络中的另一个 Agent 发起加密提问
const response = await agent.query('did:key:z6MkuTargetAgent...', '请提供最新行业分析');
console.log('解密响应:', response);
```

### 2. Python (3.9+)

Install dependencies:
```bash
pip install cryptography websockets
pip install -e ./sdks/python
```

Run a Python Agent:
```python
import asyncio
from a2net import A2NetClient, PermissionPolicy

async def main():
    agent = A2NetClient(
        relay_url="ws://127.0.0.1:8080",
        encrypt_content=True,
        permission_policy=PermissionPolicy(default_allow=True),
    )

    async def handle_query(query: str, sender: str, msg: dict) -> str:
        return f"Python Agent 回复: {query}"

    agent.on_query(handle_query)
    await agent.connect()
    print("Agent DID 地址:", agent.address)

    # 发送加密查询
    reply = await agent.query("did:key:z6MkuTargetAgent...", "你好，我是 Python Agent")
    print("收到回复:", reply)

asyncio.run(main())
```

---

## 📐 协议规范全景 (Protocol Specification)

直接在浏览器中打开 [`spec/index.html`](./spec/index.html) 即可查阅完整的协议技术标准：

- **Identity**: Ed25519 W3C `did:key` 编码标准与多密钥格式转换；
- **Wire Format**: Canonical JSON 消息格式、时间戳容差窗口（5分钟）与防重放设计；
- **Encryption**: X25519 ECDH 密钥协商 + HKDF-SHA256 派生 + AES-256-GCM AEAD 密文信封；
- **Agent Card**: ANP-07 自签名能力元数据声明与在线探测挑战。

---

## 🏢 商业企业级平台服务 (Model B Strategy)

A2Net 遵循 **Model B** 开源与商业化架构：
- **开源公开（本仓库）**：协议标准规范全集、开源 TypeScript 驱动、开源 Python 驱动均采用宽松 **MIT License**，社区可永久自由集成或基于标准实现第三方中继与工具；
- **官方商业化服务平台（A2Net Commercial Platform）**：
  - **全球加速中继集群 (Managed Relay Cluster)**：商业多租户 API Key 门禁、用量审计与跨国高可用 QoS 节点；
  - **智能体托管舰队 (Fleet Hosting)**：一键沙箱运行 Dify / FastGPT / OpenAI / Coze 智能体并保持长连接在线；
  - **链上清算所与信誉仲裁 (Clearing House & Attestation)**：基于闪电网络的原子按次结算与抗女巫动态信誉网络；
  - **企业级安全网关 (Enterprise Mesh DLP)**：秘钥/PII/内网拓扑自动脱敏与提示词越狱主动防御。

如需接入官方生产中继或获取企业私有化部署支持，请访问 [a2net.network](https://a2net.network) 或联系 `enterprise@a2net.network`。

---

## 📄 License

This repository (specification, TypeScript client SDK, Python client SDK, and examples) is licensed under the [MIT License](./LICENSE).
