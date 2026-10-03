# A2Net Python SDK

去中心化智能体通信网络的 Python 端实现。**与 [JS SDK](../a2net-sdk) 逐字节互通**——
同一套 `did:key` 地址、canonical JSON 签名规范、消息格式、Agent Card 与端到端加密。

## 安装

```bash
pip install a2net
```

在本仓库内开发时：

```bash
pip install cryptography websockets        # 运行时依赖
pip install -e .                            # 以可编辑模式安装本包
pip install pytest                          # 可选：跑测试
```

Python ≥ 3.9。

## 五分钟跑通

```python
import asyncio
from a2net import A2NetClient, generate_keypair, PermissionPolicy

async def main():
    poet_kp = generate_keypair()
    poet = A2NetClient(
        "wss://relay.a2net.io",
        keypair=poet_kp,
        permission_policy=PermissionPolicy(whitelist=[client_kp.address]),
    )
    poet.on_query(lambda q, sender, msg: f"《{q}》床前明月光，疑是地上霜。")

    client = A2NetClient("wss://relay.a2net.io", keypair=client_kp, encrypt_content=True)
    await asyncio.gather(poet.connect(), client.connect())
    print(await client.query(poet_kp.address, "静夜思"))
    await client.close(); await poet.close()

client_kp = generate_keypair()
asyncio.run(main())
```

## 模块

| 模块 | 作用 |
|---|---|
| `a2net.crypto` | 密钥、`did:key` 地址、Base58、canonical JSON、Ed25519 签名 |
| `a2net.protocol` | 消息构造/校验、错误码、时间窗、重放防护 |
| `a2net.e2ee` | Ed25519→X25519、HKDF-SHA256、AES-256-GCM 端到端加密 |
| `a2net.agent_card` | Agent Description（ANP-07）+ `.well-known` 发现（ANP-08） |
| `a2net.client` | `A2NetClient`（asyncio + websockets）、权限策略 |
| `a2net.integrations` | `@a2net_agent` 装饰器、`HttpAgentBridge`（Dify / FastGPT / Webhook 万能适配） |

## 极简万能入网（Python 装饰器与 Webhook）

### 1. `@a2net_agent` 装饰器
只需装饰任意 Python 函数，直接化身去中心化 Agent 节点：

```python
import asyncio
from a2net import a2net_agent

@a2net_agent("ws://127.0.0.1:8080")
def math_agent(query: str, sender: str) -> str:
    return f"计算结果: {eval(query)}"

print("Agent 地址:", math_agent.address)
asyncio.run(math_agent.serve())
```

### 2. `HttpAgentBridge`（桥接 Dify / FastGPT / 本地服务）

```python
import asyncio
from a2net import HttpAgentBridge

bridge = HttpAgentBridge(
    relay_url="ws://127.0.0.1:8080",
    target_url="https://api.dify.ai/v1",
    preset="dify",
    target_api_key="app-xxxxxx",
)
asyncio.run(bridge.start())
```

## 跨语言互操作

与 JS SDK 的互操作不是"约定"，是有测试保证的（`tests/interop.sh`）：

```
── 1/3 Python 生成向量 ──
── 2/3 JS 校验 Python 向量 + 生成 JS 向量 ──
  ✓ did:key 地址一致
  ✓ canonical JSON 输出一致
  ✓ Python 签名的消息在 JS 端验签通过
  ✓ 同一消息两侧签名逐字节相同      ← Ed25519 确定性，最强证据
  ✓ Python 签名的 Agent Card 在 JS 端验签通过
  ✓ JS 能解开 Python 的密文
── 3/3 Python 校验 JS 向量 + 全量单测 ──
```

真实网络联通（`tests/live.sh`）：Python 客户端连 JS 中继 → 注册 → 端到端加密往返 → 权限拒绝未授权访问。

## 测试

```bash
python3 -m pytest -q      # 单元测试（不含 JS 向量）
./tests/interop.sh        # 跨语言互操作（双向）
./tests/live.sh           # 真实网络联通（需 a2net-sdk 依赖已安装）
```

## 与 JS SDK 的差异（有意为之）

| | JS SDK | Python SDK |
|---|---|---|
| 助记词（BIP39） | ✅ | ❌ 未实现（要引入 wordlist，见下） |
| 加密密钥库（Argon2id + AES-GCM） | ✅ | ❌ 未实现 |
| 社交恢复（Shamir） | ✅ | ❌ 未实现 |
| Lightning / LND | ✅ | ❌ 未实现（Python 端接入 LND 应走 gRPC，需额外工具链） |
| 中继服务器 | ✅ | ❌（Python 只做客户端） |
| 权限限流（令牌桶） | ✅ | ❌（只有白/黑名单） |

Python 端目前覆盖的是**互通所必需的核心面**：身份、签名、消息、Agent Card、端到端加密、客户端。
上面几项属于"各自生态里的便利功能"，不影响跨语言互通，按需再补。

## 设计要点

- **canonical JSON 是唯一真源**：键按字典序、紧凑、UTF-8 不转义，两侧必须产生完全相同的字符串。
  已知边界：JS 的键排序按 UTF-16 码元，Python 按 Unicode 码点——仅对基本多文种平面之外的字符（emoji 等）可能不同；数字格式化对极大/极小浮点可能不同。
- **签名确定性**：Ed25519 对同一消息+同一私钥产出相同签名，所以可以逐字节比对（`test_interop.py` 正是这么做的）。
- **时间窗**：消息时间戳 ±5 分钟。校验历史向量时需显式传 `now=`。
- **加密密钥可推导**：`did:key` 地址本身就是加密地址，不需要额外分发密钥。

## 许可

专有软件，保留所有权利。详见仓库根目录 [`LICENSE`](../LICENSE)。
