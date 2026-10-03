"""live_client.py — 真实网络联通测试：Python 客户端 ↔ JS 中继服务器

验证 Python SDK 能按中继协议注册、收发消息，并完成端到端加密往返。

前置：中继已在 RELAY_URL 运行（见 tests/live.sh）。
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from a2net import A2NetClient, PermissionPolicy, generate_keypair  # noqa: E402

RELAY_URL = os.environ.get("RELAY_URL", "ws://127.0.0.1:8090")


async def main() -> int:
    poet_kp = generate_keypair()
    client_kp = generate_keypair()

    poet = A2NetClient(
        RELAY_URL,
        keypair=poet_kp,
        # 只允许这个客户端调用（白名单），验证权限模型在链路上生效
        permission_policy=PermissionPolicy(whitelist=[client_kp.address]),
    )
    client = A2NetClient(RELAY_URL, keypair=client_kp, encrypt_content=True)

    def handler(query: str, sender: str, msg: dict) -> str:
        return "《%s》\n床前明月光，疑是地上霜。" % query

    poet.on_query(handler)

    await asyncio.gather(poet.connect(), client.connect())
    print("  两端已接入 JS 中继")

    try:
        answer = await client.query(poet_kp.address, "静夜思", timeout=10)
        ok = "静夜思" in answer and "明月光" in answer
        print("  收到: %s" % answer.replace("\n", " / "))
        print("  %s 端到端加密往返成功" % ("✓" if ok else "✗"))
        if not ok:
            return 1

        # 未授权方应被拒
        outsider = A2NetClient(RELAY_URL)
        await outsider.connect()
        denied = False
        try:
            await outsider.query(poet_kp.address, "偷偷调用", timeout=5)
        except Exception:
            denied = True
        await outsider.close()
        print("  %s 未授权 Agent 被拒绝: %s" % ("✓" if denied else "✗", denied))
        if not denied:
            return 1
    finally:
        await client.close()
        await poet.close()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
