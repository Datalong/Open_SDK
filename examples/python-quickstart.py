#!/usr/bin/env python3
"""
A2Net Python Client Quickstart Example
Run: python3 examples/python-quickstart.py
"""
import asyncio
import os
import sys

# 将本地 Python SDK 路径加入查找
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'sdks', 'python'))

from a2net import A2NetClient


async def main():
    relay_url = os.getenv('A2NET_RELAY_URL', 'wss://relay.a2net.network')

    # 1. 初始化服务端 Agent
    responder = A2NetClient(relay_url=relay_url, encrypt_content=True)

    async def handle_query(query: str, sender: str, msg: dict) -> str:
        print(f"[Responder] 收到来自 {sender[:16]}... 的加密消息: '{query}'")
        return f"Hello from Python Agent! Echoing: {query}"

    responder.on_query(handle_query)
    await responder.connect()
    print(f"✓ Python Responder 已上线: {responder.address}")

    # 2. 初始化调用端 Agent
    caller = A2NetClient(relay_url=relay_url, encrypt_content=True)
    await caller.connect()
    print(f"✓ Python Caller 已上线:    {caller.address}")

    # 3. 发起 E2EE 加密查询
    print("\n[Caller] 正在发送端到端加密消息...")
    reply = await caller.query(responder.address, "跨语言智能体互操作性测试")
    print(f"\n[Caller] 收到解密响应: '{reply}'")

    await caller.disconnect()
    await responder.disconnect()


if __name__ == '__main__':
    asyncio.run(main())
