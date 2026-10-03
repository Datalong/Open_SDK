#!/usr/bin/env python3
"""
A2Net Python Multimodal Blob Streaming Example

演示通过端到端加密分块管道传输大文件（图片 / 音频 / PDF）：
  1. 生成内存中的二进制数据（真实场景可来自文件或模型输出）
  2. 以 64KB 分片 + E2EE 加密发送，并实时追踪进度
  3. 接收端自动组装、SHA-256 校验并回调

Run: python3 examples/python-multimodal.py
需先启动中继: npm run dev --workspace=@a2net/relay
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'sdks', 'python'))

from a2net import A2NetClient, PermissionPolicy


async def main():
    relay_url = os.getenv('A2NET_RELAY_URL', 'ws://127.0.0.1:8080')

    # 1. 接收方：注册 on_blob 回调
    receiver = A2NetClient(
        relay_url=relay_url,
        encrypt_content=True,
        permission_policy=PermissionPolicy(default_allow=True),
    )
    received = {}

    def on_blob(blob, sender):
        print(f"[Receiver] 收到来自 {sender[:16]}… 的文件:")
        print(f"  名称   : {blob.metadata.name}")
        print(f"  MIME   : {blob.metadata.mime_type}")
        print(f"  大小   : {len(blob.data) / 1024:.1f} KB")
        print(f"  分片数 : {blob.metadata.total_chunks}")
        print(f"  SHA-256: {blob.metadata.sha256[:24]}…")
        received['blob'] = blob

    receiver.on_blob(on_blob)
    await receiver.connect()
    print(f"✓ Receiver 已在线: {receiver.address}")

    # 2. 发送方
    sender = A2NetClient(relay_url=relay_url, encrypt_content=True)
    await sender.connect()
    print(f"✓ Sender 已在线:   {sender.address}")

    # 3. 构造 256KB 二进制数据（模拟图片）
    data = bytes((i * 31 + 7) & 0xFF for i in range(256 * 1024))

    print("\n[Sender] 开始端到端加密分块传输…")
    meta = await sender.send_blob(
        receiver.address,
        data,
        name='generated-image.png',
        mime_type='image/png',
        chunk_size=64 * 1024,
        on_progress=lambda pct, i, total: print(f"\r  进度: {pct}% ({i + 1}/{total})", end='', flush=True),
    )
    print(f"\n✓ 已发送 {meta.total_chunks} 个分片，SHA-256 {meta.sha256[:16]}…")

    # 4. 等待接收组装
    for _ in range(30):
        if 'blob' in received:
            break
        await asyncio.sleep(0.1)

    if 'blob' in received and received['blob'].data == data:
        print('✓ 接收端 SHA-256 校验通过，内容完整一致。')
    else:
        print('✗ 未收到文件或内容不一致。')

    await sender.close()
    await receiver.close()


if __name__ == '__main__':
    asyncio.run(main())
