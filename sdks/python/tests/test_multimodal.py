"""多模态分块 Blob 传输（Python 端）单元测试。"""
import asyncio

import pytest

from a2net import (
    A2NetClient,
    BlobMetadata,
    BlobTransferManager,
    PermissionPolicy,
    compute_sha256_hex,
    split_blob_into_chunks,
)
from a2net.multimodal import CorruptedChunkError


def _sample(n: int) -> bytes:
    return bytes((i * 17 + 3) & 0xFF for i in range(n))


def test_split_and_assemble_roundtrip():
    raw = _sample(150 * 1024)
    meta, chunks = split_blob_into_chunks(raw, "render.png", "image/png", 64 * 1024)

    assert meta.name == "render.png"
    assert meta.mime_type == "image/png"
    assert meta.size == len(raw)
    assert meta.total_chunks == 3
    assert len(chunks) == 3
    assert chunks[-1].is_final is True

    mgr = BlobTransferManager()
    mgr.init_session("did:key:sender", meta)
    out = None
    for c in chunks:
        _, out = mgr.handle_chunk("did:key:sender", c)
    assert out is not None
    assert out.data == raw
    assert compute_sha256_hex(out.data) == meta.sha256


def test_corrupted_chunk_rejected():
    raw = _sample(16 * 1024)
    meta, chunks = split_blob_into_chunks(raw, "doc.pdf", "application/pdf", 8 * 1024)
    mgr = BlobTransferManager()
    mgr.init_session("did:key:sender", meta)

    bad = chunks[0]
    bad.chunk_sha256 = "0" * 64
    with pytest.raises(CorruptedChunkError):
        mgr.handle_chunk("did:key:sender", bad)


def test_base64_and_metadata_dict_roundtrip():
    raw = _sample(4096)
    meta, _ = split_blob_into_chunks(raw, "a.bin", "application/octet-stream", 1024)
    revived = BlobMetadata.from_dict(meta.to_dict())
    assert revived == meta


def test_end_to_end_blob_streaming_over_relay():
    """通过真实中继完成 2 个 Agent 的加密分块传输。"""
    pytest.importorskip("websockets")

    from a2net.client import A2NetClient as Client

    RELAY = "ws://127.0.0.1:18311"
    raw = _sample(200 * 1024)
    expected_sha = compute_sha256_hex(raw)

    received = {}

    async def run():
        # 简易内置中继：直接转发帧（测试用，验证 SDK 侧分块管道）
        import websockets

        peers: dict = {}

        async def handler(ws):
            peers[ws] = None
            try:
                async for m in ws:
                    import json as _json

                    msg = _json.loads(m)
                    if msg.get("type") == "register":
                        peers[ws] = msg["address"]
                        await ws.send(_json.dumps({"type": "register_ack", "status": "success"}))
                        continue
                    to = msg.get("to")
                    for p, a in list(peers.items()):
                        if a == to and p is not ws:
                            await p.send(m)
            finally:
                peers.pop(ws, None)

        server = await websockets.serve(handler, "127.0.0.1", 18311)

        receiver = Client(RELAY, encrypt_content=True, permission_policy=PermissionPolicy(default_allow=True))

        async def on_blob(blob, sender):
            received["blob"] = blob

        receiver.on_blob(on_blob)
        await receiver.connect()

        sender = Client(RELAY, encrypt_content=True)
        await sender.connect()

        progress = []
        await sender.send_blob(
            receiver.address,
            raw,
            name="generated-image.png",
            mime_type="image/png",
            chunk_size=64 * 1024,
            on_progress=lambda pct, i, total: progress.append(pct),
        )

        for _ in range(60):
            if "blob" in received:
                break
            await asyncio.sleep(0.05)

        await sender.close()
        await receiver.close()
        server.close()
        await server.wait_closed()

        assert progress[-1] == 100
        blob = received.get("blob")
        assert blob is not None
        assert blob.metadata.name == "generated-image.png"
        assert blob.data == raw
        assert blob.metadata.sha256 == expected_sha

    asyncio.run(run())
