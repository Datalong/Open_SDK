"""
client.py — A2NetClient（Python）：连接中继、收发消息、端到端加密

用法::

    import asyncio
    from a2net import A2NetClient, generate_keypair

    async def main():
        kp = generate_keypair()
        client = A2NetClient("ws://127.0.0.1:8090", keypair=kp, encrypt_content=True)
        client.on_query(lambda q, sender, msg: "收到: " + q)
        await client.connect()
        print(await client.query(peer_address, "你好"))
        await client.close()

    asyncio.run(main())
"""
from __future__ import annotations

import asyncio
import inspect
import json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Union

import websockets  # type: ignore

from .crypto import KeyPair, generate_keypair
from .e2ee import decrypt_from, encrypt_for, is_encrypted
from .multimodal import (
    BlobChunk,
    BlobMetadata,
    BlobTransferManager,
    CompletedBlob,
    split_blob_into_chunks,
)
from .protocol import (
    ErrorCode,
    build_blob_chunk,
    build_blob_init,
    build_error,
    build_message,
    build_response,
    validate_message,
)

QueryHandler = Callable[[str, str, Dict[str, Any]], Union[str, Dict[str, Any], Awaitable[Any]]]
BlobHandler = Callable[[CompletedBlob, str], Union[None, Awaitable[None]]]


@dataclass
class PermissionPolicy:
    """默认拒绝；白名单优先于默认，黑名单优先于一切。"""

    default_allow: bool = False
    whitelist: List[str] = field(default_factory=list)
    blacklist: List[str] = field(default_factory=list)

    def check(self, sender: str) -> bool:
        if sender in self.blacklist:
            return False
        if sender in self.whitelist:
            return True
        return self.default_allow


class A2NetClient:
    def __init__(
        self,
        relay_url: str,
        keypair: Optional[KeyPair] = None,
        encrypt_content: bool = False,
        permission_policy: Optional[PermissionPolicy] = None,
        request_timeout: float = 30.0,
        api_key: Optional[str] = None,
    ) -> None:
        self.relay_url = relay_url
        self.keypair = keypair or generate_keypair()
        self.encrypt_content = encrypt_content
        self.policy = permission_policy or PermissionPolicy()
        self.request_timeout = request_timeout
        self.api_key = api_key

        self._ws: Any = None
        self._connected = False
        self._recv_task: Optional[asyncio.Task] = None
        self._pending: Dict[str, asyncio.Future] = {}
        self._seen: set = set()
        self._query_handler: Optional[QueryHandler] = None
        self._blob_handler: Optional[BlobHandler] = None
        self._blob_manager = BlobTransferManager()

    # -- 基本信息 --------------------------------------------------------
    @property
    def address(self) -> str:
        return self.keypair.address

    @property
    def is_connected(self) -> bool:
        return self._connected

    def on_query(self, handler: QueryHandler) -> None:
        self._query_handler = handler

    def on_blob(self, handler: BlobHandler) -> None:
        """注册多模态文件接收回调: handler(completed_blob, sender_did)。"""
        self._blob_handler = handler

    # -- 连接 ------------------------------------------------------------
    async def connect(self) -> None:
        self._ws = await websockets.connect(self.relay_url)
        reg_payload = {
            "type": "register",
            "address": self.address,
            "capabilities": ["a2net.stream.v1", "a2net.tool_call.v1"],
        }
        if self.api_key:
            reg_payload["apiKey"] = self.api_key
        await self._ws.send(json.dumps(reg_payload))
        # 等待 register_ack
        while True:
            raw = await self._ws.recv()
            try:
                msg = json.loads(raw)
            except (ValueError, TypeError):
                continue
            if msg.get("type") == "register_ack":
                if msg.get("status") == "error":
                    raise ConnectionError(f"Register failed: {msg.get('reason', 'unknown')}")
                break
        self._connected = True
        self._recv_task = asyncio.create_task(self._recv_loop())

    async def close(self) -> None:
        self._connected = False
        if self._recv_task:
            self._recv_task.cancel()
            try:
                await self._recv_task
            except (asyncio.CancelledError, Exception):  # noqa: B014
                pass
        if self._ws is not None:
            await self._ws.close()
            self._ws = None

    # -- 发送 ------------------------------------------------------------
    async def query(self, target: str, text: str, timeout: Optional[float] = None) -> str:
        if not self._connected:
            raise RuntimeError("Not connected")
        content: Dict[str, Any] = {"query": text}
        if self.encrypt_content:
            content = encrypt_for(target, json.dumps(content, ensure_ascii=False))  # type: ignore[assignment]
        msg = build_message(self.address, target, "query", content, self.keypair.private_key)
        return await self._send_and_wait(msg, timeout or self.request_timeout)

    async def send_blob(
        self,
        target: str,
        data: bytes,
        name: str = "unnamed.bin",
        mime_type: str = "application/octet-stream",
        chunk_size: int = 64 * 1024,
        on_progress: Optional[Callable[[int, int, int], None]] = None,
    ) -> BlobMetadata:
        """发送多模态二进制大文件（图片/音频/PDF），自动分块并支持端到端加密与进度回调。

        :param on_progress: 回调 (progress_pct, chunk_index, total_chunks)
        """
        if not self._connected:
            raise RuntimeError("Not connected")
        if not data:
            data = b""
        metadata, chunks = split_blob_into_chunks(data, name, mime_type, chunk_size)

        # 1. blob_init 协商元数据
        init_payload: Dict[str, Any] = {"metadata": metadata.to_dict()}
        init_content: Dict[str, Any] = init_payload
        if self.encrypt_content:
            init_content = encrypt_for(target, json.dumps(init_payload, ensure_ascii=False))
        await self._send_raw(
            build_blob_init(
                self.address,
                target,
                init_content,
                self.keypair.private_key,
                extensions={"e2ee": self.encrypt_content},
            )
        )

        # 2. 依次管道化发送分片
        total = len(chunks)
        for i, chunk in enumerate(chunks):
            chunk_payload: Dict[str, Any] = {"chunk": chunk.to_dict()}
            chunk_content: Dict[str, Any] = chunk_payload
            if self.encrypt_content:
                chunk_content = encrypt_for(target, json.dumps(chunk_payload, ensure_ascii=False))
            await self._send_raw(
                build_blob_chunk(
                    self.address,
                    target,
                    chunk_content,
                    self.keypair.private_key,
                    extensions={"e2ee": self.encrypt_content},
                )
            )
            if on_progress is not None:
                on_progress(round((i + 1) / total * 100), i, total)

        return metadata

    async def _send_and_wait(self, msg: Dict[str, Any], timeout: float) -> str:
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending[msg["id"]] = fut
        await self._ws.send(json.dumps(msg, ensure_ascii=False))
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError("Request timeout (%d)" % ErrorCode.TIMEOUT) from None
        finally:
            self._pending.pop(msg["id"], None)

    async def _send_raw(self, msg: Dict[str, Any]) -> None:
        if self._ws is not None:
            await self._ws.send(json.dumps(msg, ensure_ascii=False))

    # -- 接收 ------------------------------------------------------------
    async def _recv_loop(self) -> None:
        assert self._ws is not None
        try:
            async for raw in self._ws:
                try:
                    msg = json.loads(raw)
                except (ValueError, TypeError):
                    continue
                if msg.get("type") == "pong":
                    continue
                await self._handle_message(msg)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            self._connected = False

    async def _handle_message(self, msg: Dict[str, Any]) -> None:
        code = validate_message(msg, seen_ids=self._seen)
        if code is not None:
            return
        self._seen.add(msg["id"])

        if is_encrypted(msg.get("content")):
            try:
                plain = decrypt_from(msg["from"], msg["content"], self.keypair.private_key)
                msg["content"] = json.loads(plain)
                msg["extensions"] = dict(msg.get("extensions") or {}, e2ee=True)
            except Exception:  # noqa: BLE001
                return

        if msg["type"] == "query":
            await self._handle_query(msg)
        elif msg["type"] == "blob_init":
            self._handle_blob_init(msg)
        elif msg["type"] == "blob_chunk":
            await self._handle_blob_chunk(msg)
        elif msg["type"] in ("response", "error"):
            self._handle_reply(msg)

    def _handle_blob_init(self, msg: Dict[str, Any]) -> None:
        meta_dict = (msg.get("content") or {}).get("metadata")
        if not meta_dict:
            return
        self._blob_manager.init_session(msg["from"], BlobMetadata.from_dict(meta_dict))

    async def _handle_blob_chunk(self, msg: Dict[str, Any]) -> None:
        chunk_dict = (msg.get("content") or {}).get("chunk")
        if not chunk_dict:
            return
        try:
            _, completed = self._blob_manager.handle_chunk(
                msg["from"], BlobChunk.from_dict(chunk_dict)
            )
        except Exception:  # noqa: BLE001 - 分片校验失败不掎垮接收循环
            return
        if completed is not None and self._blob_handler is not None:
            out = self._blob_handler(completed, msg["from"])
            if inspect.isawaitable(out):
                await out

    async def _handle_query(self, msg: Dict[str, Any]) -> None:
        if not self.policy.check(msg["from"]):
            await self._send_raw(
                build_error(
                    msg, ErrorCode.PERMISSION, "Sender not permitted", self.keypair.private_key
                )
            )
            return
        if self._query_handler is None:
            await self._send_raw(
                build_error(msg, ErrorCode.INTERNAL, "No query handler", self.keypair.private_key)
            )
            return
        try:
            out = self._query_handler(msg["content"].get("query", ""), msg["from"], msg)
            if inspect.isawaitable(out):
                out = await out
            if isinstance(out, dict):
                result, metadata = out.get("result", ""), out.get("metadata")
            else:
                result, metadata = str(out), None
            resp = build_response(msg, result, self.keypair.private_key, metadata)
            if self.encrypt_content or msg.get("extensions", {}).get("e2ee") is True:
                resp["content"] = encrypt_for(msg["from"], json.dumps(resp["content"], ensure_ascii=False))
                resp = build_message(
                    resp["from"], resp["to"], "response", resp["content"], self.keypair.private_key
                )
            await self._send_raw(resp)
        except Exception as exc:  # noqa: BLE001
            await self._send_raw(
                build_error(msg, ErrorCode.INTERNAL, str(exc), self.keypair.private_key)
            )

    def _handle_reply(self, msg: Dict[str, Any]) -> None:
        reply_to = msg["content"].get("reply_to")
        fut = self._pending.get(reply_to)
        if fut is None or fut.done():
            return
        if msg["type"] == "error":
            fut.set_exception(RuntimeError(msg["content"].get("message", "error")))
        else:
            fut.set_result(msg["content"].get("result", ""))
