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
from .protocol import (
    ErrorCode,
    build_error,
    build_message,
    build_response,
    validate_message,
)

QueryHandler = Callable[[str, str, Dict[str, Any]], Union[str, Dict[str, Any], Awaitable[Any]]]


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

    # -- 基本信息 --------------------------------------------------------
    @property
    def address(self) -> str:
        return self.keypair.address

    @property
    def is_connected(self) -> bool:
        return self._connected

    def on_query(self, handler: QueryHandler) -> None:
        self._query_handler = handler

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
        elif msg["type"] in ("response", "error"):
            self._handle_reply(msg)

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
