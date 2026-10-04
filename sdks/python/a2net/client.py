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
# 流式产出回调：emit(delta) 立即发一帧增量
StreamEmit = Callable[[str], Awaitable[None]]
# 流式处理器：(query, sender, emit, msg) -> 可选最终文本
StreamQueryHandler = Callable[[str, str, StreamEmit, Dict[str, Any]], Union[str, None, Awaitable[Any]]]
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
        self._stream_query_handler: Optional[StreamQueryHandler] = None
        self._blob_handler: Optional[BlobHandler] = None
        self._blob_manager = BlobTransferManager()

    # -- 基本信息 --------------------------------------------------------
    @property
    def address(self) -> str:
        return self.keypair.address

    @property
    def is_connected(self) -> bool:
        return self._connected

    def on_stream_query(self, handler: StreamQueryHandler) -> None:
        """注册**流式**查询处理器。

        与 on_query 可同时注册：收到 stream=True 的查询时优先走流式处理器；
        未注册则回落普通处理器（退化为单帧，调用方仍拿到完整结果 —— 向后兼容）。
        """
        self._stream_query_handler = handler

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
    async def query(
        self,
        target: str,
        text: str,
        timeout: Optional[float] = None,
        *,
        stream: bool = False,
        on_delta: Optional[Callable[[str, int], None]] = None,
        stream_idle_timeout: float = 30.0,
    ) -> str:
        """发起查询。

        流式用法::

            def show(delta, seq):
                print(delta, end="", flush=True)

            full = await client.query(did, "讲个故事", stream=True, on_delta=show)

        `on_delta` 在**流进行中**被调用（首字即达），返回值仍是完整文本。
        `stream_idle_timeout` 是**帧间**最大间隔，而非总时长上限 ——
        长回答不会被它中途杀掉。
        """
        if not self._connected:
            raise RuntimeError("Not connected")
        want_stream = stream or on_delta is not None
        content: Dict[str, Any] = {"query": text}
        if want_stream:
            content["stream"] = True
        if self.encrypt_content:
            content = encrypt_for(target, json.dumps(content, ensure_ascii=False))  # type: ignore[assignment]
        msg = build_message(self.address, target, "query", content, self.keypair.private_key)
        return await self._send_and_wait(
            msg,
            timeout or self.request_timeout,
            on_delta=on_delta,
            idle_timeout=stream_idle_timeout if want_stream else None,
        )

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

    async def _send_and_wait(
        self,
        msg: Dict[str, Any],
        timeout: float,
        *,
        on_delta: Optional[Callable[[str, int], None]] = None,
        idle_timeout: Optional[float] = None,
    ) -> str:
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        # pending 项从裸 Future 改为带流式状态的容器（见 _handle_reply）
        self._pending[msg["id"]] = {
            "future": fut,
            "on_delta": on_delta,
            "chunks": {},
            "idle_timeout": idle_timeout,
            "timer": None,
        }
        await self._ws.send(json.dumps(msg, ensure_ascii=False))
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError("Request timeout (%d)" % ErrorCode.TIMEOUT) from None
        finally:
            entry = self._pending.pop(msg["id"], None)
            if entry and entry.get("timer") is not None:
                entry["timer"].cancel()

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
        # 先取原始 query（流式与普通两条路径都要用同一个值，
        # 且都要先经过 DLP 审查 —— 否则可绕过安全检查）
        raw_query = msg["content"].get("query", "")

        wants_stream = msg["content"].get("stream") is True
        if wants_stream and self._stream_query_handler is not None:
            await self._run_streaming_query(msg, raw_query)
            return

        if self._query_handler is None:
            await self._send_raw(
                build_error(msg, ErrorCode.INTERNAL, "No query handler", self.keypair.private_key)
            )
            return

        try:
            out = self._query_handler(raw_query, msg["from"], msg)
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

    async def _run_streaming_query(self, msg: Dict[str, Any], raw_query: str) -> None:
        """执行流式查询：逐块发 response（metadata.seq 递增），最后发终止帧。

        分帧约定（**必须与 TS 端逐字节一致**）：
          · 增量帧：{reply_to, result: <本块文本>, metadata: {seq, done: false}}
          · 终止帧：{reply_to, result: "",      metadata: {seq, done: true}}

        终止帧的 result 是**空串**而非完整文本：接收侧会把所有带 seq 的帧
        按序拼接（含终止帧）。若终止帧携带完整文本，拼接结果会把全文追加一遍
        —— 静默产出错误结果。空串让拼接恒等式成立：
          delta_0 + ... + delta_n + "" == 全文
        """
        use_e2ee = self.encrypt_content or msg.get("extensions", {}).get("e2ee") is True
        state = {"seq": 0, "emitted": 0}

        async def send_frame(result: str, done: bool, error: Optional[str] = None) -> None:
            metadata: Dict[str, Any] = {"seq": state["seq"], "done": done}
            if error:
                metadata["error"] = error
            resp = build_response(msg, result, self.keypair.private_key, metadata)
            if use_e2ee:
                resp["content"] = encrypt_for(
                    msg["from"], json.dumps(resp["content"], ensure_ascii=False)
                )
                resp = build_message(
                    resp["from"], resp["to"], "response", resp["content"], self.keypair.private_key
                )
            await self._send_raw(resp)
            state["seq"] += 1

        async def emit(delta: str) -> None:
            if not delta:
                return  # 空增量无意义，且会让 seq 虚增
            await send_frame(delta, False)
            state["emitted"] += len(delta)

        try:
            await self._stream_query_handler(raw_query, msg["from"], emit, msg)  # type: ignore[misc]
            await send_frame("", True)
        except Exception as exc:  # noqa: BLE001
            # 用终止帧而非 error 帧收尾：接收侧已拿到部分内容，
            # 发 error 帧会让那些内容被丢弃，且流的结束语义不明确。
            await send_frame("", True, str(exc))

    def _handle_reply(self, msg: Dict[str, Any]) -> None:
        reply_to = msg["content"].get("reply_to")
        entry = self._pending.get(reply_to)
        if entry is None:
            return
        fut: asyncio.Future = entry["future"]
        if fut.done():
            return

        if msg["type"] == "error":
            fut.set_exception(RuntimeError(msg["content"].get("message", "error")))
            return

        content = msg["content"]
        meta = content.get("metadata") or {}
        seq = meta.get("seq")
        done = meta.get("done") is True

        # ── 分片帧：累积 + 实时投递（这是低延迟体感的入口）──
        if isinstance(seq, int) and not done:
            entry["chunks"][seq] = content.get("result", "")
            # 空闲超时按「帧间隔」计：流式回答可能持续数分钟，
            # 若沿用总时长上限，一个正常的长回答会被中途杀掉。
            idle = entry.get("idle_timeout")
            if idle:
                if entry.get("timer") is not None:
                    entry["timer"].cancel()
                loop = asyncio.get_running_loop()
                entry["timer"] = loop.call_later(idle, self._on_stream_idle, reply_to)
            cb = entry.get("on_delta")
            if cb is not None:
                try:
                    cb(content.get("result", ""), seq)
                except Exception:  # noqa: BLE001 - 回调异常不应影响协议流程
                    pass
            return

        # ── 终止帧 ──
        if isinstance(seq, int) and entry["chunks"]:
            entry["chunks"][seq] = content.get("result", "")
            joined = "".join(v for _, v in sorted(entry["chunks"].items()))
            if entry.get("timer") is not None:
                entry["timer"].cancel()
            stream_err = meta.get("error")
            if isinstance(stream_err, str) and stream_err:
                # 部分内容 + 明确失败原因，两者都给调用方，不静默丢弃
                exc = RuntimeError(
                    "Stream failed after %d chars: %s" % (len(joined), stream_err)
                )
                exc.partial = joined  # type: ignore[attr-defined]
                fut.set_exception(exc)
                return
            fut.set_result(joined)
            return

        # ── 普通单帧（向后兼容路径）──
        fut.set_result(content.get("result", ""))

    def _on_stream_idle(self, reply_to: str) -> None:
        """流式空闲超时：帧间隔超限时结束该流，并保留已收到的部分内容。"""
        entry = self._pending.get(reply_to)
        if entry is None:
            return
        fut: asyncio.Future = entry["future"]
        if fut.done():
            return
        partial = "".join(v for _, v in sorted(entry["chunks"].items()))
        exc = RuntimeError(
            "Stream idle timeout: 超过 %.1fs 未收到新的分片（已收到 %d 字符）"
            % (entry.get("idle_timeout") or 0, len(partial))
        )
        exc.partial = partial  # type: ignore[attr-defined]
        fut.set_exception(exc)
