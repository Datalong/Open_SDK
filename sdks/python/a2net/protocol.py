"""
protocol.py — A2Net 消息协议 v0.2（Python 实现，与 JS 端互通）

消息字段：id, from, to, type, content, timestamp, signature, extensions?
- id 为 UUIDv4
- 时间戳有效窗口 5 分钟
- 签名覆盖 canonical JSON 的核心六字段
"""
from __future__ import annotations

import time
import uuid
from enum import IntEnum
from typing import Any, Dict, Iterable, List, Optional

from .crypto import get_sign_string, sign_message, verify_signature

MESSAGE_TYPES = ("ping", "query", "response", "error")

#: 时间戳有效窗口：5 分钟
TIMESTAMP_WINDOW_MS = 5 * 60 * 1000


class ErrorCode(IntEnum):
    FORMAT = 4001
    SIGNATURE = 4002
    PERMISSION = 4031
    RATE_LIMIT = 4032
    OFFLINE = 4041
    INTERNAL = 5001
    TIMEOUT = 5040


def _now_ms() -> int:
    return int(time.time() * 1000)


def _msg_id() -> str:
    return str(uuid.uuid4())


def build_message(
    sender: str,
    recipient: str,
    msg_type: str,
    content: Dict[str, Any],
    private_key: bytes,
    extensions: Optional[Dict[str, Any]] = None,
    timestamp: Optional[int] = None,
) -> Dict[str, Any]:
    """构造并签名一条消息。"""
    if msg_type not in MESSAGE_TYPES:
        raise ValueError("Invalid message type: %s" % msg_type)
    msg: Dict[str, Any] = {
        "id": _msg_id(),
        "from": sender,
        "to": recipient,
        "type": msg_type,
        "content": content,
        "timestamp": timestamp if timestamp is not None else _now_ms(),
        "signature": "",
    }
    if extensions is not None:
        msg["extensions"] = extensions
    msg["signature"] = sign_message(get_sign_string(msg), private_key)
    return msg


def build_query(
    sender: str,
    recipient: str,
    query_text: str,
    private_key: bytes,
    scope: Optional[Dict[str, Any]] = None,
    session_id: Optional[str] = None,
    stream: bool = False,
    extensions: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    content: Dict[str, Any] = {"query": query_text}
    if scope:
        content["scope"] = scope
    if session_id:
        content["session_id"] = session_id
    if stream:
        content["stream"] = True
    return build_message(sender, recipient, "query", content, private_key, extensions)


def build_response(
    request: Dict[str, Any],
    result: str,
    private_key: bytes,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    content: Dict[str, Any] = {"reply_to": request["id"], "result": result}
    if metadata:
        content["metadata"] = metadata
    return build_message(request["to"], request["from"], "response", content, private_key)


def build_error(
    request: Dict[str, Any],
    code: int,
    message: str,
    private_key: bytes,
    retry_after: Optional[int] = None,
) -> Dict[str, Any]:
    content: Dict[str, Any] = {"reply_to": request["id"], "code": int(code), "message": message}
    if retry_after is not None:
        content["retry_after"] = retry_after
    return build_message(request["to"], request["from"], "error", content, private_key)


def validate_message(
    msg: Any,
    seen_ids: Optional[Iterable[str]] = None,
    window_ms: int = TIMESTAMP_WINDOW_MS,
    now: Optional[int] = None,
) -> Optional[ErrorCode]:
    """校验消息：字段完整性 → 时间窗 → 签名。返回 ErrorCode 或 None（通过）。"""
    if not isinstance(msg, dict):
        return ErrorCode.FORMAT
    for f in ("id", "from", "to", "type", "content", "timestamp", "signature"):
        if f not in msg:
            return ErrorCode.FORMAT
    if not isinstance(msg["id"], str) or not isinstance(msg["from"], str) or not isinstance(msg["to"], str):
        return ErrorCode.FORMAT
    if not isinstance(msg["signature"], str) or not isinstance(msg["timestamp"], (int, float)):
        return ErrorCode.FORMAT
    if msg["type"] not in MESSAGE_TYPES:
        return ErrorCode.FORMAT
    if not isinstance(msg["content"], dict):
        return ErrorCode.FORMAT

    current = now if now is not None else _now_ms()
    if abs(current - msg["timestamp"]) > window_ms:
        return ErrorCode.SIGNATURE

    if seen_ids is not None and msg["id"] in seen_ids:
        return ErrorCode.SIGNATURE

    try:
        sign_str = get_sign_string(msg)
    except ValueError:
        return ErrorCode.FORMAT
    if not verify_signature(sign_str, msg["signature"], msg["from"]):
        return ErrorCode.SIGNATURE
    return None


def is_valid(msg: Any, **kwargs: Any) -> bool:
    """便捷断言：消息是否通过校验。"""
    return validate_message(msg, **kwargs) is None
