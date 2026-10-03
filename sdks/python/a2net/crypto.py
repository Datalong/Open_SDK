"""
crypto.py — A2Net Python SDK 身份与加密核心

与 JS 端 **逐字节互通**：
- 地址 = "did:key:z" + Base58(32 字节 Ed25519 公钥)
- 签名规范 = canonical JSON（键按字典序、紧凑序列化）后 Ed25519 → Base64
- sign 字段固定六个：content / from / id / timestamp / to / type
"""
from __future__ import annotations

import base64
import json
import math
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DID_PREFIX = "did:key:z"

#: 参与签名的六个字段（与 JS 的 SIGN_FIELDS 一致）
SIGN_FIELDS = ("content", "from", "id", "timestamp", "to", "type")

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


# ---------------------------------------------------------------------------
# Base58（与 JS 的 bs58 一致：前导零字节编码为 '1'）
# ---------------------------------------------------------------------------

def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58_ALPHABET[r] + out
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + out


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        if ch not in _B58_INDEX:
            raise ValueError("invalid base58 character: %r" % ch)
        n = n * 58 + _B58_INDEX[ch]
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + body


# ---------------------------------------------------------------------------
# Canonical JSON（签名规范的唯一真源）
# ---------------------------------------------------------------------------

def _js_number(value: float) -> str:
    """尽量复刻 JS 的 JSON.stringify(number)。"""
    if math.isnan(value) or math.isinf(value):
        raise ValueError("non-finite number in canonical JSON")
    if value == int(value) and abs(value) < 1e21:
        return str(int(value))
    return repr(value)


def canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _js_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        parts = []
        for k in sorted(value.keys()):
            parts.append(json.dumps(k, ensure_ascii=False) + ":" + canonical_json(value[k]))
        return "{" + ",".join(parts) + "}"
    raise TypeError("Unsupported type in canonical JSON: %s" % type(value).__name__)


# ---------------------------------------------------------------------------
# 身份
# ---------------------------------------------------------------------------

@dataclass
class KeyPair:
    """32 字节 Ed25519 私钥种子 + 公钥 + did:key 地址。"""

    private_key: bytes
    public_key: bytes
    address: str

    def sign(self, message: str) -> str:
        return sign_message(message, self.private_key)

    def sign_message_dict(self, msg: Dict[str, Any]) -> str:
        return sign_message(get_sign_string(msg), self.private_key)


def generate_keypair() -> KeyPair:
    seed = os.urandom(32)
    return keypair_from_private_key(seed)


def keypair_from_private_key(seed: bytes) -> KeyPair:
    if len(seed) != 32:
        raise ValueError("private key must be 32 bytes")
    pub = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes_raw()
    )
    return KeyPair(private_key=seed, public_key=pub, address=address_from_public_key(pub))


def address_from_public_key(public_key: bytes) -> str:
    return DID_PREFIX + b58encode(public_key)


def public_key_from_address(address: str) -> bytes:
    if not address.startswith(DID_PREFIX):
        raise ValueError("Invalid did:key address: %s" % address)
    pub = b58decode(address[len(DID_PREFIX):])
    if len(pub) != 32:
        raise ValueError("Invalid public key length: %d" % len(pub))
    return pub


# ---------------------------------------------------------------------------
# 签名 / 验签
# ---------------------------------------------------------------------------

def get_sign_string(msg: Dict[str, Any]) -> str:
    """从完整消息构建待签名字符串（只取核心六字段，递归排序）。"""
    subset: Dict[str, Any] = {}
    for f in SIGN_FIELDS:
        if f not in msg:
            raise ValueError("Missing field for signing: %s" % f)
        subset[f] = msg[f]
    return canonical_json(subset)


def sign_message(message: str, private_key: bytes) -> str:
    sig = Ed25519PrivateKey.from_private_bytes(private_key).sign(message.encode("utf-8"))
    return base64.b64encode(sig).decode("ascii")


def verify_signature(message: str, signature: str, address: str) -> bool:
    try:
        pub = public_key_from_address(address)
        Ed25519PublicKey.from_public_bytes(pub).verify(
            base64.b64decode(signature), message.encode("utf-8")
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
