"""
e2ee.py — 端到端加密（协议 v0.2，与 JS 端互通）

- Ed25519 身份密钥 → X25519 加解密密钥（标准双线性映射），无需额外分发密钥
- 每条消息一次性 X25519 临时密钥 → ECDH → HKDF-SHA256 → AES-256-GCM
- 信封整体替换消息的 content
"""
from __future__ import annotations

import base64
import hashlib
import os
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto import public_key_from_address

E2EE_ALG = "X25519-HKDF-SHA256-AES-256-GCM"
_HKDF_INFO = b"a2net-e2ee-v1"

_P = 2 ** 255 - 19


def ed25519_pub_to_x25519(public_key: bytes) -> bytes:
    """Ed25519 公钥 → X25519 公钥（Montgomery u = (1+y)/(1-y)）。"""
    y = int.from_bytes(public_key, "little") & ((1 << 255) - 1)
    u = ((1 + y) * pow((1 - y) % _P, _P - 2, _P)) % _P
    return u.to_bytes(32, "little")


def ed25519_priv_to_x25519(seed: bytes) -> bytes:
    """Ed25519 私钥种子 → X25519 私钥（SHA-512 前 32 字节并 clamp）。"""
    h = hashlib.sha512(seed).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return bytes(a)


def encryption_public_key_from_address(address: str) -> bytes:
    """由 did:key 地址直接得到该 Agent 的 X25519 加密公钥。"""
    return ed25519_pub_to_x25519(public_key_from_address(address))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data)


def _derive_key(shared: bytes, epk: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=epk + recipient_pub,
        info=_HKDF_INFO,
    ).derive(shared)


def encrypt_for(
    recipient_address: str,
    plaintext: str,
    ephemeral_seed: Optional[bytes] = None,
) -> Dict[str, str]:
    """加密一段明文发给收件人，返回信封 dict。"""
    recipient_pub = encryption_public_key_from_address(recipient_address)

    eph_priv_bytes = ed25519_priv_to_x25519(ephemeral_seed) if ephemeral_seed else os.urandom(32)
    eph_priv = X25519PrivateKey.from_private_bytes(eph_priv_bytes)
    eph_pub = eph_priv.public_key().public_bytes_raw()
    shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(recipient_pub))

    key = _derive_key(shared, eph_pub, recipient_pub)
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)
    return {"alg": E2EE_ALG, "epk": _b64(eph_pub), "iv": _b64(iv), "ct": _b64(ct)}


def decrypt_from(sender_address: str, envelope: Dict[str, str], recipient_private_key: bytes) -> str:
    """解密来自发件人的信封。"""
    if envelope.get("alg") != E2EE_ALG:
        raise ValueError("不支持的加密算法: %s" % envelope.get("alg"))
    if not sender_address.startswith("did:key:"):
        raise ValueError("sender_address 必须是 did:key 地址")

    recipient_priv_bytes = ed25519_priv_to_x25519(recipient_private_key)
    recipient_priv = X25519PrivateKey.from_private_bytes(recipient_priv_bytes)
    recipient_pub = recipient_priv.public_key().public_bytes_raw()

    epk = _unb64(envelope["epk"])
    shared = recipient_priv.exchange(X25519PublicKey.from_public_bytes(epk))
    key = _derive_key(shared, epk, recipient_pub)

    pt = AESGCM(key).decrypt(_unb64(envelope["iv"]), _unb64(envelope["ct"]), None)
    return pt.decode("utf-8")


def is_encrypted(content: Any) -> bool:
    return (
        isinstance(content, dict)
        and content.get("alg") == E2EE_ALG
        and isinstance(content.get("ct"), str)
    )
