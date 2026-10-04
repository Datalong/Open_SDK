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


# ───────────────────────────────────────────────────────────────────────────
# 明文长度填充（与 TS 端逐字节一致）
#
# 为什么要填充：密文的**长度**本身会泄露信息。2KB 的查询与 200KB 的应答，
# 即使内容全加密，长度也足以让中继推断出"这是长文本生成"而非"短问答"。
#
# 为什么用分级桶而非定长：定长（一律 64KB）会把 100 字节的 ping 放大 640 倍。
# 分级桶在"抹平特征"与"控制开销"之间取平衡。
#
# 为什么用随机字节而非零填充：AES-GCM 密文本身已不可区分，但零填充在
# 其他实现（如非 AEAD）下会暴露填充边界。随机填充更保守。
# ───────────────────────────────────────────────────────────────────────────

# 上限刻意设在 16KB：填充收益随载荷增大而递减，代价却线性增长。
# 超过上限则**不填充**（多模态 64KB 分片本就定长，填充到 256KB 会造成 4 倍膨胀
# 却几乎换不到隐私收益）。详见 TS 端同名常量的说明。
PAD_BUCKETS = (256, 1024, 4096, 16384)
_PAD_LEN_BYTES = 4


def padded_length(plaintext_bytes: int) -> int:
    """按分级桶计算填充后的目标长度；**返回 0 表示不填充**（已超过最大桶）。"""
    need = plaintext_bytes + _PAD_LEN_BYTES
    for b in PAD_BUCKETS:
        if need <= b:
            return b
    return 0


def pad_plaintext(plaintext: bytes) -> bytes:
    """明文 → 填充后字节（[4B 大端原长][明文][随机填充]）；无需填充时原样返回。"""
    target = padded_length(len(plaintext))
    if target == 0:
        return plaintext
    body = plaintext + os.urandom(target - len(plaintext) - _PAD_LEN_BYTES)
    return len(plaintext).to_bytes(_PAD_LEN_BYTES, "big") + body


def unpad_plaintext(padded: bytes) -> bytes:
    """填充后字节 → 明文。异常输入一律抛错，绝不返回"看起来像原文"的错数据。"""
    if len(padded) < _PAD_LEN_BYTES:
        raise ValueError("填充数据过短，无法解析长度前缀")
    orig_len = int.from_bytes(padded[:_PAD_LEN_BYTES], "big")
    avail = len(padded) - _PAD_LEN_BYTES
    if orig_len > avail:
        raise ValueError("填充长度前缀非法: 声称 %d 字节，但实际只有 %d 字节" % (orig_len, avail))
    return padded[_PAD_LEN_BYTES : _PAD_LEN_BYTES + orig_len]


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
    # 加密前做长度填充；仅当真的填充过才标记 pad=True
    raw = plaintext.encode("utf-8")
    padded = pad_plaintext(raw)
    ct = AESGCM(key).encrypt(iv, padded, None)
    out = {"alg": E2EE_ALG, "epk": _b64(eph_pub), "iv": _b64(iv), "ct": _b64(ct)}
    if len(padded) != len(raw):
        out["pad"] = True
    return out


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
    # 仅当发送方标记了填充才解填充 —— 旧格式（无 pad 字段）按原样解码
    if envelope.get("pad") is True:
        pt = unpad_plaintext(pt)
    return pt.decode("utf-8")


def is_encrypted(content: Any) -> bool:
    return (
        isinstance(content, dict)
        and content.get("alg") == E2EE_ALG
        and isinstance(content.get("ct"), str)
    )
