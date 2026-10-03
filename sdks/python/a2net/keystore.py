"""
keystore.py — 生产级磁盘加密密钥库管理器 (Python 实现)

特性：
1. 采用 PBKDF2-HMAC-SHA256 (100,000 次哈希) + AES-256-GCM 工业级标准加密私钥
2. 完全杜绝明文私钥落盘，密码保护安全存储
3. 提供 FileKeystore 封装，具备 save / load / unlock 完整生命周期
"""
import base64
import json
import os
import time
from typing import Any, Dict, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from a2net.crypto import KeyPair, keypair_from_private_key


def _derive_key(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_private_key(private_key: bytes, password: str, address: str) -> Dict[str, Any]:
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    # 将 address 作为关联数据（AAD）绑定，防止身份替换篡改
    ciphertext = aesgcm.encrypt(nonce, private_key, address.encode("utf-8"))

    return {
        "version": 1,
        "kdf": "pbkdf2-sha256",
        "iterations": 100_000,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "address": address,
        "createdAt": int(time.time() * 1000),
    }


def decrypt_private_key(keystore: Dict[str, Any], password: str) -> bytes:
    if keystore.get("kdf") != "pbkdf2-sha256":
        raise ValueError(f"Unsupported KDF: {keystore.get('kdf')}")

    salt = base64.b64decode(keystore["salt"])
    nonce = base64.b64decode(keystore["nonce"])
    ciphertext = base64.b64decode(keystore["ciphertext"])
    address = keystore["address"]
    iterations = keystore.get("iterations", 100_000)

    key = _derive_key(password, salt, iterations)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, address.encode("utf-8"))


class FileKeystore:
    def __init__(self, file_path: str, keystore_data: Dict[str, Any]):
        self.file_path = file_path
        self.keystore_data = keystore_data

    @property
    def address(self) -> str:
        return self.keystore_data["address"]

    def unlock(self, password: str) -> KeyPair:
        raw_priv = decrypt_private_key(self.keystore_data, password)
        return keypair_from_private_key(raw_priv)

    @classmethod
    def save(cls, file_path: str, keypair: KeyPair, password: str) -> "FileKeystore":
        data = encrypt_private_key(keypair.private_key, password, keypair.address)
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return cls(file_path, data)

    @classmethod
    def load(cls, file_path: str) -> "FileKeystore":
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not data.get("address") or not data.get("ciphertext"):
            raise ValueError(f"Invalid keystore format: {file_path}")
        return cls(file_path, data)

    @classmethod
    def load_and_unlock(cls, file_path: str, password: str) -> KeyPair:
        store = cls.load(file_path)
        return store.unlock(password)
