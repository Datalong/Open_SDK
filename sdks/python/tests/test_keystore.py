import os
import tempfile
import pytest
from a2net.crypto import generate_keypair
from a2net.keystore import FileKeystore, encrypt_private_key, decrypt_private_key

def test_python_keystore_save_and_unlock():
    kp = generate_keypair()
    password = "Secure-Python-Agent-Password-2025"

    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)

    try:
        # 1. 保存
        saved = FileKeystore.save(path, kp, password)
        assert saved.address == kp.address

        # 2. 读取
        loaded = FileKeystore.load(path)
        assert loaded.address == kp.address

        # 3. 错误密码拒绝
        with pytest.raises(Exception):
            loaded.unlock("wrong-password")

        # 4. 正确密码解密，公私钥和 DID 完全还原
        restored = loaded.unlock(password)
        assert restored.address == kp.address
        assert restored.public_key == kp.public_key
        assert restored.private_key == kp.private_key

        # 5. 便捷静态方法测试
        direct = FileKeystore.load_and_unlock(path, password)
        assert direct.address == kp.address
    finally:
        if os.path.exists(path):
            os.remove(path)
