"""跨语言互操作测试：校验 JS 端生成的向量。

需要先跑 `tests/interop.sh`（或手动）生成 tests/fixtures/js-fixtures.json；
文件不存在时自动跳过，保证单独跑 pytest 也能通过。
"""
import json
import os

import pytest

from a2net import (
    canonical_json,
    decrypt_from,
    get_sign_string,
    keypair_from_private_key,
    sign_message,
    validate_message,
    verify_agent_card,
)

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
JS_PATH = os.path.join(FIXTURES, "js-fixtures.json")

pytestmark = pytest.mark.skipif(
    not os.path.exists(JS_PATH), reason="js-fixtures.json 未生成，请先运行 tests/interop.sh"
)


@pytest.fixture(scope="module")
def js():
    with open(JS_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def test_did_key_matches_across_languages(js):
    kp = keypair_from_private_key(bytes.fromhex(js["seedA"]))
    assert kp.address == js["addressA"]


def test_canonical_json_matches_across_languages(js):
    assert canonical_json(js["canonicalJsonInput"]) == js["canonicalJsonSample"]


def test_js_message_verifies_in_python(js):
    # 固定向量使用历史时间戳，需显式指定 now，否则会命中 5 分钟时间窗
    assert validate_message(js["message"], now=js["message"]["timestamp"]) is None


def test_python_signature_is_byte_identical_to_js(js):
    """同一消息、同一私钥 → 两侧签名逐字节相同（Ed25519 确定性）。"""
    seed = bytes.fromhex(js["seedA"])
    assert sign_message(get_sign_string(js["message"]), seed) == js["message"]["signature"]


def test_js_agent_card_verifies_in_python(js):
    assert verify_agent_card(js["agentCard"]) is True


def test_python_can_decrypt_js_ciphertext(js):
    plain = decrypt_from(js["addressA"], js["envelope"], _seed_b())
    assert plain == js["plaintext"]


def _seed_b() -> bytes:
    """JS 侧 seedB = 0xa0..0xbf。"""
    return bytes(range(0xA0, 0xC0))
