"""emit_fixtures.py — 跨语言互操作测试（Python 侧，生成向量）

用固定种子生成消息 / Agent Card / 密文，写入 tests/fixtures/py-fixtures.json，
供 JS 侧的 check_and_emit.mjs 校验。

运行：python3 tests/emit_fixtures.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from a2net import (  # noqa: E402
    KeyPair,
    build_message,
    canonical_json,
    create_agent_card,
    encrypt_for,
    keypair_from_private_key,
    sign_agent_card,
    sign_message,
    get_sign_string,
)

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")

SEED_A = bytes(range(1, 33))  # 与 JS 侧一致：0x01..0x20
SEED_B = bytes(range(0xA0, 0xC0))


def main() -> None:
    os.makedirs(FIXTURES, exist_ok=True)
    kp_a = keypair_from_private_key(SEED_A)
    kp_b = keypair_from_private_key(SEED_B)

    canonical_input = {"b": [1, 2, {"z": None, "a": "中文"}], "a": {"y": True, "x": 1730000000000}}

    message = build_message(
        kp_a.address,
        kp_b.address,
        "query",
        {"query": "你好，JS", "scope": {"type": "task", "max_tokens": 128}},
        kp_a.private_key,
        timestamp=1730000000000,
    )

    card = sign_agent_card(
        create_agent_card(
            did=kp_a.address,
            name="Python 端助手",
            description="由 Python SDK 生成",
            url="https://py.example.com/.well-known/agent-description.json",
            relay="wss://relay.a2net.io",
            pricing={"unit": "sat", "amount": 100},
            capabilities=["poetry"],
            interfaces=[{"type": "NaturalLanguageInterface", "protocol": "A2Net"}],
        ),
        kp_a,
        created="2025-01-01T00:00:00.000Z",
    )

    envelope = encrypt_for(kp_b.address, "来自 Python 的密文", ephemeral_seed=SEED_A)

    out = {
        "address": kp_a.address,
        "addressB": kp_b.address,
        "canonicalJsonInput": canonical_input,
        "canonicalJsonSample": canonical_json(canonical_input),
        "signString": get_sign_string(message),
        "message": message,
        "agentCard": card,
        "envelope": envelope,
        "plaintext": "来自 Python 的密文",
        "crossCheck": {
            # 同一消息在 Python 端的签名，用于与 JS 逐字节比对
            "signature": sign_message(get_sign_string(message), kp_a.private_key),
        },
    }

    path = os.path.join(FIXTURES, "py-fixtures.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)
    print("已写出 %s" % path)
    print("地址: %s" % kp_a.address)


if __name__ == "__main__":
    main()
