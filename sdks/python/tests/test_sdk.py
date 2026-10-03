"""SDK 单元测试（不依赖 JS 侧）。"""
import pytest

from a2net import (
    ErrorCode,
    PermissionPolicy,
    address_from_public_key,
    build_message,
    build_query,
    build_response,
    canonical_json,
    decrypt_from,
    encrypt_for,
    encryption_public_key_from_address,
    generate_keypair,
    get_sign_string,
    is_encrypted,
    keypair_from_private_key,
    public_key_from_address,
    sign_message,
    validate_message,
    verify_signature,
)


# -- canonical JSON ---------------------------------------------------------

def test_canonical_json_sorts_keys_and_keeps_unicode():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    assert canonical_json({"中文": "值"}) == '{"中文":"值"}'
    assert canonical_json([1, "a", None, True]) == '[1,"a",null,true]'


def test_canonical_json_int_timestamp_stays_int():
    assert canonical_json({"t": 1730000000000}) == '{"t":1730000000000}'


# -- 身份 -------------------------------------------------------------------

def test_keypair_roundtrip_and_did_key():
    kp = generate_keypair()
    assert kp.address.startswith("did:key:z")
    assert public_key_from_address(kp.address) == kp.public_key
    assert address_from_public_key(kp.public_key) == kp.address
    again = keypair_from_private_key(kp.private_key)
    assert again.address == kp.address


def test_sign_and_verify():
    kp = generate_keypair()
    sig = sign_message("hello", kp.private_key)
    assert verify_signature("hello", sig, kp.address)
    assert not verify_signature("hello!", sig, kp.address)
    assert not verify_signature("hello", sig, generate_keypair().address)


# -- 消息协议 ---------------------------------------------------------------

def test_build_and_validate_message():
    a, b = generate_keypair(), generate_keypair()
    msg = build_message(a.address, b.address, "query", {"query": "hi"}, a.private_key)
    assert validate_message(msg) is None
    assert msg["type"] == "query"

    tampered = dict(msg, content={"query": "hacked"})
    assert validate_message(tampered) == ErrorCode.SIGNATURE


def test_validate_rejects_stale_timestamp():
    a, b = generate_keypair(), generate_keypair()
    msg = build_message(
        a.address, b.address, "query", {"query": "hi"}, a.private_key,
        timestamp=1_000_000_000_000,
    )
    assert validate_message(msg) == ErrorCode.SIGNATURE


def test_validate_rejects_missing_field():
    assert validate_message({"id": "x"}) == ErrorCode.FORMAT


def test_replay_detection_via_seen_ids():
    a, b = generate_keypair(), generate_keypair()
    msg = build_query(a.address, b.address, "hi", a.private_key)
    assert validate_message(msg, seen_ids={msg["id"]}) == ErrorCode.SIGNATURE


def test_response_reply_to():
    a, b = generate_keypair(), generate_keypair()
    q = build_query(a.address, b.address, "hi", a.private_key)
    r = build_response(q, "hello", b.private_key)
    assert r["content"]["reply_to"] == q["id"]
    assert r["from"] == b.address and r["to"] == a.address
    assert validate_message(r) is None


# -- 端到端加密 -------------------------------------------------------------

def test_e2ee_roundtrip_and_no_plaintext():
    alice, bob = generate_keypair(), generate_keypair()
    env = encrypt_for(bob.address, "银行卡密码 123456")
    assert is_encrypted(env)
    assert "银行卡" not in str(env)
    assert decrypt_from(alice.address, env, bob.private_key) == "银行卡密码 123456"


def test_e2ee_wrong_key_fails():
    alice, bob, carol = generate_keypair(), generate_keypair(), generate_keypair()
    env = encrypt_for(bob.address, "只给 bob")
    with pytest.raises(Exception):
        decrypt_from(alice.address, env, carol.private_key)


def test_e2ee_tamper_fails():
    alice, bob = generate_keypair(), generate_keypair()
    env = encrypt_for(bob.address, "原文")
    raw = bytearray(__import__("base64").b64decode(env["ct"]))
    raw[0] ^= 0x01
    import base64
    env["ct"] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(Exception):
        decrypt_from(alice.address, env, bob.private_key)


def test_e2ee_nondeterministic():
    bob = generate_keypair()
    a = encrypt_for(bob.address, "同样的话")
    b = encrypt_for(bob.address, "同样的话")
    assert a["ct"] != b["ct"] and a["epk"] != b["epk"]


def test_encryption_public_key_derivable_from_address():
    kp = generate_keypair()
    assert len(encryption_public_key_from_address(kp.address)) == 32


# -- 权限 -------------------------------------------------------------------

def test_permission_policy():
    peer = "did:key:zPeer"
    blocked = "did:key:zBad"
    assert PermissionPolicy(default_allow=False).check(peer) is False
    assert PermissionPolicy(default_allow=True).check(peer) is True
    assert PermissionPolicy(whitelist=[peer]).check(peer) is True
    assert PermissionPolicy(default_allow=True, blacklist=[blocked]).check(blocked) is False
    # 黑名单优先于白名单
    assert PermissionPolicy(whitelist=[blocked], blacklist=[blocked]).check(blocked) is False
