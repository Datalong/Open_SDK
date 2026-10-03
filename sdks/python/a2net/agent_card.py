"""
agent_card.py — Agent Description（ANP-07）+ .well-known 发现（ANP-08）

与 JS 端同构：对「除 proof 外的卡片正文」做 canonical JSON 后 Ed25519 签名。
"""
from __future__ import annotations

import json
import time
import urllib.request
from typing import Any, Dict, List, Optional

from .crypto import KeyPair, canonical_json, sign_message, verify_signature

E2EE_ALG_HINT = "X25519-HKDF-SHA256-AES-256-GCM"

#: ANP-08 主动发现路径
AGENT_DESCRIPTION_PATH = "/.well-known/agent-description.json"


def _signable_payload(card: Dict[str, Any]) -> str:
    payload = {k: v for k, v in card.items() if k != "proof"}
    return canonical_json(payload)


def create_agent_card(
    did: str,
    name: str,
    description: str,
    url: str,
    owner: Optional[Dict[str, Any]] = None,
    relay: Optional[str] = None,
    pricing: Optional[Dict[str, Any]] = None,
    capabilities: Optional[List[str]] = None,
    information: Optional[List[Dict[str, Any]]] = None,
    interfaces: Optional[List[Dict[str, Any]]] = None,
    protocol_version: str = "1.0.0",
    created: Optional[str] = None,
) -> Dict[str, Any]:
    """构造一张（未签名的）Agent Description。"""
    card: Dict[str, Any] = {
        "protocolType": "A2Net",
        "protocolVersion": protocol_version,
        "type": "AgentDescription",
        "url": url,
        "name": name,
        "did": did,
        "description": description,
        "created": created or _iso_now(),
        "securityDefinitions": {
            "a2net_message": {
                "scheme": "ed25519",
                "in": "header",
                "name": "X-A2Net-Signature",
            }
        },
        "security": "a2net_message",
    }
    if owner is not None:
        card["owner"] = owner
    if relay is not None:
        card["relay"] = relay
    if pricing is not None:
        card["pricing"] = pricing
    if capabilities is not None:
        card["capabilities"] = capabilities
    if information is not None:
        card["information"] = information
    if interfaces is not None:
        card["interfaces"] = interfaces
    return card


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000Z"


def sign_agent_card(
    card: Dict[str, Any], keypair: KeyPair, created: Optional[str] = None
) -> Dict[str, Any]:
    """用私钥对卡片签名，返回带 proof 的新卡片。"""
    signature = sign_message(_signable_payload(card), keypair.private_key)
    signed = dict(card)
    signed["proof"] = {
        "type": "Ed25519Signature2020",
        "created": created or _iso_now(),
        "proofPurpose": "assertionMethod",
        "verificationMethod": keypair.address,
        "signatureValue": signature,
    }
    return signed


def verify_agent_card(card: Dict[str, Any]) -> bool:
    """校验卡片签名；did 必须与 proof.verificationMethod 一致。"""
    proof = card.get("proof")
    if not isinstance(proof, dict):
        return False
    if not proof.get("signatureValue") or not proof.get("verificationMethod"):
        return False
    if card.get("did") != proof["verificationMethod"]:
        return False
    try:
        return verify_signature(
            _signable_payload(card), proof["signatureValue"], proof["verificationMethod"]
        )
    except (ValueError, TypeError):
        return False


def agent_description_url(origin: str) -> str:
    return origin.rstrip("/") + AGENT_DESCRIPTION_PATH


def resolve_agent_card(url: str, timeout: float = 10.0) -> Dict[str, Any]:
    """拉取并校验远端卡片（ANP-08 主动发现）。"""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        card = json.loads(resp.read().decode("utf-8"))
    if card.get("type") != "AgentDescription":
        raise ValueError("不是有效的 Agent Description")
    if not verify_agent_card(card):
        raise ValueError("Agent Description 签名无效")
    return card
