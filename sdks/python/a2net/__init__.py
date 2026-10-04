"""
a2net — A2Net Python SDK

去中心化智能体通信网络的 Python 端实现，与 JS 端 **逐字节互通**
（同一套 did:key 地址、canonical JSON 签名规范、消息格式、端到端加密）。
"""
from .agent_card import (
    AGENT_CARD_RECOMMENDED_FIELDS,
    AGENT_CARD_REQUIRED_FIELDS,
    AGENT_DESCRIPTION_PATH,
    agent_description_url,
    create_agent_card,
    resolve_agent_card,
    sign_agent_card,
    validate_agent_card,
    verify_agent_card,
)
from .client import A2NetClient, PermissionPolicy
from .integrations import (
    A2NetCrewAITool,
    A2NetLangChainTool,
    A2NetLlamaIndexToolSpec,
    HttpAgentBridge,
    a2net_agent,
    expose,
)
from .crypto import (
    DID_PREFIX,
    SIGN_FIELDS,
    KeyPair,
    address_from_public_key,
    b58decode,
    b58encode,
    canonical_json,
    generate_keypair,
    get_sign_string,
    keypair_from_private_key,
    public_key_from_address,
    sign_message,
    verify_signature,
)
from .e2ee import (
    E2EE_ALG,
    decrypt_from,
    ed25519_priv_to_x25519,
    ed25519_pub_to_x25519,
    encrypt_for,
    encryption_public_key_from_address,
    is_encrypted,
)
from .protocol import (
    MESSAGE_TYPES,
    TIMESTAMP_WINDOW_MS,
    ErrorCode,
    build_blob_ack,
    build_blob_chunk,
    build_blob_init,
    build_error,
    build_message,
    build_query,
    build_response,
    is_valid,
    validate_message,
)
from .multimodal import (
    DEFAULT_CHUNK_SIZE,
    BlobChunk,
    BlobIntegrityError,
    BlobMetadata,
    BlobTransferManager,
    BlobTransferSession,
    CompletedBlob,
    CorruptedChunkError,
    base64_to_bytes,
    bytes_to_base64,
    compute_sha256_hex,
    split_blob_into_chunks,
)

__version__ = "0.1.0"

__all__ = [
    # crypto
    "DID_PREFIX",
    "SIGN_FIELDS",
    "KeyPair",
    "address_from_public_key",
    "b58decode",
    "b58encode",
    "canonical_json",
    "generate_keypair",
    "get_sign_string",
    "keypair_from_private_key",
    "public_key_from_address",
    "sign_message",
    "verify_signature",
    # protocol
    "MESSAGE_TYPES",
    "TIMESTAMP_WINDOW_MS",
    "ErrorCode",
    "build_blob_ack",
    "build_blob_chunk",
    "build_blob_init",
    "build_error",
    "build_message",
    "build_query",
    "build_response",
    "is_valid",
    "validate_message",
    # e2ee
    "E2EE_ALG",
    "decrypt_from",
    "ed25519_priv_to_x25519",
    "ed25519_pub_to_x25519",
    "encrypt_for",
    "encryption_public_key_from_address",
    "is_encrypted",
    # agent card
    "AGENT_DESCRIPTION_PATH",
    "agent_description_url",
    "create_agent_card",
    "resolve_agent_card",
    "sign_agent_card",
    "verify_agent_card",
    # client
    "A2NetClient",
    "PermissionPolicy",
    # integrations
    "HttpAgentBridge",
    "a2net_agent",
    # multimodal
    "DEFAULT_CHUNK_SIZE",
    "BlobChunk",
    "BlobIntegrityError",
    "BlobMetadata",
    "BlobTransferManager",
    "BlobTransferSession",
    "CompletedBlob",
    "CorruptedChunkError",
    "base64_to_bytes",
    "bytes_to_base64",
    "compute_sha256_hex",
    "split_blob_into_chunks",
]
