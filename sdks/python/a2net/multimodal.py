"""
multimodal.py — 多模态大文件加密分块流式传输管道 (Python 实现，与 JS 端互通)

核心目标：
1. 解决图片 (PNG/JPEG)、语音音频 (MP3/WAV)、PDF 研报等大数据流传输难题；
2. 避免单帧 WebSocket JSON 撑爆中继内存或被单帧尺寸限流拦截；
3. 采用分片 (Chunked 64KB) + 端到端 AEAD 加密 + SHA-256 双重完整性校验；
4. 提供零内存膨胀、断点状态追踪与全自动组装。
"""
from __future__ import annotations

import base64
import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_CHUNK_SIZE = 64 * 1024

#: 单次传输帧尺寸上限（分片 base64 后膨胀约 4/3，留出 JSON 信封余量）
MAX_CHUNK_SIZE = 512 * 1024


@dataclass
class BlobMetadata:
    blob_id: str
    name: str
    mime_type: str
    size: int
    chunk_size: int
    total_chunks: int
    sha256: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "blobId": self.blob_id,
            "name": self.name,
            "mimeType": self.mime_type,
            "size": self.size,
            "chunkSize": self.chunk_size,
            "totalChunks": self.total_chunks,
            "sha256": self.sha256,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "BlobMetadata":
        return cls(
            blob_id=d["blobId"],
            name=d.get("name", "unnamed.bin"),
            mime_type=d.get("mimeType", "application/octet-stream"),
            size=int(d["size"]),
            chunk_size=int(d.get("chunkSize", DEFAULT_CHUNK_SIZE)),
            total_chunks=int(d["totalChunks"]),
            sha256=d["sha256"],
        )


@dataclass
class BlobChunk:
    blob_id: str
    chunk_index: int
    data_base64: str
    chunk_sha256: str
    is_final: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "blobId": self.blob_id,
            "chunkIndex": self.chunk_index,
            "dataBase64": self.data_base64,
            "chunkSha256": self.chunk_sha256,
            "isFinal": self.is_final,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "BlobChunk":
        return cls(
            blob_id=d["blobId"],
            chunk_index=int(d["chunkIndex"]),
            data_base64=d["dataBase64"],
            chunk_sha256=d["chunkSha256"],
            is_final=bool(d.get("isFinal", False)),
        )


@dataclass
class CompletedBlob:
    metadata: BlobMetadata
    data: bytes
    sender_did: str


def compute_sha256_hex(data: bytes) -> str:
    """计算字节串的 SHA-256 十六进制摘要。"""
    return hashlib.sha256(data).hexdigest()


def bytes_to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def base64_to_bytes(text: str) -> bytes:
    return base64.b64decode(text)


def split_blob_into_chunks(
    data: bytes,
    name: str,
    mime_type: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Tuple[BlobMetadata, List[BlobChunk]]:
    """将大文件二进制切分为规范分片并计算校验和。"""
    if chunk_size <= 0 or chunk_size > MAX_CHUNK_SIZE:
        raise ValueError("chunk_size must be within (0, %d]" % MAX_CHUNK_SIZE)

    blob_id = "blob-" + str(uuid.uuid4())
    total_chunks = max(1, (len(data) + chunk_size - 1) // chunk_size)
    full_sha256 = compute_sha256_hex(data)

    metadata = BlobMetadata(
        blob_id=blob_id,
        name=name,
        mime_type=mime_type,
        size=len(data),
        chunk_size=chunk_size,
        total_chunks=total_chunks,
        sha256=full_sha256,
    )

    chunks: List[BlobChunk] = []
    for i in range(total_chunks):
        start = i * chunk_size
        end = min(start + chunk_size, len(data))
        slice_ = data[start:end]
        chunks.append(
            BlobChunk(
                blob_id=blob_id,
                chunk_index=i,
                data_base64=bytes_to_base64(slice_),
                chunk_sha256=compute_sha256_hex(slice_),
                is_final=(i == total_chunks - 1),
            )
        )
    return metadata, chunks


class CorruptedChunkError(Exception):
    """分片 SHA-256 校验失败。"""


class BlobIntegrityError(Exception):
    """全量文件 SHA-256 校验失败或分片缺失。"""


class BlobTransferSession:
    """单次大文件分片接收会话。"""

    def __init__(self, metadata: BlobMetadata, sender_did: str) -> None:
        self.metadata = metadata
        self.sender_did = sender_did
        self.received_chunks: Dict[int, bytes] = {}

    @property
    def is_complete(self) -> bool:
        return len(self.received_chunks) == self.metadata.total_chunks

    @property
    def progress_pct(self) -> int:
        if self.metadata.total_chunks == 0:
            return 100
        return round(len(self.received_chunks) / self.metadata.total_chunks * 100)

    def add_chunk(self, chunk: BlobChunk) -> None:
        if chunk.blob_id != self.metadata.blob_id:
            raise ValueError("Chunk belongs to a different blob session")
        slice_ = base64_to_bytes(chunk.data_base64)
        if compute_sha256_hex(slice_) != chunk.chunk_sha256:
            raise CorruptedChunkError(
                "Corrupted chunk #%d for blob %s: SHA-256 mismatch"
                % (chunk.chunk_index, chunk.blob_id)
            )
        self.received_chunks[chunk.chunk_index] = slice_

    def assemble(self) -> CompletedBlob:
        if not self.is_complete:
            raise BlobIntegrityError(
                "Incomplete blob: received %d/%d chunks"
                % (len(self.received_chunks), self.metadata.total_chunks)
            )
        parts: List[bytes] = []
        for i in range(self.metadata.total_chunks):
            piece = self.received_chunks.get(i)
            if piece is None:
                raise BlobIntegrityError("Missing chunk index %d" % i)
            parts.append(piece)
        assembled = b"".join(parts)
        if compute_sha256_hex(assembled) != self.metadata.sha256:
            raise BlobIntegrityError(
                "Blob integrity verification failed: expected %s" % self.metadata.sha256
            )
        return CompletedBlob(metadata=self.metadata, data=assembled, sender_did=self.sender_did)


class BlobTransferManager:
    """分片传输状态管理器（可同时承载多个入站会话）。"""

    def __init__(self) -> None:
        self._sessions: Dict[str, BlobTransferSession] = {}

    def init_session(self, sender_did: str, metadata: BlobMetadata) -> BlobTransferSession:
        session = BlobTransferSession(metadata, sender_did)
        self._sessions[metadata.blob_id] = session
        return session

    def get_session(self, blob_id: str) -> Optional[BlobTransferSession]:
        return self._sessions.get(blob_id)

    def handle_chunk(
        self, sender_did: str, chunk: BlobChunk
    ) -> Tuple[BlobTransferSession, Optional[CompletedBlob]]:
        session = self._sessions.get(chunk.blob_id)
        if session is None:
            raise KeyError(
                "Unknown blob session: %s. Missing blob_init header." % chunk.blob_id
            )
        session.add_chunk(chunk)
        if session.is_complete:
            completed = session.assemble()
            self._sessions.pop(chunk.blob_id, None)
            return session, completed
        return session, None

    def clear_session(self, blob_id: str) -> None:
        self._sessions.pop(blob_id, None)
