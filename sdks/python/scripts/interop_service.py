"""
interop_service.py — 跨语言联调服务（Python 侧 Agent）

功能：
1. 启动 HTTP 站点，发布经 Ed25519 签名的 Agent Card (.well-known/agent-description.json)
2. 接入指定中继服务器（WebSocket）
3. 开启端到端加密（E2EE: X25519-HKDF-SHA256-AES-256-GCM）
4. 支持白名单访问控制（可由命令行指定允许调用的 peer DID）
5. 提供查询响应处理（翻译 / 问答）
6. 通过标准输入输出（stdin / stdout）与主调进程交互，支持主动向对端发起反向查询
"""
from __future__ import annotations

import argparse
import asyncio
import http.server
import json
import os
import socketserver
import sys
import threading
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from a2net import (
    A2NetClient,
    KeyPair,
    PermissionPolicy,
    create_agent_card,
    generate_keypair,
    sign_agent_card,
)


class CardHttpHandler(http.server.BaseHTTPRequestHandler):
    signed_card_bytes: bytes = b"{}"

    def do_GET(self) -> None:
        if self.path == "/.well-known/agent-description.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(self.signed_card_bytes)))
            self.end_headers()
            self.wfile.write(self.signed_card_bytes)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        # 静默，不打印 HTTP 访问日志污染 stdout
        pass


def run_card_server(port: int, card_bytes: bytes) -> socketserver.TCPServer:
    handler = CardHttpHandler
    handler.signed_card_bytes = card_bytes
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", port), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


def translate_text(text: str) -> str:
    cleaned = text.strip()
    mapping = {
        "hello": "你好",
        "hello world": "你好，世界",
        "hello, world": "你好，世界",
        "hello, world!": "你好，世界！",
        "good morning": "早上好",
        "who are you?": "我是 Python A2Net 智能体",
    }
    lower = cleaned.lower()
    if lower in mapping:
        return mapping[lower]
    if lower.startswith("translate:"):
        sub = lower[len("translate:"):].strip()
        if sub in mapping:
            return mapping[sub]
        return f"已翻译({sub})"
    return f"Python回声: {cleaned}"


async def stdin_reader_loop(client: A2NetClient) -> None:
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    while True:
        line_bytes = await reader.readline()
        if not line_bytes:
            break
        line = line_bytes.decode("utf-8").strip()
        if not line:
            continue
        if line == "STOP":
            print("[PY] STOP_REQUESTED", flush=True)
            break
        if line.startswith("QUERY "):
            # 格式: QUERY <target_addr> <text>
            parts = line.split(" ", 2)
            if len(parts) >= 3:
                target, text = parts[1], parts[2]
                try:
                    res = await client.query(target, text, timeout=10.0)
                    print(f"[PY] QUERY_SUCCESS {json.dumps({'target': target, 'result': res}, ensure_ascii=False)}", flush=True)
                except Exception as exc:
                    print(f"[PY] QUERY_FAILED {json.dumps({'target': target, 'error': str(exc)})}", flush=True)


async def main() -> None:
    parser = argparse.ArgumentParser(description="A2Net Python Interop Agent")
    parser.add_argument("--relay", default="ws://127.0.0.1:8090", help="Relay WebSocket URL")
    parser.add_argument("--card-port", type=int, default=8097, help="HTTP port for Agent Card")
    parser.add_argument("--allowed-peer", default=None, help="Whitelist peer address")
    args = parser.parse_args()

    keypair: KeyPair = generate_keypair()

    # 1. 构造并签名 Agent Card
    card_url = f"http://127.0.0.1:{args.card_port}/.well-known/agent-description.json"
    raw_card = create_agent_card(
        did=keypair.address,
        name="Python-Translator-Agent",
        description="A2Net Agent implemented in Python providing translation services",
        url=f"http://127.0.0.1:{args.card_port}",
        relay=args.relay,
        capabilities=["translation.v1", "nlp.v1"],
        pricing={"sat": 25, "model": "per_request"},
        interfaces=[
            {
                "type": "StructuredInterface/A2Net",
                "version": "1.0.0",
                "description": "Structured translation interface",
            }
        ],
    )
    signed_card = sign_agent_card(raw_card, keypair)
    signed_card_bytes = json.dumps(signed_card, ensure_ascii=False, indent=2).encode("utf-8")

    # 2. 启动 Agent Card HTTP 服务
    httpd = run_card_server(args.card_port, signed_card_bytes)

    # 3. 配置权限策略（白名单）
    policy = PermissionPolicy(
        default_allow=args.allowed_peer is None,
        whitelist=[args.allowed_peer] if args.allowed_peer else [],
    )

    client = A2NetClient(
        relay_url=args.relay,
        keypair=keypair,
        encrypt_content=True,
        permission_policy=policy,
    )

    def on_query_handler(query_text: str, sender: str, msg: Dict[str, Any]) -> Dict[str, Any]:
        is_e2ee = bool(msg.get("extensions", {}).get("e2ee"))
        print(
            f"[PY] QUERY_RECEIVED {json.dumps({'from': sender, 'query': query_text, 'e2ee': is_e2ee}, ensure_ascii=False)}",
            flush=True,
        )
        translated = translate_text(query_text)
        return {
            "result": translated,
            "metadata": {"engine": "python-a2net", "received_e2ee": is_e2ee},
        }

    client.on_query(on_query_handler)

    # 4. 连接中继
    await client.connect()

    # 5. 输出就绪通知给主控程序
    ready_payload = {
        "address": keypair.address,
        "card_url": card_url,
        "relay": args.relay,
    }
    print(f"[PY] READY {json.dumps(ready_payload)}", flush=True)

    # 6. 处理标准输入指令（如反向主动查询）
    try:
        await stdin_reader_loop(client)
    finally:
        await client.close()
        httpd.shutdown()
        print("[PY] SHUTDOWN_COMPLETE", flush=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
