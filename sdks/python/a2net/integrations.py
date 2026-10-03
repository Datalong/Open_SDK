"""
integrations.py — Python 原生万能智能体适配器

让任何 Python 函数、异步协程、FastAPI 接口或 Webhook 服务秒级入网：
  1. @a2net_agent 装饰器：装饰任意 Python 函数即可自动暴露为 A2Net 去中心化节点
  2. HttpAgentBridge：将任意 HTTP Webhook（Dify / FastGPT / OpenAI / 本地服务）挂载为 A2Net 节点
"""
from __future__ import annotations

import asyncio
import inspect
import json
import urllib.error
import urllib.request
from typing import Any, Awaitable, Callable, Dict, Optional, Union

from .client import A2NetClient, PermissionPolicy
from .crypto import KeyPair, generate_keypair


class HttpAgentBridge:
    """万能 HTTP 智能体网卡（Python 版）：将外部 HTTP Webhook 接入 A2Net"""

    def __init__(
        self,
        relay_url: str,
        target_url: str,
        preset: str = "custom",
        target_api_key: Optional[str] = None,
        keypair: Optional[KeyPair] = None,
        api_key: Optional[str] = None,
        permission_policy: Optional[PermissionPolicy] = None,
        encrypt_content: bool = True,
        timeout: float = 60.0,
    ) -> None:
        self.relay_url = relay_url
        self.target_url = target_url
        self.preset = preset.lower()
        self.target_api_key = target_api_key
        self.timeout = timeout
        self.client = A2NetClient(
            relay_url=relay_url,
            keypair=keypair,
            api_key=api_key,
            encrypt_content=encrypt_content,
            permission_policy=permission_policy or PermissionPolicy(default_allow=True),
        )
        self.client.on_query(self._handle_query)

    @property
    def address(self) -> str:
        return self.client.address

    async def start(self) -> None:
        await self.client.connect()

    async def stop(self) -> None:
        await self.client.close()

    async def call_agent(self, target_address: str, query: str) -> str:
        return await self.client.query(target_address, query)

    async def _handle_query(self, query: str, sender: str, msg: Dict[str, Any]) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._forward_sync, query, sender)

    def _forward_sync(self, query: str, sender: str) -> str:
        url = self.target_url
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        body: Dict[str, Any] = {}

        if self.preset == "dify":
            base = url.rstrip("/")
            url = base if base.endswith("/chat-messages") else f"{base}/chat-messages"
            if self.target_api_key:
                headers["Authorization"] = f"Bearer {self.target_api_key}"
            body = {
                "inputs": {},
                "query": query,
                "response_mode": "blocking",
                "user": sender,
            }
        elif self.preset == "fastgpt":
            base = url.rstrip("/")
            url = base if base.endswith("/chat/completions") else f"{base}/api/v1/chat/completions"
            if self.target_api_key:
                headers["Authorization"] = f"Bearer {self.target_api_key}"
            body = {
                "chatId": sender,
                "stream": False,
                "detail": False,
                "messages": [{"role": "user", "content": query}],
            }
        elif self.preset == "openai":
            base = url.rstrip("/")
            url = base if base.endswith("/chat/completions") else f"{base}/v1/chat/completions"
            if self.target_api_key:
                headers["Authorization"] = f"Bearer {self.target_api_key}"
            body = {
                "model": "default",
                "messages": [{"role": "user", "content": query}],
            }
        else:
            if self.target_api_key:
                headers["Authorization"] = f"Bearer {self.target_api_key}"
            body = {"query": query, "sender": sender}

        req = urllib.request.Request(
            url,
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                content_type = resp.headers.get("content-type", "")
                raw_bytes = resp.read()
                raw_str = raw_bytes.decode("utf-8", errors="replace")
                if "application/json" in content_type:
                    data = json.loads(raw_str)
                    if isinstance(data, dict):
                        if "answer" in data:
                            return str(data["answer"])
                        if "choices" in data and isinstance(data["choices"], list):
                            first = data["choices"][0]
                            if isinstance(first, dict) and "message" in first:
                                return str(first["message"].get("content", ""))
                        for k in ["response", "result", "reply", "text", "content"]:
                            if k in data:
                                return str(data[k])
                    return raw_str
                return raw_str
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Target agent HTTP {e.code}: {err_body[:200]}")


def a2net_agent(
    relay_url: str,
    keypair: Optional[KeyPair] = None,
    api_key: Optional[str] = None,
    encrypt_content: bool = True,
    permission_policy: Optional[PermissionPolicy] = None,
):
    """函数装饰器：将任意 Python 同步或异步函数直接作为 A2Net 智能体运行

    示例::

        @a2net_agent("ws://127.0.0.1:8080")
        def calculate(query: str, sender: str) -> str:
            return f"Answer: {eval(query)}"

        # 启动入网监听
        asyncio.run(calculate.serve())
    """

    def decorator(fn: Callable[..., Union[str, Dict[str, Any], Awaitable[Any]]]):
        client = A2NetClient(
            relay_url=relay_url,
            keypair=keypair,
            api_key=api_key,
            encrypt_content=encrypt_content,
            permission_policy=permission_policy or PermissionPolicy(default_allow=True),
        )

        async def handler(query: str, sender: str, msg: Dict[str, Any]) -> Any:
            sig = inspect.signature(fn)
            params = sig.parameters
            if len(params) == 1:
                res = fn(query)
            elif len(params) == 2:
                res = fn(query, sender)
            else:
                res = fn(query, sender, msg)

            if inspect.isawaitable(res):
                return await res
            return res

        client.on_query(handler)

        async def serve():
            await client.connect()
            try:
                while True:
                    await asyncio.sleep(1)
            finally:
                await client.close()

        # 附加属性
        fn.client = client  # type: ignore
        fn.address = client.address  # type: ignore
        fn.serve = serve  # type: ignore
        return fn

    return decorator
