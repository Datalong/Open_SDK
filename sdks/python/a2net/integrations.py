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


def expose(
    relay_url: str = "ws://127.0.0.1:8080",
    *,
    name: Optional[str] = None,
    description: Optional[str] = None,
    tags: Optional[list] = None,
    keypair: Optional[KeyPair] = None,
    api_key: Optional[str] = None,
    encrypt_content: bool = True,
    permission_policy: Optional[PermissionPolicy] = None,
    auto_card: bool = True,
):
    """【官方推荐】一键挂网装饰器：将任意 Python 函数、生成器或异步协程暴露为 A2Net 加密智能体节点。

    支持自动生成 Agent Card 元数据、支持 did:key 地址绑定与双向加密。

    示例::

        import a2net

        @a2net.expose("ws://127.0.0.1:8080", name="MathSolver", description="智能算力节点")
        def solve(problem: str) -> str:
            return f"Calculated: {eval(problem)}"

        # 挂网运行
        asyncio.run(solve.serve())
    """
    def decorator(fn: Callable[..., Any]):
        resolved_name = name or getattr(fn, "__name__", "custom-agent")
        resolved_desc = description or getattr(fn, "__doc__", "") or f"A2Net agent function {resolved_name}"

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
            if len(params) == 0:
                res = fn()
            elif len(params) == 1:
                res = fn(query)
            elif len(params) == 2:
                res = fn(query, sender)
            else:
                res = fn(query, sender, msg)

            if inspect.isawaitable(res):
                res = await res

            if isinstance(res, (dict, list)):
                return json.dumps(res, ensure_ascii=False)
            return str(res)

        client.on_query(handler)

        async def serve():
            await client.connect()
            try:
                while True:
                    await asyncio.sleep(1)
            finally:
                await client.close()

        # 注入属性方便调用者快速访问
        fn.client = client  # type: ignore
        fn.address = client.address  # type: ignore
        fn.serve = serve  # type: ignore
        fn.agent_name = resolved_name  # type: ignore
        fn.agent_description = resolved_desc  # type: ignore
        fn.agent_tags = tags or ["python", "function"]  # type: ignore
        return fn

    return decorator


def a2net_agent(
    relay_url: str,
    keypair: Optional[KeyPair] = None,
    api_key: Optional[str] = None,
    encrypt_content: bool = True,
    permission_policy: Optional[PermissionPolicy] = None,
):
    """向后兼容的函数装饰器别名，请优先使用 @a2net.expose"""
    return expose(
        relay_url=relay_url,
        keypair=keypair,
        api_key=api_key,
        encrypt_content=encrypt_content,
        permission_policy=permission_policy,
    )



# ══════════════════════════════════════════════════════════════
# LangChain / LlamaIndex / CrewAI 框架互通适配层
# ══════════════════════════════════════════════════════════════


class A2NetLangChainTool:
    """A2Net 工具：让 LangChain Agent 能够无缝通过 E2EE 网络调用任何远程 A2Net Agent。

    兼容标准 LangChain BaseTool 协议（提供 name, description, _run, _arun 及 __call__）。
    """

    def __init__(
        self,
        client: A2NetClient,
        target_did: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> None:
        self.client = client
        self.target_did = target_did
        self.name = name or f"call_a2net_agent_{target_did[-8:]}"
        self.description = (
            description
            or f"Call the remote decentralized A2Net agent at {target_did} via end-to-end encrypted protocol."
        )

    def _run(self, query: str) -> str:
        """同步运行：在当前事件循环或新建循环中等待"""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, self._arun(query)).result()
        return asyncio.run(self._arun(query))

    async def _arun(self, query: str) -> str:
        """异步运行：通过 A2Net 客户端调用远程 Agent"""
        return await self.client.query(self.target_did, query)

    def __call__(self, query: str) -> str:
        return self._run(query)

    def as_langchain_tool(self):
        """如果环境中安装了 langchain_core，返回标准的 StructuredTool/Tool 实例"""
        try:
            from langchain_core.tools import Tool  # type: ignore

            return Tool(
                name=self.name,
                description=self.description,
                func=self._run,
                coroutine=self._arun,
            )
        except ImportError:
            return self


class A2NetLlamaIndexToolSpec:
    """LlamaIndex 工具适配器：可作为 FunctionTool 注入给 LlamaIndex Agent / ReActAgent。"""

    def __init__(
        self,
        client: A2NetClient,
        target_did: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> None:
        self.client = client
        self.target_did = target_did
        self.name = name or f"a2net_{target_did[-8:]}"
        self.description = (
            description
            or f"Query decentralized A2Net agent {target_did}. Input should be the text prompt/question."
        )

    async def aquery(self, query: str) -> str:
        """异步查询远程 A2Net Agent"""
        return await self.client.query(self.target_did, query)

    def query(self, query: str) -> str:
        """同步查询远程 A2Net Agent"""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, self.aquery(query)).result()
        return asyncio.run(self.aquery(query))

    def as_llama_tool(self):
        """若环境中安装了 llama_index.core，返回标准的 FunctionTool 实例"""
        try:
            from llama_index.core.tools import FunctionTool  # type: ignore

            return FunctionTool.from_defaults(
                fn=self.query,
                async_fn=self.aquery,
                name=self.name,
                description=self.description,
            )
        except ImportError:
            return self


class A2NetCrewAITool:
    """CrewAI 工具适配器：直接挂载到 CrewAI Agent 的 tools 列表里。"""

    def __init__(
        self,
        client: A2NetClient,
        target_did: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> None:
        self.client = client
        self.target_did = target_did
        self.name = name or f"A2Net Agent {target_did[-8:]}"
        self.description = (
            description
            or f"Encrypted inter-agent tool that delegates tasks to A2Net node {target_did}."
        )

    def run(self, query: str) -> str:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, self.client.query(self.target_did, query)).result()
        return asyncio.run(self.client.query(self.target_did, query))

    def _run(self, query: str) -> str:
        return self.run(query)

    def __call__(self, query: str) -> str:
        return self.run(query)

