"""test_integrations.py — 测试 Python 端万能智能体适配器"""
import asyncio
import http.server
import json
import threading
import pytest
from a2net import a2net_agent, HttpAgentBridge, A2NetClient, generate_keypair


class DummyAgentHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(length)
        data = json.loads(raw.decode("utf-8"))

        if self.path == "/chat-messages":  # Dify
            resp = {"answer": f"Dify reply: {data.get('query')}"}
        elif self.path == "/api/v1/chat/completions":  # FastGPT
            msg = data.get("messages", [{}])[0].get("content")
            resp = {"choices": [{"message": {"content": f"FastGPT reply: {msg}"}}]}
        else:  # Custom
            resp = {"response": f"Custom reply: {data.get('query')}"}

        body = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def mock_agent_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), DummyAgentHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def test_http_agent_bridge_forward_sync(mock_agent_server):
    # 1. Custom preset
    bridge = HttpAgentBridge(
        relay_url="ws://127.0.0.1:8080",
        target_url=f"{mock_agent_server}/api/chat",
        preset="custom",
    )
    ans = bridge._forward_sync("hello", "did:key:zSender")
    assert ans == "Custom reply: hello"

    # 2. Dify preset
    dify_bridge = HttpAgentBridge(
        relay_url="ws://127.0.0.1:8080",
        target_url=mock_agent_server,
        preset="dify",
        target_api_key="dify-app-key-123",
    )
    dify_ans = dify_bridge._forward_sync("dify query", "did:key:zUser")
    assert dify_ans == "Dify reply: dify query"

    # 3. FastGPT preset
    fastgpt_bridge = HttpAgentBridge(
        relay_url="ws://127.0.0.1:8080",
        target_url=mock_agent_server,
        preset="fastgpt",
        target_api_key="fastgpt-key-456",
    )
    fastgpt_ans = fastgpt_bridge._forward_sync("fastgpt query", "did:key:zUser")
    assert fastgpt_ans == "FastGPT reply: fastgpt query"


def test_a2net_agent_decorator():
    @a2net_agent("ws://127.0.0.1:8080")
    def calc_agent(query: str, sender: str):
        return f"Calc: {query}"

    assert hasattr(calc_agent, "address")
    assert hasattr(calc_agent, "serve")
    assert hasattr(calc_agent, "client")
    assert calc_agent.address.startswith("did:key:z")
