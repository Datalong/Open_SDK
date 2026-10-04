"""
tests/test_framework_adapters.py — 验证 LangChain / LlamaIndex / CrewAI 适配器
"""
import asyncio
from unittest.mock import AsyncMock

from a2net import (
    A2NetClient,
    A2NetLangChainTool,
    A2NetLlamaIndexToolSpec,
    A2NetCrewAITool,
)


def test_langchain_tool_adapter():
    mock_client = AsyncMock(spec=A2NetClient)
    mock_client.query = AsyncMock(return_value="LangChain response from A2Net")

    target_did = "did:key:z6MkhaXgBZDvotDkL5257faiz48Z8x288jj46q5WnHcespcm"
    tool = A2NetLangChainTool(mock_client, target_did, name="remote_math")

    assert tool.name == "remote_math"
    assert "did:key" in tool.description

    # 异步执行
    async def run_async():
        res = await tool._arun("2 + 2 = ?")
        assert res == "LangChain response from A2Net"
        mock_client.query.assert_called_with(target_did, "2 + 2 = ?")

    asyncio.run(run_async())

    # 同步执行
    sync_res = tool._run("5 * 5 = ?")
    assert sync_res == "LangChain response from A2Net"


def test_llama_index_tool_spec():
    mock_client = AsyncMock(spec=A2NetClient)
    mock_client.query = AsyncMock(return_value="LlamaIndex response from A2Net")

    target_did = "did:key:z6MkhaXgBZDvotDkL5257faiz48Z8x288jj46q5WnHcespcm"
    spec = A2NetLlamaIndexToolSpec(mock_client, target_did, name="knowledge_bot")

    assert spec.name == "knowledge_bot"
    assert "knowledge_bot" in spec.name

    async def run_async():
        res = await spec.aquery("Explain quantum computing")
        assert res == "LlamaIndex response from A2Net"
        mock_client.query.assert_called_with(target_did, "Explain quantum computing")

    asyncio.run(run_async())

    sync_res = spec.query("Explain AI")
    assert sync_res == "LlamaIndex response from A2Net"


def test_crewai_tool_adapter():
    mock_client = AsyncMock(spec=A2NetClient)
    mock_client.query = AsyncMock(return_value="CrewAI response from A2Net")

    target_did = "did:key:z6MkhaXgBZDvotDkL5257faiz48Z8x288jj46q5WnHcespcm"
    crew_tool = A2NetCrewAITool(mock_client, target_did, name="ResearchBot")

    assert crew_tool.name == "ResearchBot"
    assert "ResearchBot" in crew_tool.name

    sync_res = crew_tool.run("Analyze Q3 market")
    assert sync_res == "CrewAI response from A2Net"
    mock_client.query.assert_called_with(target_did, "Analyze Q3 market")


# ───────────────────────────────────────────────────────────────────────────
# 流式响应：与 TS 端的分帧约定必须逐字节一致
# ───────────────────────────────────────────────────────────────────────────
def test_streaming_framing_contract():
    """验证本端产生的分帧形状符合约定（TS 端读取同一形状）。

    约定：
      · 增量帧  result=<delta>, metadata={seq, done: false}
      · 终止帧  result="",      metadata={seq, done: true}
    终止帧 result 必须为空 —— 接收侧会把所有带 seq 的帧按序拼接（含终止帧），
    若终止帧携带全文，拼接结果会把全文追加一遍，静默产出错误结果。
    """
    import asyncio
    from a2net import build_response, build_message, generate_keypair

    kp = generate_keypair()
    query_msg = build_message(
        kp.address, kp.address, "query", {"query": "hi", "stream": True}, kp.private_key
    )

    frames = []
    for seq, delta in enumerate(["你", "好"]):
        frames.append(build_response(query_msg, delta, kp.private_key, {"seq": seq, "done": False}))
    frames.append(build_response(query_msg, "", kp.private_key, {"seq": 2, "done": True}))

    # 拼接恒等式
    joined = "".join(f["content"]["result"] for f in frames)
    assert joined == "你好"

    # 形状断言
    assert all("seq" in f["content"]["metadata"] for f in frames)
    assert frames[-1]["content"]["metadata"]["done"] is True
    assert frames[-1]["content"]["result"] == ""

    # 这些帧必须是可签名/可验签的（协议一致性）
    from a2net import verify_signature, get_sign_string
    for f in frames:
        assert verify_signature(get_sign_string(f), f["signature"], kp.address)
    void = asyncio  # 保持导入被使用
    del void
