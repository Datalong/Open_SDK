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
