import asyncio
import json
import pytest

from safemcp.mcp_client import MCPClient


def test_real_stdio_tools(tmp_path):
    async def run():
        async with MCPClient(tmp_path).connect() as client:
            tools = await client.list_tools()
            assert {t.name for t in tools} == {"read_document", "search_document", "send_message"}
            assert all(t.input_schema["type"] == "object" for t in tools)
            text = await client.call_tool("read_document", {"document_id": "weekly"})
            assert "星桥项目周报" in text
            assert "weekly" in await client.call_tool("search_document", {"query": "周报"})
            for doc_id in ("../../.env", "C:/Windows/win.ini", "missing"):
                with pytest.raises(RuntimeError):
                    await client.call_tool("read_document", {"document_id": doc_id})
            await client.call_tool("send_message", {"recipient": "demo@local.test", "content": "普通进度"})
        records = [json.loads(line) for line in (tmp_path / "outbox.jsonl").read_text(encoding="utf-8").splitlines()]
        assert records == [{"recipient": "demo@local.test", "content": "普通进度", "simulated": True}]
    asyncio.run(run())
