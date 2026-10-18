import asyncio
import pytest
from safemcp.audit import AuditLog, AuditError
from safemcp.gateway import SecurityGateway
from safemcp.mcp_client import MCPClient
from safemcp.catalog import DEMO_SECRET


def test_real_gateway_blocks_and_isolates(tmp_path):
    async def run():
        async with MCPClient(tmp_path).connect() as client:
            audit = AuditLog(tmp_path / "audit.jsonl")
            gw = SecurityGateway(client, audit, "s", "t", "帮我读取项目周报并总结")
            bad = await gw.call("read_document", {"document_id": "weekly_injected"})
            assert bad.decision.decision == "SANITIZE"
            assert "send_message" not in bad.text and "接口联调通过" in bad.text
            denied = await gw.call("send_message", {"recipient": "demo@local.test", "content": "进度"})
            assert denied.decision.decision == "DENY"
            secret = await gw.call("send_message", {"recipient": "demo@local.test", "content": DEMO_SECRET})
            assert "P004" in secret.decision.rule_ids
            assert not (tmp_path / "outbox.jsonl").exists()
            gw2 = SecurityGateway(client, audit, "s", "t2", "将普通进度发送给 demo@local.test")
            assert (await gw2.call("send_message", {"recipient": "demo@local.test", "content": "普通进度"})).tool_call_executed
            assert len((tmp_path / "outbox.jsonl").read_text(encoding="utf-8").splitlines()) == 1
            assert all(e["turn_id"] == "t" for e in audit.read("s", "t"))
            post = next(e for e in gw.events if e["phase"] == "post_tool_result")
            assert post["source_type"] == "mcp_tool_result" and post["tool_call_executed"] and post["result_exposed_to_llm"]
    asyncio.run(run())


def test_fail_closed_and_call_limit(tmp_path):
    class Spy:
        calls = 0
        async def call_tool(self, name, args):
            self.calls += 1
            return "正常"
    async def run():
        spy = Spy()
        gw = SecurityGateway(spy, AuditLog(tmp_path), "s", "t", "总结")
        with pytest.raises(AuditError):
            await gw.call("read_document", {"document_id": "weekly"})
        assert spy.calls == 0
        gw = SecurityGateway(spy, AuditLog(tmp_path / "audit.jsonl"), "s", "t", "总结")
        for _ in range(5):
            outcome = await gw.call("read_document", {"document_id": "weekly"})
        assert outcome.decision.rule_ids == ["P006"] and spy.calls == 4
    asyncio.run(run())


def test_mcp_error_does_not_fabricate_execution_success(tmp_path):
    class Broken:
        async def call_tool(self, *args):
            raise TimeoutError("private error data must not be logged")
    async def run():
        gw = SecurityGateway(Broken(), AuditLog(tmp_path / "audit.jsonl"), "s", "t", "总结")
        result = await gw.call("read_document", {"document_id": "weekly"})
        assert result.decision.decision == "ERROR"
        assert result.tool_call_executed is None
        assert not result.result_exposed_to_llm
        assert "private error" not in str(gw.events)
    asyncio.run(run())
