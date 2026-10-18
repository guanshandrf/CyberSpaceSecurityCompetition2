import pytest
from safemcp.audit import AuditLog, AuditError, redact
from safemcp.models import AuditEvent
from safemcp.catalog import DEMO_SECRET


def test_redaction_and_turn_filter(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    for turn in ("a", "b"):
        audit.append(AuditEvent("pre_tool_call", "DENY", session_id="s", turn_id=turn,
                                reason="api_key=sk-example-private " + DEMO_SECRET))
    events = audit.read("s", "a")
    assert len(events) == 1 and events[0]["turn_id"] == "a"
    assert {"session_id", "turn_id", "phase", "rule_ids", "decision", "reason", "tool_call_executed", "result_exposed_to_llm"} <= events[0].keys()
    text = audit.path.read_text(encoding="utf-8")
    assert DEMO_SECRET not in text and "sk-example-private" not in text
    assert audit.read("other", "a") == []


def test_audit_failure(tmp_path):
    with pytest.raises(AuditError):
        AuditLog(tmp_path).append(AuditEvent("pre_tool_call", "ALLOW"))


def test_configured_key_is_redacted(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "private-provider-value-123")
    assert "private-provider-value-123" not in redact("提示 private-provider-value-123")
    assert "abc.def.value" not in redact("Authorization: Bearer abc.def.value")
