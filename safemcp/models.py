from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from uuid import uuid4


def uid(prefix):
    return f"{prefix}-{uuid4().hex}"


@dataclass
class SecurityDecision:
    phase: str
    decision: str
    risk_level: str = "none"
    rule_ids: list[str] = field(default_factory=list)
    reason: str = "配置规则检查通过；不代表绝对安全。"
    evidence_preview: str = ""
    tool_name: str = ""


@dataclass
class AuditEvent(SecurityDecision):
    event_id: str = field(default_factory=lambda: uid("evt"))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str = ""
    turn_id: str = ""
    source_type: str = "trusted_application"
    tool_call_id: str = ""
    arguments_preview: str = ""
    tool_call_executed: bool | None = False
    result_exposed_to_llm: bool = False

    def to_dict(self):
        return asdict(self)


@dataclass
class ToolOutcome:
    text: str
    decision: SecurityDecision
    tool_call_executed: bool | None = False
    result_exposed_to_llm: bool = False


@dataclass
class TurnResult:
    session_id: str
    turn_id: str
    answer: str
    status: str
    mode: str
    elapsed_ms: float
    events: list[dict]
