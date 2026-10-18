import json
from dataclasses import asdict

from safemcp.audit import AuditLog, redact
from safemcp.detector import PostToolDetector
from safemcp.models import AuditEvent, SecurityDecision, ToolOutcome, uid
from safemcp.policy import PreToolPolicy


class SecurityGateway:
    def __init__(self, client, audit: AuditLog, session_id: str, turn_id: str, trusted_request: str):
        self.client, self.audit = client, audit
        self.session_id, self.turn_id = session_id, turn_id
        self._trusted_request = trusted_request
        self.policy, self.detector = PreToolPolicy(), PostToolDetector()
        self.calls = 0
        self.events = []

    def record(self, decision, *, call_id="", args=None, executed=False, exposed=False, source="trusted_application"):
        event = AuditEvent(**asdict(decision), session_id=self.session_id, turn_id=self.turn_id,
                           source_type=source, tool_call_id=call_id,
                           arguments_preview=redact(json.dumps(args, ensure_ascii=False)) if args is not None else "",
                           tool_call_executed=executed, result_exposed_to_llm=exposed)
        self.events.append(self.audit.append(event))

    async def call(self, name, args):
        self.calls += 1
        call_id = uid("call")
        pre = self.policy.check(name, args, self._trusted_request)
        if self.calls > 4:
            pre = SecurityDecision("pre_tool_call", "DENY", "high", ["P006"], "每轮最多四次工具调用，已停止。", tool_name=name)
        # Audit authorization before any side effect. Failure raises and prevents execution.
        self.record(pre, call_id=call_id, args=args)
        if pre.decision == "DENY":
            return ToolOutcome("操作被阻断，未实际执行。原因：" + pre.reason, pre)
        try:
            raw = await self.client.call_tool(name, args)
        except Exception:
            error = SecurityDecision("tool_execution", "ERROR", "high", ["E001"],
                                     "MCP 工具失败或超时，执行状态未知；未放行返回内容。", tool_name=name)
            self.record(error, call_id=call_id, args=args, executed=None)
            return ToolOutcome(error.reason, error, None)
        return self.process_result(raw, name, args, call_id)

    def process_result(self, raw, name, args, call_id):
        post, visible = self.detector.inspect(raw, name)
        exposed = post.decision in {"ALLOW", "SANITIZE"}
        self.record(post, call_id=call_id, args=args, executed=True, exposed=exposed, source="mcp_tool_result")
        return ToolOutcome(visible, post, True, exposed)
