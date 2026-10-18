import asyncio
import json
import time
from pathlib import Path

from safemcp.audit import AuditError, AuditLog, redact
from safemcp.config import ROOT, Settings
from safemcp.gateway import SecurityGateway
from safemcp.llm_provider import DemoProvider, LiveProvider
from safemcp.mcp_client import MCPClient
from safemcp.models import SecurityDecision, TurnResult, uid


def model_tools(tools):
    return [{"type": "function", "function": {"name": t.name, "description": t.description or "",
             "parameters": {**t.input_schema, "additionalProperties": False}}} for t in tools]


async def run_turn(user_text: str, session_id: str, *, history=None, scene="normal", settings=None,
                   runtime_dir: Path | None = None, provider=None):
    started = time.perf_counter()
    turn_id = uid("turn")
    runtime_dir = runtime_dir or ROOT / "runtime"
    audit = AuditLog(runtime_dir / "audit.jsonl")
    settings = settings or Settings.from_env()
    gw = SecurityGateway(None, audit, session_id, turn_id, user_text)
    answer, status = "", "SAFE"
    owned_provider = provider is None
    mode = settings.mode if provider is None else provider.mode
    try:
        settings.validate()
        provider = provider or (DemoProvider() if settings.mode == "demo" else LiveProvider(settings))
        # Tool messages are never persisted as user/system messages in multi-turn history.
        messages = [{"role": m["role"], "content": m["content"]} for m in (history or [])[-12:]
                    if m.get("role") in {"user", "assistant"} and isinstance(m.get("content"), str)]
        messages.append({"role": "user", "content": user_text})
        gw.record(SecurityDecision("turn_start", "INFO", reason="用户任务：" + redact(user_text)))
        async with asyncio.timeout(90):
            async with MCPClient(runtime_dir).connect() as client:
                gw.client = client
                tools = model_tools(await client.list_tools())
                for _ in range(5):
                    reply = await provider.next(messages, tools, scene)
                    if not reply.calls:
                        answer = reply.content or "模型未返回文本。"
                        break
                    messages.append({"role": "assistant", "content": reply.content or None, "tool_calls": [
                        {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": json.dumps(c.arguments, ensure_ascii=False)}} for c in reply.calls]})
                    stopped = False
                    for call in reply.calls:
                        outcome = await gw.call(call.name, call.arguments)
                        messages.append({"role": "tool", "tool_call_id": call.id, "content": outcome.text})
                        if outcome.decision.decision in {"DENY", "BLOCK_RESULT", "ERROR"}:
                            answer = outcome.text
                            stopped = True
                            break
                    if stopped:
                        break
                if not answer:
                    answer = "已达到每轮工具调用上限，停止继续调用。"
    except AuditError as exc:
        answer, status = str(exc), "ERROR"
    except Exception:
        answer, status = ("运行失败：请检查 MCP 环境或真实模型的 Key、模型名、网络与工具调用支持；未自动伪装为演示成功。", "ERROR")
    finally:
        if owned_provider and provider is not None and hasattr(provider, "close"):
            try:
                await provider.close()
            except Exception:
                answer, status = "模型连接清理失败；请重试，本轮不报告处理成功。", "ERROR"
    if status != "ERROR":
        choices = {e["decision"] for e in gw.events}
        status = "ERROR" if "ERROR" in choices else "BLOCKED" if choices & {"DENY", "BLOCK_RESULT"} else "SANITIZED" if "SANITIZE" in choices else "SAFE"
    final_reason = f"最终状态 {status}。" + ("本轮未调用 MCP 工具。" if gw.calls == 0 else f"本轮提出 {gw.calls} 次工具调用。")
    try:
        gw.record(SecurityDecision("turn_end", status, reason=final_reason))
    except AuditError as exc:
        status, answer = "ERROR", str(exc)
    return TurnResult(session_id, turn_id, answer, status, mode, (time.perf_counter() - started) * 1000, gw.events)


def chat(user_text, session_id, **kwargs):
    return asyncio.run(run_turn(user_text, session_id, **kwargs))
