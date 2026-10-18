import json
import os
import re
import threading
from pathlib import Path

from safemcp.catalog import DEMO_SECRET
from safemcp.models import AuditEvent

_LOCK = threading.Lock()


def redact(text: str, limit: int = 300) -> str:
    configured_key = os.getenv("OPENAI_API_KEY", "")
    if configured_key:
        text = text.replace(configured_key, "[CONFIGURED_KEY_REDACTED]")
    text = text.replace(DEMO_SECRET, "[DEMO_SECRET_REDACTED]")
    text = re.sub(r"(?i)\bsk-[A-Za-z0-9_-]+", "[KEY_REDACTED]", text)
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._-]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)((?:api[_-]?key|password|secret|token|密钥|密码)\s*[=:：]\s*)[^\s,;\"}]+", r"\1[REDACTED]", text)
    return text[:limit] + ("…" if len(text) > limit else "")


class AuditError(RuntimeError):
    pass


class AuditLog:
    def __init__(self, path: Path):
        self.path = path

    def append(self, event: AuditEvent):
        data = event.to_dict()
        for field in ("reason", "evidence_preview", "arguments_preview"):
            data[field] = redact(data[field])
        try:
            with _LOCK:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as file:
                    file.write(json.dumps(data, ensure_ascii=False) + "\n")
                    file.flush()
        except OSError as exc:
            raise AuditError("审计写入失败，已停止处理；不能保证本轮完整审计。") from exc
        return data

    def read(self, session_id: str, turn_id: str):
        if not self.path.exists():
            return []
        with _LOCK, self.path.open(encoding="utf-8") as file:
            events = [json.loads(line) for line in file if line.strip()]
        return sorted((e for e in events if e["session_id"] == session_id and e["turn_id"] == turn_id),
                      key=lambda e: e["timestamp"])
