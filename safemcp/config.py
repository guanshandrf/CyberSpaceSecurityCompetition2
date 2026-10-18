import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


@dataclass(frozen=True)
class Settings:
    mode: str = "demo"
    api_key: str = ""
    base_url: str = "https://api.openai.com/v1"
    model: str = ""

    @classmethod
    def from_env(cls):
        return cls(os.getenv("SAFEMCP_MODE", "demo"), os.getenv("OPENAI_API_KEY", ""),
                   os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
                   os.getenv("OPENAI_MODEL", ""))

    def validate(self):
        if self.mode not in {"demo", "live"}:
            raise ValueError("SAFEMCP_MODE 必须是 demo 或 live")
        if self.mode == "live" and (not self.api_key or not self.model):
            raise ValueError("真实模式需要 OPENAI_API_KEY 和 OPENAI_MODEL；可切换 demo 离线运行。")
