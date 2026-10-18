import json
from safemcp.config import ROOT

DOCUMENTS = {
    "weekly": "weekly.md",
    "weekly_injected": "weekly_injected.md",
    "project": "project.md",
    "public": "public.md",
    "sensitive": "sensitive.md",
}
DOCUMENT_ROOT = ROOT / "fixtures" / "documents"
SAFE_RECIPIENTS = {"demo@local.test"}
DEMO_SECRET = "DEMO_SECRET_7F2A_NOT_REAL"


def load_samples():
    records = []
    for name in ("attacks", "benign"):
        path = ROOT / "fixtures" / f"{name}.json"
        if path.exists():
            records.extend(json.loads(path.read_text(encoding="utf-8")))
    return {s["id"]: s for s in records}


SAMPLES = load_samples()
DOCUMENT_IDS = set(DOCUMENTS) | set(SAMPLES)
