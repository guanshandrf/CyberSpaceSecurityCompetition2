import json
from collections import Counter

from safemcp.catalog import load_samples, DEMO_SECRET
from scripts.run_experiments import run_experiments, outbox_records


def test_dataset_is_reviewable():
    samples = list(load_samples().values())
    assert len(samples) == 100
    attacks = [s for s in samples if s["label"] == "malicious"]
    benign = [s for s in samples if s["label"] == "benign"]
    assert len(attacks) == 60 and len(benign) == 40
    assert sorted(Counter(s["category"] for s in attacks).values()) == [15] * 4
    assert sum(s["category"] == "quoted_security_teaching" for s in benign) >= 10
    assert all({"id", "label", "category", "user_task", "tool_name", "tool_result_text", "expected_behavior"} <= s.keys() for s in samples)
    assert len({s["tool_result_text"] for s in samples}) == 100


def test_real_three_group_experiment(tmp_path):
    rows, metrics, directory = run_experiments(output=tmp_path)
    assert len(rows) == 300
    groups = metrics.set_index("mode")
    assert groups.loc["A", "unsafe_tool_executed"] > groups.loc["B", "unsafe_tool_executed"] > groups.loc["C", "unsafe_tool_executed"] == 0
    assert groups.loc["C", "unsafe_tool_attempted"] > 0  # permission boundary catches detector misses
    for mode in ("A", "B", "C"):
        writes = outbox_records(directory / mode / "outbox.jsonl")
        assert len(writes) == sum(r["outbox_delta"] for r in rows if r["mode"] == mode)
        assert all(DEMO_SECRET in w["content"] for w in writes)
        audit_text = (directory / mode / "audit.jsonl").read_text(encoding="utf-8")
        assert DEMO_SECRET not in audit_text
        events = [json.loads(line) for line in audit_text.splitlines()]
        denied_call_ids = {e["tool_call_id"] for e in events if e["decision"] == "DENY"}
        assert not any(e["tool_call_id"] in denied_call_ids and e["tool_call_executed"] for e in events)
    assert all((tmp_path / name).exists() for name in ("metrics.csv", "comparison.png", "sample_results.csv", "experiment_report.md"))
    assert "不是对真实 LLM" in (tmp_path / "experiment_report.md").read_text(encoding="utf-8")
