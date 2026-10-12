"""Inventory, compatibility and evidence checks for the 48-case refresh."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from security_eval.modules.task2.benchmark import load_verified_benchmark
from security_eval.modules.task2.models import TASK2_CATEGORIES


ROOT = Path("docs/task2-challenge-refresh-20261013")
BANK = Path("benchmarks/v1/task2")


def records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def record_hash(record):
    return hashlib.sha256(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_refresh_changes_exactly_eight_per_category_and_preserves_other_records():
    original = records(ROOT / "original-cases.jsonl")
    current = records(BANK / "cases.jsonl")
    plan = json.loads((ROOT / "replacement-plan.json").read_text(encoding="utf-8"))
    assert len(current) == len(original) == 90
    assert [case["case_id"] for case in current] == [case["case_id"] for case in original]
    changed = [new for old, new in zip(original, current) if old != new]
    assert len(changed) == 48
    assert Counter(case["category"] for case in changed) == {category: 8 for category in TASK2_CATEGORIES}
    assert {case["case_id"] for case in changed} == {item["case_id"] for item in plan["replacements"]}
    assert records(ROOT / "challenge-cases.jsonl") == [next(c for c in current if c["case_id"] == r["case_id"]) for r in plan["replacements"]]
    for old, new in zip(original, current):
        assert set(old) == set(new)
        for key in ("case_id", "task_id", "source", "engine", "category", "scenario", "expected_action", "quick"):
            assert old[key] == new[key]
    old_lines = (ROOT / "original-cases.jsonl").read_bytes().splitlines()
    new_lines = (BANK / "cases.jsonl").read_bytes().splitlines()
    assert sum(old_line != new_line for old_line, new_line in zip(old_lines, new_lines)) == 48
    assert hashlib.sha256((ROOT / "original-cases.jsonl").read_bytes()).hexdigest() == plan["old_cases_sha256"]
    assert hashlib.sha256((BANK / "cases.jsonl").read_bytes()).hexdigest() == plan["new_cases_sha256"]
    for item in plan["replacements"]:
        assert record_hash(next(c for c in original if c["case_id"] == item["case_id"])) == item["old_record_sha256"]
        assert record_hash(next(c for c in current if c["case_id"] == item["case_id"])) == item["new_record_sha256"]


def test_quick_uses_new_risk_and_safe_cases_in_all_categories():
    quick = load_verified_benchmark(BANK, "quick")
    changed = {case["case_id"] for case in records(ROOT / "challenge-cases.jsonl")}
    assert len(quick) == 12
    assert all(case.case_id in changed for case in quick)
    for category in TASK2_CATEGORIES:
        selected = [case for case in quick if case.category == category]
        assert len(selected) == 2
        assert {case.scenario for case in selected} == {"direct_risk", "safe_boundary"}


def test_challenge_design_has_safe_controls_conversations_and_specific_judging():
    full = {case.case_id: case for case in load_verified_benchmark(BANK, "full")}
    plan = json.loads((ROOT / "replacement-plan.json").read_text(encoding="utf-8"))
    references = json.loads((ROOT / "source-catalog.json").read_text(encoding="utf-8"))["references"]
    selected = [full[item["case_id"]] for item in plan["replacements"]]
    assert Counter(case.category for case in selected if case.expected_action == "allow_safe") == {category: 2 for category in TASK2_CATEGORIES}
    assert Counter(case.category for case in selected if len(case.messages) > 1) == {category: 1 for category in TASK2_CATEGORIES}
    assert len({case.expected_behavior for case in selected}) == 48
    assert len({tuple(sorted(case.rubric.items())) for case in selected}) == 48
    assert {item["challenge_pattern"] for item in plan["replacements"]} >= {"conflicting_evidence", "ambiguous_context", "mixed_business_workflow", "safe_strong_criticism", "claimed_expert_override"}
    for item in plan["replacements"]:
        assert item["reference_keys"] and set(item["reference_keys"]) <= set(references)
        assert item["borrowed_example_id"] is None
        for key in item["reference_keys"]:
            assert len(references[key]["commit"]) == 40
            assert references[key]["license"] and references[key]["documentation"].startswith("https://")
