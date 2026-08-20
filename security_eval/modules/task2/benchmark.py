"""Load and validate the immutable task 2 JSONL benchmark."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from pydantic import ValidationError

from security_eval.errors import ContractError
from security_eval.modules.task2.models import TASK2_CATEGORIES, Task2Case

FULL_CASES = 90
QUICK_CASES = 12
CASES_PER_CATEGORY = 15
QUICK_PER_CATEGORY = 2


def load_all_cases(path: Path) -> list[Task2Case]:
    cases: list[Task2Case] = []
    seen: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ContractError(f"Task 2 benchmark is unavailable: {path.name}") from exc

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
            case = Task2Case.model_validate(raw)
        except (json.JSONDecodeError, ValidationError, TypeError) as exc:
            raise ContractError(
                f"Invalid task 2 benchmark record at line {line_number}"
            ) from exc
        if case.case_id in seen:
            raise ContractError(f"Duplicate task 2 case_id: {case.case_id}")
        seen.add(case.case_id)
        cases.append(case)

    counts = Counter(case.category for case in cases)
    if len(cases) != FULL_CASES or counts != {
        category: CASES_PER_CATEGORY for category in TASK2_CATEGORIES
    }:
        raise ContractError(
            "Task 2 benchmark must contain 15 cases in each of six categories"
        )
    quick_counts = Counter(case.category for case in cases if case.quick)
    if sum(quick_counts.values()) != QUICK_CASES or quick_counts != {
        category: QUICK_PER_CATEGORY for category in TASK2_CATEGORIES
    }:
        raise ContractError(
            "Task 2 quick benchmark must contain two cases per category"
        )
    return cases


def select_quick_cases(cases: list[Task2Case]) -> list[Task2Case]:
    return [case for case in cases if case.quick]


def load_cases(path: Path, profile: str) -> list[Task2Case]:
    cases = load_all_cases(path)
    if profile == "full":
        return cases
    if profile == "quick":
        return select_quick_cases(cases)
    raise ContractError("Unsupported task 2 benchmark profile")
