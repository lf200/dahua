"""Immutable benchmark loading and validation for task 1."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from security_eval.contracts import Profile
from security_eval.core.benchmark import load_task_manifest
from security_eval.errors import ContractError

CATEGORIES = (
    "prompt_injection",
    "indirect_instruction",
    "role_jailbreak",
    "logic_trap",
    "context_hijack",
)
CASES_PER_CATEGORY = 16
QUICK_CASES_PER_CATEGORY = 2
FULL_CASES = len(CATEGORIES) * CASES_PER_CATEGORY
QUICK_CASES = len(CATEGORIES) * QUICK_CASES_PER_CATEGORY
Category = Literal[
    "prompt_injection",
    "indirect_instruction",
    "role_jailbreak",
    "logic_trap",
    "context_hijack",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BenchmarkMessage(StrictModel):
    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1, max_length=5000)


class Task1Rubric(StrictModel):
    recognition: str = Field(min_length=1, max_length=1000)
    blocking: str = Field(min_length=1, max_length=1000)
    recovery: str = Field(min_length=1, max_length=1000)


class BenchmarkCase(StrictModel):
    case_id: str = Field(pattern=r"^t1-[a-z0-9-]+$", max_length=100)
    task_id: Literal[1]
    category: Category
    scenario: str = Field(min_length=1, max_length=1000)
    messages: list[BenchmarkMessage] = Field(min_length=1, max_length=10)
    expected_behavior: list[str] = Field(min_length=1)
    forbidden_outcomes: list[str] = Field(min_length=1)
    recovery_probe: str = Field(min_length=1, max_length=1000)
    rubric: Task1Rubric
    severity: Literal["low", "medium", "high", "critical"]
    tags: list[str] = Field(default_factory=list)
    quick: bool = False


class CategoryLabels(StrictModel):
    safe: str = Field(min_length=1, max_length=3000)
    unsafe: str = Field(min_length=1, max_length=3000)


class Task1Labels(StrictModel):
    categories: dict[Category, CategoryLabels]


class LoadedBenchmark(StrictModel):
    benchmark_version: str
    cases: list[BenchmarkCase]
    labels: Task1Labels


def _load_cases(path: Path) -> list[BenchmarkCase]:
    cases: list[BenchmarkCase] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ContractError(f"Cannot read task 1 benchmark cases: {path}") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            cases.append(BenchmarkCase.model_validate_json(line))
        except ValidationError as exc:
            raise ContractError(
                f"Invalid task 1 benchmark case at line {line_number}"
            ) from exc
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ContractError("Task 1 benchmark contains duplicate case_id values")
    return cases


def _load_labels(path: Path) -> Task1Labels:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        labels = Task1Labels.model_validate(raw)
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise ContractError("Invalid task 1 benchmark labels") from exc
    if set(labels.categories) != set(CATEGORIES):
        raise ContractError("Task 1 labels must cover every benchmark category")
    return labels


def _validate_complete(cases: list[BenchmarkCase]) -> None:
    if len(cases) != FULL_CASES:
        raise ContractError(
            f"Task 1 full benchmark must contain exactly {FULL_CASES} cases"
        )
    for category in CATEGORIES:
        category_cases = [case for case in cases if case.category == category]
        if len(category_cases) != CASES_PER_CATEGORY:
            raise ContractError(
                f"Task 1 category {category} must contain exactly "
                f"{CASES_PER_CATEGORY} cases"
            )
        if sum(case.quick for case in category_cases) != QUICK_CASES_PER_CATEGORY:
            raise ContractError(
                f"Task 1 category {category} must contain exactly "
                f"{QUICK_CASES_PER_CATEGORY} quick cases"
            )


def load_benchmark(
    root: Path,
    profile: Profile,
    *,
    require_complete: bool = True,
) -> LoadedBenchmark:
    """Load a hash-verified benchmark and select its stable profile subset."""

    manifest = load_task_manifest(root / "manifest.yaml")
    if manifest.task_id != 1:
        raise ContractError("Task 1 benchmark manifest has the wrong task_id")
    entries = {entry.path: entry for entry in manifest.files}
    if set(entries) != {"cases.jsonl", "labels.yaml"}:
        raise ContractError(
            "Task 1 benchmark manifest must list cases.jsonl and labels.yaml"
        )

    cases = _load_cases(root / "cases.jsonl")
    labels = _load_labels(root / "labels.yaml")
    if entries["cases.jsonl"].cases != len(cases):
        raise ContractError("Task 1 manifest case count does not match cases.jsonl")
    if require_complete:
        _validate_complete(cases)
        if manifest.full_cases != FULL_CASES or manifest.quick_cases != QUICK_CASES:
            raise ContractError(
                f"Task 1 manifest profile counts must be quick={QUICK_CASES} "
                f"and full={FULL_CASES}"
            )

    selected = cases if profile == "full" else [case for case in cases if case.quick]
    return LoadedBenchmark(
        benchmark_version=manifest.benchmark_version,
        cases=selected,
        labels=labels,
    )
