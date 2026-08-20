"""Loading and deterministic expansion of the task 4 benchmark matrix."""

from __future__ import annotations

import random
from collections import defaultdict
from pathlib import Path
from typing import Iterable

import yaml
from pydantic import ValidationError

from security_eval.errors import ContractError

from .models import MatrixCase, MatrixConfig

DEFAULT_MATRIX_PATH = Path(__file__).resolve().parents[3] / "benchmarks" / "v1" / "task4" / "matrix.yaml"


def load_matrix(path: Path = DEFAULT_MATRIX_PATH) -> MatrixConfig:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return MatrixConfig.model_validate(raw)
    except FileNotFoundError as exc:
        raise ContractError(f"Task 4 matrix not found: {path}") from exc
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise ContractError("Task 4 benchmark matrix is invalid") from exc


def benchmark_cases(matrix: MatrixConfig, profile: str) -> list[MatrixCase]:
    if profile == "quick":
        return [case for case in matrix.cases if case.quick]
    return list(matrix.cases)


def select_dynamic_cases(
    matrix: MatrixConfig,
    *,
    profile: str,
    seed: int,
    categories: Iterable[str] | None = None,
    available_user_tasks: Iterable[str] | None = None,
    available_injection_tasks: Iterable[str] | None = None,
) -> list[MatrixCase]:
    """Select defense-paired combinations not present in the frozen matrix."""

    fixed_pairs = {
        (case.user_task_id, case.injection_task_id, case.attack)
        for case in matrix.cases
        if case.attack != "none"
    }
    users = sorted(set(available_user_tasks or [f"user_task_{i}" for i in range(36)]))
    injections = sorted(set(available_injection_tasks or [f"injection_task_{i}" for i in range(14)]))
    allowed_categories = set(categories or ())
    candidates: list[tuple[str, str, str, str]] = []
    for user in users:
        for injection in injections:
            category = _dynamic_category(user, injection)
            if allowed_categories and category not in allowed_categories:
                continue
            for attack in ("important_instructions", "tool_knowledge"):
                if (user, injection, attack) not in fixed_pairs:
                    candidates.append((user, injection, attack, category))
        if not allowed_categories or "dos" in allowed_categories:
            if (user, "injection_task_0", "dos") not in fixed_pairs:
                candidates.append((user, "injection_task_0", "dos", "dos"))

    pair_limit = matrix.dynamic_limits[profile] // 2
    rng = random.Random(seed)
    buckets: dict[str, list[tuple[str, str, str, str]]] = defaultdict(list)
    for candidate in candidates:
        buckets[candidate[3]].append(candidate)
    for bucket in buckets.values():
        rng.shuffle(bucket)
    selected: list[tuple[str, str, str, str]] = []
    category_order = sorted(buckets)
    while len(selected) < pair_limit and category_order:
        next_order: list[str] = []
        for category in category_order:
            if len(selected) >= pair_limit:
                break
            bucket = buckets[category]
            if bucket:
                selected.append(bucket.pop())
            if bucket:
                next_order.append(category)
        category_order = next_order
    cases: list[MatrixCase] = []
    for index, (user, injection, attack, category) in enumerate(selected):
        for defense in ("none", "tool_filter"):
            cases.append(
                MatrixCase(
                    case_id=f"t4-dyn-{index:02d}-{user}-{injection}-{attack}-{defense}",
                    user_task_id=user,
                    injection_task_id=injection,
                    attack=attack,
                    defense=defense,
                    category=category,
                    scenario=f"Seeded dynamic {attack} attack with {defense} defense",
                )
            )
    return cases


def _dynamic_category(user_task_id: str, injection_task_id: str) -> str:
    injection_number = int(injection_task_id.rsplit("_", 1)[1])
    user_number = int(user_task_id.rsplit("_", 1)[1])
    if injection_number in {4, 5, 6, 7, 10, 11, 12}:
        return "context_leakage"
    if injection_number in {1, 8, 9}:
        return "privilege_escalation"
    if user_number in {13, 18, 20, 21, 25, 32, 33, 34}:
        return "multi_step_hijack"
    return "api_abuse"
