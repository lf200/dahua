"""Loading and deterministic expansion of the task 4 benchmark matrix."""

from __future__ import annotations

import hashlib
import random
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

import yaml
from pydantic import ValidationError

from security_eval.errors import ContractError

from .categories import dynamic_category
from .models import MatrixCase, MatrixConfig, Task4BenchmarkManifest

DEFAULT_MATRIX_PATH = Path(__file__).resolve().parents[3] / "benchmarks" / "v1" / "task4" / "matrix.yaml"
DEFAULT_MANIFEST_PATH = DEFAULT_MATRIX_PATH.with_name("manifest.yaml")


def load_matrix(path: Path = DEFAULT_MATRIX_PATH, *, manifest_path: Path | None = None) -> MatrixConfig:
    """Load the frozen matrix only after validating its task manifest and hash."""

    manifest_path = manifest_path or path.with_name("manifest.yaml")
    try:
        matrix_bytes = path.read_bytes()
        raw = yaml.safe_load(matrix_bytes.decode("utf-8"))
        matrix = MatrixConfig.model_validate(raw)
        manifest_raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        manifest = Task4BenchmarkManifest.model_validate(manifest_raw)
    except FileNotFoundError as exc:
        raise ContractError(f"Task 4 benchmark file not found: {exc.filename}") from exc
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValidationError) as exc:
        raise ContractError("Task 4 benchmark matrix or manifest is invalid") from exc

    entry = manifest.files[0]
    matrix_file = (manifest_path.parent / entry.path).resolve()
    if matrix_file != path.resolve():
        raise ContractError("Task 4 manifest does not reference the selected matrix")
    if matrix.benchmark_version != manifest.benchmark_version:
        raise ContractError("Task 4 matrix and manifest benchmark versions differ")
    quick_count = sum(case.quick for case in matrix.cases)
    if quick_count != manifest.quick_cases or len(matrix.cases) != manifest.full_cases:
        raise ContractError("Task 4 matrix case counts do not match the manifest")
    digest = hashlib.sha256(matrix_bytes).hexdigest()
    if digest != entry.sha256:
        raise ContractError("Task 4 benchmark matrix SHA-256 mismatch")
    return matrix


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
            category = dynamic_category(user, injection)
            if allowed_categories and category not in allowed_categories:
                continue
            for attack in ("important_instructions", "tool_knowledge"):
                if (user, injection, attack) not in fixed_pairs:
                    candidates.append((user, injection, attack, category))
        if (
            not allowed_categories or "dos" in allowed_categories
        ) and (user, "injection_task_0", "dos") not in fixed_pairs:
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
