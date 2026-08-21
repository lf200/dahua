"""Load and validate the immutable task 2 JSONL benchmark."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from security_eval.errors import ContractError
from security_eval.modules.task2.models import TASK2_CATEGORIES, Task2Case

FULL_CASES = 90
QUICK_CASES = 12
CASES_PER_CATEGORY = 15
QUICK_PER_CATEGORY = 2
CONTRACT_VERSION = "1.0"
BENCHMARK_VERSION = "v1"
EXPECTED_MANIFEST_FILES = {
    "cases.jsonl": 90,
    "labels.yaml": 6,
}


class _ManifestFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    cases: int = Field(ge=0)


class _Task2Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: str
    task_id: int
    benchmark_version: str
    quick_cases: int = Field(ge=0)
    full_cases: int = Field(ge=0)
    files: list[_ManifestFile] = Field(min_length=1)


def load_all_cases(path: Path) -> list[Task2Case]:
    cases: list[Task2Case] = []
    seen: set[str] = set()
    seen_prompts: set[tuple[tuple[str, str], ...]] = set()
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
        if case.source != "benchmark" or case.engine != "benchmark":
            raise ContractError(
                "Static task 2 benchmark cases must use benchmark source and engine"
            )
        if case.case_id in seen:
            raise ContractError(f"Duplicate task 2 case_id: {case.case_id}")
        prompt_key = tuple(
            (message["role"], " ".join(message["content"].split()).casefold())
            for message in case.messages
        )
        if prompt_key in seen_prompts:
            raise ContractError("Duplicate task 2 benchmark prompt")
        seen.add(case.case_id)
        seen_prompts.add(prompt_key)
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


def load_verified_benchmark(root: Path, profile: str) -> list[Task2Case]:
    root = root.resolve()
    manifest_path = root / "manifest.yaml"
    try:
        raw_manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        manifest = _Task2Manifest.model_validate(raw_manifest)
    except FileNotFoundError as exc:
        raise ContractError("Task 2 benchmark manifest is unavailable") from exc
    except (OSError, yaml.YAMLError, ValidationError, TypeError) as exc:
        raise ContractError("Task 2 benchmark manifest is invalid") from exc

    if manifest.contract_version != CONTRACT_VERSION:
        raise ContractError("Task 2 manifest contract_version must be 1.0")
    if manifest.task_id != 2:
        raise ContractError("Task 2 manifest task_id must be 2")
    if manifest.benchmark_version != BENCHMARK_VERSION:
        raise ContractError("Task 2 manifest benchmark_version must be v1")
    if manifest.quick_cases != QUICK_CASES:
        raise ContractError("Task 2 manifest quick_cases must be 12")
    if manifest.full_cases != FULL_CASES:
        raise ContractError("Task 2 manifest full_cases must be 90")

    entries = {entry.path: entry for entry in manifest.files}
    if (
        len(entries) != len(manifest.files)
        or {path: entry.cases for path, entry in entries.items()}
        != EXPECTED_MANIFEST_FILES
    ):
        raise ContractError("Task 2 manifest file list is invalid")

    for relative_path, entry in entries.items():
        file_path = root / relative_path
        try:
            digest = _sha256_file(file_path)
        except OSError as exc:
            raise ContractError(
                f"Task 2 benchmark file is unavailable: {relative_path}"
            ) from exc
        if digest != entry.sha256:
            raise ContractError(f"Task 2 benchmark file hash mismatch: {relative_path}")

    cases = load_all_cases(root / "cases.jsonl")
    if len(cases) != manifest.full_cases:
        raise ContractError("Task 2 JSONL count does not match manifest full_cases")
    selected = cases if profile == "full" else select_quick_cases(cases)
    if profile not in {"quick", "full"}:
        raise ContractError("Unsupported task 2 benchmark profile")
    expected_count = manifest.full_cases if profile == "full" else manifest.quick_cases
    if len(selected) != expected_count:
        raise ContractError("Task 2 selected case count does not match manifest")
    return selected


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
