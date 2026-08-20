"""Task-manifest validation and deterministic combined benchmark manifest generation."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from security_eval.contracts import CONTRACT_VERSION, TaskId
from security_eval.errors import ContractError


class BenchmarkFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    cases: int = Field(ge=0)

    @field_validator("path")
    @classmethod
    def path_must_be_safe_and_relative(cls, value: str) -> str:
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("benchmark file paths must be safe and relative")
        return path.as_posix()


class TaskBenchmarkManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: str = CONTRACT_VERSION
    task_id: TaskId
    benchmark_version: str = Field(min_length=1)
    quick_cases: int = Field(ge=0)
    full_cases: int = Field(ge=0)
    files: list[BenchmarkFile] = Field(min_length=1)


class CombinedBenchmarkManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: str = CONTRACT_VERSION
    benchmark_version: str
    generated_at: datetime
    tasks: list[TaskBenchmarkManifest]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_task_manifest(path: Path, *, verify_hashes: bool = True) -> TaskBenchmarkManifest:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        manifest = TaskBenchmarkManifest.model_validate(raw)
    except FileNotFoundError as exc:
        raise ContractError(f"Benchmark manifest not found: {path}") from exc
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise ContractError(f"Invalid benchmark manifest: {path}") from exc
    if manifest.contract_version != CONTRACT_VERSION:
        raise ContractError(f"Unsupported benchmark contract version in {path}")
    if manifest.quick_cases > manifest.full_cases:
        raise ContractError(f"quick_cases cannot exceed full_cases in {path}")
    if verify_hashes:
        for entry in manifest.files:
            file_path = (path.parent / entry.path).resolve()
            try:
                file_path.relative_to(path.parent.resolve())
            except ValueError as exc:
                raise ContractError(f"Benchmark file escapes manifest directory: {entry.path}") from exc
            if not file_path.is_file():
                raise ContractError(f"Benchmark file not found: {entry.path}")
            if sha256_file(file_path) != entry.sha256:
                raise ContractError(f"Benchmark file hash mismatch: {entry.path}")
    return manifest


def build_combined_manifest(
    manifest_paths: Iterable[Path],
    *,
    benchmark_version: str = "v1",
    generated_at: datetime | None = None,
) -> CombinedBenchmarkManifest:
    tasks = [load_task_manifest(path) for path in manifest_paths]
    task_ids = [item.task_id for item in tasks]
    if len(task_ids) != len(set(task_ids)):
        raise ContractError("Combined benchmark contains duplicate task IDs")
    return CombinedBenchmarkManifest(
        benchmark_version=benchmark_version,
        generated_at=generated_at or datetime.now(timezone.utc),
        tasks=sorted(tasks, key=lambda item: item.task_id),
    )


def write_combined_manifest(manifest: CombinedBenchmarkManifest, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = manifest.model_dump(mode="json")
    rendered = yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
    temp_path = output_path.with_suffix(output_path.suffix + ".tmp")
    temp_path.write_text(rendered, encoding="utf-8")
    os.replace(temp_path, output_path)
