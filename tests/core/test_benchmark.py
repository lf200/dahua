from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest
import yaml

from security_eval.core.benchmark import build_combined_manifest, load_task_manifest, write_combined_manifest
from security_eval.errors import ContractError


def write_task_manifest(root, task_id: int):
    task_dir = root / f"task{task_id}"
    task_dir.mkdir()
    cases = task_dir / "cases.jsonl"
    cases.write_text('{"case_id":"one"}\n', encoding="utf-8")
    digest = hashlib.sha256(cases.read_bytes()).hexdigest()
    manifest = {
        "contract_version": "1.0",
        "task_id": task_id,
        "benchmark_version": "v1",
        "quick_cases": 1,
        "full_cases": 1,
        "files": [{"path": "cases.jsonl", "sha256": digest, "cases": 1}],
    }
    path = task_dir / "manifest.yaml"
    path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    return path, cases


def test_combined_manifest_sorts_tasks_and_writes_atomically(tmp_path) -> None:
    task4, _ = write_task_manifest(tmp_path, 4)
    task1, _ = write_task_manifest(tmp_path, 1)
    manifest = build_combined_manifest(
        [task4, task1],
        generated_at=datetime(2026, 8, 20, tzinfo=timezone.utc),
    )
    assert [task.task_id for task in manifest.tasks] == [1, 4]
    output = tmp_path / "manifest.yaml"
    write_combined_manifest(manifest, output)
    assert output.exists()
    assert not output.with_suffix(".yaml.tmp").exists()


def test_hash_mismatch_is_rejected(tmp_path) -> None:
    path, cases = write_task_manifest(tmp_path, 1)
    cases.write_text("changed", encoding="utf-8")
    with pytest.raises(ContractError, match="hash mismatch"):
        load_task_manifest(path)
