from __future__ import annotations

import shutil

import pytest

from security_eval.core.benchmark import load_task_manifest
from security_eval.errors import ContractError
from security_eval.modules.task4.categories import dynamic_category
from security_eval.modules.task4.matrix import (
    DEFAULT_MANIFEST_PATH,
    DEFAULT_MATRIX_PATH,
    benchmark_cases,
    load_matrix,
    select_dynamic_cases,
)


def test_frozen_matrix_has_exact_quick_and_full_counts() -> None:
    matrix = load_matrix()
    quick = benchmark_cases(matrix, "quick")
    assert len(quick) == 16
    assert len(benchmark_cases(matrix, "full")) == 48
    assert {case.user_task_id for case in matrix.cases} == {
        "user_task_0",
        "user_task_18",
        "user_task_32",
    }
    assert {case.attack for case in matrix.cases} == {
        "none",
        "important_instructions",
        "tool_knowledge",
        "dos",
    }
    assert {case.attack for case in quick} == {
        "none",
        "important_instructions",
        "tool_knowledge",
        "dos",
    }
    assert sum(case.category == "multi_step_hijack" for case in quick) == 2


def test_manifest_hash_and_counts_validate() -> None:
    manifest = load_task_manifest(DEFAULT_MANIFEST_PATH)
    assert manifest.task_id == 4
    assert manifest.quick_cases == 16
    assert manifest.full_cases == 48


def test_runtime_loader_rejects_tampered_matrix(tmp_path) -> None:
    matrix_path = tmp_path / "matrix.yaml"
    manifest_path = tmp_path / "manifest.yaml"
    shutil.copyfile(DEFAULT_MATRIX_PATH, matrix_path)
    shutil.copyfile(DEFAULT_MANIFEST_PATH, manifest_path)
    original = matrix_path.read_text(encoding="utf-8")
    matrix_path.write_text(
        original.replace("Read-only calendar lookup", "Modified calendar lookup", 1),
        encoding="utf-8",
    )
    with pytest.raises(ContractError, match="SHA-256 mismatch"):
        load_matrix(matrix_path)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("task_id: 4", "task_id: 2"),
        ("benchmark_version: v1", "benchmark_version: v2"),
        ("quick_cases: 16", "quick_cases: 15"),
        ("full_cases: 48", "full_cases: 47"),
    ],
)
def test_runtime_loader_rejects_wrong_manifest_identity_or_counts(
    tmp_path, old, new
) -> None:
    matrix_path = tmp_path / "matrix.yaml"
    manifest_path = tmp_path / "manifest.yaml"
    shutil.copyfile(DEFAULT_MATRIX_PATH, matrix_path)
    manifest = DEFAULT_MANIFEST_PATH.read_text(encoding="utf-8").replace(old, new, 1)
    manifest_path.write_text(manifest, encoding="utf-8")
    with pytest.raises(ContractError, match="matrix or manifest is invalid"):
        load_matrix(matrix_path)


def test_benchmark_files_are_lf_normalized() -> None:
    attributes = DEFAULT_MATRIX_PATH.parent / ".gitattributes"
    rules = attributes.read_text(encoding="utf-8")
    assert "matrix.yaml text eol=lf" in rules
    assert "manifest.yaml text eol=lf" in rules
    assert b"\r\n" not in DEFAULT_MATRIX_PATH.read_bytes()


def test_dynamic_selection_is_seeded_and_defense_paired() -> None:
    matrix = load_matrix()
    kwargs = {
        "matrix": matrix,
        "profile": "quick",
        "seed": 91,
        "available_user_tasks": [
            "user_task_0",
            "user_task_2",
            "user_task_18",
            "user_task_32",
        ],
        "available_injection_tasks": [
            "injection_task_0",
            "injection_task_1",
            "injection_task_2",
            "injection_task_4",
        ],
    }
    first = select_dynamic_cases(**kwargs)
    second = select_dynamic_cases(**kwargs)
    assert first == second
    assert len(first) == 12
    for index in range(0, len(first), 2):
        assert first[index].defense == "none"
        assert first[index + 1].defense == "tool_filter"
        assert (
            first[index].case_id.rsplit("-", 1)[0]
            == first[index + 1].case_id.rsplit("-", 1)[0]
        )


def test_injection_task_3_is_consistently_context_leakage() -> None:
    assert dynamic_category("user_task_0", "injection_task_3") == "context_leakage"
    assert dynamic_category("user_task_18", "injection_task_3") == "context_leakage"
