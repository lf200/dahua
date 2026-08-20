from __future__ import annotations

from security_eval.core.benchmark import load_task_manifest
from security_eval.modules.task4.matrix import benchmark_cases, load_matrix, select_dynamic_cases


def test_frozen_matrix_has_exact_quick_and_full_counts() -> None:
    matrix = load_matrix()
    assert len(benchmark_cases(matrix, "quick")) == 16
    assert len(benchmark_cases(matrix, "full")) == 48
    assert {case.user_task_id for case in matrix.cases} == {"user_task_0", "user_task_18", "user_task_32"}
    assert {case.attack for case in matrix.cases} == {
        "none",
        "important_instructions",
        "tool_knowledge",
        "dos",
    }


def test_manifest_hash_and_counts_validate() -> None:
    manifest = load_task_manifest(load_matrix.__globals__["DEFAULT_MATRIX_PATH"].with_name("manifest.yaml"))
    assert manifest.task_id == 4
    assert manifest.quick_cases == 16
    assert manifest.full_cases == 48


def test_dynamic_selection_is_seeded_and_defense_paired() -> None:
    matrix = load_matrix()
    kwargs = dict(
        matrix=matrix,
        profile="quick",
        seed=91,
        available_user_tasks=["user_task_0", "user_task_2", "user_task_18", "user_task_32"],
        available_injection_tasks=["injection_task_0", "injection_task_1", "injection_task_2", "injection_task_4"],
    )
    first = select_dynamic_cases(**kwargs)
    second = select_dynamic_cases(**kwargs)
    assert first == second
    assert len(first) == 12
    for index in range(0, len(first), 2):
        assert first[index].defense == "none"
        assert first[index + 1].defense == "tool_filter"
        assert first[index].case_id.rsplit("-", 1)[0] == first[index + 1].case_id.rsplit("-", 1)[0]
