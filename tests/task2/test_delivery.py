from __future__ import annotations

import json
from pathlib import Path

from security_eval.contracts import TaskResult
from security_eval.core.benchmark import load_task_manifest
from security_eval.core.registry import ModuleRegistry, load_module_manifest


TASK_ROOT = Path("benchmarks/v1/task2")
MODULE_ROOT = Path("security_eval/modules/task2")


def test_benchmark_manifest_verifies_hashes_and_90_case_scope() -> None:
    manifest = load_task_manifest(TASK_ROOT / "manifest.yaml")

    assert manifest.task_id == 2
    assert manifest.contract_version == "1.0"
    assert manifest.benchmark_version == "v1"
    assert manifest.quick_cases == 12
    assert manifest.full_cases == 90
    assert {item.path for item in manifest.files} == {
        "ATTRIBUTION.md",
        "cases.jsonl",
        "labels.yaml",
    }
    assert (
        next(item.cases for item in manifest.files if item.path == "cases.jsonl") == 90
    )


def test_benchmark_attribution_is_revision_pinned_and_documents_changes() -> None:
    attribution = (TASK_ROOT / "ATTRIBUTION.md").read_text(encoding="utf-8")

    assert "d21a325e276a99bd69b1fbb8aa51a9f249486b72" in attribution
    assert "d7bb5bd738c1fcbc36edd83d5e7d1b71a3e2d84d" in attribution
    assert "Apache License 2.0" in attribution
    assert "Creative Commons Attribution 4.0" in attribution
    assert "SALAD-Bench" in attribution
    assert "XSTest" in attribution
    assert "modified" in attribution.lower()


def test_module_manifest_matches_registry_loaded_module() -> None:
    path = MODULE_ROOT / "module.json"
    manifest = load_module_manifest(path)
    registry = ModuleRegistry.from_manifests([path])
    module = registry.get(2)

    assert manifest.task_id == 2
    assert manifest.import_path == "security_eval.modules.task2.module"
    assert manifest.class_name == "Task2Module"
    assert manifest.dependency_file == "requirements/task2.in"
    assert module.metadata().module_version == manifest.module_version
    assert module.metadata().benchmark_version == manifest.benchmark_version


def test_task_dependency_is_owned_and_exactly_pinned() -> None:
    lines = [
        line.strip()
        for line in Path("requirements/task2.in")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert lines == ["deepteam==1.0.7"]


def test_contract_fixture_loads_and_covers_required_presentation_states() -> None:
    path = Path("tests/contract_fixtures/task_2_result.json")
    result = TaskResult.model_validate_json(path.read_text(encoding="utf-8"))

    assert result.task_id == 2
    assert result.contract_version == "1.0"
    fixture_kinds = {case.metadata.get("fixture_kind"): case for case in result.cases}
    assert set(fixture_kinds) == {
        "compliant_refusal",
        "unsafe_answer",
        "over_refusal",
        "invalid",
    }
    assert fixture_kinds["compliant_refusal"].status == "passed"
    assert fixture_kinds["unsafe_answer"].status == "failed"
    assert fixture_kinds["over_refusal"].status == "failed"
    assert fixture_kinds["over_refusal"].metadata["over_refusal"] is True
    assert fixture_kinds["invalid"].status == "invalid"
    assert fixture_kinds["invalid"].error is not None
    assert fixture_kinds["invalid"].error.code == "PARSE_ERROR"
    serialized = json.dumps(result.model_dump(mode="json"), ensure_ascii=False)
    assert "sk-" not in serialized
    assert "Bearer " not in serialized
