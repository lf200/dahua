from __future__ import annotations

import json
from pathlib import Path

from security_eval.contracts import EvaluationModule, TaskResult
from security_eval.core.registry import ModuleRegistry, load_module_manifest
from security_eval.modules.task1.module import Task1Module


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_MANIFEST = REPO_ROOT / "security_eval" / "modules" / "task1" / "module.json"
CONTRACT_FIXTURE = REPO_ROOT / "tests" / "contract_fixtures" / "task_1_result.json"


def test_module_manifest_loads_task1_without_importing_optional_deepteam() -> None:
    manifest = load_module_manifest(MODULE_MANIFEST)
    registry = ModuleRegistry.from_manifests([MODULE_MANIFEST])

    assert manifest.model_dump(mode="json", exclude={"supported_modes", "supported_profiles"}) == {
        "task_id": 1,
        "import_path": "security_eval.modules.task1.module",
        "class_name": "Task1Module",
        "module_version": "1.0.0",
        "benchmark_version": "v1",
        "contract_version": "1.0",
        "dependency_file": "requirements/task1.in",
    }
    assert manifest.supported_modes == {"benchmark", "dynamic", "hybrid"}
    assert manifest.supported_profiles == {"full", "quick"}
    module = registry.get(1)
    assert isinstance(module, Task1Module)
    assert isinstance(module, EvaluationModule)


def test_contract_fixture_contains_pass_fail_and_invalid_cases() -> None:
    result = TaskResult.model_validate(json.loads(CONTRACT_FIXTURE.read_text(encoding="utf-8")))

    assert result.task_id == 1
    assert {case.status for case in result.cases} == {"passed", "failed", "invalid"}
    assert result.benchmark_score is not None
    assert result.dynamic_score is not None
    assert result.contract_version == "1.0"


def test_task1_dependency_file_pins_verified_dynamic_stack() -> None:
    dependency_file = (REPO_ROOT / "requirements" / "task1.in").read_text(encoding="utf-8").splitlines()

    requirements = [line.strip() for line in dependency_file if line.strip() and not line.startswith("#")]
    assert requirements == [
        "deepteam==1.0.7",
        "deepeval==4.1.8",
        "pydantic-settings==2.14.2",
        "sentry-sdk==2.66.1",
    ]
