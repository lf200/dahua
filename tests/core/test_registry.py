from __future__ import annotations

import json

import pytest

from security_eval.core.registry import ModuleRegistry
from security_eval.errors import ContractError
from tests.fakes.fake_module import FakeTask1Module


def manifest(task_id: int = 1, contract_version: str = "1.0") -> dict:
    return {
        "task_id": task_id,
        "import_path": "tests.fakes.fake_module",
        "class_name": "FakeTask1Module",
        "module_version": "fake-1.0",
        "benchmark_version": "v1",
        "contract_version": contract_version,
        "dependency_file": "requirements/task1.in",
        "supported_modes": ["benchmark", "dynamic", "hybrid"],
        "supported_profiles": ["quick", "full"],
    }


def test_registry_loads_manifest(tmp_path) -> None:
    path = tmp_path / "module.json"
    path.write_text(json.dumps(manifest()), encoding="utf-8")
    registry = ModuleRegistry.from_manifests([path])
    assert registry.tasks() == (1,)
    assert isinstance(registry.get(1), FakeTask1Module)


def test_registry_rejects_contract_version(tmp_path) -> None:
    path = tmp_path / "module.json"
    path.write_text(json.dumps(manifest(contract_version="2.0")), encoding="utf-8")
    with pytest.raises(ContractError, match="Unsupported contract version"):
        ModuleRegistry.from_manifests([path])


def test_registry_rejects_duplicate_task() -> None:
    registry = ModuleRegistry()
    registry.register(FakeTask1Module())
    with pytest.raises(ContractError, match="Duplicate task_id"):
        registry.register(FakeTask1Module())
