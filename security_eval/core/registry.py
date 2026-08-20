"""Manifest-driven evaluation module discovery."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from security_eval.contracts import CONTRACT_VERSION, EvaluationModule, Mode, Profile, TaskId
from security_eval.errors import ContractError, DependencyError


class ModuleManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: TaskId
    import_path: str = Field(min_length=1)
    class_name: str = Field(min_length=1)
    module_version: str = Field(min_length=1)
    benchmark_version: str = Field(min_length=1)
    contract_version: str
    dependency_file: str = Field(min_length=1)
    supported_modes: set[Mode]
    supported_profiles: set[Profile]


def load_module_manifest(path: Path) -> ModuleManifest:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        manifest = ModuleManifest.model_validate(data)
    except FileNotFoundError as exc:
        raise DependencyError(f"Module manifest not found: {path}") from exc
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ContractError(f"Invalid module manifest: {path.name}") from exc
    if manifest.contract_version != CONTRACT_VERSION:
        raise ContractError(
            f"Unsupported contract version {manifest.contract_version} in {path.name}; expected {CONTRACT_VERSION}"
        )
    return manifest


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: dict[TaskId, EvaluationModule] = {}
        self._manifests: dict[TaskId, ModuleManifest] = {}

    @classmethod
    def from_manifests(cls, paths: Iterable[Path]) -> "ModuleRegistry":
        registry = cls()
        for path in paths:
            registry.load(path)
        return registry

    @classmethod
    def discover(cls, modules_root: Path) -> "ModuleRegistry":
        return cls.from_manifests(sorted(modules_root.glob("task*/module.json")))

    def load(self, manifest_path: Path) -> EvaluationModule:
        manifest = load_module_manifest(manifest_path)
        if manifest.task_id in self._modules:
            raise ContractError(f"Duplicate task_id in module registry: {manifest.task_id}")
        try:
            module = importlib.import_module(manifest.import_path)
            module_class = getattr(module, manifest.class_name)
            instance = module_class()
        except (ImportError, AttributeError, TypeError) as exc:
            raise DependencyError(
                f"Cannot load task {manifest.task_id} module {manifest.import_path}.{manifest.class_name}"
            ) from exc
        self.register(instance, manifest=manifest)
        return instance

    def register(self, module: EvaluationModule, *, manifest: ModuleManifest | None = None) -> None:
        if not isinstance(module, EvaluationModule):
            raise ContractError("Registered object does not implement EvaluationModule")
        task_id = module.task_id
        if task_id in self._modules:
            raise ContractError(f"Duplicate task_id in module registry: {task_id}")
        metadata = module.metadata()
        if metadata.task_id != task_id:
            raise ContractError("Module metadata task_id does not match module.task_id")
        if metadata.contract_version != CONTRACT_VERSION:
            raise ContractError("Module metadata uses an unsupported contract version")
        if manifest is not None:
            if manifest.task_id != task_id:
                raise ContractError("Manifest task_id does not match module.task_id")
            if manifest.module_version != metadata.module_version:
                raise ContractError("Manifest module_version does not match module metadata")
            if manifest.benchmark_version != metadata.benchmark_version:
                raise ContractError("Manifest benchmark_version does not match module metadata")
            if manifest.supported_modes != metadata.supported_modes:
                raise ContractError("Manifest supported_modes do not match module metadata")
            if manifest.supported_profiles != metadata.supported_profiles:
                raise ContractError("Manifest supported_profiles do not match module metadata")
            self._manifests[task_id] = manifest
        self._modules[task_id] = module

    def get(self, task_id: TaskId) -> EvaluationModule:
        try:
            return self._modules[task_id]
        except KeyError as exc:
            raise DependencyError(f"No evaluation module registered for task {task_id}") from exc

    def tasks(self) -> tuple[TaskId, ...]:
        return tuple(sorted(self._modules))

    def __len__(self) -> int:
        return len(self._modules)
