"""Private data models used by the task 4 module."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Defense = Literal["none", "tool_filter"]
Attack = Literal["none", "important_instructions", "tool_knowledge", "dos"]


class PrivateModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class MatrixCase(PrivateModel):
    case_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    )
    user_task_id: str = Field(pattern=r"^user_task_\d+$")
    injection_task_id: str | None = Field(default=None, pattern=r"^injection_task_\d+$")
    attack: Attack
    defense: Defense
    category: str = Field(min_length=1, max_length=150)
    scenario: str = Field(min_length=1, max_length=1000)
    quick: bool = False

    @model_validator(mode="after")
    def attack_shape_is_consistent(self) -> MatrixCase:
        if self.attack == "none" and self.injection_task_id is not None:
            raise ValueError("baseline cases cannot specify an injection task")
        if self.attack != "none" and self.injection_task_id is None:
            raise ValueError("attack cases must specify an injection task")
        return self


class MatrixConfig(PrivateModel):
    benchmark_version: Literal["v1"] = "v1"
    agentdojo_version: Literal["0.1.35"] = "0.1.35"
    suite: Literal["workspace"] = "workspace"
    suite_version: Literal["v1.2.2"] = "v1.2.2"
    seed: int = Field(default=42, ge=0)
    dynamic_limits: dict[Literal["quick", "full"], int]
    cases: tuple[MatrixCase, ...]

    @model_validator(mode="after")
    def case_ids_and_counts_are_valid(self) -> MatrixConfig:
        ids = [case.case_id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("matrix case IDs must be unique")
        if len(self.cases) != 48:
            raise ValueError("full task 4 matrix must contain 48 cases")
        if sum(case.quick for case in self.cases) != 16:
            raise ValueError("quick task 4 matrix must contain 16 cases")
        if self.dynamic_limits != {"quick": 12, "full": 36}:
            raise ValueError("dynamic limits must be quick=12 and full=36")
        return self


class BenchmarkFileEntry(PrivateModel):
    path: Literal["matrix.yaml"] = "matrix.yaml"
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    cases: Literal[48] = 48


class Task4BenchmarkManifest(PrivateModel):
    contract_version: Literal["1.0"] = "1.0"
    task_id: Literal[4] = 4
    benchmark_version: Literal["v1"] = "v1"
    quick_cases: Literal[16] = 16
    full_cases: Literal[48] = 48
    files: tuple[BenchmarkFileEntry, ...]

    @model_validator(mode="after")
    def contains_only_matrix(self) -> Task4BenchmarkManifest:
        if len(self.files) != 1:
            raise ValueError("task 4 manifest must contain exactly matrix.yaml")
        return self


class AdapterResult(PrivateModel):
    utility: bool
    security: bool
    messages: tuple[dict[str, Any], ...] = ()
    ground_truth_calls: tuple[dict[str, Any], ...] = ()
    environment_diff: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int = Field(ge=0)
    error: str | None = None
    agentdojo_version: str = "0.1.35"


class ParsedTrace(PrivateModel):
    utility: bool
    attack_succeeded: bool
    actual_tool_calls: int = Field(ge=0)
    sensitive_tool_calls: int = Field(ge=0)
    unauthorized_tool_calls: int = Field(ge=0)
    leakage_detected: bool
    dos_interrupted: bool
    tool_names: tuple[str, ...] = ()
    output_summary: str = ""
    environment_diff: dict[str, Any] = Field(default_factory=dict)
