"""Versioned public contracts shared by all evaluation modules and the web layer."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CONTRACT_VERSION = "1.0"

TaskId = Literal[1, 2, 4]
Mode = Literal["benchmark", "dynamic", "hybrid"]
Profile = Literal["quick", "full"]
CaseStatus = Literal["passed", "failed", "partial", "invalid"]
RunStatus = Literal["completed", "partial", "failed"]
RiskLevel = Literal["low", "medium", "high", "critical", "unknown"]
ErrorCode = Literal[
    "CONFIG_ERROR",
    "DEPENDENCY_ERROR",
    "TARGET_ERROR",
    "TIMEOUT_ERROR",
    "PARSE_ERROR",
    "CASE_ERROR",
    "CONTRACT_ERROR",
    "INTERNAL_ERROR",
]


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Evidence(ContractModel):
    kind: Literal[
        "model_output",
        "judge_reason",
        "tool_trace",
        "environment_diff",
        "recovery_probe",
        "metric",
        "error",
        "artifact",
    ]
    summary: str = Field(min_length=1, max_length=500)
    data: Any = None
    artifact_path: str | None = None
    redacted: bool = True

    @field_validator("artifact_path")
    @classmethod
    def artifact_path_must_be_relative(cls, value: str | None) -> str | None:
        if value is None:
            return value
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("artifact_path must be a safe relative path")
        return path.as_posix()


class ErrorInfo(ContractModel):
    code: ErrorCode
    message: str = Field(min_length=1, max_length=1000)
    retryable: bool = False
    case_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class Issue(ContractModel):
    severity: Literal["info", "warning", "error"]
    code: str = Field(min_length=1, max_length=100)
    message: str = Field(min_length=1, max_length=1000)


class Estimate(ContractModel):
    task_id: TaskId
    expected_cases: int = Field(ge=0)
    estimated_seconds: int = Field(ge=0)
    notes: list[str] = Field(default_factory=list)


class ModuleMetadata(ContractModel):
    contract_version: Literal["1.0"] = CONTRACT_VERSION
    task_id: TaskId
    name: str = Field(min_length=1, max_length=100)
    module_version: str = Field(min_length=1, max_length=50)
    benchmark_version: str = Field(min_length=1, max_length=50)
    supported_modes: set[Mode]
    supported_profiles: set[Profile]


class RunRequest(ContractModel):
    tasks: list[TaskId] = Field(min_length=1, max_length=3)
    mode: Mode
    profile: Profile
    seed: int = Field(default=42, ge=0, le=2_147_483_647)
    benchmark_version: str = Field(default="v1", min_length=1, max_length=50)
    authorized_target: bool = False

    @field_validator("tasks")
    @classmethod
    def tasks_must_be_unique(cls, value: list[TaskId]) -> list[TaskId]:
        if len(value) != len(set(value)):
            raise ValueError("tasks must not contain duplicates")
        return value


class ModuleRequest(ContractModel):
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$")
    mode: Mode
    profile: Profile
    seed: int = Field(ge=0, le=2_147_483_647)
    benchmark_version: str = Field(min_length=1, max_length=50)


class RunContext(ContractModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    settings: Any
    target_client: Any
    judge_client: Any
    artifact_dir: Path
    deadline: datetime
    sanitize_value: Callable[[Any], Any]

    @field_validator("artifact_dir")
    @classmethod
    def artifact_dir_must_be_absolute(cls, value: Path) -> Path:
        resolved = value.resolve()
        if not resolved.is_absolute():
            raise ValueError("artifact_dir must resolve to an absolute path")
        return resolved


class CaseResult(ContractModel):
    case_id: str = Field(min_length=1, max_length=200)
    task_id: TaskId
    source: Literal["benchmark", "dynamic"]
    engine: Literal["benchmark", "dynamic_test", "application_security", "fake"]
    category: str = Field(min_length=1, max_length=150)
    scenario: str = Field(min_length=1, max_length=1000)
    status: CaseStatus
    scores: dict[str, float] = Field(default_factory=dict)
    reason: str = Field(min_length=1, max_length=5000)
    input: Any = None
    output: Any = None
    evidence: list[Evidence] = Field(default_factory=list)
    duration_ms: int = Field(ge=0)
    error: ErrorInfo | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("scores")
    @classmethod
    def score_values_must_be_percentages(cls, value: dict[str, float]) -> dict[str, float]:
        for name, score in value.items():
            if not name or not 0 <= score <= 100:
                raise ValueError("score names must be non-empty and values must be in [0, 100]")
        return value

    @model_validator(mode="after")
    def invalid_case_requires_error(self) -> "CaseResult":
        if self.status == "invalid" and self.error is None:
            raise ValueError("invalid cases must include error information")
        return self


class CategorySummary(ContractModel):
    category: str = Field(min_length=1, max_length=150)
    valid_cases: int = Field(ge=0)
    invalid_cases: int = Field(ge=0)
    passed_cases: int = Field(ge=0)
    failed_cases: int = Field(ge=0)
    score: float | None = Field(default=None, ge=0, le=100)

    @model_validator(mode="after")
    def counts_must_balance(self) -> "CategorySummary":
        if self.passed_cases + self.failed_cases > self.valid_cases:
            raise ValueError("passed_cases + failed_cases cannot exceed valid_cases")
        return self


class TaskResult(ContractModel):
    contract_version: Literal["1.0"] = CONTRACT_VERSION
    task_id: TaskId
    module_version: str = Field(min_length=1, max_length=50)
    benchmark_version: str = Field(min_length=1, max_length=50)
    mode: Mode
    profile: Profile
    cases: list[CaseResult] = Field(default_factory=list)
    category_summaries: list[CategorySummary] = Field(default_factory=list)
    benchmark_score: float | None = Field(default=None, ge=0, le=100)
    dynamic_score: float | None = Field(default=None, ge=0, le=100)
    final_score: float | None = Field(default=None, ge=0, le=100)
    risk_level: RiskLevel = "unknown"
    errors: list[ErrorInfo] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime

    @model_validator(mode="after")
    def task_ids_and_times_must_match(self) -> "TaskResult":
        if self.finished_at < self.started_at:
            raise ValueError("finished_at cannot be earlier than started_at")
        if any(case.task_id != self.task_id for case in self.cases):
            raise ValueError("all cases must match the TaskResult task_id")
        return self


class RunReport(ContractModel):
    contract_version: Literal["1.0"] = CONTRACT_VERSION
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$")
    status: RunStatus
    request: RunRequest
    task_results: list[TaskResult]
    overall_score: float | None = Field(default=None, ge=0, le=100)
    risk_level: RiskLevel = "unknown"
    errors: list[ErrorInfo] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime

    @model_validator(mode="after")
    def report_must_be_consistent(self) -> "RunReport":
        if self.finished_at < self.started_at:
            raise ValueError("finished_at cannot be earlier than started_at")
        result_ids = [result.task_id for result in self.task_results]
        if len(result_ids) != len(set(result_ids)):
            raise ValueError("task_results must contain unique task IDs")
        if not set(result_ids).issubset(set(self.request.tasks)):
            raise ValueError("task_results must be requested tasks")
        return self


@runtime_checkable
class EvaluationModule(Protocol):
    task_id: TaskId

    def metadata(self) -> ModuleMetadata: ...

    def estimate(self, request: ModuleRequest) -> Estimate: ...

    def validate(self, context: RunContext) -> list[Issue]: ...

    def run(self, context: RunContext, request: ModuleRequest) -> TaskResult: ...


PUBLIC_SCHEMA_MODELS: tuple[type[BaseModel], ...] = (
    Evidence,
    ErrorInfo,
    Issue,
    Estimate,
    ModuleMetadata,
    RunRequest,
    ModuleRequest,
    CaseResult,
    CategorySummary,
    TaskResult,
    RunReport,
)
