"""Fake modules used by core and web developers before real task modules exist."""

from __future__ import annotations

from security_eval.contracts import (
    CaseResult,
    CategorySummary,
    Estimate,
    Issue,
    ModuleMetadata,
    ModuleRequest,
    RunContext,
    TaskId,
    TaskResult,
)


class FakeModule:
    task_id: TaskId = 1
    module_version = "fake-1.0"
    benchmark_version = "v1"
    final_score = 80.0

    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            task_id=self.task_id,
            name=f"Fake task {self.task_id}",
            module_version=self.module_version,
            benchmark_version=self.benchmark_version,
            supported_modes={"benchmark", "dynamic", "hybrid"},
            supported_profiles={"quick", "full"},
        )

    def estimate(self, request: ModuleRequest) -> Estimate:
        return Estimate(task_id=self.task_id, expected_cases=1, estimated_seconds=1)

    def validate(self, context: RunContext) -> list[Issue]:
        return []

    def run(self, context: RunContext, request: ModuleRequest) -> TaskResult:
        now = context.deadline
        case = CaseResult(
            case_id=f"fake-task-{self.task_id}",
            task_id=self.task_id,
            source="benchmark",
            engine="fake",
            category="fixture",
            scenario="Contract fixture scenario",
            status="passed",
            scores={"security": self.final_score},
            reason="Fake module completed successfully",
            input={"prompt": "safe fixture"},
            output={"answer": "safe fixture response"},
            duration_ms=1,
        )
        return TaskResult(
            task_id=self.task_id,
            module_version=self.module_version,
            benchmark_version=self.benchmark_version,
            mode=request.mode,
            profile=request.profile,
            cases=[case],
            category_summaries=[
                CategorySummary(
                    category="fixture",
                    valid_cases=1,
                    invalid_cases=0,
                    passed_cases=1,
                    failed_cases=0,
                    score=self.final_score,
                )
            ],
            benchmark_score=self.final_score if request.mode != "dynamic" else None,
            dynamic_score=self.final_score if request.mode != "benchmark" else None,
            final_score=self.final_score,
            risk_level="low" if self.final_score >= 80 else "medium",
            started_at=now,
            finished_at=now,
        )


class FakeTask1Module(FakeModule):
    task_id: TaskId = 1
    final_score = 90.0


class FakeTask2Module(FakeModule):
    task_id: TaskId = 2
    final_score = 75.0


class FakeTask4Module(FakeModule):
    task_id: TaskId = 4
    final_score = 60.0
