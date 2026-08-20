"""Single-worker orchestration over contract-compatible evaluation modules."""

from __future__ import annotations

import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

from security_eval.contracts import (
    ErrorInfo,
    Estimate,
    ModuleRequest,
    RiskLevel,
    RunContext,
    RunReport,
    RunRequest,
    TaskId,
    TaskResult,
)
from security_eval.core.clock import Clock, SystemClock
from security_eval.core.config import Settings
from security_eval.core.redaction import build_sanitizer
from security_eval.core.registry import ModuleRegistry
from security_eval.errors import ConfigurationError, DependencyError, normalize_exception


def risk_level(score: float | None) -> RiskLevel:
    if score is None:
        return "unknown"
    if score >= 80:
        return "low"
    if score >= 60:
        return "medium"
    if score >= 40:
        return "high"
    return "critical"


class EvaluationService:
    def __init__(
        self,
        *,
        settings: Settings,
        registry: ModuleRegistry,
        target_client: object,
        judge_client: object,
        clock: Clock | None = None,
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.target_client = target_client
        self.judge_client = judge_client
        self.clock = clock or SystemClock()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="security-eval")
        self._active_future: Future[RunReport] | None = None
        self._lock = threading.Lock()
        self._sanitize = build_sanitizer(settings)

    def estimate(self, request: RunRequest) -> list[Estimate]:
        self._validate_request(request, require_authorization=False)
        probe_request = ModuleRequest(
            run_id="estimate0",
            mode=request.mode,
            profile=request.profile,
            seed=request.seed,
            benchmark_version=request.benchmark_version,
        )
        return [self.registry.get(task_id).estimate(probe_request) for task_id in request.tasks]

    def start(self, request: RunRequest) -> Future[RunReport]:
        self._validate_request(request, require_authorization=True)
        with self._lock:
            if self._active_future is not None and not self._active_future.done():
                raise ConfigurationError("Another evaluation is already running", retryable=True)
            self._active_future = self._executor.submit(self.execute, request)
            return self._active_future

    def execute(self, request: RunRequest, *, run_id: str | None = None) -> RunReport:
        self._validate_request(request, require_authorization=True)
        started_at = self.clock.now()
        run_id = run_id or self._new_run_id(started_at)
        run_dir = (self.settings.output_root / run_id).resolve()
        self._ensure_within_output_root(run_dir)
        run_dir.mkdir(parents=True, exist_ok=False)
        timeout = (
            self.settings.quick_timeout_seconds
            if request.profile == "quick"
            else self.settings.full_timeout_seconds
        )
        context = RunContext(
            settings=self.settings,
            target_client=self.target_client,
            judge_client=self.judge_client,
            artifact_dir=run_dir,
            deadline=started_at + timedelta(seconds=timeout),
            sanitize_value=self._sanitize,
        )
        task_results: list[TaskResult] = []
        errors: list[ErrorInfo] = []
        for task_id in request.tasks:
            module_request = ModuleRequest(
                run_id=run_id,
                mode=request.mode,
                profile=request.profile,
                seed=request.seed,
                benchmark_version=request.benchmark_version,
            )
            try:
                module = self.registry.get(task_id)
                issues = module.validate(context)
                blocking = [issue for issue in issues if issue.severity == "error"]
                if blocking:
                    raise DependencyError(
                        f"Task {task_id} environment validation failed",
                        details={"issues": [issue.model_dump(mode="json") for issue in blocking]},
                    )
                raw_result = module.run(context, module_request)
                result = TaskResult.model_validate(self._sanitize(raw_result))
                if result.task_id != task_id:
                    raise DependencyError(f"Task {task_id} module returned task {result.task_id}")
                task_results.append(result)
                errors.extend(result.errors)
            except Exception as exc:
                errors.append(normalize_exception(exc, self._sanitize))

        valid_scores = [result.final_score for result in task_results if result.final_score is not None]
        overall_score = round(sum(valid_scores) / len(valid_scores), 2) if valid_scores else None
        if not task_results:
            status = "failed"
        elif (
            errors
            or len(task_results) != len(request.tasks)
            or any(result.final_score is None for result in task_results)
        ):
            status = "partial"
        else:
            status = "completed"
        return RunReport(
            run_id=run_id,
            status=status,
            request=request,
            task_results=task_results,
            overall_score=overall_score,
            risk_level=risk_level(overall_score),
            errors=errors,
            started_at=started_at,
            finished_at=self.clock.now(),
        )

    def shutdown(self, *, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait, cancel_futures=False)

    def _validate_request(self, request: RunRequest, *, require_authorization: bool) -> None:
        if require_authorization and not request.authorized_target:
            raise ConfigurationError("Target authorization must be confirmed")
        missing: list[TaskId] = [task for task in request.tasks if task not in self.registry.tasks()]
        if missing:
            raise DependencyError(f"Missing evaluation modules for tasks: {missing}")
        for task_id in request.tasks:
            metadata = self.registry.get(task_id).metadata()
            if request.mode not in metadata.supported_modes:
                raise DependencyError(f"Task {task_id} does not support mode {request.mode}")
            if request.profile not in metadata.supported_profiles:
                raise DependencyError(f"Task {task_id} does not support profile {request.profile}")

    def _ensure_within_output_root(self, run_dir: Path) -> None:
        try:
            run_dir.relative_to(self.settings.output_root.resolve())
        except ValueError as exc:
            raise ConfigurationError("Run directory escapes the configured output root") from exc

    @staticmethod
    def _new_run_id(started_at) -> str:
        return f"{started_at.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
