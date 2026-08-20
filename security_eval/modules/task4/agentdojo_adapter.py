"""Private AgentDojo 0.1.35 integration for the workspace sandbox."""

from __future__ import annotations

import copy
import importlib
import importlib.metadata
import time
from datetime import datetime, timezone
from typing import Any

from security_eval.contracts import RunContext
from security_eval.errors import DependencyError, EvaluationTimeoutError, TargetError

from .models import AdapterResult, MatrixCase

EXPECTED_AGENTDOJO_VERSION = "0.1.35"


class AgentDojoAdapter:
    """Run one isolated workspace case and return only serializable evidence."""

    def validate(self, context: RunContext) -> None:
        try:
            installed = importlib.metadata.version("agentdojo")
            importlib.import_module("agentdojo")
            importlib.import_module("openai")
        except (importlib.metadata.PackageNotFoundError, ImportError) as exc:
            raise DependencyError("AgentDojo 0.1.35 is not installed") from exc
        if installed != EXPECTED_AGENTDOJO_VERSION:
            raise DependencyError(
                f"Unsupported AgentDojo version {installed}; expected {EXPECTED_AGENTDOJO_VERSION}"
            )
        target = context.target_client
        for attribute in ("base_url", "api_key"):
            if not getattr(target, attribute, None):
                raise DependencyError(f"Target client does not expose {attribute} for AgentDojo")
        if not getattr(context.settings, "agentdojo_model", None):
            raise DependencyError("AgentDojo model is not configured")

    def available_task_ids(self) -> tuple[tuple[str, ...], tuple[str, ...]]:
        suite = self._suite()
        return tuple(sorted(suite.user_tasks)), tuple(sorted(suite.injection_tasks))

    def run_case(self, context: RunContext, case: MatrixCase) -> AdapterResult:
        suite = self._suite()
        pipeline = self._pipeline(context, case.defense)
        user_task = suite.get_user_task_by_id(case.user_task_id)
        injection_task = (
            suite.get_injection_task_by_id(case.injection_task_id)
            if case.injection_task_id is not None
            else None
        )
        if case.attack == "none":
            injections: dict[str, str] = {}
        else:
            attack = self._attack(case.attack, suite, pipeline)
            assert injection_task is not None
            injections = attack.attack(user_task, injection_task)

        environment = suite.load_and_inject_default_environment(injections)
        pre_environment = copy.deepcopy(environment)
        ground_truth = tuple(_jsonable(call) for call in user_task.ground_truth(copy.deepcopy(environment)))
        logger = self._capture_logger()
        started = time.perf_counter()
        try:
            with logger:
                utility, injection_goal_completed = suite.run_task_with_pipeline(
                    pipeline,
                    user_task,
                    injection_task,
                    injections,
                    environment=environment,
                )
        except Exception as exc:
            import openai

            if isinstance(exc, (openai.APITimeoutError, TimeoutError)):
                raise EvaluationTimeoutError("AgentDojo target request timed out", case_id=case.case_id) from None
            if isinstance(exc, openai.APIError):
                raise TargetError(
                    f"AgentDojo target request failed: {type(exc).__name__}",
                    case_id=case.case_id,
                ) from None
            raise
        # AgentDojo's second raw boolean means that the injection goal was
        # completed. Normalize it at the adapter boundary so this package uses
        # security=True to mean that the attack was resisted. DoS is defined by
        # loss of utility rather than by the placeholder injection task.
        security = _normalized_security(case, utility, injection_goal_completed)
        duration_ms = max(0, round((time.perf_counter() - started) * 1000))
        return AdapterResult(
            utility=utility,
            security=security,
            messages=tuple(_jsonable(message) for message in logger.messages),
            ground_truth_calls=ground_truth,
            environment_diff=_environment_diff(pre_environment, environment),
            duration_ms=duration_ms,
            error=logger.error,
            agentdojo_version=EXPECTED_AGENTDOJO_VERSION,
        )

    @staticmethod
    def _suite():
        from agentdojo.task_suite.load_suites import get_suite

        return get_suite("v1.2.2", "workspace")

    @staticmethod
    def _attack(name: str, suite: Any, pipeline: Any):
        # Imports perform official registry registration.
        importlib.import_module("agentdojo.attacks.baseline_attacks")
        importlib.import_module("agentdojo.attacks.dos_attacks")
        importlib.import_module("agentdojo.attacks.important_instructions_attacks")
        from agentdojo.attacks.attack_registry import load_attack

        return load_attack(name, suite, pipeline)

    @staticmethod
    def _pipeline(context: RunContext, defense: str):
        import openai
        from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
        from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM

        target = context.target_client
        deadline = context.deadline
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        remaining_seconds = max(1.0, (deadline - datetime.now(timezone.utc)).total_seconds())
        client = openai.OpenAI(
            api_key=target.api_key,
            base_url=target.base_url,
            timeout=min(float(getattr(target, "timeout_seconds", 60)), remaining_seconds),
        )
        model = context.settings.agentdojo_model
        llm = OpenAILLM(client, model)
        llm.name = model
        return AgentPipeline.from_config(
            PipelineConfig(
                llm=llm,
                model_id=None,
                defense=None if defense == "none" else defense,
                system_message_name=None,
                system_message=None,
            )
        )

    @staticmethod
    def _capture_logger():
        from agentdojo.logging import Logger

        class CaptureLogger(Logger):
            def __init__(self) -> None:
                self.messages: list[Any] = []
                self.error: str | None = None

            def log(self, messages: list[Any], **_: Any) -> None:
                self.messages = list(messages)

            def log_error(self, message: str) -> None:
                self.error = str(message)

        return CaptureLogger()


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _normalized_security(case: MatrixCase, utility: bool, injection_goal_completed: bool) -> bool:
    if case.attack == "none":
        return True
    if case.attack == "dos":
        return utility
    return not injection_goal_completed


def _environment_diff(before: Any, after: Any) -> dict[str, Any]:
    """Summarize changed paths without persisting workspace content."""

    from deepdiff import DeepDiff

    before_data = _jsonable(before)
    after_data = _jsonable(after)
    raw = DeepDiff(before_data, after_data, ignore_order=True).to_dict()
    summary: dict[str, Any] = {}
    for change_type, changes in raw.items():
        if isinstance(changes, dict):
            paths = sorted(str(path) for path in changes)
        elif isinstance(changes, (set, list, tuple)):
            paths = sorted(str(path) for path in changes)
        else:
            paths = [str(changes)]
        summary[str(change_type)] = {"count": len(paths), "paths": paths[:50]}
    return summary
