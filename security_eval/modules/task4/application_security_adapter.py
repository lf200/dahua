"""Private Application security engine 0.1.35 integration for the workspace sandbox."""

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

EXPECTED_ENGINE_VERSION = "0.1.35"
SUPPORTED_ATTACK_MODEL_NAMES = (
    "gpt-4o-2024-05-13",
    "gpt-4o-mini-2024-07-18",
    "gpt-4-0125-preview",
    "gpt-3.5-turbo-0125",
    "gpt-4-turbo-2024-04-09",
    "claude-3-opus-20240229",
    "claude-3-sonnet-20240229",
    "claude-3-5-sonnet-20240620",
    "claude-3-5-sonnet-20241022",
    "claude-3-7-sonnet-20250219-thinking-16000",
    "claude-3-7-sonnet-20250219",
    "claude-3-haiku-20240307",
    "command-r-plus",
    "command-r",
    "mistralai/Mixtral-8x7B-Instruct-v0.1",
    "meta-llama/Llama-3-70b-chat-hf",
    "gemini-1.5-pro-002",
    "gemini-1.5-pro-001",
    "gemini-1.5-flash-002",
    "gemini-1.5-flash-001",
    "gemini-2.0-flash-exp",
    "gemini-2.0-flash-001",
    "gemini-2.5-flash-preview-04-17",
    "gemini-2.5-pro-preview-05-06",
    "local",
    "vllm_parsed",
)
ATTACK_MODEL_ALIASES = {
    "gpt-4o": "gpt-4o-2024-05-13",
    "gpt-4o-mini": "gpt-4o-mini-2024-07-18",
    "gpt-4-turbo": "gpt-4-turbo-2024-04-09",
    "gpt-3.5-turbo": "gpt-3.5-turbo-0125",
}


class ApplicationSecurityAdapter:
    """Run one isolated workspace case and return only serializable evidence."""

    def validate(self, context: RunContext) -> None:
        try:
            installed = importlib.metadata.version("agentdojo")
            importlib.import_module("agentdojo")
            importlib.import_module("openai")
        except (importlib.metadata.PackageNotFoundError, ImportError) as exc:
            raise DependencyError("Application security engine 0.1.35 is not installed") from exc
        if installed != EXPECTED_ENGINE_VERSION:
            raise DependencyError(
                f"Unsupported Application security engine version {installed}; expected {EXPECTED_ENGINE_VERSION}"
            )
        target = context.target_client
        for attribute in ("base_url", "api_key"):
            if not getattr(target, attribute, None):
                raise DependencyError(
                    f"Target client does not expose {attribute} for Application security engine"
                )
        model = getattr(context.settings, "application_security_model", None)
        if not model:
            raise DependencyError("Application security engine model is not configured")
        resolve_engine_model_name(model)

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
        ground_truth = tuple(
            _jsonable(call)
            for call in user_task.ground_truth(copy.deepcopy(environment))
        )
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
                raise EvaluationTimeoutError(
                    "Application security engine target request timed out", case_id=case.case_id
                ) from None
            if isinstance(exc, openai.APIError):
                raise TargetError(
                    "Application security engine target request failed",
                    case_id=case.case_id,
                ) from None
            raise
        # Application security engine's second raw boolean means that the injection goal was
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
            engine_version=EXPECTED_ENGINE_VERSION,
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
        from agentdojo.agent_pipeline.agent_pipeline import (
            AgentPipeline,
            PipelineConfig,
        )
        from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM

        target = context.target_client
        deadline = context.deadline
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        remaining_seconds = max(
            1.0, (deadline - datetime.now(timezone.utc)).total_seconds()
        )
        client = openai.OpenAI(
            api_key=target.api_key,
            base_url=target.base_url,
            timeout=min(
                float(getattr(target, "timeout_seconds", 60)), remaining_seconds
            ),
        )
        model = context.settings.application_security_model
        llm = OpenAILLM(client, model)
        # Keep the real API model ID on OpenAILLM, but give Application security engine a
        # separately normalized pipeline name for its attack templates.
        llm.name = resolve_engine_model_name(model)
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


def _normalized_security(
    case: MatrixCase, utility: bool, injection_goal_completed: bool
) -> bool:
    if case.attack == "none":
        return True
    if case.attack == "dos":
        return utility
    return not injection_goal_completed


def resolve_engine_model_name(model_id: str) -> str:
    """Resolve an API model ID to a name Application security engine 0.1.35 can recognize."""

    normalized = model_id.strip()
    if normalized in ATTACK_MODEL_ALIASES:
        return ATTACK_MODEL_ALIASES[normalized]
    for supported in SUPPORTED_ATTACK_MODEL_NAMES:
        if supported in normalized:
            return supported
    aliases = ", ".join(sorted(ATTACK_MODEL_ALIASES))
    raise DependencyError(
        "Application security engine cannot identify the configured model for attack templates; "
        f"use a supported snapshot name or one of these aliases: {aliases}"
    )


def _environment_diff(before: Any, after: Any) -> dict[str, Any]:
    """Summarize changed paths without persisting workspace content."""

    from deepdiff import DeepDiff

    before_data = _jsonable(before)
    after_data = _jsonable(after)
    raw = DeepDiff(before_data, after_data, ignore_order=True).to_dict()
    summary: dict[str, Any] = {}
    for change_type, changes in raw.items():
        if isinstance(changes, (dict, set, list, tuple)):
            paths = sorted(str(path) for path in changes)
        else:
            paths = [str(changes)]
        summary[str(change_type)] = {"count": len(paths), "paths": paths[:50]}
    return summary
