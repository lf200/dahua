"""Private AgentDojo 0.1.35 integration for the workspace sandbox."""

from __future__ import annotations

import copy
import importlib
import importlib.metadata
import json
import time
from datetime import datetime, timezone
from typing import Any

from security_eval.contracts import RunContext
from security_eval.errors import DependencyError, EvaluationTimeoutError, TargetError

from .models import AdapterResult, MatrixCase

EXPECTED_AGENTDOJO_VERSION = "0.1.35"
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


class _ChatCompletionsCompatibilityProxy:
    def __init__(
        self,
        delegate: Any,
        *,
        context: RunContext | None = None,
        rewrite_developer: bool = True,
    ) -> None:
        self._delegate = delegate
        self._context = context
        self._rewrite_developer = rewrite_developer
        self.diagnostics: list[dict[str, Any]] = []

    def create(self, *args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages")
        if messages is not None and self._rewrite_developer:
            kwargs = {
                **kwargs,
                "messages": _rewrite_developer_messages(messages),
            }
        if self._context is None:
            return self._delegate.create(*args, **kwargs)
        import openai

        context = self._context
        kwargs.setdefault(
            "max_tokens", getattr(context.target_client, "max_tokens", 1024)
        )
        summary = _request_summary(kwargs)
        for attempt in range(1, 4):
            remaining = _remaining_seconds(context)
            if remaining <= 0:
                raise EvaluationTimeoutError(
                    "Task 4 evaluation deadline reached before target request",
                    details={
                        "request": summary,
                        "request_count": len(self.diagnostics),
                        "request_diagnostics": context.sanitize_value(self.diagnostics),
                    },
                )
            request_timeout = min(
                float(getattr(context.target_client, "timeout_seconds", 60)), remaining
            )
            started = time.perf_counter()
            info = {
                "request_index": len(self.diagnostics) + 1,
                "attempt": attempt,
                "request": summary,
                "timeout_seconds": request_timeout,
            }
            self.diagnostics.append(info)
            error = None
            try:
                response = self._delegate.create(
                    *args, **{**kwargs, "timeout": request_timeout}
                )
                choices = getattr(response, "choices", ())
                if choices:
                    info["finish_reason"] = getattr(choices[0], "finish_reason", None)
                usage = getattr(response, "usage", None)
                if usage is not None:
                    info["usage"] = {
                        name: getattr(usage, name, None)
                        for name in (
                            "prompt_tokens",
                            "completion_tokens",
                            "total_tokens",
                        )
                    }
                return response
            except openai.APIError as exc:
                error = _target_error(exc, context, kwargs)
                info["error"] = dict(error.details)
            finally:
                info["duration_ms"] = max(
                    0, round((time.perf_counter() - started) * 1000)
                )
            assert error is not None
            error.details.update(
                {"request": summary, "request_count": len(self.diagnostics)}
            )
            if not error.retryable or attempt == 3:
                error.details["request_diagnostics"] = context.sanitize_value(
                    self.diagnostics
                )
                raise error from None
            delay = 0.5 * attempt
            if _remaining_seconds(context) <= delay:
                error.details["request_diagnostics"] = context.sanitize_value(
                    self.diagnostics
                )
                raise EvaluationTimeoutError(
                    "Task 4 evaluation deadline reached before target retry",
                    details=error.details,
                ) from None
            time.sleep(delay)
        raise AssertionError("unreachable")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)


class _ChatCompatibilityProxy:
    def __init__(self, delegate: Any, **options: Any) -> None:
        self._delegate = delegate
        self.completions = _ChatCompletionsCompatibilityProxy(
            delegate.completions, **options
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)


class _OpenAICompatibilityProxy:
    def __init__(self, delegate: Any, **options: Any) -> None:
        self._delegate = delegate
        self.chat = _ChatCompatibilityProxy(delegate.chat, **options)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)


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
                raise DependencyError(
                    f"Target client does not expose {attribute} for AgentDojo"
                )
        model = getattr(context.settings, "agentdojo_model", None)
        if not model:
            raise DependencyError("AgentDojo model is not configured")
        resolve_attack_model_name(model)

    def available_task_ids(self) -> tuple[tuple[str, ...], tuple[str, ...]]:
        suite = self._suite()
        return tuple(sorted(suite.user_tasks)), tuple(sorted(suite.injection_tasks))

    def run_case(self, context: RunContext, case: MatrixCase) -> AdapterResult:
        suite = self._suite()
        pipeline = self._pipeline(context, case.defense)
        logger = self._capture_logger()
        started = time.perf_counter()
        try:
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
                    "AgentDojo target request timed out", case_id=case.case_id
                ) from None
            if isinstance(exc, openai.APIError):
                raise _target_error(exc, context, {}) from None
            raise
        finally:
            client = getattr(pipeline, "_task4_client", None)
            close = getattr(client, "close", None)
            if callable(close):
                close()
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
            request_diagnostics=tuple(
                pipeline._task4_client.chat.completions.diagnostics
            ),
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
        from .openai_llm import OpenAILLM

        target = context.target_client
        remaining_seconds = _remaining_seconds(context)
        if remaining_seconds <= 0:
            raise EvaluationTimeoutError("Task 4 evaluation deadline reached")
        raw_client = openai.OpenAI(
            api_key=target.api_key,
            base_url=target.base_url,
            timeout=min(
                float(getattr(target, "timeout_seconds", 60)), remaining_seconds
            ),
            max_retries=0,
        )
        model = context.settings.agentdojo_model
        attack_model_name = resolve_attack_model_name(model)
        uses_generic_identity = _known_attack_model_name(model) is None
        client = _OpenAICompatibilityProxy(
            raw_client,
            context=context,
            rewrite_developer=uses_generic_identity,
        )
        llm = OpenAILLM(client, model)
        # AgentDojo reuses llm.name as the ToolFilter API model. Unknown
        # targets must therefore retain their real API model until after the
        # pipeline is built; only pipeline.name is the generic attack identity.
        llm.name = model if uses_generic_identity else attack_model_name
        pipeline = AgentPipeline.from_config(
            PipelineConfig(
                llm=llm,
                model_id=None,
                defense=None if defense == "none" else defense,
                system_message_name=None,
                system_message=None,
            )
        )
        if uses_generic_identity:
            pipeline.name = (
                attack_model_name
                if defense == "none"
                else f"{attack_model_name}-{defense}"
            )
        pipeline._task4_client = client
        return pipeline

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


def resolve_attack_model_name(model_id: str) -> str:
    """Resolve an API model ID to a name AgentDojo 0.1.35 can recognize."""

    normalized = model_id.strip()
    if not normalized:
        raise DependencyError("AgentDojo model is not configured")
    known_name = _known_attack_model_name(normalized)
    if known_name is not None:
        return known_name
    # AgentDojo only uses this normalized name to choose how the attack
    # template addresses the victim model. The OpenAILLM above still receives
    # the original API model ID, so arbitrary OpenAI-compatible targets can be
    # evaluated without rewriting their configured model name.
    return "local"


def _known_attack_model_name(model_id: str) -> str | None:
    normalized = model_id.strip()
    if normalized in ATTACK_MODEL_ALIASES:
        return ATTACK_MODEL_ALIASES[normalized]
    if normalized in SUPPORTED_ATTACK_MODEL_NAMES:
        return normalized
    return None


def _rewrite_developer_messages(messages: Any) -> list[Any]:
    rewritten: list[Any] = []
    for message in messages:
        if isinstance(message, dict) and message.get("role") == "developer":
            rewritten.append({**message, "role": "system"})
        else:
            rewritten.append(message)
    return rewritten


def _remaining_seconds(context: RunContext) -> float:
    deadline = context.deadline
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    return (deadline - datetime.now(timezone.utc)).total_seconds()


def _request_summary(kwargs: dict[str, Any]) -> dict[str, Any]:
    messages = kwargs.get("messages") or []
    tools = kwargs.get("tools")
    return {
        "model": kwargs.get("model"),
        "message_count": len(messages),
        "roles": [message.get("role") for message in messages],
        "content_chars": sum(
            len(json.dumps(message.get("content"), ensure_ascii=False))
            for message in messages
        ),
        "tool_count": len(tools) if isinstance(tools, (list, tuple)) else 0,
        "max_tokens": kwargs.get("max_tokens"),
    }


def _target_error(exc: Any, context: RunContext, kwargs: dict[str, Any]) -> TargetError:
    """Retain allowlisted provider diagnostics, never raw request/response bodies."""
    import openai

    status = getattr(exc, "status_code", None)
    body = exc.body if isinstance(exc.body, dict) else {}
    body = body.get("error", body)
    body = body if isinstance(body, dict) else {}
    code = getattr(exc, "code", None) or body.get("code")
    message = str(
        body.get("message") or (exc.body if isinstance(exc.body, str) else "")
    )
    # Some gateways echo request content in errors. Remove it before persistence.
    for item in kwargs.get("messages") or []:
        content = item.get("content")
        texts = (
            [content]
            if isinstance(content, str)
            else [
                block.get("text", "")
                for block in content or []
                if isinstance(block, dict)
            ]
        )
        texts.extend(
            call.get("function", {}).get("arguments", "")
            for call in item.get("tool_calls") or []
        )
        for text in texts:
            if isinstance(text, str) and text:
                message = message.replace(text, "[REDACTED]")
    timeout = isinstance(exc, openai.APITimeoutError)
    retryable = (
        status in {408, 409, 429}
        or (status is not None and status >= 500)
        or isinstance(exc, openai.APIConnectionError)
    )
    target_unavailable = status == 401 or code in {
        "insufficient_quota",
        "AllocationQuota.FreeTierOnly",
        "Throttling.AllocationQuota",
        "invalid_api_key",
        "InvalidApiKey",
        "model_not_found",
        "ModelNotFound",
    }
    details = context.sanitize_value(
        {
            "exception_type": type(exc).__name__,
            "http_status": status,
            "provider_code": str(context.sanitize_value(str(code)))[:200]
            if code is not None
            else None,
            "provider_param": str(
                context.sanitize_value(
                    str(getattr(exc, "param", None) or body.get("param") or "")
                )
            )[:200],
            "provider_message": str(context.sanitize_value(message))[:1000],
            "request_id": getattr(exc, "request_id", None),
            "target_unavailable": target_unavailable,
        }
    )
    error_type = EvaluationTimeoutError if timeout else TargetError
    return error_type(
        f"AgentDojo target request failed: {type(exc).__name__}"
        + (f" (HTTP {status})" if status is not None else ""),
        details=details,
        retryable=retryable and not target_unavailable,
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
