from __future__ import annotations

from datetime import datetime, timezone
from threading import Event

import pytest

from security_eval.contracts import ModuleRequest, RunContext, RunRequest
from security_eval.core.clock import FrozenClock
from security_eval.core.registry import ModuleRegistry
from security_eval.core.service import EvaluationService
from security_eval.errors import CaseEvaluationError, ConfigurationError
from tests.fakes.fake_module import FakeTask1Module, FakeTask2Module, FakeTask4Module


class FailingTask2Module(FakeTask2Module):
    def run(self, context: RunContext, request: ModuleRequest):
        raise CaseEvaluationError("fixture task failure")


class BlockingTask1Module(FakeTask1Module):
    def __init__(self, entered: Event, release: Event) -> None:
        self.entered = entered
        self.release = release

    def run(self, context: RunContext, request: ModuleRequest):
        self.entered.set()
        self.release.wait(timeout=2)
        return super().run(context, request)


class LeakyTask1Module(FakeTask1Module):
    def run(self, context: RunContext, request: ModuleRequest):
        result = super().run(context, request)
        result.cases[0].input = {
            "api_key": context.settings.target_api_key.get_secret_value(),
            "token_count": 12,
        }
        return result


def service(settings, *modules):
    registry = ModuleRegistry()
    for module in modules:
        registry.register(module)
    return EvaluationService(
        settings=settings,
        registry=registry,
        target_client=object(),
        judge_client=object(),
        clock=FrozenClock(datetime(2026, 8, 20, 0, 0, tzinfo=timezone.utc)),
    )


def request(tasks=(1, 2, 4), authorized=True):
    return RunRequest(
        tasks=list(tasks),
        mode="hybrid",
        profile="quick",
        seed=42,
        authorized_target=authorized,
    )


def test_execute_aggregates_equal_task_weights(settings) -> None:
    runner = service(settings, FakeTask1Module(), FakeTask2Module(), FakeTask4Module())
    report = runner.execute(request(), run_id="testrun01")
    assert report.status == "completed"
    assert report.overall_score == 75.0
    assert report.risk_level == "medium"
    assert [result.task_id for result in report.task_results] == [1, 2, 4]
    runner.shutdown()


def test_execute_isolates_module_failure(settings) -> None:
    runner = service(settings, FakeTask1Module(), FailingTask2Module(), FakeTask4Module())
    report = runner.execute(request(), run_id="testrun02")
    assert report.status == "partial"
    assert [result.task_id for result in report.task_results] == [1, 4]
    assert report.errors[0].code == "CASE_ERROR"
    runner.shutdown()


def test_authorization_is_required(settings) -> None:
    runner = service(settings, FakeTask1Module())
    with pytest.raises(ConfigurationError, match="authorization"):
        runner.execute(request(tasks=(1,), authorized=False), run_id="testrun03")
    runner.shutdown()


def test_estimate_uses_public_module_method(settings) -> None:
    runner = service(settings, FakeTask1Module())
    estimates = runner.estimate(request(tasks=(1,), authorized=False))
    assert estimates[0].task_id == 1
    assert estimates[0].expected_cases == 1
    runner.shutdown()


def test_start_rejects_a_second_concurrent_run(settings) -> None:
    entered = Event()
    release = Event()
    runner = service(settings, BlockingTask1Module(entered, release))
    future = runner.start(request(tasks=(1,)))
    assert entered.wait(timeout=1)
    with pytest.raises(ConfigurationError, match="already running"):
        runner.start(request(tasks=(1,)))
    release.set()
    assert future.result(timeout=2).status == "completed"
    runner.shutdown()


def test_service_sanitizes_module_results(settings) -> None:
    runner = service(settings, LeakyTask1Module())
    report = runner.execute(request(tasks=(1,)), run_id="testrun04")
    case_input = report.task_results[0].cases[0].input
    assert case_input["api_key"] == "[REDACTED]"
    assert case_input["token_count"] == 12
    runner.shutdown()
