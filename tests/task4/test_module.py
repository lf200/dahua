from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from security_eval.contracts import ModuleRequest
from security_eval.errors import ContractError, DependencyError
from security_eval.modules.task4.agentdojo_adapter import AgentDojoAdapter
from security_eval.modules.task4.models import AdapterResult
from security_eval.modules.task4.module import Task4Module


class FakeAdapter:
    def __init__(self, *, fail_first=False, weak_category=None):
        self.calls = []
        self.fail_first = fail_first
        self.weak_category = weak_category

    def validate(self, context):
        return None

    def available_task_ids(self):
        return (
            ("user_task_0", "user_task_2", "user_task_18", "user_task_32"),
            (
                "injection_task_0",
                "injection_task_1",
                "injection_task_2",
                "injection_task_4",
            ),
        )

    def run_case(self, context, case):
        self.calls.append(case)
        if self.fail_first and len(self.calls) == 1:
            raise RuntimeError("sk-secret-value must not leak")
        attack_success = case.category == self.weak_category and case.defense == "none"
        return AdapterResult(
            utility=not (case.attack == "dos" and attack_success),
            security=not attack_success,
            messages=(
                {"role": "system", "content": "private system prompt"},
                {
                    "role": "assistant",
                    "content": [{"type": "text", "content": "safe sk-secret-value"}],
                    "tool_calls": [],
                },
            ),
            ground_truth_calls=(),
            environment_diff={},
            duration_ms=5,
        )


def request(mode="benchmark", profile="quick"):
    return ModuleRequest(
        run_id="testrun00",
        mode=mode,
        profile=profile,
        seed=7,
        benchmark_version="v1",
    )


def test_metadata_estimate_and_validation(run_context) -> None:
    module = Task4Module(adapter=FakeAdapter())
    assert module.metadata().task_id == 4
    assert module.estimate(request("benchmark")).expected_cases == 16
    assert module.estimate(request("dynamic")).expected_cases == 12
    assert module.estimate(request("hybrid")).expected_cases == 28
    assert module.validate(run_context) == []


def test_unknown_benchmark_version_is_rejected(run_context) -> None:
    unsupported = request().model_copy(update={"benchmark_version": "v2"})
    module = Task4Module(adapter=FakeAdapter())
    with pytest.raises(ContractError, match="supports benchmark version v1"):
        module.estimate(unsupported)
    with pytest.raises(ContractError, match="supports benchmark version v1"):
        module.run(run_context, unsupported)


def test_adapter_validate_rejects_unknown_model_before_cases(
    monkeypatch, run_context
) -> None:
    monkeypatch.setattr("importlib.metadata.version", lambda _: "0.1.35")
    monkeypatch.setattr("importlib.import_module", lambda _: object())
    bad_context = run_context.model_copy(
        update={
            "settings": type(
                "Settings", (), {"agentdojo_model": "company/custom-model"}
            )()
        }
    )
    with pytest.raises(DependencyError, match="cannot identify"):
        AgentDojoAdapter().validate(bad_context)


def test_benchmark_quick_returns_contract_and_sanitized_artifacts(run_context) -> None:
    adapter = FakeAdapter()
    result = Task4Module(adapter=adapter).run(run_context, request())
    assert len(result.cases) == 16
    assert {case.engine for case in result.cases} == {"agentdojo"}
    assert result.benchmark_score == 100
    assert result.dynamic_score is None
    assert all(case.metadata["single_source_score"] is True for case in result.cases)
    artifact = run_context.artifact_dir / result.cases[0].evidence[0].artifact_path
    payload = artifact.read_text(encoding="utf-8")
    assert "private system prompt" not in payload
    assert "sk-secret-value" not in payload
    assert "assistant_output_chars=" in payload


def test_dynamic_is_seeded_paired_and_within_budget(run_context) -> None:
    adapter = FakeAdapter()
    result = Task4Module(adapter=adapter).run(run_context, request("dynamic"))
    assert len(result.cases) == 12
    assert all(case.source == "dynamic" for case in result.cases)
    assert result.benchmark_score is None
    assert result.dynamic_score == 100


def test_hybrid_only_expands_weak_category(run_context) -> None:
    adapter = FakeAdapter(weak_category="context_leakage")
    result = Task4Module(adapter=adapter).run(run_context, request("hybrid"))
    dynamic = [case for case in result.cases if case.source == "dynamic"]
    assert dynamic
    assert {case.category for case in dynamic} == {"context_leakage"}
    assert result.benchmark_score is not None
    assert result.dynamic_score is not None


def test_case_failure_is_invalid_and_does_not_stop_run(run_context) -> None:
    result = Task4Module(adapter=FakeAdapter(fail_first=True)).run(
        run_context, request()
    )
    assert len(result.cases) == 16
    assert result.cases[0].status == "invalid"
    assert result.cases[0].error.code == "CASE_ERROR"
    assert result.cases[1].status != "invalid"
    assert "sk-secret-value" not in json.dumps(result.model_dump(mode="json"))


def test_expired_deadline_marks_every_case_invalid(run_context) -> None:
    expired = run_context.model_copy(
        update={"deadline": datetime.now(timezone.utc) - timedelta(seconds=1)}
    )
    result = Task4Module(adapter=FakeAdapter()).run(expired, request())
    assert len(result.cases) == 16
    assert {case.error.code for case in result.cases} == {"TIMEOUT_ERROR"}
