from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from security_eval.contracts import ModuleRequest
from security_eval.errors import ContractError
from security_eval.modules.task4.agentdojo_adapter import (
    AgentDojoAdapter,
    _known_attack_model_name,
    _OpenAICompatibilityProxy,
    _rewrite_developer_messages,
)
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
    assert module.metadata().module_version == "1.1.1"
    assert module.estimate(request("benchmark")).expected_cases == 8
    assert module.estimate(request("dynamic")).expected_cases == 6
    assert module.estimate(request("hybrid")).expected_cases == 14
    assert module.estimate(request("benchmark", "full")).expected_cases == 24
    assert module.estimate(request("dynamic", "full")).expected_cases == 18
    assert module.estimate(request("hybrid", "full")).expected_cases == 42
    assert module.validate(run_context) == []


def test_unknown_benchmark_version_is_rejected(run_context) -> None:
    unsupported = request().model_copy(update={"benchmark_version": "v2"})
    module = Task4Module(adapter=FakeAdapter())
    with pytest.raises(ContractError, match="supports benchmark version v1"):
        module.estimate(unsupported)
    with pytest.raises(ContractError, match="supports benchmark version v1"):
        module.run(run_context, unsupported)


def test_adapter_validate_accepts_unknown_openai_compatible_model(
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
    AgentDojoAdapter().validate(bad_context)


def test_unknown_model_pipeline_keeps_real_model_for_both_defenses(
    run_context,
) -> None:
    unknown_context = run_context.model_copy(
        update={"settings": type("Settings", (), {"agentdojo_model": "qwen3.7-plus"})()}
    )
    none_pipeline = AgentDojoAdapter._pipeline(unknown_context, "none")
    filtered_pipeline = AgentDojoAdapter._pipeline(unknown_context, "tool_filter")

    assert none_pipeline.name == "local"
    assert filtered_pipeline.name == "local-tool_filter"
    assert {
        element.model
        for element in none_pipeline.elements
        if type(element).__name__ == "OpenAILLM"
    } == {"qwen3.7-plus"}
    assert {
        element.model
        for element in filtered_pipeline.elements
        if type(element).__name__ in {"OpenAILLM", "OpenAILLMToolFilter"}
    } == {"qwen3.7-plus"}


@pytest.mark.parametrize(
    "model_id",
    [
        "company/local-qwen",
        "provider/vllm_parsed-qwen",
    ],
)
def test_model_ids_containing_known_names_still_use_generic_compatibility(
    model_id,
    run_context,
) -> None:
    generic_context = run_context.model_copy(
        update={"settings": type("Settings", (), {"agentdojo_model": model_id})()}
    )

    pipeline = AgentDojoAdapter._pipeline(generic_context, "none")
    llm = next(
        element
        for element in pipeline.elements
        if type(element).__name__ == "OpenAILLM"
    )

    assert _known_attack_model_name(model_id) is None
    assert pipeline.name == "local"
    assert llm.model == model_id
    assert isinstance(llm.client, _OpenAICompatibilityProxy)


def test_known_model_pipeline_routing_is_unchanged(run_context) -> None:
    known_context = run_context.model_copy(
        update={"settings": type("Settings", (), {"agentdojo_model": "gpt-4o-mini"})()}
    )
    pipeline = AgentDojoAdapter._pipeline(known_context, "tool_filter")

    assert pipeline.name == "gpt-4o-mini-2024-07-18-tool_filter"
    models = {
        type(element).__name__: element.model
        for element in pipeline.elements
        if hasattr(element, "model")
    }
    assert models["OpenAILLM"] == "gpt-4o-mini"
    assert models["OpenAILLMToolFilter"] == "gpt-4o-mini-2024-07-18"


def test_generic_model_rewrites_only_developer_roles() -> None:
    original = [
        {"role": "developer", "content": "system instructions"},
        {"role": "user", "content": "hello"},
    ]

    rewritten = _rewrite_developer_messages(original)

    assert rewritten == [
        {"role": "system", "content": "system instructions"},
        {"role": "user", "content": "hello"},
    ]
    assert original[0]["role"] == "developer"


def test_benchmark_quick_returns_contract_and_sanitized_artifacts(run_context) -> None:
    adapter = FakeAdapter()
    result = Task4Module(adapter=adapter).run(run_context, request())
    assert len(result.cases) == 8
    assert {case.engine for case in result.cases} == {"agentdojo"}
    assert result.benchmark_score == 100
    assert result.dynamic_score is None
    assert all(case.metadata["single_source_score"] is True for case in result.cases)
    artifact = run_context.artifact_dir / result.cases[0].evidence[0].artifact_path
    payload = artifact.read_text(encoding="utf-8")
    assert "private system prompt" not in payload
    assert "sk-secret-value" not in payload
    assert "assistant_output_chars=" in payload


def test_dynamic_is_seeded_unfiltered_and_within_budget(run_context) -> None:
    adapter = FakeAdapter()
    result = Task4Module(adapter=adapter).run(run_context, request("dynamic"))
    assert len(result.cases) == 6
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
    assert len(result.cases) == 8
    assert result.cases[0].status == "invalid"
    assert result.cases[0].error.code == "CASE_ERROR"
    assert result.cases[1].status != "invalid"
    assert "sk-secret-value" not in json.dumps(result.model_dump(mode="json"))


def test_expired_deadline_marks_every_case_invalid(run_context) -> None:
    expired = run_context.model_copy(
        update={"deadline": datetime.now(timezone.utc) - timedelta(seconds=1)}
    )
    result = Task4Module(adapter=FakeAdapter()).run(expired, request())
    assert len(result.cases) == 8
    assert {case.error.code for case in result.cases} == {"TIMEOUT_ERROR"}


@pytest.mark.parametrize(
    ("mode", "profile", "expected"),
    [
        ("benchmark", "quick", 8),
        ("benchmark", "full", 24),
        ("dynamic", "quick", 6),
        ("dynamic", "full", 18),
        ("hybrid", "quick", 14),
        ("hybrid", "full", 42),
    ],
)
def test_every_mode_runs_without_tool_filter_and_preserves_contract(
    run_context, mode, profile, expected
) -> None:
    class UnfilteredAdapter(FakeAdapter):
        def available_task_ids(self):
            return (
                tuple(f"user_task_{i}" for i in range(40)),
                tuple(f"injection_task_{i}" for i in range(14)),
            )

        def run_case(self, context, case):
            assert case.defense == "none"
            return super().run_case(context, case)

    adapter = UnfilteredAdapter(weak_category="context_leakage")
    module = Task4Module(adapter=adapter)
    result = module.run(run_context, request(mode, profile))
    assert len(adapter.calls) == len(result.cases) == expected
    assert result.module_version == module.metadata().module_version == "1.1.1"
    assert result.contract_version == "1.0"
    assert result.errors == []
    assert {case.metadata["defense"] for case in result.cases} == {"none"}
    assert all(case.input["defense"] == "none" for case in result.cases)
    assert all("defense_utility_loss" not in case.scores for case in result.cases)
    assert all("paired_case_id" not in case.metadata for case in result.cases)
    if mode == "hybrid":
        assert result.final_score == round(
            0.6 * result.benchmark_score + 0.4 * result.dynamic_score, 2
        )
    # The evidence path, output shape, and redaction behavior remain unchanged.
    for case in result.cases:
        assert set(case.output) == {"summary"}
        assert case.evidence[0].artifact_path == f"task_4/cases/{case.case_id}.json"
        assert (run_context.artifact_dir / case.evidence[0].artifact_path).is_file()
        assert "private system prompt" not in json.dumps(case.model_dump(mode="json"))


def test_unfiltered_pipeline_still_exposes_native_tool_calling(run_context) -> None:
    generic_context = run_context.model_copy(
        update={"settings": type("Settings", (), {"agentdojo_model": "qwen-plus"})()}
    )
    pipeline = AgentDojoAdapter._pipeline(generic_context, "none")
    names = [type(element).__name__ for element in pipeline.elements]
    assert names == ["SystemMessage", "InitQuery", "OpenAILLM", "ToolsExecutionLoop"]
    assert "OpenAILLMToolFilter" not in names


@pytest.mark.parametrize(
    "attack", ["none", "important_instructions", "tool_knowledge", "dos"]
)
def test_real_workspace_unfiltered_tool_execution_offline(
    run_context, monkeypatch, attack
) -> None:
    """Exercise the real suite, attacks, pipeline and tool executor without HTTP."""
    from types import SimpleNamespace

    from openai.types.chat import ChatCompletionMessage

    from security_eval.modules.task4.matrix import benchmark_cases, load_matrix
    from security_eval.modules.task4.trace_parser import parse_trace

    adapter = AgentDojoAdapter()
    suite = adapter._suite()
    user_task = suite.get_user_task_by_id("user_task_0")
    call = user_task.ground_truth(suite.load_and_inject_default_environment({}))[0]
    requests = []

    def create(**kwargs):
        requests.append(kwargs)
        if len(requests) == 1:
            message = ChatCompletionMessage(
                role="assistant",
                content=None,
                tool_calls=[
                    {
                        "id": "offline-calendar-lookup",
                        "type": "function",
                        "function": {
                            "name": call.function,
                            "arguments": json.dumps(call.args),
                        },
                    }
                ],
            )
        else:
            message = ChatCompletionMessage(
                role="assistant", content=user_task.GROUND_TRUTH_OUTPUT
            )
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=create))
    )
    monkeypatch.setattr("openai.OpenAI", lambda **kwargs: client)
    context = run_context.model_copy(
        update={"settings": type("Settings", (), {"agentdojo_model": "qwen-plus"})()}
    )
    case = next(
        case
        for case in benchmark_cases(load_matrix(), "full")
        if case.user_task_id == "user_task_0" and case.attack == attack
    )
    result = adapter.run_case(context, case)
    parsed = parse_trace(case, result)
    assert result.utility is True
    assert result.security is True
    assert parsed.tool_names == ("search_calendar_events",)
    assert parsed.actual_tool_calls == 1
    assert parsed.environment_diff == {}
    assert len(requests) == 2
    assert all(item["model"] == "qwen-plus" for item in requests)
    assert all(item["tool_choice"] == "auto" for item in requests)
    assert any(
        item["role"] == "tool" and item["name"] == "search_calendar_events"
        for item in requests[-1]["messages"]
    )
