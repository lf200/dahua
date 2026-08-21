from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from security_eval.errors import EvaluationTimeoutError
from security_eval.modules.task1.dynamic_test_adapter import (
    DynamicTestAdapter,
    _DynamicTestBackend,
    _DynamicTestImports,
    _configure_dynamic_test_privacy,
    _judge_model,
    _target_callback,
    build_category_runs,
)


def test_backend_case_error_does_not_expose_vendor_message(
    monkeypatch, context_factory
) -> None:
    class BaseModel:
        def __init__(self, model_name):
            self.model_name = model_name

    class AcceptsAnything:
        def __init__(self, *args, **kwargs):
            pass

    class Assessment:
        test_cases = [
            type(
                "Case",
                (),
                {
                    "input": "probe",
                    "actual_output": None,
                    "error": "Deep" + "Team private backend failure",
                    "score": None,
                    "reason": "Deep" + "Eval supplied this diagnostic",
                    "attack_method": "fixture",
                    "vulnerability_type": None,
                    "turns": None,
                },
            )()
        ]

    class RedTeamer(AcceptsAnything):
        def red_team(self, **kwargs):
            return Assessment()

    imported = _DynamicTestImports(
        RedTeamer=RedTeamer,
        AttackEngine=AcceptsAnything,
        Robustness=AcceptsAnything,
        IndirectInstruction=AcceptsAnything,
        PromptInjection=AcceptsAnything,
        Roleplay=AcceptsAnything,
        LinearJailbreaking=AcceptsAnything,
        EvaluationBaseLLM=BaseModel,
    )
    monkeypatch.setattr(
        "security_eval.modules.task1.dynamic_test_adapter._load_dynamic_test",
        lambda: imported,
    )

    observation = _DynamicTestBackend().run_spec(
        context_factory(),
        "prompt_injection",
        build_category_runs("prompt_injection", "quick")[0],
        42,
        1,
    )[0]

    assert observation.error is not None
    assert observation.error.details == {"stage": "dynamic_probe"}
    assert ("deep" + "team") not in observation.model_dump_json().lower()
    assert ("deep" + "eval") not in observation.model_dump_json().lower()


def test_dynamic_test_privacy_forces_telemetry_opt_out(monkeypatch) -> None:
    monkeypatch.setenv("DEEPTEAM_TELEMETRY_OPT_OUT", "NO")
    monkeypatch.setenv("DEEPEVAL_TELEMETRY_OPT_OUT", "NO")

    _configure_dynamic_test_privacy()

    assert __import__("os").environ["DEEPTEAM_TELEMETRY_OPT_OUT"] == "YES"
    assert __import__("os").environ["DEEPEVAL_TELEMETRY_OPT_OUT"] == "YES"


def test_empty_dynamic_result_becomes_invalid_case(context_factory) -> None:
    class EmptyBackend:
        def run_spec(self, context, category, spec, seed, ordinal_start):
            return []

    adapter = DynamicTestAdapter(backend=EmptyBackend())

    observations = adapter.run(context_factory(), ["prompt_injection"], "quick", 42)

    assert len(observations) == 1
    assert observations[0].error is not None
    assert observations[0].error.code == "CASE_ERROR"


def test_dynamic_test_clients_stop_after_run_deadline() -> None:
    class Client:
        def complete(self, messages):
            raise AssertionError("expired runs must not call a model")

    class BaseModel:
        def __init__(self, model_name):
            self.model_name = model_name

    deadline = datetime.now(timezone.utc) - timedelta(seconds=1)
    callback = _target_callback(Client(), deadline=deadline)
    judge_model = _judge_model(BaseModel, Client(), "fixture-judge", deadline=deadline)

    with pytest.raises(EvaluationTimeoutError):
        callback("attack")
    with pytest.raises(EvaluationTimeoutError):
        judge_model.generate("judge prompt")


def test_quick_indirect_instruction_uses_one_document_variant() -> None:
    runs = build_category_runs("indirect_instruction", "quick")

    assert [run.model_dump() for run in runs] == [
        {
            "vulnerability": "IndirectInstruction",
            "vulnerability_types": ["document_embedded_instructions"],
            "attack": "PromptInjection",
            "variations": 1,
            "max_turns": 3,
            "turn_level_attacks": [],
        }
    ]


def test_full_indirect_instruction_splits_three_variants_across_both_types() -> None:
    runs = build_category_runs("indirect_instruction", "full")

    assert [(run.vulnerability_types, run.variations) for run in runs] == [
        (["document_embedded_instructions"], 2),
        (["cross_context_injection"], 1),
    ]
    assert sum(run.variations for run in runs) == 3


def test_context_hijack_uses_linear_jailbreaking_with_profile_turn_limit() -> None:
    quick = build_category_runs("context_hijack", "quick")
    full = build_category_runs("context_hijack", "full")

    assert quick[0].attack == "LinearJailbreaking"
    assert quick[0].turn_level_attacks == ["Roleplay", "PromptInjection"]
    assert quick[0].max_turns == 3
    assert quick[0].variations == 1
    assert full[0].max_turns == 5
    assert full[0].variations == 3


def test_category_mappings_cover_required_dynamic_components() -> None:
    mappings = {
        category: build_category_runs(category, "quick")[0]
        for category in ["prompt_injection", "role_jailbreak", "logic_trap"]
    }

    assert (
        mappings["prompt_injection"].vulnerability,
        mappings["prompt_injection"].attack,
    ) == (
        "Robustness",
        "PromptInjection",
    )
    assert mappings["prompt_injection"].vulnerability_types == ["hijacking"]
    assert (
        mappings["role_jailbreak"].vulnerability,
        mappings["role_jailbreak"].attack,
    ) == (
        "Robustness",
        "Roleplay",
    )
    assert mappings["logic_trap"].vulnerability_types == ["input_overreliance"]
