from __future__ import annotations

import builtins
import os
from types import SimpleNamespace

import pytest
from pydantic import BaseModel

from security_eval.errors import DependencyError
from security_eval.modules.task2.dynamic_test_adapter import (
    EVALUATION_EXAMPLES,
    EVALUATION_GUIDELINES,
    VULNERABILITY_IMPORTS,
    DynamicTestAdapter,
    _configure_dynamic_test_privacy,
    _load_api,
)
from security_eval.modules.task2.models import TASK2_CATEGORIES, Task2Case


DYNAMIC_PACKAGE = "deep" + "team"
EVALUATION_PACKAGE = "deep" + "eval"


class FakeEvaluationExample:
    def __init__(self, **kwargs):
        self.values = kwargs


class FakeAttackEngine:
    created: list[dict] = []

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.created.append(kwargs)


class FakeVulnerability:
    created: list[dict] = []

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.created.append(kwargs)

    def simulate_attacks(self, purpose: str, attacks_per_vulnerability_type: int):
        assert attacks_per_vulnerability_type == 1
        return [
            SimpleNamespace(
                input=f"{purpose} variant {index}", vulnerability_type=self.types[0]
            )
            for index in range(self.attack_engine.variations)
        ]


def fake_api():
    return SimpleNamespace(
        AttackEngine=FakeAttackEngine,
        EvaluationBaseLLM=FakeEvaluationBaseLLM,
        EvaluationExample=FakeEvaluationExample,
        vulnerabilities={category: FakeVulnerability for category in TASK2_CATEGORIES},
    )


class FakeEvaluationBaseLLM:
    def __init__(self, model_name=None):
        self.model_name = model_name
        self.model = self.load_model()


class GeneratedSchema(BaseModel):
    input: str


class StructuredJudgeClient:
    def complete(self, messages):
        assert messages == [{"role": "user", "content": "generate one case"}]
        return '{"input":"generated through the frozen judge client"}'


def test_public_vulnerability_mapping_covers_exact_task_categories() -> None:
    assert set(VULNERABILITY_IMPORTS) == set(TASK2_CATEGORIES)
    assert set(EVALUATION_GUIDELINES) == set(TASK2_CATEGORIES)
    assert set(EVALUATION_EXAMPLES) == set(TASK2_CATEGORIES)
    assert all(len(EVALUATION_EXAMPLES[category]) >= 2 for category in TASK2_CATEGORIES)


def test_dynamic_test_privacy_forces_telemetry_opt_out(monkeypatch) -> None:
    monkeypatch.setenv("DEEPTEAM_TELEMETRY_OPT_OUT", "NO")
    monkeypatch.setenv("DEEPEVAL_TELEMETRY_OPT_OUT", "NO")

    _configure_dynamic_test_privacy()

    assert os.environ["DEEPTEAM_TELEMETRY_OPT_OUT"] == "YES"
    assert os.environ["DEEPEVAL_TELEMETRY_OPT_OUT"] == "YES"


def test_adapter_constructor_forces_telemetry_opt_out(monkeypatch) -> None:
    monkeypatch.setenv("DEEPTEAM_TELEMETRY_OPT_OUT", "NO")
    monkeypatch.setenv("DEEPEVAL_TELEMETRY_OPT_OUT", "NO")

    DynamicTestAdapter(api_loader=fake_api, simulator_model="judge-model")

    assert os.environ["DEEPTEAM_TELEMETRY_OPT_OUT"] == "YES"
    assert os.environ["DEEPEVAL_TELEMETRY_OPT_OUT"] == "YES"


def test_load_api_sets_privacy_before_first_third_party_import(monkeypatch) -> None:
    monkeypatch.setenv("DEEPTEAM_TELEMETRY_OPT_OUT", "NO")
    monkeypatch.setenv("DEEPEVAL_TELEMETRY_OPT_OUT", "NO")
    original_import = builtins.__import__
    attempted: list[str] = []

    def guarded_import(name, *args, **kwargs):
        if name.startswith((DYNAMIC_PACKAGE, EVALUATION_PACKAGE)):
            attempted.append(name)
            assert os.environ["DEEPTEAM_TELEMETRY_OPT_OUT"] == "YES"
            assert os.environ["DEEPEVAL_TELEMETRY_OPT_OUT"] == "YES"
            raise ModuleNotFoundError(name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)

    with pytest.raises(ModuleNotFoundError):
        _load_api()

    assert attempted


@pytest.mark.parametrize(("profile", "per_category"), [("quick", 1), ("full", 3)])
def test_generate_normalizes_variants_and_preserves_calibration(
    profile: str, per_category: int
) -> None:
    FakeAttackEngine.created.clear()
    FakeVulnerability.created.clear()
    adapter = DynamicTestAdapter(api_loader=fake_api, simulator_model="judge-model")

    cases = adapter.generate(["Bias", "Toxicity"], profile=profile, seed=17)

    assert len(cases) == 2 * per_category
    assert all(isinstance(case, Task2Case) for case in cases)
    assert {case.category for case in cases} == {"Bias", "Toxicity"}
    assert all(case.source == "dynamic" and case.engine == "dynamic_test" for case in cases)
    assert all(
        set(case.model_dump())
        == {
            "case_id",
            "task_id",
            "source",
            "engine",
            "category",
            "scenario",
            "messages",
            "expected_action",
            "expected_behavior",
            "forbidden_outcomes",
            "rubric",
            "quick",
            "metadata",
        }
        for case in cases
    )
    assert all(item["variations"] == per_category for item in FakeAttackEngine.created)
    assert all(item["evaluation_guidelines"] for item in FakeVulnerability.created)
    assert all(
        len(item["evaluation_examples"]) >= 2 for item in FakeVulnerability.created
    )


def test_same_seed_produces_same_ids_and_messages() -> None:
    adapter = DynamicTestAdapter(api_loader=fake_api, simulator_model="judge-model")

    first = adapter.generate(["Misinformation"], profile="full", seed=23)
    second = adapter.generate(["Misinformation"], profile="full", seed=23)

    assert [case.case_id for case in first] == [case.case_id for case in second]
    assert [case.messages for case in first] == [case.messages for case in second]


def test_full_profile_preserves_filtered_variants_from_each_category() -> None:
    class FilteringVulnerability(FakeVulnerability):
        def simulate_attacks(self, purpose: str, attacks_per_vulnerability_type: int):
            assert self.attack_engine.variations == 3
            return [
                SimpleNamespace(
                    input=f"{purpose} surviving variant",
                    vulnerability_type=self.types[0],
                )
            ]

    api = SimpleNamespace(
        AttackEngine=FakeAttackEngine,
        EvaluationBaseLLM=FakeEvaluationBaseLLM,
        EvaluationExample=FakeEvaluationExample,
        vulnerabilities={
            category: FilteringVulnerability for category in TASK2_CATEGORIES
        },
    )
    adapter = DynamicTestAdapter(api_loader=lambda: api, simulator_model="judge-model")

    cases = adapter.generate(["Bias", "Toxicity"], profile="full", seed=17)

    assert len(cases) == 2
    assert {case.category for case in cases} == {"Bias", "Toxicity"}
    assert all(case.metadata["requested_variations"] == 3 for case in cases)
    assert all(case.metadata["returned_variations"] == 1 for case in cases)


def test_generate_preserves_other_categories_and_marks_empty_category() -> None:
    class EmptyVulnerability(FakeVulnerability):
        def simulate_attacks(self, purpose: str, attacks_per_vulnerability_type: int):
            return []

    api = SimpleNamespace(
        AttackEngine=FakeAttackEngine,
        EvaluationBaseLLM=FakeEvaluationBaseLLM,
        EvaluationExample=FakeEvaluationExample,
        vulnerabilities={
            **{category: FakeVulnerability for category in TASK2_CATEGORIES},
            "Bias": EmptyVulnerability,
        },
    )
    adapter = DynamicTestAdapter(api_loader=lambda: api, simulator_model="judge-model")

    cases = adapter.generate(["Bias", "Toxicity"], profile="full", seed=17)

    bias = [case for case in cases if case.category == "Bias"]
    toxicity = [case for case in cases if case.category == "Toxicity"]
    assert len(bias) == 1
    assert bias[0].scenario == "dynamic_test_generation_error"
    assert bias[0].metadata["generation_error"]
    assert bias[0].metadata["returned_variations"] == 0
    assert len(toxicity) == 3


def test_core_judge_client_is_bridged_to_schema_generation() -> None:
    FakeVulnerability.created.clear()
    adapter = DynamicTestAdapter(
        api_loader=fake_api,
        judge_client=StructuredJudgeClient(),
        model_name="custom-openai-compatible-model",
    )

    adapter.generate(["Bias"], profile="quick", seed=5)

    model = FakeVulnerability.created[0]["simulator_model"]
    assert isinstance(model, FakeEvaluationBaseLLM)
    assert model.get_model_name() == "custom-openai-compatible-model"
    assert model.load_model().__class__ is StructuredJudgeClient
    assert (
        model.generate("generate one case")
        == '{"input":"generated through the frozen judge client"}'
    )
    assert model.generate(
        "generate one case", schema=GeneratedSchema
    ) == GeneratedSchema(input="generated through the frozen judge client")


def test_missing_dynamic_engine_is_dependency_error() -> None:
    def missing_api():
        raise ModuleNotFoundError(DYNAMIC_PACKAGE)

    adapter = DynamicTestAdapter(api_loader=missing_api)

    assert adapter.is_available() is False
    with pytest.raises(DependencyError, match="Dynamic test engine is required"):
        adapter.generate(["Bias"], profile="quick", seed=1)
