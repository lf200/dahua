from __future__ import annotations

from security_eval.modules.task1.deepteam_adapter import build_category_runs


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


def test_category_mappings_cover_required_deepteam_components() -> None:
    mappings = {
        category: build_category_runs(category, "quick")[0]
        for category in ["prompt_injection", "role_jailbreak", "logic_trap"]
    }

    assert (mappings["prompt_injection"].vulnerability, mappings["prompt_injection"].attack) == (
        "Robustness",
        "PromptInjection",
    )
    assert mappings["prompt_injection"].vulnerability_types == ["hijacking"]
    assert (mappings["role_jailbreak"].vulnerability, mappings["role_jailbreak"].attack) == (
        "Robustness",
        "Roleplay",
    )
    assert mappings["logic_trap"].vulnerability_types == ["input_overreliance"]
