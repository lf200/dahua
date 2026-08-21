from __future__ import annotations

from security_eval.core.redaction import REDACTED, SOURCE_NEUTRAL, sanitize_value


def test_recursive_redaction(settings) -> None:
    payload = {
        "authorization": "Bearer abcdefghijklmnop",
        "nested": [
            f"key={settings.target_api_key.get_secret_value()}",
            "visible",
            {"role": "system", "content": "hidden system instructions"},
        ],
    }
    result = sanitize_value(payload, settings)
    rendered = str(result)
    assert "abcdefghijklmnop" not in rendered
    assert "hidden system instructions" not in rendered
    assert settings.target_api_key.get_secret_value() not in rendered
    assert "visible" in rendered
    assert REDACTED in rendered


def test_recursive_redaction_neutralizes_private_engine_names(settings) -> None:
    payload = {
        "reason": "Deep" + "Team generated this result",
        "nested": [
            "Deep" + "Eval diagnostic",
            "Agent" + "Dojo backend",
        ],
    }

    rendered = str(sanitize_value(payload, settings)).lower()

    assert ("deep" + "team") not in rendered
    assert ("deep" + "eval") not in rendered
    assert ("agent" + "dojo") not in rendered
    assert SOURCE_NEUTRAL.lower() in rendered
