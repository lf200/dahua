from __future__ import annotations

from security_eval.core.redaction import REDACTED, sanitize_value


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
