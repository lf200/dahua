from __future__ import annotations

import pytest

from security_eval.core.config import load_settings
from security_eval.errors import ConfigurationError


def base_env() -> dict[str, str]:
    return {
        "TARGET_BASE_URL": "https://example.test/v1/",
        "TARGET_API_KEY": "secret",
        "TARGET_MODEL": "model-a",
    }


def test_load_settings_uses_target_for_optional_model_defaults(tmp_path) -> None:
    env = base_env() | {"OUTPUT_ROOT": str(tmp_path / "runs")}
    settings = load_settings(env, dotenv_path=None)
    assert settings.target_base_url == "https://example.test/v1"
    assert settings.judge_model == "model-a"
    assert settings.application_security_model == "model-a"
    assert settings.judge_api_key.get_secret_value() == "secret"
    assert "api_key" not in settings.public_summary()


def test_application_security_model_accepts_explicit_value() -> None:
    settings = load_settings(
        base_env() | {"APPLICATION_SECURITY_MODEL": "app-model"},
        dotenv_path=None,
    )
    assert settings.application_security_model == "app-model"
    assert settings.public_summary()["application_security_model"] == "app-model"


def test_missing_key_is_secret_safe() -> None:
    env = base_env()
    del env["TARGET_API_KEY"]
    with pytest.raises(ConfigurationError, match="TARGET_API_KEY"):
        load_settings(env, dotenv_path=None)


def test_invalid_integer_does_not_echo_other_values() -> None:
    env = base_env() | {"TARGET_TIMEOUT_SECONDS": "not-an-int"}
    with pytest.raises(ConfigurationError, match="must be an integer") as caught:
        load_settings(env, dotenv_path=None)
    assert "secret" not in str(caught.value)
