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


def test_load_settings_uses_target_for_judge_defaults(tmp_path) -> None:
    env = base_env() | {"OUTPUT_ROOT": str(tmp_path / "runs")}
    settings = load_settings(env, dotenv_path=None)
    assert settings.target_base_url == "https://example.test/v1"
    assert settings.judge_model == "model-a"
    assert settings.judge_api_key.get_secret_value() == "secret"
    assert "api_key" not in settings.public_summary()


@pytest.mark.parametrize("key", [None, "", "   "])
def test_target_key_is_optional(key) -> None:
    env = base_env()
    if key is None:
        del env["TARGET_API_KEY"]
    else:
        env["TARGET_API_KEY"] = key
    settings = load_settings(env, dotenv_path=None)
    assert settings.target_api_key.get_secret_value() == ""
    assert settings.judge_api_key.get_secret_value() == ""


def test_explicit_blank_judge_key_disables_auth() -> None:
    settings = load_settings(base_env() | {"JUDGE_API_KEY": ""}, dotenv_path=None)
    assert settings.target_api_key.get_secret_value() == "secret"
    assert settings.judge_api_key.get_secret_value() == ""


def test_keyless_target_can_use_authenticated_judge() -> None:
    settings = load_settings(
        base_env() | {"TARGET_API_KEY": "", "JUDGE_API_KEY": "judge-secret"},
        dotenv_path=None,
    )
    assert settings.target_api_key.get_secret_value() == ""
    assert settings.judge_api_key.get_secret_value() == "judge-secret"


@pytest.mark.parametrize("name", ["TARGET_BASE_URL", "TARGET_MODEL"])
def test_required_configuration_is_still_secret_safe(name) -> None:
    env = base_env()
    del env[name]
    with pytest.raises(ConfigurationError, match=name) as caught:
        load_settings(env, dotenv_path=None)
    assert "secret" not in str(caught.value)


def test_invalid_integer_does_not_echo_other_values() -> None:
    env = base_env() | {"TARGET_TIMEOUT_SECONDS": "not-an-int"}
    with pytest.raises(ConfigurationError, match="must be an integer") as caught:
        load_settings(env, dotenv_path=None)
    assert "secret" not in str(caught.value)
