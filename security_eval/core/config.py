"""Read-only application settings loaded from environment variables."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping
from urllib.parse import urlparse

from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from security_eval.errors import ConfigurationError


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target_base_url: str
    target_api_key: SecretStr
    target_model: str
    judge_base_url: str
    judge_api_key: SecretStr
    judge_model: str
    agentdojo_model: str
    target_timeout_seconds: int = Field(default=60, ge=1, le=600)
    target_max_tokens: int = Field(default=1024, ge=1, le=32768)
    quick_timeout_seconds: int = Field(default=900, ge=30, le=7200)
    full_timeout_seconds: int = Field(default=2700, ge=60, le=14400)
    output_root: Path = Path("data/runs")
    module_manifest_paths: tuple[Path, ...] = ()

    @field_validator("target_base_url", "judge_base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        cleaned = value.rstrip("/")
        parsed = urlparse(cleaned)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base URL must be an absolute HTTP(S) URL")
        if parsed.query or parsed.fragment:
            raise ValueError("base URL must not include a query or fragment")
        return cleaned

    @field_validator("target_model", "judge_model", "agentdojo_model")
    @classmethod
    def model_names_must_be_nonempty(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("model name cannot be empty")
        return cleaned

    @field_validator("output_root")
    @classmethod
    def resolve_output_root(cls, value: Path) -> Path:
        return value.resolve()

    @field_validator("module_manifest_paths")
    @classmethod
    def resolve_manifest_paths(cls, value: tuple[Path, ...]) -> tuple[Path, ...]:
        return tuple(path.resolve() for path in value)

    def public_summary(self) -> dict[str, object]:
        return {
            "target_base_url": self.target_base_url,
            "target_model": self.target_model,
            "judge_base_url": self.judge_base_url,
            "judge_model": self.judge_model,
            "agentdojo_model": self.agentdojo_model,
            "target_timeout_seconds": self.target_timeout_seconds,
            "target_max_tokens": self.target_max_tokens,
            "output_root": str(self.output_root),
        }


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"Missing required configuration: {name}")
    return value


def _as_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name, str(default)).strip()
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"Configuration {name} must be an integer") from exc


def load_settings(
    env: Mapping[str, str] | None = None,
    *,
    dotenv_path: str | Path | None = ".env",
) -> Settings:
    if env is None:
        if dotenv_path is not None:
            load_dotenv(dotenv_path=dotenv_path, override=False)
        env = os.environ

    target_key = _required(env, "TARGET_API_KEY")
    target_url = _required(env, "TARGET_BASE_URL")
    judge_key = env.get("JUDGE_API_KEY", "").strip() or target_key
    judge_url = env.get("JUDGE_BASE_URL", "").strip() or target_url
    manifests = tuple(
        Path(item.strip())
        for item in env.get("MODULE_MANIFEST_PATHS", "").split(os.pathsep)
        if item.strip()
    )

    try:
        return Settings(
            target_base_url=target_url,
            target_api_key=target_key,
            target_model=_required(env, "TARGET_MODEL"),
            judge_base_url=judge_url,
            judge_api_key=judge_key,
            judge_model=env.get("JUDGE_MODEL", "").strip() or _required(env, "TARGET_MODEL"),
            agentdojo_model=env.get("AGENTDOJO_MODEL", "").strip() or _required(env, "TARGET_MODEL"),
            target_timeout_seconds=_as_int(env, "TARGET_TIMEOUT_SECONDS", 60),
            target_max_tokens=_as_int(env, "TARGET_MAX_TOKENS", 1024),
            quick_timeout_seconds=_as_int(env, "QUICK_TIMEOUT_SECONDS", 900),
            full_timeout_seconds=_as_int(env, "FULL_TIMEOUT_SECONDS", 2700),
            output_root=Path(env.get("OUTPUT_ROOT", "data/runs")),
            module_manifest_paths=manifests,
        )
    except ConfigurationError:
        raise
    except Exception as exc:
        raise ConfigurationError("Invalid application configuration") from exc
