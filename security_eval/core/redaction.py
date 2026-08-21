"""Recursive redaction applied before persistence or presentation."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, SecretStr

from security_eval.core.config import Settings

REDACTED = "[REDACTED]"
SOURCE_NEUTRAL = "[PRIVATE_ENGINE]"
SENSITIVE_KEYS = {
    "api_key",
    "authorization",
    "bearer",
    "secret",
    "token",
    "password",
    "system_prompt",
    "system_message",
}
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+\-/]+=*")
SK_PATTERN = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
PRIVATE_ENGINE_PATTERN = re.compile(
    r"(?:deep[\s._-]*team|deep[\s._-]*eval|agent[\s._-]*dojo)",
    re.IGNORECASE,
)


def _secret_values(settings: Settings | None) -> tuple[str, ...]:
    if settings is None:
        return ()
    values = {
        settings.target_api_key.get_secret_value(),
        settings.judge_api_key.get_secret_value(),
    }
    return tuple(sorted((value for value in values if value), key=len, reverse=True))


def redact_text(text: str, settings: Settings | None = None) -> str:
    result = PRIVATE_ENGINE_PATTERN.sub(SOURCE_NEUTRAL, text)
    result = BEARER_PATTERN.sub(f"Bearer {REDACTED}", result)
    result = SK_PATTERN.sub(REDACTED, result)
    for secret in _secret_values(settings):
        result = result.replace(secret, REDACTED)
    return result


def neutralize_source_value(value: Any) -> Any:
    """Remove private engine identities from values crossing public boundaries."""

    if isinstance(value, str):
        return PRIVATE_ENGINE_PATTERN.sub(SOURCE_NEUTRAL, value)
    if isinstance(value, Mapping):
        return {
            str(neutralize_source_value(str(key))): neutralize_source_value(item)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [neutralize_source_value(item) for item in value]
    if isinstance(value, set):
        return sorted(neutralize_source_value(item) for item in value)
    return value


def _is_sensitive_key(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return normalized in SENSITIVE_KEYS or normalized.endswith(
        ("_api_key", "_password", "_secret", "_token")
    )


def sanitize_value(value: Any, settings: Settings | None = None) -> Any:
    if isinstance(value, SecretStr):
        return REDACTED
    if isinstance(value, str):
        return redact_text(value, settings)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="python")
    elif is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)

    if isinstance(value, Mapping):
        role_is_system = str(value.get("role", "")).lower() == "system"
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            neutral_key = str(neutralize_source_value(str(key)))
            if _is_sensitive_key(key) or (role_is_system and str(key).lower() == "content"):
                sanitized[neutral_key] = REDACTED
            else:
                sanitized[neutral_key] = sanitize_value(item, settings)
        return sanitized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [sanitize_value(item, settings) for item in value]
    if isinstance(value, set):
        return sorted(sanitize_value(item, settings) for item in value)
    return value


def build_sanitizer(settings: Settings):
    return lambda value: sanitize_value(value, settings)
