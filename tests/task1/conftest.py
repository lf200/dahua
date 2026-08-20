from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from security_eval.contracts import RunContext


class RecordingTarget:
    def __init__(self, *, fail_on: str | None = None, output: str = "I recognize the conflict and refuse it safely.") -> None:
        self.fail_on = fail_on
        self.output = output
        self.calls: list[list[dict[str, Any]]] = []

    def complete(self, messages: list[dict[str, Any]]) -> str:
        copied = [dict(message) for message in messages]
        self.calls.append(copied)
        joined = " ".join(str(message.get("content", "")) for message in messages)
        if self.fail_on and self.fail_on in joined:
            raise RuntimeError("target failed with Bearer secret-token")
        if messages and "recovery" in str(messages[-1].get("metadata", "")):
            return "The benign recovery answer is available."
        return self.output


class RubricJudge:
    def __init__(self, *, low_category: str | None = None, malformed: bool = False) -> None:
        self.low_category = low_category
        self.malformed = malformed
        self.calls: list[list[dict[str, Any]]] = []

    def complete(self, messages: list[dict[str, Any]]) -> str:
        self.calls.append([dict(message) for message in messages])
        if self.malformed:
            return "not-json"
        prompt = str(messages[-1]["content"])
        value = 0.5 if self.low_category and f'"category": "{self.low_category}"' in prompt else 1
        return (
            '{"recognition": %s, "blocking": %s, "recovery": 1, '
            '"reason": "Bearer secret-token was handled"}' % (value, value)
        )


def recursive_sanitizer(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("secret-token", "[REDACTED]")
    if isinstance(value, dict):
        return {key: recursive_sanitizer(item) for key, item in value.items()}
    if isinstance(value, list):
        return [recursive_sanitizer(item) for item in value]
    return value


@pytest.fixture
def context_factory(tmp_path: Path):
    def factory(
        *,
        target: object | None = None,
        judge: object | None = None,
        sanitizer=recursive_sanitizer,
    ) -> RunContext:
        return RunContext(
            settings=object(),
            target_client=target or RecordingTarget(),
            judge_client=judge or RubricJudge(),
            artifact_dir=tmp_path.resolve(),
            deadline=datetime.now(timezone.utc) + timedelta(minutes=5),
            sanitize_value=sanitizer,
        )

    return factory
