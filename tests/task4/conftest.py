from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from security_eval.contracts import RunContext


@pytest.fixture
def run_context(tmp_path):
    def sanitize(value):
        if isinstance(value, str):
            return value.replace("sk-secret-value", "[REDACTED]")
        if isinstance(value, dict):
            return {key: sanitize(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [sanitize(item) for item in value]
        return value

    return RunContext(
        settings=SimpleNamespace(agentdojo_model="test-model"),
        target_client=SimpleNamespace(
            base_url="https://example.invalid/v1",
            api_key="sk-secret-value",
            timeout_seconds=1,
        ),
        judge_client=object(),
        artifact_dir=tmp_path.resolve(),
        deadline=datetime.now(timezone.utc) + timedelta(minutes=5),
        sanitize_value=sanitize,
    )
