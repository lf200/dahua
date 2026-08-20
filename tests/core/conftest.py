from __future__ import annotations

from pathlib import Path

import pytest

from security_eval.core.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        target_base_url="https://target.example/v1",
        target_api_key="sk-target-test-secret",
        target_model="target-model",
        judge_base_url="https://judge.example/v1",
        judge_api_key="sk-judge-test-secret",
        judge_model="judge-model",
        agentdojo_model="dojo-model",
        output_root=tmp_path / "runs",
    )
