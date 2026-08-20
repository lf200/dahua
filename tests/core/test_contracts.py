from __future__ import annotations

from datetime import datetime, timezone

import pytest
from jsonschema.validators import Draft202012Validator
from pydantic import TypeAdapter, ValidationError

from scripts.generate_contract_schema import build_schema
from security_eval.contracts import CaseResult, ErrorInfo, RunRequest, TaskResult


def test_run_request_rejects_duplicate_tasks() -> None:
    with pytest.raises(ValidationError):
        RunRequest(tasks=[1, 1], mode="benchmark", profile="quick", authorized_target=True)


def test_invalid_case_requires_error() -> None:
    with pytest.raises(ValidationError):
        CaseResult(
            case_id="invalid-1",
            task_id=1,
            source="benchmark",
            engine="benchmark",
            category="test",
            scenario="invalid case",
            status="invalid",
            reason="invalid",
            duration_ms=0,
        )


def test_task_result_round_trip() -> None:
    now = datetime.now(timezone.utc)
    case = CaseResult(
        case_id="case-1",
        task_id=1,
        source="benchmark",
        engine="benchmark",
        category="prompt-injection",
        scenario="safe fixture",
        status="invalid",
        reason="fixture failure",
        duration_ms=2,
        error=ErrorInfo(code="CASE_ERROR", message="fixture failure"),
    )
    result = TaskResult(
        task_id=1,
        module_version="1.0",
        benchmark_version="v1",
        mode="benchmark",
        profile="quick",
        cases=[case],
        started_at=now,
        finished_at=now,
    )
    payload = result.model_dump_json()
    assert TypeAdapter(TaskResult).validate_json(payload) == result


def test_public_schema_contains_all_top_level_models() -> None:
    schema = build_schema()
    Draft202012Validator.check_schema(schema)
    assert "RunReport" in schema["$defs"]
    assert "TaskResult" in schema["$defs"]
    assert "CaseResult" in schema["$defs"]
