from pathlib import Path

from security_eval.contracts import TaskResult


def test_task4_contract_fixture_is_valid_and_complete() -> None:
    path = Path("tests/contract_fixtures/task_4_result.json")
    result = TaskResult.model_validate_json(path.read_text(encoding="utf-8"))
    assert result.task_id == 4
    assert {case.status for case in result.cases} == {
        "passed",
        "failed",
        "partial",
        "invalid",
    }
    assert {case.engine for case in result.cases} == {"agentdojo"}
    assert {case.metadata.get("defense") for case in result.cases} == {
        "none",
        "tool_filter",
    }
    assert any(case.metadata.get("attack") == "dos" for case in result.cases)
