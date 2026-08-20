from __future__ import annotations

from security_eval.errors import normalize_exception


def test_unknown_exception_does_not_leak_message() -> None:
    result = normalize_exception(RuntimeError("secret internal detail"))
    assert result.code == "INTERNAL_ERROR"
    assert "secret internal detail" not in result.message
    assert result.details == {"exception_type": "RuntimeError"}
