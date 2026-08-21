from __future__ import annotations

from security_eval.errors import normalize_exception


def test_unknown_exception_does_not_leak_message() -> None:
    result = normalize_exception(RuntimeError("secret internal detail"))
    assert result.code == "INTERNAL_ERROR"
    assert "secret internal detail" not in result.message
    assert result.details == {}


def test_unknown_exception_does_not_leak_vendor_class_name() -> None:
    vendor_name = "Deep" + "TeamBackendError"
    vendor_exception = type(vendor_name, (Exception,), {})

    result = normalize_exception(vendor_exception("private backend detail"))

    assert vendor_name.lower() not in result.model_dump_json().lower()
