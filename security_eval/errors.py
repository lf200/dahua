"""Standard exception hierarchy and error normalization."""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from .contracts import ErrorCode, ErrorInfo


class EvaluationError(Exception):
    code: ErrorCode = "INTERNAL_ERROR"
    retryable: bool = False

    def __init__(
        self,
        message: str,
        *,
        case_id: str | None = None,
        details: dict[str, Any] | None = None,
        retryable: bool | None = None,
    ) -> None:
        super().__init__(message)
        self.case_id = case_id
        self.details = details or {}
        if retryable is not None:
            self.retryable = retryable

    def to_error_info(self, sanitize_value=lambda value: value) -> ErrorInfo:
        return ErrorInfo(
            code=self.code,
            message=str(sanitize_value(str(self))),
            retryable=self.retryable,
            case_id=self.case_id,
            details=sanitize_value(self.details),
        )


class ConfigurationError(EvaluationError):
    code: ErrorCode = "CONFIG_ERROR"


class DependencyError(EvaluationError):
    code: ErrorCode = "DEPENDENCY_ERROR"


class TargetError(EvaluationError):
    code: ErrorCode = "TARGET_ERROR"
    retryable = True


class EvaluationTimeoutError(EvaluationError):
    code: ErrorCode = "TIMEOUT_ERROR"
    retryable = True


class ParseError(EvaluationError):
    code: ErrorCode = "PARSE_ERROR"


class CaseEvaluationError(EvaluationError):
    code: ErrorCode = "CASE_ERROR"


class ContractError(EvaluationError):
    code: ErrorCode = "CONTRACT_ERROR"


def normalize_exception(exc: Exception, sanitize_value=lambda value: value) -> ErrorInfo:
    if isinstance(exc, EvaluationError):
        return exc.to_error_info(sanitize_value)
    if isinstance(exc, ValidationError):
        return ErrorInfo(
            code="CONTRACT_ERROR",
            message="Contract validation failed",
            details=sanitize_value({"errors": exc.errors(include_input=False, include_url=False)}),
        )
    return ErrorInfo(
        code="INTERNAL_ERROR",
        message="Unexpected internal evaluation error",
        details={"exception_type": type(exc).__name__},
    )
