"""Presentation helpers for the Flask web layer.

This module converts contract objects into plain, read-only dictionaries that
Jinja templates can render safely.

Important:
- This module does NOT recalculate benchmark scores.
- This module does NOT recalculate dynamic scores.
- This module does NOT recalculate final scores.
- This module does NOT recalculate the overall score.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from security_eval.contracts import (
    CaseResult,
    ErrorInfo,
    Evidence,
    RunReport,
    TaskResult,
)


# ============================================================
# Display constants
# ============================================================

TASK_NAMES: dict[int, str] = {
    1: "Adversarial Attack Security",
    2: "Content Safety",
    4: "LLM Application Security",
}

TASK_NAMES_ZH: dict[int, str] = {
    1: "对抗攻击安全",
    2: "内容安全",
    4: "大模型应用安全",
}


STATUS_LABELS_ZH: dict[str, str] = {
    "passed": "通过",
    "failed": "失败",
    "partial": "部分通过",
    "invalid": "无效",
    "completed": "已完成",
    "running": "运行中",
    "partial_run": "部分完成",
    "failed_run": "运行失败",
}


RISK_LABELS_ZH: dict[str, str] = {
    "low": "低风险",
    "medium": "中风险",
    "high": "高风险",
    "critical": "严重风险",
    "unknown": "未知",
}


# ============================================================
# Internal helpers
# ============================================================


def _iso(value: datetime | None) -> str | None:
    """Convert datetime to ISO-8601 text for templates."""
    if value is None:
        return None

    return value.isoformat()


def _plain(value: Any) -> Any:
    """Convert Pydantic/datetime/container values to simple Python objects."""

    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")

    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [_plain(item) for item in value]

    if isinstance(value, datetime):
        return value.isoformat()

    return value


def _build_error_view(
    error: ErrorInfo | None,
) -> dict[str, Any] | None:
    """Convert ErrorInfo to a plain dictionary."""

    if error is None:
        return None

    return {
        "code": error.code,
        "message": error.message,
        "retryable": error.retryable,
        "case_id": error.case_id,
        "details": _plain(error.details),
    }


def _build_evidence_view(
    evidence: Evidence,
) -> dict[str, Any]:
    """Convert Evidence into a template-friendly object."""

    return {
        "kind": evidence.kind,
        "summary": evidence.summary,
        "data": _plain(evidence.data),
        "artifact_path": evidence.artifact_path,
        "redacted": evidence.redacted,
    }


def _percent(
    value: float,
) -> float:
    """Round percentages consistently for report cards."""

    return round(
        value,
        2,
    )


def _mean(
    values: list[float],
) -> float | None:
    if not values:
        return None

    return _percent(sum(values) / len(values))


def _build_application_security_metrics(
    cases: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Summarize application security case-level metrics for direct display."""

    valid_attack_cases = [
        case
        for case in cases
        if (
            case["status"] != "invalid"
            and case["metadata"].get("attack")
            not in {
                None,
                "none",
            }
        )
    ]

    if not valid_attack_cases:
        return []

    targeted_successes = sum(
        1
        for case in valid_attack_cases
        if float(
            case["scores"].get(
                "targeted_asr",
                0.0,
            )
        )
        >= 100.0
    )

    unauthorized_calls = sum(
        int(
            case["metadata"].get(
                "unauthorized_tool_calls",
                0,
            )
        )
        for case in valid_attack_cases
    )

    sensitive_calls = sum(
        int(
            case["metadata"].get(
                "sensitive_tool_calls",
                0,
            )
        )
        for case in valid_attack_cases
    )

    leakages = sum(
        1
        for case in valid_attack_cases
        if float(
            case["scores"].get(
                "leakage_rate",
                0.0,
            )
        )
        >= 100.0
    )

    dos_cases = [
        case for case in valid_attack_cases if case["metadata"].get("attack") == "dos"
    ]

    dos_interruptions = sum(
        1
        for case in dos_cases
        if float(
            case["scores"].get(
                "dos_interruption_rate",
                0.0,
            )
        )
        >= 100.0
    )

    utility_losses = [
        float(case["scores"]["defense_utility_loss"])
        for case in cases
        if "defense_utility_loss" in case["scores"]
    ]

    return [
        {
            "label": "Targeted ASR",
            "value": _percent(100.0 * targeted_successes / len(valid_attack_cases)),
            "suffix": "%",
        },
        {
            "label": "未授权工具调用率",
            "value": _percent(100.0 * unauthorized_calls / sensitive_calls)
            if sensitive_calls
            else 0.0,
            "suffix": "%",
        },
        {
            "label": "泄露率",
            "value": _percent(100.0 * leakages / len(valid_attack_cases)),
            "suffix": "%",
        },
        {
            "label": "DoS 中断率",
            "value": _percent(100.0 * dos_interruptions / len(dos_cases))
            if dos_cases
            else 0.0,
            "suffix": "%",
        },
        {
            "label": "防御效用损失",
            "value": _mean(utility_losses) if utility_losses else None,
            "suffix": "%",
        },
    ]


# ============================================================
# Case presentation
# ============================================================


def build_case_view(
    case: CaseResult,
) -> dict[str, Any]:
    """Convert one CaseResult into data that Jinja can display directly."""

    score_items = [
        {
            "name": name,
            "value": value,
        }
        for name, value in sorted(case.scores.items())
    ]

    return {
        "case_id": case.case_id,
        "task_id": case.task_id,
        "source": case.source,
        "engine": case.engine,
        "category": case.category,
        "scenario": case.scenario,
        "status": case.status,
        "status_label": STATUS_LABELS_ZH.get(
            case.status,
            case.status,
        ),
        # Used later by the result page to highlight problems.
        "is_problem": case.status
        in {
            "failed",
            "partial",
            "invalid",
        },
        # Keep both dictionary form and list form.
        # Dictionary form is convenient for special metrics.
        # List form is convenient for generic HTML rendering.
        "scores": dict(case.scores),
        "score_items": score_items,
        "reason": case.reason,
        "input": _plain(case.input),
        "output": _plain(case.output),
        "evidence": [_build_evidence_view(item) for item in case.evidence],
        "duration_ms": case.duration_ms,
        "error": _build_error_view(case.error),
        "metadata": _plain(case.metadata),
        # Task 2 can explicitly mark over-refusal in metadata.
        "over_refusal": bool(
            case.metadata.get(
                "over_refusal",
                False,
            )
        ),
    }


# ============================================================
# Task presentation
# ============================================================


def build_task_view(
    task: TaskResult,
) -> dict[str, Any]:
    """Convert one TaskResult into a read-only page ViewModel.

    Existing task scores are only displayed here.
    They are never recalculated.
    """

    cases = [build_case_view(case) for case in task.cases]

    # Counts are only UI statistics.
    # They do not participate in security scoring.
    counts = {
        "total": len(cases),
        "passed": sum(1 for case in task.cases if case.status == "passed"),
        "failed": sum(1 for case in task.cases if case.status == "failed"),
        "partial": sum(1 for case in task.cases if case.status == "partial"),
        "invalid": sum(1 for case in task.cases if case.status == "invalid"),
    }

    categories = [
        {
            "category": summary.category,
            "valid_cases": summary.valid_cases,
            "invalid_cases": summary.invalid_cases,
            "passed_cases": summary.passed_cases,
            "failed_cases": summary.failed_cases,
            # Directly use the category score produced by the task module.
            "score": summary.score,
        }
        for summary in task.category_summaries
    ]

    problems = [case for case in cases if case["is_problem"]]

    return {
        "task_id": task.task_id,
        "name": TASK_NAMES.get(
            task.task_id,
            f"Task {task.task_id}",
        ),
        "name_zh": TASK_NAMES_ZH.get(
            task.task_id,
            f"任务 {task.task_id}",
        ),
        "module_version": task.module_version,
        "benchmark_version": task.benchmark_version,
        "mode": task.mode,
        "profile": task.profile,
        # -----------------------------
        # Important:
        # directly consume module scores.
        # -----------------------------
        "benchmark_score": task.benchmark_score,
        "dynamic_score": task.dynamic_score,
        "final_score": task.final_score,
        "risk_level": task.risk_level,
        "risk_label": RISK_LABELS_ZH.get(
            task.risk_level,
            task.risk_level,
        ),
        "counts": counts,
        "categories": categories,
        "application_security_metrics": (_build_application_security_metrics(cases) if task.task_id == 4 else []),
        "cases": cases,
        # Failed / partial / invalid cases shown together on the page.
        "problems": problems,
        "errors": [_build_error_view(error) for error in task.errors],
        "started_at": _iso(task.started_at),
        "finished_at": _iso(task.finished_at),
    }


# ============================================================
# Whole-run presentation
# ============================================================


def build_run_view(
    report: RunReport,
) -> dict[str, Any]:
    """Convert RunReport into the ViewModel consumed by run.html."""

    tasks = [build_task_view(task) for task in report.task_results]

    # Only counting cases for UI display.
    # No security score is recalculated here.
    case_counts = {
        "total": sum(task["counts"]["total"] for task in tasks),
        "passed": sum(task["counts"]["passed"] for task in tasks),
        "failed": sum(task["counts"]["failed"] for task in tasks),
        "partial": sum(task["counts"]["partial"] for task in tasks),
        "invalid": sum(task["counts"]["invalid"] for task in tasks),
    }

    # Merge problem cases from all three tasks
    # so the page can have a "发现的问题" section.
    problems: list[dict[str, Any]] = []

    for task in tasks:
        for case in task["problems"]:
            problems.append(
                {
                    "task_id": task["task_id"],
                    "task_name": task["name_zh"],
                    **case,
                }
            )

    if report.status == "completed":
        status_label = STATUS_LABELS_ZH["completed"]

    elif report.status == "partial":
        status_label = STATUS_LABELS_ZH["partial_run"]

    else:
        status_label = STATUS_LABELS_ZH["failed_run"]

    return {
        "run_id": report.run_id,
        "status": report.status,
        "status_label": status_label,
        # Again: do NOT recalculate.
        "overall_score": report.overall_score,
        "risk_level": report.risk_level,
        "risk_label": RISK_LABELS_ZH.get(
            report.risk_level,
            report.risk_level,
        ),
        "request": {
            "tasks": list(report.request.tasks),
            "mode": report.request.mode,
            "profile": report.request.profile,
            "seed": report.request.seed,
            "benchmark_version": report.request.benchmark_version,
            "authorized_target": report.request.authorized_target,
        },
        "tasks": tasks,
        "case_counts": case_counts,
        "problems": problems,
        "errors": [_build_error_view(error) for error in report.errors],
        "started_at": _iso(report.started_at),
        "finished_at": _iso(report.finished_at),
    }
