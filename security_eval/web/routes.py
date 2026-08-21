"""HTTP routes for the Flask web layer.

This module contains only HTTP-boundary logic. It does not run evaluation
modules directly and it does not recalculate any scores.

Responsibilities:
- render the start page;
- validate HTML form input into RunRequest;
- start a background run through RunManager;
- render queued/running/final run pages;
- expose a lightweight polling API;
- return a validated RunReport as downloadable JSON.
"""

from __future__ import annotations

from typing import Any, Mapping

from flask import (
    Blueprint,
    Response,
    abort,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from pydantic import ValidationError

from security_eval.contracts import RunReport, RunRequest
from security_eval.errors import ConfigurationError
from security_eval.web.presentation import (
    TASK_NAMES_ZH,
    build_run_view,
)
from security_eval.web.run_manager import RunManager


# ============================================================
# Public configuration allowed to reach templates
# ============================================================

PUBLIC_SETTING_KEYS = frozenset(
    {
        "target_base_url",
        "target_model",
        "judge_base_url",
        "judge_model",
        "application_security_model",
        "target_timeout_seconds",
        "target_max_tokens",
        "output_root",
    }
)


# ============================================================
# Form defaults / choices
# ============================================================

DEFAULT_FORM: dict[str, Any] = {
    "tasks": [1, 2, 4],
    "mode": "hybrid",
    "profile": "quick",
    "seed": 42,
    "benchmark_version": "v1",
    "authorized_target": False,
}


TASK_CHOICES: tuple[dict[str, Any], ...] = tuple(
    {
        "task_id": task_id,
        "name_zh": TASK_NAMES_ZH[task_id],
    }
    for task_id in (1, 2, 4)
)


MODE_CHOICES: tuple[dict[str, str], ...] = (
    {
        "value": "benchmark",
        "label": "固定 Benchmark",
    },
    {
        "value": "dynamic",
        "label": "动态测试",
    },
    {
        "value": "hybrid",
        "label": "混合测试",
    },
)


PROFILE_CHOICES: tuple[dict[str, str], ...] = (
    {
        "value": "quick",
        "label": "快速模式",
    },
    {
        "value": "full",
        "label": "完整模式",
    },
)


FIELD_LABELS: dict[str, str] = {
    "tasks": "测试任务",
    "mode": "测试模式",
    "profile": "测试规模",
    "seed": "随机种子",
    "benchmark_version": "Benchmark 版本",
    "authorized_target": "目标授权确认",
}


# ============================================================
# Blueprint factory
# ============================================================


def create_routes_blueprint(
    *,
    manager: RunManager,
    public_settings: Mapping[str, Any] | None = None,
) -> Blueprint:
    """Create the web blueprint with explicit dependencies.

    ``public_settings`` must contain only non-secret configuration.

    The application factory should normally pass:

        settings.public_summary()

    Even then, this module applies an allow-list before sending
    configuration to Jinja templates, so API keys cannot accidentally
    reach the browser.
    """

    blueprint = Blueprint(
        "web",
        __name__,
    )

    # Defense in depth:
    # even if the caller accidentally passes a larger dictionary,
    # only explicitly permitted keys reach the template.
    safe_settings = {
        key: value
        for key, value in dict(public_settings or {}).items()
        if key in PUBLIC_SETTING_KEYS
    }

    # ========================================================
    # GET /
    # ========================================================

    @blueprint.get("/")
    def index() -> str:
        """Render the evaluation start page."""

        form_values = dict(DEFAULT_FORM)

        return _render_index(
            manager=manager,
            public_settings=safe_settings,
            form_values=form_values,
            estimate=_estimate_for_form(
                manager,
                form_values,
            ),
            errors=[],
        )

    # ========================================================
    # POST /api/estimate
    # ========================================================

    @blueprint.post("/api/estimate")
    def estimate_api() -> Response | tuple[Response, int]:
        """Return expected case count for the current form selection."""

        form_values = _form_values_from_request()

        try:
            estimate = _estimate_for_form(
                manager,
                form_values,
            )

        except ValidationError as exc:
            return _json_error(
                code="INVALID_REQUEST",
                message="; ".join(_validation_messages(exc)),
                status_code=400,
            )

        return jsonify(estimate)

    # ========================================================
    # POST /runs
    # ========================================================

    @blueprint.post("/runs")
    def start_run() -> Response | tuple[str, int]:
        """Validate the form, start one run and redirect to its page."""

        form_values = _form_values_from_request()

        try:
            run_request = _build_run_request(form_values)

        except ValidationError as exc:
            return (
                _render_index(
                    manager=manager,
                    public_settings=safe_settings,
                    form_values=form_values,
                    estimate=None,
                    errors=(_validation_messages(exc)),
                ),
                400,
            )

        try:
            run_id = manager.start(run_request)

        except ConfigurationError as exc:
            # Example:
            # authorized_target was not confirmed.
            return (
                _render_index(
                    manager=manager,
                    public_settings=safe_settings,
                    form_values=form_values,
                    estimate=None,
                    errors=[str(exc)],
                ),
                400,
            )

        except RuntimeError:
            # RunStorage.acquire_run_lock() raises RuntimeError
            # when another evaluation already owns the single-run lock.
            #
            # Do not expose lock-file internals to the browser.
            return (
                _render_index(
                    manager=manager,
                    public_settings=safe_settings,
                    form_values=form_values,
                    estimate=None,
                    errors=[
                        ("已有测评任务正在运行，请等待当前任务完成后再启动新的测评。")
                    ],
                ),
                409,
            )

        # PRG pattern:
        #
        # POST /runs
        #     ↓
        # 303 redirect
        #     ↓
        # GET /runs/<run_id>
        #
        # Refreshing the result page therefore does not submit
        # another evaluation.
        return redirect(
            url_for(
                "web.run_detail",
                run_id=run_id,
            ),
            code=303,
        )

    # ========================================================
    # GET /runs/<run_id>
    # ========================================================

    @blueprint.get("/runs/<run_id>")
    def run_detail(
        run_id: str,
    ) -> Response:
        """Render queued/running/final state for one run."""

        status = _safe_get_status(
            manager,
            run_id,
        )

        if status is None:
            abort(404)

        report = _safe_get_report(
            manager,
            run_id,
        )

        # presentation.py is only used when a complete
        # RunReport already exists.
        report_view = build_run_view(report) if report is not None else None

        response = make_response(
            render_template(
                "run.html",
                run_id=run_id,
                # Lightweight queued/running/final status.
                status=status,
                # None while queued/running or when a run failed
                # before a complete report could be generated.
                report=report_view,
                # run.html will use this for browser polling.
                poll_url=url_for(
                    "web.run_status_api",
                    run_id=run_id,
                ),
                # Only show the download link after the report exists.
                report_url=(
                    url_for(
                        "web.download_report",
                        run_id=run_id,
                    )
                    if report is not None
                    else None
                ),
            )
        )

        # Evaluation output may contain sensitive evidence.
        response.headers["Cache-Control"] = "no-store"

        return response

    # ========================================================
    # GET /api/runs/<run_id>
    # ========================================================

    @blueprint.get("/api/runs/<run_id>")
    def run_status_api(
        run_id: str,
    ) -> Response | tuple[Response, int]:
        """Return lightweight polling state for one run."""

        status = _safe_get_status(
            manager,
            run_id,
        )

        if status is None:
            return _json_error(
                code="NOT_FOUND",
                message="Run not found",
                status_code=404,
            )

        payload = dict(status)

        # Give the browser stable URLs instead of constructing
        # them in JavaScript.
        payload["page_url"] = url_for(
            "web.run_detail",
            run_id=run_id,
        )

        if payload.get(
            "report_available",
            False,
        ):
            payload["report_url"] = url_for(
                "web.download_report",
                run_id=run_id,
            )

        response = jsonify(payload)

        response.headers["Cache-Control"] = "no-store"

        return response

    # ========================================================
    # GET /runs/<run_id>/report.json
    # ========================================================

    @blueprint.get("/runs/<run_id>/report.json")
    def download_report(
        run_id: str,
    ) -> Response | tuple[Response, int]:
        """Download one validated RunReport as JSON."""

        # First distinguish:
        #
        # unknown run
        #
        # from:
        #
        # known run whose report is still being generated.
        status = _safe_get_status(
            manager,
            run_id,
        )

        if status is None:
            return _json_error(
                code="NOT_FOUND",
                message="Run not found",
                status_code=404,
            )

        report = _safe_get_report(
            manager,
            run_id,
        )

        if report is None:
            return _json_error(
                code="REPORT_NOT_READY",
                message=("Run report is not available yet"),
                status_code=409,
            )

        # The report has already passed RunReport validation
        # inside storage.py / run_manager.py.
        #
        # Serialize the contract object rather than blindly serving
        # arbitrary filesystem content.
        body = (
            report.model_dump_json(
                indent=2,
            )
            + "\n"
        )

        response = Response(
            body,
            status=200,
            mimetype="application/json",
        )

        response.headers["Content-Disposition"] = (
            f'attachment; filename="{run_id}-report.json"'
        )

        response.headers["Cache-Control"] = "no-store"

        response.headers["X-Content-Type-Options"] = "nosniff"

        return response

    return blueprint


# ============================================================
# Form helpers
# ============================================================


def _form_values_from_request() -> dict[str, Any]:
    """Read the HTML form while keeping values safe for redisplay."""

    tasks = request.form.getlist("tasks")

    return {
        "tasks": tasks,
        "mode": request.form.get(
            "mode",
            DEFAULT_FORM["mode"],
        ),
        "profile": request.form.get(
            "profile",
            DEFAULT_FORM["profile"],
        ),
        "seed": request.form.get(
            "seed",
            str(DEFAULT_FORM["seed"]),
        ),
        "benchmark_version": request.form.get(
            "benchmark_version",
            DEFAULT_FORM["benchmark_version"],
        ),
        "authorized_target": _checkbox_checked(request.form.get("authorized_target")),
    }


def _build_run_request(
    form_values: Mapping[str, Any],
) -> RunRequest:
    """Convert form values into the public RunRequest contract."""

    # -----------------------------
    # seed
    # -----------------------------

    seed = form_values.get(
        "seed",
        DEFAULT_FORM["seed"],
    )

    if isinstance(
        seed,
        str,
    ):
        seed = seed.strip()

        # Empty seed means:
        # use the default reproducible seed.
        if not seed:
            seed = DEFAULT_FORM["seed"]

    # -----------------------------
    # benchmark version
    # -----------------------------

    benchmark_version = str(
        form_values.get(
            "benchmark_version",
            DEFAULT_FORM["benchmark_version"],
        )
    ).strip()

    if not benchmark_version:
        benchmark_version = str(DEFAULT_FORM["benchmark_version"])

    # -----------------------------
    # tasks
    # -----------------------------

    raw_tasks = list(
        form_values.get(
            "tasks",
            [],
        )
    )

    tasks: list[Any] = []

    for item in raw_tasks:
        text = str(item).strip()

        try:
            tasks.append(int(text))

        except ValueError:
            # Keep an invalid value so Pydantic can return a proper
            # contract validation error instead of us silently
            # dropping it.
            tasks.append(text)

    # -----------------------------
    # authorization
    # -----------------------------

    authorized_value = form_values.get(
        "authorized_target",
        False,
    )

    if isinstance(
        authorized_value,
        str,
    ):
        authorized_target = _checkbox_checked(authorized_value)

    else:
        authorized_target = bool(authorized_value)

    # -----------------------------
    # final contract validation
    # -----------------------------

    return RunRequest.model_validate(
        {
            "tasks": tasks,
            "mode": form_values.get("mode"),
            "profile": form_values.get("profile"),
            "seed": seed,
            "benchmark_version": benchmark_version,
            "authorized_target": authorized_target,
        }
    )


def _checkbox_checked(
    value: str | None,
) -> bool:
    """Interpret common HTML checkbox truthy values."""

    if value is None:
        return False

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _validation_messages(
    exc: ValidationError,
) -> list[str]:
    """Return safe human-readable Pydantic validation messages."""

    messages: list[str] = []

    for item in exc.errors(
        include_input=False,
        include_url=False,
    ):
        location = item.get(
            "loc",
            (),
        )

        first = str(location[0]) if location else "request"

        label = FIELD_LABELS.get(
            first,
            first,
        )

        message = str(
            item.get(
                "msg",
                "输入无效",
            )
        )

        messages.append(f"{label}: {message}")

    return messages or ["提交的测评参数无效。"]


# ============================================================
# Rendering / lookup helpers
# ============================================================


def _render_index(
    *,
    manager: RunManager,
    public_settings: Mapping[str, Any],
    form_values: Mapping[str, Any],
    estimate: dict[str, Any] | None,
    errors: list[str],
) -> str:
    """Render index.html with one consistent context."""

    return render_template(
        "index.html",
        task_choices=TASK_CHOICES,
        mode_choices=MODE_CHOICES,
        profile_choices=PROFILE_CHOICES,
        form=dict(form_values),
        errors=errors,
        estimate=estimate,
        active_run=manager.is_active(),
        public_settings=dict(public_settings),
    )


def _estimate_for_form(
    manager: RunManager,
    form_values: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a safe estimate payload from current form values."""

    run_request = _build_run_request(
        {
            **dict(form_values),
            "authorized_target": False,
        }
    )

    estimates = manager.estimate(run_request)

    tasks = [
        {
            "task_id": item.task_id,
            "name_zh": TASK_NAMES_ZH[item.task_id],
            "expected_cases": item.expected_cases,
            "estimated_seconds": item.estimated_seconds,
            "notes": list(item.notes),
        }
        for item in estimates
    ]

    total_cases = sum(item["expected_cases"] for item in tasks)

    total_seconds = sum(item["estimated_seconds"] for item in tasks)

    return {
        "total_cases": total_cases,
        "estimated_seconds": total_seconds,
        "estimated_minutes": round(
            total_seconds / 60,
            1,
        ),
        "tasks": tasks,
    }


def _safe_get_status(
    manager: RunManager,
    run_id: str,
) -> dict[str, Any] | None:
    """Treat malformed/unknown run IDs as not found."""

    try:
        return manager.get_status(run_id)

    except (
        ValueError,
        FileNotFoundError,
    ):
        return None


def _safe_get_report(
    manager: RunManager,
    run_id: str,
) -> RunReport | None:
    """Return a report or None for malformed/unknown run IDs."""

    try:
        return manager.get_report(run_id)

    except (
        ValueError,
        FileNotFoundError,
    ):
        return None


def _json_error(
    *,
    code: str,
    message: str,
    status_code: int,
) -> tuple[Response, int]:
    """Build a small cache-disabled JSON error response."""

    response = jsonify(
        {
            "error": {
                "code": code,
                "message": message,
            }
        }
    )

    response.headers["Cache-Control"] = "no-store"

    return (
        response,
        status_code,
    )
