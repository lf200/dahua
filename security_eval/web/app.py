"""Flask application factory for the security evaluation web UI.

The web layer depends only on the public EvaluationService interface and
contract objects. It must not import Task1, Task2, Task4, DeepTeam, or
AgentDojo implementation classes.

Typical usage:

    app = create_app(
        service=evaluation_service,
        output_root="data/runs",
        public_settings={...},
    )

Tests can inject a fake service:

    app = create_app(
        service=fake_service,
        output_root=temp_dir,
        testing=True,
    )
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from flask import Flask, Response, render_template

from security_eval.web.routes import create_routes_blueprint
from security_eval.web.run_manager import RunManager
from security_eval.web.storage import RunStorage


# ============================================================
# Defaults
# ============================================================

DEFAULT_OUTPUT_ROOT = Path("data/runs")


# ============================================================
# Application factory
# ============================================================


def create_app(
    *,
    service: Any,
    output_root: str | Path = DEFAULT_OUTPUT_ROOT,
    public_settings: Mapping[str, Any] | None = None,
    testing: bool = False,
) -> Flask:
    """Create and configure the Flask application.

    Parameters
    ----------
    service:
        Public evaluation service object.

        The object is expected to provide the interface consumed by
        ``RunManager``. In the real application this should be A's
        ``EvaluationService``.

        In tests it may be a fake service.

    output_root:
        Same run output directory used by EvaluationService.

        Example:

            data/runs

    public_settings:
        Non-secret configuration safe for browser display.

        Do NOT pass API keys here.

    testing:
        Enable Flask TESTING mode.

    Returns
    -------
    Flask
        Fully configured Flask application.
    """

    if service is None:
        raise ValueError("create_app() requires an evaluation service")

    # --------------------------------------------------------
    # Create Flask application
    # --------------------------------------------------------

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    app.config.update(
        TESTING=bool(testing),
        # Keep JSON output order predictable.
        JSON_SORT_KEYS=False,
        # Jinja autoescaping remains enabled by Flask for HTML.
    )

    # --------------------------------------------------------
    # Web persistence
    # --------------------------------------------------------

    storage = RunStorage(output_root)

    # Recover stale "queued" / "running" state after a process
    # restart.
    #
    # Example:
    #
    #   application crashes
    #       ↓
    #   status.json still says "running"
    #       ↓
    #   application restarts
    #       ↓
    #   no final report exists
    #       ↓
    #   mark the stale run as failed
    #
    # This prevents the browser from displaying a run as
    # "running" forever.
    storage.recover_after_restart()

    # --------------------------------------------------------
    # Background run manager
    # --------------------------------------------------------

    manager = RunManager(
        service=service,
        storage=storage,
    )

    # --------------------------------------------------------
    # Store dependencies on Flask application
    # --------------------------------------------------------
    #
    # Do not use module-level global variables.
    #
    # app.extensions gives us:
    #
    # - isolated test applications;
    # - easy FakeService injection;
    # - multiple app instances;
    # - explicit dependency ownership.
    # --------------------------------------------------------

    app.extensions["security_eval.storage"] = storage

    app.extensions["security_eval.run_manager"] = manager

    app.extensions["security_eval.service"] = service

    # --------------------------------------------------------
    # Register HTTP routes
    # --------------------------------------------------------

    web_blueprint = create_routes_blueprint(
        manager=manager,
        public_settings=(public_settings or {}),
    )

    app.register_blueprint(web_blueprint)

    # --------------------------------------------------------
    # Error handlers
    # --------------------------------------------------------

    _register_error_handlers(app)

    # --------------------------------------------------------
    # Browser security headers
    # --------------------------------------------------------

    _register_response_headers(app)

    return app


# ============================================================
# Error pages
# ============================================================


def _register_error_handlers(
    app: Flask,
) -> None:
    """Register safe HTTP error pages."""

    @app.errorhandler(404)
    def not_found(
        _error: Exception,
    ) -> tuple[str, int]:
        return (
            render_template(
                "error.html",
                status_code=404,
                title="页面不存在",
                message=("没有找到你请求的测评页面或运行记录。"),
            ),
            404,
        )

    @app.errorhandler(405)
    def method_not_allowed(
        _error: Exception,
    ) -> tuple[str, int]:
        return (
            render_template(
                "error.html",
                status_code=405,
                title="请求方式不允许",
                message=("当前页面不支持这种请求方式。"),
            ),
            405,
        )

    @app.errorhandler(500)
    def internal_error(
        _error: Exception,
    ) -> tuple[str, int]:
        """Do not expose Python stack traces in production pages."""

        return (
            render_template(
                "error.html",
                status_code=500,
                title="系统错误",
                message=("Web 层处理请求时发生错误，请查看本地日志或重新运行测评。"),
            ),
            500,
        )


# ============================================================
# Response headers
# ============================================================


def _register_response_headers(
    app: Flask,
) -> None:
    """Add small browser-side hardening headers."""

    @app.after_request
    def add_security_headers(
        response: Response,
    ) -> Response:
        response.headers.setdefault(
            "X-Content-Type-Options",
            "nosniff",
        )

        response.headers.setdefault(
            "X-Frame-Options",
            "DENY",
        )

        response.headers.setdefault(
            "Referrer-Policy",
            "same-origin",
        )

        # Current frontend design is fully local:
        #
        # - no CDN
        # - no npm
        # - no external JavaScript
        # - no external CSS
        #
        # run.html will contain a very small inline polling
        # script, therefore inline JavaScript is currently
        # allowed.
        response.headers.setdefault(
            "Content-Security-Policy",
            (
                "default-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "script-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "object-src 'none'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            ),
        )

        return response
