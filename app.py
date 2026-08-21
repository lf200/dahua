"""Local entry point for the large-model security evaluation web app."""

from __future__ import annotations

import os
from pathlib import Path

from security_eval.core.config import Settings, load_settings
from security_eval.core.registry import ModuleRegistry
from security_eval.core.service import EvaluationService
from security_eval.core.target import JudgeClient, TargetClient
from security_eval.web.app import create_app


PROJECT_ROOT = Path(__file__).resolve().parent


def build_evaluation_service(settings: Settings | None = None) -> EvaluationService:
    """Build the real service from environment configuration and manifests."""
    settings = settings or load_settings(dotenv_path=PROJECT_ROOT / ".env")
    registry = (
        ModuleRegistry.from_manifests(settings.module_manifest_paths)
        if settings.module_manifest_paths
        else ModuleRegistry.discover(PROJECT_ROOT / "security_eval" / "modules")
    )
    return EvaluationService(
        settings=settings,
        registry=registry,
        target_client=TargetClient.from_settings(settings),
        judge_client=JudgeClient.from_settings(settings),
    )


def build_app(settings: Settings | None = None):
    """Create the Flask app while keeping secrets outside template context."""
    settings = settings or load_settings(dotenv_path=PROJECT_ROOT / ".env")
    service = build_evaluation_service(settings)
    return create_app(
        service=service,
        output_root=settings.output_root,
        public_settings=settings.public_summary(),
    )


def main() -> None:
    application = build_app()
    application.run(
        host=os.environ.get("FLASK_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_PORT", "5000")),
        debug=False,
    )


if __name__ == "__main__":
    main()
