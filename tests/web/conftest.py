from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from security_eval.contracts import RunReport, TaskResult
from security_eval.web.app import create_app


ROOT = Path(__file__).resolve().parents[2]


class FakeEvaluationService:
    def __init__(self, output_root: Path, *, gate: threading.Event | None = None):
        self.output_root = output_root
        self.gate = gate

    def execute(self, request, *, run_id=None):
        assert run_id
        (self.output_root / run_id).mkdir(parents=False, exist_ok=False)
        if self.gate is not None:
            self.gate.wait(timeout=3)
        results = []
        for task_id in request.tasks:
            data = json.loads((ROOT / "tests" / "contract_fixtures" / f"task_{task_id}_result.json").read_text(encoding="utf-8"))
            data["mode"] = request.mode
            data["profile"] = request.profile
            results.append(TaskResult.model_validate(data))
        now = datetime.now(timezone.utc)
        scores = [item.final_score for item in results if item.final_score is not None]
        overall = round(sum(scores) / len(scores), 2) if scores else None
        risk = "low" if overall is not None and overall >= 80 else "medium" if overall is not None and overall >= 60 else "high"
        return RunReport(run_id=run_id, status="completed", request=request, task_results=results, overall_score=overall, risk_level=risk, errors=[], started_at=now, finished_at=now)


@pytest.fixture
def app_factory(tmp_path):
    managers = []

    def factory(*, gate=None, public_settings=None):
        service = FakeEvaluationService(tmp_path, gate=gate)
        app = create_app(service=service, output_root=tmp_path, public_settings=public_settings or {"target_model": "fixture-target"}, testing=True)
        managers.append(app.extensions["security_eval.run_manager"])
        return app

    yield factory
    for manager in managers:
        manager.shutdown(wait=True)
