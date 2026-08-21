from __future__ import annotations

import time

from tests.web.conftest import FakeEvaluationService
from security_eval.web.app import create_app


def test_browser_journey_uses_only_contract_fixtures(tmp_path):
    service = FakeEvaluationService(tmp_path)
    app = create_app(service=service, output_root=tmp_path, testing=True)
    client = app.test_client()
    assert client.get("/").status_code == 200
    created = client.post(
        "/runs",
        data={
            "tasks": ["1", "2", "4"],
            "mode": "hybrid",
            "profile": "quick",
            "seed": "42",
            "benchmark_version": "v1",
            "authorized_target": "on",
        },
    )
    assert created.status_code == 303
    run_path = created.headers["Location"]
    run_id = run_path.rsplit("/", 1)[-1]
    for _ in range(100):
        state = client.get(f"/api/runs/{run_id}").get_json()
        if state["status"] == "completed":
            break
        time.sleep(0.02)
    else:
        raise AssertionError("run did not complete")
    assert "下载完整 JSON 报告" in client.get(run_path).get_data(as_text=True)
    assert client.get(f"/runs/{run_id}/report.json").get_json()["status"] == "completed"
    app.extensions["security_eval.run_manager"].shutdown(wait=True)
