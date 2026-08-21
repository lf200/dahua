from __future__ import annotations

import threading
import time


VALID_FORM = {
    "tasks": ["1", "2", "4"],
    "mode": "hybrid",
    "profile": "quick",
    "seed": "42",
    "benchmark_version": "v1",
    "authorized_target": "on",
}


def wait_final(client, location):
    api = "/api" + location
    for _ in range(100):
        payload = client.get(api).get_json()
        if payload["status"] in {"completed", "partial", "failed"}:
            return payload
        time.sleep(0.02)
    raise AssertionError("fake run did not finish")


def test_index_and_secret_filter(app_factory):
    app = app_factory(
        public_settings={
            "target_model": "safe-model",
            "target_api_key": "SECRET-DO-NOT-SHOW",
        }
    )
    body = app.test_client().get("/").get_data(as_text=True)
    assert "大模型安全综合测评" in body
    assert "预计测试用例" in body
    assert "110" in body
    assert "safe-model" in body
    assert "SECRET-DO-NOT-SHOW" not in body


def test_estimate_api_updates_for_selection(app_factory):
    app = app_factory()
    response = app.test_client().post(
        "/api/estimate",
        data={
            **VALID_FORM,
            "tasks": ["2"],
            "mode": "benchmark",
            "profile": "quick",
        },
    )
    payload = response.get_json()
    assert response.status_code == 200
    assert payload["total_cases"] == 18
    assert payload["tasks"] == [
        {
            "task_id": 2,
            "name_zh": "内容安全",
            "expected_cases": 18,
            "estimated_seconds": 54,
            "notes": [],
        }
    ]


def test_authorization_is_required(app_factory):
    app = app_factory()
    form = dict(VALID_FORM)
    form.pop("authorized_target")
    response = app.test_client().post("/runs", data=form)
    assert response.status_code == 400
    assert "授权" in response.get_data(as_text=True)


def test_full_fake_flow_and_download(app_factory):
    app = app_factory()
    client = app.test_client()
    response = client.post("/runs", data=VALID_FORM)
    assert response.status_code == 303
    location = response.headers["Location"]
    run_id = location.rsplit("/", 1)[-1]
    wait_final(client, location)
    page = client.get(location)
    body = page.get_data(as_text=True)
    assert page.status_code == 200
    assert "综合安全评分" in body
    assert "对抗攻击安全" in body and "内容安全" in body and "大模型应用安全" in body
    assert "Targeted ASR" in body
    assert "未授权工具调用率" in body
    assert "泄露率" in body
    assert "DoS 中断率" in body
    assert "防御效用损失" in body
    assert "发现的问题" in body and "无效" in body
    download = client.get(f"/runs/{run_id}/report.json")
    assert download.status_code == 200
    assert download.get_json()["run_id"] == run_id
    assert download.headers["Cache-Control"] == "no-store"


def test_single_active_run_returns_conflict(app_factory):
    gate = threading.Event()
    app = app_factory(gate=gate)
    client = app.test_client()
    first = client.post("/runs", data=VALID_FORM)
    assert first.status_code == 303
    second = client.post("/runs", data=VALID_FORM)
    assert second.status_code == 409
    gate.set()
    wait_final(client, first.headers["Location"])


def test_unknown_and_malformed_runs_are_not_found(app_factory):
    client = app_factory().test_client()
    for path in [
        "/runs/notfound1",
        "/api/runs/notfound1",
        "/runs/notfound1/report.json",
        "/runs/%2e%2e",
    ]:
        assert client.get(path).status_code == 404


def test_jinja_escapes_fixture_evidence(app_factory, monkeypatch):
    from tests.web.conftest import FakeEvaluationService

    original = FakeEvaluationService.execute

    def malicious(self, request, *, run_id=None):
        report = original(self, request, run_id=run_id)
        task = report.task_results[0]
        case = task.cases[1].model_copy(update={"reason": "<script>alert(1)</script>"})
        task = task.model_copy(update={"cases": [task.cases[0], case, *task.cases[2:]]})
        return report.model_copy(
            update={"task_results": [task, *report.task_results[1:]]}
        )

    monkeypatch.setattr(FakeEvaluationService, "execute", malicious)
    app = app_factory()
    client = app.test_client()
    response = client.post("/runs", data={**VALID_FORM, "tasks": ["1"]})
    wait_final(client, response.headers["Location"])
    body = client.get(response.headers["Location"]).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
