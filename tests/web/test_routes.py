from __future__ import annotations

import threading
import time
from html.parser import HTMLParser

import pytest

from security_eval.core.config import Settings
from security_eval.core.registry import ModuleRegistry
from security_eval.core.service import EvaluationService
from security_eval.web.app import create_app
from tests.fakes.fake_module import FakeTask1Module


VALID_FORM = {
    "tasks": ["1", "2", "4"],
    "mode": "hybrid",
    "profile": "quick",
    "seed": "42",
    "benchmark_version": "v1",
    "authorized_target": "on",
}

RUNTIME_DEFAULTS = {
    "target_base_url": "https://configured-target.invalid/v1",
    "target_model": "configured-target",
    "judge_base_url": "https://configured-judge.invalid/v1",
    "judge_model": "configured-judge",
}


class RuntimeInputs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inputs = {}

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "input" and attributes.get("name") in RUNTIME_DEFAULTS:
            self.inputs[attributes["name"]] = attributes


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
    assert 'name="target_model" value=""' in body
    assert "safe-model" not in body
    assert "SECRET-DO-NOT-SHOW" not in body


def test_homepage_runtime_inputs_start_blank_even_with_configured_defaults(app_factory):
    response = app_factory(public_settings=RUNTIME_DEFAULTS).test_client().get("/")
    parser = RuntimeInputs()
    parser.feed(response.get_data(as_text=True))
    assert set(parser.inputs) == set(RUNTIME_DEFAULTS)
    assert all(item["value"] == "" for item in parser.inputs.values())
    assert all(item["autocomplete"] == "off" for item in parser.inputs.values())


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_runtime_inputs_do_not_override_backend_defaults(app_factory, monkeypatch, blank):
    app = app_factory(public_settings=RUNTIME_DEFAULTS)
    manager = app.extensions["security_eval.run_manager"]
    original_start = manager.start
    overrides = []

    def start(request, *, config_overrides=None):
        overrides.append(config_overrides)
        return original_start(request, config_overrides=config_overrides)

    monkeypatch.setattr(manager, "start", start)
    client = app.test_client()
    response = client.post("/runs", data={**VALID_FORM, **{key: blank for key in RUNTIME_DEFAULTS}})
    assert response.status_code == 303
    assert wait_final(client, response.headers["Location"])["status"] == "completed"
    assert overrides == [{}]


@pytest.mark.parametrize(
    ("provided", "expected"),
    [
        ({"target_model": "  new-target  "}, {"target_model": "new-target", "agentdojo_model": "new-target"}),
        ({"judge_model": "new-judge"}, {"judge_model": "new-judge"}),
        ({"target_base_url": "http://localhost:8000/v1"}, {"target_base_url": "http://localhost:8000/v1"}),
    ],
)
def test_only_filled_runtime_inputs_override_defaults(app_factory, monkeypatch, provided, expected):
    app = app_factory(public_settings=RUNTIME_DEFAULTS)
    captured = []

    def start(request, *, config_overrides=None):
        captured.append(config_overrides)
        return "runtime-override01"

    monkeypatch.setattr(app.extensions["security_eval.run_manager"], "start", start)
    response = app.test_client().post(
        "/runs", data={**VALID_FORM, **{key: "" for key in RUNTIME_DEFAULTS}, **provided}
    )
    assert response.status_code == 303
    assert captured == [expected]


@pytest.mark.parametrize("provided", [{}, {"target_model": "new-target"}])
def test_runtime_settings_retain_unfilled_defaults_and_credentials(tmp_path, provided):
    seen = []

    class RecordingModule(FakeTask1Module):
        def run(self, context, request):
            seen.append(context.settings)
            return super().run(context, request)

    settings = Settings(
        **RUNTIME_DEFAULTS,
        target_api_key="fixture-target-key",
        judge_api_key="fixture-judge-key",
        agentdojo_model=RUNTIME_DEFAULTS["target_model"],
        output_root=tmp_path,
    )
    registry = ModuleRegistry()
    registry.register(RecordingModule())
    service = EvaluationService(
        settings=settings, registry=registry, target_client=object(), judge_client=object()
    )
    app = create_app(
        service=service, output_root=tmp_path, public_settings=settings.public_summary(), testing=True
    )
    try:
        client = app.test_client()
        response = client.post(
            "/runs",
            data={**VALID_FORM, "tasks": ["1"], **{key: "" for key in RUNTIME_DEFAULTS}, **provided},
        )
        assert response.status_code == 303
        assert wait_final(client, response.headers["Location"])["status"] == "completed"
        assert len(seen) == 1
        for key, value in RUNTIME_DEFAULTS.items():
            assert getattr(seen[0], key) == provided.get(key, value)
        assert seen[0].agentdojo_model == seen[0].target_model
        assert seen[0].target_api_key.get_secret_value() == "fixture-target-key"
        assert seen[0].judge_api_key.get_secret_value() == "fixture-judge-key"
        assert settings.target_model == RUNTIME_DEFAULTS["target_model"]
    finally:
        app.extensions["security_eval.run_manager"].shutdown(wait=True)
        service.shutdown(wait=True)


def test_invalid_submission_keeps_entered_runtime_values(app_factory):
    client = app_factory(public_settings=RUNTIME_DEFAULTS).test_client()
    response = client.post("/runs", data={"target_model": "custom-target"})
    assert response.status_code == 400
    parser = RuntimeInputs()
    parser.feed(response.get_data(as_text=True))
    assert parser.inputs["target_model"]["value"] == "custom-target"
    assert parser.inputs["judge_model"]["value"] == ""


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
    assert "Targeted ASR" not in body
    assert "未授权工具调用率" not in body
    assert "泄露率" not in body
    assert "DoS 中断率" not in body
    assert "防御效用损失" not in body
    assert '<dl class="agentdojo-metrics">' not in body
    assert "Final Score" in body and "类别明细" in body
    assert "发现的问题" in body and "无效" in body
    download = client.get(f"/runs/{run_id}/report.json")
    assert download.status_code == 200
    assert download.get_json()["run_id"] == run_id
    assert download.headers["Cache-Control"] == "no-store"


def test_task2_partial_counts_as_failed_in_result_page_only(app_factory, monkeypatch):
    from security_eval.web.presentation import build_run_view
    from tests.web.conftest import FakeEvaluationService

    original = FakeEvaluationService.execute

    def with_partials(self, request, *, run_id=None):
        report = original(self, request, run_id=run_id)
        updated = []
        for task in report.task_results:
            base = task.cases[1]
            partials = [base.model_copy(update={"case_id": f"t{task.task_id}-partial-benchmark", "status": "partial"})]
            if task.task_id == 2:
                partials.append(base.model_copy(update={
                    "case_id": "t2-partial-dynamic", "status": "partial", "source": "dynamic", "category": "Bias",
                }))
            summaries = [summary.model_copy(update={
                "valid_cases": summary.valid_cases + sum(case.category == summary.category for case in partials),
            }) for summary in task.category_summaries]
            updated.append(task.model_copy(update={"cases": [*task.cases, *partials], "category_summaries": summaries}))
        return report.model_copy(update={"task_results": updated})

    monkeypatch.setattr(FakeEvaluationService, "execute", with_partials)
    client = app_factory().test_client()
    response = client.post("/runs", data=VALID_FORM)
    location = response.headers["Location"]
    wait_final(client, location)
    run_id = location.rsplit("/", 1)[-1]
    downloaded = client.get(f"/runs/{run_id}/report.json").get_json()
    from security_eval.contracts import RunReport

    report = RunReport.model_validate(downloaded)
    before = report.model_dump()
    view = build_run_view(report)
    assert report.model_dump() == before
    task2 = next(task for task in view["tasks"] if task["task_id"] == 2)
    assert task2["counts"] == {"total": 6, "passed": 1, "failed": 4, "partial": 0, "invalid": 1}
    for category in task2["categories"]:
        original_category = next(c for c in report.task_results[1].category_summaries if c.category == category["category"])
        assert category["score"] == original_category.score
        assert category["failed_cases"] == original_category.failed_cases + (category["category"] in {"Bias", "Toxicity"})
    for task, source in zip(view["tasks"], report.task_results):
        assert task["final_score"] == source.final_score
        assert task["benchmark_score"] == source.benchmark_score
        assert task["dynamic_score"] == source.dynamic_score
        if task["task_id"] != 2:
            assert task["counts"]["partial"] == sum(c.status == "partial" for c in source.cases)
            assert task["counts"]["failed"] == sum(c.status == "failed" for c in source.cases)
            assert [c["failed_cases"] for c in task["categories"]] == [c.failed_cases for c in source.category_summaries]
    assert view["case_counts"]["failed"] == sum(c.status == "failed" or (c.task_id == 2 and c.status == "partial") for t in report.task_results for c in t.cases)
    assert sum(view["case_counts"][key] for key in ("passed", "failed", "partial", "invalid")) == view["case_counts"]["total"]
    assert sum(c["status"] == "partial" for t in downloaded["task_results"] if t["task_id"] == 2 for c in t["cases"]) == 2
    body = client.get(location).get_data(as_text=True)
    assert f'{view["case_counts"]["passed"]} 通过 · {view["case_counts"]["failed"]} 失败 · {view["case_counts"]["invalid"]} 无效' in body
    task2_body = body.split("<small>Task 2</small>", 1)[1].split("</article>", 1)[0]
    assert "<dt>Failed</dt><dd>4</dd>" in task2_body
    assert "<td>Bias</td><td>40.0</td><td>0</td><td>2</td><td>0</td>" in task2_body
    assert "<td>Toxicity</td><td>0.0</td><td>0</td><td>2</td><td>0</td>" in task2_body


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
