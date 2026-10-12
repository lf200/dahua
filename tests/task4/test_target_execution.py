"""Real SDK and AgentDojo regressions with an offline HTTP transport."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import openai
import pytest

from security_eval.errors import EvaluationTimeoutError, ParseError, TargetError
from security_eval.modules.task4.agentdojo_adapter import AgentDojoAdapter
from security_eval.modules.task4.matrix import benchmark_cases, load_matrix
from security_eval.modules.task4.module import Task4Module

from .test_module import request


def response_message(content="safe", tool_calls=None):
    return {
        "id": "offline-completion",
        "object": "chat.completion",
        "created": 0,
        "model": "test-model",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": content,
                    "tool_calls": tool_calls,
                },
            }
        ],
    }


@pytest.fixture
def endpoint(monkeypatch):
    original = openai.OpenAI
    calls, clients, timeouts, headers = [], [], [], []

    def handler(_):
        return httpx.Response(200, json=response_message())

    def respond(req):
        payload = json.loads(req.content)
        calls.append(payload)
        headers.append(dict(req.headers))
        timeouts.append(req.extensions["timeout"])
        return handler(payload)

    def factory(**kwargs):
        client = original(
            **kwargs, http_client=httpx.Client(transport=httpx.MockTransport(respond))
        )
        clients.append(client)
        return client

    monkeypatch.setattr("openai.OpenAI", factory)
    monkeypatch.setattr(
        "security_eval.modules.task4.agentdojo_adapter.time.sleep", lambda _: None
    )

    def set_handler(value):
        nonlocal handler
        handler = value

    yield SimpleNamespace(
        calls=calls, clients=clients, timeouts=timeouts, headers=headers,
        set_handler=set_handler
    )
    for client in clients:
        client.close()


def baseline():
    return benchmark_cases(load_matrix(), "quick")[0]


@pytest.mark.parametrize("api_key", ["", "   ", "sk-secret-value"])
@pytest.mark.parametrize("defense", ["none", "tool_filter"])
def test_agentdojo_auth_headers_follow_target_key(
    run_context, endpoint, monkeypatch, api_key, defense
):
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-key-must-not-be-used")
    run_context.target_client.api_key = api_key
    adapter = AgentDojoAdapter()
    adapter.validate(run_context)
    adapter.run_case(run_context, baseline().model_copy(update={"defense": defense}))
    assert endpoint.headers
    for headers in endpoint.headers:
        if api_key.strip():
            assert headers["authorization"] == f"Bearer {api_key.strip()}"
        else:
            assert "authorization" not in headers


@pytest.mark.parametrize(
    "status,code",
    [
        (400, "invalid_request_error"),
        (401, "invalid_api_key"),
        (403, "insufficient_quota"),
        (404, "model_not_found"),
        (422, "invalid_parameter"),
    ],
)
def test_permanent_api_errors_are_not_retried_and_keep_diagnostics(
    run_context,
    endpoint,
    status,
    code,
):
    endpoint.set_handler(
        lambda _: httpx.Response(
            status,
            headers={"x-request-id": "offline-req"},
            json={
                "error": {
                    "code": code,
                    "param": "messages",
                    "message": "diagnostic sk-secret-value",
                }
            },
        )
    )
    with pytest.raises(TargetError) as caught:
        AgentDojoAdapter().run_case(run_context, baseline())
    assert len(endpoint.calls) == 1
    error = caught.value
    assert error.retryable is False
    assert error.details["http_status"] == status
    assert error.details["provider_code"] == code
    assert error.details["provider_param"] == "messages"
    assert error.details["request_id"] == "offline-req"
    assert error.details["request"]["message_count"] == 2
    assert error.details["request"]["tool_count"] == 24
    assert "sk-secret-value" not in json.dumps(error.details)
    assert all(client.is_closed() for client in endpoint.clients)


def test_bad_request_on_tool_round_does_not_poison_next_case(run_context, endpoint):
    adapter = AgentDojoAdapter()
    suite = adapter._suite()
    user = suite.get_user_task_by_id("user_task_0")
    call = user.ground_truth(suite.load_and_inject_default_environment({}))[0]

    def respond(payload):
        if len(endpoint.calls) == 1:
            return httpx.Response(
                200,
                json=response_message(
                    None,
                    [
                        {
                            "id": "offline-call",
                            "type": "function",
                            "function": {
                                "name": call.function,
                                "arguments": json.dumps(call.args),
                            },
                        }
                    ],
                ),
            )
        if len(endpoint.calls) == 2:
            return httpx.Response(
                400,
                json={
                    "error": {
                        "code": "context_length_exceeded",
                        "param": "messages",
                        "message": "input too long",
                    }
                },
            )
        return httpx.Response(200, json=response_message(user.GROUND_TRUTH_OUTPUT))

    endpoint.set_handler(respond)
    with pytest.raises(TargetError) as caught:
        adapter.run_case(run_context, baseline())
    assert len(endpoint.calls) == 2
    assert caught.value.details["request"]["roles"] == [
        "system",
        "user",
        "assistant",
        "tool",
    ]
    assert caught.value.details["target_unavailable"] is False
    result = adapter.run_case(run_context, baseline())
    assert result.error is None
    assert len(endpoint.calls[-1]["messages"]) == 2
    assert len(result.request_diagnostics) == 1
    from agentdojo.logging import LOGGER_STACK

    assert LOGGER_STACK.get() == []


@pytest.mark.parametrize("status", [408, 409, 429, 500, 503])
def test_transient_failure_has_one_bounded_retry_layer(run_context, endpoint, status):
    def respond(_):
        if len(endpoint.calls) <= 2:
            return httpx.Response(
                status, json={"error": {"code": "temporary", "message": "try later"}}
            )
        return httpx.Response(200, json=response_message())

    endpoint.set_handler(respond)
    result = AgentDojoAdapter().run_case(run_context, baseline())
    assert len(endpoint.calls) == 3
    assert len(result.request_diagnostics) == 3
    assert [item["attempt"] for item in result.request_diagnostics] == [1, 2, 3]
    assert all(client.max_retries == 0 for client in endpoint.clients)


def test_sustained_server_failure_stops_after_three_attempts(run_context, endpoint):
    endpoint.set_handler(
        lambda _: httpx.Response(503, json={"error": {"message": "try later"}})
    )
    with pytest.raises(TargetError) as caught:
        AgentDojoAdapter().run_case(run_context, baseline())
    assert len(endpoint.calls) == 3
    assert caught.value.retryable is True
    assert caught.value.details["request_count"] == 3


def test_quota_exhaustion_skips_remaining_benchmark_and_dynamic_cases(
    run_context, endpoint
):
    endpoint.set_handler(
        lambda _: httpx.Response(
            403,
            json={
                "error": {
                    "code": "insufficient_quota",
                    "message": "Free quota exhausted",
                }
            },
        )
    )
    result = Task4Module().run(run_context, request("hybrid", "full"))
    assert len(endpoint.calls) == 1
    assert len(result.cases) == 42
    assert all(case.status == "invalid" for case in result.cases)
    assert result.final_score is None
    first, *skipped = result.cases
    assert first.metadata["executed"] is True
    assert first.error.details["provider_message"] == "Free quota exhausted"
    assert all(case.metadata["executed"] is False for case in skipped)
    assert all(case.duration_ms == 0 for case in skipped)
    assert all(
        case.error.details["blocked_by_case_id"] == first.case_id for case in skipped
    )
    assert all(case.error.retryable is False for case in result.cases)
    for case in result.cases:
        artifact = run_context.artifact_dir / case.evidence[0].artifact_path
        assert json.loads(artifact.read_text(encoding="utf-8"))["input"] == case.input


def test_first_two_valid_then_sixteen_400s_are_diagnosable_without_losing_valid_results(
    run_context,
    endpoint,
):
    def respond(_):
        if len(endpoint.calls) <= 2:
            return httpx.Response(200, json=response_message())
        return httpx.Response(
            400,
            json={
                "error": {
                    "code": "invalid_request_error",
                    "param": "messages",
                    "message": "unsupported message",
                }
            },
        )

    endpoint.set_handler(respond)
    result = Task4Module().run(run_context, request("dynamic", "full"))
    assert len(result.cases) == len(endpoint.calls) == 18
    assert all(case.status != "invalid" for case in result.cases[:2])
    assert all(case.status == "invalid" for case in result.cases[2:])
    assert result.dynamic_score is not None
    assert all(case.error.details["http_status"] == 400 for case in result.cases[2:])
    assert all(case.error.retryable is False for case in result.cases[2:])
    assert all(len(call["messages"]) == 2 for call in endpoint.calls)
    assert all(case.input is not None for case in result.cases)
    endpoint.set_handler(lambda _: httpx.Response(200, json=response_message()))
    second = Task4Module().run(run_context, request("dynamic", "full"))
    assert len(second.cases) == 18
    assert second.errors == []


def test_deadline_is_rechecked_before_every_tool_round(run_context, endpoint):
    adapter = AgentDojoAdapter()
    call = (
        adapter._suite()
        .get_user_task_by_id("user_task_0")
        .ground_truth(adapter._suite().load_and_inject_default_environment({}))[0]
    )

    def respond(_):
        run_context.deadline = datetime.now(timezone.utc) - timedelta(seconds=1)
        return httpx.Response(
            200,
            json=response_message(
                None,
                [
                    {
                        "id": "offline-call",
                        "type": "function",
                        "function": {
                            "name": call.function,
                            "arguments": json.dumps(call.args),
                        },
                    }
                ],
            ),
        )

    endpoint.set_handler(respond)
    with pytest.raises(EvaluationTimeoutError, match="before target request"):
        adapter.run_case(run_context, baseline())
    assert len(endpoint.calls) == 1


def test_configured_output_limit_is_used(run_context, endpoint):
    run_context.target_client.max_tokens = 256
    result = AgentDojoAdapter().run_case(run_context, baseline())
    assert endpoint.calls[0]["max_tokens"] == 256
    assert result.request_diagnostics[0]["request"]["max_tokens"] == 256


def test_error_body_is_allowlisted_and_echoed_prompts_are_removed(
    run_context, endpoint
):
    def respond(payload):
        system = payload["messages"][0]["content"][0]["text"]
        return httpx.Response(
            400,
            json={
                "error": {
                    "code": "invalid_request_error",
                    "message": f"Rejected: {system}; sk-secret-value",
                    "request": payload,
                    "api_key": "sk-secret-value",
                },
                "extra": "never persist",
            },
        )

    endpoint.set_handler(respond)
    with pytest.raises(TargetError) as caught:
        AgentDojoAdapter().run_case(run_context, baseline())
    rendered = json.dumps(caught.value.details)
    assert "sk-secret-value" not in rendered
    assert "never persist" not in rendered
    assert endpoint.calls[0]["messages"][0]["content"][0]["text"] not in rendered
    assert "[REDACTED]" in caught.value.details["provider_message"]


def test_invalid_case_duration_is_measured(monkeypatch, run_context):
    from .test_module import FakeAdapter

    ticks = iter([0.0, 0.125, *([1.0] * 20)])
    monkeypatch.setattr(
        "security_eval.modules.task4.module.time.perf_counter", lambda: next(ticks)
    )
    result = Task4Module(adapter=FakeAdapter(fail_first=True)).run(
        run_context, request()
    )
    assert result.cases[0].duration_ms == 125
    assert result.cases[0].metadata["executed"] is True
    assert result.cases[1].status != "invalid"


def test_400_allocation_quota_is_global_but_content_rejection_is_case_local(
    run_context, endpoint
):
    endpoint.set_handler(
        lambda _: httpx.Response(
            400,
            json={
                "error": {
                    "code": "Throttling.AllocationQuota",
                    "message": "quota exhausted",
                }
            },
        )
    )
    result = Task4Module().run(run_context, request())
    assert len(endpoint.calls) == 1
    assert all(case.metadata["executed"] is False for case in result.cases[1:])
    endpoint.set_handler(
        lambda _: httpx.Response(
            403,
            json={
                "error": {
                    "code": "content_policy_violation",
                    "message": "case input rejected",
                }
            },
        )
    )
    result = Task4Module().run(run_context, request())
    assert len(endpoint.calls) == 9
    assert all(case.metadata["executed"] is True for case in result.cases)


def test_remaining_deadline_can_set_subsecond_request_timeout(
    run_context, endpoint, monkeypatch
):
    monkeypatch.setattr(
        "security_eval.modules.task4.agentdojo_adapter._remaining_seconds",
        lambda _: 0.25,
    )
    AgentDojoAdapter().run_case(run_context, baseline())
    assert endpoint.timeouts[0]["read"] == 0.25


def test_deadline_prevents_a_retry_and_preserves_last_provider_error(
    run_context, endpoint, monkeypatch
):
    remaining = iter([10.0, 1.0, 0.1])
    monkeypatch.setattr(
        "security_eval.modules.task4.agentdojo_adapter._remaining_seconds",
        lambda _: next(remaining),
    )
    endpoint.set_handler(
        lambda _: httpx.Response(503, json={"error": {"message": "unavailable"}})
    )
    with pytest.raises(EvaluationTimeoutError, match="before target retry") as caught:
        AgentDojoAdapter().run_case(run_context, baseline())
    assert len(endpoint.calls) == 1
    assert caught.value.details["http_status"] == 503


def test_truncated_tool_json_is_a_diagnosable_parse_error(run_context, endpoint):
    payload = response_message(
        None,
        [
            {
                "id": "bad-json-call",
                "type": "function",
                "function": {
                    "name": "search_calendar_events",
                    "arguments": '{"query":',
                },
            }
        ],
    )
    payload["choices"][0]["finish_reason"] = "length"
    endpoint.set_handler(lambda _: httpx.Response(200, json=payload))
    with pytest.raises(ParseError) as caught:
        AgentDojoAdapter().run_case(run_context, baseline())
    assert len(endpoint.calls) == 1
    assert caught.value.details["finish_reason"] == "length"
    assert (
        caught.value.details["request_diagnostics"][0]["request"]["max_tokens"] == 1024
    )


def test_plain_text_provider_error_retains_the_diagnostic(run_context, endpoint):
    endpoint.set_handler(
        lambda _: httpx.Response(400, text="Unsupported tool response content")
    )
    with pytest.raises(TargetError) as caught:
        AgentDojoAdapter().run_case(run_context, baseline())
    assert (
        caught.value.details["provider_message"] == "Unsupported tool response content"
    )
    assert len(endpoint.calls) == 1


def test_secret_is_redacted_before_error_message_is_truncated(run_context, endpoint):
    endpoint.set_handler(
        lambda _: httpx.Response(
            400, json={"error": {"message": "x" * 995 + "sk-secret-value"}}
        )
    )
    with pytest.raises(TargetError) as caught:
        AgentDojoAdapter().run_case(run_context, baseline())
    message = caught.value.details["provider_message"]
    assert len(message) == 1000
    assert "sk-se" not in message
