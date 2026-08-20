from __future__ import annotations

import io
import json
from urllib.error import HTTPError

import pytest

from security_eval.core.target import ChatClient
from security_eval.errors import ParseError, TargetError


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self) -> bytes:
        return json.dumps(self.payload).encode()


def client() -> ChatClient:
    return ChatClient("https://example.test/v1", "sk-unit-test-secret", "model")


def test_complete_returns_first_content(monkeypatch) -> None:
    captured = {}

    def fake_urlopen(request, timeout):
        captured["auth"] = request.headers["Authorization"]
        captured["body"] = json.loads(request.data)
        return FakeResponse({"choices": [{"message": {"content": "answer"}}]})

    monkeypatch.setattr("security_eval.core.target.urlopen", fake_urlopen)
    assert client().complete([{"role": "user", "content": "hello"}]) == "answer"
    assert captured["body"]["temperature"] == 0
    assert captured["auth"].endswith("sk-unit-test-secret")


def test_complete_rejects_invalid_shape(monkeypatch) -> None:
    monkeypatch.setattr("security_eval.core.target.urlopen", lambda *args, **kwargs: FakeResponse({}))
    with pytest.raises(ParseError, match="invalid response shape"):
        client().complete([{"role": "user", "content": "hello"}])


def test_http_error_does_not_include_secret(monkeypatch) -> None:
    def fail(*args, **kwargs):
        raise HTTPError("https://example.test", 401, "denied", {}, io.BytesIO())

    monkeypatch.setattr("security_eval.core.target.urlopen", fail)
    with pytest.raises(TargetError) as caught:
        client().complete([{"role": "user", "content": "hello"}])
    assert "sk-unit-test-secret" not in str(caught.value)
