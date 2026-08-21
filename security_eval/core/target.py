"""Minimal OpenAI-compatible chat clients with secret-safe errors."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from security_eval.core.config import Settings
from security_eval.errors import ParseError, TargetError


@dataclass(frozen=True, slots=True)
class ChatClient:
    base_url: str
    api_key: str
    model: str
    timeout_seconds: int = 60
    max_tokens: int = 1024

    def complete(self, messages: Sequence[dict[str, Any]]) -> str:
        if not messages:
            raise TargetError("Chat request must contain at least one message", retryable=False)
        payload = json.dumps(
            {
                "model": self.model,
                "messages": list(messages),
                "max_tokens": self.max_tokens,
                "temperature": 0,
            },
            ensure_ascii=False,
        ).encode("utf-8")
        request = Request(
            f"{self.base_url}/chat/completions",
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
        except HTTPError as exc:
            raise TargetError(f"Chat endpoint returned HTTP {exc.code}", retryable=exc.code >= 500) from None
        except (URLError, TimeoutError, OSError):
            raise TargetError("Chat endpoint request failed") from None

        try:
            body = json.loads(raw)
            content = body["choices"][0]["message"]["content"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise ParseError("Chat endpoint returned an invalid response shape") from exc
        if not isinstance(content, str) or not content.strip():
            raise ParseError("Chat endpoint returned empty assistant content")
        return content


class TargetClient(ChatClient):
    @classmethod
    def from_settings(cls, settings: Settings) -> "TargetClient":
        return cls(
            base_url=settings.target_base_url,
            api_key=settings.target_api_key.get_secret_value(),
            model=settings.target_model,
            timeout_seconds=settings.target_timeout_seconds,
            max_tokens=settings.target_max_tokens,
        )


class JudgeClient(ChatClient):
    @classmethod
    def from_settings(cls, settings: Settings) -> "JudgeClient":
        return cls(
            base_url=settings.judge_base_url,
            api_key=settings.judge_api_key.get_secret_value(),
            model=settings.judge_model,
            timeout_seconds=settings.target_timeout_seconds,
            max_tokens=settings.target_max_tokens,
        )
