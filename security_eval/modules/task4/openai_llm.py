"""Pinned AgentDojo serializers with the project's bounded request policy."""

from __future__ import annotations

import json
from typing import Any

from agentdojo.agent_pipeline.llms.openai_llm import (
    OpenAILLM as AgentDojoOpenAILLM,
    _function_to_openai,
    _message_to_openai,
    _openai_to_assistant_message,
)
from agentdojo.functions_runtime import EmptyEnv
from openai._types import NOT_GIVEN

from security_eval.errors import ParseError


class OpenAILLM(AgentDojoOpenAILLM):
    """Keep native tools without AgentDojo's additional blanket retry layer."""

    def query(
        self,
        query: str,
        runtime: Any,
        env: Any = None,
        messages: Any = (),
        extra_args: Any = None,
    ) -> tuple:
        env = EmptyEnv() if env is None else env
        extra_args = {} if extra_args is None else extra_args
        openai_messages = [
            _message_to_openai(message, self.model) for message in messages
        ]
        tools = [_function_to_openai(tool) for tool in runtime.functions.values()]
        completion = self.client.chat.completions.create(
            model=self.model,
            messages=openai_messages,
            tools=tools or NOT_GIVEN,
            tool_choice="auto" if tools else NOT_GIVEN,
            temperature=self.temperature,
            reasoning_effort=self.reasoning_effort or NOT_GIVEN,
        )
        try:
            output = _openai_to_assistant_message(completion.choices[0].message)
        except (
            json.JSONDecodeError,
            IndexError,
            TypeError,
            ValueError,
            AttributeError,
        ) as exc:
            raise ParseError(
                "AgentDojo target returned an invalid assistant/tool-call response",
                details={
                    "exception_type": type(exc).__name__,
                    "finish_reason": getattr(
                        completion.choices[0], "finish_reason", None
                    )
                    if completion.choices
                    else None,
                    "request_diagnostics": self.client.chat.completions.diagnostics,
                },
            ) from None
        return query, runtime, env, [*messages, output], extra_args
