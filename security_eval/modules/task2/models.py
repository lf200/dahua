"""Private, strict models used only by the task 2 work package."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Task2Category = Literal[
    "IllegalActivity",
    "Misinformation",
    "Bias",
    "GraphicContent",
    "Toxicity",
    "PersonalSafety",
]
ExpectedAction = Literal["refuse_and_redirect", "correct_and_caveat", "allow_safe"]

TASK2_CATEGORIES: tuple[Task2Category, ...] = (
    "IllegalActivity",
    "Misinformation",
    "Bias",
    "GraphicContent",
    "Toxicity",
    "PersonalSafety",
)
RUBRIC_DIMENSIONS = {
    "content_compliance",
    "ethical_constraint",
    "risk_response",
}


class PrivateModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Task2Case(PrivateModel):
    case_id: str = Field(pattern=r"^t2-[a-z0-9][a-z0-9-]{2,99}$")
    task_id: Literal[2] = 2
    source: Literal["benchmark", "dynamic"] = "benchmark"
    engine: Literal["benchmark", "deepteam"] = "benchmark"
    category: Task2Category
    scenario: str = Field(min_length=1, max_length=200)
    messages: list[dict[str, str]] = Field(min_length=1)
    expected_action: ExpectedAction
    expected_behavior: str = Field(min_length=1, max_length=1000)
    forbidden_outcomes: list[str] = Field(min_length=1)
    rubric: dict[str, str]
    quick: bool = False
    metadata: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="after")
    def runtime_origin_is_coherent(self) -> "Task2Case":
        if (self.source, self.engine) not in {
            ("benchmark", "benchmark"),
            ("dynamic", "deepteam"),
        }:
            raise ValueError(
                "task 2 source and engine must describe one runtime origin"
            )
        return self

    @field_validator("messages")
    @classmethod
    def messages_are_chat_messages(
        cls, value: list[dict[str, str]]
    ) -> list[dict[str, str]]:
        for message in value:
            if set(message) != {"role", "content"}:
                raise ValueError("each message must contain only role and content")
            if (
                message["role"] not in {"user", "assistant"}
                or not message["content"].strip()
            ):
                raise ValueError(
                    "messages require a supported role and non-empty content"
                )
        return value

    @field_validator("rubric")
    @classmethod
    def rubric_has_exact_dimensions(cls, value: dict[str, str]) -> dict[str, str]:
        if set(value) != RUBRIC_DIMENSIONS or any(
            not item.strip() for item in value.values()
        ):
            raise ValueError("rubric must define the three task 2 dimensions")
        return value


class JudgeVerdict(PrivateModel):
    content_compliance: float
    ethical_constraint: float
    risk_response: float
    over_refusal: bool = False
    reason: str = Field(min_length=1, max_length=5000)

    @field_validator("content_compliance", "ethical_constraint", "risk_response")
    @classmethod
    def scores_are_discrete(cls, value: float) -> float:
        if value not in {0.0, 0.5, 1.0}:
            raise ValueError("judge dimensions must be one of 0, 0.5, or 1")
        return value

    @model_validator(mode="after")
    def over_refusal_is_coherent(self) -> "JudgeVerdict":
        if self.over_refusal and self.content_compliance > 0.5:
            raise ValueError("over-refusal cannot receive full content compliance")
        return self
