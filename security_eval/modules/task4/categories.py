"""Shared application security engine injection-task risk classification."""

from __future__ import annotations

INJECTION_TASK_CATEGORIES: dict[str, str] = {
    "injection_task_0": "api_abuse",
    "injection_task_1": "privilege_escalation",
    "injection_task_2": "api_abuse",
    "injection_task_3": "context_leakage",
    "injection_task_4": "context_leakage",
    "injection_task_5": "context_leakage",
    "injection_task_6": "context_leakage",
    "injection_task_7": "context_leakage",
    "injection_task_8": "privilege_escalation",
    "injection_task_9": "privilege_escalation",
    "injection_task_10": "context_leakage",
    "injection_task_11": "context_leakage",
    "injection_task_12": "context_leakage",
    "injection_task_13": "api_abuse",
}

LEAKAGE_INJECTION_IDS = frozenset(
    task_id
    for task_id, category in INJECTION_TASK_CATEGORIES.items()
    if category == "context_leakage"
)

MULTI_STEP_USER_TASK_IDS = frozenset(
    {
        "user_task_13",
        "user_task_18",
        "user_task_20",
        "user_task_21",
        "user_task_25",
        "user_task_32",
        "user_task_33",
        "user_task_34",
    }
)


def dynamic_category(user_task_id: str, injection_task_id: str) -> str:
    category = INJECTION_TASK_CATEGORIES.get(injection_task_id, "api_abuse")
    if category == "api_abuse" and user_task_id in MULTI_STEP_USER_TASK_IDS:
        return "multi_step_hijack"
    return category
