from __future__ import annotations

import re
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN_TERMS = ("deep" + "team", "deep" + "eval", "agent" + "dojo")
DEPENDENCY_FILES = {
    "requirements.txt",
    "requirements/task1.in",
    "requirements/task2.in",
    "requirements/task4.in",
}
TASK1_ADAPTER = "security_eval/modules/task1/dynamic_test_adapter.py"
TASK2_ADAPTER = "security_eval/modules/task2/dynamic_test_adapter.py"
TASK4_ADAPTER = "security_eval/modules/task4/application_security_adapter.py"
RUNTIME_VENDOR = FORBIDDEN_TERMS[0]
EVALUATION_VENDOR = FORBIDDEN_TERMS[1]
APPLICATION_VENDOR = FORBIDDEN_TERMS[2]
EVALUATION_BASE_CLASS = "Deep" + "EvalBaseLLM"

REQUIRED_EXACT_LINES = {
    TASK1_ADAPTER: {
        f'os.environ["{RUNTIME_VENDOR.upper()}_TELEMETRY_OPT_OUT"] = "YES"',
        f'os.environ["{EVALUATION_VENDOR.upper()}_TELEMETRY_OPT_OUT"] = "YES"',
        f"from {EVALUATION_VENDOR}.models import {EVALUATION_BASE_CLASS} as EvaluationBaseLLM",
        f"from {RUNTIME_VENDOR}.attacks.attack_engine import AttackEngine",
        f"from {RUNTIME_VENDOR}.attacks.multi_turn import LinearJailbreaking",
        f"from {RUNTIME_VENDOR}.attacks.single_turn import PromptInjection, Roleplay",
        f"from {RUNTIME_VENDOR}.red_teamer import RedTeamer",
        f"from {RUNTIME_VENDOR}.vulnerabilities import IndirectInstruction, Robustness",
    },
    TASK2_ADAPTER: {
        f'os.environ["{RUNTIME_VENDOR.upper()}_TELEMETRY_OPT_OUT"] = "YES"',
        f'os.environ["{EVALUATION_VENDOR.upper()}_TELEMETRY_OPT_OUT"] = "YES"',
        f"from {RUNTIME_VENDOR}.attacks.attack_engine import AttackEngine",
        f"from {RUNTIME_VENDOR}.metrics import EvaluationExample",
        f"from {EVALUATION_VENDOR}.models import {EVALUATION_BASE_CLASS} as EvaluationBaseLLM",
        f"from {RUNTIME_VENDOR}.vulnerabilities import (",
    },
    TASK4_ADAPTER: {
        f'installed = importlib.metadata.version("{APPLICATION_VENDOR}")',
        f'importlib.import_module("{APPLICATION_VENDOR}")',
        f'importlib.import_module("{APPLICATION_VENDOR}.attacks.baseline_attacks")',
        f'importlib.import_module("{APPLICATION_VENDOR}.attacks.dos_attacks")',
        f'importlib.import_module("{APPLICATION_VENDOR}.attacks.important_instructions_attacks")',
        f"from {APPLICATION_VENDOR}.attacks.attack_registry import load_attack",
        f"from {APPLICATION_VENDOR}.agent_pipeline.agent_pipeline import (",
        f"from {APPLICATION_VENDOR}.agent_pipeline.llms.openai_llm import OpenAILLM",
        f"from {APPLICATION_VENDOR}.logging import Logger",
        f"from {APPLICATION_VENDOR}.task_suite.load_suites import get_suite",
    },
    "tests/task1/test_dynamic_test_adapter.py": {
        f'monkeypatch.setenv("{RUNTIME_VENDOR.upper()}_TELEMETRY_OPT_OUT", "NO")',
        f'monkeypatch.setenv("{EVALUATION_VENDOR.upper()}_TELEMETRY_OPT_OUT", "NO")',
        f'assert __import__("os").environ["{RUNTIME_VENDOR.upper()}_TELEMETRY_OPT_OUT"] == "YES"',
        f'assert __import__("os").environ["{EVALUATION_VENDOR.upper()}_TELEMETRY_OPT_OUT"] == "YES"',
    },
    "tests/task2/test_dynamic_test_adapter.py": {
        f'monkeypatch.setenv("{RUNTIME_VENDOR.upper()}_TELEMETRY_OPT_OUT", "NO")',
        f'monkeypatch.setenv("{EVALUATION_VENDOR.upper()}_TELEMETRY_OPT_OUT", "NO")',
        f'assert os.environ["{RUNTIME_VENDOR.upper()}_TELEMETRY_OPT_OUT"] == "YES"',
        f'assert os.environ["{EVALUATION_VENDOR.upper()}_TELEMETRY_OPT_OUT"] == "YES"',
    },
}


def _is_required_dependency_line(path: str, line: str) -> bool:
    if path not in DEPENDENCY_FILES:
        return False
    vendor_pattern = "|".join(re.escape(term) for term in FORBIDDEN_TERMS)
    return bool(re.fullmatch(rf"(?:{vendor_pattern})==[^\s]+", line, re.IGNORECASE))


def _tracked_text_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
    )
    return [
        PROJECT_ROOT / item.decode("utf-8")
        for item in result.stdout.split(b"\0")
        if item
    ]


def _is_required_interoperability_line(path: str, line: str) -> bool:
    stripped = line.strip()
    if _is_required_dependency_line(path, stripped):
        return True
    return stripped in REQUIRED_EXACT_LINES.get(path, set())


def _find_violations(file_paths: list[Path]) -> list[str]:
    violations: list[str] = []
    for file_path in file_paths:
        relative = file_path.relative_to(PROJECT_ROOT).as_posix()
        lowered_path = relative.lower()
        if any(term in lowered_path for term in FORBIDDEN_TERMS):
            violations.append(f"{relative}:filename:{relative}")
        try:
            content = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line_number, line in enumerate(content.splitlines(), start=1):
            lowered = line.lower()
            if not any(term in lowered for term in FORBIDDEN_TERMS):
                continue
            if _is_required_interoperability_line(relative, line):
                continue
            violations.append(f"{relative}:{line_number}:{line.strip()}")
    return violations


def test_first_party_files_do_not_expose_vendor_names() -> None:
    assert _find_violations(_tracked_text_files()) == []


def test_interoperability_allowlist_rejects_decoy_lines() -> None:
    vendor = FORBIDDEN_TERMS[0]

    assert not _is_required_interoperability_line(
        "security_eval/decoy.py",
        f'value = "{vendor}"; importlib.import_module("allowed")',
    )
    assert not _is_required_interoperability_line(
        TASK1_ADAPTER,
        f'value = "{vendor}"  # TELEMETRY_OPT_OUT',
    )
    assert not _is_required_interoperability_line(
        TASK1_ADAPTER,
        f"from {vendor}.unexpected import HiddenBackend",
    )
    assert not _is_required_interoperability_line(
        TASK4_ADAPTER,
        f'importlib.import_module("{FORBIDDEN_TERMS[2]}.unexpected")',
    )


def test_vendor_name_in_tracked_filename_is_reported(tmp_path: Path) -> None:
    vendor_file = PROJECT_ROOT / f"temporary-{FORBIDDEN_TERMS[0]}-adapter.py"
    try:
        vendor_file.write_text("pass\n", encoding="utf-8")
        assert _find_violations([vendor_file]) == [
            f"{vendor_file.name}:filename:{vendor_file.name}"
        ]
    finally:
        vendor_file.unlink(missing_ok=True)
