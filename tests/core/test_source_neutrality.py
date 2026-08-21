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
IMPORT_LINE = re.compile(
    r"^\s*from\s+(?:" + "|".join(FORBIDDEN_TERMS) + r")(?:\.|\s+import\s+)"
)


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
    lowered = stripped.lower()
    if path in DEPENDENCY_FILES and any(
        lowered.startswith(f"{term}==") for term in FORBIDDEN_TERMS
    ):
        return True
    if IMPORT_LINE.match(stripped):
        return True
    if "importlib.import_module" in stripped or "importlib.metadata.version" in stripped:
        return True
    return "TELEMETRY_OPT_OUT" in stripped


def test_first_party_files_do_not_expose_vendor_names() -> None:
    violations: list[str] = []
    for file_path in _tracked_text_files():
        try:
            content = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        relative = file_path.relative_to(PROJECT_ROOT).as_posix()
        for line_number, line in enumerate(content.splitlines(), start=1):
            lowered = line.lower()
            if not any(term in lowered for term in FORBIDDEN_TERMS):
                continue
            if _is_required_interoperability_line(relative, line):
                continue
            violations.append(f"{relative}:{line_number}")

    assert violations == []
