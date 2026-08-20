from __future__ import annotations

import pytest

from scripts.merge_requirements import merge_requirement_files
from security_eval.errors import ContractError


def test_merge_is_sorted_and_deduplicated(tmp_path) -> None:
    first = tmp_path / "base.in"
    second = tmp_path / "web.in"
    first.write_text("pydantic==2.13.4\nPyYAML==6.0.3\n", encoding="utf-8")
    second.write_text("PyYAML==6.0.3\nFlask==3.1.2\n", encoding="utf-8")
    assert merge_requirement_files([second, first]) == [
        "Flask==3.1.2",
        "pydantic==2.13.4",
        "PyYAML==6.0.3",
    ]


def test_conflicting_direct_requirements_fail(tmp_path) -> None:
    first = tmp_path / "a.in"
    second = tmp_path / "b.in"
    first.write_text("Flask==3.1.1\n", encoding="utf-8")
    second.write_text("Flask==3.1.2\n", encoding="utf-8")
    with pytest.raises(ContractError, match="Conflicting requirements"):
        merge_requirement_files([first, second])
