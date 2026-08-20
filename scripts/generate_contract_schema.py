"""Generate the versioned public contract JSON Schema."""

from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pydantic import TypeAdapter

from security_eval.contracts import PUBLIC_SCHEMA_MODELS


def build_schema() -> dict[str, object]:
    definitions: dict[str, object] = {}
    for model in PUBLIC_SCHEMA_MODELS:
        definitions[model.__name__] = TypeAdapter(model).json_schema()
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://local.example/security-eval/contracts-v1.schema.json",
        "title": "Security Evaluation Public Contracts v1",
        "type": "object",
        "$defs": definitions,
    }


def main() -> int:
    output = Path("docs/contracts-v1.schema.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(build_schema(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
