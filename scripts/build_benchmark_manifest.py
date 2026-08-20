"""Validate task-owned benchmark manifests and build their combined manifest."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security_eval.core.benchmark import build_combined_manifest, write_combined_manifest
from security_eval.errors import EvaluationError


DEFAULT_INPUTS = (
    Path("benchmarks/v1/task1/manifest.yaml"),
    Path("benchmarks/v1/task2/manifest.yaml"),
    Path("benchmarks/v1/task4/manifest.yaml"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*", type=Path, default=list(DEFAULT_INPUTS))
    parser.add_argument("--output", type=Path, default=Path("benchmarks/v1/manifest.yaml"))
    parser.add_argument("--version", default="v1")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        manifest = build_combined_manifest(args.inputs, benchmark_version=args.version)
        write_combined_manifest(manifest, args.output)
    except EvaluationError as exc:
        print(f"benchmark manifest build failed: {exc}")
        return 1
    print(f"wrote {args.output} with {len(manifest.tasks)} task manifests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
