"""Re-run selected historical Task 4 cases with secret-safe diagnostics.

Run as ``python -m scripts.diagnose_task4 --help`` from the repository root.
This uses the configured live target; it never rewrites the source report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from security_eval.contracts import RunContext
from security_eval.core.config import load_settings
from security_eval.core.redaction import build_sanitizer
from security_eval.core.target import TargetClient
from security_eval.modules.task4.models import MatrixCase
from security_eval.modules.task4.module import MODULE_VERSION, Task4Module


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report", type=Path, required=True, help="Historical report.json"
    )
    parser.add_argument(
        "--case-id",
        action="append",
        required=True,
        help="Exact case ID; repeat this argument to run several cases in order",
    )
    parser.add_argument(
        "--output-root", type=Path, default=Path("outputs/task4-diagnostics")
    )
    args = parser.parse_args()
    raw_report = args.report.read_bytes()
    report = json.loads(raw_report)
    task = next(item for item in report["task_results"] if item["task_id"] == 4)
    by_id = {case["case_id"]: case for case in task["cases"]}
    if len(args.case_id) != len(set(args.case_id)):
        parser.error("Case IDs must be unique within a diagnostic run")
    missing = set(args.case_id) - by_id.keys()
    if missing:
        parser.error(f"Task 4 case IDs absent from the report: {sorted(missing)}")
    cases = [
        MatrixCase(
            case_id=case_id,
            category=by_id[case_id]["category"],
            scenario=by_id[case_id]["scenario"],
            **{
                key: by_id[case_id]["metadata"][key]
                for key in ("user_task_id", "injection_task_id", "attack", "defense")
            },
        )
        for case_id in args.case_id
    ]
    settings = load_settings()
    sanitize = build_sanitizer(settings)
    started = datetime.now(timezone.utc)
    run_id = f"{started.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    run_dir = (args.output_root / run_id).resolve()
    cases_dir = run_dir / "task_4" / "cases"
    cases_dir.mkdir(parents=True, exist_ok=False)
    context = RunContext(
        settings=settings,
        target_client=TargetClient.from_settings(settings),
        judge_client=object(),
        artifact_dir=run_dir,
        deadline=started + timedelta(seconds=settings.full_timeout_seconds),
        sanitize_value=sanitize,
    )
    module = Task4Module()
    results = module._run_cases(context, cases, "dynamic", cases_dir)
    results = [
        case.model_copy(update={"source": by_id[case.case_id]["source"]})
        for case in results
    ]
    payload = sanitize(
        {
            "kind": "task4_diagnostic_replay",
            "run_id": run_id,
            "module_version": MODULE_VERSION,
            "source_run_id": report["run_id"],
            "source_report_sha256": hashlib.sha256(raw_report).hexdigest(),
            "started_at": started.isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "configuration": settings.public_summary(),
            "case_ids": args.case_id,
            "cases": [case.model_dump(mode="json") for case in results],
        }
    )
    (run_dir / "diagnostic.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    for case in results:
        code = case.error.details.get("provider_code") if case.error else None
        print(
            f"{case.case_id}: {case.status}; duration_ms={case.duration_ms}; provider_code={code}"
        )
    print(f"Saved diagnostics to {run_dir / 'diagnostic.json'}")


if __name__ == "__main__":
    main()
