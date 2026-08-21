"""Manual local server for UI demos without API keys or model calls."""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


if __name__ == "__main__":
    from security_eval.web.app import create_app
    from tests.web.conftest import FakeEvaluationService

    output_root = Path("data/fixture-runs").resolve()
    app = create_app(
        service=FakeEvaluationService(output_root),
        output_root=output_root,
        public_settings={
            "target_model": "fixture-target",
            "judge_model": "fixture-judge",
            "application_security_model": "fixture-application",
        },
    )
    app.run(host="127.0.0.1", port=5055, debug=False, use_reloader=False)
