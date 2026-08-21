# Task 4 handoff

This package owns the application security engine application-security evaluation for task 4. It only communicates with the rest of the application through the contract models in `security_eval.contracts`.

## Install and register

Use Python 3.11 and install the shared requirements plus `requirements/task4.in`. The module manifest is `security_eval/modules/task4/module.json`; add that path to `MODULE_MANIFEST_PATHS` or let `ModuleRegistry.discover()` scan `security_eval/modules`.

Real runs require an OpenAI-compatible endpoint with native chat tool-calling support. `TARGET_BASE_URL` and `TARGET_API_KEY` are taken from the shared target client, while `APPLICATION_SECURITY_MODEL` selects the API model. application security engine 0.1.35 must also recognize the model family used by its attack templates. The common aliases `gpt-4o`, `gpt-4o-mini`, `gpt-4-turbo`, and `gpt-3.5-turbo` are mapped to application security engine's known snapshots; exact supported snapshot names are accepted directly. Unknown custom model IDs are rejected by `validate()` before any case starts.

## Benchmark and modes

- Project benchmark version: `v1`
- application security engine package: `0.1.35`
- application security engine suite: `workspace` version `v1.2.2`
- `benchmark`: frozen matrix, 16 quick or 48 full sandbox runs.
- `dynamic`: seeded, previously uncovered user/injection/attack combinations, defense-paired up to 12 quick or 36 full runs.
- `hybrid`: frozen matrix followed by dynamic cases only for categories below 80 or containing invalid cases.

Every case creates a fresh workspace environment. DoS cases only test instruction-induced abandonment of the authorized task; they never perform resource exhaustion or network attacks.

## Results and artifacts

`Task4Module.run()` returns only a validated `TaskResult`. Case-level scores include utility, utility-under-attack, targeted ASR, unauthorized tool-call rate, leakage rate, DoS interruption rate, defense utility loss when paired, and security score. Invalid cases are excluded from metric denominators.

Sanitized traces are stored below the run directory as `task_4/cases/<case_id>.json`. They contain tool names and diff paths, not full system prompts, injection text, tool arguments, API keys, or third-party pipeline objects.

## Tests

Run `pytest tests/task4 -q`. Tests use a fake adapter and static trace data; they never call application security engine, a model, or the network. The web-ready fixture is `tests/contract_fixtures/task_4_result.json`.
