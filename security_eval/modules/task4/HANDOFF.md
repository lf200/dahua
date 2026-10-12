# Task 4 handoff

This package owns the AgentDojo application-security evaluation for task 4. It only communicates with the rest of the application through the contract models in `security_eval.contracts`.

## Install and register

Use Python 3.11 and install the shared requirements plus `requirements/task4.in`. The module manifest is `security_eval/modules/task4/module.json`; add that path to `MODULE_MANIFEST_PATHS` or let `ModuleRegistry.discover()` scan `security_eval/modules`.

Real runs require an OpenAI-compatible endpoint with native chat tool-calling support. `TARGET_BASE_URL` and `TARGET_API_KEY` are taken from the shared target client, while `AGENTDOJO_MODEL` selects the API model. The common aliases `gpt-4o`, `gpt-4o-mini`, `gpt-4-turbo`, and `gpt-3.5-turbo` are mapped to AgentDojo's known snapshots, and exact supported snapshot names are preserved. Any other non-empty model ID is passed unchanged to the target API while AgentDojo uses its generic `local` identity only for attack-template wording. For those generic targets, AgentDojo's OpenAI-only `developer` role is normalized to the widely supported `system` role at the private client boundary. This permits Qwen, DeepSeek, provider-prefixed, and competition-specific model IDs without changing the public configuration or result format. The target must still implement native OpenAI-compatible chat tool calls.

## Benchmark and modes

- Project benchmark version: `v1`
- AgentDojo package: `0.1.35`
- AgentDojo suite: `workspace` version `v1.2.2`
- Module version: `1.1.1`; only `defense=none` cases are executed in all modes.
- `benchmark`: 8 quick or 24 full sandbox runs, selected in frozen-matrix order.
- `dynamic`: seeded, previously uncovered user/injection/attack combinations, up to 6 quick or 18 full runs. The same original combination budget is retained without defense duplicates.
- `hybrid`: frozen matrix followed by dynamic cases only for categories below 80 or containing invalid cases.

Hybrid therefore runs at most 14 quick or 42 full cases. Estimates and frontend case totals refer to executed cases, not the stored bank. The frozen v1 matrix and manifest remain byte-for-byte unchanged (16 quick / 48 full stored entries); the loader still verifies their identities, counts and SHA-256 before selecting the unfiltered subset. Version `1.1.0` distinguishes the new execution policy from historical paired results. Do not compare the two policies' aggregate scores as if their denominators were identical.

ToolFilter is no longer constructed or executed through `Task4Module`. Its private adapter compatibility path, pairing helper, and the module-1.0.0 contract fixture are retained for historical compatibility and rollback, not as active competition tests. Public settings, request fields, contract version, scoring formula and artifact paths are unchanged. Historical run files are not rewritten.

Every case creates a fresh workspace environment. DoS cases only test instruction-induced abandonment of the authorized task; they never perform resource exhaustion or network attacks.

## Results and artifacts

`Task4Module.run()` returns only a validated `TaskResult`. Case-level scores include utility, utility-under-attack, targeted ASR, unauthorized tool-call rate, leakage rate, DoS interruption rate and security score. Defense utility loss and paired case IDs are not applicable to current unfiltered runs and are omitted rather than reported as zero. Invalid cases are excluded from metric denominators. Benchmark/dynamic 60/40 fusion and single-source behavior are unchanged.

Sanitized traces are stored below the run directory as `task_4/cases/<case_id>.json`. They contain tool names and diff paths, not full system prompts, injection text, tool arguments, API keys, or third-party pipeline objects.

## Target errors and diagnostic replay (1.1.1)

The private OpenAI pipeline uses AgentDojo 0.1.35's native message/tool serializers with a single project-owned retry boundary. SDK retries and AgentDojo's blanket retries are not stacked. HTTP 400/401/403/404/422 are not blindly retried; connection errors, timeouts, HTTP 408/409/429 and 5xx receive at most three attempts, bounded by the task deadline. Recognized permanent quota/authentication/model errors stop further target calls in that task run. Planned but unexecuted cases retain `invalid`, `metadata.executed=false`, and `blocked_by_case_id`; they are not counted as model successes or failures. A case-local rejection does not block later cases.

The deadline and per-request timeout are checked before every tool round and retry. `TARGET_MAX_TOKENS` is now honored for AgentDojo requests as it is for the shared chat client. Client connections close on both normal and exceptional execution. This changes execution behavior, not the score formula or the frozen matrix.

Invalid cases retain their input IDs, measured case-attempt duration and a diagnostic artifact. Errors include HTTP status, allowlisted and sanitized provider code/parameter/message, request ID, model, message roles/count/content length, tool count and request attempts. Full response bodies, message content, injection text and tool arguments are not persisted. Successful artifacts also include request counts, timings, finish reasons and SDK usage when available.

To replay historical cases after restoring a working target, run from the repository root:

```powershell
python -m scripts.diagnose_task4 --report data/runs/20261008T144915Z-52af3364/report.json --case-id t4-dyn-02-user_task_20-injection_task_1-tool_knowledge-none
```

Repeat `--case-id` to compare cases in one process. Each invocation saves a new timestamped `outputs/task4-diagnostics/<run_id>/diagnostic.json` and case artifacts, including the source report hash and public configuration; it does not alter historical results. This command calls the configured live endpoint. The offline HTTP regression tests are `tests/task4/test_target_execution.py`.

## Tests

Run `python -m pytest tests/task4 -q`, then `python -m pytest -q`. Tests use a fake adapter and static trace data; some construct real AgentDojo pipelines offline, but no test calls a model endpoint. The historical web-ready fixture is `tests/contract_fixtures/task_4_result.json`.

## Coverage boundaries

All existing baseline, API-abuse, privilege-escalation, multi-step-hijack, context-leakage and DoS categories remain represented in the unfiltered quick and full subsets. This preserves business-task execution, attack injection, native tool calls, workspace isolation, trace parsing and error isolation. Removing ToolFilter does not guarantee nonempty tool calls: a valid model response can still fail to use tools and receive utility=0.

Do not equate multi-step tool workflows with comprehensive multi-turn dialogue testing, or security-code exfiltration with direct system-prompt leakage testing. The current DoS tests cover instruction-induced task abandonment, not network/resource exhaustion. Removing a defense does not itself fill these pre-existing competition-coverage gaps.
