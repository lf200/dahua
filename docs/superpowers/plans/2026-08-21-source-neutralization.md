# Source-Neutral Security Interfaces Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove vendor-specific naming from every first-party configuration, symbol, contract, report, interface, test, and document while preserving the existing security-evaluation behavior.

**Architecture:** Third-party packages remain confined to private adapter imports and runtime interoperability lines. All code outside those boundaries communicates through `DynamicTest*` and `ApplicationSecurity*` interfaces and serializes only `dynamic_test` or `application_security` identifiers. This is a hard cut with no compatibility aliases for old environment variables, Python paths, or report fields.

**Tech Stack:** Python 3.11, Pydantic v2, Flask 3.x, pytest, JSON Schema, YAML

**Spec:** `docs/superpowers/specs/2026-08-21-source-neutralization-design.md`

## Global Constraints

- Third-party names may appear only in dependency declarations, import/module-loading statements, package-version lookup strings, and required telemetry environment variables.
- Use `dynamic_test` / `DynamicTest` for dynamic adversarial and content-safety capabilities.
- Use `application_security` / `ApplicationSecurity` for isolated application and tool-use safety capabilities.
- Rename the environment variable to `APPLICATION_SECURITY_MODEL` and the settings field to `application_security_model`.
- Do not retain compatibility aliases for old configuration keys, JSON fields, CSS classes, Python symbols, or module paths.
- Preserve benchmark data, attack selection, scoring, timeouts, redaction, and path-safety behavior.
- Every commit must use Conventional Commits and contain a coherent, independently tested change.

---

### Task 1: Neutral configuration and contract vocabulary

**Files:**
- Modify: `.env.example`
- Modify: `security_eval/core/config.py`
- Modify: `security_eval/contracts.py`
- Modify: `tests/core/conftest.py`
- Modify: `tests/core/test_config.py`
- Modify: `tests/core/test_contracts.py`
- Modify: `tests/e2e/fixture_server.py`
- Regenerate: `docs/contracts-v1.schema.json`

**Interfaces:**
- Produces: `Settings.application_security_model: str`
- Produces: `CaseResult.engine: Literal["benchmark", "dynamic_test", "application_security", "fake"]`
- Produces: `Settings.public_summary()["application_security_model"]`

- [ ] **Step 1: Write failing configuration and contract tests**

```python
def test_application_security_model_uses_target_default(tmp_path) -> None:
    env = base_env() | {"OUTPUT_ROOT": str(tmp_path / "runs")}
    settings = load_settings(env, dotenv_path=None)
    assert settings.application_security_model == "model-a"


def test_application_security_model_accepts_explicit_value() -> None:
    settings = load_settings(
        base_env() | {"APPLICATION_SECURITY_MODEL": "app-model"},
        dotenv_path=None,
    )
    assert settings.application_security_model == "app-model"
    assert settings.public_summary()["application_security_model"] == "app-model"
```

- [ ] **Step 2: Run the focused tests and verify they fail on the missing neutral field**

Run: `pytest tests/core/test_config.py tests/core/test_contracts.py -q`

Expected: FAIL because `application_security_model` and the new engine literals do not exist yet.

- [ ] **Step 3: Implement the hard-cut configuration and contract rename**

Change the settings model, validator list, public summary, loader, fixtures, and `.env.example`. Remove the old key entirely; preserve fallback to `TARGET_MODEL`.

- [ ] **Step 4: Regenerate the JSON Schema and run focused tests**

Run: `python scripts/generate_contract_schema.py`

Run: `pytest tests/core tests/e2e/test_fake_journey.py -q`

Expected: PASS with only the neutral configuration and engine values in generated schema and fixtures.

- [ ] **Step 5: Commit**

```bash
git add .env.example security_eval/core/config.py security_eval/contracts.py tests/core tests/e2e/fixture_server.py docs/contracts-v1.schema.json
git commit -m "refactor(config): neutralize security engine settings"
```

### Task 2: Neutralize Task 1 dynamic testing boundary

**Files:**
- Create by renaming the existing adapter: `security_eval/modules/task1/dynamic_test_adapter.py`
- Modify: `security_eval/modules/task1/module.py`
- Modify: `security_eval/modules/task1/HANDOFF.md`
- Create by renaming the existing adapter tests: `tests/task1/test_dynamic_test_adapter.py`
- Modify: `tests/task1/test_module.py`
- Modify: `tests/contract_fixtures/task_1_result.json`

**Interfaces:**
- Produces: `DynamicTestRunSpec`, `DynamicTestBackend`, `DynamicTestAdapter`
- Produces: `DynamicObservation.engine_score` and `DynamicObservation.engine_reason`
- Produces: neutral evidence keys `dynamic_test`, `engine_score`, `engine_reason`, and `engine_version`

- [ ] **Step 1: Rename the adapter test file and write neutral-output assertions**

```python
def test_dynamic_observation_uses_neutral_evidence_names() -> None:
    observation = DynamicObservation(
        category="prompt_injection",
        scenario="dynamic prompt variant",
        target_messages=[],
        engine_score=1.0,
        engine_reason="blocked",
    )
    payload = observation.model_dump()
    assert payload["engine_score"] == 1.0
    assert payload["engine_reason"] == "blocked"
```

- [ ] **Step 2: Run Task 1 tests and verify imports or fields fail**

Run: `pytest tests/task1 tests/core/test_contracts.py -q`

Expected: FAIL until the module path, symbols, engine literals, evidence, errors, and fixture are renamed.

- [ ] **Step 3: Rename the adapter boundary and first-party vocabulary**

Keep third-party imports and runtime interoperability intact, but alias imported vendor types to neutral local names. Rewrite module notes, scenarios, error messages, evidence summaries, metadata keys, and handoff prose to capability-oriented language.

- [ ] **Step 4: Run Task 1 tests**

Run: `pytest tests/task1 tests/core/test_contracts.py -q`

Expected: PASS with `engine="dynamic_test"` for dynamic cases.

- [ ] **Step 5: Commit**

```bash
git add security_eval/modules/task1 tests/task1 tests/contract_fixtures/task_1_result.json
git commit -m "refactor(task1): neutralize dynamic testing adapter"
```

### Task 3: Neutralize Task 2 dynamic testing boundary

**Files:**
- Create by renaming the existing adapter: `security_eval/modules/task2/dynamic_test_adapter.py`
- Modify: `security_eval/modules/task2/models.py`
- Modify: `security_eval/modules/task2/module.py`
- Modify: `security_eval/modules/task2/HANDOFF.md`
- Modify: `security_eval/modules/task2/IMPLEMENTATION_PLAN.md`
- Create by renaming the existing adapter tests: `tests/task2/test_dynamic_test_adapter.py`
- Modify: `tests/task2/conftest.py`
- Modify: `tests/task2/test_delivery.py`
- Modify: `tests/task2/test_module.py`
- Modify: `tests/contract_fixtures/task_2_result.json`

**Interfaces:**
- Produces: `DynamicTestAPI` and `DynamicTestAdapter`
- Produces: `Task2Case.engine: Literal["benchmark", "dynamic_test"]`
- Preserves the upstream Task 2 `Task2Case` shape without reintroducing the removed provenance model

- [ ] **Step 1: Rename the adapter test and add neutral generated-case assertions**

```python
def test_generated_case_uses_neutral_engine(fake_api) -> None:
    adapter = DynamicTestAdapter(api_loader=lambda: fake_api)
    cases = adapter.generate(["hate"], "quick", 7)
    assert cases[0].engine == "dynamic_test"
```

- [ ] **Step 2: Run Task 2 tests and verify the old interfaces fail**

Run: `pytest tests/task2 tests/core/test_contracts.py -q`

Expected: FAIL until imports, literals, errors, and fixtures use the neutral names.

- [ ] **Step 3: Implement the Task 2 rename without changing generation behavior**

Alias third-party imported types locally, preserve lazy import and telemetry opt-out, and replace all first-party class names, variables, scenarios, errors, URLs, and prose that identify the implementation source. Keep the upstream provenance-free Task 2 model intact.

- [ ] **Step 4: Run Task 2 tests**

Run: `pytest tests/task2 tests/core/test_contracts.py -q`

Expected: PASS with unchanged case counts and scoring behavior.

- [ ] **Step 5: Commit**

```bash
git add security_eval/modules/task2 tests/task2 tests/contract_fixtures/task_2_result.json
git commit -m "refactor(task2): neutralize dynamic testing adapter"
```

### Task 4: Neutralize Task 4 application-security boundary

**Files:**
- Create by renaming the existing adapter: `security_eval/modules/task4/application_security_adapter.py`
- Modify: `security_eval/modules/task4/__init__.py`
- Modify: `security_eval/modules/task4/categories.py`
- Modify: `security_eval/modules/task4/models.py`
- Modify: `security_eval/modules/task4/module.py`
- Modify: `security_eval/modules/task4/trace_parser.py`
- Modify: `security_eval/modules/task4/HANDOFF.md`
- Modify: `benchmarks/v1/task4/matrix.yaml`
- Modify: `tests/task4/__init__.py`
- Modify: `tests/task4/conftest.py`
- Modify: `tests/task4/test_contract_fixture.py`
- Modify: `tests/task4/test_module.py`
- Modify: `tests/task4/test_trace_and_scoring.py`
- Modify: `tests/contract_fixtures/task_4_result.json`

**Interfaces:**
- Produces: `ApplicationSecurityAdapter`
- Produces: `Settings.application_security_model` consumption
- Produces: `MatrixConfig.engine_version` and `AdapterResult.engine_version`
- Produces: `engine="application_security"` and evidence key `engine_version`

- [ ] **Step 1: Write failing application-security interface assertions**

```python
def test_adapter_result_exposes_neutral_version_field() -> None:
    result = AdapterResult(
        utility=True,
        security=True,
        messages=[],
        ground_truth_calls=[],
        environment_diff={},
        duration_ms=1,
        engine_version="0.1.35",
    )
    assert result.model_dump()["engine_version"] == "0.1.35"
```

- [ ] **Step 2: Run Task 4 tests and verify old interfaces fail**

Run: `pytest tests/task4 tests/core/test_config.py -q`

Expected: FAIL until adapter imports, settings access, version fields, matrix metadata, trace payloads, errors, and fixtures are neutralized.

- [ ] **Step 3: Implement the Task 4 hard-cut rename**

Retain package imports and metadata lookup required to execute the third-party suite. Rename all first-party files, classes, constants, settings references, comments, docstrings, module metadata, trace keys, errors, and report values.

- [ ] **Step 4: Run Task 4 tests**

Run: `pytest tests/task4 tests/core/test_config.py -q`

Expected: PASS with unchanged utility/security scoring and trace parsing.

- [ ] **Step 5: Commit**

```bash
git add security_eval/modules/task4 benchmarks/v1/task4/matrix.yaml tests/task4 tests/contract_fixtures/task_4_result.json
git commit -m "refactor(task4): neutralize application security adapter"
```

### Task 5: Neutralize Web presentation and report output

**Files:**
- Modify: `security_eval/web/app.py`
- Modify: `security_eval/web/routes.py`
- Modify: `security_eval/web/presentation.py`
- Modify: `security_eval/web/templates/run.html`
- Modify: `security_eval/web/static/style.css`
- Modify: `tests/web/conftest.py`
- Modify: `tests/web/test_routes.py`
- Modify: `tests/e2e/test_fake_journey.py`

**Interfaces:**
- Consumes: `application_security_model`, `dynamic_test`, and `application_security`
- Produces: presentation key `application_security_metrics`
- Produces: CSS class `application-security-metrics`

- [ ] **Step 1: Add failing Web response assertions**

```python
def test_run_page_uses_application_security_metrics(client, completed_run) -> None:
    response = client.get(f"/runs/{completed_run}")
    assert response.status_code == 200
    assert b"Application Security" in response.data
```

Also assert the presentation dictionary contains `application_security_metrics` and no superseded vendor-keyed field.

- [ ] **Step 2: Run Web and E2E tests and verify they fail**

Run: `pytest tests/web tests/e2e -q`

Expected: FAIL until the public settings allowlist, presentation model, template, CSS, and fixture journey are updated.

- [ ] **Step 3: Implement neutral Web output**

Rename all presentation keys, helper names, template conditions, CSS selectors, docstrings, and settings allowlist entries. Ensure report downloads contain only the new contract values.

- [ ] **Step 4: Run Web and E2E tests**

Run: `pytest tests/web tests/e2e -q`

Expected: PASS with neutral HTML and report JSON.

- [ ] **Step 5: Commit**

```bash
git add security_eval/web tests/web tests/e2e
git commit -m "refactor(web): neutralize security report presentation"
```

### Task 6: Clean repository documentation and enforce the boundary

**Files:**
- Modify: `README.md`
- Modify: `docs/demo-script.md`
- Modify: `plan/architecture-five-person-parallel-development-5.md`
- Modify: `plan/feature-hybrid-security-benchmark-4.md`
- Modify: `requirements/task1.in`
- Create: `tests/core/test_source_neutrality.py`
- Modify any remaining tracked first-party text file reported by the repository scan

**Interfaces:**
- Produces: a repository-level regression test that rejects forbidden vendor identifiers outside explicit runtime-interoperability lines

- [ ] **Step 1: Write the repository guard test**

```python
FORBIDDEN_TERMS = ("deep" + "team", "deep" + "eval", "agent" + "dojo")


def test_first_party_files_do_not_expose_vendor_names() -> None:
    violations = scan_tracked_text_files(
        root=PROJECT_ROOT,
        forbidden_terms=FORBIDDEN_TERMS,
        allowed_dependency_files=ALLOWED_DEPENDENCY_FILES,
    )
    assert violations == []
```

The scanner must allow only dependency declaration lines, import/module-loading lines, package-version lookup strings, and required telemetry environment-variable lines. It must report `path:line:text` for every other match.

- [ ] **Step 2: Run the guard and capture all remaining violations**

Run: `pytest tests/core/test_source_neutrality.py -q`

Expected: FAIL and list every remaining first-party occurrence.

- [ ] **Step 3: Neutralize all remaining documentation, comments, symbols, fixture text, and requirement comments**

Do not alter dependency pins or required interoperability tokens. Remove superseded adapter/test files after confirming their neutral replacements exist.

- [ ] **Step 4: Run repository and full-suite verification**

Run: `pytest tests/core/test_source_neutrality.py -q`

Run: `pytest -q`

Run: `git diff --check`

Expected: the guard passes, the complete test suite reports zero failures, and diff validation reports no whitespace errors.

- [ ] **Step 5: Commit**

```bash
git add README.md docs plan requirements/task1.in tests/core/test_source_neutrality.py
git add -u
git commit -m "docs: remove vendor-specific implementation language"
```

### Task 7: Final audit and PR delivery

**Files:**
- Review: all changed files

**Interfaces:**
- Produces: a reviewable feature branch and GitHub pull request containing only the approved source-neutralization work

- [ ] **Step 1: Verify branch state and commit structure**

Run: `git status --short --branch`

Run: `git log --oneline origin/main..HEAD`

Expected: clean worktree and Conventional Commit messages grouped by configuration, tasks, Web, and documentation.

- [ ] **Step 2: Re-run final verification from a clean state**

Run: `pytest -q`

Run: `pytest tests/core/test_source_neutrality.py -q`

Run: `git diff --check origin/main...HEAD`

Expected: zero failures and no diff errors.

- [ ] **Step 3: Review the complete PR diff**

Run: `git diff --stat origin/main...HEAD`

Run: `git diff --name-status origin/main...HEAD`

Confirm renamed files have no duplicate superseded copies and dependency pins remain unchanged.

- [ ] **Step 4: Push and create the PR**

```bash
git push -u origin codex/source-neutral-security
gh pr create --base main --head codex/source-neutral-security --title "refactor: neutralize security engine interfaces" --body-file <prepared-pr-body>
```

The PR body must summarize the hard-cut configuration/contract changes, task adapter renames, Web/report changes, documentation cleanup, compatibility impact, and exact test results.
