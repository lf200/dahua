# Developer A handoff

Public integration surface:

- `security_eval.contracts`: versioned Pydantic models and `EvaluationModule` Protocol.
- `security_eval.core.registry.ModuleRegistry`: manifest-driven module loading.
- `security_eval.core.service.EvaluationService`: estimate, synchronous execute, and single-worker start.
- `security_eval.core.target`: OpenAI-compatible target and judge clients.
- `security_eval.core.redaction.sanitize_value`: mandatory persistence/presentation sanitizer.
- `security_eval.core.benchmark`: per-task manifest and hash validation.

Task modules must not import web modules. Web modules must not import task module internals. Use `tests.fakes.fake_module` while the real modules are unavailable.

Core verification command:

```powershell
python -m pytest tests/core -q
```

Generated assets:

```powershell
python scripts/generate_contract_schema.py
python scripts/merge_requirements.py
python scripts/build_benchmark_manifest.py
```

The benchmark command is expected to fail until task owners deliver all three child manifests.
