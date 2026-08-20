---
goal: "将混合大模型安全测评系统拆分为五个可独立开发、按统一契约直接集成的工作包"
version: "5.0"
date_created: "2026-08-20"
last_updated: "2026-08-20"
owner: "five-person-competition-team"
status: "Planned"
tags: [architecture, parallel-development, integration, deepteam, agentdojo, flask, benchmark]
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

本计划把系统拆为五个互不重叠的代码所有权区域：开发者 A 负责核心协议与编排，开发者 B 负责任务 1，开发者 C 负责任务 2，开发者 D 负责任务 4，开发者 E 负责 Flask、存储与报告。五人只通过 `contract_version="1.0"` 的 Pydantic 数据模型交互，禁止跨目录调用内部函数。开发者 B/C/D 必须提供标准化结果 fixture，开发者 E 使用 fixture 独立完成页面；因此三项真实评测尚未完成时，Web 和报告仍可开发与测试。

唯一需要全员同步的工作是开始后的前 4 小时：冻结契约、目录和错误码。契约冻结后，任何字段变更必须新建版本，不能直接修改已有字段。完成后按“核心→三个任务模块（任意顺序）→Web 报告”的顺序合并，不需要手工复制代码。

## 1. Requirements & Constraints

- **REQ-001**: 五个工作包必须拥有互斥的源文件目录；除开发者 A 外，任何人不得修改 `security_eval/core/`，除开发者 E 外，任何人不得修改 `security_eval/web/`。
- **REQ-002**: 任务 1、2、4 模块必须实现同一个 `EvaluationModule` Protocol，且只能通过 `ModuleRequest`、`RunContext`、`TaskResult` 与核心层交互。
- **REQ-003**: 统一契约必须使用 Pydantic v2，固定 `contract_version="1.0"`，所有结果在写盘、模块返回和页面加载时各校验一次。
- **REQ-004**: 任务 1 模块同时交付 20 个固定 Benchmark 用例和 DeepTeam 动态攻击；任务 2 模块同时交付 24 个固定 Benchmark 用例和 DeepTeam 动态攻击。
- **REQ-005**: 任务 4 模块的固定与动态测试全部使用 AgentDojo `workspace` 沙箱，交付固定矩阵、动态组合、trace 解析和防御前后指标。
- **REQ-006**: Flask/Web 层不得导入 DeepTeam、AgentDojo 或任务模块内部类；它只能调用核心 `EvaluationService` 并渲染 `RunReport`。
- **REQ-007**: 三个任务模块不得导入 Flask、Jinja、routes、storage 或 report；模块只允许把中间证据写到 `RunContext.artifact_dir/task_<id>/`。
- **REQ-008**: 每个任务模块必须提供 `tests/contract_fixtures/task_<id>_result.json`，内容同时覆盖通过、失败和 invalid 用例，使 Web 开发者无需真实模型即可开发。
- **REQ-009**: 每个任务模块必须提供 `module.json`，声明 `task_id`、模块导入路径、类名、依赖文件、Benchmark 版本、支持的 mode/profile 和契约版本；核心通过注册表加载，不硬编码模块内部实现。
- **REQ-010**: 运行参数固定为 `tasks: list[Literal[1,2,4]]`、`mode: Literal["benchmark","dynamic","hybrid"]`、`profile: Literal["quick","full"]`、`seed: int` 和 `authorized_target: bool`。
- **REQ-011**: `TaskResult` 必须包含任务独立得分；核心只负责计算任务 1/2/4 等权总体展示分，不允许跨任务修改原始 case 或任务分。
- **REQ-012**: 每个工作包必须有独立单元测试命令、fixture、依赖清单和 `HANDOFF.md`；交付时不能要求集成人猜测启动方式或数据格式。
- **REQ-013**: 根目录依赖文件只由开发者 A 生成；开发者 B/C/D/E 分别维护 `requirements/task1.in`、`task2.in`、`task4.in`、`web.in`，禁止多人同时编辑 `requirements.txt`。
- **REQ-014**: Benchmark 总清单不允许多人编辑；B/C/D 分别维护自己的 `benchmarks/v1/taskN/manifest.yaml`，A 使用 `scripts/build_benchmark_manifest.py` 生成只读总清单。
- **REQ-015**: 所有单元测试必须使用 mock 或 fixture，禁止默认调用真实模型；真实网络 smoke test 只在最终集成阶段由 A 统一执行。
- **SEC-001**: 统一契约中的输入、输出和 evidence 在返回前必须调用核心 `sanitize_value()`；任务模块不得自行记录 `.env`、API Key、Bearer Token 或完整系统提示词。
- **SEC-002**: AgentDojo 模块只能访问其 run artifact 目录和内置沙箱；不得向 Web 层暴露可执行工具对象或真实外部连接。
- **SEC-003**: 所有模块的错误必须转换为 `ErrorInfo`，禁止把带环境变量、路径外信息或第三方完整堆栈的异常直接显示到页面。
- **CON-001**: 五人使用独立 Git 分支和 Pull Request；一个文件只能有一个明确 owner，禁止在集成前互相 cherry-pick 未完成提交。
- **CON-002**: 七天内不实现前后端分离、数据库、Redis/Celery、Docker/Kubernetes 或生产部署；Flask 使用本地文件保存运行状态。
- **CON-003**: 契约冻结后删除或重命名字段属于破坏性变更，必须创建 `contract_version="2.0"`；本比赛周期内原则上不允许发生。
- **GUD-001**: 每人只依赖契约和公开 fixture，不依赖其他人的未完成实现；跨模块需求通过 issue 记录，不能直接修改对方代码。
- **GUD-002**: 集成测试只验证公开接口和最终行为，不测试其他模块的私有函数。
- **PAT-001**: 使用 Registry + Protocol + Contract Fixture 模式：注册表发现模块，Protocol 约束行为，fixture 解耦消费者与生产者。

### 冻结后的目录结构与文件所有权

| Owner | 独占目录/文件 | 禁止修改 |
|---|---|---|
| 开发者 A | `security_eval/core/`、`security_eval/contracts.py`、`security_eval/errors.py`、`requirements/base.in`、根 `requirements.txt`、`scripts/build_benchmark_manifest.py`、`tests/core/` | `modules/task1/`、`modules/task2/`、`modules/task4/`、`web/` |
| 开发者 B | `security_eval/modules/task1/`、`benchmarks/v1/task1/`、`requirements/task1.in`、`tests/task1/`、`tests/contract_fixtures/task_1_result.json` | core、task2、task4、web |
| 开发者 C | `security_eval/modules/task2/`、`benchmarks/v1/task2/`、`requirements/task2.in`、`tests/task2/`、`tests/contract_fixtures/task_2_result.json` | core、task1、task4、web |
| 开发者 D | `security_eval/modules/task4/`、`benchmarks/v1/task4/`、`requirements/task4.in`、`tests/task4/`、`tests/contract_fixtures/task_4_result.json` | core、task1、task2、web |
| 开发者 E | `app.py`、`security_eval/web/`、`requirements/web.in`、`tests/web/`、`tests/e2e/`、`README.md`、`docs/` | core、三个任务模块、三个 Benchmark 目录 |

### 必须在第 1 天前 4 小时冻结的接口

```python
class EvaluationModule(Protocol):
    task_id: Literal[1, 2, 4]

    def metadata(self) -> ModuleMetadata: ...
    def estimate(self, request: ModuleRequest) -> Estimate: ...
    def validate(self, context: RunContext) -> list[Issue]: ...
    def run(self, context: RunContext, request: ModuleRequest) -> TaskResult: ...
```

`ModuleRequest` 固定字段：`run_id`、`mode`、`profile`、`seed`、`benchmark_version`。`RunContext` 固定字段：`settings`、`target_client`、`judge_client`、`artifact_dir`、`deadline`、`sanitize_value`。模块不得在这两个对象上动态增加字段。

`CaseResult` 固定字段：`case_id`、`task_id`、`source`、`engine`、`category`、`scenario`、`status`、`scores`、`reason`、`input`、`output`、`evidence`、`duration_ms`、`error`、`metadata`。`status` 只能为 `passed|failed|partial|invalid`。

`TaskResult` 固定字段：`contract_version`、`task_id`、`module_version`、`benchmark_version`、`mode`、`profile`、`cases`、`category_summaries`、`benchmark_score`、`dynamic_score`、`final_score`、`risk_level`、`errors`、`started_at`、`finished_at`。

统一错误码：`CONFIG_ERROR`、`DEPENDENCY_ERROR`、`TARGET_ERROR`、`TIMEOUT_ERROR`、`PARSE_ERROR`、`CASE_ERROR`、`CONTRACT_ERROR`、`INTERNAL_ERROR`。模块内部异常必须映射到其中之一。

## 2. Implementation Steps

### Implementation Phase 1 — 开发者 A：核心协议、适配与编排

- **GOAL-001**: 提供其他四人可以立即依赖的稳定契约、模拟客户端和模块装配能力。

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | 创建 `security_eval/contracts.py`，实现 `ModuleRequest`、`RunContext`、`Evidence`、`ErrorInfo`、`CaseResult`、`CategorySummary`、`TaskResult`、`RunReport`、`ModuleMetadata`、`Estimate` 和 `Issue` Pydantic 模型；生成 `docs/contracts-v1.schema.json`。 |  |  |
| TASK-002 | 创建 `security_eval/core/config.py`、`target.py`、`redaction.py` 和 `clock.py`；实现只读 Settings、OpenAI-compatible TargetClient/JudgeClient、递归脱敏和可注入测试时钟。 |  |  |
| TASK-003 | 创建 `security_eval/core/registry.py`；扫描三个 `module.json`，校验 task_id 唯一、contract_version=1.0，并通过 importlib 实例化 EvaluationModule。 |  |  |
| TASK-004 | 创建 `security_eval/core/service.py`；实现 `EvaluationService.estimate/start/execute`，按选择任务调用模块、捕获标准错误、聚合总体展示分并返回 RunReport。 |  |  |
| TASK-005 | 创建 `security_eval/core/benchmark.py` 和 `scripts/build_benchmark_manifest.py`；校验三个子清单 Schema/SHA-256 并生成总清单，禁止直接写入子模块目录。 |  |  |
| TASK-006 | 创建 `tests/core/` 和 `tests/fakes/fake_module.py`；验证契约序列化、注册表、模块缺失、超时、partial、脱敏、总体分和错误码。 |  |  |
| TASK-007 | 创建 `requirements/base.in`、依赖合并脚本和根 `requirements.txt`；只合并四个子依赖清单，不允许自动升级固定版本。 |  |  |

开发者 A 完成标准：其他四人只安装 base 依赖即可导入契约；fake module 能跑通完整 service；`pytest tests/core -q` 返回 0；A 不实现任何任务具体用例和 HTML。

### Implementation Phase 2 — 开发者 B：任务 1 对抗攻击模块

- **GOAL-002**: 独立交付任务 1 的静态 Benchmark、DeepTeam 动态测试、三维评分和契约 fixture。

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-008 | 创建 `benchmarks/v1/task1/cases.jsonl`、`labels.yaml` 和 `manifest.yaml`；包含提示注入、间接提示、角色越狱、逻辑陷阱、上下文劫持各 4 个用例，固定 quick/full 子集与恢复探针。 |  |  |
| TASK-009 | 创建 `security_eval/modules/task1/module.py` 的 `Task1Module`，实现四个 Protocol 方法；benchmark 模式运行固定 messages，dynamic 模式调用 DeepTeam，hybrid 模式只扩展静态低分类别。 |  |  |
| TASK-010 | 创建 `security_eval/modules/task1/deepteam_adapter.py`；封装 PromptInjection、IndirectInstruction、Roleplay、Robustness、LinearJailbreaking，所有第三方对象只存在于本目录。 |  |  |
| TASK-011 | 创建 `security_eval/modules/task1/scoring.py`；按识别 30%、阻断 50%、恢复 20% 计算 0–100，输出三个子分和同会话恢复证据。 |  |  |
| TASK-012 | 创建 `security_eval/modules/task1/module.json`、`requirements/task1.in`、`HANDOFF.md` 和 `tests/contract_fixtures/task_1_result.json`。 |  |  |
| TASK-013 | 创建 `tests/task1/`；mock 目标和 DeepTeam，验证 20 个 case、quick 子集、动态变体、多轮 3/5 上限、错误隔离、契约校验和脱敏。 |  |  |

开发者 B 完成标准：`Task1Module.run()` 只返回 TaskResult；fixture 同时含 passed/failed/invalid；`pytest tests/task1 -q` 返回 0；B 不导入 Flask/AgentDojo，不修改 core。

### Implementation Phase 3 — 开发者 C：任务 2 内容安全模块

- **GOAL-003**: 独立交付任务 2 的静态 Benchmark、DeepTeam 动态测试、三维内容评分和契约 fixture。

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-014 | 创建 `benchmarks/v1/task2/cases.jsonl`、`labels.yaml` 和 `manifest.yaml`；IllegalActivity、Misinformation、Bias、GraphicContent、Toxicity、PersonalSafety 各 4 个用例，包含直接风险、绕过、包装和安全边界。 |  |  |
| TASK-015 | 创建 `security_eval/modules/task2/module.py` 的 `Task2Module`，实现四个 Protocol 方法和 benchmark/dynamic/hybrid 三种路径。 |  |  |
| TASK-016 | 创建 `security_eval/modules/task2/deepteam_adapter.py`；封装六类漏洞、EvaluationExample、evaluation_guidelines 和 AttackEngine，保持固定与动态判定口径一致。 |  |  |
| TASK-017 | 创建 `security_eval/modules/task2/scoring.py`；按内容合规 50%、伦理约束 20%、风险响应 30% 评分，同时检测过度拒绝。 |  |  |
| TASK-018 | 创建 `security_eval/modules/task2/module.json`、`requirements/task2.in`、`HANDOFF.md` 和 `tests/contract_fixtures/task_2_result.json`。 |  |  |
| TASK-019 | 创建 `tests/task2/`；验证 24 个 case、quick 子集、三种 expected_action、动态变体、过度拒绝、invalid、契约和脱敏。 |  |  |

开发者 C 完成标准：`pytest tests/task2 -q` 返回 0；fixture 能展示合规拒绝、不安全回答、过度拒绝和 invalid；C 不导入 Flask/AgentDojo，不修改 core。

### Implementation Phase 4 — 开发者 D：任务 4 AgentDojo 应用安全模块

- **GOAL-004**: 独立交付 AgentDojo 固定 Benchmark、动态组合、沙箱 trace 指标和契约 fixture。

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-020 | 创建 `benchmarks/v1/task4/matrix.yaml` 和 `manifest.yaml`；固定 workspace suite/version、user task、injection task、ImportantInstructions/ToolKnowledge/DoSAttack、None/tool_filter、quick/full 组合和 seed。 |  |  |
| TASK-021 | 创建 `security_eval/modules/task4/module.py` 的 `Task4Module`，实现四个 Protocol 方法；固定模式按 matrix，动态模式从未覆盖组合抽样，hybrid 模式补测薄弱风险。 |  |  |
| TASK-022 | 创建 `security_eval/modules/task4/agentdojo_adapter.py`；每个 case 新建沙箱，所有日志写 `artifact_dir/task_4/`，禁止暴露第三方 pipeline 对象。 |  |  |
| TASK-023 | 创建 `security_eval/modules/task4/trace_parser.py` 和 `scoring.py`；通过 environment diff、ground-truth 工具序列和 trace 计算 Utility、UUA、ASR、未授权工具调用率、泄露率、DoS 中断率和防御 utility loss。 |  |  |
| TASK-024 | 创建 `security_eval/modules/task4/module.json`、`requirements/task4.in`、`HANDOFF.md` 和 `tests/contract_fixtures/task_4_result.json`。 |  |  |
| TASK-025 | 创建 `tests/task4/`；使用固定 AgentDojo 日志 fixture 验证布尔方向、沙箱重置、异常 invalid、trace 路径、防御对比和契约。 |  |  |

开发者 D 完成标准：`pytest tests/task4 -q` 返回 0；任务 4 engine 只为 agentdojo；fixture 含 baseline/attack/defense/DoS；D 不导入 Flask/DeepTeam，不修改 core。

### Implementation Phase 5 — 开发者 E：Flask、存储、报告与演示

- **GOAL-005**: 只依赖契约 fixtures 完成用户可操作的单体应用和最终展示。

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-026 | 创建 `app.py`、`security_eval/web/app.py` 和 `routes.py`；实现 GET `/`、POST `/runs`、GET `/runs/<id>`、GET `/api/runs/<id>`、GET `/runs/<id>/report.json`，只调用 EvaluationService 公共方法。 |  |  |
| TASK-027 | 创建 `security_eval/web/storage.py`；实现 run_id 白名单、原子 status/report JSON、重启恢复、单运行锁和 artifact 下载边界。 |  |  |
| TASK-028 | 创建 `security_eval/web/presentation.py`；把 RunReport 转换为只读 ViewModel，显示静态/动态/综合分、类别、风险、AgentDojo 指标、失败证据和 invalid，不重新评分。 |  |  |
| TASK-029 | 创建 `security_eval/web/templates/` 和 `static/style.css`；使用服务端 Jinja、少量轮询 JavaScript和响应式单列页面，不引入 Node/npm/CDN。 |  |  |
| TASK-030 | 创建 `tests/web/`；逐个加载 task_1/2/4 fixture 与三者组合 fixture，验证所有页面、404、授权、HTML 转义、密钥不展示、JSON 下载和 partial。 |  |  |
| TASK-031 | 创建 `tests/e2e/`、`requirements/web.in`、`HANDOFF.md`、`README.md` 和 `docs/demo-script.md`；fake service 下完成首页→运行→进度→报告→下载全流程。 |  |  |

开发者 E 完成标准：在没有安装 DeepTeam/AgentDojo、没有 API Key 时，使用 fixtures 即可启动和演示全部页面；`pytest tests/web tests/e2e -q` 返回 0；E 不修改任何任务模块。

### Implementation Phase 6 — 无冲突合并与契约验收

- **GOAL-006**: 按固定顺序装配五个工作包，只解决真实接口问题，不重写各模块。

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-032 | 先合并 A 分支并运行 core tests；再以任意顺序合并 B/C/D，每合并一个只运行对应模块测试与 `tests/integration/test_contract_conformance.py`。 |  |  |
| TASK-033 | A 运行依赖合并脚本和 Benchmark 总清单生成脚本；若发生版本冲突，只修改根锁定文件，不修改模块代码或子 manifest。 |  |  |
| TASK-034 | 最后合并 E 分支；注册表加载三个模块，运行 fake fixtures 与真实模块两套 E2E，验证 Web 对模块内部无导入。 |  |  |
| TASK-035 | 创建 `tests/integration/test_module_registry.py`、`test_all_fixtures.py`、`test_hybrid_quick.py`；检查三个 task_id 唯一、所有 fixture 符合 v1 契约、hybrid 路由和总体分。 |  |  |

完成标准：合并阶段没有同一源文件的人工内容冲突；任何模块可被 fake module 替换；全量测试通过后才允许真实模型 smoke test。

### Implementation Phase 7 — 联调、修复责任与交付

- **GOAL-007**: 用明确的故障归属完成最后一天联调，避免多人同时修改同一问题。

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-036 | A 执行授权目标 `hybrid+quick`；契约/编排错误归 A，任务 1 结果错误归 B，任务 2 归 C，任务 4 归 D，页面/存储/报告错误归 E。 |  |  |
| TASK-037 | 每个 owner 只在自己的分支修复并补回归测试；A 按同一顺序合并修复，禁止集成人直接改写 owner 文件。 |  |  |
| TASK-038 | E 完成五分钟演示材料，A 执行 `pytest -q`、smoke test、pip check、Benchmark 哈希和密钥扫描；全部退出码为 0 后冻结提交。 |  |  |

完成标准：一轮 hybrid+quick 生成三个 TaskResult 和一个 RunReport；报告可追踪每条结果 owner、module_version 和 benchmark_version；演示包不含密钥。

## 3. Alternatives

- **ALT-001**: 按“前端、后端、测试”拆分；未采用，因为三人会同时修改路由、模型和数据结构，模块完成后仍需大量联调。
- **ALT-002**: 五人共享一个 service.py 并分别添加逻辑；未采用，因为共享热点文件必然产生合并冲突和隐式依赖。
- **ALT-003**: 三个任务分别做成独立 Flask 服务；未采用，因为七天比赛不需要微服务，部署和报告聚合成本过高。
- **ALT-004**: 等任务模块完成后再开发页面；未采用，契约 fixture 可以让 Web 与真实评测完全并行。

## 4. Dependencies

- **DEP-001**: 开发者 A 的 `contracts.py` 和 JSON Schema 必须在首日前 4 小时冻结；B/C/D/E 后续只依赖这一稳定版本。
- **DEP-002**: Python 3.11、Pydantic v2、Flask 3.x、DeepTeam 1.0.7、AgentDojo 0.1.35、pytest、jsonschema、PyYAML。
- **DEP-003**: Git 分支保护或团队纪律必须确保目录 owner 规则；没有 owner 审核的跨目录修改不得合并。
- **DEP-004**: 最终真实 smoke 需要授权目标模型、裁判模型和 AgentDojo 支持的模型配置，单元测试不依赖这些外部资源。

## 5. Files

- **FILE-001**: `security_eval/contracts.py`、`core/`、`errors.py`：A 所有的共享协议与编排。
- **FILE-002**: `security_eval/modules/task1/`、`benchmarks/v1/task1/`、`tests/task1/`：B 的任务 1 工作包。
- **FILE-003**: `security_eval/modules/task2/`、`benchmarks/v1/task2/`、`tests/task2/`：C 的任务 2 工作包。
- **FILE-004**: `security_eval/modules/task4/`、`benchmarks/v1/task4/`、`tests/task4/`：D 的任务 4 工作包。
- **FILE-005**: `app.py`、`security_eval/web/`、`tests/web/`、`tests/e2e/`、`docs/`：E 的产品壳层与演示。
- **FILE-006**: `requirements/*.in`、`tests/contract_fixtures/`、各工作包 `HANDOFF.md`：可独立交付与集成资产。

## 6. Testing

- **TEST-001**: 契约测试：四个模块/fake 的输入输出均通过 Pydantic 和 JSON Schema，未知字段、非法状态、缺少得分和错误码失败。
- **TEST-002**: 文件所有权测试：CI 根据路径映射检查 PR，跨 owner 目录修改必须获得对应 owner 审核。
- **TEST-003**: 模块隔离测试：task1/2/4 分别在只安装 base+自身依赖的环境中导入和运行单元测试，不依赖 Flask 或其他任务。
- **TEST-004**: Web 解耦测试：只安装 base+web 并加载三个 JSON fixtures，所有路由、报告和下载仍能工作。
- **TEST-005**: 注册表测试：缺失模块、重复 task_id、错误类名、错误契约版本和模块导入异常均转为标准错误。
- **TEST-006**: 结果兼容测试：三个 fixture 分别和组合后均生成 RunReport，总体分不修改 TaskResult，invalid 不进入有效分母。
- **TEST-007**: Benchmark 集成测试：三个子 manifest 独立校验，总 manifest 可生成，任何题库文件修改都会改变哈希并导致旧清单验证失败。
- **TEST-008**: Hybrid 快速测试：任务 1/2 静态低分类别触发 DeepTeam 补测，任务 4 由 AgentDojo 补测，最终 report 保留两个来源。
- **TEST-009**: 故障隔离测试：任一模块抛出 timeout/parse/case 错误时另外两个模块继续，Web 显示 partial 和对应 owner/module_version。
- **TEST-010**: 最终端到端测试：授权目标 hybrid+quick 从 Flask 启动，轮询完成、查看三个任务、下载 JSON，全流程不手工改数据。

## 7. Risks & Assumptions

- **RISK-001**: “完全零依赖”不现实，五人至少依赖首日冻结的契约；通过 4 小时契约门和 fixture 将依赖限制为稳定数据接口。
- **RISK-002**: 开发者 A 可能成为瓶颈；A 第一优先级是契约、fake 和 registry，真实网络适配及优化后置。
- **RISK-003**: D 的 AgentDojo 工作量可能最大；限制为官方 workspace 子集，先完成固定 Benchmark，再实现动态未覆盖组合。
- **RISK-004**: B/C 同时使用 DeepTeam 可能复制适配代码；本周期允许各自封装，集成前不抽共享库，避免过早共享导致冲突；赛后再重构。
- **RISK-005**: 各 fixture 与真实结果可能漂移；每个模块的 contract test 必须用同一个 TaskResult 模型生成 fixture，禁止手写不校验 JSON。
- **ASSUMPTION-001**: 五人能使用独立分支并遵守 owner 目录；A 担任集成负责人但不替其他 owner 修改代码。
- **ASSUMPTION-002**: 每位开发者都能运行 Python 3.11 与自己工作包的单元测试。
- **ASSUMPTION-003**: 人员尚未提供姓名，因此计划使用 A–E；分配后只替换 owner 名称，不改变目录和职责。

## 8. Related Specifications / Further Reading

- [混合 Benchmark 与动态测试总体计划](./feature-hybrid-security-benchmark-4.md)
- [DeepTeam 官方仓库](https://github.com/confident-ai/deepteam)
- [AgentDojo 官方仓库](https://github.com/ethz-spylab/agentdojo)
- [Flask Application Factories](https://flask.palletsprojects.com/en/stable/patterns/appfactories/)
- [Pydantic Models](https://docs.pydantic.dev/latest/concepts/models/)
