# 大模型安全综合测评系统

本项目面向已授权的大模型目标，统一执行 Task 1 对抗攻击安全、Task 2 内容安全和 Task 4 大模型应用安全测评。Flask Web 层只调用公共 `EvaluationService` 并展示契约化 `RunReport`，不重新评分，也不依赖具体攻击框架的内部实现。

## 架构

```text
Browser → Flask → RunManager → EvaluationService → Task 1 / 2 / 4
                     ↓                 ↓
               status.json       RunReport
                                      ↓
                         report.json → Result Page
```

- Task 1：固定 Benchmark 与 DeepTeam 动态对抗攻击。
- Task 2：固定 Benchmark 与 DeepTeam 动态内容安全测试。
- Task 4：AgentDojo workspace 沙箱中的应用与工具调用安全测试。
- Web：单工作线程、本地原子 JSON、重启恢复、报告展示与下载。

## 环境与安装

推荐 Python 3.11。创建虚拟环境后安装根依赖：

```bash
python -m pip install -r requirements.txt
```

开发者 E 的独立依赖声明位于 `requirements/web.in`。根 `requirements.txt` 由合并脚本维护，不应手工编辑。

## 配置

在项目根目录创建 `.env`：

```dotenv
TARGET_BASE_URL=https://example.com/v1
TARGET_API_KEY=replace-me
TARGET_MODEL=target-model
JUDGE_BASE_URL=https://example.com/v1
JUDGE_API_KEY=replace-me
JUDGE_MODEL=judge-model
AGENTDOJO_MODEL=agentdojo-model
OUTPUT_ROOT=data/runs
```

`JUDGE_BASE_URL`、`JUDGE_API_KEY`、`JUDGE_MODEL` 和 `AGENTDOJO_MODEL` 未设置时会按核心配置规则回退到目标模型配置。API Key 不会传入模板或浏览器。

## 启动

```bash
python app.py
```

默认访问 `http://127.0.0.1:5000`。可用 `FLASK_HOST`、`FLASK_PORT` 修改监听地址。首页选择任务、benchmark/dynamic/hybrid 模式、quick/full 规模，确认目标授权后启动测评。

## 测试

离线测试不调用真实模型：

```bash
pytest tests/web tests/e2e -q
pytest -q
```

Web/E2E 测试通过 `FakeEvaluationService` 加载 `tests/contract_fixtures/` 中的标准结果。真实网络 smoke test 必须显式配置已授权目标，且不应成为普通 CI 的强制步骤。

## 运行结果

每次运行写入：

```text
data/runs/<run_id>/
├── status.json
├── report.json
└── task_<id>/...
```

页面提供运行状态轮询、总体和分任务评分、风险等级、类别汇总、失败/无效案例、证据以及完整 JSON 下载。

## 安全边界

- 仅测试已明确授权的目标。
- Web 层不导入 DeepTeam、AgentDojo 或具体任务模块。
- run ID 使用严格白名单，下载路径限制在对应运行目录内。
- Jinja 保持自动转义，响应包含基本安全头并禁用敏感结果缓存。
- 状态和报告采用临时文件加原子替换写入。
- 异常页面不显示堆栈、环境变量或密钥。

比赛演示流程见 `docs/demo-script.md`。
