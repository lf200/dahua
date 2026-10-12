# Task 4 无效结果排查与修复记录

日期：2026-10-12（Asia/Shanghai）。本地代码基于 `e396181`，修复后 Task 4 模块版本为 `1.1.1`。

## 核查对象与证据边界

核查了用户指定的共享讨论，以及本地历史报告 `data/runs/20261008T144915Z-52af3364/report.json`。该报告的 Task 4 为模块 `1.1.0`、full hybrid：固定基准 24 条均取得有效结果，动态补测 18 条中前 2 条有效、后 16 条均为 `TARGET_ERROR / BadRequestError`。历史错误详情为空、耗时为 0，无法从这份报告恢复原始服务端错误。

首次真实定位使用原配置 `qwen3.7-plus`，按顺序单独执行历史 dyn-02、dyn-03、dyn-00。三条均在首次模型请求收到 HTTP 403 / `insufficient_quota`，服务端明确提示免费额度耗尽。旧 AgentDojo 请求层每条重复尝试 3 次，共观察到 9 次失败 HTTP 请求，未取得模型输出。仅保存脱敏请求摘要：`.codex_tmp/task4-diagnostic-requests.json`。

**本次确认的是当前接口额度不可用。不能将当前 HTTP 403 直接认定为 10 月 8 日 HTTP 400 的根因。** 用户随后选择先完成代码修复和离线回归，后续没有继续调用真实模型。

阿里云的官方错误码文档也列有 `400-Throttling.AllocationQuota` 和 `403-AllocationQuota.FreeTierOnly`，因此仅凭 SDK 的 `BadRequestError` 类名，不能断定错误一定来自请求格式。应结合服务端 code/message 定位：<https://help.aliyun.com/en/model-studio/error-code>。

## 已确认的代码缺陷与修复

| 原行为 | 修复后行为 |
| --- | --- |
| 所有 API 错误只保留异常类名，`details={}` | 保存 HTTP 状态、服务端 code/param/message、请求 ID，以及脱敏请求结构摘要 |
| `TargetError` 默认将 HTTP 400、401、403 等标为可重试 | 永久请求错误不盲目重试；连接错误、超时、408/409/429/5xx 至多 3 次尝试 |
| SDK 与 AgentDojo 两层重试可能叠加；AgentDojo 对 403 反复尝试 | SDK 内部重试关闭，使用一个项目请求边界控制重试 |
| 额度或凭据已明确不可用时，后续用例继续访问接口 | 在该任务运行内停止后续请求，保留计划用例并注明未执行及首个阻断用例 |
| 异常结果 `input=null`、`duration_ms=0`，没有案例文件 | 保留任务组合、实际尝试耗时和独立错误证据文件；未执行用例仍为耗时 0 |
| 仅在 pipeline 创建时根据 deadline 设置超时 | 每轮工具调用及每次重试前重新检查 deadline，支持剩余不足 1 秒的超时 |
| Task 4 绕过共享客户端，没有使用 `TARGET_MAX_TOKENS` | 原生工具调用请求使用配置的输出上限，并记录截断与解析异常的诊断信息 |
| 原生 SDK 连接未显式关闭 | 成功、API 异常和任务准备异常均释放已构建 pipeline 的客户端 |

错误字段采用白名单，去除完整错误体和被回显的请求内容，先脱敏再截断。证据不保存 API key、完整系统提示、注入文本或工具参数。请求摘要中的 `content_chars` 是字符数，不是 token 数；SDK 返回 usage 时另行记录 token 用量。

新请求层继续使用锁定的 AgentDojo 0.1.35 原生消息、工具定义及工具结果序列化。每条用例仍创建独立的 pipeline、runtime 和 workspace。没有在本次检查中找到跨用例消息累积的证据，也没有基于猜测删除动态场景或转换有效攻击结果。

## 离线验证

环境：`D:\app\Anaconda3\envs\dahua\python.exe`，Python 3.11.15、AgentDojo 0.1.35、OpenAI SDK 3.3.1。

新增测试使用真实 OpenAI SDK 与 AgentDojo，通过 `httpx.MockTransport` 提供本地模拟 HTTP 响应，不调用外部模型：

- HTTP 400 出现在第二轮工具请求时，下一条用例仍从独立的 system/user 消息开始。
- 固定与动态阶段间传递明确的额度阻断原因，full hybrid 42 条计划用例仅发出首个请求，后续为 `executed=false`。
- 400 配额错误与 403 内容拒绝按服务端 code 区分；案例局部拒绝不会停止整个批次。
- 18 条动态用例前 2 条有效、后 16 条 400：保留前 2 条有效结果，并为后 16 条保存完整诊断。换为正常模拟响应后，同一进程可继续取得 18 条有效结果。
- 408/409/429/5xx 的重试次数有界；deadline 用尽不再请求；小于 1 秒的剩余时间不被扩展为 1 秒。
- 工具参数 JSON 截断归类为 `PARSE_ERROR`，记录 `finish_reason`；秘密和完整提示不会出现在错误证据中。
- 原有原生工具执行、攻击结果归一化、矩阵完整性、评分、服务和网页测试继续通过。

最终验证：整个项目 **205 项测试通过，0 失败、0 错误、0 跳过**；其中 Task 4 74 项（原有 50 项 + 新增 24 项）。Ruff 检查和 `git diff --check` 通过。JUnit 记录：`.codex_tmp/task4-fix-regression.xml`。

```powershell
& 'D:\app\Anaconda3\envs\dahua\python.exe' -m pytest -q -p no:cacheprovider --basetemp D:\codex-test-tmp\dahua-final-verified-20261012 --junitxml=.codex_tmp\task4-fix-regression.xml
```

## 接口恢复后的真实回归

先更新本地 `.env` 的目标接口配置，再在仓库根目录执行：

```powershell
& 'D:\app\Anaconda3\envs\dahua\python.exe' -m scripts.diagnose_task4 --report data/runs/20261008T144915Z-52af3364/report.json --case-id t4-dyn-02-user_task_20-injection_task_1-tool_knowledge-none
```

随后比较单独执行 dyn-03、在同一进程按 dyn-02 → dyn-03 → dyn-00 顺序执行，以及完整动态补测。通过重复 `--case-id` 指定同一进程中的执行顺序。每次诊断写入新的 `outputs/task4-diagnostics/<UTC时间-随机ID>/diagnostic.json`，附源报告 SHA-256、模块版本、公开配置与案例证据，不覆盖历史报告。

若再次出现 HTTP 400，根据新报告的 `provider_code`、`provider_param`、`provider_message` 和 `request_diagnostics` 判断是配额、接口角色/参数、上下文长度或工具响应问题，再针对实际原因处理。

## 当前交付范围

本次更新包含 Task 4 后端请求与错误处理、诊断脚本和案例证据；按用户要求保留原有前端界面与展示逻辑。历史报告及其评分保留；本次没有更改 60/40 评分融合、冻结矩阵或 Task 1/2。低动态有效覆盖率下的正式评分门槛属于另一个评测策略改动，尚未引入。在线平台部署需另外更新代码并重新加载服务。

用户随后执行了真实 dynamic + full 运行 `20261012T072742Z-e8a390c5`。本地原始报告经核查包含 18 条有效结果（8 passed、9 failed、1 partial、0 invalid），对应 18 个案例证据文件，最终分数 68.85。该运行由用户启动；这里记录的是已保存报告的核查结果。

这轮结果页原统计栏只展示 passed/failed/invalid，使可见数量相加为 17。根因是 1 条 partial 结果没有显示在统计栏中。按用户要求，本次提交不修改前端界面与展示统计，也不修改源报告或评分。

离线回归验证了请求处理、错误隔离与证据完整性，后续真实动态运行取得 18 条有效结果。**该运行不等同于逐条重放原来那 16 条历史失败组合，历史 HTTP 400 的原始根因仍无法从旧报告确认。**
