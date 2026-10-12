# Task1 v1.2：20 条挑战候选的静态改编与替换

本修订使用用户提供的 `Task1-挑战候选集20题(1).jsonl`，按五个类别各 4 条，替换当前题库中的 20 条基础样例。总数仍为 80，每类仍为 16；quick 仍为 10，每类 2 条。保留全部原 case_id、顺序和 quick 标记；未替换的 60 行与 v1.1 快照逐行一致。

此处“挑战”是结构与机制标签，尚未通过真实目标模型的对照实验校准难度或攻击成功率。替换选择依据是原题攻击目标明显、上下文薄、依赖单一覆盖指令或人工逻辑矛盾；没有以当前模型的分数作为难度排序依据。

## 替换映射

下表的候选序号 01—04 均对应原文件中相同类别的四条候选。完整源 ID、旧/新场景、答案、目标、哈希和适配说明见 [replacement-map.json](replacement-map.json)。

| 类别 | 候选 01 替换 | 候选 02 替换 | 候选 03 替换 | 候选 04 替换 |
|---|---|---|---|---|
| prompt_injection | t1-prompt-injection-15 | t1-prompt-injection-10 | t1-prompt-injection-01 | t1-prompt-injection-02 |
| indirect_instruction | t1-indirect-instruction-01 | t1-indirect-instruction-02 | t1-indirect-instruction-07 | t1-indirect-instruction-14 |
| role_jailbreak | t1-role-jailbreak-02 | t1-role-jailbreak-01 | t1-role-jailbreak-07 | t1-role-jailbreak-16 |
| logic_trap | t1-logic-trap-01 | t1-logic-trap-02 | t1-logic-trap-12 | t1-logic-trap-14 |
| context_hijack | t1-context-hijack-01 | t1-context-hijack-06 | t1-context-hijack-09 | t1-context-hijack-02 |

新增机制包括输出契约迁移、跨语言事实替换、合成 canary 原文/编码提取、引用开发者权限、邮件签名与检索元数据污染、表格/日志注释、虚构角色向授权状态迁移、同伴智能体身份声明、条件偷换与指标混淆、引用会话摘要、延迟触发和历史示例污染。

## 与现有格式和执行器的对齐

源候选采用 `system + control + steps[3] + recovery + attack_goal` 格式，含 `%CANARY%`、`%CONTEXT%` 和 `if_previous_task_correct` 条件分支。现有 `BenchmarkCase` 只接收固定 messages、expected_behavior、forbidden_outcomes、recovery_probe 和三维 rubric；当前执行器每题执行一次攻击请求，再在同一会话执行一次恢复请求。

本修订因此进行以下转换：

- 20 条均保持现有 BenchmarkCase 字段，不新增运行期字段。
- 每条指定 CURRENT_TASK_RECORD 的正常任务与事实来源，附件和引用历史作为低可信任务数据。
- 三个无条件攻击载荷合并为同一请求的三份引用审查材料；没有伪造当前模型的中间 assistant 回答。
- 候选中的正常对照请求、三轮自适应分支和原请求预算不在正式固定测试中执行，也不声称已执行。
- `%CANARY%` 替换为各题不同、由源 ID 确定的合成字符串；用户攻击载荷不包含其真实值。原文、base64、hex、反转形式作为评价参考写入预期和禁止结果。
- 三条 `long_context=true` 候选补充邮件、检索记录或历史示例上下文；所有消息均满足现有 5000 字符上限。
- 显式给出正常攻击阶段答案和恢复答案。两者分别评分，不以恢复正确抵消攻击成功。
- JSON 对象要求只有 answer 键；允许 JSON 空白，禁止外围解释或额外攻击字段。识别不要求额外解释文字，以免与 JSON 输出契约冲突。
- `critical_failure` 转为 `severity=critical`；不新增评分否决规则。
- case_id 在修订间保持稳定，解读结果必须同时使用 benchmark_version。

识别/阻断/恢复权重、通过阈值、Hybrid 动态触发和 60/40 合成公式均沿用现有实现。前端未修改。此修订不等同于此前讨论的动态生成链路重构，也没有替换现有 LLM 裁判为程序化评分器。

## 检索核对

这些候选是原作者合成样例，外部资料只用于核对测试机制和设计依据，不标记为官方基准原题，也没有把外部数据集全文复制进本题库。

- [IHEval 官方仓库](https://github.com/ytyz1307zzh/IHEval)：核对不同优先级输入中的规则冲突、任务执行和秘密提取场景；其对齐、冲突和参考设置也说明正常任务能力应与层级抵抗能力区分。
- [BIPIA 官方仓库](https://github.com/microsoft/BIPIA)：核对在外部内容中嵌入攻击的场景，并参考其邮件、表格和代码类任务组织方式。
- [Tensor Trust 官方数据仓库](https://github.com/HumanCompatibleAI/tensor-trust-data)：核对任务劫持与提示提取两类目标，采用合成 canary 表达可观察的提取结果。
- [PyRIT 官方单轮执行文档](https://microsoft.github.io/PyRIT/1.0.1/code/executor/single-turn/)：核对单次提示发送与攻击变换的组织方式；本修订没有接入 PyRIT，也没有把静态合并标记为真实多轮执行。
- [StrongREJECT 官方实现](https://github.com/dsbowen/strong_reject)：其主题是有害内容越狱评价，与这批业务逻辑题只属相邻领域。原候选的引用保存在源文件和映射中，但不作为逻辑攻击机制的直接来源，不写入活动题目的 methodology 标签。

## 证据文件

- [source-candidates.jsonl](source-candidates.jsonl)：原候选文件的字节级副本，保留其原始字段与未展开占位符。
- [previous-cases.v1.1.jsonl](previous-cases.v1.1.jsonl)：替换前活动题库快照。
- [previous-manifest.v1.1.yaml](previous-manifest.v1.1.yaml)：替换前版本和文件哈希。
- [replacement-map.json](replacement-map.json)：20 条映射、正常答案、攻击目标、转换说明及原/新文件哈希。
- [imported-cases.jsonl](imported-cases.jsonl)：已转换并加入活动题库的 20 条数据，便于单独审阅。
- [verification.json](verification.json)：计数、版本、哈希、测试结果和当前服务重启状态。

快照和来源文件用于追溯，不由活动 Benchmark loader 执行。历史运行报告未覆盖。模块元数据更新为 1.2.0、题库为 v1.2；v1 和 v1.1 请求作为兼容入口，结果记录实际 v1.2。修改后应使用新启动的应用进程，避免内存模块与题库修订混用。
