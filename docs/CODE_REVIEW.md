# 以代码功能为主的分析

报告的主要价值是解释实现及改进选择。先讲用户可见功能、输入输出、调用链、
数据结构和算法，再分析正确性、复杂度、数值行为与优化权衡。即使没有缺陷，
也应该有代码理解；没有证据支持改动时，解释为什么保持现状。不要为流程凑 Issue。

安全审查按变化相关性开展：本次改了认证、敏感数据或不可信输入边界，才深入
相应路径。普通算法变化不套一遍部署/TLS/权限清单。正常 Build、常规执行边界、
来源回执与审计账本保留在附录；构建失败等实际阻断仍明确披露。不要把“未运行”
重复十遍来充实报告，也不要把静态推导写成实测收益。

## 大变更的阅读批次

原生 Collect/CodeValidate 的协议及单包限额保持兼容。新的通用 operator 阅读层
允许超出单个原生补丁包的代码审阅；不能仅因超限就改看最后一次提交。

```text
ces-product.cmd review prepare --config <profile> --base <period-base> --context src/caller.cpp
ces-product.cmd review complete --config <profile> --plan <plan.json> --draft <draft.json> --run <native-run>
```

先按既有授权同步/Build/audit，再准备阅读计划；命令自身只读 Git，不运行程序、
构建或模型。base 是真实周期边界，不是为了避限随意选择 HEAD~N。计划核验可排除
的自动文档提交，保留有效工作来源；每个变更路径保留 before/after，必要调用链
用 `--context` 显式加入。删除文件保留 before，新增文件保留 after。全文按行拆分，
不会只保留文件开头；每批有路径、提交、原字节 SHA、行号及完整区间文本。

默认最多256个路径、每份来源8 MiB、总读取32 MiB、每批128 KiB，可通过外部
`review.budget` 调整（上限2048路径、单文件32 MiB、总128 MiB、单批1 MiB）。
预算限制、二进制、未登记编码或超长单行成为显式缺口，不算已阅读。编码默认
UTF-8；其他编码须通过 `review.encoding_overrides` 逐路径确认，原字节哈希仍保留。
计划和草稿在仓库外；完整库存不等于已完成语义阅读。

`target_tokens=60000`、`max_tokens=120000` 是每轮助手的规划偏好，可调大。它们
不是模型 API 调用、消耗记录或宿主硬限额。助手应按功能连续分批阅读，预算不足
就保留具体未完成批次及理由，不能声称改了宿主限制，也不必为了用满预算注水。

## 功能分析草稿

Codex阅读计划中的批次及必要旧实现，写 `ces.functional_review.v1`。每个批次都要
登记 reviewed 或 deferred 及原因；每个已读批次必须关联功能分析和精确引用。
功能可以跨函数/文件，避免逐文件复述diff。`commits` 必须是对应变化的有效提交。

```json
{
  "schema": "ces.functional_review.v1",
  "input_binding_sha256": "<plan binding_sha256>",
  "coverage": [
    {"unit_id": "<unit id>", "status": "reviewed", "reason": "已阅读该区间及调用链，归入候选筛选功能。"}
  ],
  "features": [{
    "id": "candidate-selection",
    "title": "候选筛选与结果选择的变化",
    "commits": ["<effective commit>"],
    "purpose": "说明这个功能的输入、输出及使用场景。",
    "behavior_change": "比较修改前后行为，用一个具体输入例子说明区别。",
    "mechanism": "说明入口、关键分支/数据结构、算法步骤及结果如何传给调用者。",
    "correctness": "解释成立条件、边界、反例或不变量，区分静态推导与实际运行。",
    "optimization": "说明可改的热点、预期收益、额外成本和验证方式；或说明无必要改动的原因。",
    "citations": [{"unit_id": "<unit id>", "line_start": 10, "line_end": 12, "quote": "实际来源字面引用"}]
  }]
}
```

`review complete` 核验计划、每个引用和当前来源，将完整绑定记录写入 run 下的
`functional-review.json`。日报再次校验再发布。`review.require_functional_analysis=true`
时，缺此记录就停止日报发布；默认false兼容旧profile。语义分析进入快照和去重，
同作者的日报只呈现与该作者周期提交相关的功能；协作功能可同时关联多个提交。

日报正文优先功能及优化，具体缺陷另列；构建、完整覆盖缺口和追踪状态放可展开
附录，失败构建在正文单独显示。原始日志、旧报告归档和发送账本不改写或重发。
周/月/年总结沿用同一写作重心，复用已读功能分析，仅补查未覆盖的重要功能链。

这个层提供可追溯阅读和报告绑定，不是原生 CodeValidate Finding，也不独立证明
算法正确或性能提升。新代码 Issue 仍须原有原生证据、深度分析、归属/去重门。
测试和 Issue fixed/regression 的独立执行验收不变。
