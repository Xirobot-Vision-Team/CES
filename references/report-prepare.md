# EC197 — ReportPrepare：面向 AI 写报告的最小化输入（离线只读）

## 功能与严格边界

真实可调用入口是 [`construction/report_prepare.py`](../construction/report_prepare.py) 中的 `ReportPrepare.bind/from_json`。它会使用现有 EC195 `CrossRepositoryReportScope.from_json` 与 EC196 `ReportEvidenceMetrics.from_json` **重新回放原始规范 JSON**，从完整周期、全部声明仓库、明确请求的 `report.evidence.read`、精确来源/人员绑定与四渠道证据中，构造一个严格脱敏的结构化 `subject.ai_input`。它**不是** AI 模型调用、报告草稿、发布操作、原生 PowerShell ReportPrepare 注册或外部授权器。

**最重要的分层：** EC195 全仓证据读取授权 ≠ 将相关数据送到 AI 的许可。EC197 另外要求一个覆盖每个具名仓库的 `release_policy`：同一范围、周期、EC196 metrics 绑定，固定使用目的与受众、当前报表/来源/人员绑定、每仓独立 release receipt SHA、明确允许的渠道和**按仓库逐条选取的证据 ID**。缺少任何仓库、收据、精确 pin 或声明性证据读取权限就拒绝产生全部 `ai_input`（`unavailable/5`）；不会从剩余 READY 仓库偷偷拼凑“全体项目报告”。每个 SHA **仅是声明性引用**，不证明收据签名、授予者、用户同意、真实隐私审核或数据出口已获准。实际向第三方 AI 提供上下文前，需要用户/组织的可信授权和人工隐私审查。

## 端到端离线调用示例

```python
from report_prepare import ReportPrepare, PURPOSE, AUDIENCE, CHANNELS

# ec195 = 对完整仓库集合按 operation='report.evidence.read' 产生的返回值
# ec196 = 与 ec195 精确对应、由 ReportEvidenceMetrics.bind 产生的返回值
scope = ec195['subject']
metrics = ec196['subject']
policy = {
    'purpose': PURPOSE,                 # periodic_report_writing_input
    'audience': AUDIENCE,               # AI_REPORT_WRITING_REVIEW
    'scope_id': scope['scope_id'],
    'scope_binding_sha256': scope['binding_sha256'],
    'metrics_binding_sha256': metrics['binding_sha256'],
    'period_id': scope['period']['period_id'],
    'repository_grants': [{
        'repository_id': r['repository_id'],
        'report_subject_id': r['report']['report_subject_id'],
        'repository_binding_sha256': r['report']['repository_binding_sha256'],
        'people_binding_sha256': r['report']['people_binding_sha256'],
        # 下行仅演示字段格式：必须由已获独立权限的外部批准流程提供
        'release_receipt_sha256': 'a'*64,
        'allowed_channels': list(CHANNELS),
        # 保守的初始用法：不主动披露任何原始事件引用
        'selected_evidence_ids': [],
    } for r in scope['repository_set']]
}
response = ReportPrepare().bind(
    scope_json=ec195['canonical_json'],
    metrics_json=ec196['canonical_json'],
    release_policy=policy,
)
assert response['status'] == 'partial' and response['exit_code'] == 2
# 这是审阅用离线 JSON 对象；不可据此自动转发给 AI 服务
ai_input = response['subject']['ai_input']

replay = ReportPrepare().from_json(
    serialized=response['canonical_json'],
    scope_json=ec195['canonical_json'],
    metrics_json=ec196['canonical_json'],
    release_policy=policy,
)
assert replay['subject'] == response['subject']
```

真正的 release receipt 及授权范围需要由外部可信操作员提供、审查；示例 `a*64` 是**合成测试值**，并非可用授权。要发布某条证据引用，将其对应 `evidence_id` 放进所属仓库的 `selected_evidence_ids`，同时把其 `channel` 放进本仓库 `allowed_channels`。**事件若拥有 EC194 `actor_key`，即使已获得匹配的 EC194 witness，也不得选入 AI 输入**；只可把该事件排除，并标注人员关联引用已扣留。没有 EC194 原 witness 的关联引用无法通过 EC196 回放，不得绕过这一检查。

## `ai_input` 真实包含/剔除什么

- `purpose`/`audience`、原范围及指标 SHA、EC192 规范自然周期 ID/UTC `[start,end)`、按原集合排序的每仓 **SHA 化的** `repository_ref`、`report_subject_ref`、`source_mode`、EC193 source/EC194 people 绑定 SHA、已声明的覆盖窗口/路径/清单状态和受限 gap code。
- 每仓四个类型化渠道，区分 `COMPLETE_DECLARED`/`PARTIAL_DECLARED`/`UNKNOWN`/**`WITHHELD_BY_RELEASE_POLICY`**。放行集合仅覆盖上游部分证据时，原 `COMPLETE_DECLARED` **降级为 PARTIAL_DECLARED**；上游 UNKNOWN 不得提升。对空事件使用 `EMPTY_SUBMITTED_NOT_VERIFIED_ZERO`，不可写成“实际为零”。
- `citations` 只含域隔离 `cesrc1:` 的引用哈希、固定类别枚举、`UNVERIFIED_DECLARED_REFERENCE`；不含 `evidence_id` 字面量、原始 SHA/receipt、姓名、邮箱、actor_key、人员链接、源码、原始 Git/CI/AI 内容、真实路径/来源 locator、证据时刻。引用哈希可以让**持有原 EC196 内容的授权审查方**做同源重算；它不是密钥匿名化，也不认证底层证据。
- CI 输出只基于**本次真正放行**的 CI 引用重新计算信号：若存在任何被过滤的 CI 事件，强制 `REDACTED_CI_COMPLETION_UNKNOWN`；整个 CI 渠道未获许可则为 `CI_NOT_RELEASED`；即使放行了 `completed_pass_claim`，输出也仍是 `PASS_COMPLETION_CLAIM_UNVERIFIED`，不等于实际运行、通过或完成。
- `global_gap_codes` 继承 EC195/196 覆盖、来源和未认证缺口，再标注出口收据未经验证、需人工隐私审查、部分证据被扣留等；固定 `safety_instructions` 禁止个人排名、绩效推断、补编来源事实和从数字判断实际工作。`transmission_state=NOT_SENT_REQUIRES_EXTERNAL_APPROVAL`。

**只考虑交给后续 EC198 的 `subject.ai_input` 对象**，而不是 EC195/196 全量对象、政策对象、EC194 witnesses、用户自由格式文本、原始日志或任何私有库附件。对 `ai_input` 的 schema 定义见 [严格 Draft2020-12 契约](report-prepare-result.v1.schema.json)。返回的整个 subject/JSON 没有原始证据 ID、人员信息或授权收据，只保留源输入绑定 SHA 及安全投影；未经人工确认出口仍不得发出。

## 状态、重放、规模与限制

- 每次 `bind/from_json` 都要提供**原 EC195 + 原 EC196** `canonical_json`，Actor 已归属事件存在时还需 `people_subject_witnesses={repo_id: EC194原canonical_json}`，且 witness 覆盖所有 READY 仓库。只凭自称匹配的哈希或拼凑记录不能作为有效上游。
- `from_json` 再用**原 release_policy** 重跑所有授权/引用/分组/覆盖/CI 降级/引用哈希与整体绑定，比较全部 canonical JSON；不能用另一个仓库集合、周期、metrics 快照、改过的脱敏条目或放行子集重放成功。原始参数异常或篡改时 `invalid_input/4`；全仓权限、人员敏感引用或出口批准缺失时 `unavailable/5`。成功只返回 `partial/2`。
- 来源输入每份最多 1 MiB，release policy 最大 256 KiB，输出主体最大 512 KiB；EC195 最多 32 仓、EC196 最多 512 声明事件（每仓最多128）。只做内存确定性投影，不访问本地文件系统、外部 Git/CI/AI/provider、身份目录、业务库，不发邮件、不联网、不落盘、不执行 AI。
- 本实现限制**字段结构和代码路径上的披露**，但**不能证明**源记录本身无隐私编码、用户在哈希/ID 中未嵌入敏感标识、外部收据真实、用户已授权向某模型出境、tzdb 版本不可变或实际数据完整；这些属于最后用户辅助的真实环境验收。哈希引用不能代替独立信任来源。

## 下一步与统一验收

**EC198** 才负责 `report_writing` Handoff 草稿，必须沿用这一受限输入、明确区分 AI 声明和证据、禁止无证据个人绩效判断；**EC199** 负责渲染，**EC200** 负责显示/更正版本，发布另外规划。原 PowerShell V4.60/R150、15套 Smoke、真实私域授权/身份/CI/Git/AI/跨平台/E63–E66/最终端到端用户验收均 `NOT_RUN`，B-001 原 V3.10/ROUNDS 历史缺口 OPEN。
