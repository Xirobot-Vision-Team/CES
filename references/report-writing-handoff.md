# EC198 — report_writing Handoff：仅供内审的脱敏报告草稿（离线 Python）

> **可调用功能，不是外部 AI 发送许可，也不是最终报告。** 实现：[`../construction/report_writing_handoff.py`](../construction/report_writing_handoff.py)，契约：[`report-writing-handoff-result.v1.schema.json`](report-writing-handoff-result.v1.schema.json)，用例：[`../construction/test_report_writing_handoff.py`](../construction/test_report_writing_handoff.py)。施工版本 V5.08/R198，内置 PowerShell CLI 仍 V4.60/R150。

## 本轮真正实现什么

`ReportWritingHandoff.bind/from_json` 接收由 **原始 EC195 scope、EC196 metrics、EC197 release_policy** 生成的**完整规范 `prepare_json`**。每次都真正调用 EC197 `ReportPrepare.from_json`，再经 EC196→EC195 等上游原始回放：不相信消费者手填的 `binding_sha256`，不允许只传一个看似相同的局部 `ai_input`。如果任何上游仓库被阻断，或者 scope/metrics/period/source/people/release 不能精确恢复，则不产生任何 Handoff 草稿。

另需一份针对 **内部审核草稿** 的 `review_policy`，不同于 EC197 允许准备 AI context 的 release policy：固定 `purpose=report_writing_internal_review_draft_only`、`audience=HUMAN_REPORT_EDITOR_INTERNAL`、`task_kind=report_writing`、`route_id=ces.route.report_writing.v1`、`permit_review_only=true`，再钉住 EC197 的 prepared binding、ai_input SHA、scope、metrics、period；每个显式仓库都有自己的 `permit_review_only=true`、报表/来源/人员 pin、**不同于 EC197 的独立收据 SHA**，以及该仓 EC197 已脱敏 `cesrc1:` citation 的**完整精确 allowlist**。总策略收据也须独立，不允许复用旧 release receipt 或其它仓的 writer receipt。少任意一仓、跨仓引用、增删引用、额外字段或过期 pin 都拒绝。将 EC197 的引用减少后重新估算 CI/coverage 不属于本轮：需要缩小引用时，应先产生新的 EC197 release policy 和完整原始回放，然后用新上下文建立对应 EC198 策略。

**这些 receipt/SHA 均只是调用方提供的声明性绑定**，没有外部签名/受众许可/员工同意验证，不能因为本地 digest 匹配就据此将资料传给第三方，也不能把它认作法律或隐私审核已完成。

输出 `subject.handoff_draft`：

- 精确保留 **完整、未经二次扩大/偷偷减少**的 `ai_input`，含周期、32 仓上限的源/人绑定、四渠道证据、全球及逐仓/渠道缺口、撤留/未知/空非零的语义和固定安全指令。
- 构建一份真的、结构化的内部审核提纲 `outline`：开头的报告范围与时间段、每仓独立板块、每仓四个证据槽（Git、AI、CI、Unknown）、每槽的脱敏 citation/声明覆盖/CI 状态与安全描述、尾部全局缺口。**段落只能是中立固定模板和占位符**，没有未经核实的事实性成果陈述。
- 生成稳定的 `cesrhd1:` 内容摘要引用，绑定 EC197 原始规范字节 SHA、prep/scope/metrics/release、独立 review policy。此 ID **不是** EC171 实际创建的 `RunId` / `HandoffId`、不是一次 AI 调度，也不是可信签名。
- `task_kind=report_writing` 和 `route_id=ces.route.report_writing.v1` 与 EC174 既有登记名称一致，但**不改动 EC174**；EC174 的 `report_writing` EC173 输入仍标记 unsupported，本轮不会假装已注册可分发路由。
- `trust_claims` 全 false，外传状态 `NOT_AUTHORIZED_NOT_DISPATCHED`、人工审校 `PENDING_HUMAN_SOURCE_AND_PRIVACY_REVIEW`；不生成评星、排名、人员生产力结论、编造 CI PASS、原始 Git/源码/日志/身份文本，也不做持久化。

## Python 调用

在 `ces/construction` 目录的 Python 环境中：

```python
from report_writing_handoff import (
    ReportWritingHandoff, PURPOSE, AUDIENCE, TASK_KIND,
    ROUTE_ID, POLICY_SCHEMA,
)

# 假设已有可信来源**声明**的 EC195、EC196、EC197 结果与原始释放策略。
# scope_result['canonical_json'] / metrics_result['canonical_json'] /
# prepared_result['canonical_json'] 分别来自对应实际 .bind。
prepared = prepared_result['subject']

# receipt values 必须由操作员/审批系统提供，本示例不制造或认定审批收据。
policy = {
    'schema': POLICY_SCHEMA,
    'purpose': PURPOSE,
    'audience': AUDIENCE,
    'task_kind': TASK_KIND,
    'route_id': ROUTE_ID,
    'permit_review_only': True,
    'prepare_binding_sha256': prepared['binding_sha256'],
    'ai_input_sha256': prepared['ai_input_sha256'],
    'scope_binding_sha256': prepared['scope_binding_sha256'],
    'metrics_binding_sha256': prepared['metrics_binding_sha256'],
    'period_id': prepared['period_id'],
    'policy_receipt_sha256': operator_supplied_distinct_review_policy_receipt_sha256,
    'repository_grants': [
        {
            'repository_ref': repo['repository_ref'],
            'report_subject_ref': repo['report_subject_ref'],
            'source_binding_sha256': repo['source_binding_sha256'],
            'people_binding_sha256': repo['people_binding_sha256'],
            'permit_review_only': True,
            'review_receipt_sha256': operator_supplied_receipt_by_repo[repo['repository_ref']],
            'approved_citation_refs': [citation['citation_ref']
                for channel in repo['channels'] for citation in channel['citations']],
        }
        for repo in prepared['ai_input']['repositories']
    ],
}
api = ReportWritingHandoff()
result = api.bind(
    prepare_json=prepared_result['canonical_json'],
    scope_json=scope_result['canonical_json'],
    metrics_json=metrics_result['canonical_json'],
    release_policy=ec197_release_policy,
    review_policy=policy,
    people_subject_witnesses=original_ec194_witnesses_if_needed,
)
if result['status'] == 'partial':
    # 仅供人工审阅，不提交任何 AI provider，也不当作已渲染报告。
    handoff_draft = result['subject']['handoff_draft']
    checked = api.from_json(
        serialized=result['canonical_json'],
        prepare_json=prepared_result['canonical_json'],
        scope_json=scope_result['canonical_json'],
        metrics_json=metrics_result['canonical_json'],
        release_policy=ec197_release_policy,
        review_policy=policy,
        people_subject_witnesses=original_ec194_witnesses_if_needed,
    )
```

`operator_supplied_...` 是使用方需**另行取得**的占位符变量，不是本项目生成的真实签名。若上下游没有任何事件，`approved_citation_refs=[]` 合法，但不能把它写成“员工/项目没有开展活动”；每仓仍需独立审核批准。多个仓的同一 receipt SHA 会拒绝。

## 结果与拒绝约定

结果包络固定 `schema=ces.report_writing_handoff.v1`、`subject`、`canonical_json`、`limitations`。成功只能 `partial/2`，代码是 `REPORT_WRITING_HANDOFF_REVIEW_ONLY_DRAFT`（回放是 `REPORT_WRITING_HANDOFF_REPLAYED_REVIEW_DRAFT`）；无独立审核权限、原仓受限、引用集合不符或 pin 过期是 `unavailable/5`；错误数据、非规范 JSON、大小/字段不符是 `invalid_input/4`。拒绝不会返还任何局部草稿、收据原文或身份。

- 输入：EC197 规范 JSON 最多 1 MiB；策略 JSON 最多 256 KiB；输出 record 最多 1 MiB；EC197 每仓/证据上限继续生效。
- 所有输出键与值以 Draft2020-12 schema 严格约束，编辑说明来自固定的代码常量；不会从原证据 text、系统 prompt 或外部用户自由文本拼成写作指令。
- `from_json` 不只是比较自报 SHA：用**原 EC195/EC196/EC197 JSON、release policy、review policy、需要时的 EC194 witness** 重新建立完整 Handoff，再逐字节对比规范结果。`cesrhd1:` 和 binding SHA 不证明真实授权或实际 AI 处理。
- `report_writing` 不能自动评判、排名或评分人员；CI `PASS_COMPLETION_CLAIM_UNVERIFIED` 也不是 PASS；`REDACTED_CI_COMPLETION_UNKNOWN` 是不确定，不可写成通过；ProposedPR 不等于交付；未知/缺失必须展示，不能暗中跨仓合并人员活动。

## 还没有做的事

真实权限签收、撤销与隐私外传审核，真人/仓/证据/CI/Git/Provider 可信证明，EC171 活跃 Handoff、EC174 外部 AI `report_writing` 分发适配器、EC199 ReportRender、EC200 报告更正/展示、ReportPublish、持久化、原生 PowerShell 调用、真实跨平台验收都未实现或未运行。开发期合成用例**不是**最终验收。最终用户辅助阶段再联合验证 Windows/macOS/Linux、PowerShell 7、旧15 Smoke、时区数据库、真实 Git/Provider/AI/CI、E63–E66及 B-001 上游资料。
