# EC238 — 跨动作 RunId/HandoffId 一致性：真实本地关联，而非执行业务

**施工版：V5.48 / R238 / EC-238；独立 Python API/CLI。** 主入口：
[`construction/cycle_cross_action.py`](../construction/cycle_cross_action.py)
`CycleCrossActionLedger.link()`、`.attach()`、`.check()`。
严格返回格式：[`cycle-cross-action-result.v1.schema.json`](cycle-cross-action-result.v1.schema.json)。
原始快照明确锚格式：[`cycle-cross-action-snapshot.v1.schema.json`](cycle-cross-action-snapshot.v1.schema.json)。

## 真实身份和范围

- EC231 的 `run_v1_...` 是 **Cycle RunId**；EC171/172 产生并以 HMAC
  私有暂存的另一个 `run_v1_...` 是 **staged AI RunId**。两者由不同
  真实创建动作随机生成，绝不假定相等，也不把用户输入的文本当成真正创建。
- 注册前从原 EC231 0700/0600 不可变记录重读实际 Run、Action/Step、
  input hash/字节数/`source_ref`；必须重新交出**完整原始快照字节**。
  该快照在 EC231 创建时必须是下述严格 `ces.cycle_cross_action_snapshot.v1`
  五字段对象，且**当时**已记录真正 EC172 staged RunId、HandoffId、
  来源上下文摘要和来源身份摘要。没有这种锚的旧 EC231 记录不能自动升级；
  不能拿一个任意 Cycle RunId 临时拼接别人的 HandoffId。
- EC172 当前暂存目录与业务仓库目录必须是独立的安全目录；使用原有
  `TaskStaging._locked()`、私有 HMAC、完整 EC171 生命周期 replay、
  parent pin、expiry/revision/last event/source context/identity 再读取。
  **只认真正暂存记录里的 HandoffId**；手工编造的合规字符串无效。
- 注册在 EC231 私有目录内仅写入不可覆盖、0600、fsync 的两个**关联元数据**：
  `run_v1_...cross-stage-owner.json`（一个 staged Run 只能归属一个 Cycle）和
  `handoff_v1_...cross-owner.json`（一个 Handoff 只能归属一个 Cycle）；
  两者域分隔 unsigned SHA，防止误改而不是防止同 UID 恶意改写。
  原 EC231/EC172 文件无修改；业务仓库无修改。
- `attach` 接收**已经生成的生产者 JSON 原始字节**（≤512 KiB），验证
  正确的六大家族 schema、原始 ActionSet 中 `family+step_id` 和其 JSON
  内明确出现的 Cycle/Stage RunId、HandoffId、source context/identity。
  `run_id` 为整数的 CI workflow Run 不被误判成 CES RunId。
  对没有这些字段的原生产者返回值，仅登记**明确创建时的本地字节关联**，
  `identity_fields_checked=0`，绝不冒称输出的原生产者有身份签名。
- 对任一原始字节 SHA-256，只能保存一个 `artifact_<sha256>.cross-artifact.json`
  私有不可变关联。不同 Cycle、不同 Handoff、不同 family/step 若试图复用
  已登记的同一原始草稿，产生**冲突拒绝**，不是另一份成功证据。
- `check` 接受 1–32 份**新交出的完整原始字节**，复算 SHA、全部显式
  身份、阶段来源及登记记录；每份必须有原已保存的关联；任一不符则整批
  `BLOCKED_MIXED_CONTEXT` 且 `artifacts=[]`，不会返回之前几份的局部事实。
  EC231/EC172 文件缺失、损坏、非私有、过期或读中漂移则
  `UNKNOWN_BLOCKED` 且清空所有明细，不能被解释成未开始或成功。

## 快照如何创建（必须先于 EC231 create）

取得真实 EC172 `TaskStaging.stage_live()` 返回的 `run_id`、
`source_context_sha256`、`source_identity_sha256` 和该 staged 生命周期里的
真实 `handoff_id` 后，使用类似如下**严格五字段 JSON**作为 EC231
`CycleMetadataStore.create(snapshot_bytes=...)` 的原始 bytes：

```json
{
  "schema": "ces.cycle_cross_action_snapshot.v1",
  "stage_run_id": "run_v1_<48位小写hex-真实EC172运行>",
  "handoff_id": "handoff_v1_<48位小写hex-真实已暂存交接>",
  "source_context_sha256": "<EC172返回的64位小写hex>",
  "source_identity_sha256": "<EC172返回的64位小写hex>"
}
```

上方 `<...>` 只是文档占位，不是有效实际 ID；实际调用必须将值替换为
**已经由上述原模块真实持久化**的值。在 Cycle `action_set` 里包含真实的
`Code*`/`AIHandoff` 根来源步骤，并为需要关联的每一家族声明相应
`Code*`、`Finding*`、`Quality*`、`Report*`、`Knowledge*`、`Delivery*`
步骤及安全 `step_id`。这些只是计划；不能由关联推动依赖执行。

## API 示例

```python
from construction.cycle_cross_action import CycleCrossActionLedger

ledger = CycleCrossActionLedger(
    '/private/cycle-store', '/private/ec172-stage', '/private/business-repo')
linked = ledger.link(cycle_run_id, real_handoff_id,
    snapshot_bytes=exact_original_snapshot_bytes,
    source_ref=original_source_ref,
    expected_stage_parent_pin=actual_saved_ec172_pin)

attached = ledger.attach(cycle_run_id, real_handoff_id,
    expected_stage_parent_pin=actual_saved_ec172_pin,
    family='Finding', step_id='step_finding',
    artifact_bytes=exact_original_finding_result_json_bytes)

checked = ledger.check(cycle_run_id, real_handoff_id,
    expected_stage_parent_pin=actual_saved_ec172_pin,
    candidates=[{'family': 'Finding', 'step_id': 'step_finding',
                 'artifact_bytes': exact_original_finding_result_json_bytes}])
print(checked['status'], checked['local_identity_consistent'])
```

六种家族允许的既有 schema 包括：

| 家族 | 原有生产者 schema（只检外壳/明确身份，不假装全业务重放） |
| --- | --- |
| Code | `ces.code_prepare_multisource.v1` / `ces.ai_code_context.v1` |
| Finding | `ces.finding_show_result.v1` / `ces.finding_save_result.v1` |
| Quality | `ces.quality_show.v1` / `ces.quality_finding_link.v1` |
| Report | `ces.report_prepare.v1` / `ces.report_writing_handoff.v1` |
| Knowledge | `ces.knowledge_update_handoff.v1` / `ces.knowledge_impact.v1` |
| Delivery | `ces.delivery_preview.v1` / `ces.delivery_redaction.v1` |

CLI 包括 `link --snapshot-file ... --source-ref ...`、
`attach --family ... --step-id ... --artifact-file ...`、
`check --candidates-json ...`。三种命令均需
`--cycle-store --stage-store --business-repo --run-id --handoff-id --stage-parent-pin`。
候选文件本身是本地 JSON 数组，单项**恰好**有
`{ "family": "Finding", "step_id": "step_finding", "artifact_file": "/abs/producer-result.json" }`；
文件读取拒绝符号链接输入叶、BOM、大小写碰撞键、非有限 JSON、超限尺寸。
退出码：2 = 本地关联一致/记录成功（**不是**业务成功），3 = 已知混用拒绝，
5 = 无法可信确认；不会通过 0 暗示完成。

## 必须保留的限制和最终验收

- `LINKED_LOCAL_ONLY` / `ATTACHED_LOCAL_ONLY` / `CONSISTENT_LOCAL_ONLY`
  **不是**独立来源签名、Actor 身份认证、真实 producer 合法产出、
  权限批准、业务执行成功、质量通过、写入成功、AI 调用或远端交付。
  JSON 生产者外壳可被同 UID 或调用者伪造；本模块只能验证在安全私有
  存储作用域内的**显式关联、保存的原始字节和注册前确有暂存**。
- 真实 EC172 staged record 有 TTL，过期即 UNKNOWN/阻断；并非长期
  无条件可读的历史证据。EC231 未保存的原始快照无法凭 SHA 重构。
  不同 Cycle 的相同 staged Run 不得再绑定；如果同一 staged Run 产生
  多 Handoff，仍只允许一个 Cycle owner。
- **暂存目录、Cycle 目录、业务仓库必须分离。** 多文件只创建不覆盖，
  当前未提供跨文件事务、OS 断电/NFS/多机持久性保证；两份索引之间崩溃
  可能留下阻塞性的保守孤儿登记，不能自动删除或重新放行。EC240 后续
  再单独施工 replay/权限失败/并行/冲突协议。
- 本 EC **没有**更改旧 PowerShell V4.60/R150、15 Smoke、EC231–237
  原模块；没有原生 `Cycle` Action 接线（EC241），也没有 EC239 外部调度。
- [`construction/test_cycle_cross_action.py`](../construction/test_cycle_cross_action.py)
  使用真实创建/暂存的 EC171/172 HMAC 记录、真实 EC231 private Run 与
  **合成的**六类生产者输出 JSON，检查不混用、拒绝路径、完整包/CLI。
  真实企业成员/业务 producer 全重放、Git/NFS/跨操作系统、OS crash、
  PowerShell7/原15 Smoke、E63–E66 和统一人工端到端验证继续 **NOT_RUN**。
  B001 最早 V3.10/ROUNDS 原件来源缺失仍 OPEN。
