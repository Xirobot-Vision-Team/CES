# EC190 — Cross Source Mode Quality Flow / 跨源模式质量证据流转

## 1. 交付能力及不可越界语义

入口：`construction/quality_mode_flow.py` 的 `CrossModeQualityFlow(quality_view, clock=...).relate(...)`。这是独立可调用的 **Python 只读功能**，**不是** `ces.ps1` 里已经注册的原生 `QualityFlow` action。支持 2–4 个不同来源类型：`ProposedPR`, `DeliveredTarget`, `WorkingTree`（通过真正的 EC188 `QualityShow`）及可选的 `CodeInsight`（读取原始 `ces.code_insight_saved.v1` 字节、用已有 EC158 `schema_compat` 校验精确 `ci-<sha256>` 身份）。

关联只携带**两端各自的证据和来源事件上下文**，不“传播”成功/失败/漏洞状态。CodeInsight 是静态模型声明；其 `0` Finding 绝不是“0 个 Bug 已被证实”，其 Finding 也不是执行的测试。EC189 的 Finding 审阅、反证和 HMAC 账本不在本接口中被改写；想关联同模式 Finding，必须另行调用 EC189 原接口，并提供它要求的所有原始授权。这一轮**不会**把 EC189 同模式来源 bridge 当成跨模式证明。

**来源链与声明分级：** 事件证明字节的 `sha256`/确切 scope 对齐 = 数据完整性和范围一致性；独立宿主 `verify_source_event` = **宿主表示复核了指定来源事件**；并**不**代表本代码验证了真实 Git 祖先关系、PR merge、部署、生效时间或真实 CI runner。输出 `partial/2`、`source_event_verified_by_ces_git=false`、`quality_state_transferred=false`；业务仓、Issue、Git、CES 存储一律不写。

## 2. 关联与必备独立来源证据

`quality_sources` 是以来源 Mode 作为键的字典，必须有 1–3 个 Quality 模式来源；每条恰有：

```python
{
  'source_scope': { # 与 EC188 完全同形、不能省略/添加键
     'source_mode': 'ProposedPR', 'provider':'github',
     'repository':'owner/repo', 'project_id':123, 'commit_sha':'a'*40,
     'proposal_number':42
  },
  'evidence': [original_ec181_through_ec187_producer_receipt],  # substitute real selected receipts
  'captured_at_utc':'2026-10-23T05:02:00Z'  # caller-provided capture label, not trusted time
}
```

Python 示例中的 `original_ec181_through_ec187_producer_receipt` 是生产调用方须置入的真实原始 EC181–187 收据对象变量，不是内置 API 或允许伪造的样本值。WorkingTree scope 只能包含 `source_mode=WorkingTree` 和 `root_pin_sha256`。DeliveredTarget 远端 scope 保留上述六个字段，但 `proposal_number=None`；ProposedPR 必须另外 `acknowledge_historical_proposal=True`，这不会将提案升级成已交付。

若选择 CodeInsight，则 `code_insight` 严格为：`{'record_id':'ci-'+<原始字节 sha256>, 'native_source_mode':'working_tree_diff|delivered_target_diff', 'captured_at_utc':'...Z'}`。`read_code_insight(facts)` 由可信宿主从**独立授权的 CodeShow/CodeSave 存储**读出**原始 bytes**，并非由请求调用者提供“已验证”的 JSON 投影。组件将 512 KiB 内的字节交已有 EC158 inspector，核对 v1 所有字段、模型与 CI 的 false 证明位、原始内容哈希/ID；禁止无凭据/授权的路径发现、自动修复和模型摘要外泄。即使宿主提供合成字节、哈希恰好吻合，也不能变成原生 CodeSave 实际执行证明。

`relations` 每条：

```python
{
  'event_sha256':'<hex64 of ORIGINAL source event record bytes>',
  'from_item_ids':['<EC188 exact evidence_id or CodeInsight F1>'],
  'to_item_ids':['<EC188 exact evidence_id>']
}
```

每端不超过 8 个不重复 ID。非 CodeInsight 的两端都必须选择**至少一个**从原始 EC188 重查获得的 64 位证据 ID，且必须来自各自 scope，不接受跨源借 ID。CodeInsight 端可选 0..8 个原始 checked Finding `id`，空 Finding 列表允许（但不会转成通过）。关系总数 1..16；每个来源最多 96 条质量收据，4 页 × 25 的 EC188 原查询全部重走；重查失败不能输出已构建的任何关系。

`read_source_event(facts)` 必须通过独立可信来源**解析** `event_sha256`，返回 **UTF-8 JSON 原始 bytes**，≤8192 bytes，禁止从请求中直接照抄 `event` 伪造证明。组件要求字节 SHA256 与选择器匹配，并解析唯一的受版本约束 JSON 对象：

```json
{
  "schema":"ces.cross_mode_source_event.v1",
  "relation_kind":"PROPOSAL_TO_DELIVERED",
  "claim":"SUPPORTED",
  "from_mode":"ProposedPR",
  "to_mode":"DeliveredTarget",
  "from_scope_sha256":"<exact EC188 scope digest>",
  "to_scope_sha256":"<exact EC188 scope digest>",
  "occurred_at_utc":"2026-10-23T05:06:00Z",
  "recorded_at_utc":"2026-10-23T05:08:00Z",
  "proof":{
    "provider":"github","repository":"owner/repo","project_id":123,
    "proposal_number":42,"proposal_head_sha":"<proposal head commit>",
    "delivered_commit_sha":"<exact selected delivered commit>",
    "merge_event_sha256":"<sha256 of separately obtained merge provenance record>"
  }
}
```

字段类型和完整匹配在代码中逐项断言；非 SHA 解析器/宿主的字节字符串相等不能证明真实合并。事件类型：

| `relation_kind` | 必须匹配的来源方向 | `proof` 的独立绑定字段 | 不能推论 |
|---|---|---|---|
| `PROPOSAL_TO_DELIVERED` | ProposedPR → DeliveredTarget | provider/repository/project_id/proposal_number/提案 head SHA/交付目标 SHA/merge_event_sha256 | 提案自身等于交付、已部署或仍是最新 |
| `DELIVERED_TO_WORKTREE` | DeliveredTarget → WorkingTree | remote 身份、delivered_commit_sha、worktree_base_commit_sha 必须是该选择的 delivered SHA、local root pin、local_snapshot_event_sha256 | WorkingTree 字节与提交完全一致、无未提交变动 |
| `CODE_INSIGHT_TO_SOURCE` | CodeInsight → WorkingTree 或 DeliveredTarget（按旧 `native_source_mode`） | saved record ID 和 SHA、native mode、目标 scope 摘要、原 CodeInsight packet/collect 双 SHA、snapshot_map_event_sha256 | 静态审阅是测试结果、真实 Git 来源认证 |
| `CONTEXT_COMPARISON` | 任意不同 Mode | 各端分别由可信宿主取得的 `source_capture_ref_sha256`、`target_capture_ref_sha256` | 版本继承、内容等价、漏洞已修复 |

关系事件 `claim=SUPPORTED|DISPUTED` 保留不同宿主来源的同一关系正/反声明；仅当**确实提供了两条**同向 scope+关系种类、声称相反且未撤销的事件时，在结果中标 `CONTRADICTED_NOT_ACTIVE` 并列出对方摘要，不能多数投票。相反事件没有提供不代表不存在。

## 3. 授权、事件撤销和时间顺序

显式开启 `allow_flow`, `allow_quality_query`, `allow_quality_evidence_read` 三个分离开关；CodeInsight 另开 `allow_code_insight_read`。必须注入已有 EC188 的 `authorize_quality_scope`, `authorize_quality_evidence`：原实现会按每页全收据重新授权。其它回调均由宿主实现，返回 **字面值 `True`** 才视为获准；返回 `1`、`None`、抛异常或者不可调用都拒绝：

- `authorize_code_insight(facts)` / `read_code_insight(facts)`：分别授权与重读旧 CodeInsight 原始 bytes；前后两阶段。
- `authorize_source_event(facts)` / `read_source_event(facts)`：对**原始来源事件**授予独立权限并重读原始 bytes；前后两阶段。
- `verify_source_event(facts)`：可信宿主应**独立查询真实 provider merge event、Git ancestry、本地 snapshot 的 provenance**，核对 `facts.event`, `facts.from_scope/to_scope`, 所选 `source_scopes`、两边原 EC188 revision、原 CodeInsight 字节 ID 和是否撤销；`BEFORE_READ` 与 `FINALIZE` 都须重新返回 `True`。**测试用的 `lambda _: True` 不可直接作为生产身份/来源证明器。**
- `authorize_revocation(facts)` / `read_revocation(facts)` / `verify_revocation(facts)`：仅当请求包含 revocation 时强制要求独立读取/核验和前后重授权。未提供 revocation 并**不**认证不存在撤销，宿主 source verifier 必须自行核对它所掌握的权威撤销账本。

撤销选择器严格 `{'event_sha256':<事件 digest>, 'revocation_sha256':<撤销记录原始 bytes digest>}`，原始撤销字节为：

```json
{
  "schema":"ces.cross_mode_revocation.v1",
  "event_sha256":"<linked event digest>",
  "reason":"MAPPING_CORRECTED",
  "revoked_at_utc":"2026-10-23T05:10:00Z",
  "recorded_at_utc":"2026-10-23T05:11:00Z",
  "host_revocation_event_sha256":"<separately sourced host event sha256>"
}
```

`reason` 还可为 `SOURCE_RETRACTED`, `EVIDENCE_SUPERSEDED`, `HOST_PERMISSION_WITHDRAWN`；一条关联可有多条各自有效的撤销，输出完整摘要列表，关联为 `REVOKED_NOT_ACTIVE`。撤销时间不得早于事件发生时间；记录时间不得早于发生/撤销时间或超过宿主 UTC 当前 +10 秒。所有时间标签必须是明确 UTC `Z`；`captured_at_utc` 是调用者声称，`occurred_at_utc` 是宿主来源事件声称，**不是本代码认证的 Provider 时间**。

时间顺序保留：对于提案→交付、交付→工作树，要求声明的原端采集 `<=` 事件发生 `<=` 目标端采集（容忍 10 秒边界）；CodeInsight 的原静态记录读取应在原来源采样之后。失败不会偷偷重新排序成合理时间，结果标记 `TEMPORAL_CONTRADICTION_NOT_ACTIVE`；纯上下文比较为 `NOT_ORDERED_CONTEXT_COMPARISON`。结果按 `occurred_at_utc_host_declared, event_sha256` 稳定排序，不把传参顺序当成历史。

## 4. API 与拒绝边界

```python
from quality_show import QualityShow
from quality_mode_flow import CrossModeQualityFlow

viewer = QualityShow(cursor_key=host.private_ec188_cursor_key,
                     clock=host.authorized_utc_clock)
flow = CrossModeQualityFlow(viewer, clock=host.authorized_utc_clock)
result = flow.relate(
    quality_sources=host.three_explicit_scoped_original_quality_sources,
    code_insight=host.exact_saved_codeinsight_selector,
    relations=host.selected_exact_source_relation_event_shas_and_item_ids,
    revocations=host.selected_authoritative_revocation_event_shas,
    allow_flow=True, allow_quality_query=True,
    allow_quality_evidence_read=True, allow_code_insight_read=True,
    authorize_quality_scope=host.authorize_exact_ec188_scope,
    authorize_quality_evidence=host.authorize_every_ec188_receipt,
    authorize_code_insight=host.authorize_saved_codeinsight,
    read_code_insight=host.read_original_saved_record_bytes,
    authorize_source_event=host.authorize_each_independent_source_event,
    read_source_event=host.read_original_source_event_bytes,
    verify_source_event=host.recheck_real_source_event_and_revocation_log,
    authorize_revocation=host.authorize_revocation,
    read_revocation=host.read_original_revocation_bytes,
    verify_revocation=host.recheck_real_revocation_event,
    acknowledge_historical_proposal=True,
)
```

此示例中的 `host` 为**宿主必须自行实现并经可信环境验证的接口占位**，本仓库没有伪造的 Git/CI/CodeSave/身份鉴权服务。跨 Mode `source_event` 的原始提供者凭据/Git 真实性不能由数字散列替代；事件时间/撤销列表也不可能证明全世界无其它事件。无 code_insight 时必须至少提供两个 Quality 来源，CodeInsight 权限回调可以省略。若未提供原始关联/证据/授权，将返回 `invalid_input/4` 或 `unavailable/5`，**整个结果的 `sources, relations, revocations` 皆为空**。正面输出始终 `partial/2` 并有 `flow_revision_sha256`，只表示本次输入/查询的只读快照指纹。

## 5. 代码/测试与最终待验

机器契约 [`cross-mode-quality-flow-result.v1.schema.json`](cross-mode-quality-flow-result.v1.schema.json) 采用 Draft2020-12 强类型、严格必备键和无额外键：来源身份、端点每项有限 evidence IDs、静态/CI 声称数、时间对照、撤销摘要及矛盾、所有越界 proof flag 永远为 `false`。Python 代码为内存计算，不读网、不写文件、不运行测试或 Git。原 EC188 `QualityShow` 在每源最多 96 receipt、25/page 的所有页和最终首页 HMAC revision 回查；每个 cross-event/撤销/原始 CodeInsight 在 `FINALIZE` 重新读同一原字节并重新授权。以上仍不构成多系统原子快照。

开发检查：`cd ces/construction && python -m unittest -q test_quality_mode_flow`。34 个明确标为 synthetic 的本地用例（真实旧 EC188 和 EC158 校验代码配合静态伪造的宿主事件），不等于真实 CI/PR merge/CodeSave 的上线可用性。最终用户辅助核验项：独立真实 GH/GL 事件和 Git SHA 祖先链、PR squash/rebase、已交付版本/工作树内容源 pin、CodeShow 可信 main worktree、并发撤销日志、权限随时撤回、真实执行 runner 与静态审阅冲突、PowerShell7 和原 15 Smoke、Windows/macOS、E63–E66、全业务 E2E。均 **NOT_RUN**。B-001 历史 V3.10/原 ROUNDS 缺口仍 OPEN。
