# EC189 — Quality ↔ Finding 只读证据关联（V4.99/R189）

## 1. 真正交付的接口与准入边界

入口为 [`construction/quality_finding_link.py`](../construction/quality_finding_link.py) 的 `QualityFindingLinker.link()`。这是一段**可调用的 Python 源码功能**，不是模板、未来接口，也不是原生 `ces.ps1 -Action QualityFinding`。它不会写 Finding、改变审核状态、调用 Git/Issue/Provider、运行测试、生成 confirmed bug，或把 CI pass/fail 改写成实际 CES 质量验证。正面结果一律 `partial/2`，拒绝返回空 `links`、无 scope/revision 的 `invalid_input/4` 或 `unavailable/5`。

链接**不能从外部伪造的 FindingShow/QualityShow JSON 投影生成**：同一请求必须直接重跑 **真正的 EC188 `QualityShow.query`**（对所有提供的 EC181–187 producer 原始收据重新校验、每页精确 scope 与每条授权、HMAC 游标），同时直接使用 **真正的 EC179 `FindingShower.query`**（每个明确 Finding ID 都由 EC178 独立私有账本的完整 HMAC 链和新授权支持）。链接输入只允许调用者**选择**存在的 `finding_id` 和 `quality_evidence_id`、填写关系假设与复现声明。

EC177 Finding 使用 `run_id, handoff_id, stage_revision, stage_event_sha256, source_mode, task_kind, source_context_sha256, source_identity_sha256, evidence_hash, material_sha256` 这一**完整 10 字段绑定**；EC188 source 使用 `WorkingTree {source_mode,root_pin_sha256}` 或远端 `{source_mode,provider,repository,project_id,commit_sha,proposal_number}` 的不同身份域。二者不是可直接比较的同一种摘要。EC189 必须新调用可信宿主 `authorize_source_bridge` 对**两个原始完整 scope** 的**此次关联目的**分别授予 `BEFORE_READ` 和 `FINALIZE`，并另行 `authorize_association` 对每对 Finding/证据重新授予权限。宿主须独立核对这两种绑定是否真来自其有权限的选定源；示例 `lambda ...: True` 仅为离线测试夹具，**不构成正式映射器**。

即便授予桥接，输出的 `bridge_sha256` 也是对两组已声明身份的**内容指纹，不是加密签名、原始源码字节认证或实际同一 revision 证明**。本轮**源模式不同立即拒绝**：不能将 WorkingTree/ProposedPR/DeliveredTarget 之间仅凭 SHA 字符串相同而桥接；跨 Source Mode 流转留给 **EC190**。ProposedPR 另外要求当前关联重新明示 `acknowledge_historical_proposal=True`，不表示 PR 已 merge、deploy 或对应现时交付。

## 2. 精确输入与调用范式

- `quality_view`：宿主构造的真实 `QualityShow(cursor_key=...)`，HMAC cursor key 至少 32 字节；`finding_view`：真实 `FindingShower(stage_root, repo_root, finding_store_root, ...)`。构造 `QualityFindingLinker(quality_view, finding_view, note_reference_key=..., clock=...)`。**独立**的私有 `note_reference_key` 必须至少 32 字节，绝不保存在业务源码、请求/日志或 ZIP 中。时钟要求 UTC。
- `source_scope`：同一次 EC188 只读查询中，宿主授予的完整单一来源；`evidence`：最多 96 条**原始** typed EC181–187 producer 结果，附其精确 source scope 和显式 caller-capture UTC 标签；`finding_source_binding`：EC177/179 的完整十字段精确绑定；`expected_finding_store_pin`：来自真实 EC178 私有仓初始化的 pin，非复制的字符串声称。
- **六个单独授权开关**必须均为布尔 `True`：`allow_link`, `allow_quality_query`, `allow_quality_evidence_read`, `allow_finding_store_read`, `allow_finding_query`, `allow_finding_digest_details`。宿主还必须提供原 EC188 的 `authorize_quality_scope` 和 `authorize_quality_evidence` 回调，并为本轮提供 `authorize_source_bridge` 与 `authorize_association` 回调。这些是**每次调用的新许可**，不能借已签的历史记录、游标或旧 Finding 审核继承。
- `associations`：1..24 条，每条恰好 `{"finding_id":lowercase_hex64, "quality_evidence_id":lowercase_hex64, "direction":"support|counter|context", "rationale":"SHARED_HYPOTHESIS_UNVERIFIED|POSSIBLY_UNRELATED|UNDETERMINED", "reproduction": {"state":"NOT_ATTEMPTED|ATTEMPT_REPORTED_UNVERIFIED|REPRODUCED_REPORTED_UNVERIFIED|NOT_REPRODUCED_REPORTED_UNVERIFIED", "statement":null_or_utf8_text, "reported_at_utc":null_or_UTC_Z}}`。同一对不能重复；独立 Finding ≤16。`NOT_ATTEMPTED` 必须 `statement=null,reported_at_utc=null`；其它状态必须提供最多 2048 字节**调用者自己的**复现说明和不晚于当前 UTC + 10 秒的时间。不会执行这些步骤或证明声称为真。

下面展示调用形状（**`host`、`receipt_set`、`existing_finding`、`quality_record_id`、`finding_store_pin` 均需由真实已授权宿主提供**；本项目没有内置可信 host 授权服务）：

```python
from quality_show import QualityShow
from finding_show import FindingShower
from quality_finding_link import QualityFindingLinker

quality_view = QualityShow(cursor_key=host.private_quality_cursor_key)
finding_view = FindingShower(host.stage_root, host.business_root, host.finding_root,
                             clock=host.utc_clock)
linker = QualityFindingLinker(quality_view, finding_view,
                              note_reference_key=host.private_note_ref_key,
                              clock=host.utc_clock)
linked = linker.link(
    source_scope=host.authorized_exact_quality_scope,
    evidence=host.authorized_original_quality_receipts,
    finding_source_binding=host.authorized_exact_finding_binding,
    expected_finding_store_pin=host.true_finding_store_pin,
    associations=[{
        "finding_id": host.selected_existing_finding_id,
        "quality_evidence_id": host.selected_quality_record_id,
        "direction": "context", "rationale": "UNDETERMINED",
        "reproduction": {"state": "NOT_ATTEMPTED", "statement": None,
                         "reported_at_utc": None},
    }],
    allow_link=True, allow_quality_query=True, allow_quality_evidence_read=True,
    allow_finding_store_read=True, allow_finding_query=True,
    allow_finding_digest_details=True,
    authorize_quality_scope=host.authorize_quality_scope,
    authorize_quality_evidence=host.authorize_each_quality_receipt,
    authorize_source_bridge=host.authorize_exact_dual_source_mapping,
    authorize_association=host.authorize_each_proposed_pair,
    acknowledge_historical_proposal=False,  # ProposedPR 时必须单独 True
)
assert (linked['status'], linked['exit_code']) == ('partial', 2)
assert linked['effects']['defect_confirmed'] is False
```

获取选择 ID 的流程：由宿主自身先调用合法 EC188 `QualityShow.query`，使用每个 entry 的 `evidence_id`；同时使用合法 EC179 `FindingShower.query`，取得相同 Finding store/source 中已存在的 `finding_id`。**两次查询只是界面中的供选项目，不是 EC189 的新授权**；`link()` 会重查原始来源及所有许可。不同查询中的源映射由可信宿主再次建立，而非基于名称、标题、路径 SHA、branch 或 reviewer 昵称猜测。

## 3. 功能语义：CI失败不自动生成确认缺陷

| 输入种类与特征 | 候选方向 | 允许呈现的含义 |
|---|---|---|
| EC184 `ci_evidence`、EC185 远端 `observation` 的 `fail` | `support` 或 `context` | `POTENTIAL_SUPPORT_NEVER_DEFECT_PROOF`：仅为可能支持的**提供者内容声称**；测试可能与该 Finding 毫无关系 |
| 同类声明为 `pass` | `counter` 或 `context` | `POTENTIAL_COUNTEREVIDENCE_NEVER_EXONERATION`：正面结果可能构成反证，既不保证全测试覆盖也不排除缺陷 |
| EC182 远端同向明确 job/run 失败或成功结论 | 对应方向或 `context` | **provider job 元数据**，不是测试执行被 CES 证实；job/run 矛盾或缺项时只能 context |
| EC187 host run (即使 `exit_code=0` 或非零)、EC181 config、EC183 SHA、EC186 prepare、任何 partial/missing/not_run | **只允许 `context`** | runner 未鉴权/无 pin、source 配置及准备信息不是故障证据，也不是合格证明 |

`direction` 和 `rationale` 永远是**用户对证据相关性的假设**。即使原单条 EC175 密钥持有人审阅状态为 `REVIEWED`，这也不等于真实缺陷。`REJECTED` Finding 可以做上下文或反向关联，**禁止加 `support`**，避免借 CI 失败复活已经被审阅者否定的声明。Finding 现有 `UNVERIFIED / REVIEWED / REJECTED / INCONCLUSIVE` 状态、严重度/置信度**声称**、正向锚数量、覆盖缺口、ProposedPR 历史语义、存储时间和有效期全部不被改写；过期 Finding 被拒绝，不静默以历史过期记录证明当前缺陷。

每条 link 显式保留原 Finding 已有 `counter_evidence_count` 和独立获准的 `counter_evidence_annotation_sha256`（封存反证注释摘要；**原解释未存入本轮响应**）。若相同 Finding 被关联到一条 `fail` 和一条 `pass`，系统分别保留两条链接，不算“多数票”、不覆写反证、不合成 verified PASS/FAIL。`reproduction.state` 是调用者报告状态；当提供复现文字时，仅回传使用**独立 host 私钥的 HMAC-SHA256 引用**，不会泄露原步骤、路径、密码或错误输出。**调用者必须自行在受信任存储里保管原文字**，引用不能恢复说明；本组件既不存也不认证复制的报告。

## 4. 查询一致性、安全与边界

- EC188 全量原始收据（上限 96）重新查询，最多 4 页（25/页），全量判定完整后才能发布链接；沿用原 EC188 HMAC/300秒游标、每页所有收据重新授权及**全量提供集 revision**约束。按 `evidence_id` 精确定位，不允许任意字符串伪造上下文。只有 `include_numeric_metrics=False`，无需派生的 CI metric 授权。
- EC179 按每个选中 Finding ID 重开真实私有账本、核验完整 HMAC/hash 链、原 10 字段来源及 TTL、只读 digest details，所有查询必须具有**相同 Finding 存储 revision**。最终再回读首个质量页与首个 Finding ID，核对记录、两方 revision、完整输入快照；桥接和所有 pair 回调也最终重新授权。任一拒绝/篡改/过期/变更均**整体无链接返回**。
- 以上是**两套非原子读的保守漂移检测**，不是全程跨系统事务、源真伪认证、权限永不撤销或全历史完整记录的承诺。Provider 证据里的 CI run 与原 Finding 的候选代码可能来自完全无关的实验，即使宿主明确批准链接也**不能**推出原因和缺陷已存在。`recorded_at_utc` 是 caller capture 标签而非 Provider 认证运行时间。没有传入某条证据不等于其不存在。
- 单个响应有严格 [Draft2020-12 schema](quality-finding-link-result.v1.schema.json)；`effects` 的 `finding_created_or_modified`, `finding_review_state_changed`, `git_or_issue_written`, `defect_confirmed`, `test_or_quality_pass_verified` 全为 false。没有本地 cache、数据库、网络、Git、runner、PowerShell 代理或文件写接口。

## 5. 开发检查与集中验收

`cd ces/construction && python -m unittest test_quality_finding_link -q` 本轮使用 22 项离线开发场景：真实 EC178 私有 store 和 EC179 HMAC FindingShow、真实 EC188 代码和原 producer checksum 格式，含失败/通过 claim、反证 digest、审阅状态、复现文字脱敏、重复/越权/跨 mode/过期/伪造条目、分页重授权及输入突变与严格 JSON Schema。所有外部来源均为测试数据，不是在线 GH/GL、真实 repo 代码执行或人工实名审阅。

最终再由用户协助集中验证：实际密钥托管与独立 dual-source host 映射（特别是不同 mode/不同 repository 错桥接）、真实 Git SHA/working tree 字节 pin、活的 CI job/取消/失败与无关测试、过期/多租户拒绝、真实 HMAC store 权限/并发篡改、复现步骤与 Finding 反证可靠性、Windows/macOS 及 PowerShell7/原 15 Smoke、E63–E66 性能、核验过的 runner、全系统 end-to-end。B-001（缺原 V3.10 与原 ROUNDS）的历史证明缺口仍 OPEN；没有已执行的真实最终验收。
