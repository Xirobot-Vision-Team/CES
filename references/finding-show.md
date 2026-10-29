# EC179 FindingShow — 真正授权的私有 Finding 账本查询

**施工包 V4.89/R179/EC179。** 独立的 `construction/finding_show.py` 中 `FindingShower.query()` 已实现；**不是**原生 `scripts/ces.ps1 -Action FindingShow` 路由。完整输出契约：[`finding-show-result.v1.schema.json`](finding-show-result.v1.schema.json)。操作是实际只读的：不跑模型、测试、CI 或 Git，不读原源码行，不传输外部数据，不改写私有库、业务仓或 Issue。

## 1. 来源、权限与信任语义

`FindingShower` 唯一数据源是操作者先行独立建立的 **EC178 真正 CES 私有 POSIX HMAC 库**，不是调用方传入的列表、票据 SHA 或某个 `.json` 路径。每次查询都在原 EC178 `_locked/_all` 私有锁下校验根 inode/路径绑定、属主私有目录、真实 private key SHA、manifest、所有历史 batch 文件的 HMAC 和 SHA 链、全库连续序列和 Finding 身份、拒绝未知/未完成 pending/符号链接/硬链接及不符合权限文件。最后再次核对根 pin。任一批次校验失败，**整次不返回部分 Finding 元数据**。

每页都要求新的调用方**独立授权声明**：`authorize_store_read=True`（读这座私有账本）、`authorize_query=True`（执行本查询）、正确的 `expected_finding_store_pin` 和本次明确批准的 **完整十字段** `authorized_source_binding` + 精确 `query_content_for`。即使已持有 `next_cursor` 也必须重新提交这些许可。只能查询与该完整 source binding **字节值相等**的批次，不能用模式名、从旧票据拷贝的 hash、猜测的路径或 cursor 扩大范围。

> 布尔 grant 仍是**调用方授权声明**；本地 HMAC 仅证明这座库的密钥持有者及历史封存一致性，不能认证真人身份、外部 Provider、Git HEAD/分支当前状态、CI PASS、实际测试或缺陷语义真实性。`REVIEWED` 也仅为本地 HMAC key-holder 曾声明 confirm；`UNVERIFIED`、`REJECTED`、`INCONCLUSIVE` 仍是不确定陈述。所有成功读都为 `partial/2`，包括无匹配（**不能证明不存在缺陷**）。

## 2. 精确查询示例

```python
# 在工程目录内确保 construction/ 在 Python 路径中
from finding_show import FindingShower

show = FindingShower(stage_root, business_repo_root, finding_store_root,
                     codesave_root=None)  # 若 store 初始化时绑定了 CodeSave 根，必须保持同配置

# source_binding 来自经人工确认的 EC177/EC178 来源，不是旧 JSON 授权。
# 选择为本次读取明确批准的十字段原 source binding。
result = show.query(
    expected_finding_store_pin=store_pin,
    authorize_store_read=True,
    authorize_query=True,
    authorized_source_binding=authorized_source_binding,
    query_content_for="WorkingTree",  # 或明确授权的 DeliveredTarget/ProposedPR
    filters={"severity": "high", "assessment_state": "REVIEWED"},
    page_size=10,
)
assert result["status"] == "partial" and result["exit_code"] == 2
for row in result["findings"]:
    print(row["finding_id"], row["severity_claim"], row["assessment_state"])

# 每页都需重新提交同样的独立授权和 scope；cursor 本身不是权限。
if result["next_cursor"] is not None:
    next_page = show.query(
        expected_finding_store_pin=store_pin,
        authorize_store_read=True, authorize_query=True,
        authorized_source_binding=authorized_source_binding,
        query_content_for="WorkingTree",
        filters={"severity": "high", "assessment_state": "REVIEWED"},
        page_size=10,
        cursor=result["next_cursor"],
    )
```

`filters` 是严格 allowlist、精确相等且 AND 关系，无通配符、无模糊路径、无模型自然语言匹配：

- Finding/分类：`finding_id` (64 字节小写 hex)、`severity` (`info/low/medium/high/critical`)、`confidence_claim` (`low/medium/high`)、`assessment_state` (`UNVERIFIED/REVIEWED/REJECTED/INCONCLUSIVE`；没有 `ACTUALLY_TESTED`)。
- 源：`run_id`、`handoff_id`、`stage_revision`、`stage_event_sha256`、`source_context_sha256`、`source_identity_sha256`、`evidence_hash`、`material_sha256`。这些只是**完整已批准来源内的进一步收窄过滤**，无法向外扩源。
- 批次：`candidate_sha256`、`historical_proposal_only`、`coverage_complete`。
- 文件路径身份：`path_identity_sha256`。**只接受**由 EC177 `_sha(DOMAIN_PATH, source_path)` 算出的 `source_path_sha256`；不是裸路径字符串、不是裸 `sha256(path)`、也不是整个 `source_identity_sha256`。使用这个过滤条件必须在**本轮额外**设置 `authorize_path_digest_query=True`。路径 SHA 可能被猜测，使用此许可前应确认授权范围。

`page_size` 必须是精确 Python `int` 且 `1..25`，默认10。响应按保存的 batch 序号升序 + Finding 身份 digest 升序，最多512条受界内条目。返回 `matched_count`, `returned_count`, `next_cursor`。新的 cursor 用独立域 HMAC 绑定**完整授权源、过滤条件、页大小、披露级别、整个 HMAC 库修订、结果数、偏移和首次签发/截止时刻**。最多300秒、不会因翻页续期，且活跃结果先行到期会进一步缩短期限。查询变更、存储新写入、令牌篡改、到期、撤销读取/查询 grant 或根改变则 fail-closed；重新起一页从头读，不会把旧快照误当新页。无磁盘写、无 cursor 服务器状态。

## 3. v1/v2 索引兼容与覆盖缺口

EC178 的不可变 `ces.finding_save_batch.v1` 没有逐文件路径索引，EC179 **不试图通过猜测 anchor SHA 反推路径**，也不要求为只读查询重开已过期的私有源码。因此旧 HMAC v1 记录可按 ID/来源/状态/严重度检索，但 `path_index_state=LEGACY_V1_UNAVAILABLE`。若筛选路径，旧 v1 不会被判为某个路径匹配，`path_index.legacy_v1_unindexed_in_authorized_nonpath_scope` 会明确计数，并把 `path_filter_exhaustive_for_authorized_records` 置为 `false`，避免给出错误的“无结果”结论。

为让今后的 Finding 真正支持路径查询，EC179 **有限补强了 EC178 写出格式但不改写旧档**：`FindingSaver.save()` 将后续新 batch 标记为 `ces.finding_save_batch.v2`，在既有两次 EC177 真实 source/review 投影得到的正向 anchor 上另外存储逐条 `source_path_sha256` 或 `null`，带完整与否状态，并将该索引纳入原签名 `record_sha256` 和 `mac_sha256`，在读回时验证 Finding ID/锚数量/完整性关联。旧 v1 读法保持兼容、原 batch v1 Schema 不改；新 v2 严格 Schema 为 [`finding-save-batch.v2.schema.json`](finding-save-batch.v2.schema.json)。没有路径信息的原锚只记 `null`，即使是 v2 也只声明 `PARTIAL_OR_UNPATHED`；不根据 filename/模型建议相似性制造路径。

这是精确、来源局部的正向锚路径索引，不是通用仓库文件清单：未被正向锚覆盖的文件不会因此被证明无问题，也不会自动把相似 Finding 视为重复。跨 Finding 关联/重复识别留给 EC180。

## 4. 结果隐私、历史、过期和失败

默认记录仅给出 digest Finding ID、声明的 severity/confidence/state、已封存时间/失效时间、来源模式、局部覆盖率、历史 ProposedPR 标签、正反证据**计数**和路径索引完备级别。不会给出**任何** model title/analysis/action、源码路径、引用行/patch、原审查笔记或密钥。要求披露锚/quote/path/审查链接相关的**哈希详情**时，须同时提交 `include_digest_details=True` 与 `authorize_digest_details=True`，仍只返回哈希，仍不能提高真假结论。普通摘要可能泄漏低熵可猜文本的信息，应在真实授权边界内使用。

`ProposedPR` 必须另外 `acknowledge_historical_proposal_metadata=True` 才允许查询。成功显示仍清楚标注 `historical_proposal_only` 和 `coverage_complete_for_selected_source`、`coverage_missing_requirements_count`，不会认为它是当前 PR snapshot 或 delivered commit。默认过滤过期 batch；若要为了审计查看旧声明，必须**同时** `include_expired=True` 和 `authorize_expired_audit=True`，每条显示 `expired_at_query_time=True`，绝不续签 TTL、追加记录或恢复原授权。设备时钟倒退至批次时间之前、存储失效、pending、权限失配或链条被篡改整次返回 `unavailable/5`。格式/独立许可错误返回 `invalid_input/4`。拒绝信封不会返回任何部分匹配、源 scope、store pin、cursor 或文件内容。

**隐私提醒**：本机制限制了接口输出内容，但不是恶意同UID用户的 OS 级机密保证；拥有私有库磁盘读取和 key 的主体仍可能直接读 SHA 元数据。它不授予任何读取原 EC173 私有封存源码的权限。最终真人/密钥托管、跨 OS / ACL /恶意同UID/多进程竞态/断电、原生 PowerShell7/15 Smoke/真实 Provider/CI 和 E63–E66 性能及全链路联合验收仍 `NOT_RUN`，到全部施工完成后统一用户辅助。
