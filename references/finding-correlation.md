# EC180 — Finding关联：证据重叠图，而非缺陷自动去重

**完整施工包 V4.90/R180，独立 Python 入口** [`construction/finding_correlate.py`](../construction/finding_correlate.py) 的 `FindingCorrelator.correlate()`。**不是** `scripts/ces.ps1` 的原生 CLI Action；仍不提供 native FindingSave/Show、真实 CI Reader、Issue/Git 修改、联网或实际测试执行。契约：[`finding-correlation-result.v1.schema.json`](finding-correlation-result.v1.schema.json)。

## 1. 权威数据与权限

- 唯一可认为完成本地完整性校验的 Finding 是**真实** EC178 私有 POSIX HMAC 账本里的记录。关联器直接复用 EC179 FindingShow 的 `FindingShower` 和 EC178 `_locked/_all`，在同一个库锁中完整核对 manifest、私钥/根 pin、批次 HMAC/哈希链、连续序列、路径索引结构、到期时钟及最终根身份。不得传入旧 FindingShow 页面/JSON 收据冒充已授权记录。
- 要求 `authorize_correlation=True` 与正确 `expected_finding_store_pin`，加 `scopes`（1–4个）。**每个** scope 都要当轮明确授予 `authorize_store_read`、`authorize_query`、`authorize_scope_correlation`、`authorize_digest_details`，以及 `query_content_for` 与原 EC177/178 **十字段完整** `authorized_source_binding`。多 scope 或与 CodeInsight 联查还必须新授权 `authorize_cross_source_correlation=True`。grant 是调用方的**许可声明**，不认证真人。
- `authorize_path_correlation=True` 才会在内部比较 EC177 域分隔 `source_path_sha256`。不授予时仍可利用已封存 anchor/quote 和声明身份摘要，但不会产生路径共享信号。即使授权路径比较，**输出只包含信号类别**，不输出路径字符串、路径 SHA、quote、model 文字、密钥、人工笔记。可猜测路径散列不是匿名数据。
- 每个 scope 可以增加 `finding_id_allowlist`：`null`（或省略）表示完整源范围；否则为**1–64个升序无重复的64位小写hex Finding ID**，仅用于收窄，不能扩大授权来源。全库在筛选前仍先经过签名/链校验。超过64个入图节点会**整次拒绝**，不会暗中截断或错称负面结果。
- 默认不分析过期批次，`include_expired=True` 还需独立 `authorize_expired_audit=True`；历史 `ProposedPR` scope 必须单独 `acknowledge_historical_proposal_metadata=True`，它从来不是现时交付的证明。REJECTED/过期/跨不具当前对齐见证的历史提案被标记 `INELIGIBLE`，不会复活或制造同一缺陷结论。

## 2. 调用样例

```python
# 将 ces/construction 加到 sys.path，再运行；以下参数来自真实已授权库。
from finding_correlate import FindingCorrelator

c = FindingCorrelator(stage_root, business_repo_root, finding_store_root,
                      codesave_root=None)
scope = {
    "authorized_source_binding": original_ten_field_binding,
    "query_content_for": "WorkingTree",
    "authorize_store_read": True,
    "authorize_query": True,
    "authorize_scope_correlation": True,
    "authorize_digest_details": True,
    "acknowledge_historical_proposal_metadata": False,
    # "finding_id_allowlist": ["<one real exact 64-lowerhex Finding ID>"]
}
args = dict(expected_finding_store_pin=store_pin,
            authorize_correlation=True,
            scopes=[scope],
            authorize_path_correlation=True,
            page_size=20)
first = c.correlate(**args)
assert first["status"] == "partial" and first["exit_code"] == 2
for edge in first["edges"]:
    print(edge["relation_state"], edge["basis"], edge["signals"])
if first["next_cursor"]:
    second = c.correlate(**args, cursor=first["next_cursor"])
```

**CodeInsight 可选来源**：在**另外明确获准取得**历史原生 `ces.code_insight_saved.v1` 的原始记录字节后，提交 `codeinsight_records=[{"record_id":"ci-<64 hex>","raw_bytes": record_bytes}]`；同时设置 `authorize_cross_source_correlation=True`、`authorize_codeinsight_byte_inspection=True`、`authorize_codeinsight_correlation=True`。每次请求都必需这三个独立授权。最多4条记录，逐条不超过512 KiB。EC158 原解析器会检查严格 UTF-8/JSON/version/所有字段/枚举、SHA-256原始字节与完整 `ci-` ID；记录内部 `source_root` 还必须与本次**配置的** `business_repo_root` 字面精确相等，模式仅限 working_tree_diff/ delivered_target_diff。不能通过自然语言、旧分页摘要或 JSON 哈希冒充取库权限。

**关键限制**：这只是调用方交给 EC180 的 **离线字节完整性/格式检查**，不是原生 `CodeShow` 已验证 Git worktree、权限/文件名/索引快照，也不是原生 CodeSave 的真实运行或 authenticated saved-record evidence。`source_root` 相等只是一项记录里的**自声明**；即使同时满足路径与 quote 哈希，也只能形成 `CANDIDATE_SIMILARITY`。没有该独立字节输入时返回 `NOT_PROVIDED_NO_CODEINSIGHT_CLAIM`，不是 CodeInsight 没有问题。**真实 CI/测试系统读取尚在 EC182–185，EC180 不接受或制造 CI PASS/FAIL 见证；不能从静态旧记录的 `ci_verified=false` 推断当前 CI 状态。**

## 3. 关联图输出与边状态

- `nodes[]` 仅有本次允许的源中 Finding 的摘要身份/声明状态及对应 `F0..F3` / `CI` 域。每个 Finding SHA / CodeInsight record ID 是**对应来源自己的标识**，不能在另一来源中当事实认证；没有 title、路径、原文、patch、审查/测试信息。
- 对最多64个节点的每个无向节点对做内部评估（最多2,016对）；`pair_counts` 将所有对归到 `EQUIVALENT_DECLARATION`、`CANDIDATE_SIMILARITY`、`UNKNOWN`、`INELIGIBLE`。默认 `edges[]` 只枚举非 UNKNOWN 的关系；`include_unknown_pairs=True` 时也展示 UNKNOWN。`node_count`、`edge_count`、`returned_count` 都严格有界，**没有边不证明缺陷不同、不存在或已修复**。
- `EQUIVALENT_DECLARATION` 只表示 **同一份 EC177 局部声明 ID**，或在同一**精确来源绑定**下完全相同的原始声明 SHA + 封存 anchor/quote 序列。这是哈希声明等价，不是客观缺陷等价（现存 EC178 写入还禁止跨批次重复 Finding ID）。
- `CANDIDATE_SIMILARITY` 要求可比的**同一个正向 anchor**的路径 SHA + quote SHA 配对相等，或有共享的密封 EC177 anchor SHA；单独共享路径、共享一句普通文本/标题/严重度/置信度都只是 `UNKNOWN`（可能附 `SHARED_*` 弱信号）。比较不使用模型自然语言标题，更不会跨源验证因果或修复。
- `INELIGIBLE` 包括过期/REJECTED/不同 source mode/历史 ProposedPR 未具同一授权来源见证，优先于其他共享信号。`counter_evidence` 只是存在未被语义解决的标记；人工 `REVIEWED` 仍是本地密钥持有人主观声明；覆盖不完整、旧 v1 未索引、新 v2 unpathable 会保留各自 caution。
- 全部成功只返回 `partial/2`；真正无效授权、哈希/Schema、全部链损坏、容量超限则 `invalid_input/4` 或 `unavailable/5`，失败响应不输出任何命中结果。

## 4. 游标与生产未验事项

1–25 条边/页，最多180秒的**独立域** HMAC cursor 绑定完整 scope、精确 Finding allowlist、CodeInsight 原字节 SHA、路径与历史/过期授权选项、页大小、整个真实私有库修订、节点/全部边图 SHA、偏移与签发时刻。每页重新要求完整 grants；游标不能自动延长 TTL，任何参数、已提供 CodeInsight 字节、store HMAC 链、图状态或 record 失效变更会 fail-closed。私有库一次加锁快照，**CodeInsight 输入与私有账本并非跨系统原子快照**。没有任何新记录写入。

需要用户最终集中验收：目标 PowerShell7 + 原15 Smoke、真实 `CodeShow` 数据/工作树权限与 Git 当前性、真实 Provider/人工 key custody/CI/Runner、跨 OS（含 Windows/macOS）、恶意同 UID/ACL/link/网络 FS/断电、长时间并发/时间跳变、E63–E66 性能/整条阶段链。此轮在本地只执行合成开发检查；不能推定这些项目 PASS。仍保留 B-001 缺失的原 V3.10/ROUNDS 历史证据为 OPEN。
