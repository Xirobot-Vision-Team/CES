# EC344 — 独立收件名录、Ed25519 可见性原件与跨接收方缺件/分支对照

Historical record names below are archival references; those files are absent
from this source tree. See [cleanup scope](../docs/CLEANUP.md).

**V6.54 / R344 / EC-344。仅离线证据。所有通过的审计都返回 `exit_code=2` / `*_unresolved`，绝不代表实际远端 CAS/WORM 冻结、撤回、释放、全球最新发行者根或被授权选胜者。**

## 1. 三层证据，不能互相替代

| 层次 | 原件 | 应由谁信任与固定 | 审计含义 |
| --- | --- | --- | --- |
| EC343 已签旧链 | EC341 根、EC342 已独立批准的 hold、EC343 快照与 ack-set | 原有独立受信全原 SHA 和明确 root/epoch/UTC | 在**本次出示的**快照上复演旧 EC342→337 密码学、完整 ZIP/原件与 EC343 接收收据 |
| EC344 独立名录 | `ces.ec344.pinned_independent_recipient_directory.v1` | 与签名主体不同的外部保管者单独获取、固定**整原 JSON raw SHA** | 最多 6 条独立声明的接收人身份，和 EC343 原 roster 逐项比较；不充当新签署授权来源 |
| EC344 检查点 | `ces.ec344.pinned_bounded_visibility_checkpoint.v1` | 外部保管者**另行**固定 checkpoint 整原 SHA 和唯一 round nonce | 最多 8 个带全原 SHA 的 snapshot/ack-set 宣告，允许**尚未出示**原件，不能据此自证存在或真实性 |
| EC344 接收方视图 | `ces.ec344.ed25519_receiver_visibility_statement.v1` | 两名以上 EC343 roster 中的实际 Ed25519 接收方分别签名；接收方单独固定**各签名原件整 SHA** | 声称自己见过哪个 *checkpoint 条目 + 两个 SHA*；不是文件物理送达、时间可信、审计者已经拿到原件的证明 |

`directory` 与 EC343 roster **不一致时，允许出具有证据的 unresolved 不一致报告**，但不能让 directory 中的陌生人伪装成 EC343 授权签署人。每个 `sign-view` 私钥必须匹配原 EC343 的注册 receiver，EC344 不重用 EC343 收讫签名域。全部候选都标为 **本地未独立信任**，`--expected-*-sha256` 必须从外部独立受信途径获得，不能把本机工具自己打印的 SHA 当做机构背书。

## 2. 数据与约束

- **Directory** 精确字段：`schema`, `case_id`, `ec343_roster_original_raw_sha256`, `round_nonce_sha256`, `receivers`, `not_a_global_or_authoritative_recipient_registry:true`。`receivers` 为 1–6 个 `{signer_id, public_hex, organization_id}`，每一字段在目录内不得重复；允许缺列或多列以便真正报告外部名录差异。
- **Checkpoint** 精确字段：`schema`, `case_id`, `ec343_roster_original_raw_sha256`, `directory_original_raw_sha256`, `round_nonce_sha256`, `announcements`, `not_a_global_or_complete_fork_inventory:true`。`announcements` 必须为 1–8 项**按先验顺序**的 `{item_id,slot_id,snapshot_file,expected_snapshot_sha256,ack_set_file,expected_ack_set_sha256}`。每条的文件路径是规范绝对路径；一条快照可有多份不同有效 ack-set，但同一 checkpoint item ID 或完全重复的 `(snapshot SHA, ack SHA)` 禁止。**相同路径不能宣告不同整 SHA。** `slot_id` 是外部命名的对照标签，*不*意味着唯一当前版本。
- **Receiver view** 各自以 `CES/EC344/ReceiverVisibilityStatement/v1\0` 隔离 Ed25519 域真签。claim 精确绑定原 EC343 roster SHA、directory SHA、checkpoint SHA、round nonce、接收人 ID/公钥/组织、独立每-view nonce、申报 UTC、已观察到的 checkpoint item ID 及**对应 snapshot/ack 原 SHA 对**；只准 checkpoint 顺序的唯一子集，空集合法。1–2 条视图/接收人，合计 2–8 条真签、至少 **2 个不同**注册接收方，旧信任角色仍须通过 EC343 全链约束。
- **已出示**由接收审计方使用 `--presented-item-id` 明确选择，1–8 项且包含 `--anchor-item-id`。锚条目必须和独立传入的 EC343 head snapshot/ack-set 四项路径/SHA 完全一致。所有被明确标为已出示的条目**必须真的可读、SHA 正确、旧真实签章及全部引用原件可验**，否则是 `exit3/4/5` 拒绝，不能装成 `missing` 状态。其他宣告只作为未出示的**声明**，审计器不会尝试打开它们，也不会声称现实中已经丢失。
- EC344 不可用“多数人可见某版本”、相同 snapshot 的不同 ack-set 或同父 fork 推导已执行 CAS、撤销旧批次、确定新 root、全球唯一赢家；不同 view UTC 只是一方声称的时间戳，必须不晚于本次评估的**声明** UTC，仍不等于可信外部钟表。

## 3. 离线四个操作命令

使用隔离 Python：`python -I -B scripts/ces_cas_receiver_visibility.py <command> [flags]`。私钥只应放在实际 owner 控制的私有独立路径；输出 `0600`、`O_EXCL`、`fsync`、不覆盖、不进入统一控制台。下例 `$ROSTER_SHA`、`$DIRECTORY_SHA`、`$CHECKPOINT_SHA`、`$VIEW_A_SHA` 均代表在**独立途径固定**的完整原文件 SHA，不是脚本自动授信。

### A. `assemble-directory`（仅 unsigned 候选）

```bash
python -I -B scripts/ces_cas_receiver_visibility.py assemble-directory \
  --out /private/ec344-directory.json \
  --roster-file /private/ec343-roster.json --expected-roster-sha256 "$ROSTER_SHA" \
  --round-nonce-sha256 "$NEW_INDEPENDENT_ROUND_NONCE_SHA" \
  --receiver-id ec343_receiver_a --receiver-public-hex "$RECEIVER_A_PUB" \
  --receiver-organization-id organization_a \
  --receiver-id ec343_receiver_b --receiver-public-hex "$RECEIVER_B_PUB" \
  --receiver-organization-id organization_b
```

### B. `assemble-checkpoint`（声明可以涵盖未提供的原件）

```bash
python -I -B scripts/ces_cas_receiver_visibility.py assemble-checkpoint \
  --out /private/ec344-checkpoint.json \
  --roster-file /private/ec343-roster.json --expected-roster-sha256 "$ROSTER_SHA" \
  --directory-file /private/ec344-directory.json --expected-directory-sha256 "$DIRECTORY_SHA" \
  --item-id base --slot-id candidate \
  --snapshot-file /private/ec343-base.json --expected-snapshot-sha256 "$BASE_SHA" \
  --ack-set-file /private/ec343-base-ack-set.json --expected-ack-set-sha256 "$BASE_ACK_SHA" \
  --item-id branch_a --slot-id candidate \
  --snapshot-file /private/branch-a.json --expected-snapshot-sha256 "$BRANCH_A_SHA" \
  --ack-set-file /private/branch-a-acks.json --expected-ack-set-sha256 "$BRANCH_A_ACK_SHA"
```

### C. `sign-view`（逐人独立私钥签有界可见性）

```bash
python -I -B scripts/ces_cas_receiver_visibility.py sign-view \
  --out /private/receiver-a-view.json \
  --private-key-file /private/receiver-a-ed25519.key \
  --roster-file /private/ec343-roster.json --expected-roster-sha256 "$ROSTER_SHA" \
  --directory-file /private/ec344-directory.json --expected-directory-sha256 "$DIRECTORY_SHA" \
  --checkpoint-file /private/ec344-checkpoint.json --expected-checkpoint-sha256 "$CHECKPOINT_SHA" \
  --observed-item-id base --observed-item-id branch_a \
  --view-nonce-sha256 "$NEW_RECEIVER_A_VIEW_NONCE_SHA" \
  --reported-utc 2026-10-25T13:16:00Z
```

每位接收方应使用自己的私有机器/秘钥完成真实签署，再通过独立可信渠道交付完整视图原件及 SHA。签名命令只认可 original EC343 roster 中的真实接收方密钥，不为 directory 的声明签字背书。

### D. `audit-views`（受信接收端只读）

除了下面的新增字段，**必须完整提供 EC343 `verify-timeline` 的原始 mandatory flags**：
`--manifest-file`, `--expected-manifest-sha256`, `--expected-current-root-sha256`, `--expected-current-root-epoch`, `--minimum-acceptable-epoch`, `--current-root-evaluation-utc`, `--governance-roster-file`, `--expected-governance-roster-sha256`, `--review-manifest-file`, `--expected-review-manifest-sha256`, `--approval-file`, `--expected-approval-sha256`, `--hold-evaluation-utc`, `--roster-file`, `--expected-roster-sha256`, `--head-snapshot-file`, `--expected-head-snapshot-sha256`, `--head-ack-set-file`, `--expected-head-ack-set-sha256`, `--timeline-evaluation-utc`。

```bash
python -I -B scripts/ces_cas_receiver_visibility.py audit-views \
  [ALL_REQUIRED_EC343_VERIFY_TIMELINE_FLAGS] \
  --directory-file /private/ec344-directory.json --expected-directory-sha256 "$DIRECTORY_SHA" \
  --checkpoint-file /private/ec344-checkpoint.json --expected-checkpoint-sha256 "$CHECKPOINT_SHA" \
  --anchor-item-id base \
  --view-file /private/receiver-a-view.json --expected-view-sha256 "$VIEW_A_SHA" \
  --view-file /private/receiver-b-view.json --expected-view-sha256 "$VIEW_B_SHA" \
  --presented-item-id base --presented-item-id branch_a
```

上述 `[ALL_REQUIRED_...]` 是**文档占位符**，不是合法 CLI 字面参数。统一控制台使用**同样全部 `audit-views` flags**：

```text
python -I -B scripts/ces_next.py audit-receiver-visibility DeliveryAudit CompareSignedReceiverVisibility \
  [ALL_REQUIRED_EC343_VERIFY_TIMELINE_FLAGS] \
  [ALL_REQUIRED_EC344_DIRECTORY_CHECKPOINT_VIEW_AND_PRESENTED_FLAGS]
```

统一控制台只允许固定 `python -I -B ... audit-views`，严格检查控制参数和响应字段，拒绝 writer/sign/install/remote routes。它通过原 EC343 `verify_timeline` 实际复演 EC342 已签独立批准、EC341 签名同父分叉及 EC340→337 ZIP/原 SHA 历史；其余**确实已出示**条目执行 EC343 `_load_chain` + `_ackset` 完整真签/SHA/收据校验，最后复读所有新原件 SHA。对同父分叉，必须双方已出示并且同一签名父快照 SHA、相同 sequence、不同签名请求 SHA，才能写入 `verified_signed_same_parent_sibling_item_pairs`；单纯声明不构成已验证 fork。

## 4. 可审计的结果与优先级

所有成功状态均 `exit2 *_unresolved`，从高到低：
`verified_signed_same_parent_forks_unresolved`；
`same_receiver_divergent_signed_views_unresolved`；
`independent_receiver_directory_mismatch_unresolved`；
`parallel_ack_sets_same_snapshot_unresolved`；
`signed_cross_receiver_visibility_diff_unresolved`；
`signed_claimed_originals_not_presented_unresolved`；
`some_registered_receiver_views_missing_unresolved`；
`checkpoint_items_not_presented_unresolved`；
`aligned_bounded_sample_only_unresolved`。

优先级**只影响主状态名称**，不隐藏较低优先级问题。完整 JSON 同时给出：

- 原 EC343 roster 与独立目录的缺列、新增、同 ID 不同公钥/机构；未签可见性视图的原注册接收人 ID。
- 每个签署人的原始视图 SHA 列表、观察条目 union、该签署人**声称看到但本轮没出示**的 item ID。
- 不同接收方的声称 visibility 对称差；同一接收人两条在同一 checkpoint/round 中不一致的签名视图（**不判定欺诈或同一实际时刻**）。
- 已真实验证的 snapshot/ack-set SHA、sequence、原签请求类型、父 SHA 和确认人数；双方真签、已出示的同父分叉对及相同 snapshot 的不同 ack-set 对。
- 检查点宣布但本轮未出示、至少一人声称看到但未出示、在任何已提供签名 view 都无人声称看到的条目。**“未出示”不等于“全球丢失”**，也不能从只有一两个接收方的对照外推出完整全球收件人清单。

拒绝状态 `exit3/4/5`：错误外部 whole SHA、伪签或角色非 EC343 receiver、duplicate view nonce / ID / SHA 不符、选中条目不可读或缺它引用的原件、已见签名晚于评价时间、少于两位独立已签接收人、EC343/342/341 旧史验签失败、异常输出或有写入企图等。拒绝结果不能冒充通过状态。

## 5. 仍需用户累计联合验证

此 EC 的本地测试以真正 EC344/343/342 等 Ed25519 和旧原件 SHA 为主，但**旧 EC317/318 深层历史仍使用 MOCK fixture**，并不等于生产全链真实验签通过。真实世界的外部 SHA custody、接收机构身份、可信时间、隐藏 fork/完整接收方名录、global latest/winner、真实远端 CAS/WORM freeze/release/readback/nonexecution、PS7/原始 15 Smoke、跨 OS/Git/CI/Provider/E63–E66 与最终验收均 `NOT_RUN/NOT_PROVEN`；EC249 不完整、EC250 blocked、B-001 OPEN、Quality=false、final NOT_STARTED 不变。

请参考 `施工说明`、[实现](../construction/receiver_visibility/visibility.py)、[聚焦测试](../construction/receiver_visibility/test_visibility.py)、`范围`、`本地记录`、`全 SHA`、`下一轮`。
