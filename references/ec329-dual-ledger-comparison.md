# EC329 — 两份外部独立 whole-SHA 原账本的完整验签与未决本地分支比对

## 信任关系、为什么一定要保留原件

此命令不会创造也不会替您验证任何「包外可信」来源。调用方必须**先由实际可信的独立渠道**取得两份原 EC328 账本**整个原文件 raw SHA256**、原 EC326 第八签名请求和原 EC325 案卷整个原 SHA、共父原头和双子原头、两侧 EC324 来源 pin，以及每一行 EC327 第九签署者的**外部受信** ID / Ed25519 公钥 / nonce / decision / disposition / reason / 整份回执 raw SHA。不能把从一个未经受信的文件本地算出的 SHA 再当成另一条独立可信见证。

每一个非 genesis 账本还必须提供**该账本自身**所声明的 `previous_ledger_original_raw_sha256` 对应的实际完整上一账本、以及其外部独立 whole SHA；可以共享同一前置文件，甚至一边当前账本可作为另一边前置账本，但这一关联必须由 `EC328.verify_ledger` 的严格「完全旧行 + 一行新增」复验。历史条目位置和无签哈希链仅证明当前本地字节的排列，**无法替代未提供的中间快照或证明全球单一顺序**。

实际运行两次现有 EC328 真验证：先检查两份自身 SHA/规范/请求元数据，再各自逐份验第九原 Ed25519 真签、独立第八 Ed25519 真签、当前**双分支** EC325→EC294 完整旧原签历史及老角色/nonce，最后检查双方所有原件 SHA。`exit=2` 严格表示「可描述的离线本地未决状态」，而不是业务成功。拒绝时 `exit=3/4/5`，无比较通过。

## 两个只读命令

下方尖括号只是参数说明占位符，需要真实替换。旧两侧原始文件字段仍沿用 EC328，**`--left-*`、`--right-*` 指同一个旧 EC325 冲突案卷的原签历史两侧；`--branch-a-*`、`--branch-b-*` 才是本轮要比较的两份第九方审阅账本**。

```text
python3 scripts/ces_cas_review_compare.py compare-ledgers \
  --branch-a-ledger-file /private/external-ledger-a.json \
  --expected-branch-a-ledger-sha256 <A_COMPLETE_INDEPENDENT_RAW_SHA> \
  --branch-b-ledger-file /private/external-ledger-b.json \
  --expected-branch-b-ledger-sha256 <B_COMPLETE_INDEPENDENT_RAW_SHA> \
  --request-file /private/ec326-original-request.json \
  --expected-request-sha256 <EIGHTH_REQUEST_WHOLE_RAW_SHA> \
  --case-file /private/ec325-original-case.json \
  --expected-case-sha256 <DISPUTE_CASE_WHOLE_RAW_SHA> \
  --registry-id <EXTERNALLY_TRUSTED_REGISTRY_ID> \
  --expected-sequence <1_TO_16> \
  --expected-prior-registry-sha256 <ORIGINAL_PARENT_RAW_SHA_OR_64_ZEROS> \
  --request-id <EIGHTH_REQUEST_ID> \
  --target-store-namespace-id <OPAQUE_TARGET_NAMESPACE> \
  --eighth-signer-id <TRUSTED_EIGHTH_SIGNER_ID> \
  --eighth-signer-public-hex <TRUSTED_EIGHTH_ED25519_PUB> \
  --request-challenge-sha256 <TRUSTED_EIGHTH_NONCE> \
  --left-registry-file <ABS_PATH> --left-expected-registry-sha256 <SHA> \
  --left-capsule-file <ABS_PATH> \
  --left-origin-file <ABS_PATH> --left-expected-origin-sha256 <SHA> \
  --left-recipient-file <ABS_PATH> --left-expected-recipient-sha256 <SHA> \
  --right-registry-file <ABS_PATH> --right-expected-registry-sha256 <SHA> \
  --right-capsule-file <ABS_PATH> \
  --right-origin-file <ABS_PATH> --right-expected-origin-sha256 <SHA> \
  --right-recipient-file <ABS_PATH> --right-expected-recipient-sha256 <SHA> \
  [--prior-registry-file /private/original-parent-registry.json] \
  [--branch-a-prior-ledger-file /private/parent-a-original.json \
   --expected-branch-a-prior-ledger-sha256 <INDEPENDENT_A_PRIOR_WHOLE_SHA>] \
  [--branch-b-prior-ledger-file /private/parent-b-original.json \
   --expected-branch-b-prior-ledger-sha256 <INDEPENDENT_B_PRIOR_WHOLE_SHA>]
```

`sequence >= 2` 必须有真正原共同父头文件；genesis `sequence == 1` 时外部父头必须是 64 位零，且不可传父文件。**每个账本各自**前置 whole SHA 是 64 位零表示该账本为 genesis、并且不能传对应的 `--branch-*-prior-ledger-file`；否则前置 SHA 非零且必须同时传上一个完整源文件与包外独立 SHA。两个当前账本绝不能是同一路径。以上所有原件须为规范 POSIX 绝对路径、owner-private 0600 常规文件（本版沿袭原工具路径协议）。

同样参数可通过统一只读入口（移除 `compare-ledgers`，加上 action/mode 前缀）执行：

```text
python3 scripts/ces_next.py audit-hold-ledger-compare \
  DeliveryAudit CompareOfflineReviewLedgers \
  --branch-a-ledger-file ... --expected-branch-a-ledger-sha256 ... \
  --branch-b-ledger-file ... --expected-branch-b-ledger-sha256 ... \
  ...其它请求、原签左右历史和可选前置文件参数...
```

统一入口 `-I -B` 固定调用 `scripts/ces_cas_review_compare.py compare-ledgers`，不开放准备候选、账本 writer、`--out`、`--private-key-file`、CAS endpoints 或凭证。没有远端网络读取/写入。不建议用测试生成器的本地 SHA 当做生产可信锚。

## 比较输出 `relationship` 的准确含义

| 值 | 证明范围 |
|---|---|
| `same_pinned_original_bytes_unresolved` | 两份不同路径文件**完整 raw SHA 相同**且每份各自全验通过；同一份 signed review SHA 不双计 |
| `same_signed_entries_different_unsigned_snapshot_metadata_unresolved` | 所有签名条目和行域哈希完全一致，**外层无签文件元数据不同**；不认定同一原件 |
| `verified_one_entry_append_from_a_to_b_unresolved` / 反向 `...from_b_to_a...` | 方向正确的**恰好一条追加**，完整 parent whole SHA 与前置原文件实际核对，通过 EC328 验真；只限本地源原件 |
| `observed_common_row_prefix_unproven_snapshot_ancestry_unresolved` | 只观察到相同条目前缀；没有提供足够的逐版原文件链，所以**不能**声称中间有连续追加 |
| `different_one_row_appends_to_same_pinned_predecessor_unresolved` | 双方真实相同非零前置 whole SHA，各从同一独立固定原件恰好新增**一条不同**的真签审阅；**本地两条候选分支**而非全球 remote fork 证明 |
| `divergent_locally_pinned_signed_review_lists_unresolved` | 两组已验真的离线签名记录在比较位置分歧，但不能从本地未签账本推出全局唯一性或真实业务冲突结果 |

`common_exact_entry_prefix_length` 仅比较**完整行对象**（含域隔离本地哈希），`first_differing_position_if_both_have_an_entry` 标明首次有双方行的不同点，`branch_*-first_unshared_entry_receipt_sha256` 表示本地排序中第一条超出相同前缀的原签整文件 SHA；并不代表其在真实世界更早或更晚。`branch_a_only_signed_receipt_raw_sha256` / `branch_b_only_signed_receipt_raw_sha256` 是两份账本各自独有回执整原 SHA，`unique_signed_receipt_raw_sha_count` 和 `unique_signed_offline_disposition_counts` 按**两个集合 union** 去重，不能把原件在两账本同时出现理解为两份新签署。

`cross_snapshot_same_receipt_at_different_position_or_with_different_row` 披露同一 signed raw SHA 在两份快照被重排或本地行元数据不同；`cross_snapshot_distinct_receipts_with_reused_role_nonce_decision_or_path` 指不同整签名原件重用第九 ID / public key / challenge / decision ID / path，显示对应两边位置和原 SHA，`cross_snapshot_reused_role_or_nonce_detected=true` 提醒人工调查可能的重复、签署者自我矛盾或无签账本刻意拆分，而不是自动宣布所有签署者独立可信。两份真签意见也可能彼此不同：`distinct_signed_offline_dispositions_detected` 仅显示真实签名内容的差异，不等于双方真实远端操作记录。

**始终布尔 false：** `external_atomic_cas_or_worm_write_performed`、`actual_external_nonexecution_or_hold_proven`、`remote_global_latest_or_winner_proven`、`organizational_identity_or_global_history_completeness_proven`、`two_pins_alone_prove_global_uniqueness_or_authoritative_order`、`business_or_external_store_writes_performed`。新 EC329 不是线性化远端写入/远端已签 readback 适配器，更不会编造远端 CAS 头或最终成功。

## 事实与集中验收

本轮新 **15/15** 聚焦测试通过，含第八、第九测试用 Ed25519 真签；前代 EC317/318 深层旧历史在继承的**结构 fixture 中 MOCK**，隔离启动使用生产原链会正确拒绝 mock。EC329 + EC328/327/326/325 扩大联测在本环境**超时未完成**，不视作 PASS。真正生产全原链/真实独立外部信任锚、多个持钥组织与机器、实际受信 CAS/WORM/readback、PS7 原 15 Smoke、跨 OS、Provider/Git/CI/E63–E66 和最终人工联合验收全部仍待。保留 EC249 incomplete、EC250 BLOCKED、B001 OPEN、Quality PASS=false、final NOT_STARTED。
