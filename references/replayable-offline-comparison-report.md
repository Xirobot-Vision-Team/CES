# EC330 — 原 EC329 比较结果的离线可重放 whole-raw-SHA 原件

## 必须先弄清的信任前提

EC330 文件是**无签计算报告**。它内含的 `source_pin_claims_not_self_authenticating` 只是**调用时声称的**信任输入，绝不是证明其由机构、两个人、两台机器或任何外部可信托管渠道提供。`create-report` 可以本地生成候选，但**不能**使本地算出的报告 SHA 自动变为“包外受信锚”。若要求另一机构验证，必须在本程序外通过真正可信的独立渠道传递**完整报告原文件 raw SHA256**、两份 EC328 原文件及各自立即前置 SHA、所有每份第九签名人的独立身份/public/nonce/decision 信任、原第八签名请求和争议案卷 SHA、两边当前原签历史与受信父头，真实完成来源授权。即使全部校验通过，也不能把它当作外部业务执行日志。

原 EC328 签名审阅账本的每条记录在**自身原始字节里**包含回执文件的绝对路径，因此跨设备重放必须满足这些原路径或以同等原字节保全方式重建对应路径；EC330 **未**实现原文件打包、路径转换、网络通信或远程受信审计。报告本身不包含命令的绝对文件路径，也不包含私钥。新旧 source SHA/签章协议都未变更。

## 独立入口及参数

生成一份**只能算候选**的本地规范报告： 

```text
python3 scripts/ces_cas_review_report.py create-report \
  --out /private/review-ec329-report-original.json \
  --branch-a-ledger-file /private/ledger-a.json \
  --expected-branch-a-ledger-sha256 <TRUSTED_A_WHOLE_SHA> \
  --branch-b-ledger-file /private/ledger-b.json \
  --expected-branch-b-ledger-sha256 <TRUSTED_B_WHOLE_SHA> \
  --request-file /private/ec326-request.json \
  --expected-request-sha256 <TRUSTED_EIGHTH_REQUEST_SHA> \
  --case-file /private/ec325-case.json \
  --expected-case-sha256 <TRUSTED_DISPUTE_CASE_SHA> \
  --registry-id <TRUSTED_REGISTRY_ID> --expected-sequence <1_TO_16> \
  --expected-prior-registry-sha256 <PARENT_SHA_OR_64_ZEROS> \
  --request-id <REQUEST_ID> \
  --target-store-namespace-id <TARGET_NAMESPACE_ID> \
  --eighth-signer-id <TRUSTED_EIGHTH_ID> \
  --eighth-signer-public-hex <TRUSTED_EIGHTH_ED25519_PUBLIC_HEX> \
  --request-challenge-sha256 <TRUSTED_EIGHTH_NONCE> \
  --left-registry-file <ABS_ORIGINAL_PATH> --left-expected-registry-sha256 <SHA> \
  --left-capsule-file <ABS_ORIGINAL_PATH> \
  --left-origin-file <ABS_ORIGINAL_PATH> --left-expected-origin-sha256 <SHA> \
  --left-recipient-file <ABS_ORIGINAL_PATH> --left-expected-recipient-sha256 <SHA> \
  --right-registry-file <ABS_ORIGINAL_PATH> --right-expected-registry-sha256 <SHA> \
  --right-capsule-file <ABS_ORIGINAL_PATH> \
  --right-origin-file <ABS_ORIGINAL_PATH> --right-expected-origin-sha256 <SHA> \
  --right-recipient-file <ABS_ORIGINAL_PATH> --right-expected-recipient-sha256 <SHA> \
  [--prior-registry-file /private/prior-original-head.json] \
  [--branch-a-prior-ledger-file /private/a-previous-original.json \
   --expected-branch-a-prior-ledger-sha256 <TRUSTED_A_PREVIOUS_SHA>] \
  [--branch-b-prior-ledger-file /private/b-previous-original.json \
   --expected-branch-b-prior-ledger-sha256 <TRUSTED_B_PREVIOUS_SHA>]
```

读端先另外**独立保管**生成的 `report_original_raw_sha256` 以及所有上述 source trust 字段；然后运行：

```text
python3 scripts/ces_cas_review_report.py verify-report \
  --report-file /private/review-ec329-report-original.json \
  --expected-report-sha256 <INDEPENDENT_TRUSTED_COMPLETE_REPORT_RAW_SHA> \
  ...同一组由接收方外部获得的原始 source 参数（不需 --out）...
```

统一只读 `ces_next.py` 使用相同参数、没有 `verify-report` 字面子命令，必须固定 action/mode：

```text
python3 scripts/ces_next.py audit-hold-ledger-report \
  DeliveryAudit VerifyReplayableOfflineLedgerComparisonReport \
  --report-file /private/review-ec329-report-original.json \
  --expected-report-sha256 <INDEPENDENT_TRUSTED_COMPLETE_REPORT_RAW_SHA> \
  ...其余同上...
```

本轮所有旧来源路径协议均为**规范绝对 POSIX 路径**，报告必须和两账本以及全部明确输入源路径不同。报告原件为私有常规文件 `0600`；父目录必须 owner-private。签发端 `create-report` 仅 `O_EXCL` 新建，已存在（含符号链接）绝不覆盖。第一个历史 registry sequence 为 1 时旧父头原 SHA 必须全零且**不能**附父文件；后续 sequence 必须提供已受信父原件。每个 EC328 ledger 的 `expected-branch-*-prior-ledger-sha256` 默认为全零，代表 genesis，且不能传前置文件；非零则必须提供真正完整上一原账本、真实外部原 SHA，对新旧条目仅精确增加一行。与 EC329 的其他限制完全一致。

## 输出和意义

成功生成 `create-report` 返回状态 `unsigned_candidate_report_created_unresolved` 和新整文件 SHA；成功**独立重演** `verify-report` 返回 `externally_pinned_original_report_replayed_unresolved`、`original_report_exactly_reconstructed_from_pinned_inputs=true` 和 EC329 原 `relationship`。两者退出码都是 **2 未决**，绝非操作成功码 `0`。非法输入/权限/环境不可用分别 `4`/`3`/`5`，不会回退使用报告自己携带的旧 SHA。

原件 JSON 具有 `schema`, `interpretation`, `source_pin_claims_not_self_authenticating`, `recomputed_ec329_comparison`, `offline_unresolved_exit_code` 和全部显式 `false` 安全字段。它是**确定性原字节**；人工改动一空格也会破坏 whole SHA 或规范性，篡改合法 JSON 并重新固定 SHA 也不能绕过真实 EC329 完整重演后的逐原字节比对。`recomputed_ec329_comparison` 内保留同原件、直接追加、同父不同追加、缺桥接中间原件、跨账本 signer/nonce/decision 冲突和回执 SHA 去重结果。

一直为 `false` 的字段包括原 EC329 的 `external_atomic_cas_or_worm_write_performed`, `actual_external_nonexecution_or_hold_proven`, `remote_global_latest_or_winner_proven`, `organizational_identity_or_global_history_completeness_proven`, `two_pins_alone_prove_global_uniqueness_or_authoritative_order`, `business_or_external_store_writes_performed`，以及新的 `report_proves_independent_external_sha_custody`, `report_is_signed_or_organizationally_authorized`, `report_itself_proves_full_global_history_or_fork_winner`。全程**无私钥、无签发第十方声明、无外部系统网络 I/O、无真实 CAS 写/受信 readback**。

## 本轮本机证据 / 最终统一验证

命令：

```text
PYTHONPATH=construction PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest construction.replayable_comparison_report.test_report -q
```

EC330 **16/16 新聚焦 PASS，退出码 0**；真第八/九 Ed25519 测试密钥，EC317/318 深层旧 fixture 是 MOCK，隔离进程对 mock 旧历史预期拒绝 `exit4`，不是生产全原签联测通过。原 EC329+EC328/327/326/325 大联合在父包阶段超时，本轮未重跑，生产真正全链/多组织信任/外部 CAS-WORM/PS7/跨 OS/业务 Provider/Git/CI/E63–E66/最终人工验收仍保留待办。EC249 incomplete、EC250 BLOCKED、B001 OPEN、Quality PASS=false、final NOT_STARTED 不变。
