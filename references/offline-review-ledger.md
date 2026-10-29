# EC328 — 多份独立 EC327 线下处置原签的累积防重放审计（无外部 CAS）

## 目的与独立信任前提

为同一个**真实原 EC326 第八方 signed hold request**保存 1–16 份**互不重复第九签名身份/公钥/挑战/decision ID**的 EC327 已签线下审阅回执，并在另一台仅有原件、公开信任参数和完整包外 SHA pin 的验证环境中核对：所有第九 Ed25519 真签、每个回执本身独立 raw SHA、同一原第八请求 raw SHA 和 exact registry / sequence / parent / 两子头 / namespace，再用**生产 `EC327.verify_nonexecution` → `EC326.verify_request` → EC325→EC294 双侧当前全部原签历史**执行一次完整证据复演，并执行所有第九角色在同一案卷内、与旧可见角色/挑战以及与整文件 SHA 间的交叉防重放。所有原件在长重演后重新计算 SHA。新的 EC328 不改任何历史签名、签名域或已签原件。

**三个绝对边界：** (1) EC328 账本是**没有签名**的本地结构和散列链接，不是 WORM、真实 CAS 或全球最新；它的整文件 SHA 必须由**独立受信包外渠道**固定，不能读取候选后在本机自行计算“当作独立来源”。每个第九方公钥/身份是否由真实组织授权也必须由外部核定；账本内填写公钥并不自证组织可信。(2) EC327 签字只是某人做了“线下暂缓/拒绝”的**声明**，即使全部意见一致也**不能证明系统没有在其他地方执行、没有远端提交或当前头未变**。(3) EC328 不连接 endpoint、不接收凭证、无私钥签发、不触碰远端存储；始终返回 `exit=2`（未决）或拒绝 `3/4/5`，不报成功冻结、任何一方赢家、实际业务提交。

## 原件格式与单条追加协议

候选文件只用于创建账本，`--draft-file` 为绝对、规范、owner-private `0600` 的严格 canonical LF JSON，字段恰好如下。示例中 `<...>` 代表**需要用户真实替换的值**，不是可执行原件：

```json
{
  "schema": "ces.ec328.offline_nonexecution_review_draft.v1",
  "signed_request_original_raw_sha256": "<外部固定原第八请求整文件 SHA>",
  "dispute_case_original_raw_sha256": "<外部固定原 EC325 案卷 SHA>",
  "registry_id": "<original_registry_id>",
  "sequence": 1,
  "expected_remote_parent_original_raw_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "two_competing_heads_original_raw_sha256": ["<较小原子头 SHA>", "<较大原子头 SHA>"],
  "target_store_namespace_id": "<target_namespace>",
  "previous_ledger_original_raw_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "entries": [
    {
      "position": 1,
      "receipt_file": "/private/external-ninth-receipt-1.json",
      "receipt_original_raw_sha256": "<独立固定第九签名回执整文件 SHA>",
      "decision_id": "<external_decision_id_1>",
      "ninth_responder_id": "<externally_trusted_responder_id_1>",
      "ninth_responder_public_hex": "<externally_trusted_32byte_ed25519_pub_1>",
      "response_challenge_sha256": "<externally_trusted_fresh_nonce_1>",
      "disposition": "deferred_without_submission",
      "reason_code": "awaiting_authorized_external_executor"
    }
  ]
}
```

- 需用既有 `reg.raw_doc` 序列化为 ASCII JSON，按键排序、紧凑无空白、末尾**一个 LF**，无重复 key、未知字段、BOM 或第二个换行。所有路径是 POSIX 绝对规范路径，owner-private `0600` 的常规非硬链接原件；这一版不改变前代绝对路径协议，不声称 Windows 兼容已经验证。
- 每一行 `position` 是连续的 `1..N`；N=1..16。第九回执 SHA、decision ID、signer ID、公钥、challenge、文件路径**全局不重复**；第九签名另外必须与前八角色及旧真原件中所有可见 ID、公钥、历史挑战去重。每行的 disposition 只可为 `deferred_without_submission` 或 `declined_without_submission`，reason 使用 EC327 三个白名单代码。
- **候选生成**将每条记录补上 `previous_entry_commitment_sha256` 和 `entry_commitment_sha256`。第一行 previous 是 64 位零；下一行 previous 精确为前一行 commitment；commitment 是 SHA256(`b'CES/EC328/OfflineReviewEntry/v1\x00' + canonical_lf_json(含 previous、去掉自身 commitment 的该条 row))。最后一行 commitment 必须与 `ledger_head_entry_commitment_sha256` 相同。外层 schema 变为 `ces.ec328.offline_nonexecution_review_ledger.v1`，明确的 remote write / latest / authority 三项全部为**布尔 false**。这是**无签本地校验码**，不是外部时间戳。
- **追加到已固定的旧账本**：准备一个新候选，包含原账本全部条目（字段逐字节相同）并追加**恰好一条**；`previous_ledger_original_raw_sha256` 必须是独立固定的上一完整账本 raw SHA。验证时必须提供那个旧账本**完整原文件**与其**独立 trusted raw SHA**，并检查新账本比旧账本恰好多一条且旧条目、registry/parent/children/namespace 均完全一致。不能跳行、删行、修改旧条目、替换上级、改动链头。首份账本的 previous 是 64 位零、无 prior 文件，首份可包含 1..16 条，但**不能仅以其本地存在证明这些就是所有曾经出具的回执**。
- 每个账本有两个不同的值：`ledger_original_raw_sha256` 表示**整个文件真正独立固定的 SHA**；`ledger_head_entry_commitment_sha256` 仅表示**行级链的尾部计算值**，不能代替 whole SHA。若没有上一个账本完整文件，只接受首份独立 pinned 的 genesis，而非悄悄忽略先前关联。

## 真正执行命令

### 1. 生成一个未受信候选（**本地文件写**，不签名、不验真）

```bash
python3 scripts/ces_cas_review_ledger.py prepare-unsigned-ledger \
  --draft-file /private/ec328-candidate-draft.json \
  --out /private/ec328-candidate-ledger.json
```

只有**新建不可覆盖**的 0600 文件，使用 `O_EXCL/fsync`；返回候选完整 SHA 供外部独立托管。此处 `all_signatures_or_original_histories_verified=false`，不能拿此返回值当验证成功；准备器不会读取回执私钥，更不会向外部系统发包。**必须先由另一个可信流程独立固定账本的整个原始 SHA + 每个应当信任的公钥/ID/nonce、原 EC326/325 整源 pins，才可执行下一步**。

### 2. 实际只读验证（全部原件和第八信任值必填）

```text
python3 scripts/ces_cas_review_ledger.py verify-ledger \
  --ledger-file /private/ec328-pinned-review-ledger.json \
  --expected-ledger-sha256 <INDEPENDENT_COMPLETE_LEDGER_RAW_SHA> \
  --request-file /private/ec326-original-signed-request.json \
  --expected-request-sha256 <INDEPENDENT_COMPLETE_EIGHTH_RAW_SHA> \
  --case-file /private/ec325-original-dispute.json \
  --expected-case-sha256 <INDEPENDENT_WHOLE_DISPUTE_SHA> \
  --registry-id <TRUSTED_REGISTRY_ID> \
  --expected-sequence <1..16> \
  --expected-prior-registry-sha256 <TRUSTED_ORIGINAL_PARENT_SHA_OR_GENESIS_ZERO> \
  --request-id <TRUSTED_EIGHTH_REQUEST_ID> \
  --target-store-namespace-id <TRUSTED_NAMESPACE_ID> \
  --eighth-signer-id <TRUSTED_EIGHTH_ID> \
  --eighth-signer-public-hex <TRUSTED_EIGHTH_PUB> \
  --request-challenge-sha256 <TRUSTED_EIGHTH_NONCE> \
  --left-registry-file ... --left-expected-registry-sha256 ... \
  --left-capsule-file ... --left-origin-file ... \
  --left-expected-origin-sha256 ... --left-recipient-file ... \
  --left-expected-recipient-sha256 ... \
  --right-registry-file ... --right-expected-registry-sha256 ... \
  --right-capsule-file ... --right-origin-file ... \
  --right-expected-origin-sha256 ... --right-recipient-file ... \
  --right-expected-recipient-sha256 ... \
  [--prior-registry-file /private/original-parent.json] \
  [--prior-ledger-file /private/independently-pinned-old-ledger.json \
   --expected-prior-ledger-sha256 <INDEPENDENT_OLD_WHOLE_LEDGER_SHA>]
```

前代 EC326/327 的两侧原件完整 7×2 参数原样传递，sequence≥2 必须有真正原父头与独立 SHA；ledger 有 prior 则要同时提供 prior 完整原件和独立 SHA，genesis 的 prior ledger 不提供且外部 SHA 缺省全零。CLI 严格禁止任何未声明字段、未知外部端点、写 token 或私钥。它先核对账本和上一账本完整 SHA/结构/append-only 再验证每个真实 Ed25519 第九回执与原第八真签，重放第八/两侧全部旧签历史，排除所有可见角色/nonce 冲突，最后再次重读每份原件整个 SHA。

统一控制台同参数、不能生成候选：

```text
python3 scripts/ces_next.py audit-hold-ledger \
  DeliveryAudit VerifyOfflineNonExecutionReviewLedger \
  --ledger-file ... --expected-ledger-sha256 ... \
  ...其余参数与 verify-ledger 完全相同...
```

控制台只运行固定 `sys.executable -I -B <本包固定脚本路径> verify-ledger`，严格验证结果中的所有远端 false、原第八请求/案卷/parent/children/namespace pins、声明数量/分歧一致性；绝不暴露 `prepare-unsigned-ledger`、`--draft-file/--out`、签名私钥、网络或 CAS writer。成功验证真实 signed 离线争议仍返回 `exit=2`，`status` 是 `offline_review_dispositions_consistent_unresolved` 或 `multiple_offline_review_dispositions_diverge_unresolved`，`disposition_counts` 提供两种签署意见的真实数量；意见一致也非 CAS 事实。权限/密码学或 SHA pin 拒绝 `3`，非法输入 `4`，环境不可用 `5`。

## 已实际施工/未实际验证边界

本地 EC328 新 **19/19** 定向 + EC327 22 / EC326 19 / EC325 15 = **75/75** 聚焦测试实际通过，包含第五到第九角色真实 Ed25519 本地 fixture 签名、多份第九真签、重复旧角色/challenge/公开密钥/decision/路径、完整原 SHA、append 防篡改、单条追加、独立父 SHA、重签错误请求以及后置文件替换。**EC317/318 深层旧证据在继承的结构测试 fixture 内仍 MOCK**；真实 `-I -B` CLI/统一控制台对这批模拟原件预期并实际拒绝 `exit=4`，这是 fail-closed 而非真实生产原签全历史 PASS。没有真实外部第九机构身份材料、独立 SHA 托管或多设备操作、线性化 CAS/WORM/API、真实远端读回、外部 no-submission proof、全球 latest/赢家、PS7 原 15 Smoke、跨 OS、Git/Provider/CI/E63–E66 和最后验收。EC249 incomplete / EC250 BLOCKED / B001 OPEN / global Quality PASS=false / final NOT_STARTED 保留。
