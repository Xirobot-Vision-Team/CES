# EC308 — 独立 CAS 机关 Ed25519 签名决议回执的离线核验

> **边界：** EC308 只能证明一份经独立外部原始 SHA 钉住的、具有正确 Ed25519 机关签名的 **CAS 结果声明**，并从原始 EC294→EC307 证据重新重放同父分叉。它既不能自行写 CAS，也不能证明机关实际得到组织授权、外部存储确实执行了原子比较交换、回执已 WORM 持久化或目前全局 latest。绝不将 `exit_code=0` 理解为“外部提交成功已被真实验证”。

## 场景与先决条件

EC307 `compare --out` 对两条合法同父 EC306 子链出具路径无关分叉报告：`external_cas_handoff` 仅给出父索引 raw SHA 和严格排序的两个候选完整 raw SHA，`externally_authorized_selection_sha256=null`。在真实 CAS/治理系统**之外**，可存在一个外部 CAS 机关签发的“尝试按此父节点提交”的签名回执。EC308 用独立、公钥明示的验签程序审核其声明，不发签名、不投票、不选赢家。

操作方须独立获得并保管（不能从待验回执自举信任）：

- EC307 私有 case JSON 原始整文件 SHA、真实 case 文件、其所引用的三份 EC306 链以及每代真实 EC304 ledger / EC305 certificate / 最新 EC303 ZIP + ACK。
- EC307 已输出的完整路径无关原始冲突证据 JSON，以及在**包外**确认的整文件 raw SHA。
- 外部机关 `cas_authority_id` 和 **独立预先核准**的 `cas_authority_public_hex`（32 字节 Ed25519 公钥，64 lowercase hex）；独立生成并保管的本次 `request_nonce_sha256`。
- 外部 CAS 系统在操作前由可信路径获得的 `(expected_parent_cas_revision, expected_parent_cas_head_sha256)`。后者必须和 EC307 父索引原字节 SHA 完全相同，revision 只能是非负整数，且不能靠回执自证。
- CAS 机关**由外部系统**实际签发的完整 JSON 回执文件和经过独立可信传递/锚定的回执整文件 raw SHA。无这些材料则拒绝，不允许从回执内部计算一个 SHA 然后称作“独立信任”。

## 精确回执协议（v1）

外层必须为恰好三个字段：

```json
{
  "schema": "ces.ec308.external_signed_cas_decision_receipt.v1",
  "claim": {},
  "authority_signature_ed25519": "128-character lowercase hex"
}
```

`claim` 必须是以下 **15 项，不多不少**：

| 字段 | 说明 |
|---|---|
| `schema` | `ces.ec308.external_cas_decision_claim.v1` |
| `registry_id` | 真实 EC307 报告 registry ID |
| `cas_authority_id` | 包外指定机关 ID |
| `cas_authority_public_hex` | 包外指定 Ed25519 公钥 |
| `ec307_fork_evidence_raw_sha256` | 完整原始 EC307 fork evidence 文件 SHA |
| `ec307_choice_request_raw_sha256` | `SHA256(EC307.external_cas_handoff 的规范 JSON+LF)` |
| `request_nonce_sha256` | 包外钉住的本次请求 nonce SHA |
| `expected_parent_chain_raw_sha256` | 原 fork 的精确父 EC306 索引 SHA |
| `candidate_chain_raw_sha256` | EC307 固定按 raw SHA 排序的两条完整候选 SHA |
| `expected_parent_cas_revision` | 包外预先锁定的 CAS revision |
| `expected_parent_cas_head_sha256` | 包外预先锁定的 CAS head = 父 EC306 索引 SHA |
| `outcome` | `compare_exchange_committed_claim` 或 `compare_exchange_precondition_failed_claim` |
| `observed_cas_revision` | 外部机关声称的 CAS 返回 revision |
| `observed_head_chain_raw_sha256` | 外部机关声称的结果 head SHA |
| `selected_candidate_chain_raw_sha256` | 声称提交时是两候选之一；冲突失败时严格 `null` |

> 程序 `CLAIM_FIELDS` 是唯一可执行的精确字段表，不允许添加时间戳、secret、ticket 或新字段绕过版本门。签字消息为
> `b"CES/EC308/ExternalCAS/AuthorityDecisionReceipt/v1\0" + canonical_json(claim)`，
> 其中 `canonical_json` 对应原 `ec295_delivery_anchor.anchor.canonical`：UTF-8、键排序、紧凑分隔、**不带 LF**；外层回执字节则必须用 `ec302_portable_bundle.bundle.canonical` 的排序紧凑 JSON **加 1 个 LF**。签名用正确 Ed25519 私钥在**外部**执行；本包没有签名工具。

（注意：签字消息中的 `\\0` 表示一个零字节，不是两个文字字符；软件常量 `DOMAIN` 为准。）

两种结果只验证带签章的语义一致性：

1. **`compare_exchange_committed_claim`**：`observed_cas_revision = expected_parent_cas_revision + 1`；`observed_head_chain_raw_sha256 == selected_candidate_chain_raw_sha256` 且选中值必须恰是 EC307 两条已验证合法子链之一。**这只是机关对提交状态的签名声明**，不能替代外部存储读回。
2. **`compare_exchange_precondition_failed_claim`**：`observed_cas_revision > expected_parent_cas_revision`，观察 head 与原父 SHA 不同，`selected_candidate_chain_raw_sha256` 必须 `null`。不认定任何一方成功，不证明观察到的其他 head 的完整 signed lineage。

CAS 机关公钥不能复用当前/历史所有提供的 EC306 registrar 公钥、governor，以及 EC307 最新 ACK 中的 A/B witness/receiver 已知签名公钥。**这不是**对原 EC294/295 所有可能角色的完整全世界密钥隔离证明，也不是对组织的真实签发资格证明。

## 独立 CLI

所有路径必须指向调用者控制的 **owner-private 0700 目录 / 0600 单硬链接普通文件**；底层旧 EC306 读取器使用无软链接/前后 inode 元数据一致/规范 JSON 与整文件 SHA 严格核对。命令行示意：

```bash
python3 scripts/ces_cas_receipt.py verify \
  --fork-case-file /private/fork-case.json \
  --expected-fork-case-sha256 CASE_FULL_RAW_SHA \
  --fork-evidence-file /private/fork-report.json \
  --expected-fork-evidence-sha256 FORK_FULL_RAW_SHA \
  --receipt-file /private/cas-receipt.json \
  --expected-receipt-sha256 RECEIPT_FULL_RAW_SHA \
  --cas-authority-id independent_cas_site \
  --cas-public-hex INDEPENDENT_CAS_PUB_HEX \
  --request-nonce-sha256 REQUEST_NONCE_SHA \
  --expected-parent-cas-revision 27 \
  --expected-parent-cas-head-sha256 EXTERNAL_PARENT_HEAD_SHA \
  --out /private/cas-audit-report.json
```

`--out` **可选**；仅输出**无私钥、路径、主机标识或凭据**的有限 JSON 审计报告，原始字节 SHA 可独立保存，0600/O_EXCL/fsync，不覆盖已有文件。第二审计者使用上面全部独立参数，再将子命令改为 `verify-report`，删除 `--out`，增加 `--audit-report-file /private/cas-audit-report.json` 和 `--expected-audit-report-sha256 REPORT_FULL_RAW_SHA`。此时程序重新完整验签原始分叉和 CAS 声明，要求报表**逐字段**等于重新生成内容，不是信任报表的真假布尔值。

统一操作控制台**只读**：

```bash
python3 scripts/ces_next.py audit-cas DeliveryAudit VerifySignedCasReceipt \
  --fork-case-file /private/fork-case.json \
  --expected-fork-case-sha256 CASE_FULL_RAW_SHA \
  --fork-evidence-file /private/fork-report.json \
  --expected-fork-evidence-sha256 FORK_FULL_RAW_SHA \
  --receipt-file /private/cas-receipt.json \
  --expected-receipt-sha256 RECEIPT_FULL_RAW_SHA \
  --cas-authority-id independent_cas_site \
  --cas-public-hex INDEPENDENT_CAS_PUB_HEX \
  --request-nonce-sha256 REQUEST_NONCE_SHA \
  --expected-parent-cas-revision 27 \
  --expected-parent-cas-head-sha256 EXTERNAL_PARENT_HEAD_SHA
```

它仅调用固定、隔离子进程的 `verify`，**没有** `--out`、`sign`、`issue`、`rotate`、`apply`、`commit`、`--private-key`、CAS socket/URL 或更改业务状态的通路。原 Router 74 条/11 HOST_REQUIRED 与 PowerShell V4.60/R150 原业务源均不改。

## 返回码与可证明边界

- `0`：真实原签名分叉证据重放及外部 CAS **机关声明的 committed 结果签名**通过；**外部提交、授权和持久化均未验证**。
- `2`：真实原签名分叉重放及外部 CAS **机关声明的 CAS 前置条件失败签名**通过；**不选赢家**。
- `3`：拒绝、权限或签章/信任 pin 不匹配；`4`：非法输入/结构；`5`：本地材料或处理不可用。任何拒绝都不产生正面提交宣称。

未来真实生产必须再做：独立真实 CAS/WORM 控制平面、真实授权/密钥生命周期、公钥吊销与证书治理、真实请求 nonce 全局唯一与重放保护、外部提交后新 head readback (包括真实存储版本/线性化 token)、旧原始证据持久保管、两站点并发/分裂恢复与人工联合验收。原 EC249 功能不完整、EC250 BLOCKED、B001 OPEN、global Quality PASS=false 仍保持。
