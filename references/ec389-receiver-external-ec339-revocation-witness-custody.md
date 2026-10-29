# EC389 — 原 EC339 `revoked` 状态的签名发布见证与独立保管接收协议

**交付版本 V6.99/R389/EC389。** 完整输入必须包含已归档 EC388 的全部真正独立原件、EC387→EC369 的继承审计-only SHA/计数参数、本层新的接收 bundle 及原始外部 witness/custodian 证据。旧历史接收包一概不能用“验证 PASS”字段、扫描报告、发送端标签或新签发的历史 grant 代替。缺原件只能 unresolved，伪造授权不能通过。

## 只读命令

```sh
python -I -B scripts/ces_cas_historical_ec339_external_witness_archive.py derive-historical-ec339-external-witness-inventory --help
python -I -B scripts/ces_cas_historical_ec339_external_witness_archive.py audit-historical-ec339-external-witness-archive --help
python -I -B scripts/ces_next.py audit-historical-ec339-external-witness-archive DeliveryAudit AuditHistoricalEC339ExternalWitnessArchive --help
```

**EC389 新增 CLI 输入**（继承 EC388 及更早 `audit` 的全部参数；命令行均采用同名 kebab-case 形式）：

| 参数 | 用途 |
|---|---|
| `historical_ec339_external_witness_custody_archive_bundle_file` | 本轮完整接收 archive 的规范绝对路径 |
| `expected_historical_ec339_external_witness_custody_archive_bundle_sha256` | archive 整文件 SHA-256 |
| `expected_outside_retained_ec389_external_verifier_roster_sha256` | 外部事先留存的 verifier roster *整文件* SHA；必须与 bundle 指定的 roster 原件相同 |
| `historical_ec339_external_publication_inventory_shas` | 每 epoch 重复一次，接收方独立保留的发布原件摘要 |
| `historical_ec339_external_custody_inventory_shas` | 每 epoch 重复一次，独立保留的保管原件摘要 |
| `minimum_historical_ec339_external_witness_custody_pair_counts` | 每 epoch 重复一次，0–16 的已验签成对原件数量下限 |
| `expected_retained_historical_ec339_external_witness_custody_inventory_sha256` | 仅 audit 需要：整个派生**未签名**库存的外部预留 SHA |

下限与 SHA 列表必须逐 epoch 严格对应 `historical_directory_root_shas` 的真实 1–3 个元素。两通道需依原父 archive 的同序排布（升序、不重复）。缺少证据不填造 SHA；`derive` 暂不需要新 audit-only 全库存 SHA，但继承父 EC388 等级的原 audit-only 参数仍必须完整。所有合法结果均返回 `2/_unresolved`；结构错误 `4`、拒绝的签名或原件替代 `3`、环境不可用 `5`。

## 本层 archive 严格结构

以下示例仅展开一条记录，**不是**可直接执行的真实源，`<...>` 占位符须由外部原件与真实父结果替换。JSON 必须精确字段且以接收方代码规范的无额外空格 canonical JSON 存盘。

```json
{
  "schema": "ces.ec389.receiver_external_ec339_revocation_publication_archive.v1",
  "parent_ec388_canonical_result_sha256": "<本次真正执行 EC388 audit 的 canonical JSON SHA>",
  "ec388_historical_revocation_archive_original_sha256": "<旧 EC388 原 archive 整文件 SHA>",
  "claimed_directory_lineage_id": "<旧根正式 lineage ID>",
  "external_verifier_roster_original": {"path": "<绝对路径>", "sha256": "<整文件 SHA>"},
  "epochs": [
    {"epoch_index": 0, "channels": [
      {"tsa_channel_id": "<父 EC388 认证的 channel ID>",
       "external_revocation_publication_and_custody_originals": [
         {"signed_witness_original": {"path": "<见证签名原件绝对路径>", "sha256": "<原件 SHA>"},
          "signed_custody_original": {"path": "<保管签名原件绝对路径>", "sha256": "<原件 SHA>"}}
       ]}
    ]}
  ]
}
```

`external_revocation_publication_and_custody_originals` 可以为空（缺口 unresolved），每通道最多八对；只有旧 EC388 已认证为 `revoked` 的 `additional_challenged_status_originals` 可以被见证，没有可见 signed revoked 就绝不可凭本层签名制造。若后续 epoch 不修改已见证事实，签名原件的**原始路径、SHA、序号和先后顺序**必须按前缀完整继承；追加原件的 `first_published_epoch_index` 应等于新首次实际出现的 epoch。

### 未签名 external verifier roster 原件

根精确字段：`schema`、`claimed_directory_lineage_id`、`witnesses`、`custodians`；固定 `schema=ces.ec389.receiver_outside_retained_external_verifier_roster.v1`，与旧 EC388 lineage 相等。两份列表分别含 1–2 项；每项精确字段：

```json
{"signer_id": "ExternalWitness1", "public_hex": "<64 位小写 hex，32-byte Ed25519 公钥>",
 "public_key_original": {"path": "<独立真实 raw 公钥原件绝对路径>", "sha256": "<raw 32 字节 SHA>"}}
```

`signer_id` 为 `[A-Za-z][A-Za-z0-9_.:-]{0,95}`。每个 signer 的 ID、公钥、原始 raw key 文件路径互异，且与旧 EC338/339/340/341 已认证的 actor/issuer/successor/observer/signers 全部互异。该 roster **不是**由本层信任根签署的正式证书；只把其 SHA 与接收者外部输入对比。其可信来源、独立机构身份和先前保管时间必须由用户/第三方独立提供。

### witness signed original

外壳精确字段 `schema`、`claim`、`signature_ed25519`。外壳 schema = `ces.ec389.external_signed_revocation_publication_original.v1`；claim schema = `ces.ec389.external_revocation_publication_claim.v1`。Ed25519 签名覆盖**精确** `b'CES/EC389/ExternalOldEC339Revocation/Publication/v1\0' + canonical_json(claim)`，signature 为 128 位小写 hex。

`claim` 精确字段（无多余键）：

```json
{
  "schema": "ces.ec389.external_revocation_publication_claim.v1",
  "directory_lineage_id": "<EC388 真实 lineage>",
  "tsa_channel_id": "<真实 channel>",
  "first_published_epoch_index": 0,
  "role": "sender",
  "ec338_actor_receipt_original_sha256": "<EC388 已认证旧 receipt SHA>",
  "ec339_issuer_grant_original_sha256": "<EC388 已认证旧 grant SHA>",
  "ec339_signed_revoked_status_original_sha256": "<EC388 已验签的旧 revoked 原件 SHA>",
  "ec339_verifier_challenge_sha256": "<原 signed status 中的 challenge>",
  "ec339_signed_as_of_utc": "<原 signed status 的 as_of_utc>",
  "ec339_revoked_effective_utc": "<原 signed status 的 revoked_effective_utc>",
  "witness_id": "ExternalWitness1",
  "publication_sequence": 1,
  "previous_signed_witness_original_sha256": "<第一份为 64 个 0；后续为上份整件 SHA>",
  "claimed_published_utc": "2026-10-25T11:20:00Z"
}
```

`role` 严格为旧 EC340 的四角色之一；源 status 必须真实可见、`state=revoked` 且完整验签、原挑战、旧 grant/receipt、带 SHA 的原路径由 EC388 复核。首记录 `publication_sequence=1` 且 previous 全 0，此后每份严格 +1，不能复用旧 status 或 source SHA。

### custody signed original

外壳精确字段同上，外壳 schema = `ces.ec389.external_signed_revocation_custody_original.v1`；claim schema = `ces.ec389.external_revocation_custody_claim.v1`。独立 Ed25519 签名覆盖**另一个域** `b'CES/EC389/ExternalOldEC339Revocation/Custody/v1\0' + canonical_json(claim)`，要求公钥不复用见证者、公钥 raw 来源独立。

`claim` 精确字段：

```json
{
  "schema": "ces.ec389.external_revocation_custody_claim.v1",
  "directory_lineage_id": "<EC388 真实 lineage>",
  "tsa_channel_id": "<真实 channel>",
  "first_published_epoch_index": 0,
  "role": "sender",
  "ec339_signed_revoked_status_original_sha256": "<同条 witness 的 old revoked 原件 SHA>",
  "signed_witness_original_sha256": "<本条 witness 签名原件整件 SHA>",
  "custodian_id": "ExternalCustodian1",
  "custody_sequence": 1,
  "previous_signed_custody_original_sha256": "<第一份 64 个 0；后续上份 custody 原件 SHA>",
  "claimed_deposited_utc": "2026-10-25T11:25:00Z"
}
```

每条 witness/custody 属于同一 lineage、channel、role、status 和 first epoch，序号必须一致。若发布声明时间早于旧 EC339 signed `as_of`、保管声明时间早于发布声明或任意声称时间在序列中回退，输出**可见签署声明不一致**；不会拿当前操作系统时间替换旧声明或自行纠正顺序。缺 witnesses/custodies 仅暴露覆盖缺口；不替换原件。

## 收敛边界与延期人工检查

源 SHA/签名验签、双签署者分工、前序序号、retained SHA/下限和 late reread 只建立**当前可读文件**的一致性。即便所有局部源一致，也固定 unresolved；外部机构真实注册证明、不可抵赖的原始已保留 hash、公钥预注册、真实独立时钟或已收据签名的物理保管、完整全球撤销、发现未见分叉及 EC388→EC369 完整生产祖先，均不由本工具自动证明。不得将签名 witness/custody 当成旧 EC339 issuer 当前授权。

本地聚焦 **40/40**（六个外层 receiver audit 用例 MOCKED EC388→EC369，准备 fixture 中 EC387 parent MOCKED，继承老 EC317/318 MOCKED）；PS7/原始 15 Smoke、Windows/macOS、Git/CI/Provider、真实第三方手递原件和用户终验均保留待统一验证，原 R150 PowerShell 不改。
