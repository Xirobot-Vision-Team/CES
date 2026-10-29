# EC357 — 双来源 SHA-pinned 机构 root 撤销/轮换与原件 inventory 审查（离线只读）

## 可验证边界

EC357 在**每次执行**中真调用 EC356 → EC355 → EC337 的原始签名、checkpoint + witness 字节审计，绝不以已生成的父审计 JSON、字符串身份、人工记载的路径名代替父证明。若 EC356 双根跨角色真原件前提不成立，EC357 不允许任何新来源证据修复它。所有合法结果 `exit_code=2`、`status=*unresolved`，即使本地两份 reviewer 签名和库存字节全部一致也**不是最终真实身份/物理托管通过**。

新增双来源独立 `Ed25519` 原始公钥：每个 reviewer 公钥由调用方在来源 bundle **之外**单独以整文件 SHA-256 固定。bundle 持有真实 review 签名原件及相应库存原件路径，逐个完整重开；reviewer 公钥不得与 EC356 根、渠道、EC353 log/witness 和 EC354 auditor 的签名角色复用，也不得与另一 reviewer 复用。这只证明**掌握相应私钥的人签署了声明**。两个不同密钥、`source_id`、法律实体名、站点标识、本机新路径不证明独立第三方机构；必须有真实权威的线下/独立链路校验 reviewer SHA pins，不能从 bundle 自我声明推导权威。

## CLI

必须已备齐 EC356 所需**所有原件、整文件 SHA、旧评估 UTC、双根单独 SHA pins**；请使用 `--help` 列出沿用的固定参数，旧字段完全未改。`derive` 仅接受父 EC356 参数并生成待提交的原件/receipt 对照，不创建密钥/签名/新文件：

```bash
python -I -B scripts/ces_cas_institution_provenance.py \
  derive-provenance-review-handoff <全部 EC356 的 audit-two-channel-custody flags>

python -I -B scripts/ces_cas_institution_provenance.py \
  audit-institution-provenance <全部 EC356 的 audit-two-channel-custody flags> \
  --provenance-review-evaluation-utc 2026-10-26T04:00:00Z \
  --provenance-review-bundle-file /review/reviews.json \
  --expected-provenance-review-bundle-sha256 <review-bundle 整文件 SHA-256> \
  --source-a-authority-public-key-file /independent-pin/source-a.pub \
  --expected-source-a-authority-public-key-sha256 <reviewer-A 原始公钥整文件 SHA> \
  --source-b-authority-public-key-file /independent-pin/source-b.pub \
  --expected-source-b-authority-public-key-sha256 <reviewer-B 原始公钥整文件 SHA>

# 固定、隔离、只读统一入口，参数保持一样：
python -B scripts/ces_next.py audit-institution-provenance \
  DeliveryAudit AuditInstitutionProvenance <全部 audit-institution-provenance flags>
```

`--provenance-review-evaluation-utc` 是 **caller 自报**，不能代替可信 UTC。audit 允许整组来源 bundle 或某一来源缺失：缺失组合返回 2/unresolved，不能自动通过。任何一组 `*_file` 与 `*_sha256` 如果只传一个则拒绝；供给的文件如果整原 SHA 不一致、签名错误、格式超界则拒绝（`3 permission_denied / 4 invalid_input / 5 unavailable`）。输入绝不从 URL 拉取或探测系统根信任库。直接 CLI 与统一路由均不执行签名器/私钥操作。

## Bundle 原始 JSON：schema 和严格字段

`ces.ec357.pinned_source_review_bundle.v1`；严格 canonical JSON、无重复键，≤36,000 字节，最多两个不同 `slot`，单 reviewer 签名原件≤48,000 字节、最多 2 个 root records 和 48 个 inventory records。

```json
{
  "schema":"ces.ec357.pinned_source_review_bundle.v1",
  "sources":[
    {
      "slot":"a",
      "source_authority_public_key":{"path":"/independent-pin/source-a.pub","sha256":"<整文件SHA>"},
      "signed_source_review":{"path":"/review/a-original.json","sha256":"<整文件SHA>"},
      "inventory_copies":[
        {"slot":"a","ec355_receipt_original_sha256":"<原 EC355 签名回执原SHA>",
         "checkpoint_original":{"path":"/review-a/checkpoint-copy.bin","sha256":"<原 checkpoint 整 SHA>"},
         "witness_original":{"path":"/review-a/witness-copy.bin","sha256":"<原 witness 整 SHA>"}}
      ]
    }
  ]
}
```

`source_authority_public_key` 的 path+SHA 必须**逐字等于**单独从 CLI 传入的对应 slot Pin；不是 bundle 自签公钥授权。`inventory_copies` 的 `(slot, ec355_receipt_original_sha256)` 必须在本 source 的真签声明中有相应 `availability=present` 条目；不能重复。原件路径必须绝对、非 symlink 及非硬链接别名、不能指向 EC356/EC355/EC354/更老嵌套父原件，且不同 reviewer 的新 copy 不能共用同 inode。审计完成前迟到重新打开每个父 EC356 与新来源 pinned 原件，重新做 inode 与 symlink 边界检查；并不声称文件系统的原子快照。

## 签名原件：`source_signed_root_and_custody_inventory.v1`

域隔离的**实际验签**消息：

`b'CES/EC357/ImportedRootCustodyReview/v1\x00' + canonical_json(body_without_signature_ed25519_hex)`

公开字段精确如下（此例仅字段形状，不是可上传的真实证明）：

```json
{
  "schema":"ces.ec357.source_signed_root_and_custody_inventory.v1",
  "source_id":"external_review_a",
  "source_authority_public_key_original_sha256":"<source-a 32 字节公钥原件的 SHA>",
  "ec356_custody_bundle_original_sha256":"<真实重放的 EC356 bundle SHA>",
  "parent_ec356_canonical_result_sha256":"<本次真正重放的 EC356 canonical result SHA>",
  "issued_utc":"2026-10-26T03:05:00Z",
  "expires_utc":"2026-10-28T03:05:00Z",
  "root_records":[
    {"slot":"a","institution_id":"institution_a",
     "claimed_legal_entity_id":"legal_a",
     "root_public_key_original_sha256":"<EC356 a root SHA>",
     "root_state":"active","replacement_root_public_key_sha256":null,
     "root_state_effective_utc":null,"declared_physical_site_id":"site_a"},
    {"slot":"b","institution_id":"institution_b",
     "claimed_legal_entity_id":"legal_b",
     "root_public_key_original_sha256":"<EC356 b root SHA>",
     "root_state":"revoked","replacement_root_public_key_sha256":null,
     "root_state_effective_utc":"2026-10-26T03:00:00Z",
     "declared_physical_site_id":"site_b"}
  ],
  "inventory_records":[
    {"slot":"a","ec355_receipt_original_sha256":"<父真签 receipt 原 SHA>",
     "checkpoint_original_sha256":"<checkpoint 原 SHA>",
     "checkpoint_length":1234,"witness_original_sha256":"<witness 原 SHA>",
     "witness_length":456,"declared_site_id":"site_a",
     "availability":"present"}
  ],
  "signature_ed25519_hex":"<128 个小写 hex 的真实 source 签名>"
}
```

`root_state` 为 `active | revoked | rotated`。active 必须没有替代根 SHA、没有切换 UTC；revoked 必须包含自报撤销 UTC 且没有替代根；rotated 必须包含新根 SHA（不同于旧根）和切换 UTC。撤销与轮换均显式上报为未决风险，**不会自动推断权威签发者、真实撤销事实或通过其他 source 的 active 声明覆盖**。

每 source review 必须绑定真正重放的 EC356 canonical result SHA、旧 custody bundle 整原 SHA、审查公钥 SHA、已签的两个根/机构/法律实体/场地条目以及真实 receipt SHA 的 checkpoint/witness 两个原件整 SHA 与字节长度。没有库存、`availability=unavailable`、只有 SHA、声称但未交出新 copy **不**形成 inventory bytes quorum。签名完整但字节与父 EC356 真签 receipt 不一致，是显式 inventory conflict；供给的实际原件不等于自己的 signed inventory SHA/长度则直接拒绝。

## 冲突分类与状态

| 结果后缀（全部再带 `_unresolved`） | 判定 |
|---|---|
| `parent_ec356_cross_role_original_custody_unresolved` | 父跨角色原件签收/追加证据不足 |
| `two_caller_pinned_source_reviews_missing` | 没有双份独立来源签名 |
| `signed_root_revocation_or_rotation_visible` | 任一真签来源报告根撤销/轮换 |
| `signed_institution_root_site_or_source_identity_conflicts_visible` | 不同来源签名的根 SHA、法人 ID、站点或来源角色与父级/相互冲突 |
| `signed_custody_inventory_conflicts_with_verified_originals` | 两来源库存互相冲突或与真实父 receipt 原件不相符 |
| `signed_original_inventory_or_copied_bytes_incomplete` | 未覆盖全部 EC356 eligible receipt 或未呈交完整新原件 |
| `stale_or_future_self_reported_source_reviews_visible` | 自报签发时序不成立、过期或超 30 日 |
| `two_signed_source_reviews_locally_consistent_external_authentication_unproven` | **仅本地签名+原字节对应一致**，外部权威仍未证明 |

结果同时保留 `signed_revocation_or_rotation_visible`、`signed_root_identity_or_source_collision_visible`、`signed_inventory_conflicts_with_ec356_or_other_source_visible`、`missing_source_root_record_or_original_copy_visible`、`stale_or_future_self_claimed_source_utc_visible`、`source_establishments`、`inventory_evidence` 和 `parent_ec356_canonical_result_sha256`。即使某项被更高优先级结果覆盖，也不静默删除其他负面证据。

## 本轮与最终验证的明确分界

本轮 26 个不同本地合成 case 已在分段运行中观察到 PASS；再次尝试单次完整命令，前 22 个通过，测试 #23 执行期间环境超时，没有产生全套连续完成记录；#23–26 分段运行曾通过。父 EC356 的历史 case #24 **独立仍未验证**，本轮 EC357 的 #24 是另一项不同测试。合成 Ed25519 等测试密钥均由同一台设备生成，不具外部官方/法人认证意义，EC317/318 老深层 fixture 仍 MOCK。原生 PS7/15 Smoke、Windows/macOS/Git/CI/Provider/E63–E66、真实机构/两地 custody、可信 UTC、全局 fork 完整性、远端 Provider/CAS/WORM 与最终人工验收继续 NOT_RUN/NOT_PROVEN。所有新功能只读、无 signer、网络、文件生成或远端 writer。
