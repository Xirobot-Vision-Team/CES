# EC390 — 外部独立归档头及双角色签名接收回执：真实原件协议

**V7.00 / R390 / EC390；仅本轮新施工。** 这是接收端只读验证协议，不是发证、签发、官方审计通过或可信时间服务。任何新 Head 或 Receipt 都不能替代 EC389→EC369 完整、真实、未修改的父审计。父结果的 `exit_code=2` 是未决，不是 PASS；父审计必须先实际运行，外部提供的“父 PASS”或报告 SHA 不能代跑。

## 启动与继承参数

```sh
python -I -B scripts/ces_cas_historical_independent_archive_heads.py derive-historical-ec339-independent-archive-inventory --help
python -I -B scripts/ces_cas_historical_independent_archive_heads.py audit-historical-ec339-independent-archive-heads --help
python -I -B scripts/ces_next.py audit-historical-ec339-independent-archive-heads DeliveryAudit AuditHistoricalEC339IndependentArchiveHeads --help
```

**完整提供 EC389 `audit-historical-ec339-external-witness-archive` 的每个必填标量、每个历史 repeat 和所有 inherited audit-only pins**，再增加本层以下参数；命令行单词由 `snake_case` 换为 kebab-case。保持原 `expected_source_attestation_head_shas` 中字面 `none` 的既存约定。

| 新 EC390 输入（Python 名） | 解释 |
|---|---|
| `historical_ec339_independent_archive_heads_bundle_file` | 新接收包，规范绝对路径（不允许以相对路径/发送端 label 代替） |
| `expected_historical_ec339_independent_archive_heads_bundle_sha256` | 该包原始文件 SHA-256 |
| `expected_outside_retained_ec390_independent_archive_roster_sha256` | **调用方须事前独立保留**的档案签署者名册原件 SHA；不得用包内 SHA 自证 |
| `historical_ec339_independent_signed_head_inventory_shas` | 按每 epoch 逐项提交的外部预留 *已签 Head 清单* 派生 SHA；flag `--historical-ec339-independent-signed-head-inventory-sha256` |
| `historical_ec339_independent_signed_receipt_inventory_shas` | 每 epoch 外部预留 *已签 Receipt 清单* 派生 SHA；flag `--historical-ec339-independent-signed-receipt-inventory-sha256` |
| `minimum_historical_ec339_independent_signed_checkpoint_counts` | 每 epoch 真实双签名 head+receipt 配对最低数，整数 `0..2`；flag `--minimum-historical-ec339-independent-signed-checkpoint-count` |
| `expected_retained_historical_ec339_independent_archive_inventory_sha256` | **只用于 audit**，对整份未签名派生库存的外部事先 SHA 钉住 |

1–3 epoch，每 epoch 必须与真正 EC389 认证的 1–2 channel 严格同序；每 channel 最多 8 份原 EC389 已签撤销 witness/custody 对。本层每 channel 每 epoch **最多一份独立已签归档 Head** 和 **最多一份不同密钥签署的 Receipt**。允许两个字段同时 `null`（作为**证据缺失未决**），也允许 Head 有而 Receipt `null`（保管缺口）。**禁止只有 Receipt**。不接受自行填写的新 EC389 对、额外 epoch/channel 或伪造旧原件。

## 原件线格式

所有 JSON 在磁盘上必须恰好为 `canonical_json(doc)`：UTF-8、无重复键、无多余空格/尾换行；签名是 128 个小写 hex；全部 SHA 原件引用均为精确 `{"path":"<绝对真实路径>","sha256":"<64位小写 SHA>"}`。示意中的 `<...>` 不是可用输入。

接收包精确字段如下：

```json
{
  "schema": "ces.ec390.receiver_independent_ec339_revocation_archive_heads_bundle.v1",
  "parent_ec389_canonical_result_sha256": "<真实重新执行 EC389.audit 输出 canonical JSON 的 SHA>",
  "ec389_external_witness_archive_original_sha256": "<旧 EC389 archive 原始 SHA>",
  "claimed_directory_lineage_id": "<由旧原件锁定的真实 lineage>",
  "independent_archive_roster_original": {"path": "<外部名册原件>", "sha256": "<原件 SHA>"},
  "epochs": [{"epoch_index":0,"channels":[{
    "tsa_channel_id": "<认证过的父通道>",
    "signed_archive_head_original": {"path": "<独立 Head 原件>", "sha256": "<整件 SHA>"},
    "signed_head_receipt_original": {"path": "<另一个签署者 Receipt 原件>", "sha256": "<整件 SHA>"}
  }]}]
}
```

外部名册精确字段：`schema`、`claimed_directory_lineage_id`、`archivists`、`receipt_attestors`。`schema=ces.ec390.outside_retained_independent_archive_receiver_roster.v1`。两组各 1–2 人。每项 `{"signer_id":"Archivist1","public_hex":"<32字节公钥的小写hex>","public_key_original":{"path":"<独立raw文件>","sha256":"<raw SHA>"}}`；必须是真实 32-byte raw Ed25519 公钥，原件与登记 hex 一致。ID、公钥及 raw 文件路径均不重复，且与旧 EC338/339/340/341 已验证的 actor/issuer/rotation/root 角色，以及 EC389 witness/custodian 角色的公钥不复用。**“不同密钥”只证明密钥不相同，不是“法律上不同机构”的证明。**

### 1. 独立 archivist 签署整份 source snapshot

`SignedOriginal` 精确字段 `schema`、`claim`、`signature_ed25519`。外壳 schema 为 `ces.ec390.independent_signed_revocation_archive_head_original.v1`，claim schema 为 `ces.ec390.independent_revocation_archive_head_claim.v1`。签名原文为：

```text
b'CES/EC390/IndependentOldEC339Revocation/ArchiveHead/v1\0' + canonical_json(claim)
```

claim 精确字段：

```json
{
  "schema": "ces.ec390.independent_revocation_archive_head_claim.v1",
  "directory_lineage_id": "<经真实 EC389 父审计认证的 lineage>",
  "tsa_channel_id": "<认证原通道>",
  "epoch_index": 0,
  "parent_ec389_canonical_result_sha256": "<本次实际执行 EC389.audit 的 canonical 输出 SHA>",
  "ec389_external_witness_archive_original_sha256": "<旧 EC389 整件 SHA>",
  "ec389_parent_derived_inventory_sha256": "<EC389.audit 真实返回的库存 SHA>",
  "archivist_id": "Archivist1",
  "checkpoint_sequence": 1,
  "previous_signed_archive_head_original_sha256": "<第1份为64个0；后续为前一epoch同通道整件 Head SHA>",
  "ec389_signed_source_pairs": [{
    "ec339_revoked_status_original_sha256": "<EC389证实的旧EC339签名revoked SHA>",
    "ec389_signed_witness_original_sha256": "<对应 EC389 原见证签名整件 SHA>",
    "ec389_signed_custody_original_sha256": "<对应 EC389 保管签名整件 SHA>"
  }],
  "claimed_archived_utc": "2026-10-25T11:30:00Z"
}
```

`ec389_signed_source_pairs` 是完整有序原件列表而非一个可不透明覆盖的自报“Merkle root”。接收端重新打开 EC389 两种签名，重新核对旧 status/channel/sequence/prev SHA，再将每条三元组与 Head **逐件逐位置比对**。签名有效但列出不同 SHA、缺记录或顺序回退 → **保留该已签名 Head 和 adverse/unresolved**，绝不自行选择真史；伪造父审计/lineage/channel、伪造签名或非法字段 → **拒绝 3/4**。每 epoch 的 `checkpoint_sequence` 必须等于 `epoch_index+1`，跨 epoch 的 `previous_signed_archive_head_original_sha256` 必须等于前一实际可见原件 SHA；缺失或断链被报告为 adverse。

### 2. 独立 receipt attestor 签署接收 Head

另一个 signer 使用独立签名域和不同原始公钥：

```text
b'CES/EC390/IndependentOldEC339Revocation/HeadReceipt/v1\0' + canonical_json(claim)
```

外壳 schema=`ces.ec390.independent_signed_archive_head_receipt_original.v1`，claim schema=`ces.ec390.independent_archive_head_receipt_claim.v1`，claim 的精确字段：

```json
{
  "schema": "ces.ec390.independent_archive_head_receipt_claim.v1",
  "directory_lineage_id": "<认证 lineage>",
  "tsa_channel_id": "<同一认证 channel>",
  "epoch_index": 0,
  "signed_archive_head_original_sha256": "<刚核验的 Head 整件 SHA>",
  "ec389_signed_source_pairs_sha256": "<canonical_json(Head中有序 pairs 列表) 的 SHA>",
  "receipt_attestor_id": "ReceiptAttestor1",
  "receipt_sequence": 1,
  "previous_signed_receipt_original_sha256": "<第一份64个0；后续同通道前一已签Receipt原件SHA>",
  "claimed_received_utc": "2026-10-25T11:35:00Z"
}
```

此回执认证签署者当时**声称**接收指定 Head，不证明现实法律受托、跨地域持有、物理介质交接或 WORM。若 Head 的 `claimed_archived_utc` 早于 EC389 source 中已签 custody 的**声称**时间，Receipt 的 `claimed_received_utc` 早于 Head 的声称时间，或同通道后续声称 UTC 逆行，单独标出时序争议。未接入独立计时机关/RFC3161 信任链；**签名 UTC 不是可信 UTC。**

### 3. 保留清单与输出

每 epoch 生成两份规范 JSON 哈希：

- `head_inventory_sha256` 对当 epoch 所有 channel 的有序 `[{"tsa_channel_id": ..., "signed_head_sha256": <sha/null>, "signed_source_snapshot_sha256": <sha/null>}]` 作 canonical SHA。
- `receipt_inventory_sha256` 对有序 `[{"tsa_channel_id": ..., "signed_receipt_sha256": <sha/null>, "signed_head_sha256": <sha/null>}]` 作 canonical SHA。

对比调用方外部预留的每 epoch 两种 SHA 和至少签署配对数量。整份派生库存 SHA 在 `derive` 返回，需要另行离线保留；`audit` 校验其事前提供 SHA 后**不回显库存原始结构**。没有任何成功状态，所有有效/争议/缺失证据都是 `2` 且状态以 `_unresolved` 结尾。`permission_denied=3`、`invalid_input=4`、`unavailable=5`，未提供私钥签发 API、网络抓取、写入、Provider、CAS/WORM、PowerShell/Git/CI 操作。

## 重要实施边界

此协议的 Head 同时绑定**本次已形成的 EC389 receiver 报告与 bundle SHA**，故它适合接受**对既有来源作出的回顾性外部签署**，并不能凭当前代码证明“这份 Head 在早于 EC389 完整归档时就已真实存在”。独立预留 SHA 和另一个公钥也可能由同一操作者同时制造；真实第三方签名历史、链外事前保留时间、机构/职业资格、公钥预注册、物理存入、可信 UTC、完整 CRL/OCSP、隐藏 fork 及深祖先生产源均必须由用户最后独立核验。尤其不得以本轮签名或冲突判定替换旧 EC339 授权、撤销条款或 EC340 退役事实。

本轮聚焦本地真实 Ed25519 签名，不是实际第三方交付；父 EC389→EC369 在外层测试 **MOCKED**，其 EC388→EC369、EC317/318 深 fixture 也 **MOCKED**；本代码生产路径**不会** mock 父审计。最终 PS7/15 原 Smoke、OS/Git/CI/Provider/E63–E66 与用户联合验收保留 `NOT_RUN / NOT_PROVEN`。
