# EC362 — 独立离线发布副本与双来源签署保管声明协议

版本 **V6.72/R362/EC-362**。唯一父层为 EC361，`audit` 每次真实重放 EC361→EC360→…→EC337 的已提交原始签名、SHA、目录检查点、RFC6962 追加一致性及双观察者 gossip。**不接受传入 `parent_passed=true`、合成的 parent result 或缓存 JSON 来替代父级执行。** 本轮只读、离线，任何合法输出均为 `exit_code=2`，不含信任升级。

## 执行

在完整包根目录 `ces/` 的父级执行（下面父参数请按 EC361 协议补齐）：

```bash
python -I -B ces/scripts/ces_cas_directory_publication_custody.py \
  derive-directory-publication-custody-handoff [完整EC361 audit-directory-consistency父参数]

python -I -B ces/scripts/ces_cas_directory_publication_custody.py \
  audit-directory-publication-custody [完整EC361父参数] \
  --publication-copy-evaluation-utc 2026-10-26T09:00:00Z \
  --source-a-custody-public-key-file /ABS/source-a-key.bin \
  --expected-source-a-custody-public-key-sha256 <实际32byte公钥的整文件sha256> \
  --source-a-publication-manifest-file /ABS/source-a-signed.json \
  --expected-source-a-publication-manifest-sha256 <实际manifest整文件sha256> \
  --expected-source-a-checkpoint-copy-sha256 <a-checkpoint原字节sha256> \
  --expected-source-a-consistency-bundle-copy-sha256 <a-proof-bundle原字节sha256> \
  --expected-source-a-observer-a-receipt-copy-sha256 <a复制observer-a原字节sha256> \
  --expected-source-a-observer-b-receipt-copy-sha256 <a复制observer-b原字节sha256> \
  --minimum-source-a-publication-sequence 3 \
  [相同的source-b-* / expected-source-b-*与minimum-source-b-*参数]
```

固定统一入口：

```bash
python -I -B ces/scripts/ces_next.py audit-directory-publication-custody \
  DeliveryAudit AuditDirectoryPublicationCustody \
  [同一完整EC361父参数 + 本轮EC362参数]
```

**外部参数含义。** 每个源的公钥 path+SHA、签署 manifest path+SHA、四个不同角色复制原件 SHA、已独立保存的最小序列须由调用方在 manifest 外提供。允许缺少某一整套来源并得到 `unresolved/2`，但**不得因此得到本地双来源一致**；输入了路径却没有配对 SHA、无效字段或无效签名则拒绝。`--publication-copy-evaluation-utc` 为调用方时间声称，仅用于可见时窗异常检查。

## 签署 manifest 的唯一规范字节

每个来源提供一个独立绝对路径的 canonical ASCII JSON 文件，不超过 **12,000 bytes**。必须恰有以下字段（没有扩展或多义字段）：

```json
{
  "schema": "ces.ec362.signed_offline_directory_publication_copy.v1",
  "source_slot": "a",
  "claimed_source_id": "unverified_distribution_site_a",
  "custodian_public_key_original_sha256": "<真实来源公钥文件SHA256>",
  "directory_id": "<真正EC361已验目录ID>",
  "parent_ec361_canonical_result_sha256": "<本轮重新审计EC361结果canonical SHA>",
  "parent_ec360_canonical_result_sha256": "<EC361真实父EC360结果SHA>",
  "parent_directory_checkpoint_original_sha256": "<EC360目录原checkpoint整文件SHA>",
  "advertised_checkpoint_original_sha256": "<本源实际复制checkpoint整文件SHA>",
  "advertised_tree_size": 5,
  "advertised_root_sha256": "<本源实际复制checkpoint的root_SHA256>",
  "publication_sequence": 3,
  "issued_utc": "2026-10-26T08:00:00Z",
  "expires_utc": "2026-10-28T08:00:00Z",
  "copies": {
    "checkpoint": {"path": "/ABS/source-a/checkpoint.json", "sha256": "<原SHA>"},
    "consistency_bundle": {"path": "/ABS/source-a/consistency.json", "sha256": "<原SHA>"},
    "observer_a_receipt": {"path": "/ABS/source-a/observer-a.json", "sha256": "<原SHA>"},
    "observer_b_receipt": {"path": "/ABS/source-a/observer-b.json", "sha256": "<原SHA>"}
  },
  "signature_custodian_ed25519_hex": "<128个小写hex字符的真Ed25519签名>"
}
```

`source_slot` 只能 `a`/`b`。每源一份签署 manifest、一个 32 字节 caller-pinned Ed25519 公钥，双来源密钥必须不同，且不能复用上游任意已收集的签名角色。`publication_sequence` 是 `0..2147483647` 非布尔整数；来源自身 `issued_utc < expires_utc`，跨度不超过七天。真实签名严格覆盖除自身签名字段外的整个 canonical JSON：

```text
Ed25519.sign(
  b"CES/EC362/OfflineDirectoryPublicationCustody/v1\\x00" +
  canonical_json(manifest_without_signature)
)
```

上面显示 `\\x00` 是字节零的可读转义，不是反斜杠字符串。完整 canonical JSON 使用 `json.dumps(...,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)`，无重复键，所有文件都由绝对路径+真实整原 SHA 校验，复制原件大小遵循既有 EC360/361 上限。

## 本轮确实执行的核验

1. **逐次重放真实父级。** 调用 EC361 audit，不接受 `passed` 字段；本次 EC361 canonical result SHA、EC360 parent canonical result SHA、原父 checkpoint SHA、已验目录 ID 都必须与各来源真实签署字节完全相符。
2. **两份 manifest 分别由两把调用方独立 SHA pin 的 Ed25519 公钥验签。** 相同公钥字节/旧角色复用、错误签名与错误父 binding 拒绝；相同自称发布来源 ID 标记身份冲突而不建立独立法人事实。
3. **四角色 × 双来源逐原件核查。** 检查 A/B 各自提供的 checkpoint、EC361 完整 consistency proof bundle、两份 observer signed receipt 的真实字节 SHA；每一个 manifest 内 SHA 还必须与相应来源的**manifest 外单独保存**的 SHA 一致。全部四种复制品还必须和本次真实 EC361 原件的 SHA 一致，才可得局部副本相符。
4. **真正目录签名核验与可见冲突。** 逐来源使用 EC360/361 已单独 SHA pin 的目录公钥对复制 checkpoint **再验签**；核对复制原件整 SHA / 目录 ID / tree size / signed root / 身份。即使是有效的同 size 不同 root 签名，也不得让另一来源的一致副本隐藏它。可见更大/更小签署 checkpoint、与调用方保存的 head 不同原字节均不能得到本地一致，额外标注回退/当前 head 不可靠。复制版 RFC6962 proof 若与原件不同，不偷偷替代父 EC361 真 inclusion/consistency 重放。
5. **分源保留序列 floor 与独立身份。** 已签 `publication_sequence` 低于来源外部保留的 `minimum_source_{a,b}_publication_sequence` 标记回退。缺任意 floor、四角色 SHA 外 pin 或一整个来源仅 `unresolved`。签署 UTC 仅自我声称，不做可信时间升级。
6. **路径/角色隔离与末尾重读。** 严格读取绝对、规范、无链接祖先文件；独立复制材料不与父层/其他来源共用物理 inode，即使内容 SHA 一致；旧新材料最后再次读 SHA/inode 和 symlink 祖先。不创建签名私钥、不联网、不用 OS 根证书、无远端 Provider/CAS/WORM 写入。
7. **对不同原字节的观察回执**：若复制的 observer receipt 不等于 EC361 已验原件，必须验证其依旧是真正原观察者所签且引用已提供的签署 checkpoint；即使能验签，该副本也不能充当原件一致。

## 输出、拒绝与边界

正常审计返回 `ces.ec362.offline_directory_publication_custody_unresolved.v1`，`status` 为单一已观测结果的 `_unresolved` 后缀。核心布尔量包括 `both_distinct_custodian_signatures_verified_locally`、`each_four_original_copies_exactly_agree_with_parent`、`original_copies_or_caller_sha_pins_mismatch`、`independently_presented_signed_checkpoint_conflict`、`caller_publication_floor_or_newer_head_rollback`、`two_offline_signed_publication_copies_locally_coherent`。前者为本地签名证据，最后一个仅可在真父链一致、双来源各自签名/四角色 SHA 比对/floor、时间无异常且无已见冲突时为 true；但**即使 true 仍 `exit2 unresolved`**。无效/伪造材料按 `permission_denied / invalid_input / unavailable` 分别 `exit3 / exit4 / exit5`，统一子进程验证严格模式，不把下游虚假 `success` 升级为权限。

**未证明且持续不可宣称：** 官方目录/合法公示渠道、真实跨法人独立、不同物理机构或保管链、可信历史 UTC、全球最新完整公开日志/未展示分叉不存在、全面权威撤销；亦不能补救 EC317/318 深层 MOCK、旧 EC356 case24、PS7 与原 15 Smoke、E63–E66、Windows/macOS/Git/CI/Provider、CAS/WORM 远端执行与最终用户辅助验收。B001 / EC249 / EC250 / Quality / final 全部保持此前状态。
