# EC363 协议：离线签署来源历史、独立挑战与实际副本披露

**施工版 V6.73 / R363 / EC363。** 本协议是在 EC362 双来源离线发布原件基础上，新增有限时间窗口内的 **source publication history** 和 **真正 Ed25519 签署的离线 copy challenge / disclosure**。父级 `audit` 每一次都执行 EC362→EC361→…→EC337 的完整已提交签名原件验证，不接受传入“parent passed”文件代替。所有合法结果一律 `unresolved / exit 2`，拒绝为 exit 3/4/5；没有任何在线获取、生成私钥/签名或 Provider/CAS/WORM 写入。

## 使用入口

在解压的 `ces/` 上级目录：

```bash
python -I -B ces/scripts/ces_cas_publication_history.py \
  derive-publication-history-handoff [完整 EC362 audit-directory-publication-custody 参数]

python -I -B ces/scripts/ces_cas_publication_history.py \
  audit-publication-history [完整 EC362 参数] \
  --history-evaluation-utc 2026-10-26T12:00:00Z \
  --source-a-history-bundle-file /abs/a/history.json \
  --expected-source-a-history-bundle-sha256 <实际完整文件SHA256> \
  --source-a-challenger-public-key-file /abs/a/challenger.bin \
  --expected-source-a-challenger-public-key-sha256 <实际32字节公钥文件SHA256> \
  --minimum-source-a-retained-publication-sequence 2 \
  --expected-source-a-retained-manifest-sha256 <独立保存的历史/当前真签manifest SHA256> \
  --minimum-source-a-retained-directory-tree-size 5 \
  --source-a-historical-manifest-sha256 <逐条重复：历史manifest原件SHA，顺序同bundle> \
  --source-a-challenge-sha256 <逐条重复：请求原件SHA，顺序同bundle> \
  --source-a-response-sha256 <逐条重复：响应原件SHA，顺序同bundle> \
  [同样的 --source-b-* 参数]
```

受限、固定统一入口：

```bash
python -I -B ces/scripts/ces_next.py audit-publication-history \
  DeliveryAudit AuditPublicationHistory [完全相同的完整父参数和 EC363 参数]
```

`source_{a,b}_history_bundle_file` 和 `challenger_public_key_file` 均必须与其单独在 bundle 外保存的 `expected_*_sha256` 配对。三个 `--source-{a,b}-*-sha256` 为有序多次重复参数；**每份历史 manifest、每份签署请求、每份签署响应的 whole-file SHA 须在 bundle 外逐份提供**。某一来源、floor 或 SHA 缺失时只能标记不完整，永远不产生本地完整历史。外部 SHA 与 bundle 引用不符时显式标记 mismatch，即便签名有效。所有源内部身份为自称，外部密钥来源与实体资质未证明。

## 有限数量和字节

每来源最多 **4 份独立历史 manifest**（不含必需且已由 EC362 验真的当前 manifest）、**16 个独立签署请求**、**16 个独立签署响应**；bundle ≤48,000 bytes，请求 ≤8,000，响应 ≤10,000。历史 manifest 仍使用 EC362 最大 12,000 bytes，原副本上限仍使用 EC360/361 已定义的 checkpoint/observer/consistency 限制，单个源最多 4×4 份历史副本。两来源最多各一份新 challenger 32-byte Ed25519 公钥，且两把不同，不复用已识别的旧签名角色。凡新引入的文件仍必须采用绝对/规范路径、相互不同的文件角色和 inode，拒绝符号链接及其父目录，SHA、inode、链接最后重读检查（不保证同一事务快照）。

## 历史 bundle（唯一精确字段）

Bundle **本身不签名**，而由调用方在 bundle 外的 whole-file SHA 固定。它列出其他文件的 path+whole SHA，不能代替每份真实签名验证：

```json
{
  "schema": "ces.ec363.pinned_signed_source_history_bundle.v1",
  "source_slot": "a",
  "parent_ec362_canonical_result_sha256": "<本次真正重新执行EC362得到的canonical结果SHA>",
  "custodian_public_key_original_sha256": "<EC362已验本源key SHA>",
  "challenger_public_key_original_sha256": "<本源独立challenger key SHA>",
  "historical_manifest_originals": [
    {"path": "/abs/a/old-2.json", "sha256": "<整原SHA>"}
  ],
  "signed_challenge_originals": [
    {"path": "/abs/a/request-1.json", "sha256": "<整原SHA>"}
  ],
  "signed_disclosure_response_originals": [
    {"path": "/abs/a/response-1.json", "sha256": "<整原SHA>"}
  ]
}
```

每份 `historical_manifest_originals` 必须是真实 EC362 格式、由当前对应来源 custodial key 对 `CES/EC362/OfflineDirectoryPublicationCustody/v1\0 || canonical_json(除签名外字段)` 完整签署的原件；签名字段仍为 `signature_custodian_ed25519_hex`。历史必须绑定同一本次真实 EC361/EC360 结果 SHA、真实 EC360 目录锚 SHA、源身份、目录 ID 与实际 custody key。**本 EC 只认同一已重放 EC361 父快照内的有限历史**，不同父快照/密钥轮换的跨纪元长期历史不在此轮能力中。历史原件的四种 `copies` 中的 SHA 是已签广告，**不是物理文件现存、真正目录签名或真 append-only 的证明**。

`publication_sequence` 的实际源历史（包括 EC362 当前 manifest）由审计端按整数排列；同一序列两个不相同 whole-SHA 的来源真签 manifest 必须标为 signed equivocation，不从中选 winner；已展示比当前更大的序列/树大小、外部独立保存的最低序列或目录树大小不满足、独立保存的 manifest head SHA 没出现或反向，都标记回退。显示窗口内部跳号或无任何历史材料只标记不完整，不因此推断未知全世界历史是否存在。

## 请求的完整签名结构

签署挑战每次须绑定真实 EC362 canonical result（非源自称结果）、EC361 canonical SHA、旧原 manifest 原 SHA 与序列、其四角色中具体一个角色的已签 copy SHA；nonce 是独立、非零、小写 64 字节位数的 hex（32 原始字节）。

```json
{
  "schema": "ces.ec363.signed_historical_copy_challenge.v1",
  "source_slot": "a",
  "claimed_source_id": "unverified_distribution_site_a",
  "challenger_public_key_original_sha256": "<本源challenger公钥整原SHA>",
  "custodian_public_key_original_sha256": "<EC362来源公钥整原SHA>",
  "parent_ec362_canonical_result_sha256": "<真实EC362 result SHA>",
  "parent_ec361_canonical_result_sha256": "<真实EC361 result SHA>",
  "target_manifest_original_sha256": "<历史真签manifest整原SHA>",
  "target_publication_sequence": 2,
  "requested_copy_role": "checkpoint",
  "requested_copy_sha256": "<旧manifest所签checkpoint副本SHA>",
  "nonce_hex": "<64小写十六进制字符且非全0>",
  "issued_utc": "2026-10-26T09:00:00Z",
  "expires_utc": "2026-10-27T09:00:00Z",
  "signature_challenger_ed25519_hex": "<128小写十六进制Ed25519签名>"
}
```

签名消息是 `b"CES/EC363/HistoricalCopyChallenge/v1\x00" + canonical_json(去掉自身签名字段的对象)`。请求有效期自称不超过3天；被挑战的旧 manifest 必须在本次 bundle 中，并已经真正用 EC362 来源 key 验签。nonce 同场重复、同一历史 manifest 同一 copy role 被重复挑战不允许产生唯一覆盖结论；来源和挑战者签名角色必须分离。

## 响应的完整签名结构

```json
{
  "schema": "ces.ec363.signed_historical_copy_disclosure.v1",
  "source_slot": "a",
  "claimed_source_id": "unverified_distribution_site_a",
  "custodian_public_key_original_sha256": "<EC362来源custodian key SHA>",
  "parent_ec362_canonical_result_sha256": "<真实EC362 result SHA>",
  "challenge_original_sha256": "<请求whole SHA>",
  "target_manifest_original_sha256": "<与请求精确相同的历史manifest whole SHA>",
  "requested_copy_role": "checkpoint",
  "requested_copy_sha256": "<与挑战精确相同的旧copy SHA>",
  "response_kind": "disclosed",
  "disclosed_copy": {"path": "/abs/a/copy-disclosed.json", "sha256": "<实际披露原字节的SHA>"},
  "responded_utc": "2026-10-26T09:10:00Z",
  "expires_utc": "2026-10-27T09:10:00Z",
  "signature_custodian_ed25519_hex": "<128小写十六进制Ed25519签名>"
}
```

来源使用已由 EC362 真验签的 custody key 签署 `b"CES/EC363/HistoricalCopyDisclosure/v1\x00" + canonical_json(除签名字段以外的对象)`。`response_kind` 恰有：`disclosed`、`unavailable`、`withdrawn`。后二者必须使 `disclosed_copy=null`，属于有效签署的**未交付或追溯性撤回声明**，不是副本已删除、历史撤销或义务消失的证明。未回应、同一挑战有两份不同来源真签回应，都不能自动选胜出者；请求/响应未提供、签名无效或引用不是本次请求均有明确拒绝/未决分类。

`disclosed` 必须真正重新打开 `disclosed_copy` 文件，验证该文件的 SHA 与响应自带的 SHA，以及历史已签广告和挑战的目标 SHA 一致。不一致只能 unresolved mismatch。按角色进一步核验：

- `checkpoint`：**另行使用 EC360 已验且 caller-SHA-pinned 的目录公钥验证其 Ed25519 真签**，重比旧 manifest 的 directory ID/tree size/root/head 全字节 SHA；真实已见同尺寸不同 root 才能标记 directory-signed fork。
- `observer_a_receipt` / `observer_b_receipt`：完整 canonical 结构，原 EC361 已验 observer 公钥真验签、目录签署角色 SHA、EC360 parent result/anchor 与旧 manifest 的准确 head/root/size 全部逐一核对。不能把一份有签名但指向其它 head 的回执计入目标披露。
- `consistency_bundle`：比对整个旧广告 byte-SHA，检查 EC361 bundle canonical schema；它不替代父层真正计算过的 RFC6962 append-only/inclusion 验证，也**不能把历史不同树的 proof 直接标作通过**。

## 结果分类、成功边界、尚未证明

`audit-publication-history` 的输出 schema 是 `ces.ec363.offline_signed_publication_history_unresolved.v1`，固定结果字段包含 `parent_ec362_canonical_result_sha256`、两源 `source_history_reviews`、序列/保留head检查、实际签署双版本/请求冲突、缺失/不可用/撤回、真实披露的 `SHA`/目录签名重新核验、可信时间无法证实的提示，以及完整 `outcome_counts`。正常分支 `exit_code` 固定2；同一 request 真签双响应为 equivocation，不挑一个“可用”；各来源只有每份历史的 **四种 role 全部按签署请求被实际披露并复核**、外部 pins 与 floor 全、父 EC362 局部一致且无其它可见问题，才有 `bounded_signed_history_and_disclosures_locally_coherent=true`。即使为 true，仍然 `exit2 unresolved`，只能说明**有限本地输入窗口内的一致性**。

本轮不建公共发布服务、不下载 URL、不发挑战请求到网络、不生成密钥或签名、不写外部目录、Provider 或远端 CAS/WORM。caller-pinned key 和本地合成签名不能证明外部真实站点、法律上的组织独立性、物理 custody、历史可信 UTC、全网最新 directory、隐匿签署分叉不存在、全面撤销。EC356 历史 case24、EC317/318 深层 MOCK、PowerShell7 原 15 Smoke/OS/Git/CI/Provider/E63–E66/remote CAS/WORM 以及用户辅助最终验收全部持续待验；EC249 INCOMPLETE / EC250 BLOCKED / B001 OPEN / Quality=false / final NOT_STARTED 原样保留。
