# EC360 — 链外锚声称、离线授权边界、签署撤销快照和目录包含性协议

> V6.70 / R360 / EC-360；在 V6.69/R359/EC359 的**真实父签名链**之上施工，仍非法律/官方认证。本协议只读、不联网、不生成密钥/签名、不写远程 Provider/CAS/WORM。

## 1. 能验证什么，不能验证什么

每次 `audit-authority-directory` 首先重新运行 EC359→EC358→…→EC337 的真实原始签名和 whole-file SHA 验证，产生**本次** EC359 canonical result SHA。调用方另行保存的 root/witness/log 公钥**文件路径+整个原件 SHA**不在新的 bundle 内自动获得信任。两个 root 以各自 Ed25519 真签委托 EC359 当前 issuer、公钥、owner 公钥/签名 head、发行 head、当前 parent result；两个独立 witness 真签线下 root 来源**声称**；root 真签连续的完整库存**声称**和撤销快照；独立 directory key 真签 tree head 并用 RFC6962 的实际 bytes inclusion 证明当前授权/撤销 head 的存在。所有展示的撤销分支均生效，不会因为 caller 指定 head 就隐藏。

签名一致说明**相应公钥**签过这些 canonical 字节。不能确认：这些公钥真属于官方机构、实体真实存在或独立、地域依法授权、外部官方根分发真实、所有实际撤销已经披露、历史 UTC 可信、存在第三方全球公开目录，或此 checkpoint 是全网最新。`origin_reference_id` 与 `claimed_jurisdiction` 均只是有真签的**主张**，没有外部真实性证明。即使所有本地约束满足，输出依旧 `exit_code:2`、`..._unresolved`、`official_trust_anchor_origin_..._unproven:true`。无法用本 EC 修复父包 EC249/250/B001/Quality、生产 EC317/318 MOCK 或最终验收。

## 2. 文件入口与调用

独立：

```
python -I -B ces/scripts/ces_cas_authority_directory.py derive-authority-directory-handoff [全部 EC359 parent 参数]
python -I -B ces/scripts/ces_cas_authority_directory.py audit-authority-directory [全部 EC359 parent 参数] [本节 EC360 参数]
```

统一固定入口：

```
python -I -B ces/scripts/ces_next.py audit-authority-directory DeliveryAudit AuditAuthorityDirectory \
  [全部 EC359 必需/可选/repeat 参数] \
  --authority-evaluation-utc 2026-10-26T07:00:00Z \
  --authority-bundle-file /ABS/authority-bundle.json \
  --expected-authority-bundle-sha256 <64-lowercase-hex> \
  --authority-a-root-public-key-file /ABS/root-a.bin \
  --expected-authority-a-root-public-key-sha256 <64-lowercase-hex> \
  --origin-a-witness-public-key-file /ABS/witness-a.bin \
  --expected-origin-a-witness-public-key-sha256 <64-lowercase-hex> \
  --minimum-a-revocation-sequence 0 \
  --expected-a-revocation-head-sha256 <64-lowercase-hex> \
  [同样的 B 源参数] \
  --directory-public-key-file /ABS/directory-key.bin \
  --expected-directory-public-key-sha256 <64-lowercase-hex> \
  --directory-checkpoint-file /ABS/signed-checkpoint.json \
  --expected-directory-checkpoint-sha256 <64-lowercase-hex> \
  --expected-directory-head-sha256 <64-lowercase-hex> \
  --minimum-directory-tree-size 4
```

上述路径/时间/hex 均为参数格式示意，非真实可认证根。**不能只传 EC360 参数**，每次都必须保留 EC359 所需的完整原始调用输入。`derive` 只导出 handoff，不接收 EC360 额外证据；不授予实际写入权限。目录参数可不提供，届时将单独标记 `independent_signed_directory_inclusion_missing_or_invalid:true`，而不是推断目录已经发布。任何单边 path/SHA 键对非法。所有本轮 `true` 都只表示**本次提供的**本地字节检查。

## 3. 协议字段（精确白名单）

整包 `ces.ec360.authority_revocation_directory_bundle.v1`，限 `32_000` bytes，顶层仅 `schema,sources`；`sources` 至多 A/B 两个互不重复 slot，source 除下列字段以外不得有任何字段：

```json
{
  "slot": "a",
  "authority_root_public_key": {"path": "/ABS/root.bin", "sha256": "<sha256>"},
  "origin_witness_public_key": {"path": "/ABS/witness.bin", "sha256": "<sha256>"},
  "origin_original": {"path": "/ABS/origin.json", "sha256": "<sha256>"},
  "delegation_original": {"path": "/ABS/delegate.json", "sha256": "<sha256>"},
  "revocation_snapshot_originals": [{"path": "/ABS/revoke0.json", "sha256": "<sha256>"}],
  "directory_inclusions": [
    {"original_sha256": "<delegate-whole-sha>", "leaf_index": 0, "audit_path_sha256": ["<sibling-hash>"]},
    {"original_sha256": "<selected-snapshot-whole-sha>", "leaf_index": 1, "audit_path_sha256": ["<sibling-hash>"]}
  ]
}
```

其中 `root/witness` 原文只能是 `32` byte Ed25519 public key；`origin`、`delegation`、每个 snapshot、directory checkpoint 各 ≤`8_000` byte。路径为绝对规范路径；不得软链、祖先软链、硬链接到父/新角色原件，不得跨角色重复公钥 SHA；所有受 pin 约束文件结束前重新读原始字节/SHA 并复查 inode。JSON 必须严格 canonical：`json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)` 的 UTF-8 原字节；不接受多余字段、重复键、Unicode 不规范化或声称的 JSON `passed`。

### 3.1 Root 委托原件

`schema=ces.ec360.root_signed_issuer_delegation.v1`，精确字段：

`schema,slot,authority_id,root_public_key_original_sha256,issuer_public_key_original_sha256,issuer_id_as_signed_claim,owner_public_key_original_sha256,parent_owner_head_event_sha256,parent_distribution_head_original_sha256,parent_ec359_canonical_result_sha256,authorized_jurisdictions,authorized_scopes,valid_from_utc,expires_utc,signature_root_ed25519_hex`。

Ed25519 实际签名原文为 `b"CES/EC360/AuthorityDelegation/v1\0" + canonical(doc 去除 signature_root_ed25519_hex)`。严格绑定真正重放的 parent result、公钥和本次所选签名 head。`authorized_jurisdictions`、`authorized_scopes` 每项只能是有限标识符、去重升序，至少一项、最多四项。期长最多 180 天；如果缺少 `ces.reviewer_owner_distribution.v1` 范围或者 witness 声称地域不在允许集，**验签仍然有效但本地授权不成立**，不会变成官方身份。无 EC360 root 轮换/隐式续期能力。

### 3.2 独立来源 witness 声称

`schema=ces.ec360.offline_anchor_origin_witness_claim.v1`，精确字段：

`schema,slot,authority_id,claimed_jurisdiction,origin_reference_id,root_public_key_original_sha256,delegation_original_sha256,origin_witness_public_key_original_sha256,observed_utc,expires_utc,signature_witness_ed25519_hex`。

域隔离 `b"CES/EC360/AnchorOriginWitness/v1\0"`，用链外 caller-SHA-pinned 的 **另一把** Ed25519 witness 公钥真签，期长 ≤180 天。witness 记录中引用真实授权原件 SHA；引用 ID 只是声明，不会被该程序从外部验证或联网查询。

### 3.3 Root 真签撤销快照历史

`schema=ces.ec360.root_signed_revocation_inventory.v1`，精确字段：

`schema,slot,authority_id,root_public_key_original_sha256,delegation_original_sha256,scope,sequence,previous_snapshot_original_sha256,inventory_issuer_key_shas,revoked_issuer_key_shas,issued_utc,valid_until_utc,signature_root_ed25519_hex`。

签名域 `b"CES/EC360/AuthorityRevocations/v1\0"`。单源最多 5 条；序列 0 创世节点没有 previous，序列续增 1 必须有实际原签前驱；快照签署窗口不超过 14 天；SHA 列表均排序去重、≤8 项，撤销必须是库存的子集。**任何已呈现的签署快照**出现当前 issuer SHA 撤销，都标记失效；跨分支签署撤销不能被选择另一 head 遮蔽。已展示的同前驱两个后继、多创世、多个结尾、某后续快照取消前次撤销、时间倒退均视为可见矛盾；缺前驱、序列断裂、伪签名直接拒绝。未知快照/隐蔽分支并不能被证明不存在。

链外输入 `minimum_a/b_revocation_sequence` 在 0..4，`expected_a/b_revocation_head_sha256` 与记录的**原文件** SHA 对照。所选 head 有已给后代、低于 caller floor 就报告回退；完全缺头则报告材料未供应。缺少被审 issuer 的库存 SHA => `signed_issuer_inventory_coverage_missing:true`，不得把「名单没列」当成「没有撤销」。

### 3.4 独立签名 directory checkpoint 与 RFC6962

checkpoint 原文 `schema=ces.ec360.directory_signed_checkpoint.v1`，精确字段 `schema,directory_id,directory_public_key_original_sha256,tree_size,root_sha256,issued_utc,expires_utc,signature_directory_ed25519_hex`，域隔离 `b"CES/EC360/DirectoryCheckpoint/v1\0"`。树叶 ≤64，时效窗 ≤7 天。directory 公钥是第五个独立 SHA pinned 签名角色，不可当做官方透明度服务身份证。checkpoint 整原 SHA 另存输入 `expected_directory_head_sha256`，树大小 ≥ caller 外部保留的 `minimum_directory_tree_size`。

每来源在 bundle 内必须提供**所选** root delegation 原件与所选 revocation snapshot 原件各一条 proof，并用现成 EC353 RFC6962 `SHA256(0x00||原始字节)` leaf hash、`SHA256(0x01||左 SHA||右 SHA)` internal hash 和真正的 leaf index/tree size/path 验算。路径必须完整、无多余节点。验签有效但错误的 inclusion path 报 `independent_signed_directory_inclusion_missing_or_invalid`；错误签名/原件不匹配直接拒绝。目录只证明这些签署原件存在于所给**某个签名 tree root**，不证明 root 发行人真实身份、目录公示时间或全球完整性。**本轮不提供旧/新目录 checkpoint consistency proof 或多 checkpoint gossip**，后续 EC 可以继续加。

## 4. 输出与拒绝边界

- `derive-authority-directory-handoff`：只重放 EC359 的 derive handoff，输出需求清单和本地 `exit2`；`audit-authority-directory`：真实审查父 EC359..337 签名、来源、授权、撤销、目录。
- 每个合法审查结果：`schema=ces.ec360.offline_authority_revocation_directory_unresolved.v1`、`exit_code=2`、`status=..._unresolved`，显示双 source 明细、已知撤销、冲突、回退、缺失、时效、自身材料真签和完整目录证明。`two_sources_scope_and_revocation_locally_coherent` 与 `two_sources_directory_inclusion_locally_verified` 是**条件性本地结果**，并非官方认证。
- 根/证据伪签、实际前驱缺失、父 result 伪绑定、重复签名角色、非法 path/inode 为退出 3/4/5 明确 denial；固定统一路由额外验证完整输入/输出白名单和只读子进程实际 exit code。
- EC249 `INCOMPLETE`、EC250 `BLOCKED`、B001 `OPEN`、Quality=false、final `NOT_STARTED`、native PowerShell V4.60/R150 均不升级。

## 5. 本地案例与最终用户联验待办

18 个不同场景在分批/单项本地合成测试各观察 PASS（含 `python -I -B` 统一入口）。并未运行一次独立 18 项连续完整 suite，先前父 EC359/358/357/356 独立完整回归本轮也未单跑，虽然每项**真实重放**父签名原件。历史 EC356 case24 仍待联验；EC317/318 深层历史 MOCK、真实外部官方根及权威来源、trusted UTC、远程全局撤销、实际独立机构/物理 custody、native PS7/原 15 Smoke、Windows/macOS/Git/CI/Provider/E63–E66、remote CAS/WORM、用户最终验收均 NOT_PROVEN/NOT_RUN。
