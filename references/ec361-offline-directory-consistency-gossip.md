# EC361 — 多目录检查点 append-only consistency 与离线双观察者 gossip 协议

版本 **V6.71/R361/EC-361**；严格接在真实 EC360 已验双来源 root delegation、revocation、独立 directory checkpoint 和四份 RFC6962 inclusion 之后。所有密钥和材料都来自调用方离线提供，不接受缓存 `passed`、联网的 OS trust store、隐式目录授权。

## 命令

独立只读：

```bash
python -I -B ces/scripts/ces_cas_directory_consistency.py \
  derive-directory-consistency-handoff [完整 EC360 audit-authority-directory 父参数]
python -I -B ces/scripts/ces_cas_directory_consistency.py \
  audit-directory-consistency [完整 EC360 父参数] \
  --consistency-evaluation-utc 2026-10-26T08:00:00Z \
  --consistency-bundle-file /ABS/consistency.json \
  --expected-consistency-bundle-sha256 <64-lowercase-hex> \
  --observer-a-public-key-file /ABS/a.bin \
  --expected-observer-a-public-key-sha256 <64-lowercase-hex> \
  --observer-b-public-key-file /ABS/b.bin \
  --expected-observer-b-public-key-sha256 <64-lowercase-hex> \
  --minimum-consistent-directory-tree-size 5 \
  --expected-latest-consistent-directory-checkpoint-sha256 <64-lowercase-hex> \
  --expected-evolved-checkpoint-1-sha256 <64-lowercase-hex> \
  [--expected-evolved-checkpoint-2-sha256 ...] \
  [--expected-evolved-checkpoint-3-sha256 ...]
```

固定统一路线：

```bash
python -I -B ces/scripts/ces_next.py audit-directory-consistency \
  DeliveryAudit AuditDirectoryConsistency [同一完整 EC360 父参数 + 上述 EC361 参数]
```

CLI 新审计参数仅 `consistency_evaluation_utc` 必填，其他如缺损则逐字段标记 unresolved；不得凭默认值推断外部资料存在。`derive` 本身重放 EC360 audit，不接受 EC361 证据；可输出签署原件清单，不能授权写操作。所有合法输出 exit 2。新旧代码都不生成签名私钥或连接远端。

## bundle：精确字段、SHA 和大小

整包限 36,000 UTF-8 bytes，必须 canonical JSON：
`json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)`。
重复 JSON 键、类型多态、未知字段、非规范路径、虚假 SHA/硬链接/软链接祖先拒绝。字段必须**恰好**：

```json
{
  "schema": "ces.ec361.directory_consistency_observer_bundle.v1",
  "checkpoint_originals": [
    {"path": "/ABS/checkpoint-5.json", "sha256": "<checkpoint-5-whole-file-SHA>"}
  ],
  "consistency_proofs": [
    {
      "older_checkpoint_sha256": "<parent-checkpoint-whole-file-SHA>",
      "newer_checkpoint_sha256": "<checkpoint-5-whole-file-SHA>",
      "audit_path_sha256": ["<node-1-SHA>", "<node-2-SHA>"]
    }
  ],
  "observer_receipt_originals": [
    {"path": "/ABS/observer-a.json", "sha256": "<receipt-a-whole-file-SHA>"},
    {"path": "/ABS/observer-b.json", "sha256": "<receipt-b-whole-file-SHA>"}
  ],
  "head_inclusions": [
    {"original_sha256": "<EC360-delegation-a-whole-SHA>", "leaf_index": 0,
     "audit_path_sha256": ["<RFC6962-sibling-SHA>"]}
  ]
}
```

上面仅为**结构示意**，实际 `head_inclusions` 必须包含 EC360 A/B root delegation 各一和所选 revocation snapshot 各一，恰好四条，完整有效 RFC6962 路径。`checkpoint_originals` 允许 0..3 条（本地一致需要至少 1 条）；每份原件最多 8,000 bytes，树大小 `1..64`。每条 Merkle proof 最多 7 个小写 64-hex 节点。每个新增 checkpoint 在 bundle 中有 `path+sha256`，**并且**必须和 bundle 外 `expected_evolved_checkpoint_{1,2,3}_sha256` 的非空集合完全一致。外部 pin 不能被包内字段代替。最多两份 observer receipt。

目录 checkpoint 沿用 EC360 原件格式 `ces.ec360.directory_signed_checkpoint.v1`，使用 EC360 旧签名域 `CES/EC360/DirectoryCheckpoint/v1\0` 和 EC360 已经外部单独 pin 的 directory Ed25519 公钥，**目录 ID、签名公钥 SHA**必须与父 checkpoint 完全相同。真实目录签名认证不等于官方目录真实性。

### Merkle consistency 的严格语义

按展示的所有实际有效签名 checkpoint 的 `tree_size` 排序，包括 EC360 父 checkpoint。对于每对相邻的**不同树大小**，`consistency_proofs` 需要且只能提供一条边；边两端必须是展示的相应大小真实 checkpoint 整原 SHA，路径用 EC353 的 RFC6962 v1 真验证器验证。不接受额外边、重复同大小边、缺节点、多余节点、伪 SHA。不完整或 hash 不匹配=>`rfc6962_append_only_consistency_missing_or_invalid=true`，不是 append-only pass。

同一树大小多个有真签 checkpoint 若 `root_sha256` 不同，`visible_signed_same_size_checkpoint_split_view=true`，**即使其他某一条 consistency path 可验也不能选好看的分支遮蔽**。相同大小和相同 root 的重新签署不算 Merkle 分叉；无树大小增长不算得到新的 append-only consistency 证据。调用方另存最新 head 原件 SHA、最低树大小 floor；所选 head 缺失、低于 floor、低于 EC360 父树大小、或有更大已签 head 可见 => 缺失/rollback，禁止升级。

### 双观察者各自真签 receipt

每条 receipt 精确字段：

```
schema,slot,claimed_observer_id,observer_public_key_original_sha256,
directory_public_key_original_sha256,directory_id,
parent_ec360_canonical_result_sha256,
parent_directory_checkpoint_original_sha256,
observed_checkpoint_original_sha256,observed_tree_size,
observed_root_sha256,observed_utc,expires_utc,
signature_observer_ed25519_hex
```

其中 `schema="ces.ec361.signed_directory_observer_receipt.v1"`、slot 为 `a/b`、自称 observer ID 必须为有限 identifier，observed UTC < expires UTC 且时窗 ≤7d。Ed25519 域隔离签署原文：

```
b"CES/EC361/DirectoryObserverGossip/v1\x00" + canonical(receipt without signature_observer_ed25519_hex)
```

两把 observer 公钥**单独**由调用方在 bundle 外传入绝对路径和 32 byte 公钥整文件 SHA；不同 key SHA、不同角色/parent keys、不同 inode。所有签名有效仍只能认证这两把被展示的钥签过各自声明；两个自报组织名不构成两个真实独立法人。同一 observer slot 多条、假父 binding、未提供真实目标 checkpoint、错误签名都拒绝；两方不同已签 head / observer ID 冲突/缺一份 => gossip 未决而非 consensus。

### 新 head inclusion

以 EC360 原先核实过的 bundle 作为旧证据来源，审计器额外重新打开真实 A/B `delegation_original` 和 selected A/B `revocation_snapshot_original` 原文件并重验 whole-SHA，不接受重新 JSON 序列化冒充原文。按照 RFC6962：
- leaf `SHA256(b"\x00" + exact_original_bytes)`
- internal `SHA256(b"\x01" + left_sha + right_sha)`

对本轮调用方所选 head `tree_size/root_sha256` 核验恰好四个 leaf index + audit path；旧 EC360 父 cp 的包含性并不等价于任意新 head 的包含性。

## 结果、阻断与界限

每份合法 result 固定 schema `ces.ec361.offline_directory_consistency_gossip_unresolved.v1`、command `audit-directory-consistency`、`exit_code=2`、所有身份/公示/可信时间/全球完整性等否定断言一律 false。可观察局部布尔量：
- `signed_directory_append_only_locally_verified`：所有展示的相邻不同大小树确实有真 consistency 路径、无已展示同大小分裂。
- `two_distinct_observer_keys_agree_on_head_locally`：两把实际不同的 caller-pinned observer key 对本次选 head 的字段做了真实签名。
- `four_parent_originals_in_selected_head_locally_verified`：四份已核实 EC360 原始字节确有本轮新 head 的 inclusion 证明。
- `locally_coherent_signed_directory_evolution_and_gossip`：**同时要求**真实 parent EC360 locally verified、上述三项、独立 pin、head/floor 无 rollback、时间声称未表现为超界、无其他观察到的分歧。**即使 true 依然 exit2 unresolved**。

任何本地一致不能证明：本次私钥控制者真的具有政府/机构/法律权限、真实跨法人独立、全网最新目录头、未披露分叉不存在、完整全球 revocation/CRL/OCSP、可审计历史 UTC、物理 custody、远端 CAS/WORM 或 native PowerShell 通过。EC356 历史 case24、EC317/318 MOCK、原生 PowerShell7/15 Smoke、跨系统、E63–E66 和最终用户辅助验收全部留待最终统一验证。
