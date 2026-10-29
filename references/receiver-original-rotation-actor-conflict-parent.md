# EC387 — 原件接收协议：EC340 epoch1→2 八边 Ed25519 根轮换、EC339 角色历史与 EC341/342 冲突父根

## 位置与不可突破边界

本文件是 **V6.97 / R387 / EC387** 单轮增量功能的**完整历史接收侧原件协议**；并非一次外部第三方的真实交付证明。唯一父基线是 V6.96/R386/EC386 完整包。`construction/historical_rotation/rotation_archive.py` 只在 **EC386→EC369 原有接收审计已经在同一调用中真实执行**后读取下一层原件。绝不接收上游调用者自行构造的父报告 JSON 充当实证。原生 PowerShell 仍为 V4.60/R150，原签名域与原 EC337–EC342 校验器保持不改。

- 新独立只读命令：`python -I -B scripts/ces_cas_historical_rotation_archive.py derive-historical-ec340-rotation-inventory ...`，以及 `audit-historical-ec340-rotation-archive ...`。
- 唯一统一路由：`python -I -B scripts/ces_next.py audit-historical-ec340-rotation-archive DeliveryAudit AuditHistoricalEC340RotationArchive ...`。只会以原始参数调用固定子脚本，无私钥命令、无网络调用、无 Provider/CAS/WORM/Git/CI 写入。
- **所有合法观察都是 `exit_code=2` / `_unresolved`**。拒绝、无效或不可用依次 `3 / 4 / 5`；软件无法完成真外部机构、保管及最终验收证明。

## 输入与 archive 布局

必须提供全部旧 EC386 的 `PARENT_SCALARS`（**含原父审计专用 SHA 参数**）与 `PARENT_REPEATS`，再添加如下新参数；每个 repeated 参数恰有 1–3 个值，与 `historical_directory_root_shas` 的 epoch 数一致。`derive` 不接收外部最终库存摘要；`audit` 必须接收。

| 新参数名（下划线为 Python 键；CLI 使用相同连字符写法） | 目的 |
|---|---|
| `historical_ec340_signed_rotation_archive_bundle_file` | EC387 接收 archive 绝对规范路径 |
| `expected_historical_ec340_signed_rotation_archive_bundle_sha256` | 整个 EC387 archive SHA-256 |
| `historical_ec340_role_rotation_inventory_shas` | 逐 epoch 外部已保留的 EC340 根/签名/观察者库存 SHA |
| `historical_ec339_actor_grant_inventory_shas` | 逐 epoch 外部已保留的 EC339 actor/receipt/grant/status 库存 SHA |
| `minimum_historical_ec340_signed_edge_counts` | 逐 epoch 0..16；每个有效通道 8 边 |
| `minimum_historical_ec340_signed_observation_counts` | 逐 epoch 0..2；每个有效通道 1 份 |
| `minimum_historical_ec339_signed_grant_status_counts` | 逐 epoch 0..16；每个有效通道 4 grant + 4 status |
| `expected_retained_historical_ec340_signed_rotation_inventory_sha256` | audit-only，接收方完整派生库存摘要（独立保管者事先保留） |

archive 根对象**仅**允许：

```json
{
  "schema": "ces.ec387.receiver_historical_old_ec340_signed_rotation_archive.v1",
  "parent_ec386_canonical_result_sha256": "<完整真实父审计结果的规范 JSON SHA-256>",
  "ec386_historical_root_archive_original_sha256": "<整个源 EC386 archive SHA-256>",
  "claimed_directory_lineage_id": "<与真实 EC386 父 archive 相同>",
  "epochs": [{"epoch_index": 0, "channels": ["<下表 channel 对象，可按需要有两条不同通道>"]}]
}
```

`channels` 按 `tsa_channel_id` 去重并字典排序，严格与旧 EC386 真实接收档案中同 epoch 的通道完全对应。每个 channel 对象**必须**拥有以下且仅以下键：

| 字段 | 内容与谁拥有最初 SHA |
|---|---|
| `tsa_channel_id` | 与父 EC386 通道完全一致 |
| `ec340_legacy_policy_original` | `{path,sha256}`，来自真实旧 EC341 manifest context `policy_file/expected_policy_sha256` |
| `ec339_predecessor_authority_roster_original` | `{path,sha256}`，来自 manifest context `authority_roster_file/expected_authority_roster_sha256` |
| `ec340_epoch2_successor_roster_original` | `{path,sha256}`，来自已认证 EC341 manifest 首个 hop 的 successor |
| `ec340_observer_roster_original` | `{path,sha256}`，来自该首个 hop 的独立 observer roster |
| `ec340_signed_retirement_observation_original` | `{path,sha256}`，来自首个 hop 的签名观察者 claim |
| `ec340_signed_role_edges` | **8** 项：`{side,role,edge_original:{path,sha256}}`；必须按旧 EC340/341 `old` 四角色、`new` 四角色精确顺序排列，逐文件 SHA 与首个 hop 一致 |
| `ec339_original_signed_role_history` | **4** 项：`{role,receipt_original:{path,sha256},grant_original:{path,sha256},status_original:{path,sha256}}`，按旧四角色顺序，逐项来自真实旧 EC341 `history` 原件 SHA |
| `ec340_original_public_key_sources` | **13** 项：`{kind,role,public_hex,public_key_original:{path,sha256}}`，四旧 issuer、四新 issuer、一 observer、四旧 actor，按代码 `KEY_ORDER` 排列；每份原件必须正好 32 字节 |

**13 份角色公钥来源的特殊规则：**旧 issuer、epoch2 新 issuer 及观察者共九份的 `{path,sha256}` 必须**与上层 EC386 认证的 public key copy 原件完全相同**（不准交一份字节相同、路径/原件不同的新副本作为旧认证源）。四份旧 actor 的 raw source 由接收方额外提交、独立读取并与真实旧 policy `actors[]` 的公钥逐字节比对；它们不是新的签名或法律/组织授权证明，必须另外由可信外部保管者确立原件 provenance。所有 13 把公钥要求互异；完整历史签名仍由旧 EC340/EC339 原生签名验证器复核。

**缺源情况：**当 EC386 原 archive 的真实 `ec341_lineage_manifest_original=null` 且对应 governance/hold 也缺失时，EC387 对应所有引用必须 `null`，三组列表必须为 `[]`。只能报告 incomplete/unresolved；不可调用此层创建、签发或替代新签名源。

## 实际执行逻辑

1. 调用**未修改**的 `historical_root.root_archive.audit(**真实父参)`，校验真实结果结构、退出码、已知否定能力字段和 canonical SHA；随后逐字节打开旧 EC386 和新 EC387 archive，锁定连续的父源 SHA、lineage 和 epoch/channel。
2. 读取唯一从**真实 EC386 通道**传入的 EC341 manifest，以及该通道的旧 EC342 governance SHA；再次检查 governance 精确锁定 manifest 与当前根。其首个 hop 必须是 epoch2 successor；重新读取旧 epoch1 authority root、policy、全部 8 个 old/new signed edge、已签 challenged witness 及 4 actor 的旧原始 receipt/grant/status，每份显式路径和整个字节 SHA 都要与原 manifest 相同，不信任未校验的 EC353 sender label。
3. 对所有 Ed25519 原件执行**未修改**的 `issuer_root_rotation.rotation.verify_rotation()`：该原生代码分别验证八个角色/边的签名域，独立观察者 challenge、retirement/effective 时间窗口、从 epoch1 到 epoch2 的 key/id 承接、旧 EC339 签署授权和 status、旧 EC338→EC337 整个 ZIP 及 nested 原件的原有 SHA；本层只接受预期的 `exit 2 unresolved` 和原真实声明。历史授权绝不作为轮换后新 epoch 授权。
4. 精确定位旧 EC342 已批准 hold 中的 `parent_epoch`；对照 EC341 manifest 对应 epoch 的 parent root、选中 successor 及 manifest 上可见的独立签名 competing successor。epoch2 原始根必须是这个链条的第一跳祖先，不能用自己声称的最新版根取代。
5. 两个 TSA 通道及后续 epoch 逐项比较旧 policy、epoch1/epoch2 SHA、8 边签名 SHA、观察者、13 key source SHA 与旧 actor receipt/grant/status SHA；任何可见变更/ABA/回退报告 adverse/unresolved，**不选择胜者**。逐 epoch 比较外部已留存库存 SHA 和签名数量下界。`derive` 的完整库存 SHA 是**本地无签名**结果，不是外部可信第三方的库存签名。

### 完整性与安全性注意

- 原 EC339/EC340/EC341 历史 JSON 原件采用 `reg.raw_doc` 格式；绝不可把 EC353 新格式归一化误用为旧签名线格式。对全部引用做有界只读读取、整 SHA 和进程内路径复用约束；原旧 verifier 对原始文件做 late pin，额外公钥 raw 原件亦末次刷新。
- EC341 manifest 不是已签署的、由第三方全球发布的根存证；EC342 已签 approved hold 也不等于远端真正冻结。公钥 copy 不是密钥托管证明；不可见分叉、撤销历史、可信 UTC 和法人/实体独立性在外部验收前**不成立**。
- 即使本地 Ed25519 格式确实签发、通过旧原生校验器，也不能把测试 fixture 的历史 mock 祖先称为真实独立外部源。当前 EC317/318 inherited fixture **MOCKED**，outer parent test cases **MOCKED**，真实 EC386→EC369 完整第三方接收档案还**未提供**。
- 所有拒绝输入返回特定 `3/4/5`，不提升质量、最终验收或旧原生 PowerShell 功能状态。

## 开发和末期统一验收

```sh
PYTHONPATH=construction python -B -m unittest -q construction.historical_rotation.test_rotation_archive
python -B scripts/ces_cas_historical_rotation_archive.py derive-historical-ec340-rotation-inventory --help
python -B scripts/ces_cas_historical_rotation_archive.py audit-historical-ec340-rotation-archive --help
python -B scripts/ces_next.py audit-historical-ec340-rotation-archive DeliveryAudit AuditHistoricalEC340RotationArchive --help
```

完整生产验收需：独立第三方持有的旧 EC386→EC369 原始 archive、未 mock 的 EC340→EC337（含 EC317/318）的签名证据、外部 SHA 与角色公钥保管和撤销记录、真正两通道/epoch 历史、全球未披露分叉验证、可信时间及物理/远程冻结；另需 PS7/原15 Smoke、Windows/macOS、Git/CI、Provider/E63–E66 和用户最终验收。这些任务保持集中待验而非本轮假定通过。
