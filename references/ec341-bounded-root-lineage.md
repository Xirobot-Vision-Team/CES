# EC341 — Bound root lineage / 已签轮换链操作协议

**版本：V6.51/R341/EC341。** 本手册描述实际可运行代码，不证明任何现实机构、全球最新根、可信时钟、全量分叉发现、真实撤销登记，或旧 MOCK 历史已变真实。EC340 的 `epoch1→2` 保持原域、原文件、原验证入口；EC341 另以独立 Ed25519 领域实现 `epoch2→3 ... epoch7→8`。旧授权不能凭 rollover 自动授权新 epoch。

## 1. 发行候选阶段（仅独立程序，不经统一只读入口）

依照 [EC340 单跳协议](ec340-offline-issuer-root-rotation.md) 真正完成且**外部保管**旧 EC339 policy/issuer roster、第一跳 epoch2 successor、旧新8签、独立 observer roster+真实签名。不得将这些 SHA 直接从本地 candidate 自己复制为受信 SHA；必须另外取得真实独立的机构批准和来源保管。

从 epoch2 再向 epoch3 轮换：

```text
python -I -B scripts/ces_cas_issuer_lineage.py create-roster \
  --out /private/ec341/epoch3-root.json \
  --policy-file /private/ec338/policy.json --expected-policy-sha256 <独立已核实policy SHA> \
  --predecessor-roster-file /private/ec340/epoch2-root.json \
  --expected-predecessor-roster-sha256 <独立已核实epoch2 SHA> \
  --issuer-config-file /private/ec341/issuers3.json \
  --expected-issuer-config-sha256 <已审查config文件SHA> \
  --rotation-id rotation_epoch3_example \
  --rotation-nonce-sha256 <外部独立不可复用的64位小写SHA> \
  --effective-utc 2026-10-25T12:00:00Z
```

`issuers3.json` 只允许 `{"issuers":[...四个issuer...]}`，每一项仅可含 `role,issuer_id,issuer_public_hex,subject_organization_id`，按 `sender,carrier,receiver,witness` 排序，组织与 EC338 `policy.actors` 精确对应；旧新发行者的 ID、公钥不能重用，也不得使用 EC338 操作人签署密钥；所有以后代次（以及观察人）的 key/ID 不能复用更早代。所有文件用 canonical ASCII JSON (`sort_keys=True`, `separators=(',',':')`, UTF-8+LF)，源须为私有路径，独立 SHA 从外部授信。

下一步分别由**八个实际旧/新发行者密钥保管人**签署同一 new root whole SHA。以下命令仅签 `old/sender`，不能代替其他七份：

```text
python -I -B scripts/ces_cas_issuer_lineage.py sign-edge \
  --out /private/ec341/old-sender-edge3.json \
  --private-key-file /private/keys/epoch2-sender.ed25519.raw \
  --side old --role sender \
  --policy-file /private/ec338/policy.json --expected-policy-sha256 <policy SHA> \
  --predecessor-roster-file /private/ec340/epoch2-root.json \
  --expected-predecessor-roster-sha256 <epoch2 SHA> \
  --successor-roster-file /private/ec341/epoch3-root.json \
  --expected-successor-roster-sha256 <epoch3 root whole SHA>
```

所有签名均独立 Ed25519 真签，domain = `CES/EC341/IssuerRootHandoff/<old|new>/<role>/v1\0`，签名原文精确绑定 predecessor SHA / successor SHA / epoch / rotation ID / nonce / effective UTC / role / side / 该侧 issuer ID 和公钥。每个签名的 whole original SHA 必须进入一个**被外部独立先验授权**的 manifest。

另外先配置 **EC340 原观察方格式**的独立见证 trust JSON（`schema=ces.ec340.independent_root_observer_trust.v1`、transfer/policy SHA、observer ID/org/public key/out-of-band=true），用不同于历代发行者及观察人的全新 key/ID/org。见证者需先取得实际所有八份签名文件及原 SHA，再单独调用 `issue-observation`：

```text
python -I -B scripts/ces_cas_issuer_lineage.py issue-observation \
  --out /private/ec341/epoch3-observation.json \
  --private-key-file /private/keys/epoch3-observer.ed25519.raw \
  --policy-file /private/ec338/policy.json --expected-policy-sha256 <policy SHA> \
  --predecessor-roster-file /private/ec340/epoch2-root.json \
  --expected-predecessor-roster-sha256 <epoch2 root SHA> \
  --successor-roster-file /private/ec341/epoch3-root.json \
  --expected-successor-roster-sha256 <epoch3 root SHA> \
  --observer-roster-file /private/ec341/epoch3-observer.json \
  --expected-observer-roster-sha256 <observer roster SHA> \
  --old-sender-edge-file /private/ec341/old-sender-edge3.json \
  --expected-old-sender-edge-sha256 <old sender signed SHA> \
  <其他七份 old/new x 4 roles 的 edge 路径和 whole SHA> \
  --verifier-challenge-sha256 <本跳接收方独立挑战 SHA> \
  --observed-utc 2026-10-25T12:05:00Z \
  --expires-utc 2026-10-25T12:25:00Z
```

真实 CLI 的全部精确参数可由 `python -I -B scripts/ces_cas_issuer_lineage.py issue-observation --help` 显示。`observed_utc >= effective_utc`，`expires_utc > observed_utc`，最长24小时；观察人私钥只签一份独立的状态签名，不是真实完整撤销数据库核验。发起 epoch4...8 重复同一流程，每次严格相邻、全新 key/ID/nonce/observer、有效 UTC 递增。**软件最大 epoch=8（最多7跳），不是无界区块链或实际全球公证。**

候选写入仅可在独立 CLI 中进行，`0600/O_EXCL/fsync`，不覆盖既有任何字节，无远端写入。各新签原件必先经可信的外部 custody/评估流程，再交给接收方。至少一名见证人不能在多个 epoch 复用相同公钥/ID/自报机构；这只是技术上的**标识隔离**，不能证明真实人员独立。

## 2. 只读接收：规范 manifest 结构

为避免让 7 代历史变成几百个 CLI 参数，接收方必须先从**外部真正独立保管渠道**取得 canonical manifest 的**整原 SHA**。manifest 自己带有逐成员原 whole SHA 是**可认证的承诺清单**；签名仅证明密钥使用，SHA 只证明字节一致。倘若 manifest 和它的 `--expected-manifest-sha256` 都由同一个不可信现场脚本产生，就**不构成可信授权**。

顶层规范 JSON 严格仅有以下字段，字节需 `sort_keys=True`, `separators=(',',':')`, ASCII/UTF-8+LF，不含任意额外字段：

```json
{
  "schema": "ces.ec341.externally_pinned_lineage_and_fork_manifest.v1",
  "context": {
    "policy_file": "/private/ec338/policy.json",
    "expected_policy_sha256": "<可信原policy SHA>",
    "authority_roster_file": "/private/ec339/issuer-roster.json",
    "expected_authority_roster_sha256": "<可信原epoch1 whole SHA>"
  },
  "history": {
    "bundle_file": "/private/ec337/archive.zip",
    "expected_bundle_sha256": "<可信archive SHA>",
    "expected_first_hop_plan_sha256": "<旧已核实 SHA>",
    "expected_closure_sha256": "<旧已核实 SHA>",
    "expected_map_sha256": "<旧已核实 SHA>",
    "expected_handoff_sha256": "<旧已核实 SHA>",
    "left_expected_manifest_sha256": "<旧已核实 SHA>",
    "right_expected_manifest_sha256": "<旧已核实 SHA>",
    "sender_receipt_file": "/private/ec338/sender-receipt.json",
    "expected_sender_receipt_sha256": "<旧已核实 SHA>",
    "carrier_receipt_file": "/private/ec338/carrier-receipt.json",
    "expected_carrier_receipt_sha256": "<旧已核实 SHA>",
    "receiver_receipt_file": "/private/ec338/receiver-receipt.json",
    "expected_receiver_receipt_sha256": "<旧已核实 SHA>",
    "witness_receipt_file": "/private/ec338/witness-receipt.json",
    "expected_witness_receipt_sha256": "<旧已核实 SHA>",
    "sender_grant_file": "/private/ec339/sender-grant.json",
    "expected_sender_grant_sha256": "<旧已核实 SHA>",
    "carrier_grant_file": "/private/ec339/carrier-grant.json",
    "expected_carrier_grant_sha256": "<旧已核实 SHA>",
    "receiver_grant_file": "/private/ec339/receiver-grant.json",
    "expected_receiver_grant_sha256": "<旧已核实 SHA>",
    "witness_grant_file": "/private/ec339/witness-grant.json",
    "expected_witness_grant_sha256": "<旧已核实 SHA>",
    "sender_status_file": "/private/ec339/sender-status.json",
    "expected_sender_status_sha256": "<旧已核实 SHA>",
    "carrier_status_file": "/private/ec339/carrier-status.json",
    "expected_carrier_status_sha256": "<旧已核实 SHA>",
    "receiver_status_file": "/private/ec339/receiver-status.json",
    "expected_receiver_status_sha256": "<旧已核实 SHA>",
    "witness_status_file": "/private/ec339/witness-status.json",
    "expected_witness_status_sha256": "<旧已核实 SHA>",
    "evaluation_utc": "2026-10-25T10:20:00Z"
  },
  "hops": [
    {
      "epoch": 2,
      "successor_roster_file": "/private/ec340/epoch2-root.json",
      "expected_successor_roster_sha256": "<可信epoch2根 SHA>",
      "observer_roster_file": "/private/ec340/epoch2-observer.json",
      "expected_observer_roster_sha256": "<可信epoch2 observer root SHA>",
      "root_observation_file": "/private/ec340/epoch2-signed-observation.json",
      "expected_root_observation_sha256": "<可信已签观察 SHA>",
      "evaluation_utc": "2026-10-25T11:40:00Z",
      "verifier_challenge_sha256": "<与EC339历史状态一样的外部challenge SHA>",
      "edge_signatures": [
        {"side":"old","role":"sender","file":"/private/ec340/old-sender-edge.json","sha256":"<原 whole SHA>"},
        {"side":"old","role":"carrier","file":"/private/ec340/old-carrier-edge.json","sha256":"<原 whole SHA>"},
        {"side":"old","role":"receiver","file":"/private/ec340/old-receiver-edge.json","sha256":"<原 whole SHA>"},
        {"side":"old","role":"witness","file":"/private/ec340/old-witness-edge.json","sha256":"<原 whole SHA>"},
        {"side":"new","role":"sender","file":"/private/ec340/new-sender-edge.json","sha256":"<原 whole SHA>"},
        {"side":"new","role":"carrier","file":"/private/ec340/new-carrier-edge.json","sha256":"<原 whole SHA>"},
        {"side":"new","role":"receiver","file":"/private/ec340/new-receiver-edge.json","sha256":"<原 whole SHA>"},
        {"side":"new","role":"witness","file":"/private/ec340/new-witness-edge.json","sha256":"<原 whole SHA>"}
      ]
    }
  ],
  "forks": []
}
```

示例中的 `<...>` 是不符合 SHA 校验的**占位符**，不能直接当作运行文件。真实文件必须为绝对规范私有路径、SHA 64 位小写十六进制，不能指向相同实际来源路径来冒充不同角色。新一跳在 `hops` 追加同结构对象，`epoch` 从2连续增长；当 epoch≥3 时每条新签名使用 EC341 新 domain，见证签名使用 EC341 新 domain，字段结构不改变。**每跳增加11个原 whole SHA（root + 8 edges + witness root + signed observation）**，继承旧21个原 SHA；外部另行固定 manifest SHA + 当前 root SHA/epoch/floor，至少一份真正独立可信渠道证明这些值的来源，不能用 manifest 的自引用取代。

`forks` 可为 `[{"parent_epoch":2,"hop":{...完整不同successor跳原件...}}]`，不超过8条，父代需出现在主链；原件必须独立签署并 SHA 固定，复用主链相同 issuer key/nonce 或重复 successor 文件会拒绝。每一个完整真签可见同父分叉作为 **conflict_unresolved** 输出，不裁决，不发现未提供证据的分叉，不替旧或新根自动批准业务授权。

## 3. 固定只读入口和返回含义

```text
python -I -B scripts/ces_cas_issuer_lineage.py verify-lineage \
  --manifest-file /private/ec341/lineage-manifest.json \
  --expected-manifest-sha256 <从真正外部渠道固定的 manifest SHA> \
  --expected-current-root-sha256 <从受信根渠道独立确认的当前 SHA> \
  --expected-current-root-epoch 4 \
  --minimum-acceptable-epoch 3 \
  --current-root-evaluation-utc 2026-10-25T12:39:00Z
```

或同样参数经统一路由：

```text
python -I -B scripts/ces_next.py audit-issuer-root-lineage \
  DeliveryAudit VerifyBoundedIssuerRootLineage \
  --manifest-file /private/ec341/lineage-manifest.json \
  --expected-manifest-sha256 <SHA> \
  --expected-current-root-sha256 <SHA> \
  --expected-current-root-epoch 4 \
  --minimum-acceptable-epoch 3 \
  --current-root-evaluation-utc 2026-10-25T12:39:00Z
```

标准结果：本地已验且无已呈现分叉 `status=lineage_locally_verified_unresolved`；若有实际全签分叉 `status=conflict_unresolved`；两者**均 `exit_code=2`**、不等同成功的机构授权；任何格式、伪签、回退、冲突自报、越界/外部 SHA 不符、过期、源变化拒绝则 `exit_code 3/4/5`。统一入口**不接受** `--private-key-file`, `--out`, candidate signer subcommands，不会打开远端业务/Git/Provider/CAS。

## 4. 必须留到最后联合验收的外部依赖

真实发行者与观察人组织的独立密钥 custody、实际合法轮换授权、可信时间/时钟和新旧撤销登记、签名外部 custody 与 current SHA+epoch 的真正独立锚、未呈现分叉、实际 CAS/WORM/global newest/winner、无 MOCK 的旧 EC317/318 全生产链、原生 pwsh/15 Smoke/跨 OS/Git/CI/Provider/E63–E66、最终联合验收均不能由本地 synthetic fixture 证明。不要因本轮 EC341 局部真实签名测试 PASS 而修改 `EC249 incomplete / EC250 BLOCKED / B001 OPEN / Quality false / final NOT_STARTED`。

[施工说明](../EC-341.md) · [Scope](../construction/EC341_SCOPE.json) · [局部事实](../construction/EC341_LOCAL_REPORT.json) · [完整代码/全部 SHA](../construction/EC341_DELIVERY_SHA256.json)。
