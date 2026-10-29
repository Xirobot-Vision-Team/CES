# EC354 — 离线跨透明日志 Gossip 挑战/回复：签名原件、分叉保全与无法补证的独立性

## 1. 施工范围 / 证据性质

EC354 **每次运行都会重新调用 EC353 `transparency.audit`**，它会继续重放 EC352→EC337 的历史原始签名、SHA、TSA/OCSP/CRL、日志/见证 checkpoint、RFC6962 inclusion 和 consistency。**绝不接收旧审计结果 JSON 替代原件**。EC354 随后读取 EC353 已见证的 checkpoint 精确原始 SHA，以两到四个分别呈交的 SHA-pinned Ed25519 审计方密钥（也允许 0–1 个作为明确缺证情况）验证离线挑战及答复。所有被实际呈交且签名有效的观察会被保留，不选“全球最新 head”、不替私人声称登记可信公钥、不向 HTTPS 发请求。

本轮只提供校验器、只读衍生清单、固定隔离的统一审计入口；**没有密钥生成、签名者、上传/下载、远程日志写入、CAS/WORM/Provider 变更或最终审批**。实际外部机构身份、物理独立性、可信时间、完整全球 gossip 网络、真实叉路是否已被外部隐藏、原 EC317/318 生产源完整性仍均 `NOT_PROVEN`。即使全部原件签名/本地核对相符，正向结果仍是 **exit 2 / `*_unresolved`**。

## 2. 入口与基本限制

```sh
# 每次都要求 EC353 audit 的全部历史必需输入参数
python -I -B scripts/ces_cas_cross_log_gossip.py derive-gossip-handoff <全部EC353 audit参数>
python -I -B scripts/ces_cas_cross_log_gossip.py audit-cross-log-gossip <全部EC353 audit参数> \
  --gossip-evaluation-utc 2026-10-25T23:00:00Z \
  --gossip-bundle-file /trusted-pins/gossip-bundle.json \
  --expected-gossip-bundle-sha256 <真实64位小写SHA>

# 固定 Action/Mode 的统一只读入口（内部子进程始终 -I -B）
python -B scripts/ces_next.py audit-cross-log-gossip \
  DeliveryAudit AuditSignedCrossLogGossip <全部EC353 audit参数和上述三个gossip参数>
```

`--help` 可展示完整的祖先要求（文件/每原件 SHA、六个严格 claimed evaluation UTC 等）。`derive-gossip-handoff` 亦会**真实运行 EC353 全部签名核验**，列出被 log+见证核验的 checkpoint 元数据。不可用 `EC353_LOCAL_REPORT` 或 `PASS` 输出代替。运行时 `cryptography` 与 `asn1crypto` 用于旧根验证；测试 fixture 用 OpenSSL 生成本地合成的 RSA/DER/OCSP/CRL。无网络。

新增 `gossip_bundle_file` 必须是绝对、无 symlink、可确定整文件 SHA 的 canonical JSON（无 BOM、换行结尾、重复 key、非标准空白、NaN、非 UTF-8 或路径别名）；其所有文件的 `path/sha256` 均分别 pin，不能复用另一证据角色的路径，更不能与历史 EC352/EC353 的任一原件路径相同。每个新原件在最终报告前重新整原复读核对，同时复读上一层 EC353 manifest、checkpoint、见证与证明原件。

## 3. Gossip bundle 全部结构

```json
{
  "schema": "ces.ec354.pinned_cross_log_gossip_bundle.v1",
  "auditors": [
    {
      "auditor_id": "auditor_a",
      "auditor_reference": {"path": "/evidence/a-ref.json", "sha256": "<sha256>"},
      "auditor_public_key": {"path": "/evidence/a-pub.bin", "sha256": "<sha256>"}
    },
    {
      "auditor_id": "auditor_b",
      "auditor_reference": {"path": "/evidence/b-ref.json", "sha256": "<sha256>"},
      "auditor_public_key": {"path": "/evidence/b-pub.bin", "sha256": "<sha256>"}
    }
  ],
  "exchanges": [
    {
      "challenge": {"path": "/evidence/c1.json", "sha256": "<sha256>"},
      "replies": [{"path": "/evidence/r1.json", "sha256": "<sha256>"}]
    }
  ]
}
```

全部字段均为**精确键集合**，不接受多余或省略；所有 PIN 都是原件整字节 SHA，不是 JSON 子树摘要。审计员 `auditor_id` 唯一且升序；1 张规范自签 reference + 1 份 32 字节原始 Ed25519 public key，对每个审计员独立呈交。最多 **4** 位审计方、**8** 份挑战、每挑战 **0–2** 份签名回复、回复总数 **12**。任一 `(challenger,responder,log)` 前驱链最多 **3** 份；允许观察真实签署的同父竞争挑战，保留 forks 标志而不择赢家。所有新签署角色不得与其他审计方、原 EC353 log/witness、EC352 registry root/operator 或 EC351 source-attester 重用同一公钥原件 SHA。

### 3.1 自签审计员引用原件

签名域 `CES/EC354/GossipAuditorReference/v1\0`；主体是以下字段（并增加 `signature_ed25519_hex`）：

```json
{
  "schema": "ces.ec354.self_signed_external_gossip_auditor_reference.v1",
  "auditor_id": "auditor_a",
  "auditor_public_key_original_sha256": "<whole-public-key-file-sha>",
  "claimed_auditor_organization": "Example Independent Auditor",
  "claimed_auditor_directory_uri": "https://invalid.example.test/auditors",
  "valid_from_utc": "2026-10-20T00:00:00Z",
  "valid_until_utc": "2026-11-20T00:00:00Z"
}
```

自签与 HTTPS 字符串仅表明某把私钥签署了该自述，不证明这个外部机构真实存在或认证过该密钥。声称机构名称与所有已呈交日志 publisher/witness、EC352 registry issuer 的名称**不区分大小写**对照；重合时明确降级，但名称不同也不证明真实独立性。有效窗口严格、长度最多366天。签名域拼接方式始终 `domain_raw || canonical(body_without_signature)`，签名是严格小写 128 位 Ed25519 十六进制。

### 3.2 真签 challenge 原件

签名域 `CES/EC354/GossipChallenge/v1\0`，`schema=ces.ec354.signed_gossip_challenge.v1`。以下键全部必需，除签名字段外严格 canonical：

- `challenge_id`：唯一 ID；`challenger_auditor_id`,`responder_auditor_id`：不同且均在本 manifest 的名录中。
- `challenger_reference_original_sha256`,`responder_reference_original_sha256`：**这两位审计员当前已校验自签引用原件 SHA**。
- `parent_publication_bundle_original_sha256`：本次真正复核的 EC353 publication bundle 整原 SHA。
- `log_id`：EC353 中已验 log 的 ID；`log_reference_original_sha256`：该 log 的自签引用原 SHA。
- `checkpoint_original_sha256`,`tree_size`（JSON int 1..64）,`root_hash_sha256`：必须**精确**指向当前实际提供、已真正由 log 签名+独立 witness 签名的 EC353 checkpoint 和 metadata，未出示不允许作为挑战基准。
- `previous_challenge_original_sha256`：同 `(challenger,responder,log)` 已呈签名挑战的整原 SHA；首个用 `GENESIS`。必须实际呈交前驱，不能自环、成环或跨关系嫁接。若同父签了两条，记录 fork。
- `nonce_hex`：32位小写 hex，全 audit 全局唯一，防止不同挑战重放；`issued_utc`：严格 UTC、不得早于被挑战 checkpoint 所声称的发行时间，不晚于审计 `gossip_evaluation_utc`，须在双审计员自签窗口内。
- `signature_ed25519_hex`：挑战方 Ed25519 真签所有上述主体，签名也属于 challenge 整原 SHA 的一部分。

### 3.3 真签 reply 原件

签名域 `CES/EC354/GossipReply/v1\0`，`schema=ces.ec354.signed_gossip_reply.v1`。精确字段：`schema`,`challenge_original_sha256`,`responder_auditor_id`,`responder_reference_original_sha256`,`log_id`,`response_kind`,`checkpoint_original_sha256`,`tree_size`,`root_hash_sha256`,`responded_utc`,`signature_ed25519_hex`。

`response_kind` 有且只有两种：

- `checkpoint_view`：回显已收到的该 log **整原 checkpoint SHA、tree size、root hash**；如果与 EC353 已出示已验的某张 checkpoint 精确相符，则记录 `verified_ec353_signed_witnessed_checkpoint_view`；若该 SHA 未在当前 EC353 出示库存中，则只能称 `signed_unfurnished_checkpoint_claim`，**不得作为已验证叉路**。如果 SHA 在库存而 root/size 不符，拒绝。
- `unavailable_claim`：必须将所有 checkpoint 字段设为 JSON `null`，记录 `signed_unavailable_claim`；这不是现实上的不存在证明，且无法代替真实原件。

回复者必须是真实挑战的**指定另一方**，不可让挑战方自己回应；回复绑定**挑战的整原 SHA**，不能复制到别的挑战或另一个 log。`responded_utc` 不早于挑战的 claimed UTC、不晚于审计 claimed UTC，且在回复方自签窗口内。可以提交 0 回复（未应答，显式报告）、最多 2 回复。两份签名真但内容冲突时保留两个原始 SHA 并标记 `signed_responder_equivocation_visible`，**不选最后一条**。

## 4. 签名视图对比及限制

1. 每次 challenge 本身是一次来自挑战方的**真签、EC353 已验 checkpoint 观察**。每次实际签署的 `checkpoint_view` reply 是另一位审计方的观察。只有具备真正原件的响应可补足两角色 coverage，且每份 log 都必须有至少一对已验证的双角色观察。不同日志的 Merkle root **不需要相同**；不同 log 不得按同 size 直接认定 fork。
2. 同一 log、同一 tree size 的两个独立签名观察若声称了两个**EC353 真实签名、独立 witness 验证**的不同 root，保留两个根和全部 checkpoint SHA，报告 `conflicting_verified_roots` / `verified_same_log_branch_conflict_visible`。只提供签名但**未出示**的声称 root 不能获得此结论。
3. 不同 size 的同一 log 两个已验 checkpoint 只有在 EC353 本次对该 log 的**真正 RFC6962 一致性**无未解决问题、无已签分叉时，且 SHA 前驱是可逐版追溯的祖先/后代，才标注 `verified_signed_ancestor_descendant_view`；否则是 `two_verified_checkpoint_branches_without_proved_ancestry`。
4. 明确区分 `matching_signed_tree_root`、`verified_signed_ancestor_descendant_view`、`verified_same_log_same_size_conflicting_roots`、`signed_unfurnished_claim_not_verified_log_view`、`signed_unavailable_claim`、`no_signed_reply`。所有被提供且签名不正确的原件必须**拒绝**，绝不因另一条正确回复而掩盖。
5. 结果包括逐份挑战及回复整原 SHA、逐日志 size 的**不同审计方/root/SHA**对照、gossip 签名 fork、同回复双签矛盾、未应答/不可用/缺原件、声称时间是否超过7天、声称组织是否重合、每日志已覆盖的两角色列表以及每个父 TSA channel 的 EC353→EC354 结果降级。任何 favorable 情况仍 `exit2/unresolved`。

## 5. 安全/环境边界

- 校验器只解释**本轮显式出示并被 SHA-pinned 的文件**；不能证明其它已签或未签 view 从未存在、某 HTTP 站点确曾响应或第三方确曾持有同样的原件。
- 新审计方自签身份声明、声称 timestamps 与日志/见证同机 fixture 均是本地可自生成的数据；真实第三方可靠密钥来源、机构关系、分布式跨机 custody 与受信 UTC 需要用户最终统一核验。
- 原始 PowerShell CLI 仍为 V4.60/R150；EC249 incomplete、EC250 blocked、B-001 OPEN、全局 Quality=false、final NOT_STARTED；旧 EC317/318 深层 fixture 历史 MOCK，原生 PS7/15 Smoke、跨系统、Provider/CAS/WORM writer 或非执行证据以及 E63–E66 性能都未凭本功能获得现实验证。
