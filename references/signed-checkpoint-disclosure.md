# EC355 — 离线原始检查点披露：原回应者 + 第三审计员，真签、原字节、见证与 RFC6962

## 证据边界

EC355 专门处理 **EC354 中真实 Ed25519 验签、却不在 EC353 已提供材料内**的 `signed_unfurnished_checkpoint_claim`。每次调用**实际重新跑 EC354→EC353→EC337** 的历史原件验证，不接收 `EC354_LOCAL_REPORT`、旧审计 JSON 或文字声明替代原始字节。随后将同一条 EC354 `gossip_reply_original_sha256` 同时通过两条签名请求发往：**原 responder** 与**非原 challenger、非原 responder 的第三名 auditor**。第三名仅指其 Ed25519 角色/自报身份不同，不证明实际组织或物理独立。

所有用到的请求、回执、真实 checkpoint、witness、可选一致性证明都必须通过**调用者显式给出的绝对路径与精确整文件 SHA256**重新读取。`offer_only`、`unavailable_claim`、沉默的请求，**即使已真签**，仍然绝不自动变成被见证 checkpoint。只有重新读出的真实 EC353 checkpoint 签名、对应 EC353 witness 签名、精确 SHA/长度与原 EC354 声称 root/size 都核对通过，才记 `verified_furnished_original`。

无签名器、密钥生成、HTTP 客户端、自动取件、log writer、Provider/CAS/WORM 访问或 final approval。自签密钥、机构名称、HTTP URL 字符串、签名时间只能作为离线局部证据；官方独立机构、原材料全网收齐、实际物理 custody、可信 UTC、生产 EC317/318、官方根和最终验收一律 **NOT_PROVEN**。任何合法成功导入的顶级 `exit_code=2`、状态以 `_unresolved` 结尾。

## CLI 与历史完整参数

```sh
# 需要 EC354 audit-cross-log-gossip 的全部历史参数；绝不改用过去的成功结果 JSON
python -I -B scripts/ces_cas_checkpoint_disclosure.py derive-disclosure-handoff \
    <全部 EC354 audit 参数>

python -I -B scripts/ces_cas_checkpoint_disclosure.py audit-checkpoint-disclosures \
    <全部 EC354 audit 参数> \
    --checkpoint-disclosure-evaluation-utc 2026-10-25T23:50:00Z \
    --checkpoint-disclosure-bundle-file /trusted/pins/disclosure-bundle.json \
    --expected-checkpoint-disclosure-bundle-sha256 <64位小写SHA256>

python -B scripts/ces_next.py audit-checkpoint-disclosures \
    DeliveryAudit AuditSignedCheckpointDisclosures \
    <全部上述 audit-checkpoint-disclosures 参数>
```

`--help` 显示 EC337 开始的全部祖先参数。新 `checkpoint_disclosure_evaluation_utc` 特意不同于旧 EC345 既有的 `disclosure_evaluation_utc`；不能覆盖祖先时间。所有评估 UTC 是自报而非受信时间。严格 `-I -B` 子进程、JSON 响应码与 `schema` 契约，统一入口只授权固定 DeliveryAudit/Mode；拒绝伪写能力。

## Pinned Bundle（严格规范 JSON）

整个 bundle 必须为现有 `ec319 ... canonical()` 规则：单一 canonical JSON、无 BOM/换行尾、重复键、NaN、额外字段；文件原字节 SHA-256 事先独立 pin。最多 24 个 request、36 个 receipt、每 request 最多 2 个签名 receipt、同 `(claim_sha, role, target)` 最多 2 个 SHA 串联轮次；EC354 输入最多 12 条目标未出示回复。例示完整结构：

```json
{
  "schema": "ces.ec355.pinned_checkpoint_disclosure_bundle.v1",
  "requests": [
    {
      "request": {"path": "/evidence/request-1.json", "sha256": "<request原件SHA>"},
      "responses": [
        {
          "receipt": {"path": "/evidence/receipt-1.json", "sha256": "<receipt原件SHA>"},
          "checkpoint": {"path": "/evidence/checkpoint.json", "sha256": "<checkpoint原件SHA>"},
          "witness_statement": {"path": "/evidence/witness.json", "sha256": "<witness原件SHA>"},
          "consistency_proof": {"path": "/evidence/consistency.json", "sha256": "<consistency原件SHA>"}
        }
      ]
    }
  ]
}
```

缺回执使用 `responses: []`。`offer_only` 或 `unavailable_claim` 类型的回执，只允许其他三个材料指针全部为 `null`；`furnished_originals` 必须提供 checkpoint + witness 两个原始文件；一致性证明可为 `null`，但缺它不能声称新的 append-only 关系。**同一 SHA 的两份接收人副本须提供两个不同的路径**；路径别名不允许冒充两次独立测量，跨物理机器存在性仍不证明。

### 请求原件

`request` 为完整 canonical JSON，严格如下字段（所有字段不可多不可少）：

```json
{
  "schema":"ces.ec355.signed_checkpoint_disclosure_request.v1",
  "request_id":"request_a_001",
  "parent_gossip_bundle_original_sha256":"<完整EC354 gossip bundle SHA>",
  "gossip_challenge_original_sha256":"<该条EC354真的已验challenge SHA>",
  "gossip_reply_original_sha256":"<该条EC354真的已验unfurnished reply SHA>",
  "log_id":"log_a",
  "claimed_checkpoint_original_sha256":"<该reply所声称checkpoint SHA>",
  "claimed_tree_size":4,
  "claimed_root_hash_sha256":"<该reply声称root SHA>",
  "requester_auditor_id":"auditor_a",
  "requester_reference_original_sha256":"<EC354已验请求方自签ref SHA>",
  "requested_auditor_id":"auditor_b",
  "requested_reference_original_sha256":"<EC354已验目标自签ref SHA>",
  "requested_role":"original_responder",
  "previous_request_original_sha256":"GENESIS",
  "nonce_hex":"00112233445566778899aabbccddeeff",
  "issued_utc":"2026-10-25T23:10:00Z",
  "signature_ed25519_hex":"<128位Ed25519签名十六进制>"
}
```

签名消息是 `b"CES/EC355/CheckpointDisclosureRequest/v1\\x00" + canonical(JSON不含signature_ed25519_hex)`，其中 `\\x00` 表示一个真正的 0x00 字节而非字符斜线。实际字段值须来自 **本次重演 EC354**，签名者必须是**原 EC354 challenger**，`original_responder` 目标必须是原 responder；`independent_peer` 目标必须是第三名。每条 claim 分开做两个独立 signed requests，目标的 `reference_original_sha256` 不可偷换。全 EC355 请求 ID 和 nonce 唯一，同目标两轮通过 `previous_request_original_sha256` 链接，真实同父双请求作为 signed fork 留存，不择胜者。

### 接收回执原件

```json
{
  "schema":"ces.ec355.signed_checkpoint_disclosure_receipt.v1",
  "request_original_sha256":"<该请求整原SHA>",
  "gossip_reply_original_sha256":"<该EC354旧回复SHA>",
  "respondent_auditor_id":"auditor_b",
  "respondent_reference_original_sha256":"<auditor_b 已验 ref SHA>",
  "log_id":"log_a",
  "response_kind":"furnished_originals",
  "checkpoint_original_sha256":"<与旧claim一致的checkpoint真实SHA>",
  "witness_original_sha256":"<实际提交的witness整原SHA>",
  "claimed_checkpoint_length":1234,
  "claimed_witness_length":456,
  "responded_utc":"2026-10-25T23:12:00Z",
  "signature_ed25519_hex":"<签名>"
}
```

真实私钥签名的域：`CES/EC355/CheckpointDisclosureReceipt/v1\0` 加相同 canonical 去签名 JSON；不能拿 EC354 签名跨域代用。回执必须为被请求者本人在其 EC354 已验 key/ref 的有效期内作答，签名时间声明不早于请求声明时间。`offer_only` 和 `unavailable_claim` 的 `checkpoint_original_sha256` 仍填该 claim 的 SHA，但 `witness_original_sha256`、两个长度一律 `null`，manifest 的三个文件指针也一律 `null`。

## 何时可称“已验”，何时不行

1. 父 EC354 每次重新检查 EC353→EC337 的真签、log/witness、RFC6962 和整原 SHA；新文件不得复用任何祖先路径及本次其他证据路径，并在结论前全部晚期重读。
2. `furnished_originals` 先检查回执 SHA/长度及指定二份原始字节；再以从本次父 EC353 已验 bundle 读取的 log 公钥/自签引用真实验证 **checkpoint 原始 Ed25519 log 签名**，以对应见证公钥/自签引用真实验证 **witness 原始 Ed25519 签名**绑定确切的整个 checkpoint SHA、root/size、时间声明。
3. 仅同一 log 同一 tree size 可比较根；不同 log root 不得称为 fork。相同 size、不同 root 的两份真签见证视图标记 `verified_same_log_same_size_conflicting_roots`；真实相等仅标记 `verified_matching_same_size_root`。
4. 当新的 size 更大，只有 checkpoint 通过签名指向此次 EC354 挑战的父 checkpoint SHA，且真的重算 RFC6962 consistency proof，才能标记 `verified_rfc6962_append_only_relative_to_challenged_parent`。缺证据标记 `verified_signed_checkpoint_witness_but_append_only_unproven`；虚构或错链的 consistency 原件直接拒绝。
5. 原先自报的 gossip 回复时间如果早于后来 checkpoint 的已签发行时间，记录 `claimed_time_order_anomaly`，不假装当时已见到此文件。显示缺少双目标请求、无回执、只报 offer、已签 unavailable、不同回执 equivocation、同前驱分叉、时钟过期等；均不推定世界上没有原件。
6. 最佳状态也仅是两位签名者分别**出示同一内容的真实可验证副本**，不是两台机器、两个真实法律实体、可信外部原始固定、全网最新 head、官方签署或最终冻结。最终 `status=..._unresolved`、`exit_code=2`。

## 交付与人工补证清单

实现：`construction/disclosure/disclosure.py`；固定只读操作入口：`construction/disclosure/operator.py` / `scripts/ces_cas_checkpoint_disclosure.py` / `scripts/ces_next.py`；综合测试：`construction/disclosure/test_disclosure.py`。本轮测试事实记载于 `construction/EC355_LOCAL_REPORT.json`，不可把 LOCAL SYNTHETIC 当作真外部机构见证。待人工统一做真实多机构认证密钥与 SHA custody、真实外部日志/站点取件与完整性、受信时钟/TSA/CRL/OCSP、EC317/318 非 mock、PowerShell7 原15 Smoke、Windows/macOS/Git/CI/Provider/E63–E66、真实 CAS/WORM 以及最终验收。**旧 EC249 INCOMPLETE、EC250 BLOCKED、B001 OPEN、Quality=false、final NOT_STARTED 不改变。**
