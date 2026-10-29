# EC327 — 外部第九方线下「未执行」处置真签回执：原字节与完整 EC326 历史只读验证

## 能验证什么 / 不能验证什么

适用于外部*独立持钥*处理者已经另行提供一个**离线审阅处置**文档，声明其对确切 EC326 条件请求选择 `deferred_without_submission` 或 `declined_without_submission`。本协议验证其**真 Ed25519 签名、信任公钥、确切签名内容、原件 pin 和完整 EC326→EC325→EC294 证据的一致性**。它不生成真实外部回执，不发网络请求，不向外部登记写数据，也不确认该组织真实获授权或实际没有执行过操作。即使返回 `exit=2`，仅代表**签名文档与已给证据真实一致，但争议未裁决**。

此处“外部第九方”是**需要真正受信机构从包外认定的角色**，不是本程序可以通过某个本地签名来创造的外部授权身份。若没有真实提供的第九方已签原文件，本 EC 的只读验签器只能拒绝缺输入；测试里生成的第九签名只证明密码学路径可运行，不是生产 CAS 证据。尤其不能把 signed `deferred_without_submission` 推断为原子事务中已确认没有远端写。实际可证明成功的冻结仍需未来独立授权执行器、存储服务自己原子地比对当前头、独立远端读回和反回滚机制。

## 回执的规范原件（必须由独立签署方出具）

- 原始文件：最大 12,000 字节、UTF-8 ASCII JSON、字段字典序、紧凑编码、末尾一个 LF（与 CES `reg.raw_doc` 完全相同），不能有重复键、BOM、未知字段、额外空白。原件位置为 owner-private 的绝对规范文件路径，建议 `0600`。由第二受信渠道另外固定**整份原文件 SHA256**；`--expected-receipt-sha256` 不能从待验证文件本身临时自算成“独立”信任。
- 外层字段**恰好**：`schema`=`ces.ec327.ninth_offline_no_execution_disposition_receipt.v1`、`claim`、`signature_ed25519`（小写 128 hex）。Ed25519 输入为**原始签名域字节** `b'CES/EC327/NinthOfflineNonExecutionDisposition/v1\x00'` 加上 `claim` 的 `json.dumps(..., sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')`。新签名域与旧第八请求完全不同。
- `claim.schema`=`ces.ec327.ninth_offline_no_execution_disposition_claim.v1`；外部**单独选择并固定** `decision_id`、`ninth_responder_id`、`ninth_responder_public_hex`、`response_challenge_sha256`、`disposition`、`reason_code`，不可由签名文件反过来决定信任。ID 限制 `[a-z][a-z0-9_-]{1,31}`，pub 为真正 Ed25519 32 字节小写 hex，challenge 为非零小写 64 hex。
- `disposition` 严格允许 `deferred_without_submission` / `declined_without_submission`。`reason_code` 严格允许 `awaiting_authorized_external_executor` / `declined_by_local_reviewer` / `external_transaction_evidence_unavailable`。这些是线下审核声明，并非远端事务历史。所有身份与处置值都必须和包外期望相同。
- 需要与 EC326 第八真实 signed claim/包外原文件相等的字段：`signed_request_original_raw_sha256`, `dispute_case_original_raw_sha256`, `request_id`, `request_challenge_sha256`, `eighth_signer_id`, `eighth_signer_public_hex`, `target_store_namespace_id`, `registry_id`, `sequence`, `expected_remote_parent_original_raw_sha256`, `proposed_competing_child_raw_sha256`。两个子头按完整原 SHA 从小到大排序。不能以回执内容自带的 `request sha`/公钥当外部 pin。
- `offline_review_only` 必须精确为布尔 `true`。以下布尔必须全部精确为 `false`：`external_store_contacted_or_atomic_cas_attempted`、`actual_remote_hold_or_nonexecution_independently_proven`、`remote_head_or_global_latest_verified`、`any_child_winner_or_business_commit_proven`、`organization_authority_or_cross_device_uniqueness_proven`。任何被重签为 `true`、塞入成功字段/未知状态的文档必拒绝；即使文件有真的第九签名也不能升级为成功。

## 完整只读复验所需的**真实包外**输入

将已经独立得到的第九签名文档原件与 whole SHA、第九 ID/pub/nonce、decision 和原处置结果的信任值传入；同时传递 EC326 **已签请求原文件/独立 whole SHA**、第八 ID/pub/nonce/target、EC325 原案卷/独立 whole SHA，双方完整 EC324 子头+两份频道文件+EC323 capsule、原 registry ID/序号/共同原父 SHA；sequence≥2 还必须给独立受信的原父 snapshot。EC324 原频道内历史的 EC321 12 pins 和 EC322 第七方四项 trust 会再次在完整真签重演中检查。不存在默认信任、隐式读回远端或从签名回执自证的可信外部服务。

执行命令（示例只列新增与共同项；`LEFT/RIGHT` 请使用 EC326 文档中的**全部 7 个**原件参数，各自独立 SHA，其他原始信任值不得省略）：

```text
python3 scripts/ces_cas_hold_disposition.py verify-nonexecution \
  --receipt-file /private/ninth-offline-disposition.json \
  --expected-receipt-sha256 <INDEPENDENT_WHOLE_NINTH_RAW_SHA> \
  --decision-id <trusted_decision_id> \
  --ninth-responder-id <trusted_ninth_id> \
  --ninth-responder-public-hex <trusted_ninth_pub> \
  --response-challenge-sha256 <trusted_fresh_nonce> \
  --expected-disposition deferred_without_submission \
  --expected-reason-code awaiting_authorized_external_executor \
  --request-file /private/eighth-signed-request.json \
  --expected-request-sha256 <INDEPENDENT_WHOLE_EIGHTH_RAW_SHA> \
  --case-file /private/ec325-sibling-dispute.json \
  --expected-case-sha256 <INDEPENDENT_WHOLE_CASE_RAW_SHA> \
  --registry-id <trusted_registry_id> \
  --expected-sequence <1..16> \
  --expected-prior-registry-sha256 <trusted_parent_sha_or_zero_for_genesis> \
  --request-id <trusted_request_id> \
  --target-store-namespace-id <trusted_target_namespace> \
  --eighth-signer-id <trusted_eighth_signer_id> \
  --eighth-signer-public-hex <trusted_eighth_pub> \
  --request-challenge-sha256 <trusted_eighth_nonce> \
  --left-registry-file ... --left-expected-registry-sha256 ... \
  --left-capsule-file ... --left-origin-file ... \
  --left-expected-origin-sha256 ... --left-recipient-file ... \
  --left-expected-recipient-sha256 ... \
  --right-registry-file ... --right-expected-registry-sha256 ... \
  --right-capsule-file ... --right-origin-file ... \
  --right-expected-origin-sha256 ... --right-recipient-file ... \
  --right-expected-recipient-sha256 ... \
  [--prior-registry-file /private/actual-original-parent.json]
```

使用统一最小权限控制台时，参数与 `verify-nonexecution` 完全相同：

```text
python3 scripts/ces_next.py audit-hold-disposition \
  DeliveryAudit VerifyOfflineNoExecutionHoldDisposition \
  --receipt-file ... --expected-receipt-sha256 ... \
  --decision-id ... --ninth-responder-id ... --ninth-responder-public-hex ... \
  --response-challenge-sha256 ... --expected-disposition ... \
  --expected-reason-code ... --request-file ... --expected-request-sha256 ... \
  ...全部EC326原件与独立信任参数...
```

控制台实际硬编码 `python -I -B <local fixed script> verify-nonexecution`，不提供 `sign`、`--out`、私钥、URL、socket、外部 store 凭据或任何写权限。正常离线声明签名/源真签有效返回 **`exit=2`** 且 `remote...=false`；权限/信任/签名拒绝 **`3`**、输入结构/路径拒绝 **`4`**、真实环境不可用 **`5`**。从不返回 committed/winner 状态。

## 当前施工事实

22/22 新聚焦定向用例与 EC326 19 + EC325 15 合计 **56/56 PASS**。第九和第八（以及上游第五至第七）Ed25519 在本地结构 fixture 真正执行，攻击用例覆盖完整签名、重新签的造假成功、角色/nonce、双 parent 和同父 sequence2、旧原件缺失、回执替换、严格只读子程序。**旧 EC317/318 深链在 inherited test fixture 内 mock**；真实全原材生产签名链、真实组织授权、外部线性化 CAS/WORM/独立 remote readback、双设备、PowerShell7/Smoke15、跨 OS、Git/CI/E63–E66 和最终人工验收 **NOT_RUN**。使用模拟 fixture 的真实独立 `-I -B` 进程**正确拒绝 exit4**，不能叫生产全链通过。历史 EC249 incomplete、EC250 BLOCKED、B001 OPEN、Quality PASS=false、final NOT_STARTED 不变。
