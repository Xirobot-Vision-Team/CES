# EC326 — 第八独立身份离线签名的有条件争议冻结请求（无外部 CAS 写入）

## 场景和安全模型

EC325 证明的是两个不同的 **EC324 本地收件登记子头**依附同一个独立固定的原父头；其 unsigned 争议案卷不是组织授权，也不是赢家裁决。EC326 为此类已核对争议增加一个真正的第八 Ed25519 签名请求：向**指定但尚未连接**的外部登记空间提出 `request_conditional_dispute_hold_only_no_submission`，其唯一预设条件为：外部可信存储将来必须在自己的事务中**原子地比较当前头是否等于独立受信的预期原父头**。两个子头在请求中按完整 SHA 排序；不会任选其一为赢家，不会把本地签名等同于存储写成功。

这是**离线请求的创建、移交和完整再验**，不是可调用任意 URL 的网络适配器。项目没有用户提供的实际受信 CAS/WORM API、组织授权或远端当前头证明；本轮没有执行网络读取、compare-and-swap、WORM 写、授权决议、状态冻结或读回。未来由独立受信执行方处理请求，必须**另行实现**真正原子条件操作、存储端授权控制、远端响应的独立签名/读回及回滚保护；不能根据 EC326 离线输出直接设置 `committed`。

## 创建签名请求前必须从包外得到的信任信息

1. 原 EC325 unsigned 争议案卷的**整个原文件 raw SHA256**，以及 EC325 的双方头全 raw SHA、四个渠道 pin 全 raw SHA、两份 EC323 capsule、共同父头 raw SHA（序号≥2 须有原父快照）、独立 registry ID/sequence；双方渠道内必须能复查 EC321 的 12 个外部信任参数及原 EC322 第七方四个参数。
2. 预先选择**目标登记空间 ID**（`target-store-namespace-id`，仅本地符号范围，不接触任何远端）、新 `request-id`、新**第八签署者 ID 和公钥**、新 `request-challenge-sha256`。ID 仅接受小写字母开头、2–32 位的 `[a-z0-9_-]`。挑战值需在包外由可信主体另行生成并固定为非零小写 64 位 hex；本程序仅拒绝在当前两份签署历史**可见范围内**的重复，不证明全网或跨设备单调性。
3. 第八私钥文件应是受信签署者独立保管的 Ed25519 原始 32 字节私钥，正规文件 `0600`，并且与外部独立固定的第八公钥精确匹配；第八身份及公钥不得与可见原 custodian A/B、sender/receiver、registrar、witness、第七接收方和最新两渠道 operator 相同。代码验证字段独立性，**无法验证真人、机构授权或密钥持有设备实际独立**。
4. 目标请求输出 `--out` 和输入文件必须为规范绝对路径，私有父目录；本地只新建不覆盖，写入文件 `0600/O_EXCL`，刷新文件与目录。签发后应通过另一受信渠道**另外固定整份签名请求的原始 SHA**。不得只依赖请求自己包含的哈希、公钥和声称。

## 真正执行路径

签发 `sign-request` 执行顺序：校验参数、原件路径及外部信任字段，调用**生产 EC325 `verify_case`**，它双边重放 EC324→EC323→EC322→EC321→EC320→EC319→EC318→EC317→EC294 既有原签，并确保 EC325 unsigned 争议案卷能从双边原件逐字节重造，均为真实未决 `exit=2`；随后重读来源 capsule 内由原 SHA 验证的 EC321 ZIP / 两支签名快照，提取旧可见角色/挑战并拒绝复用；再次对所有当前原件 SHA 做后置校验；**完成这些步骤后才读取新私钥**并签署有界规范 LF JSON 声明。`sign-request` 不写任何外部状态。

接收端 `verify-request` 要求从包外独立固定的整份第八签名请求原 SHA、ID/pub/nonce/目标登记空间/父 SHA、EC325 案卷和**全套来源原件**。首先验证第八新签名（独立签名域 `CES/EC326/EighthIndependentOfflineConditionalConflictHoldRequest/v1\0`），阻止重签伪造 CAS success；然后对全部 EC325→EC294 原签重新验原、重做第八可见角色唯一性并逐字段重造完整 claim；最后复读原始请求文件 SHA。原案卷/渠道/父头任一变动，或修改一方、签名、请求条件、目标空间、原件 SHA、挑战值，就算自造新签名和新哈希也不会匹配**原先包外受信输入**。

请求的签名字段包含：`registry_id`、`sequence`、`expected_remote_parent_original_raw_sha256`、`dispute_case_original_raw_sha256`、按 SHA 排序的 **两个** `proposed_competing_child_raw_sha256`、target namespace、request/signer identity、public key、nonce、固定操作/条件字符串、**无远端提交/无组织权威/无赢家**的强制 `false` 标志。文件最大 16 KB；只允许规定的固定 schema、字段、规范原始 JSON。返回 `exit=2` 代表**争议与离线请求真实可验、但外部问题尚未解决**。

## 独立命令

所有参数中的目录和 SHA 均须使用真实原件/包外真值；方括号仅标注可选参数，不是字面输入：

```text
python3 scripts/ces_cas_conflict_hold.py sign-request \
  --out /private/hold-request.json \
  --private-key-file /private/eighth-ed25519.raw \
  --request-id <id> \
  --target-store-namespace-id <target_id> \
  --eighth-signer-id <eighth_id> \
  --eighth-signer-public-hex <independent_public_hex> \
  --request-challenge-sha256 <independent_nonce_sha> \
  --case-file /private/dispute.json \
  --expected-case-sha256 <externally_pinned_case_sha> \
  --registry-id <registry_id> \
  --expected-sequence <1..16> \
  --expected-prior-registry-sha256 <external_parent_sha_or_64_zeroes> \
  [--prior-registry-file /private/parent.json] \
  --left-registry-file /private/left-head.json \
  --left-expected-registry-sha256 <left_head_sha> \
  --left-capsule-file /private/left-capsule.zip \
  --left-origin-file /private/left-origin.json \
  --left-expected-origin-sha256 <left_origin_sha> \
  --left-recipient-file /private/left-recipient.json \
  --left-expected-recipient-sha256 <left_recipient_sha> \
  --right-registry-file /private/right-head.json \
  --right-expected-registry-sha256 <right_head_sha> \
  --right-capsule-file /private/right-capsule.zip \
  --right-origin-file /private/right-origin.json \
  --right-expected-origin-sha256 <right_origin_sha> \
  --right-recipient-file /private/right-recipient.json \
  --right-expected-recipient-sha256 <right_recipient_sha>
```

只读独立验签：把上面 `sign-request` 换成 `verify-request`，**删除** `--out` 和 `--private-key-file`，**新增** `--request-file /private/hold-request.json --expected-request-sha256 <independent_whole_signed_request_sha>`。其余参数全部保持一致；更换左右顺序仍会得到相同双 SHA 排序的签名声明。

最小权限统一控制台：

```text
python3 scripts/ces_next.py audit-conflict-hold \
  DeliveryAudit VerifySignedConditionalConflictHoldRequest \
  --request-file /private/hold-request.json \
  --expected-request-sha256 <independent_whole_signed_request_sha> \
  ...与 verify-request 其余相同的来源及外部 trust 参数...
```

统一控制台仅固定执行 `-I -B` 的 `verify-request` 子进程；不接受签名、私钥、`--out`、网络 endpoint、凭据、业务写或远端 CAS 写。旧控制台所有命令原样保留，旧 PowerShell V4.60/R150、Router 74 路 / 11 条 HOST_REQUIRED 未变。

## 错误和最终待验

`exit=2`：确实验过完整 EC325 争议案卷与第八签名请求（仍 **UNRESOLVED / REQUEST ONLY**）；`exit=3`：信任、签名或权限拒绝；`exit=4`：请求结构/路径/字段不合法；`exit=5`：缺陷、资源不可用或环境故障。任何一条都不是 `committed` / `winner` / `remote hold persisted`。

本轮本地 19/19 例定向执行 PASS：真实第 5/6/7/8 Ed25519；继承的轻量 EC321 fixture **模拟旧 EC317/318 深层验签**，不能当成全生产原件真签全链。独立 `-I -B` 进程运行这套模拟原件时按预期 **fail closed（exit=4）**，没有误报成功；实际未模拟的生产原链、真实授权机构、双人双机/包外 SHA 可信托管、跨 OS、PowerShell7 Smoke15、Provider/CI/E63–E66、外部线性化 WORM/CAS/读回及最终验收均留到统一用户协助验证。
