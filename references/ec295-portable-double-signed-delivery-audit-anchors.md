# EC295：可移机核验的投递审计锚点与回滚对照——独立操作手册

**版本：V6.05 / R295 / EC295。** 本轮新增的都是**离线封存和核验代码**：不打开 Provider Token、EC227 HMAC 秘钥、不访问 Unix Host、不联网、不触发原 EC225 `/submit`、不触发原 EC226 `/status`、不修改原审计。原 EC294 仍是**唯一**能够使用原 EC227 HMAC 秘钥读写原本地链并签发结果的 Host。离线 EC295 仅能验证“此前 EC294 的签名声称经校验的链头”及两名新的签名角色，不能自行证明现在磁盘或生产邮箱已验证。

## 0. 权威概念与要求

- **源证据**：保存 `scripts/ces_next.py host-delivery-reconcile ...` 或 `scripts/ces_delivery_reconcile_host.py submit ...` 的**完整 JSON 标准输出**（只接受已签回且 `ces.ec294.verified_private_delivery_reconciliation.v1` 且原 EC227 `partial/2` 和 `audit_chain_verified=true`）。连同**对应的原 EC294 完整两票 `grant` 文件**和 `Record` 模式的**原 EC226 READ 文件**，才足够重建一次原 EC294 原请求并核验 nonce、request SHA、Job、Policy、原 EC294 server Ed25519 签名和业务语义。**仅有一串 HMAC 头是不足够的。**
- **两个新线下角色**：EC295 keeper 与 witness 的两把**不同 Ed25519 公钥**，并与 EC294 server/custodian/auditor 公钥两两不同。此数学约束不等于两个真实独立自然人或物理隔离机器。证书签名都以 `CES/EC295` 新域和精确 claim 对签。
- **检查点**：含完整源证据、此前检查点 SHA、递增序号、原审计条数/头及两张新签名。新检查点必须较上一检查点**增加**审计条数并改变链头；同一观测不能伪装成新的进展。原 EC227 最多 64 条，本轮最多 64 个检查点，不自动裁剪或清链。
- **外部独立 pin**：创建完成后请另行、脱离原审计主机，使用具防删除/回滚权限控制的系统同时保存检查点文件和 `signed_checkpoint_tip_sha256`（原始 JSON **规范化内容**的 SHA256，不是文件尾换行的 SHA）。**没有这个独立可信的 tip，不能称有防回滚性质。** 内建的离线核验命令要求显式 `--expected-tip`；若对手能同时替换检查点和外部 tip，本功能无法检测。
- **不改变投递含义**：`historical_delivery_state` 永远是旧签名观测/旧历史状态，不是当前或生产已送达。`UNKNOWN_UNCONFIRMED`、Provider `ACCEPTED` 和独立 Inbox observation 的边界延续 EC294 原定义。

## 1. 准备私有保管位置与两把新线下签名

下列均在**解压的 CES 根目录**执行。以真实部署 UID、独立签名设备和可信私有 POSIX 文件系统为准，示例路径均需替换，示例不可作为真实授权。

```bash
mkdir -m 700 /secure/ec295-custody
python -I -B scripts/ces_delivery_anchor.py keygen-offline --private-out /secure/ec295-custody/keeper.key
python -I -B scripts/ces_delivery_anchor.py keygen-offline --private-out /secure/ec295-custody/witness.key
```

命令只返回对应 `public_hex`，不打印私钥。keeper/witness 应在两个独立保管环境执行签名，签名的 `prepared` 文件需通过可验证的离线路径分别交付。

从已独立核定的原 EC294 grant 的 `subject` 中取 `operation_id` 和 `job_sha256`；从 EC294 策略的可信 SHA 获得 `EC294_POLICY_RAW_SHA`。EC295 只读取原 EC294 **政策的公钥/源码摘要**，**不读取**私有原 HMAC 审计秘钥或 Provider 只读凭据：

```bash
python -I -B scripts/ces_delivery_anchor.py prepare-policy \
  --original-policy-file /secure/ec294-policy.json \
  --original-policy-sha256 <EC294_POLICY_RAW_SHA> \
  --operation-id <ORIGINAL_OPERATION_ID> \
  --job-sha256 <ORIGINAL_JOB_SHA256> \
  --keeper-public-hex <KEEPER_PUBLIC_HEX> \
  --witness-public-hex <WITNESS_PUBLIC_HEX> \
  --out /secure/ec295-custody/policy.json
```

将输出的 `policy_sha256` 原始文件 pin 交由**外部/离线保管**；后续所有步骤都需要该 SHA，缺失不得静默改为当地文件 hash。

## 2. 第一个双签检查点

原 EC294 `Record` 已独立授权、完成且其 JSON 响应有 `audit_chain_verified=true`、`status=partial`、有实际非零头，并由操作员准确保存为 `/secure/ec295-custody/294-response-1.json`；同时**保留这一次的原 EC294 `grant` 及 EC226 `READ` 原件**。若原 EC294 返回未知/签名失败/没有 ACK、仅有一条未证实的暂存、返回拒绝，**不可“造”一张成功签名回执**：先保全原现场，再由本来有权限的角色另行审批本地 EC294 Readback，不能重新 Submit。

```bash
python -I -B scripts/ces_delivery_anchor.py prepare \
  --policy-file /secure/ec295-custody/policy.json \
  --policy-sha256 <EC295_POLICY_RAW_SHA> \
  --response-file /secure/ec295-custody/294-response-1.json \
  --grant-file /secure/ec295-custody/294-grant-1.json \
  --read-grant-file /secure/ec295-custody/ec226-read-1.json \
  --out /secure/ec295-custody/prepared-1.json
python -I -B scripts/ces_delivery_anchor.py sign-keeper-offline \
  --policy-file /secure/ec295-custody/policy.json \
  --policy-sha256 <EC295_POLICY_RAW_SHA> \
  --prepared-file /secure/ec295-custody/prepared-1.json \
  --private-key-file /secure/ec295-custody/keeper.key \
  --out /secure/ec295-custody/keeper-vote-1.json
python -I -B scripts/ces_delivery_anchor.py sign-witness-offline \
  --policy-file /secure/ec295-custody/policy.json \
  --policy-sha256 <EC295_POLICY_RAW_SHA> \
  --prepared-file /secure/ec295-custody/prepared-1.json \
  --private-key-file /secure/ec295-custody/witness.key \
  --out /secure/ec295-custody/witness-vote-1.json
python -I -B scripts/ces_delivery_anchor.py assemble \
  --policy-file /secure/ec295-custody/policy.json \
  --policy-sha256 <EC295_POLICY_RAW_SHA> \
  --prepared-file /secure/ec295-custody/prepared-1.json \
  --keeper-vote-file /secure/ec295-custody/keeper-vote-1.json \
  --witness-vote-file /secure/ec295-custody/witness-vote-1.json \
  --out /secure/ec295-custody/checkpoint-1.json
```

`assemble` 返回 `signed_checkpoint_tip_sha256`。应将此检查点和 tip **移交外部独立存储**；写在原 EC294 宿主同一目录里仅是文件整理，不是防回滚锚定。失去上一次外部 tip 时暂停；**不要**接受从可疑本地目录新算出的 tip。

在不接触审计 HMAC 秘钥、甚至原 Host 不在场时，可离线重验：

```bash
python -I -B scripts/ces_next.py audit-anchor DeliveryAudit Verify \
  --policy-file /secure/ec295-custody/policy.json \
  --policy-sha256 <EC295_POLICY_RAW_SHA> \
  --checkpoint-file /secure/ec295-custody/checkpoint-1.json \
  --expected-tip <INDEPENDENTLY_PRESERVED_SIGNED_CHECKPOINT_1_TIP_SHA>
```

## 3. 后续新增检查点（真实原审计条数必须增加）

必须有**新一次独立授权且真实成功的 EC294 Record/Readback 原签名回执**，以及上次外部保存的**完整签名检查点和外部可信 tip**。前一次已有 2 条、再次真实 Record 后有 4 条，可如下继续：

```bash
python -I -B scripts/ces_delivery_anchor.py prepare \
  --policy-file /secure/ec295-custody/policy.json \
  --policy-sha256 <EC295_POLICY_RAW_SHA> \
  --response-file /secure/ec295-custody/294-response-2.json \
  --grant-file /secure/ec295-custody/294-grant-2.json \
  --read-grant-file /secure/ec295-custody/ec226-read-2.json \
  --previous-file /secure/ec295-custody/checkpoint-1.json \
  --expected-previous-tip <INDEPENDENTLY_PRESERVED_CHECKPOINT_1_TIP_SHA> \
  --out /secure/ec295-custody/prepared-2.json
# 分别由不同角色 sign-keeper-offline、sign-witness-offline，最后 assemble 到 checkpoint-2.json。
python -I -B scripts/ces_next.py audit-anchor DeliveryAudit Verify \
  --policy-file /secure/ec295-custody/policy.json \
  --policy-sha256 <EC295_POLICY_RAW_SHA> \
  --checkpoint-file /secure/ec295-custody/checkpoint-1.json \
  --checkpoint-file /secure/ec295-custody/checkpoint-2.json \
  --expected-tip <NEW_SEPARATELY_PINNED_CHECKPOINT_2_TIP_SHA>
```

`Verify` 要求按序提供从首个检查点起的**完整**链；若删去尾部检查点并尝试用旧 tip 冒充最新，检查会拒绝；但工具**不能确认**操作员提供的外部 tip 一定是不可变/最新的真实真值。

## 4. 用**另外授权的新 EC294 Readback**与外部锚点比较

先在可信外部时钟记录 `MINIMUM_REPLY_UNIX`；之后由原 EC294 流程为**最新、已知外部独立 pin 的 `audit_head_hmac_sha256`**重新签 `Readback` 两票并调用 **一次**原 EC294 Readback。它不加载只读 Provider token、不请求远端状态、不追加原 EC227 HMAC 记录。将本次 EC294 原 JSON 输出及原 grant **分别**保存在新的文件（不能使用旧 Record 的凭证和票）。

```bash
python -I -B scripts/ces_next.py audit-anchor DeliveryAudit Compare \
  --policy-file /secure/ec295-custody/policy.json \
  --policy-sha256 <EC295_POLICY_RAW_SHA> \
  --checkpoint-file /secure/ec295-custody/checkpoint-1.json \
  --expected-tip <TRUSTED_LATEST_SIGNED_CHECKPOINT_TIP_SHA> \
  --response-file /secure/ec295-custody/294-new-readback-response.json \
  --grant-file /secure/ec295-custody/294-new-readback-grant.json \
  --minimum-reply-unix <INDEPENDENTLY_RECORDED_START_UNIX_TIMESTAMP>
```

若有两张历史检查点，必须按序重复 `--checkpoint-file`；最后一张的 HMAC 头与条数必须**完全等于**最新 EC294 签名 Readback 的原审计结果，且新回执时间必须晚于上次封存回执并不早于外部指定阈值。该步骤离线执行，**只验证 EC294 Host 给出的新签名声称**，未在本离线进程重新读取原审计磁盘或独立校验可信 UTC。任何失配/ACK 丢失都应判为需人工核查，禁止自动发送、重试或“修复”日志。对已新增长度的合法审计，请先将新增证据封存成新检查点，再执行对照。

## 5. 安全、失败和联合验收

- 文件全部以**绝对路径、独占新建 `0600`、fsync** 写入。请使用受控的 `0700` 私有目录；**不要共享两把私钥**或在仓库中提交票据、HMAC/Token/收件目标私有信息。离线转移使用具有适当访问控制的安全媒介。
- 原 EC294 的 `Record` 查询可产生网络读取，且业务 `POST /status` 不等同于 `/submit`；**EC295 不做任何请求**。原 EC294 `/submit` 一次性发生与否仍只由原 EC225/288 的历史证据决定，绝不因本锚点重发。
- 签名、HMAC 与外部 tip 能让未经授权的改写和**已知道的较新头被较旧截断**发生冲突；不能证明**外部媒介确已保管、抵御同一管理员控制全部角色、历史服务器私钥始终未泄露、实际 Provider 送达**。
- 无真实独立管理员/机器/UTC、WORM/异地备份、生产级 ACL/fsync/断电、多节点调度、原 PowerShell7 15 Smoke、Windows/macOS、远端 Provider/Inbox/TLS 和最终业务验收。EC249 `FULL_FUNCTION_NOT_COMPLETE`，EC250 `BLOCKED`，B001 `OPEN`，final `NOT_STARTED`，global Quality PASS=false 保持不变。

[本轮 EC-295](../EC-295.md) · [范围](../construction/EC295_SCOPE.json) · [本地开发报告](../construction/EC295_LOCAL_REPORT.json) · [全包文件 SHA256](../construction/EC295_DELIVERY_SHA256.json)
