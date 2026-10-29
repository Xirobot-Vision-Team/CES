# EC305 — 受独立治理的离线 registrar 换钥与跨 epoch 防重放

**版本：CES V6.15 / R305 / EC305。** 此说明覆盖独立离线脚本 `scripts/ces_registrar_rollover.py`。旧 `ces_challenge_registry.py` 的 EC304 API、账本字段及已有记录字节完全不变。

## 适用范围与安全模型

EC304 的账本将 registrar 公钥固定在整份账本中，更换 registrar 不能仅在该账本追加一条新公钥记录。EC305 采用**冻结旧 EC304 账本 + 三角色域分离签字的换钥证书 + 新公钥签发的独立 EC304 账本**。`register`/`verify` 每次重验旧账本所有旧 registrar 签名、换钥证书的相关签名、新 epoch 全部 registrar 签名以及**最新 EC303→EC294 原始真签链**；还会对旧、新 epoch 两份完整账本逐条检索重复 challenge SHA 和 ACK raw SHA。

- **计划换钥**（`cutover_mode=planned`）需旧 registrar、激活 registrar、外部独立治理 governor 三角色各用自己的 32 字节 Ed25519 私钥分别签名。
- **紧急旧钥疑似失陷**（`cutover_mode=emergency_compromised`）明确**禁止旧 registrar 投票**，须预先可信的 governor 与新 registrar 双签。**不能仅凭原旧钥自签进行恢复。** governor 的真实授权组织地位必须由包外事先确认。
- 换钥声明签入：登记簿 ID、旧/新/governor 三个公钥、**旧账本完整 raw SHA 和 seq**、包外一次性 cutover nonce SHA、包外治理决议 SHA、换钥模式。各角色签名使用互不相同的 EC305 域。
- 全部输出使用 owner 0700 目录中的 0600 不覆盖新文件、O_EXCL/fsync；不在证书中放入私钥、路径或完整用户交接凭据。
- 每次**治理后的**注册/验证必须传**来自独立保管方**的换钥证书 raw SHA、旧账本 raw SHA+seq、最新新账本 raw SHA+seq（首次注册显式 `(GENESIS, 0)`）。不得让被验证文件自我指定可信 SHA。
- 本轮只实现从**一个已有 EC304 registrar epoch 到一个新 epoch**。更长的连续多次 registrar 换钥、多治理密钥代际轮换需下一 EC 的显式格式，不得靠修改旧证书或绕开本包装器。
- EC304 原独立工具本来就能使用旧私钥继续产生另一条签名分叉，EC305 **无法让那把私钥停止签名**。只有包外已宣布且不可回滚的最新换钥证书与受治理的 `verify` 消费者，才把旧钥排除在**本次新 epoch 的授权认可**之外；不是网络级吊销、真实组织身份证明或 CAS/WORM。

## 准备独立锚点

以下每次操作都要求重复传递这一组独立信任参数，**不能从 intent/certificate/ledger 文件推导成可信外部值**：

```text
--old-ledger-file /absolute/private/old-ledger-0002.json
--expected-registry-id <existing-registry-id>
--expected-retiring-registrar-public-hex <old-registrar-64-hex>
--expected-activating-registrar-public-hex <new-registrar-64-hex>
--expected-governor-public-hex <pre-trusted-governor-64-hex>
--expected-old-ledger-raw-sha256 <old-ledger-exact-file-sha256>
--expected-old-ledger-sequence <verified-old-count>
--expected-cutover-nonce-sha256 <outside-unique-cutover-nonce-hash>
--expected-governance-decision-sha256 <outside-signed-or-governed-decision-document-hash>
--expected-cutover-mode planned | emergency_compromised
```

应先由另一方在不可回滚介质上记录上述八个字段及旧账本、换钥证书、新账本的独立 pin，再把具体值输入命令行。`--expected-governance-decision-sha256` 只是在证书内绑定决议内容散列，**本代码不验证真实决议文本、审批人权限、可信时间或决议吊销清单**。

## 操作序列（离线、各角色签字可在不同设备进行）

所有子命令均附带上面的 `--old-ledger-file` 及 `--expected-*` 共通参数，以下仅展示各自专用选项；实际运行时必须补齐。

1. `prepare --out /private/cutover-intent.json`：逐条校验完整旧 EC304 已签历史与外部旧 tip，然后写未签治理声明。记录响应中的 `intent_raw_sha256` 到**包外**。
2. 每个角色分别执行 `sign --intent-file ... --expected-intent-sha256 ... --role retiring|activating|governance --private-key-file /private/role.key --out /private/role.vote.json`。签字前每次重新验证外部锚定的旧账本和声明，密码学公钥必须匹配角色位。紧急模式**只签 activating、governance**。
3. `assemble --intent-file ... --expected-intent-sha256 ... --activating-vote-file ... --governance-vote-file ... [--retiring-vote-file ...] --out /private/cutover-cert.json`：强制完整角色集合、逐张严格验证签名并写入不可覆盖证书。记录 `certificate_raw_sha256` 到包外。紧急模式提供 retiring vote 会被拒绝。
4. `verify-certificate --certificate-file /private/cutover-cert.json --expected-certificate-sha256 <outside-pin>`：重新检查旧账本、旧记录签名、三/两方域分离签字。**不表示新账本已经存在、全球换钥已生效。**
5. 在首次新 epoch 登记前由保管方明确签发 `previous_new_sequence=0`、`previous_new_ledger_sha256=GENESIS(64位零)`。执行 `register` 并附加：`--certificate-file ... --expected-certificate-sha256 ... --previous-new-ledger-file /private/new-ledger-0001.json`（首次必须省略）以及 `--expected-previous-new-ledger-sha256 ... --expected-previous-new-sequence ... --activating-private-key-file /private/new-registrar.key --out /private/new-ledger-0001.json`。还需全套 EC303 bundle/ACK/八个原始 pin/发送与接收 ID/接收公钥/挑战 SHA 参数（同 EC304 `register`，但不要求单独 registrar ID 和公钥）。**原 EC304 `register` 真实重验最新 EC303→EC294 签章后才签发**。
6. 追加第二条时传**前一新账本**路径及包外 SHA/seq，`--out` 必须新路径。EC305 先检查整个旧账本和当前新账本无跨 epoch 重复，再调用原 EC304 `register` 查同 epoch 重复；不能跳过本包装器直接使用 EC304 原 CLI。
7. `verify --certificate-file ... --expected-certificate-sha256 ... --new-ledger-file ... --expected-new-ledger-sha256 ... --expected-new-sequence ...` 并附上最新的完整 EC303 原始 bundle/ACK 与原始八 pin/接收上下文。签名链均被核对，**只重放新账本最后一条原始 ZIP/ACK**，旧的所有 ZIP/ACK 内容不在账本里，不宣称补证完成。必须核对返回 `exit_code=0` 与最新外部 pin 一致。

上面的 EC303 参数名是：

```text
--bundle-file --expected-bundle-sha256
--acknowledgement-file --expected-acknowledgement-sha256
--expected-a-id --expected-a-public-hex --expected-a-tip
--expected-b-id --expected-b-public-hex --expected-b-tip
--expected-session-tip --expected-receipt-tip
--expected-sender-id --expected-receiver-id --expected-receiver-public-hex
--expected-exchange-challenge-sha256
```

## 统一控制台（仅只读）

`scripts/ces_next.py audit-rollover DeliveryAudit VerifyRegistrarRollover` 接受上述全套 **`verify`** 独立 pin 和 ZIP/ACK 路径，仅调用固定路径上的 `scripts/ces_registrar_rollover.py verify`，不会暴露任何私钥或 `prepare/sign/assemble/register` 写入口。若需真正操作签字/发证，请单独运行离线脚本，**不要**将私钥参数传给控制台或旧 Router。

## 留待真实部署和用户终验

- 可信 governor 的事先授权与撤销、不同自然人和设备的物理分权、紧急失陷证据/决议、唯一 challenge 和 cutover nonce 发行。
- **真实原子比较并交换**：必须将旧 ledger tip、换钥证书 SHA、最新新 ledger tip+seq 写到外部独立、不可回滚的共同权威，禁止同前驱两个有效合法分叉同时被认作最新。软件只核验给定链，并不裁决 fork 或阻止旧 EC304 工具签旧账。
- 不同 OS、真实设备/NFS/网络共享文件竞争与恶意路径更换、断电持久性、HSM/KMS、生产 Provider/Inbox、PS7 原 15 Smoke、CI/Git/E63–E66、EC249/EC250/B001 全流程和最终人工联验。先前 `global Quality PASS=false` 不因本次局部成功而变化。

本地聚焦用例位于 `construction/registrar_rollover/test_rollover.py`，继承原 EC304/EC303→294 本机密码学 fixture；测试中密钥同机创建**不代表真实多人员隔离**。
