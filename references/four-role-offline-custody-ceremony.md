# EC338 — 四方离线原件交接收据：真实签名、全原 SHA 与外部信任分层

> 范围：给 EC337 的无签原字节运输包增加**可核验的、角色区分的四份 Ed25519 签名陈述**。不是联网交接服务，也不代替独立信托机构、认证手续、离线物理交接或 EC336 旧历史验签。

## 1. 参与人、可信根及文件

四种固定角色和事件必须按顺序进行，每一角色一个不同的 Ed25519 私钥、公钥、`actor_id`：

1. `sender` — `sender_declares_sealed_original_bundle`：发送者声明封装了同一个字节归档。
2. `carrier` — `carrier_declares_accepted_same_sealed_medium`：介质承运人声明已接收同一个介质。
3. `receiver` — `receiver_declares_received_same_sealed_medium`：接收者声明收到同一个介质。
4. `witness` — `independent_witness_declares_observed_receipt_chain`：独立见证人声明观察了收据链。

必须由**实际可信包外途径**独立提供 **12 项整文件原始 SHA256**：

- 先前 EC337 的**七项**：运输 ZIP 本身，以及 EC334 plan、EC335 closure/map、原 EC333 handoff、原左右 EC331 manifest 各自的 whole raw SHA。
- EC338 的一项：已经由独立信任渠道固定的 **完整策略 JSON** 的 whole raw SHA。
- EC338 的四项：`sender / carrier / receiver / witness` 各自**整份已签收据 JSON 原 SHA**；即使收据文件是发送者传来的，也不能自动以发送者自报 SHA 作为接收端的独立信任参数。

相同 `transfer_id`、介质标签 SHA、策略 SHA、原 ZIP SHA、事件顺序、角色、公钥、授权文件引用 SHA、各自 nonce 和**前一份完整已签收据的 SHA**都进入独立按角色划域的 Ed25519 签名消息。首签的 `previous_receipt_original_raw_sha256` 必须为 64 个零；后面每份必须为前签全部 LF JSON 原字节的 SHA256（包含原签名字段），不可跳行、换链、改序。四个 nonce 在本链不得重复。

### 策略 JSON 合同（须由独立信任持有人创建并固定整体 SHA）

```json
{
  "schema": "ces.ec338.externally_pinned_four_role_airgap_custody_roster.v1",
  "transfer_id": "handoff_2026_001",
  "medium_identifier_sha256": "<64 位小写十六进制；独立记录的介质标识标签哈希>",
  "original_roots": {
    "bundle_original_raw_sha256": "<外部受信 ZIP 整份原 SHA>",
    "plan_original_raw_sha256": "<EC334 plan 整份原 SHA>",
    "closure_original_raw_sha256": "<EC335 closure 整份原 SHA>",
    "map_original_raw_sha256": "<EC335 map 整份原 SHA>",
    "handoff_original_raw_sha256": "<EC333 handoff 整份原 SHA>",
    "left_manifest_original_raw_sha256": "<左 EC331 manifest 整份原 SHA>",
    "right_manifest_original_raw_sha256": "<右 EC331 manifest 整份原 SHA>"
  },
  "actors": [
    {"role":"sender","actor_id":"sender_operator","organization_id":"org_origin","public_hex":"<64 位 Ed25519 裸公钥 hex>","authorization_reference_sha256":"<外部机构记录整份 SHA>"},
    {"role":"carrier","actor_id":"carrier_operator","organization_id":"org_courier","public_hex":"<独立公钥>","authorization_reference_sha256":"<外部机构记录 SHA>"},
    {"role":"receiver","actor_id":"receiver_operator","organization_id":"org_recipient","public_hex":"<独立公钥>","authorization_reference_sha256":"<外部机构记录 SHA>"},
    {"role":"witness","actor_id":"witness_operator","organization_id":"org_external_witness","public_hex":"<独立公钥>","authorization_reference_sha256":"<外部机构记录 SHA>"}
  ],
  "authority_and_revocation_require_external_verification": true
}
```

示意占位符 **不是可直接使用的合法键值**。对象必须先变成 `sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False` 的规范 JSON，再加**且只加一个 `\n`**，文件所在目录仅本机用户可访问、文件 `0600`、无符号链接或其他硬链接。规范化不能成为“由本机代码独立批准了策略”的理由。

约束：四个不同 `actor_id/public_hex/authorization_reference_sha256`；`sender` 与 `receiver` 的 `organization_id` 不同，`witness` 的组织还须区别于其他三方。组织名称与外部授权/撤销实际状况不能仅凭 JSON 字符串核实；无外部受信组织授权时应拒绝将签名解释为官方交接完成。

## 2. 独立 signer 本地签发（不得在统一只读审计入口执行）

完整独立入口：

```text
python -I -B scripts/ces_cas_custody_chain.py sign-receipt \
  --role sender \
  --out /private/custody/sender-receipt.json \
  --private-key-file /private/keys/sender.ed25519.raw \
  --nonce-sha256 <本轮新鲜 nonce 的 64hex 摘要> \
  --signer-reported-utc 2026-10-25T10:00:00Z \
  --policy-file /private/custody/roster.json \
  --expected-policy-sha256 <已通过包外固定的策略 whole SHA> \
  --bundle-file /private/incoming/ec337-originals.zip \
  --expected-bundle-sha256 <包外 ZIP SHA> \
  --expected-first-hop-plan-sha256 <包外 plan SHA> \
  --expected-closure-sha256 <包外 closure SHA> \
  --expected-map-sha256 <包外 map SHA> \
  --expected-handoff-sha256 <包外 handoff SHA> \
  --left-expected-manifest-sha256 <包外 left SHA> \
  --right-expected-manifest-sha256 <包外 right SHA>
```

`sender` 不传 `--prior-receipt-*`。依次签署 `carrier / receiver / witness` 时，把 `--role`、`--out`、`--private-key-file`、`--nonce-sha256` 和自报日期换成该角色的独立值，并对**全部前序角色**分别补充**按时间顺序**的两项重复参数：

```text
  --prior-receipt-file /private/custody/sender-receipt.json \
  --prior-receipt-sha256 <独立提供的 sender 已签 whole SHA>
```

`receiver` 需要两组（sender, carrier），`witness` 需要三组（sender, carrier, receiver）。代码会从头再验**全部前签原 SHA + 原 Ed25519 真签 + 链**，重验真实 EC337 ZIP 全部观察持久原件与旧 ZIP 内嵌成员，**之后才读取自己的 32 原字节 Ed25519 密钥**。密钥必须在用户私有 `0600` 正规文件，不能把含 PEM 头的文本作为 32 字节原始密钥；不要向其他人传送私钥。候选签名原件通过 `O_EXCL` / `0600` / `fsync` 写入，不覆盖既存文件。

签发输出 `receipt_original_raw_sha256_local_untrusted` 只是辅助交接值，**不是受信 SHA**。受信人必须经真实受批准的独立渠道获取并冻结整份签名收据 SHA，核实签发人身份和授权，再传给下一方或最终接收核验。代码不提供创建机构证书、线上联络、授权登记、私钥签名代理或远程写的功能。

## 3. 接收端四环全验证

```text
python -I -B scripts/ces_cas_custody_chain.py verify-chain \
  --policy-file /private/custody/roster.json \
  --expected-policy-sha256 <受信策略 SHA> \
  --bundle-file /private/incoming/ec337-originals.zip \
  --expected-bundle-sha256 <受信 ZIP SHA> \
  --expected-first-hop-plan-sha256 <受信 plan SHA> \
  --expected-closure-sha256 <受信 closure SHA> \
  --expected-map-sha256 <受信 map SHA> \
  --expected-handoff-sha256 <受信 handoff SHA> \
  --left-expected-manifest-sha256 <受信 left SHA> \
  --right-expected-manifest-sha256 <受信 right SHA> \
  --sender-receipt-file /private/custody/sender-receipt.json \
  --expected-sender-receipt-sha256 <独立受信 sender 整份 SHA> \
  --carrier-receipt-file /private/custody/carrier-receipt.json \
  --expected-carrier-receipt-sha256 <独立受信 carrier 整份 SHA> \
  --receiver-receipt-file /private/custody/receiver-receipt.json \
  --expected-receiver-receipt-sha256 <独立受信 receiver 整份 SHA> \
  --witness-receipt-file /private/custody/witness-receipt.json \
  --expected-witness-receipt-sha256 <独立受信 witness 整份 SHA>
```

统一只读入口命令：把上面 `python ... ces_cas_custody_chain.py verify-chain` 替换成

```text
python -I -B scripts/ces_next.py audit-airgap-custody DeliveryAudit VerifyIndependentAirgapCustodyChain
```

并保持全部 `--...` 参数不变。统一入口固定启动**隔离只读** `verify-chain`，不提供 `sign-receipt`、EC337 `install-bundle` 或任何签署密钥/业务写入/远端 CAS 入口。验证执行时，先逐份检查受信策略/全四份规范签名收据：策略 SHA、12 个明确的外部根、角色/组织、公钥、授权引用、链 SHA、重复 nonce 与四个真实 Ed25519 域签名；再实际运行 EC337 全 ZIP/嵌套 ZIP byte inspector，最后重读全签名文件、策略和 ZIP whole SHA。

## 4. 结果与不可突破的信任边界

- 成功只返回 **`exit_code=2`、`status=...unresolved`**。指的是**本地密码学证据链与所观察原件完整性**通过，不是物理交接真实发生、相互独立物理设备、人类身份核验、授权链/撤销最新状态、可信时钟或实体验证凭证已被工具证实。
- 改一字节、改事件/角色/prev SHA、复用 nonce、重排/遗漏任何签名、重放其他策略或运输 ZIP、同机构冒充独立 witness，均必须 fail closed；策略自称“授信”无效。**即使同一人在一台机器握有四把不同密钥并签署成功，也不证明现实独立性。**
- 旧 `EC336 verify-signed-replay` 必须另外执行，前提是目标已经经 EC337 `install-bundle` 原字节落盘。旧签路径字面值不得改造，旧历史不能仅凭本次新的 custody 签名自动视为完整原签通过。
- ZIP 是未加密明文：线下介质是否加密/密封、谁实际持有、序列号是否匹配、签署密钥归属、身份撤销、真实机构/物理可信钟/最新远程状态，要由用户最终线下协作完成。
- 无 remote CAS/WORM、线性化提交、真实 nonexecution/global latest/winner、组织批准、完整无 MOCK EC294→338 旧签历史/PowerShell7 15 Smoke/跨 OS 联合验收的证据。局部回归夹具的第八/九及新增四方 Ed25519 为真签，**继承的 EC317/318 深旧链历史仍为 MOCK**。
