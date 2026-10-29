# EC339 实操 — 离线发行者签授权、挑战绑定撤销快照与 21 项 SHA 全链核验

本协议的核心是**外部先决定信任哪四把发行者公钥**，并通过独立渠道冻结相应 issuer roster 整文件 SHA，再用代码对这些公钥的真签进行验证。独立传递的 SHA、法律上的资格、真实人机分离和可信时钟不是程序能自己创造的。文件必须在单用户私有目录下是绝对标准路径、owner 0600、单一硬链接、无符号链接；规范 JSON 按 `sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False` 且仅一个末尾 `LF`。Ed25519 私钥输入为 owner 0600 的 32 **原始**字节，不是 PEM 文本。

## 1. 顺序：先 grant → EC338 policy/receipts → issuer roster → status

四个不同授权发行者分别用独立私钥签发自己对应的角色授权（逐一替换 sender / carrier / receiver / witness）：

```text
python -I -B scripts/ces_cas_issuer_authority.py issue-grant \
  --out /private/evidence/sender-grant.json \
  --private-key-file /private/issuer/sender.ed25519.raw \
  --role sender --issuer-id issuer_sender --grant-id grant_sender_001 \
  --transfer-id transfer_001 \
  --bundle-original-raw-sha256 <外部受信 EC337 ZIP SHA> \
  --actor-id operator_sender --organization-id org_sender \
  --subject-public-hex <EC338 sender 收据公钥:64hex> \
  --issued-utc 2026-10-25T09:00:00Z \
  --not-before-utc 2026-10-25T08:00:00Z \
  --not-after-utc 2026-11-25T08:00:00Z
```

输出本地 `grant_original_raw_sha256_local_untrusted`，仅供交接辅助，接收方需真正从独立可信渠道取得整份 SHA。授权覆盖**指定传输 ZIP**和特定角色/操作人公钥与有效期，不可跨传输或互换授权。**不要先做旧 EC338 policy 再签 grant**：把四份已签 grant 的**整原 SHA** 写入 EC338 policy 中对应角色 `authorization_reference_sha256`，之后按 [EC338 完整签发顺序](ec338-four-role-offline-custody-ceremony.md) 依次产生四份角色原签收据；旧原签协议**一字不改**。

外部发行者 root roster（**整原 SHA 需独立可信管护**）精确格式：

```json
{
  "schema": "ces.ec339.externally_pinned_role_issuer_roster.v1",
  "transfer_id": "transfer_001",
  "policy_original_raw_sha256": "<本次 EC338 policy 整份 SHA>",
  "issuers": [
    {"role":"sender","issuer_id":"issuer_sender","issuer_public_hex":"<issuer sender 公钥>","subject_organization_id":"org_sender"},
    {"role":"carrier","issuer_id":"issuer_carrier","issuer_public_hex":"<独立发行者公钥>","subject_organization_id":"org_carrier"},
    {"role":"receiver","issuer_id":"issuer_receiver","issuer_public_hex":"<独立发行者公钥>","subject_organization_id":"org_receiver"},
    {"role":"witness","issuer_id":"issuer_witness","issuer_public_hex":"<独立发行者公钥>","subject_organization_id":"org_witness"}
  ],
  "external_issuer_trust_and_rotation_required": true
}
```

以上占位符仅说明格式，不能直接使用。roster 必须以 EC338 policy SHA 为包外绑定，发行者 key 不能与四把 EC338 收据 key 重复；四发行者 key 也不能相互重复。选择谁是实际法定发行者、key 何时吊销/轮换，由外部受信主体负责，软件不会把自称 `issuer_id` 当作法律证书。换 root 要由可信人员另行重新出具、传播和 pin **新 roster 整原 SHA**，不能以本次 ZIP 或本次工具的自身输出来自动授权。

## 2. 接收方先发挑战，发行者签一份状态快照

接收方经独立渠道给每发行者一个**新鲜且保密管理的**随机挑战 digest `verifier_challenge_sha256`；要保存其外部产生与送达证据，重复挑战无法自动证明状态新鲜。每位 issuer 必须**自己实际审查其授权/撤销登记**，然后签署 `active` 或 `revoked`；本代码只验证其**签了什么**，不会联网查国家/企业登记。

```text
python -I -B scripts/ces_cas_issuer_authority.py issue-status \
  --out /private/evidence/sender-status.json \
  --private-key-file /private/issuer/sender.ed25519.raw \
  --role sender \
  --policy-file /private/evidence/roster-ec338.json \
  --expected-policy-sha256 <外部受信 EC338 policy SHA> \
  --authority-roster-file /private/evidence/issuer-roster.json \
  --expected-authority-roster-sha256 <外部受信 issuer roster SHA> \
  --grant-file /private/evidence/sender-grant.json \
  --expected-grant-sha256 <外部受信 sender grant whole SHA> \
  --verifier-challenge-sha256 <外部 verifier 独立产生的 SHA> \
  --state active \
  --as-of-utc 2026-10-25T10:00:00Z \
  --expires-utc 2026-10-25T11:00:00Z
```

状态为 `revoked` 时补 `--revoked-effective-utc 2026-10-25T10:15:00Z`（UTC 举例）；`active` 时不得提供撤销日期。`as_of_utc < expires_utc` 且最长 24 小时；接收时指定的 UTC 评估时刻须落在 `[as_of_utc, expires_utc)`，授权也必须在该时刻与 EC338 **自报签字时刻**有效。对于签署的 `revoked`，代码直接拒绝，不假设未来恢复或忽略其生效时间。任何 issuer 对真实登记的错误自报都不能被离线签名自动发现。

## 3. 接收者只读全链验证（统一/独立二选一）

所有 **21 项包外独立 whole SHA** 必须在接收机器被分别传入：

| 来源 | SHA 数量 | 必须独立固定 |
|---|---:|---|
| EC337 | 7 | 运输 ZIP + plan + closure + map + handoff + 左/右 manifest |
| EC338 | 5 | 四角色 roster policy + sender/carrier/receiver/witness 四签收据 |
| EC339 | 9 | issuer roster + 四签授权 grant + 四签撤销状态 status |
| 额外 | 不计入 21 文件 SHA | `verifier_challenge_sha256` 与操作员 UTC 评估时刻 |

使用下述独立脚本，无需改动 EC338 的原参数：

```text
python -I -B scripts/ces_cas_issuer_authority.py verify-authority \
  --policy-file /private/evidence/ec338-policy.json \
  --expected-policy-sha256 <可信 EC338 policy SHA> \
  --bundle-file /private/evidence/ec337-originals.zip \
  --expected-bundle-sha256 <可信 ZIP SHA> \
  --expected-first-hop-plan-sha256 <可信 plan SHA> \
  --expected-closure-sha256 <可信 closure SHA> \
  --expected-map-sha256 <可信 map SHA> \
  --expected-handoff-sha256 <可信 handoff SHA> \
  --left-expected-manifest-sha256 <可信 left SHA> \
  --right-expected-manifest-sha256 <可信 right SHA> \
  --sender-receipt-file /private/evidence/sender-receipt.json \
  --expected-sender-receipt-sha256 <可信 sender receipt SHA> \
  --carrier-receipt-file /private/evidence/carrier-receipt.json \
  --expected-carrier-receipt-sha256 <可信 carrier receipt SHA> \
  --receiver-receipt-file /private/evidence/receiver-receipt.json \
  --expected-receiver-receipt-sha256 <可信 receiver receipt SHA> \
  --witness-receipt-file /private/evidence/witness-receipt.json \
  --expected-witness-receipt-sha256 <可信 witness receipt SHA> \
  --authority-roster-file /private/evidence/issuer-roster.json \
  --expected-authority-roster-sha256 <可信 issuer roster SHA> \
  --sender-grant-file /private/evidence/sender-grant.json \
  --expected-sender-grant-sha256 <可信 sender grant SHA> \
  --carrier-grant-file /private/evidence/carrier-grant.json \
  --expected-carrier-grant-sha256 <可信 carrier grant SHA> \
  --receiver-grant-file /private/evidence/receiver-grant.json \
  --expected-receiver-grant-sha256 <可信 receiver grant SHA> \
  --witness-grant-file /private/evidence/witness-grant.json \
  --expected-witness-grant-sha256 <可信 witness grant SHA> \
  --sender-status-file /private/evidence/sender-status.json \
  --expected-sender-status-sha256 <可信 sender status SHA> \
  --carrier-status-file /private/evidence/carrier-status.json \
  --expected-carrier-status-sha256 <可信 carrier status SHA> \
  --receiver-status-file /private/evidence/receiver-status.json \
  --expected-receiver-status-sha256 <可信 receiver status SHA> \
  --witness-status-file /private/evidence/witness-status.json \
  --expected-witness-status-sha256 <可信 witness status SHA> \
  --evaluation-utc 2026-10-25T10:20:00Z \
  --verifier-challenge-sha256 <verifier 独立产生的 challenge SHA>
```

统一只读入口只需把上面的 `python -I -B ... ces_cas_issuer_authority.py verify-authority` 头换为：

```text
python -I -B scripts/ces_next.py audit-airgap-authority DeliveryAudit VerifyPinnedIssuerAuthorizationAndRevocation
```

保留全部 flags。该统一入口只执行**固定路径、固定 `-I -B` 只读的 verify-authority**，不提供 `issue-grant`, `issue-status`, `sign-receipt`, `install-bundle` 或远端 CAS Writer。输出即使全部本地可验证，也必须是 **`exit_code=2`、`...unresolved`**，且所有过度证明布尔量恒 `false`。任何缺少独立 SHA、非 canonical/私有原件、签名失效、对其他 grant/actor/role 的重放、组织/发行者 pub 不匹配、挑战错、过期/撤销、变更源等 fail closed。

## 4. 需要最终外部辅助的统一验收

至少需要：可信授权源和吊销来源公开如何核查、受信发行者 roster 的真实批准/轮换/撤销记录、私钥保管方真实身份、21 SHA 外部传递与接收人身份、挑战不可预测与使用一次性记录、可信计时设备和实物介质标识、四独立人/设备、EC294→339 **无 MOCK** 旧原签全链、EC336 独立 target replay、原生 PS7 15 套 Smoke、跨 OS/Git/Provider/CI、外部 CAS/WORM/nonexecution/latest/winner 与最终人工联合验收。缺少这些证明时，不能将成功的离线签名结果解释为“已完成正式机构交接”。
