# EC293 — 独立原 EC226 私有 DeliverySend 状态读取 Host：部署与权责说明

Historical record names below are archival references; those files are absent
from this source tree. See [cleanup scope](../docs/CLEANUP.md).

**版本 V6.03 / R293 / EC293；仅供经过独立审批的 owner-private 单目标私有测试。** 原 EC225 若已有真实的 durable submit attempt，可以按下述流程额外观察一次远端私有 Provider 状态。EC293 不能重发、撤回或扩大接收者，也不能授予一般 Router `run` 权限。原 EC226 状态查询使用固定 HTTPS `POST /status`，这是*读性质查询*，不是原 EC225 `POST /submit`。所有外部请求必须由经管理员固定的目标策略产生，不能传入 Socket。

## 1. 准备旧证据、独立权根及原始代码

需要已有原 EC288 `0600` Policy / Job / Trust（所有原 EC221–225 历史签名、精确源与原私有 sandbox target 保持不变），以及本机真实原 EC225 永久 outbox。**不能**仅凭 EC288 Host 的 `partial/2` 或 HTTP 202 推断原 Submit marker 已写入：EC293 调用原 EC226 进一步读取 `ec225-<operation>/00_RESERVED_DURABLE` + `03_SUBMIT_ATTEMPTED`，该证据是**必要但不充分**条件。

管理员在与原 EC288 写 token 分离的设备/账户中准备**独立只读查询 token**；EC293 policy 只保留 token 文件路径和 raw SHA，程序不会打开 EC288 写凭证路径。owner-only 的 policy/job/trust/只读 token/private-key/result 为 0600；私有根目录、临时持久化根为 0700，Unix socket 父目录不可组/其他写。系统将本轮的新 3 把 Host key、原 EC226 status read/inbox 2 把、原 EC288 Host 3 把、原 EC223/224/225 8 把固定为 16 个不相同的**公钥**，组织人员独立性另行人工核验。

先在 `<OWNER_PRIVATE>` 0700 目录中写入 `ec293-status-trust.json`，以下是字段模板（所有尖括号值替换为实际受治理的不同公钥和身份）：

```json
{
  "schema": "ces.ec293.private_delivery_status_trust.v1",
  "issuer_id": "status_issuer_293",
  "reader_id": "status_reader_293",
  "inbox_observer_id": "inbox_observer_293",
  "status_read_public_hex": "<EC226_OFFLINE_READ_32_BYTE_ED25519_PUBLIC_HEX>",
  "inbox_observation_public_hex": "<INDEPENDENT_INBOX_OBSERVER_PUBLIC_HEX>",
  "minimum_read_epoch": 1,
  "enable_private_status_read": true
}
```

操作程序固定：`scripts/ces_delivery_status_host.py`，可用 `python scripts/ces_delivery_status_host.py --help` 查看；系统提供 `keygen-offline --private-out <0600-file>` 为独立操作者生成原始 32-byte Ed25519 私钥，**不能**在生产由同一操作者代签所有角色。

## 2. 完整受审调用过程（每份私有文件须新路径、0600）

```bash
# 管理员先创建受保护的独立状态审计根，例如 /owner/ec293-admission (0700)。
python scripts/ces_delivery_status_host.py prepare-policy \
  --ec288-policy-file /owner/private/ec288-policy.json \
  --ec288-policy-sha256 <PINNED_EC288_POLICY_SHA256> \
  --status-trust-file /owner/private/ec293-status-trust.json \
  --read-credential-file /owner/private/status-only.token \
  --admission-root /owner/ec293-admission \
  --allowed-uid <APPROVED_UNIX_UID> \
  --custodian-public-hex <NEW_CUSTODIAN_PUBLIC_HEX> \
  --reviewer-public-hex <NEW_REVIEWER_PUBLIC_HEX> \
  --server-public-hex <NEW_SERVER_PUBLIC_HEX> \
  --enable-private-status-read --out /owner/private/ec293-policy.json

# 用独立 server 私钥部署，命令会前置验证精确 policy、全部 16 公钥独立性、
# 原始源码 SHA 与原 EC288 完整 job/trust；不会读取 EC288 POST token。
python scripts/ces_delivery_status_host.py serve \
  --socket /owner/socket/ec293.sock \
  --policy-file /owner/private/ec293-policy.json \
  --policy-sha256 <NEW_EC293_POLICY_SHA256> \
  --server-private-key-file /owner/keys/ec293-server.key

# 只有真正完成旧 Submit Attempt 的同一个 operation 才能执行状态业务。
python scripts/ces_delivery_status_host.py prepare-read-template \
  --policy-file /owner/private/ec293-policy.json \
  --policy-sha256 <NEW_EC293_POLICY_SHA256> \
  --ttl-seconds 35 --out /owner/private/ec226-read-template.json

# 由独立 EC226 状态读授权签署人操作；这是读票，绝不是原发送票。
python scripts/ces_delivery_status_host.py sign-read-offline \
  --template-file /owner/private/ec226-read-template.json \
  --private-key-file /owner/keys/independent-ec226-read.key \
  --out /owner/private/ec226-read.grant.json

python scripts/ces_delivery_status_host.py prepare-offline \
  --policy-file /owner/private/ec293-policy.json \
  --policy-sha256 <NEW_EC293_POLICY_SHA256> \
  --read-grant-file /owner/private/ec226-read.grant.json \
  --uid <APPROVED_UNIX_UID> --ttl-seconds 25 \
  --out /owner/private/ec293-status.subject.json

python scripts/ces_delivery_status_host.py sign-custodian-offline \
  --subject-file /owner/private/ec293-status.subject.json \
  --private-key-file /owner/keys/ec293-custodian.key \
  --out /owner/private/ec293-status.custodian.vote.json

python scripts/ces_delivery_status_host.py sign-reviewer-offline \
  --subject-file /owner/private/ec293-status.subject.json \
  --private-key-file /owner/keys/ec293-reviewer.key \
  --out /owner/private/ec293-status.reviewer.vote.json

python scripts/ces_delivery_status_host.py assemble \
  --subject-file /owner/private/ec293-status.subject.json \
  --custodian-vote-file /owner/private/ec293-status.custodian.vote.json \
  --reviewer-vote-file /owner/private/ec293-status.reviewer.vote.json \
  --custodian-public-hex <NEW_CUSTODIAN_PUBLIC_HEX> \
  --reviewer-public-hex <NEW_REVIEWER_PUBLIC_HEX> \
  --out /owner/private/ec293-status.host-grant.json

python scripts/ces_next.py host-delivery-status DeliverySend Readback \
  --socket /owner/socket/ec293.sock \
  --grant-file /owner/private/ec293-status.host-grant.json \
  --read-grant-file /owner/private/ec226-read.grant.json \
  --policy-sha256 <NEW_EC293_POLICY_SHA256> \
  --server-public-hex <NEW_SERVER_PUBLIC_HEX>
```

真实多角色离线签名及组织审核必须在 ≤35/25 秒短窗口内事先协调完成；逾期只能停止签名、人工确认之前是否已经请求过 Provider，**不能自动重试**已经可能产生状态请求的票。CLI 也可使用其 `submit` 原生命令，但同样必须验收 server 签名 ACK。把完整签名回复保存到受保护的原始审计材料中，不要在外部公开私有内容或 token。

## 3. 哪些状态是事实，哪些不成立

| `delivery_state` | 原 EC226 证明的有限含义 | 不得推出 |
| --- | --- | --- |
| `UNKNOWN_UNCONFIRMED` | Provider 未有可确认的正/负证据或观察失败 | 没发送、必然失败、可自动重发 |
| `ACCEPTED_PROVIDER_ATTESTED` | 已核验 Provider 对该沙箱操作的签名接受证据 | 收件方已收到、生产送达 |
| `DELIVERED_INBOX_OBSERVED` | 已核验 Provider 签章 + **另一把**收件箱观察者对确切私有测试目标及随机 challenge 的签章 | 一般互联网公开、企业正式交付、所有消息被看见 |
| `PROVIDER_REJECTION_ATTESTED` | Provider 对本次状态查询返回签名拒绝状态 | 可以不经新审批重复原发送 |
| `PROVIDER_FAILURE_ATTESTED` | Provider 对本次状态查询返回签名失败状态 | 没有过副作用、可以重复原发送 |

程序从不以 HTTP 202 或 Provider 单方 `DELIVERED` 冒充收件端核验。签名 ACK 丢失时无法区分已经消费读取票还是未收到命令，客户端一律报告 UNKNOWN；查 EC293 admission 与原 EC226 `ec226-read-*` 目录、原 EC225 outbox 和 Provider 只读审计。任何重新读取都是新的批准动作，不是网络库自动 retry，更非重复 Submit。原 EC227 durable reconciliation 属另一个独立能力，本轮未给它安装执行 Host。

## 4. 已测试事实与生产联合验证

**本地实际执行**：EC293 聚焦 17/17、未改原 EC226 24/24、未改 EC288 Host 10/10，总计 51 个不同 test cases PASS。原 EC225 *真实代码*以**假的 Provider probe/202**建立一次性沙箱 submit marker；新 Host 实际连接 Unix Socket/读取内核 peer UID/确认 16 公钥/消费签名票与 fsync admission；原 EC226 以**模拟签名** Provider `/status` 和 inbox witness 完成分类，原 EC225 历史签名真实验证，单机重复 Host grant 拒绝、独立新读票允许。**原始业务不是 fake，但是远端 Provider 及收件端都是 mock；没有联网，不能证明真实投递。**

**最终留给用户辅助**：真实独立签署设备/人、EC288/EC293 生产 UID/ACL/symlink/revocation/key rotation、读 Token 对外真实 API 权限/目标、Status-only `/status` Provider 协议与收件端独立签章、可信时钟/多进程/断电 fsync/多机器、原 PowerShell7 15 Smoke、Windows/macOS/CI/Git/Provider/原 EC227 对账，以及外部 E63–E66/全量最终验收。仍保留 `EC249=FULL_FUNCTION_NOT_COMPLETE`、`EC250=BLOCKED`、`B001=OPEN`、`final_acceptance=NOT_STARTED`、Quality PASS=false。

`本轮记录` · `范围` · `本地执行证据` · `完整文件 SHA256`。
