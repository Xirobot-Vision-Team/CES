# EC288 部署与操作：原 EC225 双签私有单目标沙箱发送 Host

本指南为**独立部署/审核需要的真实操作接口**，不是完成真实投递的证书。仅应指向用户自己控制的一处非生产沙箱测试收件箱（EMAIL/CHAT 单收件人），而不是实际客户、邮件群发或公开渠道。当前包**无真实 Provider 凭据或账号权限**；无外部 Provider 服务，宿主不能实际完成网络沙箱发送。请勿在真实账户上用测试机生成的签名 key。

## 0. 数据和权限边界

工作环境：Python3、`cryptography`、原业务依赖、Unix domain socket 和可靠的本地 POSIX fsync 文件系统。以**独立的非 root 专用宿主 UID**运行进程。`JOB`、`TRUST`、`CREDENTIAL`、`POLICY`、宿主签名 key 在归宿主 UID 的 `0700` 私有父目录中存储 `0600` 私有常规文件；输出路径不存在才可用 `O_EXCL` 新建。`OUTBOX` 与 `ADMISSIONS` 是两套不同的、始终存在的 owner `0700` **本地持久化**目录，不能在重试/重启后清空、回滚、复制成不同分片或放 NFS；还需受备份与独立审计保护。Socket 放在安全目录，Unix inode 和 peer UID 需由部署者在宿主外核对。创建策略时必须显式 `--enable-one-sandbox-send`，而调用者不能从 socket 注入凭证、报告原文或 provider URL。

部署者先独立获得：已保存且允许读取的真实 EC200 ReportHistory（或受限的 EC179 Finding）证据、原 EC221 DeliveryPreviewRequest、EC222 SensitiveReviewRequest、EC223 DeliveryIdentityRequest、EC224 DeliveryAuthorizationRequest、EC225 DeliverySendRequest，及经审查的**真实 8 个原公钥角色**。当前原 EC225 只会在最终有效隐私/目标匹配 `INTERNAL` 的场景发送；CONFIDENTIAL Finding 不可被宿主绕过原业务降级为安全外发。

可信业务 Python 进程内部可把原始 typed `DeliverySendRequest` 转成只能由宿主读的 JSON（仅示意，不包含具体私有原文）：

```python
from ec288_delivery_send_host.protocol import encode_original_request
import json
# exact_original_ec225_request 必须由独立可信宿主按 EC221-225 原业务产生/审核
job = encode_original_request(exact_original_ec225_request)
with open("/secure/host/job-draft.json", "x", encoding="utf-8") as f:
    json.dump(job, f, sort_keys=True, separators=(",", ":"))
```

须 `chmod 0600`，严禁传到 CI stdout、聊天或 Client。**源业务的数据授权不能通过填 JSON 真值模拟**：原签名、private source 以及原 EC225 会重新检查全链。原业务当前对短时效签名和本地 private source 有精确约束，离线演示 fixtures 不是生产人签。

`TRUST` 是宿主管理员保存、0o600 的精确 JSON 结构，字段如下。11 个公钥必须角色相异，真实部署还须组织上相互独立：

```json
{
  "schema": "ces.ec288.delivery_send_trust.v1",
  "enable_live_sandbox_send": true,
  "identity": {
    "issuer_id": "...",
    "directory_public_hex": "<64 hex>",
    "revocation_public_hex": "<64 hex>",
    "verification_public_hex": "<64 hex>"
  },
  "authorization": {
    "issuer_id": "...",
    "organization_id": "...",
    "approver_id": "...",
    "approval_public_hex": "<64 hex>",
    "entitlement_public_hex": "<64 hex>",
    "revocation_public_hex": "<64 hex>",
    "minimum_revocation_epoch": 1
  },
  "send": {
    "issuer_id": "...",
    "operator_id": "...",
    "side_effect_public_hex": "<64 hex>",
    "provider_capability_public_hex": "<64 hex>",
    "minimum_send_epoch": 1
  },
  "target": {
    "provider_id": "...", "account_id": "...",
    "endpoint": "https://owned-sandbox.example.net/api/v1",
    "recipient_handle": "...", "project_id": "...",
    "recipient_id": "...", "channel_id": "...",
    "audience_id": "...", "channel_kind": "CHAT",
    "recipient_identity_sha256": "<64 hex>",
    "user_controlled_sandbox": true
  }
}
```

这些 `...` 是占位说明，不能直接用来运行。provider sandbox gateway 必须实现原 EC225 `POST <endpoint>/probe`、`POST <endpoint>/submit` 协议及其签名 capability、幂等键；该 Provider 并非本轮开发/部署的东西。原 EC225 内建 `HTTPSPrivateTestTransport` 拒绝环境代理、任意 URL、重定向，真实 endpoint、合法 token 均由管理员单独签定/存储。`credential.txt` 为 16–2048 个允许 ASCII 字符、不带换行的专有 token，不能出现在 shell 命令行或投递回执内。

## 1. 创建 Host 自身三把私钥并批准精确策略

下列命令执行地点均为已授权、分别隔离的签发环境，**只展示固定接口，不代表这些权限已获得**：

```bash
python3 -I scripts/ces_delivery_send_host.py keygen-offline --private-out /secure/source-custodian.key
python3 -I scripts/ces_delivery_send_host.py keygen-offline --private-out /secure/send-authorizer.key
python3 -I scripts/ces_delivery_send_host.py keygen-offline --private-out /secure/server-reply.key

python3 -I scripts/ces_delivery_send_host.py prepare-job \
  --source-json /secure/host/job-draft.json --out /secure/host/job.json

python3 -I scripts/ces_delivery_send_host.py prepare-policy \
  --job-file /secure/host/job.json --trust-file /secure/host/trust.json \
  --credential-file /secure/host/credential.txt \
  --outbox-root /secure/host/outbox --admission-root /secure/host/admissions \
  --allowed-uid 1001 \
  --custodian-public-hex '<custodian 64 hex>' \
  --authorizer-public-hex '<authorizer 64 hex>' \
  --server-public-hex '<server 64 hex>' \
  --enable-one-sandbox-send --out /secure/host/policy.json
```

在签发批准前，管理员对 job SHA、原 EC224 审批与正文 SHA、trust SHA、token raw SHA、原 EC221–225 源码 SHA、EC288 host SHA 做独立审查；对 key 公钥/权限和真实目标作 out-of-band 验证。`prepare-policy` 输出 `policy_sha256`，它是后续 subject、Socket 客户端固定 pin。

## 2. 独立离线签票 → 宿主监听 → 单次调用

签票的 `uid` 必须是**实际上通过 Unix socket 连接的客户端 UID**，时间差限额 25 秒；跨离线机器的 subject 和票据可离线交换，但切忌暴露真正的私钥，必须人工保证能在有效窗口内完成。示意：

```bash
python3 -I scripts/ces_delivery_send_host.py prepare-offline \
  --policy-file /secure/host/policy.json --policy-sha256 '<policy sha256>' \
  --uid 1001 --ttl-seconds 25 --out /secure/host/subject.json

python3 -I scripts/ces_delivery_send_host.py sign-custodian-offline \
  --subject-file /secure/host/subject.json --private-key-file /secure/source-custodian.key \
  --out /secure/host/custodian.vote

python3 -I scripts/ces_delivery_send_host.py sign-authorizer-offline \
  --subject-file /secure/host/subject.json --private-key-file /secure/send-authorizer.key \
  --out /secure/host/authorizer.vote

python3 -I scripts/ces_delivery_send_host.py assemble-offline \
  --subject-file /secure/host/subject.json \
  --custodian-vote /secure/host/custodian.vote \
  --authorizer-vote /secure/host/authorizer.vote \
  --custodian-public-hex '<custodian 64 hex>' \
  --authorizer-public-hex '<authorizer 64 hex>' \
  --out /secure/host/exact.grant
```

启动独立 host（由专用 UID 管理，socket 目录和 host 私钥权限须经过管理员核验）：

```bash
python3 -I scripts/ces_delivery_send_host.py serve \
  --socket /secure/sockets/ec288.sock \
  --policy-file /secure/host/policy.json \
  --policy-sha256 '<policy sha256>' \
  --server-private-key /secure/server-reply.key
```

由获准 UID **仅一次**向统一 CES 控制台递交票，不传正文或 Provider 地址：

```bash
python3 -I scripts/ces_next.py host-delivery DeliverySend Send \
  --socket /secure/sockets/ec288.sock \
  --grant-file /secure/host/exact.grant \
  --policy-sha256 '<policy sha256>' \
  --server-public-hex '<server 64 hex>'
```

原 `run DeliverySend Send --request-file ...` 仍拒绝；EC288 不授权 `ReportPublish.PrivateTest`。Host 启动和此次 submit 在任何生产路径都**不会使用**开发 Mock transport。

## 3. 不可自动重试 / 联合验收待办

- `partial/2`、`SUBMISSION_UNCONFIRMED`：仅证明原 EC225 报告远端 HTTP 2xx 和用掉一次性审批；**从不代表 SENT / ACCEPTED / DELIVERED**。
- `unavailable/5`、Socket timeout、重放或回执签名/nonce/policy/code/原文 SHA 失败：即使没拿到签名 Host ACK，原 EC225 已可能走到 `/submit`；不能根据缺失回执二次发送。人工单独检查原 `outbox/ec225-<operation>` 的 marker、EC288 `admissions/ec288-<grant>`，单独授权进行 EC226+ 状态/收件箱查询；无可信正面查询不可将 UNKNOWN 宣称未发送。
- 真正组织/签发人独立性、服务身份、token 管理、provider TLS/重定向实际行为、未修改原 PowerShell7 的 15 Smoke、OS/远端 Git/CI/发布、实际沙箱 provider HTTP 与收件箱确认、时钟撤销/切换、跨主机持久化/NFS 和终验留在最终用户统一验收。切勿对真实收件人尝试以“测试”为名的发送。

代码入口：`construction/ec288_delivery_send_host/protocol.py`、`daemon.py`、`operator.py`，原不可改 `construction/delivery_send.py`。本地 evidence `construction/EC288_LOCAL_REPORT.json` / `EC-288.md`，不升级全局 Quality PASS。
