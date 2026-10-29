# EC289 — 原 EC228 `ReportPublish.PrivateTest` 独立单次宿主操作手册

**施工版本 V5.99 / R289 / EC289；不是生产发布或验收通过证书。** 本功能只对一份真正已经保存的 EC199/200 **最新不可变**报告及一个事先确定的**用户自有私有沙箱**目的地，提供额外的双线下授权后的一次机会。除严格受控的 Host 之外，原 `run ReportPublish PrivateTest` 仍默认拒绝。`/publish` 的 HTTP 2xx **不证明远端接受、文档存在或已公开**，仅返回原 EC228 `SUBMISSION_UNCONFIRMED`。

## 1. 可信对象与真实权限

需要 Python3、`cryptography`、原报告依赖、POSIX `AF_UNIX` 和支持 `fsync` 的可信本地持久化文件系统。由**独立的非 root** 专用宿主 UID 部署；原 EC228 六个角色的真实公钥必须分别独立，另外建立不同的 **source custodian / sandbox publisher / host receipt** 三个公钥。**九把不同的公钥不等于九名经证明的真实组织人员**；线下签发设备、实际角色审批、可信 UTC/吊销治理及真实 Provider 服务均需最终验收。

以下目录全部由专用 Host UID 持有，保持稳定且不随重启清空：

- `private/`：模式 `0700`；`job.json`、`trust.json`、`credential.txt`、`policy.json`、Host 私钥均为 Host UID 持有的 `0600` 普通单硬链文件，不能通过符号链接代替；通过 `O_EXCL` 新建。
- `outbox/`、`admissions/`：**两个独立的** Host UID `0700`、本地持久化、不可删除、不可回滚的目录；`outbox/ec228-<operation>` 是原业务实际发布操作账本，`admissions/ec289-<host-grant>` 是独立 Host 短票准入账本。绝不能复制到独立分片、NFS、多节点写或回滚快照，不能丢弃其一再尝试。
- `sockets/`：Host UID 持有、不可 group-write/world-access，模式 `0700`（同 UID 调用）或由部署者**明确授权可信用户组**的 `0750`；Socket 是 `0660`，真实放行仍逐连接校验**内核 peer UID**、短时双签。不同 UID 的运维用户必须有由部署者配置的组可通行目录/socket；拥有 Host 同 UID 的其他进程并非独立安全主体。
- 离线 Ed25519 私钥不得放到 Host 被调用方目录、命令行、网络或 CI 日志；用户客户端只读取 grant，不读取凭据、原报告源、trust 或 Markdown。

**宿主固定原始业务输入：** 不是新造的“已审查”布尔值。独立审核者需从原 EC199/200 真实不可变存储获取**最新版本**：`storage_root`、`slot_key`、`period_id`、**完整** `slot_members`、原 EC200 `read_policy`、`version`、`report_ref`、`record_sha256`、`rendered_sha256`、`entry_sha256`、`index_binding_sha256`；另提供原 EC228 组织许可、路由、当前撤销、**完整 Markdown 字节签名人工复核声明**、单次发布签名许可五个原 `SignedAuthorizationStatement`，以及两个明确 opt-in `True`。签名在原代码中使用六把各自不同的可信原公钥验证，provider capability 的第六把公钥用于实时签挑战。**所有原签名仍需真实的外部发行者**；不要在正式平台上使用本地测试私钥。

可信私有 Python 程序可把真正的 `ReportPublishRequest` 变成新的 owner-private Job JSON：

```python
import json
from ec289_report_publish_host.protocol import encode_original_request
job = encode_original_request(exact_original_ec228_report_publish_request)
with open('/secure/publish/private/job-draft.json', 'x', encoding='utf-8') as f:
    json.dump(job, f, sort_keys=True, separators=(',', ':'))
# 仅在可信宿主环境，随后 chmod 0600；不要发送到 Socket/CI。
```

`trust.json` 精确结构（公钥、ID 和真实 endpoint **必须由授权管理员另行填入**；此处全是说明性占位符，不可执行）：

```json
{
  "schema": "ces.ec289.report_publish_trust.v1",
  "enable_live_private_publication": true,
  "roots": {
    "issuer_id": "<approved issuer>",
    "operator_id": "<approved operator>",
    "minimum_policy_epoch": 1,
    "organization_public_hex": "<64 hex>",
    "route_public_hex": "<64 hex>",
    "revocation_public_hex": "<64 hex>",
    "content_reviewer_public_hex": "<64 hex>",
    "side_effect_public_hex": "<64 hex>",
    "provider_public_hex": "<64 hex>"
  },
  "target": {
    "provider_id": "<approved sandbox provider>",
    "account_id": "<approved account>",
    "project_id": "proj_<approved private project>",
    "destination_id": "<approved single private board>",
    "endpoint": "https://owned-private-sandbox.example.invalid/api/v1",
    "sandbox_private": true,
    "single_destination": true
  }
}
```

固定 Provider endpoint 只能被**原 EC228**用于 `POST /capability` 和至多一次 `POST /publish`。它必须真正支持签名的、只读的私有能力挑战、`create_only`、idempotency 和目的地权限验证；单靠本地 trust JSON 无法证明任何远端 ACL。`credential.txt` 是原业务支持的 16–2048 个可打印 ASCII 字符且无空白的令牌，`0600`，原始 bytes SHA pinned；不可打印到控制台回执。

## 2. 离线密钥、私有 Job 与 Host Policy

本示例路径只是操作接口，不代表有真实审批或网络权限。宿主管理员从可信源输入 Job，再固定所有文件 SHA、源码 SHA、内核允许 UID 和三把 **区别于原六把** 的新公钥。

```bash
python3 -I scripts/ces_report_publish_host.py keygen-offline --private-out /secure/signers/custodian.key
python3 -I scripts/ces_report_publish_host.py keygen-offline --private-out /secure/signers/publisher.key
python3 -I scripts/ces_report_publish_host.py keygen-offline --private-out /secure/publish/private/host-reply.key

python3 -I scripts/ces_report_publish_host.py prepare-job \
  --source-json /secure/publish/private/job-draft.json \
  --out /secure/publish/private/job.json

python3 -I scripts/ces_report_publish_host.py prepare-policy \
  --job-file /secure/publish/private/job.json \
  --trust-file /secure/publish/private/trust.json \
  --credential-file /secure/publish/private/credential.txt \
  --outbox-root /secure/publish/private/outbox \
  --admission-root /secure/publish/private/admissions \
  --allowed-uid 1001 \
  --custodian-public-hex '<custodian 64 hex>' \
  --publisher-public-hex '<publisher 64 hex>' \
  --server-public-hex '<reply 64 hex>' \
  --enable-one-private-test-publish \
  --out /secure/publish/private/policy.json
```

`prepare-policy` 用原**未修改**的 `ReportPublisher` 构造器验证独立原公钥与 HTTPS/private-only scope；独立源码 SHA 和新 Host 核心代码 SHA 均入 `policy.json`。新 policy 的 `policy_sha256` 须**另经可信信道核对**，不能盲信客户端从同一可改路径取得的 SHA。Policy **没有**签发原 EC228 审批，不能把模拟 human approval 当真。

## 3. 两张独立短票 → Host 进程 → 一次请求

同一 Unix kernel UID、相同 Job/trust/token/原审批 Markdown SHA、业务/宿主源码和 policy SHA 才能使用。最多 **20 秒**，并且原 EC228 revocation 最多 **30 秒**、side-effect grant 最多 **45 秒**；离线批准务必提前协调，超时即停止；**不能通过延长 Host TTL 绕过原签名有效期**。

```bash
python3 -I scripts/ces_report_publish_host.py prepare-offline \
  --policy-file /secure/publish/private/policy.json \
  --policy-sha256 '<policy_sha256>' --uid 1001 --ttl-seconds 20 \
  --out /secure/offline/publish-subject.json

python3 -I scripts/ces_report_publish_host.py sign-custodian-offline \
  --subject-file /secure/offline/publish-subject.json \
  --private-key-file /secure/signers/custodian.key \
  --out /secure/offline/custodian.vote

python3 -I scripts/ces_report_publish_host.py sign-publisher-offline \
  --subject-file /secure/offline/publish-subject.json \
  --private-key-file /secure/signers/publisher.key \
  --out /secure/offline/publisher.vote

python3 -I scripts/ces_report_publish_host.py assemble-offline \
  --subject-file /secure/offline/publish-subject.json \
  --custodian-vote /secure/offline/custodian.vote \
  --publisher-vote /secure/offline/publisher.vote \
  --custodian-public-hex '<custodian 64 hex>' \
  --publisher-public-hex '<publisher 64 hex>' \
  --out /secure/offline/one-private-publish.grant
```

宿主 UID 启动单线程 Unix Host，核对 Host signed reply 公钥：

```bash
python3 -I scripts/ces_report_publish_host.py serve \
  --socket /secure/publish/sockets/ec289.sock \
  --policy-file /secure/publish/private/policy.json \
  --policy-sha256 '<policy_sha256>' \
  --server-private-key /secure/publish/private/host-reply.key
```

仅授权客户端 UID 使用**字面量**统一控制台路径，实际命令不可由 `run` 提权替代：

```bash
python3 -I scripts/ces_next.py host-publish ReportPublish PrivateTest \
  --socket /secure/publish/sockets/ec289.sock \
  --grant-file /secure/offline/one-private-publish.grant \
  --policy-sha256 '<policy_sha256>' \
  --server-public-hex '<independently-pinned reply public hex>'
```

CLI 返回值：`2` 只表示有受签名 Host 回执的原业务 `partial/2`，且 Provider HTTP 返回允许码、`publication_state=SUBMISSION_UNCONFIRMED`。`3/4/5` 表示拒绝/参数错误/不可用。**即使没有响应、旧回执被替换、Host admission 已消费、原 EC228 已提交但 response 丢失，也不得从任何响应推断未发布或可重试。** 用户端的 `automatic_publish_retry_allowed` 恒为 false。

## 4. 统一延后验收 / 故障调查

- 核对 EC289 `admissions/ec289-<grant>` 和原 EC228 `outbox/ec228-<operation>` 两份耐久记录；尤其是 `01_CAPABILITY_REQUESTED`、`03_POST_ATTEMPTED`、`05_POST_UNKNOWN`。账本 claim 后即使没走到 POST，也**不得对同一原报告/目的地盲发**。应使用**新授权的只读、独立 provider 对账**，不能把 2xx 当作 EC230 的确认发布回执。
- 检查实际单目的地 TLS、真实 private endpoint ACL、Provider `create_only` 与 idempotency、cred 不被代理泄露、私有源/六个原批准人和三个新 Host 角色的真实组织独立性、撤销及时性、可信时钟、权限/备份/宕机恢复及文件系统 fsync 语义。用户没有提供这些实际目标和凭据，本轮不访问外部网络。
- 本轮开发测试使用真实存档报告、真实原 EC228 的代码与完整业务签名验证、内核 Unix UID 和 Ed25519，但 provider capability/publish 是同进程测试替身；不是生产验收。原 PowerShell7 15 Smoke、CI、真实远端可见性、Windows/macOS、多宿主/NFS、合规 DLP/人工法律审批、EC230 独立确认及完整 E2E 仍列为最终用户统一验证。EC249 未全功能 / EC250 BLOCKED / B001 OPEN / 全局质量 PASS=false。

源：`construction/ec289_report_publish_host/{protocol,daemon,operator,test_host}.py`，原模块 `construction/report_publish.py` 保留不改。完整证据：`EC-289.md`、`construction/EC289_SCOPE.json`、`construction/EC289_LOCAL_REPORT.json`、`construction/EC289_DELIVERY_SHA256.json`。
