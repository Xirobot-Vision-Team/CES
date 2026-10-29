# EC290 — 原 EC230 私有报告回执 GET：独立授权宿主操作说明

Historical record names below are archival references; those files are absent
from this source tree. See [cleanup scope](../docs/CLEANUP.md).

**本轮施工版本 V6.00 / R290 / EC290。** 唯一新增业务能力：对已经留下原 EC228 持久化 `03_POST_ATTEMPTED` 的一份原 EC199/200 私有报告，使用**原封未改的** `publication_receipts.PublicationReceiptService.inspect_report` 做一次精确的、单独批准的 HTTPS Provider `/receipts/<operation>?nonce=...` **GET**，比对 Provider Ed25519 签名回执和原报告、目标、operation、nonce、状态，落下原 EC230 独立审计。EC290 **不是**再次调用 EC228、不是远端发布写入、不是报表公开可见性证明、不是整理原 EC229 本地 worktree。

## 分离的角色和文件

- 原 EC228 六个业务公钥和五种原始完整签名、EC199/200 只读存储、原私人目标绑定，以及 EC289 `encode_original_request(req)` 输出的准确 Job 和原 EC289 `TRUST_SCHEMA` 格式 Trust JSON 必须事先在私有管理员机器中准备好；**重新签名或修改原报告内容不在 EC290 范围内**。
- 原 EC230 **read** 授权公钥 + **cleanup** 公钥两把互异密钥，后者本轮仅按原 EC230 构造契约固定、`enable_clean_linked_worktree=False`，不会接受 cleanup 操作。再有本轮新的 source custodian、receipt inspector 两把线下公钥及一把宿主 reply 签名公钥。全部 **11 把公钥不同**，但不同密钥**不能替代真实多人的组织隔离**。
- **只需提供一个新的独立 Provider 只读 GET Token**（`read_credential_file`），不需要、也不应把原 EC228 **发布/POST Credential** 配置给此宿主。EC230 历史结构校验用的原 access credential 在代码中填入明确不可签发的 `INERT_ORIGINAL_PUBLISH_TOKEN`，只用于满足原类型约束和检查读写 Token 不同。原本 EC289 写 Host 的 Credential **禁止复制到 EC290**。
- Owner-private `0600` Job、Trust、Read Token、Policy 和离线私钥（建议各角色分别保管）；`0700` 原 EC228 outbox、独立 EC230 audit、EC290 admission；Unix Socket 的父目录仅 owner 或管理员指定组可到达。宿主固定所有原始 bytes SHA、受保护源码 SHA、精确 UID、operation/target/grant SHA、Provider 身份，不允许 Socket 来客传文件路径、报告内容、URL、Token 或回调。
- 原来的 `construction/publication_receipts.py` 中 EC230 的原始 `READ_DOMAIN` 独立读审批与独立一次性 `ec230-read-*` 审计**才是提供方读取权限和持久化事实审查的真实关口**；EC290 额外的两个短票不能取代原 read signer。

## 命令范例：离线批准 + 一次性准确 GET

下述 `./owner/...` 路径是**占位符**，必须全部替换为管理员已经准备好的真实**绝对路径**，并在私有目录中运行；不要把用户凭据或私钥上传到本仓库或打包交付。使用 Python 3、cryptography、原 CES Python 依赖；此入口要求有可核实内核 peer UID 的 POSIX AF_UNIX。命令中的 `READ`, `CLEANUP`, `CUSTODIAN`, `INSPECTOR`, `SERVER` 均替换为独立离线操作得到的真实 Ed25519 公钥 hex，五把新钥不能和原六把重合。原 EC289 已提供 `prepare-job` 与离线角色 `keygen-offline` 功能，但请避免在线服务器自发签发线下角色权限。

```bash
# 先准备真实原 EC289 保存的 exact original EC228 job.json 和 trust.json
# 另在宿主 owner-private 文件中只保存一枚只读 Provider GET Token。
python3 -I -B scripts/ces_report_receipt_host.py prepare-policy \
  --job-file /owner/job.json --trust-file /owner/trust.json \
  --read-credential-file /owner/private-receipt-get.token \
  --outbox-root /owner/ec228-outbox --audit-root /owner/ec230-audit \
  --admission-root /owner/ec290-admission --allowed-uid 1000 \
  --read-public-hex READ --cleanup-public-hex CLEANUP \
  --receipt-epoch 4 --custodian-public-hex CUSTODIAN \
  --inspector-public-hex INSPECTOR --server-public-hex SERVER \
  --enable-one-private-report-readback --out /owner/receipt-policy.json

# 这里的 SHA 使用 prepare-policy 返回值；每张票使用最新的完整原始 bytes。
python3 -I -B scripts/ces_report_receipt_host.py prepare-read-template \
  --policy-file /owner/receipt-policy.json --policy-sha256 POLICY_SHA \
  --ttl-seconds 34 --out /owner/read-template.json

# 交给真正独立的原 EC230 只读审批者线下复核、签署（单次许可 1~35s）。
python3 -I -B scripts/ces_report_receipt_host.py sign-read-offline \
  --template-file /owner/read-template.json \
  --private-key-file /owner/keys/ec230-read.key --out /owner/read-permit.json

python3 -I -B scripts/ces_report_receipt_host.py prepare-offline \
  --policy-file /owner/receipt-policy.json --policy-sha256 POLICY_SHA \
  --read-grant-file /owner/read-permit.json --uid 1000 \
  --ttl-seconds 24 --out /owner/read-subject.json

python3 -I -B scripts/ces_report_receipt_host.py sign-custodian-offline \
  --subject-file /owner/read-subject.json \
  --private-key-file /offline/source-custodian.key --out /owner/custodian.vote
python3 -I -B scripts/ces_report_receipt_host.py sign-inspector-offline \
  --subject-file /owner/read-subject.json \
  --private-key-file /offline/independent-inspector.key --out /owner/inspector.vote
python3 -I -B scripts/ces_report_receipt_host.py assemble-offline \
  --subject-file /owner/read-subject.json --custodian-vote /owner/custodian.vote \
  --inspector-vote /owner/inspector.vote --custodian-public-hex CUSTODIAN \
  --inspector-public-hex INSPECTOR --out /owner/ec290-grant.json

# 单独可信服务进程；在实际操作中应先启动服务，再签发短时效许可。
python3 -I -B scripts/ces_report_receipt_host.py serve \
  --socket /owner/socket/receipt.sock \
  --policy-file /owner/receipt-policy.json --policy-sha256 POLICY_SHA \
  --server-private-key /owner/keys/receipt-server.key

# 另一终端、只选择此显式命令；不是 Router `run` 的通用 Host 提权。
python3 -I -B scripts/ces_next.py host-receipt ReportPublish Readback \
  --socket /owner/socket/receipt.sock --grant-file /owner/ec290-grant.json \
  --read-grant-file /owner/read-permit.json --policy-sha256 POLICY_SHA \
  --server-public-hex SERVER
```

**发行时注意：** 为可操作性，文档按从权限准备到调用列出命令；正式使用时应先启动 Server，再在不同角色的授权环境中临近调用时签发 ≤35 秒的 EC230 read permit 和 ≤25 秒的两票 Host grant。示例中的 `/owner/...` 是示意，任何路径、实际目标、UID 和许可时效都应经过管理员逐项审核。

## 成功与拒绝的真实含义

| 精确结果 | 正确理解 | 必须避免 |
| --- | --- | --- |
| `partial/2` + `SIGNED_PROVIDER_PRIVATE_TEST_RECORD_OBSERVED` | 本次独立 Provider 回执 GET 返回经原 EC230 校验的**单个私有测试记录**签名事实，原 EC230 `02_OBSERVATION` 已落盘 | 不能称公有/生产发布、外部世界可见或报告已经投递成功 |
| `partial/2` + `UNKNOWN_PROVIDER_REPORTS_NOT_FOUND` | 签名 Provider 回报未找到；只能记为 UNKNOWN | 不可据此断言原 EC228 未执行 POST 或绝对不存在远端记录 |
| `blocked/4`, `unavailable/5`, Host `permission_denied/3` | 原签名/身份/路径/权限/账本或 Provider 回执不满足，无法出具积极远端证据 | 不可将 Provider 201/202 或没有回执解释为发布成功 |
| Socket 断连、超时或签名回执缺失/无效 | **UNKNOWN**：EC290 host admission 或原 EC230 read audit 可能已消耗，Provider GET 也可能执行 | 不可自动换一个 grant 反复读，更不可重发 EC228 publish |

两个**互不替代**的本地一次性屏障：EC290 `admission/ec290-<host-grant-id>` fsync 发生在 GET 前；原 EC230 `audit/ec230-read-<inspection-id>/00_CLAIM` 和 `01_ATTEMPT` fsync 发生在原本只读 HTTP GET 前，只有签名 Provider 正确且当前权限仍满足才有 `02_OBSERVATION`。Host 仅做重复检查、独立 UID/线下授权、调用原 EC230、保守包装/签名，不修改原 EC230。

如果未知，隔离查看**原 EC228 outbox**、本轮 Host admission、**原 EC230 audit** 和 Provider 只读远端状态；新的读取必须在明确审计后重新独立审批，绝不能由客户端循环自动触发。权限失效到实际 HTTP syscall 之间仍有非原子时间窗；可信系统时间、存储断电耐久、Provider TLS/证书/ACL 与私有对象提供方签名仍需实际终验。

## 证据与待统一验收

- **本轮真实本地能力：** 13/13 新 EC290 cases (真实本地原 EC199/200 报告、原 EC228 journal、原 EC230 `inspect_report`、Ed25519 + Unix peer UID、独立只读票、双 Host 线下票、真实 Host 签名回执、控制台和重放/伪造/超时分支)。未修改原 `test_publication_receipts.py` 28/28；另未修改原 EC228 + EC289 Host 53/53 局部回归通过。
- Provider `HTTPSPrivateReceiptReader.read` 在聚焦用例中被 **FakeGET** 代替；实际公网/私网 HTTPS 与 Provider 完整性、真组织签名者、真实真实 UID/组分离及可信时间、真实多节点 durable filesystem、故障恢复/时钟回拨、Git/CI、原 PowerShell7 15 Smoke、Windows/macOS 和全部工程终验未验证。
- EC290 不增 Router 原 74 路由，不解除其 11 条 `HOST_REQUIRED run` 默认拒绝；原 R150 PowerShell、EC228/230 原文件以及 EC279–289 宿主源码均未修改。

详见 `EC-290`、`范围`、`本地局部报告`、`完整交付 SHA`。EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED`、B001 `OPEN`，全局 Quality PASS=false，final acceptance `NOT_STARTED` 不变。
