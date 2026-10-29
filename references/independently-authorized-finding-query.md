# EC279 — 独立双签授权的 FindingShow.Query 私有记录只读宿主（V5.89/R279）

> 这是一条**实际可执行、默认不开启、与 EC241/243 Router 分离**的读路径，不是新的通用 Router 权限，也不是 Finding 的语义、真实 CI/人类身份认证。仅支持 `FindingShow / Query`。原 Router 的 **11 条 `HOST_REQUIRED` 均继续拒绝 RequestPath**；其中仅此一条拥有 EC279 **独立受控入口**。旧原生 R150、业务 Git/Issue、EC178/179 记录格式与其他路由全都没有重写。

## 安全模型与进程边界

- **独立宿主**：`scripts/ces_finding_host.py serve` 通过操作系统 `AF_UNIX` Socket 接受请求，不监听 TCP。通过 `SO_PEERCRED`（Linux）或 `getpeereid`（支持的平台）取**实际连接者 UID**；没有能力取得内核连接者身份的系统直接拒绝，Windows 本轮未实现。宿主和客户端实际部署**必须使用不同受控 OS 主体/账户**和最小权限；本地同 UID 合成测试仅验证逻辑，不验证生产主体隔离。Socket 所在目录由宿主管理（不可 world-writable），服务创建 0660 Socket，部署方应设置正确所有者、组与 ACL。请勿将 Socket 目录放入 world-writable `/tmp` 根目录或让客户端写入 Socket 目录。
- **宿主策略不来自请求**：固定在启动参数 `--policy-file` 和**另一路部署信任来源给定的** `--policy-sha256`。策略列出 EC178 stage/business/finding 的绝对路径、可选 codesave root、**原始 FindingStore 的确切 pin**、3 把互不相同 Ed25519 公钥及允许的 UID。每次查询重新读取策略并校验 SHA 和启动时内容，策略删除/替换/权限放宽立即拒绝。宿主内的 `FindingShower` 只用该策略确定私有根和 `expected_finding_store_pin`，客户端永远无法用 JSON 指定要打开的私有根或授权布尔值。
- **两个离线签发方**：`store` 审批者和 `query` 审批者分别签署**同一个**规范 JSON subject；两个角色独立的 Ed25519 私钥不进服务端和用户查询命令。subject 精确绑定 OS UID、EC178 store pin、完整 EC179 `authorized_source_binding`、source mode、所有过滤器、分页大小、历史/路径 SHA/详情开关及各自的授权布尔位、随机 grant ID、发行/过期 UNIX 秒。有效窗口上限 **600 秒**；缺一票、错票、过期、错 UID、改旗标或改查询都会在调用 FindingShow 前被拒绝。单张票可在有效窗内用于同一签过的查询和翻页（cursor 是独立的 EC179 5 分钟 HMAC 游标，**不是**额外权限）。`store` 和 `query` 只是两个签字角色，**实际是否由独立人员/组织保护私钥仍需部署方证明**。
- **客户端验证宿主答复**：宿主使用**第三把互不相同**的 Ed25519 host 密钥，签署域隔离的响应（真实 nonce、请求内容 SHA、宿主策略 SHA、签发时刻、原 EC179 响应全文）。客户端必须事先从可信渠道拿到真实 `--server-public-hex` 和 `--policy-sha256`，验证绑定、签名和有界时间窗后才展示读取结果；自填攻击者公钥、SHA 不构成实际组织信任。服务最大请求 24 KB、签名答复 135 KB，单连接 8 秒读超时，输出不含原代码/模型文本。结果仍保留 `partial / exit_code 2`，**不升级**为“Finding 被实证为漏洞”、CI 已运行或业务完成。
- **只读含义**：Host 不调用 FindingSaver.save、Git/Issue/Provider，也不写业务目录；但复用原 EC179 `FindingShower`，需要按原 EC178 `_locked` 对账本目录取得**排他 advisory flock**，读取它的私有 `.finding-key`、HMAC 序列和工作根的身份信息，所以宿主必须具有受控私有账本读取与目录锁权限。这不是无权访问的远程公共 API，也不是数据库快照隔离或恶意本机代码沙箱。

## 依赖与三方安装

需要 Python ≥ 3.10、`cryptography`、`AF_UNIX` + 内核 peer credential。原 `construction/finding_show.py`、`finding_save.py`、EC178 私有账本必须已存在。三个签名角色应由**三个不同安全环境**保管私钥；示例里的 `/trusted/`、`/offline-store/`、`/offline-query/` 代表不同机器/OS 账户，**不可**在同一可被普通用户读取的目录里存三把真实生产私钥。

在每个独立位置运行一次密钥生成（只生成本角色的密钥；不会覆盖已有文件；私钥为 32-byte raw Ed25519、0600，stdout 只打印其**公开** 64 hex）：

```bash
python3 -I scripts/ces_finding_host.py keygen-offline --private-out /trusted/finding-host.key
python3 -I scripts/ces_finding_host.py keygen-offline --private-out /offline-store/issuer.key
python3 -I scripts/ces_finding_host.py keygen-offline --private-out /offline-query/issuer.key
```

请把三份 stdout 的 `public_hex` 按角色通过**外部可信配置途径**交给宿主管理员。宿主管理员根据真实初始化成功的 EC178 `save_store_pin` 建立唯一受信策略，例如：

```json
{
  "schema": "ces.ec279.finding_host_policy.v1",
  "stage_root": "/private/ces/stage",
  "business_repo_root": "/work/selected-repository",
  "finding_store_root": "/private/ces/findings",
  "codesave_root": null,
  "store_pin": "填写真实的64位小写store-pin",
  "store_issuer_public_hex": "填写离线store签发者真实的64位hex公钥",
  "query_issuer_public_hex": "填写离线query签发者真实的64位hex公钥",
  "server_public_hex": "填写宿主服务真实的64位hex公钥",
  "allowed_uids": [1001]
}
```

将文件保存成宿主私有的 `/trusted/finding-policy.json`，安全审查文件权限（不得 group/world 可写），从独立部署/变更管理记录取得**该文件原始字节 SHA-256**（含尾部换行），而不是让客户端 JSON 决定 pin。实际 `allowed_uids` 必须用客户端 OS 账户的真实 UID，测试例子 `1001` 不自动可信。服务宿主账户对本机真实目录必须有最小限度的账本/锁读取权限；如果业务根或私有 root 曾迁移，请先使用原 EC178/179 机制核对目录、store pin 和 root 身份。

由受控**宿主账户**启动（宿主机器的 Python 需可导入 `cryptography`，Socket 目录提前建好、所有权正确；策略和私钥必须可读，Socket 目录仅允许授权组进入）：

```bash
python3 -I scripts/ces_finding_host.py serve \
  --policy-file /trusted/finding-policy.json \
  --policy-sha256 <真实策略文件SHA256> \
  --socket /run/ces-finding/read.sock \
  --server-private-key /trusted/finding-host.key
```

宿主上线不是自动允许任何查询。运行中的 Query 收到无凭据连接、缺票/坏票、策略篡改或临时断连时均拒绝或关闭；崩溃后可能留下旧 Socket inode，管理员确认服务已停止后再手工清理，绝不可自动覆盖不可识别的路径。严禁通过网络文件共享把签名钥匙/Socket 暴露给未授权用户。

## 离线批准一条真实查询

操作者从原 EC179 已授权的真实 source binding 取**全部**字段，不要凭空生成 hash、stage receipt 或源文件内容。把下面两个占位的 `source_binding` 和 `query_content_for` 按真实 `FindingShow` 精确绑定填写。其它所有字段都是**签过后不可扩权**的字段：

```json
{
  "source_binding": {
    "run_id": "真实run_id",
    "handoff_id": "真实handoff_id",
    "stage_revision": 1,
    "stage_event_sha256": "真实64位SHA",
    "source_mode": "WorkingTree",
    "task_kind": "code_analysis",
    "source_context_sha256": "真实64位SHA",
    "source_identity_sha256": "真实64位SHA",
    "evidence_hash": "真实64位SHA",
    "material_sha256": "真实64位SHA"
  },
  "query_content_for": "WorkingTree",
  "filters": {},
  "page_size": 10,
  "include_expired": false,
  "include_digest_details": false,
  "authorize_expired_audit": false,
  "authorize_path_digest_query": false,
  "authorize_digest_details": false,
  "acknowledge_historical_proposal_metadata": false
}
```

将上面保存为 `/operator/exact-query.json`。在可校验、可传输的操作环境中首先输出**尚未授权**的精确 subject（TTL 1–600 秒）：

```bash
python3 -I scripts/ces_finding_host.py prepare-offline \
  --query-file /operator/exact-query.json --uid <操作者UID> \
  --store-pin <真实store-pin> --ttl-seconds 300 --out /operator/subject.json
```

**store 与 query 两位签发者分别在自己的隔离机器上**审核原 subject 的完整字段并运行（两者读取**相同字节**的 subject；签名不可替代操作者查看权限）：

```bash
python3 -I scripts/ces_finding_host.py sign-store-offline --subject-file /operator/subject.json \
  --private-key-file /offline-store/issuer.key --out /operator/store-vote.json
python3 -I scripts/ces_finding_host.py sign-query-offline --subject-file /operator/subject.json \
  --private-key-file /offline-query/issuer.key --out /operator/query-vote.json
```

拿到两个签名 vote 文件后在**不需要私钥**的操作者机上精确校验并组装：

```bash
python3 -I scripts/ces_finding_host.py assemble-offline \
  --subject-file /operator/subject.json \
  --store-vote /operator/store-vote.json --query-vote /operator/query-vote.json \
  --store-public-hex <可信store公钥> --query-public-hex <可信query公钥> \
  --out /operator/dual-grant.json
```

最后通过**V5.89 的统一命令入口**调用这一条固定宿主路径：

```bash
python3 -I scripts/ces_next.py host-query FindingShow Query \
  --socket /run/ces-finding/read.sock \
  --grant-file /operator/dual-grant.json \
  --policy-sha256 <事先独立确认的策略SHA256> \
  --server-public-hex <事先独立确认的宿主公钥> --pretty
```

也可以独立调用 `python3 -I scripts/ces_finding_host.py query ...`（参数相同但无 `FindingShow Query`）。完整签名回执是 `signed_reply`，其 `result` 是原 EC179 经过服务端校验私有 HMAC/源绑定的原样读结果。`next_cursor` 非空时，以**同一份有效双票**追加 `--cursor '...'` 继续下一页；票过期必须重新做两次线下审批。控制台的 `run FindingShow Query --request-file` **仍然拒绝**，`host-query IssueCreate Create` 也拒绝，不允许转交其他 10 条需要 Host 的动作。

## 退出含义与真实验收边界

- `0`：离线 keygen/prepare/sign/assemble 写出自己的**局部 artifact**。这是文件操作完成，**不代表宿主已授权**。
- `2`：宿主签名通过、返回真实 EC179 `partial` 的私有 HMAC-backed Finding 元数据。这不是漏洞/测试/当前 Git/真人真实签字的业务证明。
- `3`：权限、签名、UID、有效期、策略绑定、宿主路由隔离等拒绝。`4`：请求/格式不合法。`5`：宿主不可用/策略或账本读取失败/不可信回执。
- **本地已做**：10/10 新聚焦场景，包括真实 EC178 写入→双签 socket 查询、双签拒绝、内核 UID 绑定、真实 EC179 翻页与详情、策略热篡改拒绝、回执防伪、完整离线 CLI、EC278 控制台新子命令；原 EC278 12/12 回归通过。
- **部署/最终用户辅助验收待办**：真实三个角色物理/权限独立，生产 Socket 权限与跨 OS 用户连接，重启、删除 Socket 后人工恢复、服务账号文件 ACL、可信跨重启 UTC/NTP、防宿主/离线钥匙被盗、现网 EC178 私有账本与真实 source binding，Windows/macOS 是否具备相同 peer ID API，原 PowerShell7 15 Smoke、企业/CI/Provider 端到端链、其余十条 Host、外部 OCI/cgroup/TSA/HSM/WORM、E63–E66 和最终联验。**B001 OPEN、EC249 FULL_FUNCTION_NOT_COMPLETE、EC250 BLOCKED、final acceptance NOT_STARTED、global Quality PASS=false。**
