# EC250 — Linux 独立宿主本地 `FindingShow/Query` 实际调用入口

**工程包 V5.60/R250/EC250；源工程使用 PLAN-REV-002（原 EC250 冻结任务被保留为未达门槛、不是本轮验收）。** 本轮落实一个真实但受限的功能：在 Linux 上，宿主单独部署的私有策略文件和内核 `SO_PEERCRED` 验证客户端 UID 后，通过 AF_UNIX Socket 调用已有 EC179 `FindingShower.query` 读取 **真实 EC178 HMAC 账本**。不是只写协议或模拟 handler。本轮不改动旧 `ces.ps1`、原 15 Smoke、EC243 74 路由和 `HOST_REQUIRED` 拒绝；本宿主**单独入口**，不是给未授权 Router 注入权限。

## 运行前条件（由真实宿主部署者完成）

- Linux/POSIX AF_UNIX 且具有 `SO_PEERCRED`；Python3 及 CES 模块依赖已可用；现存的 EC178 私有 Finding 存储已经由正常过程初始化，并能由宿主进程读取。**Windows/macOS 不支持本入口，明确拒绝。**
- 宿主部署者**独立**从本机可信持久源确认三个绝对目录、可选 Codesave 根和 `expected_finding_store_pin`，从真实已获准源中配置完整 EC179 10 字段 `source_binding`。不要从外部查询请求、旧 Cursor、模型回答或来历不明的单份收据推断授权。
- 宿主创建一个位于工程目录之外、本人拥有、权限 0700 的策略目录；策略 JSON 本人拥有、权限 0600、普通文件且不可为符号链接。单独 Socket 目录为宿主拥有且**不可组写或公开访问**（0700 或 0710/0750），Socket 由宿主自动绑定为至多 0660。跨 UID 客户端访问需要实际 OS 组/目录访问权，且仍要通过策略中对**精确 UID+Scope** 的授权。
- 宿主策略本身是信任输入，**不是**当前工程签发的认证证书。开发包不存放真实配置、凭据或授权对象。独立企业身份/role/revocation、真实源合法性、跨主机隔离与宿主本身是否被攻击，都需要最后的运营验收。

## 宿主侧策略：仅示意形状，禁止直接投产

```json
{
  "schema": "ces.ec250.finding_host_policy.v1",
  "store": {
    "stage_root": "/operator/private/ces-stage",
    "business_repo_root": "/operator/pinned/business-repo",
    "finding_store_root": "/operator/private/finding-ledger",
    "codesave_root": null,
    "expected_finding_store_pin": "<operator-verified-exact-64-lowercase-hex>"
  },
  "grants": [{
    "uid": 1001,
    "scope_id": "approved_scope_001",
    "source_binding": {
      "run_id": "<from-a-real-host-verified-EC179-binding>",
      "handoff_id": "<from-the-same-binding>",
      "stage_revision": 1,
      "stage_event_sha256": "<64-lowercase-hex>",
      "source_mode": "WorkingTree",
      "task_kind": "code_analysis",
      "source_context_sha256": "<64-lowercase-hex>",
      "source_identity_sha256": "<64-lowercase-hex>",
      "evidence_hash": "<64-lowercase-hex>",
      "material_sha256": "<64-lowercase-hex>"
    },
    "source_mode": "WorkingTree",
    "allow_expired_audit": false,
    "allow_path_digest_query": false,
    "allow_digest_details": false,
    "acknowledge_historical_proposal": false
  }]
}
```

将真正的 UID、目录、完整绑定、StorePin 写入 `/operator/private/host-policy/policy.json`，文件 `chmod 600`。`scope_id` 仅是本机策略下的查找句柄，**不**是权限令牌。历史 ProposedPR 需要在独立策略中明确设置 `acknowledge_historical_proposal:true`，且 source_mode、binding 必须一致。

## 客户端请求：仅选择已批准的 Scope 与查询选项

```json
{
  "schema": "ces.ec250.finding_host_query.v1",
  "scope_id": "approved_scope_001",
  "filters": {},
  "page_size": 10,
  "cursor": null,
  "include_expired": false,
  "include_digest_details": false
}
```

客户端 JSON 严格固定上述 7 字段，不接受 `uid`、目录、授权布尔、Python 函数名、动态模块名、网络目标、令牌或私钥。`include_expired`、`include_digest_details` 和路径摘要过滤必须由宿主策略分别允许。每一分页都重读策略/精确绑定且复验账本 HMAC；旧 Cursor 只是分页提示，不是长效权限。

```sh
# 在独立宿主上启动服务端；只处理一条请求后自动退出；生产部署由宿主管理进程生命周期
python3 -I -B construction/ec250_finding_host/broker.py serve \
  --policy /operator/private/host-policy/policy.json \
  --socket /operator/private/host-socket/finding.sock \
  --max-requests 1 --accept-timeout 60

# 在已获准的客户端 OS 用户身份下，使用独立配置的宿主 UID 校验服务器身份
python3 -I -B construction/ec250_finding_host/broker.py query \
  --socket /operator/private/host-socket/finding.sock \
  --request-file /client/private/request.json --expect-host-uid 1000
```

客户端只有实际的内核 Socket 对端 UID 匹配信任配置才发送 JSON。Server 接收后由内核获取客户端 PID/UID；绝不相信请求中的伪造用户身份。授权有效时返回 `status=partial, exit_code=2` 及真实 EC179 账本查询结果；权限不足返回 `permission_denied/3`，无效请求为 `invalid_input/4`，存储或宿主不可用为 `unavailable/5`。`partial` **只证明局部 HMAC 已验证的声明读取，不证明 Finding 内容真实或缺陷存在**。

## 作用域与明确局限

- 宿主策略在**每次**请求和真实账本读取后重读；检测配置替换则丢弃响应。不能在所有调度竞态下阻止已经开始的读取，也不能代替 Linux 用户被撤销之后的 session/process 管理、跨主机锁或组织身份/role 的强校验。
- 本轮为**1 条固定宿主限定只读功能**提供单独的实际本地入口；原 Router 的 11/11 `HOST_REQUIRED` 条目仍保持拒绝。其余 10 类宿主模式（QualityRun、Knowledge、Issue 新建、Delivery/Report/DocsOnly 等）尚无此接口；本轮也**没有**实现真实 Quality 执行、Issue/Delivery 外部写或 Cycle 业务调度。
- 服务端串行处理，单请求 16KiB，响应 256KiB，策略 128KiB、最多 128 个 grant、最多 100 个请求/进程、Socket 单请求读超时 5 秒；不提供多机可用性、分布式令牌、真实企业权限、硬 CPU/磁盘/内存配额或服务审计账本。它没有主动网络外传和业务仓写指令；但授权客户端会通过本地 IPC 收到查询元数据，必须遵从真实企业隐私策略。
- **本地实测**：Linux 容器内 10 条当轮专项用例，包含真实生成的 EC178 HMAC 账本 → AF_UNIX Server → SO_PEERCRED → UID+Binding 授权 → 真实 FindingShow 查找和禁止泄露验证。它只证明本地合成用例；不代表企业/宿主/Provider/OS/性能/Windows/macOS/PowerShell7/E63–E66 的正式验收。

开发测试：`python3 -I -B construction/ec250_finding_host/test_broker.py`。原 EC249 未完成判定（历史记录，见清理前Git历史） 是 R249 的历史事实；其正式冻结阻塞条件**没有因本轮单一路由功能实现而消失**。新的 R250 施工记录见 EC250（历史记录，见清理前Git历史），当前下轮状态见 NEXT_ROUND（历史记录，见清理前Git历史）。


> Release 1.8.0: obsolete construction plans, progress/completion logs and their one-time checkers were retired. This document describes retained implementation boundaries; historical acceptance statements are not current release claims.
