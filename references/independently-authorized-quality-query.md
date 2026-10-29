# EC280 — QualityShow.Query 私有证据批次双签只读宿主（V5.90/R280）

## 目标与现有边界

本轮只新增一条**明确授权、独立进程运行、真实调用 EC188 `QualityShow.query`** 的质量证据查询路径。统一入口是：

```bash
python3 -I scripts/ces_next.py host-query QualityShow Query \
  --socket /run/ces-quality/read.sock \
  --grant-file /operator/quality-grant.json \
  --policy-sha256 <部署方独立确认的原字节策略SHA256> \
  --server-public-hex <已预先独立校验的宿主公钥>
```

原 EC241/243 Router 的 74 项注册表、11 个 `HOST_REQUIRED` 拒绝和既有 `run QualityShow Query` **保持原样**；EC279 的 `host-query FindingShow Query` 仍可使用，另外九种 HOST_REQUIRED 尚无独立宿主。旧 R150 PowerShell、EC181–188 生产者和投影逻辑不改。既有 `QualityShow.query` 接受调用者提供的收据，并明确**不验证外部收据真实性/完整覆盖**；本轮以宿主固定的**私有批次文件 + 原字节 SHA-256**让客户端不能替换一批证据，但**绝不**把锁定批次说成真实 Git/CI 证明、质量通过或供应商认证。

## 实际服务信任边界

1. **私有文件只从服务端策略指定**：独立管理的 `/trusted/quality-policy.json` 精确固定证据批次路径、其原始字节 SHA-256、游标 HMAC 密钥的私有路径与 SHA、唯一 source scope、两把离线签发公钥、第三把服务签名公钥和允许连接者的真实内核 UID。策略原字节 SHA 从启动参数及客户端独立提供；宿主每次请求均重新验证，热篡改即拒绝。证据批次和密钥必须为 regular、非符号链接、私有（无组/其他权限）文件；批次上限约 2 MiB，记录数最多 96。批次中的 EC181–187 结果仍由**原 EC188** 检查类型、同源、时间、生产者摘要及数据投影。仅批次 SHA 相符**不证明**上游收据来自真实可信主体。
2. **真实 Unix Socket + OS peer UID**：宿主使用 AF_UNIX，Linux `SO_PEERCRED` 或支持平台 `getpeereid` 取得**内核连接者 UID**。非 Unix/不可读取内核 peer 的环境不启动。Socket 父目录禁止 world-writable、路径不得已存在，Socket mode 0660。生产部署方需提供相互隔离的宿主和查询账户、可信目录权限及不可由客户写入的策略/批次/私钥；本地同 UID 测试不是这种隔离的证明。没有 HTTP/TCP、动态 Python callback 或任意路径从客户端读。
3. **两位离线签发者都批准同一份 exact subject**：`evidence` 角色允许读**指定私有证据批次**，`query` 角色允许**指定源、过滤条件、页大小、数值指标开关及历史 PR 确认**。同一个规范 subject 同时绑定内核 UID、策略 SHA、批次 SHA、随机 grant ID、发行时间和 ≤600 秒截止时间。两张 Ed25519 签名使用 EC280 独立领域前缀，与 EC279 的 FindingShow 离线票完全不可互换。两把离线签发者私钥既不在在线宿主也不在查询命令中。若数字指标未在两票精确绑定的 query 中打开，客户端不能靠修改请求升权。
4. **查询及每条证据再次核验**：通过双方签名和内核 UID 后，宿主重新读取 pin 住的批次、HMAC 密钥并构建原 EC188 `QualityShow.query`。原 EC188 的 `authorize_scope`、`authorize_evidence`、可选 `authorize_numeric_metrics` 回调只接受这个宿主加载的唯一 source scope、query digest 与被固定批次内实际包含的精确 record/receipt SHA。不接受客户端传进来的 `evidence`、授权布尔值、路径或回调。EC188 的 cursor 完整复用，签过的同一 query 可在票有效期内逐页读取；批次或游标 key 变化立即拒绝，无权仅持 cursor 读取。
5. **第三位宿主签名回复**：真实 EC188 `partial/2` 结果及拒绝由宿主另一把 Ed25519 密钥签署，包含 nonce、完整原请求 SHA、策略 SHA、批次 SHA 和签署时刻；客户端必须用**事先可信固定**的宿主公钥检查签名、时间、同源 query/scope SHA 和只读/未验证标志后显示。状态 `2` 仅表示已投影的证据*声明*，不代表**QUALITY_PASS**。单张票可复用于短 TTL 内的翻页：这是读能力，不能等同一次性、审计防重放或跨重启吊销承诺。

### 批次文件格式

先由受控的**证据采集/审核流程**独立准备一份 `/private/quality/evidence.json`（权限 0600、宿主账户可读）。该流程决定哪些记录可信且应该纳入该批次；CES 不自动发现缺失的 CI 或运行输出。格式如下，`source_scope` 必须完全匹配每条记录和策略的 source scope；`result` 应放真实 EC181–187 输出，不能使用下面示意占位运行。

```json
{
  "schema": "ces.ec280.pinned_quality_batch.v1",
  "source_scope": {
    "source_mode": "WorkingTree",
    "root_pin_sha256": "<实际64位小写根身份摘要>"
  },
  "evidence": [
    {
      "kind": "config",
      "source_scope": {
        "source_mode": "WorkingTree",
        "root_pin_sha256": "<同一个实际根身份摘要>"
      },
      "recorded_at_utc": "2026-10-25T00:00:00Z",
      "result": {"schema": "<真实 EC181 QualityDetect 输出，完整对象，非该占位值>"}
    }
  ]
}
```

`evidence` 可以为空，届时 EC188 明确返回 `NO_MATCH_IS_NOT_NO_EVIDENCE`。支持 `config / ci_metadata / sha_binding / ci_evidence / observation / run_preflight / run_session`，每条生产者摘要、字段及复杂来源验证由原 `quality_show.py` 处理。仅展示以下 SHA 命令操作，不将其 stdout 解释为第三方背书。

### 部署前独立密钥生成及 policy

由三个独立安全主体分别执行一个指令；**不要把三个真实生产私钥集中在一个目录或同一可读主机**：

```bash
python3 -I scripts/ces_quality_host.py keygen-offline --private-out /trusted/quality-host.key
python3 -I scripts/ces_quality_host.py keygen-offline --private-out /offline-evidence/issuer.key
python3 -I scripts/ces_quality_host.py keygen-offline --private-out /offline-query/issuer.key
```

每个命令仅返回该私钥对应的 `public_hex`。再由受控宿主账户生成**不同于签名私钥的**独立游标 HMAC Key（仅返回其 SHA，不返回密钥）：

```bash
python3 -I scripts/ces_quality_host.py keygen-cursor --private-out /trusted/quality-cursor.key
sha256sum /private/quality/evidence.json
```

创建由管理员拥有、`0600`、不可被操作者更改的 `/trusted/quality-policy.json`：

```json
{
  "schema": "ces.ec280.quality_host_policy.v1",
  "evidence_file": "/private/quality/evidence.json",
  "evidence_sha256": "<证据JSON文件原字节SHA256>",
  "cursor_key_file": "/trusted/quality-cursor.key",
  "cursor_key_sha256": "<keygen-cursor返回的SHA256>",
  "source_scope": {
    "source_mode": "WorkingTree",
    "root_pin_sha256": "<与批次一致的真实根身份SHA256>"
  },
  "evidence_issuer_public_hex": "<离线 evidence 签发公钥>",
  "query_issuer_public_hex": "<离线 query 签发公钥>",
  "server_public_hex": "<宿主的公开签名公钥>",
  "allowed_uids": [1001]
}
```

`allowed_uids` 示例 1001 **必须替换为查询客户端的实际操作系统 UID**。批次/密钥 SHA 都为小写 64 hex。必须从可信独立部署记录取得该 policy **最终原始字节 SHA-256**（包括换行、空格），不能从客户请求 JSON 推导。

由**拥有私有证据读取权限的受控宿主 OS 账户**启动：

```bash
python3 -I scripts/ces_quality_host.py serve \
  --socket /run/ces-quality/read.sock \
  --policy-file /trusted/quality-policy.json \
  --policy-sha256 <真实策略原字节SHA256> \
  --server-private-key /trusted/quality-host.key
```

Socket 父目录必须预建并设定准确的宿主所有权、授权访问组/ACL、禁止 world-writable。不要在 world-writable `/tmp` 目录根位置部署 Socket；若先前进程异常残留路径，管理员审查后清理，不要由服务自动覆写未知 Unix inode。建议宿主为独立最小权限账号，查询者不能改批次、游标私钥或策略。跨重启安全时间、发行者吊销、审计/泄漏响应和硬件签发体系不在 EC280 实现范围内。

### 两个离线角色批准同一条 query

操作者填写 `/operator/exact-quality-query.json`，`source_scope` 和 policy/batch 必须一致；此示例不请求数字指标：

```json
{
  "source_scope": {
    "source_mode": "WorkingTree",
    "root_pin_sha256": "<实际根身份SHA256>"
  },
  "filters": {},
  "page_size": 10,
  "include_numeric_metrics": false,
  "acknowledge_historical_proposal": false
}
```

使用真实 UID、policy SHA、证据批次 SHA 生成一份**尚未授权**的 exact subject，签发窗口严格为 1–600 秒：

```bash
python3 -I scripts/ces_quality_host.py prepare-offline \
  --query-file /operator/exact-quality-query.json \
  --uid <真实查询OS UID> \
  --policy-sha256 <真实策略SHA256> \
  --evidence-sha256 <真实批次SHA256> \
  --ttl-seconds 300 --out /operator/quality-subject.json
```

分别将**同一份 subject**交给 evidence 和 query 授权者核对完整内容并由其离线签字：

```bash
python3 -I scripts/ces_quality_host.py sign-evidence-offline \
  --subject-file /operator/quality-subject.json \
  --private-key-file /offline-evidence/issuer.key --out /operator/evidence-vote.json
python3 -I scripts/ces_quality_host.py sign-query-offline \
  --subject-file /operator/quality-subject.json \
  --private-key-file /offline-query/issuer.key --out /operator/query-vote.json
```

在操作者系统上用**事先可信的两把公钥**验证、组装；它只写票文件，绝不会宣告后端已授权：

```bash
python3 -I scripts/ces_quality_host.py assemble-offline \
  --subject-file /operator/quality-subject.json \
  --evidence-vote /operator/evidence-vote.json \
  --query-vote /operator/query-vote.json \
  --evidence-public-hex <真实独立 evidence 公钥> \
  --query-public-hex <真实独立 query 公钥> \
  --out /operator/quality-grant.json
```

然后执行文首 `scripts/ces_next.py host-query QualityShow Query ...` 或直接使用：

```bash
python3 -I scripts/ces_quality_host.py query \
  --socket /run/ces-quality/read.sock \
  --grant-file /operator/quality-grant.json \
  --policy-sha256 <事先可信的策略 SHA> \
  --server-public-hex <事先可信的宿主公钥> --pretty
```

取得结果内 `next_cursor` 后，可继续用**相同两票**附加 `--cursor '<原样完整游标>'`。若票过期，须再做两方离线授权。ProposedPR 必须在 query 里明确 `acknowledge_historical_proposal: true`；`include_numeric_metrics: true` 需签发者看到并批准**开启后的完整 subject**。额外的请求字段、路径、`authorize_*` 和任意 evidence 字段均不被接受。

## 返回语义及本轮验证

- **2 / partial**：两个离线角色及内核 UID 审批通过，主机完成*真实 EC188 质量摘要投影*并返回第三方宿主密钥的签名回执。绝不升级为质量通过，`quality_pass_verified` 与 `proof.verified_quality_pass` 仍是 false。
- **3 / permission_denied**：签名缺失/错误、内核 UID 不匹配、对象或权限范围不一致、过期或未到时、独立 host 路由未启用等。
- **4 / invalid_input**：请求形状、操作参数或离线准备输入无效。
- **5 / unavailable**：宿主、策略、批次、游标密钥、源证据、签名响应或可信来源无法核验。

**本轮本地定向执行**：EC280 使用私有文件、真实 AF_UNIX 宿主、三把真实合成 Ed25519 签名钥、EC188 真实 backend、两票、翻页、策略/批次/密钥篡改拒绝、数字指标权限、独立 CLI 与统一控制台做聚焦测试。只用 synthetic 收据、同一机器/UID 的合成三角色，不代表真实 CI Git、企业服务权限或实际验收。原 EC279 FindingShow、EC278 控制台及 native Smoke 需按随包报告准确标注完成情况。

**尚待使用者/生产环境协作的累计验收**：真实不同人及独立离线设备、受控 host 与查询者的不同 OS UID、Socket/文件 ACL、服务重启/吊销机制、可信时钟、真实 EC181–187 生产者与 CI/Provider/Git/Run 证据来源、Windows/macOS 适配、PowerShell7 原生 15 Smoke、其他九条 HOST_REQUIRED（原 Router 的 11 条仍全部默认拒绝）、以及总体验收。B001 `OPEN`、EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED`、Final Acceptance `NOT_STARTED`、Global Quality PASS=false。
