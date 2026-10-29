# EC282 — 完全独立、双离线授权的 KnowledgeImpact.Analyze Git 差异宿主

**版本 V5.92 / R282 / EC282。仅一个新功能：** 通过新的 `host-impact KnowledgeImpact Analyze` 操作入口，让原 `construction/knowledge_impact.py::KnowledgeImpact.analyze` 的 **EC204 真实已签名 Git 选定路径差异分析**可以被独立配置的 Unix 宿主实际调用。不是改写 EC204，不是 Router 的默认 Host 许可，也不自动推送/保存知识库。

## 能力与信任边界

1. **完全由服务器决定的私有工作项**：服务器以 owner-private `0600` 文件持有 EC202 request/read policy、EC203 target read policy/已签 delivery、EC204 impact policy/已签 baseline、两组信任 Ed25519 公钥、实际仓库与知识根目录、精确 Git ref 及固定 Git 可执行文件。整份工作项的**原字节 SHA256**写入服务器 owner-private `0600` 策略，并由两名不同离线签发者共同签署。客户端仅有短期 `grant`，不得选新的仓、路径、ref、钥、policy 或 handler。
2. **身份与双签**：真实 AF_UNIX `SO_PEERCRED`（或支持时 `getpeereid`）取得连接方内核 UID；必须等于工作项票中 UID 且属于 host allowlist；source/reader 两个不同 Ed25519 公钥签署**同一**含 policy SHA、job SHA、repo/ref 和 300 秒内生存期的 subject，使用 **EC282 专属签名域**。不能用 EC279、EC280、EC281 的旧授权票代替。客户端发送 nonce；host 第三把密钥签署 nonce + 完整请求 SHA + 两 SHA pin + 时间戳 + 全结果（或拒绝），客户端自己用外部提供的 host 公钥核验。
3. **调用真实 EC204 的完整重验证链**：EC202 真实受限文件/manifest 读取、EC203 原始 Git 对象与目标 commit/ref 重新验证、target delivery Ed25519 验证、EC204 baseline Ed25519 验证及 ancestry/selected Git blob 对比均使用**原实现**。新宿主比原 EC204 更保守：只有 EC204 确认**至少 1 条且所有授权选中 repository 路径均实际完成 Git 字节比较**、baseline 被确认为 commit 祖先、target 确认为签过的 delivered ref，才向客户端返回原 `partial/2` 明文投影。若 Git ref 转移、目标签名不可信、部分选中路径无法核验、私有文件被改或读取期间批准过期，一律只签署 `unavailable/5` 拒绝，**不泄露不完整的私有分析主体**。
4. **零提权/零写入**：`scripts/ces_next.py host-impact KnowledgeImpact Analyze` 才连接此单独安装的宿主；原 `run KnowledgeImpact Analyze` 仍走原 Router 拒绝。全部原 Router 74 条注册和 11 条 `HOST_REQUIRED` 的 run 路径零变更；原 PowerShell、EC202/203/204、原 EC279/280/281 均未修改。主机账号只能授予服务需要的只读仓与知识目录权限。没有任意命令、Git 网络 fetch、shell 参数注入或 Issue/Provider/Docs 写接口。运行分析不等于信任了实际组织签发者、Git 远端、commit 的商业身份或知识文本语义。

**注意结果解释**：`selected_change_set_state=SELECTED_REPOSITORY_PATHS_COMPARED` 仅表示**被逐条选中的代码文件差异**，而非整个仓库差异已扫描。`knowledge_chapter_impact_verified=false`、`whole_repository_change_set_complete=false`、`knowledge_sections_to_update=[]` 一直成立；已验证选择性 Git 字节不能推断“知识章节应修改”。`partial/2` 一直不是项目成功、Quality PASS 或发布许可。

## 安装和准备

运行环境需 Linux/兼容 AF_UNIX + 内核 peer UID、Python 3.11+、`cryptography`、有本地 Git 对象的可信只读 bare-style `.git` 布局（**不支持**不受信任的 alternates/grafts）、原 CES Python `construction/` 与只读仓库访问权。独立安装的 Git 可执行文件应来自管理员控制的只读位置。示例命令在包根 `ces/` 内执行。

**A. Host-only EC202/203/204 原始资料的准备**

先由真实独立的 source / target / baseline 管理者生成各自的证据和权限文件（模式 0600），而不是用 Host CLI 自动铸造外部 trust。需要：

- `target-keys.json` 与 `baseline-keys.json`：各自的 `key_id → Ed25519 raw public hex` JSON 映射，公钥身份、发行人授权和撤销状态需线下认证；两组不允许使用相同 Ed25519 原公钥。
- `request.json`、`bootstrap-policy.json`、`target-policy.json`、`impact-policy.json`：均是原 EC202/203/204 严格 schema 的完整真实私有文件；只读 permission/scopes 必须彼此绑定，**所有 write flag 必须关闭**。
- `target-statement.json` + `target-signature.b64`：原 EC203 的域分离 detached Ed25519 目标交付证明，b64 文件只存 canonical 88 字符签名。
- `baseline-statement.json` + `baseline-signature.b64`：原 EC204 的域分离 detached Ed25519 基线证明。新 Host 要求提供完整配对，且 target Git SHA/ref 与真实文件/祖先关系在分析当下仍有效。

B. 服务器管理员创建 `0600` **精确私有任务包**（提供 `prepare-job`，避免手工拼接 14 个字段）

```bash
python3 -I -B scripts/ces_knowledge_impact_host.py prepare-job \
  --repository-root /srv/ces/repo \
  --knowledge-root /srv/ces/knowledge \
  --repository-ref 'cesrepo1:REPLACE_WITH_64_HEX' \
  --target-ref refs/heads/main \
  --git-executable /usr/bin/git \
  --target-keys-file /srv/ces/private/target-keys.json \
  --baseline-keys-file /srv/ces/private/baseline-keys.json \
  --request-file /srv/ces/private/request.json \
  --bootstrap-policy-file /srv/ces/private/bootstrap-policy.json \
  --target-policy-file /srv/ces/private/target-policy.json \
  --impact-policy-file /srv/ces/private/impact-policy.json \
  --target-statement-file /srv/ces/private/target-statement.json \
  --target-signature-file /srv/ces/private/target-signature.b64 \
  --baseline-statement-file /srv/ces/private/baseline-statement.json \
  --baseline-signature-file /srv/ces/private/baseline-signature.b64 \
  --out /srv/ces/private/ec282-job.json
```

`prepare-job` 排他创建 `0600`，返回**仅 job SHA、repo/ref 等非秘钥值**；不能覆盖已经存在的文件，也不会替代原 EC202/203/204 的签名和原工作流。`inspect-job --job-file /srv/ces/private/ec282-job.json` 仅复核策略形状和文件字节 pin，**不会认定**外部签名合法或实际执行 Git 分析。Host admin 创建 `0600` JSON 策略（结构严格，没有其他字段）：

```json
{
  "schema": "ces.ec282.knowledge_impact_host_policy.v1",
  "job_file": "/srv/ces/private/ec282-job.json",
  "job_sha256": "THE_64_HEX_FROM_PREPARE_JOB",
  "allowed_uids": [2002],
  "source_issuer_public_hex": "RAW_ED25519_PUBLIC_HEX_A",
  "reader_issuer_public_hex": "RAW_ED25519_PUBLIC_HEX_B",
  "server_public_hex": "RAW_ED25519_PUBLIC_HEX_C"
}
```

三把 Ed25519 私钥分别用 `keygen-offline --private-out ABSOLUTE_PRIVATE_PATH` 排他创建 0600；真实部署时放在三种不同管理角色控制的独立签署环境，host 本机**只保存 server 私钥**；policy 只保存另两把公钥。三种宿主公钥不能相同，且不能与 job 里的 EC203 target 和 EC204 baseline 公钥混用。管理员须另行锁定策略文件 `sha256sum /srv/ces/private/ec282-policy.json`，`serve` 与每次客户端请求都应使用这个已人工核对的 SHA。生产不应依赖当前同机样例 signer。

C. **离线双人签发**（每位签发者实际检查完整私有任务原字节 SHA、身份、scope、目标 ref 与 expiry）：

```bash
python3 -I -B scripts/ces_knowledge_impact_host.py prepare-offline \
  --uid 2002 --policy-sha256 POLICY_SHA64 --job-sha256 JOB_SHA64 \
  --repository-ref 'cesrepo1:REPLACE_WITH_64_HEX' \
  --target-ref refs/heads/main --ttl-seconds 120 \
  --out /secured-transfer/subject.json

# 在不同离线环境，由不同人分别运行：
python3 -I -B scripts/ces_knowledge_impact_host.py sign-source-offline \
  --subject-file /secured-transfer/subject.json \
  --private-key-file /secure-source/source.ed25519 \
  --out /secured-transfer/source.vote.json
python3 -I -B scripts/ces_knowledge_impact_host.py sign-reader-offline \
  --subject-file /secured-transfer/subject.json \
  --private-key-file /secure-reader/reader.ed25519 \
  --out /secured-transfer/reader.vote.json

python3 -I -B scripts/ces_knowledge_impact_host.py assemble-offline \
  --subject-file /secured-transfer/subject.json \
  --source-vote /secured-transfer/source.vote.json \
  --reader-vote /secured-transfer/reader.vote.json \
  --source-public-hex RAW_ED25519_PUBLIC_HEX_A \
  --reader-public-hex RAW_ED25519_PUBLIC_HEX_B \
  --out /secured-transfer/impact-grant.json
```

`prepare-offline` 只创建无签名 subject；`assemble-offline` 两张相同 subject 的独立签名都核对后才会排他写 grant。已签发 subject **不能在离线签发后修改**，失效需重签；同一 grant 在 TTL 内可被多个新 nonce 读取（只读、不承诺一次性 replay cache）。

D. **启动专用宿主、真实请求：**

```bash
# 单独宿主 OS UID 运行：Socket 父目录不得 world-writable。
python3 -I -B scripts/ces_knowledge_impact_host.py serve \
  --socket /srv/ces/run/knowledge-impact.sock \
  --policy-file /srv/ces/private/ec282-policy.json \
  --policy-sha256 POLICY_SHA64 \
  --server-private-key /srv/ces/private/server.ed25519

# 另一个终端/允许的 OS UID，固定控制台字面量：
python3 -I -B scripts/ces_next.py host-impact KnowledgeImpact Analyze \
  --socket /srv/ces/run/knowledge-impact.sock \
  --grant-file /secured-transfer/impact-grant.json \
  --policy-sha256 POLICY_SHA64 \
  --server-public-hex RAW_ED25519_PUBLIC_HEX_C --pretty
```

单独客户端也可：

```bash
python3 -I -B scripts/ces_knowledge_impact_host.py analyze \
  --socket /srv/ces/run/knowledge-impact.sock \
  --grant-file /secured-transfer/impact-grant.json \
  --policy-sha256 POLICY_SHA64 \
  --server-public-hex RAW_ED25519_PUBLIC_HEX_C
```

**返回**：`verified_server_signature=true` + `signed_reply` + 原 EC204 `partial/2` `result`，或只含拒绝代码的独立签名 `permission_denied/3`、`invalid_input/4`、`unavailable/5`；本地客户端连接失败会得到**未签名** EC282 refusal，不能冒充宿主。服务器固定上限 400KiB 回复、512KiB 私有工作项、16KiB 请求；操作台为此模式设定独立的 900KiB 子进程输出上限。`--pretty` 只改变控制台打印格式。

## 重要的生产待验风险（留待最终用户辅助）

- 三个角色在**不同离线设备/人员**与单独 OS service UID、真实 ACL、密钥轮换/撤销、可信 UTC 的物理证明未完成；本机合成 Ed25519 不能证明独立签发。
- 信任的真实 EC203 target / EC204 baseline 签发者身份、独立交付来源、远程 Git/provider/CI、代码 checkout 合法性必须外部核对。Hash/签名的正确数学验证 ≠ 组织或业务授权。Job 策略可能已作出错误源选择，不能靠 Host 的 SHA pin 证明源是可信的。
- 服务内 `AnchoredClock` 只是进程内单调地板，没有离机 anti-rollback 或可信 TSA。外部 OS 文件系统替换竞态/恶意 Git 二进制替换、本地同 UID 被攻陷者及实际 rootless/多平台部署尚未攻击验收；尽量部署不可写只读仓库、管理员独占策略父目录，host OS 账号限制写权限。
- **不实现**知识章节语义映射（EC205 只会从注释/链接作有限静态关联）、KnowledgeSave 写入、远程 Provider 权限或任何 `QualityRun.Execute`。原 PowerShell 原生 15 Smoke、Windows/macOS/E63–E66、业务 Provider/CI、历史来源 B001、最终联合验收仍未完成。

本轮明确边界和本地局部结果见 `../EC-282.md`、`../construction/EC282_SCOPE.json`、`../construction/EC282_LOCAL_REPORT.json`。**EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED`、B001 `OPEN`、final acceptance `NOT_STARTED`、全工程 Quality PASS=false 不变。**
