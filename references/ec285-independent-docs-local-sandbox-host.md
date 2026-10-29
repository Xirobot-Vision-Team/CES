# EC285 — 原 EC229 `DocsOnlyPublish.LocalSandbox` 独立双授权本地 Git 宿主

**交付：V5.95 / R285 / EC285（仅一个 EC）。**

## 实际业务语义

原 CES EC241/243 Router 注册 `DocsOnlyPublish / LocalSandbox` 为 `HOST_REQUIRED`，在 `run` 模式继续拒绝。EC285 只新增一个显式宿主入口：

```bash
python3 -I -B scripts/ces_next.py host-docs DocsOnlyPublish LocalSandbox \
  --socket /absolute/private/socketdir/docs.sock \
  --grant-file /absolute/operator/grant.json \
  --policy-sha256 <原始政策文件 SHA256> \
  --server-public-hex <独立服务器 Ed25519 公钥 HEX>
```

客户端**只发送**新的 32 位随机 nonce + 两张离线 Ed25519 签署的精确工作项摘要。不会从客户端接收 Markdown、路径、Git ref、后端签名、写授权、可选命令行参数或任意目标。服务器基于预先由管理员以排他 0600 文件固定并以**原始 JSON 字节 SHA256**锁定的唯一 job 与 policy，实际执行原有、未更改的 `construction/docs_only_publish.py:DocsOnlyPublisher.publish_once`。

原 EC229 同时要求以下四个彼此不同的原业务 Ed25519 公钥真实通过：Repository Policy、Independent Content Review、Current Revocation、One-Use Side Effect Grant。服务器还必须存在另外三把互不重复、与原四把完全不同的 EC285 密钥：`custodian`（私有本地沙箱保管者）、`authorizer`（精确候选提交授权者）、`server`（完整回执签发）。**七把不同密钥 ≠ 七个真实独立自然人**；生产部署须由现实组织执行职责隔离和可信注册。本轮本地测试签名均是独立生成但同机的模拟签发者。

原 EC229 所有实际业务边界依旧执行，包括：一个事先固定的 Git commit 与 Git 身份、原仓 clean 状态、原 Git index 与 HEAD 不变、受限 `docs/.../*.md` 新文件和真实内容指纹、敏感信息拒绝、Git 筛选配置/钩子/子模块限制、隔离 worktree、原 journal 排他一次性 claim、原 Git 精确文件 diff/commit 验证、仅独立私有本地 bare repository 的新 ref、absent-ref lease 不覆盖。**只允许本地 PRIVATE sandbox ref 写入，不能当成组织已发布、远程部署成功或知识已合并。**

## 宿主准备（私有材料不入 ZIP）

要求 POSIX/Linux/macOS 且实际支持 AF_UNIX 内核 peer credential（`SO_PEERCRED` 或 `getpeereid`）；Python 3.11+、`cryptography`、真实 Git 可执行文件。管理员需要自行在有权访问原仓的专用主机上提前创建不同的真实仓/私有 worktree/私有 journal/私有 bare-sandbox Git 目录，原始 Git repo HEAD 与文件干净，所有私有根须为管理员独占目录 0700 且相互分离；Git executable 使用可信、绝对路径。客户端通过 Unix Socket 文件和 OS ACL 访问相应服务，策略中只允许指定内核 UID。

**第一步：四方原 EC229 私有签名材料先由真实权属方签发。** 参考原 `construction/test_docs_only_publish.py` 的临时实仓示例只了解输入格式；这些本地示例签名不是组织身份证明。待签名字段、四个原文签名 domain 与短时限必须遵循原 `docs_only_publish.py`。`one_use_grant.statement.code_revision_sha256` 必须是实际运行的原业务 `_code_sha()`，`target_binding_sha256`、`repo_binding_sha256`、`allowlist_sha256`、`trust_roots_sha256` 必须由原 `DocsOnlyPublisher` 在指定真实主机目录实例上计算。`repository_policy`、`content_review`、`current_revocation`、`one_use_grant` 必须分别签发并绑定完全相同的精确 job/manifest。**绝不能让 EC285 host 代签原 EC229 的四个票据**。

管理员创建一个 owner-only（0600）的 `source.json`，完整 job 结构：

```json
{
  "schema": "ces.ec285.docs_private_exact_job.v1",
  "access": {
    "issuer_id": "docs_issuer_229",
    "operator_id": "docs_operator_229",
    "project_id": "proj_docs_example123",
    "repository_id": "repo_docs_example123",
    "policy_public_hex": "<原 EC229 repository policy HEX>",
    "reviewer_public_hex": "<原 EC229 reviewer HEX>",
    "revocation_public_hex": "<原 EC229 revocation HEX>",
    "side_effect_public_hex": "<原 EC229 side-effect HEX>",
    "minimum_policy_epoch": 7,
    "repository_root": "/absolute/real-repo",
    "approved_base_commit": "<已批准的完整 40 位 commit>",
    "allowed_exact_paths": ["docs/releases/notice.md"],
    "worktree_root": "/absolute/private/worktrees",
    "journal_root": "/absolute/private/journal",
    "sandbox_bare_root": "/absolute/private/bare.git",
    "git_executable": "/usr/bin/git",
    "enable_private_local_sandbox_publish": true
  },
  "request": {
    "documents": [{
      "relative_path": "docs/releases/notice.md",
      "content_b64": "<reviewed UTF-8 Markdown 原文字节的标准 Base64>",
      "content_sha256": "<原文字节 SHA256>"
    }],
    "repository_policy": {"statement": {}, "signature_hex": "<原 EC229 第一签>"},
    "content_review": {"statement": {}, "signature_hex": "<原 EC229 第二签>"},
    "current_revocation": {"statement": {}, "signature_hex": "<原 EC229 第三签>"},
    "one_use_grant": {"statement": {}, "signature_hex": "<原 EC229 第四签>"},
    "explicitly_approve_exact_docs_only_local_publish": true
  }
}
```

示例中的空 `statement` 是结构占位，**不可直接部署**。每个 statement 必须完整且真实经过对应原业务签发。文档内容必须经过独立人工审查，不可把测试签名当成生产签名。

**第二步：宿主管理员生成、固定私有 job 和 host policy。**

```bash
cd ces
python3 -I -B scripts/ces_docs_sandbox_host.py prepare-job \
  --source-json /absolute/private/source.json \
  --out /absolute/private/docs-job.json
python3 -I -B scripts/ces_docs_sandbox_host.py inspect-job \
  --job-file /absolute/private/docs-job.json

# 以下三次各在不同离线角色机器上运行，密钥原始文件不传给 host-client
python3 -I -B scripts/ces_docs_sandbox_host.py keygen-offline \
  --private-out /absolute/private/custodian.key
python3 -I -B scripts/ces_docs_sandbox_host.py keygen-offline \
  --private-out /absolute/private/authorizer.key
python3 -I -B scripts/ces_docs_sandbox_host.py keygen-offline \
  --private-out /absolute/private/server.key

python3 -I -B scripts/ces_docs_sandbox_host.py prepare-policy \
  --job-file /absolute/private/docs-job.json \
  --allowed-uid <客户端真实内核 UID> \
  --custodian-public-hex <保管者公钥 HEX> \
  --authorizer-public-hex <授权者公钥 HEX> \
  --server-public-hex <服务器公钥 HEX> \
  --out /absolute/private/host-policy.json
```

`prepare-job` / `prepare-policy` / `inspect-job` 回显**固定哈希、project/repo ID、base commit、文件数量**，不回显文档原文。记录返回的原始 `policy_sha256`、`job_sha256`、`manifest_sha256`、`allowlist_sha256`、`target_binding_sha256` 和 `docs_backend_sha256`；不可用修改后的 JSON hash 或另一台机上计算的 inode-binding 假冒。

**第三步：两份分别独立离线审签，最长 45 秒、通常更短。** 原 EC229 revocation 单张声明最长 30 秒，one-use grant 最长 45 秒，从文件授权签发起算。应当**先准备只读资料与票据工具和宿主，再在写入窗口内签发原 EC229 的新鲜撤销与一次性原授权、完成 EC285 两票并立即执行**。长时间跨主机人工流程需要重新签发原业务短时票，不得延长 EC229 内建时效。

```bash
python3 -I -B scripts/ces_docs_sandbox_host.py prepare-offline \
  --uid <被授权真实内核 UID> \
  --policy-sha256 <policy_sha256> \
  --job-sha256 <job_sha256> \
  --project-id <project_id> --repository-id <repository_id> \
  --base-commit <base_commit> \
  --manifest-sha256 <manifest_sha256> \
  --allowlist-sha256 <allowlist_sha256> \
  --target-binding-sha256 <target_binding_sha256> \
  --docs-backend-sha256 <docs_backend_sha256> \
  --ttl-seconds 30 --out /absolute/operator/subject.json

python3 -I -B scripts/ces_docs_sandbox_host.py sign-custodian-offline \
  --subject-file /absolute/operator/subject.json \
  --private-key-file /absolute/private/custodian.key \
  --out /absolute/operator/custodian.vote.json
python3 -I -B scripts/ces_docs_sandbox_host.py sign-authorizer-offline \
  --subject-file /absolute/operator/subject.json \
  --private-key-file /absolute/private/authorizer.key \
  --out /absolute/operator/authorizer.vote.json
python3 -I -B scripts/ces_docs_sandbox_host.py assemble-offline \
  --subject-file /absolute/operator/subject.json \
  --custodian-vote /absolute/operator/custodian.vote.json \
  --authorizer-vote /absolute/operator/authorizer.vote.json \
  --custodian-public-hex <保管者公钥 HEX> \
  --authorizer-public-hex <授权者公钥 HEX> \
  --out /absolute/operator/grant.json
```

**第四步：独立守护服务和受限客户端。**

```bash
python3 -I -B scripts/ces_docs_sandbox_host.py serve \
  --socket /absolute/private/socketdir/docs.sock \
  --policy-file /absolute/private/host-policy.json \
  --policy-sha256 <policy_sha256> \
  --server-private-key /absolute/private/server.key
```

另一操作员终端执行前述 `host-docs DocsOnlyPublish LocalSandbox`。也可直接：

```bash
python3 -I -B scripts/ces_docs_sandbox_host.py publish \
  --socket /absolute/private/socketdir/docs.sock \
  --grant-file /absolute/operator/grant.json \
  --policy-sha256 <policy_sha256> \
  --server-public-hex <服务器公钥 HEX>
```

原 EC229 成功只返回 `partial/2` + `DOCS_ONLY_PRIVATE_LOCAL_SANDBOX_REF_OBSERVED`、精确 `local_candidate_commit_sha`、单次私有 `private_sandbox_ref`，而且 `published=false`、`production_or_public_published=false`、`external_publication_confirmed=false`。客户端独立验签服务端对 nonce、原请求 SHA、政策与任务 SHA、完整回执的签名和返回值结构；其他内容不得伪作成功。

## 故障与不可自动重试

原 EC229 在第一次操作前预检查四签/授权/原仓快照/文档内容与 Git 配置。EC285 额外在具体 mutating Git 命令边缘（`worktree`,`add`,`commit`,`push`）即时重读**原始字节固定**的政策/job 和短时票；若变更在最后一次检查之前发生，则拒绝该推送；检查与 Git 进程开始之间不是原子操作，极短竞态中仍可能写入，服务端必须把后验检测结果标记为 **UNKNOWN**，绝不伪称未写入。若原 EC229 **已经 durably claim**、创建 worktree/commit、发出 Git push 或发生进程/网络断联，返回的拒绝/丢失签名不得被理解为“什么也没写”；回执明确 `local_effect_outcome_unknown=true` 或客户端 `TRANSPORT_UNKNOWN`。不自动重试、不自动清理、不覆盖私有 ref。管理员需要只读检查原 EC229 journal、隔离 worktree 与精确 bare target 上的 ref SHA 后人工决定后续独立申请的处理；相同文件/基线/目标的原操作 ID 本身不可再次发布。

## 可验证范围和仍缺失的环境

本轮本地能够运行真实 POSIX Git / AF_UNIX / kernel UID / Ed25519 与原 EC229 的定向功能用例；实际生产 UNIX ACL、真实多个独立持钥人、真实组织审批、Git/CI/源归属、跨主机时钟和密钥吊销基础设施、Windows/macOS、原 15 Smoke、性能 E63–E66 均未因本轮转为 PASS。原全局 EC249 `FULL_FUNCTION_NOT_COMPLETE`、EC250 `BLOCKED`、B001 `OPEN`、最终验收 `NOT_STARTED` 和总体 QUALITY PASS=false 保持不变。

历史 EC151–284 文件全保留；只添加 EC285 独立宿主、指南/测试/状态与 `scripts/ces_next.py` 的一个精确路由；原 `docs_only_publish.py` 和原 Router、R150 PowerShell **逐字节未改**。
