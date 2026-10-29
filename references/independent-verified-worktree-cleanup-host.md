# EC292 — 原 EC230 清理业务的独立签署宿主（仅本地 linked worktree）

Historical record names below are archival references; those files are absent
from this source tree. See [cleanup scope](../docs/CLEANUP.md).

> **版本 V6.02 / R292 / EC-292。** 仅对先前原 EC229 私有 Git 提交、EC291 真实独立签名回读且原 EC230 审计仍新鲜的**同一操作**，调用**原封未修改** `PublicationReceiptService.cleanup_docs`。**这是不可逆的本地删除操作，不是只读命令。** 它不会删本地 bare Git ref、原 EC229 journal，也不会修改原仓工作区 HEAD/index 或调用网络发布。原 Git 的 worktree 管理元数据会按 `git worktree remove` 的正常语义更新。

## 1. 实际业务闭环

1. **父链仍有效：** 原 EC285 `0600` 完整原 EC229 job，原四张 EC229 签名和源文档/仓/准确 Git SHA，原始 EC229 `05_COMMIT_CREATED` + `06_PUSH_ATTEMPTED` journal 和原 private bare ref 不可漂移。EC291 受保护的原 policy/job/code SHA 必须原样有效。
2. **独立回读事实：** 先用原 EC291 `host-docs-receipt DocsOnlyPublish Readback` 获得带第三方服务端 Ed25519 签名的完整输出，并在 owner-only `0600` 文件保存该 JSON。EC292 不相信单个 `verified` 文本位：重新验 EC291 server signature、policy/job/operation/inspection/observation，重读原 EC230 `ec230-read-<inspection_id>` 的三张持久审计标记，验证历史 journal SHA、候选 commit/父提交/逐字节文档。只有 `VERIFIED_PRIVATE_LOCAL_REF_ONLY` 可继续。`UNKNOWN_PRIVATE_REF_ABSENT`、回读无 ACK、缺审计、伪造回执不可继续。
3. **本次作业可删除性的重新审查：** 原 EC230 `_eligible_worktree` 检验已注册的独立 detached linked worktree 必须具有唯一 `.git` 关联和准确候选 HEAD、干净 status、无未追踪/ignored 文件、无目录 symlink/硬链接、多余文件、源仓不能漂移，签署时绑定 worktree 的设备和 inode。**只允许原 EC230 原业务所定义的清理范围。**
4. **双层权限：** 原 EC230 `CLEAN_DOMAIN` 精确短签（≤35 秒，绑定历史 inspection_id/observation_sha、candidate commit、worktree inode、原授权/operation/target 和原业务代码 SHA）与**新增** EC292 repository custodian 和 independent reviewer 两张互不共享的≤25 秒离线域分离精确票，还需 Linux/POSIX 内核 AF_UNIX peer UID 属于 owner allowlist。第三把 EC292 独立 server key 签署含请求 nonce/请求原文哈希/policy SHA/job SHA 的完整结果。原 EC229 四把、EC230 读/清两把、EC291 三把与 EC292 新三把，**一共 12 把公钥两两不复用**；这不能证明生产中真有 12 名独立人。
5. **真正删除由旧业务执行：** EC292 先以 `ec292-clean-<operation>` 创建并 fsync 一次性 admission（**按 operation，而非 Host 授权 ID**，拒绝更换票再次尝试）；再次检查全部签名/权限/源码/仓和 worktree，然后**唯一调用原** `cleanup_docs(...)`。原 EC230 自身先 `ec230-clean-<operation>/00_CLAIM`、`01_ATTEMPT` durable fsync，重验目标再执行 `git worktree remove -- <exact-path>`，检查 worktree 消失、原 HEAD/index/ref 不变，最后写 `03_REMOVE_COMPLETED`。本轮不调用 `inspect_docs`（它必须事先由 EC291 运行），绝不调用 `DocsOnlyPublisher.publish_once`。

## 2. 预配与独立签署（具体命令）

**先准备独立 owner 私有目录（0700）和 EC291 policy/job。** 本轮客户端 `scripts/ces_docs_cleanup_host.py` 独立部署，不通过通用 Router 的 `run`。**本轮所有文件名由管理员自己规划，不允许 Socket 客户端选择实际 Git 路径或私有文档/源码。** 私钥和输出文件全部 `0600`；生产必须隔离真实签发人设备。以下为准确参数形状示例，`<...>` 为应替换的本机绝对路径/公钥。

```bash
python scripts/ces_docs_cleanup_host.py --help
python scripts/ces_docs_cleanup_host.py keygen-offline --private-out /owner/keys/cleanup-custodian.key
python scripts/ces_docs_cleanup_host.py keygen-offline --private-out /owner/keys/independent-reviewer.key
python scripts/ces_docs_cleanup_host.py keygen-offline --private-out /owner/keys/cleanup-server.key

python scripts/ces_docs_cleanup_host.py prepare-policy \
  --ec291-policy-file /owner/private/ec291-policy.json \
  --ec291-policy-sha256 <EXACT_EC291_POLICY_RAW_SHA256> \
  --readback-result-file /owner/private/ec291-readback-signed.json \
  --admission-root /owner/ec292-admissions --allowed-uid <APPROVED_UNIX_UID> \
  --cleanup-custodian-public-hex <NEW_CUSTODIAN_PUBLIC_HEX> \
  --independent-reviewer-public-hex <NEW_REVIEWER_PUBLIC_HEX> \
  --server-public-hex <NEW_SERVER_PUBLIC_HEX> \
  --enable-one-clean-linked-worktree --out /owner/private/ec292-policy.json

python scripts/ces_docs_cleanup_host.py serve \
  --socket /owner/socket/ec292.sock \
  --policy-file /owner/private/ec292-policy.json \
  --policy-sha256 <EC292_POLICY_SHA256> \
  --server-private-key /owner/keys/cleanup-server.key
```

按顺序执行已有 EC291 真实 `host-docs-receipt`，**只在验签阳性的完整结果**被立即写成 0600 证据文件后，进入本轮原 cleanup 授权窗口。注意：原 EC230 观察在本轮清理时要求**≤60 秒新鲜**，不能先挂起审批工作数小时再恢复，也不允许擅自延长旧 EC230 的上限。所有签发应在组织合规和可信钟的前提下预协调，超时要停止并走新的独立读授权与人工核对流程，**不能重试已可能删除的操作**。

```bash
python scripts/ces_docs_cleanup_host.py prepare-cleanup-template \
  --policy-file /owner/private/ec292-policy.json \
  --policy-sha256 <EC292_POLICY_SHA256> --ttl-seconds 34 \
  --out /owner/private/cleanup.template.json

python scripts/ces_docs_cleanup_host.py sign-cleanup-offline \
  --template-file /owner/private/cleanup.template.json \
  --private-key-file /owner/keys/original-ec230-cleanup.key \
  --out /owner/private/original-cleanup.grant.json

python scripts/ces_docs_cleanup_host.py prepare-offline \
  --policy-file /owner/private/ec292-policy.json \
  --policy-sha256 <EC292_POLICY_SHA256> \
  --cleanup-grant-file /owner/private/original-cleanup.grant.json \
  --uid <APPROVED_UNIX_UID> --ttl-seconds 24 \
  --out /owner/private/ec292-subject.json

python scripts/ces_docs_cleanup_host.py sign-custodian-offline \
  --subject-file /owner/private/ec292-subject.json \
  --private-key-file /owner/keys/cleanup-custodian.key \
  --out /owner/private/ec292-custodian.vote.json

python scripts/ces_docs_cleanup_host.py sign-reviewer-offline \
  --subject-file /owner/private/ec292-subject.json \
  --private-key-file /owner/keys/independent-reviewer.key \
  --out /owner/private/ec292-reviewer.vote.json

python scripts/ces_docs_cleanup_host.py assemble-offline \
  --subject-file /owner/private/ec292-subject.json \
  --custodian-vote /owner/private/ec292-custodian.vote.json \
  --reviewer-vote /owner/private/ec292-reviewer.vote.json \
  --custodian-public-hex <NEW_CUSTODIAN_PUBLIC_HEX> \
  --reviewer-public-hex <NEW_REVIEWER_PUBLIC_HEX> \
  --out /owner/private/ec292-host.grant.json

python scripts/ces_next.py host-docs-cleanup DocsOnlyPublish Cleanup \
  --socket /owner/socket/ec292.sock \
  --grant-file /owner/private/ec292-host.grant.json \
  --cleanup-grant-file /owner/private/original-cleanup.grant.json \
  --policy-sha256 <EC292_POLICY_SHA256> \
  --server-public-hex <NEW_SERVER_PUBLIC_HEX>
```

**生产策略：** 12 把公钥来自受治理的独立信任根；内核 UID、目录所有者/0700 与 Socket ACL 真正隔离；管理员固定原 job 和 EC291 policy 的 raw SHA；不允许客户端传任意 Git 路径/候选内容/源码/私钥或 ref。此宿主不会启用远程 Git 或 Provider 凭据。为了安全，先完成原 EC291 `Readback` 且确实拿到带签名阳性观察才允许调用本轮 `Cleanup`。

## 3. 结果和丢 ACK 处理

- **唯一正面结果**：原 EC230 `partial/2`, `PUBLICATION_RECEIPT_VERIFIED_LOCAL_WORKTREE_REMOVED_KEEP_REF_AND_JOURNALS`，并且 `local_worktree_cleanup_confirmed=true`、原 EC230 `ec230-clean-<op>/03_REMOVE_COMPLETED` 与 EC292 `ec292-clean-<op>/00_ADMISSION.json`。仅能断言在**本机已检查**的对应 linked worktree 被安全移除、原本地 bare ref 仍存在。不能断言远端 Git/公共发布/CI 或整个系统 Quality PASS。
- **任何其他结果**：包括内部清理业务先行未通过、dirty worktree、缺失/篡改的 EC291 原始 read audit、过时 readback、两票不独立、签名伪造、UID 错误、政策/代码/原始 job SHA 漂移，以及在可能有本地副作用后 Socket ACK 丢失/签名不符，都不能当成成功，更不代表原目录/资料安全不存在风险。**禁止自动重试**。
- **人工对账**：检查 `ec292-clean-<operation>/00_ADMISSION.json`、原 EC230 `ec230-clean-<operation>/00_CLAIM`/`01_ATTEMPT`/`03_REMOVE_COMPLETED`、原 `ec230-read-<inspection>` 三张 read audit、原 EC229 永久 journal、独立 Git bare ref 和物理 linked worktree inode/文件清单。不要在手动调查时运行清理第二次或再次 publish。

## 4. 本地范围与留给用户的统一验收

- 本地使用真实临时 Git repo/bare、原 EC229 `publish_once`、原 EC230 `inspect_docs`（经 EC291 Host）和原 EC230 `cleanup_docs`，而非模拟删目录；真实内核 AF_UNIX peer UID、Ed25519 票、耐久双账本和 `ces_next` 子进程操作台。16 个 EC292 具体场景包括成功移除、旧业务拒绝、角色签伪造、错误 UID、脏工作区、未知/假签 EC291 readback、缺失审计、陈旧回读、inode 漂移、同一 operation 重复执行和旧 Router 拒绝。
- 仍然**没验证** 12 位真正独立签发人/设备、受管理 POSIX 0700/0600/socket/SELinux ACL、可信时间/撤权/备份、生产跨进程/multi-node fsync/断电恢复/同 UID 恶意文件系统竞态、真实企业 Git 权限与远端、PowerShell7 15 组原生 Smoke、Windows/macOS 和 E63–E66 联合终验。**EC249 不完整、EC250 BLOCKED、B001 OPEN、final acceptance NOT_STARTED、global Quality PASS=false。**

**索引**：`本轮记录` · `单 EC 边界` · `实际本地结果` · `全量 SHA 清单`。
