# EC-167 — 合并提交 SHA / 本地目标树的只读关联证据

本轮新增 `construction/proposed_pr_merge.py` / `ces.proposed_pr_merge.v1`，是**独立 Python 工具**，不属于旧 PowerShell 的 `Reconcile:Remote/DeliveryAssociation` 或 `Collect:ProposedPR` 原生路由。仅关联：Provider 当前给出的 PR/MR 合并提交 SHA 声明，以及操作者指明的本地 Git 对象库中可核实的提交树与父子图。**不是目标远程仓认证、发布、部署或最终交付证明。**

## 必备输入与权限

- 合并状态下重新得到的、完整有效的 EC162 `ces.proposed_pr_identity.v1` 响应 JSON（`--expected-pin`）。旧 open 状态的 pin 在合并后不再有效，应重新观测；不能人工把 `merged` 改成 true 后冒充新证据。
- 用同一已合并 pin 实际获得的 EC166 `FRESH_OBSERVATION` 响应 JSON（`--ec166-reconciliation`）。要求其 pin、target/source/proposal IDs、OID、状态、变更数量与可信级别自洽；时间距本次执行不超过 **15 分钟**，超过或存在漂移一律拒绝，需重新执行 EC166。
- 明确选定的绝对路径本地**目标仓库根目录**（`--local-git`），它可为工作树根或裸仓目录，但不能是某个仓库的子目录。只能由操作者自行判断是否对应 Provider 目标项目；本工具无法单凭对象存在验证仓库归属。
- 网络读取和本地对象读取是两个独立的权限开关：**`--allow-network` + `--allow-local-git`**。默认两个均关闭；启用后仍需运行环境已安全设置相应 `CES_GITHUB_TOKEN` 或 `CES_GITLAB_TOKEN`。从不将 Token 明文/原始 HTTP 负载/标题或提交消息写入输出。

示例（明确具有相应权限并拥有新鲜 pin 和目标仓库时）：

```bash
cd ces
python construction/proposed_pr_merge.py \
  --provider github --repository owner/repo --number 12 \
  --expected-pin /secure/ec162-merged.json \
  --ec166-reconciliation /secure/ec166-fresh.json \
  --local-git /absolute/path/to/target-repo \
  --allow-network --allow-local-git --json

# GitLab 使用 --provider gitlab --repository group/subgroup/project --number <MR_IID>
```

不带两项显式授权，即使 JSON 有正确 SHA，也不会调用 Provider 或本地 Git。Git 命令仅包括本地 `rev-parse`、对完整固定 OID 的 `cat-file` 和 `merge-base --is-ancestor`；禁用可选锁、对象替换、懒加载取远端及继承的 `GIT_*` 配置。**不 fetch、merge、checkout、rev-update、push、读取/写入外部 Issue 或保存 CES 状态**。操作系统与 Git 行为仍需在最终用户辅助阶段多平台验证。

## 功能判定与边界

1. 校验 EC162/166 的来源类别（合成与真实不可混用）、完整 pin 指纹、状态、前后源时间、EC166 的 exact-count 及 TTL。SHA-256 指纹仅防意外篡改，输入收据未签名、不能证明 Provider 自身认证。
2. 对固定受限 API 执行**最多一次新元数据 GET**。重新解析全部 Provider 仓库/提议 ID、SHA、状态与变更文件数，若与 EC162/166 不符，直接拒绝，不使用原有文件分页/patch/hash 内容。
3. 只有报告 `merged` 且返回合法**完整** `merge_commit_sha`，才检查本地合并 commit、两个 parent commit、树对象及对象格式是否存在和一致；要求**恰好两个 parent，第二个等于 pinned head**。GitLab **不**把 `squash_commit_sha` 当作 merge commit，也不把 `diff_refs.base_sha`（merge-base）误写为目标分支 tip。
4. 目标关联：GitHub 支持 `target_tip` 是 merge 第一父提交的祖先，或 merge 已在当前观测 target tip 的历史中；GitLab 只允许 `diff_refs.start_sha` 属于第一父提交的祖先。若无本地历史联系不认可。
5. 正面输出 `LOCAL_MERGE_GRAPH_VERIFIED / partial/2`，指**本地 Git DAG/tree 核对成立 + Provider 的关联 SHA 声明字段与新鲜身份一致**。`target_repository_membership_authenticated`、`delivery_or_merge_proven`、`provider_actor_verified`、`write_authorized`始终为 false；不宣称部署/发版。所有失败输出 `UNAVAILABLE_UNKNOWN / unavailable/5`，畸形输入 `invalid_input/4`，没有 success/0。

GitHub PR 的 `merge_commit_sha` 可能因合并策略指向不同对象；GitLab MR 合并方式也并非总生成双父合并提交。**单父、无该字段、squash/rebase/fast-forward 不能据此推断关联或等价映射**，留待 EC168。即使本地对象存在，也无法证明其属于真实 Provider 的目标仓；单次 HTTPS 元数据观测与本地克隆之间没有端到端加密见证或跨系统原子性。

## 施工期与最终验收

本轮聚焦开发用例：`python -m unittest discover -s construction -p 'test_proposed_pr_merge.py'`，覆盖真实临时 Git 产生的二父 commit/tree、GitHub 已更新目标 tip、GitLab target-tip 语义、缺失 tree/commit、单父、身份/数量漂移、权限以及旧 EC161 兼容形状。该测试不使用真实 Provider Token、公开 API 或用户真实仓库，仅证明代码在开发隔离环境下的有限路径行为。PowerShell7 / 15 组旧 Smoke / Windows-macOS-Linux Git / E63–E66 资源 / 在线权限、速率和并发 / 完整端到端验收统一 `NOT_RUN`。下一轮 EC168 单独处理 squash/rebase 关联，不应在本轮判成已完成。
