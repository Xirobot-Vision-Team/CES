## 当前补充：V5.90/R280 的两个独立授权读宿主（不改变 Router 登记）

在下面 EC246 的冻结路由表之外，`scripts/ces_next.py host-query FindingShow Query`（EC279）及 `host-query QualityShow Query`（EC280）分别可访问**独立运行**的 Unix socket、两位离线签发者批准的只读后端；原 `run FindingShow Query` 与 `run QualityShow Query` **继续被 Router 拒绝**，全部 11 个 HOST_REQUIRED 请求路径维持默认拒绝。QualityShow 只对宿主所有的固定私有 EC181–187 批次运行原 EC188 投影，不能被视作认证 CI/执行结果/整体质量 PASS，详见 [EC280 宿主操作手册](independently-authorized-quality-query.md)。其余九种宿主无此独立入口。

---

# CES 当前意图路由与模块编排 — V5.57 / R247（EC246 路由目录沿用）

**适用范围：** 本页为当前**已写代码的可调用边界**，不是已通过企业、宿主、PowerShell7 或最终端到端验收的产品承诺。现有已登记 Action/Mode 共 **74 条**，其中原生 R150 **16**、新 CLI **39**、API **7**、typed Preview **1**、**HOST_REQUIRED 11**。全量逐条能力、固定 Handler、效果类别见[当前路由表](route-catalog.md)和[产品矩阵](../construction/CAPABILITY_MATRIX.json)；不要再以 EC152/R150 的源追踪、EC241 的 70 条历史清单或旧 orchestration 文案作现行路由判断。

## 先选执行边界，再编排业务动作

| 用户意图 | 当前代码中的可用入口 | 严格边界、计划依赖或拒绝条件 |
|---|---|---|
| 审查未提交变更 | 原生 `Inspect` → `Collect/WorkingTree` → `Reconcile/Snapshot` 或 `CodePrepare/Snapshot` → `CodeValidate/Snapshot`；经授权后原生 `CodeSave/Snapshot` | **旧 R150 PowerShell 专用**，使用原始 `ces.ps1` 或未传 RequestPath 的包装器；保留 `-ApprovePersist` 旧门禁，原生 PS7/15 Smoke 尚未验证 |
| 审查已交付的本地 Git 目标 | 原生 `Collect/DeliveredTarget` → `CodePrepare/Snapshot` → 分析 | 本地 ref/commit 不足以证明已部署、真实 PR/MR 合并或外部来源可信 |
| 审查远端 ProposedPR | 新 Router `Collect/ProposedPR` → `Reconcile/Remote` 或 `/DeliveryAssociation` → `CodePrepare/MultiSource` | **已有真实 CLI 处理器**，但只有在其独立 Provider 读策略/证据覆盖门槛成立时才尝试；不能由路由登记推论真实凭据、PR 身份、原子快照或交付 |
| AI 建议与交接 | `AIHandoff/Lifecycle`、`/Stage`、`/Input`、`/Route`，配合 `CodeValidate/Staged` | 已写 CLI；`Stage` 写**独立 CES 私有暂存**需明确 opt-in；Route 只给基于证据的候选与可选适配边界，不内置受信外部 AI 执行者/回传保证 |
| Finding 保存与查询 | `FindingSave/Local` 处理私有记录；`FindingShow/Query` 路由登记 | `FindingSave` 已写私有元数据处理器并需独立检查；`FindingShow/Query` 是 **HOST_REQUIRED**，独立 Router 总拒绝，真正查询只能由另行获授权的可信宿主接口提供 |
| CI/质量观察 | `QualityDetect/Observe`，`QualityReadCI/Metadata`、`/SHABinding`、`/Evidence` | 已写只读 CLI；真实 CI 通过/失败、actor、源 SHA、环境未经 Router 独立证明。`QualityRun/Preflight`、`/Execute` 和 `QualityShow/Query` **HOST_REQUIRED**，独立 Router 不会偷偷跑测试或读取私密收据 |
| 项目到期、日报/报告 | `Due/Evaluate` API → `ReportPrepare/Prepare` API → 可选 AI 草稿 → `ReportRender/Render` API → `ReportShow/History` API | 已写本地处理器；`ReportRender/SaveLocal` 才是显式 CES 私有保存 opt-in。**Render≠Publish**；`ReportPublish/PrivateTest` 为 HOST_REQUIRED，总拒绝通过独立 Router 发布 |
| 知识基线和更新建议 | `KnowledgeBootstrap/Preview` / `/Read` API → 独立 host 对 Impact/Query 的验证 → 候选 Knowledge 更新 | 前两项 API 已写；`KnowledgeImpact/Analyze`、`KnowledgeSave/SaveLocal`、`KnowledgeQuery/Chapters` **HOST_REQUIRED**，必须由受信 key/策略/存储配置宿主单独授权；建议不等于已更新知识库 |
| Issue 观察和新建判定 | `IssueSync/Read`、`IssueShow/Read`、`IssueMatch/Match` CLI → `IssueCreate/Eligibility` CLI | 前四条有既存 Handler，但真实 GH/GL Provider 读授权与来源仍另验；`IssueCreate/Create` **HOST_REQUIRED**，只能在独立可信宿主一次性授权新建，且**任何已有 Issue 修改都未登记** |
| 交付内容预览、发送与文档发布 | `DeliveryPreview/Preview` typed local preview → 独立可信 host `DeliverySend/Send` 或 `DocsOnlyPublish/LocalSandbox` | Preview 不等于已对外发送；后两者和 `ReportPublish/PrivateTest` 均 **HOST_REQUIRED**，独立 Router 拒绝伪凭据/approval。DocsOnly 的私有 worktree 模式仍会修改原仓 `.git` 管理元数据，真实隔离要现场验证 |
| 周期 Run 与外部定时器 | `Cycle/Create`、`/Inspect`、`/DAG`、`/Next`、`/Budget`、`/Pause`、`/PauseInspect`、`/Summary`、`/CrossLink`、`/CrossCheck`、`/CrossAttachGuarded`、`/SchedulePlan`、`/ScheduledSummaryGuarded`、`/GuardInspect`、`/BusinessWriteAttempt`，加 `Resume/Restore` | `Cycle` 合计 **15 个** CLI 路由；有本地 Run 元数据、状态检查和若干独立本地写入路径（必须 opt-in）。SchedulePlan 是给外部调度器的指令，**不安装调度器**；BusinessWriteAttempt Handler **总拒绝**，冲突保护不能授权跨模块业务写 |
| Schema 盘点/迁移审阅 | `SchemaReview/Inventory`、`/Audit`、`/Inspect`、`/Plan` | 四条固定 CLI；只读检查 EC242 **112** 个本地 SHA-pinned 契约及版本/源原始字节，不做数据迁移、更名或任何真实来源认证 |
| 历史 CodeShow 分析 | 原生 `CodeShow/List/Detail/Findings/Compare/Trace/Overview/Triage/Recurrence/Sequence` | 原生 R150 保存记录的读取/比对不是现实缺陷或修复结论；原有 CodeShow 大图 k≤56 兼容/性能风险留待 **EC248** 专轮评估 |

## 路由层不等于授权层

1. **原生入口**：`scripts/ces.ps1` 原字节保留，或 `scripts/ces-v5.ps1` **不指定** `-RequestPath` 的兼容委托；原 CodeSave `-ApprovePersist` 不被 Python 请求文件替代。原生 PowerShell7 和 15 Smoke **NOT_RUN**。
2. **新独立 Router**：固定 `python3 -I scripts/ces_router.py --list-routes` 显示 74 个原生/新入口。仅 `CLI`、`API` 和 `PREVIEW` 分派真实既有 Handler；它们可能返回失败/局部数据，不能证明外部业务完成。
3. **已登记但独立 Router 无权执行**：`HOST_REQUIRED` 的 11 条始终返回 `denied/3` 和 `ROUTER_INDEPENDENT_HOST_AUTHORITY_REQUIRED`。即使仓内存在独立宿主调用组件，也**不**表示 Router 可以自动构造 secrets/credential/policy/broker/批准回调。
4. **显式私有写/读网参数并非凭据**：`PRIVATE_CES_METADATA_WRITE_OPT_IN` 的 9 条登记路由要 `"acknowledge_private_ces_write": true`，且仍须满足 Handler 独立许可。CLI 的网络 flag（`--allow-network` 或 `--permit-provider-network-egress`）与 `"allow_network_read": true` 必须成对使用，仍不证明 Provider 身份/授权/响应真实。
5. **独立开发脚本不受 Router 管辖**：历史 EC244 静态审查仅盘点当时 **142 个顶层 Python main**；EC245 嵌套合成故障 runner、EC246 嵌套只读 help、EC247 嵌套跨模块 fixture runner 都**不在**那个旧数内。EC245 26-case 本地模拟不证明生产断网、保密或磁盘配额。

## 命令示例和契约读取

先看真实路由、再查看具体 Action/Mode 的只读帮助：

```sh
python3 -I scripts/ces_router.py --list-routes
python3 -I -B construction/route_documentation/route_help.py --action Cycle
python3 -I -B construction/route_documentation/route_help.py --action IssueCreate --mode Create --json
python3 -I -B construction/route_documentation/route_help.py --list-examples
python3 -I -B construction/route_documentation/route_help.py --action Due --mode Evaluate --example
```

最后一个命令返回带 `request` + `note` 的帮助对象；**只复制其中 `request`** 到绝对路径 JSON 文件，不能把帮助外壳直接送给 Router：

```sh
# /tmp/ces-due.json 保存上例的 request 部分（内容见路由目录）
python3 -I scripts/ces_router.py -Action Due -Mode Evaluate -RequestPath /tmp/ces-due.json
```

请求文件契约始终为 [`ces.unified_action_router.request.v1`](unified-action-router-request.v1.schema.json)，新执行结果始终为 [`ces.unified_action_router.v2` / **V5.53/R243**](unified-action-router-result.v2.json)，与当前**工程版本 V5.57/R247 不同**。当前结果 `partial=2`、`offline/denied=3`、`invalid=4`、`unavailable=5`；`--list-routes` 是单独的只读 inventory，退出 0。`handler_attempted` 不代表成功调用，`handler_invoked` 仅代表合法 JSON 对象，四个身份/业务成功/授权/自动推进证明字段均为 false。更多准确字段见[状态与覆盖政策](outcome-status-policy.md)。历史 v1 结果 Schema 被 EC242 锁定，不得用来解析 v2 返回。

## 模型、确定性处理器与统一交接

- **模型**负责意图分类、阅读证据、解释不确定性、形成 Finding/报告/Knowledge 的**候选**，不能把摘要、签名缺失、Provider 声称 success 或路由 Exit 2 提升为已实施业务。
- **CES Handler** 只在其自身源/身份/凭据/私有写门禁实际满足时运行，绝不隐式从用户 JSON 得到宿主密钥、外部授予或持久任务成功证明；失败/撤销/未知必须保守终止而不是自动重试。
- **一轮一个 EC**：EC246 已完成路由例子、编排说明、产品矩阵和独立帮助；EC247 已完成 15 原生 Smoke SHA/待验映射和 7 条本地跨模块合成链（详见 [EC247 指南](cross-module-regression.md)）；下轮 EC248 才处理 CodeShow 性能，EC249 最终运行手册，EC250 候选包冻结/验收交接。此处列出后续排程**不等于已施工**。

## 来源/旧版本与最终限制

旧来源记录在 [R150 历史编排](../history/legacy-docs/orchestration-R150.md)、[EC246 前页面原文归档](../history/legacy-docs/orchestration-pre-ec246-snapshot.md)、[EC152 静态路由追踪](../construction/ACTION_TRACE.json)；前者不能替代当前 74 条真实路由清单。

用户辅助的 **PowerShell7/15 Smoke、真实企业主体/Source SHA/Provider/Git/Issue/DocsOnly、OS/同 UID/NFS/磁盘/网络/跨主机、E63–E66、最终集成验收**仍 **NOT_RUN**，B001 原 V3.10/ROUNDS 缺口仍 **OPEN**。部分独立模块已有本地合成/离线测试，也不得描述成真实企业生产通过。
