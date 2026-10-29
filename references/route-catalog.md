# EC246 — 路由及功能矩阵（V5.56/R246）

**现状：** 74 条固定 Action/Mode = **16 原生 R150 + 39 CLI + 7 API + 1 Preview + 11 HOST_REQUIRED**。
这是对 EC243 V2 Router 的真实列表整理，不是 74 项业务执行或现场验收证书。
完整机器可读条目见 [`route-catalog.json`](route-catalog.json)；
同一 74 条目已填入 [`CAPABILITY_MATRIX.json`](../construction/CAPABILITY_MATRIX.json) 的 `unified_v5_routes`。

## 如何读取本地帮助（不执行 Handler）

```sh
python3 -I -B construction/route_documentation/route_help.py --help
python3 -I -B construction/route_documentation/route_help.py --action Cycle
python3 -I -B construction/route_documentation/route_help.py --action IssueCreate --mode Create --json
python3 -I -B construction/route_documentation/route_help.py --list-examples
python3 -I -B construction/route_documentation/route_help.py --action Due --mode Evaluate --example
python3 -I -B scripts/ces_router.py --list-routes
```

命令帮助只读封装已有 `inventory()` 并与本地发布矩阵逐条比对，差异时拒绝显示旧示例；
它不是新增 Action、host bridge、自动授权、源码签名或业务运行器。
`scripts/ces_router.py --help` 保持源代码冻结时 R243 的参数说明；上面的 EC246 帮助为**单独入口**。

## 执行路径与返回语义

| 类型 | 真正调用方式 | 能否在独立新 Router 执行 | 语义 |
|---|---|---|---|
| LEGACY_NATIVE_R150 (16) | `scripts/ces.ps1` 或 `ces-v5.ps1` **不带 RequestPath** | 否 | 原本 R150 参数与许可，真实 PS7/Smoke 未跑 |
| CLI (39) | 绝对 JSON 请求 `argv`，固定子命令前缀由 Router 添加 | 可能尝试 | 可能拒绝、离线或部分返回，不是任务完成 |
| API (7) | 绝对 JSON 请求 `parameters`，可按固定 allowlist 使用 `init` | 可能尝试 | 本地处理器返回，不是任务完成 |
| PREVIEW (1) | 已审查固定 typed `parameters` | 可能尝试 | 不发送内容，仍受源读取许可 |
| HOST_REQUIRED (11) | 登记身份可查看；请求文件不能携带 provider/credential/callback | **否，固定拒绝** | `denied/3`, `ROUTER_INDEPENDENT_HOST_AUTHORITY_REQUIRED` |

### 独立授权和证据边界

- `PRIVATE_CES_METADATA_WRITE_OPT_IN` 仅允许独立通过本地 handler 检查后写 CES 私有元数据，需要 `"acknowledge_private_ces_write": true`；**不是**业务源码、外部 Issue、Git 仓或发送权限。
- `IssueCreate/Create` 仅能在独立 host 可信凭据 + 一次授权 + ledger 中调用真正实现，**独立 Router 始终拒绝**；任何已有 Issue 修改都未登记。
- `DocsOnlyPublish/LocalSandbox` 在独立 Router 始终拒绝；真正独立宿主路径要求经过独立四类授权的本地 Git 私有 sandbox。`git worktree add` 仍会改原仓 `.git` 管理元数据。
- `Cycle/BusinessWriteAttempt` 虽是 CLI Handler 路径，真实 EC240 handler 也总是拒绝尝试的业务写；不要凭 route_kind 判定实际效果。
- `allow_network_read` 与模块 `--allow-network` / `--permit-provider-network-egress` 需要**同时**提供，是用户选择网络行为，不能代替 host/provider 授权。
- 原生 `ces.ps1`、EC242 冻结的 112 Schema、EC243 Router/wire、EC244 307 SHA 锁都保留未改；`EC245` 负向 runner 作为嵌套 developer 命令单独使用，**不**计入 74 条。

## 完整 74 条产品路由

| Action | Mode | 类型 | 本地调用能力 / 权限说明 |
|---|---|---|---|
| `inspect` | `无固定 mode` | `LEGACY_NATIVE_R150` | 仅通过原生 PowerShell 接口；新 Router 的请求文件接口不会执行 |
| `collect` | `workingtree` | `LEGACY_NATIVE_R150` | 仅通过原生 PowerShell 接口；新 Router 的请求文件接口不会执行 |
| `collect` | `deliveredtarget` | `LEGACY_NATIVE_R150` | 仅通过原生 PowerShell 接口；新 Router 的请求文件接口不会执行 |
| `reconcile` | `snapshot` | `LEGACY_NATIVE_R150` | 仅通过原生 PowerShell 接口；新 Router 的请求文件接口不会执行 |
| `codeprepare` | `snapshot` | `LEGACY_NATIVE_R150` | 仅通过原生 PowerShell 接口；新 Router 的请求文件接口不会执行 |
| `codevalidate` | `snapshot` | `LEGACY_NATIVE_R150` | 仅通过原生 PowerShell 接口；新 Router 的请求文件接口不会执行 |
| `codesave` | `snapshot` | `LEGACY_NATIVE_R150` | 仅通过原生 PowerShell 接口；新 Router 的请求文件接口不会执行 |
| `codeshow` | `list` | `LEGACY_NATIVE_R150` | 仅通过原生 PowerShell 接口；新 Router 的请求文件接口不会执行 |
| `codeshow` | `detail` | `LEGACY_NATIVE_R150` | 仅通过原生 PowerShell 接口；新 Router 的请求文件接口不会执行 |
| `codeshow` | `findings` | `LEGACY_NATIVE_R150` | 仅通过原生 PowerShell 接口；新 Router 的请求文件接口不会执行 |
| `codeshow` | `compare` | `LEGACY_NATIVE_R150` | 仅通过原生 PowerShell 接口；新 Router 的请求文件接口不会执行 |
| `codeshow` | `trace` | `LEGACY_NATIVE_R150` | 仅通过原生 PowerShell 接口；新 Router 的请求文件接口不会执行 |
| `codeshow` | `overview` | `LEGACY_NATIVE_R150` | 仅通过原生 PowerShell 接口；新 Router 的请求文件接口不会执行 |
| `codeshow` | `triage` | `LEGACY_NATIVE_R150` | 仅通过原生 PowerShell 接口；新 Router 的请求文件接口不会执行 |
| `codeshow` | `recurrence` | `LEGACY_NATIVE_R150` | 仅通过原生 PowerShell 接口；新 Router 的请求文件接口不会执行 |
| `codeshow` | `sequence` | `LEGACY_NATIVE_R150` | 仅通过原生 PowerShell 接口；新 Router 的请求文件接口不会执行 |
| `Collect` | `ProposedPR` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Reconcile` | `Remote` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Reconcile` | `DeliveryAssociation` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `CodePrepare` | `MultiSource` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `AIHandoff` | `Lifecycle` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `AIHandoff` | `Stage` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `AIHandoff` | `Input` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `AIHandoff` | `Route` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `CodeValidate` | `Staged` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `CodeSave` | `Staged` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `FindingSave` | `Local` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `FindingShow` | `Query` | `HOST_REQUIRED` | 可登记和拒绝，无独立授权宿主；仅列示处理器，不执行它 |
| `QualityDetect` | `Observe` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `QualityReadCI` | `Metadata` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `QualityReadCI` | `SHABinding` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `QualityReadCI` | `Evidence` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `QualityRun` | `Preflight` | `HOST_REQUIRED` | 可登记和拒绝，无独立授权宿主；仅列示处理器，不执行它 |
| `QualityRun` | `Execute` | `HOST_REQUIRED` | 可登记和拒绝，无独立授权宿主；仅列示处理器，不执行它 |
| `QualityShow` | `Query` | `HOST_REQUIRED` | 可登记和拒绝，无独立授权宿主；仅列示处理器，不执行它 |
| `Due` | `Evaluate` | `API` | 固定 Python API 方法；请求参数必须满足处理器实际签名，不认定业务成功 |
| `ReportPrepare` | `Prepare` | `API` | 固定 Python API 方法；请求参数必须满足处理器实际签名，不认定业务成功 |
| `ReportRender` | `Render` | `API` | 固定 Python API 方法；请求参数必须满足处理器实际签名，不认定业务成功 |
| `ReportRender` | `SaveLocal` | `API` | 固定 Python API 方法；请求参数必须满足处理器实际签名，不认定业务成功 |
| `ReportShow` | `History` | `API` | 固定 Python API 方法；请求参数必须满足处理器实际签名，不认定业务成功 |
| `KnowledgeBootstrap` | `Preview` | `API` | 固定 Python API 方法；请求参数必须满足处理器实际签名，不认定业务成功 |
| `KnowledgeBootstrap` | `Read` | `API` | 固定 Python API 方法；请求参数必须满足处理器实际签名，不认定业务成功 |
| `KnowledgeImpact` | `Analyze` | `HOST_REQUIRED` | 可登记和拒绝，无独立授权宿主；仅列示处理器，不执行它 |
| `KnowledgeSave` | `SaveLocal` | `HOST_REQUIRED` | 可登记和拒绝，无独立授权宿主；仅列示处理器，不执行它 |
| `KnowledgeQuery` | `Chapters` | `HOST_REQUIRED` | 可登记和拒绝，无独立授权宿主；仅列示处理器，不执行它 |
| `IssueSync` | `Read` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `IssueShow` | `Read` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `IssueMatch` | `Match` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `IssueCreate` | `Eligibility` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `IssueCreate` | `Create` | `HOST_REQUIRED` | 可登记和拒绝，无独立授权宿主；仅列示处理器，不执行它 |
| `DeliveryPreview` | `Preview` | `PREVIEW` | 构建既有类型的本地预览请求；不发送外部内容、不保证源授权 |
| `DeliverySend` | `Send` | `HOST_REQUIRED` | 可登记和拒绝，无独立授权宿主；仅列示处理器，不执行它 |
| `ReportPublish` | `PrivateTest` | `HOST_REQUIRED` | 可登记和拒绝，无独立授权宿主；仅列示处理器，不执行它 |
| `DocsOnlyPublish` | `LocalSandbox` | `HOST_REQUIRED` | 可登记和拒绝，无独立授权宿主；仅列示处理器，不执行它 |
| `Cycle` | `Create` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Cycle` | `Inspect` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Cycle` | `DAG` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Cycle` | `Next` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Cycle` | `Budget` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Cycle` | `Pause` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Cycle` | `PauseInspect` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Resume` | `Restore` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Cycle` | `Summary` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Cycle` | `CrossLink` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Cycle` | `CrossCheck` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Cycle` | `CrossAttachGuarded` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Cycle` | `SchedulePlan` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Cycle` | `ScheduledSummaryGuarded` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Cycle` | `GuardInspect` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `Cycle` | `BusinessWriteAttempt` | `CLI` | 真实 EC240 处理器只拒绝业务写尝试，不能视为授权 |
| `SchemaReview` | `Inventory` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `SchemaReview` | `Audit` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `SchemaReview` | `Inspect` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |
| `SchemaReview` | `Plan` | `CLI` | 请求文件经固定命令行处理器尝试执行；允许处理器拒绝/局部返回，不认定业务成功 |

## 固定且可审查的调用示例

请求 JSON 的 `schema` 固定为 `ces.unified_action_router.request.v1`；进程返回使用 **`ces.unified_action_router.v2` / V5.53/R243**，即使工程包已升至 V5.56/R246。
旧 `unified-action-router-result.v1.schema.json` 是 EC242 历史 SHA 冻结格式，**不能**拿来校验当前结果；应选 [`unified-action-router-result.v2.json`](unified-action-router-result.v2.json)。
请求 Schema 只定义共用 JSON 形状；它**不会**验证每个 handler 的 argparse/API 语义、业务源身份或真实权限。

在工程根目录保存一个 JSON 请求文件的绝对路径，例如 `/tmp/ces-route-request.json`，运行：

```sh
python3 -I scripts/ces_router.py -Action Due -Mode Evaluate -RequestPath /tmp/ces-route-request.json
# 可选：仅在有 PowerShell7 的宿主上人工运行；目前没有本地实测证据
pwsh -NoProfile -File scripts/ces-v5.ps1 -Action Due -Mode Evaluate -RequestPath /tmp/ces-route-request.json -Json
```

实际 JSON 样本由只读工具导出（含预期受限状态，不含凭据）：

### `Due/Evaluate`

可直接调用的合成日历观测；返回 partial/2 不代表已执行定时任务；需要本机 IANA timezone 数据 预期：partial/2 或明确的受限/错误状态；永不证明任务完成。

```json
{
  "schema": "ces.unified_action_router.request.v1",
  "action": "Due",
  "mode": "Evaluate",
  "parameters": {
    "project_timezone": "America/Los_Angeles",
    "cadence": "day",
    "observed_at": "2026-10-24T15:00:00Z",
    "never_processed": true
  }
}
```

### `SchemaReview/Inventory`

读取工程内 112 个 EC242 固定 Schema 名录；只读盘点不验证任意业务记录 预期：partial/2（目录数据只作信息），不是 schema 全域可信声明。

```json
{
  "schema": "ces.unified_action_router.request.v1",
  "action": "SchemaReview",
  "mode": "Inventory",
  "argv": []
}
```

### `SchemaReview/Audit`

审阅固定 Schema 的已知元数据问题；只读、不迁移或修复数据 预期：partial/2 或受限/错误状态；已知旧债不能当作零问题。

```json
{
  "schema": "ces.unified_action_router.request.v1",
  "action": "SchemaReview",
  "mode": "Audit",
  "argv": []
}
```

### `IssueCreate/Create`

专门演示宿主受限路由在独立 Router 中拒绝，不携带伪凭据 预期：denied/3，reason_code=ROUTER_INDEPENDENT_HOST_AUTHORITY_REQUIRED。

```json
{
  "schema": "ces.unified_action_router.request.v1",
  "action": "IssueCreate",
  "mode": "Create"
}
```

### `DocsOnlyPublish/LocalSandbox`

仅演示只读查看注册身份后的宿主拒绝；绝不尝试 Git 写入 预期：denied/3，reason_code=ROUTER_INDEPENDENT_HOST_AUTHORITY_REQUIRED。

```json
{
  "schema": "ces.unified_action_router.request.v1",
  "action": "DocsOnlyPublish",
  "mode": "LocalSandbox"
}
```

## 退出码与能力说明

| 新 Router 返回 status | 退出码 | 唯一安全解释 |
|---|---:|---|
| `partial` | 2 | 有限观察或未认证的成功陈述；不是业务完成 |
| `offline` | 3 | 本地处理器报告断网/网络禁用；不是线上离线验收证据 |
| `denied` | 3 | 不满足已实现路由/许可/宿主边界 |
| `invalid` | 4 | 请求/本地输入不符合约束 |
| `unavailable` | 5 | 处理器/证据/输出或状态不可可靠确定 |

`--list-routes` 是**独立**只读 inventory，退出码 0，不使用 V2 Action 结果 JSON 的形状。
`handler_attempted` 是尝试调用，`handler_invoked` 是收到合法 JSON；`business_effect_verified`、`permissions_granted_by_router`、`external_identity_authenticated_by_router`、`tasks_advanced_by_router` 恒为 `false`。
合成用例见 [`EC245 指南`](failure-mode-offline-privacy-resource.md)；运行器是 `python3 -I -B construction/negative_scenarios/run.py --run`，输出 `LOCAL_SIMULATION_PASSED_NOT_ONLINE_ACCEPTANCE`，不能声称真实断网、保密或 OS 资源配额通过。

## 集中验收仍待用户协助

Native PowerShell7、原 15 Smoke、外部企业 Actor/Provider/Git/Issue/DocsOnly、真实传输/保密/断网/磁盘隔离/同 UID/NFS、E63–E66 和最终端到端验收均 **NOT_RUN**。
原 V3.10/ROUNDS 缺失 B001 **OPEN**。EC247 才处理跨模块回归用例覆盖，不在 EC246 提前开发。
