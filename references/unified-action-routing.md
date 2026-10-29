## EC250 (post-router separately installed Linux host service; does not change this router)

A new separate operator-owned [FindingShow host broker](ec250-linux-finding-host.md) actually reads the existing HMAC store through a Linux AF_UNIX/SO_PEERCRED and private UID/scope policy. The original 74 routes, including the 11 always-denied HOST_REQUIRED entries of this unprivileged router, stay unchanged. This is not an authorization flag for this router, nor enterprise auth or business-write capability. Original freeze and full-function gate remain blocked.

---

# CES 统一路由当前使用说明 — V5.57/R247 工程包（EC246 路由目录沿用）

**当前权威路由目录：** [74 条逐 Action/Mode 清单与样本](route-catalog-ec246.md) ·
[机器可读目录](route-catalog-ec246.json) ·
[`CAPABILITY_MATRIX.json` 的 `unified_v5_routes`](../construction/CAPABILITY_MATRIX.json) ·
[只读独立 CLI 帮助](../construction/ec246_docs/route_help.py)。

- 当前固定**74 个登记项** = **16 旧 R150 PowerShell（仅原生 CLI）+
  39 Python CLI + 7 Python API + 1 typed Preview + 11 HOST_REQUIRED**。
  HOST_REQUIRED 是**已登记、不能通过本 Router 执行**，不是安装一个
  无凭据写路由。路由包含一个 `Cycle/BusinessWriteAttempt` CLI，其原 Handler
  总是拒绝业务写，不能按 CLI 标签推断会写入。
- 当前工程包是 **V5.57/R247**，但实际请求仍固定
  `ces.unified_action_router.request.v1`；实际新结果始终固定
  **`ces.unified_action_router.v2` / V5.53/R243**，
  这是未修改 EC243 协议的正确结果，**不是**版本号漏升。
  [`unified-action-router-result.v2.json`](unified-action-router-result.v2.json)
  是当前结果 Schema；
  [`unified-action-router-result.v1.schema.json`](unified-action-router-result.v1.schema.json)
  是 112 个 EC242 历史锁定合同之一，不能用它解释当前 V2 结果。
- CLI 的 `--list-routes` 是只读盘点返回、exit 0，不是 V2 Action
  envelope。新请求的 `partial/2`、`offline/3`、`denied/3`、
  `invalid/4`、`unavailable/5` 均**不能**证明业务完成。收到合法 Handler
  JSON 和 `handler_attempted=true` 也不能提供许可；即使 Handler 声称
  `success/0`，Router 仍按未验证结果归一化。
- `python3 -I -B construction/ec246_docs/route_help.py --help` 展示
  EC246 按真实固定 Action/Mode 的帮助；它是独立**只读**文档入口，不调用
  Handler。原 `scripts/ces_router.py --help` 和 `scripts/ces-v5.ps1`
  文件保持 EC243 已冻结的源码/注释，不修改；旧 `scripts/ces.ps1` 完整保留。
- [EC245 26 个合成故障场景](failure-mode-offline-privacy-resource.md)
  属独立**开发用**嵌套运行器，**不**属于 74 条 Action/Mode，
  其本地报告不等于真实断网/保密/资源配额、OS 或企业授权验收。

## 最短可操作示例（无联网、无业务写）

```sh
python3 -I scripts/ces_router.py --list-routes
python3 -I -B construction/ec246_docs/route_help.py --list-examples
python3 -I -B construction/ec246_docs/route_help.py --action Due --mode Evaluate --example
```

将最后一条命令显示的 JSON 的 `request` 对象复制至**绝对路径**文件
（例如 `/tmp/ces-due.json`），而不是把包括 `note/expected_result` 的
帮助外层对象整体当请求传给 Router。调用：

```sh
python3 -I scripts/ces_router.py -Action Due -Mode Evaluate -RequestPath /tmp/ces-due.json
```

这种 Due API 示例在本地只计算一天的周期，不安装定时器、校验外部来源、
保存处理记录或触发真实报告。另有 `SchemaReview/Inventory`、
`SchemaReview/Audit` 的本地只读示例和 `IssueCreate/Create`、
`DocsOnlyPublish/LocalSandbox` 的**预期被拒绝**示例，见上面的目录。
传递任意 CLI 子命令时 `argv` 不包含 Router 自动加入的固定 prefix，
私有 CES 写必须另加 `acknowledge_private_ces_write:true`，
启用网络相关 CLI flag 时还需对应 `allow_network_read:true`。
**这两种布尔量都不是授权证明。**

**未验收：** 原生 PS7/15 Smoke、企业 actor/source/provider、真实外网、
外部 Issue/DocsOnly Git、OS/NFS/磁盘限额、E63–E66 与最终用户辅助
联合验收全部 `NOT_RUN`。B001 上游 V3.10/ROUNDS 缺口仍 `OPEN`。

---

## 下文保留 EC241/242/243 的历史版本说明

下文中的 **70 项**、**V5.51/R241**、以及 EC241 当时对
`exit 2` 的叙述仅表示原始 EC241 发布时点；
**当前应以上述 EC246 摘要及逐路由表、EC243 V2 状态策略为准。**

> **EC243 current update (V5.53/R243):** 74 fixed registrations remain. New Action
> dispatch results use `ces.unified_action_router.v2` (not V1), five canonical
> `partial/offline/denied/invalid/unavailable` statuses and exits 2/3/4/5.
> Handler exit 0, its reported `success`, a schema-readable record or local
> metadata creation remains `partial` / unverified, never business success.
> Original child status/exit/result are still visible; `handler_attempted`
> distinguishes an attempted call from a valid returned JSON result.
> Refer to [EC243 status policy](outcome-status-policy.md) and
> [strict V2 result contract](unified-action-router-result.v2.json).
> The historical V1 schema below is retained byte-for-byte in EC242's pinned catalog.

---

> **EC242 update (V5.52/R242):** the unified router now includes four real, read-only `SchemaReview` modes: `Inventory`, `Audit`, `Inspect`, `Plan`. Total **74** entries (16 legacy + 58 Python). The historical 70-entry statement below documents EC241 and is not a statement about the new release. `Inspect/Plan` require `argv` such as `["--input","/absolute/record.json","--domain","Cycle"]`; `Audit/Inventory` use an empty `argv`. A router exit 2 still only means the inspection handler returned, not that a record was accepted, migrated, or trusted. See [EC242 guide](schema-migration-review.md).

# EC241 unified Action/Mode routing — V5.51 / R241

This package has **two distinct execution paths**. Historical R150 PowerShell
`ces.ps1` keeps its original bytes, dispatcher and permission checks; the new
`ces-v5.ps1` wrapper delegates all legacy calls to it. New opt-in Action/Mode
calls use the fixed-dispatch Python `scripts/ces_router.py` and the `construction/
unified_action_router.py` registry. They do not import unreviewed code from
user-chosen paths, do not read credentials from the request file, and do not
create host approval, enterprise identity or evidence provenance.

## Invocation

Inspect the complete inventory without executing a handler:

```sh
python3 -I scripts/ces_router.py --list-routes
```

For a new route, create an **absolute-path** UTF-8 request JSON file, for
example `/tmp/ces-due.json` (this example is synthetic, not evidence):

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

```sh
python3 -I scripts/ces_router.py -Action Due -Mode Evaluate -RequestPath /tmp/ces-due.json
# Optional, if PowerShell 7 and Python 3 are installed:
pwsh -NoProfile -File scripts/ces-v5.ps1 -Action Due -Mode Evaluate -RequestPath /tmp/ces-due.json -Json
```

Legacy usage is unchanged, including the old CodeSave gate:

```sh
pwsh -NoProfile -File scripts/ces.ps1 -Action Inspect -RepoPath /absolute/repo -Json
pwsh -NoProfile -File scripts/ces-v5.ps1 -Action Inspect -RepoPath /absolute/repo -Json
```

For a CLI-backed route, specify **`argv`** without the module's fixed subcommand
prefix. `Cycle/Inspect` example (replace root and ID with a real existing local
EC231 Run):

```json
{
  "schema": "ces.unified_action_router.request.v1",
  "action": "Cycle",
  "mode": "Inspect",
  "argv": ["--store", "/absolute/private/ces", "--run-id", "run-example"]
}
```

The existing module's documented argparse syntax remains authoritative;
incorrect flags or missing data result in a deterministic failure, never a
fabricated record. `Cycle/Create`, `Cycle/Pause`, `Cycle/CrossLink`,
`Cycle/CrossAttachGuarded`, `Cycle/ScheduledSummaryGuarded`, staged `CodeSave`,
`FindingSave`, and `AIHandoff/Stage` use CES **private local metadata writes**;
these must include `"acknowledge_private_ces_write": true` and must pass the
underlying handler's independent local checks. This opt-in cannot grant a
business write or provider permission.

For the existing issue eligibility calculator, send `IssueCreate/Eligibility`
with `"argv": []` and a structured `"stdin_json"` matching EC218's input
contract; other routes cannot inject stdin. Remote **read-only** CLI handlers
may require the `--allow-network` flag **and**
`"allow_network_read": true`; these are separate, untrusted opt-ins, not
provider credentials. Nothing here creates or modifies a remote record.

## Route families and boundary truth

- **70 listed entries:** 16 historical R150 Action/Mode entries (legacy
  dispatcher only) + 54 explicit V5.51 registered Action/Mode entries.
- **CLI:** actual existing Python argparse module with an allowlisted source
  path and fixed prefix, bounded runtime/output and no implicit stdin.
- **API:** actual existing typed Python method (no dynamic module/symbol from
  JSON); only simple JSON-shaped arguments accepted, returned object preserved.
- **PREVIEW:** typed construction of existing EC221 `DeliveryPreviewRequest`,
  `ReportSelection`/`FindingSelection` and `Destination`; never sends content.
- **HOST_REQUIRED:** registered but **rejects** with
  `ROUTER_INDEPENDENT_HOST_AUTHORITY_REQUIRED` until an independently
  authorized host adapter exists. Includes actual IssueCreate POST,
  DeliverySend, ReportPublish, DocsOnlyPublish, KnowledgeImpact/Save/Query,
  QualityRun, and access-controlled FindingShow and QualityShow. The request
  must not carry fake credentials/providers/authorization callback objects.
- Legacy routes are **not callable through JSON**: invoke the original
  `ces.ps1` or `ces-v5.ps1` *without* `-RequestPath`. The latter passes the
  exact caller-supplied old PowerShell parameters to unchanged old code.

Real handler return and permission are different things. Every dispatch result
has `handler_result`, `handler_exit_code`, `handler_invoked`,
`business_effect_verified=false`, `permissions_granted_by_router=false`,
`tasks_advanced_by_router=false`. Handler-specific `exit_code` and `status`
remain visible inside `handler_result` and must be interpreted by the
caller. (历史 EC241 语义) The wrapper's `2` once described an eligible bounded JSON
result. **当前 EC243/V2 的 2 仅代表 `partial`（未认证的局部结果）**，
而不是任意合法 JSON 都退出 2；负面处理器状态可归为 3/4/5。 Exit `3`
means denial/legacy-only/explicit handler block; `4` invalid request or
handler rejection; `5` unavailable, timeout, undecodable or unknown outcome.
Inventory-only returns exit `0` and does not run any handler.

## Trust, platform and acceptance limitations

Request JSON is size-bounded (256 KiB), rejects duplicate/case-colliding keys,
BOM, oversized/symlink last-component request files (where supported), and
nonfinite numbers. CLI parameter count/length, execution time (45 s),
result byte size and imported target sources are bounded. Filesystem ancestor
symlink, same-UID tampering, OS kill, network and subprocess behavior are not
host-attested; the router is not a sandbox and cannot authenticate content or
actor. An untrusted checkout must not be executed or pointed at privileged
resources merely because the route exists.

Do not route a business write by relabeling an action; CodeSave legacy
permission remains inside the untouched R150 process, and independent
external host-specific write calls are **not executable** in this release.
Existing direct Python module calls remain outside EC241 router guarantees.
This EC does not install enterprise providers, a trusted clock, six producers,
a production scheduler or a secret store. Native PowerShell 7 wrapper and
original 15 Smoke were **NOT_RUN** in the current Linux environment. Source
B001 and user-assisted E63–E66/full integration acceptance remain open.

Related: [request contract](unified-action-router-request.v1.schema.json),
[result contract](unified-action-router-result.v1.schema.json),
[EC241 build report](../EC-241.md),
[focused tests](../construction/test_unified_action_router.py).


## EC247 新增独立回归数据入口（不更改 74 路由）

[EC247 跨模块回归与 15 原生 Smoke SHA 映射](ec247-cross-module-regression.md) 可以只读查看原 Smoke 来源、用固定合成输入验证 7 组跨模块边界、单独导出 13 个可用于原 Router 的请求 V1 JSON。`--run` 的 Cycle 私有元数据只在一次性临时目录创建；没有执行旧 15 Smoke、实际 Provider/Git/企业账号/OS/E63–E66/最终联合验收。
