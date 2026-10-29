# EC247 跨模块可复现测试数据与覆盖映射 — V5.57/R247

本轮**只补充可复现的本地跨模块输入与开发回归执行器**，没有实施 EC248/249/250，也没有替代最终用户辅助联合验收。新入口在 `construction/cross_module_regression/runner.py`，它**不是**第 75 条 CES Action/Mode、不是宿主 broker、不是原生 PowerShell Smoke 的替代品。

## 直接使用

从 `ces/` 工程根目录执行（Python 3；无需凭据）：

```sh
# 只查来源：15 份原 Smoke 精确字节指纹、7 组联动情境、固定权限说明，不执行任何测试
python3 -I -B construction/cross_module_regression/runner.py --plan

# 对真实的已有 Python Router/Handler 进行固定合成输入联动开发检查
# 只在一次性私有临时目录允许 Cycle 元数据的显式测试写；清理后退出
python3 -I -B construction/cross_module_regression/runner.py --run

# 仅执行 Cycle 合成跨模块链
python3 -I -B construction/cross_module_regression/runner.py --run --only cycle_source_chain

# 为最终现场人工辅助验证导出：必须是已存在父目录下的**全新绝对路径**，不覆盖文件
python3 -I -B construction/cross_module_regression/runner.py --prepare /tmp/ces-ec247-manual-inputs

# 聚焦功能测试：既有 Handler 真实 local 调用/边界/导出恢复，不等于外部验收
python3 -I -B construction/cross_module_regression/test_runner.py
```

`--prepare` 在新目录里保留四份原始合成输入，另外生成 `requests/` 下的 **13 个可以直接交给 `scripts/ces_router.py` 的独立请求 V1 JSON 文件**、`router-request-commands.txt`（将 `EXPORT_DIR` 替换为真正绝对路径）、`native-smoke-commands.txt`。后一文件只列出 15 行原生待跑命令，**不会由 EC247 执行**。导出目录必须不存在，不能位于 CES 工程内或其父目录，且不允许符号链接祖先；仍不保证对抗恶意同 UID 并发目录替换。

## 原始 15 个原生 Smoke：字节锁定且待人工现场运行

| 原 Smoke 文件 | 主覆盖意图 | 状态 |
|---|---|---|
| `Inspect.Smoke.ps1` | 本地 Git 根与 main/linked/bare 区分 | NOT_RUN |
| `Collect.Smoke.ps1` | WorkingTree 变更收集 | NOT_RUN |
| `DeliveredTarget.Smoke.ps1` | DeliveredTarget 指向与快照 | NOT_RUN |
| `Reconcile.Smoke.ps1` | 不同时间点同一路径内容漂移 | NOT_RUN |
| `CodePrepare.Smoke.ps1` | Snapshot 准备结果 | NOT_RUN |
| `CodeValidate.Smoke.ps1` | 草稿合规检查 | NOT_RUN |
| `CodeSave.Smoke.ps1` | 原 CodeSave 双门禁与本地持久化 | NOT_RUN |
| `CodeShow.Smoke.ps1` | 保存历史 List/Detail | NOT_RUN |
| `CodeFindings.Smoke.ps1` | Findings 结构查询 | NOT_RUN |
| `CodeCompare.Smoke.ps1` | Compare 对照结果 | NOT_RUN |
| `CodeTrace.Smoke.ps1` | Trace 展示 | NOT_RUN |
| `CodeOverview.Smoke.ps1` | Overview 汇总 | NOT_RUN |
| `CodeTriage.Smoke.ps1` | Triage 分组 | NOT_RUN |
| `CodeRecurrence.Smoke.ps1` | Recurrence 范围与窗口 | NOT_RUN |
| `CodeSequence.Smoke.ps1` | Sequence k1..56 兼容形状（**非性能认证**） | NOT_RUN |

这 15 个 `.ps1` 脚本原本各自构造独立临时 Git 数据，EC247 不修改/重复包装脚本；[`manifest.json`](../construction/fixtures/cross_module/manifest.json) 记录**逐文件当前 SHA256**、旧路由、覆盖意图与统一的 `NOT_RUN_NATIVE_PWSH7_GIT`。`CodeSequence.Smoke.ps1` 原字节约 1.8 MiB，读取上限特意独立设为 4 MiB，没有错误认定它超过 1 MiB 就损坏。原 15 套 Smoke 在需要 PowerShell 7 + Git 的用户批准测试环境再运行，可能产生临时 Git 数据；不要针对真实业务仓直接运行。

## 7 条可复现的新模块跨界功能链

| 情境 ID | 调用已有模块的实际链路 | 必须观察的状态与安全性质 |
|---|---|---|
| `schema_admission` | SchemaReview Inventory → Audit → Inspect → Plan | 审阅 112 个来源固定 Schema；合成 EC242 Cycle v1 记录可读、同契约 Plan NOOP 不改源字节、未迁移 |
| `calendar_period` | Due Evaluate → NaturalPeriod from_instant → from_id | UTC/周周期真实起止边界、时长和 period ID 重算相同；不得冒充已调度/已报表 |
| `cycle_source_chain` | Cycle Create（先拒绝未授权，再在独立私有临时目录显式 opt-in）→ Inspect → Next → Summary → BusinessWriteAttempt | 真正写入并重读 EC231 私有元数据；Next 绑定 R150 源但不执行；Summary 保持 NOT_STARTED；禁止业务写；记录 SHA 读取前后相同 |
| `code_save_gates` | CodePrepare MultiSource 错误输入 → CodeSave Staged（无 opt-in）→ 原 CodeSave Snapshot | 新准备缺资料拒绝；新私有写不执行；原 PowerShell CodeSave 不被 Python Router 绕过 |
| `issue_creation_boundary` | IssueCreate Eligibility 无效合成请求 → IssueCreate Create | 仅开发输入拒绝；宿主 Issue 创建未尝试、3/denied |
| `delivery_publication_boundary` | DeliveryPreview 无效请求 → DeliverySend / DocsOnlyPublish / ReportPublish | 预览验证错误、不越权尝试；三个宿主发布/发送接口全部 3/denied，未调用宿主 handler |
| `provider_network_boundary` | Collect ProposedPR 带 `--allow-network` 但缺独立 Router 显式网络 opt-in | Router 3/denied，不进入远端 Provider，不读取凭据 |

所有 Router 调用仍使用原 EC243 **请求 V1、结果 V2 / V5.53/R243**；当前 **V5.57/R247 只是完整工程包的版本**。EC247 在执行前比对原 15 套 Smoke 原始文件 SHA、四份测试输入 SHA、7 条固定链、13 个固定示例请求和当前 74 条固定 Router 的版本，变化不悄悄重解释。Runner 并不从测试数据导入任意模块/代码或执行任意供应商 URL，输出只记受限状态和步骤 ID，不包含处理器原文、路径、token、仓库身份。

## 已执行与未执行要严格分开

- 当轮在本地 Python 环境实际得到：**7/7 真实本地合成联动场景通过；10/10 EC247 专项测试通过**。这些是有限的开发反馈，不能宣称对生产权限/源码真实性验证。运行环境可能不同，届时按 `LOCAL_DEVELOPMENT_INCOMPLETE` 如实记录。
- 原始 15 个 PowerShell Smoke **0/15 本轮执行**，不是 `15/15 PASSED`；真实 PowerShell 7、OS/Windows/macOS、真实 Git/Provider/Issue/DocsOnly 组织账号、企业审批、网络隔离与隐私泄露、E63–E66 资源性能、最终联合验收一律 **NOT_RUN**。继承的旧 `plan_guard.py` 枚举检查仍报 31 个 R246 起就存在的 `actions[]` 状态码不匹配，本轮未改这 31 个能力项，不能将旧 gate 称作 PASS。EC244 独立静态审查 41/41 与源 SHA 307/307 对齐仅属静态来源核查。
- Cycle 私有仓在一次性 `TemporaryDirectory` 中创建，开发机允许的本地磁盘元数据写**不是对任何用户业务源或仓库的写权限**。不能把 Python Router 的 `handler_invoked`、`partial` 或自报测试状态当作宿主授权/实际成功证明；同 UID 文件系统恶意并发、临时文件磁盘硬限额和无外网 OS sandbox 都没有在这里得到证明。
- 原始 V3.10 冻结总规格与原 `ROUNDS.json` 缺失的 B001 仍保持 OPEN；计划状态不得用本轮场景覆盖率掩盖这一缺口。

**本轮交付文件：** `EC-247.md`（历史记录，见清理前Git历史）、[`runner.py`](../construction/cross_module_regression/runner.py)、[`test_runner.py`](../construction/cross_module_regression/test_runner.py)、[`manifest.json`](../construction/fixtures/cross_module/manifest.json)、四份固定输入文件、`LEGACY_REGRESSION_RESULTS.json`（历史记录，见清理前Git历史）、原文件逐条 SHA 留存 receipt。下轮只施工 EC248（CodeShow 兼容/性能），不得误记作当轮已完成。


> Release 1.8.0: obsolete construction plans, progress/completion logs and their one-time checkers were retired. This document describes retained implementation boundaries; historical acceptance statements are not current release claims.
