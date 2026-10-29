# EC233 — Cycle Next 处理器（**只选择真实处理器，不执行任务**）

当前施工包 **V5.43 / R233 / EC233**。模块
[`construction/cycle_next.py`](../construction/cycle_next.py) 新增真实可调用的
`CycleNextHandler(private_dir).next(run_id)` / `next` CLI。它消费**已有**
EC231 0700/0600 私有不可变记录，调用 EC232 DAG 检查，按原始 step 声明顺序
选择**一项**依赖为零且状态 `NOT_STARTED` 的真实处理器引用。它没有更改
PowerShell V4.60/R150，也**没有注册原生 `-Action Cycle -Mode Next`**。

## 功能与严格边界

1. 首先重新打开真实 RunId，复用 EC232 的哈希与外部可选 pin 校验，
   检查全图无环；本模块随后重新读记录并再次比较 RunId、原记录 SHA、
   ActionSet SHA、input SHA 和图 SHA，在提议后再次读回核对。
   此流程防止已观察到的记录变化继续产生旧的路由，但**不是**对抗
   同 UID 更改/回滚/网络文件系统竞争的加密认证或锁定快照。
2. **严格依赖屏障：** EC231 没有 `COMPLETED` 或可验证的执行状态；
   `DECLARED_PARTIAL` 和 `UNKNOWN` 不是“前置任务已完成”。因此**仅** DAG
   第一波原生无依赖 root 可作为 Next 候选，第一波之外全部列在
   `blocked_by_step_ids`，不自动跳往下一层，也不因为重复调用而推进。
   任何不可信部分/未知状态使整体 `BLOCKED_NO_NEXT`。多个独立 root
   会报告在 `ready_root_step_ids`，仅提议**原声明顺序第一项**；如果
   第一项没有实现处理器，不偷偷跳过而返回 `none`。
3. **实际路由，不接受 caller 私造 registry。** 对原生七 Action / 16
   Action+Mode 路线使用原 EC155 `read_registry/resolve/check_registry`，
   严格验证原 EC152 真实 PowerShell 分派源、已实施的函数与子模式、
   EC157/159 已审阅的源码变化与 CodeSave `ApprovePersist` 阻断。
   当前 EC155 `planned_capabilities` 和后来不断更新的矩阵之间有一项
   **已知的旧状态对比偏差**，本轮仅放行该特定*计划表*提示，
   **其他所有源码/路由校验问题均阻断**。输出真实
   `scripts/ces.ps1` 入口、存在的 `.ps1` 处理器路径/函数、文件
   SHA-256、准确 Action/Mode、必需操作参数与关联 Smoke；
   只表示源码中有实现，**不表示本机 PowerShell 已运行通过**。
4. **四类 Next 返回：**
   - `cli_action`：仅原本已存在的**只读** PowerShell 路由，如
     `Inspect`、`Collect:WorkingTree`、`CodePrepare:Snapshot`、
     `CodeShow:Findings`，status=`NEXT_PROPOSED_NO_EXECUTION`；
     `Inspect` 忽略 Mode，`CodeShow` 必须显式指定其已实现 Mode，
     Snapshot 动作按原生规则处理默认 Mode。
   - `ai_handoff`：仅明确的 `AIHandoff/CodeAnalysis`，源指向
     **实际 EC174** `HandoffRouter.route`/`code_analysis`，验证当前
     Python 方法、原源码路径及 EC232 完整包所保留的 EC174 源哈希。
     需要另外构造真正的 EC173 授权输入、独立 route/read 审批，
     真正外传还要额外审批；并**没有调用 AI**，无模型结果或
     外部账号/Actor 真实性断言。
   - `await_permission`：仅真实原生 `CodeSave:Snapshot` 处理器，
     提示人工明确提供 `ApprovePersist` 等参数；它**没有申请或赋予**
     任何权限，也没有持久化 `PAUSED` 节点。实际暂停/批准协议属于 EC235。
   - `none`：环、未知/缺失/变化记录、未实现 Action/Mode、
     未验证处理器源码、状态无法证明时返回。`none` **不是**
     “完成全部任务”，也不是可以重试写操作的许可。
5. `next_step` 非空时必须包含真实注册路由、处理器源文件与符号、
   当前文件 SHA、最少操作参数提示、未运行状态及原 step ID。
   独立 `proposal_sha256` 绑定 RunId/记录/图/路由建议，是**无签名摘要**，
   不是审批/执行 token。`trust.*` 始终不能声明来源/Actor/运行结果验证，
   `effects.*` **全部为 false**。

## CLI 示例

先用 EC231 创建一个真实的私有 RunId，可使用 `Inspect`（只读）
作为声明步骤，EC233 不接受临时 action JSON 代替已保存的记录。

```bash
python construction/cycle_next.py next \
  --store /host-private/ces-cycle-records \
  --run-id run_v1_<48_lower_hex_digits> \
  --expected-record-sha256 <64_lower_hex_digits> \
  --expected-action-set-sha256 <64_lower_hex_digits> \
  --expected-input-sha256 <64_lower_hex_digits>
```

三个 `--expected-*` 都是**可选**的外部保存一致性 pin。
从可能被篡改的**同一个原文件**读 pin 再传回去不能提供真实性证明。
输出一行完整 JSON，严格遵循
[`cycle-next-result.v1.schema.json`](cycle-next-result.v1.schema.json)（Draft 2020-12）。

退出码：`0` 为只读 `cli_action` 的**提议**（未执行），`2` 为
需要人工交接的 `ai_handoff` 或 `await_permission`，`3` 为
`BLOCKED_NO_NEXT`，`5` 为 `UNKNOWN_BLOCKED`；CLI 语法错误仍由
argparse 返回 `2`，以 `status`/`reason_code` 区分。无一退出码意味着
Cycle / Git / AI / 外部 Provider 有任务成功。

标准 Python 接口（项目根目录或把 `construction` 加到模块路径）：

```python
from construction.cycle_next import CycleNextHandler

result = CycleNextHandler('/host-private/ces-cycle-records').next(
    'run_v1_' + '<真实的48位十六进制RunId>',
    expected_record_sha256='<独立保存的64位hex摘要>',
)
assert result['effects']['handler_invoked'] is False
assert result['effects']['write_authorized'] is False
```

## 当前绝不能从 Next 推断的能力

- 没有执行、参数自动补齐、源仓库实时验证、自动调度、原生 PS Cycle
  Action、PowerShell7 当前可运行性或原十五 Smoke 验收。
- 原始 EC231 元数据无法保存 VERIFIED/DONE，因此不能实现真正的
  “执行一项后 Next 下一项”；需要后续 EC236/238 的受信状态/证据绑定。
  多次调用当前 `next` **应当保持同一选择**。
- 没有 EC234 的运行预算/速率/输出消耗控制、EC235 的权限暂停、
  EC236 Resume、EC237 Summary、EC238 跨 Action 可信 Handoff、
  EC239/240 调度/并发控制。`AIHandoff` 需要现有 EC173/174 的
  分别授权，不得把纯路线说明视作外传同意。
- 没有独立可信 PKI/Actor/源快照身份、同 UID 防篡改签名、生产
  OS/FS/NFS/多主机一致性或权限批准。`next_step.handler`
  只能帮助操作者识别**真实已实施的处理器**，不能直接传给自动执行器。

## 开发检查 / 最终验收

本轮 `construction/test_cycle_next.py` 的 **32 项聚焦开发场景**使用
真实 EC231 临时私有记录、EC232 DAG、已有原生静态路由和 EC174
处理器，覆盖四种结果、真实文件 SHA/Mode、依赖屏障、未知/部分
拒绝、环、外部 pin、变化竞争、防越权 schema、CLI 退出码和源码
漂移阻断。未调用 PowerShell、Git/外部 AI/provider 或真实客户输入。

**最终统一人工验收 NOT_RUN：** 真实宿主的原生 PowerShell7/15 Smoke、
客户 RepoPath/Mode 参数/真实 handler 行为、EC173 外传许可和独立
身份、真实 CodeSave 权限、R150 静态已审阅漂移、同 UID/OS
掉电/NFS/多主机、Windows/macOS、E63–E66 与全功能联验。
B001 原始 V3.10/ROUNDS 上游证据缺口仍 OPEN。
