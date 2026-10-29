# EC234：Cycle Next 的本地预算、速率与输出控制

**版本：** 施工包 V5.44/R234/EC234。入口是
`construction/cycle_budget.py` 的 `CycleBudgetGuard`，不是原生
PowerShell `Cycle` Action、执行器、调度器、EC235 的暂停记录或 EC236 的
Resume。EC231 的私有记录仍是不可变的 `CYCLE_METADATA_ONLY`，其
`budget.enforcement` 仍为 `CAPTURE_ONLY_NO_RUN_ENFORCEMENT`；这个
原字段描述**记录自身**不具备执行预算，不能被改写为已真实执行。

## 1. 真正实施并实际计量的边界

`CycleBudgetGuard` 只接收一个已经存在的 EC231 私有 RunId，使用
`CycleMetadataStore.load()` 严格读取并校验，固定原始 `record_sha256`、
`action_set_sha256` 和 `input.sha256`，支持调用方独立保留的三个可选
摘要 pin。不接受导入伪 JSON RunId。每次 `inspect()` 在单对象互斥锁
内再次读取记录，拒绝任何已观察到的变更；EC233 随后自己完成
EC232 DAG/来源/处理器校验，随后再做一次当前记录比对。

- **建议检查次数：** `max_step_inspections` 不大于 EC231
  `budget.limits.max_steps`。每次*已经获准的检查*计一次，无论
  `Next` 返回阻断还是建议。**不是已经执行的步骤数**。达到次数上限
  后在下一次调用 EC233 前拒绝。
- **滑动窗口速率：** `rate_max_calls` 次／`rate_window_ms`，使用
  `time.monotonic_ns()`，同一对象的多线程检查使用锁；老窗口令牌可
  过期。超速返回 STOP 且当前会话封闭，不排队、不擅自恢复。
  这是**同一 Python 对象、同一进程中的限速**，不能冒充跨进程、
  多主机或持久 token bucket。
- **时间/CPU：** 以进程内单调墙钟和 `process_time_ns()` 测量
  会话内的本地处理。进入检查前、完成 EC233 后、编码响应后再次
  观察，达到上限丢弃建议。无法以 Python 检查点中断阻塞调用；
  不是内核 watchdog、CPU quota、真实外部任务截止保证。CPU 观察是
  当前 Python 进程，可能包含其它线程。
- **输入/诊断/材料字节：** EC231 的 `input.byte_length` 是历史
  *实际提供过的输入快照字节数*，而不是当次重新读取的快照内容。
  `diagnostic_bytes` 必须是真正 Python `bytes`，只累计长度，
  永不反序列化、回显、写入或认作可靠 evidence。证据和材料预算
  不足时在调用下一层之前拒绝。`material_bytes` 是
  **input size + accepted diagnostic size + own serialized output** 的
  会计约束，不是实际 RSS、磁盘 IO 或远程 API 额度。
- **真实输出字节：** 返回 `BudgetMessage.payload` 为已包含尾随
  `\n` 的完整 ASCII JSON 行；编码内容含累积 `usage.output_bytes`
  自己的数值，迭代计算精确总长。实际输出超过所配 EC231 上限就
  剥离 `next_proposal`，保留 STOP/未执行步骤清单；如果连最小
  完整 JSON 都装不下（例如创建记录时选择 `output_bytes=1`），
  返回 `payload=b''`、退出码 3，不输出半截 JSON，也不绕过预算
  泄露内容。调用方必须原样输出这些字节，不能自行追加日志。

所有覆盖值只能**降低** EC231 原预算；不能以布尔值、浮点数、
类型强制转换或未知参数扩大预算。CPU 默认为 `min(wall_ms, 10000)`，
同时降低 wall 时会自动缩小默认 CPU 限额；显式冲突拒绝。
默认同对象限速为每 1000ms 最多 4 次、窗口设置允许 1～60000ms。

## 2. 返回契约

Schema：[`cycle-budget-result.v1.schema.json`](cycle-budget-result.v1.schema.json)，
Draft 2020-12，**内嵌 EC233 的严格 `next_proposal` Schema**。

- `NO_EXECUTION_PROPOSAL`（CLI 退出 0）：仅已有、可追溯 EC233
  的 `cli_action`，不表示执行结果，也不承诺完整任务成功。
- `AWAIT_OPERATOR_ONLY`（2）：已有 EC174 `ai_handoff` 或原
  CodeSave `await_permission` 建议，但**没有取得授权**。
- `NO_EXECUTION_BLOCKED`（3）：DAG 有环、源不可用、第一根
  未实现等，无可提供的处理器建议。
- `STOPPED_BUDGET`（3）：步检数、速率、时间、CPU、证据、输出、
  材料预算已达界或不可安全输出；**不再调用**下一检查。
- `UNKNOWN_BLOCKED`（5）：已观察到 RunId/记录变化、源或内部
  接口不确定等，完全取消下一处理器建议。

`remaining_step_ids` 包括当前 EC231 ActionSet 的**全部**声明步骤，
不会由于 `Next` 建议已经出现就移除第一根，更不声称依赖已完成。
记录已被替换、损坏或身份未知时 `remaining_known=false`、
`remaining_step_ids=[]`、`unperformed_count=null`；空数组**不代表
没有剩余工作**。

机器结果中所有 `trust.*` 与 `effects.*` 均为 `false`。
`rate_scope`、`enforcement_scope` 解释真实边界；
`usage.admitted_inspections`、`usage.evidence_bytes`、
`usage.output_bytes` 只属于这个临时对象，与 EC231 原 `budget.usage`
中的执行字段**绝不混淆，也不写回**。

## 3. 调用方法

在 CES 工程根目录、满足 EC231 私有记录 POSIX 权限前提下：

```bash
python construction/cycle_budget.py inspect \
  --store /absolute/owner-private/cycle-store \
  --run-id run_v1_<48-lowercase-hex>
```

参数 `--checks 3` 可在**同一对象**内依次读取最多 3 次，因而
共享步预算、时间、速率与输出总量；一旦停止/阻断/未知，立即终止。
`--max-step-inspections 2 --rate-max-calls 2 --rate-window-ms 1000`
等可降低上限。允许 `--expected-record-sha256`、
`--expected-action-set-sha256`、`--expected-input-sha256` 从独立
持有的证据 pin 原记录。**不要让同一不可信来源既编辑记录又
提供 pin**，自校验 SHA 不构成身份证书。

Python API 示例：

```python
from construction.cycle_budget import CycleBudgetGuard

guard = CycleBudgetGuard('/absolute/owner-private/cycle-store', run_id,
                         overrides={'max_step_inspections': 1})
result = guard.inspect(diagnostic_bytes=b'local diagnostic bytes')
# result.payload 已被严格计量且自带结尾换行；不可再拼接。
# result.exit_code 为 0/2/3/5。result.parsed() 可以用于消费者读取。
```

如果无法读取有效真实记录，CLI **stdout 为空且 exit 5**，仅
在 stderr 给出非秘密原因码；此时不存在可信的剩余工作清单或预算。

## 4. 明确没有实现的行为 / 后续统一验收

- **没有**实际 PowerShell/AI/远程 Provider 的任务执行、CPU/RAM/
  磁盘/进程硬配额、网络 egress quota、跨进程/主机全局限速。
- **没有** EC235 持久 `await_permission`、EC236 Resume、EC237
  Summary、EC238 跨动作 evidence 身份、EC239 调度或 EC240
  并行事务；不自动消费下一根、没有“执行完成”状态。
- same UID 篡改、读写竞态、进程终止、Host crash/clock 异常、NFS、
  多主机/Windows/macOS、PowerShell7/原 15 Smoke、E63-E66 以及
  真实企业权限/源/AI 均**等待最终统一人工辅助验收**，不能凭
  开发模拟场景宣称通过。B001 缺失原 V3.10/ROUNDS 仍未解决。
