# EC237 — Cycle Summary（只读、来源复核、不得伪造完成）

施工版本 **V5.47/R237/EC-237**。实现入口：
[`CycleSummaryReporter.summary()`](../construction/cycle_summary.py)；
严格返回 Schema：[cycle-summary.v1.schema.json](cycle-summary.v1.schema.json)。

## 实际实现内容

Summary 在**同一次调用内**读取已有的真实 EC231 0700/0600 私有 `RunId`
元数据、复核 EC232 的真实 DAG、两次重新计算 EC233 现有处理器的**实际源代码绑定**，
并在有 EC235 持久 `DENY` sidecar 时重新验证真实暂停记录、其处理器和原始
Action/Graph/Proposal 绑定。原元数据与 sidecar 在结束前重新读取并比较，
若观测到漂移，返回 `UNKNOWN_BLOCKED`，**不给出旧步骤的局部成功**。
不存在的 sidecar 与损坏、非私有、符号链接 sidecar 是不同情况；后者不能假装无暂停。

输出包括：按原始声明顺序的步骤、原 Action/Mode、未认证的 `NOT_STARTED` /
`DECLARED_PARTIAL` / `UNKNOWN` 状态；依赖未证明清单、保存的声明性证据
SHA/时间/HandoffId、可核对的记录/DAG/提议/暂停内容摘要、拒绝放行门；
EC231 存档时声明的 input bytes、预算 limits/usage，以及可选 EC235 拒绝性
预算检查单次观测次数/输出字节。**以上 SHA、HandoffId、用量仅为来自
未独立签名的现有本地记录的声明或一致性验证**，不证明真实源码、业务结果、
独立审批、付费、运行时 CPU/时间/输出的总数。

不同状态的保守解释：

| `status` | 事实解释 |
| --- | --- |
| `NOT_STARTED` | 实际源码支持一个建议处理器，但没有执行。 |
| `AWAIT_PERMISSION_NO_CHECKPOINT` | 当前 CodeSave 第一 root 需要独立原生 `ApprovePersist`；未发现 EC235 持久暂停，不等于许可。 |
| `PAUSED_PERMISSION_REQUIRED` | 已验证现有 EC235 `NOT_PROVIDED` 或 `DECLINED` 的 `DENY` 暂停；原所有动作依旧未执行。 |
| `OPERATOR_HANDOFF_REQUIRED` | 有 EC174 真实 AIHandoff 路由建议，未做独立 AI/操作者授权、交接或任务调用。 |
| `UNVERIFIED_PROGRESS_BLOCKED` | 原 EC231 `PARTIAL` 或 `UNKNOWN` 仅是声明，不足以跳过步骤或推导成功。 |
| `BLOCKED_NO_HANDLER` | 原第一个 root 无可验证的已实现处理器，不能跳过到后续。 |
| `BLOCKED_DAG_CYCLE` | EC232 明确检测依赖环，不能给出可执行顺序。 |
| `UNKNOWN_BLOCKED` | 缺失、篡改、权限不安全、pin 不符、旧/新读取漂移、来源校验失效或任何关键数据不可靠；步骤、证据、成本均清空。 |

`counts.verified_success` 和 `counts.verified_failure` 固定为 **0**：
这**不是**断言全部失败或业务实际上没有执行，而是本系统没有独立可信的成功/失败
证据。`counts.dependency_blocked` 统计带有任意依赖的步骤（因为现有 EC231
没有可认证的 SUCCEEDED 状态）；多个根节点中只会提议最早一个可核对处理器。
`declared_evidence_sha256`、`declared_observed_at_utc` 和 `declared_handoff_id`
绝不能被误认为核验通过的证据内容。原 `snapshot_bytes` 不读取、不回显。

## Python API

```python
from construction.cycle_summary import CycleSummaryReporter

report = CycleSummaryReporter('/absolute/owner-private/ec231-store').summary(
    'run_v1_<原有真实48位hex>',
    # 可选：保存在本地记录之外的 SHA-256 预期值（仅防部分漂移，不是签名）
    # expected_record_sha256='<64位hex>',
    # expected_action_set_sha256='<64位hex>',
    # expected_input_sha256='<64位hex>',
    # expected_pause_sha256='<64位hex>',
)
print(report['status'], report['counts'], report['steps'])
```

## 命令行

```bash
python construction/cycle_summary.py summary \
  --store /absolute/owner-private/ec231-store \
  --run-id run_v1_<原有真实48位hex> \
  --expected-record-sha256 <可信外部保管的原64位hex>
```

输出为单行、排序稳定、ASCII JSON，报告长度最多 **128 KiB**（131072 bytes
的 canonical JSON）。退出码 **2**=生成**无任务成功证明**的只读汇总，
**3**=已知阻塞（环/无路由/未认证进展），**5**=无法可信读取。
没有代码 0 来暗示整个 Cycle 成功。未提供外部 SHA pin 的返回依旧可用于
诊断，但不能抗同 UID 改写或可信来源重放。

`record_binding` 中的 SHA 绑定和双重读取不能代替真正的来源签名、内容来源、
Git 仓库认证或多主机防重放。EC234 的本地进程内检查配额**不涵盖**
EC237 的两次 EC233 源检查；本模块提供 128KiB 输出边界，但不执行 OS
级 CPU/IO/RSS 限额。EC236 `restore()` 的新鲜输入比较也不由 Summary
替用户代做：如需验证现场快照，应单独执行 EC236 `restore` 的真实字节比较，
且即使比对一致，仍无执行权限。EC238 跨动作 HandoffId、EC239 scheduler、
EC240 重放并行、EC241 原生 Cycle 路由都不在本轮内。

测试：[42 项本地聚焦情景](../construction/test_cycle_summary.py) 覆盖真实私有
Run、DAG/Next、DENY checkpoint、JSON Schema、声明证据、成本未知、篡改
与 CLI。它们不构成 PowerShell7/Windows/macOS、原15套 Smoke、
真实企业签署/ApprovePersist/业务写、same-UID/NFS/掉电/多主机、E63–E66
或最终验收。本包保留原 V4.60/R150 PowerShell CLI，不注册原生
`Cycle -Mode Summary`。原 B001 缺少的 V3.10/ROUNDS 依旧 OPEN。
