# EC235：真实 Cycle RunId 的持久 `await_permission` 阻断节点

**施工版本：V5.45 / R235 / EC235。** 对外接口：
[`CyclePermissionPauseStore`](../construction/cycle_permission_pause.py)，
严格存档契约：[`cycle-permission-pause.v1.schema.json`](cycle-permission-pause.v1.schema.json)。
这是**有界、只允许拒绝的本地暂停记录**：不是授权服务器、CodeSave 执行器、
AI 调度器、审批令牌、已完成步骤日志、EC236 Resume 或原生 PowerShell Cycle Action。

## 真正实现的链路

1. **仅存在的 EC231 RunId。** 必须在支持 POSIX `O_NOFOLLOW` 的本机、现有专属
   0700 目录中有合法 EC231、文件 0600/单硬链接的原始 immutable metadata。
   可额外携带来自独立保管方的 `record/action-set/input` 三个 digest pin，
   与原记录内容不符立即拒绝；哈希自校验本身**不是**签名或身份验证。
2. **一次真正 EC234 预算化 `inspect()`。** EC235 实际新建 EC234
   `CycleBudgetGuard`，不接受用户传进来的“某个 Next JSON”。仅当预算内检查
   返回完整非截断、原输出字节数已计量的 `AWAIT_OPERATOR_ONLY` + 实际 EC233
   `await_permission` 时才能继续。时间、输出、速率、步检数、证据限额不足、
   输入漂移、DAG/handler 不可用都没有暂停记录。这里的 `admitted_inspections=1`
   是本次只读建议检查，**不是已执行一个业务步骤**。
3. **精确源/步骤绑定。** 仅原生已编写的 `CodeSave:Snapshot`，且是原
   EC232 DAG 的第一项未执行、零依赖根；记录实际 `step_id`、
   `Record/ActionSet/Input/Graph/Next Proposal` 摘要、源声明、Actor 声明、
   handler/CLI 实际文件路径、符号与本轮静态源码 SHA。原版 CodeSave 的
   `ApprovePersist` 是明确的**外部独立审批门槛**；本模块不接受批准凭据，
   也不将 `requested`/`suggested` 解释成许可。
4. **不可覆盖的持久阻断。** 原目录增加唯一
   `<RunId>.permission-pause.v1.json`，独立 192-bit `pause_id`，
   `O_EXCL|O_NOFOLLOW` / 精确 0600 / 有界 16KiB / fd fsync / 目录 fsync /
   读回确认。存档中的 `status` 只能是 `PAUSED_AWAITING_PERMISSION` 或
   `PAUSED_PERMISSION_DECLINED`。`permission_gate.gate_result=DENY`、
   `independent_approval_verified=false`、`can_resume=false`，且原始全部步骤仍
   `NOT_STARTED`。无论是否有当前“操作员拒绝”声明，都不会调用 CodeSave、AI
   或任何真实写/发布处理器，也不会自动推进后继步骤。
5. **重启后真实重新校验。** `load/inspect` 用原 RunId 重新读取原始
   EC231 记录和侧记录，严格验证域分离 hash、存档形状、现存 source/Actor
   声明、所有步骤、处理器源码绑定以及 EC233 当前 `await_permission` 结果。
   原记录改变、源漂移、侧记录损坏/缺失、签名伪造式的权限字段、
   文件软/硬链接或来源不可用均报错阻断；不会补造新的任务状态。
   **注意：** `inspect` 的源码复查是本地单独的只读检查，**不算作**之前
   EC234 临时 Guard 里的跨进程累计额度，也不是任何全局预算证明。

## 可运行命令与返回

先用 EC231 生成真实的 `CodeSave:Snapshot` 单根或第一个待授权根；
其它模式或非 CodeSave 根不会生成权限暂停。命令中的 RunId/路径仅为模板：

```bash
python construction/cycle_permission_pause.py pause \
  --store /absolute/owner-private/cycle-store \
  --run-id run_v1_<48_lower_hex_digits> \
  --operator-response NOT_PROVIDED \
  --expected-record-sha256 <independently_saved_64_hex_sha>

python construction/cycle_permission_pause.py inspect \
  --store /absolute/owner-private/cycle-store \
  --run-id run_v1_<48_lower_hex_digits>
```

拒绝审批时可第一次创建时提供 `--operator-response DECLINED`。两种输入都只
持久保存 **DENY**，不是验证过的 Actor 签名。`APPROVED`、布尔授权、
外部 Next JSON、任意 handler、原 EC231 运行状态编辑以及第二次覆盖写入
均不可用。也可通过 EC234 原有 `--max-step-inspections`、
`--output-bytes`、`--wall-ms` 等选项**降低**一次检查预算；超限失败。

```python
from construction.cycle_permission_pause import CyclePermissionPauseStore

service = CyclePermissionPauseStore('/absolute/owner-private/cycle-store')
saved = service.pause('run_v1_' + '<真实48位十六进制RunId>')
assert saved['status'] == 'PAUSED_AWAITING_PERMISSION'
assert saved['permission_gate']['gate_result'] == 'DENY'
assert saved['effects']['can_resume'] is False
# 程序重新启动之后：
same_denial = CyclePermissionPauseStore('/absolute/owner-private/cycle-store').inspect(saved['run_id'])
```

CLI 返回 **2** 表示已经安全保存/读取一个**仍等待人工处理**的侧记录，
不代表业务成功、批准或完成。返回 **5**、`UNKNOWN_BLOCKED` 和有限原因码
表示路径、RunId、预算、许可、损坏、冲突、来源等问题导致拒绝。若原数据
改动，历史 sidecar 保留原字节且不可覆盖，操作者必须单独审查原始资料，
**不得因检查失败而自动清空暂停或重试写操作**。临时目录/私有目录不能
放在不可信的可修改祖先路径下。

## 不可跨越的实际信任边界

- `pause_sha256`、`Record SHA`、`Proposal SHA` 是**无签名的内容一致性
  摘要**，不能阻止同一 UID 恶意重写、回滚，也不能认证外部 Actor、
  当前仓库快照/签名/用户意图。可选三个独立 pin 是漂移检测，不是公钥许可。
- 文件系统侧记录的 fsync 不保证操作系统掉电、NFS、多主机或目录替换竞态。
  一旦文件已经创建但写入/fsync/读回未知，**保留 uncertain sidecar**，
  不报告成功、不会自动删除/覆盖重试，后续 `inspect` 因损坏会拒绝。
- 本轮新代码没有可进入业务写操作的执行路径。原 PowerShell7
  `CodeSave` 需要的真实 `ApprovePersist` 审批仍由原处理器自身实现；
  本轮只是持久记录**该独立门尚未满足**，不是实现身份认证、批准签名、
  新权限后状态跃迁或全局审批工作流。后续 EC236 Resume 必须另行设计
  来源重验、授权和可信恢复；**本轮没有 Resume API**。
- EC234 预算的测量对象仍只是它自己的建议输出、诊断和本进程检查；
  EC235 的本地文件 fsync/读回/后续 `inspect` 不在原 EC234 `output_bytes`
  或硬进程 IO 限额之内，也不会被描写成跨请求持久计量。没有外部 watchdog、
  全局速率、OS RSS/IO/网络配额。
- **验证仍待最终用户统一辅助执行：** 真实企业 actor/source/用户许可与
  CodeSave 门、PowerShell7、原 15 套 Smoke、Windows/macOS、同 UID/并发
  目录攻击、系统 crash/掉电/NFS/多主机、E63–E66 性能及整个产品集成；
  旧 B001 V3.10/ROUNDS 上游来源缺口未解决。

EC235 本地聚焦开发场景仅见
[`construction/test_cycle_permission_pause.py`](../construction/test_cycle_permission_pause.py)；
所有原 PowerShell V4.60/R150 和以前 EC 的功能代码均不在本轮变更范围。
