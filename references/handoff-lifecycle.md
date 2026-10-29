# EC171 — RunId / HandoffId 生命周期状态模型（独立可运行）

**位置：** `construction/handoff_lifecycle.py` · **契约：** [`handoff-lifecycle.v1.json`](handoff-lifecycle.v1.json) · **本轮：** V4.81/R171。此模块供后续 EC172–176 复用，**不是**已经能启动 AI、写暂存、执行原生 `AIHandoff` 或断电恢复的系统。冻结 PowerShell `CodePrepare:Snapshot` 和 EC170 独立多来源上下文入口均不改变。

## 身份创建和信任界线

`Lifecycle.preview(prepared)`验证已形成的 EC170 上下文，**永不生成 RunId/HandoffId**。只有 `Lifecycle.create()` 输入合法、操作键合法且开始真实*内存会话创建*时，才由系统 CSPRNG 生成一个192位随机 `run_v1_...`；只有父运行进入 `ACTIVE`、上下文与全局revision重新核对后调用 `create_handoff()`，才生成独立 `handoff_v1_...`。不可用自增时间戳、固定哈希、上下文hash或示意字符串当成实际创建的ID。离线模块不拥有全局身份注册/跨进程幂等存储，所以随机ID不等于“已经持久化的任务”。

三个身份维度**不混淆**：RunId=本次内存运行，HandoffId=此运行下一次明确创建的任务，`context_sha256` + `identity_sha256`=EC170上下文及来源摘要；人工/外部主体仅可用 `declared_actor("human"|"external", subject)`记录未验证标签，不会形成 actor_key、Provider主体认证或写操作许可。源绑定校验 EC170 自身域分隔上下文哈希、`WorkingTree/DeliveredTarget/ProposedPR`模式与源身份一致性、自报`success/partial`及否定证明标记。**哈希一致不等于来源可信或AI真实执行**；不保存 raw patch/source text 到生命周期记录。

## 状态转换（显式、无跳级）

| 当前状态 | 唯一允许的下一步 | 约束 |
|---|---|---|
| `CREATED` | `READY` / `UNAVAILABLE` / `CANCELLED` | 直接拒绝 `ACTIVE`/`COMPLETED`；早期不可用/取消不声称执行开始 |
| `READY` | `ACTIVE` / `UNAVAILABLE` / `CANCELLED` | 已确认准备，不自动启动AI或外部任务 |
| `ACTIVE` | `COMPLETED` / `PARTIAL` / `UNAVAILABLE` / `FAILED` / `CANCELLED` | 均为调用方声明的本地状态，不是外部执行鉴权 |
| 任一终态 | **无** | 相同、逆序或重启后的终态复活全部拒绝 |

- `partial`来源只有显式 `acknowledge_partial=True` 才能从 `CREATED→READY`；它既不能让run也不能让handoff达成`COMPLETED`。`COMPLETED`强制携带**调用方声明的64位SHA256结果指针**，并非验证了AI输出；其他终态必须有稳定大写 `reason_code`，`PARTIAL`可附声明的结果摘要。
- 创建Handoff要求父Run为`ACTIVE`，且本轮只允许与EC170一致的`code_analysis` task kind；`report_writing` 等任务路由保留给 EC174。父Run不允许带仍在进行的Handoff结算终态；父Run `COMPLETED`须至少一个Handoff且**全部**为`COMPLETED`，不可用/部分完成的任务不得冒充全部成功。
- 全局每个有效事件revision/seq各加一，实例自身revision也加一；每次写状态均须传当前`expected_revision`、完全相同的 `context_sha256`及8–64字节安全 `operation_key`。重复键即使参数相同也返回`OPERATION_REPLAY`而**不重复执行**；同键不同含义返回`OPERATION_CONFLICT`。并发由实例锁与CAS序号阻断，失败不变更已存在事件；限32 handoff、256条事件，不因越界而抛弃历史。
- 事件记录UTC微秒时间、单调序号、上次事件的SHA256和域分隔本事件哈希、原因、可选结果摘要和未验证主体标签。事件hash链可检查误改，却不带MAC/签名，因此**不能鉴权生产者，也不能成为可写入授权凭证**。

## 独立API调用示意

```python
from handoff_lifecycle import Lifecycle, declared_actor

# prepared 是已获得的完整 EC170 多来源构造结果（见上一轮文档）。
session = Lifecycle.create(prepared, "run-create-0001",
                           actor_claim=declared_actor("human", "operator"))
snapshot = session.snapshot()
context_digest = snapshot["source"]["context_sha256"]

snapshot = session.advance_run("READY", expected_revision=snapshot["revision"],
    context_sha256=context_digest, operation_key="run-ready-0001",
    acknowledge_partial=snapshot["source"]["quality"] == "partial")
snapshot = session.advance_run("ACTIVE", expected_revision=snapshot["revision"],
    context_sha256=context_digest, operation_key="run-active-0001")
snapshot = session.create_handoff(expected_revision=snapshot["revision"],
    context_sha256=context_digest, operation_key="handoff-create-0001")
# 此时才有真正生成的 HandoffId。不要推断 AI 已被调用。
```

调用者可继续用`advance_handoff(handoff_id, "READY"/"ACTIVE"/终态, ..., expected_revision=..., context_sha256=..., operation_key=...)`推进，具体API见源码和聚焦用例。状态API不执行外部业务，也不鉴权“COMPLETED”的内容；未来EC173–175必须绑定实际staged文件与输出再审核，绝不能跳过。

CLI示意（从`ces/`根执行）：

```bash
python construction/handoff_lifecycle.py --preview /path/to/ec170-result.json
python construction/handoff_lifecycle.py --create-run /path/to/ec170-result.json --operation-key run-create-0001
python construction/handoff_lifecycle.py --inspect-checkpoint /path/to/checkpoint.json
```

`--preview`返回`run_id:null`；`--create-run`**只创建该Python进程内的会话**并把JSON checkpoint送到stdout，`persisted:false`，不是安装了可恢复后台任务。独立 CLI 暂无对不可信JSON checkpoint执行`advance`的选项，因为没有持久化信任根。`--inspect-checkpoint`仅严格复算事件、投影、时间、序号与SHA链：即便自洽，仍返回 `unavailable/5 / RECOVERY_NOT_ATTESTED`，不返回可被误用为已创建的运行ID、不恢复Live对象，也不宣告旧任务成功。重新开始只能明确创建一个**新的Run**，不能复活旧终态。EC172才规划独立授权的安全暂存与恢复信任边界。

## 拒绝行为、上限及留待统一验收

对非法来源/主体、自相矛盾的Mode/上下文hash、重复大小写JSON键、BOM/非有限常量、错误revision、旧operation key、跳级/终态复活、未闭合handoff、超量事件、回拨时钟等，返回显式失败并保持live会话不变。来源输入最多4MiB，checkpoint最多256KiB，不接纳顶层未知checkpoint字段；读取文件只接受当前路径的常规文件，禁止符号链接输入叶节点。事件操作键仅是去重标签，**不是访问令牌**。

EC171的离线案例依赖**合成的**EC170 WorkingTree/DeliveredTarget/ProposedPR上下文，不代表真实外部Actor/AI回执。PowerShell7、原15套Smoke、真GH/GL/外部AI接入、Windows/macOS/Linux路径/Git、E63–E66性能及端到端用户联验继续`NOT_RUN`；B-001 原V3.10/ROUNDS来源缺口仍 OPEN。最终集中人工验收请参照[`../construction/FINAL_ACCEPTANCE.md`](../construction/FINAL_ACCEPTANCE.md)。
