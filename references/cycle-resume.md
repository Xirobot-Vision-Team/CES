# EC236 — Cycle Resume 输入/断点复核（只读恢复检查）

**施工版本 V5.46/R236**。入口：[`CycleResumeHandler`](../construction/cycle_resume.py)；
机器返回契约：[`cycle-resume-check.v1.schema.json`](cycle-resume-check.v1.schema.json)。
`restore()` 是**读取现有安全暂停状态 + 重新校验输入的一次检查**，不是执行中断的工作，
也不是 `CodeSave` 授权、后台调度或原生 `Cycle -Mode Resume`。

## 业务功能与决策语义

1. **基线必须真实存在。** 按原 EC231 `run_v1_...` 从已有 POSIX 0700
   私有目录加载不变的 `.cycle.json`；重新从磁盘打开 EC235 的
   `.permission-pause.v1.json`，独立验证精确 0600/单硬链接、严格字段/
   域分离自哈希、Run/Step/ActionSet/Input/Graph/Proposal/Actor 声明绑定，
   EC233 当前实际 CodeSave:Snapshot handler/入口的文件 SHA，以及原始全部
   `NOT_STARTED`。第二次读取暂停和源记录来检测可观察的中途改动。
2. **必须重新提交真实输入 bytes + source_ref。** 不接受只有 SHA 的
   伪“重新扫描”、缺失快照、超过 1 MiB 的快照、从原侧记录直接复制的
   `input_sha256` 代替内容。计算真正新鲜的 SHA-256 和字节长度，并按
   **精确字节、长度及区分大小写的 source_ref** 比对原始 EC231。
3. **若字节或者 source_ref 变化**：返回 `REPREPARE_REQUIRED` 和
   `CREATE_FRESH_RUN_AND_REPREPARE`。原 RunId 和暂停记录**都不修改**；
   不重用旧的建议或状态。新准备必须是另一项显式的、经过正确来源确认的
   EC231/CodePrepare 工作流，本模块不自动创建新运行或搬移旧批准。
4. **若全部一致**：返回 `PAUSED_PERMISSION_REQUIRED`，如实展示原先
   `NOT_PROVIDED` 或 `DECLINED`，以及精确全部未执行 Step ID/状态。
   `next_action=REVALIDATE_INDEPENDENT_PERMISSION_OUTSIDE_RESUME`，
   **只是恢复暂停状态视图**；原 sidecar 中的 `DENY` 仍然是 `DENY`。
5. **若文件缺失、权限不私有、内容损坏、pin 变化、来源/handler 漂移、
   重新加载失败或输入不可确认**：返回 `UNKNOWN_BLOCKED`，不能把
   “没有暂停文件”解释为自由可执行。必须人工审查历史记录。

三个状态一律：`can_resume=false`、`can_dispatch=false`、
`steps_executed=false`、`write_authorized=false`、
`independent_approval_verified=false`。**状态恢复 ≠ 执行恢复**。
权限必须由原业务执行器独立进行 `ApprovePersist` 检查；EC236 既不调用
执行器也不消费批准凭据，更不会把用户口头许可、签名字段、哈希一致
或暂停状态解读为通过原业务权限门。

## 可运行接口

```python
from construction.cycle_resume import CycleResumeHandler

checker = CycleResumeHandler('/absolute/0700/private-cycle-store')
result = checker.restore(
    'run_v1_<实际48个小写hex>',
    snapshot_bytes=b'<重新获取的真实输入内容>',
    source_ref='local:my-current-source',
    # 可选：由独立保管位置保存的精确历史散列（一致性 pin，非授权）
    # expected_record_sha256='<64个小写hex>',
    # expected_action_set_sha256='<64个小写hex>',
    # expected_input_sha256='<64个小写hex>',
    # expected_pause_sha256='<64个小写hex>',
)
print(result['status'], result['next_action'])
```

在命令行，每次 `restore` 必须重新提供当前文件内容，不能只传快照摘要：

```bash
python construction/cycle_resume.py restore \
  --store /absolute/owner-private/cycle-store \
  --run-id run_v1_<48hex> \
  --snapshot-file /absolute/path/to/fresh-snapshot.bin \
  --source-ref local:my-current-source \
  --expected-record-sha256 <64hex> \
  --expected-pause-sha256 <64hex>
```

若不持有独立 pin 可省略可选选项；但无法因此获得来源认证。
`--snapshot-file` 必须绝对路径、是非 symlink 的普通文件；采用有界
`O_NOFOLLOW` 读取和读前/读后 inode/size/mtime/ctime 比对，且**在
整个 EC236 存档与 handler 复查后再读一次**。检测到文件变化直接
`UNKNOWN_BLOCKED`。原文数据不写入暂停、结果或 CLI 标准输出，
只显示摘要、状态和未执行 Step IDs。

退出码：`2` = 安全读取了**仍被拒绝放行**的旧暂停；`3` = 检测到输入变更，
**必须重准备**；`5` = 来源/文件/参数/历史不可靠，需要人工审查。
没有任何一个退出码代表 Resume 执行成功或业务处理完成。

## 精确边界与未验收项

- EC231 原输入和 actor/source_ref 本身来自未认证的调用者；新鲜
  snapshot bytes 必须由操作者单独绑定到**实际**需要检查的仓库/数据源。
  用旧 bytes 重新提交会得到相同摘要，但绝不证明现场仓库未变。
- `record_sha256`、`pause_sha256` 和可选 pin 是**无签名的内容一致性
  摘要**；攻击者若能同时改写它们或同 UID 替换记录，不能防重放。
  目录祖先改变、文件系统竞态、掉电、NFS、多主机和权限服务器没有
  在本轮获得可信保证。更改源码 SHA 会使检查拒绝，不会自动重试。
- 本功能是新独立 Python API/CLI；没有修改原 PowerShell V4.60/R150
  的 Action 路由、CodeSave 写逻辑，或创造原生 `Cycle -Mode Resume`。
  EC234 的进程内 Next 配额不自动覆盖 EC236 调用、两次源重读或
  整个系统 I/O。EC237 Summary、EC238 Handoff、EC239 scheduler、
  EC240 并行冲突以及后续真实运行执行，仍不属于本轮。
- `test_cycle_resume.py` 中的聚焦本地开发用例检查真实一次性 EC231/EC235
  文件、边界拒绝和 CLI；它们不代表 PowerShell7、原15套 Smoke、
  真实企业 actor/权限/来源验证、Windows/macOS、NFS/crash、多机或
  E63–E66 性能验收。这些集中放入最终用户辅助验收（当前 NOT_RUN）。
  原冻结 V3.10/ROUNDS 上游证据缺口 B001 保持 OPEN。
