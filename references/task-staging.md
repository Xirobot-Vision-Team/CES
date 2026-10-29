# EC172 — CES 私有任务暂存（V4.82 / R172）

**实现**：[`construction/task_staging.py`](../construction/task_staging.py) · **契约**：[`task-staging.v1.json`](task-staging.v1.json) · **本轮记录**：[`EC-172.md`](../EC-172.md)。这是独立的本地 Python 暂存层，不改 PowerShell 主路由，不处理 EC173 的 AI 输入包和 `InputPath`，不发送 AI 请求，不写业务仓、Git 或远程 Provider。

## 先有真实任务、再有不可覆盖的暂存

- **明确授权、私有父边界**：用户先自行建立 *不在被分析业务仓内* 的空 CES 专属目录，且该目录和其**直接父目录**均由当前 POSIX UID 所有、`0700`；路径必须是规范绝对路径，全部目录分量以 `O_DIRECTORY|O_NOFOLLOW` 逐级打开；需同时指定业务仓根，拒绝二者互相嵌套或物理 inode 根别名。存储初始化须 `--approve-init`，每次真正新暂存须再次 `--approve-stage`；EC170的内容披露许可、EC171的actor声明不授予此授权。
- **稳定父身份**：初始化生成32字节本地私钥和128位随机 store ID，记录stage根与业务仓根的`dev/ino`、当前 UID 及路径 SHA。返回 `parent_pin`；所有后续操作强制重传，且逐次重新打开/校对目录身份。初始化只能针对空私有目录，**不会在业务仓下创建目录**。根/直接父权限不足、祖先symlink、Windows reparse/无法实现OS防护、同名/旧布局一律 fail closed，不自行退化成不安全的普通文件IO。
- **真正提交后才宣称staged ID**：`start`先校验完整EC170 context及source identity/source mode，再在 `flock` 排他保护下查重；首次真实创建才调用 EC171 `Lifecycle.create` 生成192位随机 RunId，校验revision=1、来源、操作键、TTL，再以私有独占临时文件写入无原始源码的EC171快照及最小绑定元数据。使用文件`fsync`、同目录硬链接 `link-if-absent` **原子无覆盖**公开最终记录，然后目录`fsync`、删除临时链和再次`fsync`。错误时尝试安全清理未发布临时文件，**不会回传新的已暂存RunId**；不保证任意异常/断电后的完成语义。
- **局部本地完整性**：单记录包括source context/identity摘要、source mode/task、EC171 global revision/event末哈希、首个创建操作键、创建及过期UTC、store和parent pin、EC171可完整重放快照；有独立 HMAC-SHA256 和定域checkpoint散列，读取时要求文件常规、owner-private、链接数1、严格规范JSON、MAC有效、hash-chain/投影可重放。私钥不是人、Provider、外部执行、代码来源或远端仓的身份认证材料，同UID进程能接触私钥，系统/磁盘快照回滚也不能靠此HMAC识别。
- **重入只读且幂等**：同`operation_key`＋EC170 `source`／mode／identity／revision／TTL／actor标签，且未过期的 `start`返回原有 RunId，**不额外mint一个已暂存RunId**；`reenter`再要求完全相同的parent pin、明确run ID、创建操作键、来源及revision。TTL 60～86400秒（默认900），重试不延长；过期返回 `STAGING_EXPIRED_NO_REENTRY/unavailable`，**保留原记录且不复用原ID**。总上限128份不可覆盖阶段记录，容量用尽后需人工重新规划私有目录与留存策略；本轮不做静默GC。
- **检查与断点限制**：`inspect`只返回数量/过期数量，不泄漏源码或整份快照。检测到未清理的 `.pending-*`、未知文件、坏MAC、过大/重复记录、异常硬链接、越界或文件系统不能确认的竞态，都返回`unavailable`。有可信本地存储不等于可以由原EC171 JSON重造可变 `Lifecycle`；**本轮只支持可核对的只读再进入，并不提供运行中任务/上次AI成功的恢复**。事故后必须现场人工确认和清理，不能从未发布的临时文件推断成功。

## 命令与API

在受支持且拥有可用私有目录的POSIX环境，假设操作人员已在业务仓**外**创建一个私有父目录和一个空stage子目录（路径须是真实规范目录、非symlink）：

```bash
# Example only: choose absolute canonical paths suitable for your host.
mkdir -m 700 /home/operator/ces-private
mkdir -m 700 /home/operator/ces-private/task-staging
python construction/task_staging.py --init \
  --root /home/operator/ces-private/task-staging \
  --business-repo-root /home/operator/project --approve-init

# Save the returned parent_pin. --start JSON is a complete EC170 result;
# it must be a previously prepared, source-explicit result, not a raw patch.
python construction/task_staging.py --start /safe/ec170-result.json \
  --root /home/operator/ces-private/task-staging \
  --business-repo-root /home/operator/project \
  --operation-key create-run-0001 --parent-pin PIN_FROM_INIT \
  --approve-stage --ttl-seconds 900

# Retry --start with exactly the same parameters to get the original ID.
# Or use strictly read-only reentry; neither method launches AI.
python construction/task_staging.py --reenter /safe/ec170-result.json \
  --root /home/operator/ces-private/task-staging \
  --business-repo-root /home/operator/project \
  --operation-key create-run-0001 --parent-pin PIN_FROM_INIT \
  --run-id RUN_ID_FROM_STAGE --expected-revision 1
```

Python直接接口：

```python
from task_staging import TaskStaging

store = TaskStaging("/home/operator/ces-private/task-staging", "/home/operator/project")
pin = store.initialize(approve_init=True)["parent_pin"]  # once, on empty root
result = store.start(prepared, operation_key="create-run-0001",
                     expected_parent_pin=pin, authorize_stage=True,
                     expected_revision=1, ttl_seconds=900)
# A pre-existing EC171 Lifecycle object can alternatively be staged once:
# store.stage_live(session, expected_parent_pin=pin, authorize_stage=True,
#     context_sha256=source_sha, expected_revision=revision,
#     operation_key=initial_run_creation_key, ttl_seconds=900)
# No method turns a stage receipt back into a mutable or externally executed run.
```

`success/0`仅表示**本地暂存创建或只读核对**完成；`invalid_input/4`表示调用方授权或绑定错误，`unavailable/5`表示环境、文件、过期或可信度不足。出于安全考虑返回中**没有**可用的`InputPath`、可运行的任务恢复对象、外部AI结果或写业务仓许可；内存`RunId/HandoffId`只有明确创建后才存在，暂存RunId只在实际提交成功的响应中出现。见[EC171状态模型](handoff-lifecycle.md)。

## 终局用户协助验收（仍未运行）

本轮离线聚焦用例只模拟本地POSIX测试目录、线程竞争、symlink、HMAC篡改、TTL、模拟失败，不是 macOS/Windows/Linux 三平台级审计，也不是断电故障注入。待最终统一核验：Windows reparse/ACL与原生路由（本轮故意未支持）、macOS与Linux openat/硬链接/权限、父目录交换/跨进程竞争/网络文件系统/实际断电、私钥备份/回滚、防滥用磁盘容量、真实EC170 → EC171 → staged → EC173/EC174 AI → 验证/保存的合法端到端边界。原15套PowerShell Smoke、E63–E66资源、远端Provider和最终人工验收仍 `NOT_RUN`；B-001旧V3.10原规格缺口仍 `OPEN`。
