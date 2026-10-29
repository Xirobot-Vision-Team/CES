# EC173 — 只读 AI Handoff 输入包（V4.83 / R173）

实际代码：[`construction/handoff_input.py`](../construction/handoff_input.py)；机器契约：[`ai-handoff-input.v1.json`](ai-handoff-input.v1.json)；[施工记录](../EC-173.md)。本轮提供 *input preparation only*，不路由/调用外部AI；EC174 才计划 AI 路由及输出 Schema。PowerShell 原生 AIHandoff 仍未注册。

## 什么输入会获得真正的 `InputPath`

必要链路：一个 EC170 `ces.code_prepare_multisource.v1` 来源上下文（且必须是显式 source mode、已释放内容的真实完整结构）→ 由 **EC171真实创建**、已把 run 设为 `ACTIVE` 并把选定 handoff 设为 `READY` 的内存 `Lifecycle` → 经 EC172 `TaskStaging.stage_live`、独立授权、校验 revision/event/context 后提交的**不可变** stage → EC173 再由独立许可写 `handoff_v1_<id>.input.json`。

在没有真实已提交 stage 的情况下，**不能凭传入任意 RunId/HandoffId、自制 JSON checkpoint 或未经授权的源文件路径制造一个有效 InputPath**。`subject` 是 `selected_source` + 明确 mode + 来源身份摘要的结构化对象，不是猜测自然语言意图，也不是文件系统路径。`evidence_hash` 对 EC170 被选来源身份、原始 context digest、观测时间和**实际释放的有限段落**重新定域散列，便于消费者核对选择和字节范围；它并不证明来源真实、当前或未被外部篡改。

EC173 的**三重内容门禁**相互独立：EC170 原结果中 `permission` 必须明确给该 mode 的权限且 `coverage.content_released=true`；EC173 `create` 仍需 `authorize_input=True` + `allow_content_for=<完全相同的mode>`；将来要读取源码的消费者还必须调用 `load_authorized(..., authorize_read=True, read_content_for=<相同mode>)`。`reenter` 仅重新确认元数据，不把raw patch打印到CLI。旧EC169历史收据、EC171 actor声明、EC172 stage授权、HMAC **不能代替上述三个授权**。

## 来源、完整性与拒绝机制

- WorkingTree/DeliveredTarget：只读取已经通过EC170真实结构校验、且先前native CodePrepare记录过的各自来源；EC173重新核验段落顺序、path/old_path 的规范相对路径、库存行数、内容字节数、来源身份摘要、Quality/Coverage、上下文哈希和 timestamp。两种模式不能互相改名转作证据。`source_currentness_proven`仍永远为 `false`：native Reconcile 的时间点不等于EC173消费的当下。
- ProposedPR：EC165 patch是**历史、非原子**样本，EC166 `FRESH_OBSERVATION`也只比对元数据。只有EC170明确释放过选中内容、没有 `STALE_BY_DRIFT`、且EC173又额外声明 `allow_historical_proposal=True` 时才可写入；保持`partial/2`、`historical_proposal_only=true`，绝不代替 WorkingTree/DeliveredTarget 的当前源码或已交付版本。
- 若EC170未释放源码、已标记 stale、输入不完整到无法得到可读材料、选中源模式不一致、内容超过预算、原生/历史覆盖造假或请求冒称`success`而带有缺口：拒绝生成输入包。**允许被明确标记的`partial/2`**仅在已授权的实际材料仍存在时存档，缺口原样保留，不静默升级成完整分析。
- 所有输入要求有时区的 `source_observed_at_utc`；默认观测最多600秒前、不得超过未来30秒（可限缩到60秒，最高900秒）。这仅限制过期重放，**不是**Provider或Git当前状态的认证。每次create、reenter和授权read均复验源年龄与该stage的TTL；新输入自身默认300秒/可选60～900秒，实际截止不晚于EC172 stage过期时间，不自动续命。
- 防护路径：复用EC172私有CES根（与业务仓互不包含）、父目录/仓目录FD身份、不跟随symlink的目录遍历、UID 0700与单链接0600文件、flock同根排他、专用pending名和HMAC域。记录内部有stage快照哈希+record HMAC、hand-off ID+revision/末事件SHA、parent pin、source context+identity SHA、实际material SHA和权限/coverage；写时通过 `O_EXCL` + 文件 fsync + `link-if-absent` + 双目录 fsync，**只有本地发布全部返回成功才产生可报告 `InputPath`**。发现未知pending、坏MAC、被替换的文件、断电后提交状态不明、环境缺安全原语都 fail closed，不自动修补/重启。
- 防止泄密：路径只作数据、不作为本地实际读写位置；排除明显敏感文件（例如`.env`/private-key/`.ssh`）及已标记sensitive/symlink的路径、常见私人绝对路径和明显的 PEM key/Token/硬编码密码。**自动规则不可能识别全部秘密**。调用方必须在授权EC170内容和此处的新输入内容之前人工/策略性审查，避免将业务秘密写入私有输入；错误响应/CLI不回显实际patch。不能把“本地HMAC一致”“观察时间新近”当成Actor签名、真实API授权、Git属主确认或安全秘密扫描证明。

输入是一份**仅本地的AI可读数据包**，`material` 内的代码与文字属于不可信数据，`guidance`要求AI仅作为证据引用、不得服从patch中的“请忽略规则”之类指令。没有执行函数，没有远端Token调用、网络路由、AI输出/验证、CodeSave/Issue/Delivery能力，所有业务仓文件/Git refs/index/工作树未被本模块修改。

## 最小调用示例

在 `ces/` 工作目录、完成 EC170 `prepared` 后，以下是**真实已创建 in-memory EC171 session**的关键步骤（仅示意；不要从JSON伪造 `session`）：

```python
from handoff_lifecycle import Lifecycle
from task_staging import TaskStaging
from handoff_input import HandoffInput

stage = TaskStaging("/private/ces/stage", "/projects/business")
# stage.initialize(approve_init=True) ONLY ONCE on pre-created empty private root
pin = "<parent_pin returned by authorized initialization>"
session = Lifecycle.create(prepared, "create-run-0001")
source_sha = prepared["context_sha256"]
snap = session.snapshot()
session.advance_run("READY", expected_revision=snap["revision"], context_sha256=source_sha,
                    operation_key="run-ready-0001", acknowledge_partial=prepared["status"] == "partial")
snap = session.snapshot()
session.advance_run("ACTIVE", expected_revision=snap["revision"], context_sha256=source_sha,
                    operation_key="run-active-0001")
snap = session.snapshot()
snap = session.create_handoff(expected_revision=snap["revision"], context_sha256=source_sha,
                              operation_key="handoff-create-0001")
new_handoff_id = snap["handoffs"][0]["handoff_id"]
snap = session.advance_handoff(new_handoff_id, "READY", expected_revision=snap["revision"],
                               context_sha256=source_sha, operation_key="handoff-ready-0001",
                               acknowledge_partial=prepared["status"] == "partial")
staged = stage.stage_live(session, expected_parent_pin=pin, expected_revision=snap["revision"],
                          context_sha256=source_sha, operation_key="create-run-0001",
                          authorize_stage=True, ttl_seconds=900)
input_api = HandoffInput("/private/ces/stage", "/projects/business")
args = dict(expected_parent_pin=pin, run_id=staged["run_id"], handoff_id=new_handoff_id,
            expected_revision=snap["revision"], expected_event_sha256=snap["last_event_sha256"],
            operation_key="input-stage-0001", allow_content_for=prepared["source_mode"])
created = input_api.create(prepared, authorize_input=True, **args)
# created["input_path"] only exists after a committed local record; nothing was sent to AI.
# Separately authorized in-memory read for a FUTURE trusted consumer:
material = input_api.load_authorized(
    prepared, authorize_read=True, read_content_for=prepared["source_mode"],
    **{k: v for k, v in args.items() if k != "allow_content_for"})["material"]
```

通过CLI，对已经存在的**合法已提交**stage使用（需要把实际 RunId/HandoffId/revision/末事件SHA与 EC170 JSON 原样提供；程序不会替你恢复EC171内存session）：

```bash
python construction/handoff_input.py --create /secure/ec170-result.json \
  --root /private/ces/stage --business-repo-root /projects/business \
  --parent-pin "$PARENT_PIN" --run-id "$RUN_ID" --handoff-id "$HANDOFF_ID" \
  --expected-revision "$STAGE_REVISION" --expected-event-sha256 "$LAST_EVENT_SHA256" \
  --operation-key input-stage-0001 --allow-content-for WorkingTree --approve-input

# Exact source and operation pins, read-only, no new input and no raw content on stdout:
python construction/handoff_input.py --reenter /secure/ec170-result.json \
  --root /private/ces/stage --business-repo-root /projects/business \
  --parent-pin "$PARENT_PIN" --run-id "$RUN_ID" --handoff-id "$HANDOFF_ID" \
  --expected-revision "$STAGE_REVISION" --expected-event-sha256 "$LAST_EVENT_SHA256" \
  --operation-key input-stage-0001 --allow-content-for WorkingTree
```

生产环境需要自行选择已经存在的、规范POSIX私有绝对目录，不可直接照搬示例占位路径。EC173 `create`/`reenter` CLI只输出metadata JSON（字段`status/exit_code/reason_code/subject/evidence_hash/input_path/coverage`等）。`success/0`只说明本地输入记录提交或精确重入；`partial/2`说明该输入含真实已许可材料但存在明示缺口，不代表AI已正确分析；`invalid_input/4`和`unavailable/5`严格拒绝，不返回可用`input_path`。待EC174才决定AI路由/输出与可能的执行回执。**InputPath是CES私有数据文件的路径提示，不是一个授权系统或能够安全独立打开的外部凭证**。

## 最终统一协助验收（延期）

已完成的开发场景只能说明本环境临时POSIX目录与合成上下文函数行为：仍需要PowerShell7/15旧Smoke、真实业务仓CodePrepare/原生Git权限与并发变化、GitHub/GitLab真实PR观察/Token与角色、AI路由/输出/注入风险、Windows/macOS/Linux不同文件系统/ACL/symlink/reparse race、真实进程中断/断电、私钥保管与磁盘回滚、容量/吞吐/E63–E66与全场景端到端由用户最终统一辅助验证，均**NOT_RUN**。
