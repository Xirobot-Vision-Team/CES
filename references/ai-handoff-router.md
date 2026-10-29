# EC174 — AI Handoff task_kind 路由与候选输出（V4.84/R174）

运行代码：[`../construction/ai_handoff_router.py`](../construction/ai_handoff_router.py)；[严格机器契约](ai-handoff-router.v1.json)；[EC174施工报告](../EC-174.md)。这是一条**可以执行的独立Python路由/候选校验链**，仍不是原生 PowerShell `AIHandoff`、已登录的外部AI客户端、经过证明的模型结果、FindingSave或CodeValidate。

## 能做什么

`HandoffRouter.route` 需要调用方明确输入 `requested_task_kind`。仅注册 `code_analysis / report_writing / knowledge_update / finding_analysis` 四种kind；**目前只有** `code_analysis -> ces.route.code_analysis.v1` 具备EC173真实输入构造与路由权限链。其余三种任务仅占确定性的路由注册槽位，因尚无相应输入构造器而以 `unavailable/5` 拒绝；未知kind以 `invalid_input/4` 拒绝。**不从subject、代码、patch、README或自然语言猜测kind。**

可复用已实际创建的EC171 ACTIVE run / READY handoff、经EC172签名提交的私有stage及EC173独立授权不可变InputPath：每次调用都重复检查私有POSIX根、证据MAC、RunId/HandoffId、父pin、stage revision、last event SHA、task_kind、source_mode、context+identity+material摘要、evidence_hash、content read grant、观察时间与TTL。路由本身还要求新 `authorize_route=True`。未授权、已过期、混源、伪造stage/HMAC、ProposedPR缺历史许可/EC166旧内容发生漂移则拒绝，不向adapter发送任何内容。EC173中可能`partial/2`的缺口仍被保留，绝不升级成完整current source。

`action="schema_only"` 默认不含任何外部adapter、Provider、网络及源码转发；返回元数据+空`findings`，是对**真实输入证据**的可用路由schema检验，`partial/2`+`ROUTE_SCHEMA_ONLY_NO_AI_DISPATCH`，不表示AI已经执行。CLI只开放这种模式，且必须显式 `--approve-route --approve-read`，始终只在stdout输出元数据、不会输出原始代码和patch。

## 可选调用方Adapter边界（**没有内置外部连接**）

只有真正需要发送时，调用者显式传递：`action="dispatch"`, `approve_external_transfer=True`, `transfer_content_for=read_content_for`, `bridge_id="operator_callback_v1"`, 非空`provider_claim`及一个自己实现的 `adapter` 函数。缺一不可；EC170/172/173的既有内容授权、写stage授权或HMAC均**不能替代新的向第三方披露授权**。调用者先审查EC173素材以免泄露未被正则识别的密钥/隐私，再自己负责供应商身份核验、账户/密钥保管、网络隔离、超时、审核、披露许可及输出来源验证。本模块**没有**默认HTTP请求、自动Provider发现、内置API Key、任意shell/插件执行或写入行为。

Adapter契约是 `adapter(request_json_bytes: bytes, provider_claim: str, timeout_hint_seconds: int) -> bytes`。请求schema是`ces.ai_handoff_dispatch.v1`，带`route_id`、task_kind、stage和source `source_binding`、`coverage_assessment`、仅本次来源的 `source_material`（不可信数据）及独立的指令边界。代码内容绝不能被当作system指令或新权限。Adapter来自本地调用方、并**没有经本模块认证**；`provider_claim`和候选的`actor_claim`都是文本自报。Adapter可执行网络/文件的副作用不受本模块控制，`timeout_hint`不是本模块强制的deadline。任何自定义adapter必须自行完成真实连接、安全隔离、退出清理和认证，不能依据一次callback返回宣称外部AI已运行。无可用adapter时`unavailable/5`，不生成虚构AI结果。

调用前按授权读取EC173输入；回调返回后**再次**重新加载、核对来源/stage、权限与当前有效期。若回调过程中超时、出错、输入到期/被改动或返回非法JSON则`unavailable/5`，拒绝返回候选finding；但如果回调已被调用，`effects.source_material_released_to_callback=true`（**已披露，无法回收**），不得伪装为未发生传递。Adapter异常文本可能带源码/token，错误响应不会回显。

## 候选与输出契约

候选输入必须是至多192 KiB严格UTF-8 JSON对象，schema=`ces.ai_handoff_candidate.v1`，**只允许且必须包含**：

- `schema`, `route_id`, `task_kind`, `source_binding`（RunId/HandoffId/revision/event/context/identity/evidence/material SHA/mode全字段精确类型与值匹配）；
- `coverage_assessment`（来源quality/complete/missingRequirements与原始来源**精确**一致，不得声称填补缺口）；
- `summary`（最多4000字符）、`actor_claim`（1–64位ASCII安全标签，永远UNVERIFIED）、`findings`（最多32项）。

每项finding只允许`title/severity/confidence/analysis/suggested_action/anchors`，最多5个至少1个证据锚。每个锚只允许 `segment_index`（0基）、`item_index`（非patch时0基；patch必须null）、`line_number`（**在段落或所选素材内**1基）及`quote`（最多512字符，且与该索引的**完整单行**原文严格相等）。对于git diff patch，不能将段落行数伪称为真实文件行号，输出的`source_path`明确为null；对EC173 untracked或ProposedPR selected patch的数组素材，才从已经选定且校验的那条`path`回显。输出计算自己的域隔离`anchor_sha256`，只证明EC173本地素材位置匹配，**不是**代码语义/活Git/Provider认证。发现丢锚、伪引用、跨来源/序号冲突、重复锚点、过大、非有限数、重复JSON字段、密钥/明显私人路径或新增`status/exit_code`的候选一律拒绝。

输出统一schema=`ces.ai_handoff_route_result.v1`，包含权威`status/exit_code/reason_code/action/route_id/task_kind/source_binding/source/coverage/provider/result/effects/trust_boundary`。状态由**本地代码**负责，模型不能回填：

| 事实 | status / exit_code | 解释 |
|---|---|---|
| 本地真实路由结构和权限核对完成（没调用adapter） | `partial / 2` | 没有AI输出 |
| adapter返回并通过**本地JSON/锚点结构**检查 | `partial / 2` | AI断言仍`UNVERIFIED_AI_ASSERTION_NOT_PERSISTED_FINDING` |
| 未注册kind、缺路由/独立授权或无效请求 | `invalid_input / 4` | 不披露内容 |
| 已注册但无输入构造器、私有stage/输入无效或过期、provider不可用、非法候选/回调错误 | `unavailable / 5`（个别上游参数/权限错误为4） | 不生成成功结果 |
| `success / 0` | **本轮不存在** | 未有可客观证明的AI/代码验证成功 |

绝不执行 EC175 Staged CodeValidate、EC176 Staged CodeSave或EC177 Finding；`result.persisted_finding_created=false`，无模型输出落盘，无业务仓、Git、Issue写入。`candidate_sha256`只是本地候选摘要，不是远端收据。

## Python调用与CLI

导入路径是`construction/`（或将其加入 `PYTHONPATH`），`prepared`/stage/EC173私有输入必须此前**真实创建**：

```python
from ai_handoff_router import HandoffRouter
router = HandoffRouter('/private/ces/store', '/projects/business')
options = dict(
    requested_task_kind='code_analysis',
    expected_parent_pin=pin, run_id=run_id, handoff_id=handoff_id,
    expected_revision=stage_revision, expected_event_sha256=stage_event_sha,
    operation_key=ec173_input_operation_key,
    authorize_route=True, authorize_read=True,
    read_content_for='WorkingTree',
)
local_only = router.route(prepared, **options)  # no adapter, no network, partial/2
# Optional integration only after fresh explicit transfer approval and independent
# provider/egress/secret review. adapter is YOUR implementation, not bundled.
# candidate = router.route(prepared, **options, action='dispatch',
#     approve_external_transfer=True, transfer_content_for='WorkingTree',
#     bridge_id='operator_callback_v1', provider_claim='declared-provider',
#     adapter=your_verified_transport)
```

CLI example (schema-only, private read approval required):

```bash
python construction/ai_handoff_router.py --schema-only /private/prepared.json \
  --root /private/ces/store --business-repo-root /projects/business \
  --parent-pin "$PARENT_PIN" --run-id "$RUN_ID" --handoff-id "$HANDOFF_ID" \
  --expected-revision "$REV" --expected-event-sha256 "$EVENT_SHA" \
  --operation-key "$EC173_INPUT_OPERATION_KEY" --task-kind code_analysis \
  --allow-content-for WorkingTree --approve-route --approve-read
```

无真实stage/输入、缺source grant或未准备好私有POSIX目录将得到拒绝响应；上例是操作模板，不是已有可用对象。另见[合成用例说明](../construction/fixtures/README.md)、[`test_ai_handoff_router.py`](../construction/test_ai_handoff_router.py)；用例中的回调完全是**内存合成字节**，并没有外部模型调用。

## 最终延期验证

开发本地28项聚焦用例的通过只说明模拟EC170/171/172/173状态及本地候选处理路径，不证实Provider、密钥、真实网络、外部AI响应来源、提示注入防御有效性、源文件当前原子快照、任意秘密不泄露或业务Finding语义正确。原生PowerShell7/15 Smoke、真实GH/GL/AI、Windows/macOS/Linux及对抗性FS/断电/并发、外部时间/超时、E63–E66性能和完整人工辅助验收仍`NOT_RUN`，应在全功能完成后统一验证。

**EC198 后续边界说明（2026-10-23）**：新 [`ReportWritingHandoff`](../construction/report_writing_handoff.py) 针对 `report_writing` 创建的是全链精确回放、独立授权的**离线内部审核草稿**，借用本路由登记的 `ces.route.report_writing.v1` 名称，但不建立 EC173 InputPath、EC171 Run/HandoffId，也不修改本模块 `TASK_ROUTES['report_writing'].ec173_input_supported=False`，不能视为本路由可 dispatch 或已有外部 AI Provider。完整契约另见[EC198 指南](report-writing-handoff.md)。
