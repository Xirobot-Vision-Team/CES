# EC199 — ReportRender（本地离线内部渲染、受控保存、幂等重试与版本索引）

**构建：V5.09 / R199 / EC199；内置 PowerShell CLI 仍 V4.60/R150。**

入口：[`../construction/report_render.py`](../construction/report_render.py)。
输出契约：[`report-render-result.v1.schema.json`](report-render-result.v1.schema.json)。
独立权限声明契约：[`report-render-policy.v1.schema.json`](report-render-policy.v1.schema.json)。
开发期用例：[`../construction/test_report_render.py`](../construction/test_report_render.py)。

## 1. 实际可调用行为

`ReportRender.render()` 要求原始、**完整的 EC198 `handoff_json` 规范字节**、
原 EC197 `prepare_json`、EC196 `metrics_json`、EC195 `scope_json`、
EC197 `release_policy`、EC198 `review_policy` 和新增的独立 `render_policy`。
每次实际调用 EC198 `.from_json()`，由 EC198 向下重放 EC197→EC196→EC195
（如需要还须提供 EC194 `people_subject_witnesses`）。不认可自行拼装的 `ai_input`、
匿名缩略稿、离线自证哈希或篡改后的 `handoff_draft`。

本轮**真正生成**一份完整 UTF-8 Markdown 内部报告，包含 UTC 周期、全仓范围、
每个仓的 report/source/people 钉子、Source Mode 与 ProposedPR 提醒、
完整四渠道 Git/AI/CI/Unknown 声明、每项 `cesrc1:` 脱敏引用、CI 不可信状态、
逐渠道覆盖原因及逐仓/全局缺口。输出同时生成按仓/渠道分开的机器可读
`sections_manifest`、`slot_members`、`rendered_sha256`、`cesrr1:` 报告引用、
`cesrslot1:` 稳定报告槽和内容 `binding_sha256`。

**没有**开放用户或模型任意拼接叙述入口：固定中立文字 + 已审核可重放的
类型引用组成 Markdown。缺记录≠零活动；`completed_pass_claim`≠ CI 已真实通过；
`ProposedPR`≠已合并/已交付；来源/收据/审批均为调用方声明、未经真实性校验；
不会给员工分数、排名或绩效结论。

`ReportRender.from_json()` 必须携带全部相同原件和各层 policy，重新计算
**全部规范结果**，对比原始规范 JSON 字节，而不只检查 `report_ref` 和 SHA。

## 2. 独立授权边界

新增 `render_policy`（不是 EC197 数据读取/AI release、也不是 EC198
report_writing review 许可）：

- 固定 `schema=ces.report_render_policy.v1`、
  `purpose=periodic_report_internal_render_only`、
  `audience=HUMAN_REPORT_EDITOR_INTERNAL`、`permit_internal_render=true`。
  `permit_local_save` 是**另一个显式 opt-in**；纯渲染可 `false`。
- 精确绑定原 EC198 `draft_ref` / `draft_binding_sha256` /
  `review_policy_binding_sha256`，以及 prepare/ai_input/scope/metrics/period 当前钉子。
  传入稳定 `slot_key`，对同一周期和完整 report_subject 成员集形成报告版本槽。
- 每个原仓均需独立 grant，包含当前仓的 report/source/people pin、
  `permit_internal_render=true`、独立 `render_receipt_sha256`、
  **等于 EC198 已发布脱敏引用全量集合**的 `approved_citation_refs`。
  少仓、跨仓、缺引用、额外引用、重复 SHA/不同阶段重用收据拒绝全份渲染。
- 本地保存要求**顶层与所有仓**同时 `permit_local_save=true`，绝不把
  `render` 的许可隐式升级为 `save`；`report_publish` 不属于任一许可。

`policy_receipt_sha256` 和各仓收据 SHA 只是**声明性、不受信任**的标识，
不是密码学认证签名，不证明真实业务批准/身份合法/隐私同意。
主机、用户与机构仍应使用外部真实审批和授权检查。

## 3. Python 最小调用

在 `ces/construction` 目录执行。以下大写变量由宿主程序/人工授权
**真实提供**，不是本模块生成的审批收据：

```python
from report_render import ReportRender, POLICY_SCHEMA, PURPOSE, AUDIENCE

h = handoff_result['subject']
pins = h['source_pins']
policy = {
    'schema': POLICY_SCHEMA,
    'purpose': PURPOSE,
    'audience': AUDIENCE,
    'permit_internal_render': True,
    'permit_local_save': False,
    'slot_key': 'periodic-internal',
    'draft_ref': h['draft_ref'],
    'draft_binding_sha256': h['binding_sha256'],
    'review_policy_binding_sha256': h['review_policy_binding_sha256'],
    'prepare_binding_sha256': pins['prepare_binding_sha256'],
    'ai_input_sha256': pins['ai_input_sha256'],
    'scope_binding_sha256': pins['scope_binding_sha256'],
    'metrics_binding_sha256': pins['metrics_binding_sha256'],
    'period_id': pins['period_id'],
    'policy_receipt_sha256': OPERATOR_RENDER_POLICY_RECEIPT_SHA256,
    'repository_grants': [
        {
            'repository_ref': repo['repository_ref'],
            'report_subject_ref': repo['report_subject_ref'],
            'source_binding_sha256': repo['source_binding_sha256'],
            'people_binding_sha256': repo['people_binding_sha256'],
            'permit_internal_render': True,
            'permit_local_save': False,
            'render_receipt_sha256': OPERATOR_RENDER_RECEIPTS[repo['repository_ref']],
            'approved_citation_refs': [
                c['citation_ref']
                for channel in repo['evidence_slots']
                for c in channel['citations']
            ],
        }
        for repo in h['handoff_draft']['outline']['repository_sections']
    ],
}
inputs = dict(
    handoff_json=handoff_result['canonical_json'],
    prepare_json=prepare_result['canonical_json'],
    scope_json=scope_result['canonical_json'],
    metrics_json=metrics_result['canonical_json'],
    release_policy=ec197_release_policy,
    review_policy=ec198_review_policy,
    render_policy=policy,
    people_subject_witnesses=original_ec194_witnesses_or_none,
)
engine = ReportRender()
rendered = engine.render(**inputs)
if rendered['status'] == 'partial':
    markdown = rendered['subject']['rendered_markdown']  # 仅供本地内部审核
    replayed = engine.from_json(
        serialized=rendered['canonical_json'], **inputs
    )
```

## 4. 保存、重试与版本索引（EC199）

实际持久化通过 `ReportRender.save()`，**只面向 POSIX** 环境：
调用方须先创建一块独立于业务 Git 仓库的、已存在且 owner-only (`0700`)
的可信绝对路径 `storage_root`，路径的任何父组件不得是符号链接，且任一祖先目录不得存在 `.git`、`.hg` 或 `.svn` 仓库标记；防止误写业务源码树。
代码使用 descriptor-relative `O_NOFOLLOW`、私有 `.ces-report-render-v1`
目录、`0600` 文件、整个索引上的 POSIX `flock` 合作写入锁，
对报告 JSON 与 Markdown 文件做独占 `O_EXCL` 不可变创建，
对槽索引使用 fsync + 同目录 temp 文件 `os.replace` 原子提交。

```python
# 真实人工批准本地保存后，创建一份新的 policy:
policy['permit_local_save'] = True
for grant in policy['repository_grants']:
    grant['permit_local_save'] = True
inputs['render_policy'] = policy

result = engine.save(
    storage_root=OWNER_PRIVATE_DEDICATED_REPORT_DIRECTORY,
    expected_previous_version=0,  # 首次写入该 slot；版本2时设为 1
    operation_id='report-save-operation-0001',  # 稳定、仅该请求使用
    **inputs,
)
# result['storage'] -> version, index_binding_sha256, entry_sha256,
# report_ref, state=SAVED_NEW_VERSION | REPLAY_ALREADY_SAVED |
# IDENTICAL_RENDER_EXISTS。永远 publication_state=NOT_PUBLISHED。
```

**语义**：

1. 同一 `operation_id` + 完全相同的报告重试，返回原 version（不会重复增加）；
   相同 token 但不同内容拒绝 `SAVE_OPERATION_CONFLICT`。
2. 不同 token 对**相同报告**不会增加重复版本（返回
   `IDENTICAL_RENDER_EXISTS`）。新内容必须显式提供与旧索引一致的
   `expected_previous_version`，否则 `STALE_INDEX_EXPECTED_VERSION_CONFLICT`，
   绝不静默覆盖旧版本。
3. 每槽最多 **64** 个不可变报告版本；`index-<slot sha>.json` 记录
   单调编号、`operation_id`、内容 SHA、前版 entry SHA 链以及索引 SHA。
   原始 `report-<report sha>.json` / `.md` 文件不可覆盖；每次写入前
   重读并校验现有索引链与被索引内容完整性。写报告中断可能留下
   **未入索引的不可变孤儿文件**；原操作重试时复用同内容再完成索引，
   不会自动删除这些孤儿、也不会自动发布。
4. 存储输出只返回 SHA/状态/版本，不返回宿主绝对路径。
   `operation_id` 和 `slot_key` 限制为短 ASCII token，路径不进入报告正文。
5. macOS/Linux 的具体文件系统原子性、强制锁/恶意并发、主机崩溃持久性、
   NFS/共享文件系统、恶意持有 owner 权限的人、跨 OS 行为**未实测**；
   `flock` 仅保护**合作使用本协议**的写入者，哈希不是存储真伪认证。
   不要把受控本地存储当作外部可信保管库。
6. Windows 可使用无文件操作的 `render/from_json`，但安全本地保存被
   明确标记 `unavailable/5`（POSIX 依赖未满足），绝不退化为不安全覆盖。

## 5. 拒绝与边界

纯渲染成功、回放成功与本地保存成功均为 `partial/2`（证据和审批声明
仍未验证）；错误数据为 `invalid_input/4`，缺独立授权、过期引用、
存储不安全或版本冲突为 `unavailable/5`。所有错误原因只返回常量代码，
不回显证据/个人信息/路径。拒绝时 `subject/canonical_json/storage=null`。

保存操作实际会**写入宿主明确选择的专用私有 CES 目录**（这是本轮新增
的真实代码能力），但不会读改任何业务仓、提交 Git、更新 Issue/知识库，
不会调用 AI Provider、EC171/EC174、原生 PowerShell，也不会做
**ReportPublish**。EC200 的报告浏览/更正差异还没有实施。

待用户最后集中辅助验收：实际来源和审批/撤销可信性、真实 Git/CI/Provider、
PowerShell7/旧15 Smoke、Windows/macOS/Linux、文件系统与恶意并发、E63–E66、
时区数据库及原历史 B-001；开发期人工构造的合成单元测试不是这些外部证明。
