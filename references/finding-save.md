> **EC179兼容更新（V4.89/R179）：** 下文是EC178写入时的历史指南；现已真实实现单独的 [`FindingShow`](finding-show.md) Python只读查询（非原生CLI）。未来新 `FindingSaver.save()` 写出 [`batch.v2`](finding-save-batch.v2.schema.json) 的已签 HMAC `path_index`，旧 `batch.v1` 仍按原型读回/重放且**不推算路径索引、不迁移**。凡以下文字称“EC179下一轮/未实现”的只表示**当时 EC178 版本的历史边界**；现行权威为EC179最新指南。

# EC178 FindingSave — CES 私有 Finding 声明批次保存指南

> **实现身份：V4.88 / R178 / EC178。** 本组件是 `construction/finding_save.py` 的独立 Python API；**不是** PowerShell `ces.ps1 -Action FindingSave` 原生路由，也不是 EC179 的 FindingShow。该原生路由当前仍 `NOT_IMPLEMENTED`。

## 实际支持的能力和语义

`FindingSaver` 将本轮获得明确逐项授权的 EC177 `Finding` **声明**写入预先由操作者建立的、与业务仓/EC172 私有 stage/可选 EC176 CodeSave 目录完全分离的 CES 私有目录。写入的是最小化、结构化、不可覆盖的 finding 元数据记录；即使成功落盘，响应也必须是 `partial/2`，绝非语义上已证实的缺陷、实际 CI PASS、测试记录、当前远端 Git 事实、合规审计或真人鉴权证明。

### 1. 创建并独立授权目标目录

调用方先在独立、可信的 **POSIX 本地文件系统**上，由当前用户创建一个存在且空的目录，连同直接父目录使用 `0700`。所有绝对路径组件必须经过无符号链接跟随的打开/身份复核；任何相同、嵌套或目录身份重叠的 stage、业务根、Finding 根与可选 CodeSave 根都拒绝。文件和私钥存储为仅属主 `0600`。在缺少 `dir_fd`、`O_NOFOLLOW`、`flock`、硬链接原子发布等预期原语的平台上直接拒绝，**不得降级**成普通路径写。

下面代码中的 `stage_root`、`repo_root`、`store_root` 是由操作者自己选择并隔离的绝对路径，密钥不能放进日志或 CLI 参数：

```python
# 在 CES 工程根运行本段；EC178 Python 模块采用 construction/ 下平级导入。
import sys
sys.path.insert(0, '/absolute/path/to/ces/construction')  # 按实际工程目录修改
from finding_save import FindingSaver

saver = FindingSaver(
    stage_root, repo_root, store_root,
    codesave_root=None,            # 仅在真正使用 EC176 HMAC saved_link 时配置
)
init = saver.initialize(approve_init=True)  # 初始化只允许空的独立私有根
assert init['status'] == 'success'
store_pin = init['save_store_pin']  # 保存并复用；绝不从未经核验的旧 Finding JSON 继承
```

若已将 CES `construction/` 加入 Python 模块搜索路径（例如从该目录运行），可直接使用 `from finding_save import FindingSaver`。管理 CLI 只支持 `--init` 与 `--inspect`（均有独立授权参数）；**没有**可在命令行直接发送源码、签字密钥或保存 finding 的管理命令。

### 2. 先取得真实 EC177 投影，仅将身份用于选择

操作者必须先经 EC170 单一明确来源、EC171 真实 Run/Handoff、EC172 密封私有 stage、EC173 InputPath、EC174 路由候选、EC175 独立复核，调用 **真正** `FindingProjector.project()`，得到最近一次合法的 `partial/2` 投影。其正面 Finding 供人工**选择 ID**，但这个投影或 `projection_sha256` **都不是写入授权**。

`projection_kwargs` 必须是能重新调用 `FindingProjector.project(prepared, route_result, validation_result, **projection_kwargs)` 的 **完整原始参数集**，须包含新的 `finding_operation_key`、`authorize_project=True`、`authorize_read=True`、`project_content_for` 与本次 save 来源严格一致，并关闭全部原文披露。若要使用原 EC175 人工 HMAC 审核，还必须提供真实的 `manual_review` 声明、`trusted_verifier_key`、独立审阅许可和源 pin；若要使用 EC176 保存关联，必须另行授予 EC176 私有库读取/关联权限与真实 store pin。旧 receipt、旧哈希或复制的 JSON 不能充当 HMAC 证明。

调用保存时要重新提供原始 `prepared`、`route_result`、`validation_result` 的完整对象，以便 EC178 **前后各重新投影一次**：每次 EC177 又独立调用 EC175 两轮验证原 source/stage/candidate/完整行锚与可能的 HMAC reviewer 声明。中间漂移全量拒绝；第二次是在 Finding 库排它锁内执行。

### 3. 提交整批逐项授权的 Finding ID

```python
# prepared / route_result / validation_result / projection_kwargs 均来自上述真实链。
# preview 是同样参数获得的当前 EC177 有效只读投影。
approved_ids = [f['finding_id'] for f in preview['findings'] if approve_each(f)]

result = saver.save(
    prepared, route_result, validation_result,
    expected_finding_store_pin=store_pin,
    finding_save_operation_key='ec178-independent-save-operation-001',
    authorized_finding_ids=approved_ids,  # 逐条新批准，不能仅使用“全选”默认授权
    authorize_save=True,
    authorize_source_read=True,
    save_content_for='WorkingTree',       # 也可指定严格同源的 DeliveredTarget/ProposedPR
    projection_kwargs=projection_kwargs,
    operator_label='operator-declaration', # 只是声明，不验证操作者身份
    expected_projection_sha256=preview['projection_sha256'],  # 可选的内容相等检查，不是授权
    ttl_seconds=300,
)
assert result['status'] == 'partial' and result['exit_code'] == 2
assert result['effects']['finding_declarations_persisted'] is True
```

示例里的 `approve_each` 必须是业务侧真实的逐条人工选择过程，而非本项目自带函数。`finding_save_operation_key` 是独立的幂等标识，**不能**与 EC173 Input、EC175 Validate、EC177 Project、可选 EC176 CodeSave 复用；保存集合必须由同一来源的当前 Finding ID 组成，最多 32 条。`authorized_finding_ids` 既不接受一个模糊 scope，也不接受未知/重复/跨来源 ID；空选择是拒绝而非成功。

**默认仅可保存 `REVIEWED`**，含义仅是 EC175 中真实本地 HMAC key-holder 的 `confirm` 声明，并不代表缺陷为真。如确有保留未签/拒绝/悬而未决的核查日志的需要，必须**同时**设置 `allow_non_reviewed=True` 与 `acknowledge_non_reviewed=True`。它们会原样以 `UNVERIFIED / REJECTED / INCONCLUSIVE` 的不确定性被保存，永远不升级为 `ACTUALLY_TESTED`。部分覆盖额外需要 `acknowledge_partial_coverage=True`；历史 `ProposedPR` 需要 EC177 投影自身的历史许可，**本次保存再另行**设置 `approve_historical_proposal_save=True`。

### 4. 只读汇总与下一轮边界

```python
summary = saver.inspect(expected_finding_store_pin=store_pin, authorize_inspect=True)
# 仅返回批次数、Finding 声明数、已过期批次数、固定容量；不披露详细 Finding
```

`inspect` 是只读存储管理汇总；按身份/来源/路径/严重度边界的分页查询、权限化显示与正式 `FindingShow` 留给 **EC179**，本轮不实现。`initialize` 的初始化成功 `success/0` 只指**空库已创建**，不是保存成功。`save` 的成功为 `partial/2`；拒绝为 `invalid_input/4` 或 `unavailable/5`。发布硬链接成功后、最后 `fsync` 失败时报告 `UNCERTAIN_MANUAL_REVIEW_REQUIRED`；此时文件可能已经存在，**不能**据此自动重试或宣称没有副作用。

## 实际记录格式、有效期与去重

- [`finding-save-batch.v1.schema.json`](finding-save-batch.v1.schema.json) 是 Draft 2020-12 的严格结构契约；每个不可覆盖 `finding_batch_000001_<operation_hash>.json` 是签 HMAC 的完整**批次**，内部逐条保存 Finding 结构/ID/模型 severity-confidence 声明、复核状态与签字哈希、正向行锚摘要/原文摘要、调用者反证解释摘要及不确定性，而**不保存源代码原文/路径/patch/模型自由文本/复核笔记或签字密钥**。低熵短文本的普通 SHA 摘要仍可能被离线猜测，本库不是形式化脱敏保证；需要更强隐私时须另行设计 keyed 摘要/访问审计。完整来源绑定、授权集合审计摘要、原审查/投影/可选 EC176 链接摘要都参与 HMAC。
- 同一保存操作键 + **相同合法内容和授权**可以只读幂等返回，既不新写也不延期。更改内容/来源/授权/目标 pin 或重放时证明时效变短均拒绝。不同操作试图再次保存已存在的同一精确 Finding ID，即使旧批次已到期也会拒绝。本轮只去重**完全相同身份**，不把相似内容或旧新来源推断为同一缺陷。
- 保存最大 TTL 为 900 秒，最短请求 TTL 60 秒；实际过期时间还受原 EC175 检验收据、EC173 来源时间窗、EC175 审阅 HMAC 时间窗和可选 EC176 链接的**更短期限**约束。过期记录保留作本地审计，不能自动恢复、覆盖或续命。库最多 128 批、512 Finding、单批 256 KiB。
- 发布使用 POSIX 目录 fd、排它 `flock`、新建 `0600` 临时文件、文件 fsync、原子 no-clobber `link`、目录 fsync、清理临时名并再次 fsync；按连续 seq 加哈希链。未知文件名、未完成 `.pending-...`、丢失/损坏历史、硬链接、HMAC 不符或目录/文件身份改变都拒绝，**不自动修复或清理证据**。保留并完整校验所有历史记录；这是本地进程级可靠性设计，不是断电、恶意同 UID、远端存储、审计不可抵赖证明。
- `.finding-key` 是此私有 CES 库的 HMAC 密钥，不是外部认证 CA 或硬件根。被同 UID 读取/复制、复原密钥或物理介质损坏时，本地 HMAC 无法防范同身份伪造，需外部密钥管理和真正的独立身份/环境证据。任何人工/CI/缺陷真实性都不应从 `status=partial`、`REVIEWED` 或 HMAC 成功推断。

## 未做和集中验收清单

本轮**未**添加 PowerShell native FindingSave、EC179 FindingShow、issue/business Git 写入、测试/质量/报告/知识/发布/周期后续动作，也未认证 Provider、reviewer、当前 Git、远端 CI 或实际缺陷。局部合成用例提供开发自检，不是最终业务验收。待最终用户统一辅助：PowerShell7 + 原 15 Smoke、真实源/审阅者/密钥托管/客观测试、跨进程/跨 OS/ACL/恶意同 UID/断电 fsync 边界、资源性能 E63–E66、下游完整链和 V3.10/原 ROUNDS 缺失源 B-001。
