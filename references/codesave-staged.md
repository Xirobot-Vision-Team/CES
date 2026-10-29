# EC176 — Staged CodeSave：只允许独立授权的 CES 私有元数据落盘

**V4.86/R176/EC-176；独立 Python 消费者，不是已接入旧 PowerShell 路由的 `CodeSave -Mode Staged`。** 真实函数为 [`StagedCodeSaver`](../construction/codesave_staged.py) 的 `initialize/save/read_saved/inspect`，机器接口见 [`codesave-staged.v1.json`](codesave-staged.v1.json)。**只存元数据，不存草稿、patch、模型分析文字、人工复核笔记或业务仓文件；并不生成 EC177 Finding。**

## 为什么 EC175 结果不能直接持久化

EC174 `dispatch` 成功也只得到 `partial/2` 的未证明模型候选。EC175 的 `validation_receipt_sha256` 是**无秘钥**摘要，原结果的 `status=partial`、`manual_verified_count` 等字段均可由调用方改写；仅凭其 SHA 或把 `codesave_authorized=false` 改成 true，无法获得保存许可。EC176 在每次实际保存时要求一个独立的 `authorize_save=True`、独立 `authorize_read=True` 与精确的 `save_content_for`，并以新增的 `save_operation_key` 精确指向一个事先初始化并由调用者钉住的 CES 私有目标。保存时不是消耗 EC175 结果声称成功，而是**在内存重新运行原 EC175 源码验证及原签字 HMAC 验证两次**，再对比先前的完整结果（排除随时间变化的时间戳/收据）和调用者预先钉住的旧结果摘要。

为了将权限与误报分开，v1 默认要求 **至少 1 条 finding 且每条都收到另外授权且有效的 HMAC `confirm` 声明**。`reject` / `inconclusive` / 没有签字 / 无 finding 不能保存。签字仅表明“独立配置的本地验证秘钥持有者作了此决定”；不会确认真实审核人身份、真实缺陷、测试/CI PASS、活体 Git 状态或模型身份。只允许保存**该声明的哈希**，绝不代替未来 EC177 的语义 Finding 认证。`ProposedPR` 因历史来源必须额外有 `approve_historical_proposal_metadata_save=True`；缺口不完整的素材需要 `acknowledge_partial_coverage=True`，元数据继续标记不完整。

## 目标与落盘格式

操作者**先自行建立**与业务仓和 EC172 stage 都不重叠的 CES 私有保存根，其**直接父目录和根目录**必须为实际进程用户所有且权限 `0700`。路径必须是无符号链接的绝对规范路径。不提供自动 mkdir、不扫描业务仓、也不隐式选择目标。首次调用 `initialize(approve_init=True)` 时需为空根目录，只会创建独立 `.codesave-key`、`.codesave-lock`、`manifest.json`，将真实目录 dev/ino/uid、路径哈希、EC172 根和业务根身份绑定到 `save_store_pin`；之后由操作者保存该 pin。

`save(...)` 将所有内容先在内存检查，获取独立保存根的目录 `flock`，全量验 HMAC 旧记录，并再次执行 EC175 验证。新记录形如 `save_<SHA256(new operation key)>.json`，包含密封的精确 Run/Handoff/stage/event/source identity 摘要、候选/路由/草稿/人工签字/验证收据摘要、每条 finding SHA、覆盖率完整性标志、时间戳和**全部为 false** 的外部认证/CI/真实代码/Finding 状态；不包含 source path、line quote、草稿文字或 review notes。独立本地 HMAC-SHA256 与记录哈希互补：前者检测没有密钥的意外改动，后者便于复查；二者都不是远端身份认证。

文件经私有根 `dir_fd`、`O_EXCL` 私有临时名、数据 `fsync`、严格 pin 复核和 `os.link(..., follow_symlinks=False)` **无覆盖发布**，最后目录 `fsync`。相同 operation key、相同上下文在未过期时幂等读取原收据，**不延长 TTL**；同 key 不同证据或另一 key 重复保存同候选拒绝；旧文件被篡改、产生额外目录项/硬链接或未完成临时事务时 fail closed。若链接后 durability 无法确定，将报告 `CODESAVE_PUBLISH_DURABILITY_UNCERTAIN` 和 `ces_metadata_commit_state=UNCERTAIN_MANUAL_REVIEW_REQUIRED`，不能自行宣告未写入或成功。

## Python 真实 API 调用顺序

```python
from construction.codesave_staged import StagedCodeSaver  # or add construction/ to sys.path

saver = StagedCodeSaver(stage_root, business_repo_root, save_root)
init = saver.initialize(approve_init=True)  # one-time, PRE-CREATED EMPTY owner-private save_root
save_pin = init["save_store_pin"]

# prepared: EC170 actual authorized response
# route_result: EC174 actual dispatch outcome (never schema_only)
# validated: prior EC175.validate(...) output WITH separately signed complete manual review
# review: the SAME individually signed EC175 manual review, not just the unkeyed receipt
# reviewer_key: secret provisioned independently of model, EC172 key and business repo
saved = saver.save(
    prepared, route_result, validated,
    expected_save_store_pin=save_pin,
    expected_parent_pin=stage_parent_pin, run_id=run_id, handoff_id=handoff_id,
    expected_revision=stage_revision, expected_event_sha256=stage_event_sha256,
    input_operation_key=input_create_key,
    validation_operation_key=codevalidate_operation_key,
    save_operation_key="codesave-staged-0001",  # NEW operation, distinct from both previous keys
    expected_candidate_sha256=pinned_ec174_candidate_sha,
    expected_validation_receipt_sha256=pinned_ec175_validation_receipt_sha,
    authorize_save=True, authorize_read=True, save_content_for="WorkingTree",
    manual_review=review, authorize_manual_review=True,
    manual_review_content_for="WorkingTree",
    trusted_verifier_id=trusted_reviewer_id, trusted_verifier_key=reviewer_key,
)
assert (saved["status"], saved["exit_code"]) == ("partial", 2)
assert saved["effects"]["ces_metadata_record_committed"] is True
assert saved["effects"]["finding_created"] is False

# Separately granted HMAC-authenticated metadata read, never a Finding:
record = saver.read_saved(
    expected_save_store_pin=save_pin, save_operation_key="codesave-staged-0001",
    authorize_read=True, read_content_for="WorkingTree")
```

以上为参数结构示例，**所有变量需要通过真实的前置步骤、独立权限决策与机密配置得到**，示例没有任何真实 Provider/人工审查/业务仓提交。`StagedCodeSaver.save` 只允许程序内传入验证人秘钥，不提供命令行密钥参数，防止 shell history/进程列表泄密。命令行仅有 `--init --approve-init`、`--inspect --save-store-pin`、`--read --approve-read --read-content-for` 三种本地管理模式。`init/inspect` 局部操作可 `success/0`，**正常实际 CodeSave 永远 `partial/2`**，拒绝则 `invalid_input/4` 或 `unavailable/5`。

## 安全与后续义务

保存目录是 CES 自有的私有目录而非用户业务 Git、Issue 或原 EC172 staging。仅支持存在 `fcntl.flock`、无跟随 `dir_fd`、原子硬链接和同步语义的 POSIX 本地配置；在 Windows 或不支持的 FS 上拒绝，无退化为不安全路径写入。风险仍包括恶意同 UID 进程访问秘钥、物理断电期间 fsync、真正的恶意并发交换、过期后 record 的审计/长期保留策略（此版不提供删除）及 cross-OS 差异。所有这些放到施工完后的用户联合验收，不得用合成测试冒充已证明。

当前代码本身可以保存**有限且真实的 CES 本地元数据**；但它**不代表已经新增原生 `CodeSave:Staged` 命令**，也没有 EC177 Finding 保存。下轮只应实施 EC177 Finding schema，复查 EC176 的本地记录 HMAC、过期、来源与人工签字时不能把单条哈希视为真实缺陷证据。
