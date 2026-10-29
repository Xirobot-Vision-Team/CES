# EC175 — Staged CodeValidate：草稿与独立验证证明分层（V4.85/R175）

对应 [机器契约](codevalidate-staged.v1.json)、[施工报告](../EC-175.md) 和 [实现代码](../construction/codevalidate_staged.py)。本轮属于 **独立 Python 施工入口** `StagedCodeValidator.validate`，**不是**尚未注册的 PowerShell `CodeValidate -Mode Staged`，更不是 EC176 `CodeSave -Mode Staged`。默认无持久化、无执行、无 Git/Issue/业务源文件写入。

## 实际流程、输入与授权

必须先在 EC170→171→172→173 链中真正创建 `ACTIVE` Run / `READY` Handoff、提交 HMAC 封存的 CES 私有 stage/InputPath，再用 EC174 `HandoffRouter.route(action="dispatch")` 的**实际 callback 返回**形成 `AI_CANDIDATE_RECEIVED_UNVERIFIED`。EC174 `schema_only`、callback 失败、AI 输出伪造 `success`、外部 Provider 未绑定均不构成可验证草稿。

本轮要求额外 `authorize_validate=True` 和 `authorize_read=True`，`validate_content_for`必须等于已授权 EC173 单一来源，`validation_operation_key`必须是新的、与 EC173 `input_operation_key` 不同的键。parent pin、RunId、HandoffId、revision、末事件 SHA、EC173 input operation key、ProposedPR 历史许可及 source age 都要精确回放。`expected_candidate_sha256`由调用者独立钉住为 EC174 结果的规范化哈希，禁止用草稿内容替换期望值后把它称为既有可信结果。

调用时不仅核对 EC174 route 的 schema/task/action/status/Provider 未认证/外传标志，还**重新读取 EC173 完整授权素材**，逐条重建 segment/item/quote 和所有 anchor SHA，检查每项 ordinal、标题/分析/建议、coverage、source quality、context/identity/material/evidence 的 hash、Run/Handoff 修订绑定，重算整个候选 SHA。可选传 `ces.codevalidate_staged_draft.v1` 完整草稿，只有与 EC174 规范化结果**完全相同**才接受，编辑任何字段必须重新请求来源授权/产生新候选。函数在返回前再次读取封存输入、有效期、权限/源码内容，一旦漂移立即拒绝。

这是**确定性的本地引用/结构验证**，并非缺陷语义或“当前 Git 事实”。即使 EC170 quality 为 `success`，也只能说明选中来源的准备质量；EC170/173不是当前同一瞬间的可信 Git 原子读数。`ProposedPR`始终保留历史/缺覆盖/`partial`。Model Provider 与 actor 仅自报，本轮不为旧 route outcome 提供密码学来源认证：调用方进程若能同时伪造 route 结果及其未签 SHA，无法证明那个 callback 真的来自 AI。结构校验通过仍返回 `partial/2`，从不自动升级成 `success/0`、`FindingSave`、真实 CI PASS 或 CodeSave 授权。

## 区分草稿、拒绝、未验证、可信人工签字

- 无效/已改草稿、缺来源、权限拒绝、修订错配、HMAC损坏/过期：顶层 `candidate.state=REJECTED`、`invalid_input/4` 或 `unavailable/5`，无残留发现条目。
- 结构/证据锚核对完成：`candidate.state=STRUCTURALLY_CHECKED_DRAFT`，每条 `review_state=UNVERIFIED_SEMANTIC_ASSERTION`，顶层仍 `partial/2`。
- **可选独立人工校核**：另配操作者可信 32–64 字节 HMAC 秘钥和与AI分离的 `trusted_verifier_id`，按 `ces.codevalidate_manual_review.v1` 对当前 Run/Handoff/revision/context/candidate、专属 validation operation key、审核时间/有效期及**每一条** `finding_sha256` 的 `confirm/reject/inconclusive` 和审核说明签名。额外要求 `authorize_manual_review=True`、`manual_review_content_for=exact source mode`。只有签名与本地钉住的 verifier 配置严格一致，才会标记 `VERIFIED_BY_PINNED_MANUAL_REVIEW_SIGNATURE` / `REJECTED_BY_PINNED_MANUAL_REVIEW` / `UNVERIFIED_REVIEW_INCONCLUSIVE`。
- 签名只能**证明持有配置秘钥者声明了何种审核结论**；不证明其确实是某位自然人、审核语义正确、真实外部模型执行、当前 Git 内容或 CI/测试运行。审核说明仅返回 SHA，完整审核文字不回显。验签失败不是“未验证仍可保存”，而是整次拒绝。单条被审核人驳回不会自动删除原草稿，后续保存须独立决定；**本轮所有结果 `codesave_authorized=false`**。

SHA-256 `validation_receipt_sha256` 仅提供结果内容的域隔离指纹，不是 HMAC、签章、可离线继承的自动写权限。EC176必须重新验证实际来源、调用者身份/权限、绑定和期限，不能只看 EC175 `partial/2` 或复制本收据。

## Python 接入示例

在 `construction/` 的 Python 模块搜索路径中：

```python
from codevalidate_staged import StagedCodeValidator
validator = StagedCodeValidator('/owner/private/ces', '/work/business')
validated = validator.validate(
    prepared,                     # EC170 单一来源对象，仍具有来源精确 content grant
    ec174_dispatch_result,        # 不是 schema_only，也不是模型任意 JSON
    expected_parent_pin=pin,
    run_id=run_id, handoff_id=handoff_id,
    expected_revision=rev, expected_event_sha256=last_event_sha,
    input_operation_key='ec173-input-unique',
    validation_operation_key='ec175-validate-unique',
    authorize_validate=True, authorize_read=True,
    validate_content_for='WorkingTree',
    expected_candidate_sha256=ec174_dispatch_result['result']['candidate_sha256'],
)
assert validated['status'] == 'partial'
assert not validated['effects']['codesave_authorized']
```

以上代码是接口示例，`prepared`/ID/PrivateStore/EC174 outcome 必须由前序真实创建，**示例自身不生成这些对象**。`expected_candidate_sha256`应由可信调用方在获取 EC174 结果时冻结；若事后从不可信草稿重新读取它，防篡改保护只能视为同一对象的自洽性。

可选审核材料的 MAC 算法（**在独立可信审核方环境**实施，而非让 AI 自己生成；切勿将 key 传给 AI/存到业务仓）：

```python
import hmac, hashlib
from task_staging import _canonical
from codevalidate_staged import DOMAIN_REVIEW

# review = 完整 v1 审核对象，先不含 mac_sha256，来源/草稿/每条finding都已审查
# reviewer_key = 外部注入的独立私有随机32-64字节，不得使用EC172 staging key
review['mac_sha256'] = hmac.new(
    reviewer_key, DOMAIN_REVIEW + _canonical(review), hashlib.sha256
).hexdigest()

# validate(..., manual_review=review, authorize_manual_review=True,
#          manual_review_content_for='WorkingTree',
#          trusted_verifier_id='pinned-reviewer', trusted_verifier_key=reviewer_key)
```

`reviewed_at_utc`/`expires_at_utc` 为 UTC `YYYY-MM-DDTHH:MM:SSZ`，最长审核有效期 300 秒，时间必须不早于来源观测、不过度超前、在 EC173 输入与本轮有效窗口内；整次操作不运行 shell、测试或任意补丁文本。`review_notes`不能含明显密钥，输出只保留其摘要。

## 只读 CLI

```bash
python construction/codevalidate_staged.py --prepared /secure/ec170.json \
  --route-result /secure/ec174-dispatch.json \
  --root /owner/private/ces --business-repo-root /work/business \
  --parent-pin "$PIN" --run-id "$RUN_ID" --handoff-id "$HANDOFF_ID" \
  --expected-revision "$REV" --expected-event-sha256 "$EVENT_SHA" \
  --input-operation-key ec173-input-unique \
  --validation-operation-key ec175-validate-unique \
  --expected-candidate-sha256 "$PINNED_CANDIDATE_SHA256" \
  --allow-content-for WorkingTree --approve-read --approve-validate
```

本轮 CLI **故意没有** `--exec` / `--apply-patch` / `--save` / `--trusted-verifier-key`，避免秘钥被命令行或终端历史读取；签名审核仅通过可信 Python 调用方注入。CLI 输出元数据、计数、摘要和审核状态，不回显源码/patch/候选正文，退出码仅2/4/5。输入路径的叶节点要求非符号链接受限读；跨祖先路径、敌意同UID竞态仍须在目标OS综合验收。

## 开发与统一延期验收

[`construction/test_codevalidate_staged.py`](../construction/test_codevalidate_staged.py) 的合成场景使用临时私有POSIX目录与真实调用的EC170→174本地链，覆盖被修改的草稿/锚点、来源切换、伪成功标志、HMAC与input过期、postflight权限撤销、ProposedPR历史约束、人工签名确权/错绑/失效及CLI只读。它们不是实际 AI/真人、业务当前Git、真实测试运行或外部资格验证。原生PowerShell7、15 Smoke、GH/GL/AI Provider、签字人实际身份/安全秘钥分发、跨 OS/恶意文件系统竞态和断电、性能 E63–E66、EC176 CodeSave→Finding→Quality→全业务链及最终用户辅助验收仍为 `NOT_RUN/NOT_STARTED`。
