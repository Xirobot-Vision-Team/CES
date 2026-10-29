# EC177 — 独立 Finding Schema：有来源的“声明”，不是自动成立的“缺陷”

**当前完整包 V4.87/R177/EC-177。** 可运行 Python 入口：
[`construction/finding_schema.py`](../construction/finding_schema.py) 的
`FindingProjector.project(...)`；正式结构契约
[`finding-schema.v1.schema.json`](finding-schema.v1.schema.json) 采用 JSON Schema 2020-12。
本轮**只生成内存 Finding**，不写 CES 记录、Issue、Git、业务源码，也**没有 EC178 `FindingSave`**。旧 PowerShell CLI 仍为 V4.60/R150，不包含此路线。

## 真正实现的区分

- **不可混淆的身份**：`finding_id = SHA256("CES-EC177-FINDING-STABLE-IDENTITY-v1\0" + canonical({source_binding,candidate_sha256,finding_sha256,ordinal}))`；包含 EC171 RunId/HandoffId、EC172 stage revision/event、EC170/173 完整所选来源/材料指纹和 EC174 原始候选/逐条 SHA。相同来源候选的重复投影 ID 稳定；不同 revision、candidate 或发现无自动跨版本同一性。SHA 是内容寻址，**不签名、不证明真伪**。
- **声明与观测分层**：`severity` 与 `confidence` 是两个互不替代的模型声明，`confidence` 不是概率。正面 `positive_anchors` 与可选 `counter_evidence` 全部对应 EC173 HMAC 私有输入的确切行；`anchor_sha256` 是对输入局部行的证据锚，不等于真实 Git 工作区的当前行。反证包含独立 `interpretation`，仅为调用者提出的解释，不视为已证实的反驳，也不以“没有反证”推出不存在。
- **审查状态不越权**：
  - `UNVERIFIED`：没有完整 EC175 HMAC 人工审查声明；
  - `REVIEWED`：单条 `confirm` 的本地签字已在当前调用独立复核；不代表缺陷真实存在；
  - `REJECTED`：单条 `reject` 的本地签字持有者作否定声明；也不是客观测试判假；
  - `INCONCLUSIVE`：单条 `inconclusive` 声明；
  - `ACTUALLY_TESTED` **仅保留在状态词汇中，不是当前 EC177 能输出的状态**。没有真实独立、安全受控、与具体 source/claim/SHA 绑定的测试记录与认证运行器，本轮不会模拟此状态。合约 `assessment.state` 明确禁止该值，直到后续明确的版本升级。
- **反证与不确定性保留**：自动报告 live Git 未证实、Provider/真实 reviewer 未认证、CI/实际测试未运行、语义未证实、反证未穷尽；历史 ProposedPR 永远注明非现行交付源码；所选来源覆盖不完整时单独写出 `SELECTED_SOURCE_COVERAGE_INCOMPLETE` 和缺口数/哈希。
- **默认零原文泄露**：无论是否关联存储，默认 `title/analysis/suggested_action/quote/interpretation = null`，输出相应 SHA；`source_path` **从不输出**，最多输出独立域 SHA，`segment_label` 同样只输出域 SHA；原 reviewer notes/密钥不返回。显式 `disclose_text=True` 必须同时具备新的 `authorize_text_disclosure=True` 及 `disclose_content_for=selected_source`，仍遵循上游明显机密/私人绝对路径静态筛除。这个过滤不保证排除所有秘密；不要将输出交给不受信任主体。
- **可选旧元数据关联必须是真的**：有单独保存根的场景，必须新的 `authorize_saved_link=True`、`authorize_saved_record_read=True`、源作用域及 `expected_save_store_pin`、准确 `save_operation_key`。用真正 EC176 `read_saved` 重新核验目录、HMAC、TTL 和有限私有记录；逐字段对齐当前重新核验的 Run/Handoff、stage、source、candidate、route、draft、review、所有 finding hashes 和 coverage。没有这些资料不会“接受一份 JSON 中的保存声称”；同样不会认为存过元数据就是持久化 Finding。

## 权限与调用顺序

程序先从真实 EC170→EC171→EC172→EC173→EC174→EC175 得到 `prepared / route_result / validation_result`（不是复制别人的声称），持有可信、单独配置的 reviewer 密钥（若有人工审查）；然后：

```python
from construction.finding_schema import FindingProjector  # 或将 construction/ 加入 sys.path

projector = FindingProjector(stage_root, business_repo_root, save_root=optional_ec176_root)
projection = projector.project(
    prepared, route_result, validation_result,
    expected_parent_pin=parent_pin,
    run_id=run_id, handoff_id=handoff_id,
    expected_revision=revision, expected_event_sha256=event_sha,
    input_operation_key=input_op, validation_operation_key=validation_op,
    finding_operation_key="finding-project-v1-0001",  # 全新 operation，不复用 input/validate/save
    expected_candidate_sha256=pinned_ec174_sha,
    expected_validation_receipt_sha256=pinned_ec175_receipt,
    authorize_project=True, authorize_read=True,
    project_content_for="WorkingTree",
    # 若要使用原 EC175 HMAC 人工 review，须提供完全相同的原始 review 与独立密钥：
    # manual_review=review, authorize_manual_review=True,
    # manual_review_content_for="WorkingTree",
    # trusted_verifier_id=verifier_id, trusted_verifier_key=verifier_key,
    # 若要关联 EC176 私有保存摘要，还需提供 save_root，并增加独立以下授权：
    # expected_save_store_pin=store_pin, save_operation_key=save_op,
    # authorize_saved_link=True, authorize_saved_record_read=True,
)
assert (projection["status"], projection["exit_code"]) == ("partial", 2)
assert projection["effects"]["findings_persisted"] is False
```

默认 `counter_evidence=None`。可另传一个最多 32 项的数组（每 Finding 最多 3 组，每组最多 3 个锚；全部原文 JSON 合计最多 48 KiB），例如：

```python
counter_evidence = [
    {
        "ordinal": 1,
        "anchors": [{"segment_index": 0, "item_index": None,
                     "line_number": 4, "quote": "+new"}],
        "interpretation": "The selected line may not be on an executable path."
    }
]
```

行号是**EC173 封存的片段行号**，不是 Git 文件行号。任何 quote / source segment 变化都拒绝，注解未经签字则不会变成客观测试证明。公开原文须另加 `disclose_text=True, authorize_text_disclosure=True, disclose_content_for="WorkingTree"`，**不是默认行为**。

若是 `ProposedPR`，必须新的 `allow_historical_proposal=True` 和 `acknowledge_historical_only=True`；不能由历史保存记录或 EC175 部分结果继承授权。无需读 EC176 时，不设 `save_root`、不传保存授权即可完成未保存/拒绝/不确定的原始候选投影。EC176 只能保存完整人工 `confirm` 的旧元数据，不能用于构造拒绝/不确定的旧保存关联。

## 约束、用法与后续

1. `project()` **至少两次实际调用 EC175**，验证前序完整来源与未签名 receipt 的全稳定字段，再取源构建反证，按需读 EC176 并最后重验。状态正面只返回 `partial/2`；任何拒绝是 `invalid_input/4` 或 `unavailable/5` 且空 Finding。真实凭据泄漏/恶意同 UID/秘钥托管、源镜像实际内容、远程 actor 和 Git/CI 不是本组件可认证的对象。
2. JSON Schema 2020-12 描述**正面的 partial 响应**，禁止任何 `ACTUALLY_TESTED` 或 `semantic_truth` 正面声称。Schema 匹配和输出 unkeyed `projection_sha256` 只是结构、内容一致性；**不能作为第三方独立签字或写入许可**。下游 EC178 必须重新从原始私有来源核验证据并申请新的持久化授权，而不是盲收任意投影 JSON。
3. 无机器执行、不使用网络或插件，不操作业务 repo；真实外部 Provider/reviewer、完整 PowerShell/native、跨OS攻击和最终联验延后用户协助。开发合成用例详见 [`construction/fixtures/ec177/README.md`](../construction/fixtures/README.md) 和 [`EC-177.md`](../EC-177.md)。
