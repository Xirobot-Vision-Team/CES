# EC196 — ReportEvidenceMetrics：来源分型、证据覆盖与不可推断边界

## 定位

[`construction/report_evidence_metrics.py`](../construction/report_evidence_metrics.py) 是可调用的**离线、只读 Python**能力，支持 `ReportEvidenceMetrics.bind/from_json`。它消费**已有** EC195 `CrossRepositoryReportScope` 的精确规范 JSON，处理使用者在权限许可下显式提供的证据摘要与覆盖声明。模块不扫描工作树、不连接 Git/CI/AI/Provider、不写入报告、不调用原生 PowerShell、不保存数据，也不产生个人绩效评分。

**四个互不等价的渠道**：

| `channel` | 允许的 `kind` | 语义 |
| --- | --- | --- |
| `git_activity` | `commit_claim` / `pull_request_claim` / `change_claim` | Git 活动的**申报引用**，不证明真实提交、合并、交付或质量 |
| `ai_conclusion` | `analysis_claim` / `finding_claim` / `recommendation_claim` | AI 推理/建议的**申报引用**，不是事实、缺陷确认或测试 |
| `ci_execution` | `completed_pass_claim` / `completed_fail_claim` / `completed_inconclusive_claim` / `running_claim` / `not_run_claim` / `canceled_claim` | CI 任务状态的**申报引用**；无经认证的实际执行/结束证明 |
| `unknown_signal` | `not_collected` / `unavailable` / `redacted` / `unattributable` | 明确记录未知和不可用，不能变成零、PASS 或猜测 |

`declaration_count` 是**本轮提交的类型化证据摘要条数**，不是该周期的真实 commit 数、LOC、工作量、产出、员工成绩或绩效。输出**没有个人计数汇总、质量打分、排行榜、个人判定**；不接受额外 `LOC`、`score` 等字段。AI 结论不得升级为经验证事实。`ci_completion_signal=PASS_COMPLETION_CLAIM_UNVERIFIED` 也绝非 CI 已真正通过。

## 使用路径与输入

1. 用 EC192 计算真实 IANA 时区周期，在 EC193/194 获取报告主体，在 EC195 **明确枚举全部本次需要的仓库**，分别提交完整周期授权，并设置 `requested_operation='report.evidence.read'`。确保每个仓库显式授予 `report.scope.read`、`report.actors.read`、`report.evidence.read`；EC195 只做声明性交集，不证明真实 ACL。
2. 把 `CrossRepositoryReportScope.bind` 返回的 **`canonical_json` 原字节**传给 `scope_json`。不要把整个 response JSON 或自己重组的 JSON 代入。
3. 只有全仓都为 READY 且证据权限在**全体仓库交集**中，才能对每仓提交一条 coverage 声明，列出且按顺序给齐四个 `CHANNELS`。`state` 必须明确是 `COMPLETE_DECLARED`、`PARTIAL_DECLARED` 或 `UNKNOWN`：前两者要 `receipt_sha256`；PARTIAL / UNKNOWN 必须给 `reason_codes`，UNKNOWN 的 receipt 必须为 `null`。所谓 COMPLETE 仅是“收集方自己声明完整”，**从来不是验证过完整**。
4. 每个 evidence 必须含 `repository_id`、`report_subject_id`、当前 `repository_binding_sha256` 与 `people_binding_sha256`、`period_id`、安全 `evidence_id`、`channel`、`kind`、周期内 `occurred_at_utc`、不早于发生时刻的 `recorded_at_utc`、`evidence_sha256`、`source_receipt_sha256`、以及可空的 `actor_key`。输入**不可**包含原始提交说明、文本、源码、邮件、AI 回答、CI 日志或邮箱姓名；摘要与收据 SHA 仅作为声明哈希引用，不做鉴真。
5. `actor_key=null` 表示不做人员归属；若填写仓库作用域 EC194 actor_key，必须提供 `people_subject_witnesses={repo_id: 原EC194 canonical_json}`（**恰好所有 READY 仓库**），并同时匹配 EC194 具体 `evidence_refs` 内的 ID、SHA、发生时刻和源绑定，actor 还需有 identity receipt。即使全部匹配，状态仍为 `EC194_DECLARED_EVIDENCE_LINK_UNVERIFIED`，不证明作者、身份、贡献关系或绩效。

```python
from report_evidence_metrics import ReportEvidenceMetrics, CHANNELS

# ec195 是请求 report.evidence.read 的 CrossRepositoryReportScope.bind 正常返回值。
# 下面以无原始事件的安全初始化为例。真实工程由明确获授权的调用方注入引用。
rows = ec195['subject']['repository_set']
coverage = [{
    'repository_id': row['repository_id'],
    'channels': [{
        'channel': ch,
        'state': 'UNKNOWN',
        'receipt_sha256': None,
        'reason_codes': ['DATA_NOT_PROVIDED']
    } for ch in CHANNELS]
} for row in rows]

result = ReportEvidenceMetrics().bind(
    scope_json=ec195['canonical_json'],
    coverage=coverage,
    evidence=[],
)
# 仅当 EC195 的完整集合声明具有证据权限时接受上述 coverage。
assert result['status'] == 'partial' and result['exit_code'] == 2
assert result['subject']['claims']['ci_runs_executed_or_completed_verified'] is False

replayed = ReportEvidenceMetrics().from_json(
    serialized=result['canonical_json'],
    scope_json=ec195['canonical_json'],
)
assert replayed['subject'] == result['subject']
```

**有真实输入声明引用的例子**：以 `row = ec195['subject']['repository_set'][0]`（必须 READY）为前提：

```python
event = {
    'repository_id': row['repository_id'],
    'report_subject_id': row['report']['report_subject_id'],
    'repository_binding_sha256': row['report']['repository_binding_sha256'],
    'people_binding_sha256': row['report']['people_binding_sha256'],
    'period_id': ec195['subject']['period']['period_id'],
    'evidence_id': 'ci-run-receipt-001',
    'channel': 'ci_execution',
    'kind': 'completed_pass_claim',
    'occurred_at_utc': '2026-10-23T12:00:00Z',  # 必须在真实报告周期内
    'recorded_at_utc': '2026-10-23T12:05:00Z',
    'evidence_sha256': 'e' * 64,       # 合成示例，非真实签收
    'source_receipt_sha256': 'd' * 64, # 合成示例，不是验签
    'actor_key': None,
}
# event 一定要通过同一周期、同一仓库的所有 pin 检查，才会被计入。
```

**注意**：如果任何显式仓库 GAP、授权被拒或 EC195 的 `requested_operation` 不是 `report.evidence.read`，接口只允许 `coverage=[]` 与 `evidence=[]`，返回所有仓库均为 `BLOCKED` 的声明性缺口视图；不能越权仅读其它 READY 仓库的证据。

## 指标、覆盖与异常语义

- `repository_metrics` 保持全部 EC195 仓库、仓库逻辑键、report/source/people pin、Source Mode、原始 EC195 缺口，并为四个渠道逐一输出 `declared_coverage_state`、`effective_coverage_state`、`coverage_receipt_sha256`、`coverage_reason_codes`、`declaration_count`、`kinds_present` 与 CI completion claim 信号。
- EC195 若报告周期覆盖不全、只选路径子集或清单不完整，则对原始 COMPLETE 声明做**不可逆向升级**的保守降级：`PARTIAL_DECLARED`，无法验证清单完整时 `UNKNOWN`；不会伪装整个项目范围已完全覆盖。
- 对某个渠道没有提交事件，`empty_observation_meaning=ZERO_SUBMITTED_NOT_VERIFIED_ZERO`，不是“现实中没有任何提交/AI/CI”，更不是 CI 成功。CI 的 PASSED、FAILED、INCONCLUSIVE 同时出现，输出 `CONFLICTING_COMPLETION_CLAIMS_UNVERIFIED`，不随机选一个状态。
- `evidence_refs` 只包含经类型校验的 SHA/opaque-key/UTC/mode 关联及来源**声明类别**，没有密文、真实身份详情或已确认质量结果；每个仓库最多128条，总计512条。一个仓库内不能复用 `evidence_id`，不同仓库不自动合并。`ProposedPR` 保持为提案 Source Mode，始终标记 `PROPOSED_PR_NOT_DELIVERED_TARGET`。
- 拒绝结果 `invalid_input/4` 没有 `subject` 和 `canonical_json`；上游时区规则无法回放可为 `unavailable/5`。成功总为 `partial/2`，**从不输出 `success/0`**。
- `from_json` 必须传回**原始对应的 EC195 规范 JSON**，重算完整上游范围、全仓权限、四渠道、证据 pin、排序、计数和 `binding_sha256`。有 actor 关联还必须提供原 EC194 witnesses，缺 witness 不通过。此过程可挡住篡改/错绑定，**没有秘钥签名，也不能挡住能够伪造整条上游声明链的攻击者**。

## 后继与人工统一验证

EC196 **未实现** EC197 ReportPrepare、EC198 report_writing、EC199 ReportRender、EC200 更正展示，及 ReportPublish/定时/远端/原生 PowerShell Action。真实 Git/Provider/CI 身份权限验真、外部收据真实性、PowerShell7 / 15 原 Smoke、Windows/macOS/Linux、E63-E66 和最终用户联验均 **NOT_RUN**；不能把本机 synthetic `unittest` 通过称为这些条件通过。前代 B-001 V3.10/原 ROUNDS 缺证仍 OPEN。
