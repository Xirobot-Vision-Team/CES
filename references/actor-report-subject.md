# CES EC-194 — 单仓库人员报告主体：稳定 actor_key、授权边界与未归属证据

## 1. 目标与严格边界

[`ActorReportSubject`](../construction/actor_report_subject.py) 是 EC194 的**只读、零外部 I/O**人员报告主体模型。它只在一个已经由 EC193 `RepositoryReportSubject.from_json` 完整回放成功的单仓库报告主体内，把调用者明确提供的外部不可变主体 tuple 变成**仓库作用域稳定 `actor_key`**，再将严格匹配同一仓库、同一报告槽、同一 EC193 `binding_sha256`、同一报告时间窗的通用证据引用归入该 actor。

本模块不会访问身份 Provider、企业目录、Git、CI、文件系统、网络或 PowerShell；不会读取邮件、用户名、Git author、提交正文或源代码内容；不会生成 LOC/commit 数等绩效指标，也不会给任何人打分。**所有成功结果固定是 `partial/2`。** `actor_key` 只是本仓库内的稳定聚合键，不是登录身份、全球人员 ID、Provider 签名、雇佣关系证明或写权限。

EC194 只做单仓库人员主体，不做：

- EC195 多仓库授权交集或跨仓人员合并；
- EC196 Git/AI/CI 指标与证据完整度语义；
- EC197 ReportPrepare；
- ReportRender / ReportPublish / 定时任务 / Issue / Git / 业务仓写入；
- 原生 PowerShell 报告路由。

## 2. 输入接口

```python
from actor_report_subject import ActorReportSubject

result = ActorReportSubject().bind(
    repository_subject_json=ec193_result['canonical_json'],
    actors=[
        {
            'identity': {
                'authority': 'github',
                'tenant': 'acme',
                'immutable_subject_id': '10001',
            },
            'display_label': 'Alex',              # 可空；只做摘要，不参与身份
            'identity_receipt_sha256': '1' * 64, # 调用者提供；本模块不验真
            'authorization': {
                'purpose': 'periodic_repository_report',
                'receipt_sha256': '2' * 64,
                'valid_from_utc': '2026-10-23T00:00:00Z',
                'valid_until_exclusive_utc': '2026-10-24T00:00:00Z',
            },
        }
    ],
    evidence=[
        {
            'evidence_id': 'evt-001',
            'identity': {
                'authority': 'github',
                'tenant': 'acme',
                'immutable_subject_id': '10001',
            },
            'occurred_at_utc': '2026-10-23T12:00:00Z',
            'repository_id': ec193_subject['repository']['repository_id'],
            'report_subject_id': ec193_subject['report_subject_id'],
            'source_binding_sha256': ec193_subject['binding_sha256'],
            'evidence_sha256': '4' * 64,
        }
    ],
)
```

`actors` 最多 128 个；`evidence` 最多 1024 条。至少存在一个 actor 声明或一条证据引用。所有结构都采用**exact-field**校验，未知字段会拒绝，避免调用者偷偷塞入 `verified=true`、成绩、邮箱、权限或其它未定义语义。

### 外部身份 tuple

`identity = {authority, tenant, immutable_subject_id}`：

- `authority` 是调用者明确选择的身份命名空间，例如 `github`、`gitlab` 或组织目录适配器名；必须是小写安全键。
- `tenant` 和 `immutable_subject_id` 必须是 NFC、无控制字符、非空、长度受限的显式字符串。这里仅检查形状，**不证明 Provider 真正把该字段定义为不可变 ID**。
- `display_label` 可用于界面关联，但输出只保存域隔离 SHA256；它**绝不参与 actor_key**。同名、改名、相同 Git author、相同邮箱或相同用户名都不能自动合并两个主体。
- `identity_receipt_sha256` 可以引用上层独立身份验证器保存的收据字节摘要，但 EC194 不读取收据、不验签、不联网，因此即使存在仍是 `DECLARED_STABLE_SCOPE_UNVERIFIED_RECEIPT`。缺失时为 `...NO_RECEIPT`，且**任何匹配证据都不会归属给该 actor**，而会进入 `unattributed_evidence / ACTOR_IDENTITY_PROOF_MISSING`。

这条“缺 identity receipt 不归属证据”的规则不是把 SHA 当认证；它只是比“仅凭名字/邮箱/tuple 就合并”更保守。真实身份认证仍需未来独立 Provider/目录适配器在受控环境产生可验证事实。

## 3. 稳定、但仅限仓库作用域的 actor_key

EC194 首先计算：

```text
identity_scope_sha256 = SHA256(
  "CES-EC194-IDENTITY-SCOPE-v1\0" + canonical(authority, tenant, immutable_subject_id)
)

actor_key = "cesra1:" + SHA256(
  "CES-EC194-REPOSITORY-ACTOR-v1\0" +
  canonical(repository_id, identity_scope_sha256)
)
```

因此：

- 同一 EC193 逻辑 `repository_id` + 同一外部身份 tuple，在不同报告期、不同本地 clone 路径、不同 `report_key` 下得到相同 `actor_key`；
- 同一个外部 tuple 在**不同 repository_id** 下得到不同 actor_key，EC194 不允许跨仓自动合并；
- `display_label`、授权 receipt、证据、Git SHA、报告期变化不会改 actor_key；
- `actor_subject_id = cesras1:...` 另外绑定 `report_subject_id + actor_key`，表示“该 actor 在这个具体报告槽中的主体”；
- `people_subject_id = cesprs1:...` 只绑定 EC193 的报告槽、仓库和周期，actor 集合/证据/授权改变时保持槽位稳定，由 `binding_sha256` 反映具体声明变化。

这些 SHA 都是**非密钥摘要，不是 HMAC/签名**。如果外部不可变 ID 或 tenant 可猜，摘要也可能被字典枚举；机密身份映射应由上层受控系统保管。

## 4. 显式报告授权

每个 actor 必须有：

```json
{
  "purpose": "periodic_repository_report",
  "receipt_sha256": "<64 lowercase hex>",
  "valid_from_utc": "...Z",
  "valid_until_exclusive_utc": "...Z"
}
```

授权窗口必须覆盖 EC193 `coverage.window` 的完整 `[start,end)`；不能只覆盖部分报告窗。输出状态固定为 `DECLARED_GRANTED_UNVERIFIED`，并生成 `authorization_binding_sha256` 绑定 actor_key、repository_id、report_subject_id、period_id、purpose、receipt 和窗口。

该 receipt 仍只是调用者声明的摘要：EC194 不读取原授权记录、不校验签名、不判断授权人是否有权授权，也**绝不把它转成写权限**。无显式授权或授权窗口不足会直接拒绝该 actor 声明，防止把人员证据默认纳入报告。

## 5. 证据必须精确落在同一仓库、报告槽和时间窗

每条 evidence 只是**证据引用**，不含代码或提交正文。必须显式带：

- `repository_id`：必须等于嵌入 EC193 主体；
- `report_subject_id`：必须等于嵌入 EC193 报告槽；
- `source_binding_sha256`：必须等于当前 EC193 完整声明 binding；这样 coverage、source selector、SHA/receipt/路径范围变更后，旧证据不能悄悄复用；
- `occurred_at_utc`：必须位于 EC193 `coverage.window` 的左闭右开区间内；
- `evidence_sha256`：只作为外部证据字节摘要引用，本模块不读取原始证据，也不证明其真实性；
- `identity`：可为空。为空则 `ACTOR_IDENTITY_MISSING`；有 tuple 但没有对应显式授权 actor 则 `ACTOR_NOT_AUTHORIZED_OR_DECLARED`；有 actor 但缺 identity receipt 则 `ACTOR_IDENTITY_PROOF_MISSING`。

只有“tuple → 仓库作用域 actor_key”精确匹配、且 actor 有 identity receipt 与报告授权声明时，evidence 才进入该 actor 的 `evidence_refs`。**显示名永远不参与匹配。** 未归属证据仍保留其事件 ID、UTC 时间、证据摘要和 source binding，但不会输出未授权人员的 identity hash/actor_key，从而避免通过报告间接建立未授权人员关联。

EC194 不统计 evidence 数量，不计算 LOC、提交数、PR 数、CI 通过率或任何个人排名；这些属于后续 EC196，而且即使以后实现，也必须携带证据覆盖缺口而不能把数量直接等价为绩效。

## 6. 输出、回放和失败模型

严格机器契约为 [`actor-report-subject-result.v1.schema.json`](actor-report-subject-result.v1.schema.json)。成功记录包含：

- 完整嵌入并再次回放验证的 EC193 `repository_subject`；
- 排序后的 actor 列表，包含 actor_key、actor_subject_id、身份/显示名摘要、显式授权绑定和已归属证据引用；
- `unattributed_evidence`；
- `coverage_gaps`；
- 所有真实性/绩效/写入 claim 均为 `false`；
- 完整 `binding_sha256`。

`from_json(serialized)` 要求规范 JSON 字节、拒绝重复/大小写冲突 key、非有限数、额外字段和变造摘要；它会再次调用 EC193 `RepositoryReportSubject.from_json`，因此周期/tzdb、仓库逻辑 ID、source/coverage 等上游规则仍需成立。它能发现普通篡改，但**不能防止一个能重算所有 SHA 的攻击者伪造整份记录**，因为没有密钥或外部签名。

状态约定：

- `partial / 2`：结构自洽、范围明确、仍未认证；
- `invalid_input / 4`：字段、授权窗、仓库/report/source binding、时间或回放不一致；
- `unavailable / 5`：上游 EC193/EC192 因环境时区资源等不可用而无法回放。

`claims` / `limitations` 永远不宣称 actor 身份认证、授权认证、证据归属认证、完整人员覆盖、完整贡献覆盖、跨仓身份链接、指标计算、个人绩效判断、报告发布、业务写入或原生 PowerShell 注册。

## 7. 后续边界

EC195 才能在多个**逐仓明确授权**的 EC194 主体之间建模仓库集合与权限交集；不能因为两个 repository-scoped actor_key 的 identity 摘要相似就自动合并。EC196 才增加 Git/AI/CI 等指标/证据覆盖语义，并必须维持“不以 commit/LOC 直接评价人员”的退出门。EC197 才进入 ReportPrepare。

真实身份 Provider / 企业目录认证、实际授权收据验签、真实 Git/CI/Provider 事件、Windows/macOS/Linux、PowerShell7、原15套 Smoke、E63–E66和最终用户联合验收均仍 **NOT_RUN**。
