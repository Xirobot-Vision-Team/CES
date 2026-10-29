# CES EC195 — 显式跨仓库报告范围与权限交集（只读）

## 1. 定位与接口

[`CrossRepositoryReportScope`](../construction/cross_repository_report_scope.py) 是 EC195 真实可调用的离线 Python 模块；只构建**调用者显式列举**的 EC194/193/192 报告范围和**逐仓独立报告权限的交集**。没有仓库扫描、默认组织枚举、Git/CI/Provider/目录服务读取、提交计数、个人评价或对业务仓/CES/Issue/远端的写入。成功固定 `partial/2`，不等于权限认证或“组织全量”验收。

```python
from cross_repository_report_scope import CrossRepositoryReportScope

# period 来自真实 EC192 NaturalPeriod.from_id/from_instant 的成功响应。
# actor_a、actor_b 来自 EC194 ActorReportSubject.bind 的成功响应；
# 它们各自完整嵌入、回放了独立 EC193 RepositoryReportSubject。

def entry(ec194, *, repository_keys, operations):
    subject = ec194['subject']
    report = subject['repository_subject']
    return {
        'repository': repository_keys,  # namespace_key/project_key/repository_key
        'expected': {
            'report_subject_id': report['report_subject_id'],
            'repository_binding_sha256': report['binding_sha256'],
            'people_binding_sha256': subject['binding_sha256'],
        },
        'availability': 'SUBMITTED',
        'people_subject_json': ec194['canonical_json'],
        'authorization': {
            'purpose': 'periodic_cross_repository_report',
            'receipt_sha256': 'c' * 64,  # 示例；生产中应为独立真实收据 SHA
            'valid_from_utc': period['period']['start_utc'],
            'valid_until_exclusive_utc': period['period']['end_exclusive_utc'],
            'granted_operations': operations,
        },
    }

api = CrossRepositoryReportScope()
response = api.bind(
    period_json=period['canonical_json'],
    requested_operation='report.scope.read',
    repositories=[
        entry(actor_a, repository_keys={
            'namespace_key':'team', 'project_key':'product', 'repository_key':'api'},
            operations=['report.scope.read', 'report.actors.read']),
        entry(actor_b, repository_keys={
            'namespace_key':'team', 'project_key':'product', 'repository_key':'web'},
            operations=['report.scope.read']),
    ],
    actor_links=[],
)
assert response['status'] == 'partial' and response['exit_code'] == 2
assert response['subject']['effective_operations'] == ['report.scope.read']
```

以上片段是**调用形状示意**，不是实际 Provider/身份授权样例，`actor_a/actor_b/period` 需由调用方事先生成；`'c'*64` 是开发演示数据，不代表权限签发。

每轮至多32个**唯一逻辑仓库**、128个显式 link 声明（每个2–16个不同仓库）。单个上游 EC194 JSON 最大262,144字节，所有上游合计最多4MiB，输出最大1MiB；每个上游先走 `ActorReportSubject.from_json`，从而重新检查 EC193/192。未知字段和无效顶层结构拒绝。

## 2. 缺失/不可访问/过期绑定不能被悄悄省略

每个 `repositories` 元素都必须先给出独立逻辑仓库身份：`repository = {namespace_key, project_key, repository_key}`。使用 EC193 相同的域分离规则派生 `cesrepo1`，**不依靠本地路径或凭显示名搜索其它仓库**。`availability` 取 `SUBMITTED / MISSING / INACCESSIBLE`：

- 对 `SUBMITTED`，需同时提供 `people_subject_json`、该仓库明确的三重 `expected` pin（EC193 `report_subject_id`、EC193 `binding_sha256`、EC194 `binding_sha256`）和独立 EC195 操作授权。报告期必须与共同 EC192 周期完整一致；`source_mode`、`source_selector`、报告槽、覆盖窗口与绑定摘要各仓分别保存。
- 对 `MISSING / INACCESSIBLE`，要求 subject 和授权都为 `null`，保持该仓库的身份和已知 expected pins；返回**独立的、具名** `REPOSITORY_MISSING / REPOSITORY_INACCESSIBLE` 缺口。
- 对 `SUBMITTED` 中的坏 JSON、缺提交、跨仓冒充、错期、错报告槽、旧 EC193/EC194 摘要、授权缺失/畸形/窗口不足、无请求操作权限，保留该仓库 `status=GAP` 和对应独立 `reason_codes`，`report=null`，绝不静默删除或混进可用交集。请求中的未知仓库/缺失主体不会被其它仓库补齐。
- 即使结构与权限均合格，若 EC193 自报仅部分 UTC 报告窗口、选定路径子集或非完整清单声明，仍逐仓标记 `PARTIAL_PERIOD_WINDOW`、`SELECTED_PATH_SCOPE`、`PATH_INVENTORY_UNVERIFIED`；这类**覆盖缺口**不等同于撤销权限，但绝不可用作完整证据证明。

`coverage_gaps` 中每项同时携带 `repository` 三元键、`repository_id` 和对应 `reason_codes`；`repository_set` 中有**全部明确要求的仓库**。即使没有逐仓缺口，`global_gaps` 仍标注 `REPOSITORY_UNIVERSE_NOT_VERIFIED`，绝不因为“所选集合已处理”就声称组织全量仓库被覆盖。

## 3. 授权交集：只缩小，不推断权限

每仓独立授权 `purpose=periodic_cross_repository_report`，收据 SHA、UTC `[valid_from,valid_until)` 要**覆盖共同 EC192 周期的完整 UTC 窗口**，并在 `granted_operations` 列表中逐项声明允许的操作。EC194 actor 的 `periodic_repository_report` 不能替代这项独立的跨仓操作授权。支持以下有限权限：

| permission | 意义 | 同仓还需明确声明 |
| --- | --- | --- |
| `report.scope.read` | 跨仓范围元数据读取 | 无 |
| `report.actors.read` | 聚合人员引用权限 | `report.scope.read` |
| `report.evidence.read` | 聚合证据引用权限（EC195仍不输出证据） | `report.scope.read`, `report.actors.read` |
| `report.actors.link` | 允许提交可回放的显式人员链接提案 | `report.scope.read`, `report.actors.read` |

实现首先从每仓**明确列出**的集合里剔除任何缺依赖的操作，不会自动添加任何父级权限；对每个非READY（缺失、不可访问、错期、旧绑定、未经授权）的仓库采用**空权限集合**；最后对**全体明确列举仓库**求交，得到 `effective_operations`。只有请求操作在交集里且全部仓库READY，`requested_operation_declared_for_all` 才能为真。授权 receipt/hash/state 都只是调用者声明、无验签/撤销查询/真实 ACL 确认，不能作任何原生 Action 或发布/写入权限使用。

EC195 的输出仅包含每个READY仓库的**报告槽/模式/selector/覆盖状态/绑定摘要投影**，不序列化整份人员报告、姓名、完整 EC194 actor inventory、贡献证据、源码片段或测试日志。GAP 仓库只输出身份、预期 pin 和有限原因；不能借返回值提取被拒绝身份或证据。全部真实性、报告出版、打分、写入 claims 均固定 `false`。

## 4. 显式人员链接：只作为未认证提案

**默认 `actor_links=[]`，即使跨仓 identity_scope_sha256 或 display_label 相同，也不会自动创建任何 link。** 可选的输入形式：

```python
link = {
    'link_key': 'explicit-team-subject-1',  # 当前周期请求内唯一、非姓名的安全键
    'receipt_sha256': 'd' * 64,             # 独立链接批准收据，未验签
    'members': [
        {'repository_id': actor_a['subject']['repository_subject']['repository']['repository_id'],
         'actor_key': actor_a['subject']['actors'][0]['actor_key']},
        {'repository_id': actor_b['subject']['repository_subject']['repository']['repository_id'],
         'actor_key': actor_b['subject']['actors'][0]['actor_key']},
    ],
}
```

只有 `report.actors.link` 出现在**所有所选仓库的交集**，成员所指仓库全READY、actor 确实出现在绑定时回放的 EC194 人员表、**每一成员都至少声明了 identity receipt**、且全部 `identity_scope_sha256` 相等，才输出 `actor_link_proposals / DECLARED_SAME_SCOPE_UNVERIFIED`。即使全部满足，仍然不是 Provider/目录服务验证的同一真人：无全局 `actor_key`、无自动 evidence 混合或评分。不同 authority/tenant/immutable subject 的跨平台真人映射在 EC195 **明确不自动处理**，留给后续独立签名身份核验能力。

不满足条件则仅输出 `actor_link_gaps: [{link_key, reason_code}]`，**不回传被拒绝成员的 actor_key 或 identity_scope_sha256**。link 输入永远不能扩展权限集合。

## 5. 持久化回放及边界

- `from_json(serialized=...)` 会检查规范 JSON、重复/大小写冲突键、禁止浮点/额外字段、EC192 周期规范回放、逐仓逻辑 ID/报告槽/人员槽派生、授权摘要和周期窗口、权限依赖与全体交集、link 成员键的作用域算法、逐仓和全局缺口、绑定 SHA、规范排序。返回 `CROSS_REPOSITORY_SCOPE_REPLAYED_STRUCTURAL_ONLY`，仍是 `partial/2`。
- 由于 EC195 **不外带原始 EC194 人员/证据记录**，仅凭以上摘要自洽**无法重新证明这些投影最初来自有效 EC194**，也无法证明某仓库在真实世界中缺失或不可访问。需要强些的离线检查时，传入 `people_subject_witnesses={repository_id: 原EC194 canonical_json}`，必须覆盖**恰好全部 READY 仓库**，再逐仓完整重放 EC194→EC193→EC192，并对照所有投影与被接受链接 actor。该函数返回 `...REPLAYED_WITH_WITNESSES`；但这依旧没有认证 Provider/身份或授权收据，也不能验证 GAP 状态是真是假。
- 所有 SHA 是无密钥摘要，可被能重算记录的人伪造；`scope_id` 是显式请求周期/操作/仓库集合的稳定标识，`binding_sha256` 表示该声明版本，不是 HMAC/签名。不把 actor 或仓库 ID 的哈希当作个人隐私加密。
- `invalid_input/4` 表示请求结构/重复仓库/非法链接/规范回放失败；当周期回放因系统时区规则无法执行时为 `unavailable/5`；单仓不可用不会导致其它仓库丢失，而是保留 `SUBJECT_REPLAY_UNAVAILABLE` 的逐仓覆盖缺口。正常结构化范围输出始终 `partial/2`，即使某仓未被授权也只是保守表达缺口，不能执行被拒绝的操作。

## 6. EC195 的结束边界

只施工**跨仓库范围与权限交集**。EC196 才能区分 Git/AI/CI 指标和证据覆盖，不得把 commit/LOC 直接当绩效；EC197 才开始 ReportPrepare 输入构建。Native PowerShell `ReportPrepare`/`ReportRender`/`ReportPublish`、真实 Provider/目录验签、仓库发现、调度、写入、PowerShell7/旧15 Smoke、跨 OS/E63–E66 和最终用户辅助联合验收仍未施工或 **NOT_RUN**。
