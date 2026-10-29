# EC193 — 仓库报告主体的显式绑定（只读、单仓库、声明式）

## 1. 交付目标与边界

独立 Python 入口 [`RepositoryReportSubject`](../construction/repository_report_subject.py) 在**不读磁盘、不扫描用户机器、不开 Git/Provider/CI、不写任何内容**的情况下，将一个**明确指定的逻辑仓库**、`report_key`、**唯一来源模式**、边界明确的路径/时间覆盖范围，与 EC192 已重算、验证的自然周期绑定，并返回稳定的规范 JSON。此操作不是实际的 ReportPrepare、报告统计、报表发布、身份认证，也不是原生 PowerShell Action。

- `bind(period_json, repository, report_key, source, coverage)` 绑定一条单仓库声明；`from_json(serialized)` 严格复核已序列化声明、派生 SHA、实际 EC192 周期/UTC 边界。成功仅 `partial/2`；输入拒绝 `invalid_input/4`；EC192 时区资源不可用 `unavailable/5`。
- 不接受无来源的“在机器上找仓库”或“推断上一次来源”。`namespace_key / project_key / repository_key / report_key` 都**必须由调用者明确提供**，大小写敏感，不能自动归并。
- `WorkingTree`、`DeliveredTarget`、`ProposedPR` 是**互不等价的来源类型**：每种类型须使用匹配的 selector kind，且 locator 种类必须匹配。Git 对象 SHA 和已有收据的 SHA 都只是**调用者声明的字符串**；没有读取/校验对象、Provider 仓库 ID、收据原始字节、签名或可信 authority，因此绝不会产生“已验证仓库”“已交付”“PR已合并”“实际完成覆盖”的结论。

## 2. 必需输入（无隐式默认值）

```python
from natural_period import NaturalPeriod
from repository_report_subject import RepositoryReportSubject

period_result = NaturalPeriod().from_id(period_id='cesnp1:day:UTC:2026-10-23')
assert period_result['status'] == 'partial'
p = period_result['period']

result = RepositoryReportSubject().bind(
    period_json=period_result['canonical_json'],  # EC192 原始规范 period JSON
    repository={
        'namespace_key': 'divisionA',
        'project_key': 'demo',
        'repository_key': 'api',
        'locator': {'kind': 'local_root', 'value': '/work/demo/api'},
    },
    report_key='repo-activity',
    source={
        'mode': 'WorkingTree',
        'selector': {'kind': 'checkout_key', 'key': 'working-main'},
        'git_object': {'algorithm': 'sha1', 'oid': 'a' * 40},  # 声称的 SHA，不是验签
        'receipt_sha256': None,
        'observed_at_utc': '2026-10-24T12:00:00Z',  # 采样时间≠本周期行为证据
    },
    coverage={
        'window': {
            'start_utc': p['start_utc'],
            'end_exclusive_utc': p['end_exclusive_utc'],
        },
        'includes': [
            {'kind': 'directory', 'path': 'src'},
            {'kind': 'file', 'path': 'README.md'},
        ],
        'excludes': [{'kind': 'directory', 'path': 'src/generated'}],
        'inventory_state': 'partial_declared',
    },
)
assert result['status'] == 'partial' and result['exit_code'] == 2
assert result['subject']['claims']['git_object_verified'] is False
assert 'PATH_EXCLUSIONS_DECLARED' in result['subject']['coverage_gaps']
replay = RepositoryReportSubject().from_json(serialized=result['canonical_json'])
assert replay['subject'] == result['subject']
```

在 `ces/construction` 目录直接运行，或通过 `PYTHONPATH=ces/construction` 导入。模块只使用 Python 标准库以及相邻的 EC192 [`natural_period.py`](../construction/natural_period.py)；运行时有效 IANA 时区数据规则由 EC191/192 负责。`jsonschema` **仅为本轮测试用途**，不是业务模块运行依赖。

| 来源 `mode` | 强制 `selector.kind` | 允许的 `repository.locator.kind` | 核心持续缺口 |
|---|---|---|---|
| `WorkingTree` | `checkout_key` | `local_root` | 未原子钉住真实工作区/Git 索引、路径只经词法检查 |
| `DeliveredTarget` | `delivery_key` | `local_root`, `remote_repository`, `provider_repository_id` | 声明 `delivery_key` 或 Git SHA **不等于**实证远程交付 |
| `ProposedPR` | `proposal_key` | `remote_repository`, `provider_repository_id` | 只描述 PR 逻辑候选，不能转换成 DeliveredTarget 或声称已合并 |

`git_object` 为 `null` 或严格 `{"algorithm":"sha1","oid":"<40位小写hex>"}` / `sha256` 与64位小写hex；`receipt_sha256` 为 `null` 或64位小写hex，不接受布尔式 `verified` 字段。不要求 Git OID 存在才能**表达**主体，但缺失时有明确 `GIT_OBJECT_CLAIM_MISSING`，有值时始终 `GIT_OBJECT_UNVERIFIED`。观察时间可为空或 UTC 秒级 `YYYY-MM-DDTHH:MM:SSZ`；它不证明报告周期内发生过业务活动，允许报告期后独立采样。所有来源和覆盖状态保留 `CALLER_DECLARED_ONLY`。

## 3. 仓库定位与路径选择

仓库逻辑身份键是独立的业务命名空间 (`namespace_key / project_key / repository_key`)，**不是本地目录、HTTP URL、供应商整数 ID 或 commit-label SHA**。三键各为1–64 ASCII 字符（字母数字开头、其余可含 `._-`），`report_key` 同规范，避免不同报告目的共用同一报告槽。定位符由调用者显式提供，但返回记录只包含 `locator_kind` 和**域隔离 SHA256 指纹**，不原样回显本机路径或远端 URL、token；原始定位符需由上层另外保留并重新授权才可真正读取。`from_json` 不可能从哈希还原原始路径，也不冒充 locator 已重新验证。**域 SHA 是非加密口令的公开指纹，并不能防止攻击者通过猜测常见路径/URL 做字典匹配；机密定位符应由外层受控系统另行保管/授权，不应依赖此指纹保密。**

- `local_root`：只接受非卷根的 POSIX 绝对路径（如 `/work/demo/api`）或 Windows 盘符绝对路径（如 `C:\work\api`），拒绝相对路径、`..`、`.`、连续分隔、UNC、盘符别名/Windows设备名及裸 `/`、`C:\`。**仅词法检查**，未检查路径存在、符号链接、设备挂载、文件系统权限或 Git common-dir。
- `remote_repository`：必须是不带 userinfo/query/fragment/百分号转义的 `https://host/namespace/repository`，禁止显式凭据和路径遍历；不发网络请求、不相信域名归属，也不从 URL 提取可信 commit。
- `provider_repository_id`：必须是 `github:58392` 或 `gitlab:12345` 这种**带调用者命名空间**的非空标识；仍只是调用者输入的声称，未验证是该 Provider 受信的 repository identity。

`coverage.includes` **至少一个、最多64个** repo-relative 逻辑 selector：`{'kind':'repository','path':''}` 明确表示“意图选择整个仓库”，`directory` 和 `file` 均须明确 `path`；`excludes` 至多64个，可排除已选择区域内的严格子目录/文件，但不允许排除整个仓库。路径用 NFC、POSIX `/` 分隔、无 `..`/`.`、反斜线、冒号、通配符、百分号转义、控制字符；拒绝重叠、重复及 casefold 等价 selector，防止范围合并时重复计数和跨平台歧义。此处的目录/文件类型也是**声明**，没有执行 filesystem stat。

`coverage.window` 使用规范 UTC 左闭右开 `[start_utc,end_exclusive_utc)`，须为 EC192 **同一个自然周期 UTC 区间的非空子区间**。完整周期窗口仅表示“选择的时间窗覆盖整段”，不证明任何事件在其中，也不说明该期间所有文件被观察。`inventory_state` 仅可为 `unknown / partial_declared / complete_declared`；即使调用者声称 `complete_declared`，`coverage_inventory_verified` 恒 `false`。时间/路径部分覆盖与明确排除产生独立 `coverage_gaps`。

## 4. 标识、哈希与回放

- `repository.repository_id = 'cesrepo1:' + SHA256('CES-EC193-REPO-ID-v1\0' + canonical(namespace,project,repo))`。逻辑仓库 ID 不包含 checkout 路径或 SHA，两个克隆位置不变；不同命名空间/项目不同 ID。它不是防伪 ID。
- `report_subject_id = 'cesrs1:' + SHA256('CES-EC193-REPORT-SUBJECT-v1\0' + canonical(report_key,repository_id,period_id,start_utc,end_exclusive_utc,mode,selector))`，稳定代表**单仓库、周期和选定来源**的报告槽。coverage 变化、候选 Git OID 变化或重新采样只修改 binding，不会悄悄变成新报告主体；不同 report_key/PR selector/来源模式会有不同 subject ID。
- `coverage_sha256 = SHA256('CES-EC193-COVERAGE-v1\0' + canonical(window/includes/excludes/inventory_state))`。路径 selector 会排序，输入列表顺序不影响 hash。`binding_sha256` 对除自身外的完整 subject 规范 JSON 作域隔离 SHA，追踪同一报告槽的声明变动；**所有散列都不是 HMAC / 签名 / 公钥认证**。
- JSON 使用 `json.dumps(..., sort_keys=True, ensure_ascii=True, separators=(',',':'), allow_nan=False)`；上限65536字符，重复/大小写冲突 key、额外字段、别名字段、非规范空白和变造哈希均拒绝。`from_json` 使用 EC192 `NaturalPeriod.from_json` 按**当前** tzdb 重新计算 UTC 边界；没有固定 IANA tzdb release 时跨环境漂移将拒绝而非静默改写。解析时**不扫描任何仓库**，也不会反查被哈希的 raw locator。

## 5. 拒绝模型与下一轮接口

契约 [`repository-report-subject-result.v1.schema.json`](repository-report-subject-result.v1.schema.json) 严格区分 `partial/2`（结构自洽但未验证事实）、`invalid_input/4`（不可信/冲突/越界）和 `unavailable/5`（来自 EC192 的时区资源失败）。失败必须将 `subject`、`canonical_json` 原子清为 `null`，不输出路径和字段原值。正面 `claims` 与包络 `limitations` 所有验证/外部执行/写入项均为 `false`，`coverage_gaps` 按类别保留具体待补证据。

后续 **EC194** 可在不篡改此仓库主体模型的前提下增加经过验证的 `actor_key` 贡献证据；**EC195** 再构建各自明示授权的多仓库集合；**EC196** 分离指标与 Git/AI/CI 证据；**EC197** 才做真正的 ReportPrepare。到时必须重新获得用户权限并重新读取可信 Git/Provider/receipt 原始数据，将验证结果作为**独立受信证据**绑定，不得单靠 `report_subject_id` / `binding_sha256` 或 `complete_declared` 提升可信度。没有真实仓库审计、真实 Git、CI/provider、跨平台/时区复现、原生 PowerShell7/15 Smoke、E63–E66或最终用户辅助验收的 `PASS` 结论。
