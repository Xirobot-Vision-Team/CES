# EC192 — 自然周期唯一标签与 UTC 左闭右开区间

## 1. 可运行入口 / 准确范围

独立只读 Python 入口 [`construction/natural_period.py`](../construction/natural_period.py)
的 `NaturalPeriod` 支持四个真正可调用的方法：

- `from_instant(project_timezone=..., cadence=..., observed_at=...)`：从**明确带 offset 的观测 instant**归属自然周期、生成规范 ID 和 UTC `[start,end)`。
- `from_id(period_id=...)`：解析严格自然周期 ID，按执行时的当前 IANA tzdb **重新计算**边界。
- `from_json(serialized=...)`：读取先前输出的规范 JSON，检查字段/边界/身份并与**当前** tzdb 重新计算结果逐字比对；不对疑似时区法令变更或篡改做静默迁移。
- `compare(left_id=..., right_id=...)`：只比较 **同项目时区 key、同 cadence** 的两个自然周期，输出时间顺序 `order = -1|0|1` 和 UTC 边界是否 `touching`；不同 lane 拒绝。

所有入口输出同一 [`ces.natural_period.v1` 机器契约](natural-period-result.v1.schema.json)，成功 `partial/2`；无 report、调度、外部账本、真实项目/仓库身份认证或原生 PowerShell Period/Due 路由。需要 `PYTHONPATH=construction` 或从 `ces/construction/` 目录运行。

## 2. 标识格式、排序与项目隔离

周期的稳定可读 ID 格式为：

`cesnp1:{cadence}:{project_timezone}:{calendar_label}`

| `cadence` | `calendar_label`（严格 ASCII、零补位） | 示例 |
|---|---|---|
| `day` | 项目当地 `YYYY-MM-DD` | `cesnp1:day:America/New_York:2026-03-08` |
| `week` | **ISO week-year** `YYYY-Www`，周一开始 | `cesnp1:week:Europe/Berlin:2020-W53` |
| `month` | 项目当地 `YYYY-MM` | `cesnp1:month:UTC:2024-02` |
| `year` | 项目当地 `YYYY` | `cesnp1:year:Asia/Tokyo:2026` |

`week` 的 `YYYY` **是 ISO 周所属年，不等同于观察日历年的年份**：2021-01-01 本地所在的周属于 `2020-W53`，真实周一锚为 2020-12-28。无效 ISO 第 53 周、2月30日、`0000`、未补位日期及任意额外 ID 字段均拒绝。解析严格保留项目提供的 zone key 大小写与别名；`UTC` 与 `Etc/UTC` 可在相同 offset 下构成**不同**的 ID，绝不擅自合并别名。`CST/PST` 和 `Etc/GMT±N` 歧义简写拒绝；非 UTC 时区需运行环境有 IANA tzdb，**绝无执行机本地时间回退**。

`period_index` 是**同一 `(project_timezone, cadence)` lane 内的自然日历排序数字**：day 为 `date.toordinal()`，week 为 ISO 周一序号 `(ordinal-1)//7`，month 为 `year*12 + month-1`，year 为 `year`。同 lane 可按 `period_index` 或 `compare()` 排序；**禁止不同 lane 直接按 index、标签或 ID 做全局时间排序**。跳过的整天导致 day index 不连续，不影响真实相邻 UTC 区间的 `touching=true`。一个项目切换时区后应由上游业务保存显式 timezone policy/history，并另行定义策略；本库不会默认为历史周期重新贴新时区标签。

**ID 不是项目唯一主键，更不是报表唯一主键。** 两个不同仓库/项目如果同频率、同 zone key、同本地周期，将得到相同 ID。EC193 才设计真实仓库报表主体及显式 source binding；即使报告使用周期 ID 作为组成部分，仍须独立绑定项目/仓库来源、报告类型与生成/确认回执。周期 ID 也不认证 Git SHA、人物、真实 ReportPrepare 内容或已完成的 Due 处理。

## 3. UTC `[start,end)` 的真实自然周期语义

上游 EC191 的真实项目本地午夜算法用于计算自然锚与下一自然锚，选择重复午夜的**更早真实时刻**，对缺失午夜选 gap 后**首个真实时刻**。其间所有 UTC instant 归属于当前周期（`start_utc <= observed_at < end_exclusive_utc`）；等于右界的 instant 属于下一周期。时长用两个 UTC instant 相减，绝不把日/周/月/年强制改为固定 86400 秒倍数。

| 项目自然周期 | 真实 UTC 左界 | 真实 UTC 右界（不含） | 真实秒数 |
|---|---|---|---:|
| New York 2026-03-08 DST 开始日 | `2026-03-08T05:00:00Z` | `2026-03-09T04:00:00Z` | 82,800（23h） |
| New York 2026-11-01 DST 结束日 | `2026-11-01T04:00:00Z` | `2026-11-02T05:00:00Z` | 90,000（25h） |
| Berlin ISO `2020-W53` | `2020-12-27T23:00:00Z` | `2021-01-03T23:00:00Z` | 604,800（7天） |
| UTC 2024-02 月 | `2024-02-01T00:00:00Z` | `2024-03-01T00:00:00Z` | 2,505,600（29天） |

其他特别情形：`Australia/Lord_Howe` 2026-10-04 为 23.5h；`America/Santiago` 2018-08-12 缺失 00:00，其首个真实时间是本地 `01:00-03:00`；`America/Havana` 2026-11-01 重复零点取第一次（UTC 04:00）。`Pacific/Apia` **2011-12-30 整个本地日期不存在**，该日 `cesnp1:day:Pacific/Apia:2011-12-30` 必须拒绝，12-29 的真实右界为 12-31 的真实左界，不能创设零秒报表。输出同时记录 `calendar_anchor_date` 与 `actual_start_local_date`；若整个起始日期被删除，但更大的 week/月仍实际存在，前者允许为计划周一/月初，后者则指出真实第一个本地日期。

## 4. 具体调用和规范 JSON 传递

```python
from natural_period import NaturalPeriod

p = NaturalPeriod()
answer = p.from_instant(
    project_timezone='America/New_York',
    cadence='day',
    observed_at='2026-03-08T12:00:00Z',
)
assert answer['status'] == 'partial' and answer['exit_code'] == 2
assert answer['period']['period_id'] == 'cesnp1:day:America/New_York:2026-03-08'
assert answer['period']['elapsed_seconds'] == 82800
assert answer['period']['start_utc'] == '2026-03-08T05:00:00Z'
assert answer['period']['end_exclusive_utc'] == '2026-03-09T04:00:00Z'

# 返回的 canonical_json 是完整 period 对象，不是包含 status 的外层包络。
serialized = answer['canonical_json']
replay = p.from_json(serialized=serialized)
assert replay['status'] == 'partial'
assert replay['period'] == answer['period']
assert p.from_id(period_id=answer['period']['period_id'])['period'] == answer['period']

comparison = p.compare(
    left_id='cesnp1:day:Pacific/Apia:2011-12-29',
    right_id='cesnp1:day:Pacific/Apia:2011-12-31',
)
assert comparison['comparison']['order'] == -1
assert comparison['comparison']['touching'] is True
```

`canonical_json` 使用 UTF-8 可表述的 ASCII-escaped JSON、**字典 key 排序**、紧凑 `(',', ':')` 分隔符，无非标准数字和空白；等同于 `json.dumps(period, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)`。`from_json` 只接收整个**完全匹配**的规范字符串，拒绝重复 key、数组、任意多余字段、非规范空白和超过 4096 字符的载荷。会用当前 tzdb 重新计算所有标识、ISO 周规则、本地边界和 UTC 区间；若字段/边界不一致返回 `PERIOD_JSON_IDENTITY_MISMATCH` 或 `PERIOD_JSON_INTERVAL_MISMATCH`，**不**自动把历史数据改写为新边界。

对本地存储的报表去重，应由将来的独立报告主体模块将 **(明确项目身份、来源/报表种类、period_id、规范 UTC 区间、规则版本)** 组合起来，并在真实 durable ledger 上做原子处理。此组件没有外部授权、签名或事务，不能拿 `canonical_json` 自身当权威执行凭据。

## 5. 失败、局限与终验

严格结果契约覆盖 `partial/2`、`invalid_input/4` 与 `unavailable/5`。非法时间戳（无明确 offset / naive datetime）、未知/歧义 IANA 时区、无效日期、非法 ISO 周、已删除整天、跨时区/频率比较、非规范/变造的 JSON 都返回安全拒绝；缺失 tzdb 或不可解析日历边界返回 `unavailable/5`。失败时 `period`、`canonical_json`、`comparison` 均为 `null`，不向拒绝者泄露先前可用区间或 host 路径。

**时区规则不变 ≠ 时区规则已被固定**：规范 `period_id` 只保存显式 zone key 与本地周期标签，*不包含 tzdb 版本*。运行环境的 `ZoneInfo` 规则/别名表可能随 OS/tzdata/新法令变化，使同一个 period ID 在另一环境算出不同的 UTC 边界；存储的 `canonical_json` 在新环境 `from_json()` 会 fail closed，但无法判断差异是法令/库变更还是篡改。需要跨环境/历史严格复现的运行方应在外部部署和报告证据中固定并记录真实 tzdb release、二进制/来源哈希和时区政策版本。本轮没有实现这类受认证配置管理。

本轮有限聚焦 `python -m unittest -q test_natural_period` + Python 编译 + 合约 Schema 的开发验证，**不等于** PowerShell7/原15 Smoke、不同OS tzdb 发行版、真实仓库/用户/项目配置、到期账本、报告构建/发布、Git/Provider/CI、E63–E66 或全工程最终人工辅助验收。源/权威缺口 B-001 继续 OPEN，后续下一轮 EC193 才施工仓库报告主体。
