# EC191 — Project-local Due calendar / 项目时区与到期判断

## 1. 实际能力和与后续 EC 的边界

入口为独立 Python 只读模块 `construction/due_calendar.py` 中的
`DueCalendar(clock=None).evaluate(...)`。**不是原生 PowerShell `ces.ps1 -Action Due`
路由**，没有定时任务、持久化处理记录、业务仓或远端写入。`day`/`week`/`month`/`year`
都按**项目明确指定的 IANA 时区**做日历算术，绝不采用主机本地时区。

**语义：** 一份报告在其覆盖的自然周期**结束**时成为候选到期事项；对应事件时间为**下一自然周期**的第一真实时刻。周一为 ISO 周首；月初 1 日和每年 1 月 1 日起算。
`most_recent_due_boundary_local` 是最近已发生的本地边界（之前的自然周期已结束）；
`next_due_boundary_local` 是当前自然周期结束时的下一个候选到期点。
`current_period` 与 `last_closed_period` 给出项目日历中的时期起点、下期日历日期和带数字 UTC offset 的本地时间及真实经过秒数（历史 IANA LMT 允许带秒偏移，例如 `+00:19:32`）。
`last_closed_period` 始终是真实存在的最近一个完整自然周期；若历史时区曾跳过整个本地日，则不会把不存在的日当作一份虚构报告。

**没有跨越 EC192 范围：** 本轮不输出/持久化规范自然周期 ID、跨时区 UTC 左闭右开区间 ID 或 ISO 周编号的 canonical serialization；`elapsed_seconds` 仅是两个真实本地边界对应的时间差。EC192 的可交换期间标识和 UTC 区间序列化仍为 `PLANNED`。

## 2. 确切调用

```python
from due_calendar import DueCalendar

calculator = DueCalendar()
result = calculator.evaluate(
    project_timezone='America/Los_Angeles',
    cadence='day',
    observed_at='2026-10-23T12:00:00Z',
    last_processed_boundary='2026-10-22T07:00:00Z',
)
assert result['decision']['state'] == 'DUE'
assert result['calendar']['most_recent_due_boundary_local'] == '2026-10-23T00:00:00-07:00'
```

模块位于 `construction/` 下；可用 `PYTHONPATH=construction python your_program.py`，
或从 `ces/construction/` 直接导入。`observed_at` 可为有明确 `Z` / `±HH:MM`
offset 的 RFC3339 秒级时间戳（最多微秒小数）或 Python aware `datetime`；省略时仅调用内部 UTC aware clock，**不**读宿主本地时区。项目 `project_timezone` 必需且大小写精确，支持 `UTC` 与明确的多段 IANA zone（如 `Asia/Shanghai`, `Europe/Berlin`），拒绝 `CST`, `PST`, `EST`, `GMT`、`Etc/GMT+8` 这种易混淆缩写/反号表示和未经识别的 IANA 名。对非 `UTC` 的地区时区，容器/宿主必须提供可用的 IANA tzdb；单独指定 `UTC` 则使用内置固定零偏移，不需要 tzdb。地区时区缺库绝不悄悄改用系统本地时间。

`last_processed_boundary` 是**最近被成功处理的到期事件本身的边界时间**（UTC 或带明确 offset 的 instant），不是报告生成完毕/发出的时间。它必须严格等于某个已发生的该时区/频率的自然周期边界，且不晚于当前最近可处理的 boundary；非日历边界和未来边界均拒绝。这个值应该来自独立、可靠的外部事务状态，但 EC191 **既不加载也不认证**此状态。调用者要负责把处理行为与持久化确认原子绑定，避免并发重复发报告。

| 处理历史 | `decision.state` | `is_due` | 解释 |
|---|---|---|---|
| 没有历史信息 | `UNKNOWN` | `null` | 不擅自假定用户以前没处理 |
| 明确 `never_processed=True` 且无边界 | `DUE` | `true` | 调用者声明未处理；本库无法核验 |
| 处理边界等于本次最近候选 boundary | `NOT_DUE` | `false` | 此次候选到期事项已被调用方声明处理 |
| 处理边界等于上一真实自然周期边界 | `DUE` | `true` | 最新一个周期可处理 |
| 处理边界更早 | `OVERDUE` | `true` | 至少连续两个到期事件没有被声明处理 |

一个示例：洛杉矶 `2026-10-23T12:00:00Z` 本地 05:00，当前日为 10 月 23 日、最近关闭的日期为 10 月 22 日，最新 boundary 本地 10 月 23 日 00:00（`2026-10-23T07:00:00Z`）。上次声明处理的 boundary 若为本地 10 月 22 日 00:00，则此刻 `DUE`；若是 10 月 21 日 00:00，则是 `OVERDUE`；若等于 10 月 23 日 00:00，则 `NOT_DUE`。一个 `observed_at` 如果早于项目日期的自然边界，只会归属前一个项目日期，不会按 UTC 机器日期强行切期。

## 3. 时钟跳变及确定性

- **DST 春季跳时**：美国纽约 2026-03-08 自然日只有 23 个真实小时；冬季回拨 2026-11-01 有 25 个小时；澳大利亚 Lord Howe 跳 30 分钟，相关日期是 23.5/24.5 小时。
- **午夜不存在**：如智利 2018-08-12 午夜跳到 01:00，会从 gap 后首个真实时刻算起，不会直接将不存在的 `00:00` 贴上 `tzinfo`。
- **午夜重复**：两次发生的 `00:00` 选**时间线上较早的真实午夜**，禁止用较晚一次的重复午夜作为处理边界。
- **跨年/闰年**：ISO 周始终取本地周一（如 2021-01-01 所属周从 2020-12-28 开始）；月、年通过真实年月日推算，禁止 `30*86400` 或 `365*86400` 简化。
- **被整天跳过**：例如 Apia 2011-12-30，本地日历从 12 月 29 日跳到 12 月 31 日；不创建空日的虚假报告。受 Python `datetime` 有限年份约束，在极端年份无法形成完整前后边界会 fail closed。

**环境真实性界限：** 对一个固定 tzdb 版本及输入，计算可重现；运行环境的 `zoneinfo` OS/`tzdata` 版本**没有**在本产物固定。不同版本的历史或未来法定时区规则可能不同，要求严格复现时应由实际运行宿主固定并记录 tzdb 版本；不能因 fixture 在某一个本地 tzdb 成功而证明跨系统一致。历史时间戳/处理边界是调用者提供的外部声明，本模块没有可信授时、外部 ledger 授权或过去调用的 HMAC 凭据。

## 4. 返回契约和失败行为

严格响应结构见 [`project-due-calendar-result.v1.schema.json`](project-due-calendar-result.v1.schema.json)。有效计算返回 `partial/2`（**日历计算已执行，但不等于报告运行/持久化事件已证实**），有处理历史才给可执行的 `DUE|OVERDUE|NOT_DUE`；没有历史给 `UNKNOWN`。

所有非法的缩写时区、无 offset 时间、未知频率、矛盾历史、不是周期边界的确认和日期上溢都以 `invalid_input/4` 且 `calendar=null` 拒绝；缺失 tzdb、可信 UTC 时钟失败、无法解析真实午夜等返回 `unavailable/5`。错误不包含用户时区字符串或主机路径，保留可机读的 `DUE_...` 错误码。`limitations` 的六个证明位一律为 `false`，禁止将本组件结果解释为定时程序已安装、ReportPrepare 已出报告、外部业务主体已确认或原生 CLI Action 已注册。

## 5. 本轮运行与最后验收

EC191 执行了 `cd ces/construction && python -m unittest -q test_due_calendar`，34 个聚焦 Python 开发场景通过，使用当时容器安装的 IANA tzdb 和 Draft2020-12 JSON Schema。另有 `python -m py_compile` 和工程计划/文件清单轻量检查。此类本地开发测试**不等于**系统联合验收、时区库跨平台版本一致性验收或原生 Due CLI 测试。以下留待最后用户辅助统一测试：Windows/macOS/Linux 时区数据库来源和版本；历史/法令新时区边界；有权限且事务性的多进程处理记录、并发/崩溃重试；用户真实项目配置；PowerShell7 原15套 Smoke、业务报表/定时/邮件完整流、E63–E66 性能以及历史 V3.10/ROUNDS B-001 缺口。
