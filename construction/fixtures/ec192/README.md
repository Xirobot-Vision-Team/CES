# EC192 focused natural-period fixtures (development only)

`construction/test_natural_period.py` invokes the actual `NaturalPeriod` API and validates
all responses against Draft2020-12 `references/natural-period-result.v1.schema.json`.
No fabricated provider, Git or report execution receipts are included.

Representative real-zoneinfo examples: ISO week `2020-W53` across the year 2020/2021,
New York 23-hour spring-forward and 25-hour fall-back days, Havana folded 00:00,
Santiago's missing 00:00, Lord Howe's 30-minute DST, Samoa's nonexistent
2011-12-30, Amsterdam historical offset seconds, leap February/year,
canonical JSON round-trip, interval drift/tamper refusal, same-lane ordering
and safe denials for invalid timestamps, zones, labels and mixed lanes.

The current platform's IANA timezone database determines test expectations.
A test PASS does **not** authenticate that tzdb release or verify production
project settings, scheduler, real reports, native PowerShell or cross-OS results.
