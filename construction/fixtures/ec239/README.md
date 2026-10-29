# EC239 local fixtures and honest scheduler scope

The focus tests in `construction/test_cycle_external_scheduler.py` create real
new EC231 owner-private 0700/0600 Run records with synthetic snapshot bytes,
then exercise the real read-only EC237 Summary route. There is no checked-in
fake scheduler installation, fake cron event record or simulated business
success. Claimed `--trigger-id` and scheduled UTC ticks are **synthetic caller
claims**. Repeated trigger IDs are intentionally **not** deduplicated.

Focus cases: absent host = instructions only, declared configured host = claim
only in plan, actual in-process EC237 read-only inspection on supplied external
trigger, hourly/daily/weekly UTC alignment, missing / invalid / mismatched
inputs and externally supplied SHA pins, unsupported existing action Summary
block, stale/corrupt/nonprivate owner record fail closed, one-line bounded CLI
status and strict Draft2020-12 schema. No actual host recurring scheduler is
created, contacted or independently tested. No CodeSave, AI, delivery,
permission grant, step mutation or external effect.

Final unified acceptance is deferred for real cron/Task Scheduler/orchestrator
wiring and clocks, independently pinned run data, real source/actor/permission,
PowerShell7/15 Smoke, Windows/macOS, NFS/OS failure, EC240 overlap/replay,
EC241 native Cycle and E63–E66. Original B001 remains OPEN.
