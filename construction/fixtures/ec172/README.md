# EC172 focused offline fixtures

The deterministic fixture constructor lives in `construction/test_task_staging.py` and
reuses `test_handoff_lifecycle.context()` to produce internally coherent synthetic
EC170 WorkingTree / DeliveredTarget output. The local `TemporaryDirectory`
contains only an owner-private staging root and an unrelated fake business
repository with one sentinel file. Nothing here authenticates real business
repository contents, a provider, or an AI invocation.

Coverage: independent init and append approvals; RunId only after real
commit, minimal snapshot and keyed private HMAC; strict parent/repo pin and
source/revision/operation/TTL/actor matching; idempotent new-run retries and
read-only cross-instance reentry; expiry without renewal; file/entry limits;
no-follow ancestry/leaf, nonprivate/overlapping parent, unexpected entries,
hardlinks, HMAC and checkpoint tampering; root drift; two concurrent writers;
forced prepublish race/failed link rollback and fail-closed interrupted
publish; standalone CLI init/start/retry/reenter/inspect; staging a real EC171
session with created handoff. Run tests from `construction/`:

```bash
python -m unittest -q test_task_staging.py
```

This is functional development evidence only. Actual interrupted power, active
OS symlink race under hostile mutation, cross-process crash, Windows/macOS
ACL/reparse/HFS/APFS characteristics, remote AI, native Smoke and final
user-assisted acceptance remain NOT_RUN.
