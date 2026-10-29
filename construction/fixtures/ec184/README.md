# EC184 synthetic focused fixture evidence — no live CI or native acceptance

Source: [`test_quality_ci_evidence.py`](../../test_quality_ci_evidence.py) and retained EC182 / EC183 synthetic provider adapters. **34 focused local synthetic checks** ran in construction; this is NOT authenticated provider, native PowerShell or final production test evidence.

- GitHub Actions job log API **302** then allowlisted signed Azure download, credentials **never** forwarded; GitLab selected job direct trace. TAP13/pytest complete/failed/skipped/ambiguous, missing log, zero-test `not_run`, parser vs provider-conclusion conflict.
- GitLab **job-specific** JUnit (including distinct error vs failure counts), Coverage.py JSON, Cobertura XML with declared-counter verification. Mismatched report vs log falls back to `partial`.
- GitHub workflow artifact metadata, run/SHA/branch/numeric repository association, optional digest, signed archive URL, single ZIP entry in memory, pre/post metadata drift. GitHub run-only JUnit does **not** impersonate an exact job/attempt.
- Negative cases for changed source or CI recheck, receipt tampering/age, mismatch/falsely escalated receipt effects, missing scope grant, content size/type, forged signed redirect, malicious ZIP path, duplicate JSON, DTD/XML invalidity, report path/selection, mixed/synthetic permissions.
- All synthetic positive classifications still `status=partial` / exit 2 and synthetic provenance; no actual test executed by CES, and no provider, business, Git, Issue, or local archive write.

Run only the focused development checks when appropriate:

```sh
cd ces/construction
python -m unittest test_quality_ci_evidence -q
```

The strict output contract is [`quality-ci-evidence-result.v1.schema.json`](../../../references/quality-ci-evidence-result.v1.schema.json), and operator guidance is [`quality-ci-evidence.md`](../../../references/quality-ci-evidence.md).

**Deferred and not claimed:** real online GH/GL requests and credentials, signed link live behavior, actual CI reporters/runner integrity, native PowerShell7 and original 15 Smoke, Windows/macOS/Git, E63–66 scale/performance and final full-system user-assisted acceptance.
