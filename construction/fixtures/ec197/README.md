# EC197 fixtures / focused replay harness

[`test_report_prepare.py`](../../test_report_prepare.py) programmatically creates real **EC192 NaturalPeriod → EC193 RepositoryReportSubject → EC194 ActorReportSubject → EC195 CrossRepositoryReportScope → EC196 ReportEvidenceMetrics** offline synthetic canonical inputs and a distinct per-repository metadata-release policy for EC197. No fixtures with raw credentials, source code, personal activity logs, emails or approved real user data are bundled.

The test suite covers: whole-set read/export permissions, unique independent per-repository receipts, source/people/scope/metrics/period pins, allowlisted channels and evidence IDs, redacted `cesrc1` citations, empty/withheld/partial coverage, unverified/conflicting/withheld CI, ProposedPR, actor-linked export refusal even with EC194 witness, privacy-closed policy keys, canonical sorting and full original-input replay. Both positive and denial envelopes pass strict Draft2020-12 validation. Hashes and approval receipts are synthetic claims, not trustworthy signatures. Egress and actual AI execution are intentionally not exercised.

Run from `ces/construction` when a local Python + `jsonschema` install exists:

```shell
python -m unittest -q test_report_prepare
```

Native PowerShell7/15 original Smoke, remote identities/grant receipts/Git/CI, cross-OS, time-zone database drift, final full assisted acceptance and original historical B-001 evidence remain **NOT_RUN / OPEN**.
