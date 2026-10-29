# CES Engineering Suite

[简体中文](README.md) · English

CES is a source-bound assistant workflow for repository reports, code Issues,
maintained knowledge documents and opt-in project test review. The assistant
reads real source and writes analysis; CES collects, binds, checks, archives
and publishes that evidence. It does not autonomously infer defects from a
passing build or produce new reasoning merely by formatting a report.

## Capabilities

- Daily and period reports with explicit coverage and source citations.
- Deep code-Issue proposals, author attribution, deduplication and tracking.
- Incremental knowledge and manifest-owned documentation publication.
- Project test contracts, structured results, evidence-bound report analysis.
- Explicit function/feature developer registration and failure-report CC routing.
- GitHub mentions and assignments with durable send/readback receipts.

Every repository, command, account and recipient comes from an external profile.
Execution, test runs, publication and scheduling are off by default. GitHub
notification mail remains subject to recipient settings.

## Quick start

Requirements: Python 3.12+ and Git. PowerShell 7 is needed by native source
collection even when the operator runs under Linux. Optional legacy POSIX
features have additional requirements; see [installation](docs/INSTALLATION.md).

```text
python -m venv .venv
# Windows:
.venv\Scripts\python.exe -B operator/ces_product.py --help
# Linux/macOS with the appropriate dependencies installed:
.venv/bin/python -B operator/ces_product.py --help
python -B -m unittest discover -s operator -p "test_*.py"
python -B tools/release_check.py
```

Copy operator/profile.example.json **outside** this repository, fill actual
paths/account IDs and leave write/execute flags disabled until authorized. Run
`doctor --config <profile>` to inspect the configured scope. The Python CLI,
Windows `ces-product.cmd` and `sh ./ces-product` refer to the same operator.

## Documentation

- [Installation and supported scope](docs/INSTALLATION.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Product guide](docs/PRODUCT_GUIDE.md)
- [Testing and ownership registration](docs/TESTING.md)
- [Notifications and delivery limits](docs/NOTIFICATIONS.md)
- [Development](docs/DEVELOPMENT.md) and [contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md) and [threat model](docs/SECURITY_MODEL.md)
- [Known limitations](docs/KNOWN_ISSUES.md)

The maintained operator version is in PRODUCT.json; VERSION retains the legacy
1.0 protocol identity. Current source checks are local consistency checks, not
certification, production acceptance or proof all legacy features work. CI uses
isolated fixtures and no live project credentials.

Licensed under Apache-2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and
[third-party information](THIRD_PARTY.md).

Release preparation: **1.8.0**. See [cleanup and release scope](docs/CLEANUP.md).
