# Contributing to CES

Bug reports, documentation improvements and focused pull requests are welcome.
Before contributing, read [architecture](docs/ARCHITECTURE.md), [security](SECURITY.md)
and [development](docs/DEVELOPMENT.md).

## Start locally

Use Python 3.12+, Git and PowerShell 7 for native evidence collection. The
operator regression suite uses the Python standard library and disposable
fixtures; it needs no GitHub credentials or access to a real project.

```text
python -B -m unittest discover -s operator -p "test_*.py"
python -B tools/release_check.py
```

## Review expectations

- Keep repository names, developer accounts, absolute installation paths and
  project commands out of general implementation. Use external profiles.
- Add behavioral regression tests for changed execution, publication, attribution
  or result-validation boundaries. Do not create real Issues to test the product.
- Preserve durable send ledgers and unknown-POST protection. Tests must not
  contact live GitHub, run project software or use real credentials.
- Keep execution opt-in, preserve member edits and distinguish observations from
  inferred root causes. A passing build is not runtime or fix verification.
- Preserve protocol schemas, hash domains and compatibility imports. Explain
  deliberate changes to the protected legacy implementation and its tests.
- Use synthetic examples. Do not submit project profiles, log dumps, personal
  directories, notification receipts, private repository names or datasets.

Describe the problem, final behavior, tests run and remaining limits in a PR.
The delegated AI maintainer reviews changes before merging; see
[GOVERNANCE.md](GOVERNANCE.md) for self-authored PR review and CI requirements.

## License and contributions

Contributions intentionally submitted for inclusion are under Apache-2.0 unless
explicitly stated otherwise and agreed by the maintainers. Only submit material
you have the right to contribute. Preserve any existing attribution and identify
third-party material and its license. See LICENSE for the governing terms.
