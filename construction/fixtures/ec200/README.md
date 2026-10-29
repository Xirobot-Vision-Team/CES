# EC200 local development fixtures / implementation note

`test_report_history.py` rebuilds original EC192–199 results from existing
synthetic test constructors; it creates only temporary owner-private POSIX
`.ces-report-render-v1` stores and does not include private credentials or
production reports. It validates real immutable bytes and index re-reads,
independent read/Markdown/correction grant declarations, selection by exact
subject/period, five-category comparisons and a redaction change reconstructed
from a *fresh* EC197 release→198 draft→199 render chain. Error cases cover
mutation, stale CAS, replay, symlink and nonprivate storage.

Run from `ces/construction`: `python -m unittest -q test_report_history`.
Successful synthetic results are **not** proof of human approval, live source
integrity, independently executed CI, cross-OS persistence, original native
PowerShell Smoke or production correctness. Final assisted verification is
still deferred until all EC construction rounds are delivered.
