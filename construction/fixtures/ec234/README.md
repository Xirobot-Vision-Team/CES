# EC234 development fixtures (synthetic only)

The focused test methods in `construction/test_cycle_budget.py` create real,
short-lived EC231 0700/0600 local metadata records with **synthetic** input
bytes and declared actors/Actions. They read actual EC232/EC233 standalone
Python and existing original handler SOURCE for provenance, but never run
PowerShell or an AI provider, authenticate a user or enable native Cycle.

Scenarios include single- and multi-root records, cyclic DAG, unsupported
and CodeSave/AI routes, monotonic wall/process CPU deadline observations,
sliding-window rate exhaustion, step-inspection admissions, exact cumulative
ASCII JSON output bytes (including trailing newline), diagnostic byte
accounting, insufficient output budget -> ZERO bytes, source-record drift,
independent pin refusal, invalid budget overrides and same-object threaded
admission, embedded Draft2020-12 schema positive/negative variants and CLI.

No corporate credentials, external endpoints, user repositories, genuine
execution results or historical attestation are embedded. Tests are local
development exercises, NOT PowerShell/15 Smoke/OS watchdog/cross-process/
production-host acceptance. Runtime metadata and legacy PowerShell remain
unchanged.
