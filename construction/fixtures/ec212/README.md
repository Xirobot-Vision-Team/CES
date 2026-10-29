# EC212 local synthetic-only fixtures

EC212 deliberately reuses **EC211** isolated fake GitHub/GitLab repository/issue
JSON objects from `../ec211/` in the new `test_issue_sync.py` transport.
No provider credentials, real Issue IDs, transport logs, private data or
persistent cache are included. Positive results are `SYNTHETIC_OBSERVED`.
EC212 has no stored issue snapshots: this directory is descriptive only.
