# EC182 scoped synthetic-only test corpus

`construction/test_quality_read_ci.py` embeds bounded fake GitHub and GitLab metadata objects. `FakeTransport` returns locally constructed dictionaries, *not* captured Provider data or secrets. Any positive result is always labelled `SYNTHETIC/NOT_PROVEN_SYNTHETIC` and remains `partial/2`.

Covers project-path and immutable ID comparisons; GH workflow/run/attempt/selected job and GH 100-item page boundaries; GL project/pipeline/job independent IDs; branch/commit field equality; final statuses, allow_failure, freshness, timestamp drift, token presence, per-endpoint callback denial, JSON parsing limits and no-redirect transport allowlisting. All live Provider token/API scenarios are deferred to final assisted acceptance.
