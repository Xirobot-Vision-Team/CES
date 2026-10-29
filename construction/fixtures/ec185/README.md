# EC185 focused synthetic developer fixtures — not release acceptance

The executable fixtures are constructed by [`test_quality_observation.py`](../../test_quality_observation.py) using the **real EC181–EC184 Python modules**, synthetic GitHub/GitLab transports from the preceding tests, temporary POSIX WorkingTree fixtures and independent per-scope callback gates.

29 checked scenarios cover local/remote/both sources, GH/GL and PR mode, exact selected job log and missing/zero/unparseable tests, GitLab job-exact coverage and JUnit disagreement, GitHub workflow/run-level JUnit conflicting with job log, hashed reproducible report selectors without path or signed URL disclosure, every essential permission opt-in and final revoke, source/CI tampering and drift, local file content mutation between rechecks, falsified provider fields/counts/proof despite recomputed non-authenticating digests, strict Draft2020-12 schema rejecting fake performance, benchmark, attested actor, source equivalence and top-level pass.

Run a focused developer check only if needed:

```sh
cd ces/construction
python -m unittest test_quality_observation -q
```

**NOT_RUN:** actual provider network/TLS tokens and signed redirects; real CI runner, log trust or human identity; authenticated Git object bytes; native PowerShell7+original 15 Smoke; Windows/macOS; original E63–E66 performance; full-system joint user-assisted acceptance. Do not count synthetic checks as an executed CI test or benchmark observation of user code.
