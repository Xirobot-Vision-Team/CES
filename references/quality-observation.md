# EC185 — Quality observation envelope (`ces.quality_observation.v1`)

**V4.95/R185, independent Python-only read/compose.** Entry: [`construction/quality_observation.py`](../construction/quality_observation.py), `QualityObservation.collect`. Result schema: [`quality-observation-result.v1.schema.json`](quality-observation-result.v1.schema.json). It is **not** native PowerShell `QualityReadCI`, `QualityRun`, or `QualityShow`. It neither executes tests nor measures benchmarks. Every positive output is `status=partial`, `exit_code=2`, even if `observations.tests.classification="pass"`.

## Input and genuine adapter chain

Select at least one track; do not manufacture a successful receipt by filling output JSON. The **optional local** track is `LocalConfigSelection(repo_root, source_pin, candidate_paths)` and is observed by **the actual EC181** `QualityDetector.detect`, using its own recent `observe_root` pin, strict POSIX nofollow path checks and independently trusted per-root/per-file authorization callbacks. If remote is also selected, it runs twice on either side of remote reads and aborts if selected configuration observations drift. Stat-only files are **not content-reverified** and the repository is not wholly enumerated.

The **optional remote** track is `quality_sha_bind.SourceSelection(CISelection(...), mode='DeliveredTarget' or 'ProposedPR', proposal_number=...)` plus **complete, recent** EC182 `ci_receipt` and EC183 `association_receipt` objects, and EC184 `ReportSelection`. `collect` genuinely calls `QualityCIEvidence.read`; EC184 in turn validates the two original receipts, re-runs the genuine EC183 association before and after reading bounded selected job log/reports, independently re-reads EC182 provider run/job/source metadata and checks for drift, and enforces per-endpoint host grants. No supplied hashes are trusted as signatures. A forged hash does not grant network access or source authority.

For both tracks, three separate layers of explicit consent matter: (a) `allow_compose=True` and a trusted `authorize_compose` callback authorizing both `BEFORE_READ` and `FINALIZE`, (b) track-specific opt-ins and independent per-root/per-path or source/CI/content callbacks, and (c) real host policy and owner-provisioned credentials for live remote reads. **Never replace scope-policy callbacks with unconditional `lambda _: True` in production.** Development transport injection must be explicitly `allow_synthetic_development=True` and is always labeled `SYNTHETIC`.

```python
# Run with ces/construction on PYTHONPATH; example assumes all receipts,
# selections, credentials and trusted callbacks were obtained by the host.
from quality_observation import QualityObservation, LocalConfigSelection
from quality_ci_evidence import ReportSelection

observer = QualityObservation()
observation = observer.collect(
    local=LocalConfigSelection(repo_root, pinned_local_root,
                               ['pyproject.toml', 'pytest.ini']),
    remote=selected_ci_source,  # sha.SourceSelection with exact CISelection
    report=ReportSelection(kind='coverage_json', gitlab_path='reports/coverage.json'),
    ci_receipt=previous_ec182_result,
    association_receipt=previous_ec183_result,
    ci_credential=ci_token, source_credential=source_token,
    allow_compose=True, allow_local_config=True,
    allow_remote_ci_evidence=True,
    allow_network=True, allow_ci_recheck=True,
    allow_source_recheck=True, allow_receipt_reuse=True,
    allow_job_log=True, allow_report=True,
    authorize_compose=trusted_compose_gate,
    authorize_local_source=trusted_local_source_gate,
    authorize_local_path=trusted_local_path_gate,
    authorize_ci=trusted_ci_gate, authorize_source=trusted_remote_source_gate,
    authorize_content=trusted_content_gate)
```

For **local-only**, omit all remote selection/receipts/report/credentials and keep every remote opt-in at the default `False`; use `allow_compose=True`, `allow_local_config=True` plus the three relevant host callbacks. For **remote-only**, omit local and use `allow_compose=True`, `allow_remote_ci_evidence=True` with its network+CI/source/receipt/job log independent opt-ins, callbacks and credentials. The no-report case uses `report=ReportSelection()` or omits it with `allow_report=False`.

There is deliberately no `--approve-all` convenience CLI: the host must supply actual scope-granting callbacks and appropriate credentials and must not silently grant itself access.

## Versioned result and meanings

| Member | Meaning | Strict limitation |
|---|---|---|
| `source.local` and `observations.local_config` | `WorkingTree` root pin, time, allowlisted config counts and static language/tool/profile descriptors | Independent of remote SHA; no repo-wide inventory or test execution |
| `source.remote` and `observations.ci_metadata` | Exact provider/project/branch/SHA/run/attempt/job field claims, source mode, API version and observed times | Fresh provider metadata **association**, not an independently hashed Git object, authenticated human/runner or atomic provider snapshot |
| `observations.tests` | `missing / not_run / partial / fail / pass` **parsed claim**, `total/passed/failed/skipped` if complete and sourced; JUnit-vs-log disagreements retained | A parsed `pass` is never CES-executed or independently verified PASS; GitHub workflow artifact is **run-level only** |
| `observations.coverage` | Provider coverage report `lines_total`, `lines_covered`, `percent` only if safe parser returns `measured`; envelope relabels this `provider_reported` | No standalone verified coverage measurement; GitHub artifact job provenance cannot be inferred |
| `observations.performance` | Fixed `state=not_measured`, `benchmark_samples=0`, `metrics=[]`, no runtime, hardware or baseline | A CI job duration, parser rate or arbitrary log text must never be promoted to measured performance |
| `evidence_refs` | Ordered kinds plus content/receipt `sha256`, domain-separated `selector_sha256`, available byte counts, scope, transport and exact observed times | Hashes only support reproducibility/checking with retained authorized inputs; **not** signatures or provider/actor identity proof. Path and signed URLs are intentionally absent |
| `execution_environment` | Real *collector-process* Python version and platform strings (unattested), explicitly unknown CI runner/actor/OS/image and tools | Collector != CI environment; runner/actor and installed tools remain unverified |
| `grants`, `proof`, `effects` | Distinct compose/local/CI transport permissions, negative proof flags, bounded read counts, zero command/write/test/benchmark effects | Callback-approved access != attested human identity; even full reads are `partial/2` |

`observation_sha256 = SHA256("CES-EC185-QUALITY-OBSERVATION-v1\\0" || canonical_JSON(payload))` is a **non-authenticating** digest of `observed_at_utc, source, observations, evidence_refs, execution_environment, grants, proof`. Similarly, `selector_sha256` includes the exact selected scope; report selections are hashed rather than returning their path, signed URL, or token. Retain the original scoped selection and receipts privately to reproduce a reference. There is no implicit privilege or automatic future QualityRun/Show interpretation of these hashes.

All evidence must be bounded and freshly scoped. Maximum aggregate output is 192 KiB, remote evidence receipt 192 KiB, independently checked upstream receipt sizes, EC181 at most 64 explicit paths and 1 MiB parsed config bytes, EC184 at most eight content GETs, optional local re-observation twice, overall 170-second compose window. EC184's stricter per-file/content/network limits still apply. No arbitrary command execution or CES/Git/Issue/Provider/business file writes occur.

## Atomic refusal and disagreement

Every refused operation returns `status=invalid_input/4` or `unavailable/5`, a stable `QUALITYOBSERVATION_*` reason, **null** for `source`, `observations`, `execution_environment`, `grants`, `proof`, `observed_at_utc` and `observation_sha256`, and an empty reference list. No partial successful sub-track leaks if a later read, grant recheck, content parse, observation deadline or source/CI/local drift fails. Request counts on refusal are effect counters, not permission/quality proofs.

The strict Draft 2020-12 contract fixes all benchmark, test/runner, human, Git byte, source-equivalence and atomicity proofs to `false`; forbids top-level `pass` and `success`; and rejects unexpected fields. For GitHub, a workflow/run artifact cannot provide exact job/attempt attribution. A conflicting run artifact's JUnit count is only a *separate* run-scope declaration and does not override the exact job log. A GitLab exact-job JUnit/log disagreement degrades the test classification to `partial`.

## Verification handoff (not production acceptance)

`cd ces/construction && python -m unittest test_quality_observation -q` exercises 29 synthetic development checks using genuine EC181, EC182, EC183 and EC184 implementations with synthetic provider data. No real network, trusted real provider token, native PowerShell7, original 15 Smoke, Windows/macOS/Git/CI-runner/actor authentication, real CI execution or E63–E66 benchmark tests were run. The entire real/user-assisted acceptance remains **NOT_RUN** and will be reviewed after planned implementation completes.
