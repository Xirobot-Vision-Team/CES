# EC183 — CI / independent source SHA association (standalone read-only Python)

**Actual entry:** `construction/quality_sha_bind.py`, `SourceSelection` and `QualitySHABinder.bind`. Strict returned envelope: [`quality-sha-bind-result.v1.schema.json`](quality-sha-bind-result.v1.schema.json). This is **not** a native `QualityReadCI` PowerShell CLI route.

## Supported and unsupported source identities

- **`DeliveredTarget`:** bind one current remote named branch tip to **the same immutable Provider numeric repository/project ID** and exact 40-hex Git SHA recorded in the earlier EC182 run and in a fresh authorized EC182 observation. It is a *provider repository branch-toplevel commit at the instant of the observations*, not verified deployment or actual business working tree.
- **`ProposedPR`:** bind one specifically numbered **open** GitHub PR or GitLab MR **from the same repository** to its selected head SHA; require exact source/target numeric repository IDs, branch, immutable PR/MR object ID, fresh open state and exact head SHA. For GitLab, also require `diff_refs.head_sha == MR.sha`; recheck both proposal and branch. A fork would require a separate authorized immutable source repository identity and is **refused**, never misbound to the target repository. A PR/MR **merge-ref CI run** whose SHA differs from actual head is also refused, never silently equated.
- `WorkingTree`, deployed/released artifacts, fork proposals and arbitrary local Git roots are **not supported by this remote-only source reader**. A local or deployed checkout needs independent ownership, tree and cleanliness/target attestation that EC183 does not provide. Refusal is `invalid_input/4` or `unavailable/5` without retained source association.

## Execution and permissions

1. Produce an **actual EC182** `ces.quality_read_ci.v1` `partial/2` receipt (prior output JSON, not a fabricated SHA label). Choose the same `CISelection` project/run/attempt/job/branch/commit and one **explicit** `SourceSelection(mode, proposal_number, receipt_max_age_seconds)`; receipt age must be 60–900 seconds, default 300. EC182 CI age budget still applies. The SHA-256 in EC182 is *unkeyed integrity/drift detection, not a Provider or actor signature*.
2. Authorize **four distinct opt-ins**: `allow_network`, `allow_ci_read`, `allow_receipt_reuse` and `allow_source_read`. Pass separate out-of-band **CI and source credentials** and two truly independent project-scoped `authorize_ci` / `authorize_source` callbacks. The callbacks receive the numeric project, SHA, branch, attempt, job, mode, exact proposal, operation and per-endpoint `read_kind`. No consent is inferred from EC181 config, a previous CI grant or a caller-supplied receipt. Real network use requires grants for each GET **and finalization**; a local CLI switch is an operator declaration only, not a verified user identity.
3. Validate all original EC182 fields, version/coverage/provenance/hash and short-lived timestamp **before source network activity**. First read source project identity, branch and (if requested) PR/MR, then the commit metadata endpoint. Re-run **actual `QualityCIReader.read`** under new opt-ins and grants, including its run/attempt/job rechecks. A changed CI conclusion, work identity, run timestamp, job/attempt or SHA revokes the candidate binding. After CI, re-read the source proposal, branch and project identity; any drift fails closed, with no leaked half-bound data. Recheck both grant callbacks just before emission.
4. Every source call is TLS `GET` to a fixed GitHub or GitLab API host, no redirects, ambient proxies or retries; response JSON ≤256 KiB and no duplicate JSON keys, at most **5 source GETs (branch) or 7 (PR)** plus **3–5 EC182 GETs**, ≤8 seconds/request, combined deadline ≤70 seconds. A Provider commit-metadata SHA is checked, **not downloaded raw Git object bytes or locally rehashed**. Existing source may mutate after final recheck; cross-GET atomic snapshots are **not** claimed.
5. A real authorized metadata-only match returns `partial/2` with `association_level=PROVIDER_SOURCE_CI_METADATA_ASSOCIATED`, exact expected source/CI SHA, separately scoped provenance, unkeyed association SHA256 and the explicit negatives: `git_object_bytes_hashed=false`, `working_tree_verified=false`, `tests_executed_by_ces=false`. It does not prove CI actually ran claimed tests, who started it, Git object content, deployment, global PASS, or a complete quality assessment. GH/GL CI failure can still be *associated*; it is not a success claim.

### Callable API

```python
from quality_read_ci import CISelection
from quality_sha_bind import SourceSelection, QualitySHABinder

selection = SourceSelection(
    CISelection('github', 'owner/repo', 1234, 99, 9001, 2, 7001,
                'main', 'a' * 40, 3600),
    mode='DeliveredTarget', proposal_number=None,
    receipt_max_age_seconds=300)

result = QualitySHABinder().bind(
    selection, ci_receipt=previous_actual_ec182_response,
    source_credential=source_token, ci_credential=ci_token,
    allow_network=True, allow_ci_read=True,
    allow_receipt_reuse=True, allow_source_read=True,
    authorize_source=operator_project_source_policy,
    authorize_ci=operator_project_ci_policy)
# Output is a bounded association declaration, never a test PASS.
```

For a standalone CLI, call `python construction/quality_sha_bind.py --help`. Supply `--receipt path.json`, all exact CI identity arguments, `--source-mode DeliveredTarget` or `--source-mode ProposedPR --proposal-number N`, `--allow-network --allow-ci-read --allow-receipt-reuse --allow-source-read`. The real CLI reads `CES_SOURCE_GITHUB_TOKEN` or `CES_SOURCE_GITLAB_TOKEN` **and separately** the EC182 `CES_QUALITY_GITHUB_TOKEN` / `CES_QUALITY_GITLAB_TOKEN` from the environment; never use tokens in command-line arguments or printed JSON. CLI callback only reflects operator declaration: embedding applications must implement their own authenticated authorization and auditing.

### Development vs live data

Custom injected transports yield `SYNTHETIC`. Production default **refuses** synthetic receipts and transports; `allow_synthetic_development=True` explicitly permits synthetic-only scenarios in tests, with `coverage.ci_source_sha_associated=false`, zero live GETs and `SYNTHETIC_EQUALITY_ONLY` even after structural success. Synthetic and live transports/receipts cannot be mixed. Never relabel fixture data as live by changing a JSON flag. `partial/2` is never a quality PASS or native CLI success.

**Deferred final acceptance:** real GitHub/GitLab tokens, true repo ownership and ACLs, DNS/TLS/network faults, concurrent PR/branch/CI reruns, fork/merge tests, multi-OS and hostile Provider schema cases, native PowerShell7 + 15 Smoke, real checkout/commit object hash, EC184 logs/coverage, EC186+ safe test runner, resource/performance and final joint human acceptance remain **NOT_RUN**. No CES metadata store, business file, Git, Issue or remote record is written in this module.

Provider references: [GitHub branch Git ref](https://docs.github.com/en/rest/git/refs), [GitHub pull](https://docs.github.com/en/rest/pulls/pulls), [GitHub commit object](https://docs.github.com/en/rest/git/commits), [GitLab branches](https://docs.gitlab.com/api/branches/), [GitLab merge requests](https://docs.gitlab.com/api/merge_requests/), [GitLab commits](https://docs.gitlab.com/api/commits/).
