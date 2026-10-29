# EC184 — bounded CI job logs / reports (read-only GitHub Actions and GitLab CI)

This is a **callable standalone Python adapter**, not registered as the existing PowerShell `QualityReadCI` or `QualityRun` action. Module: [`construction/quality_ci_evidence.py`](../construction/quality_ci_evidence.py), `QualityCIEvidence.read`. Strict JSON Schema 2020-12: [`ces.quality_ci_evidence.v1`](quality-ci-evidence-result.v1.schema.json). This round adds **only EC184** atop the separately approved EC182 metadata reader + EC183 source/CI SHA association. Native CLI still V4.60/R150. A positive response **always has `status=partial`, `exit_code=2`**, even if `classification=pass`. `pass` is a bounded parsed *provider log / report claim*, **not** proof of actual tests, verified runner, actor, Git bytes, current working tree or global CI integrity.

## Scope and real read path

Select an **exact** provider, immutable numeric project/repository ID and canonical repository path, run/pipeline ID, GH workflow ID, GH retry attempt (GitLab attempt `None`), job ID, branch, 40-char SHA, and source mode (`DeliveredTarget` or same-repo `ProposedPR`). Never choose a vague latest run. Take two existing, still-fresh JSON responses:

1. Original **EC182** `ces.quality_read_ci.v1` receipt for exactly that selected run/attempt/job/SHA. It contains an **unkeyed** integrity hash, not a trusted signed fact.
2. Associated **EC183** `ces.quality_sha_bind.v1` positive `partial/2` receipt whose exact selected source/CI and the original EC182 hash match. Its digest, claimed effects, trustworthy boundary flags, age (<=300 s), receipt age/transport and synthetic provenance are strictly checked. Again, the receipt is NOT an authorization token or cryptographic Provider attestation.

Give **six separate explicit switches** as applicable: `allow_network`, `allow_ci_recheck`, `allow_source_recheck`, `allow_receipt_reuse`, `allow_job_log`, and (only with a selected report) `allow_report`. Also supply two **independent credential strings** and three **independent trusted callbacks**: `authorize_ci`, `authorize_source`, `authorize_content`. Source and CI grants apply on each provider read and final recheck; content grant receives full exact selection and `read_kind`, including the signed-link host+URL digest and finalization. The callback must authenticate the **operator and exact authorization scope** out of band: a flag, receipt or source file does not do that. No auto-requesting broad credentials or ambient provider login.

The reader performs a new real EC183 binder pass **before**, and independently again **after**, the content fetches; each binder pass executes the actual EC182 CI run/job observation and checks source branch, project identity and relevant PR/MR head. Any change/expired receipt/permission refusal rejects without partial data. These are snapshots from distinct HTTPS GETs; there is **no atomic provider-wide snapshot**.

| Content | GitHub Actions | GitLab CI |
|---|---|---|
| Job log | `GET /repos/{owner}/{repo}/actions/jobs/{job_id}/logs`, expect `302` to short-lived signed GitHub/Azure download URL. Follow **exactly one** allowlisted HTTPS redirect with **no API token forwarded**. | `GET /api/v4/projects/{project_id}/jobs/{job_id}/trace` — job-ID scoped direct text response. Untrusted redirect refused. |
| Optional JUnit / coverage | Exact user-selected numeric artifact ID and exact entry path in its ZIP; before/after artifact metadata must identify selected immutable numeric project ID, selected **run ID**, SHA, branch; optional provider `sha256` verified. One safe in-memory ZIP entry extracted, no disk write. **GitHub artifact belongs to the run, not guaranteed to the selected job/attempt**: JUnit cannot substitute for a missing job-scoped log. | Exact safe user-selected artifact file path via `GET /api/v4/projects/{project_id}/jobs/{job_id}/artifacts/{path}`. A result belongs to the selected GitLab **job ID**. Untrusted redirected artifact refused. |
| Report formats | `junit_xml`, `coverage_json` (Coverage.py JSON totals), `cobertura_xml` | same |

Parsers recognize unambiguous **TAP 13** plans/results and **pytest terminal summaries** from logs; strict **JUnit XML** testcase counts with separate failure/error/skip counters; **Coverage.py JSON** total/covered/missing/percentage consistency and **Cobertura XML** line totals/rates. Unsupported formats/duplicate JSON keys/XML declarations with DTD, malformed data, contradictory counters, multi-summary logs, partial captures or crossed provider job conclusions stay `partial` and must not become a `pass` claim. Raw logs, XML, path names, test case names and token strings are **not returned**. Only source/format/state, numerical counts, byte lengths, SHA-256s and bounded totals leave the parser.

Classification is `missing` (the exact job log absent), `not_run` (an explicit zero-test plan), `partial` (unparsed/incomplete/ambiguous or skipped tests), `fail` (uniquely scoped result reports failures and selected job conclusion is failure) or `pass` (complete uniquely scoped bounded parsed test claim and selected job conclusion is success). For GitLab, a trusted exact-job JUnit report may provide that claim when log is unavailable; for GitHub, run-only artifacts cannot fill this gap. `report_evidence.state` separately distinguishes `not_requested`, `missing`, `partial`, `measured` (coverage), and JUnit `pass/fail/not_run` without upgrading `classification` or overall `status`.

## API example (embedding host, not an authorization shortcut)

```python
from quality_read_ci import CISelection
from quality_sha_bind import SourceSelection
from quality_ci_evidence import QualityCIEvidence, ReportSelection

selection = SourceSelection(
    CISelection('github', 'owner/repo', 1234, 99, 9001, 2, 7001,
                'main', 'a' * 40, 3600),
    mode='DeliveredTarget', proposal_number=None,
    receipt_max_age_seconds=300)

# The callbacks must be installed by your trusted independent policy layer.
# These names denote host-provided functions, NOT functions generated by a receipt.
result = QualityCIEvidence().read(
    selection,
    report=ReportSelection(kind='coverage_json', github_artifact_id=991,
                           github_entry='reports/coverage.json'),
    ci_receipt=actual_ec182_response,
    association_receipt=actual_ec183_response,
    ci_credential=separate_ci_credential,
    source_credential=separate_source_credential,
    allow_network=True, allow_ci_recheck=True, allow_source_recheck=True,
    allow_receipt_reuse=True, allow_job_log=True, allow_report=True,
    authorize_ci=trusted_ci_scope_policy,
    authorize_source=trusted_source_scope_policy,
    authorize_content=trusted_content_scope_policy)
# Do NOT interpret result['classification'] == 'pass' as an actual runner PASS.
```

A log-only call uses `report=ReportSelection()` and `allow_report=False`.

### CLI (operator mode only)

Pass existing EC182 and EC183 JSON files that actually match the same selection and are still fresh:

```sh
# Set the two independent tokens securely in the invoking environment, not argv.
# CES_QUALITY_GITHUB_TOKEN  / CES_SOURCE_GITHUB_TOKEN for GitHub;
# CES_QUALITY_GITLAB_TOKEN  / CES_SOURCE_GITLAB_TOKEN for GitLab.
python construction/quality_ci_evidence.py \
  --ci-receipt /secure/ci182.json --association-receipt /secure/bind183.json \
  --provider github --repository owner/repo --project-id 1234 \
  --workflow-id 99 --run-id 9001 --attempt 2 --job-id 7001 \
  --branch main --commit-sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --ci-max-age 3600 --source-mode DeliveredTarget \
  --report-kind coverage_json --github-artifact-id 991 \
  --github-report-entry reports/coverage.json \
  --allow-network --allow-ci-recheck --allow-source-recheck \
  --allow-receipt-reuse --allow-job-log --allow-report
```

For GitLab: `--provider gitlab --repository group/project --project-id N --run-id PIPELINE_ID --job-id JOB_ID --branch main --commit-sha ... --source-mode DeliveredTarget --report-kind junit_xml --gitlab-report-path reports/junit.xml`, omit `--workflow-id` and `--attempt`. For GH log-only omit report arguments and `--allow-report`; similarly GL. For `ProposedPR`, include `--proposal-number N` and supply an actually matching EC183 original result. CLI switches are only **operator declarations**: they do not independently authenticate policy/identity; production embedding must wire real host policy. Refusal returns `invalid_input/4` or `unavailable/5`, with no result scope, content or claim.

## Safety and budget contract

- The **content** HTTP transport only uses TLS-verified fixed GitHub/GitLab API endpoints and narrowly allowlisted GH Azure/result download hosts. No ambient proxies, automatic redirects, retries, cookies, shell, arbitrary URL or provider writes; signed URL is opaque, redacted and **only its hash** may enter authorization callback. Signed content fetch sends no source/CI authorization header. GitLab redirects are refused until their host/credential security is separately designed and live checked.
- `MAX_LOG_BYTES=512 KiB`, `MAX_REPORT_BYTES=256 KiB`, GitHub ZIP `<=2 MiB` / expanded `<=1 MiB`, metadata `<=64 KiB`, <=64 safe ZIP entries, <=8 content GETs, <=8 seconds per GET, <=120 seconds total in the EC184 content phase. Stored data never includes raw log or ZIP. ZIP is processed **in memory** with no filesystem extraction, traversal, symlinks, encryption, huge ratios, duplicate case-insensitive names or unsafe compression.
- EC182 and EC183 each impose their **own** source/CI GET/time budgets, and before/after rebinds repeat those reads. Stale/revoked/forged/mixed synthetic-live receipt or recheck drift triggers refusal. A previously emitted SHA digest alone never proves provenance, authorizes a new GET or proves a test ran.
- Custom fake transports require `allow_synthetic_development=True`, return `permission.transport=SYNTHETIC` and `trust_boundary=SYNTHETIC_NO_PROVIDER_PROOF`. Never mix synthetic with live transports/receipts and never cite fixture PASS as real Provider verification.
- **Deferred final acceptance**: live GitHub/GitLab token/ACL and real redirect hosts, endpoint schema/version variations, actual CI log formatting and artifact signatures, branch/CI rerun drift, sustained TLS/DNS/rate limits, native PowerShell7/15 Smoke, Windows/macOS/Git objects, execution by EC186+ safe runner, E63–E66 performance and full combined human acceptance are **NOT_RUN**. Old B-001 frozen upstream spec gap remains OPEN.

Official references: [GitHub jobs](https://docs.github.com/en/rest/actions/workflow-jobs), [GitHub artifacts](https://docs.github.com/en/rest/actions/artifacts), [GitLab jobs](https://docs.gitlab.com/api/jobs/), [GitLab job artifacts](https://docs.gitlab.com/api/job_artifacts/).
