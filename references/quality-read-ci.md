# EC182 QualityReadCI — provider metadata read, never test execution

## Scope and precise distinction

The **independent Python** [`construction/quality_read_ci.py`](../construction/quality_read_ci.py) reads exact GitHub Actions workflow-run + **attempt-specific** job metadata or GitLab CI project + pipeline + job metadata over bounded, explicitly authorized HTTPS GET. This is a genuine implementation of CI metadata retrieval—not a source-config inference, not a CLI switch registered in `scripts/ces.ps1`, and not a CES test runner. Native PowerShell `QualityReadCI` remains `NOT_IMPLEMENTED` until the later routing phase (EC241).

Result contract: [`quality-read-ci-result.v1.schema.json`](quality-read-ci-result.v1.schema.json), `schema=ces.quality_read_ci.v1`; **positive is always `partial` / exit `2`**; refusals `invalid_input/4` (malformed selection/opt-ins/credential) or `unavailable/5` (auth denied, unsafe/incomplete/stale/conflicting Provider observation). `observation.run` and `observation.job` report separate CI **provider claims**. A value of `success` cannot be transformed into CES `success/0`, Git state, a deployed commit, or evidence that CES executed tests.

## Identity and authorization

The host or operator must supply **all** selection values; no auto-discovery, ambiguous latest run, arbitrary URLs or config-file credentials:

| Field | GitHub Actions | GitLab CI |
|---|---|---|
| `provider` | `github` | `gitlab` |
| `repository` | `owner/repo` | `group/project` (nested groups supported) |
| `project_id` | **numeric immutable GitHub repository ID** | **numeric immutable GitLab project ID** |
| `workflow_id` | numeric workflow ID, required | `None` |
| `run_id` | numeric **workflow run ID** | numeric **pipeline ID** |
| `attempt` | numeric `run_attempt`, required; exact attempt jobs route | `None`; retry creates a new job ID |
| `job_id` | exact job numeric ID in the requested run attempt | exact job numeric ID within pipeline |
| `branch`, `commit_sha` | exact expected provider branch field and nonzero 40-hex SHA | same, exact API field equality only |
| `max_result_age_seconds` | required 60–2,592,000 seconds | same |

Before any I/O: `allow_network=True` **and** `allow_ci_metadata=True`, a nonempty dedicated CI credential, and an independent callable `authorize(scope)` that explicitly approves each exact provider/project/run/job/branch/sha and `read_kind` (plus final permission recheck). The callback must be installed by the trusted host, not derived from user-uploaded JSON or the EC181 project's configuration file. An exception/false/revocation is a refusal and the entire candidate observation is discarded. No local git root or EC181 config permission creates a CI read grant. In the standalone CLI, the two opt-in switches represent only **operator assertions**, not an authenticated human or a cryptographically signed host grant; real provider access is separately subject to the token's permissions and the remote HTTPS API.

`StrictHTTPSCITransport` accepts only the fixed `api.github.com` and `gitlab.com` API hosts; it uses TLS verification, HTTP GET, no redirect, no environment proxy, no retry, no shell, no arbitrary configured base URL, an 8-second maximum per GET and 35-second overall deadline. Each response must be JSON, strict UTF-8 with no duplicate keys/nonfinite numeric values, up to 1 MiB. GitHub allows up to 3 full pages of 100 attempt jobs; page sizes/counts/duplicate IDs/identity must be internally consistent. A bigger or drifting run is `unavailable`, never silently truncated. Total provider reads ≤5; GitLab reads project→pipeline→job→pipeline recheck. GitHub reads run→attempt jobs (1–3 pages)→run recheck.

`HTTPS_200_TOKEN_PRESENT` means exactly that the fixed TLS endpoint responded to a GET with a token present; **not** that the user's subject, credential privileges outside the requested GET, actor identity, CI authenticity beyond the provider response, or current local Git was attested. The output has no token, source code, command lines, logs, artifacts, runner identity or unbounded provider JSON. Output SHA-256 is a deterministic tamper-evident *digest*, **not a Provider signature**. An injected transport used for unit tests is labelled `SYNTHETIC` / `NOT_PROVEN_SYNTHETIC` and cannot be presented as `LIVE_HTTPS` via the public `QualityCIReader(transport=...)` API.

## Programmatic example — replace host callback with real policy

```python
from construction.quality_read_ci import CISelection, QualityCIReader

selection = CISelection(
    provider='github', repository='OWNER/REPO', project_id=123456,
    workflow_id=789, run_id=12345678, attempt=1, job_id=987654,
    branch='main', commit_sha='a' * 40,
    max_result_age_seconds=3600,
)

def authorized_by_host(facts):
    # Example only. Implement this in the trusted host by exact identity/route
    # with its own per-resource authorization source, and return True only when
    # that host policy independently allows the described metadata read.
    return False

result = QualityCIReader().read(
    selection, credential=None, allow_network=False,
    allow_ci_metadata=False, authorize=authorized_by_host,
)
# By design, this example refuses: it does NOT contact a real provider.
```

To use actual remote CI with the API, the trusted host passes a credential from its own secret manager, both opt-ins and a grant callback bound to the exact scope. **Never** send a secret in command-line arguments or a source repo file.

## CLI example (manual, live only with explicit grant)

The CLI reads `CES_QUALITY_GITHUB_TOKEN` or `CES_QUALITY_GITLAB_TOKEN` from its **process environment only**; it does not scan files, `.env`, package scripts, IDE configuration or EC181 inventory. Without both opt-in flags, it emits a single strict refusal JSON and does not open the network. For real GitHub metadata (replace all placeholders with authorized real IDs and the actual 40-character commit), run:

```bash
python construction/quality_read_ci.py \
  --provider github --repository OWNER/REPO --project-id 123456 \
  --workflow-id 789 --run-id 12345678 --attempt 1 --job-id 987654 \
  --branch main --commit-sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --max-result-age-seconds 3600 --allow-network --allow-ci-metadata
```

For GitLab use `--provider gitlab`, `--repository GROUP/PROJECT`, the project ID, pipeline ID and job ID; **omit** `--workflow-id` and `--attempt`. Install a trusted runtime policy in the programmatic integration rather than treating an operator flag as full identity authentication. A read-only API token with the narrowest practical scope is recommended; HTTPS 200 does not prove least-privilege.

## Refusal and provenance rules

- GH exact immutable repository numeric ID + name, workflow ID, run ID, **run_attempt**, head branch/SHA and selected attempt job `run_id`/`head_sha` must agree. Failed, cancelled, skipped, timed-out, queued, stale, partial or ambiguous states are **not** accepted as final job observations, except a **completed failure** is legitimately reported as a provider failure claim.
- GL numeric project ID + full path, pipeline ID/project ID, branch/SHA, job ID and job pipeline/project/commit/ref must match. `allow_failure` is emitted separately and never interpreted as a green job; archived/erased/cancelled, in-progress and unverifiable jobs are rejected.
- Check timestamps and bounded caller-selected age for run updated and job completed; reject future, invalid or reversed timestamps. Re-read the run/pipeline before return and reject changed normalized metadata. This is **not** an atomic cross-request snapshot: races that do not affect the verified fields can exist.
- Missing mandatory field, provider schema/version drift, count >300 GH jobs, mismatched branch/SHA/project/job/attempt or revocation returns a refusal with `source`, `observation`, `coverage` and digest **all null**. Raw response bodies, URLs from the Provider, token and arbitrary error strings are never returned.
- Commit-SHA *field equality* is only against the expected caller selection. EC183 independently proves exact target source/Git association; EC184 handles logs/coverage, EC186+ handles execution, EC241 native CLI routing. None are implemented by EC182.

## Development evidence / final acceptance

Focused [`test_quality_read_ci.py`](../construction/test_quality_read_ci.py) uses **fully synthetic** GH/GL responses and an injected transport. These tests can validate branch identity, bounded paging, drift refusal, permissions and stable JSON, **not** remote token validity, actual GitHub/GitLab CI, real repository ownership, production OS/network policies, origin veracity, native PowerShell/Smoke, execution runners, E63–E66 or end-to-end permissions. All those require final user-assisted acceptance and remain `NOT_RUN`. No Git, business tree, Issue, CES record or provider record is ever written by this module.

Official API references: [GitHub run](https://docs.github.com/en/rest/actions/workflow-runs), [GitHub attempt jobs](https://docs.github.com/en/rest/actions/workflow-jobs), [GitLab pipeline](https://docs.gitlab.com/api/pipelines/), [GitLab job](https://docs.gitlab.com/api/jobs/).
