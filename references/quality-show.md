# EC188 QualityShow: read-only, exact-source evidence projections

**Delivered in:** CES construction V4.98 / R188 / EC188. **Callable entrypoint:** [`QualityShow.query`](../construction/quality_show.py); **strict result contract:** [`ces.quality_show.v1`](quality-show-result.v1.schema.json). **Development fixtures:** [`test_quality_show.py`](../construction/test_quality_show.py). **Native PowerShell `QualityShow`: NOT_IMPLEMENTED** (PowerShell CLI remains V4.60/R150). The module exposes a standalone Python query, not a new native command, persistence service, quality authority, or trusted CI runner.

## Exact request and trust model

Construct a `QualityShow(cursor_key=HOST_OWNED_SECRET_32_BYTES_OR_MORE, clock=HOST_UTC_CLOCK)` in the trusted **host application**. Do not embed or derive the cursor key from repository source, code paths, local config or query fields; rotate and protect it separately. The host is responsible for storing/obtaining already permitted EC181-187 outputs and granting each source/read operation on every request. No store is included or opened; no source, Git, CI, shell or runner operation is performed by `query`.

Call `query` with the following *named* inputs:

| Argument | Required / allowed | Meaning |
|---|---|---|
| `source_scope` | required exact object | WorkingTree: **only** `{"source_mode":"WorkingTree","root_pin_sha256":"<64 lowercase hex>"}`. DeliveredTarget or ProposedPR: **only** `source_mode`, `provider` (`github`/`gitlab`), `repository` (canonical owner/project path), positive numeric `project_id`, `commit_sha` (40/64 lowercase hex), `proposal_number` (null for DeliveredTarget, positive integer for ProposedPR). | 
| `evidence` | list, 0..96 entries | Each item **exactly** `{"kind": K, "result": ORIGINAL_EC181_187_OUTPUT, "source_scope": EXACT_SAME_SOURCE_SCOPE, "recorded_at_utc": "YYYY-MM-DDTHH:MM:SS[.ffffff]Z"}`. `recorded_at_utc` is a **caller-supplied capture label**, not an authenticated producer observation, run start time or currentness proof. |
| `allow_query`, `allow_evidence_read` | two distinct literal `True` opt-ins | Query authorization and evidence-reading permission are independent. Defaults deny. |
| `authorize_scope` | trusted callable | Called with phase `BEFORE_READ` and `FINALIZE`, exact source and hashed query purpose, must return literal `True` at both points. |
| `authorize_evidence` | trusted callable | Called once for **every** evidence item, including ones excluded by a filter or on a later cursor page. Gets receipt hash, item hash, kind, source, capture label. Must grant the exact item, not broadly the repository. |
| `page_size`, `cursor` | 1..25, default 10; optional opaque continuation string | Deterministic page of currently allowed, exactly source-scoped projections. Do not treat cursor as a grant. |
| `filters` | `kinds`, `classification`, `from_utc`, `until_utc` only | Inclusive time bounds; strict known kinds and classification enumeration, ordered by capture UTC **descending**, then evidence hash **ascending**. Filtered absence is never proof of no evidence. |
| `include_numeric_metrics`, `authorize_numeric_metrics` | defaults `False`, separate exact-scoped callable when enabled | Opt in separately to bounded, provider-declared test counts and coverage line numbers/percentages. A metric remains an unauthenticated claim. |
| `acknowledge_historical_proposal` | literal `True` for `ProposedPR` | ProposedPR source is historical proposal-head evidence **only**, never proof of target branch merge/deploy/current delivery. |

The source and record scopes must match exactly. A locally obtained WorkingTree root pin is **not** a content-addressed repository inventory; a matching remote provider SHA field is **not** an independently computed Git object digest. No caller-supplied link may combine a local root pin and a remote revision as though their bytes are equivalent.

**Host integration sketch** (illustrative: authorization logic and upstream receipt retrieval are intentionally NOT supplied):

```python
from quality_show import QualityShow

viewer = QualityShow(cursor_key=host_key_from_private_credential_store)
result = viewer.query(
    source_scope=the_currently_authorized_exact_scope,
    evidence=the_fully_retrieved_authorized_candidate_receipts,
    allow_query=explicit_query_grant,
    allow_evidence_read=explicit_evidence_read_grant,
    authorize_scope=host_policy.authorize_exact_source_query,
    authorize_evidence=host_policy.authorize_exact_receipt_read,
    page_size=10,
)
# A second page MUST repeat all data, opt-ins and live authorizations,
# and pass cursor=result["next_cursor"].
# Never interpret result["status"] == "partial" as passing tests.
```

## Seven independently typed evidence classes

| `kind` | Origin | What is surfaced | Mandatory uncertainty |
|---|---|---|---|
| `config` | EC181 QualityDetect | Number of selected local config paths; parse gaps | Selected-path discovery only; neither repo-wide nor tests run. Must match exact local root pin. |
| `ci_metadata` | EC182 QualityReadCI | GH/GL declared run/job states and conclusions, and transport class | Metadata fields do not include an explicit ProposedPR/DeliveredTarget mode; query mode is caller selected. `success` is provider text, **not** CES PASS. |
| `sha_binding` | EC183 QualitySHA binding | Matching provider source/CI SHA fields | Field equality does not authenticate Git object bytes or a single atomic snapshot. |
| `ci_evidence` | EC184 QualityCI evidence | Parsed test `pass/fail/partial/missing/not_run` plus source of claim, report scope; optional numeric claim | Logs/reports not independently executed or attested; GH workflow-run artifacts may not identify selected exact job. |
| `observation` | EC185 observation | Separate local config *or* remote reported test/coverage observations | Cross-mode revision equivalence unproven; performance always unmeasured, no attested benchmark. |
| `run_preflight` | EC186 safety gate | Fixed supported profile (`python.pytest`/`python.ruff`) and prepared-only state | A non-executable plan; no actual kernel isolation or test execution. Must match the exact WorkingTree pin. |
| `run_session` | EC187 budgeted host protocol | Host-reported execution state, exit code, capture/truncation, interrupted and stop/reap flags | **EC187 result itself contains no source pin**. The scope is **caller linked only**, not cryptographically or empirically corroborated. Host exit `0` never proves tests ran/passed; no stdout/stderr contents disclosed. Remote attachment is forbidden. |

The module recomputes the original checksum fields for EC181..EC186 **using the genuine producer checksum algorithms**, after verifying correct producer schemas and result `partial/2`. The EC187 result has no analogous signed or source-bound result; an authentic cancellation-before-broker receipt (`execution=null`, `output=null`) is explicitly displayed as `NOT_STARTED_CANCELLED_BEFORE_BROKER`, never as a successful or failed test; its structural fields and negative proof flags are validated but not attested. **No upstream checksum authenticates provenance**: an actor who can construct a receipt can compute its checksum. Host access control must establish who may supply/view it; signed scope authorization still does not demonstrate test correctness or actual runner isolation.

Any unsupported positive `verified` proof flag or incompatible source/result is rejected fail-closed with empty entries. The full caller batch is checked even when only one page is requested; a mixed-scope record fails the **whole** query, never a partial cross-scope disclosure. Query payload or source modification during authorization fails closed.

## Output, redaction and page consistency

Output `schema=ces.quality_show.v1`, successful projection `status=partial`, `exit_code=2`; refusal `invalid_input/4` or `unavailable/5`. Positive output includes `scope` with source mode, *claimed* pin/SHA, source-identity proof false; `query_sha256`; `revision_sha256`; counts; fixed sort order; `entries`; opaque `next_cursor`; `coverage`; `proof`; `effects`; and an explicit trust boundary. No evidence item or original callback result is directly serialized back.

- **Never displayed:** repo path, branch/token/credential/URLs, GitHub/GitLab log text, captured stdout/stderr, arbitrary timestamps from internal receipts, CI parsed raw excerpts, arbitrary config bodies/scripts, job artifact archive or model/source text. The public scope includes only mode, provider name and *claimed digest* (not repository path or numeric ID). Entries use strict fixed-value fields, finite bounded integers, whitelisted status strings and SHA-like item IDs. Optional provider report numbers require separately granted access.
- **Coverage is intentionally negative:** every global proof flag is false; `present_evidence_classes`, `not_supplied_classes`, supplied gaps and EC187 interruption/truncation counts describe **the current caller-supplied batch**, not repository-wide truth. A `pass` in an entry is always a **provider parsed classification**. `ci_pass_claim_count_not_verified` counts such claims, never validated passing tests. Host exit 0 is separately labeled as *not* verified PASS.
- **Cursor lifetime:** HMAC-SHA256 with independently secret host key, issue and expiry labels and 300-second maximum lifetime. Bound to scope/query/filter/page-size/numeric grant selection and **full supplied-evidence set revision**, including filtered-out records. For later pages the host resupplies the same full batch and live grants; additions, changes, removals, key rotation, changed filter/page size, tampering, expiry and revoked permissions fail closed. An HMAC cursor grants nothing by itself; it does not prove a source or the current state of any external ledger.
- **Bounds:** 96 supplied receipts, 256 KiB per receipt, 2 MiB combined batch, 25 entries per page, 96 KiB result, 2048-character continuation token, fixed 300-second maximum cursor TTL. All timestamps must be UTC `Z`, up to microsecond precision; capture labels over 10 seconds in the future are unavailable. A refusal returns no record-derived summary, count, scope or source identity.

## Development verification and production acceptance

`cd ces/construction && python -m unittest test_quality_show -q` exercises **55 offline development cases**, strict Draft 2020-12 result conformance, original EC181-187 Python producer implementations using only synthetic GH/GL metadata, host stubs and temporary POSIX roots. The tests use a synthetic clock, fixture-only approvals and HMAC keys. They **do not** demonstrate a live provider identity, real CI execution, a trusted kernel runner, verified git source byte identity or a PowerShell native `QualityShow` implementation.

The host application must supply credential/vault custody, independent authorization policies and receipt provenance/lifetime enforcement. Live GitHub/GitLab, mutable real repositories, PowerShell 7+15 original Smoke tests, Windows/macOS, hostile callback races/multitenant threat model, performance E63-E66 and final user-assisted integration acceptance are **NOT_RUN**; collect them in final acceptance with the user's help. The upstream V3.10/ROUNDS historical gap B-001 remains **OPEN**. **EC189 Finding linkage is not part of EC188**; this query never creates, edits or confirms a Finding or defect.
