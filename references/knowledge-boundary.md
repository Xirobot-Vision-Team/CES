# EC201 KnowledgeBoundary — current-state and evidence trust boundaries

**Construction release V5.11/R201.** This is a **standalone, in-memory Python evidence model**, not `KnowledgeBootstrap`, `KnowledgeImpact`, `KnowledgeSave`, a native PowerShell action, a trusted Git delivery verifier, or documentation publication. It never reads a repository, Git object, Provider, CI, user directory, document store or network and has **no file/system/business write path**.

## Entry points

```python
import json
from construction.knowledge_boundary import KnowledgeBoundary, canonical

api = KnowledgeBoundary()
preview = api.binding_preview(request_json=canonical(request))
# Independently authorize the exact request: separately obtain read_policy.
# read_policy.request_binding_sha256 == preview['subject']['request_binding_sha256']
# read_policy.scope_binding_sha256   == preview['subject']['scope_binding_sha256']
# Each observation_grant matches an observation binding in the preview.
result = api.inspect(request_json=canonical(request),
                     read_policy_json=canonical(read_policy))
assert result['exit_code'] == 2 or result['subject'] is None
```

When running from `construction/`, import with `from knowledge_boundary import ...`. The two inputs **must be independently supplied, strictly canonical JSON strings** (sorted ASCII-escaped keys, no extra whitespace, duplicate/case-colliding keys, floats, unknown fields or oversized payloads). The request schema is [`knowledge-boundary-request.v1.schema.json`](knowledge-boundary-request.v1.schema.json), the separate read policy is [`knowledge-boundary-read-policy.v1.schema.json`](knowledge-boundary-read-policy.v1.schema.json), and the output schema is [`knowledge-boundary-result.v1.schema.json`](knowledge-boundary-result.v1.schema.json). Output contains no arbitrary claims, source excerpts, tokens or base64 content.

### A bounded example

```python
import base64, hashlib

source_bytes = b'cache now uses versioned slots'  # caller-supplied, NOT Git proof
source_hash = hashlib.sha256(source_bytes).hexdigest()
request = {
  'schema':'ces.knowledge_boundary_request.v1',
  'operation':'knowledge.boundary.inspect',
  'scope':{
    'repository_ref':'cesrepo1:'+'1'*64,
    'knowledge_space_key':'architecture',
    'period':{'period_id':'month-2026-10',
              'start_utc':'2026-10-01T00:00:00Z',
              'end_utc':'2026-11-01T00:00:00Z'},
    'target':{'mode':'DeliveredTarget',
              'revision':{'algorithm':'sha1','oid':'2'*40},
              'source_receipt_sha256':None},
    'source_policy_revision':'policy-v1'
  },
  'observations':[{
    'observation_key':'obs1','claim_key':'cache-layout',
    'origin':'delivered_source',
    'source_revision':{'algorithm':'sha1','oid':'2'*40},
    'evidence_receipt_sha256':None,
    'content_sha256':source_hash,
    'content_base64':base64.b64encode(source_bytes).decode('ascii'),
    'observed_at_utc':'2026-10-10T00:00:00Z',
    'coverage':'partial_declared'
  }]
}
api = KnowledgeBoundary()
preview = api.binding_preview(request_json=canonical(request))['subject']
read_policy = {
  'schema':'ces.knowledge_boundary_read_policy.v1',
  'purpose':'knowledge_boundary_read_only',
  'repository_ref':request['scope']['repository_ref'],
  'knowledge_space_key':'architecture','period_id':'month-2026-10',
  'source_policy_revision':'policy-v1',
  'request_binding_sha256':preview['request_binding_sha256'],
  'scope_binding_sha256':preview['scope_binding_sha256'],
  'permit_boundary_read':True,
  'permit_provenance_projection':False,
  'permit_content_digest':True,
  'permit_knowledge_write':False,'permit_business_source_write':False,
  'permit_issue_write':False,'permit_publish':False,
  'read_receipt_sha256':'3'*64,
  'observation_grants':[{
    **preview['observation_bindings'][0],
    'permit_observation_read':True,
    'permit_content_digest':True,
    'read_receipt_sha256':'4'*64
  }]
}
result = api.inspect(request_json=canonical(request),
                     read_policy_json=canonical(read_policy))
assert result['subject']['claims'][0]['evidence_state'] == (
    'LOCAL_BYTES_INTEGRITY_ONLY_DELIVERY_UNVERIFIED')
assert result['subject']['verified_delivered_facts'] == []
```

All receipt hashes in this example are **synthetic declarations, not permission grants from a trusted authority**. For actual operational use, callers must obtain and verify external authorization independently; this module checks completeness and binding of declarations but does **not** authenticate human identity, revocations, receipt issuer, Git provenance or business governance.

## Trust categories and promotion barrier

| Observation `origin` | Result | May enter trusted current architecture? |
|---|---|---|
| `delivered_source` with exact caller-declared target revision, in declared period, and locally matching bytes to supplied SHA256 | `BYTES_MATCH_EXPECTED_HASH_DELIVERY_UNVERIFIED` | **No**. Matching two caller-supplied values does not authenticate Git object/branch/merge/delivery. |
| `delivered_source` with only digest metadata | `DELIVERED_SOURCE_DIGEST_DECLARED_ONLY` | **No**. Unread content and purported receipt are declarations. |
| `delivered_source` with different or null target revision | `OTHER_DELIVERED_SOURCE_UNVERIFIED` / `TARGET_REVISION_UNKNOWN` | **No**. Do not borrow a different version's pin. |
| `proposed_pr` (even if head OID equals declared target OID) | `CANDIDATE_NOT_DELIVERED` | **No**. Never assume merge/target branch/current. |
| `working_tree` | `WORKTREE_NOT_DELIVERED` | **No**. Local changes are not release state. |
| `ai_assertion` / `ci_assertion` | `UNVERIFIED_AI_ASSERTION` / `UNVERIFIED_CI_ASSERTION` | **No**. Not source architecture evidence or authenticated execution. |
| `unknown` / missing observations | `UNKNOWN_UNAVAILABLE` / no eligible source | **No**. Do not invent absence/completeness or current fact. |

Every valid `inspect` returns `partial/2`, `current_architecture_state=UNKNOWN_NOT_AUTHENTICATED`, and an empty `verified_delivered_facts` array. **`DELIVERED_SOURCE_VERIFIED` is an explicitly *unimplemented future state*, never reachable through caller flags or hashes in EC201.** EC203 will need a genuinely independent trusted target Git/SHA verification path before any promotion is even eligible. EC202 will supply separately authorized knowledge snapshots (including empty-state provenance); EC204–210 will implement impact assessment, candidate isolation, AI revision, immutable save, conflict handling and update/query integration.

Multiple observations with the same `claim_key` are **grouped but never merged into a fact**. A claim with two distinct matching-target delivered content digests in the same period becomes `CONFLICTING_DELIVERED_SOURCE_DECLARATIONS` rather than picking the later or PR content. An observation outside the declared UTC half-open period is counted as out-of-period and cannot be eligible source evidence for that period. A missing target revision and an absent time/period window remain explicit unknowns, not implicit branch fallback.

## Scope, privacy and limits

- Request pins: explicit `repository_ref`, `knowledge_space_key`, `source_policy_revision`, `period_id`, optional bounded UTC `[start,end)`, target `DeliveredTarget` Git algorithm+OID and optional untrusted receipt. A period is **declared** and cannot independently establish business-calendar rules.
- Every `observation_key` is unique and lexically ordered; each observation carries explicit `claim_key`, origin, optional source revision/receipt, optional SHA256+base64 bytes, UTC time, and **declared** coverage. Maximum: 128 observations, 64 claims, 4,096 bytes per source observation, 1 MiB canonical request, 128 KiB policy. Source identity is *declared*, not looked up.
- Separate read policy **must** match the complete content-bound request SHA, scope SHA, exact repository/namespace/period/policy version, plus each observation's SHA and a separate affirmative read grant. Raw-byte digest checking needs an additional top-level **and per-observation** permission; provenance projection defaults to hidden unless separately authorized. No grant or stale/mismatched policy => `subject=null` and no partial projection. All write/publication intent flags must be `false` and **no write API exists even if flags are forged**.
- Returned `observation_ref`, scope/ref and policy hashes are correlation identifiers, **not unforgeable receipts or signatures**. Output omits base64/text and never emits a source's Git OID, content digest or purported receipt unless `permit_provenance_projection` is separately granted; the source mode, coverage uncertainty, assessment and fixed-key observation references remain visible to authorized boundary readers.
- Error results contain **only fixed reason codes**, never caller-provided strings or partial subject content. `invalid_input/4` is malformed or noncanonical; `unavailable/5` is denied/stale, source bytes inconsistent, or other input processing uncertainty.

### Explicit not implemented / final verification

EC201 does **not** read actual knowledge documents, inspect real Git objects, verify a Provider delivery, accept self-declared currentness, run CI, call AI, update CES knowledge, modify business source, issue or publish docs. No native PowerShell Knowledge route, no complete workflow or cross-repository authority delegation. Current local synthetic tests and Draft2020-12 schema checks are development evidence only. Provider identity, real Git and ACL, OS behavior, original 15 PowerShell Smoke, E63–E66 and final user-assisted end-to-end acceptance remain `NOT_RUN`. B-001 original V3.10/ROUNDS evidence gap remains `OPEN`.
