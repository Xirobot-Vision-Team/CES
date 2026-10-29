# EC200 — ReportShow and corrected immutable historical reports (V5.10/R200)

Entry point: `../construction/report_history.py`. Actual implementation:
`ReportHistory.show`, `ReportHistory.correct`, and `local_store_binding`.

Contracts:
[`report-history-read-policy.v1.schema.json`](report-history-read-policy.v1.schema.json),
[`report-history-correction-policy.v1.schema.json`](report-history-correction-policy.v1.schema.json),
[`report-history-result.v1.schema.json`](report-history-result.v1.schema.json).
All results are **internal `partial/2` unpublished declarations** or safe
`invalid_input/4` / `unavailable/5` refusal. No PowerShell action was wired.

## Actual read-only behavior

EC200 **opens an existing EC199 owner-private POSIX store without creating it**:
`storage_root/.ces-report-render-v1`. As in EC199, every ancestor is opened
without following symlinks, Git/Mercurial/Subversion source ancestors are
refused, and the directory and regular files must be owned by the current uid
and private. Reads use advisory shared `flock` on the store directory and
bounded, nofollow descriptor-relative opens; no chmod/repair/index rewrite.
The independently supplied EC200 read policy must pin the same directory's
**root+store device/inode/uid fingerprint** (`store_binding_sha256`), full
exact sorted repository/report-subject list, period, slot key, stable EC199
`cesrslot1` and independent per-repository declared grants/receipts. None of
these digests is a token, external authorization/signature or assurance about
malicious filesystem owners. A trusted host must verify human/business rights
before providing both directory access and the separate policy.

Every lookup derives **the exact EC199 slot identity from slot_key + period_id
+ the complete report_subject/repository membership**, rather than an
untrusted filename. It loads and verifies the full index and **all** referenced
historical JSON/Markdown bytes, canonical JSON encoding, content digests,
per-entry previous-entry chain, bounded 64-version sequence, document/reference
bindings, complete four-channel per-repository manifest, original scope and
period pins. Missing, stale or corrupt history refuses the entire query.
It never calls an AI provider, Git/CI endpoint, identity directory, or
ReportPublish. A selected version can be read while newer versions remain
present; no older JSON/Markdown is rewritten or deleted.

`show()` returns selected `version`, `report_ref`, `entry_sha256`, the full
bounded immutable version list, exact SHA/source/policy pins, a per-repository
Git/AI/CI/unknown display with coverage and released typed SHA-only citations,
and a **reconstructed typed comparison** (by default against the previous
version; `compare_to_version` allows any other existing version). Differences
are grouped as `source`, `scope`, `permission`, `citation`, `coverage`:

- Source: EC197/198 content/SHA pins, mode, per-repository source and people
  binding declarations; scope: scope ref, path and inventory/gap fields.
- Permission: stored release/render **policy binding digests** and observed
  per-channel release states. **EC199 does not persist the original individual
  grant booleans**, so a changed digest is *not* an assertion that some specific
  person actually authorized or revoked anything.
- Citations: exact per-repository/per-channel added/removed counts, first 32
  sorted SHA-only refs each direction, explicit omitted counts, and digest of
  full before/after sets. Coverage: four independent declared channel states,
  reasons, CI status, and declared period completeness. A claimed CI PASS is
  not verified execution.

The complete original EC199 Markdown is returned only on an explicit
`include_markdown=True` request **and** separate top-level + every-repository
`permit_rendered_markdown=True` opt-ins. By default it is `null`.

### Read usage

First obtain `first` from a successful, independently authorized EC199
`ReportRender.save()` response, or supply its equivalent pinned slot/member
references and your own valid read grants. The placeholders below are
**not real permissions**; they must be populated via the trusted caller.

```python
from report_history import (
    ReportHistory, local_store_binding, READ_POLICY_SCHEMA, READ_PURPOSE, AUDIENCE,
)

s = first['subject']
read_policy = {
    'schema': READ_POLICY_SCHEMA,
    'purpose': READ_PURPOSE,
    'audience': AUDIENCE,
    'permit_history_read': True,
    'permit_rendered_markdown': False,
    'report_slot_ref': s['report_slot_ref'],
    'slot_key': s['slot_key'],
    'period_id': s['period_id'],
    'slot_members': s['slot_members'],  # entire, sorted 1..32 member set
    'store_binding_sha256': local_store_binding(PRIVATE_EXISTING_STORAGE_ROOT),
    'policy_receipt_sha256': DISTINCT_READ_POLICY_RECEIPT_SHA256,
    'repository_grants': [
        {'repository_ref': m['repository_ref'],
         'report_subject_ref': m['report_subject_ref'],
         'permit_history_read': True, 'permit_rendered_markdown': False,
         'read_receipt_sha256': INDEPENDENT_READ_RECEIPT_BY_REPO[m['repository_ref']]}
        for m in s['slot_members']
    ],
}
result = ReportHistory().show(
    storage_root=PRIVATE_EXISTING_STORAGE_ROOT, slot_key=s['slot_key'],
    period_id=s['period_id'], slot_members=s['slot_members'],
    read_policy=read_policy, version=None, include_markdown=False,
)
if result['status'] == 'partial':
    version = result['subject']['selected_version']
    history = result['subject']['history']
    comparison = result['subject']['comparison']
```

## Correction: real EC199 append, no replacement

`correct()` requires **both** the valid EC200 read policy and a separate
fixed-purpose `ces.report_history_correction_policy.v1`: its own exact pinned
store, slot, period and complete repository members; an independent positive
`permit_append_correction` top-level and per repository; fresh disjoint
SHA receipt declarations; the exact previous version, previous report ref and
entry hash; a stable operation id; and sorted requested changed categories.
Additionally, the **new** EC199 render policy must separately opt in to local
save for the full repository set. EC200 calls the genuine EC199 `render()` and
its original EC198→197→196→195 exact-source replay. The prospective report
must have exactly the same slot/period/members, a distinct content ref and
exactly the set of authorized change categories (no undeclared source,
scope, permission, citation or coverage edits).

After preflight, the real writer is **EC199 `ReportRender.save()`**, with its
owner-private immutable no-overwrite files, cooperative exclusive lock,
compare-and-swap `expected_previous_version`, hash chain and operation-id
idempotency. Different concurrent modifications refuse as stale; an exact
same-operation, same-candidate immediate next-version retry is read-only and
returns `REPLAY_ALREADY_SAVED`. A post-commit display error is returned as
unavailable while retaining the EC199 save receipt, so clients do not
mistakenly assume no commit occurred. Correction responses read back the
persisted version and include the full five-category comparison.

```python
from report_history import CORRECTION_POLICY_SCHEMA, CORRECTION_PURPOSE

correction_policy = {
    'schema': CORRECTION_POLICY_SCHEMA,
    'purpose': CORRECTION_PURPOSE,
    'audience': AUDIENCE,
    'permit_append_correction': True,
    'store_binding_sha256': read_policy['store_binding_sha256'],
    'report_slot_ref': s['report_slot_ref'],
    'slot_key': s['slot_key'],
    'period_id': s['period_id'],
    'slot_members': s['slot_members'],
    'expected_previous_version': first['storage']['version'],
    'previous_report_ref': first['storage']['report_ref'],
    'previous_entry_sha256': first['storage']['entry_sha256'],
    'operation_id': 'approved-internal-correction-0002',
    'correction_categories': ['citation', 'coverage', 'permission', 'source'],
    'policy_receipt_sha256': DISTINCT_CORRECTION_POLICY_RECEIPT_SHA256,
    'repository_grants': [
        {'repository_ref': m['repository_ref'],
         'report_subject_ref': m['report_subject_ref'],
         'permit_append_correction': True,
         'correction_receipt_sha256': INDEPENDENT_CORRECTION_RECEIPT_BY_REPO[m['repository_ref']]}
        for m in s['slot_members']
    ],
}
corrected = ReportHistory().correct(
    storage_root=PRIVATE_EXISTING_STORAGE_ROOT,
    read_policy=read_policy, correction_policy=correction_policy,
    handoff_json=NEW_EC198_CANONICAL_JSON,
    prepare_json=NEW_EC197_CANONICAL_JSON,
    metrics_json=NEW_EC196_CANONICAL_JSON,
    scope_json=NEW_EC195_CANONICAL_JSON,
    release_policy=NEW_EC197_RELEASE_POLICY,
    review_policy=NEW_EC198_REVIEW_POLICY,
    render_policy=NEW_INDEPENDENT_EC199_RENDER_AND_LOCAL_SAVE_POLICY,
    people_subject_witnesses=NEW_EC194_WITNESSES_OR_NONE,
)
# Every actual difference category must be authorized, and every authorized
# category must have a real difference; compute categories before approval.
```

**Provenance limitation:** EC199's immutable version index stores entry
operation IDs but not a signed correction-intent field or historic grant
values. EC200 can *always reconstruct* source/scope/permission-binding/
citation/coverage differences, and returns the requested reason categories
and receipt in the append response. It **does not falsely claim** that the
separate correction intent has been permanently recorded in the EC199 index.
Any later version created through EC199 `save()` directly is displayed as
`NOT_RECORDED_IN_EC199_INDEX`, not automatically called a correction.

## Development-only verification and remaining acceptance

Synthetic EC192–199 originals in `../construction/test_report_history.py`
exercise actual fresh EC199 private storage with reads, historical selection,
source/redaction replays, five-category deltas, append+idempotent retry,
permission boundaries, corrupt index/Markdown, absent/symlink/non-private
stores and original-byte retention. This validates only the observed local
Python/POSIX behavior. **Deferred, not passed:** real authorization/identity
and revocation, independent full-source/CI authenticity, file owner attack,
multiple OS/filesystems/NFS/crash/locking hazards, external network/AI,
native PowerShell7 and the original 15 Smoke, E63–E66, final user-assisted
acceptance, and historical source blocker B-001.
