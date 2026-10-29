# EC-169 — Explicit local evidence persistence and authorization boundary

**Standalone implementation:** [`construction/proposed_pr_evidence_store.py`](../construction/proposed_pr_evidence_store.py), schema `ces.proposed_pr_evidence_store.v1`, immutable records `ces.proposed_pr_evidence_receipt.v1`. This adds a *separate* storage permission to EC166 metadata reconciliation, EC167 two-parent merge association, and EC168 squash/single-commit/exact-head association. It is **not** a native PowerShell `Reconcile:Remote/DeliveryAssociation`, `CodeSave`, `DeliverySend` or `Collect:ProposedPR` handler. It never calls a Provider, runs Git, mutates a source tree, updates CES legacy stores, changes an Issue or publishes/delivers anything.

## Operator procedure: no implicit permission inheritance

Use an operator-provisioned, **empty, owned, private directory** outside any business repository/worktree. On supported POSIX systems only, pre-create it (`mkdir -m 700 /secure/path/to/ces-receipts`) and select a stable `store-id` (3–48 lower-case ASCII letters/digits/`_`/`-`, starting with a letter). No parent is created by the tool. It checks each absolute ancestor with no-follow directory handles; a symlinked ancestor/root/records component, permissive root, unrelated files or a changed store ID fail closed. **Do not use a real user's private repo or shared CES/CodeSave directory as the receipt root.**

```bash
cd ces
# 0: operator prepares an EMPTY root and verifies the intended path
mkdir -m 700 /secure/path/to/ces-receipts

# 1: one-time, separate *explicit* authorization for this empty local store
python construction/proposed_pr_evidence_store.py init \
  --root /secure/path/to/ces-receipts --store-id team_evidence --allow-init

# 2: read-only preview of a previously generated EC166, EC167, or EC168 JSON
python construction/proposed_pr_evidence_store.py preview \
  --root /secure/path/to/ces-receipts --store-id team_evidence \
  --evidence /secure/observations/ec168.json --ttl 900

# 3: only after operator review of preview, explicit permission for ONE append
#    Replace the placeholder with preview.details.authorization_digest verbatim
python construction/proposed_pr_evidence_store.py commit \
  --root /secure/path/to/ces-receipts --store-id team_evidence \
  --evidence /secure/observations/ec168.json --ttl 900 \
  --allow-evidence-write --authorization-digest 'sha256:PREVIEW_DIGEST_HERE'

# 4: integrity-checked, read-only history and expiry state
python construction/proposed_pr_evidence_store.py history \
  --root /secure/path/to/ces-receipts --store-id team_evidence \
  --evidence /secure/observations/ec168.json
```

A `preview` exposes a digest of **the requested action scope**, not an approval token from a service. `--allow-evidence-write` and the exact matching digest must **both** be supplied *for each distinct append*. The digest binds store path, store ID and random instance ID, fixed disclosure policy, keyed subject/source evidence identity, TTL and expected prior receipt. Any different input, location, store instance, TTL or prior-revision head requires another preview/approval. Provider network, local Git read, merged PR status, EC168 `partial/2`, prior CES CodeSave permission, a cached digest or an `init` permission **never** grants this append permission. A CLI flag represents an **operator assertion**, not an authenticated human identity or signature; integrate real identity/ACLs in a later explicitly authorized platform flow.

`init` makes only `manifest.json` (restricted, includes a per-store random HMAC key), `transaction.lock` (advisory POSIX `flock`), and private `records/`. Initialization of an existing/non-empty directory is rejected rather than repaired or overwritten. The manifest binds the exact original lexical absolute path; moving/copying a store to another location intentionally blocks automatic opening, pending a separate versioned migration design.

## Stored evidence: minimum disclosure and explicit provenance

Only validated portions of **these exact v1 source responses** are supported: `ces.proposed_pr_reconcile.v1` (`FRESH_OBSERVATION`, `STALE_BY_DRIFT`, `UNAVAILABLE_UNKNOWN`), `ces.proposed_pr_merge.v1` and `ces.proposed_pr_linear.v1` (their known local association or unknown states). Inputs reporting `success/0`, another source schema version, invalid `status/exit_code`, conflicting source/observation labels, incorrect local positive flags or an upstream `write_authorized`, `delivery_or_merge_proven` or `provider_actor_verified` flag are refused. A result too early in EC167/168 to identify a stable subject is not saved; a partial result never receives new Provider authority from being stored.

The receipt records **only** a fixed allowlist: original *source schema*, partial/unavailable state, known reason code, provider type, synthetic flag, separate **Provider metadata claim** and **operator-selected local Git claim** labels, observed timestamps, bounded TTL/expiry, keyed identities, revision, prior receipt and whether the prior revision was expired or on another pin. No raw source JSON, PR title, commit OID, file/diff path, source code, patch/diff body, access token, authorization credentials, target repo location, HTTP headers or original repository path/number is persisted. Proposal subject and original-input identity are keyed-HMAC digests (no bare SHA of guessable repo names); the local secret is not returned by preview/history. Even an input that carries extra sensitive fields cannot expand the persisted schema.

The HMAC catches corruption or out-of-band edits made **without access to the store key**; it does not sign the Provider claim, authenticate an actor, prove that the JSON producer was not impersonated, or resist an operator who can read and replace both the manifest key and records. Synthetic vs reported-live is a **source assertion**, not a confirmed HTTP transaction. Stored receipts and history always say `source_result_authenticated=false`, `target_repository_membership_authenticated=false`, `provider_merge_or_delivery_proven=false`; neither a Provider-provided SHA nor a locally matching tree authenticates remote delivery/deployment.

## Idempotency, revisions, TTL and refresh

- Only one final record name exists per keyed subject/revision: `records/<64-hex-subject>.000001.json`, `...000002.json`, etc. Private temporary files are fsynced and atomically hard-linked into **no-clobber** revision slots, then immediately unlinked under the store lock and the directory fsynced. Existing record bytes never change. Invalid/unexpected entries or a broken HMAC/revision chain block reads **and** new appends; the program never sweeps an orphan or overwrites a malformed record automatically. Unexpected I/O during publication is `APPEND_OUTCOME_UNKNOWN`; inspect the store before deciding whether an append happened.
- Resubmitting identical source evidence with the original scoped approval while its record remains active returns `DUPLICATE_NO_WRITE`, **not** a new record or a TTL extension. An identical record whose TTL has expired returns `EXPIRED_DUPLICATE_REOBSERVE` / `unavailable/5`, even with prior approval. No automatic refresh from mere passage of time, a digest, or stale data.
- `--ttl` is an integer from **60 through 3600 seconds**, default **900 seconds**. A positive observation must be no older than **900 seconds**; future clock skew beyond **60 seconds** is rejected. TTL starts from the **earliest observed input** (Provider and/or local Git, not the later save), so delayed persistence does not extend freshness. An `UNAVAILABLE_UNKNOWN` with no new Provider observation can only be stored for **up to 300 seconds**, labelled `NO_FRESH_PROVIDER_OBSERVATION` and **never** promoted to a positive result.
- A changed observation for the same stable Provider proposal ID creates a **new immutable revision** and records `prior_receipt_id`, `prior_state_at_write`, and `prior_pin_changed`. Where both revisions report Provider timestamps, a fresh receipt must have a **strictly newer** observed Provider timestamp. Different proof states or a changed pin cannot refresh an earlier observation with the same/stale timestamp. `history` computes current expiry from the caller's current UTC time; expired records stay as historical evidence, not silently reclassified to current.
- Storage is bounded: at most **128 KiB source JSON**, **8 KiB per stored receipt**, **2,048 receipts overall**, **128 revisions per subject**, and a bounded read/scan of the selected store. Capacity/full history fails closed; no pruning or automatic migration. `status=partial/exit_code=2` from this gate reports **local** preview/persistence/history only, not an upstream successful task.

## Failure, OS support and migrations

Native safe operations require POSIX dir-fd no-follow/open/link/unlink and advisory `flock`; Windows or a filesystem without these properties returns `SECURE_POSIX_DIRFD_LOCKS_UNAVAILABLE` (or another unavailable error). This deliberately avoids a weaker cross-OS fallback that might write through symlinks or overwrite a record. On POSIX the tool verifies owner-private directory modes and regular owner-private manifest, lock and records, pins directory descriptors and rechecks that the selected root still refers to the same directory before final publication. This does not provide a secure namespace against a fully privileged/same-user malicious actor actively replacing the entire directory tree or a power-loss durability guarantee on every network filesystem; deployment-specific filesystem semantics and user-level ACL attestation remain deferred.

A run interrupted before `commit` is read-only; an interruption during the atomic publication may leave an already-linked final record or a private `.pending-*.tmp` orphan. An orphan blocks subsequent automatic appends pending operator inspection. The tool removes only a temporary file that **it created in its own invocation** and never silently deletes someone else's evidence. If files might have been committed around an I/O failure, do not blindly re-run with a new authorization: inspect history and/or the filesystem.

No automatic v1→v2 migration is available. A schema bump requires an explicitly reviewed reader/writer and migration grant; existing records never get rewritten in place. Existing EC165 snapshot receipt and historical `ces.local_store.v1` CodeSave records are **not** converted or duplicated automatically. Original PowerShell CLI still has 29 `NOT_IMPLEMENTED` native modes. Real Provider permissions, process-isolation correctness against concurrent hostile writes, cross-OS filesystem/Git behavior, cross-module end-to-end handoff, PowerShell7/15 Smoke and final user-assisted acceptance remain **NOT_RUN**.

Developer-only scenarios: `python -m unittest discover -s construction -p 'test_proposed_pr_evidence_store.py'` (25 focused offline cases including real disposable-Git + synthetic upstream consumers). Fixture/readme: [`construction/fixtures/ec169/README.md`](../construction/fixtures/ec169/README.md). These are **not** real Provider, native PowerShell or OS acceptance tests.
