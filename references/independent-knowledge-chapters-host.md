# EC283 — independently signed `KnowledgeQuery / Chapters` private read host

Historical record names below are archival references; those files are absent
from this source tree. See [cleanup scope](../docs/CLEANUP.md).

**Release:** V5.93/R283/EC283, optional Linux/Unix AF_UNIX deployment. This
entrypoint exposes the **existing EC210 `KnowledgeLifecycle.query`**. It does
not implement a second, less-restricted knowledge query engine, nor open
Router `HOST_REQUIRED` by inference. The original `run KnowledgeQuery Chapters`
still returns permission denied. The new, separately deployed entry is
`python3 -I scripts/ces_next.py host-chapters KnowledgeQuery Chapters ...`.

## Actual behaviors

Three original EC210 projections are supported, for either the exact pinned
**source snapshot** or **selected immutable local metadata version**:

| Projection | Result | Required original proof |
| --- | --- | --- |
| `hashes_only` | Selected section ordinals and SHA256; no text, no search | Real EC206/208 private stores, verified source snapshot and metadata manifests, EC210 bound query policy |
| `match_snippets` | Up to 16 bounded matching lines per selected section | All hash requirements **plus** EC202 content read grant and fresh EC210 text + term-search grants; private versions must replay prior contributing EC206/207 approvals |
| `full_sections` | Base64 exact Markdown section bytes with checked section SHA | All hash requirements **plus** EC202 content grant and EC210 full-section/appropriate restricted-version grants; private versions replay prior contributing EC206/207 evidence |

The fixed `query_request` selects at most eight unique section ordinals, one
view, one immutable head/version/content pin and at most four exact search
terms. Only the host administrator can prepare it; **the socket request has no
query, path, term, key, role or permission fields**. Source text is at most
256 KiB across the verified response (otherwise signed `unavailable/5`).
EC210 itself limits snippets to 200 characters each. The host independently
checks projected content against the EC210 returned selected SHA and section
length, rejects overbroad/unknown output and never upgrades `partial/2` to
verified organizational facts.

### Deployment and isolation

1. Deploy a *separate* trusted, non-root, dedicated server account with read
   access to the four **pre-existing**, mutually disjoint repository/knowledge,
   EC206 candidate and EC208 version-store roots. The original EC206 and EC208
   POSIX/private manifest checks must pass; **this host never initializes or
   writes either store**. Keep server policy/job/host key in owner-only `0600`
   private files and administer the AF_UNIX socket directory and `0660` socket
   ACL separately. No network broker or public port is opened.
2. Enroll **three different** independent 32-byte Ed25519 public keys:
   `custodian` (exact private store/view consent), `reader` (text disclosure
   consent), and `server` (full signed reply). Do not reuse the EC208
   `independent_reviewer` or `knowledge_owner` approval keys for any of the
   three host roles. Production key enrollment, revocation and signer identity
   require independent administrators; local `keygen-offline` only creates
   cryptographic keys, **not organizational signer authority**.
3. Provision the current EC208 trusted approver public registry in a
   private JSON file, e.g.:

   ```json
   {"owner01":{"role":"knowledge_owner","public_hex":"<64 hex>"},"reviewer01":{"role":"independent_reviewer","public_hex":"<64 hex>"}}
   ```

   An optional `--revoked-approvers-file` is a private JSON object
   `{ "revoked_approvers": ["revoked-key-id"] }` (sorted, unique). The two
   required approver roles must each have at least one unrevoked key.
4. Obtain the **real upstream EC210** `query_request` and `query_policy` as
   exact JSON files, built from `KnowledgeLifecycle.query_binding_preview`
   against the intended *current store snapshot*. `query_policy` is NOT
   invented by the host: it must match the EC210 `query_authorization_scope_sha256`
   and permission receipt and contain no write/publish permissions. For text
   projections, also provide the original EC202 `bootstrap_request` and
   `bootstrap_read_policy`, binding the identical chapter bytes and snapshot.
   For a private version with contributing writers, additionally supply the
   actual `ces.knowledge_lifecycle_version_evidence.v1` object whose `versions`
   list contains the exact per-version EC207 handoff and EC206 candidate-read
   policies. Do not provide these text-permission bundles for `hashes_only`.

### Host-owned immutable job

Create, for example, a private exact query job (all paths below stand for
real full absolute paths fixed by the server administrator):

```sh
python3 -I scripts/ces_knowledge_chapters_host.py prepare-job \
  --repository-root /srv/ces/repo --knowledge-root /srv/ces/knowledge \
  --candidate-root /var/lib/ces/candidate --version-root /var/lib/ces/versions \
  --candidate-store-id knowledge_candidate --version-store-id knowledge_versions \
  --repository-ref 'cesrepo1:<64-lowercase-hex>' \
  --knowledge-space-key architecture --period-id period01 \
  --source-policy-revision policy-v1 --chapter-path knowledge.md \
  --trusted-approvers-file /operator/private/ec208-approvers.json \
  --query-request-file /operator/private/ec210-query.json \
  --query-policy-file /operator/private/ec210-policy.json \
  --out /operator/private/ec283-job.json
```

Use `--bootstrap-request-file` and `--bootstrap-policy-file` for text
projections, plus `--version-evidence-file` when a private version's selected
section contributors require replay. All input JSON files must be private to
the host administrator (`0600`). `prepare-job` uses exclusive, no-follow
`0600` creation, writes and fsyncs the entire exact job, **will not overwrite**
any existing output, and returns only the raw file SHA, public projection/view
and query request SHA. Inspect a separately provisioned job without disclosing
its content:

```sh
python3 -I scripts/ces_knowledge_chapters_host.py inspect-job \
  --job-file /operator/private/ec283-job.json
```

The administrator separately installs a `0600` policy JSON, schema
`ces.ec283.knowledge_chapters_host_policy.v1` with **exactly** these fields:

```json
{
  "schema": "ces.ec283.knowledge_chapters_host_policy.v1",
  "job_file": "/operator/private/ec283-job.json",
  "job_sha256": "<exact SHA256 of job file including final newline>",
  "allowed_uids": [1001],
  "custodian_issuer_public_hex": "<64 lowercase hex>",
  "reader_issuer_public_hex": "<64 lowercase hex>",
  "server_public_hex": "<64 lowercase hex>"
}
```

`sha256sum /operator/private/ec283-host-policy.json` gives the complete
original-byte **policy pin**. Never compute these hashes over prettified JSON:
line endings, spaces and the final newline affect the pin. The server starts
only if it can read and verify the installed job and policy bytes, 3 separate
host signer identities and distinct EC208 approver identities.

### Offline two-person signing and actual host query

On separately controlled signing machines, generate key files if no registered
organizational keys already exist:

```sh
python3 -I scripts/ces_knowledge_chapters_host.py keygen-offline --private-out /offline/custodian.ed25519
python3 -I scripts/ces_knowledge_chapters_host.py keygen-offline --private-out /offline/reader.ed25519
python3 -I scripts/ces_knowledge_chapters_host.py keygen-offline --private-out /operator/server.ed25519
```

The policy's three `*_public_hex` values must be obtained through an
**independent enrolled source**, not from the unauthenticated query response.
From `inspect-job`, the two offline authorities agree on the public job SHA,
repository reference, projection, view, exact query request SHA, fixed
allowed kernel UID, policy SHA and ≤300 seconds authorization duration:

```sh
python3 -I scripts/ces_knowledge_chapters_host.py prepare-offline \
  --uid 1001 --policy-sha256 '<policy-file-sha>' \
  --job-sha256 '<job-file-sha>' --repository-ref 'cesrepo1:<64-hex>' \
  --query-view source_snapshot --projection hashes_only \
  --query-request-sha256 '<query-sha>' --ttl-seconds 180 \
  --out /offline/subject.json
python3 -I scripts/ces_knowledge_chapters_host.py sign-custodian-offline \
  --subject-file /offline/subject.json \
  --private-key-file /offline/custodian.ed25519 \
  --out /offline/custodian.vote.json
python3 -I scripts/ces_knowledge_chapters_host.py sign-reader-offline \
  --subject-file /offline/subject.json \
  --private-key-file /offline/reader.ed25519 \
  --out /offline/reader.vote.json
python3 -I scripts/ces_knowledge_chapters_host.py assemble-offline \
  --subject-file /offline/subject.json \
  --custodian-vote /offline/custodian.vote.json \
  --reader-vote /offline/reader.vote.json \
  --custodian-public-hex '<enrolled-custodian-pub>' \
  --reader-public-hex '<enrolled-reader-pub>' \
  --out /operator/private/chapters.grant.json
```

Then launch the isolated service with a pinned host key:

```sh
python3 -I scripts/ces_knowledge_chapters_host.py serve \
  --socket /run/ces/chapters.sock \
  --policy-file /operator/private/ec283-host-policy.json \
  --policy-sha256 '<policy-file-sha>' \
  --server-private-key /operator/private/server.ed25519
```

The independent unprivileged client can use either the exact direct host
`query` command or the **unified operator console**, which still checks the
original Router registration:

```sh
python3 -I scripts/ces_next.py host-chapters KnowledgeQuery Chapters \
  --socket /run/ces/chapters.sock \
  --grant-file /operator/private/chapters.grant.json \
  --policy-sha256 '<policy-file-sha>' \
  --server-public-hex '<independently-pinned-server-pub>'
```

The actual `partial/2` response is an EC210 source/private-version **read**, not
an authoritative knowledge revision, current architecture attestation or
publication success. A host-signed `unavailable/5` contains *no private
selected-section payload* when any original policy, historical version replay,
source SHA, repository/knowledge root, policy/job SHA, grant, TTL or data
projection check fails. Invalid pre-frame traffic receives no signed reply.
The complete result/denial signature includes fresh 128-bit request nonce,
canonical request SHA, policy SHA, job SHA and host time. Client checks its
independently pinned server public key before accepting any data.

### Explicit limitations / deferred final verification

- Original Router 74 entries, all 11 original `HOST_REQUIRED` `run` refusals,
  R150 PowerShell, EC202/206/207/208/210 implementation, EC279–282 optional
  hosts and EC249/250/B001 historical status remain unchanged.
- Files and manifests with SHA/HMAC prove *local consistency under the supplied
  authorities*, not correct organizational content, real external Git history
  or enterprise source/approver custody. The EC210 content policy's
  `permission_receipt_sha256` is itself a pin, not independently certified
  evidence that a signer is an employee. Separate host and offline issuers are
  essential for real deployment; local tests share a machine and often UID.
- The same short-lived offline grant may authorize repeated reads until expiry
  while the raw job/policy remain unchanged. It is **not one-time-use** and
  does not provide independent global clock trust, persistent revocation or
  off-host antirollback. The host has only an in-process monotone clock floor.
- The original EC210 body/section snapshot is verified on read; the host
  rechecks full pinned job and policy after the backend call. This is **not**
  proof against a compromised local Python runtime, same-UID malicious
  administrator, malicious OS, hostile file mount, or race after the final
  check. Production must control package installation and permissions.
- Native PowerShell7/15 Smoke, real Windows/macOS runtime, actual production
  three-role separation, original CI/Git/Provider sources, E63–E66 performance,
  B001 V3.10/ROUNDS provenance and final user-assisted acceptance remain open.
  Global quality `PASS` is **not** asserted by this host.

[Source](../construction/knowledge_chapters_host/) ·
[Focused tests](../construction/knowledge_chapters_host/test_host.py) ·
`EC283 record` ·
`local report`.
