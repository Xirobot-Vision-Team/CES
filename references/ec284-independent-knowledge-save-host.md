# EC284 — Original EC208 exact local knowledge metadata save host

**Scope.** One optional separate AF_UNIX Unix/POSIX service invokes the original `construction/knowledge_version_save.py:KnowledgeVersionSave.save`. `ces_next.py host-save KnowledgeSave SaveLocal` is the only new operator action. The original Router `run KnowledgeSave SaveLocal` still refuses host privilege; the original source Markdown, business Git repository and provider integrations remain unwritable through this service. This is a *real* immutable local metadata append, **not** knowledge publication.

## 1. Real prerequisites and custody

- On a dedicated POSIX host/user, prepare **four mutually disjoint roots** (real repository, source knowledge snapshot, existing EC206 candidate store, existing EC208 version store) with the original store permissions/manifests/locks and original EC202/206/207 provenance. The new service **never initializes** either private store.
- Separately enroll the original two EC208 approval keys: `independent_reviewer` and `knowledge_owner`; original EC208 will actually verify their exact approval statements and UTC lifetime. This host also requires distinct EC284 `custodian`, `authorizer`, and `server` keys: **five distinct public keys** in the minimal deployment. Real organizations must manage independence, rotation, revocation, secure backups and time trust outside this sample. Do not put offline private signing keys on the serving host or in the ZIP.
- Build one **real original EC207** handoff, including its original `handoff_request_json`, `handoff_policy_json` and `candidate_read_policies_json` and the **real EC208** `request_json`, `save_policy_json` and 2 independent original EC208 approvals. The original EC208 `preview` must be `partial` with the *exact* `authorization_scope_sha256` that is put in the save policy. The manifest pin, chapter snapshot, candidate IDs and EC208 selected section replacement **must already validate** under unchanged original EC208; this host does not synthesize or relax that business policy.
- All JSON input artifacts, private job/policy and server private key are stored in admin-controlled `0600` files. The socket parent directory must not be world-writable, and its socket ACL/UID admission must actually be enforced. This is not a network/web service and has no remote broker impersonation mode.

## 2. Prepare the immutable exact job and host policy

The private administrator runs the following command with paths under their control. `prepare-job` refuses symlinks/nonprivate JSON and exclusive-creates one new `0600` pinned file; it never prints replacement text:

```sh
python3 -I scripts/ces_knowledge_save_host.py prepare-job \
  --repository-root /srv/ces/repo --knowledge-root /srv/ces/knowledge \
  --candidate-root /var/lib/ces/candidates --version-root /var/lib/ces/versions \
  --candidate-store-id knowledge_candidate --version-store-id knowledge_versions \
  --repository-ref 'cesrepo1:<64-lowercase-hex>' \
  --knowledge-space-key architecture --period-id period01 \
  --source-policy-revision policy-v1 --chapter-path knowledge.md \
  --trusted-approvers-file /operator/private/ec208-approved-public.json \
  --save-request-file /operator/private/ec208-save-request.json \
  --handoff-request-file /operator/private/ec207-handoff-request.json \
  --handoff-policy-file /operator/private/ec207-handoff-policy.json \
  --candidate-read-policies-file /operator/private/ec207-candidate-read.json \
  --save-policy-file /operator/private/ec208-save-policy.json \
  --approvals-file /operator/private/ec208-original-two-approvals.json \
  --out /operator/private/ec284-save-job.json
```

`--revoked-approvers-file` can be provided with a `{"revoked_approvers": ["key-id"]}` sorted, unique array. The approvers registry contains **only public keys** such as:

```json
{"reviewer01":{"role":"independent_reviewer","public_hex":"<64-lowercase-hex>"},"owner01":{"role":"knowledge_owner","public_hex":"<64-lowercase-hex>"}}
```

The service administrator creates a `0600` policy file **with exactly the following fields** and pins its raw file SHA externally:

```json
{
  "schema": "ces.ec284.knowledge_save_host_policy.v1",
  "job_file": "/operator/private/ec284-save-job.json",
  "job_sha256": "<sha256 of RAW 0600 job file bytes>",
  "allowed_uids": [1001],
  "custodian_issuer_public_hex": "<registered independent offline signer public hex>",
  "authorizer_issuer_public_hex": "<registered second offline signer public hex>",
  "server_public_hex": "<separately pinned HOST reply signer public hex>"
}
```

Use `sha256sum /operator/private/ec284-policy.json` to obtain its **raw file** policy SHA. Do not hash reserialized JSON: the final newline is included. `inspect-job --job-file /operator/private/ec284-save-job.json` returns **only** the public binding values `job_sha256`, `repository_ref`, `save_key`, `save_request_sha256`, `authorization_scope_sha256`, `new_chapter_sha256`; it never performs a save.

## 3. Separate offline authorization of this one exact write

On **separately operated offline machines**, use registered EC284 keys. `keygen-offline --private-out /offline/....ed25519` is available for setup only, not an attestation of human or organizational authority. Each offline signer independently inspects policy/job pins, private selected source and EC208 approval custody through their **external** procedures before signing:

```sh
python3 -I scripts/ces_knowledge_save_host.py prepare-offline \
  --uid 1001 --policy-sha256 '<policy-raw-sha256>' \
  --job-sha256 '<job-raw-sha256>' --repository-ref 'cesrepo1:<64-hex>' \
  --save-key version_one --save-request-sha256 '<request-canonical-sha256>' \
  --authorization-scope-sha256 '<original EC208 preview binding>' \
  --new-chapter-sha256 '<original EC208 expected new content sha>' \
  --ttl-seconds 180 --out /offline/save.subject.json
python3 -I scripts/ces_knowledge_save_host.py sign-custodian-offline \
  --subject-file /offline/save.subject.json \
  --private-key-file /offline/custodian.ed25519 \
  --out /offline/custodian.vote.json
python3 -I scripts/ces_knowledge_save_host.py sign-authorizer-offline \
  --subject-file /offline/save.subject.json \
  --private-key-file /offline/authorizer.ed25519 \
  --out /offline/authorizer.vote.json
python3 -I scripts/ces_knowledge_save_host.py assemble-offline \
  --subject-file /offline/save.subject.json \
  --custodian-vote /offline/custodian.vote.json \
  --authorizer-vote /offline/authorizer.vote.json \
  --custodian-public-hex '<enrolled-custodian-pubhex>' \
  --authorizer-public-hex '<enrolled-authorizer-pubhex>' \
  --out /operator/private/ec284-save.grant.json
```

The grant lives for **up to 300 seconds**, fixes the actual **kernel peer UID**, requested action, raw job/policy and original EC208 exact request, save key, signed EC208 permission binding and replacement chapter hash. It contains **no source Markdown or original approver private keys**. Source/metadata root write access comes only from the deployment user and original EC208; a grant cannot cause a business-repository write.

## 4. Actual host and client invocation

```sh
python3 -I scripts/ces_knowledge_save_host.py serve \
  --socket /run/ces/knowledge-save.sock \
  --policy-file /operator/private/ec284-policy.json \
  --policy-sha256 '<policy-raw-sha256>' \
  --server-private-key /operator/private/server.ed25519
```

From the allowlisted Unix peer UID, provide only the assembled grant and the **independently verified, pinned** server public key:

```sh
python3 -I scripts/ces_next.py host-save KnowledgeSave SaveLocal \
  --socket /run/ces/knowledge-save.sock \
  --grant-file /operator/private/ec284-save.grant.json \
  --policy-sha256 '<policy-raw-sha256>' \
  --server-public-hex '<independently-enrolled-server-pubhex>'
```

The direct equivalent `python3 -I scripts/ces_knowledge_save_host.py save ...` uses identical `--socket`, `--grant-file`, `--policy-sha256`, `--server-public-hex`. Untrusted socket requests cannot select a different job, change private path, save arbitrary text or add permission flags. A fresh nonce and canonical request SHA are signed into the reply. All five previously implemented optional host integrations are unaffected; no changes to original Router policy.

## 5. Response interpretation and failure/retry discipline

The service **may actually append a private version**. Do not treat `partial/2` as a trial run:

- `KNOWLEDGE_SAVE_NEW_IMMUTABLE_LOCAL_VERSION_APPENDED` + `local_version_metadata_written=true`: original EC208 actually created one exclusive immutable metadata file and returned its `version_id`, `version_number` and SHA. The original source Markdown is not overwritten.
- `KNOWLEDGE_SAVE_ALREADY_SAVED_IDEMPOTENT_NO_WRITE` + `local_version_metadata_written=false`: EC208 independently verified that the exact same save key, exact request and approvals were *already* saved; no new file was created by the repeated invocation.
- `unavailable/5` + `local_write_outcome_unknown=true`: DO NOT automatically retry. The reply may have been lost after the write; EC208 may have committed before an I/O exception; or an approved job/policy may have changed after the backend began. A missing or unverifiable host reply is also unknown at the operator-client boundary. Inspect the **original private version store** using original `KnowledgeVersionSave.inspect()` with the same pinned roots and keys, reconcile `save_key` and original version receipts and investigate host audit before considering a new independently approved action. The service does not do silent rollback or clean up ambiguous versions.
- Denied/expired/fake grants and drift **before** `save()` yield signed `permission_denied`/`unavailable` with no backend write. Invalid preadmission frames receive no reply. All signed denials omit replacement text, original approvals and store content.

Original EC208 can append **local draft metadata only**, never prove organizational signer identity, source custody/currentness, publication, actual Issue/Provider/CI operations or overall Quality PASS. A sampled same-machine test with five generated keys proves cryptographic flow **locally**, not separation of humans or independent production authorities. The same time-limited grant can be replayed before expiry; EC208 original save key/idempotent check governs safe duplicates. No durable cross-restart nonce expenditure, HSM/WORM proof or independently trusted UTC is introduced.

### Verification still deferred

Actual production OS UID/ACL constraints; five independent approver/server humans/keys, original source/Git/CI and original EC206/207/208 policy quality, attack surface of compromised local interpreter/OS, original PowerShell7/15 Native Smoke, Windows/macOS, E63–E66 performance, original B001 V3.10/ROUNDS provenance and final product acceptance are **not** demonstrated by EC284. Full-function/EC249 remains incomplete, EC250 blocked and global Quality PASS=false.

[Implementation](../construction/ec284_knowledge_save_host/) · [EC284](../EC-284.md) · [local scoped test report](../construction/EC284_LOCAL_REPORT.json).
