# EC202 KnowledgeBootstrap — local bounded repository + CES snapshot read

**施工包 V5.12 / R202 / EC202。** This is a *real, standalone POSIX local file reader* with explicit independent read-policy declarations; it is **not** an authenticated Git-delivery verifier, current-architecture database, external connector, native PowerShell command, KnowledgeImpact, KnowledgeSave or knowledge publisher.

## What can be read

- One explicit **repository root**, read as *unverified local filesystem contents*, not as a delivered Git commit. Local bytes may contain proposals, uncommitted changes or outdated files; no branch or target OID trust is inferred.
- One separate **CES knowledge namespace root**, with a bounded canonical `ces-snapshot.v1.json` manifest and up to 32 explicitly selected knowledge files. Manifest `snapshot_version`, scope, `captured_at_utc`, coverage declaration, entry digest and byte length are checked against what is actually read, but the manifest's author and institutional truth are **not** authenticated.
- A **missing or empty** knowledge directory is valid *input*, not a runtime crash. The result records `STORE_MISSING_UNINITIALIZED` or `EMPTY_DIRECTORY_UNINITIALIZED`, includes an explicitly non-authoritative `empty_initialization_proposal` for an empty manifest, and **does not create files or a directory**. A valid zero-entry manifest gives `EMPTY_MANIFEST_DECLARED_UNVERIFIED`, which is a snapshot declaration, not proof that the organizational knowledge universe is empty. A nonempty directory without a manifest becomes `UNINDEXED_NONEMPTY_DIRECTORY`.

Both roots are passed through trusted host configuration, **never accepted as paths inside the request JSON**. They must be absolute local POSIX directory paths, with existing non-symlink ancestors. The repository directory must already exist; the knowledge directory may be missing at the *final* component. All IO uses descriptor-relative `O_DIRECTORY/O_NOFOLLOW` and read-only file opens; symlinks (including intermediate components), special files and source traversal are not followed. No `.git`, `.hg`, `.svn`, `.env`, `..`, absolute requested source path or manifest-as-source selector is permitted. A hardlink from a trusted root and malicious concurrent filesystem owners are not fully isolated; run in a trusted, access-controlled environment.

## Fixed scopes and permissions

Call [`KnowledgeBootstrap.binding_preview`](../construction/knowledge_bootstrap.py) to obtain exact SHA256 bindings for request, EC201-compatible scope, both root device/inode/path identities and each selected source. An **independent** service/authorized host must issue the corresponding policy; the example SHA receipt is not a signature, user identity or unrevoked authorization. Do not auto-generate an authorizing policy from an untrusted request.

The canonical JSON request pins:

- Exact `repository_ref`, `knowledge_space_key`, `source_policy_revision`, UTC half-open or explicitly unknown period, and optional **unverified** declared `DeliveredTarget` OID from EC201's scope syntax.
- Optional expected manifest byte SHA; `null` deliberately permits discovering an unknown manifest **without implying trusted currentness**. Where a manifest is expected, pass its independently obtained SHA to expose unexpected replacement.
- Up to 32 sorted unique `{source_key,kind,relative_path,expected_sha256,coverage}` selections; kind is `repository` or `ces_knowledge`, never caller-selectable "verified delivered". A knowledge selection must appear in the validated manifest. A selection omitted from the manifest is not silently treated as a new section.

The *independent* read policy must exactly pin those hashes, the full repository/knowledge namespace/period/policy, a top-level affirmative read receipt and the complete sorted per-source grant set. It independently gates repository read, knowledge read and manifest read. A denied source is **not stat'ed or opened**, and is returned as `DENIED_NOT_INSPECTED`; a denied manifest is not parsed. A partial grant does not silently drop requested sources. The policy separately gates provenance (`permit_provenance_projection`) and raw selected bytes (`permit_content_projection` **plus per-source consent**). Source content appears only as bounded base64; no implicit network, AI egress, editing or publication happens. All write-intent flags must remain false, and the implementation exposes **no file write method**.

Failures to match root/request/policy pins refuse the entire call, with no partial subject. Denied individual selections and missing/corrupt knowledge sources create explicit `coverage_gaps` without reading unauthorized bytes. The response lists source-level `MISSING`, `OVERSIZED`, `UNAVAILABLE`, `SNAPSHOT_NOT_AVAILABLE`, `NOT_IN_SNAPSHOT_MANIFEST`, `EXPECTED_SHA_MISMATCH`, `MANIFEST_ENTRY_MISMATCH` or `READ_UNVERIFIED` states. File SHA256 digest calculations are **actual byte checks**, but neither this equality nor a matching declared target SHA proves that Git committed, merged, deployed or released these bytes. `current_architecture_state=UNKNOWN_NOT_AUTHENTICATED`, `verified_delivered_facts=[]` and every successful response `status=partial/exit_code=2` remain invariant.

## Manifest format

Located at `ces-snapshot.v1.json` directly under the CES knowledge root; this is a canonical UTF-8 JSON file (ASCII-escaped keys, sorted keys, no whitespace outside JSON strings, no float/duplicate keys). Example with one declared section:

```json
{"captured_at_utc":"2026-10-10T12:00:00Z","coverage":"partial_declared","entries":[{"relative_path":"sections/cache.md","sha256":"<64-lowercase-hex-of-document-bytes>","size_bytes":42}],"knowledge_space_key":"architecture","repository_ref":"cesrepo1:<64-lowercase-hex-namespace>","schema":"ces.knowledge_snapshot_manifest.v1","snapshot_version":"snapshot-0001","source_policy_revision":"policy-v1"}
```

Replace the illustrative `<...>` tokens with real lowercase hex strings and use `boundary.canonical(manifest)` to serialize the final object. Manifest entries must be sorted by path and have distinct case-folded paths, each regular document no larger than 16 KiB. An unknown/missing/invalid manifest never authorizes reading arbitrary knowledge files. Manifest `complete_declared` is always a **claim**, not observed exhaustive repository coverage.

## Python example (two-stage, approved policy)

```python
from construction.knowledge_boundary import canonical
from construction.knowledge_bootstrap import KnowledgeBootstrap

# Trusted host config, not derived from request JSON:
reader = KnowledgeBootstrap(repository_root='/approved/local/repo',
                            knowledge_root='/approved/ces/architecture')
request = {
  'schema': 'ces.knowledge_bootstrap_request.v1',
  'operation': 'knowledge.bootstrap.read',
  'scope': {
    'repository_ref': 'cesrepo1:' + '1'*64,
    'knowledge_space_key': 'architecture', 'source_policy_revision': 'policy-v1',
    'period': {'period_id': 'oct-2026',
               'start_utc': '2026-10-01T00:00:00Z',
               'end_utc': '2026-11-01T00:00:00Z'},
    'target': {'mode': 'DeliveredTarget', 'revision': None,
               'source_receipt_sha256': None}
  },
  'expected_manifest_sha256': None,
  'sources': [{'source_key': 'repo-module', 'kind': 'repository',
               'relative_path': 'src/module.py',
               'expected_sha256': None, 'coverage': 'unknown'}]
}
pins = reader.binding_preview(request_json=canonical(request))['subject']
# The real application independently authorizes the user, root, precise scope
# and each selected source, then issues a fixed-purpose read policy from pins.
# This is only an illustrative, NOT authenticated receipt:
policy = {
  'schema': 'ces.knowledge_bootstrap_read_policy.v1',
  'purpose': 'knowledge_bootstrap_local_read_only',
  'repository_ref': request['scope']['repository_ref'],
  'knowledge_space_key': 'architecture', 'period_id': 'oct-2026',
  'source_policy_revision': 'policy-v1',
  'request_binding_sha256': pins['request_binding_sha256'],
  'scope_binding_sha256': pins['scope_binding_sha256'],
  'repository_root_binding_sha256': pins['repository_root_binding_sha256'],
  'knowledge_root_binding_sha256': pins['knowledge_root_binding_sha256'],
  'permit_bootstrap_read': True, 'permit_repository_read': True,
  'permit_knowledge_read': False, 'permit_manifest_read': False,
  'permit_provenance_projection': False, 'permit_content_projection': False,
  'permit_knowledge_write': False, 'permit_repository_write': False,
  'permit_business_source_write': False, 'permit_issue_write': False,
  'permit_publish': False, 'read_receipt_sha256': 'a'*64,
  'source_grants': [
      {'source_key': item['source_key'],
       'source_binding_sha256': item['source_binding_sha256'],
       'permit_source_read': True, 'permit_content_projection': False,
       'read_receipt_sha256': 'b'*64}
      for item in pins['source_bindings']]
}
result = reader.read(request_json=canonical(request),
                     read_policy_json=canonical(policy))
assert result['status'] == 'partial' or result['subject'] is None
```

Read policy `permit_manifest_read=False` deliberately gives a `MANIFEST_ACCESS_DENIED` gap above, and does not reveal knowledge-store contents. For a full knowledge snapshot, independently authorize `permit_knowledge_read=True`, `permit_manifest_read=True` and explicit granted `ces_knowledge` sources. A missing directory only yields an **initialization proposal**, never a side effect. To see SHA and manifest provenance, separately grant `permit_provenance_projection`; to receive source bytes, also grant *both* content permissions. The request, policy and result have strict Draft 2020-12 schemas:

- [`knowledge-bootstrap-request.v1.schema.json`](knowledge-bootstrap-request.v1.schema.json)
- [`knowledge-bootstrap-read-policy.v1.schema.json`](knowledge-bootstrap-read-policy.v1.schema.json)
- [`knowledge-snapshot-manifest.v1.schema.json`](knowledge-snapshot-manifest.v1.schema.json)
- [`knowledge-bootstrap-result.v1.schema.json`](knowledge-bootstrap-result.v1.schema.json)

## Boundaries, deferred work and acceptance

Maximum 32 selected sources / manifest entries, 16 KiB per source, 256 KiB aggregate selected-source bytes, 64 KiB manifest, 256 KiB canonical request, 64 KiB read policy. Bounded output and local nofollow reads are developed on POSIX; Windows/macOS/Linux parity, NFS/hostile concurrent mutation, hardlink abuse, timezone/provider identity, real Git delivery proof and business authorization issuer/revocation need final user-assisted verification. The POSIX unit fixture suite is development evidence, **not** real-organization permissions or current architecture.

This module does **not** implement EC203 target Git/OID/delivery authentication, EC204 Impact diff, EC206 candidate store, EC208 KnowledgeSave, native PowerShell Knowledge route, provider/API/CI/AI or Issue/Docs writes. Existing EC201 [`KnowledgeBoundary`](knowledge-boundary.md) still distinguishes DeliveredTarget *declarations*, ProposedPR/WorkingTree candidates, AI/CI assertions and unknowns: nothing from an EC202 source read can bypass that barrier. The historical B-001 original V3.10/ROUNDS evidence gap remains OPEN.
