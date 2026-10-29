# EC208 temporary owner-private fixture — development only

`construction/test_knowledge_version_save.py` constructs an isolated temporary **real** EC206 candidate store and EC207 read-granted Handoff, writes a disposable `ces-snapshot.v1.json` and existing Markdown chapter bytes, constructs a distinct POSIX owner-private version metadata root, and registers two **ephemeral test-only** Ed25519 public keys. It runs actual local `initialize`, `preview`, `save` and `inspect` against nofollow/fcntl/HMAC/O_EXCL files. Private signing keys are generated in-memory by the test and are **not bundled** or valid for organizational approval.

From `ces/construction`, with Python, `cryptography` and (for separate schema checks) `jsonschema` installed:

```bash
python -m unittest -q test_knowledge_version_save.py
```

The scenarios cover positive one-section version append, source and business-code byte preservation, deterministic same-request/approval idempotency, two-version predecessor chaining, optimistic stale parent refusal, before/after/whole chapter mismatches, EC205 section reference mismatch, EC207 selection and candidate ID tampering, two-role Ed25519 signature/expiry mismatch, role registry/revocation drift, EC207 read grant reapplication, restricted persistence grant, private-store path/symlink failures, corrupted record rejection (including local HMAC re-computation) and invalid JSON.

**Not a production endorsement**: tests run on one available POSIX host with ephemeral local trust and caller-created EC204/205 results. No live signer directory, approval custody, role/permission revocation verification, source-of-truth ownership, external AI, provider, native PowerShell, Windows/macOS/NFS, adversarial multi-process race or final joint acceptance is represented. Do not run fixtures against real knowledge roots or reuse test keys for actual approval. If `cryptography`, POSIX `fcntl` or the private file APIs are missing, postpone acceptance and record `NOT_RUN`; do not bypass the gates.
