# EC366 wire protocol — two externally pinned institution root-provenance views

**V6.76 / R366 / EC366.** This layer verifies *cryptographic consistency of presented independent copies*, not official identity. It does not call a URL, DNS, trust store, certificate transparency provider, institution API, signer, or remote storage. Its only accepted assessment exit is **2 (`unresolved`)**. A locally coherent result is **not** a legal independence, authority, custodian, trusted UTC, completeness, or latest-global-log certificate.

## Parent and exact public original boundary

Every `audit-root-provenance` first invokes the original `ec365_directory_lineage.lineage.audit` with all of its existing EC365 inputs. Thus EC365 truly replays the EC364 historical/cross-epoch EC363/362/361 through EC337 source originals, actual Ed25519 root handoffs, and direct RFC6962 proofs. EC366 computes **SHA-256 of the canonical entire EC365 result** and checks the new bundle's `parent_ec365_canonical_result_sha256` against it; it never accepts a supplied `parent_passed` field or cached favorable JSON. It independently reopens the EC364 historical snapshot root-key originals so extra directory-signed checkpoints can be checked with the actual epoch signer.

Existing EC365 flags are inherited, not repaired. EC366 reads `epoch_lineage_reviews`, `signed_directory_handoff_reviews`, `true_directory_root_generation`, and the parent result's locally-authorized flag. Caller-provided institution keys cannot self-authorize changed EC365 directory root keys. Full old and new key original SHAs and source A/B manifest original SHAs remain checked by EC365's own replay and caller SHAs.

## Required external independent inputs

The CLI extends **all** EC365 `audit-directory-authority` arguments. It adds:

| Option | Bound and rule |
| --- | --- |
| `--root-provenance-evaluation-utc` | Required caller-asserted `YYYY-MM-DDTHH:MM:SSZ`, not a trusted clock; must not precede EC365 evaluation |
| `--root-provenance-bundle-file` and `--expected-root-provenance-bundle-sha256` | Separate pair, `None/None` gives an explicitly missing-evidence unresolved assessment |
| `--institution-root-public-key-file` and `--institution-root-public-key-sha256` | Exactly twice, ordered first `origin_registry`, then `independent_archive`; 32-byte Ed25519 keys, **externally retained whole original SHA** distinct from each other and from any known current/historical signer role |
| `--institution-claimed-id` | Exactly twice, order fixed to the two roles, distinct IDs independently retained by caller; names/roles are **claims**, not recognized legal identities |
| `--signed-institution-status-sha256` | 0..8 externally retained whole-file digests in bundle role order and event order; at most 4 verified signed events per role |
| `--signed-institution-attestation-sha256` | 0..8 externally retained whole-file digests in bundle role order and event order; at most 4 verified signed attests per role |
| `--minimum-retained-origin-registry-sequence`, `--minimum-retained-independent-archive-sequence` | Optional caller floor 1..8; absent floor blocks local corroboration |
| `--expected-retained-{origin-registry,independent-archive}-{status,attestation}-head-sha256` | Four separately retained whole-file heads; missing or mismatching heads block corroboration |
| `--additional-signed-checkpoint-sha256` | 0..4 external digests, in bundle order; every extra original must be genuinely Ed25519-signed by the actual corresponding EC365 directory signer |

All material is read-only, strictly canonical JSON where applicable, exact-field-checked, bounded in size, SHA-256-pinned over raw bytes, and rejected if it is a symbolic link / symlink ancestor, wrong file type, forbidden path/inode alias, wrong signing key, or false signature. Parent identity and new evidence identities are rechecked at the end (not an atomic filesystem snapshot). New signature messages use **separate domain prefixes**:

- `CES/EC366/InstitutionRootStatus/v1\x00` + canonical JSON without the status signature.
- `CES/EC366/InstitutionRootProvenance/v1\x00` + canonical JSON without the attestation signature.

**Private Ed25519 keys appear only inside the synthetic local test fixture, never in production commands or verifier.**

## Actual bundle, statuses and attestations

Outer bundle exact fields: `schema = ces.ec366.two_institution_root_provenance_bundle.v1`, `parent_ec365_canonical_result_sha256`, `claimed_directory_lineage_id` from the replayed signed directory source, `institutions` (exactly 2), `additional_signed_checkpoints` (0..4). Each ordered `institutions` entry has exact `claimed_institution_id`, `claimed_institution_role`, `institution_public_key_original_sha256`, `signed_status_events` (file/SHA refs), and `signed_provenance_attestations` (file/SHA refs). All refs must also match the independently retained command-line SHA stream.

A genuine **status** original has schema `ces.ec366.institution_root_status.v1`, exact institution key SHA, role, claimed ID, EC365 parent canonical SHA, `sequence` (0..8), `previous_status_original_sha256`, `action` (`activate`, `renew`, `revoke`, `rotate`), optional successor public-key SHA only for `rotate`, signed `issued_utc` and `expires_utc`, and `signature_institution_ed25519_hex`. Genesis must be `sequence: 0`, `previous: null`, `action: activate`; later status events must descend from the actual immediately preceding SHA. Signed sibling children and gaps are visible, never arbitrarily elected. **Any actually verified `revoke` or `rotate` is terminal for EC366 local corroboration**; a signed successor key claim is *not* a new trusted root, and no implicit key promotion occurs. Missing or stale caller status-head pins also block local corroboration.

A genuine **attestation** original has schema `ces.ec366.institution_signed_root_provenance.v1`, exact institution key SHA, role, claimed ID, parent EC365 canonical SHA, current status original SHA, `sequence` (1..8), `previous_attestation_original_sha256`, `directory_lineage_id`, `attestation_kind` (`corroborate`, `dispute`, `withdraw`), **actual EC365 root-generation index**, and these signed actual-endpoint lists:

- `epoch_signed_directory_observations`: bounded array of exact `epoch_index`, directory key original SHA, copied signed-checkpoint original SHA, signed tree size and Merkle root, EC361 parent canonical SHA, source A/B manifest original SHAs. Full equality with the live EC365 replay is checked.
- `signed_directory_handoff_original_shas`: complete ordered list of actual EC365 double-signed handoff original SHAs, not unsigned declarations.
- `observed_checkpoint_original_sha256`, `observed_tree_size`, `observed_merkle_root_sha256`: must correspond to an actual parent signed checkpoint or an independently furnished **verified** extra checkpoint original.
- Claimed `issued_utc`, `expires_utc`, real Ed25519 signature under its institution root and distinct signature domain.

Every attestation is signature-checked even if it is inconsistent, revoked, disputed, stale, or forks a previous statement. A forged signature is **denied** (code 3), whereas an authentically signed conflicting parent/root/Merkle view is **explicitly reported unresolved** (exit 2), not silently dropped. A current corroboration requires the exact caller-retained **unique** latest attestation/status heads, active status bound by that attestation, valid signed claim window relative to claimed evaluation, `corroborate` kind, complete true EC365 epoch/handoff matching, and **observation of the actual latest EC365 signed checkpoint SHA**. Both distinct roles must qualify and all flags must be clear for `locally_two_institutions_correlate_on_same_real_directory_lineage=true`.

Extra signed checkpoints are an array of objects with `signer_epoch_index` (actual replayed epoch 0..2) and `original` (`path` + `sha256`). The auditor reopens the corresponding epoch root-key original, genuinely verifies the extra checkpoint's original directory Ed25519 signature, directory ID, SHA and advertised tree size/root. **Same signer + same tree size + genuinely differing signed Merkle roots** cause a true observed split-view flag. A larger/older signed extra checkpoint without an actual RFC6962 proof is explicitly flagged unproven append-only; two institution-signed claims about that checkpoint alone are never called a proven directory fork.

The signed claimed times are bounded to 7-day intervals but cannot establish trustworthy history or globally current status. Externally retained status/attestation sequences and heads are not a global or legal trust registry.

## Standalone and unified read-only entrypoints

The standalone package CLI is `scripts/ces_cas_root_provenance.py`, with `derive-root-provenance-handoff` (requires full actual EC365 parent inputs and prints the parent canonical SHA + missing external material instructions) and `audit-root-provenance` (requires that parent, UTC, and new pins/refs). Real failures return code **3 `permission_denied`**, **4 `invalid_input`**, or **5 `unavailable`**, with bounded structured denial JSON; lawful reports always **2 `unresolved`**.

The fixed consolidated entry is:

```text
python scripts/ces_next.py audit-root-provenance DeliveryAudit AuditRootProvenance \
  [ALL EXISTING EC365 REQUIRED AND OPTIONAL ARGUMENTS, INCLUDING REPEATED PINS] \
  --root-provenance-evaluation-utc 2026-10-26T12:00:00Z \
  --root-provenance-bundle-file /absolute/external/provenance-bundle.json \
  --expected-root-provenance-bundle-sha256 <SHA256> \
  --institution-root-public-key-file /absolute/external/registry.pub \
  --institution-root-public-key-sha256 <SHA256> \
  --institution-claimed-id ExampleOriginRegistry \
  --institution-root-public-key-file /absolute/external/archive.pub \
  --institution-root-public-key-sha256 <SHA256> \
  --institution-claimed-id ExampleIndependentArchive \
  [FOUR RETAINED HEAD SHAs, TWO FLOORS AND EXTERNALLY RETAINED STATUS/ATTESTATION SHAs]
```

Here `<SHA256>` denotes a required real lowercase 64-character digest, not a copyable literal. The parent inputs cannot be omitted for a real invocation. The unified command launches the **fixed package-controlled** `python -I -B` child, checks strict input bounds and reply JSON/result-code/flags consistency, and never uses a caller-provided executable path.

## Risks and outstanding verification

Even two different independent caller-pinned public keys, two active signed status heads, matching raw original hashes and valid directory checkpoints **do not prove real legal/physical institutional independence, official appointment, external root ownership, trusted UTC, complete global logging or absent hidden forks**. Prior EC365 and EC317/318 limits are inherited and kept visible. Full EC366 historic true-parent test execution, EC356 historical case24, inherited production deep MOCK replacement, native PowerShell7 original 15 Smoke, Windows/macOS/Git/CI/Provider/E63–E66, official public institutions, remote CAS/WORM, and final user-assisted acceptance remain pending.

[Implementation](../construction/ec366_root_provenance/provenance.py) · [fixture](../construction/ec366_root_provenance/test_provenance.py) · [scope](../construction/EC366_SCOPE.json) · [local facts](../construction/EC366_LOCAL_REPORT.json).
