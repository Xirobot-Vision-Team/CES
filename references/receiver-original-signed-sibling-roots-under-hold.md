# EC386 — Receiver authentic old EC341 signed sibling-root conflict under original EC342 approved hold

Construction package **V6.96 / R386 / EC386**. This receiver layer only *reopens original signed bytes*; it creates no keys, signatures, institutional authority, remote hold, trusted clock, or offsite evidence.

## Mandatory real source ancestry

The audit **executes** unmodified `historical_change.change_archive.audit(**all_pinned_parent_inputs)` on every call. It does not accept a user-authored parent PASS JSON. It hashes the exact canonical `exit_code=2` parent result, separately reopens the original EC385 receiver bundle (its whole SHA must equal the independently supplied parent SHA), checks its original epoch/channel ordering and the original `ec342_governance_roster_original` / `ec342_hold_request_original` references, and requires the new archive to point to the actual EC385 audit SHA, archive SHA and lineage ID. The unchanged upstream EC385 receiver itself requires actual EC384→EC369 audits and complete original EC342/343 predecessors, or it reports unresolved; if the parent genuinely has no old source, the new channel **must stay empty** rather than inject a new claim.

The old EC342 original governance SHA is the source of authority for selecting the alleged EC341 manifest SHA and **one exact signed sibling pair**. The old EC341 manifest has no signature of its own. EC386 separately reopens that exact manifest SHA, the old EC341 complete reference inventory, the original issuer root and role roster, every main-chain and competing root roster, all eight separately Ed25519-signed old/new role edges per hop, and the independent signer/witness roster and signed observation. It then runs **unchanged** `root_lineage.lineage.verify_lineage` (which replays EC340→EC337) and **unchanged** `conflict_hold.hold._trusted_case` to verify that the original independently registered hold actors select exactly the same originally signed parent, selected child, and different competing child. The original signed EC342 initiator hold claim is verified under its original domain and cross-checked against the original EC343 signed base snapshot holding that SHA. Every old signature, chronology, observation challenge, root/epoch, and no-ABA rule remains an old legacy requirement: EC386 does not reimplement weaker cryptographic checks.

**Wire-format preservation:** original EC341 documents use `offline_transfer_registry.registry.raw_doc` (canonical LF JSON), not the later EC353 canonical encoding. EC386 must validate the original old encoding and the **whole original byte SHA**, not translate and re-sign or silently reject genuine historical files. Raw public-key copies are data: they must match the old issuer/observer roster byte-for-byte but cannot prove real institutional identity, custody or independent authority.

## EC386 receiver bundle (exact fields)

Bundle `schema` is `ces.ec386.receiver_historical_old_ec341_signed_root_conflict_archive.v1`; exact top-level keys:

- `schema`
- `parent_ec385_canonical_result_sha256`
- `ec385_historical_change_archive_original_sha256`
- `claimed_directory_lineage_id`
- `epochs` — 1 to 3 ordered epochs, each exact `epoch_index` and `channels` (one or two, identical ordered channel IDs to the real EC385 parent).

Each channel has **exactly**:

| Key | Source and rule |
| --- | --- |
| `tsa_channel_id` | Same authentic ordered old EC385 channel ID |
| `ec342_governance_roster_original` | Exact `{path,sha256}` from that authentic old EC385 channel |
| `ec342_signed_hold_request_original` | Exact `{path,sha256}` from old EC385 `ec342_hold_request_original` |
| `ec341_lineage_manifest_original` | Whole-file `{path,sha256}`; SHA **must** equal the governance original's `lineage_manifest_original_raw_sha256` |
| `ec341_manifest_dependency_originals` | Ordered full `{path,sha256}` array equal to the original EC341 `_check_manifest()` dependency list, including all context, old source/history, EC337 archive ZIP and every true signed hop and sibling |
| `ec341_signer_public_key_copies` | Array of exact `{public_hex, public_key_original}` ordered by public hex; covers the old issuer roster, all successor issuers, all separate witnesses, including forks, with unique 32-byte SHA-pinned raw public key copies |

All file references use **exactly** `{ "path": "/absolute/normalized/path", "sha256": "64-lowercase-hex" }`; old legacy original paths embedded in the manifest must exactly match the corresponding new receiver source entries. No replaced, omitted, reordered, duplicate or out-of-roster dependency source is accepted. Every matching raw key copy must contain exactly the 32 bytes named by the original issuer or witness roster. These copies may be prepared for local byte comparison; **they are not themselves EC341-signed original key certificates**. Genuine Ed25519 verification comes exclusively from the old original signed edge and observation documents.

**Missing upstream:** when EC385 has no authenticated original `ec342_governance_roster_original` and hold SHA, all new channel fields except `tsa_channel_id` must be `null`, with the two lists empty. The channel reports no authentic EC341 source and counts zero. Missing historically signed originals can never be filled with a newly generated receiver manifest.

## Inputs and deterministic inventory

Standalone read-only entry points:

```sh
python -B scripts/ces_cas_historical_root_conflict_archive.py derive-historical-ec341-root-inventory --help
python -B scripts/ces_cas_historical_root_conflict_archive.py audit-historical-ec341-root-conflict-archive --help
```

Fixed unified isolated read-only entry:

```sh
python -B scripts/ces_next.py audit-historical-ec341-root-conflict-archive DeliveryAudit AuditHistoricalEC341RootConflictArchive --help
```

Each standalone command inherits **all EC385 audit inputs**, including its external retained inventory SHA and original receiver archive path and SHA. In addition:

| Switch | Required value |
| --- | --- |
| `--historical-ec341-signed-root-conflict-archive-bundle-file` | Absolute pinned EC386 receiver bundle path |
| `--expected-historical-ec341-signed-root-conflict-archive-bundle-sha256` | SHA-256 over exact original EC386 bytes |
| `--historical-ec341-signed-root-inventory-sha256` | One outside-retained SHA **per epoch** for all original root/edge/witness sources and conflict identifiers |
| `--historical-ec342-root-conflict-binding-inventory-sha256` | One outside-retained SHA **per epoch** for old EC342 hold binding, root SHA trio and public-key copy SHA inventory |
| `--minimum-historical-ec341-signed-edge-count` | One bounded integer per epoch (0–240) |
| `--minimum-historical-ec341-signed-observation-count` | One bounded integer per epoch (0–30) |
| `--minimum-historical-ec341-verified-sibling-count` | One bounded integer per epoch (0–16); only actually signed and observed conflicts count |
| `--expected-retained-historical-ec341-signed-root-conflict-inventory-sha256` | **Audit only**: full independently retained unsigned receiver-verified inventory SHA |

A **derive** call returns a deterministic local **unsigned** inventory and SHA, not a certificate. After genuinely independent retention, an **audit** call can check the caller's SHA and numeric floors; a caller-entered matching SHA alone does not prove this retention actually happened. The normalized canonical live EC385 parent result SHA forms part of the derived inventory. Two channels and later epochs are compared conservatively for changed, regressed or ABA root/branch evidence; no winner is selected or hidden fork count inferred. EC353 sender-label paths and caller-supplied archive paths are explicitly barred from new authenticated old EC341 original sources.

## Status / rejection / external limitations

All lawful observations (including a fully verified, genuinely signed *visible conflict*) return **exit code 2 and a `_unresolved` status**. Rejected role/signature, input and unavailable originals return **3/4/5**, with exact nonpromoting denial JSON. The fixed `ces_next.py` entry invokes the fixed installed offline verifier using `python -I -B`, checks the complete JSON schema and every negative-capability field, and never permits arbitrary child commands or private-key signing.

Old EC341 real cryptographic local signing only proves claims made by the keys whose bytes were supplied and matched the old roster. It **does not** establish real-world institution identity, an independently licensed/root-trusted issuer, independent custody, key nonrevocation, all global competing roots, globally latest epoch, physical hold or delivery, remote CAS/WORM effect, reliably calibrated UTC, or full EC337 non-mock third-party historical ancestry. The EC344 source checkpoint remains **unsigned**. Existing EC249 INCOMPLETE, EC250 BLOCKED, B001 OPEN, Quality=false, final NOT_STARTED, and original native PowerShell V4.60/R150 remain unchanged.

## Local scope of the bundled tests

**18/18** focused old-format tests passed in a single invocation with locally generated genuine old EC341 issuer, witness, signed edge and observation bytes, EC342 original hold and EC343 bound base. Of these, **three** outer EC386 audit/inventory tests **MOCK** the EC385→EC369 parent receiver engine while truly rechecking the old EC341 cryptographic branch and its hold; old EC317/318 inherited deeper ancestry uses legacy **MOCK** fixtures. No independent, genuine full production EC385→EC369 receiver corpus or full historical EC341→EC337 third-party archive was furnished. Original PowerShell 7/15 Smoke, OS/Git/CI/Provider E63–E66 and final user acceptance are postponed for unified user-assisted validation.
