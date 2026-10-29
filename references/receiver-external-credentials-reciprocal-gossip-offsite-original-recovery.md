# EC395: original external-credential claims, reciprocal signed witness disclosure and two-site copy recovery

**Construction release:** V7.05 / R395 / EC395. **Scope:** receiver-only, offline, no permission grant. This is a *bounded cryptographic evidence-verification contract*, not a grant of accreditation, legal custody, globally complete publication, judicial jurisdiction, qualified TSA status, or physical WORM status. One EC only. The unchanged EC394 audit is actually invoked; it calls the unchanged EC393 audit and therefore EC392 and both EC391 histories. An inherited external reported PASS cannot replace that real audit.

## Commands and parent integrity

```
cd ces
python -I -B scripts/ces_cas_historical_credential_gossip_archive.py derive-historical-ec339-credential-gossip-archive-inventory --help
python -I -B scripts/ces_cas_historical_credential_gossip_archive.py audit-historical-ec339-credential-gossip-archive --help
python -I -B scripts/ces_next.py audit-historical-ec339-credential-gossip-archive DeliveryAudit AuditHistoricalEC339CredentialGossipArchive --help
```

The standalone `derive-...-inventory` receives **all EC394 `audit` arguments** (including its externally retained inventory SHA), all eight new scalar inputs and four new repeated inputs. The `audit-...` additionally requires `--expected-retained-historical-ec339-credential-gossip-archive-inventory-sha256` from another, demonstrably prior channel, never an ad hoc value copied from the same derive invocation. Derive intentionally emits an *unsigned* full inventory; audit reports only its digest. Every valid/evaluable outcome uses `exit_code=2` / `*_unresolved`; invalid inputs, forged/unauthorized originals or unavailable sources deny 4/3/5. No legal PASS state.

New scalar input names (pass each with `--` and hyphens in place of underscores):

- `historical_ec339_credential_gossip_archive_bundle_file` and `expected_historical_ec339_credential_gossip_archive_bundle_sha256`: actual absolute SHA-pinned bundle original.
- `expected_outside_retained_ec395_role_roster_sha256`: two issuers + two offsite archivists roster, externally pinned.
- `expected_outside_retained_ec395_external_licensing_basis_sha256`: original **opaque** alleged licensing/public-register bytes; neither provenance nor official truth follows from their presence.
- `expected_outside_retained_ec395_first_credential_original_sha256`: credential original of issuer A, **not whichever credential happens to be first in a caller-chosen list**.
- `expected_outside_retained_ec395_first_offsite_receipt_original_sha256`: first epoch receipt from *the first original roster archivist*, not an arbitrary available receipt.
- `expected_outside_retained_ec395_credential_issuer_a_public_hex` and `_issuer_b_public_hex`: distinct externally retained raw 32-byte Ed25519 public keys.

New repeats, **exactly one value per 1–3 historical epochs**:

| Receiver argument | Repeat CLI flag | Allowed value |
|---|---|---|
| `historical_ec339_reciprocal_gossip_inventory_shas` | `--historical-ec339-reciprocal-gossip-inventory-sha256` | external SHA-256 of signed offer/ack/confirm review rows |
| `historical_ec339_offsite_replica_inventory_shas` | `--historical-ec339-offsite-replica-inventory-sha256` | external SHA-256 of both archivists' signed copy-review rows |
| `minimum_historical_ec339_reciprocal_gossip_counts` | `--minimum-historical-ec339-reciprocal-gossip-count` | integer 0–1; count only if all three signed stages, complete parent view, verified stamp times and clean parent are present |
| `minimum_historical_ec339_offsite_replica_counts` | `--minimum-historical-ec339-offsite-replica-count` | integer 0–2; each count requires a distinct signed, genuine-stamped, source-identical archive receipt, bounded genuine gossip and credentials |

The receiver recomputes inventories from actual verified originals. External floor disagreement is adverse and remains unresolved; it is not quietly replaced by the currently observed digest. This is *not* cryptographic proof that the pins were held prior to the dispute.

## Source format, signers, timestamps and history

All manifest, claim and signed originals use exact-key canonical JSON. The canonical object-to-be-signed uses `offline_transfer_registry.registry.canonical`; signatures are raw Ed25519 hex on the domain prefix plus canonical claim bytes. The relevant `schema` constants and complete exact allowed key sets are in `construction/accredited_gossip/protocol.py` and are authoritative. Every reference is `{"path":"absolute normalized path","sha256":"64-lowercase-hex"}`. Genuine timestamp tokens are **raw original DER RFC3161 CMS/X509** verified with the original, unchanged EC394 witness TSA root and furnished signed CRLs; `claimed_*_utc` is not accepted as an independently authenticated timestamp. The receiver does not use online OCSP, issue timestamps or generate keys.

EC395 bundle `ces.ec395.original_credentials_reciprocal_gossip_archive_bundle.v1` has these exact top-level fields:

```
{
  "schema": "ces.ec395.original_credentials_reciprocal_gossip_archive_bundle.v1",
  "claimed_directory_lineage_id": "<same actual EC394 lineage>",
  "parent_ec394_registered_witness_bundle_original": {"path":"...","sha256":"..."},
  "external_role_roster_original": {"path":"...","sha256":"..."},
  "external_licensing_basis_original": {"path":"...","sha256":"..."},
  "external_credential_attestations": [ {"issuer_id":"...","signed_credential_original": {"path":"...","sha256":"..."}, "rfc3161_credential_token_original": {"path":"...","sha256":"..."}}, "<second issuer same shape>" ],
  "epochs": [{"epoch_index":0,"gossip":{"offer":{},"acknowledge":{},"confirm":{}},"archives":[{},{}]}]
}
```

The illustrative string `"<second issuer same shape>"` above is a placeholder for an actual *object*, not valid wire input. All four signer entries in the original role roster have precisely `role_id`, `site_id`, `public_hex`, `public_key_original`; two `credential_issuers` and two `offsite_archivists` are required. They must be pairwise different in key, site label and signer ID and must not reuse EC393 custody party/operator or EC394 registrar/dispute/witness keys/sites/party IDs. Raw original bytes must exactly match the claimed public key. This is **identity collision resistance**, not proof of organizational independence in law.

The two independent signed credential originals use `ces.ec395.original_signed_cross_authority_credential.v1` and domain:

```
CES/EC395/IndependentlySignedExternalCredential/v1\0
```

Each exact claim `ces.ec395.signed_cross_authority_credential_claim.v1` binds: lineage, credential issuer ID and site, actual original EC394 external role roster SHA, actual original EC393 custody roster SHA, genuine EC394 bundle SHA, opaque external licensing source SHA, exact EC394 TSA X509 root **certificate DER digest** and policy OID, SHA of the canonical sorted roster of *all relevant current raw signer keys* (EC394 four external roles, EC393 four custody roles, and new four roles), fixed claimed scope `local_evidence_custody_and_timestamp_origins`, issued UTC, and effective start/end UTC. Both actual Ed25519 signatures and separate RFC3161 original tokens must verify; claimed windows must cover the declared cutoff for local bounded qualification counts. A signed credential presented after the cutoff is not a prior credential. Faked signatures, mismatched roots, credentials for another bundle, or licenses pinned only by the new caller are denied or marked adverse, never granted official trust.

## Three genuinely signed, timestamped reciprocal witness stages

Every epoch contains exactly three `gossip` slots: `offer`, `acknowledge`, `confirm`. Each slot has precisely `signed_original` and `rfc3161_token_original` references, both null only for a declared absence. The **same genuine two Ed25519 EC394 witness signers** participate in A→B→A order; no newly supplied witness key can replace them.

- A's signed `offer` references the SHA of the **real audited EC394 unsigned inventory**, authenticated original EC394 bundle SHA, actual EC394 signed cutoff notice SHA, epoch, A and B role IDs, ordered signed original witness observations claimed from A and B, a ZERO predecessor and claimed exchange UTC. Domain: `CES/EC395/ReciprocalWitnessOffer/v1\0`.
- B's signed `acknowledge` has the same exact claim fields in the reversed roles and binds the **original SHA of A's offer**, not an unsigned reconstruction. Domain: `CES/EC395/ReciprocalWitnessAcknowledgement/v1\0`.
- A's signed `confirm` binds the **original SHA of B's acknowledgement**. Domain: `CES/EC395/ReciprocalWitnessConfirmation/v1\0`.

Every claim uses schema `ces.ec395.signed_reciprocal_disclosure_claim.v1`, fields `directory_lineage_id`, `parent_ec394_bundle_original_sha256`, `parent_ec394_verified_inventory_sha256`, `ec394_signed_dispute_notice_sha256`, `epoch_index`, `stage`, `witness_id`, `peer_witness_id`, `own_observation_shas`, `peer_observation_shas`, `previous_stage_signed_original_sha256`, `claimed_exchange_utc`, and `schema`. Signed outer original uses schema `ces.ec395.original_signed_reciprocal_witness_disclosure.v1`, `claim` and `signature_ed25519`.

The receiver reopens each observation's actual EC394 original reference from the *unchanged parent bundle*. That parent audit cryptographically verified signatures on real EC393 operator-signed log Heads. Supplying an unknown observation SHA in gossip is rejected as **not verified**. A genuine signed *subset* or discrepancy is retained as a named original per-stage disclosure conflict, never rewritten as a consensus or silently ignored. Non-monotonic signed/genuine-token times, absent prior stage, a token later than the cutoff, or a missing genuine witness makes gossip unbounded. A locally complete exchange requires the exact two actual observed source sets and all three timestamped, chronologically ordered originals; inherited visible signed fork is still adverse and is never awarded a winner. A later signed claim is required to occur **after the previous stage's authenticated token time**, not merely after its self-declared clock.

## Two separate signed original-to-replica recovery claims

Each epoch's `archives` has exactly **two** archivist groups, one for each actual new roster archivist:

```
{
  "archivist_id": "<original role ID>",
  "signed_receipt_original": {"path":"...","sha256":"..."},
  "rfc3161_receipt_token_original": {"path":"...","sha256":"..."},
  "copies": [
    {"source_original":{"path":"...","sha256":"..."},
     "offsite_copy_original":{"path":"different distinct path","sha256":"same original bytes SHA"}}
  ]
}
```

The receiver builds its *own* exact bounded required source set from authentic EC394 originals (bundle, EC393 link, external roster, trust registry, case file, signed notice/status and original tokens, all site registration generation original and raw key/token materials, EC394 genuine signed observations and their Head/token originals through that epoch), plus EC395 two signed credential originals/tokens, new issuer/custodian roster, original opaque licensing register, all three gossip signatures/tokens. Bounded **100 unique original bytes**, each max **600,000 bytes**, to avoid accidental unbounded file-system scans. This is not claimed to include all pre-EC394 history; EC394 still audits that inherited history independently.

The exact complete set of required **source paths + SHA** must be copied at both distinct claimed archive sites, independently. Source originals are re-read and their byte copies re-read and compared exactly, not merely compared by filename. Replicas may not alias a source, another replica, an inherited original, a credential/gossip original, or a signer key path. The signer signs the canonical SHA of the **full path-bound source/replica pairs**, actual EC394 original and verified parent inventory SHA, notice SHA, present epoch and archivist site, externally pinned licensing basis SHA, genuine confirmed gossip SHA, predecessor *signed receipt SHA per archivist* (or ZERO for the first epoch), and sealed UTC. Domain: `CES/EC395/IndependentOffsiteOriginalReadback/v1\0`; schema `ces.ec395.original_signed_offsite_recovery_receipt.v1`, claim schema `ces.ec395.signed_offsite_recovery_receipt_claim.v1`.

Receipt signatures are checked against the original second-line archivist Ed25519 keys; each has real RFC3161 token and CRL evaluation. A positive local bounded readback additionally requires the seal UTC to follow the authenticated final gossip timestamp and the latest furnished credential timestamp; later epochs may not jump across an absent predecessor or roll back their signed archival timestamps. A missing, late or otherwise unbounded archivist receipt breaks that archivist\'s continuity for all later epochs; subsequent signatures cannot restore the per-epoch bounded count even when their own signatures verify. Both originals and their independent copies are read with path/SHA constraints and a final source reread; still *not* a kernel-atomic snapshot, signed physical location attestation, or external WORM readback.

**No circular archive manifest**: the EC395 bundle original itself is *not* required as an archived source because it embeds the signed archive receipt and replica references. Archival receipt sources may include prior genuine EC394 bundle bytes and other preexisting source originals; not themselves or their enclosing EC395 manifest. The full EC395 bundle is separately externally SHA pinned for audit.

A cryptographically signed inventory row or signed receipt **cannot prove** it actually existed at the claimed date, was seen by a legally recognized regulator, was distributed on a public channel, was held on physically separate WORM hardware, or that all potentially contradictory unseen signed Heads/OCSP revocations have been disclosed. The true authorized archive, legal issuer registration, case cutoff and physical site proof remain independently required.

## Reporting, denial, restrictions, final validation ledger

Signed parent + child original references, signed credential/timestamp summary, three per-epoch gossip stages, divergence cases, full signed archive pair-digests and counts appear in the unsigned derive inventory. Audit includes only digest and bounded source counts. External retained source SHA/count floors and a different-channel final whole inventory SHA are mandatory. Genuine but stale or missing proofs retain `*_unresolved` with adverse booleans. Forged signatures, non-actual original references, changed source bytes, alias path, malformed key/JSON/role/sequence or original copy mismatch are rejected with 3,4 or 5 according to cause. All legal output statuses remain **exit 2**, including locally internally consistent evidence. The last three real-world nonclaim flags always remain true; all `NEGATIVES` fields always false.

The receiver does not create keys, credentials, attested originals, DER tokens or new historical facts. It does not write sender files, CAS/WORM/device, network, Provider, Git, CI or native PowerShell. The `ces_next.py` route fixes `DeliveryAudit AuditHistoricalEC339CredentialGossipArchive`, calls an isolated Python process and strictly parses its output; it cannot convert a child 2/unresolved into success.

**Locally observed EC395 tests:** 13 focused tests passed, including true local Ed25519 issuer/witness/archivist signatures and original-to-replica bytes; one full child `derive → audit` integration builds true child signatures and fixtures but **mocks EC394 parent audit and off-line TSA timestamp checking**. Syntax and the two help entrypoints parse. No original real independent qualified regulator or TSA was contacted, no official licensing status or issuance capability was tested, and no real historical EC390→317 or true post-EC394 inherited DER token corpus was run. Deferred as cumulative, final user-assisted tests: full real EC394 enhanced history from previous round, fully independent real regulator/licensing and qualified TSA verification, real public signed fork dissemination and global revocation/reconciliation, physical offsite CAS/WORM device and time-of-retention verification, original PS7/15 Smoke, Windows/macOS, Git/CI, Provider E63–E66 and product final acceptance. Quality remains false, EC249 INCOMPLETE, EC250 BLOCKED, B001 OPEN, native PowerShell V4.60/R150 unchanged.
