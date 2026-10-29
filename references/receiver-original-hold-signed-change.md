# EC385 — Receiver-only original EC342 approved hold / EC343 signed-change archive contract

Construction release **V6.95 / R385**, new single EC **385**. This is an **evidence-reopening receiver**; no signer, offsite publisher, physical-delivery agent, revocation oracle, clock authority, or CAS writer is provided.

## Trust boundary and mandatory evidence ancestry

The audit calls actual unchanged `historical_offer.offer_archive.audit(**full_parent_arguments)` at invocation time and checks its exact unresolved schema and canonical-result digest. It independently reopens, whole-file-SHA-pinned, the actual **EC382→EC383→EC384** original receiver bundles, including the EC383↔EC382 and EC384↔EC383 source digest links, expected lineage, epoch and ordered channel sets. Where old EC348 original inputs exist, it invokes the old true EC348→EC345 original replay. A source absent from an authenticated prior archive **cannot** be substituted by a newer caller document. EC353 sender path labels cannot be upgraded to trusted receiver originals.

For each epoch and ordered TSA channel, supply the EC385 archive with exact fields `schema`, `parent_ec384_canonical_result_sha256`, `ec384_historical_offer_archive_original_sha256`, `claimed_directory_lineage_id`, and `epochs`. `schema` must be `ces.ec385.receiver_historic_ec342_approved_hold_ec343_signed_change_archive.v1`; each epoch contains exactly `epoch_index`, `channels`. The channel is a strict complete object with the following keys (every raw file reference has exact `path` and `sha256`):

- `tsa_channel_id`
- `ec342_governance_roster_original`, `ec342_hold_request_original`, `ec342_review_manifest_original`, `ec342_external_approval_original`, `ec342_signed_review_originals` (full ordered array of every signed review)
- `ec343_source_head_snapshot_original`, `ec343_source_head_ack_set_original`, `ec343_original_source_head_receiver_receipts` (all signed predecessor receipts)
- `ec343_signed_target_snapshot_original`, `ec343_signed_target_ack_set_original`, `ec343_original_target_receiver_receipts` (original target signed receipts)
- `ec343_original_signed_change_request`, `ec343_original_signed_change_approval` (different authorizing registered signer keys)
- `ec343_change_proposer_public_key_original` (identical original to actual EC384→EC345 proposer key), `ec343_change_approver_public_key_original` (original exact registered approver public bytes)
- `ec343_competing_signed_successors` (0–2 ordered complete same-parent siblings; each contains exact `snapshot_original`, `ack_set_original`, `signed_change_original`, `signed_approval_original`, `receiver_receipt_originals`)

**The provided target is not arbitrary.** It must match the original signed EC345 source snapshot and ACK pair already verified in EC383 and EC384, and must occur as the same `item_id` in the old **unsigned** EC344 checkpoint originally bound to EC383. A sibling must have an independent signed EC343 whole SHA/nonce and be listed in that same checkpoint. The legacy EC343 `_load_chain` and `_ackset` verifiers must reopen and validate the exact original Ed25519 signature domains and claims including signed predecessor receipt time, before counting a visible fork. Signed predecessor ACKs require every registered receiver; partial signed target ACK counts are adverse/unresolved, never a proven delivered result.

If a channel's authentically pinned EC348 source is truly missing, channel fields must be empty/`null` with no synthetic signed originals, and the output remains unresolved. The engine rejects extra channel/epoch/branch keys, forged SHA/reused file roles, path substitutions and signature mismatches. This module supports the original **EC342 base snapshot → one EC343 signed change** predecessor; it does not claim generalized multi-hop history recovery from a single EC345 source.

## New CLI argument names

The standalone wrapper is `scripts/ces_cas_historical_change_archive.py`. Its read-only subcommands are:

```sh
python -B scripts/ces_cas_historical_change_archive.py derive-historical-ec343-change-inventory --help
python -B scripts/ces_cas_historical_change_archive.py audit-historical-ec343-change-archive --help
python -B scripts/ces_next.py audit-historical-ec343-change-archive DeliveryAudit AuditHistoricalEC343ChangeArchive --help
```

All prior EC369–EC384 required original source arguments must be supplied unchanged; use `--help` for their exact inherited full names. EC385 adds:

| CLI flag | Meaning |
| --- | --- |
| `--historical-ec343-change-approval-archive-bundle-file` | Absolute, normalized receiver-local EC385 canonical JSON file |
| `--expected-historical-ec343-change-approval-archive-bundle-sha256` | Outside-received whole-file SHA-256 of EC385 archive |
| `--historical-ec342-approved-hold-inventory-sha256` | Once per epoch, external-retained canonical SHA-256 over verified signed EC342 originals |
| `--historical-ec343-signed-change-inventory-sha256` | Once per epoch, external-retained canonical SHA-256 over verified signed EC343 changes |
| `--minimum-historical-ec342-signed-review-count` | Once per epoch, signed reviewer-original minimum |
| `--minimum-historical-ec343-signed-change-count` | Once per epoch, signed change-original minimum |
| `--minimum-historical-ec343-signed-ack-count` | Once per epoch, signed receiver receipt-original minimum, including base and submitted targets |
| `--expected-retained-historical-ec343-change-approval-inventory-sha256` | **Audit only**, separately retained SHA of complete receiver-verified inventory (not emitted as proof) |

`derive` emits the deterministic **unsigned** inventory and its digest for independent future retention. `audit` compares its digest against an independently provided reference. An identical caller-supplied SHA is still not proof that any external party ever received the inventory; all normal outcomes remain **exit 2 unresolved**. Denied/invalid/unavailable use exit codes **3/4/5**. The fixed unified route invokes only the isolated `python -I -B` verifier and verifies the complete denial/success JSON schema with conservative negative capability flags. No private signing API, network, mutable archive publication or native PowerShell update is added.

## Important nonclaims

The old EC342 signed vote quorum and EC343 signed change/approval are only byte-level **claims by the registered public keys**. They do not establish legal power, person or institution identity, genuinely independent custody, irreversible WORM/CAS state, remote operational freeze or release, physical receipt, a globally complete fork census, unrevoked keys or certified UTC. The EC344 checkpoint is **unsigned**. Matching two paths/local sources is not a third-party forensic proof. The historical EC347→EC337 test ancestor and external EC384→EC369 production replay have not been independently validated this round. Prior `Quality=false`, final `NOT_STARTED` and all historical gate states are unchanged.
