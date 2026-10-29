# EC352 — Verified offline attester-key registry references, rotation and revocation

**Single bounded round: V6.62 / R352 / EC-352.** The auditor consumes **explicitly presented originals only**. It does not fetch websites, enroll public keys, sign records, create institutional identities, or accept an alleged earlier verification result. First it **executes EC351→EC350→EC349→EC337** again (original signed keeper and receipt history, RFC3161/CMS/X509, root/source Ed25519 statements, DER OCSP + CRL). Only then does it evaluate *new*, separately SHA-pinned, signed institutional-registry **claims**.

## Critical trust boundary

Verifying two genuinely different raw Ed25519 keys, two signed root-reference documents and complete signed key histories proves that the **provided keys signed the provided bytes**. The self-signed roots and separately typed SHA-256 hashes do **not** prove that the keys belong to a named outside regulator/publisher, that the registries are independently curated or complete, or that a website, time, qualified TSA, real revocation feed, legal identity or external custody is genuine. A third-party independent source for each official root and historical key is still required. Even the most favorable result is **`exit_code = 2`, `*_unresolved`**, never PASS or ACCEPT.

## Implemented evidence and guarantees

1. **0–2 root channels**, usually `registry_a` and `registry_b`, in ascending order. Each has a nonempty canonical UTF-8 JSON *self-signed root reference* (up to 12 KiB), a separate **32-byte raw Ed25519** root public key, and independent whole-original SHA-256 pins for both. Root reference declares a claimed issuer name, unfetched HTTPS document URI, channel ID, key-file SHA, and <=366-day caller-evaluation validity. Verify the real Ed25519 signature against the supplied key. A root key cannot be shared across registry channels or reused as an EC351 source attester key.
2. **0–8 event originals total, at most 6 per registry, sequence 1–4.** Each is a canonical UTF-8 JSON signed event (up to 24 KiB), with an explicit whole-file SHA and a separately SHA-pinned 32-byte *operational signer public-key file*; repeated use of that **same signer original within the same registry** is allowed. The event root signs the exact event body independently of the operational signer. No event file, root reference, root key or signer may alias a parent original or an incompatible new role. Reject modified bytes and perform final re-read drift detection.
3. **Verified sequence and key history:** sequence 1 must be `activate` with `previous_event_sha256 = "GENESIS"`, signed by the root and the new operational signer. `renew` requires the same operator key and its genuine signature. `rotate` requires the **previous operator's genuine signature and the new operator's genuine signature**, in different signature domains, *plus root signature*, with a different next key. `revoke` is a terminal root-signed emergency revocation of the operational signer, with no new entries and no operator-signature assertion. An event after a revoked signer, an unknown predecessor, wrong SHA predecessor, a forged old/new signature, a reused cross-registry operator key or an unsupported operation is denied. Refuse silently restoring a source key revoked in the observed signed ancestry.
4. **All visible branches validated, no "newest winner":** the SHA-pointer graph is completely checked over every presented event. Up to two children per signed predecessor; multiple terminal heads are reported as a visible fork, never hidden by choosing a greater sequence, later claimed UTC, or a favorable signer. An invalid signature inside a visible fork is **denied**, not treated as a legitimate fork ambiguity. Previously unsupplied event heads, epochs and hidden global forks remain unproven.
5. **Exact EC351 attester and TSA bindings:** up to two sorted per-event entries per TSA channel with exact SHA pins of the *real EC351 verified signed statement*, raw attester-key file, policy/source document, TSA root original file and X.509 DER fingerprint, plus policy OID, signed `authorized` / `revoked` status and bounded window. Do not infer authorization merely because a registry contains a matching name. A contradictory signed SHA/policy/source claim is `contradictory_signed_binding` and unresolved, not upgraded. Missing latest-snapshot record, missing history, signed revocation, a signer-root revocation, expired current snapshot/entry or a gap between signed epochs all remain distinguishable. Historical attestations for a *different* source-key on the same TSA channel are kept visible; a new grant for the EC351 source key is not a clean key rollover unless the earlier key has an explicitly signed retirement/revocation. The earlier key is a signed registry claim, not independent proof of that older key's custody.
6. **Retrospective history cannot prove earlier ownership:** an event first authorizing an EC351 source-key only *after* that EC351 source statement's signed issuance is classified `retroactive_registry_claim_only`; a later signed grant cannot manufacture an earlier institutional authorization. Both registries must independently provide matching, live, **continuously** signed historical grants before the locally most favorable *claim-consistent* state is possible. All claimed times still come from local original signers and caller evaluation, not a reliable external clock.
7. **Inherit all EC351 defects:** missing or forked root/TSA ancestry, unpinned receipt, bad clock or signed CRL, missing/unknown/stale/contradictory OCSP, missing attester source statement and incomplete external origin always dominate registry consistency. No remote Provider/CAS/WORM reader/writer, network, private-key, TSA issuer, OS root trust-store selection, real institution lookup, global registry discovery, legal status grant, or final approval path exists.

## Fixed operation routes

The standalone operator accepts all existing **EC351 audit** flags (and thus EC350/EC349 flags) as documented in [EC351](ec351-tsa-origin-ocsp.md). Its handoff command needs **only** all EC351 flags; it actually replays the signed parent chain and prints exact source-key/source-document SHA bindings for manually requesting third-party registry materials.

```sh
python -I -B scripts/ces_cas_attester_registry.py derive-registry-handoff <all EC351 flags>
python -I -B scripts/ces_cas_attester_registry.py audit-registry-history <all EC351 flags> --registry-evaluation-utc 2026-10-25T23:00:00Z <aligned registry flags>
```

For the fixed unified read-only route:

```sh
python scripts/ces_next.py audit-attester-key-registries DeliveryAudit AuditOfflineAttesterKeyRegistryHistory <all EC351 flags> --registry-evaluation-utc 2026-10-25T23:00:00Z <aligned registry flags>
```

The `2026-10-25` date is only a **syntax example**. Use the actual declared evaluation instant. Registry evaluation must not precede EC351 provenance evaluation. Exactly one self-contained `python -I -B` child runs on the unified route, and child JSON schema/counts/negative-authority fields are constrained by the unified router. No `--sign`, `--private-key`, `--output`, `--network`, or remote writer option exists.

| New repeatable audit flag | Required alignment / meaning |
| --- | --- |
| `--registry-evaluation-utc` | One exact UTC `YYYY-MM-DDTHH:MM:SSZ` caller claim |
| `--registry-channel-id` | 0–2 distinct ascending registry IDs |
| `--registry-root-reference-file` | One canonical root reference per registry ID |
| `--expected-registry-root-reference-sha256` | Whole-file root reference pin |
| `--registry-root-public-key-file` | Separate raw 32-byte Ed25519 key per registry ID |
| `--expected-registry-root-public-key-sha256` | Exact key-file byte SHA, **not official registration** |
| `--registry-event-channel-id` | One registry ID per event (up to eight total) |
| `--registry-event-file` | One complete canonical signed event original per ID |
| `--expected-registry-event-sha256` | Event-original whole SHA, exact-index aligned |
| `--registry-signer-public-key-file` | Current operational signer key original for each event; the prior key for `rotate` is found by verified predecessor SHA |
| `--expected-registry-signer-public-key-sha256` | Aligned key original whole SHA |

Every root repeat has one root record. Every event repeat has one event record. Event arrays are not head selectors; every presented event is inspected. File paths are absolute, normalized, and nonsymlink at point of reading, and whole-file SHA mismatches are denied. On an incomplete environment, genuine `cryptography` / `asn1crypto` verification may return `unavailable`, **not pass-through success**.

## Canonical signed root-reference JSON

Exactly these fields, all strings. The independent root public key **original file SHA** must match the reference, and `self_signature_ed25519_hex` verifies over `ROOT_DOMAIN + canonical_JSON(body_without_signature)`, with domain bytes `CES/EC352/RegistryRootReference/v1\0`. Required `schema` string: `ces.ec352.self_signed_institutional_registry_reference.v1`.

```json
{
  "schema": "ces.ec352.self_signed_institutional_registry_reference.v1",
  "registry_channel_id": "registry_a",
  "root_public_key_original_sha256": "<sha256 of raw 32-byte root key>",
  "claimed_issuer_organization": "Example claimed root institution",
  "claimed_issuer_document_uri": "https://example.org/registry-root",
  "valid_from_utc": "2026-10-25T10:00:00Z",
  "valid_until_utc": "2026-10-26T10:00:00Z",
  "self_signature_ed25519_hex": "<128 lowercase hex signature>"
}
```

## Canonical signed registry-event JSON

Exactly these keys. Signatures are **not part of the body** and all verify over the *same canonical event body* with **different role-specific prefixes**:

- Root: `CES/EC352/RootAuthorizedEvent/v1\0` (`root_signature_ed25519_hex`).
- New/current operator: `CES/EC352/OperationalSignerEvent/v1\0` (`current_signer_signature_ed25519_hex`); set literal `NONE` only for root emergency `revoke`.
- Old operator on `rotate`: `CES/EC352/PriorSignerRotation/v1\0` (`previous_signer_signature_ed25519_hex`); set literal `NONE` on `activate`, `renew`, `revoke`.

```json
{
  "schema": "ces.ec352.root_authorized_key_registry_event.v1",
  "registry_channel_id": "registry_a",
  "sequence": 1,
  "previous_event_sha256": "GENESIS",
  "event_kind": "activate",
  "root_reference_original_sha256": "<sha of self-signed root reference bytes>",
  "root_public_key_original_sha256": "<sha of root key original bytes>",
  "signer_public_key_original_sha256": "<sha of current operator key original bytes>",
  "issued_utc": "2026-10-25T10:30:00Z",
  "valid_until_utc": "2026-10-25T12:30:00Z",
  "entries": [
    {
      "tsa_channel_id": "channel_0",
      "source_attestation_original_sha256": "<sha of EC351 signed source statement original>",
      "attester_public_key_original_sha256": "<sha of EC351 raw attester public key original>",
      "source_document_original_sha256": "<sha of EC351 policy/source original>",
      "tsa_root_original_sha256": "<sha of EC350 X509 root original>",
      "tsa_root_der_sha256": "<sha of EC350 X509 parsed root certificate DER>",
      "tsa_policy_oid": "1.2.3.4.5.350",
      "authorization": "authorized",
      "not_before_utc": "2026-10-25T10:00:00Z",
      "not_after_utc": "2026-10-26T10:00:00Z"
    }
  ],
  "root_signature_ed25519_hex": "<128 lowercase hex signature>",
  "previous_signer_signature_ed25519_hex": "NONE",
  "current_signer_signature_ed25519_hex": "<128 lowercase hex signature>"
}
```

Angle-bracket fields are explanatory placeholders and **are not valid signed evidence**. Use CES's `reg.canonical(...)` sorted-key canonical JSON, not a pretty-printed copy; every SHA must be lowercase actual whole-file SHA of the supplied original. Sequence-2+ `previous_event_sha256` is the **exact preceding event original SHA**. For rotation, separately present the new signer public key and let the verifier retrieve the old key from the signed predecessor original. A root-signed `revoke` is terminal and contains `entries=[]`, both operator signatures `NONE`.

## Outcomes, limits and user-assisted checks

Seven outcomes: inherited EC351 unresolved; two root references absent; signed history incomplete; signed fork/contradictory binding; signer/key revocation or retrospective grant; stale/gapped/missing authorization; or both signed, fresh, historically bound registries consistent **yet real outside issuer authority unproven**. They all return **exit 2**, never a success exit0; cryptographic/path/role violations deny with exit3/4/5.

The operator still needs independently verified real root custody and institution authorization, official history completeness, third-party registry issuance and independently calibrated times, actual TSA and OCSP/CRL provenance and nonce exchange, unseen branches, old EC317/318 production evidence, offsite physical custody, remote CAS/WORM and Provider outcomes, native PS7 and 15 Smoke, Windows/macOS/Git/CI/Provider/E63–E66 and final acceptance. **EC249 incomplete, EC250 blocked, B-001 OPEN, global Quality=false, final NOT_STARTED** remain unchanged. All 26+ synthetic fixtures in this round use locally generated keys and do not establish external authority.
