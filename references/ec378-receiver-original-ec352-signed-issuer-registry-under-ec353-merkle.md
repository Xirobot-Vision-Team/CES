# EC378 / signed EC352 originals below genuine old EC353 Merkle leaves

## Trust boundary and dependency

Original context is EC352 `construction/ec352_key_registry/registry.py` and EC353 `construction/ec353_transparency/transparency.py`. This extension reuses their **actual original domains**; it never signs or invents a replacement historical record. It first executes `ec377_historical_transparency.transparency_archive.audit(**entire_parent_input)` from the production source. This requires authentic signed EC353 log/witness/Merkle original replay and the live EC376→369 receiver chain before any new EC352 original receives an adjudication.

A historic EC353 publication manifest may contain `path` values that refer to sender-side filenames that have never existed on the receiver machine. These are **historical SHA labels only**. The receiver-supplied absolute normalized `{ "path": "/real/receiver/original", "sha256": "64 lowercase hex" }` references identify the only files read. Original bytes are independently checked with full SHA and canonical JSON; old manifest sender labels are added to a denylist and never opened. All source and new archive references are independent whole-SHA pinned.

## New receiver archive (canonical JSON, no generated cryptographic credentials)

```
{
 "schema":"ces.ec378.receiver_historical_ec352_registry_original_archive.v1",
 "parent_ec377_canonical_result_sha256":"<actual canonical whole JSON SHA>",
 "ec377_historical_transparency_archive_original_sha256":"<actual parent archive whole SHA>",
 "claimed_directory_lineage_id":"<same actual EC377 directory lineage>",
 "epochs":[
  {"epoch_index":0,
   "claimed_tsa_channel_ids":["HistoricTsaA","HistoricTsaB"],
   "registries":[
    {"registry_channel_id":"HistoricRegistryA",
     "root_public_key_original":{"path":"/receiver/registryA/root.key","sha256":"<actual SHA>"},
     "root_reference_original":{"path":"/receiver/registryA/root.json","sha256":"<actual SHA>"},
     "events":[{"signed_event_original":{"path":"/receiver/registryA/event1.json","sha256":"<actual SHA>"},
                "signer_public_key_original":{"path":"/receiver/registryA/operator.key","sha256":"<actual SHA>"}}]},
    {"registry_channel_id":"HistoricRegistryB", "root_public_key_original":{"path":"...","sha256":"..."},
     "root_reference_original":{"path":"...","sha256":"..."},
     "events":[{"signed_event_original":{"path":"...","sha256":"..."},
                "signer_public_key_original":{"path":"...","sha256":"..."}}]}
   ]}
 ]
}
```

All SHA/path placeholders in the example must be replaced with actual originals; example `...` paths are intentionally **not executable evidence**. `epochs` length 1–3 must exactly equal the production parent epoch count and each epoch index must match. Two sorted unique registry channel IDs are required. Each has 1–6 signed events, at most 8 signed events total per epoch. `claimed_tsa_channel_ids` is a sorted, distinct list of 1–4 syntactically valid names, used only to bound the *claimed* entries inside cryptographically signed EC352 events, **not** to certify EC351 sources. All original JSON must be canonical in the unchanged parent format.

### Input scalar additions

- `--historical-registry-archive-bundle-file` and `--expected-historical-registry-archive-bundle-sha256`: independently pinned new receiver archive.
- `--expected-retained-historical-registry-inventory-sha256`: audit-only SHA of the previously derived **unsigned** inventory, copied and retained outside the tool; never supplied by the receiver bundle itself.

### Repeated per-historic-epoch additions

- `--historical-registry-root-key-inventory-sha256`: SHA of canonical ordered array `[{registry_channel_id,root_public_key_original_sha256,root_reference_original_sha256}, ...]`.
- `--historical-registry-signed-head-inventory-sha256`: SHA of canonical ordered array `[{registry_channel_id,signed_terminal_head_original_shas:[...]}, ...]`.
- `--minimum-historical-registry-signed-event-count`: per-epoch external floor (0–8).
- `--minimum-historical-registry-dual-log-inclusion-count`: sum of actually covered `(log, artifact_kind, artifact_original_sha256)` pairs on unique signed-head ancestries of both old logs (0–20). Both logs must independently include *every* root-reference and event original for a fully consistent local result; a single log's inclusion is insufficient.

All EC377 and earlier exact parent command arguments remain mandatory. In the standalone derive command the new audit-only inventory SHA is intentionally omitted; the existing parent EC377 retained inventory SHA is **still mandatory**. For a production audit, the operator must retain a derive inventory SHA outside the receiver input archive and supply that value. The stored SHA is not a signature and is not itself independent proof of physical custody.

## Verifier rules

- The **unchanged** EC352 root document is verified under `CES/EC352/RegistryRootReference/v1\0` using exactly the reopened 32-byte root public key. Its registry ID, root-key SHA, claimed organization/URL, `valid_from`/`valid_until` and Ed25519 bytes are checked. This is self-signature of a **claimed** issuer, not official credential verification.
- Every unchanged signed EC352 event is reopened under its whole SHA and checked with `CES/EC352/RootAuthorizedEvent/v1\0` (root signing key) and `CES/EC352/OperationalSignerEvent/v1\0` (actual event signer public key, except terminal revoke). Root-reference SHA, root-key SHA, signer SHA, event kind/sequence, entries and issue/expiry are exact. No event can extend beyond its own signed root reference. Historical `rotate` additionally requires an actual predecessor operational key signature under `CES/EC352/PriorSignerRotation/v1\0`. Non-rotation prohibits swapping the operational key. Signed predecessor graph and forbidden re-grant after an already signed branch revocation are checked using unchanged EC352 `_validate_chain`.
- The historical EC377 unsigned manifest is only used to map old SHA labels. The EC377 old real log/witness and signed checkpoint replay is performed again from receiver copies; every claimed original EC352 root or event SHA must appear in a **verified RFC6962 inclusion** under an **authentically Ed25519 log-signed checkpoint** with an actually witness-signed original. Only checkpoints in the unique append-consistent head ancestry count toward complete dual-log coverage.
- Reader byte cache exists only because the same exact SHA-pinned root/event file must be read once as an authenticated EC353 *leaf* and once as an authenticated EC352 *signed document*. Cache reuse is permitted only for those narrowly enumerated roles; signer keys, auditor keys, parent archives and other old origin role paths cannot be relabeled. File identity is rechecked in the inherited late whole-SHA/identity check and forbidden sender path intersection.
- Authentic old EC375 root/channel custody keys and EC376 auditor keys, independently reopened from previously verified receiver parent archives, and EC353 log/witness keys are prohibited as new root/operator signers. Claimed root organization collisions with purported log/witness organizations and repeated role/key claims are adverse, never proof of separate legal institutions.
- Root public key and its original signed root-reference SHA are stable across consecutive epochs unless true old root-authorized transfer evidence exists. The EC352 original event signature domain contains no such cross-root transfer, so any observed root change stays unresolved. If an epoch uses a different terminal signed event, the new signed predecessor ancestry must genuinely include the preceding epoch's signed head; otherwise raise an adverse cross-epoch flag.

## Outcome / error and excluded guarantees

`derive-historical-registry-inventory` produces `schema: ces.ec378.unsigned_receiver_old_ec352_signed_registry_inventory_unresolved.v1` with an explicit unsigned nested inventory and `receiver_verified_historical_registry_inventory_sha256`. `audit-historical-registry-archive` only reports the inventory hash and strict per-epoch summaries under `schema: ces.ec378.receiver_real_ec352_issuer_signed_registry_merkle_ancestry_unresolved.v1`; it never exports a PASS. Both lawful commands return **2/unresolved**, even with pristine fixture crypto, because actual EC351→337 canonical signed originals have not been re-executed. SHA/role/format/signature denials are **3 permission_denied**, **4 invalid_input** or **5 unavailable**. The isolated `ces_next.py` route validates exact response schemas, all false prohibited assertions, external SHA/floor constraints, count sums and lawful exit code, without elevating disputed evidence.

Do not infer actual official issuer qualification, genuine EC351 source attestation key, complete EC352 public root census, globally current EC353 log head, global absence of hidden forks or revocations, independently trusted UTC, physically separate institutions, complete EC355/356 old canonical parent results, external CAS/WORM writes, final acceptance or native PowerShell smoke. These are pending upstream original records and separate assisted acceptance. EC249/EC250/B001/Quality/final gates remain unchanged.
