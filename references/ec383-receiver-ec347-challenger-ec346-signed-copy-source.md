# EC383 receiver original protocol: authorized EC347 challenger / receivers and authentic EC346 signed copy-source bytes

Receiver-only, **V6.93/R383/EC383**. All paths in this handoff are receiver-held absolute normalized originals; SHA256 is lowercase 64-hex, independently captured **before** audit. The software cannot prove a same-operator SHA is externally retained, nor that a claimed storage ID corresponds to separately controlled hardware.

## Exactly structured new source archive

Supply `--historical-ec347-site-provenance-archive-bundle-file` with its whole-file `--expected-historical-ec347-site-provenance-archive-bundle-sha256`. The original JSON **must** use exactly the following fields (illustrative list cardinalities only):

```json
{
  "schema": "ces.ec383.receiver_historic_ec347_signer_ec346_copy_provenance_archive.v1",
  "parent_ec382_canonical_result_sha256": "<SHA256 of actual live EC382 audit canonical JSON>",
  "ec382_historical_keeper_archive_original_sha256": "<whole SHA256 of actual EC382 original archive>",
  "claimed_directory_lineage_id": "<actual inherited authenticated lineage ID>",
  "epochs": [
    {
      "epoch_index": 0,
      "channels": [
        {
          "tsa_channel_id": "<real authenticated EC382 channel ID>",
          "ec343_authority_roster_original": {"path": "/receiver/ec343-roster-original.json", "sha256": "<whole SHA>"},
          "ec344_receiver_directory_original": {"path": "/receiver/ec344-directory-original.json", "sha256": "<whole SHA>"},
          "ec344_source_checkpoint_original": {"path": "/receiver/ec344-checkpoint-original.json", "sha256": "<whole SHA>"},
          "ec347_challenger_public_key_original": {"path": "/receiver/ec347-proposer-ed25519-public-raw32.bin", "sha256": "<whole SHA>"},
          "ec347_signed_challenge_originals": [{"path": "/receiver/ec347-round1-challenge.json", "sha256": "<whole SHA>"}],
          "ec347_signed_response_originals": [{"path": "/receiver/ec347-round1-response.json", "sha256": "<whole SHA>"}],
          "ec346_signed_observation_originals": [{"path": "/receiver/ec346-old-signed-copy-event.json", "sha256": "<whole SHA>"}],
          "ec345_verified_source_snapshot_original": {"path": "/receiver/ec345-verified-original-snapshot.bin", "sha256": "<whole SHA>"},
          "ec345_verified_source_ack_set_original": {"path": "/receiver/ec345-verified-original-ackset.bin", "sha256": "<whole SHA>"},
          "ec346_receiver_copy_site_originals": [
            {
              "receiver_id": "<old EC343 authenticated receiver ID>",
              "receiver_public_key_original": {"path": "/receiver/ec346-actor-public-raw32.bin", "sha256": "<whole SHA>"},
              "ec346_latest_signed_observation_original": {"path": "/receiver/ec346-last-signed-copy-event.json", "sha256": "<whole SHA>"},
              "claimed_storage_id": "<EXACT historical signed storage ID; not independent proof>",
              "copy_id": "<EXACT historical signed copy ID>",
              "explicit_copy_snapshot_original": {"path": "/receiver/local-copy-snapshot.bin", "sha256": "<current independently pinned SHA>"},
              "explicit_copy_ack_set_original": {"path": "/receiver/local-copy-ackset.bin", "sha256": "<current independently pinned SHA>"}
            }
          ]
        }
      ]
    }
  ]
}
```

In a real archive, `epochs` have the exact historic **1–3** indices and channels exactly the signed-authorized EC382 parent channel roster in canonical order (at most two per epoch). The three `signed_*_originals` lists must contain **all and exactly** the original signatures in the actual replayed old EC348 input: all EC347 challenge rounds (1–3), **all** EC347 signed receiver responses (not just latest), and **all** old EC346 signed receiver observation events, in their historical source order. The `ec346_receiver_copy_site_originals` list contains exactly one row per **old authenticated receiver whose original EC346 observation chain was replayed**, in original EC343 receiver roster order. The roster is historically bound through the unchanged prior EC343/342/341... replay; do **not** generate a new alleged authorization root or substitute another signer roster.

The `ec347_challenger_public_key_original` and every `receiver_public_key_original` are exact SHA-pinned original **raw 32-byte Ed25519** public key files, not PEM or private keys. They must match respective original EC343 proposer/receiver roster keys. Source snapshot and ACK files must match the genuine EC344 checkpoint/old EC345 validated source path and bytes. The original EC343 roster JSON may have a noncanonical whole-file encoding; its entire original SHA is pinned, while Ed25519 signatures are separately verified over the historic protocol's canonical **claim**, retaining the original bytes without inventing a new SHA.

**Explicit copy rule:** `explicit_copy_snapshot_original` and `explicit_copy_ack_set_original` must both be actual independently SHA-pinned receiver-accessible bytes or both `null`. They may only be populated for a receiver that actually signed the **last** EC347 `measured_readback` round, and their paths must equal that reply's and the corresponding EC346 latest observation's signed original copy paths. The old observation, signed response and original EC345 source SHA **and length** are all compared to locally measured current bytes. If one or both files are unavailable, set both to `null` and preserve **unresolved**; do not read a path from a signed JSON claim by default. Signed `unavailable_claim` is adverse rather than evidence of remeasurement. A complete original history may exist even where not all current physical copy bytes can be presented; it is not acceptance.

**Entire historic source missing:** if the matching original EC382 channel's `ec348_full_replay_inputs_original` is `null`, set all channel objects ending `_original` to `null` and all channel list fields ending `_originals` to `[]`; the mandatory `tsa_channel_id` remains. This reports missing original source unresolved; fabricated signer/copy evidence is denied.

## New externally retained comparator flags (one per epoch, in order)

| Purpose | CLI flag | Type |
| --- | --- | --- |
| Original challenger/authorized receiver inventory | `--historical-ec347-actor-authorization-inventory-sha256` | SHA256 |
| Original EC346 signed event/copy site inventory | `--historical-ec346-copy-site-inventory-sha256` | SHA256 |
| Minimum EC347 challenged registered receiver count | `--minimum-historical-ec347-authorized-receiver-count` | bounded integer |
| Minimum EC346 original signed observation count | `--minimum-historical-ec346-signed-observation-count` | bounded integer |
| Minimum current locally retested EC346 copy **pairs** | `--minimum-historical-ec346-byte-retested-copy-count` | bounded integer |

The full audited final inventory adds a separate single `--expected-retained-historical-ec347-site-provenance-inventory-sha256`. **Derive mode omits only this final audit comparator**, while requiring all inherited EC382 audit values. The derived archive inventory object is **unsigned**. Preserve its SHA independently and furnish it as an audit comparator; deriving it yourself is not a third-party attestation. Missing/inconsistent historic inputs, witnessed signatures or copy bytes never become success merely because counters and hashes match. The new full result/derivation/audit CLI options are visible with `--help`.

## Processing and security boundary

- Every normal audit starts with **unmodified `ec382.audit`**, whose normal code requires actual old EC381→EC369 receiver original ancestry. Then reopen actual EC382 whole original and signed old EC347/346 originals. The old EC348→EC337 source is replayed if recovered, never replaced by a result report, private key or unit-test stand-in.
- Old EC346 signed observation original files are authenticated under `ces.ec346` original Ed25519 domain and public keys belonging to the actual EC343 receiver roster. EC347 challenge original files are separately signature-verified under the historic `ces.ec347` challenger domain with the original EC343 proposer. EC347 receiver responses use the *different unchanged reply domain*, including original challenge SHA/nonce, receiver public key, signed EC346 head SHA and source digest. The signed root/roster lineage from the original ancestor must still verify under inherited old code.
- Both EC349 channels in one historic epoch must agree on these old signer/source originals. Successor epochs cannot change a same-channel historical signer root, snapshot source or roll backward signed EC346 receiver head sequence without surfacing an adverse unresolved result. Fork completeness beyond visible originals remains unproven.
- Receiver-only hardened reads use path normalization, symlink protections, role-disjoint paths, exact SHA/size and repeated final identity checks. Sender origin labels from old EC353 are prohibited; no online/Provider/WORM/CAS or source mutation permitted. All lawful outputs exit **2 unresolved**, not completed acceptance. Denial exit 3, invalid input 4, unavailable 5.

## Test and non-proof honesty

`PYTHONPATH=construction python -m unittest -v ec383_historical_readback.test_readback_archive`: 33 focused local tests, 33 passes. Old EC346/347/348 signing and source replay are **genuine locally generated legacy-format originals**, but the imported deep EC347→EC337 test ancestor is **MOCKED**, and two new engine inventory tests **MOCK the full outer EC382→369 production parent** to constrain run cost. No independent provider third-party history, TSA/legal identity, physical independent machine/custodian, calibrated UTC, real external SHA-retention timestamp, global fork completeness, native PS7/OS/CI or final acceptance has been supplied/proven.
