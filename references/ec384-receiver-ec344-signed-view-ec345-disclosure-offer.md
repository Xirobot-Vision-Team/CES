# EC384 — receiver-controlled original EC344 signed views and EC345 disclosure offer lineage

**V6.94/R384/EC384**, strictly one incremental EC. A receiver supplies locally held **true original files** and separately retained lowercase whole-file SHA-256 pins. Nothing in this protocol gives a directory, an offer, a hash supplied by the same caller, a claimed UTC, or a claimed physical location independent legal/institutional authority.

## Original signers and actual checkpoint status

The original **EC343** governance roster is an inherited, verified old source; its `change_proposer` is the authorized EC345 challenge signer, while its `receivers` are independently authorized EC344 visibility-statement and EC345 response signers. Their originally published **raw 32-byte Ed25519 public keys** are reopened, verified against roster key, ID and organization, and compared against the identical actual EC383 public keys whenever the receiver has an EC346 signed copy site. A new key cannot be substituted to rescue an old signed claim.

The **EC344 directory** and **EC344 publication/visibility checkpoint** are **unsigned, SHA-pinned** scoped announcements. They are *not signed publication checkpoints*, nor proofs that a file was independently delivered. The real cryptographic claims are the separate registered receiver **Ed25519-signed EC344 visibility statements** (historic `CES/EC344/ReceiverVisibilityStatement/v1\0` domain). EC345 proposer-signed challenge originals use their different old `CES/EC345/OneItemDisclosureChallenge/v1\0` domain; registered receiver disclosure offers/unavailable responses use `CES/EC345/ReceiverDisclosureResponse/v1\0`. Do not silently treat a signed challenge as a signed offer.

## Archive envelope — exact JSON keys

Use the original receiver's `--historical-ec345-disclosure-archive-bundle-file` and pinned `--expected-historical-ec345-disclosure-archive-bundle-sha256`:

```json
{
  "schema": "ces.ec384.receiver_historic_ec344_view_ec345_signed_offer_archive.v1",
  "parent_ec383_canonical_result_sha256": "<actual canonical full LIVE EC383 audit SHA256>",
  "ec383_historical_site_archive_original_sha256": "<whole SHA256 of authentic EC383 receiver archive>",
  "claimed_directory_lineage_id": "<exact lineage ID bound through real EC383>",
  "epochs": [{
    "epoch_index": 0,
    "channels": [{
      "tsa_channel_id": "<actual authenticated old EC383/382 channel ID>",
      "ec345_disclosure_issuer_public_key_original": {
        "path": "/receiver/old-ec345-proposer-raw32.bin",
        "sha256": "<whole SHA256, SAME original ref as EC383 challenger>"
      },
      "ec344_ec345_registered_receiver_keys_originals": [
        {
          "receiver_id": "<first genuine EC343 registered receiver ID>",
          "receiver_public_key_original": {
            "path": "/receiver/first-receiver-raw32.bin",
            "sha256": "<whole SHA256, SAME EC383 ref when receiver is an EC346 site>"
          }
        }
      ],
      "ec344_signed_visibility_originals": [
        {"path": "/receiver/old-ec344-signed-view1.json", "sha256": "<whole SHA256>"}
      ],
      "ec345_signed_challenge_originals": [
        {"path": "/receiver/old-ec345-signed-challenge1.json", "sha256": "<whole SHA256>"}
      ],
      "ec345_signed_response_originals": [
        {"path": "/receiver/old-ec345-signed-response1.json", "sha256": "<whole SHA256>"}
      ]
    }]
  }]
}
```

The illustrative lists are abbreviated. In a real source the `epochs` array contains exactly **1–3** original authenticated epochs, each with the **exact same ordered 1–2 signed EC349 channel IDs** as both the authentic EC382 and EC383 parent original archives. A channel with a genuine old EC348 source **must** include **all** EC343 registered receiver keys in old roster order, exactly **all** old EC344 signed views, exactly **all** original EC345 signed challenges and **all** original signed responses, preserving original order, source paths and whole-file SHA values from the actual historical EC348→EC345 replay. No new signer identities, issuer claims or omitted signed revocations may be slipped into those lists.

The EC344 view list has at least two independently registered receiver signatures; historic bounds allow at most eight signed views, and at most two views per receiver. EC345 challenges are bounded by the old source and must be sequential per target item, using the original unsigned checkpoint's source SHA/context, predecessor **path and whole original SHA**, original challenge nonce, authorized proposer, actual requested audiences and historic evaluation time. Each EC345 signed response must reference the actual challenge SHA, one eligible authorized receiver, correct receiver nonce/time and historic offer/unavailable kind. An original **signed offer** for the actually furnished EC345 item is required, but conflicting signed unavailable claims remain adverse and **unresolved**. Never infer that an offer moved any physical bytes or that signed source paths were automatically opened in this new surface.

When the matching old EC382 channel's `ec348_full_replay_inputs_original` is `null`, supply `ec345_disclosure_issuer_public_key_original: null` and **all four channel list fields** as `[]`; only the authentic `tsa_channel_id` remains populated. This is a lawful incomplete-source **exit 2** outcome, not an invitation to fabricate an old EC345 audit. The retained EC383 receipt, source-site SHA and full parent audit are compulsory even in derive mode.

## External SHA/count floors per epoch

| Exact CLI option | Values |
| --- | --- |
| `--historical-ec344-signed-visibility-inventory-sha256` | SHA256 of derived exact registered receiver, view, checkpoint original inventory |
| `--historical-ec345-authorized-offer-inventory-sha256` | SHA256 of derived exact issuer, challenge, response and source inventory |
| `--minimum-historical-ec344-signed-visibility-count` | integer 0–16 |
| `--minimum-historical-ec345-signed-challenge-count` | integer 0–16 |
| `--minimum-historical-ec345-signed-offer-count` | integer 0–64 |

Also supply `--expected-retained-historical-ec345-disclosure-inventory-sha256` **only** to audit. `derive-historical-ec345-disclosure-inventory` returns the canonical **unsigned** verified inventory and its SHA. Retain it **outside** this software before audit if independent comparison is desired. Re-running derive and feeding its output straight back is not proof of genuinely prior independent retention. Every inherited parent audit comparator (including EC383) is still required for both commands.

## Read-only operation

```sh
python scripts/ces_cas_historical_ec345_disclosure_archive.py derive-historical-ec345-disclosure-inventory --help
python scripts/ces_cas_historical_ec345_disclosure_archive.py audit-historical-ec345-disclosure-archive --help
python scripts/ces_next.py audit-historical-ec345-disclosure-archive DeliveryAudit AuditHistoricalEC345DisclosureArchive --help
PYTHONPATH=construction python -m unittest -q ec384_historical_offer.test_offer_archive
```

`audit` invokes the **real unchanged EC383.audit → EC382→EC369** receiver original replay, then reopens original parent EC383/EC382 archives and the true original EC348→EC345 source with SHA-pinned actual files, not audit reports. Reconciles all old signatures against the exact EC343 actors, unsigned EC344 checkpoint and genuine old EC345 source; hashes exact per-epoch inventories, enforces both-channel old-original agreement and same-channel historic prefix / anti-rollback. Hardened original reads reject role aliasing and prohibited old EC353 sender-origin labels, and do late SHA/inode checks. The fixed unified route uses only `python -I -B` and exact outcome schemas. Lawful outcomes **exit 2 unresolved**; denied / invalid / unavailable **3 / 4 / 5**. No native PowerShell, private key signer, remote storage/network/provider/CAS/WORM operation is issued.

## Known unproved acceptance and validation backlog

Local tests are generated from old-format authentic **Ed25519-signed** EC344 and EC345 original bytes. **32/32** new focused unit tests run in one suite; two scoped cases execute old genuinely signed EC348→EC345 source replay. The **imported older EC347→EC337 signed-origin fixture is MOCKED**; three isolated new envelope tests **MOCK the external EC383→EC369 parent and old EC353 label handler** but exercise actual reopens of new signed original files. They are *not* a real external independent full historical archive audit. Unavailable until user-assisted external acceptance: complete genuinely recovered independent old EC346→EC337 corpus, native PS7 original 15 Smoke, real full EC383→EC369 production external child, independent old SHA retention and global signed fork completeness, institution legal authority, physical/offsite custody and certified UTC, OS/Git/CI/Provider tests and final acceptance. No PASS is claimed for any of these.
