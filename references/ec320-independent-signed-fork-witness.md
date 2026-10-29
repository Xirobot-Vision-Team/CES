# EC320 — Sixth independent offline Ed25519 fork-witness protocol

**Package V6.30 / R320 / EC320.** This EC does not provide external consensus, WORM, monotonic CAS, a trusted clock, identity governance, or a winner for the fork. It authenticates only the witnessed, bounded, externally pinned *original signed histories* supplied on this run.

## What is cryptographically signed

`attest` requires **two separately original whole-SHA-pinned EC319 snapshot JSONs** with **matching pinned genesis** and different signed sibling entries at the same sequence, both genuinely verified by EC319's `compare()`. That call independently repeats *every visible EC318→EC294 signature and the entire EC319 signed registry*, reading the original evidence through two explicit local mappings. The sixth witness is disjoint by **ID and public key** from both custodian IDs/keys, the registrar, and **every sender/receiver seen anywhere in either branch**, not just the tips. Its fresh SHA-256 challenge must not match any registrar-epoch, pinned old EC316 latest, sender/receiver/closure or registrar-entry challenge *visible in either branch*. It cannot prove uniqueness outside the supplied evidence.

Only after this full replay, a local 32-byte raw Ed25519 private key is loaded (owner-private file). The witness signs `b'CES/EC320/SixthIndependentSignedRegistrarForkObservation/v1\0' + canonical_claim_bytes`, where the domain contains a real single NUL terminator, and `canonical_claim_bytes` is ASCII, sorted-key, compact JSON with no trailing LF. The signed envelope is canonical ASCII sorted-key compact JSON **plus exactly one LF**. Its exact raw file SHA differs from the canonical in-memory claim digest. All outputs require fresh 0600 single-owner private paths with O_EXCL, file/parent fsync and are never overwritten.

The signed claim contains: `case_id`, `witness_id`, `witness_public_hex`, `witness_challenge_sha256`, fixed observation, `registry_id`, `registrar_id/public`, genesis signed record raw SHA, original EC317 bundle SHA, inherited full original replay digest and source count, left/right EC319 **snapshot** original raw SHAs, left/right signed **head** raw SHAs, signed common **parent** raw SHA, both genuine sibling signed-record raw SHAs, 1–4 bounded per-branch counts and the divergent sequence. Private file paths are **never** signed into the result. The caller is responsible for keeping the unchanged source ZIP, receipts and materials maps intact for later independent replay.

## Usage: standalone sign (only on an independently authorized sixth signer)

All file paths below must be normalized absolute paths with private owner-controlled parents and correct 0600 files. The two `materials-file` inputs are EC319 canonical-LF JSON path mappings, **not** cryptographic authority. Keep their original byte material independent and unchanged; each full SHA below must come from independent custody, not from the unsigned file being tested.

```sh
python3 scripts/ces_cas_fork_witness.py attest \
  --case-id case_320 --witness-id separate_witness \
  --witness-public-hex EXTERNALLY_TRUSTED_SIXTH_ED25519_PUBLIC_HEX \
  --witness-challenge-sha256 FRESH_WITNESS_CHALLENGE_SHA256 \
  --left-file /private/site/registrar-left.json \
  --expected-left-sha256 LEFT_WHOLE_RAW_SHA256 \
  --left-materials-file /private/site/left-path-map.json \
  --expected-left-head-raw-sha256 LEFT_SIGNED_HEAD_RAW_SHA256 \
  --right-file /private/site/registrar-right.json \
  --expected-right-sha256 RIGHT_WHOLE_RAW_SHA256 \
  --right-materials-file /private/site/right-path-map.json \
  --expected-right-head-raw-sha256 RIGHT_SIGNED_HEAD_RAW_SHA256 \
  --expected-genesis-raw-sha256 SAME_SIGNED_GENESIS_RAW_SHA256 \
  --registrar-id independent_registrar \
  --registrar-public-hex EXTERNALLY_TRUSTED_FIFTH_PUBLIC_HEX \
  --private-key-file /private/witness/raw-ed25519-secret.bin \
  --out /private/witness/new-sixth-fork-attestation.json
```

`exit=2` is **positive evidence of an actual bounded fork**, not a healthy registry head. All invalid signature/pin, signer collision, material failure, false fork and bad arguments return 3/4/5 with fail-closed JSON and no attestation. Keep `attestation_original_raw_sha256` from the result **in independent custody**. Do not package actual private keys with the project.

## Usage: independent read-only full-source re-verification

Use the same arguments as above for `case-id`, all four witness pins (identity, public, challenge and case) and all 11 branch pins/paths. Replace `attest` with `verify` and replace `--private-key-file/--out` with:

```sh
python3 scripts/ces_cas_fork_witness.py verify \
  --witness-file /private/recipient/received-sixth-attestation.json \
  --expected-witness-sha256 INDEPENDENT_ATTESTATION_WHOLE_RAW_SHA256 \
  --case-id case_320 --witness-id separate_witness \
  --witness-public-hex EXTERNALLY_TRUSTED_SIXTH_ED25519_PUBLIC_HEX \
  --witness-challenge-sha256 FRESH_WITNESS_CHALLENGE_SHA256 \
  --left-file /private/recipient/registrar-left.json \
  --expected-left-sha256 LEFT_WHOLE_RAW_SHA256 \
  --left-materials-file /private/recipient/left-path-map.json \
  --expected-left-head-raw-sha256 LEFT_SIGNED_HEAD_RAW_SHA256 \
  --right-file /private/recipient/registrar-right.json \
  --expected-right-sha256 RIGHT_WHOLE_RAW_SHA256 \
  --right-materials-file /private/recipient/right-path-map.json \
  --expected-right-head-raw-sha256 RIGHT_SIGNED_HEAD_RAW_SHA256 \
  --expected-genesis-raw-sha256 SAME_SIGNED_GENESIS_RAW_SHA256 \
  --registrar-id independent_registrar \
  --registrar-public-hex EXTERNALLY_TRUSTED_FIFTH_PUBLIC_HEX
```

The unified read-only operator entry uses **exactly** these verify parameters, prefixed by `audit-transfer-fork DeliveryAudit VerifyIndependentForkAttestation`, and dispatches only a fixed `python -I -B` child. There is no unified `attest`, no private key, no output path, no Host/Provider/CAS write and no ability to override the physical signing authorization. A true fork is explicitly `exit=2`; a malformed artifact is NOT a positive result.

`verify` first checks the sixth signed certificate's externally pinned whole raw SHA and sixth Ed25519 signature. It then ignores all claimed path authority, calls the existing EC319 `compare` on the two independently pinned snapshots, replays both entire old evidence histories, verifies the sixth role and challenge separation against both, and byte-canonically compares the fresh fork claim to the signed claim. Signed claims **never** determine original SHA expectations or which files to read.

## Test and final acceptance limitations

Focused: `PYTHONPATH=construction PYTHONDONTWRITEBYTECODE=1 python -B -m unittest construction.ec320_fork_witness.test_witness_structure -v` (12 new EC320 cases + 5 imported EC319 structure cases; both fifth and sixth real Ed25519 keys; **old heavy EC317/EC318 are mocked here**). The EC319 inherited fully genuine fixture is in `construction/ec319_offline_transfer_registry/test_registry.py` and was not completed in the parent round due to an expensive 200-second setup timeout. Full original fixture and physical signers, external trusted registrar/CAS/WORM, owner permissions on Windows/macOS, real organization revocation/authorization, trusted nonce/time, PS7 Smoke15, production Provider/Inbox/Git/CI/E63–E66 and final business acceptance remain expressly unverified.
