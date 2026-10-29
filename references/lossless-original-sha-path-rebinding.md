# EC317 Runbook — lossless relocation of original EC316 signed evidence

## 1. Establish off-bundle trust BEFORE opening any transferred ZIP

Keep the **source machine's original ABSOLUTE PATH STRINGS**, not substitute receiver paths, and independently retain:

- Original `EC316` custody chain original raw SHA (`--expected-chain-sha256`) and its exact original source-side path (`--chain-file`)
- Original latest `EC315` ledger root raw SHA and original path string
- Last custodian certificate whole raw SHA and latest external challenge SHA
- Both signer IDs and **two distinct authenticated** Ed25519 public keys, acquired outside the ZIP
- On reception, the **complete raw ZIP SHA** separately frozen by the sender and authentically delivered to receiver, not solely copied from ZIP's own metadata

The sender should not proceed if the old EC316 verification fails. Original private source files must be present under their real original paths at export; original paths do NOT need to exist on the receiver. This mechanism currently speaks canonical POSIX absolute paths on a POSIX owner-private filesystem; Windows/macOS production FS behavior needs separate validation.

## 2. Export from a source-side private 0700 parent

```
python3 scripts/ces_cas_rebind.py export \
  --chain-file /source/private/ec316-chain.json \
  --expected-chain-sha256 CHAIN_ORIGINAL_SHA \
  --ledger-manifest-file /source/private/ec315-ledger.json \
  --expected-ledger-manifest-sha256 LEDGER_ORIGINAL_SHA \
  --expected-latest-certificate-sha256 CERT_ORIGINAL_SHA \
  --expected-latest-challenge-sha256 CHALLENGE_SHA \
  --custodian-a-id CUST_A --custodian-a-public-hex A_PUBLIC_HEX \
  --custodian-b-id CUST_B --custodian-b-public-hex B_PUBLIC_HEX \
  --out /source/private/ec317-lossless-evidence.zip
```

The sender verifies all original signatures, collects only the exact real source read closure, requires private canonical source files, runs the full original signed verifier a **second time against exact copied source bytes**, and then saves a single exclusive `0600` ZIP with fixed member metadata and parent fsync. The ZIP contains the original byte-identical JSON and original EC302 ZIP dependencies. There is **no private signing key** and **no automatic source-path redaction**. Do not place sensitive metadata on unapproved storage. If the output already exists, export fails rather than overwrites.

An `exit_code:0` provides `bundle_original_raw_sha256`, `source_reference_count`, `distinct_byte_object_count`, and the path-independent original signed replay result commitment. Record and securely communicate the ZIP SHA **out of band**.

## 3. Receiver-side read-only verification in an unrelated private 0700 directory

Copy the whole ZIP onto the receiver as a new 0600 single-link regular file in a 0700 directory. Receiver independently inputs **unchanged original source-side paths** and trust pins:

```
python3 scripts/ces_cas_rebind.py verify \
  --bundle-file /receiver/private/transferred.zip \
  --expected-bundle-sha256 FULL_ORIGINAL_ZIP_SHA \
  --chain-file /source/private/ec316-chain.json \
  --expected-chain-sha256 CHAIN_ORIGINAL_SHA \
  --ledger-manifest-file /source/private/ec315-ledger.json \
  --expected-ledger-manifest-sha256 LEDGER_ORIGINAL_SHA \
  --expected-latest-certificate-sha256 CERT_ORIGINAL_SHA \
  --expected-latest-challenge-sha256 CHALLENGE_SHA \
  --custodian-a-id CUST_A --custodian-a-public-hex A_PUBLIC_HEX \
  --custodian-b-id CUST_B --custodian-b-public-hex B_PUBLIC_HEX
```

For the unified operator console, replace the first command prefix with:

```
python3 scripts/ces_next.py audit-rebind DeliveryAudit VerifyPortableSignedCheckpoint [the SAME verify flags]
```

Console can only call fixed isolated `verify` and does not offer `--out`, `export`, private keys, signing, persistence, network, business/Provider/Host, or CAS writes. Exit `0` means the supplied bounded original signatures are consistent; `3/4/5` are denial/invalid/unavailable respectively. Receiver reconstructs sources exclusively in a short-lived 0700 temporary directory, never extracting ZIP-specified paths directly. Every original-path reference missing from the enumerated bundle is a denial, even if the receiver also happens to have a readable file at that original absolute path. Extra unreferenced objects are denied too.

## Security and deferrals

**Original JSON/SHA stays original.** EC317 makes no new signed claim that the mutable filesystem paths are trusted or that a new organization has authorized the ZIP. The transport binding is checked against caller-held ZIP pin and against replay of every original true signature. It is not a signed relocation governance attestation, recipient ACK, secure channel, antivirus/DLP scanner, independent WORM notarization, true atomic linearizable CAS, or all-world latest assertion. The private ZIP may contain sensitive absolute paths and metadata even with credential fields screened; use encryption in transit/at rest outside this tool. An actively malicious same-UID process may still race the local filesystem despite the inode and byte-repeat checks; production storage isolation and external sealed snapshot are not provided.

Native PowerShell7 Smoke15, real source/recipient physical-machine transfers, multi-OS filesystem semantics, production Provider/Inbox/Git/CI/E63–E66, authorized real custodian management and revocation, physical CAS/WORM, independent SHA freezing, and final human acceptance remain deferred. EC249 incomplete / EC250 BLOCKED / B001 OPEN / overall Quality PASS=false remain.
