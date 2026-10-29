# EC316 Runbook — two offline custody signers of genuinely replayed EC315 checkpoints

## Trust and retained inputs

All JSON sources are owner-private 0600 canonical UTF-8 JSON with LF, under 0700 real directories. Raw signed source manifests and evidence files must retain their **original bytes and absolute path references**; EC316 does not rewrite them or pretend a SHA pin stays valid after path substitution. `expected_*_sha256` values are whole-file raw SHA-256 obtained and retained OUTSIDE the proposed new manifest. The two custodian public keys/IDs must be independently acquired, authorized, pinned and checked by the caller; EC316 checks signature/key separation but cannot authenticate their real-world ownership.

Each signer has its own locally private 32-byte raw Ed25519 key file. Never put keys, passphrases or network tokens into CLI args, archives or audit reports. Perform `sign` on the respective custodian's separate device, after securely copying the **exact** claim and required original source history without loosening the on-disk 0600/0700 contract. A shared host fixture with two generated keys is a development-only test, not independent custody.

## First delivery (GENESIS)

The latest EC315 root manifest must itself have **exactly one signed-original-compatible delivery**. Choose two *distinct* custodians A/B with public key IDs distinct from the CAS issuer, and a caller-generated independent 64-character lowercase SHA challenge; externally freeze both public keys and challenge before signing.

Use the standalone script `python3 scripts/ces_cas_custody.py` with the following common arguments on `prepare`, `sign`, `assemble`, and `seal-chain`:

```
--ledger-manifest-file /private/source/ec315-root.json
--expected-ledger-manifest-sha256 ROOT_WHOLE_RAW_SHA
--custodian-a-id CUST_A_ID
--custodian-a-public-hex A_32_BYTE_PUBLIC_HEX
--custodian-b-id CUST_B_ID
--custodian-b-public-hex B_32_BYTE_PUBLIC_HEX
--external-unique-challenge-sha256 NEW_EXTERNAL_CHALLENGE_SHA
--expected-prior-certificate-sha256 GENESIS
```

First prepare the canonical claim with `prepare [common] --out /private/out/claim.json`. Retain the **whole raw** claim SHA independently. On the **A** signer run `sign [common] --claim-file /private/out/claim.json --expected-claim-sha256 CLAIM_SHA --role a --private-key-file /private/key-a.bin --out /private/out/a.vote.json` and analogously on B with `--role b` and its own key, to two different *never-overwritten* output paths. The `sign` step independently re-executes original EC315 evidence and checks the pinned prepared claim before creating the signature.

On the assembly machine run `assemble [common] --claim-file ... --expected-claim-sha256 ... --custodian-a-vote-file /private/out/a.vote.json --custodian-b-vote-file /private/out/b.vote.json --out /private/out/cert.json`. Freeze the resulting **complete certificate raw SHA** externally. `assemble` checks both actual Ed25519 signatures over the exactly same original claim under **different domain prefixes** and both independent public keys.

Run `seal-chain [common] --certificate-file /private/out/cert.json --expected-certificate-sha256 CERT_SHA --out /private/out/chain.json`. Freeze the complete chain SHA. It re-verifies both votes and all historical original evidence before writing one private, never-overwritten chain manifest. Note that the chain manifest holds private absolute **file references**, so do not publish it as a purported path-free object.

Final independent verifier:

```
python3 scripts/ces_cas_custody.py verify \
  --chain-file /private/out/chain.json --expected-chain-sha256 CHAIN_RAW_SHA \
  --ledger-manifest-file /private/source/ec315-root.json \
  --expected-ledger-manifest-sha256 ROOT_RAW_SHA \
  --expected-latest-certificate-sha256 CERT_RAW_SHA \
  --expected-latest-challenge-sha256 CHALLENGE_SHA \
  --custodian-a-id CUST_A_ID --custodian-a-public-hex A_PUBLIC_HEX \
  --custodian-b-id CUST_B_ID --custodian-b-public-hex B_PUBLIC_HEX
```

## Append another delivery

Produce a **new** valid EC315 root containing exactly one additional valid delivery and an unchanged valid prefix, and independently retain the old cert raw SHA and old chain raw SHA. The above common arguments become:

```
--ledger-manifest-file /private/source/ec315-new-root.json
--expected-ledger-manifest-sha256 NEW_ROOT_RAW_SHA
--custodian-a-id ... --custodian-a-public-hex ...
--custodian-b-id ... --custodian-b-public-hex ...
--external-unique-challenge-sha256 FRESH_NEW_CHALLENGE_SHA
--prior-chain-file /private/previous/chain.json
--expected-prior-chain-sha256 PREVIOUS_CHAIN_WHOLE_RAW_SHA
--expected-prior-certificate-sha256 PREVIOUS_CERT_WHOLE_RAW_SHA
```

Repeat prepare → independently sign twice → assemble → seal-chain → verify. Historical chain manifests/certificates AND historical original EC315 root/source files **must remain available**; latest root is *not* a substitute for proving an older certificate's old signed bounded candidate. Maximum four certificates/one per EC315 delivery, no skipping or reordering. A double-spent challenge, changed custodian identity/key, duplicate historical certificate or changed original prefix fails closed.

## Read-only console, exit codes, and boundaries

The read-only console accepts the `verify` set of parameters with its own action prefix:

```
python3 scripts/ces_next.py audit-custody DeliveryAudit VerifyDualSignedCasCheckpoint \
  --chain-file ... --expected-chain-sha256 ... \
  --ledger-manifest-file ... --expected-ledger-manifest-sha256 ... \
  --expected-latest-certificate-sha256 ... \
  --expected-latest-challenge-sha256 ... \
  --custodian-a-id ... --custodian-a-public-hex ... \
  --custodian-b-id ... --custodian-b-public-hex ...
```

It uses an isolated subprocess `-I -B`, fixed binary, bounded parser/output and does **not** forward any private signing key/`--out`/Host/CAS/network/Provider access. Exit `0`: all bounded originals and two Ed25519 cert signers are consistent; exit `3`: permission/signature/consistency issue; exit `4`: invalid input; exit `5`: unavailable/OS/verification. A returned 0 is **not** proof of independent human custody, real physical WORM or a globally latest CAS state. Any production deployment still needs an independently operated PKI, immutable latest-root pin, physical store behavior and final user acceptance.
