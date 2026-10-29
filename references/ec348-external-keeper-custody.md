# EC348 - Offline independently signed keeper-SHA inventory import

Release **V6.58 / R348 / EC348**. The historic PowerShell runtime version remains **V4.60 / R150**. This protocol is an import-and-verification tool; it does **not** generate or certify a real outside institution, physical copy, trusted timestamp, external ledger, or legal hold. Its most favorable signed result is always `exit_code=2` and `_unresolved`.

## 1. Source of truth and the safe handoff

Supply the **entire exact EC347 audit input set**, including the original EC346 through EC337 signed-source inputs, all EC345/346/347 original paths **and independently determined whole-original SHA-256 hashes**, and the latest presented EC347 readback rounds. The EC348 engine actually replays `ec347_readback_challenge.readback.audit_readbacks`; a claimed `verified=True` shortcut is not accepted. A keeper subject must have a real signed `measured_readback` in the final EC347 round. EC347 `unavailable_claim` or no response is reported as ineligible in the unsigned public checklist.

Use the strictly read-only checklist command to obtain the exact case/context, eligible receivers, current challenge SHA and **complete** older manifest/roster/view/challenge/reply/copy SHA inventory. Its output is **unsigned** and must be independently reviewed, received and pinned; a locally created checklist is never evidence of third-party possession.

```bash
python -I -B scripts/ces_cas_external_keeper_custody.py derive-checklist --help
python -I -B scripts/ces_cas_external_keeper_custody.py audit-external-custody --help
python -I -B scripts/ces_next.py audit-external-keeper-custody \
  DeliveryAudit AuditExternalKeeperCustody --help
```

The command help enumerates every inherited EC347 argument. Both audit entrypoints use the same explicit source inputs. The unified entrypoint forwards only to the fixed `-I -B audit-external-custody` child after input/schema checks; it cannot expose a signing mode, private key, ledger writer, file copy, installer or Provider/CAS/WORM action.

## 2. Independently furnished Ed25519 directory

The external reviewer independently furnishes `--keeper-directory-file` and `--expected-keeper-directory-sha256`, and obtains `--expected-directory-root-public-hex` from an independent channel. These **caller-supplied** trust assertions are not autonomously attested by CES.

- Document outer schema `ces.ec348.ed25519_external_keeper_directory.v1`, with **exactly** `schema`, `claim`, `signature_ed25519`.
- Signed claim schema `ces.ec348.external_keeper_directory_claim.v1` has the fields enumerated in `ec348_external_custody.custody.D_FIELDS` (case ID, canonical EC347 context SHA, latest challenge original SHA, source pair SHA, root actor, keeper roster, validity UTC, restrictive scope, explicit non-authority flag).
- Directory authority actor: `{signer_id,public_hex,organization_id}`. Each of **2-4** keepers has that actor triple plus `{ledger_id,subject_receiver_id}`. The subject list matches the original EC347 challenged audience **in order**. Distinct public keys, signer IDs, organizations and ledger IDs are required; no reuse of the enumerated original EC343/EC342 actors. Matching labels/keys are never accepted as independent custody evidence.
- Sign with external root Ed25519 private key (not included with CES) over `b'CES/EC348/ExternalKeeperDirectory/v1\0' + reg.canonical(claim)` and encode the signature as lowercase hexadecimal. The original JSON bytes and SHA must be independently supplied as a single pinned file.
- Claimed validity must begin no earlier than the EC347 evaluation and no later than this EC348 evaluation; claim/report times are **not trusted wall-clock evidence**.

## 3. Keeper receipt, original ledger and version history

- Signed receipt outer schema `ces.ec348.ed25519_keeper_whole_original_receipt.v1`, signed claim schema `ces.ec348.keeper_whole_original_receipt_claim.v1`. Exact claim fields are listed in `custody.R_FIELDS`. A keeper signs only its own directory slot using `b'CES/EC348/ExternalKeeperInventoryReceipt/v1\0' + reg.canonical(claim)` with its Ed25519 private key **outside CES**.
- Each receipt must bind the exact original directory SHA, full EC347 context SHA, latest EC347 challenge and **that receiver's original signed reply whole SHA**. `whole_original_inventory` must equal the full source/roster/governance/EC344-347 inventory produced by `_inventory`; no omissions or arbitrary extra items are accepted.
- `store_claim` is sequence 1; sequence 2 or 3 is `renewal_claim` or `revocation_claim`. An increment requires an explicitly presented prior genuine signed original path and whole SHA by the **same** keeper and receiver; a revoked predecessor cannot renew. At most **three versions**, at most **two signed siblings** per version, and **24 signed receipts total** across four keepers. Signed branches remain visible unresolved forks; no self-selected newest winner.
- Signed nonce must be globally unique **among all supplied EC345/346/347 and EC348 originals**. Signed time must be canonical UTC, ordered and within directory claim window. A renewal after its predecessor's signed expiry remains an explicit `signed_keeper_ancestry_has_self_reported_expiry_gap` and is downgraded to expiry status.
- Non-revoked keeper receipts include both claimed snapshot/ack whole raw SHA-256 and byte lengths. Revocation must set all four content fields to `null`; it reports a signed claim, **not physical file deletion**. The `ledger_original_raw_sha256` field is the alleged original SHA of the keeper's **unwrapped unsigned ledger** (`custody._ledger_fields(claim)`); receipt SHA, directory SHA, older input originals and source SHA cannot be reused as a self-looping ledger reference.
- Receipt paths must be in original keeper roster order, then sequence, then whole receipt SHA. An entry whose independent external receipt SHA was **not** obtained must supply the literal `UNPINNED`: the engine may read its bytes and check Ed25519 but the head's entire ancestry is **not externally pinned**. Never replace a missing SHA with a local auto-computed digest and call it external custody.

## 4. Optional explicitly furnished byte retest

Only when the reviewer explicitly gives all four aligned arrays `--presented-keeper-id`, `--presented-ledger-file`, `--expected-presented-ledger-sha256`, `--presented-copy-snapshot-file`, `--presented-copy-ack-set-file` does the audit open an allegedly external ledger and two copy bytes for that keeper. It verifies the ledger **raw SHA and canonical inventory**, computes the true copy SHA+length and compares them with keeper-signed and EC345 source hashes. Without this list, none of those claimed ledger or copy paths is discovered or read.

Every explicitly named ledger/copy path must be different from every other new file and from all source EC347/346 originals or signed old copy paths; owner-private, no symbolic links, no multiple hard-link aliases and bounded bytes are inherited from the old signed transport. All read keeper files are rehashed at the end of the audit to detect drift. A mismatching retest is reported separately from signed source mismatch, expiration and fork.

## 5. Auditable outcomes, NOT_PROVEN and delivery boundaries

`keeper_outcomes` lists each slot (including a completely unanswered keeper), signed version count and all visible terminal SHA hashes, current head kind or unresolved fork, whether **every original in the entire selected ancestry** had a caller-provided pin, signed-claim time expiry gaps, alleged ledger SHA-sharing, signed bytes vs original receiver/source and the optional actual-byte retest.

Nine bounded outcome names from `custody.OUTCOMES` are: `no_keeper_receipt_presented`, `keeper_current_receipt_missing_external_sha_pin`, `keeper_signed_versions_fork`, `keeper_signed_revocation`, `keeper_directory_or_receipt_expired`, `keeper_signed_bytes_differ_from_receiver`, `keeper_explicit_retest_changed_since_signed_receipt`, `keeper_signed_receipt_matches_receiver_unproven`, and `keepers_share_same_claimed_ledger_original_not_independent`. If two alleged keepers share exactly the same claimed ledger original SHA, the otherwise best outcome is downgraded. The overall status always ends `_unresolved` and `exit_code=2`.

**Separation of facts:** A real Ed25519 signature and a caller-provided SHA anchor can be tested locally. They **do not** establish the signer's legal identity, control of a physically independent machine, real-world external whole-SHA custody, trusted UTC, actual historical long-term bytes, hidden fork completeness, or remote Provider/CAS/WORM freeze, release, readback or nonexecution. All relevant result `NEGATIVES` remain `false`. EC317/318 deep historical fixture remains MOCK; original PowerShell7/15 Smoke, OS/CI/Provider and final user acceptance remain NOT_RUN/NOT_PROVEN. EC249 incomplete, EC250 blocked, B-001 OPEN, global Quality false and final acceptance NOT_STARTED remain unchanged.

Sources: [core](../construction/ec348_external_custody/custody.py), [CLI](../construction/ec348_external_custody/operator.py), [tests](../construction/ec348_external_custody/test_custody.py), [standalone entrypoint](../scripts/ces_cas_external_keeper_custody.py), [EC348 record](../EC-348.md).
