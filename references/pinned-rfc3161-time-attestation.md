# EC273 — pinned RFC 3161 timestamp attestation of the EC272 live signed receipt

**Scope:** V5.83/R273/EC273; explicit opt-in; no replacement of existing `ec272`, PowerShell or the original 74-action Router. This adds one capability: a cryptographically validated timestamp from an operator-pinned external RFC 3161 TSA, bound to the exact current EC272 witness-ratified checkpoint and live signed tail. It is **not** an external nonrollbackable sequence store.

## What the new function actually authenticates

The new `rfc3161_timestamp_host/timeproof.py` produces a standard DER `TimeStampReq` with a 128-bit random nonce and required signed certificate. The SHA256 message imprint covers a domain-separated canonical statement containing the **full SHA256 of the current EC272 signed checkpoint**, **full SHA256 of the live segment manifest**, **full SHA256 of the latest EC271 two-signature receipt**, global sequence, predecessor receipt SHA, EC270 closure/recovered root SHA, EC267 governance SHA/epoch, receipt validity, and exact three-witness roster.

An external operator sends that `.tsq` to a real independent RFC 3161 service and stores the returned complete DER **TimeStampResp** (.tsr). No new software issues a timestamp by itself; offline test certificates are only synthetic fixtures. The verifier uses an **absolute SHA-pinned root-owned OpenSSL executable** for RFC 3161/CMS checks, plus a **byte-pinned PEM trust-store**, optional byte-pinned intermediates, exact **DER SHA256 of the TSA leaf X.509 certificate**, pinned RFC 3161 OID policy, private TSQ/TSR SHA pins, certificate-chain validation, content imprint and RFC 3161 nonce matching. Its strict DER parser separately checks token `genTime`, policy, nonce, imprint, serial, and mandatory request canonicality without relying on human-readable parsing.

The token is only admitted if its signed time lies inside the current fully signed live receipt's `[not_before, expires)` window, not more than 30 seconds before the latest two-witness signing observation, not more than 30 seconds into the future of the host's inherited monotonic/wall-clock effective time, is at least the operator-provided `minimum_time_unix`, and is no older than the configured 1..900 seconds. A token minted for a different checkpoint, live manifest or newest receipt **cannot** be reused: its message imprint differs. The 128-bit nonce is additionally checked against the exact TSQ, preventing casual use of an unrelated TSA response.

`rfc3161_timestamp_host/serve.py` is a **separate strict host** deriving from the full EC272 host, preserving all mandatory signed historical root recovery, governance revocations, EC266 signed source/Git and EC265 custody, EC264 signed audit, EC253 lease, strict OCI/cgroup controls and session/egress active-recall checks. It verifies timestamp evidence before socket/lease activity and throughout active sessions. Disappearance, corruption, expiry, signer or trust change aborts/revokes the current session through the inherited cleanup path. Neither client requests nor sessions can choose a different TSA trust configuration. All legacy host/Router permission denials remain unchanged.

## Operator workflow (Linux / nonroot private files)

Run from the extracted `ces/` directory. Every `--...` option that accepts a file must point to an **absolute owner-private existing path** in a private `0700` directory, with single-link regular `0600` files; never use symlinks or shared writable trees. Any credential read as input must be stable throughout verification. Program-generated new TSQ is exclusive and fsynced using existing EC266 private-file primitives. A renewed token needs a new TSQ and a fresh strict host restart with updated independent pins.

Prepare the complete `$HISTORY_ARGS` and `$FRESH_WITNESSES` arrays as documented in [EC272](witness-ratified-freshness-rollover.md); these contain old/new signed root+closure/governance/council and 3 separately pinned Ed25519 witnesses. `$TAIL_ARGS` must contain the **exact latest** `--checkpoint`/SHA, `--freshness-chain`/SHA, minimum sequence, expected previous receipt SHA, and minimum signed checkpoint number. For these offline commands, additionally pass any known `--forbidden-public-sha256` role keys.

```bash
# Step 1: fully verify EC272 and generate a fresh, canonical high-entropy TSQ.
python3 -I -B construction/rfc3161_timestamp_host/serve.py prepare-request \
  "${HISTORY_ARGS[@]}" "${FRESH_WITNESSES[@]}" "${TAIL_ARGS[@]}" \
  --tsa-policy-oid 1.3.6.1.4.1.55555.273 --output "$PRIVATE/tsq-001.der"

# Step 2: acquire a real RFC 3161 TimeStampResp from the separately trusted
# TSA (method depends on that external operator). Store as PRIVATE/tsr-001.der
# and chmod it to 0600. Do not treat the test CA/signers as production trust.

# Step 3: compute independently pinned hashes from actual bytes.
sha256sum "$PRIVATE/tsq-001.der" "$PRIVATE/tsr-001.der" \
  "$PRIVATE/tsa-roots.pem" /usr/bin/openssl
# TSA leaf pin is the DER certificate hash, *not* the PEM-file hash:
openssl x509 -in "$PRIVATE/tsa-leaf.pem" -outform DER | sha256sum
```

For a **real** TSA, use its actual policy OID, and obtain its leaf certificate and CA bundle directly from the independently authenticated TSA governance/trust-store owner. The OID above is only an example. Pin every external root and intermediate deliberately; do not silently import the machine's default CA store. If intermediates are necessary, pass `--tsa-intermediates` and `--tsa-intermediates-sha256` as a pair.

```bash
# Prepare these operator-pinned arguments using the printed hashes/paths.
TSA_ARGS=(
  --tsa-policy-oid "$REAL_TSA_POLICY_OID"
  --tsa-request "$PRIVATE/tsq-001.der" --tsa-request-sha256 "$QUERY_PIN"
  --tsa-response "$PRIVATE/tsr-001.der" --tsa-response-sha256 "$RESPONSE_PIN"
  --tsa-ca-bundle "$PRIVATE/tsa-roots.pem" --tsa-ca-bundle-sha256 "$ROOTS_PIN"
  --tsa-leaf-cert-sha256 "$TSA_LEAF_DER_SHA256"
  --tsa-openssl-binary /usr/bin/openssl --tsa-openssl-binary-sha256 "$OPENSSL_PIN"
  --tsa-max-age-seconds 600 --tsa-minimum-time-unix "$OPERATOR_EXTERNAL_TIME_FLOOR"
)

# Step 4: reverify full EC272 history and the TSA time proof offline.
python3 -I -B construction/rfc3161_timestamp_host/serve.py verify-proof \
  "${HISTORY_ARGS[@]}" "${FRESH_WITNESSES[@]}" "${TAIL_ARGS[@]}" \
  "${TSA_ARGS[@]}"

# Step 5: strict host. HOST_ARGS are the exact full EC272 verify-gate/serve
# source Git, custody/audit, lease/OCI and policy inputs from the EC272 guide.
python3 -I -B construction/rfc3161_timestamp_host/serve.py verify-gate \
  "${HOST_ARGS[@]}" "${TSA_ARGS[@]}"
python3 -I -B construction/rfc3161_timestamp_host/serve.py serve \
  "${HOST_ARGS[@]}" "${TSA_ARGS[@]}" \
  --socket "$PRIVATE/ec273.sock" --max-sessions 1 --accept-timeout 60
```

`prepare-request`, `verify-proof`, `verify-gate` and `serve` do not accept a private witness key or a TSA private key. The first three print JSON with `status=partial` and exit code **2** on bounded positive local proof (not an enterprise-wide PASS); failure returns **5** and a fixed denial reason. `serve` exits **0** only after a completed bounded socket session lifecycle, not an attested quality result.

## How to develop and locally replay the tests

```bash
# Run from ces/. The original tests intentionally require nonroot and real local git.
runuser -u nobody -- /opt/pyvenv/bin/python3 -I -B \
  construction/rfc3161_timestamp_host/test_timeproof.py
runuser -u nobody -- /opt/pyvenv/bin/python3 -I -B \
  construction/rfc3161_timestamp_host/test_host.py
```

The tests use OpenSSL to generate **synthetic self-signed CA + signer with critical timestamping-only EKU**, then construct a genuine DER RFC 3161 response against a real locally generated EC272 signed tail. OpenSSL checks real RSA CMS signing and chain verification, even though identities are not independent. The strict service test runs actual local Git, AF_UNIX socket, UID, lease and signed audit; **OCI/Podman and cgroup-v2 kernel exercise remain mocked**. No real remote TSA transaction, CRL/OCSP revocation check, external trusted-time accuracy, physically separate TSA machine/HSM, independent trust ceremony, nonrollbackable remote epoch/checkpoint escrow, physical WORM, remote forge/CI/enterprise assertions, original PowerShell7 15 Smoke, Windows/macOS or final unified acceptance was performed.

## Precise limitations

- A valid RFC 3161 token authenticates **what the TSA signed and its certified UTC claim**, not independent proof that the TSA clock is physically honest or its time is precise. The code does not independently query NTP/GPS/TSA servers or perform OCSP/CRL revocation. Provision and audit the real TSA operator, policy, CA/leaf trust, clock and revocation mechanism separately.
- No trusted rollback-resistant record of **the latest** checkpoint, root epoch, TSQ token SHA, time floor or sequence is maintained off-host. Operator-controlled pinned floors are still required and may be replayed after a machine reboot unless anchored externally. A new package needs an independently obtained anchor; local file hashes alone are not an off-host escrow.
- EC272's sealed intermediate receipt bodies are still **not** revalidated at runtime, only at their two-witness checkpoint issuance; the new timestamp binds the current checkpoint SHA and tail, not independent knowledge that sealed historical witnesses were honest. Physical WORM / forensic readback is an additional task.
- Revalidating an OpenSSL-signed timestamp on every active-recall guard is intentional. A token is **not** silently renewed in place; its request/response pins are fixed for host lifetime. New signed tails, a new TSA request, renewal/leaf rotation, changed policy/trust, a too-old token, or a new operator time floor require an explicit new host instance and an independent pin update.
- OpenSSL is an explicitly trusted **root-owned, exact SHA-pinned** local executable. The operating system, filesystem privacy and exact binary identity are still underlying host assumptions; the SHA pre-execution check is not a hardware attestation or a race-proof binary execution guarantee. A physically separate TSA is not part of the delivered package.

**Outstanding global status:** EC249 `FULL_FUNCTION_NOT_COMPLETE`, original EC250 freeze `BLOCKED`, historical B001 `OPEN`, 11 original Router `HOST_REQUIRED` denied, final acceptance `NOT_STARTED`, overall Quality PASS **NOT_VERIFIED**.
