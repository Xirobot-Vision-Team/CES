# EC413: exact original issuer-direct LOTL CA OCSP evidence contract

## Parent requirement / operating modes

The normal production entry `lotl_ocsp.protocol.audit` must first call
**real unchanged** `lotl_crl.protocol.audit`, which itself calls real
EC411 signed XAdES certificate identity, EC410 genuine signed LOTL/X.509
issuer path, EC409 signed national TSL, EC408 original OCSP, EC407 institutional
CMS and the full older original evidence chain. All EC412 **audit** arguments,
including its own retained SHA and all ancestor original outside pins, are
required even in EC413 **derive** mode. A prior adverse report remains adverse.
A caller must supply independently retained original source files and SHA256
values; derive is for calculating *unsigned* inventory bytes and **does not
mint an independent original provenance or public time witness**.

### New argument names

| New option | Strict meaning |
|---|---|
| `--historical-ec339-lotl-ocsp-bundle-file` | Path of original read-only JSON bundle |
| `--expected-historical-ec339-lotl-ocsp-bundle-sha256` | SHA256 of exact JSON bundle bytes |
| `--expected-outside-ec413-first-historical-root-ocsp-sha256` | Independently retained SHA256 of epoch-0 root-signed original historical intermediate status |
| `--expected-outside-ec413-first-historical-intermediate-ocsp-sha256` | Epoch-0 intermediate-signed historical LOTL signer response |
| `--expected-outside-ec413-first-evaluation-root-ocsp-sha256` | Epoch-0 root-signed evaluation intermediate response |
| `--expected-outside-ec413-first-evaluation-intermediate-ocsp-sha256` | Epoch-0 intermediate-signed evaluation LOTL signer response |
| `--historical-ec339-lotl-ocsp-epoch-inventory-sha256` | Repeat once per original source epoch (one to three), with **preheld** per-epoch inventory digest |
| `--minimum-historical-ec339-joint-lotl-ocsp-publisher-count` | Repeat once per original epoch, integer 0, 1 or 2; no ancestor promotion |
| `--expected-retained-historical-ec339-lotl-ocsp-inventory-sha256` | **Audit-only:** independent exact digest of complete derived original inventory |

Each source hash must be nonzero lowercase 64-character SHA256, and four
first-epoch pins must be distinct. These names are additive, not replacements
for existing EC412/EC411/EC410 and deeper flags.

### Original JSON shape

The example uses placeholders, **not** authentic official CA/OCSP evidence.
Each source reference must contain exactly `path` and `sha256`, bound to
immutable original bytes. `parent_ec412_original_lotl_crl_bundle_original`
must equal the exact path/SHA source already passed to the genuine EC412
parent audit.

```json
{
  "schema": "ces.ec413.original_lotl_ca_ocsp_bundle.v1",
  "claimed_directory_lineage_id": "SAME AS ORIGINAL EC410/EC412",
  "parent_ec412_original_lotl_crl_bundle_original": {
    "path": "/immutable/original/ec412_crl_bundle.json",
    "sha256": "64 lowercase hex characters"
  },
  "epochs": [
    {
      "epoch_index": 0,
      "historical_root_ca_ocsp_original": {"path": "/immutable/root_hist.ocsp", "sha256": "64 lowercase hex characters"},
      "historical_intermediate_ca_ocsp_original": {"path": "/immutable/mid_hist.ocsp", "sha256": "64 lowercase hex characters"},
      "evaluation_root_ca_ocsp_original": {"path": "/immutable/root_eval.ocsp", "sha256": "64 lowercase hex characters"},
      "evaluation_intermediate_ca_ocsp_original": {"path": "/immutable/mid_eval.ocsp", "sha256": "64 lowercase hex characters"}
    }
  ]
}
```

For one to three parent epochs, there are **four distinct genuine signed DER
responses per present epoch**, with exactly one answer for each of the two
pinned certificate link targets and each historical/evaluation source time.
The first epoch must exist. Later epochs can contain four `null` OCSP fields
only when the original parent EC412 source epoch is already incomplete;
partial and reappearing sets are rejected. Sources cannot reuse SHA/path
identity of any former source, each other, original CA certificate or ancestor
manifest. All sources are SHA-readback checked.

## X509/OCSP cryptographic restrictions

The scoped subset permits only **direct-issuer signed** RFC6960
`BasicOCSPResponse` with a successful top-level response, one `SingleResponse`,
no embedded delegated responder certificate, no response or single extensions,
canonical complete DER encoding, and SHA256 CertID. The `issuerNameHash`,
`issuerKeyHash` and serial must exactly match real SHA-pinned EC410 root→mid
or mid→LOTL signer certificates; the response must be signed with the **real
issuer's** RSA key (≥2048 bits, PKCS#1 v1.5 with SHA256) or ECDSA key
(P-256 with SHA256), verified against original TBSResponseData. ResponderID
must be the actual issuer subject name or SHA1-derived subject-key identifier
of the same pinned issuer's key (RFC6960 responder key hash; this SHA1 key
identifier is **not** authorization to use SHA1 signatures or CertIDs).
Issuer must have CA basic constraints and `keyCertSign` authorization.
No delegated OCSP responders, nonce/response extensions, multiple responses,
weak RSA, SHA1 CertID, SHA1 signature, RSA-PSS or unfamiliar algorithm are
supported in this intentionally narrow implementation. Refusal of these
otherwise legitimate variants is a **profile limitation**, not proof the
external responder is untrustworthy.

`thisUpdate < nextUpdate` and at most 14 days interval, `producedAt` within
this interval allowing up to ±5 minutes clock skew, seconds-precision signed
UTC, and `producedAt` inside pinned issuer cert validity. For each checked
historical original, all actual EC411 cryptographically verified XAdES
SigningTime and original EC407 **two** historical CMS-signed publisher custody
claim times must be covered by both issuer responses and pinned issuer/target
X509 validity. Evaluation covers actual signed EC411 XAdES time plus original
inherited EC407 evaluation UTC. Require source instants no earlier than
`producedAt - 5 minutes` and no later than `producedAt + 7 days` for a
conservatively contemporaneous answer. This is **not** independent qualified
clock or public response archive proof. Signed `thisUpdate` must increase and
`producedAt` must not decrease between consecutive historical/evaluation and
subsequent source epoch responses by the same issuer.

Signed OCSP status GOOD yields locally bounded *possible* positive consistency
only if all windows and the genuine EC412 parent are already complete and
non-adverse; REVOKED and UNKNOWN are adverse and never upgraded by any
publisher floor. Revocation time must not be impossibly later than signed
response production. Even entirely GOOD evidence returns **UNRESOLVED**.

## Commands and status contract

```
python -I -B scripts/ces_cas_historical_lotl_ocsp.py derive-historical-ec339-lotl-ocsp-inventory --help
python -I -B scripts/ces_cas_historical_lotl_ocsp.py audit-historical-ec339-lotl-ocsp --help
python -I -B scripts/ces_next.py audit-historical-ec339-lotl-ocsp DeliveryAudit AuditHistoricalEC339LOTLIssuerOCSP --help
```

With actual complete original files, invoke a selected command with **all**
inherited EC412 audit flags followed by EC413 additional options above. Derive
returns schema `ces.ec413.unsigned_lotl_ca_ocsp_inventory_unresolved.v1` and
`unsigned_lotl_issuer_ocsp_inventory`. The audit returns
`ces.ec413.original_lotl_ca_ocsp_unresolved.v1`, requiring external retained
inventory SHA, and an exact original binary/source re-read. Both genuine
local combinations return **exit 2 unresolved only**. Invalid or unsupported
original/claims return **exit 3**, malformed inputs **exit 4**, unavailable
parent or environment **exit 5**, never status PASS. Unified routing is fixed
at `DeliveryAudit / AuditHistoricalEC339LOTLIssuerOCSP`; it checks child
report schema, original source/receipt link and invariants before forwarding.

No OCSP URL lookup, no certificate/key issuance, private issuer signing,
network, archive/business original modification or native PowerShell changes.
The cryptographically pinned signing key and response signed times do not
prove independent official Commission/OJEU CA ownership, authentic service
appointment, third-party historical original public receipt, qualified time,
all global revocation, complete ETSI/eIDAS legality, or physical WORM.
Actual official source originals, real unmocked complete ancestry and native
user-assisted final verification remain future dependencies; they are not
silently designated PASS.
