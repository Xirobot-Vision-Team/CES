# EC408 — institutional RFC6960 historical/evaluation original OCSP receiver

This strictly **offline, read-only** verifier audits authentic *signature mathematics
and original-file consistency* of separately issued OCSP response DER for both
institutional RSA custody leaf certificates introduced by EC407. It does not
create OCSP, private keys, certificates, public trust-list originals or legal
credibility. `institutional_cms.protocol.audit` is always called first in
production, preserving its real EC406/405/404/403/402/401/400/399/398 and
earlier ancestors, CRLs, CMS and signed original-source bindings.

## Authentic source format and trust boundary

All `{ "path": "/absolute/private/original.der", "sha256": "64 lowercase hex" }`
references must be independently obtained, pinned, regular non-symlink private
original files; the receiver checks byte SHA-256 and final readback. Provide
*actual RFC6960 DER OCSPResponse originals*, not JSON declaring `good` and not
unsigned or self-issued status reports. The producedAt/thisUpdate/nextUpdate
fields are **signed issuer/delegate statements**; they do not independently
prove when that OCSP was publicly delivered or that the issuer is accredited.

The response must be exactly one successful BasicOCSPResponse, exact DER,
SHA-256/384/512 CertID of the *actual EC407 original leaf and root*, no
unknown response/single-response extensions, and an issuer or tightly
issuer-delegated responder signature. The original issuer certificate is the
same EC407 independently pinned root; a delegated responder must have an
issuer-signed original certificate, single exact embedded DER certificate,
`id-kp-OCSPSigning`, key usage, non-CA, issuer authorization, valid time and
OCSPNoCheck. Cross-institution shared responder keys and path reuse are denied.
OCSPNoCheck **does not establish actual global responder revocation absence**.

For **each of the two publishers in each of 1–3 epochs**, one historical OCSP
original must cover the EC407 *actually CMS-signed* custody-claim instant,
with claimed producedAt not later than that instant +5 minutes. One distinct
evaluation OCSP original must cover the exact externally chosen EC407 evaluation
instant, with signed producedAt within 5 minutes of that instant. Both must be
produced no later than that evaluation instant and contain signed `good` for
joint local credit. Signed `revoked` or `unknown`, stale, late, uncovered or
noncontemporaneous responses remain visible but give **zero** positive credit
for that role. Forged signatures/CertID/delegation/DER deny with 3/4/5. A
later original may be a half-pair **only by explicit denial**; complete missing
pairs after epoch 0 remain unresolved permanently (cannot resume later).

## Original manifest and exact fields

One outside SHA-pinned *actual original* manifest:

```json
{
  "schema": "ces.ec408.original_institutional_dual_window_ocsp_bundle.v1",
  "claimed_directory_lineage_id": "actual-parent-lineage",
  "parent_ec407_original_institutional_cms_bundle_original": {
    "path": "/offline/original-ec407.json", "sha256": "..."
  },
  "epochs": [{
    "epoch_index": 0,
    "publishers": [{
      "publisher_id": "PublisherA",
      "institutional_signer_id": "InstitutionA",
      "root_certificate_sha256": "...",
      "leaf_certificate_sha256": "...",
      "original_historical_ocsp_response": {"path":"/offline/a-old.der","sha256":"..."},
      "original_evaluation_ocsp_response": {"path":"/offline/a-new.der","sha256":"..."},
      "historical_delegated_responder_certificate_original": null,
      "evaluation_delegated_responder_certificate_original": null
    }, {
      "publisher_id": "PublisherB",
      "institutional_signer_id": "InstitutionB",
      "root_certificate_sha256": "...",
      "leaf_certificate_sha256": "...",
      "original_historical_ocsp_response": {"path":"/offline/b-old.der","sha256":"..."},
      "original_evaluation_ocsp_response": {"path":"/offline/b-new.der","sha256":"..."},
      "historical_delegated_responder_certificate_original": null,
      "evaluation_delegated_responder_certificate_original": null
    }]
  }]
}
```

Every object uses exact keys; all original SHA values above must be **real
lowercase 64-digit SHA256**. The two institutional signer IDs, publisher IDs,
parent manifest and external EC407 certificate root/leaf pins must match the
true unchanged EC407 originals. The receiver reopens the real signed EC407
custody statements to get the actual signed claim times. It also reopens the
EC406 and EC405 original manifests to protect inherited nested paths.

For epochs after the first, both response references may be `null` for a role
*only together*, with both delegate refs `null`; that role is permanently
missing and counts as unresolved. First epoch requires two complete response
pairs. A delegate original may be reused by the *same role* for historical
and evaluation responses, but never shared between publishers, nor reuse a
root or custody leaf SPKI.

## Independent externally held inputs and CLI

The new `--` flags correspond to the following underscore-named scalar keys:

```
historical_ec339_institutional_ocsp_bundle_file
expected_historical_ec339_institutional_ocsp_bundle_sha256
expected_outside_ec408_first_a_historical_ocsp_sha256
expected_outside_ec408_first_b_historical_ocsp_sha256
expected_outside_ec408_first_a_evaluation_ocsp_sha256
expected_outside_ec408_first_b_evaluation_ocsp_sha256
expected_retained_historical_ec339_institutional_ocsp_inventory_sha256 (audit only)
```

Additionally, the operator **must supply all real prior EC407 audit scalar,
repeat and parent inventory pins unchanged**. Add one of each per epoch:

```
--historical-ec339-institutional-ocsp-epoch-inventory-sha256 64hex
--minimum-historical-ec339-joint-institutional-ocsp-publisher-count 0|1|2
```

These per-epoch and final inventory values are not self-issued approvals. Use
`derive-historical-ec339-institutional-ocsp-inventory` to calculate an
*unsigned* inventory of the actual original DER and genuine local parent
report; check/retain external SHA values separately before `audit-...`.
The derive command still requires an independently pinned new manifest, four
distinct first-response originals and per-epoch outside pins/floors. Any
SHA/count disagreement is **unresolved**, not silently corrected.

Use the exact isolated commands:

```
python -I -B scripts/ces_cas_historical_institutional_ocsp.py --help
python -I -B scripts/ces_next.py audit-historical-ec339-institutional-ocsp DeliveryAudit AuditHistoricalEC339InstitutionalOCSP --help
```

All otherwise locally consistent evidence returns JSON with `exit_code=2`
and `_unresolved`; denial of invalid originals/arguments returns 3/4/5. No
`PASS` code exists. No signing, cert issuance, network, mutable provider,
PowerShell, Git, CI, external WORM or court/government source lookup occurs.
No official historical ETSI TL/LOTL, prior public OCSP distribution, timestamp
calibration, issuer independence, global revocation, actual physical WORM or
entire unmocked source ancestry has been supplied or proved. The original
PowerShell CLI stays V4.60/R150; EC249/EC250/B001/Quality/final gates remain
open for the user-assisted final acceptance phase.
