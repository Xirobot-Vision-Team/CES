#!/usr/bin/env python3
"""EC412: original SHA-pinned LOTL CA/signer CRL signatures and window coverage.

This is a strict offline full-CRL subprofile, NOT independent proof of official
CA/Commission/OJEU accreditation, public issuance or complete revocation.
Production MUST call real, unmodified EC411.audit, whose production ancestry
calls EC410, EC409, EC408, EC407 and all older original verifiers. None of
those checks is substituted or rewritten here. Every result remains unresolved.
"""
from __future__ import annotations

from datetime import timezone
import hashlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import CRLEntryExtensionOID, ExtensionOID

from ec295_delivery_anchor import anchor as errors
from ec372_historical_authority import authority_archive as io
from ec394_registered_witness import registered_witness as readers
from ec411_xades_certificate import protocol as parent

lotl = parent.parent
cms = lotl.cms

RESULT_SCHEMA = "ces.ec412.original_lotl_ca_crl_unresolved.v1"
DERIVE_SCHEMA = "ces.ec412.unsigned_lotl_ca_crl_inventory_unresolved.v1"
DENIAL_SCHEMA = "ces.ec412.lotl_ca_crl_denial.v1"
BUNDLE_SCHEMA = "ces.ec412.original_lotl_ca_crl_bundle.v1"
INVENTORY_SCHEMA = "ces.ec412.unsigned_lotl_ca_crl_inventory.v1"

PARENT_SCALARS = (*parent.PARENT_SCALARS, *parent.AUDIT_ONLY)
PARENT_REPEATS = (*parent.PARENT_REPEATS, *parent.REPEAT_NAMES)
NEW_SCALARS = (
    "historical_ec339_lotl_crl_bundle_file",
    "expected_historical_ec339_lotl_crl_bundle_sha256",
    "expected_outside_ec412_first_historical_root_crl_sha256",
    "expected_outside_ec412_first_historical_intermediate_crl_sha256",
    "expected_outside_ec412_first_evaluation_root_crl_sha256",
    "expected_outside_ec412_first_evaluation_intermediate_crl_sha256",
)
AUDIT_ONLY = ("expected_retained_historical_ec339_lotl_crl_inventory_sha256",)
NEW_REPEATS = (
    ("historical_ec339_lotl_crl_epoch_inventory_shas",
     "--historical-ec339-lotl-crl-epoch-inventory-sha256"),
    ("minimum_historical_ec339_joint_lotl_crl_publisher_counts",
     "--minimum-historical-ec339-joint-lotl-crl-publisher-count"),
)
REPEAT_NAMES = tuple(k for k, _ in NEW_REPEATS)
FLAGS = (
    "inherited_real_ec411_and_older_original_ancestry_adverse",
    "outside_original_lotl_crl_first_epoch_or_retained_pin_disagrees",
    "one_or_more_later_original_lotl_crl_pairs_missing",
    "verified_crl_and_real_ec411_original_joint_coverage_incomplete",
    "independent_official_root_issuer_and_crl_publication_unproven",
    "historical_public_originals_qualified_time_and_global_revocation_unproven",
    "full_unmocked_external_ancestry_native_worm_and_acceptance_unproven",
)
OUTCOMES = (
    "ec412_inherited_real_ec411_or_older_originals_adverse",
    "ec412_outside_lotl_crl_source_inventory_pins_disagree",
    "ec412_later_original_lotl_crl_evidence_missing",
    "ec412_original_ca_crl_and_real_ec411_coverage_incomplete",
    "ec412_official_ca_root_and_issuer_provenance_unproven",
    "ec412_public_history_and_global_revocation_not_proven",
    "ec412_full_external_original_history_and_acceptance_unproven",
)
NEGATIVES = (
    "issuer_signed_crl_or_local_sha_pin_is_government_commission_accreditation",
    "valid_original_crl_proves_independent_historic_public_distribution",
    "signed_xades_signingtime_is_a_qualified_independent_timestamp",
    "pinned_ca_issued_crl_proves_exhaustive_global_revocation_status",
    "no_revoked_serial_in_one_crl_is_online_ocsp_or_delta_crl_coverage",
    "signed_lotl_child_cures_adverse_real_ec411_or_older_ancestry",
    "receiver_issued_crls_certificates_private_keys_or_signed_originals",
    "receiver_fetched_distribution_urls_or_mutated_business_source_files",
    "receiver_claimed_legal_pass_physical_worm_native_or_final_acceptance",
)
BUNDLE_FIELDS = {
    "schema", "claimed_directory_lineage_id",
    "parent_ec410_signed_lotl_bundle_original",
    "parent_ec410_outside_operator_roster_original", "epochs",
}
EPOCH_FIELDS = {
    "epoch_index",
    "historical_root_ca_crl_original", "historical_intermediate_ca_crl_original",
    "evaluation_root_ca_crl_original", "evaluation_intermediate_ca_crl_original",
}
CRL_ROLES = ("root", "intermediate")
WINDOWS = ("historical", "evaluation")
MAX_BUNDLE = 115_000
MAX_CRL = 4_000_000
MAX_REVOKED = 20_000


def need(condition, reason, status="permission_denied"):
    if condition is not True:
        raise errors.AnchorError("EC412_" + reason, status)


def exact(value, expected, context):
    need(type(value) is dict and set(value) == expected,
         context + "_EXACT_FIELDS_REQUIRED")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(value):
    return parent.digest(value)


def _inputs(opts, deriving):
    required = {*PARENT_SCALARS, *PARENT_REPEATS, *NEW_SCALARS, *REPEAT_NAMES}
    if not deriving:
        required.update(AUDIT_ONLY)
    need(set(opts) == required, "FULL_EC411_AND_CRL_ARGUMENT_CONTRACT",
         "invalid_input")
    inherited = {key: opts[key] for key in (*PARENT_SCALARS, *PARENT_REPEATS)}
    # Prior signed original inventory pins MUST be present even in derive mode.
    parent._inputs(inherited, False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]], opts[NEW_SCALARS[1]],
                           "EC412_ORIGINAL_CRL_BUNDLE")
    for key in (*NEW_SCALARS[2:], *(() if deriving else AUDIT_ONLY)):
        need(lotl.good_sha(opts[key]), "OUTSIDE_ORIGINAL_CRL_SHA_REQUIRED",
             "invalid_input")
    need(len({opts[key] for key in NEW_SCALARS[2:]}) == 4,
         "FOUR_DISTINCT_FIRST_ORIGINAL_CRL_PINS_REQUIRED", "invalid_input")
    n = len(opts["historical_directory_root_shas"])
    need(1 <= n <= 3, "ONE_TO_THREE_PARENT_EPOCHS", "invalid_input")
    for key in REPEAT_NAMES:
        v = opts[key]
        need(type(v) is list and len(v) == n,
             "CRL_EPOCH_PIN_AND_FLOOR_COUNT", "invalid_input")
        if key.startswith("minimum_"):
            need(all(type(x) is int and 0 <= x <= 2 for x in v),
                 "CRL_JOINT_PUBLISHER_FLOOR", "invalid_input")
        else:
            need(all(lotl.good_sha(x) for x in v),
                 "CRL_EPOCH_INVENTORY_SHA", "invalid_input")
    return inherited


def _parent_report(report, opts):
    keys = {
        "schema", "command", "status", "exit_code", "offline_unresolved_exit_code",
        "verified_live_ec410_report_sha256",
        "verified_live_ec410_inventory_sha256",
        "original_signed_lotl_bundle_sha256",
        "receiver_verified_xades_cert_v2_inventory_sha256",
        "verified_joint_signed_xades_v2_and_real_ec410_parent_publishers",
        "xades_cert_v2_epoch_reviews",
        "bounded_original_signed_xades_cert_v2_and_real_ec410_consistency",
        "sender_origin_path_required_or_read",
        "ec339_to_ec337_full_independent_unmocked_external_acceptance_performed",
        *parent.FLAGS, *parent.NEGATIVES,
    }
    need(type(report) is dict and set(report) == keys and
         report.get("schema") == parent.RESULT_SCHEMA and
         report.get("command") == "audit-historical-ec339-xades-cert-v2" and
         report.get("exit_code") == report.get("offline_unresolved_exit_code") == 2 and
         report.get("original_signed_lotl_bundle_sha256") ==
             opts[lotl.NEW_SCALARS[1]] and
         report.get("receiver_verified_xades_cert_v2_inventory_sha256") ==
             opts[parent.AUDIT_ONLY[0]] and
         all(lotl.good_sha(report.get(k)) for k in (
             "verified_live_ec410_report_sha256",
             "verified_live_ec410_inventory_sha256")) and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report[k] is True for k in parent.FLAGS[-3:]) and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         report.get("sender_origin_path_required_or_read") is False and
         report.get("ec339_to_ec337_full_independent_unmocked_external_acceptance_performed")
             is False and
         report.get("bounded_original_signed_xades_cert_v2_and_real_ec410_consistency")
             is (not any(report[k] for k in parent.FLAGS[:4])) and
         report.get("status") ==
             next((parent.OUTCOMES[i] for i, k in enumerate(parent.FLAGS)
                   if report[k]), parent.OUTCOMES[-1]) + "_unresolved",
         "UNCHANGED_REAL_EC411_REPORT_CONTRACT_INVALID", "unavailable")
    rows = report.get("xades_cert_v2_epoch_reviews")
    n = len(opts["historical_directory_root_shas"])
    rowkeys = {
        "epoch_index", "verified_genuine_original_signed_xades_v2_pair",
        "joint_real_ec410_and_original_xades_v2_publisher_count",
        "xades_v2_epoch_inventory_sha256",
        "genuine_ec410_parent_joint_signed_lotl_publisher_count",
    }
    need(type(rows) is list and len(rows) == n and all(
         type(row) is dict and set(row) == rowkeys and
         type(row["epoch_index"]) is int and row["epoch_index"] == i and
         type(row["verified_genuine_original_signed_xades_v2_pair"]) is int and
         row["verified_genuine_original_signed_xades_v2_pair"] in (0, 1) and
         all(type(row[k]) is int and 0 <= row[k] <= 2 for k in (
             "joint_real_ec410_and_original_xades_v2_publisher_count",
             "genuine_ec410_parent_joint_signed_lotl_publisher_count")) and
         (row["verified_genuine_original_signed_xades_v2_pair"] == 1 or
          row["joint_real_ec410_and_original_xades_v2_publisher_count"] == 0) and
         row["joint_real_ec410_and_original_xades_v2_publisher_count"] <=
             row["genuine_ec410_parent_joint_signed_lotl_publisher_count"] and
         lotl.good_sha(row["xades_v2_epoch_inventory_sha256"])
         for i, row in enumerate(rows)) and
         type(report.get(
             "verified_joint_signed_xades_v2_and_real_ec410_parent_publishers")) is int and
         report["verified_joint_signed_xades_v2_and_real_ec410_parent_publishers"] ==
             sum(row["joint_real_ec410_and_original_xades_v2_publisher_count"]
                 for row in rows),
         "REAL_EC411_ORIGINAL_EPOCH_COUNT_CONTRACT_INVALID", "unavailable")
    return digest(report)


def _extension(exts, oid, name):
    try:
        return exts.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound as exc:
        raise errors.AnchorError("EC412_CRL_" + name + "_REQUIRED",
                                 "permission_denied") from exc


def _crl_window(raw, issuer, target, at_times, *, role, window, prior=None):
    """Verify true issuer-signed full CRL DER, not caller-supplied assertions."""
    need(type(raw) is bytes and 0 < len(raw) <= MAX_CRL,
         "ORIGINAL_CRL_DER_SIZE_INVALID")
    try:
        crl = x509.load_der_x509_crl(raw)
    except (ValueError, TypeError) as exc:
        raise errors.AnchorError("EC412_ORIGINAL_CRL_DER_INVALID",
                                 "permission_denied") from exc
    need(crl.public_bytes(serialization.Encoding.DER) == raw,
         "ORIGINAL_CRL_NOT_CANONICAL_DER")
    need(crl.issuer == issuer.subject and
         crl.signature_algorithm_oid in (
             x509.SignatureAlgorithmOID.RSA_WITH_SHA256,
             x509.SignatureAlgorithmOID.ECDSA_WITH_SHA256),
         "CRL_ISSUER_OR_SIGNING_ALGORITHM_MISMATCH")
    ku = _extension(issuer.extensions, ExtensionOID.KEY_USAGE,
                    "ISSUER_CA_KEY_USAGE")
    need(ku.key_cert_sign and ku.crl_sign,
         "REAL_ISSUER_CA_NOT_AUTHORIZED_TO_SIGN_CRLS")
    need(set(e.oid for e in crl.extensions) == {
         ExtensionOID.CRL_NUMBER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER},
         "FULL_CRL_REQUIRES_EXACT_NUMBER_AND_AUTHORITY_KEY_ID")
    number = _extension(crl.extensions, ExtensionOID.CRL_NUMBER, "NUMBER")
    aki = _extension(crl.extensions, ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                     "AUTHORITY_KEY_ID")
    ski = _extension(issuer.extensions, ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                     "ISSUER_SUBJECT_KEY_ID")
    need(type(number.crl_number) is int and 0 < number.crl_number < 2**63 and
         aki.key_identifier is not None and aki.key_identifier == ski.digest and
         (aki.authority_cert_serial_number is None or
          aki.authority_cert_serial_number == issuer.serial_number) and
         (aki.authority_cert_issuer is None or
          any(isinstance(n, x509.DirectoryName) and n.value == issuer.subject
              for n in aki.authority_cert_issuer)),
         "CRL_NUMBER_OR_REAL_CA_AUTHORITY_KEY_ID_MISMATCH")
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            need(key.key_size >= 2048 and
                 crl.signature_algorithm_oid ==
                     x509.SignatureAlgorithmOID.RSA_WITH_SHA256,
                 "CRL_RSA2048_SHA256_ISSUER_REQUIRED")
            key.verify(crl.signature, crl.tbs_certlist_bytes,
                       padding.PKCS1v15(), hashes.SHA256())
        else:
            need(isinstance(key, ec.EllipticCurvePublicKey) and
                 isinstance(key.curve, ec.SECP256R1) and
                 crl.signature_algorithm_oid ==
                     x509.SignatureAlgorithmOID.ECDSA_WITH_SHA256,
                 "CRL_ECDSA_P256_SHA256_ISSUER_REQUIRED")
            key.verify(crl.signature, crl.tbs_certlist_bytes,
                       ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise errors.AnchorError("EC412_GENUINE_ORIGINAL_CA_CRL_SIGNATURE_INVALID",
                                 "permission_denied") from exc
    this = crl.last_update_utc
    nxt = crl.next_update_utc
    need(this is not None and nxt is not None and this < nxt and
         this.microsecond == nxt.microsecond == 0 and
         issuer.not_valid_before_utc <= this <= issuer.not_valid_after_utc and
         len(at_times) >= 1 and
         all(this <= at < nxt and issuer.not_valid_before_utc <= at <=
             issuer.not_valid_after_utc for at in at_times),
         "CRL_AUTHENTIC_ISSUE_NEXTUPDATE_SOURCE_WINDOW_NOT_COVERED")
    if prior is not None:
        need(number.crl_number > prior["number"] and this > prior["this"],
             "CA_CRL_NUMBER_OR_THISUPDATE_ROLLBACK")
    need(len(crl) <= MAX_REVOKED, "CRL_REVOKED_ENTRY_LIMIT_EXCEEDED")
    seen = set()
    for entry in crl:
        need(entry.serial_number > 0 and entry.serial_number not in seen and
             entry.revocation_date_utc <= this and
             all(e.oid in (CRLEntryExtensionOID.CRL_REASON,
                           CRLEntryExtensionOID.INVALIDITY_DATE)
                 for e in entry.extensions),
             "CRL_REVOKED_ENTRY_DUPLICATE_FUTURE_OR_UNKNOWN_EXTENSION")
        seen.add(entry.serial_number)
        try:
            reason = entry.extensions.get_extension_for_oid(
                CRLEntryExtensionOID.CRL_REASON).value
        except x509.ExtensionNotFound:
            reason = None
        need(reason is None or reason.reason != x509.ReasonFlags.remove_from_crl,
             "DELTA_OR_REMOVE_FROM_CRL_NOT_SUPPORTED")
    need(target.serial_number not in seen,
         "PINNED_LOTL_CERTIFICATE_REVOKED_IN_GENUINE_CA_CRL")
    return {
        "original_crl_sha256": sha(raw),
        "actual_ca_x509_der_sha256": sha(issuer.public_bytes(
            serialization.Encoding.DER)),
        "checked_target_x509_der_sha256": sha(target.public_bytes(
            serialization.Encoding.DER)),
        "ca_crl_number": number.crl_number,
        "signed_this_update_utc": this.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "signed_next_update_utc": nxt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "revoked_entry_count": len(seen),
        "real_ca_signature_verified": True,
        "target_serial_unlisted_as_of_each_window": True,
        "_state": {"number": number.crl_number, "this": this},
    }


def _ec407_historical_claims(opts, n, lineage, doc):
    # Reopen actual signed source statement bytes already checked by EC407.
    old = {"path": opts[cms.NEW_SCALARS[0]],
           "sha256": opts[cms.NEW_SCALARS[1]]}
    bundle = doc(old, "ec412_reopen_real_ec407_signed_custody",
                 cms.MAX_BUNDLE)
    exact(bundle, cms.BUNDLE_FIELDS, "REAL_EC407_CMS_ORIGINAL_BUNDLE")
    need(bundle["schema"] == cms.BUNDLE_SCHEMA and
         bundle["claimed_directory_lineage_id"] == lineage and
         type(bundle["epochs"]) is list and len(bundle["epochs"]) == n,
         "SIGNED_EC407_CUSTODY_SOURCE_EPOCHS_DO_NOT_MATCH")
    claims = []
    for i, epoch in enumerate(bundle["epochs"]):
        exact(epoch, cms.EPOCH_FIELDS, "REAL_EC407_CUSTODY_EPOCH")
        need(type(epoch["epoch_index"]) is int and epoch["epoch_index"] == i and
             type(epoch["publishers"]) is list and len(epoch["publishers"]) == 2,
             "REAL_EC407_TWO_PUBLISHER_CUSTODY_REQUIRED")
        roles = set()
        times = []
        for row in epoch["publishers"]:
            exact(row, cms.ROLE_FIELDS, "REAL_EC407_CUSTODY_PUBLISHER")
            need(row["publisher_id"] not in roles,
                 "EC407_CUSTODY_ROLE_REPLAY")
            roles.add(row["publisher_id"])
            statement = doc(parent.ref(row["original_custody_statement"]),
                            "ec412_original_ec407_signed_custody_statement",
                            cms.MAX_STATEMENT)
            exact(statement, cms.STATEMENT_FIELDS, "EC407_SIGNED_STATEMENT")
            need(statement["schema"] == cms.STATEMENT_SCHEMA and
                 statement["directory_lineage_id"] == lineage and
                 statement["publisher_id"] == row["publisher_id"] and
                 statement["epoch_index"] == i,
                 "ACTUAL_EC407_STATEMENT_IDENTITY_EPOCH_MISMATCH")
            times.append(lotl.utc(statement["claimed_custody_utc"]))
        claims.append(times)
    return claims, old


def _engine(deriving, **opts):
    inherited = _inputs(opts, deriving)
    live = parent.audit(**inherited)  # NEVER MOCKED IN PRODUCTION
    parent_sha = _parent_report(live, opts)
    n = len(opts["historical_directory_root_shas"])
    lineage = opts["claimed_historical_directory_lineage_id"]
    read, doc, late = readers._readers()
    bundle_ref = {"path": opts[NEW_SCALARS[0]], "sha256": opts[NEW_SCALARS[1]]}
    bundle = doc(bundle_ref, "ec412_original_ca_crl_bundle", MAX_BUNDLE)
    exact(bundle, BUNDLE_FIELDS, "ORIGINAL_CA_CRL_BUNDLE")
    ec410_ref = {"path": opts[lotl.NEW_SCALARS[0]],
                 "sha256": opts[lotl.NEW_SCALARS[1]]}
    need(bundle["schema"] == BUNDLE_SCHEMA and
         bundle["claimed_directory_lineage_id"] == lineage and
         bundle["parent_ec410_signed_lotl_bundle_original"] == ec410_ref and
         type(bundle["epochs"]) is list and len(bundle["epochs"]) == n,
         "CRL_BUNDLE_NOT_BOUND_TO_ACTUAL_SIGNED_LOTL_AND_EPOCHS")
    ec410_bundle = doc(ec410_ref, "ec412_original_ec410_lotl_bundle",
                       lotl.MAX_BUNDLE)
    exact(ec410_bundle, lotl.BUNDLE_FIELDS, "ACTUAL_EC410_SOURCE_BUNDLE")
    need(ec410_bundle["schema"] == lotl.BUNDLE_SCHEMA and
         ec410_bundle["claimed_directory_lineage_id"] == lineage and
         type(ec410_bundle["epochs"]) is list and
         len(ec410_bundle["epochs"]) == n,
         "REAL_EC410_SIGNED_LOTL_SOURCE_MISMATCH")
    roster_ref = lotl.ref(ec410_bundle["outside_lotl_operator_roster_original"])
    need(roster_ref == bundle["parent_ec410_outside_operator_roster_original"] and
         roster_ref["sha256"] == opts[lotl.NEW_SCALARS[2]],
         "CRL_BUNDLE_CA_ROSTER_MUST_EQUAL_EC410_OUTSIDE_PIN")
    roster = doc(roster_ref, "ec412_outside_pinned_ca_signer_roster",
                 lotl.MAX_ROSTER)
    exact(roster, lotl.ROSTER_FIELDS, "ACTUAL_EC410_CA_ROSTER")
    need(roster["schema"] == lotl.ROSTER_SCHEMA and
         roster["claimed_directory_lineage_id"] == lineage,
         "ACTUAL_EC410_CA_ROSTER_LINEAGE_MISMATCH")
    cert_refs = {
        "root": lotl.ref(roster["lotl_trust_anchor_certificate_original"]),
        "intermediate": lotl.ref(roster["lotl_intermediate_ca_certificate_original"]),
        "signer": lotl.ref(roster["lotl_signer_certificate_original"]),
    }
    for i, role in enumerate(("root", "intermediate", "signer")):
        need(cert_refs[role]["sha256"] == opts[lotl.NEW_SCALARS[3 + i]],
             "MUST_USE_ORIGINAL_EC410_INDEPENDENT_CA_AND_SIGNER_PINS")
    raw_cert = {role: read(cert_refs[role], "ec412_actual_original_" + role,
                           lotl.MAX_CERT) for role in cert_refs}
    chain = lotl._chain({"root": raw_cert["root"],
                         "mid": raw_cert["intermediate"],
                         "signer": raw_cert["signer"]}, [])  # unchanged chain rules
    claims, ec407_ref = _ec407_historical_claims(opts, n, lineage, doc)
    evaluation = lotl.utc(opts["ec407_institutional_evaluation_utc"])
    flags = {k: False for k in FLAGS}
    flags[FLAGS[0]] = (
        not live["bounded_original_signed_xades_cert_v2_and_real_ec410_consistency"] or
        any(row["joint_real_ec410_and_original_xades_v2_publisher_count"] != 2
            for row in live["xades_cert_v2_epoch_reviews"]))
    used_paths = {bundle_ref["path"], roster_ref["path"], ec410_ref["path"],
                  ec407_ref["path"], *(v["path"] for v in cert_refs.values())}
    used_shas = {bundle_ref["sha256"], roster_ref["sha256"], ec410_ref["sha256"],
                 ec407_ref["sha256"], *(v["sha256"] for v in cert_refs.values())}
    reviews, records = [], []
    previous = {role: None for role in CRL_ROLES}
    missing = False
    first_shas = []
    total = 0
    for i, epoch in enumerate(bundle["epochs"]):
        exact(epoch, EPOCH_FIELDS, "ORIGINAL_LOTL_CRL_EPOCH")
        need(type(epoch["epoch_index"]) is int and epoch["epoch_index"] == i,
             "ORIGINAL_CRL_EPOCH_INDEX_MISMATCH")
        ec410_epoch = ec410_bundle["epochs"][i]
        exact(ec410_epoch, lotl.EPOCH_FIELDS, "ORIGINAL_EC410_SIGNED_LOTL_EPOCH")
        expected_pair = bool(live["xades_cert_v2_epoch_reviews"][i][
                             "verified_genuine_original_signed_xades_v2_pair"])
        values = [epoch[w + "_" + r + "_ca_crl_original"]
                  for w in WINDOWS for r in CRL_ROLES]
        if all(v is None for v in values):
            need(i > 0 and not expected_pair,
                 "FIRST_OR_PARENT_PRESENT_ORIGINAL_CRL_PAIR_MISSING")
            missing = True
            flags[FLAGS[2]] = flags[FLAGS[3]] = True
            record = {"epoch_index": i, "historical": None, "evaluation": None,
                      "complete_original_ca_crl_four_documents": False,
                      "joint_real_ec411_and_genuine_crl_publisher_count": 0}
        else:
            need(all(v is not None for v in values) and not missing and
                 expected_pair,
                 "PARTIAL_REAPPEARING_OR_PARENT_MISSING_CA_CRL_PAIR")
            ec410_refs = [lotl.ref(ec410_epoch[
                "original_" + w + "_signed_lotl_xml"]) for w in WINDOWS]
            signer_raw = raw_cert["signer"]
            signed = {}
            for w, source_ref in zip(WINDOWS, ec410_refs):
                need(source_ref["path"] not in used_paths and
                     source_ref["sha256"] not in used_shas,
                     "PARENT_LOTL_ORIGINAL_SOURCE_PATH_OR_SHA_REPLAY")
                used_paths.add(source_ref["path"])
                used_shas.add(source_ref["sha256"])
                verified = parent._verify_signed_original(
                    source_ref, signer_raw,
                    {"original_signed_lotl_sha256": source_ref["sha256"],
                     "original_lotl_signer_certificate_sha256": sha(signer_raw),
                     "xmlsig_reference_count": 2,
                     "xades_signed_properties_verified": True}, read)
                signed[w] = lotl.utc(verified["authenticated_signing_time_utc"])
            coverage_times = {
                "historical": [signed["historical"], *claims[i]],
                "evaluation": [signed["evaluation"], evaluation],
            }
            checked = {}
            for w in WINDOWS:
                checked[w] = {}
                for role in CRL_ROLES:
                    source_ref = lotl.ref(epoch[w + "_" + role +
                                                "_ca_crl_original"])
                    need(source_ref["path"] not in used_paths and
                         source_ref["sha256"] not in used_shas,
                         "CA_CRL_PATH_ALIAS_OR_SHA_REPLAY")
                    used_paths.add(source_ref["path"])
                    used_shas.add(source_ref["sha256"])
                    raw = read(source_ref, "ec412_original_" + w + "_" + role +
                               "_issuer_signed_ca_crl", MAX_CRL)
                    issuing = chain["root"] if role == "root" else chain["mid"]
                    target = chain["mid"] if role == "root" else chain["signer"]
                    review = _crl_window(
                        raw, issuing, target, coverage_times[w],
                        role=role, window=w, prior=previous[role])
                    previous[role] = review.pop("_state")
                    checked[w][role] = review
                    if i == 0:
                        first_shas.append(source_ref["sha256"])
            joint = (
                2 if (not flags[FLAGS[0]] and
                      live["xades_cert_v2_epoch_reviews"][i][
                          "joint_real_ec410_and_original_xades_v2_publisher_count"] == 2)
                else 0
            )
            if joint != 2:
                flags[FLAGS[3]] = True
            record = {"epoch_index": i,
                      "historical": checked["historical"],
                      "evaluation": checked["evaluation"],
                      "complete_original_ca_crl_four_documents": True,
                      "joint_real_ec411_and_genuine_crl_publisher_count": joint}
        epoch_sha = digest(record)
        if (epoch_sha != opts[REPEAT_NAMES[0]][i] or
            record["joint_real_ec411_and_genuine_crl_publisher_count"] <
                opts[REPEAT_NAMES[1]][i]):
            flags[FLAGS[1]] = True
        records.append(record)
        reviews.append({
            "epoch_index": i,
            "verified_original_ca_crl_historical_evaluation_four_documents":
                int(record["complete_original_ca_crl_four_documents"]),
            "joint_genuine_crl_and_real_ec411_parent_publisher_count":
                record["joint_real_ec411_and_genuine_crl_publisher_count"],
            "lotl_ca_crl_epoch_inventory_sha256": epoch_sha,
            "genuine_ec411_parent_xades_v2_joint_publisher_count":
                live["xades_cert_v2_epoch_reviews"][i][
                    "joint_real_ec410_and_original_xades_v2_publisher_count"],
        })
        total += record["joint_real_ec411_and_genuine_crl_publisher_count"]
    need(len(first_shas) == 4, "FIRST_FOUR_ORIGINAL_CA_CRLS_REQUIRED")
    if first_shas != [opts[k] for k in NEW_SCALARS[2:]]:
        flags[FLAGS[1]] = True
    inventory = {
        "schema": INVENTORY_SCHEMA,
        "directory_lineage_id": lineage,
        "verified_live_ec411_original_report_sha256": parent_sha,
        "verified_live_ec411_signed_cert_inventory_sha256":
            live["receiver_verified_xades_cert_v2_inventory_sha256"],
        "actual_ec410_lotl_bundle_sha256": ec410_ref["sha256"],
        "actual_outside_pinned_ec410_ca_chain_shas":
            [cert_refs[k]["sha256"] for k in ("root", "intermediate", "signer")],
        "actual_ec407_original_cms_bundle_sha256": ec407_ref["sha256"],
        "first_four_original_ca_crl_shas": first_shas,
        "full_crl_profile": "ROOT_SIGNS_INTERMEDIATE_CRL__INTERMEDIATE_SIGNS_LOTL_SIGNER_CRL_SHA256_AKI_NUMBER_WINDOWS",
        "epochs": records,
    }
    invsha = digest(inventory)
    if not deriving and invsha != opts[AUDIT_ONLY[0]]:
        flags[FLAGS[1]] = True
    for path, (expected, max_bytes) in late.items():
        reloaded = io._read({"path": path, "sha256": expected},
                            "ec412_final_original_sha_readback",
                            max_bytes, {}, {}, set())
        need(sha(reloaded) == expected,
             "ACTUAL_CRL_OR_ORIGINAL_CHANGED_BETWEEN_READS")
    for key in FLAGS[-3:]:
        flags[key] = True
    return {
        "schema": DERIVE_SCHEMA if deriving else RESULT_SCHEMA,
        "command": ("derive-historical-ec339-lotl-crl-inventory" if deriving
                    else "audit-historical-ec339-lotl-crl"),
        "status": next((OUTCOMES[i] for i, k in enumerate(FLAGS)
                        if flags[k]), OUTCOMES[-1]) + "_unresolved",
        "exit_code": 2,
        "offline_unresolved_exit_code": 2,
        "verified_live_ec411_report_sha256": parent_sha,
        "verified_live_ec411_inventory_sha256":
            live["receiver_verified_xades_cert_v2_inventory_sha256"],
        "original_lotl_ca_crl_bundle_sha256": bundle_ref["sha256"],
        "receiver_verified_lotl_ca_crl_inventory_sha256": invsha,
        "verified_joint_crl_and_real_ec411_parent_publishers": total,
        "lotl_ca_crl_epoch_reviews": reviews,
        "bounded_original_ca_crl_and_real_ec411_parent_consistency":
            not any(flags[k] for k in FLAGS[:4]),
        "sender_origin_path_required_or_read": False,
        "ec339_to_ec337_full_independent_unmocked_external_acceptance_performed": False,
        **flags,
        **{k: False for k in NEGATIVES},
        **({"unsigned_lotl_ca_crl_inventory": inventory} if deriving else {}),
    }


def derive_inventory(**opts):
    return _engine(True, **opts)


def audit(**opts):
    return _engine(False, **opts)
