#!/usr/bin/env python3
"""EC308: strictly read-only verification of an *externally issued* CAS claim.

The original EC307 case and report are BOTH independently raw-SHA pinned,
and are re-evaluated against EC306 -> EC304/305 -> EC303/294 original
signatures. A third-party Ed25519 signature is then checked under an
independently supplied CAS public key. This verifies WHAT the issuer signed,
NOT whether the issuer was actually authorized, had a linearizable store,
durably committed, or is currently the world's latest authoritative state.

There is intentionally no sign/issue, commit, network, key-loading, retry,
CAS update, or external state writer in this module.
"""
from __future__ import annotations

from typing import Any
from cryptography.exceptions import InvalidSignature

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from delivery_anchor import operator as store
from portable_bundle import bundle as b
from receiver_ack import ack as receiver
from registrar_epochs import epochs as epochs
from registrar_forks import forks
from registrar_forks import operator as fork_operator

RECEIPT_SCHEMA = "ces.ec308.external_signed_cas_decision_receipt.v1"
CLAIM_SCHEMA = "ces.ec308.external_cas_decision_claim.v1"
REPORT_SCHEMA = "ces.ec308.external_signed_cas_claim_audit.v1"
RESULT_SCHEMA = "ces.ec308.cas_receipt_audit_result.v1"
DENIAL_SCHEMA = "ces.ec308.cas_receipt_audit_denial.v1"
DOMAIN = b"CES/EC308/ExternalCAS/AuthorityDecisionReceipt/v1\0"
OUTCOMES = frozenset(("compare_exchange_committed_claim",
                      "compare_exchange_precondition_failed_claim"))
MAX_RECEIPT_BYTES = 8192
MAX_AUDIT_REPORT_BYTES = 12_000
MAX_CAS_REVISION = 2**63 - 2
RECEIPT_FIELDS = frozenset({"schema", "claim", "authority_signature_ed25519"})
CLAIM_FIELDS = frozenset({
    "schema", "registry_id", "cas_authority_id", "cas_authority_public_hex",
    "ec307_fork_evidence_raw_sha256", "ec307_choice_request_raw_sha256",
    "request_nonce_sha256", "expected_parent_chain_raw_sha256",
    "candidate_chain_raw_sha256", "expected_parent_cas_revision",
    "expected_parent_cas_head_sha256", "outcome",
    "observed_cas_revision", "observed_head_chain_raw_sha256",
    "selected_candidate_chain_raw_sha256"})
TRUST_FIELDS = frozenset({
    "cas_authority_id", "cas_authority_public_hex",
    "expected_request_nonce_sha256", "expected_parent_cas_revision",
    "expected_parent_cas_head_sha256"})


def need(condition: Any, code: str, status: str = "permission_denied") -> None:
    if condition is not True:
        raise a.AnchorError("EC308_" + code, status)


def _sha(value: Any) -> bool:
    return epochs._positive_sha(value)


def _trust(trust: dict) -> None:
    a.exact(trust, TRUST_FIELDS, "EC308_EXACT_EXTERNAL_TRUST_FIELDS_REQUIRED")
    need(type(trust["cas_authority_id"]) is str and
         receiver.ID.fullmatch(trust["cas_authority_id"]) is not None,
         "CAS_AUTHORITY_ID_MUST_BE_EXTERNALLY_SPECIFIED")
    need(type(trust["cas_authority_public_hex"]) is str and
         a.valid_pub(trust["cas_authority_public_hex"]),
         "EXTERNAL_CAS_ED25519_PUBLIC_PIN_REQUIRED")
    need(_sha(trust["expected_request_nonce_sha256"]) and
         _sha(trust["expected_parent_cas_head_sha256"]),
         "EXTERNAL_NONCE_AND_PARENT_HEAD_PINS_REQUIRED")
    revision = trust["expected_parent_cas_revision"]
    need(type(revision) is int and 0 <= revision < MAX_CAS_REVISION,
         "EXTERNALLY_PINNED_PARENT_CAS_REVISION_INVALID")


def _known_signer_keys(case: dict) -> set[str]:
    """Key separation from available full registrar epochs and ACK signers.

    The full original signature verifier remains authoritative; this separate
    read is ONLY to assemble an extra exclusion set from already pinned data.
    Historical EC294/295 signers not present here are NOT claimed excluded.
    """
    root_spec = case["parent"]
    docs = [epochs._owner_private_read(
        root_spec["chain_file"], root_spec["external"]["chain_raw_sha256"])]
    for name in ("candidate_a", "candidate_b"):
        entry = case[name]
        docs.append(epochs._owner_private_read(
            entry["chain_file"], entry["expected_chain_raw_sha256"]))
    keys: set[str] = set()
    for doc in docs:
        keys.update((doc["governor_public_hex"],
                     doc["initial_registrar_public_hex"]))
        keys.update(ep["registrar_public_hex"] for ep in doc["epochs"])
    for name in ("candidate_a", "candidate_b"):
        ack_proof = case[name]["ack_proof"]
        if ack_proof is not None:
            keys.update((ack_proof["receiver_public_hex"],
                         ack_proof["pins"]["a_public_hex"],
                         ack_proof["pins"]["b_public_hex"]))
    return keys


def _parse_receipt(file: str, expected_sha: str) -> tuple[dict, dict]:
    need(_sha(expected_sha), "RECEIPT_INDEPENDENT_RAW_SHA_PIN_REQUIRED")
    receipt = epochs._owner_private_read(file, expected_sha)
    need(len(b.canonical(receipt)) <= MAX_RECEIPT_BYTES,
         "RECEIPT_EXCEEDS_PROTOCOL_SIZE_LIMIT")
    a.exact(receipt, RECEIPT_FIELDS, "EC308_RECEIPT_FIELDS_INVALID")
    need(receipt["schema"] == RECEIPT_SCHEMA, "RECEIPT_SCHEMA_INVALID")
    claim = a.exact(receipt["claim"], CLAIM_FIELDS,
                    "EC308_SIGNED_CLAIM_FIELDS_INVALID")
    need(claim["schema"] == CLAIM_SCHEMA, "SIGNED_CLAIM_SCHEMA_INVALID")
    signature = receipt["authority_signature_ed25519"]
    need(type(signature) is str and a.SIG.fullmatch(signature) is not None,
         "SIGNATURE_MUST_BE_64_BYTE_LOWERCASE_HEX")
    return receipt, claim


def evaluate(*, fork_case_file: str, expected_fork_case_sha256: str,
             fork_evidence_file: str, expected_fork_evidence_sha256: str,
             receipt_file: str, expected_receipt_sha256: str,
             trust: dict) -> dict:
    """Revalidate signed original fork + bounded independently pinned CAS claim.

    Return value is an unsigned read-only *audit* of one real Ed25519-signed
    issuer assertion. Even a valid issuer signature does not attest an atomic
    CAS or prove a globally authorized, linearizable, durable latest value.
    """
    _trust(trust)
    need(_sha(expected_fork_case_sha256) and
         _sha(expected_fork_evidence_sha256) and _sha(expected_receipt_sha256),
         "THREE_INDEPENDENT_RAW_SHA_PINS_REQUIRED")
    case = fork_operator.read_case(fork_case_file, expected_fork_case_sha256)
    parent = case["parent"]
    options = {
        "parent_chain_file": parent["chain_file"],
        "parent_external": parent["external"],
        "parent_ledger_files": parent["ledger_files"],
        "parent_certificate_files": parent["certificate_files"],
        "candidate_a": case["candidate_a"],
        "candidate_b": case["candidate_b"],
    }
    # Signature replay is crucial: validating only a supplied EC307 JSON and
    # an issuer's signature would allow a signed fake fork to be laundered.
    replay = forks.verify_report(
        **options, evidence_file=fork_evidence_file,
        expected_evidence_report_sha256=expected_fork_evidence_sha256)
    need(replay["exit_code"] == 2 and
         replay["original_signatures_and_new_ack_proofs_reverified"] is True,
         "REAL_ORIGINAL_SIGNED_FORK_REPLAY_REQUIRED")
    fork = forks._read_report(fork_evidence_file, expected_fork_evidence_sha256)
    handoff = fork["external_cas_handoff"]
    parent_sha = fork["parent_chain_raw_sha256"]
    candidates = handoff["allowed_candidate_chain_raw_sha256"]
    need(parent_sha == trust["expected_parent_cas_head_sha256"] and
         parent_sha == handoff["expected_parent_chain_raw_sha256"] and
         type(candidates) is list and len(candidates) == 2 and
         candidates == sorted(candidates) and len(set(candidates)) == 2,
         "INDEPENDENT_PARENT_HEAD_OR_VALID_TWO_CANDIDATE_HANDOFF_REQUIRED")

    receipt, claim = _parse_receipt(receipt_file, expected_receipt_sha256)
    need(claim["registry_id"] == fork["registry_id"] and
         claim["cas_authority_id"] == trust["cas_authority_id"] and
         claim["cas_authority_public_hex"] == trust["cas_authority_public_hex"] and
         claim["ec307_fork_evidence_raw_sha256"] == expected_fork_evidence_sha256 and
         claim["ec307_choice_request_raw_sha256"] == b.digest(b.canonical(handoff)) and
         claim["request_nonce_sha256"] == trust["expected_request_nonce_sha256"] and
         claim["expected_parent_chain_raw_sha256"] == parent_sha and
         claim["candidate_chain_raw_sha256"] == candidates and
         claim["expected_parent_cas_revision"] == trust["expected_parent_cas_revision"] and
         claim["expected_parent_cas_head_sha256"] ==
             trust["expected_parent_cas_head_sha256"],
         "SIGNED_CLAIM_NOT_EQUAL_EXTERNAL_PINS_OR_REPLAYED_FORK")
    need(claim["cas_authority_public_hex"] not in _known_signer_keys(case),
         "CAS_SIGNER_MUST_NOT_REUSE_KNOWN_REGISTRAR_GOVERNOR_ACK_SIGNER")
    try:
        io.pub_from_hex(trust["cas_authority_public_hex"]).verify(
            bytes.fromhex(receipt["authority_signature_ed25519"]),
            DOMAIN + a.canonical(claim))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise a.AnchorError("EC308_CAS_AUTHORITY_ED25519_SIGNATURE_INVALID",
                            "permission_denied") from exc

    prev = trust["expected_parent_cas_revision"]
    observed = claim["observed_cas_revision"]
    observed_head = claim["observed_head_chain_raw_sha256"]
    selected = claim["selected_candidate_chain_raw_sha256"]
    outcome = claim["outcome"]
    need(outcome in OUTCOMES, "UNKNOWN_CAS_OUTCOME")
    need(type(observed) is int and prev < observed <= MAX_CAS_REVISION and
         _sha(observed_head), "SIGNED_CAS_RESULT_REVISION_OR_HEAD_INVALID")
    if outcome == "compare_exchange_committed_claim":
        need(observed == prev + 1 and
             type(selected) is str and selected in candidates and
             observed_head == selected,
             "COMMIT_CLAIM_MUST_ADVANCE_ONE_REVISION_TO_EXACT_CANDIDATE")
        status = "issuer_signed_commit_claim_verified_external_commit_not_proven"
    else:
        # A failed compare does NOT select any candidate, and does NOT
        # automatically prove that the observed head's own lineage is valid.
        need(selected is None and observed_head != parent_sha,
             "PRECONDITION_FAILURE_HAS_NO_WINNER_AND_MUST_SHOW_DRIFT")
        status = "issuer_signed_precondition_failure_claim_verified_current_head_not_proven"

    report = {
        "schema": REPORT_SCHEMA,
        "status": status,
        "registry_id": fork["registry_id"],
        "cas_authority_id": trust["cas_authority_id"],
        "cas_authority_public_hex": trust["cas_authority_public_hex"],
        "fork_case_raw_sha256": expected_fork_case_sha256,
        "fork_evidence_raw_sha256": expected_fork_evidence_sha256,
        "fork_choice_request_raw_sha256": b.digest(b.canonical(handoff)),
        "signed_cas_receipt_raw_sha256": expected_receipt_sha256,
        "signed_cas_claim_raw_sha256": b.digest(b.canonical(claim)),
        "request_nonce_sha256": trust["expected_request_nonce_sha256"],
        "expected_parent_chain_raw_sha256": parent_sha,
        "candidate_chain_raw_sha256": candidates,
        "expected_parent_cas_revision": prev,
        "observed_cas_revision": observed,
        "observed_head_chain_raw_sha256": observed_head,
        "selected_candidate_chain_raw_sha256": selected,
        "issuer_signed_outcome": outcome,
        "original_ec294_through_ec307_signatures_and_fork_replayed": True,
        "distinct_known_original_signer_role_key_checked": True,
        "issuer_ed25519_signature_verified": True,
        "independent_external_cas_authority_real_world_authorization_proven": False,
        "real_store_linearizability_durability_or_fresh_readback_proven": False,
        "global_latest_head_or_competing_branch_resolution_proven": False,
        "request_nonce_global_uniqueness_or_replay_prevention_proven": False,
        "off_host_cas_or_business_write_performed": False,
        "any_private_signing_key_loaded": False,
        "signed_receipt_is_a_claim_not_a_verified_cas_execution": True,
    }
    need(len(b.canonical(report)) <= MAX_AUDIT_REPORT_BYTES,
         "AUDIT_REPORT_EXCEEDS_BOUNDED_SIZE")
    return report


def verify(*, out: str | None = None, **options) -> dict:
    report = evaluate(**options)
    if out is not None:
        store.store(out, report, MAX_AUDIT_REPORT_BYTES)
    return {
        "status": report["status"],
        "exit_code": (0 if report["issuer_signed_outcome"] ==
                      "compare_exchange_committed_claim" else 2),
        "signed_cas_receipt_raw_sha256": report["signed_cas_receipt_raw_sha256"],
        "audit_report_raw_sha256": b.digest(b.canonical(report)),
        "audit_report_written": out is not None,
        "issuer_ed25519_signature_verified": True,
        "original_signed_fork_replayed": True,
        "selected_candidate_chain_raw_sha256":
            report["selected_candidate_chain_raw_sha256"],
        "real_external_cas_commit_or_latest_proven": False,
        "real_world_authority_proven": False,
        "business_or_external_store_write_performed": False,
    }


def verify_report(*, audit_report_file: str,
                  expected_audit_report_sha256: str, **options) -> dict:
    need(_sha(expected_audit_report_sha256),
         "AUDIT_REPORT_INDEPENDENT_RAW_SHA_PIN_REQUIRED")
    # EC307's read method has identical canonical 0600/O_NOFOLLOW and
    # inode-stability protections; we impose our tighter report budget below.
    saved = forks._read_report(audit_report_file, expected_audit_report_sha256)
    need(len(b.canonical(saved)) <= MAX_AUDIT_REPORT_BYTES,
         "AUDIT_REPORT_EXCEEDS_BOUNDED_SIZE")
    new = evaluate(**options)
    need(saved == new, "AUDIT_REPORT_DIFFERS_FROM_FULL_REPLAY_AND_ISSUER_SIGNATURE")
    result = verify_result(new)
    result["audit_report_raw_sha256"] = expected_audit_report_sha256
    result["audit_report_written"] = False
    result["status"] = "externally_pinned_signed_cas_claim_audit_fully_reverified"
    return result


def verify_result(report: dict) -> dict:
    """Small non-authoritative result; mirrors verify without rereading files."""
    return {
        "status": report["status"],
        "exit_code": (0 if report["issuer_signed_outcome"] ==
                      "compare_exchange_committed_claim" else 2),
        "signed_cas_receipt_raw_sha256": report["signed_cas_receipt_raw_sha256"],
        "audit_report_raw_sha256": b.digest(b.canonical(report)),
        "audit_report_written": False,
        "issuer_ed25519_signature_verified": True,
        "original_signed_fork_replayed": True,
        "selected_candidate_chain_raw_sha256":
            report["selected_candidate_chain_raw_sha256"],
        "real_external_cas_commit_or_latest_proven": False,
        "real_world_authority_proven": False,
        "business_or_external_store_write_performed": False,
    }
