#!/usr/bin/env python3
"""EC308 offline verification client. No signing, CAS, network or business writes."""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from . import receipt as r


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        "Offline Ed25519 issuer-signed CAS receipt claim audit; "
        "NOT a live CAS/WORM operation or proof of global latest. "
        "Every source SHA and authority key must be independently supplied."))
    sub = p.add_subparsers(dest="command", required=True)
    for command in ("verify", "verify-report"):
        q = sub.add_parser(command, help=(
            "fully replay EC307 fork and check signed CAS authority claim"
            if command == "verify" else
            "replay all original signatures and verify pinned unsigned audit report"))
        for flag in (
            "fork-case-file", "expected-fork-case-sha256",
            "fork-evidence-file", "expected-fork-evidence-sha256",
            "receipt-file", "expected-receipt-sha256",
            "cas-authority-id", "cas-public-hex", "request-nonce-sha256",
            "expected-parent-cas-revision", "expected-parent-cas-head-sha256"
        ):
            q.add_argument("--" + flag, required=True,
                           type=int if flag == "expected-parent-cas-revision" else str)
        if command == "verify":
            q.add_argument("--out", help="optional private O_EXCL/fsync audit report")
        else:
            q.add_argument("--audit-report-file", required=True)
            q.add_argument("--expected-audit-report-sha256", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        opts = {
            "fork_case_file": args.fork_case_file,
            "expected_fork_case_sha256": args.expected_fork_case_sha256,
            "fork_evidence_file": args.fork_evidence_file,
            "expected_fork_evidence_sha256": args.expected_fork_evidence_sha256,
            "receipt_file": args.receipt_file,
            "expected_receipt_sha256": args.expected_receipt_sha256,
            "trust": {
                "cas_authority_id": args.cas_authority_id,
                "cas_authority_public_hex": args.cas_public_hex,
                "expected_request_nonce_sha256": args.request_nonce_sha256,
                "expected_parent_cas_revision": args.expected_parent_cas_revision,
                "expected_parent_cas_head_sha256": args.expected_parent_cas_head_sha256,
            },
        }
        if args.command == "verify":
            result = r.verify(**opts, out=args.out)
        else:
            result = r.verify_report(
                **opts, audit_report_file=args.audit_report_file,
                expected_audit_report_sha256=args.expected_audit_report_sha256)
        print(json.dumps({
            "schema": r.RESULT_SCHEMA, "command": args.command, **result,
            "independent_external_real_authority_verified": False,
            "external_atomicity_or_worm_receipt_readback_proven": False,
            "current_global_latest_verified": False,
        }, sort_keys=True, separators=(",", ":")))
        return result["exit_code"]
    except Exception as exc:
        status = (exc.status if isinstance(exc, (a.AnchorError, io.HostError))
                  else "unavailable")
        code = (exc.code if isinstance(exc, (a.AnchorError, io.HostError))
                else "EC308_LOCAL_VERIFICATION_UNAVAILABLE")
        rc = {"permission_denied": 3, "invalid_input": 4, "unavailable": 5}.get(status, 5)
        print(json.dumps({
            "schema": r.DENIAL_SCHEMA, "command": args.command,
            "status": status, "reason_code": code, "exit_code": rc,
            "signed_cas_claim_verified": False,
            "real_external_cas_or_latest_proven": False,
            "external_store_or_original_business_write_performed": False,
        }, sort_keys=True, separators=(",", ":")))
        return rc


if __name__ == "__main__":
    raise SystemExit(main())
