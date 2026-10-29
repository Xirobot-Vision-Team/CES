#!/usr/bin/env python3
"""EC412 isolated offline original LOTL CRL receiver. No positive PASS."""
from __future__ import annotations

import argparse
import json

from ec295_delivery_anchor import anchor as errors
from ec279_finding_query_host import protocol as host
from ec411_xades_certificate import operator as previous
from . import protocol as core


def parser():
    p = argparse.ArgumentParser(description=(
        "Read-only original pinned LOTL issuer-signed X509 full CRLs for "
        "intermediate CA and LOTL signer in both source windows. Mandatory "
        "real unmodified EC411 -> EC410 -> all older original receiver audits; "
        "never official/public accreditation or positive success."))
    sub = p.add_subparsers(dest="command", required=True)
    inherited_parser = next(
        a.choices["audit-historical-ec339-xades-cert-v2"]
        for a in previous.parser()._actions
        if isinstance(a, argparse._SubParsersAction))
    inherited_flags = {
        a.dest: a.option_strings[0]
        for a in inherited_parser._actions
        if a.dest in core.PARENT_REPEATS and a.option_strings
    }
    if set(inherited_flags) != set(core.PARENT_REPEATS):
        raise RuntimeError("EC412 inherited exact EC411 CLI contract changed")
    for command in ("derive-historical-ec339-lotl-crl-inventory",
                    "audit-historical-ec339-lotl-crl"):
        sp = sub.add_parser(command,
            help="Genuine offline historical/evaluation signed CA CRL originals")
        scalars = (*core.PARENT_SCALARS, *core.NEW_SCALARS)
        if command.startswith("audit-"):
            scalars += core.AUDIT_ONLY
        for key in scalars:
            sp.add_argument("--" + key.replace("_", "-"), required=True)
        for key, flag in (
            *((k, inherited_flags[k]) for k in core.PARENT_REPEATS),
            *core.NEW_REPEATS
        ):
            sp.add_argument(flag, dest=key, action="append",
                **({"default": []} if key == "historical_dual_handoff_shas"
                   else {"required": True}),
                **({"type": int} if key.startswith("minimum_") else {}))
    return p


def denial(command, exc):
    if isinstance(exc, (errors.AnchorError, host.HostError)):
        status, code = exc.status, exc.code.upper()
    else:
        status, code = "unavailable", "EC412_LOCAL_IO_OR_UNEXPECTED_EXCEPTION"
    return {
        "schema": core.DENIAL_SCHEMA,
        "command": command, "status": status, "reason_code": code,
        "exit_code": {"permission_denied": 3,
                      "invalid_input": 4, "unavailable": 5}.get(status, 5),
        "offline_unresolved_exit_code": 2,
        "sender_origin_path_required_or_read": False,
        "ec339_to_ec337_full_independent_unmocked_external_acceptance_performed": False,
        **{k: False for k in core.NEGATIVES},
    }


def main(argv=None):
    parsed = vars(parser().parse_args(argv))
    command = parsed.pop("command")
    parsed["expected_source_attestation_head_shas"] = [
        None if s == "none" else s
        for s in parsed["expected_source_attestation_head_shas"]]
    try:
        result = (core.derive_inventory(**parsed) if command.startswith("derive-")
                  else core.audit(**parsed))
    except Exception as exc:
        result = denial(command, exc)
    print(json.dumps(result, sort_keys=True, ensure_ascii=True, allow_nan=False,
                     separators=(",", ":")))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
