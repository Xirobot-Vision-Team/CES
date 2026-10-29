#!/usr/bin/env python3
"""EC-156: consume the EXISTING ces.cli.v1 wire envelope without running CES.

This is an offline, read-only consumer. It deliberately does not launch pwsh,
touch a repository, authorize writes, or interpret business evidence as verified.
The CLI still self-reports V4.60/R150; EC-157 made reviewed source hardening
changes without upgrading its existing ces.cli.v1 wire-format contract.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CONTRACT_PATH = ROOT / "references" / "cli-response-contract.v1.json"
DEFAULT_LIMIT_BYTES = 128 * 1024 * 1024


class ContractError(Exception):
    """Invalid JSON, truncated input, unsupported contract, or unsafe file read."""


def _reject_duplicate_keys(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in items:
        if key in result:
            raise ContractError(f"duplicate JSON object member: {key!r}")
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> Any:
    raise ContractError(f"non-JSON numeric constant: {value}")


def parse_one_json(payload: bytes) -> dict[str, Any]:
    """Exactly one JSON object; rejects BOM, duplicates and NaN/Infinity.

    Rejecting duplicates matters for status, read_only and coverage: otherwise
    two consumers may reach opposite conclusions about one output.
    """
    try:
        text = payload.decode("utf-8", errors="strict")
        obj = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_constant,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ContractError(f"invalid UTF-8 JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ContractError("the ces.cli.v1 response must be one JSON object")
    return obj


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    obj = parse_one_json(path.read_bytes())
    if (obj.get("contract_id") != "ces.cli.v1.response"
            or obj.get("wire_schema_version") != "ces.cli.v1"):
        raise ContractError("unrecognized EC-156 response contract")
    return obj


def read_limited(path: str, max_bytes: int) -> bytes:
    if max_bytes < 1:
        raise ContractError("--max-bytes must be a positive number")
    try:
        if path == "-":
            data = sys.stdin.buffer.read(max_bytes + 1)
        else:
            with open(path, "rb") as stream:
                data = stream.read(max_bytes + 1)
    except OSError as exc:
        raise ContractError(f"could not read response: {exc}") from exc
    if len(data) > max_bytes:
        raise ContractError(
            f"response exceeds consumer limit {max_bytes} bytes; "
            "increase --max-bytes if the complete output is expected"
        )
    return data


def _is_type(value: Any, type_name: str) -> bool:
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "boolean":
        return type(value) is bool
    if type_name == "array":
        return isinstance(value, list)
    if type_name == "object":
        return isinstance(value, dict)
    if type_name == "object_or_null":
        return value is None or isinstance(value, dict)
    raise ContractError(f"unsupported declared field type: {type_name}")


def evaluate(
    obj: Mapping[str, Any],
    contract: Mapping[str, Any],
    observed_exit_code: int | None = None,
) -> dict[str, Any]:
    """Validate wire shape and report consumer-relevant outcome.

    Does not require every coverage flag to be true: most are non-applicable
    for any given Action, and success never means all 31 probes ran.
    """
    issues: list[dict[str, str]] = []
    advisories: list[str] = []

    def issue(code: str, field: str, detail: str) -> None:
        issues.append({"code": code, "field": field, "detail": detail})

    required = contract["required_fields"]
    for key, typename in required.items():
        if key not in obj:
            issue("MISSING_FIELD", key, f"required {typename} field is absent")
        elif not _is_type(obj[key], typename):
            issue("FIELD_TYPE_MISMATCH", key, f"expected {typename}")

    if obj.get("schema_version") != contract["wire_schema_version"]:
        issue("SCHEMA_MISMATCH", "schema_version", "not the ces.cli.v1 wire schema")
    for name in ("product_version", "build", "action", "reason_code"):
        if name in obj and isinstance(obj[name], str) and not obj[name].strip():
            issue("EMPTY_IDENTITY_FIELD", name, "non-empty string required")

    # The source advertises these lists in every envelope. They are descriptors,
    # not evidence that a handler has executed or that proposed actions exist.
    for name in (
        "supported_actions", "supported_collect_modes", "supported_codeshow_modes"
    ):
        value = obj.get(name)
        if isinstance(value, list) and any(
            not isinstance(item, str) or not item for item in value
        ):
            issue("INVALID_LIST_ITEM", name, "expected only non-empty strings")
    warns = obj.get("warnings")
    if isinstance(warns, list) and any(not isinstance(x, str) for x in warns):
        issue("INVALID_WARNING", "warnings", "warning items must be strings")

    statuses = contract["statuses"]
    status = obj.get("status")
    expected_exit = None
    if isinstance(status, str) and status in statuses:
        expected_exit = statuses[status]["exit_code"]
    elif "status" in obj and isinstance(status, str):
        issue("UNKNOWN_STATUS", "status", "status is not in the R150 source contract")

    # Caller-supplied observed process exit code is distinct from status's
    # expected code. Absence cannot be treated as an observed successful exit.
    if observed_exit_code is not None and expected_exit is not None:
        if observed_exit_code != expected_exit:
            issue(
                "EXIT_MISMATCH",
                "process_exit_code",
                f"observed {observed_exit_code} but {status} expects {expected_exit}",
            )

    if status == "not_implemented" and obj.get("reason_code") != "NOT_IMPLEMENTED":
        issue(
            "NOT_IMPLEMENTED_REASON_MISMATCH",
            "reason_code",
            "R150 not_implemented routes use NOT_IMPLEMENTED",
        )

    action = obj.get("action")
    if isinstance(action, str) and isinstance(status, str):
        authored = {
            name.lower() for name in contract["authored_actions"]
        }
        # Merely copying a plausible v1 envelope must not make a planned
        # Quality/Issue/Delivery/Cycle handler look implemented.
        if action.lower() not in authored and status != "not_implemented":
            issue(
                "UNREGISTERED_ACTION_RESULT", "action",
                "R150 has no handler for this action; status must be not_implemented",
            )

    if isinstance(action, str) and isinstance(obj.get("read_only"), bool):
        if action.lower() == "codesave":
            if obj["read_only"]:
                issue(
                    "WRITING_ACTION_MARKED_READ_ONLY", "read_only",
                    "R150 CodeSave marks its action read_only=false even when denied",
                )
        elif not obj["read_only"]:
            issue(
                "UNDECLARED_WRITING_ACTION", "read_only",
                "R150 only marks CodeSave as potentially writing CES metadata",
            )

    cov = obj.get("coverage")
    reported_true: list[str] = []
    reported_false: list[str] = []
    unknown_coverage: list[str] = []
    if isinstance(cov, dict):
        known = set(contract["coverage"]["fields"])
        for name in contract["coverage"]["fields"]:
            if name not in cov:
                issue("MISSING_COVERAGE_FLAG", f"coverage.{name}",
                      "R150 New-Envelope initializes this flag")
            elif type(cov[name]) is not bool:
                issue("COVERAGE_FLAG_TYPE", f"coverage.{name}",
                      "coverage flags must be JSON booleans, not 0/1/null")
            elif cov[name]:
                reported_true.append(name)
            else:
                reported_false.append(name)
        for name in cov:
            if name not in known:
                unknown_coverage.append(name)
                if type(cov[name]) is not bool:
                    issue("UNKNOWN_COVERAGE_FLAG_TYPE", f"coverage.{name}",
                          "extension coverage flags must still be JSON booleans")
        if unknown_coverage:
            advisories.append(
                "unrecognized coverage flags retained; not used to infer source behavior"
            )

    if isinstance(action, str) and isinstance(cov, dict):
        # These are *internal consistency* checks on the self-reported wire
        # fields, not independently authenticated facts about Git or storage.
        if action.lower() == "inspect" and status == "success":
            for flag in ("repository_checked", "worktree_checked",
                         "stable_root_verified", "head_checked"):
                if cov.get(flag) is not True:
                    issue(
                        "INSPECT_SUCCESS_FLAG_MISSING", f"coverage.{flag}",
                        "R150 Inspect success sets this flag true",
                    )
        if action.lower() == "codesave" and status == "success":
            if cov.get("code_result_persisted") is not True:
                issue(
                    "CODE_SAVE_SUCCESS_FLAG_MISSING",
                    "coverage.code_result_persisted",
                    "R150 CodeSave success sets persistence flag true",
                )
            if not isinstance(obj.get("data"), dict) or obj["data"].get("persisted") is not True:
                issue(
                    "CODE_SAVE_SUCCESS_DATA_MISSING", "data.persisted",
                    "R150 CodeSave success reports persisted=true",
                )
        if (action.lower() == "codesave"
                and obj.get("reason_code") == "CODE_SAVE_AUTHORIZATION_REQUIRED"
                and cov.get("code_result_persisted") is True):
            issue(
                "UNAUTHORIZED_WRITE_CONTRADICTION",
                "coverage.code_result_persisted",
                "authorization denial cannot simultaneously report persistence",
            )
        if (action.lower() == "codeshow" and status in ("success", "partial")
                and isinstance(obj.get("data"), dict)
                and isinstance(obj["data"].get("mode"), str)
                and obj["data"]["mode"].lower() not in {
                    m.lower() for m in contract["authored_codeshow_modes"]
                }):
            issue(
                "UNREGISTERED_CODESHOW_MODE", "data.mode",
                "source CodeShow has no handler for the reported mode",
            )

    if (obj.get("product_version") != contract["source"]["product_version"]
            or obj.get("build") != contract["source"]["build"]):
        advisories.append(
            "the envelope declares another product/build; this R150-derived "
            "contract may require source-specific review"
        )

    # We do not inspect arbitrary nested `data` or `evidence` values. In
    # particular, Sequence k1..56 nested structures must be preserved as-is.
    outcome = statuses.get(status, {}).get("consumer_disposition") if isinstance(status, str) else None
    return {
        "contract_id": contract["contract_id"],
        "wire_schema_version": obj.get("schema_version"),
        "conforms": len(issues) == 0,
        "issues": issues,
        "advisories": advisories,
        "action": action,
        "status": status,
        "reason_code": obj.get("reason_code"),
        "next_step": obj.get("next_step"),
        "consumer_disposition": outcome,
        "expected_process_exit_code": expected_exit,
        "observed_process_exit_code": observed_exit_code,
        "exit_code_observed": observed_exit_code is not None,
        "exit_matches_status": (
            None if observed_exit_code is None or expected_exit is None
            else observed_exit_code == expected_exit
        ),
        "read_only_action_reported": obj.get("read_only"),
        "code_save_write_confirmed": False,  # Parser cannot authenticate a save.
        "data_present": obj.get("data") is not None,
        "warning_count": len(warns) if isinstance(warns, list) else None,
        "evidence_entry_count": (
            len(obj["evidence"]) if isinstance(obj.get("evidence"), list) else None
        ),
        "coverage": {
            "reported_true": reported_true,
            "reported_false_or_not_established": reported_false,
            "unknown_flags": sorted(unknown_coverage),
            "total_known": len(contract["coverage"]["fields"]),
            "flags_are_self_reported_not_independently_verified": True,
            "false_does_not_mean_no_changes_or_a_failed_check": True,
            "all_flags_true_not_required_for_success": True,
        },
        "runtime_or_business_claims_verified": False,
    }


def source_alignment(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only reviewed-current-source & existing coverage initializer check."""
    checks: dict[str, bool] = {}
    problems: list[str] = []
    files = {
        "entry": ROOT / contract["source"]["entry"],
        "registry": ROOT / contract["source"]["action_registry"],
    }
    for key, path in files.items():
        if not path.is_file():
            checks[key + "_sha256"] = False
            problems.append(f"source file missing: {path.relative_to(ROOT)}")
        else:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            expected = contract["source"][key + "_sha256"]
            checks[key + "_sha256"] = digest == expected
            if digest != expected:
                problems.append(f"{key} source changed; contract must be reviewed")

    for relpath, expected in contract["source"]["handler_sha256"].items():
        path = ROOT / relpath
        name = "handler_sha256:" + relpath
        checks[name] = path.is_file() and hashlib.sha256(
            path.read_bytes()
        ).hexdigest() == expected
        if not checks[name]:
            problems.append(f"authored handler changed or missing: {relpath}")

    entry = files["entry"]
    if entry.is_file():
        source_text = entry.read_text(encoding="utf-8-sig")
        try:
            scope = source_text.split("        coverage = [ordered]@{", 1)[1].split(
                "\n        }", 1
            )[0]
            actual_flags = re.findall(
                r"^\s+([a-z][a-z0-9_]+)\s*=\s*\$false\s*$", scope, flags=re.M
            )
        except IndexError:
            actual_flags = []
        checks["coverage_initializer"] = (
            actual_flags == contract["coverage"]["fields"]
        )
        if not checks["coverage_initializer"]:
            problems.append("source coverage initializer differs from contract")
        checks["finish_json_contract"] = all(
            token in source_text for token in [
                "function Finish {",
                "if ($Json) {",
                "ConvertTo-Json -InputObject $Envelope -Depth $jsonDepth -Compress",
                "exit $ExitCode",
                "if ($Action -ieq 'CodeShow' -and $Mode -ieq 'Sequence') { 20 } else { 12 }",
            ]
        )
        if not checks["finish_json_contract"]:
            problems.append("source Finish JSON/text/exit serialization changed")

    return {
        "source_kind": "STATIC_SOURCE_ALIGNMENT_ONLY",
        "aligned": len(checks) >= 4 and all(checks.values()),
        "checks": checks,
        "problems": problems,
        "native_powershell_executed": False,
    }


def _print_output(data: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, ensure_ascii=False, separators=(",", ":")))
        return
    if "consumer_disposition" in data:
        print(
            f"CES {data.get('action')} | {data.get('status')} "
            f"({data.get('reason_code')}) | conforms={data['conforms']}"
        )
        expected = data.get("expected_process_exit_code")
        actual = data.get("observed_process_exit_code")
        print(f"Expected process exit: {expected}; observed: "
              f"{actual if actual is not None else 'NOT_SUPPLIED'}")
        print("Coverage set (self-reported true / known): "
              f"{len(data['coverage']['reported_true'])}/"
              f"{data['coverage']['total_known']} — NOT a completeness score")
        print("Data and evidence have NOT been verified or reprinted.")
        for item in data["issues"]:
            print(f"Contract issue {item['code']} [{item['field']}]: {item['detail']}")
        for advisory in data["advisories"]:
            print(f"Advisory: {advisory}")
    else:
        print(f"R150 source alignment: {data.get('aligned', False)}")
        for problem in data.get("problems", []):
            print(f"Source issue: {problem}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only ces.cli.v1 response consumer (does NOT execute CES)"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="parse and interpret one -Json envelope")
    inspect.add_argument("--input", default="-", metavar="FILE",
                         help="CES stdout capture, or - for stdin")
    inspect.add_argument("--process-exit", type=int, default=None,
                         help="actual pwsh process exit code, if independently captured")
    inspect.add_argument("--max-bytes", type=int, default=DEFAULT_LIMIT_BYTES)
    inspect.add_argument("--json", action="store_true", help="output machine summary")
    check = commands.add_parser("check-source", help="compare contract with R150 source")
    check.add_argument("--json", action="store_true")
    show = commands.add_parser("contract", help="print this consumer's wire contract")
    show.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    try:
        contract = load_contract()
        if args.command == "inspect":
            obj = parse_one_json(read_limited(args.input, args.max_bytes))
            result = evaluate(obj, contract, observed_exit_code=args.process_exit)
            _print_output(result, args.json)
            return 0 if result["conforms"] else 1
        if args.command == "check-source":
            result = source_alignment(contract)
            _print_output(result, args.json)
            return 0 if result["aligned"] else 1
        if args.command == "contract":
            # contract output is declarative, not a recorded native CLI response
            print(json.dumps(contract, ensure_ascii=False,
                             indent=None if args.json else 2))
            return 0
        return 2
    except (ContractError, OSError, KeyError, TypeError) as exc:
        print(f"response-contract error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
