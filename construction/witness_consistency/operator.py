#!/usr/bin/env python3
"""EC299 private offline witness ceremony and two-witness read-only comparison.

Preparation and signing are intentionally independent commands: the signing
side must supply and cryptographically replay the signed original audit lane.
The compare side never loads private keys or accesses network/business Hosts.
"""
from __future__ import annotations

import argparse
import hmac
import json

from cryptography.hazmat.primitives import serialization
from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from delivery_anchor import operator as storage
from anchor_lineage import lineage as l
from anchor_conflicts import conflicts as c
from . import witness as w


def _parent(*, witness_id: str, public_hex: str, sequence: int,
            previous_receipt_file: str | None,
            expected_previous_receipt_sha256: str | None) -> str:
    if sequence == 1:
        l.require(previous_receipt_file is None and
                  expected_previous_receipt_sha256 is None,
                  'EC299_GENESIS_OBSERVATION_MUST_NOT_DECLARE_PREDECESSOR')
        return a.GENESIS
    l.require(type(sequence) is int and 2 <= sequence <= w.MAX_OBSERVATIONS and
              l.absolute_file(previous_receipt_file) and
              l.sha_pin(expected_previous_receipt_sha256),
              'EC299_NON_GENESIS_REQUIRES_EXTERNALLY_PINNED_PREVIOUS_RECEIPT',
              'permission_denied')
    old = io.read_doc(previous_receipt_file, w.MAX_RECEIPT_BYTES)
    prev = w.verify_receipt(old, expected_witness_id=witness_id,
                             expected_public_hex=public_hex)
    l.require(hmac.compare_digest(a.sha(old), expected_previous_receipt_sha256) and
              prev['sequence'] == sequence - 1,
              'EC299_PREVIOUS_RECEIPT_SIGNATURE_SEQUENCE_OR_TIP_MISMATCH',
              'permission_denied')
    return a.sha(old)


def _claim(*, witness_id: str, witness_public_hex: str, sequence: int,
           previous_receipt_file: str | None,
           expected_previous_receipt_sha256: str | None,
           lane: dict, previous_lane: dict | None = None) -> dict:
    prior = _parent(witness_id=witness_id, public_hex=witness_public_hex,
                    sequence=sequence,
                    previous_receipt_file=previous_receipt_file,
                    expected_previous_receipt_sha256=expected_previous_receipt_sha256)
    claim, commit, snaps = w.verified_claim_from_lane(lane,
        witness_id=witness_id, public_hex=witness_public_hex,
        sequence=sequence, previous_digest=prior)
    if sequence > 1:
        l.require(type(previous_lane) is dict and set(previous_lane) == c.LANE_KEYS,
                  'EC299_PREVIOUS_FULL_SIGNED_EVIDENCE_REQUIRED_FOR_NEW_SIGNATURE',
                  'permission_denied')
        old = io.read_doc(previous_receipt_file, w.MAX_RECEIPT_BYTES)
        previous_claim = old['claim']
        previous_rebuilt, previous_commit, previous_snap = w.verified_claim_from_lane(
            previous_lane, witness_id=witness_id, public_hex=witness_public_hex,
            sequence=sequence - 1,
            previous_digest=previous_claim['previous_observation_sha256'])
        l.require(previous_claim == previous_rebuilt,
                  'EC299_PREVIOUS_SIGNED_OBSERVATION_NOT_MATCH_FULL_ORIGINAL_PROOFS',
                  'permission_denied')
        relation, _ = w.relationship((previous_commit, previous_snap),
                                      (commit, snaps))
        l.require(relation == 'a_signed_checkpoint_ancestor_of_b',
                  'EC299_OPERATOR_CANNOT_SIGN_NONMONOTONIC_OBSERVATION_HISTORY',
                  'permission_denied')
    else:
        l.require(previous_lane is None,
                  'EC299_GENESIS_MUST_NOT_IMPORT_PREVIOUS_LANE')
    return claim


def prepare(*, witness_id: str, witness_public_hex: str, sequence: int,
            previous_receipt_file: str | None,
            expected_previous_receipt_sha256: str | None,
            lane: dict, out: str, previous_lane: dict | None = None) -> dict:
    claim = _claim(witness_id=witness_id,
                   witness_public_hex=witness_public_hex,
                   sequence=sequence,
                   previous_receipt_file=previous_receipt_file,
                   expected_previous_receipt_sha256=expected_previous_receipt_sha256,
                   lane=lane, previous_lane=previous_lane)
    draft = {'schema': w.DRAFT_SCHEMA, 'claim': claim}
    digest = storage.store(out, draft, w.MAX_RECEIPT_BYTES)
    return {
        'schema': 'ces.ec299.observation_draft_proposed.v1',
        'status': 'offline_observation_unsigned_draft',
        'draft_sha256': digest, 'sequence': sequence,
        'lineage_commitment_sha256': claim['lineage_commitment_sha256'],
        'external_observation_tip_saved_or_authority_authenticated': False,
        'original_host_send_or_network_executed': False,
    }


def sign_observation(*, draft_file: str,
                     expected_draft_sha256: str, private_key_file: str,
                     previous_receipt_file: str | None,
                     expected_previous_receipt_sha256: str | None,
                     lane: dict, out: str, previous_lane: dict | None = None) -> dict:
    l.require(l.absolute_file(draft_file) and l.sha_pin(expected_draft_sha256),
              'EC299_SIGNING_REQUIRES_EXTERNALLY_PINNED_DRAFT_SHA',
              'permission_denied')
    draft = io.read_doc(draft_file, w.MAX_RECEIPT_BYTES)
    l.exact(draft, w.DRAFT_KEYS, 'EC299_DRAFT_FIELDS_INVALID')
    l.require(draft['schema'] == w.DRAFT_SCHEMA and
              hmac.compare_digest(a.sha(draft), expected_draft_sha256),
              'EC299_DRAFT_SHA_OR_SCHEMA_CHANGED', 'permission_denied')
    claim = l.exact(draft['claim'], w.CLAIM_KEYS, 'EC299_DRAFT_CLAIM_INVALID')
    rebuilt = _claim(witness_id=claim['witness_id'],
        witness_public_hex=claim['witness_public_hex'],
        sequence=claim['sequence'], previous_receipt_file=previous_receipt_file,
        expected_previous_receipt_sha256=expected_previous_receipt_sha256,
        lane=lane, previous_lane=previous_lane)
    l.require(claim == rebuilt,
              'EC299_OFFLINE_SIGNATURE_DRAFT_NOT_MATCH_CURRENT_FULLY_REVERIFIED_EVIDENCE',
              'permission_denied')
    key = io.private_from_file(private_key_file)
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    l.require(hmac.compare_digest(pub, claim['witness_public_hex']),
              'EC299_PRIVATE_KEY_NOT_EXTERNALLY_PINNED_WITNESS',
              'permission_denied')
    receipt = {'schema': w.RECEIPT_SCHEMA, 'claim': claim,
               'signature_ed25519': w.sign_claim(claim, key)}
    w.verify_receipt(receipt, expected_witness_id=claim['witness_id'],
                     expected_public_hex=pub)
    digest = storage.store(out, receipt, w.MAX_RECEIPT_BYTES)
    return {
        'schema': 'ces.ec299.observation_signed_offline.v1',
        'status': 'signed_observation_not_externally_retained',
        'signed_observation_sha256': digest,
        'witness_public_hex': pub, 'sequence': claim['sequence'],
        'real_organization_independence_or_external_pin_saved': False,
        'original_host_send_or_network_executed': False,
    }


def compare(*, manifest_file: str, a_id: str, a_public_hex: str,
            a_tip: str, b_id: str, b_public_hex: str, b_tip: str,
            out: str | None = None, report_file: str | None = None,
            expected_report_sha256: str | None = None) -> dict:
    l.require(l.absolute_file(manifest_file),
              'EC299_ABSOLUTE_OBSERVATION_MANIFEST_REQUIRED')
    if report_file is not None or expected_report_sha256 is not None:
        l.require(out is None and l.absolute_file(report_file) and
                  l.sha_pin(expected_report_sha256),
                  'EC299_REVERIFY_REPORT_REQUIRES_EXPLICIT_EXTERNAL_SHA',
                  'permission_denied')
        historical = io.read_doc(report_file, w.MAX_REPORT_BYTES)
        l.require(hmac.compare_digest(a.sha(historical), expected_report_sha256),
                  'EC299_INDEPENDENT_REPORT_SHA_MISMATCH', 'permission_denied')
    else:
        historical = None
    manifest = io.read_doc(manifest_file, w.MAX_MANIFEST_BYTES)
    report = w.compare_witnesses(manifest=manifest,
        a_id=a_id, a_public_hex=a_public_hex, a_tip=a_tip,
        b_id=b_id, b_public_hex=b_public_hex, b_tip=b_tip)
    if historical is not None:
        l.require(historical == report,
                  'EC299_REPORT_NOT_IDENTICAL_TO_REVERIFIED_WITNESS_LOGS',
                  'permission_denied')
    if out is not None:
        storage.store(out, report, w.MAX_REPORT_BYTES)
    return report


def _lane_args(cmd: argparse.ArgumentParser) -> None:
    for flag in ('inputs-file', 'commitment-file',
                 'expected-commitment-sha256', 'expected-root-tip',
                 'expected-latest-tip', 'expected-latest-bridge-sha256'):
        cmd.add_argument('--' + flag, required=True)


def _previous_lane_args(cmd: argparse.ArgumentParser) -> None:
    for flag in ('inputs-file', 'commitment-file',
                 'expected-commitment-sha256', 'expected-root-tip',
                 'expected-latest-tip', 'expected-latest-bridge-sha256'):
        cmd.add_argument('--previous-' + flag)


def _witness_args(cmd: argparse.ArgumentParser) -> None:
    for flag in ('witness-id', 'witness-public-hex'):
        cmd.add_argument('--' + flag, required=True)
    cmd.add_argument('--sequence', type=int, required=True)
    cmd.add_argument('--previous-receipt-file')
    cmd.add_argument('--expected-previous-receipt-sha256')


def _compare_args(cmd: argparse.ArgumentParser) -> None:
    for flag in ('manifest-file', 'expected-a-id', 'expected-a-public-hex',
                 'expected-a-tip', 'expected-b-id', 'expected-b-public-hex',
                 'expected-b-tip'):
        cmd.add_argument('--' + flag, required=True)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='EC299: offline two-witness signed observation consistency, not WORM or global latest authority')
    subs = p.add_subparsers(dest='command', required=True)
    draft = subs.add_parser('prepare-observation')
    _witness_args(draft)
    _lane_args(draft)
    _previous_lane_args(draft)
    draft.add_argument('--out', required=True)
    sign = subs.add_parser('sign-observation')
    _lane_args(sign)
    _previous_lane_args(sign)
    sign.add_argument('--draft-file', required=True)
    sign.add_argument('--expected-draft-sha256', required=True)
    sign.add_argument('--private-key-file', required=True)
    sign.add_argument('--previous-receipt-file')
    sign.add_argument('--expected-previous-receipt-sha256')
    sign.add_argument('--out', required=True)
    compare_cmd = subs.add_parser('compare-witnesses')
    _compare_args(compare_cmd)
    compare_cmd.add_argument('--out', help='optional private digest-only proposal; exclusive')
    recheck = subs.add_parser('verify-report')
    _compare_args(recheck)
    recheck.add_argument('--report-file', required=True)
    recheck.add_argument('--expected-report-sha256', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        cmd = args.command
        if cmd in ('prepare-observation', 'sign-observation'):
            lane = {k: getattr(args, k) for k in c.LANE_KEYS}
            prev = {k: getattr(args, 'previous_'+k) for k in c.LANE_KEYS}
            prev_lane = prev if any(v is not None for v in prev.values()) else None
            if prev_lane is not None:
                l.require(all(v is not None for v in prev.values()),
                    'EC299_ALL_SIX_PREVIOUS_EC297_INPUT_FIELDS_REQUIRED')
            if cmd == 'prepare-observation':
                result = prepare(witness_id=args.witness_id,
                    witness_public_hex=args.witness_public_hex,
                    sequence=args.sequence,
                    previous_receipt_file=args.previous_receipt_file,
                    expected_previous_receipt_sha256=args.expected_previous_receipt_sha256,
                    lane=lane, previous_lane=prev_lane, out=args.out)
            else:
                result = sign_observation(draft_file=args.draft_file,
                    expected_draft_sha256=args.expected_draft_sha256,
                    private_key_file=args.private_key_file,
                    previous_receipt_file=args.previous_receipt_file,
                    expected_previous_receipt_sha256=args.expected_previous_receipt_sha256,
                    lane=lane, previous_lane=prev_lane, out=args.out)
            rc = 0
        else:
            report = compare(manifest_file=args.manifest_file,
                a_id=args.expected_a_id, a_public_hex=args.expected_a_public_hex,
                a_tip=args.expected_a_tip, b_id=args.expected_b_id,
                b_public_hex=args.expected_b_public_hex,
                b_tip=args.expected_b_tip,
                out=args.out if cmd == 'compare-witnesses' else None,
                report_file=args.report_file if cmd == 'verify-report' else None,
                expected_report_sha256=(args.expected_report_sha256
                    if cmd == 'verify-report' else None))
            rc = report['exit_code']
            result = {
                'schema': w.RESULT_SCHEMA, 'status': report['status'],
                'exit_code': rc, 'report_sha256': a.sha(report),
                'report': report,
                'report_reverified_against_explicit_external_sha': cmd == 'verify-report',
                'real_independent_off_host_witness_custody_proven': False,
                'production_send_or_network_executed': False,
            }
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
        return rc
    except Exception as exc:
        status = exc.status if isinstance(exc, (a.AnchorError, io.HostError)) else 'unavailable'
        reason = exc.code if isinstance(exc, (a.AnchorError, io.HostError)) else 'EC299_OFFLINE_WITNESS_OPERATION_UNAVAILABLE'
        rc = {'permission_denied': 3, 'invalid_input': 4, 'unavailable': 5}[status]
        print(json.dumps({
            'schema': w.DENIAL_SCHEMA, 'status': status,
            'exit_code': rc, 'reason_code': reason,
            'any_witness_log_consistency_or_external_custody_claimed': False,
            'production_send_or_network_executed': False,
        }, sort_keys=True, separators=(',', ':')))
        return rc


if __name__ == '__main__':
    raise SystemExit(main())
