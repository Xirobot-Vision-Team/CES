#!/usr/bin/env python3
"""EC300 offline double-signing ceremony and replay-only gossip verification."""
from __future__ import annotations

import argparse
import hmac
import json

from cryptography.hazmat.primitives import serialization
from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from delivery_anchor import operator as storage
from anchor_lineage import lineage as l
from . import gossip as g


def _build(a: argparse.Namespace) -> dict:
    return g.build_next_claim(
        witness_manifest_file=a.witness_manifest_file,
        a_id=a.expected_a_id, a_public_hex=a.expected_a_public_hex,
        a_tip=a.expected_a_tip,
        b_id=a.expected_b_id, b_public_hex=a.expected_b_public_hex,
        b_tip=a.expected_b_tip,
        sequence=a.sequence,
        independent_challenge_sha256=a.independent_challenge_sha256,
        prior_history_file=a.prior_history_file,
        expected_previous_session_sha256=a.expected_previous_session_sha256)


def _recheck_proposal(args: argparse.Namespace) -> dict:
    l.require(l.absolute_file(args.proposal_file) and
              l.sha_pin(args.expected_proposal_sha256),
              'EC300_EXPLICIT_PRIVATE_PROPOSAL_FILE_AND_EXTERNAL_SHA_REQUIRED',
              'permission_denied')
    doc = io.read_doc(args.proposal_file, g.MAX_PROPOSAL_BYTES)
    l.exact(doc, g.PROPOSAL_FIELDS, 'EC300_PROPOSAL_FIELDS_INVALID')
    l.require(doc['schema'] == g.PROPOSAL_SCHEMA and
              hmac.compare_digest(a.sha(doc), args.expected_proposal_sha256),
              'EC300_PROPOSAL_SHA_MISMATCH', 'permission_denied')
    claim = l.exact(doc['claim'], g.CLAIM_FIELDS, 'EC300_PROPOSAL_CLAIM_FIELDS_INVALID')
    l.require(a.canonical(claim) == a.canonical(_build(args)),
              'EC300_PROPOSAL_NOT_EQUAL_NEW_FULLY_REVERIFIED_SESSION_CLAIM',
              'permission_denied')
    return claim


def prepare(args: argparse.Namespace) -> dict:
    claim = _build(args)
    proposal = {'schema': g.PROPOSAL_SCHEMA, 'claim': claim}
    digest = storage.store(args.out, proposal, g.MAX_PROPOSAL_BYTES)
    return {'schema': 'ces.ec300.offline_session_proposed.v1',
            'status': 'unsigned_bilateral_proposal_not_authenticated',
            'proposal_sha256': digest, 'sequence': claim['sequence'],
            'comparison_status': claim['comparison_status'],
            'both_witness_signatures_present': False,
            'off_host_custody_or_external_challenge_authenticated': False,
            'original_send_or_network_executed': False}


def sign(args: argparse.Namespace) -> dict:
    claim = _recheck_proposal(args)
    role = args.role
    l.require(role in ('a','b'), 'EC300_SIGNER_ROLE_INVALID')
    key = io.private_from_file(args.private_key_file)
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    l.require(hmac.compare_digest(pub, claim[role]['witness_public_hex']),
              'EC300_SIGNER_PRIVATE_KEY_DOES_NOT_MATCH_PINNED_ROLE',
              'permission_denied')
    vote = g.sign_vote(claim, role, key)
    g.verify_vote(vote, claim, role)
    digest = storage.store(args.out, vote, g.MAX_VOTE_BYTES)
    return {'schema': 'ces.ec300.offline_role_vote_signed.v1',
            'status': 'one_offline_role_signed_not_bilaterally_assembled',
            'role': role, 'vote_sha256': digest,
            'claim_sha256': a.sha(claim),
            'comparison_status': claim['comparison_status'],
            'off_host_custody_or_real_org_identity_authenticated': False,
            'original_send_or_network_executed': False}


def assemble(args: argparse.Namespace) -> dict:
    claim = _recheck_proposal(args)
    votes = {}
    for role in ('a','b'):
        file = getattr(args, 'vote_'+role+'_file')
        pin = getattr(args, 'expected_vote_'+role+'_sha256')
        l.require(l.absolute_file(file) and l.sha_pin(pin),
                  'EC300_BOTH_OFFLINE_VOTE_FILES_AND_EXTERNAL_SHAS_REQUIRED',
                  'permission_denied')
        vote = io.read_doc(file, g.MAX_VOTE_BYTES)
        l.require(hmac.compare_digest(a.sha(vote), pin),
                  'EC300_EXPLICIT_VOTE_SHA_MISMATCH', 'permission_denied')
        g.verify_vote(vote, claim, role)
        votes[role] = vote
    session = {'schema':g.SESSION_SCHEMA,'claim':claim,
               'vote_a':votes['a'],'vote_b':votes['b']}
    sha = a.sha(session)
    g.verify_session(session, expected_sha256=sha, rebuilt_claim=claim)
    digest = storage.store(args.out, session, g.MAX_SESSION_BYTES)
    return {'schema': 'ces.ec300.offline_bilateral_session_assembled.v1',
            'status': 'both_ed25519_roles_signed_not_externally_custodied',
            'signed_session_sha256': digest,
            'sequence': claim['sequence'],
            'comparison_status': claim['comparison_status'],
            'comparison_exit_code': claim['comparison_exit_code'],
            'off_host_worm_freshness_or_global_latest_proven': False,
            'original_send_or_network_executed': False}


def verify(*, history_file: str, a_id: str, a_public_hex: str, a_tip: str,
           b_id: str, b_public_hex: str, b_tip: str,
           expected_session_tip: str, out: str | None = None,
           old_report_file: str | None = None,
           expected_report_sha256: str | None = None) -> dict:
    l.require(l.absolute_file(history_file),
              'EC300_ABSOLUTE_GOSSIP_FULL_HISTORY_FILE_REQUIRED')
    historical = None
    if old_report_file is not None or expected_report_sha256 is not None:
        l.require(out is None and l.absolute_file(old_report_file) and
                  l.sha_pin(expected_report_sha256),
                  'EC300_REPORT_REVERIFY_REQUIRES_AN_EXTERNAL_SHA',
                  'permission_denied')
        historical = io.read_doc(old_report_file, g.MAX_REPORT_BYTES)
        l.require(hmac.compare_digest(a.sha(historical), expected_report_sha256),
                  'EC300_REPORT_EXTERNAL_PIN_DOES_NOT_MATCH_FILE',
                  'permission_denied')
    doc = io.read_doc(history_file, g.MAX_HISTORY_BYTES)
    result, _ = g.verify_full_history(doc,
        a_id=a_id, a_public_hex=a_public_hex, a_tip=a_tip,
        b_id=b_id, b_public_hex=b_public_hex, b_tip=b_tip,
        expected_session_tip=expected_session_tip)
    if historical is not None:
        l.require(a.canonical(historical) == a.canonical(result),
                  'EC300_REPORT_NOT_EQUAL_RECOMPUTED_ALL_HISTORICAL_EVIDENCE',
                  'permission_denied')
    if out is not None:
        storage.store(out, result, g.MAX_REPORT_BYTES)
    return result


def _pin_args(p: argparse.ArgumentParser) -> None:
    for flag in ('expected-a-id','expected-a-public-hex','expected-a-tip',
                 'expected-b-id','expected-b-public-hex','expected-b-tip'):
        p.add_argument('--'+flag, required=True)


def _session_args(p: argparse.ArgumentParser) -> None:
    _pin_args(p)
    p.add_argument('--witness-manifest-file', required=True)
    p.add_argument('--sequence', type=int, required=True)
    p.add_argument('--independent-challenge-sha256', required=True)
    p.add_argument('--prior-history-file')
    p.add_argument('--expected-previous-session-sha256')


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='EC300 offline two-key double-signed gossip; not remote transport, WORM or freshness')
    sub = p.add_subparsers(dest='command', required=True)
    prep = sub.add_parser('prepare-session')
    _session_args(prep)
    prep.add_argument('--out', required=True)
    signing = sub.add_parser('sign-session')
    _session_args(signing)
    signing.add_argument('--proposal-file', required=True)
    signing.add_argument('--expected-proposal-sha256', required=True)
    signing.add_argument('--role', choices=('a','b'), required=True)
    signing.add_argument('--private-key-file', required=True)
    signing.add_argument('--out', required=True)
    assembled = sub.add_parser('assemble-session')
    _session_args(assembled)
    assembled.add_argument('--proposal-file', required=True)
    assembled.add_argument('--expected-proposal-sha256', required=True)
    for role in ('a','b'):
        assembled.add_argument('--vote-'+role+'-file', required=True)
        assembled.add_argument('--expected-vote-'+role+'-sha256', required=True)
    assembled.add_argument('--out', required=True)
    for name in ('verify-history','verify-report'):
        check = sub.add_parser(name)
        _pin_args(check)
        check.add_argument('--history-file', required=True)
        check.add_argument('--expected-session-tip', required=True)
        if name == 'verify-history':
            check.add_argument('--out')
        else:
            check.add_argument('--report-file', required=True)
            check.add_argument('--expected-report-sha256', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == 'prepare-session':
            result = prepare(args); rc = 0
        elif args.command == 'sign-session':
            result = sign(args); rc = 0
        elif args.command == 'assemble-session':
            result = assemble(args); rc = 0
        else:
            report = verify(history_file=args.history_file,
                a_id=args.expected_a_id,
                a_public_hex=args.expected_a_public_hex, a_tip=args.expected_a_tip,
                b_id=args.expected_b_id,
                b_public_hex=args.expected_b_public_hex, b_tip=args.expected_b_tip,
                expected_session_tip=args.expected_session_tip,
                out=args.out if args.command == 'verify-history' else None,
                old_report_file=(args.report_file if args.command == 'verify-report' else None),
                expected_report_sha256=(args.expected_report_sha256
                    if args.command == 'verify-report' else None))
            rc = report['exit_code']
            result = {
                'schema': g.RESULT_SCHEMA, 'status': report['status'],
                'exit_code': rc, 'report': report, 'report_sha256': a.sha(report),
                'reverified_against_independently_pinned_report_sha256':
                    args.command == 'verify-report',
                'actual_two_site_worm_or_independent_custodian_proven': False,
                'original_send_or_network_executed': False,
            }
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
        return rc
    except Exception as exc:
        status = exc.status if isinstance(exc, (a.AnchorError, io.HostError)) else 'unavailable'
        reason = exc.code if isinstance(exc, (a.AnchorError, io.HostError)) else 'EC300_GOSSIP_OPERATION_UNAVAILABLE'
        rc = {'permission_denied':3,'invalid_input':4,'unavailable':5}[status]
        print(json.dumps({
            'schema':g.DENIAL_SCHEMA, 'status':status, 'exit_code':rc,
            'reason_code':reason,
            'any_signed_bilateral_session_or_rollback_proof_claimed':False,
            'original_send_or_network_executed':False,
        }, sort_keys=True, separators=(',', ':')))
        return rc


if __name__ == '__main__':
    raise SystemExit(main())
