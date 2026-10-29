#!/usr/bin/env python3
"""EC316 offline prepare/sign/assemble/seal and strictly read-only verify.

Only `verify` is allowed through the unified console. Private keys are read
only from 0600 local files by the separate `sign` CLI command.
"""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from . import checkpoint as c


def _trust_args(p: argparse.ArgumentParser) -> None:
    for role in c.ROLES:
        p.add_argument('--custodian-' + role + '-id', required=True)
        p.add_argument('--custodian-' + role + '-public-hex', required=True)


def _ledger_args(p: argparse.ArgumentParser) -> None:
    p.add_argument('--ledger-manifest-file', required=True)
    p.add_argument('--expected-ledger-manifest-sha256', required=True)


def _context_args(p: argparse.ArgumentParser) -> None:
    _ledger_args(p)
    _trust_args(p)
    p.add_argument('--external-unique-challenge-sha256', required=True)
    p.add_argument('--prior-chain-file')
    p.add_argument('--expected-prior-chain-sha256')
    p.add_argument('--expected-prior-certificate-sha256', required=True,
                   help='GENESIS on first EC315 delivery, else offline-frozen prior cert whole SHA')


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=(
        'EC316 dual independent offline custodians attest exact replayed EC315 '
        'signed-source checkpoint, bounded 1..4. No physical CAS or WORM access.'))
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('prepare', 'sign', 'assemble', 'seal-chain'):
        cmd = sub.add_parser(name)
        _context_args(cmd)
        cmd.add_argument('--out', required=True,
                         help='new exclusive 0600 canonical owner-private JSON')
        if name in ('sign', 'assemble'):
            cmd.add_argument('--claim-file', required=True)
            cmd.add_argument('--expected-claim-sha256', required=True)
        if name == 'sign':
            cmd.add_argument('--role', required=True, choices=c.ROLES)
            cmd.add_argument('--private-key-file', required=True,
                             help='0600 32 raw Ed25519 private bytes, never pass key on argv')
        if name == 'assemble':
            cmd.add_argument('--custodian-a-vote-file', required=True)
            cmd.add_argument('--custodian-b-vote-file', required=True)
        if name == 'seal-chain':
            cmd.add_argument('--certificate-file', required=True)
            cmd.add_argument('--expected-certificate-sha256', required=True)
    v = sub.add_parser('verify', help='only permitted unified-console mode; full true original replay')
    _ledger_args(v)
    _trust_args(v)
    v.add_argument('--chain-file', required=True)
    v.add_argument('--expected-chain-sha256', required=True)
    v.add_argument('--expected-latest-certificate-sha256', required=True)
    v.add_argument('--expected-latest-challenge-sha256', required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    trust = {name: getattr(args, name) for name in c.TRUST_FIELDS}
    try:
        if args.command == 'verify':
            result = c.verify(chain_file=args.chain_file,
                expected_chain_sha256=args.expected_chain_sha256,
                ledger_manifest_file=args.ledger_manifest_file,
                expected_ledger_manifest_sha256=args.expected_ledger_manifest_sha256,
                trust=trust,
                expected_latest_certificate_sha256=
                    args.expected_latest_certificate_sha256,
                expected_latest_challenge_sha256=
                    args.expected_latest_challenge_sha256)
        else:
            context = {
                'ledger_manifest_file': args.ledger_manifest_file,
                'expected_ledger_manifest_sha256':
                    args.expected_ledger_manifest_sha256,
                'trust': trust,
                'external_unique_challenge_sha256':
                    args.external_unique_challenge_sha256,
                'prior_chain_file': args.prior_chain_file,
                'expected_prior_chain_sha256': args.expected_prior_chain_sha256,
                'expected_prior_certificate_sha256':
                    args.expected_prior_certificate_sha256,
            }
            if args.command == 'prepare':
                result = c.prepare(**context, out=args.out)
            elif args.command == 'sign':
                result = c.sign(**context, out=args.out,
                    claim_file=args.claim_file,
                    expected_claim_sha256=args.expected_claim_sha256,
                    role=args.role, private_key_file=args.private_key_file)
            elif args.command == 'assemble':
                result = c.assemble(**context, out=args.out,
                    claim_file=args.claim_file,
                    expected_claim_sha256=args.expected_claim_sha256,
                    custodian_a_vote_file=args.custodian_a_vote_file,
                    custodian_b_vote_file=args.custodian_b_vote_file)
            elif args.command == 'seal-chain':
                result = c.seal_chain(**context, out=args.out,
                    certificate_file=args.certificate_file,
                    expected_certificate_sha256=args.expected_certificate_sha256)
            else:
                raise AssertionError('unreachable')
        print(json.dumps({
            'schema': c.RESULT_SCHEMA, 'command': args.command, **result,
            'physical_cas_or_external_global_latest_proven': False,
            'independent_human_control_of_keys_proven': False,
            'external_business_cas_provider_or_worm_write_performed': False,
        }, sort_keys=True, separators=(',', ':')))
        return result['exit_code']
    except Exception as exc:
        status = exc.status if isinstance(exc, (a.AnchorError, io.HostError)) else 'unavailable'
        reason = exc.code if isinstance(exc, (a.AnchorError, io.HostError)) else (
            'EC316_OFFLINE_DUAL_CUSTODIAN_SOURCE_VERIFICATION_UNAVAILABLE')
        rc = {'permission_denied':3, 'invalid_input':4, 'unavailable':5}.get(status,5)
        print(json.dumps({
            'schema': c.DENIAL_SCHEMA, 'command': args.command,
            'status':status, 'reason_code':reason, 'exit_code':rc,
            'complete_replay_or_two_signatures_accepted':False,
            'physical_cas_or_global_latest_proven':False,
            'external_business_cas_provider_or_worm_write_performed':False,
        }, sort_keys=True, separators=(',', ':')))
        return rc
