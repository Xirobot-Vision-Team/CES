#!/usr/bin/env python3
"""EC297 CLI: portable multi-hop EC296 rotation lineage; no external I/O.

Propose is a local verified DRAFT for separate external custody. Verify always
requires multiple independently sourced digest arguments and revalidates every
original EC294/EC295 receipt + four EC296 signatures from scratch.
"""
from __future__ import annotations

import argparse
import json

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from ec295_delivery_anchor import operator as storage
from . import lineage as l


def propose(*, inputs_file: str, out: str) -> dict:
    spec = io.read_doc(inputs_file, l.MAX_INPUT_BYTES)
    doc = l.build_commitment(spec)
    storage.store(out, doc, l.MAX_COMMITMENT_BYTES)
    return {
        'schema': 'ces.ec297.lineage_commitment_proposed.v1',
        'status': 'untrusted_offline_lineage_proposal_only',
        'lineage_commitment_sha256': a.sha(doc),
        'epoch_count': doc['epoch_count'],
        'rotation_count': doc['bridge_count'],
        'root_checkpoint_tip_sha256': doc['root_checkpoint_tip_sha256'],
        'latest_checkpoint_tip_sha256': doc['latest_checkpoint_tip_sha256'],
        'latest_rotation_bridge_sha256': doc['latest_rotation_bridge_sha256'],
        'independent_off_host_retention_performed': False,
        'final_antirollback_verification_performed': False,
        'new_provider_query_or_original_send_executed': False,
    }


def verify(*, inputs_file: str, commitment_file: str,
           expected_commitment_sha256: str, expected_root_tip: str,
           expected_latest_tip: str,
           expected_latest_bridge_sha256: str) -> dict:
    l.require(all(l.sha_pin(v) for v in (
        expected_commitment_sha256, expected_root_tip, expected_latest_tip,
        expected_latest_bridge_sha256)),
        'EC297_FOUR_INDEPENDENT_EXTERNAL_DIGEST_INPUTS_REQUIRED',
        'permission_denied')
    candidate = io.read_doc(commitment_file, l.MAX_COMMITMENT_BYTES)
    l.require(a.sha(candidate) == expected_commitment_sha256,
              'EC297_EXTERNAL_LINEAGE_COMMITMENT_SHA_MISMATCH_OR_ROLLBACK',
              'permission_denied')
    spec = io.read_doc(inputs_file, l.MAX_INPUT_BYTES)
    computed = l.build_commitment(spec)
    return l.check_commitment(
        candidate, computed,
        expected_commitment_sha256=expected_commitment_sha256,
        expected_root_tip=expected_root_tip,
        expected_latest_tip=expected_latest_tip,
        expected_latest_bridge_sha256=expected_latest_bridge_sha256)


def parser() -> argparse.ArgumentParser:
    app = argparse.ArgumentParser(
        description='EC297: offline multi-epoch EC295/EC296 full-history verifier; '
                    'not an immutable external pin store or a production sender')
    sub = app.add_subparsers(dest='command', required=True)
    p = sub.add_parser('propose-lineage', help='produce untrusted portable commitment draft')
    p.add_argument('--inputs-file', required=True)
    p.add_argument('--out', required=True)
    p = sub.add_parser('verify-lineage', help='check original proofs against explicit external pins')
    p.add_argument('--inputs-file', required=True)
    p.add_argument('--commitment-file', required=True)
    p.add_argument('--expected-commitment-sha256', required=True)
    p.add_argument('--expected-root-tip', required=True)
    p.add_argument('--expected-latest-tip', required=True)
    p.add_argument('--expected-latest-bridge-sha256', required=True)
    return app


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == 'propose-lineage':
            result = propose(inputs_file=args.inputs_file, out=args.out)
        elif args.command == 'verify-lineage':
            result = verify(
                inputs_file=args.inputs_file,
                commitment_file=args.commitment_file,
                expected_commitment_sha256=args.expected_commitment_sha256,
                expected_root_tip=args.expected_root_tip,
                expected_latest_tip=args.expected_latest_tip,
                expected_latest_bridge_sha256=args.expected_latest_bridge_sha256)
        else:
            raise AssertionError('unknown action')
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
        return 0
    except Exception as exc:
        status = exc.status if isinstance(exc, a.AnchorError) else 'unavailable'
        reason = exc.code if isinstance(exc, a.AnchorError) else 'EC297_OFFLINE_LINEAGE_UNAVAILABLE'
        code = {'permission_denied':3,'invalid_input':4,'unavailable':5}[status]
        print(json.dumps({
            'schema': l.DENIAL_SCHEMA,
            'status': status, 'exit_code': code, 'reason_code': reason,
            'independent_external_custody_established': False,
            'production_delivery_or_original_audit_write_executed': False,
        }, sort_keys=True, separators=(',', ':')))
        return code


if __name__ == '__main__':
    raise SystemExit(main())
