#!/usr/bin/env python3
"""EC296 two-epoch four-person offline rotation ceremony and verifier.

Every signing step checks complete original EC294/EC295 histories afresh.
File writes are O_EXCL/0600, fsync of file and private parent (EC295 helper).
This CLI never invokes a network service or executes the original sender.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from delivery_anchor import operator as previous
from . import rotation as r


def _data(*, old_policy_file: str, old_policy_sha256: str,
          old_checkpoint_files: list[str], expected_old_tip: str,
          new_policy_file: str, new_policy_sha256: str,
          new_checkpoint_files: list[str], proposed_new_tip: str,
          minimum_fresh_readback_unix: int | None = None) -> tuple[dict,dict,dict]:
    r.require(type(old_checkpoint_files) is list and
              type(new_checkpoint_files) is list and
              1 <= len(old_checkpoint_files) <= a.MAX_CHECKPOINTS and
              1 <= len(new_checkpoint_files) <= a.MAX_CHECKPOINTS,
              'EC296_BOTH_COMPLETE_ORDERED_EPOCH_CHAINS_REQUIRED')
    old = a.load_policy(old_policy_file, old_policy_sha256)
    new = a.load_policy(new_policy_file, new_policy_sha256)
    old_cp = [io.read_doc(path, a.MAX_CHECKPOINT_BYTES)
              for path in old_checkpoint_files]
    new_cp = [io.read_doc(path, a.MAX_CHECKPOINT_BYTES)
              for path in new_checkpoint_files]
    claim = r.claim_from_histories(
        old_policy=old, old_policy_sha=old_policy_sha256,
        old_checkpoints=old_cp, old_expected_tip=expected_old_tip,
        new_policy=new, new_policy_sha=new_policy_sha256,
        new_checkpoints=new_cp, new_proposed_tip=proposed_new_tip,
        minimum_fresh_readback_unix=minimum_fresh_readback_unix)
    return old, new, claim


def prepare(*, out: str, **inputs) -> dict:
    _old, _new, claim = _data(**inputs)
    doc = r.prepare(claim)
    previous.store(out, doc, r.MAX_PREPARED_BYTES)
    return {
        'schema': 'ces.ec296.rotation_prepared_result.v1',
        'status': 'offline_rotation_prepared_only',
        'prepared_sha256': a.sha(doc),
        'old_checkpoint_tip_sha256': claim['old_checkpoint_tip_sha256'],
        'proposed_new_checkpoint_tip_sha256': claim['new_checkpoint_tip_sha256'],
        'four_independent_offline_votes_still_required': True,
        'remote_provider_or_original_send_executed': False,
    }


def offline_vote(*, role: str, prepared_file: str, private_key_file: str,
                 out: str, **inputs) -> dict:
    r.require(role in r.ROLES, 'EC296_SIGNING_ROLE_INVALID')
    old, new, claim = _data(**inputs)
    prepared = io.read_doc(prepared_file, r.MAX_PREPARED_BYTES)
    r.check_prepared(prepared, claim)
    key = io.private_from_file(private_key_file)
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    r.require(public == r.role_pub(role, old, new),
              'EC296_PRIVATE_KEY_NOT_PINNED_TO_SELECTED_OLD_OR_NEW_ROLE',
              'permission_denied')
    signature = r.sign(role, claim, key)
    vote = {'schema': r.VOTE_SCHEMA, 'role': role,
            'prepared_sha256': a.sha(prepared),
            'signature_ed25519': signature}
    previous.store(out, vote, r.MAX_VOTE_BYTES)
    return {
        'schema': 'ces.ec296.rotation_offline_vote_created.v1',
        'role': role, 'prepared_sha256': a.sha(prepared),
        'original_audit_hmac_or_provider_secret_accessed': False,
        'private_key_returned': False,
    }


def assemble(*, prepared_file: str, vote_files: dict[str,str],
             out: str, **inputs) -> dict:
    old, new, claim = _data(**inputs)
    prepared = io.read_doc(prepared_file, r.MAX_PREPARED_BYTES)
    r.check_prepared(prepared, claim)
    r.require(type(vote_files) is dict and set(vote_files) == set(r.ROLES),
              'EC296_FOUR_VOTE_FILES_REQUIRED')
    signs = {}
    for role in r.ROLES:
        vote = io.read_doc(vote_files[role], r.MAX_VOTE_BYTES)
        r.exact(vote, r.VOTE_FIELDS, 'EC296_OFFLINE_VOTE_FIELDS_INVALID')
        r.require(vote['schema'] == r.VOTE_SCHEMA and
                  vote['role'] == role and
                  vote['prepared_sha256'] == a.sha(prepared),
                  'EC296_VOTE_NOT_FOR_EXACT_PREPARED_ROTATION',
                  'permission_denied')
        signature = vote['signature_ed25519']
        r.verify_vote_signature(role, claim, signature,
                                r.role_pub(role, old, new))
        signs[role + '_signature_ed25519'] = signature
    bridge = {'schema': r.BRIDGE_SCHEMA, 'claim': claim, **signs}
    pinned = a.sha(bridge)
    # Verify the complete bridge BEFORE placing any bytes on disk; the SHA
    # here is only a candidate for independent OFF-HOST retention.
    r.verify_bridge(bridge, claim, old, new,
                    externally_pinned_bridge_sha=pinned)
    previous.store(out, bridge, r.MAX_BRIDGE_BYTES)
    return {
        'schema': 'ces.ec296.rotation_bridge_created.v1',
        'rotation_bridge_sha256': pinned,
        'new_checkpoint_tip_sha256': claim['new_checkpoint_tip_sha256'],
        'external_retention_of_old_and_new_tips_and_bridge_required': True,
        'external_immutable_retention_or_real_independent_people_proven': False,
        'remote_provider_or_original_send_executed': False,
    }


def verify(*, bridge_file: str, expected_rotation_sha256: str,
           expected_new_tip: str, **inputs) -> dict:
    # Same exact new tip must be independently re-supplied at verify, not
    # merely read from an untrusted bridge or a local checkpoint file.
    r.require(a.valid_sha(expected_new_tip) and
              expected_new_tip == inputs['proposed_new_tip'],
              'EC296_EXTERNALLY_PINNED_NEW_TIP_REQUIRED',
              'permission_denied')
    old, new, claim = _data(**inputs)
    bridge = io.read_doc(bridge_file, r.MAX_BRIDGE_BYTES)
    return r.verify_bridge(bridge, claim, old, new,
                           externally_pinned_bridge_sha=expected_rotation_sha256)


def _history_flags(parser: argparse.ArgumentParser) -> None:
    for opt in ('old-policy-file', 'old-policy-sha256',
                'new-policy-file', 'new-policy-sha256',
                'expected-old-tip', 'proposed-new-tip'):
        parser.add_argument('--' + opt, required=True)
    parser.add_argument('--old-checkpoint-file', required=True, action='append')
    parser.add_argument('--new-checkpoint-file', required=True, action='append')
    parser.add_argument('--minimum-fresh-readback-unix', type=int)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=(
        'EC296: four independent Ed25519 cross-signatures over two offline '
        'EC295 checkpoint epochs; never sends or reads remote status'))
    sub = root.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare')
    _history_flags(p)
    p.add_argument('--out', required=True)
    for role in r.ROLES:
        p = sub.add_parser('sign-' + role.replace('_', '-') + '-offline')
        _history_flags(p)
        p.add_argument('--prepared-file', required=True)
        p.add_argument('--private-key-file', required=True)
        p.add_argument('--out', required=True)
    p = sub.add_parser('assemble')
    _history_flags(p)
    p.add_argument('--prepared-file', required=True)
    for role in r.ROLES:
        p.add_argument('--' + role.replace('_','-') + '-vote-file',required=True)
    p.add_argument('--out', required=True)
    p = sub.add_parser('verify-rotation')
    _history_flags(p)
    p.add_argument('--bridge-file', required=True)
    p.add_argument('--expected-rotation-sha256', required=True)
    p.add_argument('--expected-new-tip', required=True)
    return root


def _input_args(args: argparse.Namespace) -> dict:
    return dict(
        old_policy_file=args.old_policy_file,
        old_policy_sha256=args.old_policy_sha256,
        old_checkpoint_files=args.old_checkpoint_file,
        expected_old_tip=args.expected_old_tip,
        new_policy_file=args.new_policy_file,
        new_policy_sha256=args.new_policy_sha256,
        new_checkpoint_files=args.new_checkpoint_file,
        proposed_new_tip=args.proposed_new_tip,
        minimum_fresh_readback_unix=args.minimum_fresh_readback_unix,
    )


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        options = _input_args(args)
        if args.command == 'prepare':
            result = prepare(out=args.out, **options)
        elif args.command.startswith('sign-'):
            role = args.command[5:-8].replace('-','_')
            result = offline_vote(role=role,
                   prepared_file=args.prepared_file,
                   private_key_file=args.private_key_file,
                   out=args.out, **options)
        elif args.command == 'assemble':
            votes = {role: getattr(args,role+'_vote_file') for role in r.ROLES}
            result = assemble(prepared_file=args.prepared_file,
                              vote_files=votes, out=args.out, **options)
        elif args.command == 'verify-rotation':
            result = verify(bridge_file=args.bridge_file,
                    expected_rotation_sha256=args.expected_rotation_sha256,
                    expected_new_tip=args.expected_new_tip, **options)
        else:
            raise AssertionError('unhandled rotation command')
        print(json.dumps(result, sort_keys=True, separators=(',',':')))
        return 0
    except Exception as exc:
        status = exc.status if isinstance(exc, a.AnchorError) else 'unavailable'
        reason = exc.code if isinstance(exc, a.AnchorError) else 'EC296_ROTATION_UNAVAILABLE'
        code = {'permission_denied':3, 'invalid_input':4, 'unavailable':5}[status]
        print(json.dumps({
            'schema': r.DENIAL_SCHEMA, 'status': status,
            'exit_code': code, 'reason_code': reason,
            'external_custody_established': False,
            'remote_provider_or_original_send_executed': False,
        }, sort_keys=True, separators=(',',':')))
        return code


if __name__ == '__main__':
    raise SystemExit(main())
