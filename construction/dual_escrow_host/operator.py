#!/usr/bin/env python3
"""EC275 operator: inspect/reconcile and resume exact two-site EC274 CAS.

Use EC274's verified-tail prepare, independent offline witness signature and
assemble commands to create ONE canonical, SHA-pinned record. Both authorities
consume the SAME bytes; this command never creates witness credentials or
re-signs a failed, possibly partial transaction. No retry with a new record.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from source_provenance_host import provenance as prov
from emergency_recovery_host import recovery as rec
from emergency_recovery_host import serve as old_cli
from remote_escrow_host import escrow as esc
from dual_escrow_host.quorum import DualEscrow, DualEscrowError


def clients(args:argparse.Namespace) -> DualEscrow:
    paths=args.freshness_witness_public
    pins=args.freshness_witness_public_sha256
    if len(paths)!=len(pins):
        raise DualEscrowError('EC275_WITNESS_PATH_SHA_PAIRS_REQUIRED')
    keys=esc.witness_keys(list(zip(paths,pins)))
    params=dict(namespace=args.escrow_namespace,witness_keys_map=keys,
                root=args.root_sha256,closure=args.closure_sha256)
    first=esc.RemoteClient(host=args.escrow_host,port=int(args.escrow_port),
        ca_path=args.escrow_tls_ca,ca_pin=args.escrow_tls_ca_sha256,
        leaf_pin=args.escrow_tls_leaf_sha256,
        escrow_public_path=args.escrow_public,
        escrow_public_pin=args.escrow_public_sha256,**params)
    second=esc.RemoteClient(host=args.secondary_escrow_host,
        port=int(args.secondary_escrow_port),
        ca_path=args.secondary_escrow_tls_ca,
        ca_pin=args.secondary_escrow_tls_ca_sha256,
        leaf_pin=args.secondary_escrow_tls_leaf_sha256,
        escrow_public_path=args.secondary_escrow_public,
        escrow_public_pin=args.secondary_escrow_public_sha256,**params)
    return DualEscrow(first,second)


def _record(args:argparse.Namespace) -> dict:
    raw=prov._bytes(args.record,esc.MAX_RECORD)
    if esc.sha(raw)!=esc._sha(args.record_sha256):
        raise DualEscrowError('EC275_OPERATOR_RECORD_FILE_PIN_MISMATCH')
    return esc._parse(raw,esc.MAX_RECORD,'EC275_OPERATOR_RECORD_NONCANONICAL')


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description='EC275 two independently operated escrows, resumable CAS')
    sub=p.add_subparsers(dest='action',required=True)
    remote=('escrow_host','escrow_port','escrow_namespace','escrow_tls_ca',
            'escrow_tls_ca_sha256','escrow_tls_leaf_sha256','escrow_public',
            'escrow_public_sha256')
    secondary=('secondary_escrow_host','secondary_escrow_port',
        'secondary_escrow_tls_ca','secondary_escrow_tls_ca_sha256',
        'secondary_escrow_tls_leaf_sha256','secondary_escrow_public',
        'secondary_escrow_public_sha256')
    for action in ('inspect-dual','inspect-advance','advance-dual'):
        cmd=sub.add_parser(action)
        old_cli._required(cmd,remote+secondary+('root_sha256','closure_sha256'))
        cmd.add_argument('--freshness-witness-public',action='append',required=True)
        cmd.add_argument('--freshness-witness-public-sha256',action='append',required=True)
        if action=='inspect-dual':
            old_cli._required(cmd,('expected-head-sha256',))
            cmd.add_argument('--minimum-index',type=int,required=True)
        else:
            old_cli._required(cmd,('record','record_sha256','expected_previous_sha256'))
    return p


def main(argv:list[str]|None=None) -> int:
    args=parser().parse_args(argv)
    try:
        duo=clients(args)
        if args.action=='inspect-dual':
            pin=esc._sha(args.expected_head_sha256)
            floor=esc.integer(args.minimum_index,1,esc.MAX_RECORDS,
                              'EC275_OPERATOR_INDEX_FLOOR_INVALID')
            record,head=duo.read_pair(minimum_index=floor)
            if record is None or head!=pin:
                raise DualEscrowError('EC275_DUAL_HEAD_DIFFERS_FROM_OPERATOR_PIN')
            result={'status':'partial','exit_code':2,
                'reason_code':'EC275_TWO_INDEPENDENT_SIGNED_HEAD_READS_MATCH',
                'record_sha256':head,'record_index':record['proposal']['record_index'],
                'both_nonce_bound_signatures_verified':True,
                'physical_independence_verified':False}
        else:
            record=_record(args)
            if args.action=='inspect-advance':
                result=duo.inspect_advance(record,record_sha256=args.record_sha256,
                          previous_sha256=args.expected_previous_sha256)
            else:
                result=duo.advance(record,record_sha256=args.record_sha256,
                          previous_sha256=args.expected_previous_sha256)
        print(json.dumps(result,sort_keys=True))
        return 2
    except (rec.RecoveryError,OSError,ValueError,TypeError) as exc:
        print(json.dumps({'status':'unavailable','exit_code':5,
            'reason_code':getattr(exc,'code','EC275_OPERATOR_UNAVAILABLE')},sort_keys=True))
        return 5


if __name__=='__main__':
    raise SystemExit(main())
