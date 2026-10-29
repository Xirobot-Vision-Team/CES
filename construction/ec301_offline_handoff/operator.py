#!/usr/bin/env python3
"""EC301 local offline offer/sign/countersign ceremony and read-only verifier."""
from __future__ import annotations

import argparse
import hmac
import json

from cryptography.hazmat.primitives import serialization
from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from ec295_delivery_anchor import operator as storage
from ec297_anchor_lineage import lineage as l
from . import handoff as h


def _params(args: argparse.Namespace) -> dict:
    return dict(history_file=args.history_file,
        a_id=args.expected_a_id,a_public_hex=args.expected_a_public_hex,
        a_tip=args.expected_a_tip,
        b_id=args.expected_b_id,b_public_hex=args.expected_b_public_hex,
        b_tip=args.expected_b_tip,session_tip=args.expected_session_tip,
        sequence=args.sequence,sender_role=args.sender_role,
        exchange_challenge_sha256=args.exchange_challenge_sha256,
        prior_journal_file=args.prior_journal_file,
        expected_previous_receipt_sha256=args.expected_previous_receipt_sha256,
        expected_prior_a_tip=args.expected_prior_a_tip,
        expected_prior_b_tip=args.expected_prior_b_tip,
        expected_prior_session_tip=args.expected_prior_session_tip)


def _rebuild(args:argparse.Namespace) -> dict:
    return h.build_next_claim(**_params(args))


def _pinned_doc(path:str,sha:str,limit:int,fields:frozenset[str],schema:str,code:str) -> dict:
    l.require(l.absolute_file(path) and l.sha_pin(sha),
              code+'_PATH_OR_EXTERNAL_SHA_REQUIRED','permission_denied')
    doc=io.read_doc(path,limit)
    l.exact(doc,fields,code+'_FIELDS_INVALID')
    l.require(doc['schema']==schema and h._same(a.sha(doc),sha),
              code+'_SCHEMA_OR_EXTERNAL_SHA_MISMATCH','permission_denied')
    return doc


def _matching_key(path: str,public: str):
    key=io.private_from_file(path)
    local=key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()
    l.require(hmac.compare_digest(local,public),
              'EC301_PRIVATE_KEY_DOES_NOT_MATCH_EXTERNALLY_PINNED_ROLE',
              'permission_denied')
    return key


def prepare(args:argparse.Namespace)->dict:
    claim=_rebuild(args)
    draft={'schema':h.DRAFT_SCHEMA,'claim':claim}
    digest=storage.store(args.out,draft,h.MAX_DRAFT_BYTES)
    return {'schema':'ces.ec301.handoff_proposed.v1',
        'status':'unsigned_offline_handoff_draft','draft_sha256':digest,
        'sequence':claim['sequence'],'sender_role':claim['sender_role'],
        'latest_session_sha256':claim['latest_session_sha256'],
        'historical_comparison_status':claim['historical_comparison_status'],
        'historical_comparison_exit_code':claim['historical_comparison_exit_code'],
        'genuine_cross_site_custody_verified':False,
        'network_or_original_send_executed':False}


def sign_offer(args:argparse.Namespace)->dict:
    claim=_rebuild(args)
    doc=_pinned_doc(args.draft_file,args.expected_draft_sha256,h.MAX_DRAFT_BYTES,
                    h.DRAFT_FIELDS,h.DRAFT_SCHEMA,'EC301_DRAFT')
    l.exact(doc['claim'],h.CLAIM_FIELDS,'EC301_DRAFT_CLAIM_FIELDS_INVALID')
    l.require(a.canonical(doc['claim'])==a.canonical(claim),
              'EC301_DRAFT_NOT_EQUAL_FULL_REVERIFIED_PARENT_HISTORY',
              'permission_denied')
    key=_matching_key(args.private_key_file,
                      claim[claim['sender_role']]['witness_public_hex'])
    offer=h.make_offer(claim,key)
    h.verify_offer(offer,claim)
    digest=storage.store(args.out,offer,h.MAX_OFFER_BYTES)
    return {'schema':'ces.ec301.handoff_offer_signed.v1',
        'status':'sender_signed_offer_not_yet_recipient_acknowledged',
        'signed_offer_sha256':digest, 'sender_role':claim['sender_role'],
        'recipient_role':claim['recipient_role'],
        'historical_comparison_status':claim['historical_comparison_status'],
        'historical_comparison_exit_code':claim['historical_comparison_exit_code'],
        'actual_remote_delivery_proven':False,
        'network_or_original_send_executed':False}


def accept_offer(args:argparse.Namespace)->dict:
    claim=_rebuild(args)
    offer=_pinned_doc(args.offer_file,args.expected_offer_sha256,h.MAX_OFFER_BYTES,
                      h.OFFER_FIELDS,h.OFFER_SCHEMA,'EC301_OFFER')
    h.verify_offer(offer,claim)
    key=_matching_key(args.private_key_file,
                      claim[claim['recipient_role']]['witness_public_hex'])
    receipt=h.make_receipt(offer,key)
    digest=a.sha(receipt)
    h.verify_receipt(receipt,rebuilt_claim=claim,expected_receipt_sha256=digest)
    actual=storage.store(args.out,receipt,h.MAX_RECEIPT_BYTES)
    return {'schema':'ces.ec301.handoff_offer_acknowledged.v1',
        'status':'both_role_keys_signed_same_offline_offer',
        'signed_receipt_sha256':actual,
        'signed_offer_sha256':a.sha(offer),
        'sender_role':claim['sender_role'],'recipient_role':claim['recipient_role'],
        'historical_comparison_status':claim['historical_comparison_status'],
        'historical_comparison_exit_code':claim['historical_comparison_exit_code'],
        'actual_separate_device_transport_or_external_worm_verified':False,
        'network_or_original_send_executed':False}


def verify(*,journal_file:str,a_id:str,a_public_hex:str,a_tip:str,
           b_id:str,b_public_hex:str,b_tip:str,session_tip:str,receipt_tip:str,
           out:str|None=None,old_report_file:str|None=None,
           expected_report_sha256:str|None=None)->dict:
    l.require(l.absolute_file(journal_file),'EC301_ABSOLUTE_JOURNAL_REQUIRED')
    historical=None
    if old_report_file is not None or expected_report_sha256 is not None:
        l.require(out is None and l.absolute_file(old_report_file) and
                  l.sha_pin(expected_report_sha256),
                  'EC301_INDEPENDENT_PINNED_REPORT_FILE_REQUIRED',
                  'permission_denied')
        historical=io.read_doc(old_report_file,h.MAX_REPORT_BYTES)
        l.require(h._same(a.sha(historical),expected_report_sha256),
                  'EC301_REPORT_EXTERNAL_SHA_MISMATCH','permission_denied')
    doc=io.read_doc(journal_file,h.MAX_JOURNAL_BYTES)
    result,_=h.verify_journal(doc,a_id=a_id,a_public_hex=a_public_hex,
        a_tip=a_tip,b_id=b_id,b_public_hex=b_public_hex,b_tip=b_tip,
        session_tip=session_tip,receipt_tip=receipt_tip)
    if historical is not None:
        l.require(a.canonical(result)==a.canonical(historical),
                  'EC301_REPORT_NOT_EQUAL_RECOMPUTED_HISTORICAL_SOURCE',
                  'permission_denied')
    if out is not None:
        storage.store(out,result,h.MAX_REPORT_BYTES)
    return result


def _pins(p:argparse.ArgumentParser)->None:
    for f in ('expected-a-id','expected-a-public-hex','expected-a-tip',
              'expected-b-id','expected-b-public-hex','expected-b-tip',
              'expected-session-tip'):
        p.add_argument('--'+f,required=True)


def _new_args(p:argparse.ArgumentParser)->None:
    _pins(p)
    p.add_argument('--history-file',required=True)
    p.add_argument('--sequence',type=int,required=True)
    p.add_argument('--sender-role',choices=('a','b'),required=True)
    p.add_argument('--exchange-challenge-sha256',required=True)
    for f in ('prior-journal-file','expected-previous-receipt-sha256',
              'expected-prior-a-tip','expected-prior-b-tip',
              'expected-prior-session-tip'):
        p.add_argument('--'+f)


def parser()->argparse.ArgumentParser:
    p=argparse.ArgumentParser(description='EC301 offline sender offer and separate recipient acknowledgement; no network or independent-custody proof')
    subs=p.add_subparsers(dest='command',required=True)
    draft=subs.add_parser('prepare-offer');_new_args(draft)
    draft.add_argument('--out',required=True)
    sign=subs.add_parser('sign-offer');_new_args(sign)
    sign.add_argument('--draft-file',required=True)
    sign.add_argument('--expected-draft-sha256',required=True)
    sign.add_argument('--private-key-file',required=True)
    sign.add_argument('--out',required=True)
    accept=subs.add_parser('accept-offer');_new_args(accept)
    accept.add_argument('--offer-file',required=True)
    accept.add_argument('--expected-offer-sha256',required=True)
    accept.add_argument('--private-key-file',required=True)
    accept.add_argument('--out',required=True)
    for name in ('verify-journal','verify-report'):
        verify=subs.add_parser(name);_pins(verify)
        verify.add_argument('--journal-file',required=True)
        verify.add_argument('--expected-receipt-tip',required=True)
        if name=='verify-journal': verify.add_argument('--out')
        else:
            verify.add_argument('--report-file',required=True)
            verify.add_argument('--expected-report-sha256',required=True)
    return p


def main(argv:list[str]|None=None)->int:
    args=parser().parse_args(argv)
    try:
        if args.command=='prepare-offer':
            result=prepare(args);rc=0
        elif args.command=='sign-offer':
            result=sign_offer(args);rc=0
        elif args.command=='accept-offer':
            result=accept_offer(args);rc=0
        else:
            report=verify(journal_file=args.journal_file,
                 a_id=args.expected_a_id,a_public_hex=args.expected_a_public_hex,
                 a_tip=args.expected_a_tip,b_id=args.expected_b_id,
                 b_public_hex=args.expected_b_public_hex,b_tip=args.expected_b_tip,
                 session_tip=args.expected_session_tip,
                 receipt_tip=args.expected_receipt_tip,
                 out=args.out if args.command=='verify-journal' else None,
                 old_report_file=args.report_file if args.command=='verify-report' else None,
                 expected_report_sha256=args.expected_report_sha256
                    if args.command=='verify-report' else None)
            rc=report['exit_code']
            result={'schema':h.RESULT_SCHEMA,'status':report['status'],
                'exit_code':rc,'report':report,'report_sha256':a.sha(report),
                'report_reverified_against_independent_sha':args.command=='verify-report',
                'real_off_host_custody_or_actual_network_transport_proven':False,
                'original_provider_inbox_or_send_executed':False}
        print(json.dumps(result,sort_keys=True,separators=(',',':')))
        return rc
    except Exception as exc:
        status=exc.status if isinstance(exc,(a.AnchorError,io.HostError)) else 'unavailable'
        reason=exc.code if isinstance(exc,(a.AnchorError,io.HostError)) else 'EC301_HANDOFF_OPERATION_UNAVAILABLE'
        rc={'permission_denied':3,'invalid_input':4,'unavailable':5}.get(status,5)
        print(json.dumps({'schema':h.DENIAL_SCHEMA,'status':status,
            'reason_code':reason,'exit_code':rc,
            'any_authenticated_cross_site_delivery_or_rollback_claimed':False,
            'original_provider_inbox_or_send_executed':False},
            sort_keys=True,separators=(',',':')))
        return rc


if __name__=='__main__':raise SystemExit(main())
