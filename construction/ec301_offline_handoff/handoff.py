#!/usr/bin/env python3
"""EC301: cryptographic offline offer/acknowledgement and replayable custody journal.

Transport is deliberately OUT of scope. Sender and receiver independently
reverify the full original EC300 history at their respective file locations.
A sender signs an offer; the opposite key signs *those exact offer bytes* as an
acknowledgement. Success proves key signatures, NOT people, receipt delivery,
trusted site isolation, clock time, or existence of an append-only external store.

Each later transfer is predicated on a complete, pinned, older receipt journal
and a *strictly extended* signed EC300 session history. Source data is never
inferred to be trustworthy solely from a submitted offer or its signature.
"""
from __future__ import annotations

import hmac
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from ec297_anchor_lineage import lineage as l
from ec300_bilateral_gossip import gossip as g

DOMAIN = b'CES/EC301/DeliveryAudit/OfflineSenderReceiverHandoff/v1\0'
CLAIM_SCHEMA = 'ces.ec301.offline_handoff_claim.v1'
DRAFT_SCHEMA = 'ces.ec301.offline_handoff_draft.v1'
OFFER_SCHEMA = 'ces.ec301.signed_offline_handoff_offer.v1'
RECEIPT_SCHEMA = 'ces.ec301.bilaterally_signed_offline_handoff_receipt.v1'
JOURNAL_SCHEMA = 'ces.ec301.complete_offline_handoff_receipt_journal.v1'
REPORT_SCHEMA = 'ces.ec301.offline_handoff_journal_report.v1'
RESULT_SCHEMA = 'ces.ec301.offline_handoff_verification_result.v1'
DENIAL_SCHEMA = 'ces.ec301.offline_handoff_denial.v1'
MAX_EXCHANGES = 8
MAX_DRAFT_BYTES = 9_000
MAX_OFFER_BYTES = 10_000
MAX_RECEIPT_BYTES = 11_000
MAX_JOURNAL_BYTES = 100_000
MAX_REPORT_BYTES = 45_000
WITNESS_FIELDS = frozenset({'witness_id','witness_public_hex',
                            'latest_observation_sha256',
                            'signed_observation_sha256_chain'})
CLAIM_FIELDS = frozenset({
    'schema', 'sequence', 'previous_receipt_sha256',
    'independent_exchange_challenge_sha256', 'sender_role', 'recipient_role',
    'original_audit_identity', 'a', 'b', 'full_signed_session_sha256_chain',
    'latest_session_sha256', 'verified_ec300_report_sha256',
    'historical_comparison_status', 'historical_comparison_exit_code',
})
DRAFT_FIELDS = frozenset({'schema','claim'})
OFFER_FIELDS = frozenset({'schema','claim','sender_signature_ed25519'})
RECEIPT_FIELDS = frozenset({'schema','offer','recipient_signature_ed25519'})
JOURNAL_FIELDS = frozenset({'schema','a_id','a_public_hex','b_id','b_public_hex','entries'})
ENTRY_FIELDS = frozenset({'signed_receipt_file','expected_receipt_sha256',
                          'ec300_history_file','expected_a_tip',
                          'expected_b_tip','expected_session_tip'})


def _same(a1: Any, b1: Any) -> bool:
    return type(a1) is str and type(b1) is str and hmac.compare_digest(a1,b1)


def _ids(a_id: str, a_public_hex: str, b_id: str, b_public_hex: str) -> None:
    g.check_identities(a_id,a_public_hex,b_id,b_public_hex)


def _verified_parent(history_file: str, *, a_id: str, a_public_hex: str,
                     a_tip: str, b_id: str, b_public_hex: str,
                     b_tip: str, session_tip: str) -> dict:
    l.require(l.absolute_file(history_file) and l.sha_pin(session_tip),
              'EC301_COMPLETE_EC300_HISTORY_AND_EXTERNAL_SESSION_TIP_REQUIRED',
              'permission_denied')
    history = io.read_doc(history_file,g.MAX_HISTORY_BYTES)
    report, _ = g.verify_full_history(history, a_id=a_id,
        a_public_hex=a_public_hex, a_tip=a_tip, b_id=b_id,
        b_public_hex=b_public_hex, b_tip=b_tip,
        expected_session_tip=session_tip)
    return report


def _witness(report: dict, role: str) -> dict:
    witness=report['witness_'+role]
    return {
        'witness_id': witness['witness_id'],
        'witness_public_hex': witness['witness_public_hex'],
        'latest_observation_sha256': witness['externally_pinned_latest_observation_sha256'],
        'signed_observation_sha256_chain': list(witness['verified_observation_receipt_sha256_chain']),
    }


def claim_from_report(report: dict, *, sequence: int,
                      previous_receipt_sha256: str,
                      independent_exchange_challenge_sha256: str,
                      sender_role: str) -> dict:
    l.require(type(sequence) is int and 1 <= sequence <= MAX_EXCHANGES and
              a.valid_sha(previous_receipt_sha256) and
              (sequence == 1) == (previous_receipt_sha256 == a.GENESIS) and
              l.sha_pin(independent_exchange_challenge_sha256) and
              type(sender_role) is str and sender_role in ('a','b'),
              'EC301_SEQUENCE_PREDECESSOR_CHALLENGE_OR_SENDER_ROLE_INVALID',
              'permission_denied')
    l.require(report['schema'] == g.REPORT_SCHEMA and
              type(report['history_session_count']) is int and
              1 <= report['history_session_count'] <= g.MAX_SESSIONS and
              len(report['full_signed_bilateral_session_sha256_chain']) ==
                  report['history_session_count'],
              'EC301_ORIGINAL_VERIFIED_EC300_REPORT_INVALID',
              'permission_denied')
    return {
        'schema':CLAIM_SCHEMA, 'sequence':sequence,
        'previous_receipt_sha256':previous_receipt_sha256,
        'independent_exchange_challenge_sha256':independent_exchange_challenge_sha256,
        'sender_role':sender_role,
        'recipient_role':'b' if sender_role=='a' else 'a',
        'original_audit_identity':report['original_audit_identity'],
        'a':_witness(report,'a'),'b':_witness(report,'b'),
        'full_signed_session_sha256_chain':list(report['full_signed_bilateral_session_sha256_chain']),
        'latest_session_sha256':report['externally_pinned_latest_bilateral_session_sha256'],
        'verified_ec300_report_sha256':a.sha(report),
        'historical_comparison_status':report['status'],
        'historical_comparison_exit_code':report['exit_code'],
    }


def _check_claim(claim: Any) -> dict:
    l.exact(claim,CLAIM_FIELDS,'EC301_CLAIM_FIELDS_INVALID')
    l.require(claim['schema']==CLAIM_SCHEMA and
              type(claim['sender_role']) is str and claim['sender_role'] in ('a','b') and
              claim['recipient_role']==('b' if claim['sender_role']=='a' else 'a') and
              type(claim['sequence']) is int and 1 <= claim['sequence'] <= MAX_EXCHANGES and
              a.valid_sha(claim['previous_receipt_sha256']) and
              l.sha_pin(claim['independent_exchange_challenge_sha256']) and
              (claim['sequence']==1)==(claim['previous_receipt_sha256']==a.GENESIS) and
              l.sha_pin(claim['verified_ec300_report_sha256']) and
              l.sha_pin(claim['latest_session_sha256']),
              'EC301_CLAIM_CONTRACT_INVALID','permission_denied')
    for role in ('a','b'):
        spec=l.exact(claim[role],WITNESS_FIELDS,'EC301_WITNESS_CLAIM_FIELDS_INVALID')
        l.require(type(spec['signed_observation_sha256_chain']) is list and
                  1 <= len(spec['signed_observation_sha256_chain']) <= 8 and
                  all(l.sha_pin(d) for d in spec['signed_observation_sha256_chain']) and
                  _same(spec['signed_observation_sha256_chain'][-1],
                        spec['latest_observation_sha256']),
                  'EC301_SIGNED_WITNESS_RECEIPT_CHAIN_INVALID','permission_denied')
    chain=claim['full_signed_session_sha256_chain']
    l.require(type(chain) is list and 1<=len(chain)<=g.MAX_SESSIONS and
              all(l.sha_pin(s) for s in chain) and
              _same(chain[-1],claim['latest_session_sha256']),
              'EC301_SIGNED_SESSION_CHAIN_INVALID','permission_denied')
    return claim


def _message(role: str, content: dict) -> bytes:
    l.require(role in ('sender','recipient'),'EC301_INVALID_SIGNATURE_ROLE')
    return DOMAIN+role.encode('ascii')+b'\0'+a.canonical(content)


def _verify_sig(sig: Any, key_hex: str, role: str, content: dict) -> None:
    l.require(type(sig) is str and a.SIG.fullmatch(sig) is not None,
              'EC301_ED25519_SIGNATURE_FORMAT_INVALID','permission_denied')
    try:
        io.pub_from_hex(key_hex).verify(bytes.fromhex(sig), _message(role,content))
    except (InvalidSignature,ValueError,TypeError,io.HostError) as exc:
        raise a.AnchorError('EC301_ED25519_SENDER_OR_RECIPIENT_SIGNATURE_INVALID',
                            'permission_denied') from exc


def make_offer(claim: dict, key: Ed25519PrivateKey) -> dict:
    _check_claim(claim)
    return {'schema':OFFER_SCHEMA,'claim':claim,
            'sender_signature_ed25519':key.sign(_message('sender',claim)).hex()}


def verify_offer(offer: Any, rebuilt_claim: dict) -> None:
    l.exact(offer,OFFER_FIELDS,'EC301_OFFER_FIELDS_INVALID')
    l.require(offer['schema']==OFFER_SCHEMA and
              len(a.canonical(offer))+1<=MAX_OFFER_BYTES,
              'EC301_OFFER_SCHEMA_OR_SIZE_INVALID')
    claim=_check_claim(offer['claim'])
    l.require(a.canonical(claim)==a.canonical(rebuilt_claim),
              'EC301_OFFER_NOT_EQUAL_REVERIFIED_COMPLETE_EC300_HISTORY',
              'permission_denied')
    _verify_sig(offer['sender_signature_ed25519'],
                claim[claim['sender_role']]['witness_public_hex'],
                'sender',claim)


def make_receipt(offer: dict, key: Ed25519PrivateKey) -> dict:
    return {'schema':RECEIPT_SCHEMA,'offer':offer,
            'recipient_signature_ed25519':key.sign(_message('recipient',offer)).hex()}


def verify_receipt(receipt: Any, *, rebuilt_claim: dict,
                   expected_receipt_sha256: str) -> dict:
    l.exact(receipt,RECEIPT_FIELDS,'EC301_RECEIPT_FIELDS_INVALID')
    l.require(receipt['schema']==RECEIPT_SCHEMA and
              len(a.canonical(receipt))+1<=MAX_RECEIPT_BYTES and
              l.sha_pin(expected_receipt_sha256) and
              _same(a.sha(receipt),expected_receipt_sha256),
              'EC301_RECEIPT_NOT_EQUAL_EXTERNALLY_PINN_DIGEST',
              'permission_denied')
    offer=receipt['offer']
    verify_offer(offer,rebuilt_claim)
    _verify_sig(receipt['recipient_signature_ed25519'],
                rebuilt_claim[rebuilt_claim['recipient_role']]['witness_public_hex'],
                'recipient',offer)
    return rebuilt_claim


def _progress(old: dict, new: dict) -> None:
    l.require(a.canonical(old['original_audit_identity'])==
                  a.canonical(new['original_audit_identity']) and
              all(old[r]['witness_id']==new[r]['witness_id'] and
                  _same(old[r]['witness_public_hex'],new[r]['witness_public_hex'])
                  for r in ('a','b')),
              'EC301_AUDIT_OR_WITNESS_IDENTITIES_CHANGED','permission_denied')
    old_sessions=old['full_signed_session_sha256_chain']
    new_sessions=new['full_signed_session_sha256_chain']
    l.require(len(new_sessions)>len(old_sessions) and
              new_sessions[:len(old_sessions)]==old_sessions,
              'EC301_OLD_SIGNED_SESSION_HISTORY_NOT_STRICTLY_EXTENDED',
              'permission_denied')
    for role in ('a','b'):
        pre=old[role]['signed_observation_sha256_chain']
        post=new[role]['signed_observation_sha256_chain']
        l.require(len(post)>=len(pre) and post[:len(pre)]==pre,
                  'EC301_WITNESS_OBSERVATION_PREFIX_REMOVED_OR_REPLACED',
                  'permission_denied')


def validate_journal(doc: Any) -> dict:
    l.exact(doc,JOURNAL_FIELDS,'EC301_JOURNAL_FIELDS_INVALID')
    l.require(doc['schema']==JOURNAL_SCHEMA and
              len(a.canonical(doc))+1<=MAX_JOURNAL_BYTES,
              'EC301_JOURNAL_SCHEMA_OR_SIZE_INVALID')
    _ids(doc['a_id'],doc['a_public_hex'],doc['b_id'],doc['b_public_hex'])
    entries=doc['entries']
    l.require(type(entries) is list and 1<=len(entries)<=MAX_EXCHANGES,
              'EC301_JOURNAL_MUST_HAVE_ONE_TO_EIGHT_ENTRIES')
    for entry in entries:
        l.exact(entry,ENTRY_FIELDS,'EC301_JOURNAL_ENTRY_FIELDS_INVALID')
        l.require(l.absolute_file(entry['signed_receipt_file']) and
                  l.absolute_file(entry['ec300_history_file']) and
                  all(l.sha_pin(entry[k]) for k in (
                    'expected_receipt_sha256','expected_a_tip',
                    'expected_b_tip','expected_session_tip')),
                  'EC301_JOURNAL_SOURCE_FILES_AND_EXTERNAL_PINS_REQUIRED',
                  'permission_denied')
    return doc


def verify_journal(doc: Any, *, a_id: str, a_public_hex: str, a_tip: str,
                   b_id: str, b_public_hex: str, b_tip: str,
                   session_tip: str, receipt_tip: str) -> tuple[dict,list[dict]]:
    validate_journal(doc)
    _ids(a_id,a_public_hex,b_id,b_public_hex)
    last=doc['entries'][-1]
    l.require(_same(doc['a_id'],a_id) and _same(doc['b_id'],b_id) and
              _same(doc['a_public_hex'],a_public_hex) and
              _same(doc['b_public_hex'],b_public_hex) and
              l.sha_pin(a_tip) and l.sha_pin(b_tip) and
              l.sha_pin(session_tip) and l.sha_pin(receipt_tip) and
              _same(last['expected_a_tip'],a_tip) and
              _same(last['expected_b_tip'],b_tip) and
              _same(last['expected_session_tip'],session_tip) and
              _same(last['expected_receipt_sha256'],receipt_tip),
              'EC301_FOUR_INDEPENDENT_LATEST_TIPS_MUST_MATCH_FULL_JOURNAL',
              'permission_denied')
    old_sha=a.GENESIS
    challenges:set[str]=set()
    claims:list[dict]=[]
    parent_reports:list[dict]=[]
    for index,entry in enumerate(doc['entries'],1):
        report=_verified_parent(entry['ec300_history_file'],
             a_id=a_id,a_public_hex=a_public_hex,a_tip=entry['expected_a_tip'],
             b_id=b_id,b_public_hex=b_public_hex,b_tip=entry['expected_b_tip'],
             session_tip=entry['expected_session_tip'])
        receipt=io.read_doc(entry['signed_receipt_file'],MAX_RECEIPT_BYTES)
        l.exact(receipt,RECEIPT_FIELDS,'EC301_SIGNED_RECEIPT_FIELDS_INVALID')
        raw_offer=l.exact(receipt['offer'],OFFER_FIELDS,'EC301_SIGNED_OFFER_FIELDS_INVALID')
        raw_claim=l.exact(raw_offer['claim'],CLAIM_FIELDS,'EC301_SIGNED_CLAIM_FIELDS_INVALID')
        challenge=raw_claim['independent_exchange_challenge_sha256']
        sender_role=raw_claim['sender_role']
        claim=claim_from_report(report,sequence=index,
              previous_receipt_sha256=old_sha,
              independent_exchange_challenge_sha256=challenge,
              sender_role=sender_role)
        verify_receipt(receipt,rebuilt_claim=claim,
                       expected_receipt_sha256=entry['expected_receipt_sha256'])
        l.require(challenge not in challenges,
                  'EC301_SIGNED_EXCHANGE_CHALLENGE_REUSED', 'permission_denied')
        if claims:
            _progress(claims[-1],claim)
        challenges.add(challenge)
        claims.append(claim)
        parent_reports.append(report)
        old_sha=entry['expected_receipt_sha256']
    conflict=any(r['ever_observed_signed_competing_evidence'] for r in parent_reports)
    inconclusive=any(r['ever_observed_inconclusive_histories'] for r in parent_reports)
    if conflict:
        status='signed_competing_evidence_in_received_history'; exit_code=2
    elif inconclusive:
        status='inconclusive_signed_histories_in_received_history'; exit_code=2
    else:
        status='all_supplied_offline_handoffs_cryptographically_consistent'; exit_code=0
    path_free={
        'schema':REPORT_SCHEMA,'status':status,'exit_code':exit_code,
        'original_audit_identity':claims[0]['original_audit_identity'],
        'witness_a':{'witness_id':a_id,'witness_public_hex':a_public_hex,
            'latest_observation_sha256':a_tip},
        'witness_b':{'witness_id':b_id,'witness_public_hex':b_public_hex,
            'latest_observation_sha256':b_tip},
        'externally_pinned_latest_session_sha256':session_tip,
        'externally_pinned_latest_receipt_sha256':receipt_tip,
        'signed_receipt_sha256_chain':[e['expected_receipt_sha256'] for e in doc['entries']],
        'fully_reverified_ec300_report_sha256_chain':[a.sha(r) for r in parent_reports],
        'signed_ec300_session_sha256_chain_per_handoff':[
            list(c['full_signed_session_sha256_chain']) for c in claims],
        'sender_roles_in_order':[c['sender_role'] for c in claims],
        'handoff_count':len(claims),
        'old_signed_sessions_strictly_preserved_and_extended':True,
        'old_witness_observations_preserved_on_both_roles':True,
        'same_offer_signed_by_sender_and_countersigned_by_recipient':True,
        'all_original_ec294_through_ec300_sources_reverified_per_handoff':True,
        'historical_signed_competing_evidence_observed':conflict,
        'historical_inconclusive_evidence_observed':inconclusive,
        'real_two_site_handoff_or_human_independence_proven':False,
        'external_worm_or_trusted_utc_proven':False,
        'globally_unique_latest_or_unseen_forks_excluded':False,
        'original_network_provider_or_inbox_executed':False,
    }
    l.require(len(a.canonical(path_free))+1<=MAX_REPORT_BYTES,
              'EC301_JOURNAL_REPORT_EXCEEDS_BUDGET')
    return path_free,claims


def build_next_claim(*, history_file:str, a_id:str,a_public_hex:str,a_tip:str,
                     b_id:str,b_public_hex:str,b_tip:str,session_tip:str,
                     sequence:int,sender_role:str,exchange_challenge_sha256:str,
                     prior_journal_file:str|None=None,
                     expected_previous_receipt_sha256:str|None=None,
                     expected_prior_a_tip:str|None=None,
                     expected_prior_b_tip:str|None=None,
                     expected_prior_session_tip:str|None=None) -> dict:
    _ids(a_id,a_public_hex,b_id,b_public_hex)
    l.require(type(sequence) is int and 1<=sequence<=MAX_EXCHANGES and
              type(sender_role) is str and sender_role in ('a','b') and
              l.sha_pin(exchange_challenge_sha256),
              'EC301_NEW_EXCHANGE_SEQUENCE_ROLE_OR_CHALLENGE_INVALID',
              'permission_denied')
    old_claims:list[dict]=[]
    previous=a.GENESIS
    if sequence==1:
        l.require(all(x is None for x in (prior_journal_file,
            expected_previous_receipt_sha256,expected_prior_a_tip,
            expected_prior_b_tip,expected_prior_session_tip)),
            'EC301_GENESIS_CANNOT_DECLARE_UNVERIFIED_PREVIOUS_JOURNAL')
    else:
        l.require(l.absolute_file(prior_journal_file) and
                  all(l.sha_pin(x) for x in (expected_previous_receipt_sha256,
                     expected_prior_a_tip,expected_prior_b_tip,
                     expected_prior_session_tip)),
                  'EC301_PREVIOUS_FULL_JOURNAL_AND_FOUR_EXTERNAL_PINS_REQUIRED',
                  'permission_denied')
        journal=io.read_doc(prior_journal_file,MAX_JOURNAL_BYTES)
        validate_journal(journal)
        l.require(len(journal['entries'])==sequence-1,
                  'EC301_PREVIOUS_JOURNAL_MISSING_AN_EXCHANGE',
                  'permission_denied')
        _,old_claims=verify_journal(journal,
            a_id=a_id,a_public_hex=a_public_hex,a_tip=expected_prior_a_tip,
            b_id=b_id,b_public_hex=b_public_hex,b_tip=expected_prior_b_tip,
            session_tip=expected_prior_session_tip,
            receipt_tip=expected_previous_receipt_sha256)
        previous=expected_previous_receipt_sha256
        l.require(exchange_challenge_sha256 not in
                  {c['independent_exchange_challenge_sha256'] for c in old_claims},
                  'EC301_NEW_CHALLENGE_ALREADY_USED_BY_PREVIOUS_RECEIPT',
                  'permission_denied')
    report=_verified_parent(history_file,a_id=a_id,a_public_hex=a_public_hex,
        a_tip=a_tip,b_id=b_id,b_public_hex=b_public_hex,b_tip=b_tip,
        session_tip=session_tip)
    claim=claim_from_report(report,sequence=sequence,
        previous_receipt_sha256=previous,
        independent_exchange_challenge_sha256=exchange_challenge_sha256,
        sender_role=sender_role)
    if old_claims:
        _progress(old_claims[-1],claim)
    return claim
