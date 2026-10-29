#!/usr/bin/env python3
"""EC345: one-item, bounded Ed25519 disclosure challenges with independently pinned originals.

The change proposer SIGNS the request, registered receivers independently SIGN
their own answer, and the auditor verifies raw originals only if explicitly
furnished. A signed offer is not a file delivery. A signed "unavailable" answer
is not evidence that the original does not exist anywhere. No remote side effects.
"""
from __future__ import annotations

import inspect
from collections import defaultdict
from typing import Any

from ec295_delivery_anchor import anchor
from ec319_offline_transfer_registry import registry as reg
from ec338_independent_custody import ceremony
from ec339_offline_authority import authority as old
from ec340_issuer_root_rotation import rotation
from ec343_hold_receipts import timeline as prior
from ec344_receiver_visibility import visibility as vis

CHALLENGE_SCHEMA='ces.ec345.ed25519_pinned_disclosure_challenge.v1'
CHALLENGE_CLAIM_SCHEMA='ces.ec345.pinned_disclosure_challenge_claim.v1'
RESPONSE_SCHEMA='ces.ec345.ed25519_bounded_receiver_disclosure_response.v1'
RESPONSE_CLAIM_SCHEMA='ces.ec345.bounded_receiver_disclosure_response_claim.v1'
RESULT_SCHEMA='ces.ec345.signed_disclosure_gap_audit_unresolved.v1'
DENIAL_SCHEMA='ces.ec345.signed_disclosure_gap_audit_denial.v1'
CHALLENGE_DOMAIN=b'CES/EC345/OneItemDisclosureChallenge/v1\0'
RESPONSE_DOMAIN=b'CES/EC345/ReceiverDisclosureResponse/v1\0'
OFFER='offer_disclosure'
UNAVAILABLE='unavailable_claim'
MAX_ATTEMPTS=3
MAX_CHALLENGES=8
MAX_RESPONSES=MAX_CHALLENGES*prior.MAX_RECEIVERS
CHALLENGE_FIELDS={
    'schema','case_id','ec343_roster_original_raw_sha256',
    'directory_original_raw_sha256','checkpoint_original_raw_sha256',
    'round_nonce_sha256','anchor_item_id','baseline_presented_item_ids',
    'basis_signed_view_original_sha256s','target_item_id','target_slot_id',
    'target_snapshot_file','target_snapshot_original_raw_sha256',
    'target_ack_set_file','target_ack_set_original_raw_sha256',
    'audience_receiver_ids','attempt_number','previous_challenge_file',
    'previous_challenge_original_raw_sha256','challenge_nonce_sha256',
    'issued_utc','issuer_id','issuer_public_hex','issuer_organization_id',
    'scope','not_a_remote_or_global_disclosure_order'}
RESPONSE_FIELDS={
    'schema','case_id','ec343_roster_original_raw_sha256',
    'challenge_original_raw_sha256','target_item_id',
    'target_snapshot_original_raw_sha256','target_ack_set_original_raw_sha256',
    'receiver_id','receiver_public_hex','receiver_organization_id',
    'response_kind','response_nonce_sha256','reported_utc','scope',
    'no_global_absence_or_physical_delivery_claim'}
NEGATIVES=(
    'signed_request_is_legal_process_or_real_institutional_authority',
    'signed_offer_alone_proves_original_delivered',
    'signed_unavailable_claim_proves_global_absence',
    'unanswered_request_proves_missing_original',
    'two_receiver_disagreement_proves_fraud_or_selects_winner',
    'complete_receiver_roster_or_hidden_forks_enumerated',
    'claimed_reported_utc_is_external_trusted_time',
    'remote_cas_worm_provider_freeze_release_or_write_executed',
    'fully_unmocked_old_history_or_final_acceptance_proven')


def need(value: Any, code: str, status: str='invalid_input')->None:
    if value is not True:
        raise anchor.AnchorError('EC345_'+code,status)


def _candidate(command:str,sha:str)->dict:
    return {'schema':RESULT_SCHEMA,'command':command,
            'status':'owner_private_signed_candidate_requires_independent_sha_pin',
            'exit_code':2,'candidate_original_raw_sha256':sha,
            'offline_unresolved_exit_code':2,
            **{k:False for k in NEGATIVES}}


def _ordered_ids(ids:Any,order:list[str],*,min_count:int,max_count:int,
                 code:str)->None:
    need(type(ids) is list and min_count<=len(ids)<=max_count and
         all(type(v) is str and v in order for v in ids) and
         len(set(ids))==len(ids) and ids==[v for v in order if v in ids],
         code)


def _challenge_claim(*,r:dict,roster_sha:str,d:dict,directory_sha:str,
                     c:dict,checkpoint_sha:str,item_id:str,
                     anchor_item_id:str,baseline_presented_item_ids:list[str],
                     view_shas:list[str],audience_receiver_ids:list[str],
                     attempt_number:int,previous_challenge_file:str|None,
                     previous_challenge_sha:str|None,
                     challenge_nonce_sha256:str,issued_utc:str)->dict:
    byid={a['item_id']:a for a in c['announcements']}
    order=list(byid)
    need(item_id in byid and ceremony._id(anchor_item_id) and
         anchor_item_id in byid and anchor_item_id!=item_id,
         'ONE_ANNOUNCED_UNPRESENTED_NONANCHOR_TARGET_REQUIRED')
    _ordered_ids(baseline_presented_item_ids,order,min_count=1,
                 max_count=vis.MAX_ITEMS,code='EXACT_ORDERED_BASELINE_PRESENTED_IDS_REQUIRED')
    need(anchor_item_id in baseline_presented_item_ids and
         item_id not in baseline_presented_item_ids,
         'TARGET_MUST_NOT_HAVE_BEEN_PRESENTED_IN_BASELINE')
    receivers=[x['signer_id'] for x in r['receivers']]
    _ordered_ids(audience_receiver_ids,receivers,min_count=2,
                 max_count=prior.MAX_RECEIVERS,
                 code='TWO_TO_FOUR_REGISTERED_CHALLENGE_RECEIVERS_REQUIRED')
    need(type(view_shas) is list and 2<=len(view_shas)<=vis.MAX_VIEWS and
         all(ceremony._sha(v) for v in view_shas) and len(set(view_shas))==len(view_shas),
         'TWO_TO_EIGHT_INDEPENDENT_VIEW_SHA_PINS_REQUIRED')
    need(type(attempt_number) is int and 1<=attempt_number<=MAX_ATTEMPTS,
         'ATTEMPT_NUMBER_OUT_OF_BOUNDS')
    need((attempt_number==1 and previous_challenge_file is None and
          previous_challenge_sha is None) or
         (attempt_number>1 and type(previous_challenge_file) is str and
          ceremony._sha(previous_challenge_sha)),
         'PREDECESSOR_REQUIRED_ONLY_FOR_LATER_ATTEMPTS')
    need(ceremony._sha(challenge_nonce_sha256) and ceremony._utc(issued_utc),
         'FRESH_CHALLENGE_NONCE_AND_CLAIMED_UTC_REQUIRED')
    target=byid[item_id]; who=r['change_proposer']
    return {'schema':CHALLENGE_CLAIM_SCHEMA,
        'case_id':r['case_id'],
        'ec343_roster_original_raw_sha256':roster_sha,
        'directory_original_raw_sha256':directory_sha,
        'checkpoint_original_raw_sha256':checkpoint_sha,
        'round_nonce_sha256':c['round_nonce_sha256'],
        'anchor_item_id':anchor_item_id,
        'baseline_presented_item_ids':baseline_presented_item_ids,
        'basis_signed_view_original_sha256s':view_shas,
        'target_item_id':item_id,'target_slot_id':target['slot_id'],
        'target_snapshot_file':target['snapshot_file'],
        'target_snapshot_original_raw_sha256':target['expected_snapshot_sha256'],
        'target_ack_set_file':target['ack_set_file'],
        'target_ack_set_original_raw_sha256':target['expected_ack_set_sha256'],
        'audience_receiver_ids':audience_receiver_ids,
        'attempt_number':attempt_number,
        'previous_challenge_file':previous_challenge_file,
        'previous_challenge_original_raw_sha256':previous_challenge_sha,
        'challenge_nonce_sha256':challenge_nonce_sha256,
        'issued_utc':issued_utc,'issuer_id':who['signer_id'],
        'issuer_public_hex':who['public_hex'],
        'issuer_organization_id':who['organization_id'],
        'scope':'one_checkpoint_item_only_requested_without_execution',
        'not_a_remote_or_global_disclosure_order':True}


def _next_attempt_consistent(previous:dict,current:dict)->None:
    """Reject a newly signed follow-up before its bytes become an irreversible candidate."""
    common=('target_item_id','target_slot_id','target_snapshot_file',
         'target_snapshot_original_raw_sha256','target_ack_set_file',
         'target_ack_set_original_raw_sha256','anchor_item_id',
         'basis_signed_view_original_sha256s','baseline_presented_item_ids',
         'audience_receiver_ids')
    need(all(previous[k]==current[k] for k in common) and
         previous['attempt_number']+1==current['attempt_number'] and
         previous['challenge_nonce_sha256']!=current['challenge_nonce_sha256'] and
         old._time(previous['issued_utc'])<=old._time(current['issued_utc']),
         'CHALLENGE_PREDECESSOR_SEQUENCE_AND_CONTEXT_REQUIRED')


def _read_challenge(path:str,sha:str,*,r:dict,roster_sha:str,
                    d:dict,directory_sha:str,c:dict,checkpoint_sha:str,
                    pins:dict[str,str])->dict:
    """Validate complete bounded predecessor chain; never trust self-pinned SHA."""
    prior.pin(pins,path,sha)
    doc=prior.read(path,sha,'EC345_SIGNED_CHALLENGE')
    claim=doc.get('claim') if type(doc) is dict else None
    need(type(claim) is dict and set(claim)==CHALLENGE_FIELDS,
         'SIGNED_CHALLENGE_EXACT_CLAIM_REQUIRED')
    expected=_challenge_claim(r=r,roster_sha=roster_sha,d=d,
        directory_sha=directory_sha,c=c,checkpoint_sha=checkpoint_sha,
        item_id=claim.get('target_item_id'),
        anchor_item_id=claim.get('anchor_item_id'),
        baseline_presented_item_ids=claim.get('baseline_presented_item_ids'),
        view_shas=claim.get('basis_signed_view_original_sha256s'),
        audience_receiver_ids=claim.get('audience_receiver_ids'),
        attempt_number=claim.get('attempt_number'),
        previous_challenge_file=claim.get('previous_challenge_file'),
        previous_challenge_sha=claim.get('previous_challenge_original_raw_sha256'),
        challenge_nonce_sha256=claim.get('challenge_nonce_sha256'),
        issued_utc=claim.get('issued_utc'))
    need(claim==expected,'CHALLENGE_MUST_MATCH_EXACT_CHECKPOINT_AND_SIGNER')
    prior._signed(doc,CHALLENGE_SCHEMA,CHALLENGE_DOMAIN,
                  r['change_proposer']['public_hex'],'EC345_REQUESTER')
    if claim['attempt_number']>1:
        parent_path=claim['previous_challenge_file']
        parent_sha=claim['previous_challenge_original_raw_sha256']
        need(parent_path!=path,'CHALLENGE_CANNOT_PRECEDE_ITSELF')
        parent=_read_challenge(parent_path,parent_sha,r=r,roster_sha=roster_sha,
            d=d,directory_sha=directory_sha,c=c,checkpoint_sha=checkpoint_sha,pins=pins)
        _next_attempt_consistent(parent,claim)
    return claim


def issue_challenge(*,out:str,private_key_file:str,roster_file:str,
                    expected_roster_sha256:str,directory_file:str,
                    expected_directory_sha256:str,checkpoint_file:str,
                    expected_checkpoint_sha256:str,
                    view_files:list[str],view_shas:list[str],
                    anchor_item_id:str,baseline_presented_item_ids:list[str],
                    item_id:str,audience_receiver_ids:list[str],
                    attempt_number:int,challenge_nonce_sha256:str,issued_utc:str,
                    previous_challenge_file:str|None=None,
                    expected_previous_challenge_sha256:str|None=None)->dict:
    r,d,c,pins=vis._prepared(roster_file=roster_file,
       expected_roster_sha256=expected_roster_sha256,
       directory_file=directory_file,expected_directory_sha256=expected_directory_sha256,
       checkpoint_file=checkpoint_file,expected_checkpoint_sha256=expected_checkpoint_sha256)
    views,_=vis._signed_views(view_files=view_files,view_shas=view_shas,
        r=r,d=d,c=c,roster_sha=expected_roster_sha256,
        directory_sha=expected_directory_sha256,
        checkpoint_sha=expected_checkpoint_sha256,
        evaluation_utc=issued_utc,pins=pins)
    need(any(item_id in v['ids'] for entries in views.values() for v in entries),
         'TARGET_MUST_BE_CLAIMED_VISIBLE_IN_GENUINE_SIGNED_EC344_VIEW')
    claim=_challenge_claim(r=r,roster_sha=expected_roster_sha256,d=d,
        directory_sha=expected_directory_sha256,c=c,
        checkpoint_sha=expected_checkpoint_sha256,item_id=item_id,
        anchor_item_id=anchor_item_id,
        baseline_presented_item_ids=baseline_presented_item_ids,
        view_shas=view_shas,audience_receiver_ids=audience_receiver_ids,
        attempt_number=attempt_number,
        previous_challenge_file=previous_challenge_file,
        previous_challenge_sha=expected_previous_challenge_sha256,
        challenge_nonce_sha256=challenge_nonce_sha256,issued_utc=issued_utc)
    if attempt_number>1:
        previous=_read_challenge(previous_challenge_file,
            expected_previous_challenge_sha256,
            r=r,roster_sha=expected_roster_sha256,d=d,
            directory_sha=expected_directory_sha256,c=c,
            checkpoint_sha=expected_checkpoint_sha256,pins=pins)
        _next_attempt_consistent(previous,claim)
    key,pub=rotation._private_key_public(private_key_file)
    need(prior.same(pub,r['change_proposer']['public_hex']),
         'ONLY_EC343_CHANGE_PROPOSER_MAY_SIGN_CHALLENGE','permission_denied')
    need(out not in {claim['target_snapshot_file'],claim['target_ack_set_file']},
         'CHALLENGE_OUTPUT_MUST_NOT_ALIAS_TARGET_ORIGINAL')
    doc={'schema':CHALLENGE_SCHEMA,'claim':claim,
         'signature_ed25519':key.sign(CHALLENGE_DOMAIN+reg.canonical(claim)).hex()}
    return _candidate('issue-challenge',prior._write(out,doc,pins,private_key_file))


def _response_claim(r:dict,roster_sha:str,challenge_sha:str,challenge:dict,
                    actor:dict,response_kind:str,response_nonce_sha256:str,
                    reported_utc:str)->dict:
    need(response_kind in (OFFER,UNAVAILABLE) and
         ceremony._sha(response_nonce_sha256) and ceremony._utc(reported_utc),
         'EXACT_RESPONSE_KIND_NONCE_AND_UTC_REQUIRED')
    need(actor['signer_id'] in challenge['audience_receiver_ids'],
         'RESPONSE_SIGNER_NOT_IN_NAMED_CHALLENGE_AUDIENCE')
    need(response_nonce_sha256!=challenge['challenge_nonce_sha256'] and
         old._time(challenge['issued_utc'])<=old._time(reported_utc),
         'RESPONSE_MUST_FOLLOW_ITS_CHALLENGE')
    return {'schema':RESPONSE_CLAIM_SCHEMA,'case_id':r['case_id'],
        'ec343_roster_original_raw_sha256':roster_sha,
        'challenge_original_raw_sha256':challenge_sha,
        'target_item_id':challenge['target_item_id'],
        'target_snapshot_original_raw_sha256':
            challenge['target_snapshot_original_raw_sha256'],
        'target_ack_set_original_raw_sha256':
            challenge['target_ack_set_original_raw_sha256'],
        'receiver_id':actor['signer_id'],
        'receiver_public_hex':actor['public_hex'],
        'receiver_organization_id':actor['organization_id'],
        'response_kind':response_kind,
        'response_nonce_sha256':response_nonce_sha256,
        'reported_utc':reported_utc,
        'scope':'signed_offer_or_local_availability_claim_only',
        'no_global_absence_or_physical_delivery_claim':True}


def sign_response(*,out:str,private_key_file:str,roster_file:str,
                  expected_roster_sha256:str,directory_file:str,
                  expected_directory_sha256:str,checkpoint_file:str,
                  expected_checkpoint_sha256:str,challenge_file:str,
                  expected_challenge_sha256:str,response_kind:str,
                  response_nonce_sha256:str,reported_utc:str)->dict:
    r,d,c,pins=vis._prepared(roster_file=roster_file,
       expected_roster_sha256=expected_roster_sha256,
       directory_file=directory_file,expected_directory_sha256=expected_directory_sha256,
       checkpoint_file=checkpoint_file,expected_checkpoint_sha256=expected_checkpoint_sha256)
    challenge=_read_challenge(challenge_file,expected_challenge_sha256,
        r=r,roster_sha=expected_roster_sha256,d=d,
        directory_sha=expected_directory_sha256,c=c,
        checkpoint_sha=expected_checkpoint_sha256,pins=pins)
    key,pub=rotation._private_key_public(private_key_file)
    matches=[x for x in r['receivers'] if prior.same(x['public_hex'],pub)]
    need(len(matches)==1,'ONLY_REGISTERED_EC343_RECEIVER_MAY_SIGN_RESPONSE',
         'permission_denied')
    claim=_response_claim(r,expected_roster_sha256,expected_challenge_sha256,
        challenge,matches[0],response_kind,response_nonce_sha256,reported_utc)
    need(out not in {challenge['target_snapshot_file'],challenge['target_ack_set_file']},
         'RESPONSE_OUTPUT_MUST_NOT_ALIAS_TARGET_ORIGINAL')
    doc={'schema':RESPONSE_SCHEMA,'claim':claim,
         'signature_ed25519':key.sign(RESPONSE_DOMAIN+reg.canonical(claim)).hex()}
    return _candidate('sign-response',prior._write(out,doc,pins,private_key_file))


def audit_disclosures(*,challenge_files:list[str],challenge_shas:list[str],
                      response_files:list[str],response_shas:list[str],
                      disclosed_item_ids:list[str],disclosure_evaluation_utc:str,
                      **baseline)->dict:
    """Replay EC344, then pinned signed attempts/responses; no auto-fetch of missing files."""
    mandatory=set(inspect.signature(vis.audit_views).parameters)
    need(set(baseline)==mandatory,'FULL_EC344_BASELINE_TRUST_ARGUMENTS_REQUIRED')
    need(ceremony._utc(disclosure_evaluation_utc) and
         old._time(baseline['timeline_evaluation_utc'])<=
             old._time(disclosure_evaluation_utc),
         'DISCLOSURE_EVALUATION_MUST_FOLLOW_BASELINE')
    need(type(challenge_files) is list and type(challenge_shas) is list and
         1<=len(challenge_files)<=MAX_CHALLENGES and
         len(challenge_files)==len(challenge_shas) and
         len(set(challenge_files))==len(challenge_files) and
         type(response_files) is list and type(response_shas) is list and
         len(response_files)==len(response_shas) and
         len(response_files)<=MAX_RESPONSES and
         len(set(response_files))==len(response_files),
         'BOUNDED_INDEPENDENT_WHOLE_SHA_CHALLENGE_AND_RESPONSE_PAIRS_REQUIRED')
    need(type(disclosed_item_ids) is list and
         len(disclosed_item_ids)<=vis.MAX_ITEMS and
         len(set(disclosed_item_ids))==len(disclosed_item_ids),
         'BOUNDED_UNIQUE_EXPLICIT_DISCLOSURE_IDS_REQUIRED')
    baseline_report=vis.audit_views(**baseline)
    need(baseline_report['exit_code']==2 and
         baseline_report['true_ec342_signed_fork_and_old_originals_replayed'] is True,
         'REAL_EC344_AND_EC343_TO_EC337_HISTORY_REPLAY_MANDATORY',
         'permission_denied')
    r,d,c,pins=vis._prepared(roster_file=baseline['roster_file'],
        expected_roster_sha256=baseline['expected_roster_sha256'],
        directory_file=baseline['directory_file'],
        expected_directory_sha256=baseline['expected_directory_sha256'],
        checkpoint_file=baseline['checkpoint_file'],
        expected_checkpoint_sha256=baseline['expected_checkpoint_sha256'])
    byid={x['item_id']:x for x in c['announcements']}
    original_order=list(byid)
    targetable=set(baseline_report['claimed_visible_but_not_presented_item_ids'])
    _ordered_ids(disclosed_item_ids,original_order,min_count=0,
        max_count=vis.MAX_ITEMS,code='DISCLOSED_IDS_MUST_USE_CHECKPOINT_ORDER')
    need(set(disclosed_item_ids)<=targetable,
         'ONLY_BASELINE_CLAIMED_BUT_UNPRESENTED_ORIGINALS_CAN_BE_DISCLOSED')
    for path,sha in ((baseline['manifest_file'],baseline['expected_manifest_sha256']),
                     (baseline['governance_roster_file'],baseline['expected_governance_roster_sha256']),
                     (baseline['review_manifest_file'],baseline['expected_review_manifest_sha256']),
                     (baseline['approval_file'],baseline['expected_approval_sha256']),
                     (baseline['head_snapshot_file'],baseline['expected_head_snapshot_sha256']),
                     (baseline['head_ack_set_file'],baseline['expected_head_ack_set_sha256']),
                     *zip(baseline['view_files'],baseline['view_shas'],strict=True)):
        prior.pin(pins,path,sha)
    need(not (set(challenge_files)&set(response_files)),
         'ONE_ORIGINAL_CANNOT_BE_CHALLENGE_AND_RESPONSE')
    challenges=[]
    by_challenge={}
    for path,sha in zip(challenge_files,challenge_shas,strict=True):
        claim=_read_challenge(path,sha,r=r,
            roster_sha=baseline['expected_roster_sha256'],d=d,
            directory_sha=baseline['expected_directory_sha256'],
            c=c,checkpoint_sha=baseline['expected_checkpoint_sha256'],pins=pins)
        need(claim['target_item_id'] in targetable and
             claim['anchor_item_id']==baseline['anchor_item_id'] and
             claim['basis_signed_view_original_sha256s']==baseline['view_shas'] and
             claim['baseline_presented_item_ids']==baseline['presented_item_ids'],
             'CHALLENGE_MUST_NAME_ACTUAL_EC344_VERIFIED_MISSING_CLAIM')
        need(old._time(baseline['timeline_evaluation_utc'])<=
                old._time(claim['issued_utc'])<=old._time(disclosure_evaluation_utc),
             'CHALLENGE_CLAIM_TIME_OUTSIDE_EVALUATION_WINDOW')
        need(sha not in by_challenge,'DUPLICATE_CHALLENGE_SHA')
        by_challenge[sha]=claim
        challenges.append({'path':path,'sha256':sha,'claim':claim})
    # All attempts supplied: one chain per item, canonical checkpoint order,
    # strictly contiguous 1..N and no same-item competing attempt overwrite.
    order=[(original_order.index(x['claim']['target_item_id']),
            x['claim']['attempt_number']) for x in challenges]
    need(order==sorted(order) and len(set(order))==len(order),
         'CHALLENGES_MUST_BE_CANONICAL_AND_UNAMBIGUOUS')
    challenge_nonces=set()
    latest_by_item={}
    for ch in challenges:
        q=ch['claim']; item=q['target_item_id']; idx=q['attempt_number']
        predecessor=latest_by_item.get(item)
        need((predecessor is None and idx==1) or
             (predecessor is not None and idx==predecessor['claim']['attempt_number']+1
              and q['previous_challenge_original_raw_sha256']==predecessor['sha256']
              and q['previous_challenge_file']==predecessor['path']),
             'ALL_CONTIGUOUS_ATTEMPTS_MUST_BE_PRESENT_AND_PINNED')
        need(q['challenge_nonce_sha256'] not in challenge_nonces,
             'CHALLENGE_NONCE_REUSED_ACROSS_ATTEMPTS_OR_ITEMS')
        challenge_nonces.add(q['challenge_nonce_sha256'])
        latest_by_item[item]=ch
    responses_by_challenge=defaultdict(list)
    nonces=set(challenge_nonces)
    response_order=[]
    for path,sha in zip(response_files,response_shas,strict=True):
        prior.pin(pins,path,sha)
        doc=prior.read(path,sha,'EC345_PINNED_SIGNED_RESPONSE')
        claim=doc.get('claim') if type(doc) is dict else None
        need(type(claim) is dict and set(claim)==RESPONSE_FIELDS,
             'SIGNED_RESPONSE_EXACT_CLAIM_REQUIRED')
        challenge_sha=claim.get('challenge_original_raw_sha256')
        need(type(challenge_sha) is str and challenge_sha in by_challenge,
             'RESPONSE_MUST_BIND_A_PRESENTED_CHALLENGE_SHA')
        q=by_challenge[challenge_sha]
        actor=next((a for a in r['receivers']
                    if a['signer_id']==claim.get('receiver_id')),None)
        need(actor is not None,'RESPONSE_ONLY_FROM_REGISTERED_EC343_RECEIVER')
        expected=_response_claim(r,baseline['expected_roster_sha256'],
            challenge_sha,q,actor,claim.get('response_kind'),
            claim.get('response_nonce_sha256'),claim.get('reported_utc'))
        need(claim==expected,'RESPONSE_EXACT_CHALLENGE_ITEM_SIGNER_REQUIRED')
        prior._signed(doc,RESPONSE_SCHEMA,RESPONSE_DOMAIN,
                      actor['public_hex'],'EC345_RECEIVER_RESPONSE')
        need(old._time(claim['reported_utc'])<=old._time(disclosure_evaluation_utc),
             'RESPONSE_CLAIMED_UTC_AFTER_DISCLOSURE_EVALUATION')
        need(claim['response_nonce_sha256'] not in nonces,
             'RESPONSE_OR_CHALLENGE_NONCE_REUSED')
        nonces.add(claim['response_nonce_sha256'])
        existing=responses_by_challenge[challenge_sha]
        need(all(x['receiver_id']!=claim['receiver_id'] for x in existing),
             'ONE_RECEIVER_ONE_RESPONSE_PER_CHALLENGE')
        existing.append({'receiver_id':claim['receiver_id'],
              'response_kind':claim['response_kind'],
              'response_original_raw_sha256':sha,
              'reported_utc':claim['reported_utc']})
        ch_index=next(i for i,x in enumerate(challenges) if x['sha256']==challenge_sha)
        receiver_index=q['audience_receiver_ids'].index(claim['receiver_id'])
        response_order.append((ch_index,receiver_index))
    need(response_order==sorted(response_order),
         'RESPONSES_MUST_FOLLOW_CHALLENGE_AND_AUDIENCE_ORDER')
    for item_id in disclosed_item_ids:
        need(any(q['claim']['target_item_id']==item_id and
                 any(x['response_kind']==OFFER for x in
                     responses_by_challenge[q['sha256']]) for q in challenges),
             'CANNOT_VERIFY_UNSOLICITED_UNCLAIMED_DISCLOSURE_ORIGINAL')
    verified={}
    for item_id in disclosed_item_ids:
        verified[item_id]=vis._verified_item(byid[item_id],r,
            baseline['expected_roster_sha256'],pins,
            evaluation_utc=disclosure_evaluation_utc,
            governance_roster_file=baseline['governance_roster_file'],
            review_manifest_file=baseline['review_manifest_file'],
            approval_file=baseline['approval_file'])
    prior.late(pins)
    results=[]
    for item_id in original_order:
        item_challenges=[x for x in challenges if x['claim']['target_item_id']==item_id]
        if not item_challenges:
            continue
        replies=[x for ch in item_challenges for x in
                 responses_by_challenge[ch['sha256']]]
        kinds={x['response_kind'] for x in replies}
        responders={x['receiver_id'] for x in replies}
        conflict=(len(responders)>=2 and OFFER in kinds and UNAVAILABLE in kinds)
        result_kind=('two_receiver_conflicting_response' if conflict else
            'delivered_and_full_raw_sha_verified' if item_id in verified else
            'signed_unavailable_claim' if UNAVAILABLE in kinds else
            'signed_offer_but_originals_not_furnished' if OFFER in kinds else
            'request_unanswered')
        results.append({'item_id':item_id,'result_kind':result_kind,
            'attempt_count':len(item_challenges),
            'challenge_original_raw_sha256s':[x['sha256'] for x in item_challenges],
            'response_count':len(replies),
            'verified_furnished_originals':item_id in verified,
            'verified_original_detail':verified.get(item_id),
            'signed_receiver_answers':[{
                'challenge_original_raw_sha256':ch['sha256'],
                'attempt_number':ch['claim']['attempt_number'],
                'responses':responses_by_challenge[ch['sha256']]}
                for ch in item_challenges],
            'unanswered_attempt_numbers':[ch['claim']['attempt_number']
                for ch in item_challenges if not responses_by_challenge[ch['sha256']]],
            'conflict_is_a_signed_claim_difference_not_fraud_or_global_absence':conflict})
    precedence=('two_receiver_conflicting_response',
        'delivered_and_full_raw_sha_verified','signed_unavailable_claim',
        'signed_offer_but_originals_not_furnished','request_unanswered')
    found={x['result_kind'] for x in results}
    status=next(v+'_unresolved' for v in precedence if v in found)
    return {'schema':RESULT_SCHEMA,'command':'audit-disclosures',
            'status':status,'exit_code':2,'case_id':r['case_id'],
            'checkpoint_original_raw_sha256':baseline['expected_checkpoint_sha256'],
            'directory_original_raw_sha256':baseline['expected_directory_sha256'],
            'registered_ec343_roster_original_raw_sha256':baseline['expected_roster_sha256'],
            'baseline_signed_visibility_status':baseline_report['status'],
            'baseline_claimed_visible_but_not_presented_item_ids':
                baseline_report['claimed_visible_but_not_presented_item_ids'],
            'challenge_count':len(challenges),'response_count':len(response_files),
            'disclosure_evaluation_utc':disclosure_evaluation_utc,
            'item_outcomes':results,
            'outcome_counts':{x:sum(v['result_kind']==x for v in results)
                              for x in precedence},
            'verified_furnished_item_ids':list(verified),
            'true_ec342_signed_fork_and_old_originals_replayed':True,
            'no_global_delivery_or_absence_inferred':True,
            'offline_unresolved_exit_code':2,
            **{k:False for k in NEGATIVES}}
