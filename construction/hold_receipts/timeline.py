#!/usr/bin/env python3
"""EC343: explicitly *offline* signed receipt and revision-request timeline.

Each receiver signs a bounded, whole-original-SHA-pinned snapshot of the
EC342 hold/review/approval, or a successor request and independent approval.
An acknowledgement is receipt of named bytes, NOT agreement, a freeze, or
proof of actual delivery.  A withdrawal is a REQUEST, never a CAS deletion.
Competing signed successors are exposed and never silently linearized.
"""
from __future__ import annotations

from datetime import timedelta
import hmac
from typing import Any

from delivery_anchor import anchor
from offline_transfer_registry import registry as reg
from fork_case_transport import case
from independent_custody import ceremony
from offline_authority import authority as old
from issuer_root_rotation import rotation
from conflict_hold import hold as oldhold

ROSTER_SCHEMA='ces.ec343.externally_pinned_receiver_and_change_roster.v1'
BASE_SCHEMA='ces.ec343.pinned_base_hold_snapshot.v1'
NEXT_SCHEMA='ces.ec343.pinned_transition_snapshot.v1'
RECEIPT_CLAIM='ces.ec343.receiver_original_receipt_claim.v1'
RECEIPT_SCHEMA='ces.ec343.ed25519_receiver_original_receipt.v1'
ACK_SET_SCHEMA='ces.ec343.exact_signed_receiver_receipt_set.v1'
CHANGE_CLAIM='ces.ec343.offline_hold_change_request_claim.v1'
CHANGE_SCHEMA='ces.ec343.ed25519_hold_change_request.v1'
APPROVAL_CLAIM='ces.ec343.independent_change_review_claim.v1'
APPROVAL_SCHEMA='ces.ec343.ed25519_change_review_approval.v1'
RESULT_SCHEMA='ces.ec343.signed_hold_timeline_unresolved.v1'
DENIAL_SCHEMA='ces.ec343.signed_hold_timeline_denial.v1'
D_ACK=b'CES/EC343/IndependentReceiverReceipt/v1\0'
D_CHANGE=b'CES/EC343/OfflineHoldChangeRequest/v1\0'
D_APPROVAL=b'CES/EC343/IndependentChangeReview/v1\0'
ACTIONS=('request_revision','request_withdrawal','request_supersession')
MAX_VERSIONS=6
MAX_RECEIVERS=4
LIMIT=65000
REF_FIELDS=frozenset({'file','sha256'})
ROSTER_FIELDS=frozenset({'schema','case_id','case_nonce_sha256',
    'governance_roster_original_raw_sha256','hold_original_raw_sha256',
    'review_manifest_original_raw_sha256','approval_original_raw_sha256',
    'change_proposer','change_approver','receivers',
    'all_receivers_required','no_remote_execution_authorized'})
BASE_FIELDS=frozenset({'schema','sequence','case_id','roster_original_raw_sha256',
    'governance_roster_file','expected_governance_roster_sha256',
    'hold_file','expected_hold_sha256','review_manifest_file',
    'expected_review_manifest_sha256','approval_file','expected_approval_sha256'})
NEXT_FIELDS=frozenset({'schema','sequence','case_id','roster_original_raw_sha256',
    'previous_snapshot_file','expected_previous_snapshot_sha256',
    'previous_ack_set_file','expected_previous_ack_set_sha256',
    'change_file','expected_change_sha256','change_approval_file',
    'expected_change_approval_sha256'})
NEGATIVES=(
    'receiver_signature_proves_real_physical_delivery_or_institution',
    'acknowledgements_or_majority_execute_remote_hold',
    'withdrawal_request_releases_or_deletes_actual_remote_freeze',
    'revision_or_supersession_changes_prior_signed_originals',
    'signed_competing_transition_selects_a_winner',
    'complete_global_forks_revocations_or_latest_root_proven',
    'claimed_signed_utc_is_external_trusted_time',
    'all_real_institutional_signer_independence_proven',
    'complete_unmocked_ec317_ec318_old_production_proven',
    'any_remote_cas_worm_provider_or_business_write_performed')


def need(cond: Any, code: str, status: str='permission_denied') -> None:
    if cond is not True:
        raise anchor.AnchorError('EC343_'+code,status)


def same(a: Any,b: Any)->bool:
    return type(a) is str and type(b) is str and hmac.compare_digest(a,b)


def digest(path: str)->str:
    return case.sha(reg._private_read(path,LIMIT,'EC343_WHOLE_ORIGINAL'))


def read(path: str, expected: str, label: str)->dict:
    return oldhold._read(path,expected,'EC343_'+label,LIMIT)


def validate_refs(*pairs: tuple[str,str]):
    paths=[p for p,_ in pairs]
    rotation._paths(*paths)
    for _,sha in pairs:
        need(ceremony._sha(sha),'EXTERNAL_WHOLE_SHA_REQUIRED','invalid_input')


def late(pins: dict[str,str])->None:
    for path,sha in pins.items():
        need(same(digest(path),sha),'ORIGINAL_CHANGED_DURING_AUDIT')


def pin(pins: dict[str,str],path: str,sha: str)->None:
    validate_refs((path,sha))
    need(path not in pins or pins[path]==sha,
         'ONE_PATH_CANNOT_NAME_DIFFERENT_ORIGINALS','invalid_input')
    pins[path]=sha


def roster(path: str, sha: str, gov: dict|None=None)->dict:
    doc=read(path,sha,'RECEIVER_ROSTER')
    need(type(doc) is dict and set(doc)==ROSTER_FIELDS and
         doc.get('schema')==ROSTER_SCHEMA and
         ceremony._id(doc.get('case_id')) and
         all(ceremony._sha(doc.get(k)) for k in (
             'case_nonce_sha256','governance_roster_original_raw_sha256',
             'hold_original_raw_sha256','review_manifest_original_raw_sha256',
             'approval_original_raw_sha256')) and
         doc.get('all_receivers_required') is True and
         doc.get('no_remote_execution_authorized') is True and
         oldhold._actor(doc.get('change_proposer')) and
         oldhold._actor(doc.get('change_approver')) and
         type(doc.get('receivers')) is list and
         2<=len(doc['receivers'])<=MAX_RECEIVERS and
         all(oldhold._actor(a) for a in doc['receivers']),
         'EXACT_SEPARATELY_PINNED_RECEIVER_ROSTER_REQUIRED','invalid_input')
    actors=[doc['change_proposer'],doc['change_approver'],*doc['receivers']]
    for field in oldhold.ACTOR_FIELDS:
        need(len({a[field] for a in actors})==len(actors),
             'RECEIVER_AND_CHANGE_ROLE_REUSE_DENIED','invalid_input')
    if gov is not None:
        need(doc['case_id']==gov['case_id'] and
             ceremony._sha(doc['governance_roster_original_raw_sha256']),
             'EXACT_EC342_CASE_REQUIRED','invalid_input')
        previous=[gov['initiator'],gov['external_approver'],*gov['reviewers']]
        for field in oldhold.ACTOR_FIELDS:
            forbidden={a[field] for a in previous}
            need(all(a[field] not in forbidden for a in actors),
                 'EC342_ROLE_REUSED_AS_EC343_RECEIVER_OR_CHANGE_AUTHORITY',
                 'invalid_input')
    return doc


def _base_document(r: dict, roster_sha: str, *, governance_roster_file: str,
                   hold_file: str, review_manifest_file: str, approval_file: str)->dict:
    return {'schema':BASE_SCHEMA,'sequence':0,'case_id':r['case_id'],
        'roster_original_raw_sha256':roster_sha,
        'governance_roster_file':governance_roster_file,
        'expected_governance_roster_sha256':r['governance_roster_original_raw_sha256'],
        'hold_file':hold_file,'expected_hold_sha256':r['hold_original_raw_sha256'],
        'review_manifest_file':review_manifest_file,
        'expected_review_manifest_sha256':r['review_manifest_original_raw_sha256'],
        'approval_file':approval_file,'expected_approval_sha256':r['approval_original_raw_sha256']}


def _base_local(doc: dict,r: dict,roster_sha: str,pins: dict)->dict:
    need(set(doc)==BASE_FIELDS and doc.get('schema')==BASE_SCHEMA and
         type(doc.get('sequence')) is int and doc['sequence']==0,
         'EXACT_BASE_SNAPSHOT_REQUIRED','invalid_input')
    expected=_base_document(r,roster_sha,
          governance_roster_file=doc['governance_roster_file'],
          hold_file=doc['hold_file'],
          review_manifest_file=doc['review_manifest_file'],
          approval_file=doc['approval_file'])
    need(doc==expected,'BASE_SNAPSHOT_MUST_BIND_EC342_UNCHANGED_WHOLE_ORIGINALS',
         'invalid_input')
    validate_refs(*[(doc[k],doc[v]) for k,v in (
        ('governance_roster_file','expected_governance_roster_sha256'),
        ('hold_file','expected_hold_sha256'),
        ('review_manifest_file','expected_review_manifest_sha256'),
        ('approval_file','expected_approval_sha256'))])
    gov=oldhold._governance(doc['governance_roster_file'],doc['expected_governance_roster_sha256'])
    need(gov['case_id']==r['case_id'],'EC342_CASE_ID_MISMATCH','invalid_input')
    # Local writers do not turn their own roster into a source of trusted actor identity.
    previous=[gov['initiator'],gov['external_approver'],*gov['reviewers']]
    new=[r['change_proposer'],r['change_approver'],*r['receivers']]
    for field in oldhold.ACTOR_FIELDS:
        banned={a[field] for a in previous}
        need(all(a[field] not in banned for a in new),
             'EC342_SIGNING_ROLE_REUSED_BY_RECEIVER_OR_CHANGE_ROLE','invalid_input')
    base_review,hold,support,_,refs,pins_reviews=oldhold._review_manifest(
        doc['review_manifest_file'],doc['expected_review_manifest_sha256'],
        gov,doc['expected_governance_roster_sha256'])
    need(support>=gov['required_support_quorum'] and
         base_review['hold_file']==doc['hold_file'] and
         same(base_review['expected_hold_sha256'],doc['expected_hold_sha256']),
         'BASE_HOLD_EXACT_APPROVED_REVIEW_AND_QUORUM_REQUIRED')
    approval=oldhold._read(doc['approval_file'],doc['expected_approval_sha256'],
                           'EC343_BASE_APPROVAL')
    claim=approval.get('claim') if type(approval) is dict else None
    need(type(claim) is dict and ceremony._utc(claim.get('approval_reported_utc')),
         'BASE_INDEPENDENT_APPROVAL_CLAIM_REQUIRED','invalid_input')
    expected=oldhold._approval_claim(gov,doc['expected_governance_roster_sha256'],
         doc['expected_review_manifest_sha256'],doc['expected_hold_sha256'],
         hold,support,claim['approval_reported_utc'])
    need(claim==expected,'BASE_APPROVAL_EXACT_REVIEW_SET_MISMATCH','invalid_input')
    oldhold._verify_signed(approval,oldhold.APPROVAL_SCHEMA,oldhold.DOMAIN_APPROVAL,
                           gov['external_approver']['public_hex'],'EC343_BASE_APPROVAL')
    for ref in oldhold._read(doc['review_manifest_file'],
            doc['expected_review_manifest_sha256'],'EC343_REVIEWS')['attestations']:
        vote=oldhold._read(ref['file'],ref['sha256'],'EC343_VOTE')
        need(old._time(vote['claim']['reviewer_reported_utc'])<=
             old._time(claim['approval_reported_utc']),
             'BASE_APPROVAL_PRECEDES_VOTE','invalid_input')
    for k,v in (('governance_roster_file','expected_governance_roster_sha256'),
                ('hold_file','expected_hold_sha256'),
                ('review_manifest_file','expected_review_manifest_sha256'),
                ('approval_file','expected_approval_sha256')):
        pin(pins,doc[k],doc[v])
    for p,s in zip(refs,pins_reviews,strict=True):pin(pins,p,s)
    return {'sequence':0,'status':'base_approved','kind':'base',
        'last_approval_sha':doc['expected_approval_sha256'],
        'last_approval_utc':claim['approval_reported_utc'],
        'hold_window':(hold['issued_utc'],hold['expires_utc']),
        'base_doc':doc,'history_nonce':set(),
        'last_snapshot_sha':None,'last_ack_utc':claim['approval_reported_utc']}


def _signed(doc: dict,schema: str,domain: bytes,public_hex: str,label: str):
    oldhold._verify_signed(doc,schema,domain,public_hex,'EC343_'+label)


def _ack_claim(r:dict,roster_sha:str,snapshot_sha:str,seq:int,
               actor:dict,received_utc:str)->dict:
    need(ceremony._utc(received_utc),'RECEIVER_UTC_REQUIRED','invalid_input')
    return {'schema':RECEIPT_CLAIM,'case_id':r['case_id'],
        'roster_original_raw_sha256':roster_sha,
        'snapshot_original_raw_sha256':snapshot_sha,'sequence':seq,
        'base_hold_original_raw_sha256':r['hold_original_raw_sha256'],
        'base_review_original_raw_sha256':r['review_manifest_original_raw_sha256'],
        'base_approval_original_raw_sha256':r['approval_original_raw_sha256'],
        'receiver_id':actor['signer_id'],
        'receiver_public_hex':actor['public_hex'],
        'receiver_organization_id':actor['organization_id'],
        'received_utc':received_utc,
        'scope':'received_pinned_offline_snapshot_originals_only',
        'not_a_provider_freeze_or_withdrawal':True}


def _ackset(path:str,sha:str,snapshot_path:str,snapshot_sha:str,
            r:dict,roster_sha:str,seq:int,window:tuple[str,str],
            pins:dict, not_before_utc:str,
            evaluation_utc:str|None=None)->tuple[int,str]:
    doc=read(path,sha,'ACK_SET')
    need(type(doc) is dict and set(doc)=={'schema','snapshot_file',
         'expected_snapshot_sha256','receipts'} and doc.get('schema')==ACK_SET_SCHEMA and
         doc.get('snapshot_file')==snapshot_path and
         doc.get('expected_snapshot_sha256')==snapshot_sha and
         type(doc.get('receipts')) is list and len(doc['receipts'])<=len(r['receivers']),
         'ACK_SET_MUST_BIND_EXACT_SNAPSHOT_AND_BOUNDED_RECEIPTS','invalid_input')
    pin(pins,path,sha)
    byid={a['signer_id']:a for a in r['receivers']}
    seen=set(); times=[]
    for ref in doc['receipts']:
        need(type(ref) is dict and set(ref)==REF_FIELDS and
             ceremony._sha(ref.get('sha256')),
             'PINNED_RECEIVER_RECEIPT_FILE_REQUIRED','invalid_input')
        pin(pins,ref['file'],ref['sha256'])
        signed=read(ref['file'],ref['sha256'],'RECEIPT')
        c=signed.get('claim') if type(signed) is dict else None
        rid=c.get('receiver_id') if type(c) is dict else None
        need(type(rid) is str and rid in byid and rid not in seen,
             'ONE_RECEIPT_PER_REGISTERED_INDEPENDENT_RECEIVER','invalid_input')
        seen.add(rid)
        t=c.get('received_utc')
        expected=_ack_claim(r,roster_sha,snapshot_sha,seq,byid[rid],t)
        need(c==expected,'ACKNOWLEDGEMENT_CLAIM_NOT_EXACT','invalid_input')
        _signed(signed,RECEIPT_SCHEMA,D_ACK,byid[rid]['public_hex'],'RECEIVER')
        need(old._time(window[0])<=old._time(t)<old._time(window[1]) and
             old._time(not_before_utc)<=old._time(t),
             'STALE_OR_PREAPPROVAL_RECEIVER_ACK','invalid_input')
        if evaluation_utc is not None:
            need(old._time(t)<=old._time(evaluation_utc),
                 'RECEIVER_ACK_AFTER_INDEPENDENT_EVALUATION','invalid_input')
        times.append(t)
    return len(seen),max(times) if times else window[0]


def _transition_claim(r:dict,roster_sha:str,parent:dict,parent_sha:str,
                      parent_ack_sha:str,kind:str,summary_sha:str,nonce:str,
                      successor_case_id:str,issued_utc:str)->dict:
    need(kind in ACTIONS and ceremony._sha(summary_sha) and ceremony._sha(nonce) and
         ceremony._utc(issued_utc) and
         ((kind=='request_supersession' and ceremony._id(successor_case_id) and
           successor_case_id!=r['case_id']) or
          (kind!='request_supersession' and successor_case_id=='')),
         'EXACT_CHANGE_ACTION_NONCE_AND_SUPERSESSION_TARGET_REQUIRED','invalid_input')
    need(old._time(parent['last_ack_utc'])<=old._time(issued_utc)<
         old._time(parent['hold_window'][1]),
         'CHANGE_MUST_FOLLOW_RECEIPT_WITHIN_SIGNED_HOLD_WINDOW','invalid_input')
    actor=r['change_proposer']
    return {'schema':CHANGE_CLAIM,'case_id':r['case_id'],
        'case_nonce_sha256':r['case_nonce_sha256'],
        'roster_original_raw_sha256':roster_sha,
        'base_hold_original_raw_sha256':r['hold_original_raw_sha256'],
        'base_approval_original_raw_sha256':r['approval_original_raw_sha256'],
        'sequence':parent['sequence']+1,
        'previous_snapshot_original_raw_sha256':parent_sha,
        'previous_ack_set_original_raw_sha256':parent_ack_sha,
        'previous_approval_original_raw_sha256':parent['last_approval_sha'],
        'change_request_kind':kind,'change_summary_sha256':summary_sha,
        'change_nonce_sha256':nonce,'requested_successor_case_id':successor_case_id,
        'proposer_id':actor['signer_id'],'proposer_public_hex':actor['public_hex'],
        'proposer_organization_id':actor['organization_id'],
        'issued_utc':issued_utc,'only_an_offline_request_not_execution':True,
        'both_original_sibling_successors_remain_unresolved':True}


def _approval_claim(r:dict,roster_sha:str,parent:dict,proposal_sha:str,
                    proposal:dict,approved_utc:str)->dict:
    need(ceremony._utc(approved_utc) and
         old._time(proposal['issued_utc'])<=old._time(approved_utc)<
         old._time(parent['hold_window'][1]),
         'CHANGE_APPROVAL_CANNOT_PRECEDE_PROPOSAL_OR_EXPIRE','invalid_input')
    actor=r['change_approver']
    return {'schema':APPROVAL_CLAIM,'case_id':r['case_id'],
        'roster_original_raw_sha256':roster_sha,
        'sequence':proposal['sequence'],
        'change_original_raw_sha256':proposal_sha,
        'previous_snapshot_original_raw_sha256':proposal['previous_snapshot_original_raw_sha256'],
        'previous_ack_set_original_raw_sha256':proposal['previous_ack_set_original_raw_sha256'],
        'previous_approval_original_raw_sha256':proposal['previous_approval_original_raw_sha256'],
        'base_approval_original_raw_sha256':r['approval_original_raw_sha256'],
        'approval_reported_utc':approved_utc,
        'approver_id':actor['signer_id'],'approver_public_hex':actor['public_hex'],
        'approver_organization_id':actor['organization_id'],
        'decision':'review_of_request_only_not_authorization_to_execute',
        'no_actual_hold_release_revision_or_winner':True}


def _validate_change(change_file:str,change_sha:str,approval_file:str,
                     approval_sha:str,parent:dict,parent_sha:str,parent_ack_sha:str,
                     r:dict,roster_sha:str,pins:dict)->tuple[dict,dict]:
    pin(pins,change_file,change_sha);pin(pins,approval_file,approval_sha)
    signed=read(change_file,change_sha,'CHANGE')
    c=signed.get('claim') if type(signed) is dict else None
    need(type(c) is dict,'SIGNATURE_CHANGE_CLAIM_REQUIRED','invalid_input')
    expected=_transition_claim(r,roster_sha,parent,parent_sha,parent_ack_sha,
        c.get('change_request_kind'),c.get('change_summary_sha256'),
        c.get('change_nonce_sha256'),c.get('requested_successor_case_id'),
        c.get('issued_utc'))
    need(c==expected,'CHANGE_CLAIM_AND_PREVIOUS_APPROVAL_NOT_EXACT','invalid_input')
    need(c['change_nonce_sha256'] not in parent['history_nonce'],
         'CROSS_VERSION_CHANGE_NONCE_REPLAY_DENIED','invalid_input')
    _signed(signed,CHANGE_SCHEMA,D_CHANGE,r['change_proposer']['public_hex'],
            'CHANGE_PROPOSER')
    approved=read(approval_file,approval_sha,'CHANGE_APPROVAL')
    a=approved.get('claim') if type(approved) is dict else None
    need(type(a) is dict,'SIGNATURE_CHANGE_APPROVAL_CLAIM_REQUIRED','invalid_input')
    expected=_approval_claim(r,roster_sha,parent,change_sha,c,
                             a.get('approval_reported_utc'))
    need(a==expected,'CHANGE_APPROVER_MUST_BIND_EXACT_PREDECESSOR_AND_REQUEST',
         'invalid_input')
    _signed(approved,APPROVAL_SCHEMA,D_APPROVAL,
            r['change_approver']['public_hex'],'CHANGE_APPROVER')
    return c,a


def _load_chain(snapshot_path:str,snapshot_sha:str,r:dict,roster_sha:str,
                pins:dict,*,depth:int=0)->dict:
    need(depth<=MAX_VERSIONS,'MAX_SNAPSHOT_CHAIN_DEPTH_EXCEEDED','invalid_input')
    pin(pins,snapshot_path,snapshot_sha)
    doc=read(snapshot_path,snapshot_sha,'SNAPSHOT')
    need(type(doc) is dict,'EXACT_SNAPSHOT_REQUIRED','invalid_input')
    if doc.get('schema')==BASE_SCHEMA:
        state=_base_local(doc,r,roster_sha,pins)
    else:
        need(set(doc)==NEXT_FIELDS and doc.get('schema')==NEXT_SCHEMA and
             type(doc.get('sequence')) is int and
             1<=doc['sequence']<=MAX_VERSIONS and
             doc.get('case_id')==r['case_id'] and
             doc.get('roster_original_raw_sha256')==roster_sha,
             'EXACT_LIMITED_TRANSITION_SNAPSHOT_REQUIRED','invalid_input')
        validate_refs(*[(doc[k],doc[v]) for k,v in (
             ('previous_snapshot_file','expected_previous_snapshot_sha256'),
             ('previous_ack_set_file','expected_previous_ack_set_sha256'),
             ('change_file','expected_change_sha256'),
             ('change_approval_file','expected_change_approval_sha256'))])
        parent=_load_chain(doc['previous_snapshot_file'],
                    doc['expected_previous_snapshot_sha256'],r,roster_sha,pins,
                    depth=depth+1)
        need(doc['sequence']==parent['sequence']+1,
             'SNAPSHOT_SEQUENCE_MUST_BE_CONTIGUOUS','invalid_input')
        count,ack_time=_ackset(doc['previous_ack_set_file'],
            doc['expected_previous_ack_set_sha256'],
            doc['previous_snapshot_file'],doc['expected_previous_snapshot_sha256'],
            r,roster_sha,parent['sequence'],parent['hold_window'],pins,
            parent['last_approval_utc'])
        need(count==len(r['receivers']),
             'ALL_PRIOR_REGISTERED_RECEIVERS_MUST_SIGN_BEFORE_NEXT_CHANGE',
             'permission_denied')
        parent={**parent,'last_ack_utc':max(parent['last_approval_utc'],ack_time)}
        c,a=_validate_change(doc['change_file'],doc['expected_change_sha256'],
             doc['change_approval_file'],doc['expected_change_approval_sha256'],
             parent,doc['expected_previous_snapshot_sha256'],
             doc['expected_previous_ack_set_sha256'],r,roster_sha,pins)
        history=set(parent['history_nonce']);history.add(c['change_nonce_sha256'])
        state={**parent,'sequence':doc['sequence'],'status':c['change_request_kind'],
               'kind':'change','last_approval_sha':doc['expected_change_approval_sha256'],
               'last_approval_utc':a['approval_reported_utc'],
               'last_ack_utc':a['approval_reported_utc'],'history_nonce':history,
               'change_sha':doc['expected_change_sha256'],
               'parent_sha':doc['expected_previous_snapshot_sha256'],
               'change_approval_sha':doc['expected_change_approval_sha256']}
    state['last_snapshot_sha']=snapshot_sha
    state['last_snapshot_path']=snapshot_path
    return state


def _candidate(command:str,sha:str)->dict:
    return {'schema':RESULT_SCHEMA,'command':command,'exit_code':2,
        'status':'owner_private_candidate_untrusted',
        'candidate_original_raw_sha256':sha,'offline_unresolved_exit_code':2,
        **{k:False for k in NEGATIVES}}


def _write(out:str,doc:dict,inputs:dict[str,str],private:str|None=None)->dict:
    rotation._paths(out,*inputs.keys(),*([private] if private else []))
    return_sha=old._write_and_check(out,doc,
        [*inputs.keys(),*([private] if private else [])],
        late_recheck=lambda:late(inputs))
    return return_sha


def assemble_base(*,out:str,roster_file:str,expected_roster_sha256:str,
                  governance_roster_file:str,hold_file:str,
                  review_manifest_file:str,approval_file:str)->dict:
    validate_refs((roster_file,expected_roster_sha256))
    r=roster(roster_file,expected_roster_sha256)
    doc=_base_document(r,expected_roster_sha256,
       governance_roster_file=governance_roster_file,hold_file=hold_file,
       review_manifest_file=review_manifest_file,approval_file=approval_file)
    pins={roster_file:expected_roster_sha256}
    _base_local(doc,r,expected_roster_sha256,pins)
    return _candidate('assemble-base',_write(out,doc,pins))


def sign_ack(*,out:str,private_key_file:str,roster_file:str,
             expected_roster_sha256:str,snapshot_file:str,
             expected_snapshot_sha256:str,received_utc:str)->dict:
    r=roster(roster_file,expected_roster_sha256)
    pins={roster_file:expected_roster_sha256}
    state=_load_chain(snapshot_file,expected_snapshot_sha256,r,
                      expected_roster_sha256,pins)
    key,pub=rotation._private_key_public(private_key_file)
    receiver=[a for a in r['receivers'] if same(pub,a['public_hex'])]
    need(len(receiver)==1,'ONLY_REGISTERED_RECEIVER_PRIVATE_KEY_CAN_ACK')
    need(old._time(state['last_approval_utc'])<=old._time(received_utc)<
         old._time(state['hold_window'][1]),
         'RECEIPT_MUST_FOLLOW_APPROVAL_AND_PRECEDE_HOLD_EXPIRY',
         'invalid_input')
    c=_ack_claim(r,expected_roster_sha256,expected_snapshot_sha256,
                 state['sequence'],receiver[0],received_utc)
    doc={'schema':RECEIPT_SCHEMA,'claim':c,
         'signature_ed25519':key.sign(D_ACK+reg.canonical(c)).hex()}
    return _candidate('sign-ack',_write(out,doc,pins,private_key_file))


def assemble_ack_set(*,out:str,roster_file:str,expected_roster_sha256:str,
                     snapshot_file:str,expected_snapshot_sha256:str,
                     receipt_files:list[str],receipt_shas:list[str])->dict:
    need(type(receipt_files) is list and type(receipt_shas) is list and
         len(receipt_files)==len(receipt_shas) and len(receipt_files)<=MAX_RECEIVERS,
         'MATCHED_BOUNDED_RECEIVER_RECEIPTS_REQUIRED','invalid_input')
    r=roster(roster_file,expected_roster_sha256)
    pins={roster_file:expected_roster_sha256}
    state=_load_chain(snapshot_file,expected_snapshot_sha256,r,
                      expected_roster_sha256,pins)
    doc={'schema':ACK_SET_SCHEMA,'snapshot_file':snapshot_file,
         'expected_snapshot_sha256':expected_snapshot_sha256,
         'receipts':[{'file':f,'sha256':s} for f,s in zip(receipt_files,receipt_shas,strict=True)]}
    # Validate an ephemeral index without writing it or trusting a self-pin.
    _inspect_ack_doc(doc,snapshot_file,expected_snapshot_sha256,r,
                     expected_roster_sha256,state,pins)
    return _candidate('assemble-ack-set',_write(out,doc,pins))


def _inspect_ack_doc(doc:dict,snapshot_file:str,snapshot_sha:str,r:dict,
                     roster_sha:str,state:dict,pins:dict)->tuple[int,str]:
    # Use the same validator as for a pinned file, without a temporary disk file.
    need(type(doc) is dict and set(doc)=={'schema','snapshot_file',
        'expected_snapshot_sha256','receipts'} and doc.get('schema')==ACK_SET_SCHEMA and
        doc.get('snapshot_file')==snapshot_file and
        doc.get('expected_snapshot_sha256')==snapshot_sha and
        type(doc.get('receipts')) is list and len(doc['receipts'])<=len(r['receivers']),
        'EXACT_RECEIVER_SET_STRUCTURE_REQUIRED','invalid_input')
    seen=set();latest=state['last_approval_utc']
    byid={a['signer_id']:a for a in r['receivers']}
    for ref in doc['receipts']:
        need(type(ref) is dict and set(ref)==REF_FIELDS and
             ceremony._sha(ref.get('sha256')),
             'PINNED_RECEIVER_ORIGINAL_REQUIRED','invalid_input')
        pin(pins,ref['file'],ref['sha256'])
        signed=read(ref['file'],ref['sha256'],'ACK_SET_MEMBER')
        c=signed.get('claim') if type(signed) is dict else None
        rid=c.get('receiver_id') if type(c) is dict else None
        need(type(rid) is str and rid in byid and rid not in seen,
             'DUPLICATE_OR_UNREGISTERED_RECEIVER','invalid_input')
        seen.add(rid)
        expected=_ack_claim(r,roster_sha,snapshot_sha,state['sequence'],byid[rid],
                             c.get('received_utc'))
        need(c==expected,'ACK_MEMBER_CLAIM_NOT_EXACT','invalid_input')
        _signed(signed,RECEIPT_SCHEMA,D_ACK,byid[rid]['public_hex'],'RECEIVER')
        need(old._time(state['last_approval_utc'])<=old._time(c['received_utc'])<
             old._time(state['hold_window'][1]),
             'RECEIPT_BEFORE_APPROVAL_OR_AFTER_HOLD_EXPIRY','invalid_input')
        if old._time(c['received_utc'])>old._time(latest):latest=c['received_utc']
    return len(seen),latest


def issue_change(*,out:str,private_key_file:str,roster_file:str,
                 expected_roster_sha256:str,previous_snapshot_file:str,
                 expected_previous_snapshot_sha256:str,previous_ack_set_file:str,
                 expected_previous_ack_set_sha256:str,request_kind:str,
                 change_summary_sha256:str,change_nonce_sha256:str,
                 requested_successor_case_id:str,issued_utc:str)->dict:
    r=roster(roster_file,expected_roster_sha256)
    pins={roster_file:expected_roster_sha256}
    parent=_load_chain(previous_snapshot_file,expected_previous_snapshot_sha256,
                       r,expected_roster_sha256,pins)
    count,latest=_ackset(previous_ack_set_file,expected_previous_ack_set_sha256,
             previous_snapshot_file,expected_previous_snapshot_sha256,r,
             expected_roster_sha256,parent['sequence'],parent['hold_window'],pins,
             parent['last_approval_utc'])
    need(count==len(r['receivers']),
         'NO_REVISION_UNTIL_EVERY_DECLARED_RECEIVER_ACKNOWLEDGES_PARENT')
    need(parent['sequence']<MAX_VERSIONS,'MAX_BOUNDED_VERSIONS_REACHED','invalid_input')
    key,pub=rotation._private_key_public(private_key_file)
    need(same(pub,r['change_proposer']['public_hex']),
         'ONLY_INDEPENDENT_CHANGE_PROPOSER_PRIVATE_KEY')
    parent={**parent,'last_ack_utc':max(latest,parent['last_approval_utc'])}
    c=_transition_claim(r,expected_roster_sha256,parent,
           expected_previous_snapshot_sha256,expected_previous_ack_set_sha256,
           request_kind,change_summary_sha256,change_nonce_sha256,
           requested_successor_case_id,issued_utc)
    need(change_nonce_sha256 not in parent['history_nonce'],
         'CROSS_VERSION_NONCE_MUST_BE_NEW','invalid_input')
    signed={'schema':CHANGE_SCHEMA,'claim':c,
            'signature_ed25519':key.sign(D_CHANGE+reg.canonical(c)).hex()}
    return _candidate('issue-change',_write(out,signed,pins,private_key_file))


def approve_change(*,out:str,private_key_file:str,roster_file:str,
                   expected_roster_sha256:str,previous_snapshot_file:str,
                   expected_previous_snapshot_sha256:str,previous_ack_set_file:str,
                   expected_previous_ack_set_sha256:str,change_file:str,
                   expected_change_sha256:str,approval_reported_utc:str)->dict:
    r=roster(roster_file,expected_roster_sha256)
    pins={roster_file:expected_roster_sha256}
    parent=_load_chain(previous_snapshot_file,expected_previous_snapshot_sha256,
                       r,expected_roster_sha256,pins)
    count,latest=_ackset(previous_ack_set_file,expected_previous_ack_set_sha256,
            previous_snapshot_file,expected_previous_snapshot_sha256,r,
            expected_roster_sha256,parent['sequence'],parent['hold_window'],pins,
             parent['last_approval_utc'])
    need(count==len(r['receivers']),'APPROVER_CANNOT_SKIP_PARENT_ACKS')
    parent={**parent,'last_ack_utc':max(parent['last_approval_utc'],latest)}
    pin(pins,change_file,expected_change_sha256)
    signed=read(change_file,expected_change_sha256,'CHANGE_BEFORE_APPROVAL')
    c=signed.get('claim') if type(signed) is dict else None
    need(type(c) is dict,'CHANGE_CLAIM_REQUIRED','invalid_input')
    expected=_transition_claim(r,expected_roster_sha256,parent,
        expected_previous_snapshot_sha256,expected_previous_ack_set_sha256,
        c.get('change_request_kind'),c.get('change_summary_sha256'),
        c.get('change_nonce_sha256'),c.get('requested_successor_case_id'),c.get('issued_utc'))
    need(c==expected and c['change_nonce_sha256'] not in parent['history_nonce'],
         'EXACT_FRESH_CHANGE_PRECONDITION_REQUIRED','invalid_input')
    _signed(signed,CHANGE_SCHEMA,D_CHANGE,r['change_proposer']['public_hex'],
            'CHANGE_PROPOSER')
    key,pub=rotation._private_key_public(private_key_file)
    need(same(pub,r['change_approver']['public_hex']),
         'ONLY_INDEPENDENT_CHANGE_APPROVER_PRIVATE_KEY')
    claim=_approval_claim(r,expected_roster_sha256,parent,
                          expected_change_sha256,c,approval_reported_utc)
    doc={'schema':APPROVAL_SCHEMA,'claim':claim,
         'signature_ed25519':key.sign(D_APPROVAL+reg.canonical(claim)).hex()}
    return _candidate('approve-change',_write(out,doc,pins,private_key_file))


def assemble_snapshot(*,out:str,roster_file:str,expected_roster_sha256:str,
                      previous_snapshot_file:str,expected_previous_snapshot_sha256:str,
                      previous_ack_set_file:str,expected_previous_ack_set_sha256:str,
                      change_file:str,expected_change_sha256:str,
                      change_approval_file:str,expected_change_approval_sha256:str)->dict:
    r=roster(roster_file,expected_roster_sha256)
    pins={roster_file:expected_roster_sha256}
    parent=_load_chain(previous_snapshot_file,expected_previous_snapshot_sha256,
                       r,expected_roster_sha256,pins)
    count,latest=_ackset(previous_ack_set_file,expected_previous_ack_set_sha256,
             previous_snapshot_file,expected_previous_snapshot_sha256,r,
             expected_roster_sha256,parent['sequence'],parent['hold_window'],pins,
             parent['last_approval_utc'])
    need(count==len(r['receivers']),'SNAPSHOT_REQUIRES_COMPLETE_PARENT_RECEIPTS')
    parent={**parent,'last_ack_utc':max(latest,parent['last_approval_utc'])}
    _validate_change(change_file,expected_change_sha256,change_approval_file,
       expected_change_approval_sha256,parent,expected_previous_snapshot_sha256,
       expected_previous_ack_set_sha256,r,expected_roster_sha256,pins)
    need(parent['sequence']<MAX_VERSIONS,'MAX_VERSIONS_EXCEEDED','invalid_input')
    doc={'schema':NEXT_SCHEMA,'sequence':parent['sequence']+1,'case_id':r['case_id'],
         'roster_original_raw_sha256':expected_roster_sha256,
         'previous_snapshot_file':previous_snapshot_file,
         'expected_previous_snapshot_sha256':expected_previous_snapshot_sha256,
         'previous_ack_set_file':previous_ack_set_file,
         'expected_previous_ack_set_sha256':expected_previous_ack_set_sha256,
         'change_file':change_file,'expected_change_sha256':expected_change_sha256,
         'change_approval_file':change_approval_file,
         'expected_change_approval_sha256':expected_change_approval_sha256}
    return _candidate('assemble-snapshot',_write(out,doc,pins))


def _reserved_signers(r:dict,gov:dict,manifest:dict)->None:
    """Prevent EC343 text-role reuse with already verified lineage identities."""
    actors=[r['change_proposer'],r['change_approver'],*r['receivers']]
    reserved={f:set() for f in ('signer_id','public_hex','organization_id')}
    def collect(items):
        for item in items:
            for fromkey,tokey in (('actor_id','signer_id'),('issuer_id','signer_id'),
                    ('observer_id','signer_id'),('public_hex','public_hex'),
                    ('issuer_public_hex','public_hex'),('observer_public_hex','public_hex'),
                    ('organization_id','organization_id'),
                    ('subject_organization_id','organization_id'),
                    ('observer_organization_id','organization_id')):
                if type(item.get(fromkey)) is str:
                    reserved[tokey].add(item[fromkey])
    base=manifest['context']
    policy=oldhold._read(base['policy_file'],base['expected_policy_sha256'],
                         'EC343_POLICY')
    auth=oldhold._read(base['authority_roster_file'],
                       base['expected_authority_roster_sha256'],'EC343_ISSUERS')
    collect(policy['actors']);collect(auth['issuers'])
    for item in [*manifest['hops'],*(x['hop'] for x in manifest['forks'])]:
        root=oldhold._read(item['successor_roster_file'],
                           item['expected_successor_roster_sha256'],'EC343_ROOT')
        obs=oldhold._read(item['observer_roster_file'],
                          item['expected_observer_roster_sha256'],'EC343_OBSERVER')
        collect(root['issuers']);collect([obs])
    need(all(a[f] not in reserved[f] for a in actors for f in reserved),
         'EC343_RECEIVER_OR_CHANGE_REUSES_SIGNED_ROOT_ACTOR_WITNESS_OR_ISSUER',
         'invalid_input')


def verify_timeline(*,manifest_file:str,expected_manifest_sha256:str,
       expected_current_root_sha256:str,expected_current_root_epoch:int,
       minimum_acceptable_epoch:int,current_root_evaluation_utc:str,
       governance_roster_file:str,expected_governance_roster_sha256:str,
       review_manifest_file:str,expected_review_manifest_sha256:str,
       approval_file:str,expected_approval_sha256:str,
       hold_evaluation_utc:str,roster_file:str,expected_roster_sha256:str,
       head_snapshot_file:str,expected_head_snapshot_sha256:str,
       head_ack_set_file:str,expected_head_ack_set_sha256:str,
       timeline_evaluation_utc:str,
       competing_snapshot_file:str|None=None,
       expected_competing_snapshot_sha256:str|None=None,
       competing_ack_set_file:str|None=None,
       expected_competing_ack_set_sha256:str|None=None)->dict:
    need((competing_snapshot_file is None)==(expected_competing_snapshot_sha256 is None) and
         (competing_ack_set_file is None)==(expected_competing_ack_set_sha256 is None) and
         (competing_snapshot_file is None)==(competing_ack_set_file is None) and
         ceremony._utc(timeline_evaluation_utc) and
         ceremony._utc(hold_evaluation_utc) and
         ceremony._utc(current_root_evaluation_utc) and
         old._time(hold_evaluation_utc)<=old._time(timeline_evaluation_utc) and
         old._time(current_root_evaluation_utc)<=old._time(timeline_evaluation_utc),
         'EXACT_OPTIONAL_COMPETING_PAIR_AND_EVALUATION_REQUIRED','invalid_input')
    pinset={}
    for p,s in ((manifest_file,expected_manifest_sha256),
                (governance_roster_file,expected_governance_roster_sha256),
                (review_manifest_file,expected_review_manifest_sha256),
                (approval_file,expected_approval_sha256),
                (roster_file,expected_roster_sha256)):
        pin(pinset,p,s)
    gov=oldhold._governance(governance_roster_file,expected_governance_roster_sha256)
    r=roster(roster_file,expected_roster_sha256,gov)
    need(r['governance_roster_original_raw_sha256']==expected_governance_roster_sha256 and
         r['review_manifest_original_raw_sha256']==expected_review_manifest_sha256 and
         r['approval_original_raw_sha256']==expected_approval_sha256,
         'ROSTER_DOES_NOT_MATCH_EXTERNALLY_PINNED_EC342_CASE','invalid_input')
    legacy=oldhold.verify_hold(manifest_file=manifest_file,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_current_root_sha256=expected_current_root_sha256,
        expected_current_root_epoch=expected_current_root_epoch,
        minimum_acceptable_epoch=minimum_acceptable_epoch,
        current_root_evaluation_utc=current_root_evaluation_utc,
        governance_roster_file=governance_roster_file,
        expected_governance_roster_sha256=expected_governance_roster_sha256,
        review_manifest_file=review_manifest_file,
        expected_review_manifest_sha256=expected_review_manifest_sha256,
        hold_evaluation_utc=hold_evaluation_utc,
        approval_file=approval_file,expected_approval_sha256=expected_approval_sha256)
    need(legacy['status']=='hold_verified_unresolved' and
         legacy['hold_original_raw_sha256']==r['hold_original_raw_sha256'] and
         legacy['separate_approver_signature_verified'] is True and
         legacy['signed_sibling_fork_and_historical_full_replay_verified'] is True,
         'EC342_APPROVED_FULL_REAL_SIGNED_FORK_REPLAY_REQUIRED')
    # EC342 has already performed full lineage verification. Re-read the signed
    # manifest here solely to constrain new names/keys/orgs against older roles.
    manifest=oldhold._read(manifest_file,expected_manifest_sha256,
                           'EC343_LINEAGE_ROLES',oldhold.lineage.MAX_MANIFEST_BYTES)
    _reserved_signers(r,gov,manifest)
    main=_load_chain(head_snapshot_file,expected_head_snapshot_sha256,
                     r,expected_roster_sha256,pinset)
    need(main['base_doc']['governance_roster_file']==governance_roster_file and
         main['base_doc']['review_manifest_file']==review_manifest_file and
         main['base_doc']['approval_file']==approval_file,
         'BASE_SNAPSHOT_ABSOLUTE_ORIGINAL_PATHS_NOT_INDEPENDENTLY_PINNED',
         'invalid_input')
    count,latest=_ackset(head_ack_set_file,expected_head_ack_set_sha256,
          head_snapshot_file,expected_head_snapshot_sha256,r,expected_roster_sha256,
          main['sequence'],main['hold_window'],pinset,
          main['last_approval_utc'],timeline_evaluation_utc)
    need(old._time(main['last_approval_utc'])<=old._time(timeline_evaluation_utc),
         'HEAD_CHANGE_APPROVAL_IN_RECEIVER_FUTURE','invalid_input')
    sibling=False;sibling_ack=0;other=None
    if competing_snapshot_file is not None:
        other=_load_chain(competing_snapshot_file,expected_competing_snapshot_sha256,
                          r,expected_roster_sha256,pinset)
        sibling_ack,_=_ackset(competing_ack_set_file,expected_competing_ack_set_sha256,
           competing_snapshot_file,expected_competing_snapshot_sha256,r,
           expected_roster_sha256,other['sequence'],other['hold_window'],
           pinset,other['last_approval_utc'],timeline_evaluation_utc)
        need(main['sequence']>0 and other['sequence']==main['sequence'] and
             main['parent_sha']==other['parent_sha'] and
             expected_head_snapshot_sha256!=expected_competing_snapshot_sha256 and
             main['change_sha']!=other['change_sha'],
             'ONLY_INDEPENDENT_SIGNED_SAME_PARENT_SIBLING_CHANGES_ARE_COMPARABLE',
             'invalid_input')
        need(old._time(other['last_approval_utc'])<=old._time(timeline_evaluation_utc),
             'COMPETING_CHANGE_APPROVAL_IN_RECEIVER_FUTURE','invalid_input')
        sibling=True
    # All new originals are re-pinned; EC342 verified and re-pinned older ones.
    late(pinset)
    stale=old._time(timeline_evaluation_utc)>=old._time(main['hold_window'][1])
    status=('competing_change_requests_unresolved' if sibling else
            'receiver_ack_incomplete_unresolved' if count<len(r['receivers']) else
            'hold_window_expired_unresolved' if stale else
            'withdrawal_requested_unresolved' if main['status']=='request_withdrawal' else
            'supersession_requested_unresolved' if main['status']=='request_supersession' else
            'revision_requested_unresolved' if main['status']=='request_revision' else
            'baseline_acknowledged_unresolved')
    return {'schema':RESULT_SCHEMA,'command':'verify-timeline','status':status,
        'exit_code':2,'case_id':r['case_id'],
        'roster_original_raw_sha256':expected_roster_sha256,
        'lineage_manifest_original_raw_sha256':expected_manifest_sha256,
        'governance_roster_original_raw_sha256':expected_governance_roster_sha256,
        'hold_original_raw_sha256':r['hold_original_raw_sha256'],
        'base_approval_original_raw_sha256':expected_approval_sha256,
        'head_snapshot_original_raw_sha256':expected_head_snapshot_sha256,
        'head_ack_set_original_raw_sha256':expected_head_ack_set_sha256,
        'competing_snapshot_original_raw_sha256':expected_competing_snapshot_sha256,
        'competing_ack_set_original_raw_sha256':expected_competing_ack_set_sha256,
        'head_sequence':main['sequence'],
        'head_request_kind':main['status'],
        'registered_receiver_count':len(r['receivers']),
        'head_distinct_receiver_acks':count,
        'competing_distinct_receiver_acks':sibling_ack,
        'competing_signed_same_parent_requests_observed':sibling,
        'hold_claim_window_expired_at_evaluation':stale,
        'timeline_evaluation_utc':timeline_evaluation_utc,
        'true_ec342_sibling_fork_and_old_originals_replayed':True,
        'offline_unresolved_exit_code':2,
        **{k:False for k in NEGATIVES}}
