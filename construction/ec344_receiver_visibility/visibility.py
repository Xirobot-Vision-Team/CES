#!/usr/bin/env python3
"""EC344 offline, bounded recipient visibility evidence comparison.

Three independent evidence layers are deliberately separate:
  1. A custodian-pinned *candidate* recipient directory and announcement checkpoint.
  2. Real Ed25519 statements from EC343 registered receivers about their own view.
  3. Originals explicitly PRESENTED to this audit, replayed through EC343 / EC342.

An announcement is NOT an original, a claimed sighting is NOT its verification,
and an unpresented original is NOT proof of real-world absence.  Every favorable
outcome is unresolved/exit 2; no selection of a winner or remote operation.
"""
from __future__ import annotations

from itertools import combinations
from typing import Any

from ec295_delivery_anchor import anchor
from ec319_offline_transfer_registry import registry as reg
from ec338_independent_custody import ceremony
from ec339_offline_authority import authority as old
from ec340_issuer_root_rotation import rotation
from ec343_hold_receipts import timeline as prior

DIRECTORY_SCHEMA='ces.ec344.pinned_independent_recipient_directory.v1'
CHECKPOINT_SCHEMA='ces.ec344.pinned_bounded_visibility_checkpoint.v1'
VIEW_CLAIM_SCHEMA='ces.ec344.receiver_visibility_claim.v1'
VIEW_SCHEMA='ces.ec344.ed25519_receiver_visibility_statement.v1'
RESULT_SCHEMA='ces.ec344.bounded_signed_receiver_visibility_unresolved.v1'
DENIAL_SCHEMA='ces.ec344.bounded_signed_receiver_visibility_denial.v1'
DOMAIN=b'CES/EC344/ReceiverVisibilityStatement/v1\0'
MAX_DIRECTORY=6
MAX_ITEMS=8
MAX_VIEWS=8
MAX_PER_RECEIVER=2
DIRECTORY_FIELDS={'schema','case_id','ec343_roster_original_raw_sha256',
                  'round_nonce_sha256','receivers',
                  'not_a_global_or_authoritative_recipient_registry'}
CHECKPOINT_FIELDS={'schema','case_id','ec343_roster_original_raw_sha256',
                   'directory_original_raw_sha256','round_nonce_sha256',
                   'announcements','not_a_global_or_complete_fork_inventory'}
ITEM_FIELDS={'item_id','slot_id','snapshot_file','expected_snapshot_sha256',
             'ack_set_file','expected_ack_set_sha256'}
VIEW_CLAIM_FIELDS={'schema','case_id','ec343_roster_original_raw_sha256',
                   'directory_original_raw_sha256',
                   'checkpoint_original_raw_sha256','round_nonce_sha256',
                   'receiver_id','receiver_public_hex','receiver_organization_id',
                   'observed_announcements','view_nonce_sha256','reported_utc',
                   'scope','no_complete_custody_or_execution_claim'}
OBS_FIELDS={'item_id','snapshot_original_raw_sha256',
            'ack_set_original_raw_sha256'}
NEGATIVES=(
    'directory_or_checkpoint_is_global_latest_or_complete',
    'recipient_signature_proves_physical_custody_institution_or_trusted_time',
    'unpresented_original_proven_missing_from_real_world',
    'unannounced_or_hidden_branches_discovered',
    'different_valid_ack_sets_change_signed_snapshot_or_approval',
    'signed_same_parent_fork_or_majority_selects_winner',
    'offline_revision_withdrawal_or_supersession_executed',
    'remote_provider_cas_worm_freeze_release_or_write_performed',
    'unmocked_ec317_ec318_old_history_or_final_acceptance_proven')


def need(value: Any, code: str, status: str='invalid_input')->None:
    if value is not True:
        raise anchor.AnchorError('EC344_'+code,status)


def _candidate(command:str, sha:str)->dict:
    return {'schema':RESULT_SCHEMA,'command':command,
            'status':'owner_private_candidate_not_independently_trusted',
            'exit_code':2,'candidate_original_raw_sha256':sha,
            'offline_unresolved_exit_code':2,
            **{k:False for k in NEGATIVES}}


def _actors_unique(actors:list[dict])->bool:
    return (all(prior.oldhold._actor(a) for a in actors) and
        all(len({a[k] for a in actors})==len(actors)
            for k in prior.oldhold.ACTOR_FIELDS))


def _read_directory(path:str,sha:str,r:dict,roster_sha:str,
                    pins:dict[str,str])->dict:
    prior.pin(pins,path,sha)
    d=prior.read(path,sha,'EC344_DIRECTORY')
    need(type(d) is dict and set(d)==DIRECTORY_FIELDS and
         d.get('schema')==DIRECTORY_SCHEMA and
         d.get('case_id')==r['case_id'] and
         d.get('ec343_roster_original_raw_sha256')==roster_sha and
         ceremony._sha(d.get('round_nonce_sha256')) and
         d.get('not_a_global_or_authoritative_recipient_registry') is True and
         type(d.get('receivers')) is list and
         1<=len(d['receivers'])<=MAX_DIRECTORY and
         _actors_unique(d['receivers']),
         'INDEPENDENT_DIRECTORY_EXACT_BOUNDED_ROSTER_REQUIRED')
    return d


def _item(item:dict)->bool:
    return (type(item) is dict and set(item)==ITEM_FIELDS and
            ceremony._id(item.get('item_id')) and
            ceremony._id(item.get('slot_id')) and
            ceremony._sha(item.get('expected_snapshot_sha256')) and
            ceremony._sha(item.get('expected_ack_set_sha256')))


def _validate_announcements(announcements:Any)->None:
    need(type(announcements) is list and
         1<=len(announcements)<=MAX_ITEMS and all(_item(x) for x in announcements),
         'ONE_TO_EIGHT_EXACT_CHECKPOINT_ANNOUNCEMENTS_REQUIRED')
    need(len({x['item_id'] for x in announcements})==len(announcements),
         'DUPLICATE_CHECKPOINT_ITEM_ID')
    pairset=set()
    promised={}
    for item in announcements:
        # Announced originals can legitimately be unavailable on this machine:
        # validate only paths/digests here, NEVER silently read to trust them.
        prior.validate_refs(
            (item['snapshot_file'],item['expected_snapshot_sha256']),
            (item['ack_set_file'],item['expected_ack_set_sha256']))
        pair=(item['expected_snapshot_sha256'],item['expected_ack_set_sha256'])
        need(pair not in pairset,'DUPLICATE_ANNOUNCEMENT_ORIGINAL_PAIR')
        pairset.add(pair)
        for path,sha in ((item['snapshot_file'],item['expected_snapshot_sha256']),
                         (item['ack_set_file'],item['expected_ack_set_sha256'])):
            need(path not in promised or prior.same(promised[path],sha),
                 'ONE_ANNOUNCED_PATH_CANNOT_HAVE_TWO_WHOLE_SHA_VALUES')
            promised[path]=sha


def _read_checkpoint(path:str,sha:str,r:dict,roster_sha:str,
                     d:dict,directory_sha:str,pins:dict[str,str])->dict:
    prior.pin(pins,path,sha)
    c=prior.read(path,sha,'EC344_CHECKPOINT')
    need(type(c) is dict and set(c)==CHECKPOINT_FIELDS and
         c.get('schema')==CHECKPOINT_SCHEMA and
         c.get('case_id')==r['case_id'] and
         c.get('ec343_roster_original_raw_sha256')==roster_sha and
         c.get('directory_original_raw_sha256')==directory_sha and
         c.get('round_nonce_sha256')==d['round_nonce_sha256'] and
         c.get('not_a_global_or_complete_fork_inventory') is True,
         'CHECKPOINT_MUST_BIND_EXACT_DIRECTORY_ROUND_AND_OLD_ROSTER')
    _validate_announcements(c.get('announcements'))
    return c


def _observed(ids:list[str],byid:dict[str,dict],order:list[str])->list[dict]:
    need(type(ids) is list and len(ids)<=MAX_ITEMS and
         all(type(v) is str and v in byid for v in ids) and
         len(set(ids))==len(ids) and
         ids==[item_id for item_id in order if item_id in ids],
         'OBSERVED_IDS_MUST_BE_UNIQUE_SUBSET_IN_CHECKPOINT_ORDER')
    return [{'item_id':v,
             'snapshot_original_raw_sha256':byid[v]['expected_snapshot_sha256'],
             'ack_set_original_raw_sha256':byid[v]['expected_ack_set_sha256']}
            for v in ids]


def _view_claim(r:dict,roster_sha:str,directory_sha:str,checkpoint_sha:str,
                c:dict,actor:dict,ids:list[str],view_nonce_sha256:str,
                reported_utc:str)->dict:
    need(ceremony._sha(view_nonce_sha256) and ceremony._utc(reported_utc),
         'FRESH_VIEW_NONCE_AND_CLAIMED_UTC_REQUIRED')
    byid={x['item_id']:x for x in c['announcements']}
    entries=_observed(ids,byid,list(byid))
    return {'schema':VIEW_CLAIM_SCHEMA,
        'case_id':r['case_id'],'ec343_roster_original_raw_sha256':roster_sha,
        'directory_original_raw_sha256':directory_sha,
        'checkpoint_original_raw_sha256':checkpoint_sha,
        'round_nonce_sha256':c['round_nonce_sha256'],
        'receiver_id':actor['signer_id'],'receiver_public_hex':actor['public_hex'],
        'receiver_organization_id':actor['organization_id'],
        'observed_announcements':entries,'view_nonce_sha256':view_nonce_sha256,
        'reported_utc':reported_utc,
        'scope':'signed_partial_visibility_claim_only_not_verified_possession',
        'no_complete_custody_or_execution_claim':True}


def _prepared(*,roster_file:str,expected_roster_sha256:str,
              directory_file:str,expected_directory_sha256:str,
              checkpoint_file:str|None=None,expected_checkpoint_sha256:str|None=None):
    pins={roster_file:expected_roster_sha256}
    r=prior.roster(roster_file,expected_roster_sha256)
    d=_read_directory(directory_file,expected_directory_sha256,r,
                      expected_roster_sha256,pins)
    c=None
    if checkpoint_file is not None:
        need(expected_checkpoint_sha256 is not None,
             'CHECKPOINT_SHA_MANDATORY')
        c=_read_checkpoint(checkpoint_file,expected_checkpoint_sha256,
                          r,expected_roster_sha256,d,expected_directory_sha256,pins)
    return r,d,c,pins


def assemble_directory(*,out:str,roster_file:str,expected_roster_sha256:str,
                       round_nonce_sha256:str,receivers:list[dict])->dict:
    r=prior.roster(roster_file,expected_roster_sha256)
    doc={'schema':DIRECTORY_SCHEMA,'case_id':r['case_id'],
         'ec343_roster_original_raw_sha256':expected_roster_sha256,
         'round_nonce_sha256':round_nonce_sha256,'receivers':receivers,
         'not_a_global_or_authoritative_recipient_registry':True}
    need(ceremony._sha(round_nonce_sha256) and type(receivers) is list and
         1<=len(receivers)<=MAX_DIRECTORY and _actors_unique(receivers),
         'EXACT_SEPARATE_RECIPIENT_DIRECTORY_CANDIDATE_REQUIRED')
    sha=prior._write(out,doc,{roster_file:expected_roster_sha256})
    return _candidate('assemble-directory',sha)


def assemble_checkpoint(*,out:str,roster_file:str,expected_roster_sha256:str,
                        directory_file:str,expected_directory_sha256:str,
                        announcements:list[dict])->dict:
    r,d,_,pins=_prepared(roster_file=roster_file,
         expected_roster_sha256=expected_roster_sha256,
         directory_file=directory_file,expected_directory_sha256=expected_directory_sha256)
    _validate_announcements(announcements)
    doc={'schema':CHECKPOINT_SCHEMA,'case_id':r['case_id'],
         'ec343_roster_original_raw_sha256':expected_roster_sha256,
         'directory_original_raw_sha256':expected_directory_sha256,
         'round_nonce_sha256':d['round_nonce_sha256'],
         'announcements':announcements,
         'not_a_global_or_complete_fork_inventory':True}
    # Don't pin/read announced originals: they can be absent by design.
    need(out not in {path for a in announcements for path in
             (a['snapshot_file'],a['ack_set_file'])},
         'CHECKPOINT_OUTPUT_CANNOT_ALIAS_ANNOUNCED_ORIGINAL')
    sha=prior._write(out,doc,pins)
    return _candidate('assemble-checkpoint',sha)


def sign_view(*,out:str,private_key_file:str,
              roster_file:str,expected_roster_sha256:str,
              directory_file:str,expected_directory_sha256:str,
              checkpoint_file:str,expected_checkpoint_sha256:str,
              observed_item_ids:list[str],view_nonce_sha256:str,
              reported_utc:str)->dict:
    r,d,c,pins=_prepared(roster_file=roster_file,
         expected_roster_sha256=expected_roster_sha256,
         directory_file=directory_file,expected_directory_sha256=expected_directory_sha256,
         checkpoint_file=checkpoint_file,expected_checkpoint_sha256=expected_checkpoint_sha256)
    key,pub=rotation._private_key_public(private_key_file)
    who=[a for a in r['receivers'] if prior.same(a['public_hex'],pub)]
    need(len(who)==1,'ONLY_EC343_REGISTERED_RECEIVER_MAY_SIGN_VISIBILITY',
         'permission_denied')
    claim=_view_claim(r,expected_roster_sha256,expected_directory_sha256,
                      expected_checkpoint_sha256,c,who[0],observed_item_ids,
                      view_nonce_sha256,reported_utc)
    doc={'schema':VIEW_SCHEMA,'claim':claim,
         'signature_ed25519':key.sign(DOMAIN+reg.canonical(claim)).hex()}
    sha=prior._write(out,doc,pins,private_key_file)
    return _candidate('sign-view',sha)


def _signed_views(*,view_files:list[str],view_shas:list[str],r:dict,d:dict,c:dict,
                  roster_sha:str,directory_sha:str,checkpoint_sha:str,
                  evaluation_utc:str,pins:dict[str,str])->tuple[dict,dict]:
    need(type(view_files) is list and type(view_shas) is list and
         2<=len(view_files)<=MAX_VIEWS and
         len(view_files)==len(view_shas) and
         len(set(view_files))==len(view_files),
         'TWO_TO_EIGHT_SEPARATELY_PINNED_SIGNED_VIEWS_REQUIRED')
    byactor={x['signer_id']:x for x in r['receivers']}
    byid={x['item_id']:x for x in c['announcements']}
    ordered=list(byid)
    views_by_receiver:dict[str,list[dict]]={}
    nonces=set()
    for path,sha in zip(view_files,view_shas,strict=True):
        prior.pin(pins,path,sha)
        v=prior.read(path,sha,'EC344_RECEIVER_VIEW')
        claim=v.get('claim') if type(v) is dict else None
        need(type(claim) is dict and set(claim)==VIEW_CLAIM_FIELDS,
             'SIGNED_RECEIVER_VIEW_EXACT_CLAIM_REQUIRED')
        who=byactor.get(claim.get('receiver_id'))
        need(who is not None,'ONLY_EC343_REGISTERED_RECEIVER_MAY_PRESENT_VIEW')
        observed=claim.get('observed_announcements')
        need(type(observed) is list and len(observed)<=MAX_ITEMS and
             all(type(x) is dict and set(x)==OBS_FIELDS for x in observed),
             'SIGNED_EXACT_ANNOUNCEMENT_SHA_PAIRS_REQUIRED')
        ids=[x['item_id'] for x in observed]
        expected=_view_claim(r,roster_sha,directory_sha,checkpoint_sha,
                             c,who,ids,claim.get('view_nonce_sha256'),
                             claim.get('reported_utc'))
        need(claim==expected,
             'VIEW_MUST_MATCH_EXACT_CHECKPOINT_PINS_AND_REGISTERED_RECEIVER')
        prior._signed(v,VIEW_SCHEMA,DOMAIN,who['public_hex'],
                      'EC344_INDEPENDENT_VISIBILITY')
        need(old._time(claim['reported_utc'])<=old._time(evaluation_utc),
             'VIEW_CLAIM_TIME_AFTER_INDEPENDENT_EVALUATION')
        need(claim['view_nonce_sha256'] not in nonces,
             'SIGNED_VIEW_NONCE_REUSED_IN_PRESENTED_ROUND')
        nonces.add(claim['view_nonce_sha256'])
        group=views_by_receiver.setdefault(who['signer_id'],[])
        need(len(group)<MAX_PER_RECEIVER,
             'AT_MOST_TWO_SIGNED_VIEWS_PER_REGISTERED_RECEIVER')
        group.append({'sha256':sha,'ids':ids,'reported_utc':claim['reported_utc']})
    need(len(views_by_receiver)>=2,
         'AT_LEAST_TWO_DISTINCT_REGISTERED_RECEIVER_SIGNATURES_REQUIRED')
    return views_by_receiver,byid


def _verified_item(item:dict,r:dict,roster_sha:str,
                   pins:dict[str,str],*,evaluation_utc:str,
                   governance_roster_file:str,review_manifest_file:str,
                   approval_file:str)->dict:
    snapshot_path=item['snapshot_file']
    snapshot_sha=item['expected_snapshot_sha256']
    ack_path=item['ack_set_file']
    ack_sha=item['expected_ack_set_sha256']
    s=prior._load_chain(snapshot_path,snapshot_sha,r,roster_sha,pins)
    need(s['base_doc']['governance_roster_file']==governance_roster_file and
         s['base_doc']['review_manifest_file']==review_manifest_file and
         s['base_doc']['approval_file']==approval_file,
         'PRESENTED_SNAPSHOT_MUST_REPLAY_INDEPENDENTLY_PINNED_EC342_BASE')
    count,_=prior._ackset(ack_path,ack_sha,snapshot_path,snapshot_sha,
               r,roster_sha,s['sequence'],s['hold_window'],pins,
               s['last_approval_utc'],evaluation_utc)
    need(old._time(s['last_approval_utc'])<=old._time(evaluation_utc),
         'PRESENTED_APPROVAL_AFTER_EVALUATION')
    return {'item_id':item['item_id'],'slot_id':item['slot_id'],
            'snapshot_original_raw_sha256':snapshot_sha,
            'ack_set_original_raw_sha256':ack_sha,
            'sequence':s['sequence'],'request_kind':s['status'],
            'parent_snapshot_original_raw_sha256':s.get('parent_sha'),
            'change_original_raw_sha256':s.get('change_sha'),
            'verified_receiver_ack_count':count}


def audit_views(*,manifest_file:str,expected_manifest_sha256:str,
                expected_current_root_sha256:str,expected_current_root_epoch:int,
                minimum_acceptable_epoch:int,current_root_evaluation_utc:str,
                governance_roster_file:str,expected_governance_roster_sha256:str,
                review_manifest_file:str,expected_review_manifest_sha256:str,
                approval_file:str,expected_approval_sha256:str,
                hold_evaluation_utc:str,roster_file:str,expected_roster_sha256:str,
                head_snapshot_file:str,expected_head_snapshot_sha256:str,
                head_ack_set_file:str,expected_head_ack_set_sha256:str,
                timeline_evaluation_utc:str,
                directory_file:str,expected_directory_sha256:str,
                checkpoint_file:str,expected_checkpoint_sha256:str,
                anchor_item_id:str,view_files:list[str],view_shas:list[str],
                presented_item_ids:list[str])->dict:
    need(type(presented_item_ids) is list and
         1<=len(presented_item_ids)<=MAX_ITEMS and
         all(type(x) is str for x in presented_item_ids) and
         len(set(presented_item_ids))==len(presented_item_ids) and
         ceremony._id(anchor_item_id),
         'PRESENTED_IDS_AND_ANCHOR_REQUIRED')
    pins={}
    for path,sha in ((manifest_file,expected_manifest_sha256),
                     (governance_roster_file,expected_governance_roster_sha256),
                     (review_manifest_file,expected_review_manifest_sha256),
                     (approval_file,expected_approval_sha256),
                     (roster_file,expected_roster_sha256)):
        prior.pin(pins,path,sha)
    r,d,c,additional=_prepared(roster_file=roster_file,
       expected_roster_sha256=expected_roster_sha256,
       directory_file=directory_file,expected_directory_sha256=expected_directory_sha256,
       checkpoint_file=checkpoint_file,expected_checkpoint_sha256=expected_checkpoint_sha256)
    for path,sha in additional.items():prior.pin(pins,path,sha)
    byid={item['item_id']:item for item in c['announcements']}
    need(all(v in byid for v in presented_item_ids) and
         anchor_item_id in presented_item_ids and
         presented_item_ids==[x for x in byid if x in presented_item_ids],
         'ONLY_CHECKPOINT_IDS_IN_CANONICAL_ORDER_MAY_BE_PRESENTED')
    a=byid[anchor_item_id]
    need(a['snapshot_file']==head_snapshot_file and
         a['expected_snapshot_sha256']==expected_head_snapshot_sha256 and
         a['ack_set_file']==head_ack_set_file and
         a['expected_ack_set_sha256']==expected_head_ack_set_sha256,
         'ANCHOR_MUST_MATCH_EC343_INDEPENDENT_HEAD_TRUST_ARGUMENTS')
    # Full signed EC342 -> EC337 and EC343 root/role/history replay performed
    # exactly as in the previous receiver. No remote/custody/winner claims.
    baseline=prior.verify_timeline(
        manifest_file=manifest_file,expected_manifest_sha256=expected_manifest_sha256,
        expected_current_root_sha256=expected_current_root_sha256,
        expected_current_root_epoch=expected_current_root_epoch,
        minimum_acceptable_epoch=minimum_acceptable_epoch,
        current_root_evaluation_utc=current_root_evaluation_utc,
        governance_roster_file=governance_roster_file,
        expected_governance_roster_sha256=expected_governance_roster_sha256,
        review_manifest_file=review_manifest_file,
        expected_review_manifest_sha256=expected_review_manifest_sha256,
        approval_file=approval_file,expected_approval_sha256=expected_approval_sha256,
        hold_evaluation_utc=hold_evaluation_utc,roster_file=roster_file,
        expected_roster_sha256=expected_roster_sha256,
        head_snapshot_file=head_snapshot_file,
        expected_head_snapshot_sha256=expected_head_snapshot_sha256,
        head_ack_set_file=head_ack_set_file,
        expected_head_ack_set_sha256=expected_head_ack_set_sha256,
        timeline_evaluation_utc=timeline_evaluation_utc)
    need(baseline['exit_code']==2 and
         baseline['true_ec342_sibling_fork_and_old_originals_replayed'] is True,
         'FULL_EC343_SIGNED_HISTORY_REPLAY_MANDATORY','permission_denied')
    views,byid=_signed_views(view_files=view_files,view_shas=view_shas,
        r=r,d=d,c=c,roster_sha=expected_roster_sha256,
        directory_sha=expected_directory_sha256,
        checkpoint_sha=expected_checkpoint_sha256,
        evaluation_utc=timeline_evaluation_utc,pins=pins)
    verified=[_verified_item(byid[v],r,expected_roster_sha256,pins,
        evaluation_utc=timeline_evaluation_utc,
        governance_roster_file=governance_roster_file,
        review_manifest_file=review_manifest_file,
        approval_file=approval_file) for v in presented_item_ids]
    # Re-pin ALL read originals after verifying signatures. An unpresented pair
    # is intentionally NOT opened: absence is a bounded audit-sample gap.
    prior.late(pins)
    prior_map={x['signer_id']:x for x in r['receivers']}
    directory_map={x['signer_id']:x for x in d['receivers']}
    missing_in_directory=[i for i in prior_map if i not in directory_map]
    additional_in_directory=[i for i in directory_map if i not in prior_map]
    identity_conflicts=[i for i in prior_map if i in directory_map and
                        prior_map[i]!=directory_map[i]]
    directory_match=not (missing_in_directory or
                         additional_in_directory or identity_conflicts)
    missing_signed_receivers=[i for i in prior_map if i not in views]
    by_receiver_union={i:set().union(*(set(v['ids']) for v in vals))
                       for i,vals in views.items()}
    divergent_same_receiver=[]
    for receiver_id,vals in views.items():
        if len(vals)==2 and set(vals[0]['ids'])!=set(vals[1]['ids']):
            divergent_same_receiver.append(receiver_id)
    cross_receiver_differences=[]
    for left,right in combinations(by_receiver_union,2):
        lset=by_receiver_union[left]; rset=by_receiver_union[right]
        if lset!=rset:
            cross_receiver_differences.append({
                'left_receiver_id':left,'right_receiver_id':right,
                'left_only_item_ids':[i for i in byid if i in lset-rset],
                'right_only_item_ids':[i for i in byid if i in rset-lset]})
    presented=set(presented_item_ids)
    observed_claims=set().union(*by_receiver_union.values())
    unpresented=[i for i in byid if i not in presented]
    claimed_not_presented=[i for i in unpresented if i in observed_claims]
    receiver_view_evidence=[
        {'receiver_id':receiver_id,
         'signed_view_original_sha256s':[x['sha256'] for x in vals],
         'union_claimed_item_ids':[i for i in byid if i in by_receiver_union[receiver_id]],
         'claimed_but_not_presented_item_ids':[
             i for i in unpresented if i in by_receiver_union[receiver_id]]}
        for receiver_id,vals in views.items()]
    unobserved_announced=[i for i in byid if i not in observed_claims]
    signed_sibling_pairs=[]
    parallel_ack_set_pairs=[]
    for left,right in combinations(verified,2):
        if (left['sequence']>0 and left['sequence']==right['sequence'] and
            left['parent_snapshot_original_raw_sha256']==
                right['parent_snapshot_original_raw_sha256'] and
            left['change_original_raw_sha256']!=right['change_original_raw_sha256']):
            signed_sibling_pairs.append([left['item_id'],right['item_id']])
        if (left['snapshot_original_raw_sha256']==right['snapshot_original_raw_sha256']
            and left['ack_set_original_raw_sha256']!=right['ack_set_original_raw_sha256']):
            parallel_ack_set_pairs.append([left['item_id'],right['item_id']])
    status=(
        'verified_signed_same_parent_forks_unresolved' if signed_sibling_pairs else
        'same_receiver_divergent_signed_views_unresolved' if divergent_same_receiver else
        'independent_receiver_directory_mismatch_unresolved' if not directory_match else
        'parallel_ack_sets_same_snapshot_unresolved' if parallel_ack_set_pairs else
        'signed_cross_receiver_visibility_diff_unresolved' if cross_receiver_differences else
        'signed_claimed_originals_not_presented_unresolved' if claimed_not_presented else
        'some_registered_receiver_views_missing_unresolved' if missing_signed_receivers else
        'checkpoint_items_not_presented_unresolved' if unpresented else
        'aligned_bounded_sample_only_unresolved')
    return {'schema':RESULT_SCHEMA,'command':'audit-views','status':status,
        'exit_code':2,'case_id':r['case_id'],
        'ec343_roster_original_raw_sha256':expected_roster_sha256,
        'directory_original_raw_sha256':expected_directory_sha256,
        'checkpoint_original_raw_sha256':expected_checkpoint_sha256,
        'anchor_item_id':anchor_item_id,
        'head_snapshot_original_raw_sha256':expected_head_snapshot_sha256,
        'head_ack_set_original_raw_sha256':expected_head_ack_set_sha256,
        'timeline_evaluation_utc':timeline_evaluation_utc,
        'registered_receiver_count':len(r['receivers']),
        'directory_receiver_count':len(d['receivers']),
        'independent_directory_matches_ec343_roster':directory_match,
        'missing_in_independent_directory_receiver_ids':missing_in_directory,
        'additional_independent_directory_receiver_ids':additional_in_directory,
        'directory_identity_conflict_receiver_ids':identity_conflicts,
        'distinct_receivers_with_signed_views':len(views),
        'signed_receiver_view_evidence':receiver_view_evidence,
        'missing_registered_receiver_signed_view_ids':missing_signed_receivers,
        'same_receiver_divergent_signed_view_ids':divergent_same_receiver,
        'cross_receiver_signed_visibility_differences':cross_receiver_differences,
        'checkpoint_announced_count':len(byid),
        'presented_and_full_history_verified_count':len(verified),
        'verified_presented_items':verified,
        'checkpoint_not_presented_item_ids':unpresented,
        'claimed_visible_but_not_presented_item_ids':claimed_not_presented,
        'not_claimed_visible_in_any_presented_view_item_ids':unobserved_announced,
        'verified_signed_same_parent_sibling_item_pairs':signed_sibling_pairs,
        'different_verified_ack_sets_same_snapshot_item_pairs':parallel_ack_set_pairs,
        'true_ec342_signed_fork_and_old_originals_replayed':True,
        'complete_global_receiver_census_or_branch_enumeration_proven':False,
        'offline_unresolved_exit_code':2,
        **{k:False for k in NEGATIVES}}
