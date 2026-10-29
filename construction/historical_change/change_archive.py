#!/usr/bin/env python3
"""EC385: original EC342 hold approval -> EC343 signed change lineage.

Audit only.  A real EC384->EC369 audit, original EC383/382/384 archives,
original EC348->EC337 replay and raw-sha-pinned EC342/343 files precede every
signed-transition claim.  No supplied key, review or snapshot creates authority.
"""
from __future__ import annotations

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from offline_authority import authority as clock
from conflict_hold import hold as old342
from hold_receipts import timeline as old343
from receiver_visibility import visibility as old344
from dual_channel_anchor import anchor as old349
from transparency import transparency as old353
from historical_authority import authority_archive as p372
from historical_disclosure import disclosure_archive as p376
from historical_offer import offer_archive as parent

RESULT_SCHEMA='ces.ec385.receiver_original_ec342_hold_ec343_signed_change_unresolved.v1'
DERIVE_SCHEMA='ces.ec385.unsigned_original_ec342_ec343_change_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec385.receiver_original_ec342_ec343_change_denial.v1'
BUNDLE_SCHEMA='ces.ec385.receiver_historic_ec342_approved_hold_ec343_signed_change_archive.v1'
INVENTORY_SCHEMA='ces.ec385.receiver_verified_historic_hold_change_inventory.v1'
MAX_BUNDLE=245_000
MAX_ORIGINAL=300_000
NEW_SCALARS=('historical_ec343_change_approval_archive_bundle_file',
             'expected_historical_ec343_change_approval_archive_bundle_sha256')
AUDIT_ONLY=('expected_retained_historical_ec343_change_approval_inventory_sha256',)
NEW_REPEATS=(
 ('historical_ec342_approved_hold_inventory_shas','--historical-ec342-approved-hold-inventory-sha256'),
 ('historical_ec343_signed_change_inventory_shas','--historical-ec343-signed-change-inventory-sha256'),
 ('minimum_historical_ec342_signed_review_counts','--minimum-historical-ec342-signed-review-count'),
 ('minimum_historical_ec343_signed_change_counts','--minimum-historical-ec343-signed-change-count'),
 ('minimum_historical_ec343_signed_ack_counts','--minimum-historical-ec343-signed-ack-count'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
PARENT_SCALARS=(*parent.PARENT_SCALARS,*parent.NEW_SCALARS,*parent.AUDIT_ONLY)
PARENT_REPEATS=(*parent.PARENT_REPEATS,*parent.REPEAT_NAMES)
BUNDLE_FIELDS={'schema','parent_ec384_canonical_result_sha256',
               'ec384_historical_offer_archive_original_sha256',
               'claimed_directory_lineage_id','epochs'}
EPOCH_FIELDS={'epoch_index','channels'}
CHANNEL_FIELDS={
 'tsa_channel_id','ec342_governance_roster_original','ec342_hold_request_original',
 'ec342_review_manifest_original','ec342_external_approval_original',
 'ec342_signed_review_originals','ec343_source_head_snapshot_original',
 'ec343_source_head_ack_set_original','ec343_original_source_head_receiver_receipts',
 'ec343_signed_target_snapshot_original','ec343_signed_target_ack_set_original',
 'ec343_original_signed_change_request','ec343_original_signed_change_approval',
 'ec343_original_target_receiver_receipts','ec343_change_proposer_public_key_original',
 'ec343_change_approver_public_key_original','ec343_competing_signed_successors'}
SIBLING_FIELDS={'snapshot_original','ack_set_original','signed_change_original',
                'signed_approval_original','receiver_receipt_originals'}
FLAGS=(
 'inherited_live_ec384_through_ec369_signed_original_dispute',
 'outside_retained_ec342_ec343_original_sha_or_count_floor_disagrees',
 'genuine_old_ec342_ec343_original_predecessor_or_source_missing',
 'old_ec342_signed_hold_review_approval_or_signer_roles_incomplete',
 'old_ec343_signed_change_approval_predecessor_or_receipt_incomplete',
 'visible_original_ec343_independently_signed_competing_successor_fork',
 'old_ec342_ec343_original_channels_or_later_epoch_signed_rollback',
 'full_unmocked_old_ec343_through_ec337_external_chain_not_proven',
 'independent_signer_custody_global_fork_census_physical_effect_and_trusted_utc_unproven',
)
OUTCOMES=(
 'ec385_inherited_live_original_signed_receiver_parent_dispute',
 'ec385_outside_retained_signed_hold_change_inventory_or_floor_disagrees',
 'ec385_old_ec342_ec343_pinned_source_or_predecessor_unavailable',
 'ec385_old_ec342_independent_signed_approval_or_roles_incomplete',
 'ec385_old_ec343_signed_change_approval_or_receiver_ack_missing',
 'ec385_observed_genuine_signed_same_parent_ec343_successor_fork',
 'ec385_old_ec342_ec343_signed_source_channel_or_epoch_rollback',
 'ec385_old_ec343_through_ec337_independent_external_original_history_incomplete',
 'ec385_no_physical_legal_external_custody_global_fork_or_trusted_clock_proof',
)
NEGATIVES=(
 'ec342_approval_is_executed_remote_cas_hold_or_legal_authority',
 'ec343_signed_revision_or_withdrawal_releases_modifies_or_selects_old_hold',
 'ec343_change_proposer_can_approve_own_signed_request',
 'a_receiver_ack_signature_is_approval_or_proof_of_physical_delivery',
 'ec344_unsigned_checkpoint_authenticates_global_publication_or_winner',
 'signed_visible_successors_exclude_unreported_competing_changes',
 'caller_inventory_sha_was_independently_archived_by_this_software',
 'self_reported_utc_is_certified_external_time',
 'a_public_key_file_authenticates_real_institution_or_revocation_status',
 'a_supplied_original_replaces_the_ec383_ec384_authenticated_ec345_source',
 'ec353_sender_labels_are_trusted_receiver_original_paths',
 'missing_old_originals_replaced_with_private_keys_mocks_or_latest_claim',
 'private_signers_network_remote_provider_cas_worm_or_native_ps_invoked',
 'inherited_ec366_through_ec337_fixture_mock_removed_or_final_acceptance_granted',
)


def need(ok,code,status='invalid_input'):
    if ok is not True:raise errors.AnchorError('EC385_'+code,status)


def exact(doc,fields,code):
    need(type(doc) is dict and set(doc)==set(fields),code+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return parent.sha(raw)


def _inputs(opts,derive):
    required=set(PARENT_SCALARS)|set(PARENT_REPEATS)|set(NEW_SCALARS)|set(REPEAT_NAMES)
    if not derive:required.update(AUDIT_ONLY)
    need(set(opts)==required,'EXACT_LIVE_PARENT_AND_EC385_INPUTS_REQUIRED')
    popts={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    parent._inputs(popts,False)
    p372.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                             'EC385_RECEIVER_PINNED_EC343_CHANGE_APPROVAL_ARCHIVE')
    if not derive:need(old353._sha(opts[AUDIT_ONLY[0]]),'RETAINED_EC385_INVENTORY_PIN_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'HISTORIC_EPOCH_BOUNDS')
    for key in REPEAT_NAMES:
        arr=opts[key]
        need(type(arr) is list and len(arr)==n,'EXACT_EPOCH_SHA_FLOOR_CENSUS_'+key.upper())
        if key.startswith('minimum_'):
            cap=(old349.MAX_CHANNELS*old342.MAX_REVIEWERS if 'review' in key else
                 old349.MAX_CHANNELS*3 if 'change' in key else
                 old349.MAX_CHANNELS*old343.MAX_RECEIVERS*4)
            need(all(type(x) is int and 0<=x<=cap for x in arr),
                 'BOUNDED_SIGNED_ORIGINAL_COUNT_'+key.upper())
        else:need(all(old353._sha(x) for x in arr),'OUTSIDE_ORIGINAL_SHA_'+key.upper())
    return popts


def _parent(result,n):
    need(type(result) is dict and result.get('schema')==parent.RESULT_SCHEMA and
         result.get('exit_code')==2 and
         result.get('sender_origin_path_required_or_read') is False and
         result.get('ec345_through_ec337_full_independent_original_historical_acceptance_performed') is False and
         type(result.get('historical_ec345_disclosure_epoch_reviews')) is list and
         len(result['historical_ec345_disclosure_epoch_reviews'])==n,
         'LIVE_AUTHENTIC_EC384_THROUGH_EC369_PARENT_AUDIT_REQUIRED','unavailable')
    return sha(canonical.canonical(result))


def _ref(ref,path,digest,code):
    parent._ref(ref,path,digest,'EC385_'+code)


def _original(ref,read,code):
    return parent.parent.previous._json_original(
        read(ref,'ec385_'+code+'_'+ref['sha256'],MAX_ORIGINAL),'EC385_'+code)


def _key(ref,actor,read,code):
    raw=read(ref,'ec385_'+code+'_'+ref['sha256'],32)
    need(len(raw)==32 and raw.hex()==actor['public_hex'],
         'ORIGINAL_PUBLIC_KEY_NOT_IN_AUTHENTIC_REGISTERED_SIGNER_ROSTER_'+code,
         'permission_denied')


def _receipts(refs,index,read,code):
    exact(index,{'schema','snapshot_file','expected_snapshot_sha256','receipts'},code+'_INDEX')
    need(index['schema']==old343.ACK_SET_SCHEMA and type(index['receipts']) is list and
         type(refs) is list and len(refs)==len(index['receipts']) and
         len(refs)<=old343.MAX_RECEIVERS,'EXACT_SIGNED_RECEIPT_CENSUS_'+code,'permission_denied')
    for requested,legacy in zip(refs,index['receipts'],strict=True):
        exact(legacy,old343.REF_FIELDS,code+'_LEGACY_RECEIPT')
        _ref(requested,legacy['file'],legacy['sha256'],code+'_LEGACY_RECEIPT_BIND')
        doc=_original(requested,read,code+'_signed_receipt')
        exact(doc,{'schema','claim','signature_ed25519'},code+'_SIGNED_RECEIPT')
        need(doc['schema']==old343.RECEIPT_SCHEMA,code+'_REGISTERED_RECEIVER_SIGNATURE_SCHEMA',
             'permission_denied')
    return len(refs)


def _missing(channel):
    return {'tsa_channel_id':channel,'full_original_ec342_ec343_source_replay':False,
      'ec342_governance_sha256':None,'ec342_approved_hold_sha256':None,
      'ec342_signed_review_sha256s':[],'ec342_external_approval_sha256':None,
      'ec343_source_head_snapshot_sha256':None,'ec343_source_head_ack_sha256':None,
      'ec343_target_snapshot_sha256':None,'ec343_target_ack_sha256':None,
      'ec343_signed_change_sha256':None,'ec343_signed_change_approval_sha256':None,
      'ec343_change_request_kind':None,'ec343_signed_sibling_sha256s':[],
      'ec342_signed_review_count':0,'ec343_signed_change_count':0,
      'ec343_verified_signed_receiver_ack_count':0,
      'old_ec342_source_or_signed_approval_incomplete':True,
      'ec343_signed_change_or_predecessor_incomplete':True,
      'ec343_same_parent_signed_fork_observed':False}


def _check_branch(snapref,ackref,change_ref,approval_ref,receipt_refs,
                  *,source_snap,source_ack,roster,roster_sha,read,role,
                  pinned_base_roster,eval_utc):
    snap=_original(snapref,read,role+'_transition_snapshot')
    exact(snap,old343.NEXT_FIELDS,role+'_TRANSITION')
    need(snap['schema']==old343.NEXT_SCHEMA and snap['sequence']==1 and
         snap['case_id']==roster['case_id'] and
         snap['roster_original_raw_sha256']==roster_sha and
         snap['previous_snapshot_file']==source_snap['path'] and
         snap['expected_previous_snapshot_sha256']==source_snap['sha256'] and
         snap['previous_ack_set_file']==source_ack['path'] and
         snap['expected_previous_ack_set_sha256']==source_ack['sha256'],
         'CHANGE_MUST_POINT_TO_OLD_EC342_APPROVED_PARENT_SNAPSHOT_AND_ACK_'+role,
         'permission_denied')
    _ref(change_ref,snap['change_file'],snap['expected_change_sha256'],role+'_REQUEST_ORIGINAL')
    _ref(approval_ref,snap['change_approval_file'],snap['expected_change_approval_sha256'],
         role+'_APPROVAL_ORIGINAL')
    change_doc=_original(change_ref,read,role+'_signed_change')
    appr_doc=_original(approval_ref,read,role+'_signed_approval')
    exact(change_doc,{'schema','claim','signature_ed25519'},role+'_SIGNED_CHANGE')
    exact(appr_doc,{'schema','claim','signature_ed25519'},role+'_SIGNED_APPROVAL')
    old343._signed(change_doc,old343.CHANGE_SCHEMA,old343.D_CHANGE,
                   roster['change_proposer']['public_hex'],role+'_CHANGE_PROPOSER')
    old343._signed(appr_doc,old343.APPROVAL_SCHEMA,old343.D_APPROVAL,
                   roster['change_approver']['public_hex'],role+'_INDEPENDENT_APPROVER')
    claim=change_doc['claim'];approval=appr_doc['claim']
    need(type(claim) is dict and type(approval) is dict,
         'EC343_SIGNED_CHANGE_AND_APPROVAL_CLAIMS_REQUIRED_'+role,
         'permission_denied')
    # Reconstruct BOTH signed claims from the actual, already replayed old
    # EC342 predecessor plus the last *verified* receiver ACK time. Comparing
    # to a synthetic timestamp would silently weaken the exact chain proof.
    expected_change=old343._transition_claim(roster,roster_sha,pinned_base_roster,
         source_snap['sha256'],source_ack['sha256'],
         claim.get('change_request_kind'),claim.get('change_summary_sha256'),
         claim.get('change_nonce_sha256'),claim.get('requested_successor_case_id'),
         claim.get('issued_utc'))
    need(claim==expected_change,
         'SIGNED_CHANGE_MUST_MATCH_EXACT_AUTHENTIC_PREDECESSOR_AND_ROLE_'+role,
         'permission_denied')
    expected_approval=old343._approval_claim(roster,roster_sha,pinned_base_roster,
         change_ref['sha256'],claim,approval.get('approval_reported_utc'))
    need(approval==expected_approval,
         'SIGNED_INDEPENDENT_APPROVAL_MUST_BIND_EXACT_CHANGE_SHA_AND_PREDECESSOR_'+role,
         'permission_denied')
    ack=_original(ackref,read,role+'_signed_receiver_ack_set')
    need(ack.get('snapshot_file')==snapref['path'] and
         ack.get('expected_snapshot_sha256')==snapref['sha256'],
         'EC343_RECEIVER_ACK_INDEX_MUST_BIND_SAME_VERIFIED_TARGET_'+role,
         'permission_denied')
    count=_receipts(receipt_refs,ack,read,role+'_target')
    # Historic official verifier reopens all original EC342 review signatures,
    # base receiver signatures, change/approval and successor ACK signatures.
    pins={}
    state=old343._load_chain(snapref['path'],snapref['sha256'],roster,roster_sha,pins)
    need(state['sequence']==1 and state['kind']=='change' and
         state['parent_sha']==source_snap['sha256'] and
         state['change_sha']==change_ref['sha256'] and
         state['change_approval_sha']==approval_ref['sha256'],
         'LEGACY_FULL_ORIGINAL_SIGNATURE_CHAIN_MUST_VERIFY_'+role,
         'permission_denied')
    verified_count,_=old343._ackset(ackref['path'],ackref['sha256'],snapref['path'],
         snapref['sha256'],roster,roster_sha,1,state['hold_window'],pins,
         state['last_approval_utc'],eval_utc)
    need(verified_count==count and
         clock._time(claim['issued_utc'])<=clock._time(approval['approval_reported_utc']) and
         clock._time(approval['approval_reported_utc'])<=clock._time(eval_utc),
         'EXACT_REGISTERED_SIGNED_RECEIPTS_AND_SIGNED_TIME_BOUNDS_'+role,
         'permission_denied')
    old343.late(pins)
    return {'change_ref':change_ref,'approval_ref':approval_ref,'snapshot_ref':snapref,
            'ack_ref':ackref,'change':claim,'approval':approval,
            'receiver_receipt_shas':[x['sha256'] for x in receipt_refs],
            'ack_count':verified_count,'ack_complete':verified_count==len(roster['receivers'])}


def _channel(row,old384,old383,old382,read,forbidden):
    exact(row,CHANNEL_FIELDS,'EC385_CHANNEL')
    channel=row['tsa_channel_id']
    need(channel==old384['tsa_channel_id']==old383['tsa_channel_id']==old382['tsa_channel_id'],
         'CHANNEL_NOT_IN_AUTHENTIC_EC384_EC383_EC382_SOURCE','permission_denied')
    ref348=old382['ec348_full_replay_inputs_original']
    if ref348 is None:
        need(old384['ec345_disclosure_issuer_public_key_original'] is None and
             all(row[k] is None for k in CHANNEL_FIELDS if k not in (
            'tsa_channel_id','ec342_signed_review_originals',
            'ec343_original_source_head_receiver_receipts',
            'ec343_original_target_receiver_receipts','ec343_competing_signed_successors')) and
            all(row[k]==[] for k in ('ec342_signed_review_originals',
            'ec343_original_source_head_receiver_receipts',
            'ec343_original_target_receiver_receipts','ec343_competing_signed_successors')),
            'NO_UNTRUSTED_SIGNED_SOURCE_INJECTED_WHEN_OLD_REPLAY_UNAVAILABLE',
            'permission_denied')
        return _missing(channel)
    ctx=parent.parent.previous.previous._ec348_original(ref348,read,forbidden)
    src=ctx['inputs']
    # The target is the *actual* EC345 -> EC346 original delivered snapshot,
    # not a fresh caller-chosen EC343 sibling. The source head is the original
    # EC344 baseline preceding that signed EC345 source.
    roster_ref=old383['ec343_authority_roster_original']
    _ref(roster_ref,src['roster_file'],src['expected_roster_sha256'],
         'EC383_AUTHENTIC_EC343_SIGNER_ROSTER')
    roster=_original(roster_ref,read,'ec343_roster')
    exact(roster,old343.ROSTER_FIELDS,'AUTHENTIC_EC343_ROLE_ROSTER')
    need(roster['schema']==old343.ROSTER_SCHEMA and
         roster['governance_roster_original_raw_sha256']==src['expected_governance_roster_sha256'] and
         roster['review_manifest_original_raw_sha256']==src['expected_review_manifest_sha256'] and
         roster['approval_original_raw_sha256']==src['expected_approval_sha256'],
         'ROSTER_MUST_BIND_OLD_EC342_APPROVED_HOLD_ORIGINAL','permission_denied')
    def matched(name,path,digest):_ref(row[name],path,digest,'AUTHENTIC_'+name.upper())
    matched('ec342_governance_roster_original',src['governance_roster_file'],
            src['expected_governance_roster_sha256'])
    matched('ec342_review_manifest_original',src['review_manifest_file'],
            src['expected_review_manifest_sha256'])
    matched('ec342_external_approval_original',src['approval_file'],
            src['expected_approval_sha256'])
    matched('ec343_source_head_snapshot_original',src['head_snapshot_file'],
            src['expected_head_snapshot_sha256'])
    matched('ec343_source_head_ack_set_original',src['head_ack_set_file'],
            src['expected_head_ack_set_sha256'])
    matched('ec343_signed_target_snapshot_original',
            old383['ec345_verified_source_snapshot_original']['path'],
            old383['ec345_verified_source_snapshot_original']['sha256'])
    matched('ec343_signed_target_ack_set_original',
            old383['ec345_verified_source_ack_set_original']['path'],
            old383['ec345_verified_source_ack_set_original']['sha256'])
    proposer=row['ec343_change_proposer_public_key_original']
    _ref(proposer,old384['ec345_disclosure_issuer_public_key_original']['path'],
         old384['ec345_disclosure_issuer_public_key_original']['sha256'],
         'AUTHENTIC_EC384_EC345_CHANGE_PROPOSER_KEY')
    _key(proposer,roster['change_proposer'],read,'proposer')
    _key(row['ec343_change_approver_public_key_original'],roster['change_approver'],
         read,'independent_approver')
    gov=_original(row['ec342_governance_roster_original'],read,'old_ec342_governance')
    base=_original(row['ec343_source_head_snapshot_original'],read,'old_ec342_base_snapshot')
    exact(base,old343.BASE_FIELDS,'AUTHENTIC_EC342_PREVIOUS_BASE')
    need(base['schema']==old343.BASE_SCHEMA and base['sequence']==0 and
         base['roster_original_raw_sha256']==src['expected_roster_sha256'] and
         base['governance_roster_file']==src['governance_roster_file'] and
         base['review_manifest_file']==src['review_manifest_file'] and
         base['approval_file']==src['approval_file'] and
         base['expected_governance_roster_sha256']==src['expected_governance_roster_sha256'] and
         base['expected_hold_sha256']==roster['hold_original_raw_sha256'] and
         base['expected_review_manifest_sha256']==src['expected_review_manifest_sha256'] and
         base['expected_approval_sha256']==src['expected_approval_sha256'],
         'ONLY_AUTHENTIC_BASE_EC342_HOLD_PREDECESSOR_SUPPORTED','permission_denied')
    matched('ec342_hold_request_original',base['hold_file'],base['expected_hold_sha256'])
    hold=_original(row['ec342_hold_request_original'],read,'old_ec342_signed_hold')
    review=_original(row['ec342_review_manifest_original'],read,'old_ec342_signed_reviews')
    appr=_original(row['ec342_external_approval_original'],read,'old_ec342_signed_approval')
    exact(gov,old342.GOVERNANCE_FIELDS,'EC342_GOVERNANCE')
    exact(review,old342.REVIEW_MANIFEST_FIELDS,'EC342_REVIEW_INDEX')
    exact(hold,{'schema','claim','signature_ed25519'},'EC342_INITIATOR_SIGNATURE')
    exact(appr,{'schema','claim','signature_ed25519'},'EC342_EXTERNAL_APPROVER_SIGNATURE')
    need(gov['schema']==old342.GOVERNANCE_SCHEMA and
         gov['case_id']==roster['case_id'] and
         all(roster['change_approver'][k] not in {a[k] for a in (
             gov['initiator'],gov['external_approver'],*gov['reviewers'],
             roster['change_proposer'],*roster['receivers'])}
             for k in ('signer_id','public_hex','organization_id')),
         'INDEPENDENT_EC343_APPROVER_MUST_NOT_REUSE_EC342_OR_RECEIVER_ROLES',
         'permission_denied')
    old342._verify_signed(hold,old342.HOLD_SCHEMA,old342.DOMAIN_HOLD,
                          gov['initiator']['public_hex'],'EC385_EC342_SIGNED_HOLD')
    old342._verify_signed(appr,old342.APPROVAL_SCHEMA,old342.DOMAIN_APPROVAL,
                          gov['external_approver']['public_hex'],
                          'EC385_EC342_INDEPENDENT_SIGNED_APPROVAL')
    need(review['schema']==old342.REVIEW_MANIFEST_SCHEMA and
         review['hold_file']==base['hold_file'] and
         review['expected_hold_sha256']==base['expected_hold_sha256'] and
         type(review['attestations']) is list and
         len(review['attestations'])>=gov['required_support_quorum'],
         'EC342_QUORUM_REFERENCES_AUTHENTIC_HOLD','permission_denied')
    oldreviews=row['ec342_signed_review_originals']
    need(type(oldreviews) is list and len(oldreviews)==len(review['attestations']) and
         len(oldreviews)<=old342.MAX_REVIEWERS,'EC342_SIGNED_REVIEW_CENSUS_REQUIRED',
         'permission_denied')
    for rr,orig in zip(oldreviews,review['attestations'],strict=True):
        exact(orig,old342.REVIEW_REF_FIELDS,'AUTHENTIC_EC342_REVIEW_REFERENCE')
        _ref(rr,orig['file'],orig['sha256'],'EC342_REVIEW_ORIGINAL')
        signed=_original(rr,read,'ec342_signed_review')
        exact(signed,{'schema','claim','signature_ed25519'},'EC342_SIGNED_REVIEW')
        need(signed['schema']==old342.REVIEW_SCHEMA,'EC342_REVIEW_SIGNED_SCHEMA',
             'permission_denied')
    baseacks=_original(row['ec343_source_head_ack_set_original'],read,
                      'ec343_source_head_receiver_ack_index')
    need(baseacks.get('snapshot_file')==src['head_snapshot_file'] and
         baseacks.get('expected_snapshot_sha256')==src['expected_head_snapshot_sha256'],
         'EC343_PREVIOUS_RECEIVER_ACK_MUST_NAME_SOURCE_HEAD','permission_denied')
    baseackcount=_receipts(row['ec343_original_source_head_receiver_receipts'],
                           baseacks,read,'ec343_source_head')
    need(baseackcount==len(roster['receivers']),
         'EC343_FULL_RECEIVER_SIGNED_BASE_ACK_REQUIRED','permission_denied')
    # Actual legacy verifier checks the old EC342 review quorum and approval,
    # all preceding signed receiver ACKs and their signed chronology.
    pins={}
    base_state=old343._load_chain(src['head_snapshot_file'],
            src['expected_head_snapshot_sha256'],roster,src['expected_roster_sha256'],pins)
    verified,last_previous_ack=old343._ackset(src['head_ack_set_file'],src['expected_head_ack_set_sha256'],
            src['head_snapshot_file'],src['expected_head_snapshot_sha256'],roster,
            src['expected_roster_sha256'],0,base_state['hold_window'],pins,
            base_state['last_approval_utc'],src['timeline_evaluation_utc'])
    need(verified==baseackcount==len(roster['receivers']),
         'OLD_EC342_GENUINE_APPROVAL_AND_EC343_RECEIVER_SIGNED_ACKS_REQUIRED',
         'permission_denied')
    # Preserve the exact verified previous signed receipt time as EC343 does.
    # This is still signer-reported time, never independent calibrated UTC.
    base_state={**base_state,'last_ack_utc':max(base_state['last_approval_utc'],
                                                last_previous_ack)}
    old343.late(pins)
    target=row['ec343_signed_target_snapshot_original']
    finalack=row['ec343_signed_target_ack_set_original']
    # Bind verified offer and signed target to the *same* historical item, not
    # just to a pair of unrelated authentic EC343 changes.
    checkpoint=_original(old383['ec344_source_checkpoint_original'],read,
                         'authenticated_ec344_unsigned_checkpoint')
    exact(checkpoint,old344.CHECKPOINT_FIELDS,'ORIGINAL_EC344_CHECKPOINT')
    matched_targets=[x for x in checkpoint['announcements'] if
                     x['snapshot_file']==target['path'] and
                     x['expected_snapshot_sha256']==target['sha256'] and
                     x['ack_set_file']==finalack['path'] and
                     x['expected_ack_set_sha256']==finalack['sha256']]
    need(checkpoint['schema']==old344.CHECKPOINT_SCHEMA and
         len(matched_targets)==1 and matched_targets[0]['item_id']==src['item_id'] and
         src['item_id'] in src['disclosed_item_ids'],
         'EC343_SIGNED_TARGET_NOT_GENUINE_EC384_DISCLOSED_SOURCE',
         'permission_denied')
    main=_check_branch(target,finalack,
       row['ec343_original_signed_change_request'],
       row['ec343_original_signed_change_approval'],
       row['ec343_original_target_receiver_receipts'],
       source_snap=row['ec343_source_head_snapshot_original'],
       source_ack=row['ec343_source_head_ack_set_original'],
       roster=roster,roster_sha=src['expected_roster_sha256'],read=read,role='target',
       pinned_base_roster=base_state,eval_utc=src['timeline_evaluation_utc'])
    # EC344's checkpoint is unsigned: a second SHA-pinned independently signed
    # EC343 same-parent transition proves only a *visible local fork*, not that
    # anyone else received it or that it is a global fork census.
    siblings=[];seen={target['sha256']};nonce={main['change']['change_nonce_sha256']}
    need(type(row['ec343_competing_signed_successors']) is list and
         len(row['ec343_competing_signed_successors'])<=2,
         'MAX_TWO_EXPLICIT_COMPETING_SAME_PARENT_ORIGINALS','permission_denied')
    for i,s in enumerate(row['ec343_competing_signed_successors']):
        exact(s,SIBLING_FIELDS,'COMPETING_SIGNED_BRANCH')
        r=s['snapshot_original'];ack=s['ack_set_original']
        need(r['sha256'] not in seen,'DISTINCT_COMPETING_SUCCESSOR_SNAPSHOT_REQUIRED',
             'permission_denied')
        need(any(x['snapshot_file']==r['path'] and
          x['expected_snapshot_sha256']==r['sha256'] and
          x['ack_set_file']==ack['path'] and
          x['expected_ack_set_sha256']==ack['sha256']
          for x in checkpoint['announcements']),
          'ONLY_ORIGINALLY_CHECKPOINT_LISTED_SIGNED_SIBLING_CAN_BE_COMPARED',
          'permission_denied')
        b=_check_branch(r,ack,s['signed_change_original'],s['signed_approval_original'],
          s['receiver_receipt_originals'],source_snap=row['ec343_source_head_snapshot_original'],
          source_ack=row['ec343_source_head_ack_set_original'],roster=roster,
          roster_sha=src['expected_roster_sha256'],read=read,role='sibling_'+str(i),
          pinned_base_roster=base_state,eval_utc=src['timeline_evaluation_utc'])
        need(b['change']['change_nonce_sha256'] not in nonce and
             b['change_ref']['sha256']!=main['change_ref']['sha256'],
             'SIGNER_REUSED_CHANGE_NONCE_OR_DUPLICATED_SIBLING_REQUEST',
             'permission_denied')
        nonce.add(b['change']['change_nonce_sha256']);seen.add(r['sha256']);siblings.append(b)
    need([b['snapshot_ref']['sha256'] for b in siblings]==
         sorted({b['snapshot_ref']['sha256'] for b in siblings}),
         'COMPETING_SIGNED_SIBLING_CANONICAL_SHA_ORDER_REQUIRED',
         'permission_denied')
    all_acks=baseackcount+main['ack_count']+sum(s['ack_count'] for s in siblings)
    return {'tsa_channel_id':channel,'full_original_ec342_ec343_source_replay':True,
       'ec342_governance_sha256':row['ec342_governance_roster_original']['sha256'],
       'ec342_approved_hold_sha256':row['ec342_hold_request_original']['sha256'],
       'ec342_signed_review_sha256s':[r['sha256'] for r in oldreviews],
       'ec342_external_approval_sha256':row['ec342_external_approval_original']['sha256'],
       'ec343_source_head_snapshot_sha256':src['expected_head_snapshot_sha256'],
       'ec343_source_head_ack_sha256':src['expected_head_ack_set_sha256'],
       'ec343_target_snapshot_sha256':target['sha256'],
       'ec343_target_ack_sha256':finalack['sha256'],
       'ec343_signed_change_sha256':main['change_ref']['sha256'],
       'ec343_signed_change_approval_sha256':main['approval_ref']['sha256'],
       'ec343_change_request_kind':main['change']['change_request_kind'],
       'ec343_signed_sibling_sha256s':[s['snapshot_ref']['sha256'] for s in siblings],
       'ec342_signed_review_count':len(oldreviews),
       'ec343_signed_change_count':1+len(siblings),
       'ec343_verified_signed_receiver_ack_count':all_acks,
       'old_ec342_source_or_signed_approval_incomplete':False,
       'ec343_signed_change_or_predecessor_incomplete':(not main['ack_complete'] or
           any(not x['ack_complete'] for x in siblings)),
       'ec343_same_parent_signed_fork_observed':bool(siblings)}


def _engine(derive,**opts):
    popts=_inputs(opts,derive)
    parent_result=parent.audit(**popts)   # Actual live EC384->EC369; no report input.
    n=len(opts['historical_directory_root_shas']);psha=_parent(parent_result,n)
    pins={};categories={};forbidden=set();cache={}
    def read(ref,role,cap):
        p372.prior.lineage.parent.ref_check(ref,'EC385_'+role)
        path=ref['path']
        if path in cache:
            old_sha,raw,old_role=cache[path]
            need(path not in forbidden and old_sha==ref['sha256'] and
                 old_role==role and len(raw)<=cap,
                 'ORIGINAL_PATH_ROLE_ALIAS_SHA_OR_CAP_CONFLICT','permission_denied')
            return raw
        raw=p372._read(ref,'ec385_'+role,cap,pins,categories,forbidden)
        cache[path]=(ref['sha256'],raw,role)
        return raw
    def bundle(ref,role,fields,schema,cap):
        b=old353.strict_json(read(ref,role,cap),'EC385_'+role)
        exact(b,fields,role)
        need(b['schema']==schema and type(b['epochs']) is list and
             len(b['epochs'])==n,'AUTHENTIC_ORIGINAL_'+role,'permission_denied')
        return b
    ref384={'path':opts['historical_ec345_disclosure_archive_bundle_file'],
      'sha256':opts['expected_historical_ec345_disclosure_archive_bundle_sha256']}
    old384=bundle(ref384,'real_parent_ec384',parent.BUNDLE_FIELDS,parent.BUNDLE_SCHEMA,
                  parent.MAX_BUNDLE)
    ref383={'path':opts['historical_ec347_site_provenance_archive_bundle_file'],
      'sha256':opts['expected_historical_ec347_site_provenance_archive_bundle_sha256']}
    old383=bundle(ref383,'real_ec383',parent.parent.BUNDLE_FIELDS,
                  parent.parent.BUNDLE_SCHEMA,parent.parent.MAX_BUNDLE)
    ref382={'path':opts['historical_ec348_keeper_archive_bundle_file'],
      'sha256':opts['expected_historical_ec348_keeper_archive_bundle_sha256']}
    old382=bundle(ref382,'real_ec382',parent.parent.previous.BUNDLE_FIELDS,
                  parent.parent.previous.BUNDLE_SCHEMA,parent.parent.previous.MAX_BUNDLE)
    ref385={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    new=bundle(ref385,'new_ec385_receiver_archive',BUNDLE_FIELDS,BUNDLE_SCHEMA,MAX_BUNDLE)
    need(new['parent_ec384_canonical_result_sha256']==psha and
         new['ec384_historical_offer_archive_original_sha256']==ref384['sha256'] and
         old384['ec383_historical_site_archive_original_sha256']==ref383['sha256'] and
         old383['ec382_historical_keeper_archive_original_sha256']==ref382['sha256'] and
         new['claimed_directory_lineage_id']==old384['claimed_directory_lineage_id']==
          old383['claimed_directory_lineage_id']==old382['claimed_directory_lineage_id']==
          opts['claimed_historical_directory_lineage_id'],
         'ARCHIVE_MUST_BIND_LIVE_PARENT_AND_AUTHENTIC_EC384_TO_EC382_ORIGINALS',
         'permission_denied')
    # These are rejected as receiver originals even if sender labels happen to
    # name a readable path. Retain parent's explicit EC353 sender exclusion.
    ref377={'path':opts['historical_transparency_archive_bundle_file'],
            'sha256':opts['expected_historical_transparency_archive_bundle_sha256']}
    old377=bundle(ref377,'real_ec377',parent.parent.previous.previous.p379.p377.BUNDLE_FIELDS,
      parent.parent.previous.previous.p379.p377.BUNDLE_SCHEMA,
      parent.parent.previous.previous.p379.p377.MAX_BUNDLE)
    for ep in old377['epochs']:
        sender=old353.strict_json(read(ep['ec353_publication_bundle_original'],
          'ec353_untrusted_sender_labels_'+ep['ec353_publication_bundle_original']['sha256'],
          old353.MAX_BUNDLE),'EC385_EC353_SENDER_LABELS')
        parent.parent.previous.previous.p379._old_sender_labels(sender,forbidden)
    forbidden.update(v for k,v in opts.items() if k.endswith('_file') and type(v) is str)
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not parent_result['local_ec344_signed_views_ec345_authorized_offer_originals_consistent']
    epoch_reviews=[];inventories=[];previous_by_channel={};total_review=total_change=total_ack=0
    for idx,(ep,new384,old383ep,old382ep) in enumerate(zip(new['epochs'],
          old384['epochs'],old383['epochs'],old382['epochs'],strict=True)):
        for source,fields,kind in ((ep,EPOCH_FIELDS,'EC385_EPOCH'),
             (new384,parent.EPOCH_FIELDS,'EC384_EPOCH'),
             (old383ep,parent.parent.EPOCH_FIELDS,'EC383_EPOCH'),
             (old382ep,parent.parent.previous.EPOCH_FIELDS,'EC382_EPOCH')):
            exact(source,fields,kind)
            need(source['epoch_index']==idx and type(source['channels']) is list,
                 kind+'_INDEX_CHANNELS','permission_denied')
        count=len(ep['channels'])
        need(1<=count<=old349.MAX_CHANNELS and
             all(len(x['channels'])==count for x in (new384,old383ep,old382ep)),
             'ORIGINAL_SIGNED_CHANNEL_CENSUS','permission_denied')
        ids=[[r.get('tsa_channel_id') for r in x['channels']] for x in
             (ep,new384,old383ep,old382ep)]
        need(all(ids[0]==values for values in ids[1:]) and
             ids[0]==sorted(set(ids[0])),
             'CHANNEL_SIGNER_AND_ORDER_MUST_MATCH_EC384_PARENT','permission_denied')
        channels=[]
        for row,p384,p383,p382 in zip(ep['channels'],new384['channels'],
                                     old383ep['channels'],old382ep['channels'],strict=True):
            r=_channel(row,p384,p383,p382,read,forbidden)
            channels.append(r)
            flags[FLAGS[2]]|=not r['full_original_ec342_ec343_source_replay']
            flags[FLAGS[3]]|=r['old_ec342_source_or_signed_approval_incomplete']
            flags[FLAGS[4]]|=r['ec343_signed_change_or_predecessor_incomplete']
            flags[FLAGS[5]]|=r['ec343_same_parent_signed_fork_observed']
            before=previous_by_channel.get(r['tsa_channel_id'])
            if before is not None and r['full_original_ec342_ec343_source_replay']:
                same=('ec342_governance_sha256','ec342_approved_hold_sha256',
                      'ec342_signed_review_sha256s','ec342_external_approval_sha256',
                      'ec343_source_head_snapshot_sha256','ec343_source_head_ack_sha256',
                      'ec343_target_snapshot_sha256','ec343_target_ack_sha256',
                      'ec343_signed_change_sha256','ec343_signed_change_approval_sha256',
                      'ec343_change_request_kind')
                flags[FLAGS[6]]|=(not before['full_original_ec342_ec343_source_replay'] or
                    any(r[k]!=before[k] for k in same) or
                    r['ec343_signed_sibling_sha256s'][:len(before['ec343_signed_sibling_sha256s'])]!=
                       before['ec343_signed_sibling_sha256s'])
            previous_by_channel[r['tsa_channel_id']]=r
        if len(channels)==2:
            fields=('ec342_governance_sha256','ec342_approved_hold_sha256',
              'ec342_signed_review_sha256s','ec342_external_approval_sha256',
              'ec343_source_head_snapshot_sha256','ec343_source_head_ack_sha256',
              'ec343_target_snapshot_sha256','ec343_target_ack_sha256',
              'ec343_signed_change_sha256','ec343_signed_change_approval_sha256',
              'ec343_signed_sibling_sha256s')
            flags[FLAGS[6]]|=any(channels[0][key]!=channels[1][key] for key in fields)
        holds=[{k:r[k] for k in ('tsa_channel_id','ec342_governance_sha256',
           'ec342_approved_hold_sha256','ec342_signed_review_sha256s',
           'ec342_external_approval_sha256','ec343_source_head_snapshot_sha256',
           'ec343_source_head_ack_sha256')} for r in channels]
        changes=[{k:r[k] for k in ('tsa_channel_id','ec343_target_snapshot_sha256',
           'ec343_target_ack_sha256','ec343_signed_change_sha256',
           'ec343_signed_change_approval_sha256','ec343_change_request_kind',
           'ec343_signed_sibling_sha256s','ec343_same_parent_signed_fork_observed')}
           for r in channels]
        hsha=sha(canonical.canonical(holds));csha=sha(canonical.canonical(changes))
        cr=sum(r['ec342_signed_review_count'] for r in channels)
        cc=sum(r['ec343_signed_change_count'] for r in channels)
        ca=sum(r['ec343_verified_signed_receiver_ack_count'] for r in channels)
        total_review+=cr;total_change+=cc;total_ack+=ca
        flags[FLAGS[1]]|=(hsha!=opts['historical_ec342_approved_hold_inventory_shas'][idx]
          or csha!=opts['historical_ec343_signed_change_inventory_shas'][idx]
          or cr<opts['minimum_historical_ec342_signed_review_counts'][idx]
          or cc<opts['minimum_historical_ec343_signed_change_counts'][idx]
          or ca<opts['minimum_historical_ec343_signed_ack_counts'][idx])
        epoch_reviews.append({'epoch_index':idx,'original_signed_ec342_reviewer_count':cr,
          'original_signed_ec343_change_count':cc,
          'original_signed_ec343_receiver_ack_count':ca,
          'ec342_approved_hold_inventory_sha256':hsha,
          'ec343_signed_change_inventory_sha256':csha,
          'visible_signed_same_parent_branch_count':sum(len(r['ec343_signed_sibling_sha256s']) for r in channels),
          'missing_actual_original_source_channels':sum(not r['full_original_ec342_ec343_source_replay'] for r in channels),
          'local_original_ec342_approved_hold_and_ec343_signed_change_consistent':bool(channels) and
             all(r['full_original_ec342_ec343_source_replay'] and
                 not r['ec343_signed_change_or_predecessor_incomplete'] and
                 not r['old_ec342_source_or_signed_approval_incomplete'] and
                 not r['ec343_same_parent_signed_fork_observed'] for r in channels)})
        inventories.append({'epoch_index':idx,'original_ec342_signed_approved_hold_sources':holds,
           'original_ec343_independent_signed_change_approvals':changes,
           'ec342_approved_hold_inventory_sha256':hsha,
           'ec343_signed_change_inventory_sha256':csha})
    p372.prior.lineage.parent.ref_check(ref384,'EC385_REAL_EC384_PARENT_REF')
    p372.prior.lineage.parent.ref_check(ref385,'EC385_RECEIVER_BUNDLE_REF')
    p376.prior.tsa._check_late(pins)
    p376.prior.ec357._late_identity_check(pins,set())
    flags[FLAGS[7]]=True;flags[FLAGS[8]]=True
    inv={'schema':INVENTORY_SCHEMA,
         'live_ec384_through_ec369_parent_result_canonical_sha256':psha,
         'authentic_ec384_receiver_original_sha256':ref384['sha256'],
         'receiver_ec385_change_archive_original_sha256':ref385['sha256'],
         'claimed_directory_lineage_id':new['claimed_directory_lineage_id'],
         'historical_ec342_approved_hold_ec343_signed_change_epoch_reviews':inventories}
    invsha=sha(canonical.canonical(inv))
    if not derive and invsha!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    local=not any(flags[k] for k in FLAGS[:7])
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
       'command':'derive-historical-ec343-change-inventory' if derive else
                 'audit-historical-ec343-change-archive',
       'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                     OUTCOMES[-1])+'_unresolved',
       'exit_code':2,'offline_unresolved_exit_code':2,
       'verified_live_parent_ec384_canonical_result_sha256':psha,
       'historical_ec343_change_archive_bundle_original_sha256':ref385['sha256'],
       'receiver_verified_historical_ec343_change_inventory_sha256':invsha,
       'genuine_old_ec342_signed_review_original_count':total_review,
       'genuine_old_ec343_signed_change_original_count':total_change,
       'genuine_old_ec343_signed_receiver_ack_original_count':total_ack,
       'historical_ec343_change_epoch_reviews':epoch_reviews,
       'local_ec342_approved_hold_ec343_signed_change_originals_consistent':local,
       'sender_origin_path_required_or_read':False,
       'ec343_through_ec337_full_independent_original_historical_acceptance_performed':False,
       **flags,**{k:False for k in NEGATIVES},
       **({'unsigned_verified_historical_ec343_change_inventory':inv,
           'caller_external_inventory_pin_created_or_certified':False} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
