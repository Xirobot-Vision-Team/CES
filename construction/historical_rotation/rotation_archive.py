#!/usr/bin/env python3
"""EC387: re-open the authentic EC340 epoch-1 -> epoch-2 root rotation.

Mandatory unchanged EC386->EC369 receiver replay precedes this layer. The
EC341 manifest and EC342 approved hold come from the authenticated EC386
archive, never from a caller-provided replacement. The original EC340 verifier
replays all 8 Ed25519 issuer signatures, its signed observer and EC339->EC337.

A copied raw public key, a signed self-description or a locally derived SHA is
NOT institutional authority, off-site custody, trusted time or global finality.
No business code, original key or archive is written by either operator.
"""
from __future__ import annotations

import json

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from offline_authority import authority as old339
from issuer_root_rotation import rotation as old340
from root_lineage import lineage as old341
from conflict_hold import hold as old342
from transparency import transparency as old353
from historical_authority import authority_archive as p372
from historical_transparency import transparency_archive as p377
from historical_source import source_archive as p379
from historical_root import root_archive as parent

RESULT_SCHEMA='ces.ec387.receiver_old_ec340_epoch1_to_epoch2_original_rotation_unresolved.v1'
DERIVE_SCHEMA='ces.ec387.unsigned_old_ec340_epoch_root_rotation_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec387.receiver_old_ec340_epoch_root_rotation_denial.v1'
BUNDLE_SCHEMA='ces.ec387.receiver_historical_old_ec340_signed_rotation_archive.v1'
INVENTORY_SCHEMA='ces.ec387.receiver_verified_old_ec340_original_rotation_inventory.v1'
MAX_BUNDLE=350_000
MAX_ORIGINAL=320_000
NEW_SCALARS=('historical_ec340_signed_rotation_archive_bundle_file',
             'expected_historical_ec340_signed_rotation_archive_bundle_sha256')
AUDIT_ONLY=('expected_retained_historical_ec340_signed_rotation_inventory_sha256',)
NEW_REPEATS=(
 ('historical_ec340_role_rotation_inventory_shas','--historical-ec340-role-rotation-inventory-sha256'),
 ('historical_ec339_actor_grant_inventory_shas','--historical-ec339-actor-grant-inventory-sha256'),
 ('minimum_historical_ec340_signed_edge_counts','--minimum-historical-ec340-signed-edge-count'),
 ('minimum_historical_ec340_signed_observation_counts','--minimum-historical-ec340-signed-observation-count'),
 ('minimum_historical_ec339_signed_grant_status_counts','--minimum-historical-ec339-signed-grant-status-count'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
PARENT_SCALARS=(*parent.PARENT_SCALARS,*parent.NEW_SCALARS,*parent.AUDIT_ONLY)
PARENT_REPEATS=(*parent.PARENT_REPEATS,*parent.REPEAT_NAMES)
BUNDLE_FIELDS={'schema','parent_ec386_canonical_result_sha256',
               'ec386_historical_root_archive_original_sha256',
               'claimed_directory_lineage_id','epochs'}
EPOCH_FIELDS={'epoch_index','channels'}
CHANNEL_FIELDS={'tsa_channel_id','ec340_legacy_policy_original',
  'ec339_predecessor_authority_roster_original',
  'ec340_epoch2_successor_roster_original','ec340_observer_roster_original',
  'ec340_signed_retirement_observation_original','ec340_signed_role_edges',
  'ec339_original_signed_role_history','ec340_original_public_key_sources'}
EDGE_FIELDS={'side','role','edge_original'}
ROLE_HISTORY_FIELDS={'role','receipt_original','grant_original','status_original'}
KEY_SOURCE_FIELDS={'kind','role','public_hex','public_key_original'}
KEY_ORDER=(*(('old_issuer',r) for r in old340.ROLES),
           *(('new_issuer',r) for r in old340.ROLES),
           ('observer','independent'),
           *(('historical_actor',r) for r in old340.ROLES))
FLAGS=(
 'inherited_live_ec386_through_ec369_old_signed_root_or_hold_dispute',
 'external_retained_ec340_ec339_sha_or_signed_count_floor_disagrees',
 'old_ec340_authenticated_first_hop_or_parent_source_unavailable',
 'old_ec340_exact_eight_cross_signatures_and_observer_not_recovered',
 'old_ec339_original_actor_grant_status_or_role_key_source_not_recovered',
 'old_ec340_epoch2_rotation_not_bound_to_ec341_ec342_true_conflict_parent',
 'old_ec340_two_channel_or_later_epoch_root_actor_aba_rollback',
 'old_ec340_to_ec337_unmocked_external_history_not_independently_proven',
 'global_legal_key_custody_revocation_remote_freeze_and_trusted_utc_not_proven',
)
OUTCOMES=(
 'ec387_inherited_signed_root_hold_receiver_dispute',
 'ec387_offsite_claimed_rotation_and_actor_inventory_floor_disagrees',
 'ec387_authentic_signed_first_rotation_parent_original_unavailable',
 'ec387_old_epoch_transition_ed25519_observer_source_incomplete',
 'ec387_old_actor_grant_status_public_source_incomplete',
 'ec387_old_epoch2_to_ec341_conflict_parent_binding_disagrees',
 'ec387_cross_channel_epoch_root_or_actor_history_rollback',
 'ec387_deep_old_ec340_through_ec337_external_source_unproven',
 'ec387_no_global_legal_physical_or_trusted_time_authority',
)
NEGATIVES=(
 'ec340_issuer_signatures_establish_legal_institutional_authority',
 'ec339_historical_grants_authorize_actions_after_rotation',
 'ec340_epoch_two_root_is_independently_global_latest',
 'ec341_visible_signed_sibling_pair_exhausts_all_forks',
 'ec342_governance_signed_hold_proves_remote_freeze_executed',
 'raw_public_key_copies_prove_offsite_rekey_or_key_custody',
 'source_sha_inventory_was_independently_signed_by_this_software',
 'signed_observer_reported_time_is_calibrated_utc',
 'historical_actors_issuers_and_witnesses_are_physically_independent',
 'ec353_sender_label_paths_are_receiver_authenticated_originals',
 'missing_old_historical_originals_can_be_recreated_to_pass',
 'any_private_key_remote_provider_git_ci_cas_worm_or_native_ps_writes_performed',
 'unmocked_ec317_ec318_external_historical_replay_or_final_acceptance_proven',
)


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC387_'+code,status)


def exact(doc,fields,code):
    need(type(doc) is dict and set(doc)==set(fields),code+'_FIELDS_REQUIRED')


def sha(raw):return parent.sha(raw)


def _inputs(opts,derive):
    required=set((*PARENT_SCALARS,*PARENT_REPEATS,*NEW_SCALARS,*REPEAT_NAMES))
    if not derive:required.update(AUDIT_ONLY)
    need(set(opts)==required,'EXACT_EC386_PARENT_AND_EC387_RECEIVER_INPUTS_REQUIRED')
    old={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    parent._inputs(old,False)  # include the real parent audit-only original pin
    p372.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                             'EC387_RECEIVER_PINNED_EPOCH_ROTATION_ARCHIVE')
    if not derive:
        need(old353._sha(opts[AUDIT_ONLY[0]]),
             'INDEPENDENTLY_RETAINED_ROTATION_INVENTORY_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'HISTORIC_EPOCH_BOUNDS')
    caps={'minimum_historical_ec340_signed_edge_counts':16,
          'minimum_historical_ec340_signed_observation_counts':2,
          'minimum_historical_ec339_signed_grant_status_counts':16}
    for name in REPEAT_NAMES:
        arr=opts[name]
        need(type(arr) is list and len(arr)==n,'ORIGINAL_EPOCH_CENSUS_'+name.upper())
        if name in caps:
            need(all(type(v) is int and 0<=v<=caps[name] for v in arr),
                 'BOUNDED_SIGNED_ORIGINAL_FLOOR_'+name.upper())
        else:
            need(all(old353._sha(v) for v in arr),
                 'EXTERNALLY_RETAINED_ORIGINAL_SHA_'+name.upper())
    return old


def _parent(result,n):
    need(type(result) is dict and result.get('schema')==parent.RESULT_SCHEMA and
         result.get('exit_code')==2 and
         result.get('sender_origin_path_required_or_read') is False and
         result.get('ec341_through_ec337_full_independent_original_historical_acceptance_performed') is False and
         type(result.get('historical_ec341_root_conflict_epoch_reviews')) is list and
         len(result['historical_ec341_root_conflict_epoch_reviews'])==n and
         type(result.get('local_old_ec341_signed_root_conflict_ec342_hold_originals_consistent')) is bool and
         all(result.get(k) is False for k in parent.NEGATIVES) and
         all(type(result.get(k)) is bool for k in parent.FLAGS) and
         all(result[k] is True for k in parent.FLAGS[-2:]) and
         result.get('status')==next((parent.OUTCOMES[i] for i,k in enumerate(parent.FLAGS)
              if result[k]),parent.OUTCOMES[-1])+'_unresolved' and
         result['local_old_ec341_signed_root_conflict_ec342_hold_originals_consistent']==(
              not any(result[k] for k in (*parent.FLAGS[:5],parent.FLAGS[6]))),
         'ACTUAL_UNCHANGED_EC386_THROUGH_EC369_PARENT_REQUIRED','unavailable')
    return sha(canonical.canonical(result))


def _ref(candidate,path,digest,role):
    parent._ref(candidate,path,digest,'EC387_'+role)


def _json(read,ref,role):
    return parent._json(read,ref,'EC387_'+role)


def _missing(channel):
    return {'tsa_channel_id':channel,'full_original_ec340_signed_rotation_replay':False,
       'ec340_policy_sha256':None,'ec339_predecessor_sha256':None,
       'ec340_epoch2_successor_sha256':None,'ec340_observer_sha256':None,
       'ec340_signed_observation_sha256':None,'ec340_effective_utc':None,
       'ec340_verifier_challenge_sha256':None,
       'ec340_first_hop_edge_sha256s':[],
       'ec339_receipt_grant_status_sha256s':[],
       'ec340_original_public_key_copy_sha256s':[],
       'ec341_conflict_parent_epoch':None,'ec341_conflict_parent_root_sha256':None,
       'ec340_signed_role_edge_count':0,'ec340_signed_observation_count':0,
       'ec339_signed_grant_status_count':0,
       'ec340_root_originals_incomplete':True,
       'ec339_actor_source_originals_incomplete':True,
       'ec340_conflict_parent_not_proven':True}


def _channel(row,source,read):
    """Reopen originals *from the EC386 authenticated channel*, not labels.

    The authentic parent archive has already passed its live EC386 audit when
    called by _engine. The direct function is also testable with signed old
    test corpus; it never accepts a replacement manifest from the new bundle.
    """
    exact(row,CHANNEL_FIELDS,'RECEIVER_CHANNEL')
    exact(source,parent.CHANNEL_FIELDS,'AUTHENTIC_EC386_CHANNEL')
    channel=row['tsa_channel_id']
    need(channel==source['tsa_channel_id'],'TRUE_PARENT_CHANNEL_MISMATCH',
         'permission_denied')
    if source['ec341_lineage_manifest_original'] is None:
        need(source['ec342_governance_roster_original'] is None and
             source['ec342_signed_hold_request_original'] is None and
             all(row[k] is None for k in CHANNEL_FIELDS if k not in (
                 'tsa_channel_id','ec340_signed_role_edges',
                 'ec339_original_signed_role_history','ec340_original_public_key_sources')) and
             row['ec340_signed_role_edges']==[] and
             row['ec339_original_signed_role_history']==[] and
             row['ec340_original_public_key_sources']==[],
             'MISSING_PARENT_MUST_NOT_ACCEPT_NEW_SIGNED_FIRST_ROOT',
             'permission_denied')
        return _missing(channel)
    need(source['ec342_governance_roster_original'] is not None and
         source['ec342_signed_hold_request_original'] is not None,
         'SIGNED_PARENT_HOLD_REQUIRED','permission_denied')
    manifest_ref=source['ec341_lineage_manifest_original']
    manifest=_json(read,manifest_ref,'authentic_ec341_manifest')
    old341._check_manifest(manifest)  # exact legacy manifest shape and SHA pins
    context,history,first=manifest['context'],manifest['history'],manifest['hops'][0]
    gov=old342._governance(source['ec342_governance_roster_original']['path'],
                          source['ec342_governance_roster_original']['sha256'])
    need(gov['lineage_manifest_original_raw_sha256']==manifest_ref['sha256'] and
         gov['current_root_original_raw_sha256']==manifest['hops'][-1]['expected_successor_roster_sha256'],
         'PARENT_HOLD_MUST_PIN_TRUE_UNMODIFIED_EC341_MANIFEST','permission_denied')
    pins=(
      ('ec340_legacy_policy_original',context['policy_file'],context['expected_policy_sha256']),
      ('ec339_predecessor_authority_roster_original',context['authority_roster_file'],
        context['expected_authority_roster_sha256']),
      ('ec340_epoch2_successor_roster_original',first['successor_roster_file'],
        first['expected_successor_roster_sha256']),
      ('ec340_observer_roster_original',first['observer_roster_file'],
        first['expected_observer_roster_sha256']),
      ('ec340_signed_retirement_observation_original',first['root_observation_file'],
        first['expected_root_observation_sha256']),
    )
    docs={}
    for key,path,digest in pins:
        _ref(row[key],path,digest,'EXACT_MANIFEST_'+key.upper())
        docs[key]=_json(read,row[key],key)
    legacy=docs['ec339_predecessor_authority_roster_original']
    successor=docs['ec340_epoch2_successor_roster_original']
    observer=docs['ec340_observer_roster_original']
    policy=docs['ec340_legacy_policy_original']
    need(type(policy.get('actors')) is list and len(policy['actors'])==4 and
         legacy.get('schema')==old339.ROSTER_SCHEMA and
         successor.get('schema')==old340.ROOT_SCHEMA and
         observer.get('schema')==old340.OBSERVER_ROOT_SCHEMA and
         successor['predecessor_roster_original_raw_sha256']==
             row['ec339_predecessor_authority_roster_original']['sha256'] and
         successor['epoch']==2,
         'OLD_EC340_MUST_BEGIN_AT_TRUE_EC339_EPOCH_ONE','permission_denied')
    signed_edges=row['ec340_signed_role_edges']
    need(type(signed_edges) is list and len(signed_edges)==8,
         'ALL_EIGHT_SIGNED_FIRST_HOP_EDGES_REQUIRED','permission_denied')
    edge_paths={};edge_shas={};edge_refs=[]
    for i,edge in enumerate(signed_edges):
        exact(edge,EDGE_FIELDS,'SIGNED_SIDE_ROLE_EDGE')
        side,role=old340.EDGE_KEYS[i]
        manifest_edge=first['edge_signatures'][i]
        need(edge['side']==manifest_edge['side']==side and
             edge['role']==manifest_edge['role']==role,
             'EXACT_OLD_NEW_ROLE_SIGNED_EDGE_ORDER','permission_denied')
        ref=edge['edge_original']
        _ref(ref,manifest_edge['file'],manifest_edge['sha256'],
             'SIGNED_EDGE_MUST_MATCH_AUTHENTIC_EC341_FIRST_HOP')
        edge_paths[(side,role)]=ref['path'];edge_shas[(side,role)]=ref['sha256']
        edge_refs.append(ref)
        _json(read,ref,'old_ec340_ed25519_'+side+'_'+role)
    receipts=row['ec339_original_signed_role_history']
    need(type(receipts) is list and len(receipts)==4,
         'FOUR_SIGNED_HISTORICAL_ROLE_HISTORY_ROWS_REQUIRED','permission_denied')
    role_history=[];receipt_pin=[]
    for i,item in enumerate(receipts):
        exact(item,ROLE_HISTORY_FIELDS,'EC339_ACTOR_ROLE_HISTORY')
        role=old340.ROLES[i]
        need(item['role']==role,'EC339_SIGNED_ROLE_ORDER_MISMATCH','permission_denied')
        matched={'role':role}
        for kind in ('receipt','grant','status'):
            key=kind+'_original'
            fname=role+'_'+kind+'_file';sha_key='expected_'+role+'_'+kind+'_sha256'
            _ref(item[key],history[fname],history[sha_key],
                 'SIGNED_EC339_'+role.upper()+'_'+kind.upper())
            signed=_json(read,item[key],'old_ec339_'+role+'_'+kind)
            need(type(signed.get('claim')) is dict,
                 'EC339_SIGNED_ROLE_HISTORY_CLAIM_REQUIRED','permission_denied')
            matched[kind]=item[key]['sha256']
            receipt_pin.append(item[key]['sha256'])
        role_history.append(matched)
    # The visible root/actor public bytes must match actual *roster* sources.
    # The 9 root/observer copies must additionally be the identical original
    # reference already pinned by EC386, not a replacement signed-key path.
    source_copies={item['public_hex']:item['public_key_original'] for item in
                   source['ec341_signer_public_key_copies']}
    need(len(source_copies)==len(source['ec341_signer_public_key_copies']),
         'DUPLICATED_AUTHENTIC_EC386_ISSUER_PUBLIC_KEY_SOURCE','permission_denied')
    key_sources=row['ec340_original_public_key_sources']
    need(type(key_sources) is list and len(key_sources)==len(KEY_ORDER),
         'ALL_OLD_NEW_WITNESS_AND_HISTORICAL_ACTOR_RAW_PUBLIC_KEYS_REQUIRED',
         'permission_denied')
    key_shas=[];all_pub=[];key_original_bytes={}
    for i,item in enumerate(key_sources):
        exact(item,KEY_SOURCE_FIELDS,'ORIGINAL_RAW_PUBLIC_KEY_SOURCE')
        kind,role=KEY_ORDER[i]
        need(item['kind']==kind and item['role']==role,
             'ORDERED_ROLE_SCOPED_PUBLIC_KEY_SOURCE_REQUIRED','permission_denied')
        idx=old340.ROLES.index(role) if role in old340.ROLES else None
        pub=(legacy['issuers'][idx]['issuer_public_hex'] if kind=='old_issuer' else
             successor['issuers'][idx]['issuer_public_hex'] if kind=='new_issuer' else
             observer['observer_public_hex'] if kind=='observer' else
             policy['actors'][idx]['public_hex'])
        need(item['public_hex']==pub and old353._sha(pub),
             'PUB_SOURCE_MUST_MATCH_MANIFEST_PINNED_ROLE_OR_ACTOR','permission_denied')
        if kind!='historical_actor':
            need(pub in source_copies and
                 item['public_key_original']==source_copies[pub],
                 'FIRST_HOP_KEY_MUST_REUSE_AUTHENTIC_PARENT_EC386_ORIGINAL',
                 'permission_denied')
        key_ref=item['public_key_original']
        raw=read(key_ref,'ec387_raw_public_'+kind+'_'+role,32)
        need(len(raw)==32 and raw.hex()==pub,
             'SINGLE_RAW_ED25519_PUBLIC_KEY_COPY_MUST_MATCH_SIGNED_ROOT',
             'permission_denied')
        key_shas.append(key_ref['sha256']);all_pub.append(pub)
        key_original_bytes[key_ref['path']]=raw
    need(len(set(all_pub))==len(all_pub),
         'REUSED_OLD_NEW_ISSUER_WITNESS_OR_ACTOR_KEY','permission_denied')
    # Independently execute the unmodified legacy EC340 full original verifier,
    # not a caller-provided verdict. That code checks all 8 Ed25519 domains,
    # challenged signed observer, historical EC339 actors/grants/status, and
    # full EC338->EC337 SHA-bound ZIP replay with a late entire-file recheck.
    result=old340.verify_rotation(
       **context,**history,
       successor_roster_file=first['successor_roster_file'],
       expected_successor_roster_sha256=first['expected_successor_roster_sha256'],
       expected_current_root_sha256=first['expected_successor_roster_sha256'],
       expected_current_root_epoch=2,
       observer_roster_file=first['observer_roster_file'],
       expected_observer_roster_sha256=first['expected_observer_roster_sha256'],
       root_observation_file=first['root_observation_file'],
       expected_root_observation_sha256=first['expected_root_observation_sha256'],
       edge_files=edge_paths,edge_shas=edge_shas,
       root_evaluation_utc=first['evaluation_utc'],
       verifier_challenge_sha256=first['verifier_challenge_sha256'])
    need(result.get('schema')==old340.RESULT_SCHEMA and
         result.get('exit_code')==2 and
         result.get('status')=='historical_old_epoch_and_cross_signed_successor_locally_verified_unresolved' and
         result.get('predecessor_roster_original_raw_sha256')==context['expected_authority_roster_sha256'] and
         result.get('successor_roster_original_raw_sha256')==first['expected_successor_roster_sha256'] and
         result.get('historical_ec339_to_ec337_original_full_replay_verified') is True and
         result.get('eight_separate_old_new_ed25519_signatures_verified') is True and
         result.get('independent_observer_challenged_signed_retirement_verified') is True and
         result.get('historical_ec339_not_accepted_as_new_epoch_authorization') is True and
         all(result.get(k) is False for k in old340.NEGATIVES),
         'UNCHANGED_EC340_EC339_EC337_ED25519_AND_HISTORY_REPLAY_REQUIRED',
         'permission_denied')
    # Recheck that this true first root feeds the specific visible EC341 conflict
    # that the old, independently approved EC342 signed hold named.
    parent_epoch=gov['parent_epoch']
    need(type(parent_epoch) is int and 1<=parent_epoch<=len(manifest['hops']) and
         manifest['hops'][parent_epoch-1]['expected_successor_roster_sha256']==
             gov['selected_successor_original_raw_sha256'] and
         (context['expected_authority_roster_sha256'] if parent_epoch==1 else
          manifest['hops'][parent_epoch-2]['expected_successor_roster_sha256'])==
             gov['parent_root_original_raw_sha256'] and
         any(f['parent_epoch']==parent_epoch and
             f['hop']['expected_successor_roster_sha256']==
               gov['alternative_successor_original_raw_sha256']
             for f in manifest['forks']),
         'GENUINE_EC340_ROOT_MUST_BE_ANCESTOR_OF_APPROVED_EC341_SIBLING_CONFLICT',
         'permission_denied')
    # A new independent source copied from already pinned parent is NOT a new
    # authority, but reread those 9 roots and all 4 newly supplied actor bytes.
    for item in key_sources:
        key_ref=item['public_key_original']
        fresh=p372._read(key_ref,'ec387_late_'+key_ref['sha256'],32,{}, {},set())
        need(fresh==key_original_bytes[key_ref['path']],
             'OLD_ROLE_PUBLIC_SOURCE_CHANGED_AFTER_SIGNED_ROTATION_REPLAY',
             'permission_denied')
    return {'tsa_channel_id':channel,
       'full_original_ec340_signed_rotation_replay':True,
       'ec340_policy_sha256':context['expected_policy_sha256'],
       'ec339_predecessor_sha256':context['expected_authority_roster_sha256'],
       'ec340_epoch2_successor_sha256':first['expected_successor_roster_sha256'],
       'ec340_observer_sha256':first['expected_observer_roster_sha256'],
       'ec340_signed_observation_sha256':first['expected_root_observation_sha256'],
       'ec340_effective_utc':successor['effective_utc'],
       'ec340_verifier_challenge_sha256':first['verifier_challenge_sha256'],
       'ec340_first_hop_edge_sha256s':[edge_shas[k] for k in old340.EDGE_KEYS],
       'ec339_receipt_grant_status_sha256s':role_history,
       'ec340_original_public_key_copy_sha256s':key_shas,
       'ec341_conflict_parent_epoch':parent_epoch,
       'ec341_conflict_parent_root_sha256':gov['parent_root_original_raw_sha256'],
       'ec340_signed_role_edge_count':8,
       'ec340_signed_observation_count':1,
       'ec339_signed_grant_status_count':8,
       'ec340_root_originals_incomplete':False,
       'ec339_actor_source_originals_incomplete':False,
       'ec340_conflict_parent_not_proven':False}


def _engine(derive,**opts):
    popts=_inputs(opts,derive)
    parent_result=parent.audit(**popts)  # MANDATORY real, unmodified EC386->EC369
    n=len(opts['historical_directory_root_shas'])
    parent_sha=_parent(parent_result,n)
    pins={};categories={};forbidden=set();cache={}
    def read(ref,role,cap):
        p372.prior.lineage.parent.ref_check(ref,'EC387_'+role)
        path=ref['path']
        if path in cache:
            original_sha,raw=cache[path]
            need(path not in forbidden and original_sha==ref['sha256'] and len(raw)<=cap,
                 'REUSED_SOURCE_PATH_SHA_CAP_OR_SENDER_LABEL','permission_denied')
            return raw
        raw=p372._read(ref,'ec387_source_'+ref['sha256'],cap,pins,categories,forbidden)
        cache[path]=(ref['sha256'],raw)
        return raw
    ref386={'path':opts[parent.NEW_SCALARS[0]],'sha256':opts[parent.NEW_SCALARS[1]]}
    ref387={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    def bundle(ref,role,fields,schema,cap=MAX_BUNDLE):
        doc=old353.strict_json(read(ref,'ec387_bundle_'+role,cap),'EC387_'+role)
        exact(doc,fields,'ARCHIVE_'+role)
        need(doc['schema']==schema and type(doc['epochs']) is list and
             len(doc['epochs'])==n,'EXACT_AUTHENTIC_ARCHIVE_SCHEMA_EPOCHS_'+role,
             'permission_denied')
        return doc
    earlier=bundle(ref386,'old_ec386_root',parent.BUNDLE_FIELDS,
                   parent.BUNDLE_SCHEMA,parent.MAX_BUNDLE)
    current=bundle(ref387,'receiver_ec387_rotation',BUNDLE_FIELDS,BUNDLE_SCHEMA)
    need(current['parent_ec386_canonical_result_sha256']==parent_sha and
         current['ec386_historical_root_archive_original_sha256']==ref386['sha256'] and
         current['claimed_directory_lineage_id']==earlier['claimed_directory_lineage_id']==
             opts['claimed_historical_directory_lineage_id'],
         'REAL_EC386_CANONICAL_VERDICT_WHOLE_ORIGINAL_AND_LINEAGE_REQUIRED',
         'permission_denied')
    # Forbid sender-origin EC353 labels as independently recovered receiver
    # originals, and any caller-controlled archive path reintroduced as source.
    ref377={'path':opts['historical_transparency_archive_bundle_file'],
            'sha256':opts['expected_historical_transparency_archive_bundle_sha256']}
    sender_index=bundle(ref377,'ec377_sender_index',p377.BUNDLE_FIELDS,
                        p377.BUNDLE_SCHEMA,p377.MAX_BUNDLE)
    for ep in sender_index['epochs']:
        label_ref=ep['ec353_publication_bundle_original']
        sender=old353.strict_json(read(label_ref,'sender_labels',old353.MAX_BUNDLE),
                                  'EC387_SENDER_LABELS_UNTRUSTED')
        p379._old_sender_labels(sender,forbidden)
        forbidden.add(label_ref['path'])
    forbidden.add(ref377['path'])
    forbidden.update(v for k,v in opts.items() if k.endswith('_file') and type(v) is str)
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not parent_result['local_old_ec341_signed_root_conflict_ec342_hold_originals_consistent']
    epochs=[];inventory=[];previous={};edges_total=observer_total=grant_total=0
    for idx,(ep,ancestor) in enumerate(zip(current['epochs'],earlier['epochs'],strict=True)):
        exact(ep,EPOCH_FIELDS,'EC387_EPOCH')
        exact(ancestor,parent.EPOCH_FIELDS,'AUTHENTIC_EC386_EPOCH')
        need(ep['epoch_index']==ancestor['epoch_index']==idx and
             type(ep['channels']) is list and type(ancestor['channels']) is list and
             1<=len(ep['channels'])==len(ancestor['channels'])<=2,
             'EPOCH_AND_CHANNEL_CENSUS_BOUND_TO_TRUE_PARENT','permission_denied')
        ids=[[r.get('tsa_channel_id') for r in rows] for rows in
             (ep['channels'],ancestor['channels'])]
        need(ids[0]==ids[1] and ids[0]==sorted(set(ids[0])),
             'SORTED_PARENT_CHANNEL_IDENTITIES_REQUIRED','permission_denied')
        rows=[]
        for row,source in zip(ep['channels'],ancestor['channels'],strict=True):
            result=_channel(row,source,read)
            rows.append(result)
            flags[FLAGS[2]]|=not result['full_original_ec340_signed_rotation_replay']
            flags[FLAGS[3]]|=result['ec340_root_originals_incomplete']
            flags[FLAGS[4]]|=result['ec339_actor_source_originals_incomplete']
            flags[FLAGS[5]]|=result['ec340_conflict_parent_not_proven']
            prior=previous.get(result['tsa_channel_id'])
            identity=tuple(k for k in result if k not in (
                'tsa_channel_id','ec340_signed_role_edge_count',
                'ec340_signed_observation_count','ec339_signed_grant_status_count',
                'ec340_root_originals_incomplete','ec339_actor_source_originals_incomplete',
                'ec340_conflict_parent_not_proven'))
            if prior:
                flags[FLAGS[6]]|=(not prior['full_original_ec340_signed_rotation_replay'] or
                    any(prior[k]!=result[k] for k in identity) or
                    any(result[k]<prior[k] for k in (
                     'ec340_signed_role_edge_count','ec340_signed_observation_count',
                     'ec339_signed_grant_status_count')))
            previous[result['tsa_channel_id']]=result
        if len(rows)==2:
            flags[FLAGS[6]]|=any(rows[0][k]!=rows[1][k] for k in identity)
        rotations=[{k:r[k] for k in (
            'tsa_channel_id','ec340_policy_sha256','ec339_predecessor_sha256',
            'ec340_epoch2_successor_sha256','ec340_observer_sha256',
            'ec340_signed_observation_sha256','ec340_effective_utc',
            'ec340_verifier_challenge_sha256','ec340_first_hop_edge_sha256s',
            'ec340_original_public_key_copy_sha256s',
            'ec341_conflict_parent_epoch','ec341_conflict_parent_root_sha256',
            'ec340_signed_role_edge_count','ec340_signed_observation_count')} for r in rows]
        actors=[{k:r[k] for k in ('tsa_channel_id','ec340_policy_sha256',
            'ec339_predecessor_sha256','ec339_receipt_grant_status_sha256s',
            'ec339_signed_grant_status_count')} for r in rows]
        rotation_sha=sha(canonical.canonical(rotations));actor_sha=sha(canonical.canonical(actors))
        edges=sum(r['ec340_signed_role_edge_count'] for r in rows)
        obs=sum(r['ec340_signed_observation_count'] for r in rows)
        grants=sum(r['ec339_signed_grant_status_count'] for r in rows)
        edges_total+=edges;observer_total+=obs;grant_total+=grants
        flags[FLAGS[1]]|=(rotation_sha!=opts['historical_ec340_role_rotation_inventory_shas'][idx] or
            actor_sha!=opts['historical_ec339_actor_grant_inventory_shas'][idx] or
            edges<opts['minimum_historical_ec340_signed_edge_counts'][idx] or
            obs<opts['minimum_historical_ec340_signed_observation_counts'][idx] or
            grants<opts['minimum_historical_ec339_signed_grant_status_counts'][idx])
        epochs.append({'epoch_index':idx,
            'old_ec340_eight_way_signed_role_edge_count':edges,
            'old_ec340_signed_observation_count':obs,
            'old_ec339_signed_grant_status_count':grants,
            'old_ec340_rotation_inventory_sha256':rotation_sha,
            'old_ec339_actor_history_inventory_sha256':actor_sha,
            'missing_authentic_ec340_original_channels':sum(not r['full_original_ec340_signed_rotation_replay'] for r in rows),
            'local_old_ec340_rotation_and_ec341_conflict_parent_consistent':
                all(r['full_original_ec340_signed_rotation_replay'] for r in rows) and
                not flags[FLAGS[6]]})
        inventory.append({'epoch_index':idx,
            'old_ec340_signed_root_rotations':rotations,
            'old_ec339_original_actor_role_histories':actors,
            'old_ec340_rotation_inventory_sha256':rotation_sha,
            'old_ec339_actor_history_inventory_sha256':actor_sha})
    flags[FLAGS[7]]=True;flags[FLAGS[8]]=True
    inv={'schema':INVENTORY_SCHEMA,
       'live_ec386_to_ec369_parent_canonical_result_sha256':parent_sha,
       'receiver_original_ec386_root_archive_sha256':ref386['sha256'],
       'receiver_original_ec387_rotation_archive_sha256':ref387['sha256'],
       'claimed_directory_lineage_id':current['claimed_directory_lineage_id'],
       'historical_ec340_rotation_epoch_reviews':inventory}
    invsha=sha(canonical.canonical(inv))
    if not derive and invsha!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    local=not any(flags[k] for k in (*FLAGS[:7],))
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
      'command':'derive-historical-ec340-rotation-inventory' if derive else
                'audit-historical-ec340-rotation-archive',
      'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                    OUTCOMES[-1])+'_unresolved',
      'exit_code':2,'offline_unresolved_exit_code':2,
      'verified_live_parent_ec386_canonical_result_sha256':parent_sha,
      'historical_ec340_rotation_archive_original_sha256':ref387['sha256'],
      'receiver_verified_old_ec340_signed_rotation_inventory_sha256':invsha,
      'genuine_old_ec340_signed_edge_count':edges_total,
      'genuine_old_ec340_signed_observation_count':observer_total,
      'genuine_old_ec339_signed_grant_status_count':grant_total,
      'historical_ec340_rotation_epoch_reviews':epochs,
      'local_old_ec340_signed_rotation_ec341_conflict_parent_originals_consistent':local,
      'sender_origin_path_required_or_read':False,
      'ec340_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
      **flags,**{k:False for k in NEGATIVES},
      **({'unsigned_verified_old_ec340_rotation_inventory':inv,
          'caller_retained_inventory_sha_independently_certified':False} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
