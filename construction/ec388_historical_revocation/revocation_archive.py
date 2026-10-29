#!/usr/bin/env python3
"""EC388: historical EC339 role grants, challenged revocation and EC340 retirement.

The unchanged EC387->EC369 receiver audit is mandatory, not a supplied PASS.
Authenticated EC387/EC386 originals provide the sole baseline; supplementary
EC339 status originals remain individually SHA-pinned and Ed25519-verified.
A status is a signed *claim* as of a stated time, not a timestamp authority,
real-time revocation lookup, legal authority, or permission after epoch-1 ends.
This module never creates or replaces a signed original.
"""
from __future__ import annotations

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec338_independent_custody import ceremony as old338
from ec339_offline_authority import authority as old339
from ec340_issuer_root_rotation import rotation as old340
from ec341_root_lineage import lineage as old341
from ec353_transparency import transparency as old353
from ec372_historical_authority import authority_archive as p372
from ec377_historical_transparency import transparency_archive as p377
from ec379_historical_source import source_archive as p379
from ec387_historical_rotation import rotation_archive as parent

RESULT_SCHEMA='ces.ec388.receiver_old_ec339_issuer_grant_revocation_retirement_unresolved.v1'
DERIVE_SCHEMA='ces.ec388.unsigned_old_ec339_issuer_revocation_retirement_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec388.receiver_old_ec339_issuer_revocation_retirement_denial.v1'
BUNDLE_SCHEMA='ces.ec388.receiver_historical_old_ec339_issuer_revocation_archive.v1'
INVENTORY_SCHEMA='ces.ec388.receiver_verified_old_ec339_retirement_role_state_inventory.v1'
MAX_BUNDLE=370_000
NEW_SCALARS=('historical_ec339_retirement_revocation_archive_bundle_file',
             'expected_historical_ec339_retirement_revocation_archive_bundle_sha256')
AUDIT_ONLY=('expected_retained_historical_ec339_retirement_revocation_inventory_sha256',)
NEW_REPEATS=(
 ('historical_ec339_retirement_role_inventory_shas','--historical-ec339-retirement-role-inventory-sha256'),
 ('historical_ec339_revocation_transition_inventory_shas','--historical-ec339-revocation-transition-inventory-sha256'),
 ('minimum_historical_ec338_signed_actor_receipt_counts','--minimum-historical-ec338-signed-actor-receipt-count'),
 ('minimum_historical_ec339_retirement_status_counts','--minimum-historical-ec339-retirement-status-count'),
 ('minimum_historical_ec339_signed_revocation_transition_counts','--minimum-historical-ec339-signed-revocation-transition-count'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
PARENT_SCALARS=(*parent.PARENT_SCALARS,*parent.NEW_SCALARS,*parent.AUDIT_ONLY)
PARENT_REPEATS=(*parent.PARENT_REPEATS,*parent.REPEAT_NAMES)
BUNDLE_FIELDS={'schema','parent_ec387_canonical_result_sha256',
               'ec387_historical_rotation_archive_original_sha256',
               'claimed_directory_lineage_id','epochs'}
EPOCH_FIELDS={'epoch_index','channels'}
CHANNEL_FIELDS={'tsa_channel_id','ec338_policy_original','ec339_issuer_roster_original',
                'ec340_successor_roster_original','ec340_retirement_observation_original',
                'ec339_role_retirement_reviews'}
ROLE_FIELDS={'role','actor_receipt_original','issuer_grant_original',
             'baseline_status_original','additional_challenged_status_originals'}
STATUS_FIELDS={'signed_status_original','verifier_challenge_sha256','evaluation_utc'}
FLAGS=(
 'inherited_live_ec387_through_ec369_signed_rotation_or_original_dispute',
 'external_retained_ec338_ec339_sha_or_signed_role_evidence_floor_disagrees',
 'authentic_ec338_actor_grant_status_predecessor_source_unavailable',
 'signed_challenged_ec339_status_spanning_true_epoch1_retirement_not_recovered',
 'ec339_old_issuer_signed_revocation_state_conflict_or_aba_detected',
 'old_ec339_grant_window_does_not_cover_ec340_retirement_boundary',
 'old_ec339_retirement_channel_or_later_epoch_original_history_rollback',
 'old_ec339_through_ec337_unmocked_external_historical_chain_not_independently_proven',
 'global_revocation_completeness_issuer_authority_physical_custody_and_trusted_utc_not_proven',
)
OUTCOMES=(
 'ec388_inherited_live_signed_rotation_or_historical_original_dispute',
 'ec388_outside_retained_grant_revocation_sha_or_count_disagrees',
 'ec388_authentic_ec338_ec339_original_role_predecessor_unavailable',
 'ec388_challenged_signed_status_across_epoch1_retirement_missing',
 'ec388_visible_signed_old_issuer_revocation_contradiction_or_aba',
 'ec388_historical_grant_expired_or_not_effective_at_root_retirement',
 'ec388_cross_channel_or_epoch_historical_grant_status_rollback',
 'ec388_unmocked_external_ec339_to_ec337_history_not_proven',
 'ec388_global_revocation_legal_physical_or_trusted_time_authority_not_proven',
)
NEGATIVES=(
 'ec339_old_root_signed_grants_are_new_epoch_authorizations',
 'old_issuer_signing_status_after_rotation_is_current_issuer_authority',
 'ec340_root_retirement_automatically_revokes_every_ec339_actor_grant',
 'a_status_claimed_as_of_time_proves_its_actual_issue_time',
 'locally_verified_revocation_status_is_a_complete_global_crl_or_ocsp_check',
 'operator_evaluation_utc_or_signed_claim_is_a_trusted_calibrated_clock',
 'sha_inventory_or_signed_original_self_certifies_external_key_custody',
 'four_public_keys_or_signed_receipts_prove_distinct_real_people_or_institutions',
 'ec341_ec342_signed_conflict_hold_proves_global_latest_root_or_remote_freeze',
 'ec353_sender_origin_label_is_independent_receiver_original',
 'missing_original_history_can_be_recreated_or_signed_to_complete_audit',
 'any_private_key_network_provider_cas_worm_git_ci_or_native_ps_write_performed',
 'deep_unmocked_ec317_ec318_real_production_or_final_acceptance_completed',
)


def need(ok,reason,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC388_'+reason,status)


def exact(obj,fields,name):
    need(type(obj) is dict and set(obj)==set(fields),name+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return parent.sha(raw)


def _inputs(opts,derive):
    keys=set((*PARENT_SCALARS,*PARENT_REPEATS,*NEW_SCALARS,*REPEAT_NAMES))
    if not derive:keys.update(AUDIT_ONLY)
    need(set(opts)==keys,'EXACT_UNCHANGED_PARENT_EC387_AND_EC388_INPUTS_REQUIRED')
    earlier={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    parent._inputs(earlier,False)
    p372.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                             'EC388_RECEIVER_PINNED_HISTORICAL_ROLE_STATUS_ARCHIVE')
    if not derive:
        need(old353._sha(opts[AUDIT_ONLY[0]]),'OUTSIDE_RETAINED_WHOLE_INVENTORY_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'HISTORICAL_EPOCH_BOUNDS_REQUIRED')
    caps={'minimum_historical_ec338_signed_actor_receipt_counts':8,
          'minimum_historical_ec339_retirement_status_counts':8,
          'minimum_historical_ec339_signed_revocation_transition_counts':8}
    for name in REPEAT_NAMES:
        arr=opts[name]
        need(type(arr) is list and len(arr)==n,'PER_EPOCH_ORIGINAL_CENSUS_REQUIRED_'+name.upper())
        if name in caps:
            need(all(type(v) is int and 0<=v<=caps[name] for v in arr),
                 'SIGNED_EVIDENCE_FLOOR_OUT_OF_BOUNDS_'+name.upper())
        else:
            need(all(old353._sha(v) for v in arr),
                 'EXTERNALLY_RETAINED_ORIGINAL_SHA_REQUIRED_'+name.upper())
    return earlier


def _parent(report,n):
    need(type(report) is dict and report.get('schema')==parent.RESULT_SCHEMA and
         report.get('exit_code')==2 and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec340_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         type(report.get('historical_ec340_rotation_epoch_reviews')) is list and
         len(report['historical_ec340_rotation_epoch_reviews'])==n and
         type(report.get('local_old_ec340_signed_rotation_ec341_conflict_parent_originals_consistent')) is bool and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report[k] is True for k in parent.FLAGS[-2:]) and
         report.get('status')==next((parent.OUTCOMES[i] for i,k in enumerate(parent.FLAGS)
             if report[k]),parent.OUTCOMES[-1])+'_unresolved' and
         report['local_old_ec340_signed_rotation_ec341_conflict_parent_originals_consistent']==(
             not any(report[k] for k in parent.FLAGS[:7])),
         'ACTUAL_LIVE_UNCHANGED_EC387_TO_EC369_AUDIT_REQUIRED','unavailable')
    return sha(canonical.canonical(report))


def _ref(candidate,source,name):
    need(type(source) is dict and set(source)=={'path','sha256'},
         name+'_PARENT_REFERENCE_REQUIRED','permission_denied')
    parent._ref(candidate,source['path'],source['sha256'],'EC388_'+name)


def _json(read,ref,name):
    return parent._json(read,ref,'EC388_'+name)


def _missing(channel):
    return {'tsa_channel_id':channel,'full_original_ec339_role_retirement_replay':False,
       'ec338_policy_sha256':None,'ec339_issuer_roster_sha256':None,
       'ec340_epoch2_successor_sha256':None,'ec340_retirement_observation_sha256':None,
       'ec340_effective_utc':None,'ec339_verified_role_histories':[],
       'ec339_signed_retirement_statuses':[],
       'ec338_signed_actor_receipt_count':0,'ec339_challenged_retirement_status_count':0,
       'ec339_signed_revocation_transition_count':0,
       'missing_retirement_boundary_status':True,'visible_role_revocation_conflict':False,
       'grant_invalid_at_root_retirement':True}


def _signed_status(ref,entry,issuer,grant,grant_ref,read):
    """Verify original Ed25519 revoked/active domain without EC339's active-only rule.

    EC339's original audit correctly rejects *revoked* for its historic active
    verification. Here a signed revocation is EVIDENCE, not an allowed action.
    """
    raw=read(ref,'ec339_challenged_original_'+grant['role'],old339.MAX_SIGNED)
    doc,_=old339._read_json(ref['path'],ref['sha256'],old339.MAX_SIGNED,
                            'EC388_SIGNED_STATUS_'+grant['role'].upper())
    need(sha(raw)==ref['sha256'] and type(doc) is dict,
         'STATUS_SHA_AND_OLD_CANONICAL_ORIGINAL_REQUIRED','permission_denied')
    claim=old339._verify_sig(doc,old339.STATUS_SCHEMA,old339.STATUS_CLAIM_SCHEMA,
                             issuer['issuer_public_hex'],
                             old339._domain('Status',grant['role']),'STATUS')
    need(type(claim) is dict and set(claim)==old339.STATUS_FIELDS and
         claim['schema']==old339.STATUS_CLAIM_SCHEMA and
         claim['transfer_id']==grant['transfer_id'] and
         claim['role']==grant['role']==issuer['role'] and
         claim['issuer_id']==issuer['issuer_id'] and
         claim['grant_id']==grant['grant_id'] and
         claim['grant_original_raw_sha256']==grant_ref['sha256'] and
         claim['verifier_challenge_sha256']==entry['verifier_challenge_sha256'] and
         old338._sha(entry['verifier_challenge_sha256']) and
         claim['state'] in ('active','revoked'),
         'SIGNED_STATUS_MUST_BIND_EXACT_CHALLENGE_GRANT_ROLE_AND_ISSUER',
         'permission_denied')
    old339._interval(claim['as_of_utc'],claim['expires_utc'],
                     old339.MAX_STATUS_LIFETIME,'EC388_SIGNED_STATUS_MAX_24_HOURS')
    need(old339._time(claim['as_of_utc'])<=old339._time(entry['evaluation_utc'])<
         old339._time(claim['expires_utc']),
         'SIGNED_STATUS_EVALUATION_MUST_FALL_IN_ORIGINAL_WINDOW','permission_denied')
    revoked=claim['revoked_effective_utc']
    need((claim['state']=='active' and revoked is None) or
         (claim['state']=='revoked' and old338._utc(revoked) and
          old339._time(grant['issued_utc'])<=old339._time(revoked)<=
          old339._time(claim['as_of_utc'])),
         'REVOCATION_EFFECTIVE_TIME_MUST_NOT_BE_FUTURE_OR_BEFORE_GRANT',
         'permission_denied')
    return claim


def _channel(row,source,root_source,read):
    """No replacement grant/receipt/baseline; they are in the real EC387 parent."""
    exact(row,CHANNEL_FIELDS,'CHANNEL');exact(source,parent.CHANNEL_FIELDS,'EC387_PARENT_CHANNEL')
    channel=row['tsa_channel_id']
    need(channel==source['tsa_channel_id']==root_source['tsa_channel_id'],
         'EXACT_AUTHENTIC_CHANNEL_LINEAGE_REQUIRED','permission_denied')
    if source['ec340_legacy_policy_original'] is None:
        need(root_source['ec341_lineage_manifest_original'] is None and
             all(row[k] is None for k in CHANNEL_FIELDS if k not in (
                 'tsa_channel_id','ec339_role_retirement_reviews')) and
             row['ec339_role_retirement_reviews']==[],
             'MISSING_PARENT_CANNOT_BE_REPLACED_WITH_NEW_GRANT_OR_STATUS',
             'permission_denied')
        return _missing(channel)
    need(root_source['ec341_lineage_manifest_original'] is not None and
         source['ec339_predecessor_authority_roster_original'] is not None,
         'SIGNED_EC387_AND_EC386_PREDECESSORS_REQUIRED','permission_denied')
    original_pairs=(
       ('ec338_policy_original','ec340_legacy_policy_original'),
       ('ec339_issuer_roster_original','ec339_predecessor_authority_roster_original'),
       ('ec340_successor_roster_original','ec340_epoch2_successor_roster_original'),
       ('ec340_retirement_observation_original','ec340_signed_retirement_observation_original'))
    for key,old_key in original_pairs:
        _ref(row[key],source[old_key],'PARENT_LOCKED_'+key.upper())
    manifest=_json(read,root_source['ec341_lineage_manifest_original'],
                   'TRUE_EC341_MANIFEST_FROM_EC386')
    old341._check_manifest(manifest)
    context,history,first=manifest['context'],manifest['history'],manifest['hops'][0]
    policy=_json(read,row['ec338_policy_original'],'EXACT_EC338_POLICY')
    old338._policy_validate(policy,policy['original_roots'])
    legacy=old339._load_roster(row['ec339_issuer_roster_original']['path'],
             row['ec339_issuer_roster_original']['sha256'],policy,
             row['ec338_policy_original']['sha256'])
    successor=_json(read,row['ec340_successor_roster_original'],'SIGNED_ROTATION_SUCCESSOR')
    old340._validate_successor(successor,legacy,row['ec339_issuer_roster_original']['sha256'],
                               policy,row['ec338_policy_original']['sha256'])
    need(context['policy_file']==row['ec338_policy_original']['path'] and
         context['expected_policy_sha256']==row['ec338_policy_original']['sha256'] and
         context['authority_roster_file']==row['ec339_issuer_roster_original']['path'] and
         context['expected_authority_roster_sha256']==row['ec339_issuer_roster_original']['sha256'] and
         first['successor_roster_file']==row['ec340_successor_roster_original']['path'] and
         first['expected_successor_roster_sha256']==row['ec340_successor_roster_original']['sha256'] and
         first['root_observation_file']==row['ec340_retirement_observation_original']['path'] and
         first['expected_root_observation_sha256']==row['ec340_retirement_observation_original']['sha256'],
         'AUTHENTIC_LEGACY_EC341_MANIFEST_ONLY_NOT_CALLER_SELF_DESCRIPTION',
         'permission_denied')
    observation=_json(read,row['ec340_retirement_observation_original'],
                      'ROOT_RETIREMENT_SIGNED_OBSERVATION')
    need(type(observation.get('claim')) is dict and
         observation['claim'].get('predecessor_roster_original_raw_sha256')==
             row['ec339_issuer_roster_original']['sha256'] and
         observation['claim'].get('successor_roster_original_raw_sha256')==
             row['ec340_successor_roster_original']['sha256'] and
         observation['claim'].get('predecessor_root_state')=='retired' and
         observation['claim'].get('successor_root_state')=='active',
         'REAL_SIGNED_EC340_RETIREMENT_BOUNDARY_REQUIRED','permission_denied')
    effective=old339._time(successor['effective_utc'])
    reviews=row['ec339_role_retirement_reviews']
    need(type(reviews) is list and len(reviews)==4,
         'EXACT_FOUR_ROLE_SPECIFIC_SIGNED_ORIGINAL_REVIEWS_REQUIRED','permission_denied')
    outputs=[]; transitions=[]; previous_sha=old338.ZERO
    missing_boundary=False;state_conflict=False;expired_grant=False;status_count=revocation_count=0
    for i,entry in enumerate(reviews):
        exact(entry,ROLE_FIELDS,'SIGNED_EC339_ROLE')
        role=old340.ROLES[i]
        need(entry['role']==role,'ORIGINAL_SIGNED_ROLE_ORDER_REQUIRED','permission_denied')
        historical=source['ec339_original_signed_role_history'][i]
        need(historical['role']==role,'EC387_ROLE_LOCK_REQUIRED','permission_denied')
        for key,pname in (('actor_receipt_original','receipt_original'),
                          ('issuer_grant_original','grant_original'),
                          ('baseline_status_original','status_original')):
            _ref(entry[key],historical[pname],'CERTIFIED_EC387_'+role+'_'+key)
            _json(read,entry[key],'CERTIFIED_EC387_'+role+'_'+key)
        actor,issuer=policy['actors'][i],legacy['issuers'][i]
        receipt,receipt_raw=old338._load_receipt(
            entry['actor_receipt_original']['path'],entry['actor_receipt_original']['sha256'],
            policy,row['ec338_policy_original']['sha256'],i,previous_sha)
        previous_sha=sha(receipt_raw)
        grant=old339._load_grant(entry['issuer_grant_original']['path'],
            entry['issuer_grant_original']['sha256'],issuer,actor,policy)
        baseline=old339._load_status(entry['baseline_status_original']['path'],
            entry['baseline_status_original']['sha256'],issuer,grant,
            entry['issuer_grant_original']['sha256'],first['verifier_challenge_sha256'],
            history['evaluation_utc'])
        need(old339._time(grant['not_before_utc'])<=
             old339._time(receipt['claim']['signer_reported_utc'])<
             old339._time(grant['not_after_utc']),
             'TRUE_EC338_SIGNED_RECEIPT_MUST_BE_IN_SIGNED_GRANT_WINDOW','permission_denied')
        grant_covers=old339._time(grant['not_before_utc'])<=effective<old339._time(grant['not_after_utc'])
        expired_grant|=not grant_covers
        additions=entry['additional_challenged_status_originals']
        need(type(additions) is list and len(additions)<=2,
             'MAXIMUM_TWO_ADDITIONAL_SIGNED_RETIREMENT_STATUS_ORIGINALS_PER_ROLE')
        status_seen={entry['baseline_status_original']['sha256']}
        challenge_seen={baseline['verifier_challenge_sha256']}
        after=[];claims=[baseline];boundary=None
        for j,item in enumerate(additions):
            exact(item,STATUS_FIELDS,'EXTRA_CHALLENGED_STATUS')
            ref=item['signed_status_original']
            p372.prior.lineage.parent.ref_check(ref,'EC388_SIGNED_ADDITIONAL_STATUS')
            need(ref['sha256'] not in status_seen and
                 item['verifier_challenge_sha256'] not in challenge_seen,
                 'NO_REPLAYED_OLD_STATUS_OR_CHALLENGE_WITHIN_ROLE','permission_denied')
            status_seen.add(ref['sha256']);challenge_seen.add(item['verifier_challenge_sha256'])
            claim=_signed_status(ref,item,issuer,grant,entry['issuer_grant_original'],read)
            stamp=old339._time(claim['as_of_utc'])
            cross=stamp<=effective<old339._time(claim['expires_utc'])
            later=stamp>=effective
            need(cross or later,
                 'STATUS_MUST_SPAN_RETIREMENT_OR_DECLARED_LATER_NOT_AN_OLD_STALE_CLAIM',
                 'permission_denied')
            need(j==0 or old339._time(after[-1]['as_of_utc'])<stamp,
                 'SIGNED_STATUS_ORIGINALS_MUST_HAVE_STRICT_ASCENDING_CLAIMED_AS_OF',
                 'permission_denied')
            if cross:
                need(boundary is None,'ONLY_ONE_EXACT_RETIREMENT_WINDOW_STATUS_PER_ROLE',
                     'permission_denied')
                # This comparison uses the root's historical effective_utc as a
                # boundary, NOT a claimed live clock or fresh verifier challenge.
                boundary=ref['sha256'];status_count+=1
            # The first authentic revoked status is a signed transition from
            # the verified active baseline, including one that crosses the
            # retirement instant. Repeated revoked claims are evidence, not
            # additional independent state transitions.
            if claim['state']=='revoked' and not any(
                    earlier['state']=='revoked' for earlier in after):
                revocation_count+=1
            after.append({'sha256':ref['sha256'],'state':claim['state'],
                'as_of_utc':claim['as_of_utc'],'expires_utc':claim['expires_utc'],
                'revoked_effective_utc':claim['revoked_effective_utc'],
                'verifier_challenge_sha256':claim['verifier_challenge_sha256'],
                'evaluation_utc':item['evaluation_utc'],
                'classification':'retirement_window' if cross else 'post_retirement_claim_only'})
            claims.append(claim)
        # Baseline always predates retirement; its validity end may be the
        # precise retirement instant (then it does NOT cover that boundary).
        if boundary is None:missing_boundary=True
        if not grant_covers and any(x['state']=='active' for x in claims[1:]):
            state_conflict=True
        # Once any signed status reports revoked, no later signed active claim
        # can silently clear it; also reject same/before baseline time as ABA.
        was_revoked=False;last=old339._time(baseline['as_of_utc'])
        for position,claim in enumerate(claims):
            t=old339._time(claim['as_of_utc'])
            if (position and t<=last) or (was_revoked and claim['state']=='active'):
                state_conflict=True
            last=t
            was_revoked|=(claim['state']=='revoked')
        outputs.append({'role':role,'actor_receipt_sha256':entry['actor_receipt_original']['sha256'],
          'issuer_grant_sha256':entry['issuer_grant_original']['sha256'],
          'baseline_status_sha256':entry['baseline_status_original']['sha256'],
          'issuer_id':issuer['issuer_id'],'issuer_public_hex':issuer['issuer_public_hex'],
          'actor_id':actor['actor_id'],'grant_id':grant['grant_id'],
          'grant_not_before_utc':grant['not_before_utc'],
          'grant_not_after_utc':grant['not_after_utc'],
          'grant_covers_retirement_boundary':grant_covers,
          'baseline_status_as_of_utc':baseline['as_of_utc'],
          'retirement_window_status_sha256':boundary,
          'additional_signed_statuses':after})
        transitions.append({'role':role,'grant_sha256':entry['issuer_grant_original']['sha256'],
            'original_signed_statuses':after})
    # Late real-file reread, not just a cached SHA or signed self-description.
    for entry in reviews:
        for item in entry['additional_challenged_status_originals']:
            ref=item['signed_status_original']
            reread=p372._read(ref,'ec388_late_'+ref['sha256'],old339.MAX_SIGNED,{}, {},set())
            need(sha(reread)==ref['sha256'],
                 'SIGNED_RETIREMENT_STATUS_CHANGED_AFTER_ED25519_REPLAY','permission_denied')
    return {'tsa_channel_id':channel,'full_original_ec339_role_retirement_replay':True,
       'ec338_policy_sha256':row['ec338_policy_original']['sha256'],
       'ec339_issuer_roster_sha256':row['ec339_issuer_roster_original']['sha256'],
       'ec340_epoch2_successor_sha256':row['ec340_successor_roster_original']['sha256'],
       'ec340_retirement_observation_sha256':row['ec340_retirement_observation_original']['sha256'],
       'ec340_effective_utc':successor['effective_utc'],
       'ec339_verified_role_histories':outputs,'ec339_signed_retirement_statuses':transitions,
       'ec338_signed_actor_receipt_count':4,
       'ec339_challenged_retirement_status_count':status_count,
       'ec339_signed_revocation_transition_count':revocation_count,
       'missing_retirement_boundary_status':missing_boundary,
       'visible_role_revocation_conflict':state_conflict,
       'grant_invalid_at_root_retirement':expired_grant}


def _engine(derive,**opts):
    popts=_inputs(opts,derive)
    p_report=parent.audit(**popts)  # Always live unchanged EC387->EC369 audit.
    n=len(opts['historical_directory_root_shas'])
    psha=_parent(p_report,n)
    pins={};cats={};forbidden=set();cache={}
    def read(ref,role,cap):
        p372.prior.lineage.parent.ref_check(ref,'EC388_'+role)
        path=ref['path']
        if path in cache:
            digest,raw=cache[path]
            need(path not in forbidden and digest==ref['sha256'] and len(raw)<=cap,
                 'SOURCE_PATH_SHA_CAP_OR_SENDER_ORIGIN_REUSE','permission_denied')
            return raw
        raw=p372._read(ref,'ec388_'+role,cap,pins,cats,forbidden)
        cache[path]=(ref['sha256'],raw)
        return raw
    def archive(ref,name,fields,schema,cap):
        doc=old353.strict_json(read(ref,name,cap),'EC388_'+name)
        exact(doc,fields,'ARCHIVE_'+name)
        need(doc['schema']==schema and type(doc['epochs']) is list and
             len(doc['epochs'])==n,'EXACT_PARENT_ARCHIVE_SCHEMA_AND_EPOCHS_'+name,
             'permission_denied')
        return doc
    ref386={'path':opts[parent.parent.NEW_SCALARS[0]],
            'sha256':opts[parent.parent.NEW_SCALARS[1]]}
    ref387={'path':opts[parent.NEW_SCALARS[0]],'sha256':opts[parent.NEW_SCALARS[1]]}
    ref388={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    ancestor=archive(ref386,'parent_ec386_root',parent.parent.BUNDLE_FIELDS,
                     parent.parent.BUNDLE_SCHEMA,parent.parent.MAX_BUNDLE)
    earlier=archive(ref387,'parent_ec387_rotation',parent.BUNDLE_FIELDS,
                    parent.BUNDLE_SCHEMA,parent.MAX_BUNDLE)
    current=archive(ref388,'receiver_ec388_role_status',BUNDLE_FIELDS,BUNDLE_SCHEMA,MAX_BUNDLE)
    need(current['parent_ec387_canonical_result_sha256']==psha and
         current['ec387_historical_rotation_archive_original_sha256']==ref387['sha256'] and
         current['claimed_directory_lineage_id']==earlier['claimed_directory_lineage_id']==
             ancestor['claimed_directory_lineage_id']==opts['claimed_historical_directory_lineage_id'] and
         earlier['ec386_historical_root_archive_original_sha256']==ref386['sha256'],
         'ACTUAL_LIVE_PARENT_CANONICAL_SHA_WHOLE_SOURCE_AND_LINEAGE_REQUIRED',
         'permission_denied')
    # Old EC353 sender labels are NOT receiver paths. Rebuild the inherited
    # denylist before opening any additional original from this new archive.
    ref377={'path':opts['historical_transparency_archive_bundle_file'],
            'sha256':opts['expected_historical_transparency_archive_bundle_sha256']}
    sender_index=archive(ref377,'old_ec377_sender_index',p377.BUNDLE_FIELDS,
                         p377.BUNDLE_SCHEMA,p377.MAX_BUNDLE)
    for ep in sender_index['epochs']:
        label_ref=ep['ec353_publication_bundle_original']
        label=old353.strict_json(read(label_ref,'old_sender_labels',old353.MAX_BUNDLE),
                                 'EC388_SENDER_LABELS_UNTRUSTED')
        p379._old_sender_labels(label,forbidden)
        forbidden.add(label_ref['path'])
    forbidden.add(ref377['path'])
    forbidden.update(v for k,v in opts.items() if k.endswith('_file') and type(v) is str)
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not p_report['local_old_ec340_signed_rotation_ec341_conflict_parent_originals_consistent']
    epoch_rows=[];inventory=[];previous={};receipt_total=boundary_total=revoked_total=0
    for idx,(ep,p_ep,root_ep) in enumerate(zip(current['epochs'],earlier['epochs'],
                                               ancestor['epochs'],strict=True)):
        exact(ep,EPOCH_FIELDS,'RECEIVER_EPOCH')
        exact(p_ep,parent.EPOCH_FIELDS,'EC387_PARENT_EPOCH')
        exact(root_ep,parent.parent.EPOCH_FIELDS,'EC386_AUTHENTIC_EPOCH')
        need(ep['epoch_index']==p_ep['epoch_index']==root_ep['epoch_index']==idx and
             type(ep['channels']) is list and type(p_ep['channels']) is list and
             type(root_ep['channels']) is list and
             1<=len(ep['channels'])==len(p_ep['channels'])==len(root_ep['channels'])<=2,
             'EXACT_PARENT_EPOCH_CHANNEL_CENSUS_REQUIRED','permission_denied')
        ids=[[x.get('tsa_channel_id') for x in rows] for rows in
             (ep['channels'],p_ep['channels'],root_ep['channels'])]
        need(ids[0]==ids[1]==ids[2] and ids[0]==sorted(set(ids[0])),
             'AUTHENTIC_PARENT_CHANNEL_ORDER_AND_IDS_REQUIRED','permission_denied')
        rows=[]
        for row,p_row,root_row in zip(ep['channels'],p_ep['channels'],
                                      root_ep['channels'],strict=True):
            result=_channel(row,p_row,root_row,read)
            rows.append(result)
            flags[FLAGS[2]]|=not result['full_original_ec339_role_retirement_replay']
            flags[FLAGS[3]]|=result['missing_retirement_boundary_status']
            flags[FLAGS[4]]|=result['visible_role_revocation_conflict']
            flags[FLAGS[5]]|=result['grant_invalid_at_root_retirement']
            prev=previous.get(result['tsa_channel_id'])
            if prev is not None:
                stable=('full_original_ec339_role_retirement_replay','ec338_policy_sha256',
                        'ec339_issuer_roster_sha256','ec340_epoch2_successor_sha256',
                        'ec340_retirement_observation_sha256','ec340_effective_utc')
                if any(prev[k]!=result[k] for k in stable):flags[FLAGS[6]]=True
                for before,after in zip(prev['ec339_verified_role_histories'],
                                         result['ec339_verified_role_histories']):
                    for k in ('role','actor_receipt_sha256','issuer_grant_sha256',
                              'baseline_status_sha256','issuer_id','issuer_public_hex',
                              'grant_id','grant_not_before_utc','grant_not_after_utc'):
                        if before[k]!=after[k]:flags[FLAGS[6]]=True
                    old=before['additional_signed_statuses']
                    new=after['additional_signed_statuses']
                    if new[:len(old)]!=old:flags[FLAGS[6]]=True
            previous[result['tsa_channel_id']]=result
        if len(rows)==2 and all(r['full_original_ec339_role_retirement_replay'] for r in rows):
            for x,y in zip(rows[0]['ec339_verified_role_histories'],
                           rows[1]['ec339_verified_role_histories']):
                stable=('actor_receipt_sha256','issuer_grant_sha256','baseline_status_sha256',
                        'issuer_id','issuer_public_hex','grant_id')
                if any(x[k]!=y[k] for k in stable):flags[FLAGS[6]]=True
                observed={}
                for role_row in (x,y):
                    for claim in role_row['additional_signed_statuses']:
                        key=claim['as_of_utc']
                        if key in observed and observed[key]!=claim['state']:
                            flags[FLAGS[4]]=True
                        observed[key]=claim['state']
                # Across channels, a later signed 'active' after a separately
                # observed 'revoked' is still ABA; each channel alone may
                # have shown a monotone, internally consistent fragment.
                ordered=sorted((claim['as_of_utc'],claim['state']) for role_row in (x,y)
                               for claim in role_row['additional_signed_statuses'])
                revoked_seen=False
                for _claimed_utc,state in ordered:
                    if revoked_seen and state=='active':flags[FLAGS[4]]=True
                    if state=='revoked':revoked_seen=True
        role_inventory=[{'tsa_channel_id':r['tsa_channel_id'],
                         'root_retirement_utc_claim':r['ec340_effective_utc'],
                         'ec338_policy_sha256':r['ec338_policy_sha256'],
                         'ec339_roster_sha256':r['ec339_issuer_roster_sha256'],
                         'role_reviews':r['ec339_verified_role_histories']}
                        for r in rows]
        transition_inventory=[{'tsa_channel_id':r['tsa_channel_id'],
                 'signed_revocation_history':r['ec339_signed_retirement_statuses']}
                for r in rows]
        role_sha=sha(canonical.canonical(role_inventory))
        transition_sha=sha(canonical.canonical(transition_inventory))
        receipts=sum(r['ec338_signed_actor_receipt_count'] for r in rows)
        boundaries=sum(r['ec339_challenged_retirement_status_count'] for r in rows)
        revoked=sum(r['ec339_signed_revocation_transition_count'] for r in rows)
        receipt_total+=receipts;boundary_total+=boundaries;revoked_total+=revoked
        flags[FLAGS[1]]|=(
            role_sha!=opts['historical_ec339_retirement_role_inventory_shas'][idx] or
            transition_sha!=opts['historical_ec339_revocation_transition_inventory_shas'][idx] or
            receipts<opts['minimum_historical_ec338_signed_actor_receipt_counts'][idx] or
            boundaries<opts['minimum_historical_ec339_retirement_status_counts'][idx] or
            revoked<opts['minimum_historical_ec339_signed_revocation_transition_counts'][idx])
        epoch_rows.append({'epoch_index':idx,'verified_old_ec338_signed_actor_receipt_count':receipts,
            'verified_old_ec339_boundary_status_count':boundaries,
            'verified_old_ec339_revoked_status_transition_count':revoked,
            'old_ec339_role_original_inventory_sha256':role_sha,
            'old_ec339_revocation_transition_inventory_sha256':transition_sha,
            'missing_authentic_ec339_parent_source_channels':sum(
                not r['full_original_ec339_role_retirement_replay'] for r in rows),
            'local_old_ec339_grants_revocation_and_retirement_consistent':(
                all(r['full_original_ec339_role_retirement_replay'] and
                    not r['missing_retirement_boundary_status'] and
                    not r['visible_role_revocation_conflict'] and
                    not r['grant_invalid_at_root_retirement'] for r in rows)
                and not flags[FLAGS[4]] and not flags[FLAGS[6]])})
        inventory.append({'epoch_index':idx,
            'verified_old_ec339_retirement_role_originals':role_inventory,
            'verified_old_ec339_revocation_status_claims':transition_inventory,
            'old_ec339_role_original_inventory_sha256':role_sha,
            'old_ec339_revocation_transition_inventory_sha256':transition_sha})
    flags[FLAGS[7]]=True;flags[FLAGS[8]]=True
    derived={'schema':INVENTORY_SCHEMA,
       'live_ec387_to_ec369_parent_canonical_result_sha256':psha,
       'receiver_original_ec387_rotation_archive_sha256':ref387['sha256'],
       'receiver_original_ec388_revocation_archive_sha256':ref388['sha256'],
       'claimed_directory_lineage_id':current['claimed_directory_lineage_id'],
       'historical_ec339_retirement_epoch_reviews':inventory}
    digest=sha(canonical.canonical(derived))
    if not derive and digest!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    local=not any(flags[k] for k in FLAGS[:7])
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
       'command':'derive-historical-ec339-retirement-inventory' if derive else
                 'audit-historical-ec339-retirement-archive',
       'status':next((OUTCOMES[i] for i,key in enumerate(FLAGS) if flags[key]),
                     OUTCOMES[-1])+'_unresolved',
       'exit_code':2,'offline_unresolved_exit_code':2,
       'verified_live_parent_ec387_canonical_result_sha256':psha,
       'historical_ec339_retirement_archive_original_sha256':ref388['sha256'],
       'receiver_verified_old_ec339_retirement_inventory_sha256':digest,
       'genuine_old_ec338_signed_actor_receipt_count':receipt_total,
       'genuine_old_ec339_retirement_window_signed_status_count':boundary_total,
       'genuine_old_ec339_signed_revoked_transition_count':revoked_total,
       'historical_ec339_retirement_epoch_reviews':epoch_rows,
       'local_old_ec339_signed_grant_revocation_retirement_originals_consistent':local,
       'sender_origin_path_required_or_read':False,
       'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
       **flags,**{k:False for k in NEGATIVES},
       **({'unsigned_verified_old_ec339_retirement_inventory':derived,
           'caller_retained_inventory_sha_independently_certified':False} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
