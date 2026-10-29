#!/usr/bin/env python3
"""EC386: receiver-side EC341 authentic signed same-parent root conflict under EC342.

All checks are read-only. The unmodified EC385 -> EC369 receiver audit MUST
execute first; this layer reopens actual parent EC385 whole-file originals, then
verifies the unchanged EC341 -> EC337 signed lineage and the independently
approved EC342 hold which selected the genuinely signed sibling pair.

An EC341 manifest is UNSIGNED, issuer / observer public-key raw copies are NOT
institution credentials, caller-retained SHA floors are NOT off-site attestations,
and a local signature does not execute a freeze, reveal all forks, or supply UTC.
"""
from __future__ import annotations
import json

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from offline_authority import authority as clock
from root_lineage import lineage as old341
from conflict_hold import hold as old342
from hold_receipts import timeline as old343
from transparency import transparency as old353
from historical_authority import authority_archive as p372
from historical_transparency import transparency_archive as p377
from historical_source import source_archive as p379
from historical_change import change_archive as parent

RESULT_SCHEMA='ces.ec386.receiver_old_ec341_signed_sibling_root_conflict_unresolved.v1'
DERIVE_SCHEMA='ces.ec386.unsigned_old_ec341_signed_root_conflict_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec386.receiver_old_ec341_signed_root_conflict_denial.v1'
BUNDLE_SCHEMA='ces.ec386.receiver_historical_old_ec341_signed_root_conflict_archive.v1'
INVENTORY_SCHEMA='ces.ec386.receiver_verified_old_ec341_original_conflict_inventory.v1'
MAX_BUNDLE=320_000
MAX_ORIGINAL=320_000
MAX_OLD_ARCHIVE=48_000_000
MAX_KEY_COPIES=4+5*(old341.MAX_EPOCH-1+old341.MAX_FORKS)
NEW_SCALARS=('historical_ec341_signed_root_conflict_archive_bundle_file',
             'expected_historical_ec341_signed_root_conflict_archive_bundle_sha256')
AUDIT_ONLY=('expected_retained_historical_ec341_signed_root_conflict_inventory_sha256',)
NEW_REPEATS=(
 ('historical_ec341_signed_root_inventory_shas','--historical-ec341-signed-root-inventory-sha256'),
 ('historical_ec342_root_conflict_binding_inventory_shas','--historical-ec342-root-conflict-binding-inventory-sha256'),
 ('minimum_historical_ec341_signed_edge_counts','--minimum-historical-ec341-signed-edge-count'),
 ('minimum_historical_ec341_signed_observation_counts','--minimum-historical-ec341-signed-observation-count'),
 ('minimum_historical_ec341_verified_sibling_counts','--minimum-historical-ec341-verified-sibling-count'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
PARENT_SCALARS=(*parent.PARENT_SCALARS,*parent.NEW_SCALARS,*parent.AUDIT_ONLY)
PARENT_REPEATS=(*parent.PARENT_REPEATS,*parent.REPEAT_NAMES)
BUNDLE_FIELDS={'schema','parent_ec385_canonical_result_sha256',
               'ec385_historical_change_archive_original_sha256',
               'claimed_directory_lineage_id','epochs'}
EPOCH_FIELDS={'epoch_index','channels'}
CHANNEL_FIELDS={
 'tsa_channel_id','ec342_governance_roster_original',
 'ec342_signed_hold_request_original','ec341_lineage_manifest_original',
 'ec341_manifest_dependency_originals','ec341_signer_public_key_copies',
}
KEY_COPY_FIELDS={'public_hex','public_key_original'}
FLAGS=(
 'inherited_live_ec385_through_ec369_original_signed_source_dispute',
 'outside_retained_ec341_ec342_original_sha_or_signature_floor_disagrees',
 'authentic_old_ec341_source_or_ec342_predecessor_unavailable',
 'old_ec341_original_manifest_signed_root_or_witness_chain_not_recovered',
 'old_ec342_signed_hold_not_bound_to_independently_verified_sibling_roots',
 'visible_genuinely_signed_old_ec341_same_parent_root_conflict',
 'old_ec341_root_channel_or_later_epoch_aba_rollback',
 'full_unmocked_ec341_through_ec337_external_original_history_not_proven',
 'global_fork_identity_key_custody_remote_hold_and_trusted_utc_not_proven',
)
OUTCOMES=(
 'ec386_inherited_live_historical_receiver_signed_original_dispute',
 'ec386_independent_original_sha_and_signed_count_floor_disagrees',
 'ec386_old_ec341_original_signed_root_source_or_hold_unavailable',
 'ec386_old_ec341_full_signed_lineage_originals_missing_or_incomplete',
 'ec386_old_ec342_hold_not_proven_to_bind_exact_signed_sibling_roots',
 'ec386_visible_independently_signed_same_parent_ec341_root_conflict',
 'ec386_old_ec341_root_aba_channel_or_epoch_rollback',
 'ec386_deep_independent_ec341_to_ec337_external_replay_unproven',
 'ec386_no_global_legal_physical_custody_or_trusted_clock_authority',
)
NEGATIVES=(
 'signed_root_conflict_selects_a_global_winner_or_complete_fork_set',
 'ec341_unsigned_lineage_manifest_is_a_signed_offsite_checkpoint',
 'ec342_signed_hold_is_executed_remote_freeze_or_legal_issuer_authority',
 'signed_claimed_time_is_calibrated_external_utc',
 'public_key_raw_copies_are_independently_authorized_institutional_keys',
 'sha_floor_is_offsite_custody_proven_by_this_software',
 'visible_signed_forks_exclude_hidden_or_revoked_other_keys',
 'ec343_signed_changes_release_or_resolve_ec341_root_conflict',
 'ec353_sender_origin_labels_are_trusted_receiver_original_paths',
 'missing_originals_can_be_replaced_by_fresh_mocks_keys_or_reissued_signatures',
 'private_key_network_provider_remote_cas_worm_git_ci_or_native_ps_writes_performed',
 'deep_old_ec337_nonmock_independent_acceptance_or_final_review_completed',
)


def need(ok, code, status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC386_'+code,status)


def exact(doc,fields,code):
    need(type(doc) is dict and set(doc)==set(fields),code+'_FIELDS_REQUIRED')


def sha(raw):return parent.sha(raw)


def _inputs(opts,derive):
    required=set((*PARENT_SCALARS,*PARENT_REPEATS,*NEW_SCALARS,*REPEAT_NAMES))
    if not derive: required.update(AUDIT_ONLY)
    need(set(opts)==required,'EXACT_UNMODIFIED_PARENT_AND_EC386_INPUTS_REQUIRED')
    popts={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    parent._inputs(popts,False)
    p372.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                             'EC386_RECEIVER_PINNED_SIGNED_ROOT_ARCHIVE')
    if not derive:
        need(old353._sha(opts[AUDIT_ONLY[0]]),'EXTERNAL_RETAINED_ORIGINAL_INVENTORY_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'HISTORIC_EPOCH_BOUNDS')
    caps={'minimum_historical_ec341_signed_edge_counts':8*15*2,
          'minimum_historical_ec341_signed_observation_counts':15*2,
          'minimum_historical_ec341_verified_sibling_counts':old341.MAX_FORKS*2}
    for key in REPEAT_NAMES:
        values=opts[key]
        need(type(values) is list and len(values)==n,'EPOCH_INVENTORY_CENSUS_'+key.upper())
        if key.startswith('minimum_'):
            need(all(type(v) is int and 0<=v<=caps[key] for v in values),
                 'BOUNDED_SIGNATURE_FLOORS_'+key.upper())
        else:
            need(all(old353._sha(v) for v in values),
                 'NONZERO_EXTERNAL_INVENTORY_SHA_'+key.upper())
    return popts


def _parent(result,n):
    need(type(result) is dict and result.get('schema')==parent.RESULT_SCHEMA and
         result.get('exit_code')==2 and
         result.get('sender_origin_path_required_or_read') is False and
         result.get('ec343_through_ec337_full_independent_original_historical_acceptance_performed') is False and
         type(result.get('historical_ec343_change_epoch_reviews')) is list and
         len(result['historical_ec343_change_epoch_reviews'])==n and
         type(result.get('local_ec342_approved_hold_ec343_signed_change_originals_consistent')) is bool,
         'ACTUAL_LIVE_UNMODIFIED_EC385_THROUGH_EC369_RECEIVER_AUDIT_REQUIRED','unavailable')
    return sha(canonical.canonical(result))


def _ref(ref,path,digest,code):
    parent._ref(ref,path,digest,'EC386_'+code)


def _source_read(read,ref,code,cap=MAX_ORIGINAL):
    return read(ref,'ec386_original_'+ref['sha256'],cap)


def _json(read,ref,code):
    raw=_source_read(read,ref,code)
    try:
        doc=json.loads(raw.decode('utf-8'),object_pairs_hook=old353._object_pairs,
          parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)))
    except (ValueError,UnicodeError,TypeError) as exc:
        raise errors.AnchorError('EC386_'+code+'_JSON_INVALID','invalid_input') from exc
    # Old EC341/342 originals use reg.raw_doc, not EC353's newer encoding;
    # never recanonicalize signed bytes into a different wire format.
    need(type(doc) is dict and canonical.raw_doc(doc)==raw,
         code+'_ORIGINAL_EC341_CANONICAL_WIRE_REQUIRED','permission_denied')
    return doc


def _missing(channel):
    return {'tsa_channel_id':channel,'full_original_ec341_signed_root_replay':False,
            'ec341_manifest_sha256':None,'ec342_governance_sha256':None,
            'ec342_hold_sha256':None,'ec341_parent_root_sha256':None,
            'ec341_selected_root_sha256':None,'ec341_competing_root_sha256':None,
            'ec341_current_root_sha256':None,'ec341_current_epoch':None,
            'ec341_root_original_sha256s':[],
            'ec341_original_signed_dependency_sha256s':[],
            'ec341_verifiable_public_key_copy_sha256s':[],
            'ec341_original_signed_edge_count':0,
            'ec341_original_signed_observation_count':0,
            'ec341_observed_signed_sibling_count':0,
            'ec342_original_signed_hold_predecessor_incomplete':True,
            'ec341_verified_signed_source_incomplete':True}


def _expected_key_rosters(manifest,read):
    """Collect signer public keys from *already pinned* old roster originals.

    These key copies are deliberately not admitted as grants or institutional
    keys. old341 must verify every edge/observation with roster-embedded keys.
    """
    roles={}
    def add(pub,desc):
        need(type(pub) is str and len(pub)==64 and pub==pub.lower(),
             'SOURCE_ROSTER_PUBLIC_KEY_REQUIRED','permission_denied')
        need(pub not in roles,'OLD_ROOT_SIGNER_OR_OBSERVER_KEY_ABA_'+desc,
             'permission_denied')
        roles[pub]=desc
    oldroot=_json(read,{'path':manifest['context']['authority_roster_file'],
           'sha256':manifest['context']['expected_authority_roster_sha256']},
           'legacy_root')
    for issuer in oldroot['issuers']:add(issuer['issuer_public_hex'],'legacy_issuer')
    for hop in [*manifest['hops'],*(f['hop'] for f in manifest['forks'])]:
        child=_json(read,{'path':hop['successor_roster_file'],
                     'sha256':hop['expected_successor_roster_sha256']},'signed_hop_root')
        witness=_json(read,{'path':hop['observer_roster_file'],
                     'sha256':hop['expected_observer_roster_sha256']},'signed_hop_witness')
        for issuer in child['issuers']:add(issuer['issuer_public_hex'],'new_issuer')
        add(witness['observer_public_hex'],'witness')
    need(len(roles)<=MAX_KEY_COPIES,'BOUNDED_PUBLIC_KEY_COPY_CENSUS')
    return sorted(roles)


def _channel(row,source,read):
    exact(row,CHANNEL_FIELDS,'EC386_CHANNEL')
    exact(source,parent.CHANNEL_FIELDS,'PARENT_EC385_AUTHENTIC_CHANNEL')
    channel=row['tsa_channel_id']
    need(channel==source['tsa_channel_id'],'AUTHENTIC_EC385_CHANNEL_MISMATCH',
         'permission_denied')
    if source['ec342_governance_roster_original'] is None:
        need(source['ec342_hold_request_original'] is None and
             all(row[x] is None for x in CHANNEL_FIELDS if x not in (
                 'tsa_channel_id','ec341_manifest_dependency_originals',
                 'ec341_signer_public_key_copies')) and
             row['ec341_manifest_dependency_originals']==[] and
             row['ec341_signer_public_key_copies']==[],
             'MISSING_PARENT_SOURCE_CANNOT_ACCEPT_CALLER_SIGNED_ROOT_REPLACEMENT',
             'permission_denied')
        return _missing(channel)
    _ref(row['ec342_governance_roster_original'],
         source['ec342_governance_roster_original']['path'],
         source['ec342_governance_roster_original']['sha256'],
         'EXACT_PARENT_EC385_SIGNED_HOLD_GOVERNANCE')
    _ref(row['ec342_signed_hold_request_original'],
         source['ec342_hold_request_original']['path'],
         source['ec342_hold_request_original']['sha256'],
         'EXACT_PARENT_EC385_SIGNED_HOLD_REQUEST')
    gov=old342._governance(row['ec342_governance_roster_original']['path'],
                          row['ec342_governance_roster_original']['sha256'])
    # The old EC342 governance SHA is authenticated by the EC385->EC369 parent,
    # not chosen by an untrusted replacement EC341 manifest.
    _source_read(read,row['ec342_governance_roster_original'],'authentic_governance')
    hold=old342._load_hold(row['ec342_signed_hold_request_original']['path'],
             row['ec342_signed_hold_request_original']['sha256'],gov,
             row['ec342_governance_roster_original']['sha256'])
    _source_read(read,row['ec342_signed_hold_request_original'],'original_signed_hold')
    manifestref=row['ec341_lineage_manifest_original']
    need(type(manifestref) is dict,'AUTHENTIC_OLD_EC341_MANIFEST_REF_REQUIRED',
         'permission_denied')
    need(manifestref.get('sha256')==gov['lineage_manifest_original_raw_sha256'],
         'EC342_GOVERNANCE_MUST_PIN_TRUE_OLD_EC341_MANIFEST_SHA','permission_denied')
    manifest=_json(read,manifestref,'ec341_manifest')
    paths,pins=old341._check_manifest(manifest)
    # Reject substitution: all manifest-named original dependencies (including
    # eight signed edges per hop, observer signed originals, original EC337 ZIP)
    # must be individually enumerated, SHA-matched, and opened as receiver
    # originals BEFORE unchanged old EC341 follows any of their embedded paths.
    refs=row['ec341_manifest_dependency_originals']
    need(type(refs) is list and len(refs)==len(paths) and
         len(refs)<=2+len(old341.HISTORY_FIELDS)//2+15*11,
         'EXACT_FULL_LEGACY_SOURCE_DEPENDENCY_CENSUS_REQUIRED',
         'permission_denied')
    for request,path,pin in zip(refs,paths,pins,strict=True):
        _ref(request,path,pin,'MANIFEST_ORIGINAL_SOURCE_MUST_BE_PINNED')
        _source_read(read,request,'manifest_dependency',
             MAX_OLD_ARCHIVE if path==manifest['history']['bundle_file'] else old341.MAX_MANIFEST_BYTES)
    expected_keys=_expected_key_rosters(manifest,read)
    pubcopies=row['ec341_signer_public_key_copies']
    need(type(pubcopies) is list and len(pubcopies)==len(expected_keys),
         'EVERY_LEGACY_NEW_ISSUER_AND_WITNESS_PUBLIC_KEY_COPY_REQUIRED',
         'permission_denied')
    copy_sha=[]
    for item,pub in zip(pubcopies,expected_keys,strict=True):
        exact(item,KEY_COPY_FIELDS,'OLD_EC341_RAW_PUBLIC_KEY_COPY')
        need(item['public_hex']==pub,'CANONICAL_SORTED_ISSUER_AND_WITNESS_KEY_SET_REQUIRED',
             'permission_denied')
        raw=_source_read(read,item['public_key_original'],'public_key_copy',32)
        need(raw.hex()==pub and len(raw)==32,
             'SOURCE_PUBLIC_KEY_BYTES_MUST_MATCH_SIGNED_ROSTER_KEY','permission_denied')
        copy_sha.append(item['public_key_original']['sha256'])
    # The unchanged old EC341 validator verifies all eight side/role Ed25519
    # signatures and the independent signed witness on each true branch,
    # all signed chronology constraints, ABA, the legacy EC340->EC337 ancestry.
    lineage_args={'manifest_file':manifestref['path'],
       'expected_manifest_sha256':manifestref['sha256'],
       'expected_current_root_sha256':gov['current_root_original_raw_sha256'],
       'expected_current_root_epoch':gov['current_root_epoch'],
       'minimum_acceptable_epoch':gov['minimum_acceptable_epoch'],
       'current_root_evaluation_utc':gov['current_root_evaluation_utc']}
    result=old341.verify_lineage(**lineage_args)
    need(result.get('schema')==old341.RESULT_SCHEMA and
         result.get('exit_code')==2 and result.get('status')=='conflict_unresolved' and
         result.get('historical_ec340_to_ec337_real_original_replay_verified') is True and
         result.get('only_supplied_externally_pinned_forks_examined') is True,
         'UNCHANGED_OLD_EC341_ALL_SIGNED_ROOTS_OBSERVATIONS_AND_EC337_REPLAY_REQUIRED',
         'permission_denied')
    # This further checks the original EC342 hold is pinned to precisely ONE
    # signed same-parent EC341 sibling and the hold actors are textually
    # different from all original EC341 signers, not physically independent.
    trusted,verified_manifest=old342._trusted_case(gov,lineage_args)
    need(trusted['fork_conflicts']==result['fork_conflicts'] and
         verified_manifest==manifest,
         'OLD_EC342_EXACT_INDEPENDENT_SIGNED_SIBLING_HOLD_REQUIRED',
         'permission_denied')
    matches=[x for x in result['fork_conflicts'] if
             x['parent_epoch']==gov['parent_epoch'] and
             x['parent_roster_original_raw_sha256']==gov['parent_root_original_raw_sha256'] and
             x['selected_successor_original_raw_sha256']==gov['selected_successor_original_raw_sha256'] and
             x['alternative_successor_original_raw_sha256']==gov['alternative_successor_original_raw_sha256']]
    need(len(matches)==1 and
         hold['parent_root_original_raw_sha256']==gov['parent_root_original_raw_sha256'] and
         hold['selected_successor_original_raw_sha256']==gov['selected_successor_original_raw_sha256'] and
         hold['alternative_successor_original_raw_sha256']==gov['alternative_successor_original_raw_sha256'],
         'ONLY_THE_PARENTS_ACTUAL_SIGNED_SIBLING_PAIR_CAN_BE_ON_HOLD',
         'permission_denied')
    # Also check the old EC343 signed base really includes this approved hold.
    base=_json(read,source['ec343_source_head_snapshot_original'],'ec343_base')
    exact(base,old343.BASE_FIELDS,'TRUE_EC343_HOLD_PREDECESSOR_BASE')
    need(base['expected_governance_roster_sha256']==
           row['ec342_governance_roster_original']['sha256'] and
         base['expected_hold_sha256']==row['ec342_signed_hold_request_original']['sha256'],
         'TRUE_EC343_BASE_MUST_BIND_SIGNED_GOVERNANCE_AND_HOLD','permission_denied')
    # The unchanged EC341 verifier independently reopens every historically
    # signed source and whole ZIP on its own late source pass. Do an *actual*
    # fresh secure reread of our additional raw-public-key copies too (rather
    # than merely returning our earlier memoized bytes); these are byte checks,
    # never institutional identity or custody credentials.
    for request,cap in [(manifestref,MAX_ORIGINAL),
                        *[(x['public_key_original'],32) for x in pubcopies]]:
        fresh=p372._read(request,'ec386_late_'+request['sha256'],cap,
                         {},{},set())
        need(fresh==_source_read(read,request,'late_stable_original',cap),
             'ORIGINAL_EC341_MANIFEST_OR_PUBKEY_COPY_CHANGED_DURING_REPLAY',
             'permission_denied')
    return {'tsa_channel_id':channel,
       'full_original_ec341_signed_root_replay':True,
       'ec341_manifest_sha256':manifestref['sha256'],
       'ec342_governance_sha256':row['ec342_governance_roster_original']['sha256'],
       'ec342_hold_sha256':row['ec342_signed_hold_request_original']['sha256'],
       'ec341_parent_root_sha256':gov['parent_root_original_raw_sha256'],
       'ec341_selected_root_sha256':gov['selected_successor_original_raw_sha256'],
       'ec341_competing_root_sha256':gov['alternative_successor_original_raw_sha256'],
       'ec341_current_root_sha256':gov['current_root_original_raw_sha256'],
       'ec341_current_epoch':gov['current_root_epoch'],
       'ec341_root_original_sha256s':[manifest['context']['expected_authority_roster_sha256'],
           *[h['expected_successor_roster_sha256'] for h in manifest['hops']],
           *[f['hop']['expected_successor_roster_sha256'] for f in manifest['forks']]],
       'ec341_original_signed_dependency_sha256s':pins,
       'ec341_verifiable_public_key_copy_sha256s':copy_sha,
       'ec341_original_signed_edge_count':result['real_role_signature_count'],
       'ec341_original_signed_observation_count':result['real_observer_signature_count'],
       'ec341_observed_signed_sibling_count':len(result['fork_conflicts']),
       'ec342_original_signed_hold_predecessor_incomplete':False,
       'ec341_verified_signed_source_incomplete':False}


def _engine(derive,**opts):
    popts=_inputs(opts,derive)
    parent_result=parent.audit(**popts)   # real, unchanged EC385->EC369 mandatory
    n=len(opts['historical_directory_root_shas'])
    psha=_parent(parent_result,n)
    pins={};categories={};forbidden=set();cache={}
    def read(ref,role,cap):
        p372.prior.lineage.parent.ref_check(ref,'EC386_'+role)
        path=ref['path']
        if path in cache:
            earlier_sha,raw=cache[path]
            need(path not in forbidden and earlier_sha==ref['sha256'] and
                 len(raw)<=cap,'REUSED_SOURCE_PATH_SHA_CAP_OR_SENDER_ALIAS',
                 'permission_denied')
            return raw
        raw=p372._read(ref,'ec386_source_'+ref['sha256'],cap,pins,categories,forbidden)
        cache[path]=(ref['sha256'],raw)
        return raw
    ref385={'path':opts[parent.NEW_SCALARS[0]],'sha256':opts[parent.NEW_SCALARS[1]]}
    ref386={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    def bundle(ref,role,fields,schema,cap=MAX_BUNDLE):
        b=old353.strict_json(_source_read(read,ref,role,cap),'EC386_'+role)
        exact(b,fields,role)
        need(b['schema']==schema and type(b['epochs']) is list and
             len(b['epochs'])==n,'ORIGINAL_ARCHIVE_SCHEMA_EPOCH_CENSUS_'+role,
             'permission_denied')
        return b
    old=bundle(ref385,'old_ec385_parent',parent.BUNDLE_FIELDS,parent.BUNDLE_SCHEMA,
               parent.MAX_BUNDLE)
    new=bundle(ref386,'ec386_receiver',BUNDLE_FIELDS,BUNDLE_SCHEMA)
    need(new['parent_ec385_canonical_result_sha256']==psha and
         new['ec385_historical_change_archive_original_sha256']==ref385['sha256'] and
         new['claimed_directory_lineage_id']==old['claimed_directory_lineage_id']==
             opts['claimed_historical_directory_lineage_id'],
         'TRUE_LIVE_PARENT_EC385_RESULT_ARCHIVE_AND_LINEAGE_ID_REQUIRED',
         'permission_denied')
    # As in EC385, sender-side EC353 publication references are not receiver
    # originals. Build explicit forbidden paths BEFORE any old EC341 dependency
    # read or historic verifier follows a manifest-listed path.
    ref377={'path':opts['historical_transparency_archive_bundle_file'],
            'sha256':opts['expected_historical_transparency_archive_bundle_sha256']}
    sender_archive=bundle(ref377,'old_ec377_sender_index',p377.BUNDLE_FIELDS,
                          p377.BUNDLE_SCHEMA,p377.MAX_BUNDLE)
    for ep in sender_archive['epochs']:
        sender_ref=ep['ec353_publication_bundle_original']
        sender=old353.strict_json(_source_read(read,sender_ref,'sender_labels',
                  old353.MAX_BUNDLE),'EC386_UNTRUSTED_SENDER_LABELS')
        p379._old_sender_labels(sender,forbidden)
        forbidden.add(sender_ref['path'])
    forbidden.add(ref377['path'])
    forbidden.update(v for k,v in opts.items() if k.endswith('_file') and type(v) is str)
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not parent_result['local_ec342_approved_hold_ec343_signed_change_originals_consistent']
    epochs=[];inventory=[];previous={};total_edges=total_obs=total_forks=0
    for idx,(ep,legacy_ep) in enumerate(zip(new['epochs'],old['epochs'],strict=True)):
        exact(ep,EPOCH_FIELDS,'EC386_EPOCH')
        exact(legacy_ep,parent.EPOCH_FIELDS,'PARENT_EC385_EPOCH')
        need(ep['epoch_index']==legacy_ep['epoch_index']==idx and
             type(ep['channels']) is list and type(legacy_ep['channels']) is list and
             len(ep['channels'])==len(legacy_ep['channels']) and
             1<=len(ep['channels'])<=2,
             'EXACT_PARENT_EPOCH_CHANNEL_CENSUS','permission_denied')
        ids=[[r.get('tsa_channel_id') for r in lines] for lines in
             (ep['channels'],legacy_ep['channels'])]
        need(ids[0]==ids[1] and ids[0]==sorted(set(ids[0])),
             'ORIGINAL_CHANNEL_ID_ORDER_MUST_MATCH_PARENT','permission_denied')
        lines=[]
        for row,source in zip(ep['channels'],legacy_ep['channels'],strict=True):
            r=_channel(row,source,read)
            lines.append(r)
            flags[FLAGS[2]]|=not r['full_original_ec341_signed_root_replay']
            flags[FLAGS[3]]|=r['ec341_verified_signed_source_incomplete']
            flags[FLAGS[4]]|=r['ec342_original_signed_hold_predecessor_incomplete']
            flags[FLAGS[5]]|=r['ec341_observed_signed_sibling_count']>0
            earlier=previous.get(r['tsa_channel_id'])
            if earlier is not None:
                identity=('ec341_manifest_sha256','ec342_governance_sha256',
                  'ec342_hold_sha256','ec341_parent_root_sha256',
                  'ec341_selected_root_sha256','ec341_competing_root_sha256',
                  'ec341_current_root_sha256','ec341_current_epoch',
                  'ec341_root_original_sha256s',
                  'ec341_original_signed_dependency_sha256s')
                flags[FLAGS[6]]|=(not earlier['full_original_ec341_signed_root_replay'] or
                    any(earlier[k]!=r[k] for k in identity) or
                    r['ec341_original_signed_edge_count']<earlier['ec341_original_signed_edge_count'] or
                    r['ec341_original_signed_observation_count']<earlier['ec341_original_signed_observation_count'] or
                    r['ec341_observed_signed_sibling_count']<earlier['ec341_observed_signed_sibling_count'])
            previous[r['tsa_channel_id']]=r
        if len(lines)==2:
            identity=('ec341_manifest_sha256','ec342_governance_sha256','ec342_hold_sha256',
              'ec341_parent_root_sha256','ec341_selected_root_sha256',
              'ec341_competing_root_sha256','ec341_current_root_sha256',
              'ec341_current_epoch','ec341_root_original_sha256s',
              'ec341_original_signed_dependency_sha256s')
            flags[FLAGS[6]]|=any(lines[0][k]!=lines[1][k] for k in identity)
        roots=[{k:r[k] for k in ('tsa_channel_id','ec341_manifest_sha256',
          'ec341_parent_root_sha256','ec341_selected_root_sha256',
          'ec341_competing_root_sha256','ec341_current_root_sha256',
          'ec341_current_epoch','ec341_root_original_sha256s',
          'ec341_original_signed_dependency_sha256s',
          'ec341_original_signed_edge_count',
          'ec341_original_signed_observation_count',
          'ec341_observed_signed_sibling_count')} for r in lines]
        holds=[{k:r[k] for k in ('tsa_channel_id','ec342_governance_sha256',
          'ec342_hold_sha256','ec341_manifest_sha256',
          'ec341_parent_root_sha256','ec341_selected_root_sha256',
          'ec341_competing_root_sha256',
          'ec341_verifiable_public_key_copy_sha256s')} for r in lines]
        rsha=sha(canonical.canonical(roots));hsha=sha(canonical.canonical(holds))
        edges=sum(r['ec341_original_signed_edge_count'] for r in lines)
        obs=sum(r['ec341_original_signed_observation_count'] for r in lines)
        forks=sum(r['ec341_observed_signed_sibling_count'] for r in lines)
        total_edges+=edges;total_obs+=obs;total_forks+=forks
        flags[FLAGS[1]]|=(rsha!=opts['historical_ec341_signed_root_inventory_shas'][idx] or
          hsha!=opts['historical_ec342_root_conflict_binding_inventory_shas'][idx] or
          edges<opts['minimum_historical_ec341_signed_edge_counts'][idx] or
          obs<opts['minimum_historical_ec341_signed_observation_counts'][idx] or
          forks<opts['minimum_historical_ec341_verified_sibling_counts'][idx])
        epochs.append({'epoch_index':idx,'old_ec341_signed_edge_count':edges,
           'old_ec341_signed_witness_count':obs,
           'old_ec341_verified_visible_sibling_count':forks,
           'ec341_signed_root_inventory_sha256':rsha,
           'ec342_signed_hold_conflict_binding_inventory_sha256':hsha,
           'missing_original_old_ec341_source_channels':sum(not r['full_original_ec341_signed_root_replay'] for r in lines),
           'local_old_ec341_root_conflict_ec342_hold_sources_consistent':
               all(r['full_original_ec341_signed_root_replay'] for r in lines) and
               not flags[FLAGS[6]]})
        inventory.append({'epoch_index':idx,
          'ec341_original_signed_root_handoffs':roots,
          'ec342_original_signed_hold_conflict_bindings':holds,
          'ec341_signed_root_inventory_sha256':rsha,
          'ec342_signed_hold_conflict_binding_inventory_sha256':hsha})
    flags[FLAGS[7]]=True;flags[FLAGS[8]]=True
    inv={'schema':INVENTORY_SCHEMA,
         'live_ec385_to_ec369_parent_canonical_result_sha256':psha,
         'receiver_original_ec385_change_archive_sha256':ref385['sha256'],
         'receiver_original_ec386_root_archive_sha256':ref386['sha256'],
         'claimed_directory_lineage_id':new['claimed_directory_lineage_id'],
         'historical_ec341_root_conflict_epoch_reviews':inventory}
    invsha=sha(canonical.canonical(inv))
    if not derive and invsha!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    local=not any(flags[k] for k in FLAGS[:5]+FLAGS[6:7])
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
       'command':'derive-historical-ec341-root-inventory' if derive else
                 'audit-historical-ec341-root-conflict-archive',
       'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                     OUTCOMES[-1])+'_unresolved',
       'exit_code':2,'offline_unresolved_exit_code':2,
       'verified_live_parent_ec385_canonical_result_sha256':psha,
       'historical_ec341_signed_root_conflict_archive_original_sha256':ref386['sha256'],
       'receiver_verified_old_ec341_signed_root_inventory_sha256':invsha,
       'genuine_old_ec341_signed_edge_count':total_edges,
       'genuine_old_ec341_signed_observation_count':total_obs,
       'genuine_old_ec341_visible_signed_sibling_count':total_forks,
       'historical_ec341_root_conflict_epoch_reviews':epochs,
       'local_old_ec341_signed_root_conflict_ec342_hold_originals_consistent':local,
       'sender_origin_path_required_or_read':False,
       'ec341_through_ec337_full_independent_original_historical_acceptance_performed':False,
       **flags,**{k:False for k in NEGATIVES},
       **({'unsigned_verified_old_ec341_root_conflict_inventory':inv,
           'caller_retained_inventory_sha_independently_certified':False} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
