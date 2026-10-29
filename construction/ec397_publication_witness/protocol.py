#!/usr/bin/env python3
"""EC397: bounded OFFLINE proof-of-receipt of real EC396 public-log originals.

A true EC396 audit is executed every time. This module validates two new
independently keyed observers' original, SHA-pinned receipt signatures, the
original EC396 publisher's signed dispatch, actual bytes delivered to each
channel, authentic furnished RFC3161 tokens, and signed fork evidence.

No given witness, even with a valid timestamp, establishes that anyone on the
public internet saw the material *before* a real-world dispute. No official
registrar, regulatory, OCSP, network, or physical-WORM claim is inferred.
"""
from __future__ import annotations

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec353_transparency import transparency as tr
from ec372_historical_authority import authority_archive as io
from ec396_public_integrity import protocol as parent

RESULT_SCHEMA='ces.ec397.receiver_two_channel_publication_unresolved.v1'
DERIVE_SCHEMA='ces.ec397.unsigned_two_channel_publication_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec397.two_channel_publication_denial.v1'
INVENTORY_SCHEMA='ces.ec397.unsigned_two_channel_publication_inventory.v1'
BUNDLE_SCHEMA='ces.ec397.original_two_channel_publication_bundle.v1'
ROSTER_SCHEMA='ces.ec397.two_outside_publication_observers.v1'
DISPATCH_SCHEMA='ces.ec397.original_signed_publication_dispatch.v1'
DISPATCH_CLAIM='ces.ec397.signed_publication_dispatch_claim.v1'
RECEIPT_SCHEMA='ces.ec397.original_signed_channel_observation.v1'
RECEIPT_CLAIM='ces.ec397.signed_channel_observation_claim.v1'
DISPATCH_DOMAIN=b'CES/EC397/PublicHeadDispatch/v1\0'
RECEIPT_DOMAIN=b'CES/EC397/IndependentChannelObserved/v1\0'
ZERO='0'*64
MAX_BUNDLE=400_000
MAX_ROSTER=15_000
MAX_SIGNED=70_000

PARENT_SCALARS=(*parent.PARENT_SCALARS,*parent.NEW_SCALARS,*parent.AUDIT_ONLY)
PARENT_REPEATS=(*parent.PARENT_REPEATS,*parent.REPEAT_NAMES)
NEW_SCALARS=(
 'historical_ec339_publication_witness_bundle_file',
 'expected_historical_ec339_publication_witness_bundle_sha256',
 'expected_outside_retained_ec397_observer_roster_sha256',
 'expected_outside_retained_ec397_channel_a_public_hex',
 'expected_outside_retained_ec397_channel_b_public_hex',
 'expected_outside_retained_ec397_first_dispatch_sha256',
 'expected_outside_retained_ec397_first_channel_a_receipt_sha256',
 'expected_outside_retained_ec397_first_channel_b_receipt_sha256',
)
AUDIT_ONLY=('expected_retained_historical_ec339_publication_witness_inventory_sha256',)
NEW_REPEATS=(
 ('historical_ec339_channel_delivery_inventory_shas','--historical-ec339-channel-delivery-inventory-sha256'),
 ('historical_ec339_publication_fork_inventory_shas','--historical-ec339-publication-fork-inventory-sha256'),
 ('minimum_historical_ec339_signed_channel_delivery_counts','--minimum-historical-ec339-signed-channel-delivery-count'),
 ('minimum_historical_ec339_two_channel_pair_counts','--minimum-historical-ec339-two-channel-pair-count'),
)
REPEAT_NAMES=tuple(x for x,_ in NEW_REPEATS)
FLAGS=(
 'inherited_real_ec396_registry_log_or_device_originals_disputed',
 'independently_retained_publication_inventory_or_floor_disagrees',
 'publisher_dispatch_original_signature_chain_or_timestamp_incomplete',
 'two_independent_timestamped_channel_receipts_or_copy_recovery_incomplete',
 'genuine_signed_same_epoch_log_fork_or_public_observation_disagreement',
 'inter_epoch_dispatch_or_channel_predecessor_continuity_unbounded',
 'real_independent_pre_dispute_public_availability_not_established',
 'full_official_registry_global_revocation_and_physical_worm_not_established',
 'qualified_legal_evidence_and_final_product_acceptance_not_established',
)
OUTCOMES=(
 'ec397_real_parent_public_history_disputed',
 'ec397_external_sha_or_channel_count_floor_disagrees',
 'ec397_signed_dispatch_or_qualified_timestamp_incomplete',
 'ec397_independent_signed_witness_original_copy_delivery_incomplete',
 'ec397_authenticated_evidence_of_public_log_equivocation_or_disagreement',
 'ec397_signed_channel_predecessor_continuity_unbounded',
 'ec397_actual_prior_public_availability_not_proven',
 'ec397_official_authority_revocation_or_physical_worm_not_proven',
 'ec397_final_legal_and_product_acceptance_not_proven',
)
NEGATIVES=(
 'two_signatures_on_furnished_documents_prove_independent_internet_publication',
 'site_labels_and_different_keys_prove_independent_corporate_governance',
 'time_stamped_local_receipts_prove_genuine_delivery_at_claimed_historical_time',
 'furnished_single_head_or_two_observers_exclude_unseen_forks',
 'furnished_official_licenses_and_online_revocation_are_independently_accepted',
 'physical_worm_or_old_device_storage_is_authenticated',
 'furnished_rfc3161_originals_prove_legally_qualified_tsa_or_dispute_cutoff',
 'private_ed25519_signatures_or_timestamp_tokens_are_issued_by_receiver',
 'receiver_used_network_git_ci_provider_or_wrote_originals',
 'native_powershell_and_full_historical_external_validation_have_passed',
 'product_quality_or_final_user_acceptance_is_promoted',
)
BUNDLE_FIELDS={'schema','claimed_directory_lineage_id','parent_ec396_public_integrity_bundle_original',
               'outside_observer_roster_original','epochs'}
ROSTER_FIELDS={'schema','claimed_directory_lineage_id','channels'}
ROLE_FIELDS={'role_id','site_id','channel_id','public_hex','public_key_original'}
EPOCH_FIELDS={'epoch_index','dispatch','channels','conflicting_heads'}
DISPATCH_FIELDS={'signed_original','rfc3161_token_original'}
DISPATCH_CLAIM_FIELDS={'schema','directory_lineage_id','parent_ec396_bundle_sha256',
 'parent_ec396_verified_inventory_sha256','epoch_index','dispatch_sequence','log_signer_id',
 'public_log_signed_head_original_sha256','public_log_merkle_size',
 'public_log_merkle_root_sha256','previous_dispatch_original_sha256','claimed_dispatched_utc'}
CHANNEL_FIELDS={'channel_id','signed_receipt_original','rfc3161_token_original',
 'copied_dispatch_original','copied_public_log_head_original'}
RECEIPT_CLAIM_FIELDS={'schema','directory_lineage_id','parent_ec396_bundle_sha256',
 'parent_ec396_verified_inventory_sha256','epoch_index','channel_id','observer_id',
 'observer_site_id','public_log_head_original_sha256','public_log_merkle_size',
 'public_log_merkle_root_sha256','dispatch_signed_original_sha256',
 'previous_channel_receipt_original_sha256','recovered_original_copies_inventory_sha256',
 'claimed_observed_utc'}
FORK_FIELDS={'signed_head_original','rfc3161_token_original'}
SIGNED_FIELDS={'schema','claim','signature_ed25519'}


def require(test,code,status='invalid_input'):
    if test is not True:
        raise errors.AnchorError('EC397_'+code,status)


def exact(value,fields,code):
    require(type(value) is dict and set(value)==fields,code+'_EXACT_FIELDS_REQUIRED')


def valid_sha(value):return parent.valid_sha(value)


def rawref(ref):
    return parent.rawref(ref)


def cdigest(obj):return parent.cdigest(obj)


def digest(raw):return parent.digest(raw)


def _inputs(opts,derive):
    required=set((*PARENT_SCALARS,*PARENT_REPEATS,*NEW_SCALARS,*REPEAT_NAMES))
    if not derive:required.update(AUDIT_ONLY)
    require(set(opts)==required,'COMPLETE_REAL_EC396_AND_EC397_INPUTS_REQUIRED')
    inherited={key:opts[key] for key in (*PARENT_SCALARS,*PARENT_REPEATS)}
    parent._inputs(inherited,False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],'EC397_BUNDLE')
    for k in (NEW_SCALARS[2],*NEW_SCALARS[5:]):
        require(valid_sha(opts[k]),'INDEPENDENT_RETAINED_SHA_REQUIRED')
    for k in NEW_SCALARS[3:5]:
        require(parent.parent.prior._hexkey(opts[k]),'INDEPENDENT_OBSERVER_RAW_PUBLIC_KEY_REQUIRED')
    require(opts[NEW_SCALARS[3]]!=opts[NEW_SCALARS[4]],
            'INDEPENDENT_CHANNEL_PUBLIC_KEYS_MUST_DIFFER','permission_denied')
    if not derive:require(valid_sha(opts[AUDIT_ONLY[0]]),'SEPARATELY_RETAINED_WHOLE_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    require(1<=n<=3,'HISTORICAL_EPOCH_COUNT_OUTSIDE_BOUND')
    for key in REPEAT_NAMES:
        vals=opts[key]
        require(type(vals) is list and len(vals)==n,'ONE_OUTSIDE_COUNT_OR_SHA_PER_EPOCH_REQUIRED')
        if key.startswith('minimum_'):
            upper=1 if 'pair' in key else 2
            require(all(type(v) is int and 0<=v<=upper for v in vals),
                    'OUTSIDE_CHANNEL_MINIMUM_INVALID')
        else:
            require(all(valid_sha(v) for v in vals),'OUTSIDE_CHANNEL_HISTORY_SHA_INVALID')
    return inherited


def _parent_report(report,opts):
    required={'schema','command','status','exit_code','offline_unresolved_exit_code',
      'verified_live_ec395_report_sha256','verified_live_ec395_inventory_sha256',
      'original_public_integrity_bundle_sha256','receiver_verified_public_integrity_inventory_sha256',
      'signed_pre_cutoff_registry_active_role_count','verified_public_log_original_inclusion_set_count',
      'independent_signed_device_original_readback_count',
      'signed_revocation_or_suspension_observation_count','public_integrity_epoch_reviews',
      'local_original_public_history_and_device_copy_consistency',
      'sender_origin_path_required_or_read',
      'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
      *parent.FLAGS,*parent.NEGATIVES}
    require(type(report) is dict and set(report)==required and
       report.get('schema')==parent.RESULT_SCHEMA and
       report.get('command')=='audit-historical-ec339-public-integrity' and
       report.get('exit_code')==2 and report.get('offline_unresolved_exit_code')==2 and
       report.get('status')==next((parent.OUTCOMES[i] for i,k in enumerate(parent.FLAGS)
           if report[k]),parent.OUTCOMES[-1])+'_unresolved' and
       report.get('sender_origin_path_required_or_read') is False and
       report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
       all(type(report.get(k)) is bool for k in parent.FLAGS) and
       all(report[k] is True for k in parent.FLAGS[-3:]) and
       all(report.get(k) is False for k in parent.NEGATIVES) and
       report.get('local_original_public_history_and_device_copy_consistency') is
           (not any(report[k] for k in parent.FLAGS[:6])) and
       report.get('original_public_integrity_bundle_sha256')==opts[parent.NEW_SCALARS[1]] and
       report.get('receiver_verified_public_integrity_inventory_sha256')==opts[parent.AUDIT_ONLY[0]] and
       all(valid_sha(report.get(k)) for k in ('verified_live_ec395_report_sha256',
             'verified_live_ec395_inventory_sha256')),
       'REAL_EC396_AUDIT_AND_INDEPENDENT_HISTORY_SHA_INVALID','unavailable')
    n=len(opts['historical_directory_root_shas'])
    rows=report['public_integrity_epoch_reviews']
    expected={'epoch_index','current_offline_signed_registry_roles',
      'verified_rfc6962_original_inclusion_sets','verified_device_signed_original_receipt_readbacks',
      'registry_inventory_sha256','log_inclusion_inventory_sha256',
      'device_recovery_inventory_sha256','signed_revoked_or_suspended_roles'}
    require(type(rows) is list and len(rows)==n and all(
       type(r) is dict and set(r)==expected and type(r['epoch_index']) is int and
       r['epoch_index']==i and all(type(r[k]) is int and 0<=r[k]<=upper for k,upper in (
           ('current_offline_signed_registry_roles',4),
           ('verified_rfc6962_original_inclusion_sets',1),
           ('verified_device_signed_original_receipt_readbacks',2),
           ('signed_revoked_or_suspended_roles',4))) and
       all(valid_sha(r[k]) for k in ('registry_inventory_sha256',
                          'log_inclusion_inventory_sha256','device_recovery_inventory_sha256'))
       for i,r in enumerate(rows)),
       'REAL_EC396_EPOCH_COUNTS_AND_SHA_HISTORY_INVALID','unavailable')
    require(all(type(report[k]) is int and report[k]==sum(r[j] for r in rows)
                for k,j in (
                 ('signed_pre_cutoff_registry_active_role_count','current_offline_signed_registry_roles'),
                 ('verified_public_log_original_inclusion_set_count','verified_rfc6962_original_inclusion_sets'),
                 ('independent_signed_device_original_readback_count','verified_device_signed_original_receipt_readbacks'),
                 ('signed_revocation_or_suspension_observation_count','signed_revoked_or_suspended_roles'))),
             'REAL_EC396_COUNT_SUMS_INVALID','unavailable')
    return cdigest(report)


def _signed(ref,read,schema,claim_schema,fields,code):
    raw=read(rawref(ref),'ec397_'+code,MAX_SIGNED)
    obj=tr.strict_json(raw,'EC397_'+code)
    exact(obj,SIGNED_FIELDS,code)
    exact(obj['claim'],fields,code+'_CLAIM')
    require(obj['schema']==schema and obj['claim']['schema']==claim_schema,
            code+'_SIGNED_SCHEMA_INVALID','permission_denied')
    return raw,obj['claim'],obj['signature_ed25519']


def _roster(roster,rosterref,opts,lineage,parent_roster,ec395_roster,anchor,read):
    exact(roster,ROSTER_FIELDS,'WITNESS_ROSTER')
    require(roster['schema']==ROSTER_SCHEMA and
            roster['claimed_directory_lineage_id']==lineage and
            rosterref['sha256']==opts[NEW_SCALARS[2]] and
            type(roster['channels']) is list and len(roster['channels'])==2,
            'INDEPENDENT_TWO_CHANNEL_ROSTER_INVALID','permission_denied')
    keys=set(anchor['known_keys']);sites=set(anchor['known_sites']);ids=set(anchor['known_ids'])
    protected=set()
    for role in (*ec395_roster['credential_issuers'],*ec395_roster['offsite_archivists'],
                 parent_roster['registry_signer'],parent_roster['transparency_log_signer'],
                 *parent_roster['device_operators']):
        keys.add(role['public_hex']);sites.add(role['site_id']);ids.add(role['role_id'])
        protected.add(role['public_key_original']['path'])
    channel_names=set();roles={}
    for i,role in enumerate(roster['channels']):
        exact(role,ROLE_FIELDS,'CHANNEL_WITNESS_ROLE')
        require(parent.parent._id(role['role_id']) and role['role_id'] not in ids and
                parent.parent._id(role['site_id']) and role['site_id'] not in sites and
                parent.parent._id(role['channel_id']) and role['channel_id'] not in channel_names and
                role['channel_id'] not in ids and role['channel_id'] not in sites and
                parent.parent.prior._hexkey(role['public_hex']) and role['public_hex'] not in keys,
                'TWO_CHANNEL_WITNESS_KEYS_SITES_IDS_NOT_INDEPENDENT','permission_denied')
        keyref=rawref(role['public_key_original'])
        require(keyref['path'] not in protected,'RAW_WITNESS_KEY_PATH_REUSED','permission_denied')
        raw=read(keyref,'independently_pinned_witness_raw_ed25519_public_key',32)
        require(len(raw)==32 and raw.hex()==role['public_hex'] and
                role['public_hex']==opts[NEW_SCALARS[3+i]],
                'CHANNEL_WITNESS_PUBLIC_KEY_OUTSIDE_PIN_MISMATCH','permission_denied')
        ids.add(role['role_id']);sites.add(role['site_id']);keys.add(role['public_hex'])
        channel_names.add(role['channel_id']);roles[role['channel_id']]=role
        protected.add(keyref['path'])
    return roles,protected


def _stamp(raw,ref,trust,aid,read,evaluation,cutoff,claimed,flags):
    pflags={k:False for k in parent.FLAGS}
    stamp=parent._stamp(raw,ref,trust,aid,read,evaluation,cutoff,claimed,pflags)
    if pflags[parent.FLAGS[5]]:flags[FLAGS[2]]=True
    return stamp


def _bounded(stamp,claimed,cutoff):return parent._bounded(stamp,claimed,cutoff)


def _dispatch(ep,idx,role,headref,head_claim,head_stamp,prev_sha,prev_gen,
              parentref,parent_sha,lineage,read,trust,aid,evaluation,cutoff,flags):
    exact(ep,DISPATCH_FIELDS,'PUBLISHER_DISPATCH')
    if ep['signed_original'] is None:
        require(ep['rfc3161_token_original'] is None,'ABSENT_DISPATCH_HAS_TIMESTAMP')
        flags[FLAGS[2]]=True
        return {'signed_original_sha256':None,'timestamp_sha256':None,
           'head_original_sha256':headref['sha256'] if headref else None,
           'pre_cutoff_dispatch':False,'_gen':None,'_raw':None}
    require(headref is not None and head_claim is not None,
            'DISPATCH_REQUIRES_GENUINE_PARENT_HEAD','permission_denied')
    raw,claim,sig=_signed(ep['signed_original'],read,DISPATCH_SCHEMA,DISPATCH_CLAIM,
            DISPATCH_CLAIM_FIELDS,'SIGNED_PUBLISHER_DISPATCH')
    require(claim['directory_lineage_id']==lineage and
          claim['parent_ec396_bundle_sha256']==parentref['sha256'] and
          claim['parent_ec396_verified_inventory_sha256']==parent_sha and
          type(claim['epoch_index']) is int and claim['epoch_index']==idx and
          type(claim['dispatch_sequence']) is int and claim['dispatch_sequence']==idx+1 and
          claim['log_signer_id']==role['role_id'] and
          claim['public_log_signed_head_original_sha256']==headref['sha256'] and
          claim['public_log_merkle_size']==head_claim['tree_size'] and
          claim['public_log_merkle_root_sha256']==head_claim['merkle_root_sha256'] and
          claim['previous_dispatch_original_sha256']==prev_sha,
          'SIGNED_DISPATCH_WRONG_REAL_HEAD_OR_PREDECESSOR','permission_denied')
    parent.parent._signer(role['public_hex'],sig,DISPATCH_DOMAIN,claim,
                          'EC397_AUTHENTIC_PUBLISHER_DISPATCH')
    claimed=parent.parent._time(claim['claimed_dispatched_utc'])
    stamp=_stamp(raw,ep['rfc3161_token_original'],trust,aid,read,evaluation,cutoff,claimed,flags)
    ordered=(head_stamp is not None and _bounded(head_stamp,parent.parent._time(
         head_claim['claimed_published_utc']),cutoff) and
         claimed>=head_stamp['gen'] and _bounded(stamp,claimed,cutoff) and
         (idx==0 or prev_gen is not None) and
         (prev_gen is None or stamp['gen']>=prev_gen))
    if not ordered:flags[FLAGS[2]]=True
    return {'signed_original_sha256':rawref(ep['signed_original'])['sha256'],
        'timestamp_sha256':stamp['sha256'] if stamp else None,
        'head_original_sha256':headref['sha256'],'pre_cutoff_dispatch':bool(ordered),
        '_gen':stamp['gen'] if stamp else None,'_raw':raw}


def _channel(item,idx,role,dispatch,headref,headraw,head_claim,prevsha,prevgen,prevok,
             parentref,parent_sha,lineage,read,trust,aid,evaluation,cutoff,
             protected,copy_paths,flags):
    exact(item,CHANNEL_FIELDS,'CHANNEL_ORIGINAL_EVIDENCE')
    require(item['channel_id']==role['channel_id'],'UNKNOWN_CHANNEL_ID','permission_denied')
    if item['signed_receipt_original'] is None:
        require(item['rfc3161_token_original'] is None and
                item['copied_dispatch_original'] is None and
                item['copied_public_log_head_original'] is None,
                'ABSENT_CHANNEL_RECEIPT_WITH_COPIES_OR_TOKEN')
        flags[FLAGS[3]]=True
        return {'channel_id':role['channel_id'],'signed_receipt_sha256':None,
                'timestamp_sha256':None,'originals_recovered':0,
                'pre_cutoff_genuine_channel_receipt':False,'_gen':None}
    require(dispatch['_raw'] is not None and headraw is not None and headref is not None,
            'CHANNEL_RECEIPT_MUST_BE_FOR_REAL_DISPATCH_AND_HEAD','permission_denied')
    copies=(item['copied_dispatch_original'],item['copied_public_log_head_original'])
    require(all(x is not None for x in copies),
            'SIGNED_CHANNEL_RECEIPT_MISSING_COMPLETE_ORIGINAL_COPIES','permission_denied')
    copyrows=[]
    for name,ref,source in (('dispatch',copies[0],dispatch['_raw']),
                            ('public_head',copies[1],headraw)):
        rr=rawref(ref)
        require(rr['path'] not in protected and rr['path'] not in copy_paths and
                rr['sha256']==digest(source),
                'CHANNEL_COPY_PATH_ALIAS_OR_SHA_MISMATCH','permission_denied')
        copy_paths.add(rr['path'])
        data=read(rr,'independent_channel_byte_for_byte_'+name,MAX_SIGNED)
        require(data==source,'CHANNEL_COPY_NOT_EXACT_ORIGINAL_BYTES','permission_denied')
        copyrows.append({'kind':name,'original_sha256':digest(source),
                         'original_copy_path':rr['path'],'copy_sha256':rr['sha256']})
    raw,claim,sig=_signed(item['signed_receipt_original'],read,RECEIPT_SCHEMA,RECEIPT_CLAIM,
         RECEIPT_CLAIM_FIELDS,'SIGNED_CHANNEL_RECEIPT')
    require(claim['directory_lineage_id']==lineage and
       claim['parent_ec396_bundle_sha256']==parentref['sha256'] and
       claim['parent_ec396_verified_inventory_sha256']==parent_sha and
       type(claim['epoch_index']) is int and claim['epoch_index']==idx and
       claim['channel_id']==role['channel_id'] and
       claim['observer_id']==role['role_id'] and
       claim['observer_site_id']==role['site_id'] and
       claim['public_log_head_original_sha256']==headref['sha256'] and
       claim['public_log_merkle_size']==head_claim['tree_size'] and
       claim['public_log_merkle_root_sha256']==head_claim['merkle_root_sha256'] and
       claim['dispatch_signed_original_sha256']==dispatch['signed_original_sha256'] and
       claim['previous_channel_receipt_original_sha256']==prevsha and
       claim['recovered_original_copies_inventory_sha256']==cdigest(copyrows),
       'SIGNED_CHANNEL_RECEIPT_WRONG_SOURCE_IDENTITY_OR_RECOVERY_SHA','permission_denied')
    parent.parent._signer(role['public_hex'],sig,RECEIPT_DOMAIN,claim,
                          'EC397_INDEPENDENT_CHANNEL_OBSERVER_SIGNATURE')
    claimed=parent.parent._time(claim['claimed_observed_utc'])
    stamp=_stamp(raw,item['rfc3161_token_original'],trust,aid,read,evaluation,cutoff,claimed,flags)
    continuous=(prevok and (idx==0 or prevgen is not None))
    ordered=(bool(dispatch['pre_cutoff_dispatch']) and continuous and
          dispatch['_gen'] is not None and claimed>=dispatch['_gen'] and
          _bounded(stamp,claimed,cutoff) and
          (prevgen is None or stamp['gen']>=prevgen))
    if not continuous:flags[FLAGS[5]]=True
    if not ordered:flags[FLAGS[3]]=True
    return {'channel_id':role['channel_id'],
       'signed_receipt_sha256':rawref(item['signed_receipt_original'])['sha256'],
       'timestamp_sha256':stamp['sha256'] if stamp else None,
       'originals_recovered':2,'pre_cutoff_genuine_channel_receipt':bool(ordered),
       '_gen':stamp['gen'] if stamp else None}


def _forks(records,idx,headref,head_claim,role,parentref,parent_sha,lineage,
           read,trust,aid,evaluation,cutoff,flags):
    require(type(records) is list and len(records)<=2,'AT_MOST_TWO_ORIGINAL_FORK_HEADS')
    seen=set();seen_hashes=set();rows=[]
    for item in records:
        exact(item,FORK_FIELDS,'FORK_EVIDENCE')
        ref=rawref(item['signed_head_original'])
        require(ref['path'] not in seen and ref['sha256'] not in seen_hashes,
                'DUPLICATE_SIGNED_FORK_ORIGINAL_OR_BYTES')
        seen.add(ref['path']);seen_hashes.add(ref['sha256'])
        require(headref is not None and head_claim is not None and ref!=headref,
                'FORK_MUST_REFER_TO_EXISTING_PARENT_HEAD','permission_denied')
        raw,claim,sig=_signed(ref,read,parent.LOG_SCHEMA,parent.LOG_CLAIM,
                        parent.LOG_CLAIM_FIELDS,'SIGNED_CONFLICTING_HEAD')
        parent.parent._signer(role['public_hex'],sig,parent.LOG_DOMAIN,claim,
                             'EC397_AUTHENTIC_ALTERNATIVE_EC396_HEAD')
        require(all(claim[k]==head_claim[k] for k in head_claim if k not in (
                 'merkle_root_sha256','tree_size','claimed_published_utc')) and
                (claim['tree_size']!=head_claim['tree_size'] or
                 claim['merkle_root_sha256']!=head_claim['merkle_root_sha256']) and
                type(claim['tree_size']) is int and 4<=claim['tree_size']<=tr.MAX_LOG_LEAVES and
                valid_sha(claim['merkle_root_sha256']) and
                type(claim['epoch_index']) is int and claim['epoch_index']==idx,
                'FORK_MUST_BE_SAME_AUTHENTIC_EPOCH_SEQUENCE_DIFFERENT_ROOT_OR_SIZE',
                'permission_denied')
        claimed=parent.parent._time(claim['claimed_published_utc'])
        stamp=_stamp(raw,item['rfc3161_token_original'],trust,aid,read,evaluation,cutoff,claimed,flags)
        bounded=bool(_bounded(stamp,claimed,cutoff))
        flags[FLAGS[4]]=True
        if not bounded:flags[FLAGS[2]]=True
        rows.append({'signed_conflicting_head_sha256':ref['sha256'],
            'conflicting_merkle_root_sha256':claim['merkle_root_sha256'],
            'conflicting_tree_size':claim['tree_size'],
            'authentic_same_epoch_fork':True,'pre_cutoff_genuine_token':bounded})
    return rows


def _engine(derive,**opts):
    inherited=_inputs(opts,derive)
    actual=parent.audit(**inherited)  # mandatory production EC396->EC395->EC394->...
    real_parent_report_sha=_parent_report(actual,opts)
    n=len(opts['historical_directory_root_shas'])
    lineage=opts['claimed_historical_directory_lineage_id']
    evaluation=parent.parent._time(opts['ec391_tsa_evaluation_utc'])
    cutoff=parent.parent._time(opts[parent.parent.prior.parent.NEW_SCALARS[5]])
    read,doc,late=parent.parent.prior._readers()
    rootref={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    bundle=doc(rootref,'original_ec397_two_channel_publication_bundle',MAX_BUNDLE)
    exact(bundle,BUNDLE_FIELDS,'TWO_CHANNEL_BUNDLE')
    pref={'path':opts[parent.NEW_SCALARS[0]],'sha256':opts[parent.NEW_SCALARS[1]]}
    require(bundle['schema']==BUNDLE_SCHEMA and
            bundle['claimed_directory_lineage_id']==lineage and
            bundle['parent_ec396_public_integrity_bundle_original']==pref and
            type(bundle['epochs']) is list and len(bundle['epochs'])==n,
            'EC397_BUNDLE_NOT_BOUND_TO_REAL_EC396','permission_denied')
    pbundle=doc(pref,'true_parent_ec396_public_integrity_bundle',parent.MAX_BUNDLE)
    exact(pbundle,parent.BUNDLE_FIELDS,'PARENT_EC396_BUNDLE')
    require(pbundle['schema']==parent.BUNDLE_SCHEMA and
            pbundle['claimed_directory_lineage_id']==lineage and len(pbundle['epochs'])==n,
            'PARENT_EC396_ORIGINAL_EPOCHS_INVALID','permission_denied')
    ec395ref=rawref(pbundle['parent_ec395_credential_gossip_bundle_original'])
    require(ec395ref=={'path':opts[parent.parent.NEW_SCALARS[0]],
                        'sha256':opts[parent.parent.NEW_SCALARS[1]]},
            'PARENT_EC396_EC395_ROOT_CHANGED','permission_denied')
    ec395bundle=doc(ec395ref,'actual_parent_ec395_bundle',parent.parent.MAX_BUNDLE)
    anchor=parent.parent._actual_parent_source(ec395bundle,opts,read,doc)
    ec395roster=doc(rawref(ec395bundle['external_role_roster_original']),
                   'actual_parent_ec395_independent_roster',parent.parent.MAX_ROSTER)
    _ec395_roles,_ec395_keypaths=parent.parent._roster(
       ec395roster,rawref(ec395bundle['external_role_roster_original']),opts,lineage,read,
       anchor['known_keys'],anchor['known_sites'],anchor['known_ids'])
    parentroster=doc(rawref(pbundle['outside_authority_roster_original']),
                     'actual_parent_ec396_registry_log_and_device_roster',parent.MAX_ROSTER)
    _ec396_roles,_ec396_keypaths=parent._roster(
        parentroster,rawref(pbundle['outside_authority_roster_original']),opts,
        lineage,anchor,ec395roster,read)
    rosterref=rawref(bundle['outside_observer_roster_original'])
    roles,rolepaths=_roster(doc(rosterref,'independent_ec397_channel_roster',MAX_ROSTER),
              rosterref,opts,lineage,parentroster,ec395roster,anchor,read)
    logrole=parentroster['transparency_log_signer']
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not actual['local_original_public_history_and_device_copy_consistency']
    protected={rootref['path'],pref['path'],ec395ref['path'],rosterref['path'],
               pbundle['outside_authority_roster_original']['path'],
               ec395bundle['external_role_roster_original']['path'],
               pbundle['purported_public_catalog_original']['path']}
    protected.update(rolepaths)
    protected.update(_ec395_keypaths)
    protected.update(_ec396_keypaths)
    # Predeclare every signed/timestamp original and every parent source, including
    # future epochs, BEFORE allowing any channel copy path to be read.
    def collect(value):
        if type(value) is dict:
            if set(value)=={'path','sha256'} and type(value['path']) is str:
                protected.add(value['path'])
            else:
                for v in value.values():collect(v)
        elif type(value) is list:
            for v in value:collect(v)
    collect(pbundle);collect(ec395bundle)
    for ep in bundle['epochs']:
        exact(ep,EPOCH_FIELDS,'EC397_EPOCH_PREFLIGHT')
        exact(ep['dispatch'],DISPATCH_FIELDS,'SIGNED_DISPATCH_PREFLIGHT')
        for key in DISPATCH_FIELDS:collect(ep['dispatch'][key])
        require(type(ep['channels']) is list and len(ep['channels'])==2,
                'TWO_CHANNEL_OBSERVATION_GROUPS_REQUIRED')
        for ch in ep['channels']:
            exact(ch,CHANNEL_FIELDS,'CHANNEL_PREFLIGHT')
            collect(ch['signed_receipt_original']);collect(ch['rfc3161_token_original'])
        require(type(ep['conflicting_heads']) is list and len(ep['conflicting_heads'])<=2,
                'FORK_ORIGINAL_COUNT_TOO_LARGE')
        for f in ep['conflicting_heads']:
            exact(f,FORK_FIELDS,'FORK_PREFLIGHT')
            collect(f['signed_head_original']);collect(f['rfc3161_token_original'])
    copies=set();prev_dispatch=ZERO;prev_dispatch_gen=None;dispatch_ok=True
    prev_receipts={role['channel_id']:ZERO for role in roles.values()}
    prev_receipt_gen={id_:None for id_ in roles}
    prev_receipt_ok={id_:True for id_ in roles}
    reviews=[];inventory_epochs=[];all_forks=[]
    delivery_total=0;pair_total=0
    firstdispatch=None;firstreceipts={}
    for idx,ep in enumerate(bundle['epochs']):
        require(type(ep['epoch_index']) is int and ep['epoch_index']==idx,
                'PUBLISH_EPOCH_INDICES_NOT_CONTIGUOUS','permission_denied')
        parentep=pbundle['epochs'][idx]
        require(type(parentep) is dict and 'log' in parentep,
                'TRUE_PARENT_LOG_EPOCH_MISSING','unavailable')
        headep=parentep['log'];exact(headep,parent.LOG_FIELDS,'REAL_SIGNED_HEAD_ENTRY')
        headref=headep['signed_head_original']
        if headref is not None:
            headraw,headclaim,headsig=_signed(headref,read,parent.LOG_SCHEMA,
                  parent.LOG_CLAIM,parent.LOG_CLAIM_FIELDS,'REAL_EC396_SIGNED_HEAD')
            parent.parent._signer(logrole['public_hex'],headsig,parent.LOG_DOMAIN,
                          headclaim,'EC397_REAL_EC396_SIGNED_HEAD')
            claimed=parent.parent._time(headclaim['claimed_published_utc'])
            headstamp=_stamp(headraw,headep['rfc3161_token_original'],anchor['trust'],
                           anchor['authority'],read,evaluation,cutoff,claimed,flags)
        else:headraw=headclaim=headstamp=None
        dispatch=_dispatch(ep['dispatch'],idx,logrole,headref,headclaim,headstamp,
            prev_dispatch,prev_dispatch_gen,pref,
            actual['receiver_verified_public_integrity_inventory_sha256'],lineage,
            read,anchor['trust'],anchor['authority'],evaluation,cutoff,flags)
        if idx==0:firstdispatch=dispatch['signed_original_sha256']
        if not dispatch['pre_cutoff_dispatch'] or not dispatch_ok:
            dispatch_ok=False;flags[FLAGS[5]]=True
        prev_dispatch=dispatch['signed_original_sha256'] or ZERO
        prev_dispatch_gen=dispatch['_gen']
        forkrows=_forks(ep['conflicting_heads'],idx,headref,headclaim,logrole,pref,
               actual['receiver_verified_public_integrity_inventory_sha256'],lineage,
               read,anchor['trust'],anchor['authority'],evaluation,cutoff,flags)
        all_forks.extend({'epoch_index':idx,**r} for r in forkrows)
        require(type(ep['channels']) is list and len(ep['channels'])==2,
                'TWO_CHANNELS_REQUIRED')
        rows=[];seen=set();count=0
        for ch in ep['channels']:
            require(type(ch) is dict and ch.get('channel_id') in roles and
                    ch['channel_id'] not in seen,
                    'UNKNOWN_OR_DUPLICATED_CHANNEL_ID','permission_denied')
            channel=ch['channel_id'];seen.add(channel)
            r=_channel(ch,idx,roles[channel],dispatch,headref,headraw,headclaim,
               prev_receipts[channel],prev_receipt_gen[channel],prev_receipt_ok[channel],
               pref,actual['receiver_verified_public_integrity_inventory_sha256'],lineage,
               read,anchor['trust'],anchor['authority'],evaluation,cutoff,
               protected,copies,flags)
            if idx==0:firstreceipts[channel]=r['signed_receipt_sha256']
            prev_receipts[channel]=r['signed_receipt_sha256'] or ZERO
            prev_receipt_gen[channel]=r.pop('_gen')
            if not r['pre_cutoff_genuine_channel_receipt'] or not dispatch_ok:
                prev_receipt_ok[channel]=False
            r['pre_cutoff_genuine_channel_receipt']=bool(prev_receipt_ok[channel] and
                          not flags[FLAGS[4]] and not flags[FLAGS[0]] and
                          actual['public_integrity_epoch_reviews'][idx][
                            'verified_rfc6962_original_inclusion_sets']==1)
            count+=int(r['pre_cutoff_genuine_channel_receipt'])
            rows.append(r)
        require(seen==set(roles),'BOTH_INDEPENDENT_CHANNELS_REQUIRED','permission_denied')
        rows.sort(key=lambda r:r['channel_id'])
        if forkrows or flags[FLAGS[4]]:count=0
        pair=int(count==2)
        dispatch_public={k:v for k,v in dispatch.items() if not k.startswith('_')}
        deliveries={'dispatch':dispatch_public,'channel_receipts':rows}
        ds=cdigest(deliveries);fs=cdigest(forkrows)
        if ds!=opts[NEW_REPEATS[0][0]][idx] or fs!=opts[NEW_REPEATS[1][0]][idx] or (
            count<opts[NEW_REPEATS[2][0]][idx] or pair<opts[NEW_REPEATS[3][0]][idx]):
            flags[FLAGS[1]]=True
        delivery_total+=count;pair_total+=pair
        reviews.append({'epoch_index':idx,'verified_signed_channel_deliveries':count,
            'verified_two_channel_observation_pair':pair,
            'authentic_signed_conflicting_log_heads':len(forkrows),
            'channel_delivery_inventory_sha256':ds,
            'signed_fork_originals_inventory_sha256':fs})
        inventory_epochs.append({'epoch_index':idx,'channel_deliveries':deliveries,
                                 'genuine_signed_conflicting_heads':forkrows})
    expect_first=[opts[NEW_SCALARS[5]],opts[NEW_SCALARS[6]],opts[NEW_SCALARS[7]]]
    got_first=[firstdispatch,firstreceipts.get(
      next(iter(roles))),firstreceipts.get(list(roles)[1])]
    if got_first!=expect_first:flags[FLAGS[1]]=True
    inventory={'schema':INVENTORY_SCHEMA,'directory_lineage_id':lineage,
       'live_verified_ec396_report_sha256':real_parent_report_sha,
       'real_ec396_bundle_original_sha256':pref['sha256'],
       'real_ec396_inventory_sha256':actual['receiver_verified_public_integrity_inventory_sha256'],
       'outside_retained_two_channel_role_roster_sha256':rosterref['sha256'],
       'outside_retained_first_dispatch_sha256':opts[NEW_SCALARS[5]],
       'outside_retained_first_channel_receipt_shas':[opts[NEW_SCALARS[6]],opts[NEW_SCALARS[7]]],
       'epochs':inventory_epochs,'observed_genuine_signed_forks':all_forks}
    inventory_sha=cdigest(inventory)
    if not derive and inventory_sha!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    for path,(sha,cap) in late.items():
        raw=io._read({'path':path,'sha256':sha},
            'ec397_final_bounded_original_byte_readback',cap,{},{},set())
        require(digest(raw)==sha,'SIGNED_SOURCE_CHANGED_DURING_AUDIT','permission_denied')
    for key in FLAGS[-3:]:flags[key]=True
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
        'command':('derive-historical-ec339-publication-witness-inventory' if derive else
                   'audit-historical-ec339-publication-witness'),
        'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),OUTCOMES[-1])+'_unresolved',
        'exit_code':2,'offline_unresolved_exit_code':2,
        'verified_live_ec396_report_sha256':real_parent_report_sha,
        'verified_live_ec396_inventory_sha256':actual['receiver_verified_public_integrity_inventory_sha256'],
        'original_two_channel_publication_bundle_sha256':rootref['sha256'],
        'receiver_verified_two_channel_publication_inventory_sha256':inventory_sha,
        'verified_independent_signed_channel_delivery_count':delivery_total,
        'verified_two_channel_observation_pair_count':pair_total,
        'visible_authentic_signed_public_log_fork_count':len(all_forks),
        'publication_epoch_reviews':reviews,
        'bounded_local_two_channel_original_integrity':not any(flags[k] for k in FLAGS[:6]),
        'sender_origin_path_required_or_read':False,
        'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
        **flags,**{key:False for key in NEGATIVES},
        **({'unsigned_two_channel_publication_inventory':inventory} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)


def audit(**opts):return _engine(False,**opts)
