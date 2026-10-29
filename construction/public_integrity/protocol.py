#!/usr/bin/env python3
"""EC396 offline verifier for signed registry history, public-log Merkle history,
and two independent claimed WORM device readbacks.

Actual unchanged EC395 audit is mandatory. This verifies furnished original bytes,
Ed25519 domains, actual RFC3161 originals/CRLs, RFC6962 inclusion/consistency,
and exact recovery of genuine EC395 archive receipts. It deliberately does not
claim an official registry, internet publication, legal accreditation, hardware
WORM, custody age, global revocation or qualified time authority.
"""
from __future__ import annotations

from datetime import timedelta
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from transparency import transparency as tr
from historical_authority import authority_archive as io
from accredited_gossip import protocol as parent

RESULT_SCHEMA='ces.ec396.receiver_public_registry_merkle_worm_unresolved.v1'
DERIVE_SCHEMA='ces.ec396.unsigned_public_registry_merkle_worm_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec396.public_registry_merkle_worm_denial.v1'
INVENTORY_SCHEMA='ces.ec396.unsigned_public_registry_merkle_worm_inventory.v1'
BUNDLE_SCHEMA='ces.ec396.original_registry_log_worm_evidence_bundle.v1'
ROSTER_SCHEMA='ces.ec396.outside_registry_log_and_two_device_operators.v1'
REGISTRY_SCHEMA='ces.ec396.original_signed_public_registry_snapshot.v1'
REGISTRY_CLAIM='ces.ec396.signed_public_registry_snapshot_claim.v1'
LOG_SCHEMA='ces.ec396.original_signed_public_transparency_head.v1'
LOG_CLAIM='ces.ec396.signed_public_transparency_head_claim.v1'
WORM_SCHEMA='ces.ec396.original_signed_device_custody_attestation.v1'
WORM_CLAIM='ces.ec396.signed_device_custody_attestation_claim.v1'
REGISTRY_DOMAIN=b'CES/EC396/OutsideRegistrySnapshot/v1\0'
LOG_DOMAIN=b'CES/EC396/OutsideMerkleHead/v1\0'
WORM_DOMAIN=b'CES/EC396/IndependentDeviceReadback/v1\0'
ZERO='0'*64
MAX_BUNDLE=800_000
MAX_ROSTER=20_000
MAX_SIGNED=70_000
MAX_CATALOG=180_000
MAX_DEVICE=180_000
MAX_COPY=600_000
PARENT_SCALARS=(*parent.PARENT_SCALARS,*parent.NEW_SCALARS,*parent.AUDIT_ONLY)
PARENT_REPEATS=(*parent.PARENT_REPEATS,*parent.REPEAT_NAMES)
NEW_SCALARS=(
 'historical_ec339_public_integrity_bundle_file',
 'expected_historical_ec339_public_integrity_bundle_sha256',
 'expected_outside_retained_ec396_role_roster_sha256',
 'expected_outside_retained_ec396_public_catalog_original_sha256',
 'expected_outside_retained_ec396_registry_public_hex',
 'expected_outside_retained_ec396_transparency_log_public_hex',
 'expected_outside_retained_ec396_first_registry_snapshot_sha256',
 'expected_outside_retained_ec396_first_device_attestation_sha256',
)
AUDIT_ONLY=('expected_retained_historical_ec339_public_integrity_inventory_sha256',)
NEW_REPEATS=(
 ('historical_ec339_public_registry_inventory_shas','--historical-ec339-public-registry-inventory-sha256'),
 ('historical_ec339_public_log_inventory_shas','--historical-ec339-public-log-inventory-sha256'),
 ('historical_ec339_device_readback_inventory_shas','--historical-ec339-device-readback-inventory-sha256'),
 ('minimum_historical_ec339_current_registry_roles','--minimum-historical-ec339-current-registry-role-count'),
 ('minimum_historical_ec339_merkle_inclusion_sets','--minimum-historical-ec339-merkle-inclusion-set-count'),
 ('minimum_historical_ec339_two_device_readbacks','--minimum-historical-ec339-two-device-readback-count'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
FLAGS=(
 'inherited_real_ec395_credential_gossip_or_archive_disputed',
 'outside_retained_public_history_or_inventory_floor_disagrees',
 'registry_signed_revocation_suspension_or_time_line_adverse',
 'signed_public_merkle_history_inclusion_consistency_or_prior_time_unproven',
 'independent_device_receipt_or_original_byte_readback_incomplete',
 'rfc3161_official_time_or_cross_epoch_predecessor_unbounded',
 'public_legal_registry_and_qualified_regulator_identity_not_proven',
 'prior_publication_and_physical_separate_worm_not_proven',
 'global_ocsp_forks_real_custody_and_final_product_acceptance_not_proven',
)
OUTCOMES=(
 'ec396_inherited_signed_external_credentials_or_custody_disputed',
 'ec396_outside_retained_public_history_sha_or_count_floors_disagree',
 'ec396_signed_registry_revocation_or_historical_status_adverse',
 'ec396_public_merkle_log_inclusion_prefix_or_timestamp_incomplete',
 'ec396_two_distinct_signed_device_readbacks_incomplete',
 'ec396_rfc3161_or_independently_signed_predecessor_freshness_unresolved',
 'ec396_official_public_registry_and_legal_authority_not_established',
 'ec396_actual_prior_publication_and_physical_worm_not_established',
 'ec396_global_external_history_and_final_acceptance_not_established',
)
NEGATIVES=(
 'caller_pinned_issuer_key_or_charter_proves_official_legal_accreditation',
 'furnished_registry_signature_proves_online_government_registry_or_complete_crl_ocsp',
 'furnished_signed_log_and_merkle_inclusion_prove_internet_prior_publication',
 'verified_rfc6962_consistency_proves_no_hidden_global_log_forks',
 'different_site_labels_and_key_bytes_prove_independent_legal_companies',
 'two_device_operator_signatures_prove_attested_physical_worm_or_airgap',
 'locally_recovered_copy_proves_physical_prior_retention_at_historical_time',
 'locally_pinned_tsa_original_proves_qualified_calibrated_public_utc',
 'machine_status_claims_alone_prove_vendor_device_or_immutable_storage',
 'receiver_used_network_online_registry_ocsp_provider_or_git_ci',
 'receiver_generated_signatures_keys_timestamps_or_worm_writes',
 'inherited_original_powerShell_or_full_ec317_ec318_prod_acceptance_proven',
 'final_quality_and_user_acceptance_promoted',
)
BUNDLE_FIELDS={'schema','claimed_directory_lineage_id','parent_ec395_credential_gossip_bundle_original',
               'outside_authority_roster_original','purported_public_catalog_original','epochs'}
ROSTER_FIELDS={'schema','claimed_directory_lineage_id','registry_signer','transparency_log_signer','device_operators'}
ROLE_FIELDS={'role_id','site_id','public_hex','public_key_original'}
EPOCH_FIELDS={'epoch_index','registry','log','devices'}
ORIGINAL_STAMP_FIELDS={'signed_original','rfc3161_token_original'}
REGISTRY_SIGNED_FIELDS={'schema','claim','signature_ed25519'}
REGISTRY_CLAIM_FIELDS={'schema','directory_lineage_id','parent_ec395_bundle_sha256',
 'parent_ec395_verified_inventory_sha256','public_catalog_original_sha256','epoch_index',
 'registry_sequence','previous_registry_snapshot_sha256','registry_signer_id',
 'subjects','claimed_snapshot_utc'}
SUBJECT_FIELDS={'role_id','public_hex','status','effective_utc'}
LOG_FIELDS={'signed_head_original','rfc3161_token_original','leaves','consistency_path_sha256'}
LOG_SIGNED_FIELDS={'schema','claim','signature_ed25519'}
LOG_CLAIM_FIELDS={'schema','directory_lineage_id','parent_ec395_bundle_sha256',
 'parent_ec395_verified_inventory_sha256','epoch_index','log_signer_id','log_sequence',
 'previous_signed_log_head_sha256','tree_size','merkle_root_sha256',
 'registry_snapshot_original_sha256','claimed_published_utc'}
LEAF_FIELDS={'kind','signed_original','index','path_sha256'}
LEAF_KINDS=('registry','gossip_confirm','archive_a','archive_b')
DEVICE_FIELDS={'operator_id','device_inventory_original','signed_attestation_original',
               'rfc3161_token_original','copies'}
COPY_FIELDS={'source_original','device_copy_original'}
WORM_SIGNED_FIELDS={'schema','claim','signature_ed25519'}
WORM_CLAIM_FIELDS={'schema','directory_lineage_id','parent_ec395_bundle_sha256',
 'parent_ec395_verified_inventory_sha256','epoch_index','device_operator_id',
 'device_site_id','device_serial_id','claimed_storage_mode','device_inventory_sha256',
 'public_log_head_original_sha256','previous_epoch_attestation_sha256',
 'original_to_device_copy_inventory_sha256','claimed_sealed_utc','claimed_retention_until_utc'}


def require(ok,code,status='invalid_input'):
    if ok is not True:raise errors.AnchorError('EC396_'+code,status)


def exact(x,fields,code):
    require(type(x) is dict and set(x)==fields,code+'_EXACT_FIELDS_REQUIRED')


def valid_sha(x):return parent._sha(x) and x!=ZERO


def digest(raw):return parent.digest(raw)


def cdigest(x):return parent.cdigest(x)


def rawref(x):
    exact(x,{'path','sha256'},'ORIGINAL_SOURCE_REFERENCE')
    require(valid_sha(x['sha256']),'NONZERO_PIN_REQUIRED')
    return x


def _inputs(opts,derive):
    required=set((*PARENT_SCALARS,*PARENT_REPEATS,*NEW_SCALARS,*REPEAT_NAMES))
    if not derive: required.update(AUDIT_ONLY)
    require(set(opts)==required,'COMPLETE_INHERITED_AND_NEW_INPUTS_REQUIRED')
    inherited={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    parent._audit_input(inherited,False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],'EC396_BUNDLE')
    for k in (NEW_SCALARS[2],NEW_SCALARS[3],NEW_SCALARS[6],NEW_SCALARS[7]):
        require(valid_sha(opts[k]),'INDEPENDENTLY_RETAINED_ORIGINAL_SHA_REQUIRED')
    for k in (NEW_SCALARS[4],NEW_SCALARS[5]):
        require(parent.prior._hexkey(opts[k]),'INDEPENDENTLY_RETAINED_PUBLIC_KEY_REQUIRED')
    require(opts[NEW_SCALARS[4]]!=opts[NEW_SCALARS[5]],'REGISTRY_AND_LOG_KEY_REUSED','permission_denied')
    if not derive:require(valid_sha(opts[AUDIT_ONLY[0]]),'INDEPENDENT_WHOLE_INVENTORY_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    require(1<=n<=3,'EPOCH_COUNT_OUTSIDE_BOUND')
    for k in REPEAT_NAMES:
        vals=opts[k]
        require(type(vals) is list and len(vals)==n,'ONE_OUTSIDE_FLOOR_PER_EPOCH_REQUIRED')
        if k.startswith('minimum_'):
            upper=4 if 'registry_roles' in k else 1 if 'inclusion_sets' in k else 2
            require(all(type(x) is int and 0<=x<=upper for x in vals),'OUTSIDE_MINIMUM_OUT_OF_RANGE')
        else:require(all(valid_sha(x) for x in vals),'EPOCH_OUTSIDE_SHA_REQUIRED')
    return inherited


def _parent_report(report,opts):
    fields={'schema','command','status','exit_code','offline_unresolved_exit_code',
     'verified_live_ec394_report_sha256','verified_live_ec394_inventory_sha256',
     'original_credential_gossip_archive_sha256',
     'receiver_verified_credential_gossip_archive_inventory_sha256',
     'original_independently_signed_credential_count',
     'cryptographically_bounded_reciprocal_gossip_count',
     'cryptographically_bounded_two_site_archive_replica_count',
     'genuine_signed_reciprocal_gossip_disclosure_conflict_count',
     'inherited_genuinely_operator_signed_log_fork_count',
     'credential_gossip_archive_epoch_reviews','visible_genuinely_signed_reciprocal_witness_view_conflicts',
     'local_credential_gossip_and_readback_consistency',
     'sender_origin_path_required_or_read',
     'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
     *parent.FLAGS,*parent.NEGATIVES}
    require(type(report) is dict and set(report)==fields and
      report.get('schema')==parent.RESULT_SCHEMA and
      report.get('command')=='audit-historical-ec339-credential-gossip-archive' and
      report.get('status')==next((parent.OUTCOMES[i] for i,k in enumerate(parent.FLAGS)
          if report[k]),parent.OUTCOMES[-1])+'_unresolved' and
      report.get('exit_code')==2 and report.get('offline_unresolved_exit_code')==2 and
      report.get('sender_origin_path_required_or_read') is False and
      report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
      all(report.get(k) is False for k in parent.NEGATIVES) and
      all(type(report.get(k)) is bool for k in parent.FLAGS) and
      all(report[k] is True for k in parent.FLAGS[-3:]) and
      report.get('local_credential_gossip_and_readback_consistency') is (
         not any(report[k] for k in parent.FLAGS[:7])) and
      report.get('original_credential_gossip_archive_sha256')==opts[parent.NEW_SCALARS[1]] and
      report.get('receiver_verified_credential_gossip_archive_inventory_sha256')==opts[parent.AUDIT_ONLY[0]] and
      all(valid_sha(report.get(k)) for k in ('verified_live_ec394_report_sha256',
           'verified_live_ec394_inventory_sha256')),
      'REAL_EC395_PARENT_AUDIT_OR_OUTSIDE_SHA_NOT_VERIFIED','unavailable')
    epochs=report['credential_gossip_archive_epoch_reviews'];n=len(opts['historical_directory_root_shas'])
    require(type(epochs) is list and len(epochs)==n and all(
       type(e) is dict and set(e)=={
        'epoch_index','cryptographically_bounded_reciprocal_gossip_count',
        'verified_two_source_original_recovery_count',
        'genuine_parent_observation_originals_readback','required_archived_unique_original_count',
        'reciprocal_signed_gossip_inventory_sha256','offsite_signed_recovery_inventory_sha256',
        'signed_disclosed_gossip_divergences'} and type(e['epoch_index']) is int and
       e['epoch_index']==i and
       type(e['cryptographically_bounded_reciprocal_gossip_count']) is int and
       0<=e['cryptographically_bounded_reciprocal_gossip_count']<=1 and
       type(e['verified_two_source_original_recovery_count']) is int and
       0<=e['verified_two_source_original_recovery_count']<=2 and
       type(e['signed_disclosed_gossip_divergences']) is int and
       0<=e['signed_disclosed_gossip_divergences']<=3 and
       type(e['genuine_parent_observation_originals_readback']) is int and
       0<=e['genuine_parent_observation_originals_readback']<=4 and
       type(e['required_archived_unique_original_count']) is int and
       1<=e['required_archived_unique_original_count']<=36 and
       all(valid_sha(e[k]) for k in ('reciprocal_signed_gossip_inventory_sha256',
                                      'offsite_signed_recovery_inventory_sha256'))
       for i,e in enumerate(epochs)) and
       type(report['visible_genuinely_signed_reciprocal_witness_view_conflicts']) is list and
       len(report['visible_genuinely_signed_reciprocal_witness_view_conflicts'])<=3*n and
       type(report['original_independently_signed_credential_count']) is int and
       0<=report['original_independently_signed_credential_count']<=2 and
       type(report['inherited_genuinely_operator_signed_log_fork_count']) is int and
       0<=report['inherited_genuinely_operator_signed_log_fork_count']<=2*n and
       report['cryptographically_bounded_reciprocal_gossip_count']==sum(
         e['cryptographically_bounded_reciprocal_gossip_count'] for e in epochs) and
       report['cryptographically_bounded_two_site_archive_replica_count']==sum(
         e['verified_two_source_original_recovery_count'] for e in epochs) and
       report['genuine_signed_reciprocal_gossip_disclosure_conflict_count']==sum(
         e['signed_disclosed_gossip_divergences'] for e in epochs),
       'REAL_EC395_REPORT_HISTORY_AND_COUNTS_INVALID','unavailable')
    return cdigest(report)


def _signed(ref,read,schema,claim_schema,claim_fields,role):
    original=rawref(ref)
    raw=read(original,'ec396_signed_'+role,MAX_SIGNED)
    signed=tr.strict_json(raw,'EC396_'+role)
    exact(signed,{'schema','claim','signature_ed25519'},role)
    claim=signed['claim'];exact(claim,claim_fields,role+'_CLAIM')
    require(signed['schema']==schema and claim['schema']==claim_schema,
            role+'_SCHEMA_DISAGREES','permission_denied')
    return raw,claim,signed['signature_ed25519']


def _signed_verify(role,sig,domain,claim,where):
    parent._signer(role['public_hex'],sig,domain,claim,'EC396_'+where)


def _stamp(raw,ref,trust,aid,read,evaluation,cutoff,claimed,flags):
    dummy={k:False for k in parent.FLAGS}
    if ref is None:
        flags[FLAGS[5]]=True;return None
    stamp=parent._stamp(raw,rawref(ref),trust,aid,read,evaluation,cutoff,claimed,dummy)
    if dummy[parent.FLAGS[6]]:flags[FLAGS[5]]=True
    return stamp


def _bounded(stamp,claimed,cutoff):return parent._bounded(stamp,claimed,cutoff)


def _roster(doc,ref,opts,lineage,anchor,ec395_roster,read):
    exact(doc,ROSTER_FIELDS,'INDEPENDENT_PUBLIC_AUTHORITY_ROSTER')
    require(doc['schema']==ROSTER_SCHEMA and doc['claimed_directory_lineage_id']==lineage and
       ref['sha256']==opts[NEW_SCALARS[2]],'PUBLIC_AUTHORITY_ROSTER_PIN_INVALID','permission_denied')
    require(type(doc['device_operators']) is list and len(doc['device_operators'])==2,
            'TWO_DEVICE_OPERATORS_REQUIRED')
    existing_keys=set(anchor['known_keys']);existing_sites=set(anchor['known_sites']);existing_ids=set(anchor['known_ids'])
    existing_paths={x['public_key_original']['path'] for group in ('credential_issuers','offsite_archivists')
                    for x in ec395_roster[group]}
    for group in ('credential_issuers','offsite_archivists'):
        for role in ec395_roster[group]:
            existing_keys.add(role['public_hex']);existing_sites.add(role['site_id']);existing_ids.add(role['role_id'])
    roles={};paths=set(existing_paths)
    for role in (doc['registry_signer'],doc['transparency_log_signer'],*doc['device_operators']):
        exact(role,ROLE_FIELDS,'PUBLIC_REGISTRY_LOG_DEVICE_ROLE')
        require(parent._id(role['role_id']) and role['role_id'] not in existing_ids and
                parent._id(role['site_id']) and role['site_id'] not in existing_sites and
                parent.prior._hexkey(role['public_hex']) and role['public_hex'] not in existing_keys,
                'INDEPENDENT_SIGNER_KEYS_SITES_ROLE_IDS_REQUIRED','permission_denied')
        rr=rawref(role['public_key_original'])
        require(rr['path'] not in paths,'PUBLIC_AUTHORITY_KEY_PATH_ALIAS','permission_denied')
        key=read(rr,'original_unreused_ec396_public_key',32)
        require(len(key)==32 and key.hex()==role['public_hex'],
                'RAW_PUBLIC_SIGNER_KEY_SOURCE_CHANGED','permission_denied')
        for set_,value in ((existing_keys,role['public_hex']),
                           (existing_sites,role['site_id']),
                           (existing_ids,role['role_id'])):set_.add(value)
        paths.add(rr['path']);roles[role['role_id']]=role
    require(doc['registry_signer']['public_hex']==opts[NEW_SCALARS[4]] and
            doc['transparency_log_signer']['public_hex']==opts[NEW_SCALARS[5]],
            'REGISTRY_AND_TRANSPARENCY_OUTSIDE_PUBLIC_KEY_PINS_DISAGREE',
            'permission_denied')
    return roles,paths


def _subjects(parent_roster):
    return sorted(({'role_id':r['role_id'],'public_hex':r['public_hex']}
            for group in ('credential_issuers','offsite_archivists')
            for r in parent_roster[group]),key=lambda r:r['role_id'])


def _registry(item,epoch,role,subjects,prev_ref,prev_stamp,parentref,parent_sha,catalogref,
              lineage,read,trust,aid,evaluation,cutoff,flags,history):
    exact(item,ORIGINAL_STAMP_FIELDS,'REGISTRY_SNAPSHOT_EPOCH')
    ref=item['signed_original']
    if ref is None:
        require(item['rfc3161_token_original'] is None,'ABSENT_REGISTRY_CANNOT_HAVE_TOKEN')
        flags[FLAGS[2]]=True;return {'signed_original_sha256':None,
           'timestamp_sha256':None,'current_verified_roles':0,
           'signed_revoked_or_suspended_roles':[],'pre_cutoff':False,'_gen':None}
    raw,claim,sig=_signed(ref,read,REGISTRY_SCHEMA,REGISTRY_CLAIM,
                             REGISTRY_CLAIM_FIELDS,'SIGNED_REGISTRY_SNAPSHOT')
    require(claim['directory_lineage_id']==lineage and
            claim['parent_ec395_bundle_sha256']==parentref['sha256'] and
            claim['parent_ec395_verified_inventory_sha256']==parent_sha and
            claim['public_catalog_original_sha256']==catalogref['sha256'] and
            type(claim['epoch_index']) is int and claim['epoch_index']==epoch and
            type(claim['registry_sequence']) is int and claim['registry_sequence']==epoch+1 and
            claim['previous_registry_snapshot_sha256']==prev_ref and
            claim['registry_signer_id']==role['role_id'],
            'SIGNED_REGISTRY_SNAPSHOT_SOURCE_OR_CHAIN_INVALID','permission_denied')
    entries=claim['subjects'];require(type(entries) is list and len(entries)==4,
                 'EXACTLY_FOUR_REGISTERED_ROLES_REQUIRED','permission_denied')
    status=[];current=0;adverse=[];latest_effect=None
    require(all(type(e) is dict and set(e)==SUBJECT_FIELDS for e in entries),
            'REGISTRY_SUBJECT_FIELDS_REQUIRED')
    require([{'role_id':e['role_id'],'public_hex':e['public_hex']} for e in entries]==subjects,
            'REGISTRY_MUST_INCLUDE_EXACT_FOUR_REAL_EC395_KEYS','permission_denied')
    for e in entries:
        require(e['status'] in ('active','revoked','suspended'),
                'REGISTRY_STATUS_INVALID')
        t=parent._time(e['effective_utc'])
        past=history.get(e['role_id'])
        if past:
            if t<past[1] or (past[0]=='revoked' and e['status']!='revoked') or (
                     e['status']!='revoked' and past[0]=='suspended' and e['status']=='active'
                     and t==past[1]):
                flags[FLAGS[2]]=True
        if t>cutoff:flags[FLAGS[2]]=True
        history[e['role_id']]=(e['status'],t)
        if e['status']=='active':current+=1
        else: adverse.append({'role_id':e['role_id'],'status':e['status']})
        latest_effect=t if latest_effect is None else max(latest_effect,t)
    _signed_verify(role,sig,REGISTRY_DOMAIN,claim,'REGISTRY_SNAPSHOT')
    claimed=parent._time(claim['claimed_snapshot_utc'])
    stamp=_stamp(raw,item['rfc3161_token_original'],trust,aid,read,evaluation,cutoff,claimed,flags)
    chain_time=prev_stamp is None or (stamp is not None and stamp['gen']>=prev_stamp)
    good=bool(_bounded(stamp,claimed,cutoff) and chain_time and
              latest_effect is not None and latest_effect<=claimed and
              latest_effect<=stamp['gen'] and (epoch==0 or prev_stamp is not None))
    if not good:flags[FLAGS[5]]=True
    if adverse:flags[FLAGS[2]]=True
    return {'signed_original_sha256':rawref(ref)['sha256'],
          'timestamp_sha256':stamp['sha256'] if stamp else None,
          'current_verified_roles':current if good and not adverse and not flags[FLAGS[2]] else 0,
          'signed_revoked_or_suspended_roles':adverse,'pre_cutoff':good,
          '_gen':stamp['gen'] if stamp else None}


def _expected_log_sources(parentbundle,epoch,registryref):
    ep=parentbundle['epochs'][epoch]
    gossip=ep['gossip'];archives=ep['archives']
    require(type(archives) is list and len(archives)==2,
            'REAL_EC395_TWO_ARCHIVE_SOURCE_ROWS_MISSING','unavailable')
    out={'registry':registryref,
         'gossip_confirm':gossip['confirm']['signed_original']}
    out['archive_a']=archives[0]['signed_receipt_original']
    out['archive_b']=archives[1]['signed_receipt_original']
    return out


def _inclusions(leaves,expected,read,root,size,flags):
    require(type(leaves) is list and len(leaves)<=4,'FOUR_PUBLICATION_LEAF_PROOFS_MAX')
    seen=set();positions=set();rows=[]
    for leaf in leaves:
        exact(leaf,LEAF_FIELDS,'PUBLICATION_INCLUSION')
        kind=leaf['kind']
        require(kind in LEAF_KINDS and kind not in seen,'PUBLIC_LEAF_KIND_DUPLICATE_OR_UNKNOWN')
        seen.add(kind)
        ref=rawref(leaf['signed_original'])
        require(expected[kind] is not None and ref==expected[kind],
                'PUBLIC_PROOF_MUST_OPEN_ACTUAL_PARENT_SIGNED_ORIGINAL','permission_denied')
        index=leaf['index'];proof=leaf['path_sha256']
        require(type(index) is int and 0<=index<size and index not in positions,
                'PUBLIC_LEAF_INDEX_INVALID_OR_REUSED')
        positions.add(index)
        require(type(proof) is list and len(proof)<=32 and all(valid_sha(x) for x in proof),
                'PUBLIC_MERKLE_PROOF_PATH_FORMAT_INVALID')
        raw=read(ref,'true_signed_ec395_or_public_registry_leaf_original',MAX_SIGNED)
        valid=tr.verify_inclusion(tr.leaf_hash(raw),index,size,bytes.fromhex(root),
                                  [bytes.fromhex(x) for x in proof])
        if not valid:flags[FLAGS[3]]=True
        rows.append({'kind':kind,'original_sha256':ref['sha256'],
                     'leaf_index':index,'verified_rfc6962_inclusion':valid})
    complete=bool(len(rows)==4 and all(x['verified_rfc6962_inclusion'] for x in rows))
    if not complete:flags[FLAGS[3]]=True
    return sorted(rows,key=lambda x:LEAF_KINDS.index(x['kind'])),complete


def _log(item,epoch,role,registryref,old_head,old_size,old_root,old_gen,
         parentref,parent_sha,lineage,expected,read,trust,aid,evaluation,cutoff,flags):
    exact(item,LOG_FIELDS,'PUBLIC_SIGNED_LOG_EPOCH')
    ref=item['signed_head_original']
    if ref is None:
        require(item['rfc3161_token_original'] is None and item['leaves']==[] and
                item['consistency_path_sha256']==[],'ABSENT_LOG_CANNOT_HAVE_PROOFS')
        flags[FLAGS[3]]=True
        return {'signed_head_sha256':None,'timestamp_sha256':None,'merkle_size':0,
           'included_true_originals':0,'prefix_consistent':False,'complete':False,'_gen':None,
           '_size':None,'_root':None}
    raw,claim,sig=_signed(ref,read,LOG_SCHEMA,LOG_CLAIM,LOG_CLAIM_FIELDS,'PUBLIC_SIGNED_LOG_HEAD')
    require(claim['directory_lineage_id']==lineage and
      claim['parent_ec395_bundle_sha256']==parentref['sha256'] and
      claim['parent_ec395_verified_inventory_sha256']==parent_sha and
      type(claim['epoch_index']) is int and claim['epoch_index']==epoch and
      claim['log_signer_id']==role['role_id'] and
      type(claim['log_sequence']) is int and claim['log_sequence']==epoch+1 and
      claim['previous_signed_log_head_sha256']==old_head and
      claim['registry_snapshot_original_sha256']==(
          registryref['sha256'] if registryref is not None else None),
      'PUBLIC_SIGNED_LOG_CHAIN_AND_PARENT_BINDING_INVALID','permission_denied')
    size=claim['tree_size'];root=claim['merkle_root_sha256']
    require(type(size) is int and 4<=size<=tr.MAX_LOG_LEAVES and valid_sha(root),
            'PUBLIC_LOG_SIGNED_TREE_SIZE_OR_ROOT_INVALID')
    _signed_verify(role,sig,LOG_DOMAIN,claim,'PUBLIC_TRANSPARENCY_HEAD')
    claimed=parent._time(claim['claimed_published_utc'])
    stamp=_stamp(raw,item['rfc3161_token_original'],trust,aid,read,evaluation,cutoff,claimed,flags)
    consistency=item['consistency_path_sha256']
    require(type(consistency) is list and len(consistency)<=32 and
            all(valid_sha(x) for x in consistency),'SIGNED_LOG_CONSISTENCY_PROOF_FORMAT_INVALID')
    if epoch==0:
        prefix_ok=(consistency==[])
    elif old_size is not None:
        prefix_ok=tr.verify_consistency(old_size,size,bytes.fromhex(old_root),
               bytes.fromhex(root),[bytes.fromhex(x) for x in consistency])
    else:prefix_ok=False
    if not prefix_ok:flags[FLAGS[3]]=True
    rows,complete=_inclusions(item['leaves'],expected,read,root,size,flags)
    bounded=bool(_bounded(stamp,claimed,cutoff) and (old_gen is None or stamp['gen']>=old_gen)
       and (epoch==0 or old_gen is not None) and prefix_ok and complete)
    if not bounded:flags[FLAGS[3]]=True
    return {'signed_head_sha256':rawref(ref)['sha256'],
       'timestamp_sha256':stamp['sha256'] if stamp else None,'merkle_size':size,
       'included_true_originals':len([r for r in rows if r['verified_rfc6962_inclusion']]),
       'prefix_consistent':prefix_ok,'complete':bounded,'_gen':stamp['gen'] if stamp else None,
       '_size':size,'_root':root,'_rows':rows}


def _copies(entry,expected,read,forbidden,all_copy_paths):
    require(type(entry) is list and len(entry)<=2,'TWO_SOURCE_RECOVERY_MAX')
    seen=set();rows=[]
    for pair in entry:
        exact(pair,COPY_FIELDS,'DEVICE_RECOVERED_COPY')
        src=rawref(pair['source_original']);copy=rawref(pair['device_copy_original'])
        require(src in expected,'DEVICE_SOURCE_MUST_BE_REAL_EC395_SIGNED_RECEIPT',
                'permission_denied')
        require(src['path'] not in seen,'DEVICE_SOURCE_REPEATED')
        seen.add(src['path'])
        require(copy['path'] not in forbidden and copy['path'] not in all_copy_paths and
                copy['path']!=src['path'] and copy['sha256']==src['sha256'],
                'DEVICE_COPY_PATH_ALIAS_OR_SHA_MISMATCH','permission_denied')
        original=read(src,'authentic_ec395_offsite_signed_receipt',MAX_SIGNED)
        raw=read(copy,'independently_recovered_device_copy',MAX_SIGNED)
        require(original==raw,'DEVICE_READBACK_BYTES_DIFFER_FROM_ORIGINAL','permission_denied')
        all_copy_paths.add(copy['path'])
        rows.append({'source_original_sha256':src['sha256'],
                     'device_copy_original_sha256':copy['sha256'],
                     'source_path':src['path'],'copy_path':copy['path']})
    return sorted(rows,key=lambda r:r['source_path']),len(seen)==2


def _device(entry,epoch,role,expected,parentref,parent_sha,logref,log_gen,
            previous,previous_gen,continuous,read,trust,aid,evaluation,cutoff,flags,
            forbidden,used_copies,lineage):
    exact(entry,DEVICE_FIELDS,'SIGNED_DEVICE_ATTESTATION_GROUP')
    require(entry['operator_id']==role['role_id'],
            'SIGNED_DEVICE_OPERATOR_ID_NOT_IN_ROSTER','permission_denied')
    inv=rawref(entry['device_inventory_original'])
    require(inv['path'] in forbidden,'DEVICE_INVENTORY_NOT_PREDECLARED',
            'permission_denied')
    read(inv,'opaque_physical_worm_claimed_device_inventory',MAX_DEVICE)
    rows,complete=_copies(entry['copies'],expected,read,forbidden,used_copies)
    d=cdigest(rows)
    original=entry['signed_attestation_original']
    if original is None:
        require(entry['rfc3161_token_original'] is None and rows==[],
                'ABSENT_SIGNED_DEVICE_RECEIPT_HAS_TOKEN_OR_COPIES')
        flags[FLAGS[4]]=True
        return {'operator_id':role['role_id'],'signed_attestation_sha256':None,
                'timestamp_sha256':None,'verified_two_receipt_copies':0,'device_serial_id':None,
                'pre_cutoff_device_readback':False,'copy_inventory_sha256':d,'_gen':None}
    raw,claim,sig=_signed(original,read,WORM_SCHEMA,WORM_CLAIM,WORM_CLAIM_FIELDS,'DEVICE_SIGNED_ATTESTATION')
    require(claim['directory_lineage_id']==lineage and
       claim['parent_ec395_bundle_sha256']==parentref['sha256'] and
       claim['parent_ec395_verified_inventory_sha256']==parent_sha and
       type(claim['epoch_index']) is int and claim['epoch_index']==epoch and
       claim['device_operator_id']==role['role_id'] and
       claim['device_site_id']==role['site_id'] and
       parent._id(claim['device_serial_id']) and
       claim['claimed_storage_mode']=='worm_append_only_claimed' and
       claim['device_inventory_sha256']==inv['sha256'] and
       claim['public_log_head_original_sha256']==(
              logref['sha256'] if logref is not None else None) and
       claim['previous_epoch_attestation_sha256']==previous and
       claim['original_to_device_copy_inventory_sha256']==d,
       'SIGNED_DEVICE_WORM_CLAIM_SOURCE_OR_PREDECESSOR_INVALID','permission_denied')
    _signed_verify(role,sig,WORM_DOMAIN,claim,'DEVICE_CUSTODY')
    sealed=parent._time(claim['claimed_sealed_utc'])
    retained=parent._time(claim['claimed_retention_until_utc'])
    stamp=_stamp(raw,entry['rfc3161_token_original'],trust,aid,read,evaluation,cutoff,sealed,flags)
    bounded=bool(complete and continuous and _bounded(stamp,sealed,cutoff) and
       retained>cutoff and retained>sealed and
       log_gen is not None and sealed>=log_gen and stamp['gen']>=log_gen and
       (previous_gen is None or stamp['gen']>=previous_gen) and
       (epoch==0 or previous!=ZERO))
    if not bounded:flags[FLAGS[4]]=True
    return {'operator_id':role['role_id'],
       'signed_attestation_sha256':rawref(original)['sha256'],
       'timestamp_sha256':stamp['sha256'] if stamp else None,
       'verified_two_receipt_copies':len(rows),'device_serial_id':claim['device_serial_id'],
       'pre_cutoff_device_readback':bounded,'copy_inventory_sha256':d,
       '_gen':stamp['gen'] if stamp else None}


def _engine(derive,**opts):
    inherited=_inputs(opts,derive)
    # *Actual* historic re-verification, never consume a caller-provided PASS.
    actual=parent.audit(**inherited)
    live_parent_sha=_parent_report(actual,opts)
    evaluation=parent._time(opts['ec391_tsa_evaluation_utc'])
    cutoff=parent._time(opts[parent.prior.parent.NEW_SCALARS[5]])
    lineage=opts['claimed_historical_directory_lineage_id']
    read,doc,late=parent.prior._readers()
    rootref={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    bundle=doc(rootref,'original_ec396_public_integrity_bundle',MAX_BUNDLE)
    exact(bundle,BUNDLE_FIELDS,'REGISTRY_PUBLIC_LOG_WORM_BUNDLE')
    parentref={'path':opts[parent.NEW_SCALARS[0]],'sha256':opts[parent.NEW_SCALARS[1]]}
    require(bundle['schema']==BUNDLE_SCHEMA and
        bundle['claimed_directory_lineage_id']==lineage and
        bundle['parent_ec395_credential_gossip_bundle_original']==parentref and
        type(bundle['epochs']) is list and len(bundle['epochs'])==len(opts['historical_directory_root_shas']),
        'ORIGINAL_PUBLIC_EVIDENCE_PARENT_OR_LINEAGE_INVALID','permission_denied')
    parentbundle=doc(parentref,'actual_ec395_original_credential_and_archive_bundle',parent.MAX_BUNDLE)
    exact(parentbundle,parent.BUNDLE_FIELDS,'ORIGINAL_PARENT_EC395_BUNDLE')
    require(parentbundle['schema']==parent.BUNDLE_SCHEMA and
            parentbundle['claimed_directory_lineage_id']==lineage,
            'ACTUAL_EC395_BUNDLE_LINEAGE_INVALID','permission_denied')
    anchor=parent._actual_parent_source(parentbundle,opts,read,doc)
    role_ref=rawref(parentbundle['external_role_roster_original'])
    ec395_roster=doc(role_ref,'authentic_ec395_two_issuer_two_archivist_roster',parent.MAX_ROSTER)
    exact(ec395_roster,parent.ROSTER_FIELDS,'ORIGINAL_EC395_CREDENTIAL_ROLE_ROSTER')
    # The parent audit genuinely verified these signatures, and we reopen raw keys.
    parent._roster(ec395_roster,role_ref,opts,lineage,read,
       anchor['known_keys'],anchor['known_sites'],anchor['known_ids'])
    rosterref=rawref(bundle['outside_authority_roster_original'])
    rost=doc(rosterref,'original_public_registry_log_device_operators',MAX_ROSTER)
    roles,keypaths=_roster(rost,rosterref,opts,lineage,anchor,ec395_roster,read)
    catref=rawref(bundle['purported_public_catalog_original'])
    require(catref['sha256']==opts[NEW_SCALARS[3]],
            'PURPORTED_PUBLIC_CATALOG_EXTERNAL_SHA_DISAGREES','permission_denied')
    read(catref,'purported_authoritative_public_catalog_not_proof_of_official_status',MAX_CATALOG)
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=bool(not actual['local_credential_gossip_and_readback_consistency'] or
       actual['genuine_signed_reciprocal_gossip_disclosure_conflict_count'] or
       actual['inherited_genuinely_operator_signed_log_fork_count'])
    forbidden={rootref['path'],parentref['path'],rosterref['path'],role_ref['path'],catref['path']}
    forbidden.update(keypaths)
    # Reject copies colliding with any historical EC395 source, registry/log or receipt.
    def collect(x):
        if type(x) is dict:
            if set(x)=={'path','sha256'} and type(x['path']) is str:
                forbidden.add(x['path'])
            else:
                for v in x.values():collect(v)
        elif type(x) is list:
            for v in x:collect(v)
    collect(parentbundle)
    # Predeclare *all* signed originals and device identities before reading a
    # single copy: a later epoch's original may never alias an earlier copy.
    # Do not include device copies in this protected source collection.
    for ep in bundle['epochs']:
        exact(ep,EPOCH_FIELDS,'PUBLIC_EVIDENCE_EPOCH_PREFLIGHT')
        exact(ep['registry'],ORIGINAL_STAMP_FIELDS,'REGISTRY_ORIGINAL_PREFLIGHT')
        exact(ep['log'],LOG_FIELDS,'MERKLE_ORIGINAL_PREFLIGHT')
        for k in ORIGINAL_STAMP_FIELDS:collect(ep['registry'][k])
        for k in ('signed_head_original','rfc3161_token_original'):collect(ep['log'][k])
        require(type(ep['devices']) is list and len(ep['devices'])==2,
                'TWO_DEVICE_GROUPS_REQUIRED')
        for d in ep['devices']:
            exact(d,DEVICE_FIELDS,'DEVICE_GROUP_PREFLIGHT')
            for k in ('signed_attestation_original','rfc3161_token_original'):
                collect(d[k])
    inventory_paths=set()
    for ep in bundle['epochs']:
        for d in ep['devices']:
            inventory=rawref(d['device_inventory_original'])
            require(inventory['path'] not in forbidden and
                    inventory['path'] not in inventory_paths,
                    'DEVICE_INVENTORY_ALIASES_SIGNED_SOURCE_OR_ANOTHER_DEVICE',
                    'permission_denied')
            inventory_paths.add(inventory['path'])
    forbidden.update(inventory_paths)
    subjects=_subjects(ec395_roster)
    prev_registry=ZERO;prev_registry_gen=None;old_head=ZERO;old_size=None;old_root=None;old_log_gen=None
    prev_devices={x['role_id']:ZERO for x in rost['device_operators']}
    prev_generations={x['role_id']:None for x in rost['device_operators']}
    prev_continuity={x['role_id']:True for x in rost['device_operators']}
    registry_states={};used_copy_paths=set();reviews=[];inventory_epochs=[]
    first_registry=None;first_device=None
    registry_count=0;logs_count=0;device_count=0;all_revocations=[]
    for i,ep in enumerate(bundle['epochs']):
        exact(ep,EPOCH_FIELDS,'PUBLIC_EVIDENCE_EPOCH')
        require(type(ep['epoch_index']) is int and ep['epoch_index']==i,
                'PUBLIC_EPOCH_INDEX_NOT_CONTIGUOUS','permission_denied')
        registryref=ep['registry']['signed_original'] if type(ep['registry']) is dict else None
        role=rost['registry_signer']
        registry=_registry(ep['registry'],i,role,subjects,prev_registry,prev_registry_gen,
                parentref,actual['receiver_verified_credential_gossip_archive_inventory_sha256'],
                catref,lineage,read,anchor['trust'],anchor['authority'],evaluation,cutoff,
                flags,registry_states)
        if i==0:first_registry=registry['signed_original_sha256']
        prev_registry=registry['signed_original_sha256'] or ZERO
        prev_registry_gen=registry.pop('_gen')
        all_revocations.extend({'epoch_index':i,**r} for r in registry['signed_revoked_or_suspended_roles'])
        expected=_expected_log_sources(parentbundle,i,registryref)
        log=_log(ep['log'],i,rost['transparency_log_signer'],registryref,
          old_head,old_size,old_root,old_log_gen,parentref,
          actual['receiver_verified_credential_gossip_archive_inventory_sha256'],lineage,
          expected,read,anchor['trust'],anchor['authority'],evaluation,cutoff,flags)
        old_head=log['signed_head_sha256'] or ZERO
        old_size=log.pop('_size');old_root=log.pop('_root');old_log_gen=log.pop('_gen')
        leafrows=log.pop('_rows',[])
        logref=ep['log']['signed_head_original']
        expected_receipts=[r for r in (
            parentbundle['epochs'][i]['archives'][0]['signed_receipt_original'],
            parentbundle['epochs'][i]['archives'][1]['signed_receipt_original']) if r is not None]
        require(type(ep['devices']) is list and len(ep['devices'])==2,
                'EXACTLY_TWO_DEVICE_ATTESTATIONS_REQUIRED')
        devices=[];seen=set()
        for d in ep['devices']:
            require(type(d) is dict and 'operator_id' in d,
                    'DEVICE_OPERATOR_ID_MISSING')
            ident=d['operator_id']
            require(ident in prev_devices and ident not in seen,
                    'TWO_DISTINCT_RECORDED_DEVICE_OPERATORS_REQUIRED','permission_denied')
            seen.add(ident)
            result=_device(d,i,roles[ident],expected_receipts,parentref,
             actual['receiver_verified_credential_gossip_archive_inventory_sha256'],
             logref,old_log_gen,prev_devices[ident],prev_generations[ident],
             prev_continuity[ident],read,anchor['trust'],anchor['authority'],evaluation,
             cutoff,flags,forbidden,used_copy_paths,lineage)
            prev_continuity[ident]=result['pre_cutoff_device_readback']
            prev_devices[ident]=result['signed_attestation_sha256'] or ZERO
            prev_generations[ident]=result.pop('_gen')
            devices.append(result)
        require(seen==set(prev_devices),'BOTH_DISTINCT_DEVICE_OPERATORS_MISSING','permission_denied')
        serials=[x['device_serial_id'] for x in devices if x['device_serial_id'] is not None]
        require(len(serials)==len(set(serials)),
                'DEVICE_SERIAL_REUSED_BY_TWO_OPERATORS','permission_denied')
        if i==0:
            firstid=rost['device_operators'][0]['role_id']
            first_device=next(x['signed_attestation_sha256'] for x in devices
                              if x['operator_id']==firstid)
        registry_public_count=registry['current_verified_roles'] if not flags[FLAGS[0]] else 0
        log_public_count=int(bool(log['complete'] and registry['pre_cutoff'] and
             not flags[FLAGS[0]] and not flags[FLAGS[2]]))
        device_public_count=sum(int(x['pre_cutoff_device_readback']) for x in devices)
        if not (log_public_count and registry_public_count==4):device_public_count=0
        rrows={'snapshot':{k:v for k,v in registry.items() if k!='signed_revoked_or_suspended_roles'},
               'signed_adverse_statuses':registry['signed_revoked_or_suspended_roles']}
        lrows={'head':log,'included_signed_originals':leafrows}
        drows=sorted(devices,key=lambda d:d['operator_id'])
        rd=cdigest(rrows);ld=cdigest(lrows);dd=cdigest(drows)
        if (rd!=opts[NEW_REPEATS[0][0]][i] or ld!=opts[NEW_REPEATS[1][0]][i] or
            dd!=opts[NEW_REPEATS[2][0]][i] or
            registry_public_count<opts[NEW_REPEATS[3][0]][i] or
            log_public_count<opts[NEW_REPEATS[4][0]][i] or
            device_public_count<opts[NEW_REPEATS[5][0]][i]):flags[FLAGS[1]]=True
        registry_count+=registry_public_count;logs_count+=log_public_count;device_count+=device_public_count
        reviews.append({'epoch_index':i,'current_offline_signed_registry_roles':registry_public_count,
            'verified_rfc6962_original_inclusion_sets':log_public_count,
            'verified_device_signed_original_receipt_readbacks':device_public_count,
            'registry_inventory_sha256':rd,'log_inclusion_inventory_sha256':ld,
            'device_recovery_inventory_sha256':dd,
            'signed_revoked_or_suspended_roles':len(registry['signed_revoked_or_suspended_roles'])})
        inventory_epochs.append({'epoch_index':i,'registry':rrows,'log':lrows,'devices':drows})
    if first_registry!=opts[NEW_SCALARS[6]] or first_device!=opts[NEW_SCALARS[7]]:
        flags[FLAGS[1]]=True
    inventory={'schema':INVENTORY_SCHEMA,'directory_lineage_id':lineage,
       'actual_verified_ec395_live_report_sha256':live_parent_sha,
       'actual_parent_ec395_bundle_original_sha256':parentref['sha256'],
       'actual_parent_ec395_inventory_sha256':actual['receiver_verified_credential_gossip_archive_inventory_sha256'],
       'outside_retained_public_signer_roster_sha256':rosterref['sha256'],
       'outside_retained_purported_public_catalog_sha256':catref['sha256'],
       'outside_retained_first_signed_registry_sha256':opts[NEW_SCALARS[6]],
       'outside_retained_first_signed_device_sha256':opts[NEW_SCALARS[7]],
       'epochs':inventory_epochs,'signed_revocation_or_suspension_observations':all_revocations}
    inventory_sha=cdigest(inventory)
    if not derive and inventory_sha!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    # Last read of every original and recovered bytes that we used. This is
    # not OS-level atomic snapshot isolation or a proof of prior physical WORM.
    for path,(sha,cap) in late.items():
        latest=io._read({'path':path,'sha256':sha},
                         'ec396_final_bounded_source_readback',cap,{},{},set())
        require(digest(latest)==sha,'VERIFIED_ORIGINAL_CHANGED_DURING_AUDIT',
                'permission_denied')
    for k in FLAGS[-3:]:flags[k]=True
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
      'command':('derive-historical-ec339-public-integrity-inventory' if derive else
                 'audit-historical-ec339-public-integrity'),
      'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),OUTCOMES[-1])+'_unresolved',
      'exit_code':2,'offline_unresolved_exit_code':2,
      'verified_live_ec395_report_sha256':live_parent_sha,
      'verified_live_ec395_inventory_sha256':actual['receiver_verified_credential_gossip_archive_inventory_sha256'],
      'original_public_integrity_bundle_sha256':rootref['sha256'],
      'receiver_verified_public_integrity_inventory_sha256':inventory_sha,
      'signed_pre_cutoff_registry_active_role_count':registry_count,
      'verified_public_log_original_inclusion_set_count':logs_count,
      'independent_signed_device_original_readback_count':device_count,
      'signed_revocation_or_suspension_observation_count':len(all_revocations),
      'public_integrity_epoch_reviews':reviews,
      'local_original_public_history_and_device_copy_consistency':not any(flags[k] for k in FLAGS[:6]),
      'sender_origin_path_required_or_read':False,
      'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
      **flags,**{k:False for k in NEGATIVES},
      **({'unsigned_public_integrity_inventory':inventory} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)

def audit(**opts):return _engine(False,**opts)
