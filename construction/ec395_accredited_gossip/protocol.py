#!/usr/bin/env python3
"""EC395 strictly read-only cross-organizational evidence exchange and recovery.

Always perform the actual unchanged EC394 audit, including EC393/392/391.
The receiver checks original bytes, independent Ed25519 authority/witness/custodian
signatures, offline genuine RFC3161 tokens/CRLs, signed gossip history and
source-identical two-site copies. Assertions of accreditation, archival age,
legal authority or physically separate WORM cannot be proved by supplied files.
"""
from __future__ import annotations

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec353_transparency import transparency as tr
from ec372_historical_authority import authority_archive as io
from ec394_registered_witness import registered_witness as prior

RESULT_SCHEMA='ces.ec395.receiver_independent_credential_gossip_archive_unresolved.v1'
DERIVE_SCHEMA='ces.ec395.unsigned_credential_gossip_archive_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec395.credential_gossip_archive_denial.v1'
INVENTORY_SCHEMA='ces.ec395.unsigned_credential_gossip_archive_inventory.v1'
BUNDLE_SCHEMA='ces.ec395.original_credentials_reciprocal_gossip_archive_bundle.v1'
ROSTER_SCHEMA='ces.ec395.original_two_issuers_two_archivists_roster.v1'
CREDENTIAL_SCHEMA='ces.ec395.original_signed_cross_authority_credential.v1'
CREDENTIAL_CLAIM_SCHEMA='ces.ec395.signed_cross_authority_credential_claim.v1'
GOSSIP_SCHEMA='ces.ec395.original_signed_reciprocal_witness_disclosure.v1'
GOSSIP_CLAIM_SCHEMA='ces.ec395.signed_reciprocal_disclosure_claim.v1'
RECEIPT_SCHEMA='ces.ec395.original_signed_offsite_recovery_receipt.v1'
RECEIPT_CLAIM_SCHEMA='ces.ec395.signed_offsite_recovery_receipt_claim.v1'
CREDENTIAL_DOMAIN=b'CES/EC395/IndependentlySignedExternalCredential/v1\0'
GOSSIP_DOMAINS={
 'offer':b'CES/EC395/ReciprocalWitnessOffer/v1\0',
 'acknowledge':b'CES/EC395/ReciprocalWitnessAcknowledgement/v1\0',
 'confirm':b'CES/EC395/ReciprocalWitnessConfirmation/v1\0',
}
RECEIPT_DOMAIN=b'CES/EC395/IndependentOffsiteOriginalReadback/v1\0'
ZERO='0'*64
# Up to 3 epochs x 2 independent archive sites x 100 path-bound original/copy pairs.
MAX_BUNDLE=1_500_000
MAX_ROSTER=25_000
MAX_SIGNED=60_000
MAX_BASIS=180_000
MAX_COPY=600_000
MAX_COPY_ITEMS=100
PARENT_SCALARS=(*prior.PARENT_SCALARS,*prior.NEW_SCALARS,*prior.AUDIT_ONLY)
PARENT_REPEATS=(*prior.PARENT_REPEATS,*prior.REPEAT_NAMES)
NEW_SCALARS=(
 'historical_ec339_credential_gossip_archive_bundle_file',
 'expected_historical_ec339_credential_gossip_archive_bundle_sha256',
 'expected_outside_retained_ec395_role_roster_sha256',
 'expected_outside_retained_ec395_external_licensing_basis_sha256',
 'expected_outside_retained_ec395_first_credential_original_sha256',
 'expected_outside_retained_ec395_first_offsite_receipt_original_sha256',
 'expected_outside_retained_ec395_credential_issuer_a_public_hex',
 'expected_outside_retained_ec395_credential_issuer_b_public_hex',
)
AUDIT_ONLY=('expected_retained_historical_ec339_credential_gossip_archive_inventory_sha256',)
NEW_REPEATS=(
 ('historical_ec339_reciprocal_gossip_inventory_shas',
  '--historical-ec339-reciprocal-gossip-inventory-sha256'),
 ('historical_ec339_offsite_replica_inventory_shas',
  '--historical-ec339-offsite-replica-inventory-sha256'),
 ('minimum_historical_ec339_reciprocal_gossip_counts',
  '--minimum-historical-ec339-reciprocal-gossip-count'),
 ('minimum_historical_ec339_offsite_replica_counts',
  '--minimum-historical-ec339-offsite-replica-count'),
)
REPEAT_NAMES=tuple(key for key,_ in NEW_REPEATS)
FLAGS=(
 'inherited_real_ec394_registration_custody_or_signed_fork_disputed',
 'outside_retained_credential_original_or_epoch_floors_disagree',
 'credential_signer_or_external_licensing_basis_unbounded',
 'original_reciprocal_signed_disclosure_incomplete_or_late',
 'genuine_signed_cross_witness_view_conflict_or_parent_log_fork_visible',
 'two_independently_signed_complete_offsite_readbacks_missing',
 'credential_gossip_or_archival_rfc3161_crl_stale_revoked_or_late',
 'official_external_regulator_qualified_tsa_and_real_entity_status_unproven',
 'physical_independent_worm_prior_publication_and_dispute_cutoff_unproven',
 'global_hidden_forks_revocation_census_and_final_acceptance_unproven',
)
OUTCOMES=(
 'ec395_inherited_ec394_site_witness_and_historical_custody_disputed',
 'ec395_outside_retained_credentials_or_epoch_inventory_floors_disagree',
 'ec395_independent_credential_licensing_basis_not_bounded',
 'ec395_signed_inter_witness_gossip_or_reciprocal_acknowledgement_missing',
 'ec395_genuine_cross_organization_signed_split_view_disclosed',
 'ec395_two_distinct_signed_archives_and_original_readbacks_incomplete',
 'ec395_timestamp_crl_revocation_or_pre_cutoff_freshness_unresolved',
 'ec395_official_legal_regulatory_and_tsa_qualification_not_established',
 'ec395_real_prior_dispute_publication_and_physical_worm_not_established',
 'ec395_global_visibility_full_revocation_and_product_acceptance_not_established',
)
NEGATIVES=(
 'two_outside_public_keys_and_signed_licenses_prove_real_judicial_accreditation',
 'opaque_external_licensing_bytes_prove_a_current_official_legal_register',
 'distinct_archival_paths_prove_physically_independent_worm_devices',
 'readback_of_today_copy_proves_prior_offsite_storage_at_signature_time',
 'reciprocal_witness_signatures_prove_genuine_network_distribution_or_global_consensus',
 'signed_gossip_with_no_visible_fork_proves_no_hidden_third_party_log_heads',
 'furnished_tsa_root_and_crl_prove_independently_qualified_time_or_global_ocsp',
 'caller_pins_or_token_dates_alone_prove_true_external_dispute_cutoff',
 'receiver_signed_credential_gossip_receipt_or_issued_timestamp',
 'receiver_performed_network_provider_git_ci_cas_worm_or_powershell_write',
 'ec339_issuer_authority_final_quality_or_user_acceptance_promoted',
 'complete_real_ec390_to_ec317_external_independently_verified_history',
)
BUNDLE_FIELDS={'schema','claimed_directory_lineage_id',
 'parent_ec394_registered_witness_bundle_original','external_role_roster_original',
 'external_licensing_basis_original','external_credential_attestations','epochs'}
ROSTER_FIELDS={'schema','claimed_directory_lineage_id','credential_issuers','offsite_archivists'}
ROLE_FIELDS={'role_id','site_id','public_hex','public_key_original'}
CREDENTIAL_GROUP_FIELDS={'issuer_id','signed_credential_original','rfc3161_credential_token_original'}
CREDENTIAL_FIELDS={'schema','claim','signature_ed25519'}
CREDENTIAL_CLAIM_FIELDS={'schema','directory_lineage_id','issuer_id','issuer_site_id',
 'ec394_external_roster_original_sha256','ec393_custody_roster_original_sha256',
 'parent_ec394_registered_bundle_original_sha256',
 'external_licensing_basis_original_sha256','ec394_tsa_root_certificate_der_sha256',
 'ec394_tsa_policy_oid','credential_subject_key_digest_sha256',
 'claimed_accreditation_scope','claimed_issued_utc','claimed_valid_from_utc','claimed_valid_until_utc'}
EPOCH_FIELDS={'epoch_index','gossip','archives'}
GOSSIP_FIELDS={'offer','acknowledge','confirm'}
GOSSIP_ITEM_FIELDS={'signed_original','rfc3161_token_original'}
GOSSIP_FIELDS_SIGNED={'schema','claim','signature_ed25519'}
GOSSIP_CLAIM_FIELDS={'schema','directory_lineage_id','parent_ec394_bundle_original_sha256',
 'parent_ec394_verified_inventory_sha256','ec394_signed_dispute_notice_sha256',
 'epoch_index','stage','witness_id','peer_witness_id','own_observation_shas',
 'peer_observation_shas','previous_stage_signed_original_sha256','claimed_exchange_utc'}
ARCHIVE_FIELDS={'archivist_id','signed_receipt_original','rfc3161_receipt_token_original','copies'}
COPY_FIELDS={'source_original','offsite_copy_original'}
RECEIPT_FIELDS={'schema','claim','signature_ed25519'}
RECEIPT_CLAIM_FIELDS={'schema','directory_lineage_id','parent_ec394_bundle_original_sha256',
 'parent_ec394_verified_inventory_sha256','ec394_signed_dispute_notice_sha256',
 'epoch_index','archivist_id','archivist_site_id','previous_epoch_signed_receipt_sha256',
 'confirmed_gossip_original_sha256','original_to_replica_inventory_sha256',
 'external_licensing_basis_original_sha256','claimed_sealed_utc'}


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC395_'+code,status)


def exact(value,fields,code):
    need(type(value) is dict and set(value)==set(fields),code+'_EXACT_FIELDS_REQUIRED')


def _sha(x):
    return prior._sha(x)


def digest(raw):
    return prior.parent.sha(raw)


def cdigest(obj):
    return digest(canonical.canonical(obj))


def _id(x):
    return prior._ident(x)


def _time(x):
    return prior._utc(x)


def _rawref(ref):
    need(type(ref) is dict and set(ref)=={'path','sha256'},'PATH_SHA_REF_REQUIRED')
    need(_sha(ref['sha256']) and ref['sha256']!=ZERO,'NONZERO_SOURCE_SHA_REQUIRED')
    return ref


def _audit_input(opts,derive):
    required=set((*PARENT_SCALARS,*PARENT_REPEATS,*NEW_SCALARS,*REPEAT_NAMES))
    if not derive:required.update(AUDIT_ONLY)
    need(set(opts)==required,'EXACT_INHERITED_AND_NEW_INPUTS_REQUIRED')
    inherited={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    prior._inputs(inherited,False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],'EC395_BUNDLE')
    for k in NEW_SCALARS[2:6]:
        need(_sha(opts[k]) and opts[k]!=ZERO,'EXTERNALLY_RETAINED_SHA_REQUIRED')
    for k in NEW_SCALARS[6:]:
        need(prior._hexkey(opts[k]),'EXTERNALLY_RETAINED_ISSUER_KEY_REQUIRED')
    if not derive:
        need(_sha(opts[AUDIT_ONLY[0]]) and opts[AUDIT_ONLY[0]]!=ZERO,
             'EXTERNAL_WHOLE_INVENTORY_SHA_REQUIRED')
    epochs=len(opts['historical_directory_root_shas'])
    need(1<=epochs<=3,'ONE_TO_THREE_EPOCHS_ONLY')
    for key in REPEAT_NAMES:
        vals=opts[key]
        need(type(vals) is list and len(vals)==epochs,'EXACT_ONE_FLOOR_PER_EPOCH_REQUIRED')
        if key.startswith('minimum_'):
            ceiling=1 if 'gossip' in key else 2
            need(all(type(v) is int and 0<=v<=ceiling for v in vals),
                 'SIGNED_EPOCH_MINIMUM_IS_OUT_OF_RANGE')
        else:
            need(all(_sha(v) and v!=ZERO for v in vals),
                 'EXTERNAL_EPOCH_INVENTORY_SHA_REQUIRED')
    return inherited


def _parent_report(report,opts):
    required={'schema','command','status','exit_code','offline_unresolved_exit_code',
      'verified_live_ec393_report_sha256','verified_live_ec393_inventory_sha256',
      'historical_registered_witness_original_sha256',
      'receiver_verified_registered_witness_inventory_sha256',
      'cryptographically_timestamped_pre_handoff_registered_site_role_count',
      'cryptographically_timestamped_pre_cutoff_independent_witness_count',
      'visible_genuine_signed_log_fork_count','signed_key_status_snapshot_sha256',
      'furnished_signed_key_revocation_count','registered_witness_epoch_reviews',
      'visible_signed_log_fork_cases','local_registered_key_and_independent_witness_consistency',
      'sender_origin_path_required_or_read',
      'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
      *prior.FLAGS,*prior.NEGATIVES}
    need(type(report) is dict and set(report)==required and
         report.get('schema')==prior.RESULT_SCHEMA and
         report.get('command')=='audit-historical-ec339-registered-witness' and
         report.get('exit_code')==2 and report.get('offline_unresolved_exit_code')==2 and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         report.get('historical_registered_witness_original_sha256')==opts[prior.NEW_SCALARS[1]] and
         report.get('receiver_verified_registered_witness_inventory_sha256')==opts[prior.AUDIT_ONLY[0]] and
         all(report.get(k) is False for k in prior.NEGATIVES) and
         all(type(report.get(k)) is bool for k in prior.FLAGS) and
         all(report[k] is True for k in prior.FLAGS[-3:]) and
         type(report.get('local_registered_key_and_independent_witness_consistency')) is bool and
         report['local_registered_key_and_independent_witness_consistency']==(
             not any(report[k] for k in prior.FLAGS[:7])) and
         report.get('status')==next((prior.OUTCOMES[i] for i,k in enumerate(prior.FLAGS)
            if report[k]),prior.OUTCOMES[-1])+'_unresolved' and
         all(_sha(report.get(k)) for k in (
            'verified_live_ec393_report_sha256','verified_live_ec393_inventory_sha256')),
         'REAL_EC394_AUDIT_OR_RETAINED_PARENT_INVENTORY_NOT_VERIFIED','unavailable')
    epochs=report['registered_witness_epoch_reviews']
    n=len(opts['historical_directory_root_shas'])
    need(type(epochs) is list and len(epochs)==n and
         all(type(r) is dict and set(r)=={
          'epoch_index','pre_handoff_registered_site_roles',
          'pre_cutoff_independent_log_witnesses','site_key_registration_inventory_sha256',
          'third_party_witness_inventory_sha256','visible_valid_signed_log_fork_count'} and
          r['epoch_index']==idx and type(r['epoch_index']) is int and
          all(type(r[k]) is int and 0<=r[k]<=(2 if 'witnesses' in k or 'fork' in k else 4)
              for k in ('pre_handoff_registered_site_roles',
                'pre_cutoff_independent_log_witnesses','visible_valid_signed_log_fork_count')) and
          all(_sha(r[k]) for k in ('site_key_registration_inventory_sha256',
            'third_party_witness_inventory_sha256'))
          for idx,r in enumerate(epochs)) and
         report['cryptographically_timestamped_pre_handoff_registered_site_role_count']==sum(
          r['pre_handoff_registered_site_roles'] for r in epochs) and
         report['cryptographically_timestamped_pre_cutoff_independent_witness_count']==sum(
          r['pre_cutoff_independent_log_witnesses'] for r in epochs) and
         report['visible_genuine_signed_log_fork_count']==sum(
          r['visible_valid_signed_log_fork_count'] for r in epochs) and
         type(report['visible_signed_log_fork_cases']) is list and
         len(report['visible_signed_log_fork_cases'])<=2*n and
         (report['signed_key_status_snapshot_sha256'] is None or
          _sha(report['signed_key_status_snapshot_sha256'])),
         'REAL_EC394_EPOCH_HISTORY_OR_SOURCE_COUNTS_INVALID','unavailable')
    return cdigest(report)


def _roster(roster,rolesref,opts,lineage,read,existing,existing_sites,existing_ids):
    exact(roster,ROSTER_FIELDS,'EXTERNAL_SIGNER_ROSTER')
    need(roster['schema']==ROSTER_SCHEMA and
         roster['claimed_directory_lineage_id']==lineage and
         rolesref['sha256']==opts[NEW_SCALARS[2]],
         'EXTERNAL_ORIGINAL_SIGNER_ROSTER_PIN_INVALID','permission_denied')
    for k in ('credential_issuers','offsite_archivists'):
        need(type(roster[k]) is list and len(roster[k])==2,
             'EXACTLY_TWO_ISSUERS_AND_TWO_OFFSITE_ARCHIVISTS_REQUIRED')
    seen_keys=set(existing);seen_ids=set(existing_ids);seen_sites=set(existing_sites)
    all_roles=[];all_paths=set()
    for group in ('credential_issuers','offsite_archivists'):
        for item in roster[group]:
            exact(item,ROLE_FIELDS,'INDEPENDENT_ROLE')
            need(_id(item['role_id']) and item['role_id'] not in seen_ids and
                 _id(item['site_id']) and item['site_id'] not in seen_sites and
                 prior._hexkey(item['public_hex']) and item['public_hex'] not in seen_keys,
                 'CREDENTIAL_AND_CUSTODY_SIGNER_KEY_SITE_ID_INDEPENDENCE_REQUIRED',
                 'permission_denied')
            keyref=_rawref(item['public_key_original'])
            need(keyref['path'] not in all_paths,
                 'INDEPENDENT_SIGNER_RAW_KEY_SOURCE_PATH_REUSED','permission_denied')
            raw=read(keyref,'original_issuer_or_offsite_archivist_raw_public_key',32)
            need(len(raw)==32 and raw.hex()==item['public_hex'],
                 'GENUINE_RAW_PUBLIC_KEY_ORIGINAL_DISAGREES','permission_denied')
            seen_ids.add(item['role_id']);seen_sites.add(item['site_id'])
            seen_keys.add(item['public_hex']);all_paths.add(keyref['path'])
            all_roles.append(item)
    a,b=roster['credential_issuers']
    need(a['public_hex']==opts[NEW_SCALARS[6]] and
         b['public_hex']==opts[NEW_SCALARS[7]],
         'OUTSIDE_INDEPENDENT_ISSUER_PUBLIC_KEY_PINS_DISAGREE','permission_denied')
    return {item['role_id']:item for item in all_roles}, all_paths


def _stamp(raw,ref,trust,authority,read,evaluation,cutoff,claimed,flags):
    if ref is None:
        flags[FLAGS[6]]=True
        return None
    pf={k:False for k in prior.FLAGS}
    stamp=prior._timestamp(raw,ref,trust,authority,read,evaluation,cutoff,claimed,pf)
    if pf[prior.FLAGS[5]] or pf[prior.FLAGS[6]]:
        flags[FLAGS[6]]=True
    return stamp


def _bounded(stamp,claimed,cutoff):
    return bool(stamp is not None and stamp['clean'] and
       claimed<=stamp['gen']<=cutoff)


def _signer(pub,sig,domain,claim,role):
    prior._signed(pub,sig,domain,claim,role)


def _signed(ref,read,fields,schema,claim_fields,claim_schema,code):
    raw=read(_rawref(ref),'original_'+code,MAX_SIGNED)
    obj=tr.strict_json(raw,'EC395_'+code)
    exact(obj,fields,code)
    claim=obj['claim'];exact(claim,claim_fields,code+'_CLAIM')
    need(obj['schema']==schema and claim['schema']==claim_schema,
         code+'_SCHEMA_INVALID','permission_denied')
    return raw,obj,claim


def _actual_parent_source(bundle,opts,read,doc):
    """Reopen EC394 inputs, never accept caller-supplied summaries of originals."""
    actualref={'path':opts[prior.NEW_SCALARS[0]],'sha256':opts[prior.NEW_SCALARS[1]]}
    need(bundle['parent_ec394_registered_witness_bundle_original']==actualref,
         'MUST_CHAIN_EXACT_GENUINE_EC394_BUNDLE','permission_denied')
    parentbundle=doc(actualref,'authentic_ec394_registered_witness_bundle',prior.MAX_BUNDLE)
    prior.exact(parentbundle,prior.BUNDLE_FIELDS,'REAL_EC394_BUNDLE')
    oldref=parentbundle['parent_ec393_custody_bundle_original']
    oldbundle=doc(oldref,'authentic_ec393_custody_bundle',prior.parent.MAX_BUNDLE)
    prior.parent.exact(oldbundle,prior.parent.BUNDLE_FIELDS,'REAL_EC393_BUNDLE')
    ec393_roster_ref=oldbundle['custody_log_roster_original']
    ec393_roster=doc(ec393_roster_ref,'authentic_ec393_party_roster',prior.parent.MAX_ROSTER)
    prior.parent.exact(ec393_roster,prior.parent.ROSTER_FIELDS,'REAL_EC393_ROSTER')
    ec394_roster_ref=parentbundle['external_trust_roster_original']
    ec394_roster=doc(ec394_roster_ref,'authentic_ec394_external_roster',prior.MAX_ROSTER)
    prior.exact(ec394_roster,prior.ROSTER_FIELDS,'REAL_EC394_ROSTER')
    trustref=parentbundle['witness_tsa_registry_original']
    trust=prior.parent.prior._trust_registry(
        doc(trustref,'verified_parent_ec394_tsa_roster',prior.parent.prior.MAX_TRUST),
        trustref,opts[prior.NEW_SCALARS[3]],opts['claimed_historical_directory_lineage_id'],read)
    authority=parentbundle['witness_tsa_authority_id']
    need(authority in trust,'REAL_EC394_TSA_AUTHORITY_MISSING','permission_denied')
    identifiers=[];keys=[];sites=[]
    for x in (*ec393_roster['custody_parties'],):
        keys.append(x['public_hex']);sites.append(x['site_id']);identifiers.append(x['party_id'])
    keys.append(ec393_roster['log_public_hex']);identifiers.append(ec393_roster['log_operator_id'])
    for role in (ec394_roster['registrar'],ec394_roster['dispute_authority'],
                 *ec394_roster['witnesses']):
        keys.append(role['public_hex']);sites.append(role['site_id']);identifiers.append(role['role_id'])
    refs=[actualref,oldref,ec393_roster_ref,ec394_roster_ref,trustref]
    return {'ec394_bundle':parentbundle,'ec394_roster':ec394_roster,
        'ec394_roster_ref':ec394_roster_ref,'ec393_roster':ec393_roster,
        'ec393_roster_ref':ec393_roster_ref,'trust':trust,'authority':authority,
        'tsa_root_sha':trust[authority]['root_sha'],
        'tsa_policy':trust[authority]['policy'],
        'known_keys':keys,'known_sites':sites,'known_ids':identifiers,
        'protected_refs':refs}


def _subjects(anchor,roles):
    subjects=[]
    r=anchor['ec394_roster']
    for name,role in (('registrar',r['registrar']),('dispute_authority',r['dispute_authority'])):
        subjects.append({'kind':name,'id':role['role_id'],'public_hex':role['public_hex']})
    for role in r['witnesses']:
        subjects.append({'kind':'log_witness','id':role['role_id'],'public_hex':role['public_hex']})
    for role in anchor['ec393_roster']['custody_parties']:
        subjects.append({'kind':'old_site_custodian','id':role['party_id'],'public_hex':role['public_hex']})
    for role in roles.values():
        if role['role_id'] not in (x['role_id'] for x in (anchor['ec394_roster']['registrar'],
                                             anchor['ec394_roster']['dispute_authority'])):
            subjects.append({'kind':'external_new_role','id':role['role_id'],
                             'public_hex':role['public_hex']})
    return sorted(subjects,key=lambda item:(item['kind'],item['id']))


def _credentials(bundle,roles,anchor,opts,read,trust,aid,evaluation,cutoff,flags,
                 parentref,licenseref,lineage):
    groups=bundle['external_credential_attestations']
    need(type(groups) is list and len(groups)==2,
         'TWO_EXTERNAL_ISSUER_CREDENTIAL_SLOTS_REQUIRED')
    issuer_ids={r['role_id'] for r in roles.values() if r['public_hex'] in
        (opts[NEW_SCALARS[6]],opts[NEW_SCALARS[7]])}
    need(len(issuer_ids)==2,'EXACT_TWO_PINNED_CREDENTIAL_ISSUERS_REQUIRED')
    subject_sha=cdigest(_subjects(anchor,roles))
    seen=set();out=[];local_ok=True;credential_generations=[]
    for group in groups:
        exact(group,CREDENTIAL_GROUP_FIELDS,'ISSUER_ORIGINAL_CREDENTIAL_GROUP')
        issuer_id=group['issuer_id']
        need(issuer_id in issuer_ids and issuer_id not in seen,
             'CREDENTIAL_ISSUER_MISSING_OR_REUSED','permission_denied')
        seen.add(issuer_id)
        ref=group['signed_credential_original'];token=group['rfc3161_credential_token_original']
        if ref is None:
            need(token is None,'ORPHAN_CREDENTIAL_TIMESTAMP_DENIED','permission_denied')
            flags[FLAGS[2]]=True;local_ok=False
            out.append({'issuer_id':issuer_id,'credential_sha256':None,
                        'timestamp_sha256':None,'bounded_before_cutoff':False})
            continue
        raw,obj,claim=_signed(ref,read,CREDENTIAL_FIELDS,CREDENTIAL_SCHEMA,
                             CREDENTIAL_CLAIM_FIELDS,CREDENTIAL_CLAIM_SCHEMA,'SIGNED_CREDENTIAL')
        need(claim['directory_lineage_id']==lineage and
             claim['issuer_id']==issuer_id and
             claim['issuer_site_id']==roles[issuer_id]['site_id'] and
             claim['ec394_external_roster_original_sha256']==anchor['ec394_roster_ref']['sha256'] and
             claim['ec393_custody_roster_original_sha256']==anchor['ec393_roster_ref']['sha256'] and
             claim['parent_ec394_registered_bundle_original_sha256']==parentref['sha256'] and
             claim['external_licensing_basis_original_sha256']==licenseref['sha256'] and
             claim['ec394_tsa_root_certificate_der_sha256']==anchor['tsa_root_sha'] and
             claim['ec394_tsa_policy_oid']==anchor['tsa_policy'] and
             claim['credential_subject_key_digest_sha256']==subject_sha and
             claim['claimed_accreditation_scope']=='local_evidence_custody_and_timestamp_origins',
             'GENUINE_CREDENTIAL_DOES_NOT_BIND_ACTUAL_PARENT_AND_ORIGINAL_AUTHORITIES',
             'permission_denied')
        issued=_time(claim['claimed_issued_utc'])
        start=_time(claim['claimed_valid_from_utc'])
        end=_time(claim['claimed_valid_until_utc'])
        need(start<=issued<end,'CREDENTIAL_CLAIMED_WINDOW_ORDER_INVALID','permission_denied')
        _signer(roles[issuer_id]['public_hex'],obj['signature_ed25519'],
                CREDENTIAL_DOMAIN,claim,'CROSS_AUTHORITY_CREDENTIAL')
        stamp=_stamp(raw,token,trust,aid,read,evaluation,cutoff,issued,flags)
        if stamp is not None:credential_generations.append(stamp['gen'])
        bounded=bool(_bounded(stamp,issued,cutoff) and start<=cutoff<=end and start<=issued)
        if not bounded:flags[FLAGS[2]]=True;local_ok=False
        out.append({'issuer_id':issuer_id,'credential_sha256':ref['sha256'],
             'timestamp_sha256':stamp['sha256'] if stamp else None,
             'bounded_before_cutoff':bounded})
    need(seen==issuer_ids,'TWO_GENUINE_ISSUER_SLOTS_REQUIRED','permission_denied')
    first_issuer=next(role['role_id'] for role in roles.values()
        if role['public_hex']==opts[NEW_SCALARS[6]])
    first_credential=next(row['credential_sha256'] for row in out
        if row['issuer_id']==first_issuer)
    if first_credential!=opts[NEW_SCALARS[4]]:
        flags[FLAGS[1]]=True
    return out, local_ok, (max(credential_generations) if credential_generations else None)


def _parent_observation_sources(bundle,epoch,read):
    """Collect exact parent originals previously verified by the real EC394 audit."""
    entry=bundle['epochs'][epoch]
    prior.exact(entry,prior.EPOCH_FIELDS,'ACTUAL_PARENT_WITNESS_EPOCH')
    by_id={}
    signed_sources=[];heads=[]
    for group in entry['witnesses']:
        prior.exact(group,prior.WITNESS_GROUP_FIELDS,'ACTUAL_PARENT_WITNESS_GROUP')
        wid=group['witness_id']
        need(wid not in by_id,'DUPLICATE_PARENT_WITNESS_GROUP','unavailable')
        refs=[]
        for obs in group['observations']:
            prior.exact(obs,prior.OBS_FIELDS,'ACTUAL_PARENT_SIGNED_WITNESS_OBSERVATION')
            ref=obs['signed_witness_observation_original']
            if ref is not None:
                _rawref(ref)
                # EC394 already checked both the signed observation and genuine old log Head.
                refs.append(ref['sha256']);signed_sources.append(ref)
            head=obs['observed_signed_log_head_original']
            if head is not None:heads.append(_rawref(head))
        need(len(set(refs))==len(refs),'PARENT_WITNESS_SHA_DUPLICATE','unavailable')
        by_id[wid]=tuple(sorted(refs))
    return by_id,signed_sources,heads


def _gossip_step(item,stage,witness,peer,predecessor,parentref,parent_digest,
                 notice_sha,epoch,lineage,read,trust,aid,evaluation,cutoff,flags):
    exact(item,GOSSIP_ITEM_FIELDS,'ORIGINAL_SIGNED_GOSSIP_STEP')
    ref=item['signed_original'];token=item['rfc3161_token_original']
    if ref is None:
        need(token is None,'ORPHAN_GOSSIP_TIMESTAMP_DENIED','permission_denied')
        flags[FLAGS[3]]=True
        return None
    raw,obj,claim=_signed(ref,read,GOSSIP_FIELDS_SIGNED,GOSSIP_SCHEMA,
            GOSSIP_CLAIM_FIELDS,GOSSIP_CLAIM_SCHEMA,'RECIPROCAL_GOSSIP_'+stage.upper())
    need(claim['directory_lineage_id']==lineage and
         claim['parent_ec394_bundle_original_sha256']==parentref['sha256'] and
         claim['parent_ec394_verified_inventory_sha256']==parent_digest and
         claim['ec394_signed_dispute_notice_sha256']==notice_sha and
         type(claim['epoch_index']) is int and claim['epoch_index']==epoch and
         claim['stage']==stage and claim['witness_id']==witness['role_id'] and
         claim['peer_witness_id']==peer['role_id'] and
         claim['previous_stage_signed_original_sha256']==predecessor and
         type(claim['own_observation_shas']) is list and
         type(claim['peer_observation_shas']) is list and
         len(claim['own_observation_shas'])<=2 and
         len(claim['peer_observation_shas'])<=2 and
         all(_sha(x) and x!=ZERO for x in
             (*claim['own_observation_shas'],*claim['peer_observation_shas'])) and
         claim['own_observation_shas']==sorted(set(claim['own_observation_shas'])) and
         claim['peer_observation_shas']==sorted(set(claim['peer_observation_shas'])),
         'SIGNED_GOSSIP_CHAIN_IS_NOT_BOUND_TO_AUTHENTIC_WITNESS_ORIGINALS',
         'permission_denied')
    observed=_time(claim['claimed_exchange_utc'])
    _signer(witness['public_hex'],obj['signature_ed25519'],GOSSIP_DOMAINS[stage],
            claim,'RECIPROCAL_WITNESS_'+stage.upper())
    stamp=_stamp(raw,token,trust,aid,read,evaluation,cutoff,observed,flags)
    return {'sha256':ref['sha256'],'claim':claim,'claimed':observed,'stamp':stamp,
            'bounded':_bounded(stamp,observed,cutoff),'source':ref}


def _gossip(gossip,epoch,anchor,parent_source,parentref,parent_digest,notice_sha,
           lineage,read,trust,aid,evaluation,cutoff,flags):
    exact(gossip,GOSSIP_FIELDS,'EPOCH_RECIPROCAL_SIGNED_GOSSIP')
    witnesses=anchor['ec394_roster']['witnesses']
    need(type(witnesses) is list and len(witnesses)==2,
         'AUTHENTIC_PARENT_MUST_HAVE_TWO_WITNESSES','unavailable')
    a,b=witnesses
    expected,sources,heads=_parent_observation_sources(parent_source,epoch,read)
    need(set(expected)=={a['role_id'],b['role_id']},
         'REAL_PARENT_WITNESS_SIGNER_IDS_DO_NOT_MATCH','unavailable')
    specs=[('offer',a,b,ZERO),('acknowledge',b,a,None),('confirm',a,b,None)]
    chain=[];previous=None
    for stage,sender,peer,predecessor in specs:
        prev=predecessor if predecessor is not None else (previous['sha256'] if previous else ZERO)
        step=_gossip_step(gossip[stage],stage,sender,peer,prev,parentref,parent_digest,
                   notice_sha,epoch,lineage,read,trust,aid,evaluation,cutoff,flags)
        if step is None:
            previous=None
            chain.append(None)
            # A later signed stage cannot invent a non-existent predecessor.
            continue
        if stage!='offer' and previous is None:
            need(False,'SIGNED_GOSSIP_HAS_MISSING_PREDECESSOR','permission_denied')
        chain.append(step);previous=step
    divergence=[];last_utc=None;bound_all=True
    for idx,step in enumerate(chain):
        if step is None:
            bound_all=False;continue
        stage=specs[idx][0]
        c=step['claim']
        own=expected[c['witness_id']];peer=expected[c['peer_witness_id']]
        actual_own=tuple(c['own_observation_shas']); actual_peer=tuple(c['peer_observation_shas'])
        # Unknown purported signed evidence is not silently accepted as verified.
        need(set(actual_own).issubset(set(own)) and set(actual_peer).issubset(set(peer)),
             'GOSSIP_CITES_UNVERIFIED_SIGNED_WITNESS_ORIGINAL','permission_denied')
        if actual_own!=own or actual_peer!=peer:
            flags[FLAGS[4]]=True
            divergence.append({'stage':stage,'witness_id':c['witness_id'],
               'advertised_own_original_shas':list(actual_own),'advertised_peer_original_shas':list(actual_peer),
               'verified_parent_own_original_shas':list(own),'verified_parent_peer_original_shas':list(peer)})
        if last_utc is not None and step['claimed']<last_utc:
            flags[FLAGS[3]]=True;bound_all=False
        if idx>0 and chain[idx-1] and chain[idx-1]['stamp'] and (
                step['claimed']<chain[idx-1]['stamp']['gen']):
            flags[FLAGS[3]]=True;bound_all=False
        last_utc=step['claimed']
        if not step['bounded'] or (idx>0 and chain[idx-1] and
           step['stamp'] and chain[idx-1]['stamp'] and
           step['stamp']['gen']<chain[idx-1]['stamp']['gen']):
            flags[FLAGS[3]]=True;bound_all=False
    complete=bool(len(chain)==3 and all(chain) and bound_all and not divergence)
    if not complete:flags[FLAGS[3]]=True
    rows=[{'stage':s,'signed_original_sha256':x['sha256'] if x else None,
           'token_sha256':x['stamp']['sha256'] if x and x['stamp'] else None,
           'bounded_before_cutoff':bool(x and x['bounded'])}
          for (s,_,_,_),x in zip(specs,chain)]
    return {'complete':complete,'rows':rows,'divergences':divergence,
           'confirmed_original_sha256':chain[-1]['sha256'] if chain[-1] else ZERO,
           'confirmed_token_generation_time':chain[-1]['stamp']['gen']
               if chain[-1] and chain[-1]['stamp'] else None,
           'signed_originals':[x['source'] for x in chain if x],
           'token_originals':[gossip[step]['rfc3161_token_original']
               for step in ('offer','acknowledge','confirm')
               if gossip[step]['rfc3161_token_original'] is not None],
           'signed_observations':sources,'signed_heads':heads}


def _required_archive_sources(parentref,anchor,parent_source,gossip,external_new_refs=(),epoch=0):
    """Recover the bounded EC394/395 credential, time, witness and gossip corpus.

    Includes every referenced EC394 registration generation, signed observation
    and timestamp, not just the user-selected 'best' head. Does not claim to
    cover every ancient EC317->390 source or every unseen public archive.
    """
    refs=[parentref,anchor['ec394_roster_ref'],
       parent_source['parent_ec393_custody_bundle_original'],
       parent_source['witness_tsa_registry_original'],
       parent_source['external_trust_roster_original'],
       parent_source['original_dispute_case_file'],
       parent_source['signed_dispute_notice_original'],
       parent_source['dispute_notice_rfc3161_token_original'],
       parent_source['key_status_snapshot_original'],
       parent_source['key_status_snapshot_rfc3161_token_original'],
       *gossip['signed_observations'],*gossip['signed_heads'],
       *gossip['signed_originals'],*gossip['token_originals'],
       *external_new_refs]
    for history in parent_source['site_key_histories']:
        prior.exact(history,prior.HISTORY_FIELDS,'REAL_PARENT_SITE_HISTORY')
        refs.append(history['registered_site_identity_original'])
        for generation in history['generations']:
            prior.exact(generation,prior.GENERATION_FIELDS,'REAL_PARENT_REGISTRATION_GENERATION')
            refs.extend((generation['signed_site_key_registration_original'],
                         generation['registered_public_key_original'],
                         generation['rfc3161_registration_token_original']))
    for old_epoch in parent_source['epochs'][:epoch+1]:
        prior.exact(old_epoch,prior.EPOCH_FIELDS,'REAL_PARENT_EPOCH')
        for group in old_epoch['witnesses']:
            prior.exact(group,prior.WITNESS_GROUP_FIELDS,'REAL_PARENT_WITNESS_GROUP')
            for obs in group['observations']:
                prior.exact(obs,prior.OBS_FIELDS,'REAL_PARENT_OBSERVATION')
                refs.extend((obs['signed_witness_observation_original'],
                             obs['rfc3161_witness_token_original'],
                             obs['observed_signed_log_head_original']))
    refs=[_rawref(r) for r in refs if r is not None]
    unique={}
    for ref in refs:
        if ref['sha256'] in unique:
            need(unique[ref['sha256']]==ref,
                 'SAME_PARENT_SHA_WITH_DIFFERENT_ORIGINAL_PATH_NOT_ALLOWED',
                 'permission_denied')
        unique[ref['sha256']]=ref
    need(1<=len(unique)<=MAX_COPY_ITEMS,
         'ARCHIVE_SOURCE_SET_OUTSIDE_BOUNDED_ORIGINAL_COUNT')
    return sorted(unique.values(),key=lambda r:(r['sha256'],r['path']))


def _archive_copy_pairs(copies,required,read,forbidden_paths,used_copies):
    need(type(copies) is list and len(copies)==len(required),
         'COMPLETE_SOURCE_ORIGINAL_TO_RECOVERED_COPY_SET_REQUIRED',
         'permission_denied')
    wanted={(ref['path'],ref['sha256']):ref for ref in required}
    seen=set();rows=[]
    for pair in copies:
        exact(pair,COPY_FIELDS,'ORIGINAL_TO_OFFSITE_COPY')
        source=_rawref(pair['source_original']);replica=_rawref(pair['offsite_copy_original'])
        key=(source['path'],source['sha256'])
        need(key in wanted and key not in seen,
             'ARCHIVE_COPY_DOES_NOT_REFERENCE_THE_EXACT_REAL_SOURCE_ORIGINAL',
             'permission_denied')
        seen.add(key)
        need(replica['path'] not in forbidden_paths and
             replica['path'] not in used_copies and replica['path']!=source['path'] and
             replica['sha256']==source['sha256'],
             'OFFSITE_REPLICA_ALIASES_PRIOR_SOURCE_OR_ANOTHER_ARCHIVE_OR_SHA_DIFFERS',
             'permission_denied')
        original=read(source,'authenticated_ec394_source_for_byte_readback',MAX_COPY)
        copied=read(replica,'independent_custody_site_archived_byte_replica',MAX_COPY)
        need(original==copied,
             'OFFSITE_ARCHIVE_BYTES_DIFFER_FROM_AUTHENTIC_PARENT_ORIGINAL',
             'permission_denied')
        used_copies.add(replica['path'])
        rows.append({'source_original':source,'offsite_copy_original':replica})
    need(len(seen)==len(wanted),'OFFSITE_ARCHIVE_REQUIRED_ORIGINALS_MISSING','permission_denied')
    return sorted(rows,key=lambda row:(row['source_original']['sha256'],
                                        row['source_original']['path']))


def _archive(entry,epoch,archivist,previous,confirmed_sha,confirmed_generation,
             credential_generation,previous_generation,parentref,parent_digest,
             notice_sha,basis_sha,required,read,trust,aid,evaluation,cutoff,
             forbidden_paths,used_copies,lineage,flags,prior_chain_ok):
    exact(entry,ARCHIVE_FIELDS,'SIGNED_INDEPENDENT_ARCHIVE_GROUP')
    need(entry['archivist_id']==archivist['role_id'],
         'ARCHIVIST_ID_MUST_MATCH_OUTSIDE_PINNED_ROSTER','permission_denied')
    ref=entry['signed_receipt_original'];token=entry['rfc3161_receipt_token_original']
    if ref is None:
        need(token is None and entry['copies']==[],
             'MISSING_SIGNED_OFFSITE_RECEIPT_CANNOT_CLAIM_COPIES_OR_TIMESTAMP',
             'permission_denied')
        flags[FLAGS[5]]=True
        return {'archivist_id':archivist['role_id'],'signed_receipt_sha256':None,
                 'timestamp_sha256':None,'recovered_originals':0,
                 'pre_cutoff_signed_copy_readback':False,'inventory_sha256':None,
                 '_stamp_generation':None}
    rows=_archive_copy_pairs(entry['copies'],required,read,forbidden_paths,used_copies)
    d=cdigest(rows)
    raw,obj,claim=_signed(ref,read,RECEIPT_FIELDS,RECEIPT_SCHEMA,
                          RECEIPT_CLAIM_FIELDS,RECEIPT_CLAIM_SCHEMA,'ORIGINAL_ARCHIVE_RECEIPT')
    need(claim['directory_lineage_id']==lineage and
         claim['parent_ec394_bundle_original_sha256']==parentref['sha256'] and
         claim['parent_ec394_verified_inventory_sha256']==parent_digest and
         claim['ec394_signed_dispute_notice_sha256']==notice_sha and
         type(claim['epoch_index']) is int and claim['epoch_index']==epoch and
         claim['archivist_id']==archivist['role_id'] and
         claim['archivist_site_id']==archivist['site_id'] and
         claim['previous_epoch_signed_receipt_sha256']==previous and
         claim['confirmed_gossip_original_sha256']==confirmed_sha and
         claim['original_to_replica_inventory_sha256']==d and
         claim['external_licensing_basis_original_sha256']==basis_sha,
         'OFFSITE_RECEIPT_SIGNATURE_NOT_BOUND_TO_ORIGINALS_HISTORY_AND_GOSSIP',
         'permission_denied')
    sealed=_time(claim['claimed_sealed_utc'])
    _signer(archivist['public_hex'],obj['signature_ed25519'],
            RECEIPT_DOMAIN,claim,'INDEPENDENT_ARCHIVIST_SEALED_READBACK')
    stamp=_stamp(raw,token,trust,aid,read,evaluation,cutoff,sealed,flags)
    bounded=bool(_bounded(stamp,sealed,cutoff) and
                 confirmed_generation is not None and sealed>=confirmed_generation and
                 stamp['gen']>=confirmed_generation and
                 credential_generation is not None and sealed>=credential_generation and
                 (previous_generation is None or sealed>=previous_generation) and
                 (epoch==0 or previous!=ZERO) and prior_chain_ok)
    if not bounded:flags[FLAGS[5]]=True
    return {'archivist_id':archivist['role_id'],'signed_receipt_sha256':ref['sha256'],
            'timestamp_sha256':stamp['sha256'] if stamp else None,
            'recovered_originals':len(rows),'pre_cutoff_signed_copy_readback':bounded,
            'inventory_sha256':d,'_stamp_generation':stamp['gen'] if stamp else None}


def _engine(derive,**opts):
    inherited=_audit_input(opts,derive)
    # Not supplied a PASS: executes unchanged actual EC394, then EC393/392/two EC391.
    actual=prior.audit(**inherited)
    actual_sha=_parent_report(actual,opts)
    lineage=opts['claimed_historical_directory_lineage_id']
    evaluation=_time(opts['ec391_tsa_evaluation_utc'])
    cutoff=_time(opts[prior.parent.NEW_SCALARS[5]])
    read,doc,late=prior._readers()
    original={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    bundle=doc(original,'genuine_credential_gossip_offsite_bundle',MAX_BUNDLE)
    exact(bundle,BUNDLE_FIELDS,'SIGNED_WITNESS_RECOVERY_BUNDLE')
    parentref={'path':opts[prior.NEW_SCALARS[0]],'sha256':opts[prior.NEW_SCALARS[1]]}
    need(bundle['schema']==BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id']==lineage and
         type(bundle['epochs']) is list and
         len(bundle['epochs'])==len(opts['historical_directory_root_shas']),
         'CREDENTIAL_GOSSIP_BUNDLE_LINEAGE_OR_EPOCH_COUNT_INVALID',
         'permission_denied')
    anchor=_actual_parent_source(bundle,opts,read,doc)
    parent_source=anchor['ec394_bundle']
    rosterref=_rawref(bundle['external_role_roster_original'])
    rolestore=doc(rosterref,'two_issuers_two_archivists_original',MAX_ROSTER)
    roles,keypaths=_roster(rolestore,rosterref,opts,lineage,read,
         anchor['known_keys'],anchor['known_sites'],anchor['known_ids'])
    licenseref=_rawref(bundle['external_licensing_basis_original'])
    need(licenseref['sha256']==opts[NEW_SCALARS[3]],
         'EXTERNAL_LICENSE_SOURCE_SHA_OUTSIDE_PIN_DISAGREES','permission_denied')
    read(licenseref,'opaque_official_licensing_basis_not_trusted_as_official',MAX_BASIS)
    trust=anchor['trust'];aid=anchor['authority']
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not actual['local_registered_key_and_independent_witness_consistency'] or bool(
        actual['visible_genuine_signed_log_fork_count'])
    flags[FLAGS[4]]=bool(actual['visible_genuine_signed_log_fork_count'])
    creds,creds_clean,credential_generation=_credentials(bundle,roles,anchor,opts,read,trust,aid,
           evaluation,cutoff,flags,parentref,licenseref,lineage)
    known_parent_roster=anchor['ec394_roster']
    witness_roles=known_parent_roster['witnesses']
    notice_ref=parent_source['signed_dispute_notice_original']
    need(notice_ref is not None,'REAL_EC394_SIGNED_DISPUTE_NOTICE_REQUIRED',
         'unavailable')
    notice_sha=notice_ref['sha256']
    original_source_paths={r['path'] for r in anchor['protected_refs']}
    original_source_paths.update((original['path'],rosterref['path'],licenseref['path']))
    original_source_paths.update(keypaths)
    def add_real_refs(obj):
        if type(obj) is dict:
            if set(obj)=={'path','sha256'} and type(obj['path']) is str:
                original_source_paths.add(obj['path'])
            else:
                for v in obj.values():add_real_refs(v)
        elif type(obj) is list:
            for v in obj:add_real_refs(v)
    add_real_refs(parent_source)
    for group in bundle['external_credential_attestations']:
        for k in ('signed_credential_original','rfc3161_credential_token_original'):
            r=group[k]
            if r is not None:original_source_paths.add(_rawref(r)['path'])
    for ep in bundle['epochs']:
        exact(ep,EPOCH_FIELDS,'SIGNED_CROSSVIEW_ARCHIVE_EPOCH')
        exact(ep['gossip'],GOSSIP_FIELDS,'SIGNED_INTER_WITNESS_GOSSIP')
        for name in ('offer','acknowledge','confirm'):
            item=ep['gossip'][name];exact(item,GOSSIP_ITEM_FIELDS,'WITNESS_EXCHANGE_STAGE')
            for k in ('signed_original','rfc3161_token_original'):
                r=item[k]
                if r is not None:original_source_paths.add(_rawref(r)['path'])
        need(type(ep['archives']) is list and len(ep['archives'])==2,
             'EXACTLY_TWO_OFFSITE_CUSTODY_GROUPS_PER_EPOCH')
        for arch in ep['archives']:
            exact(arch,ARCHIVE_FIELDS,'ARCHIVE_EPOCH_ORIGINAL')
            for k in ('signed_receipt_original','rfc3161_receipt_token_original'):
                r=arch[k]
                if r is not None:original_source_paths.add(_rawref(r)['path'])
    reviews=[];signed_gossip_divergences=[];inventory_epochs=[]
    prev_receipts={r['role_id']:ZERO for r in rolestore['offsite_archivists']}
    prev_receipt_generations={r['role_id']:None for r in rolestore['offsite_archivists']}
    # A previously unbounded or absent receipt breaks this archivist's chain
    # permanently for later epoch count floors, even if new signatures appear.
    previous_receipt_chain_ok={r['role_id']:True for r in rolestore['offsite_archivists']}
    used_copy_paths=set();first_receipt_sha=None;gossip_count=0;archive_count=0
    # Do NOT archive EC395 bundle itself: the bundle embeds archive receipt
    # SHA refs and its inclusion would create an impossible circular hash.
    additional_archive_refs=[rosterref,licenseref]
    for credential in bundle['external_credential_attestations']:
        additional_archive_refs.extend(credential[k] for k in (
            'signed_credential_original','rfc3161_credential_token_original'))
    for epoch,ep in enumerate(bundle['epochs']):
        need(type(ep['epoch_index']) is int and ep['epoch_index']==epoch,
             'ARCHIVE_EPOCH_INDEX_NOT_CONTIGUOUS','permission_denied')
        gossip=_gossip(ep['gossip'],epoch,anchor,parent_source,parentref,
               actual['receiver_verified_registered_witness_inventory_sha256'],
               notice_sha,lineage,read,trust,aid,evaluation,cutoff,flags)
        for case in gossip['divergences']:
            signed_gossip_divergences.append({'epoch_index':epoch,**case})
        required=_required_archive_sources(parentref,anchor,parent_source,gossip,
                                            additional_archive_refs,epoch=epoch)
        archives=[];seen=set();asite=0
        for arch in ep['archives']:
            ident=arch['archivist_id']
            need(ident in roles and ident in prev_receipts and ident not in seen,
                 'TWO_DISTINCT_REGISTERED_ARCHIVISTS_REQUIRED','permission_denied')
            seen.add(ident)
            result=_archive(arch,epoch,roles[ident],prev_receipts[ident],
                  gossip['confirmed_original_sha256'],gossip['confirmed_token_generation_time'],
                  credential_generation,prev_receipt_generations[ident],parentref,
                  actual['receiver_verified_registered_witness_inventory_sha256'],
                  notice_sha,licenseref['sha256'],required,read,trust,aid,evaluation,
                  cutoff,original_source_paths,used_copy_paths,lineage,flags,
                  previous_receipt_chain_ok[ident])
            previous_receipt_chain_ok[ident]=result['pre_cutoff_signed_copy_readback']
            if result['signed_receipt_sha256'] is not None:
                prev_receipts[ident]=result['signed_receipt_sha256']
                prev_receipt_generations[ident]=result.pop('_stamp_generation')
            else:
                # An absent epoch receipt must not silently skip to an older
                # predecessor; preserve the gap as a ZERO predecessor.
                prev_receipts[ident]=ZERO
                prev_receipt_generations[ident]=None
                result.pop('_stamp_generation')
            archives.append(result)
            asite+=int(result['pre_cutoff_signed_copy_readback'])
        need(seen==set(prev_receipts),'BOTH_OFFSITE_ARCHIVISTS_REQUIRED','permission_denied')
        if epoch==0:
            first_archivist_id=rolestore['offsite_archivists'][0]['role_id']
            first_receipt_sha=next(x['signed_receipt_sha256'] for x in archives
                                   if x['archivist_id']==first_archivist_id)
        grows=sorted(gossip['rows'],key=lambda x:('offer','acknowledge','confirm').index(x['stage']))
        archive_rows=sorted(archives,key=lambda x:x['archivist_id'])
        gdigest=cdigest(grows);adigest=cdigest(archive_rows)
        parent_witness_count=actual['registered_witness_epoch_reviews'][epoch]['pre_cutoff_independent_log_witnesses']
        trusted_gossip=bool(gossip['complete'] and creds_clean and
             parent_witness_count==2 and not flags[FLAGS[0]])
        trusted_archive=asite if creds_clean and trusted_gossip else 0
        if (gdigest!=opts[NEW_REPEATS[0][0]][epoch] or
            adigest!=opts[NEW_REPEATS[1][0]][epoch] or
            int(trusted_gossip)<opts[NEW_REPEATS[2][0]][epoch] or
            trusted_archive<opts[NEW_REPEATS[3][0]][epoch]):
            flags[FLAGS[1]]=True
        if asite!=2:flags[FLAGS[5]]=True
        gossip_count+=int(trusted_gossip);archive_count+=trusted_archive
        reviews.append({'epoch_index':epoch,
            'cryptographically_bounded_reciprocal_gossip_count':int(trusted_gossip),
            'verified_two_source_original_recovery_count':trusted_archive,
            'genuine_parent_observation_originals_readback':len(gossip['signed_observations']),
            'required_archived_unique_original_count':len(required),
            'reciprocal_signed_gossip_inventory_sha256':gdigest,
            'offsite_signed_recovery_inventory_sha256':adigest,
            'signed_disclosed_gossip_divergences':len(gossip['divergences'])})
        inventory_epochs.append({'epoch_index':epoch,'authenticated_witness_gossip':grows,
             'signed_offsite_receipts_and_readbacks':archive_rows,
             'observed_signed_original_sha_conflicts':gossip['divergences']})
    if first_receipt_sha!=opts[NEW_SCALARS[5]]:flags[FLAGS[1]]=True
    inventory={'schema':INVENTORY_SCHEMA,'claimed_directory_lineage_id':lineage,
      'actual_live_ec394_report_sha256':actual_sha,
      'actual_live_ec394_inventory_sha256':actual['receiver_verified_registered_witness_inventory_sha256'],
      'actual_original_ec394_registered_bundle_sha256':parentref['sha256'],
      'credential_gossip_archive_bundle_original_sha256':original['sha256'],
      'outside_retained_two_issuer_two_archivist_roster_sha256':rosterref['sha256'],
      'outside_retained_opaque_licensing_basis_sha256':licenseref['sha256'],
      'outside_retained_first_credential_sha256':opts[NEW_SCALARS[4]],
      'outside_retained_first_archival_receipt_sha256':opts[NEW_SCALARS[5]],
      'original_signed_independent_issuer_credentials':creds,
      'original_reciprocal_signed_gossip_and_archival_epochs':inventory_epochs,
      'genuine_signed_witness_observation_view_divergences':signed_gossip_divergences,
      'genuine_ec394_signed_log_fork_cases':actual['visible_signed_log_fork_cases']}
    inventory_sha=cdigest(inventory)
    if not derive and inventory_sha!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    # Bound final readback of every object observed in this receiver invocation.
    for path,(original_sha,cap) in late.items():
        current=io._read({'path':path,'sha256':original_sha},
                         'ec395_end_of_verification_original_readback',cap,{},{},set())
        need(digest(current)==original_sha,
             'SIGNED_CREDENTIAL_GOSSIP_OR_OFFSITE_COPY_CHANGED_DURING_VERIFICATION',
             'permission_denied')
    flags[FLAGS[7]]=True
    flags[FLAGS[8]]=True
    flags[FLAGS[9]]=True
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
      'command':('derive-historical-ec339-credential-gossip-archive-inventory' if derive
                 else 'audit-historical-ec339-credential-gossip-archive'),
      'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),OUTCOMES[-1])+'_unresolved',
      'exit_code':2,'offline_unresolved_exit_code':2,
      'verified_live_ec394_report_sha256':actual_sha,
      'verified_live_ec394_inventory_sha256':actual['receiver_verified_registered_witness_inventory_sha256'],
      'original_credential_gossip_archive_sha256':original['sha256'],
      'receiver_verified_credential_gossip_archive_inventory_sha256':inventory_sha,
      'original_independently_signed_credential_count':sum(int(x['bounded_before_cutoff']) for x in creds),
      'cryptographically_bounded_reciprocal_gossip_count':gossip_count,
      'cryptographically_bounded_two_site_archive_replica_count':archive_count,
      'genuine_signed_reciprocal_gossip_disclosure_conflict_count':len(signed_gossip_divergences),
      'inherited_genuinely_operator_signed_log_fork_count':actual['visible_genuine_signed_log_fork_count'],
      'credential_gossip_archive_epoch_reviews':reviews,
      'visible_genuinely_signed_reciprocal_witness_view_conflicts':signed_gossip_divergences,
      'local_credential_gossip_and_readback_consistency':not any(flags[k] for k in FLAGS[:7]),
      'sender_origin_path_required_or_read':False,
      'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
      **flags,**{k:False for k in NEGATIVES},
      **({'unsigned_credential_gossip_archive_inventory':inventory} if derive else {})}


def derive_inventory(**opts):
    return _engine(True,**opts)


def audit(**opts):
    return _engine(False,**opts)
