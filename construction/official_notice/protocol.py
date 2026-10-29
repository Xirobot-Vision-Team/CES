#!/usr/bin/env python3
"""EC398: offline, byte-accurate external notice/registrar + twin-custodian audit.

Mandatory genuine EC397 audit precedes ANY EC398 credit.  Ed25519 signatures,
parent EC396 signed subject status, RFC3161 evidence, and original/copy bytes are
checked.  A furnished 'official' notice and a registered key DO NOT authenticate
a government, legal authorization, historical public availability, or physical WORM.
No network, private signing, token issuance, or evidence writes in this module.
"""
from __future__ import annotations

from delivery_anchor import anchor as errors
from historical_authority import authority_archive as io
from publication_witness import protocol as parent

RESULT_SCHEMA = 'ces.ec398.receiver_external_notice_revocation_custody_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec398.unsigned_notice_revocation_custody_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec398.notice_revocation_custody_denial.v1'
INVENTORY_SCHEMA = 'ces.ec398.unsigned_notice_revocation_custody_inventory.v1'
BUNDLE_SCHEMA = 'ces.ec398.original_external_notice_and_dual_custody_bundle.v1'
ROSTER_SCHEMA = 'ces.ec398.external_registrar_and_two_custodians_roster.v1'
NOTICE_SCHEMA = 'ces.ec398.original_signed_registry_notice.v1'
NOTICE_CLAIM = 'ces.ec398.original_signed_registry_notice_claim.v1'
CUSTODY_SCHEMA = 'ces.ec398.original_signed_notice_custody_receipt.v1'
CUSTODY_CLAIM = 'ces.ec398.original_signed_notice_custody_claim.v1'
NOTICE_DOMAIN = b'CES/EC398/ExternallyPinnedRegistryNotice/v1\0'
CUSTODY_DOMAIN = b'CES/EC398/IndependentNoticeOriginalCustody/v1\0'
ZERO = '0'*64
MAX_BUNDLE = 380_000
MAX_ROSTER = 20_000
MAX_SIGNED = 80_000
MAX_SOURCE = 240_000

PARENT_SCALARS = (*parent.PARENT_SCALARS,*parent.NEW_SCALARS,*parent.AUDIT_ONLY)
PARENT_REPEATS = (*parent.PARENT_REPEATS,*parent.REPEAT_NAMES)
NEW_SCALARS = (
    'historical_ec339_external_notice_bundle_file',
    'expected_historical_ec339_external_notice_bundle_sha256',
    'expected_outside_retained_ec398_notice_roster_sha256',
    'expected_outside_retained_ec398_registrar_public_hex',
    'expected_outside_retained_ec398_custodian_a_public_hex',
    'expected_outside_retained_ec398_custodian_b_public_hex',
    'expected_outside_retained_ec398_first_source_notice_sha256',
    'expected_outside_retained_ec398_first_signed_notice_sha256',
    'expected_outside_retained_ec398_first_custodian_a_receipt_sha256',
    'expected_outside_retained_ec398_first_custodian_b_receipt_sha256',
)
AUDIT_ONLY = ('expected_retained_historical_ec339_external_notice_inventory_sha256',)
NEW_REPEATS = (
    ('historical_ec339_external_notice_inventory_shas',
     '--historical-ec339-external-notice-inventory-sha256'),
    ('historical_ec339_dual_notice_custody_inventory_shas',
     '--historical-ec339-dual-notice-custody-inventory-sha256'),
    ('minimum_historical_ec339_corroborated_active_notice_roles',
     '--minimum-historical-ec339-corroborated-active-notice-role-count'),
    ('minimum_historical_ec339_notice_custodian_readbacks',
     '--minimum-historical-ec339-notice-custodian-readback-count'),
)
REPEAT_NAMES = tuple(k for k,_ in NEW_REPEATS)
FLAGS = (
    'inherited_real_ec397_publication_evidence_disputed',
    'independent_outside_notice_original_shas_or_count_floors_disagree',
    'signed_notice_source_or_qualified_timestamp_missing_or_unbounded',
    'authenticated_parent_registry_and_new_notice_revocation_or_status_conflict',
    'dual_custodian_genuine_signed_three_original_readbacks_incomplete',
    'cross_epoch_notice_or_custody_time_predecessor_broken',
    'official_gazette_and_true_legal_registrar_authority_not_proven',
    'actual_pre_dispute_public_availability_or_physical_worm_not_proven',
    'complete_external_revocation_qualified_tsa_and_final_acceptance_not_proven',
)
OUTCOMES = (
    'ec398_real_parent_publication_or_fork_history_disputed',
    'ec398_independent_notice_sha_inventory_or_count_floor_disagrees',
    'ec398_signed_notice_original_or_prior_timestamp_incomplete',
    'ec398_authenticated_notice_and_parent_revocation_status_disagree',
    'ec398_dual_notice_original_custody_or_signed_receipt_incomplete',
    'ec398_signed_epoch_notice_or_custody_predecessor_unbounded',
    'ec398_official_legal_publication_and_registrar_authorization_not_proven',
    'ec398_actual_historical_public_availability_and_physical_worm_not_proven',
    'ec398_global_revocation_tsa_and_final_acceptance_not_proven',
)
NEGATIVES = (
    'externally_pinned_registrar_keys_prove_legal_government_accreditation',
    'opaque_gazette_original_proves_legally_effective_official_announcement',
    'signed_local_status_list_proves_exhaustive_crl_ocsp_or_true_revocation',
    'copied_notice_and_independent_keys_prove_pre_dispute_public_retrievability',
    'signed_custody_receipts_establish_physical_worm_or_separate_corporate_control',
    'claimed_utc_or_furnished_der_prove_qualified_tsa_or_legal_dispute_cutoff',
    'three_recovered_file_copies_exclude_globally_hidden_forks_or_source_deletions',
    'receiver_generated_new_signatures_private_keys_rfc3161_or_custody_writes',
    'receiver_queried_government_registry_network_provider_git_ci_or_ocsp',
    'native_powershell_and_unmocked_external_historical_suite_passed',
    'final_product_quality_or_user_acceptance_is_promoted',
)

BUNDLE_FIELDS = {'schema','claimed_directory_lineage_id',
 'parent_ec397_publication_bundle_original','outside_notice_roster_original','epochs'}
ROSTER_FIELDS = {'schema','claimed_directory_lineage_id','registrar','custodians'}
ROLE_FIELDS = {'role_id','site_id','public_hex','public_key_original'}
CUSTODIAN_ROLE_FIELDS = ROLE_FIELDS|{'channel_id'}
EPOCH_FIELDS = {'epoch_index','source_notice_original','notice','custodians'}
STAMP_FIELDS = {'signed_original','rfc3161_token_original'}
CUSTODY_FIELDS = {'channel_id','signed_receipt_original','rfc3161_token_original',
 'copied_source_notice_original','copied_signed_notice_original',
 'copied_parent_channel_receipt_original'}
SIGNED_FIELDS = {'schema','claim','signature_ed25519'}
SUBJECT_FIELDS = {'role_id','public_hex','status','effective_utc'}
NOTICE_CLAIM_FIELDS = {'schema','directory_lineage_id',
 'parent_ec397_bundle_sha256','parent_ec397_verified_inventory_sha256',
 'parent_ec396_signed_registry_snapshot_sha256','epoch_index',
 'notice_sequence','registrar_id','source_notice_original_sha256',
 'previous_signed_notice_original_sha256','subjects','claimed_published_utc'}
CUSTODY_CLAIM_FIELDS = {'schema','directory_lineage_id',
 'parent_ec397_bundle_sha256','parent_ec397_verified_inventory_sha256',
 'epoch_index','channel_id','custodian_id','custodian_site_id',
 'signed_notice_original_sha256','source_notice_original_sha256',
 'parent_signed_channel_receipt_original_sha256',
 'previous_custodian_receipt_original_sha256','three_original_copy_inventory_sha256',
 'claimed_archived_utc'}


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC398_'+code,status)


def exact(v,fields,code):
    need(type(v) is dict and set(v)==fields,code+'_EXACT_FIELDS_REQUIRED')


def rawref(v):return parent.rawref(v)
def valid_sha(v):return parent.valid_sha(v)
def digest(v):return parent.digest(v)
def cdigest(v):return parent.cdigest(v)
def _utc(v):return parent.parent.parent._time(v)
def _bounded(stamp,claimed,cutoff):return parent._bounded(stamp,claimed,cutoff)


def _inputs(opts,derive):
    required = set((*PARENT_SCALARS,*PARENT_REPEATS,*NEW_SCALARS,*REPEAT_NAMES))
    if not derive:required.update(AUDIT_ONLY)
    need(set(opts)==required,'COMPLETE_REAL_EC397_AND_NEW_INPUTS_REQUIRED')
    inherited={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    parent._inputs(inherited,False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],'EC398_BUNDLE')
    for k in (NEW_SCALARS[2],*NEW_SCALARS[6:]):
        need(valid_sha(opts[k]),'INDEPENDENT_SHA_PIN_REQUIRED')
    for k in NEW_SCALARS[3:6]:
        need(parent.parent.parent.prior._hexkey(opts[k]),'INDEPENDENT_RAW_PUBLIC_KEY_REQUIRED')
    need(len({opts[k] for k in NEW_SCALARS[3:6]})==3,
         'EXTERNAL_REGISTRAR_AND_CUSTODIAN_KEYS_REUSED','permission_denied')
    if not derive:need(valid_sha(opts[AUDIT_ONLY[0]]),'OUTSIDE_WHOLE_INVENTORY_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'HISTORICAL_EPOCH_COUNT_OUTSIDE_BOUND')
    for k in REPEAT_NAMES:
        vals=opts[k]
        need(type(vals) is list and len(vals)==n,'EXTERNAL_SHA_OR_COUNT_PER_EPOCH_REQUIRED')
        if k.startswith('minimum_'):
            cap=4 if 'active_notice' in k else 2
            need(all(type(v) is int and 0<=v<=cap for v in vals),
                 'EXTERNAL_FLOOR_OUTSIDE_BOUND')
        else:
            need(all(valid_sha(v) for v in vals),'EXTERNAL_EPOCH_SHA_INVALID')
    return inherited


def _parent_report(report,opts):
    common={'schema','command','status','exit_code','offline_unresolved_exit_code',
      'sender_origin_path_required_or_read',
      'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
      'verified_live_ec396_report_sha256','verified_live_ec396_inventory_sha256',
      'original_two_channel_publication_bundle_sha256',
      'receiver_verified_two_channel_publication_inventory_sha256',
      'verified_independent_signed_channel_delivery_count',
      'verified_two_channel_observation_pair_count',
      'visible_authentic_signed_public_log_fork_count','publication_epoch_reviews',
      'bounded_local_two_channel_original_integrity',*parent.FLAGS,*parent.NEGATIVES}
    n=len(opts['historical_directory_root_shas'])
    need(type(report) is dict and set(report)==common and
      report.get('schema')==parent.RESULT_SCHEMA and
      report.get('command')=='audit-historical-ec339-publication-witness' and
      report.get('exit_code')==2 and report.get('offline_unresolved_exit_code')==2 and
      report.get('sender_origin_path_required_or_read') is False and
      report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
      all(report.get(k) is False for k in parent.NEGATIVES) and
      all(type(report.get(k)) is bool for k in parent.FLAGS) and
      all(report[k] is True for k in parent.FLAGS[-3:]) and
      report.get('status')==next((parent.OUTCOMES[i] for i,k in enumerate(parent.FLAGS)
                                     if report[k]),parent.OUTCOMES[-1])+'_unresolved' and
      report.get('bounded_local_two_channel_original_integrity') is
         (not any(report[k] for k in parent.FLAGS[:6])) and
      report.get('original_two_channel_publication_bundle_sha256')==opts[parent.NEW_SCALARS[1]] and
      report.get('receiver_verified_two_channel_publication_inventory_sha256')==opts[parent.AUDIT_ONLY[0]] and
      all(valid_sha(report.get(k)) for k in ('verified_live_ec396_report_sha256',
           'verified_live_ec396_inventory_sha256')),
      'REAL_EC397_PARENT_AUDIT_SHA_STATUS_INVALID','unavailable')
    rows=report.get('publication_epoch_reviews')
    fields={'epoch_index','verified_signed_channel_deliveries',
            'verified_two_channel_observation_pair','authentic_signed_conflicting_log_heads',
            'channel_delivery_inventory_sha256','signed_fork_originals_inventory_sha256'}
    need(type(rows) is list and len(rows)==n and all(
       type(r) is dict and set(r)==fields and type(r['epoch_index']) is int and
       r['epoch_index']==i and all(type(r[k]) is int and 0<=r[k]<=cap for k,cap in (
         ('verified_signed_channel_deliveries',2),
         ('verified_two_channel_observation_pair',1),
         ('authentic_signed_conflicting_log_heads',2))) and
       all(valid_sha(r[k]) for k in ('channel_delivery_inventory_sha256',
                                     'signed_fork_originals_inventory_sha256')) and
       (r['verified_two_channel_observation_pair']!=1 or
        r['verified_signed_channel_deliveries']==2) and
       (r['authentic_signed_conflicting_log_heads']==0 or
        r['verified_signed_channel_deliveries']==0)
       for i,r in enumerate(rows)),
       'REAL_EC397_EPOCH_REVIEWS_MALFORMED','unavailable')
    for report_key,row_key in (
      ('verified_independent_signed_channel_delivery_count','verified_signed_channel_deliveries'),
      ('verified_two_channel_observation_pair_count','verified_two_channel_observation_pair'),
      ('visible_authentic_signed_public_log_fork_count','authentic_signed_conflicting_log_heads')):
        need(type(report.get(report_key)) is int and
             report[report_key]==sum(r[row_key] for r in rows),
             'REAL_EC397_COUNT_SUMS_INCORRECT','unavailable')
    return cdigest(report)


def _signed(ref,read,schema,claim_schema,claim_fields,label):
    return parent._signed(ref,read,schema,claim_schema,claim_fields,label)


def _sign(role,sig,domain,claim,label):
    parent.parent.parent._signer(role['public_hex'],sig,domain,claim,'EC398_'+label)


def _stamp(raw,ref,trust,aid,read,evaluation,cutoff,claimed,flags,flag):
    parentflags={k:False for k in parent.FLAGS}
    stamp=parent._stamp(raw,ref,trust,aid,read,evaluation,cutoff,claimed,parentflags)
    if parentflags[parent.FLAGS[2]]:flags[flag]=True
    return stamp


def _collect_sources(v,protected):
    if type(v) is dict:
        if set(v)=={'path','sha256'} and type(v['path']) is str:
            protected.add(v['path'])
        else:
            for vv in v.values():_collect_sources(vv,protected)
    elif type(v) is list:
        for vv in v:_collect_sources(vv,protected)


def _roster(roster,ref,opts,lineage,anchor,ec395,ec396,ec397,read,protected):
    exact(roster,ROSTER_FIELDS,'EXTERNAL_CUSTODY_ROSTER')
    need(roster['schema']==ROSTER_SCHEMA and
         roster['claimed_directory_lineage_id']==lineage and
         ref['sha256']==opts[NEW_SCALARS[2]] and
         type(roster['custodians']) is list and len(roster['custodians'])==2,
         'EXTERNAL_REGISTRY_AND_CUSTODY_ROSTER_NOT_PINNED','permission_denied')
    keys=set(anchor['known_keys']);sites=set(anchor['known_sites']);ids=set(anchor['known_ids'])
    for role in (*ec395['credential_issuers'],*ec395['offsite_archivists'],
                 ec396['registry_signer'],ec396['transparency_log_signer'],
                 *ec396['device_operators'],*ec397['channels']):
        keys.add(role['public_hex']);sites.add(role['site_id']);ids.add(role['role_id'])
        protected.add(rawref(role['public_key_original'])['path'])
    channels={r['channel_id'] for r in ec397['channels']}
    need(len(channels)==2,'PARENT_TWO_CHANNEL_ROSTER_INVALID','unavailable')
    mirror={}
    for i,role in enumerate((roster['registrar'],*roster['custodians'])):
        exact(role,ROLE_FIELDS if i==0 else CUSTODIAN_ROLE_FIELDS,
              'REGISTRAR_OR_CUSTODIAN_ROLE')
        need(parent.parent.parent._id(role['role_id']) and role['role_id'] not in ids and
             parent.parent.parent._id(role['site_id']) and role['site_id'] not in sites and
             parent.parent.parent.prior._hexkey(role['public_hex']) and
             role['public_hex'] not in keys,
             'REGISTRAR_CUSTODIAN_ROLE_SITE_KEY_REUSE','permission_denied')
        keyref=rawref(role['public_key_original'])
        need(keyref['path'] not in protected,'RAW_PUBLIC_KEY_PATH_REUSED','permission_denied')
        raw=read(keyref,'ec398_new_independent_raw_public_key',32)
        need(len(raw)==32 and raw.hex()==role['public_hex'] and
             role['public_hex']==opts[NEW_SCALARS[3+i]],
             'OUTSIDE_KEY_PIN_OR_RAW_PUBLIC_KEY_MISMATCH','permission_denied')
        protected.add(keyref['path'])
        keys.add(role['public_hex']);sites.add(role['site_id']);ids.add(role['role_id'])
        if i:
            need(role['channel_id'] in channels and role['channel_id'] not in mirror,
                 'TWO_EXACT_DISTINCT_PARENT_CHANNEL_CUSTODIANS_REQUIRED','permission_denied')
            mirror[role['channel_id']]=role
    need(set(mirror)==channels,'BOTH_REAL_PARENT_CHANNELS_MUST_BE_MIRRORED','permission_denied')
    return roster['registrar'],mirror


def _parent_registry(registry_entry,idx,role,read,trust,aid,evaluation,cutoff,flags):
    exact(registry_entry,parent.parent.ORIGINAL_STAMP_FIELDS,'REAL_PARENT_REGISTRY_EPOCH')
    if registry_entry['signed_original'] is None:
        need(registry_entry['rfc3161_token_original'] is None,
             'ABSENT_REAL_PARENT_REGISTRY_HAS_TOKEN','permission_denied')
        return None,None,None
    ref=rawref(registry_entry['signed_original'])
    raw,claim,sig=_signed(ref,read,parent.parent.REGISTRY_SCHEMA,
                     parent.parent.REGISTRY_CLAIM,parent.parent.REGISTRY_CLAIM_FIELDS,
                     'AUTHENTIC_PARENT_EC396_REGISTRY')
    _sign(role,sig,parent.parent.REGISTRY_DOMAIN,claim,
          'REOPENED_PARENT_SIGNED_REGISTRY')
    need(type(claim['epoch_index']) is int and claim['epoch_index']==idx,
         'REAL_PARENT_REGISTRY_EPOCH_MISMATCH','permission_denied')
    claimed=_utc(claim['claimed_snapshot_utc'])
    stamp=_stamp(raw,registry_entry['rfc3161_token_original'],trust,aid,read,
                 evaluation,cutoff,claimed,flags,FLAGS[2])
    return ref,claim,stamp


def _notice(ep,idx,role,preg_ref,preg_claim,preg_stamp,prev_sha,prev_stamp,prev_ok,
            pref,parentsha,lineage,read,trust,aid,evaluation,cutoff,flags,subject_history):
    exact(ep['notice'],STAMP_FIELDS,'NOTICE_EPOCH')
    source=ep['source_notice_original']
    if ep['notice']['signed_original'] is None:
        need(ep['notice']['rfc3161_token_original'] is None and source is None,
             'ABSENT_NOTICE_HAS_SOURCE_OR_TIMESTAMP','permission_denied')
        flags[FLAGS[2]]=True
        return {'source_notice_sha256':None,'signed_notice_sha256':None,
           'timestamp_sha256':None,'parent_registry_snapshot_sha256':
                preg_ref['sha256'] if preg_ref else None,
           'matching_signed_registry_subjects':0,'active_corroborated_roles':0,
           'signed_status_conflicts':0,'pre_cutoff_continuous':False,
           '_gen':None,'_raw':None,'_source':None}
    need(source is not None and preg_ref is not None and preg_claim is not None,
         'NOTICE_REQUIRES_REAL_PARENT_REGISTRY_AND_SOURCE','permission_denied')
    sr=rawref(source); sourcebytes=read(sr,'opaque_signed_external_source_notice',MAX_SOURCE)
    raw,claim,sig=_signed(ep['notice']['signed_original'],read,NOTICE_SCHEMA,
                 NOTICE_CLAIM,NOTICE_CLAIM_FIELDS,'EC398_SIGNED_REGISTRY_NOTICE')
    need(claim['directory_lineage_id']==lineage and
         claim['parent_ec397_bundle_sha256']==pref['sha256'] and
         claim['parent_ec397_verified_inventory_sha256']==parentsha and
         claim['parent_ec396_signed_registry_snapshot_sha256']==preg_ref['sha256'] and
         type(claim['epoch_index']) is int and claim['epoch_index']==idx and
         type(claim['notice_sequence']) is int and claim['notice_sequence']==idx+1 and
         claim['registrar_id']==role['role_id'] and
         claim['source_notice_original_sha256']==sr['sha256'] and
         claim['previous_signed_notice_original_sha256']==prev_sha,
         'NOTICE_PARENT_REGISTRY_SOURCE_OR_PREDECESSOR_INVALID','permission_denied')
    subjects=claim['subjects'];real_subjects=preg_claim['subjects']
    need(type(subjects) is list and len(subjects)==4 and
         type(real_subjects) is list and len(real_subjects)==4 and
         all(type(s) is dict and set(s)==SUBJECT_FIELDS for s in subjects) and
         all(type(s) is dict and set(s)==SUBJECT_FIELDS for s in real_subjects) and
         all(subjects[i]['role_id']==real_subjects[i]['role_id'] and
             subjects[i]['public_hex']==real_subjects[i]['public_hex']
             for i in range(4)),
         'NEW_NOTICE_CANNOT_SUBSTITUTE_REAL_EC395_ROLE_IDENTITIES','permission_denied')
    match=0;conflicts=0;latest=None;revoked_or_suspended=False;rollback=False
    for item,old in zip(subjects,real_subjects):
        need(item['status'] in ('active','suspended','revoked'),
             'NOTICE_SIGNED_ROLE_STATUS_INVALID')
        moment=_utc(item['effective_utc'])
        parentmoment=_utc(old['effective_utc'])
        if item['status']==old['status'] and moment==parentmoment:match+=1
        else:conflicts+=1
        previous=subject_history.get(item['role_id'])
        if previous is not None and (moment<previous[1] or
           (previous[0]=='revoked' and item['status']!='revoked') or
           (previous[0]=='suspended' and item['status']=='active' and moment<=previous[1])):
            rollback=True
        subject_history[item['role_id']]=(item['status'],moment)
        if item['status']!='active':revoked_or_suspended=True
        latest=moment if latest is None else max(latest,moment)
        if moment>cutoff:rollback=True
    _sign(role,sig,NOTICE_DOMAIN,claim,'AUTHENTIC_NEW_REGISTRAR_NOTICE')
    claimed=_utc(claim['claimed_published_utc'])
    stamp=_stamp(raw,ep['notice']['rfc3161_token_original'],trust,aid,read,
                 evaluation,cutoff,claimed,flags,FLAGS[2])
    good=bool(_bounded(stamp,claimed,cutoff) and preg_stamp is not None and
              _bounded(preg_stamp,_utc(preg_claim['claimed_snapshot_utc']),cutoff) and
              claimed>=preg_stamp['gen'] and latest is not None and latest<=claimed and
              (idx==0 or (prev_ok and prev_stamp is not None)) and
              (prev_stamp is None or stamp['gen']>=prev_stamp))
    if not good:flags[FLAGS[2]]=True
    if idx and (not prev_ok or prev_stamp is None):flags[FLAGS[5]]=True
    if conflicts or revoked_or_suspended or rollback:flags[FLAGS[3]]=True
    active=4 if match==4 and not revoked_or_suspended and not rollback and good else 0
    return {'source_notice_sha256':sr['sha256'],
       'signed_notice_sha256':rawref(ep['notice']['signed_original'])['sha256'],
       'timestamp_sha256':stamp['sha256'] if stamp else None,
       'parent_registry_snapshot_sha256':preg_ref['sha256'],
       'matching_signed_registry_subjects':match,'active_corroborated_roles':active,
       'signed_status_conflicts':conflicts,'pre_cutoff_continuous':good,
       '_gen':stamp['gen'] if stamp else None,'_raw':raw,'_source':sourcebytes}


def _copy_check(ref,source,name,read,protected,used):
    r=rawref(ref)
    need(r['path'] not in protected and r['path'] not in used and
         r['sha256']==digest(source),
         'CUSTODY_COPY_SOURCE_ALIAS_OR_SHA_MISMATCH','permission_denied')
    used.add(r['path'])
    copy=read(r,'independent_ec398_custodian_original_copy_'+name,
              MAX_SOURCE if name=='source_notice' else MAX_SIGNED)
    need(copy==source,'CUSTODY_COPY_BYTES_DIFFER','permission_denied')
    return {'kind':name,'source_sha256':digest(source),'copy_sha256':r['sha256'],
            'copy_path':r['path']}


def _custody(item,idx,role,parentchannel,observerrole,notice,prevsha,prevgen,prevok,
             pref,parentsha,lineage,read,trust,aid,evaluation,cutoff,flags,protected,used):
    exact(item,CUSTODY_FIELDS,'CUSTODIAN_EPOCH')
    need(item['channel_id']==role['channel_id'],
         'UNKNOWN_OR_WRONG_CUSTODIAN_CHANNEL','permission_denied')
    if item['signed_receipt_original'] is None:
        need(all(item[x] is None for x in CUSTODY_FIELDS if x not in (
             'channel_id','signed_receipt_original')),
             'ABSENT_CUSTODY_RECEIPT_WITH_TOKEN_OR_COPIES','permission_denied')
        flags[FLAGS[4]]=True
        return {'channel_id':role['channel_id'],'signed_receipt_sha256':None,
           'timestamp_sha256':None,'three_originals_recovered':0,
           'pre_cutoff_continuous_custody':False,'_gen':None}
    need(notice['_raw'] is not None and parentchannel is not None and
         parentchannel['signed_receipt_original'] is not None,
         'CUSTODIAN_REQUIRES_GENUINE_NOTICE_AND_PARENT_OBSERVER_ORIGINAL',
         'permission_denied')
    parentref=rawref(parentchannel['signed_receipt_original'])
    observerraw,observerclaim,observersig=_signed(parentref,read,parent.RECEIPT_SCHEMA,
         parent.RECEIPT_CLAIM,parent.RECEIPT_CLAIM_FIELDS,'REAL_EC397_CHANNEL_OBSERVER')
    _sign(observerrole,observersig,parent.RECEIPT_DOMAIN,observerclaim,
          'REOPENED_REAL_CHANNEL_RECEIPT_SIGNATURE')
    need(observerclaim['channel_id']==role['channel_id'] and
         type(observerclaim['epoch_index']) is int and observerclaim['epoch_index']==idx,
         'CUSTODY_PARENT_CHANNEL_RECEIPT_WRONG_EPOCH','permission_denied')
    obsclaimed=_utc(observerclaim['claimed_observed_utc'])
    obstamp=_stamp(observerraw,parentchannel['rfc3161_token_original'],trust,aid,read,
           evaluation,cutoff,obsclaimed,flags,FLAGS[4])
    refs=(('source_notice',item['copied_source_notice_original'],notice['_source']),
          ('signed_notice',item['copied_signed_notice_original'],notice['_raw']),
          ('parent_receipt',item['copied_parent_channel_receipt_original'],observerraw))
    need(all(ref is not None for _,ref,_ in refs),
         'CUSTODIAN_MISSING_THREE_COMPLETE_SOURCE_COPIES','permission_denied')
    rows=[_copy_check(ref,src,kind,read,protected,used) for kind,ref,src in refs]
    raw,claim,sig=_signed(item['signed_receipt_original'],read,CUSTODY_SCHEMA,
               CUSTODY_CLAIM,CUSTODY_CLAIM_FIELDS,'EC398_SIGNED_CUSTODIAN_RECEIPT')
    need(claim['directory_lineage_id']==lineage and
         claim['parent_ec397_bundle_sha256']==pref['sha256'] and
         claim['parent_ec397_verified_inventory_sha256']==parentsha and
         type(claim['epoch_index']) is int and claim['epoch_index']==idx and
         claim['channel_id']==role['channel_id'] and
         claim['custodian_id']==role['role_id'] and
         claim['custodian_site_id']==role['site_id'] and
         claim['signed_notice_original_sha256']==notice['signed_notice_sha256'] and
         claim['source_notice_original_sha256']==notice['source_notice_sha256'] and
         claim['parent_signed_channel_receipt_original_sha256']==parentref['sha256'] and
         claim['previous_custodian_receipt_original_sha256']==prevsha and
         claim['three_original_copy_inventory_sha256']==cdigest(rows),
         'SIGNED_CUSTODY_SOURCE_NOTICE_OR_COPY_DIGEST_INVALID','permission_denied')
    _sign(role,sig,CUSTODY_DOMAIN,claim,'AUTHENTIC_INDEPENDENT_CUSTODIAN_RECEIPT')
    claimed=_utc(claim['claimed_archived_utc'])
    stamp=_stamp(raw,item['rfc3161_token_original'],trust,aid,read,
                 evaluation,cutoff,claimed,flags,FLAGS[4])
    contiguous=bool(prevok and (idx==0 or prevgen is not None))
    ordered=bool(contiguous and notice['pre_cutoff_continuous'] and
         notice['_gen'] is not None and obstamp is not None and
         _bounded(obstamp,obsclaimed,cutoff) and
         claimed>=notice['_gen'] and claimed>=obstamp['gen'] and
         _bounded(stamp,claimed,cutoff) and
         (prevgen is None or stamp['gen']>=prevgen))
    if not contiguous:flags[FLAGS[5]]=True
    if not ordered:flags[FLAGS[4]]=True
    return {'channel_id':role['channel_id'],
       'signed_receipt_sha256':rawref(item['signed_receipt_original'])['sha256'],
       'timestamp_sha256':stamp['sha256'] if stamp else None,
       'three_originals_recovered':3,
       'pre_cutoff_continuous_custody':bool(ordered),
       '_gen':stamp['gen'] if stamp else None}


def _engine(derive,**opts):
    inherited=_inputs(opts,derive)
    actual=parent.audit(**inherited)  # REQUIRED unchanged genuine EC397->EC396->...
    verified_parent_sha=_parent_report(actual,opts)
    n=len(opts['historical_directory_root_shas'])
    lineage=opts['claimed_historical_directory_lineage_id']
    evaluation=_utc(opts['ec391_tsa_evaluation_utc'])
    cutoff=_utc(opts[parent.parent.parent.prior.parent.NEW_SCALARS[5]])
    read,doc,late=parent.parent.parent.prior._readers()
    rootref={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    bundle=doc(rootref,'original_external_registry_notice_and_two_custodians',MAX_BUNDLE)
    exact(bundle,BUNDLE_FIELDS,'EC398_EXACT_NOTICE_BUNDLE')
    pref={'path':opts[parent.NEW_SCALARS[0]],'sha256':opts[parent.NEW_SCALARS[1]]}
    need(bundle['schema']==BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id']==lineage and
         bundle['parent_ec397_publication_bundle_original']==pref and
         type(bundle['epochs']) is list and len(bundle['epochs'])==n,
         'BUNDLE_PARENT_OR_EPOCHS_NOT_REAL','permission_denied')
    pbundle=doc(pref,'real_parent_ec397_publication_bundle',parent.MAX_BUNDLE)
    exact(pbundle,parent.BUNDLE_FIELDS,'REAL_PARENT_EC397_BUNDLE')
    p396ref=rawref(pbundle['parent_ec396_public_integrity_bundle_original'])
    need(p396ref=={'path':opts[parent.parent.NEW_SCALARS[0]],
                    'sha256':opts[parent.parent.NEW_SCALARS[1]]},
         'REAL_EC397_PARENT_EC396_SOURCE_DRIFT','permission_denied')
    p396=doc(p396ref,'real_parent_ec396_public_registry_bundle',parent.parent.MAX_BUNDLE)
    p395ref=rawref(p396['parent_ec395_credential_gossip_bundle_original'])
    p395=doc(p395ref,'real_parent_ec395_credential_bundle',parent.parent.parent.MAX_BUNDLE)
    anchor=parent.parent.parent._actual_parent_source(p395,opts,read,doc)
    r395ref=rawref(p395['external_role_roster_original'])
    r395=doc(r395ref,'real_parent_ec395_role_roster',parent.parent.parent.MAX_ROSTER)
    _oldroles,k395=parent.parent.parent._roster(r395,r395ref,opts,lineage,read,
       anchor['known_keys'],anchor['known_sites'],anchor['known_ids'])
    r396ref=rawref(p396['outside_authority_roster_original'])
    r396=doc(r396ref,'real_parent_ec396_role_roster',parent.parent.MAX_ROSTER)
    _oldroles,k396=parent.parent._roster(r396,r396ref,opts,lineage,anchor,r395,read)
    r397ref=rawref(pbundle['outside_observer_roster_original'])
    r397=doc(r397ref,'real_parent_ec397_observer_roster',parent.MAX_ROSTER)
    observer_roles,k397=parent._roster(r397,r397ref,opts,lineage,r396,r395,anchor,read)
    rosterref=rawref(bundle['outside_notice_roster_original'])
    protected={rootref['path'],pref['path'],p396ref['path'],p395ref['path'],
               r395ref['path'],r396ref['path'],r397ref['path'],rosterref['path']}
    protected.update(k395);protected.update(k396);protected.update(k397)
    _collect_sources(pbundle,protected);_collect_sources(p396,protected)
    _collect_sources(p395,protected)
    roster=doc(rosterref,'three_independent_external_notice_role_origins',MAX_ROSTER)
    registrar,mirrors=_roster(roster,rosterref,opts,lineage,anchor,r395,r396,r397,
                              read,protected)
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not actual['bounded_local_two_channel_original_integrity']
    newly_signed_sources=set()
    for ep in bundle['epochs']:
        exact(ep,EPOCH_FIELDS,'NOTICE_EPOCH_PREFLIGHT')
        exact(ep['notice'],STAMP_FIELDS,'NOTICE_STAMP_PREFLIGHT')
        for ref in (ep['source_notice_original'],*ep['notice'].values()):
            if ref is not None:
                rr=rawref(ref)
                need(rr['path'] not in protected and
                     rr['path'] not in newly_signed_sources,
                     'EXTERNAL_NOTICE_SOURCE_CANNOT_ALIAS_PARENT_OR_OTHER_EPOCH',
                     'permission_denied')
                newly_signed_sources.add(rr['path'])
                protected.add(rr['path'])
        need(type(ep['custodians']) is list and len(ep['custodians'])==2,
             'TWO_CUSTODIAN_ROWS_REQUIRED')
        for c in ep['custodians']:
            exact(c,CUSTODY_FIELDS,'CUSTODY_PREFLIGHT')
            for k in ('signed_receipt_original','rfc3161_token_original'):
                if c[k] is not None:
                    rr=rawref(c[k])
                    need(rr['path'] not in protected and
                         rr['path'] not in newly_signed_sources,
                         'NEW_CUSTODIAN_SOURCE_PATH_REUSE', 'permission_denied')
                    newly_signed_sources.add(rr['path'])
                    protected.add(rr['path'])
    first_notice=None;first_source=None;first_custodians={}
    noticeprev=ZERO;prev_noticegen=None;noticeok=True
    prev_receipts={cid:ZERO for cid in mirrors}
    prev_gens={cid:None for cid in mirrors}
    prev_ok={cid:True for cid in mirrors}
    used_copies=set();history={};reviews=[];inventory_epochs=[]
    total_active=total_reads=total_conflicts=0
    for idx,ep in enumerate(bundle['epochs']):
        need(type(ep['epoch_index']) is int and ep['epoch_index']==idx,
             'NOTICE_EPOCHS_NOT_CONTIGUOUS','permission_denied')
        p396ep=p396['epochs'][idx];p397ep=pbundle['epochs'][idx]
        regref,regclaim,regstamp=_parent_registry(p396ep['registry'],idx,
          r396['registry_signer'],read,anchor['trust'],anchor['authority'],
          evaluation,cutoff,flags)
        notice=_notice(ep,idx,registrar,regref,regclaim,regstamp,
          noticeprev,prev_noticegen,noticeok,pref,
          actual['receiver_verified_two_channel_publication_inventory_sha256'],
          lineage,read,anchor['trust'],anchor['authority'],evaluation,cutoff,flags,history)
        if idx==0:
            first_source=notice['source_notice_sha256']
            first_notice=notice['signed_notice_sha256']
        noticeprev=notice['signed_notice_sha256'] or ZERO
        prev_noticegen=notice['_gen']
        if not notice['pre_cutoff_continuous']:noticeok=False
        # The EC397 parent observer originals must be those audited in the parent,
        # not arbitrary receipts furnished by a new custodian.
        parent_channels=p397ep['channels']
        need(type(parent_channels) is list and len(parent_channels)==2 and
             all(type(x) is dict and x.get('channel_id') in mirrors for x in parent_channels) and
             len({x['channel_id'] for x in parent_channels})==2,
             'REAL_PARENT_BOTH_CHANNEL_ORIGINALS_REQUIRED','unavailable')
        realchannels={c['channel_id']:c for c in parent_channels}
        rows=[];seen=set();credit=0
        for row in ep['custodians']:
            need(type(row) is dict and row.get('channel_id') in mirrors and
                 row['channel_id'] not in seen,
                 'CUSTODIAN_CHANNEL_UNRECOGNIZED_OR_DUPLICATE','permission_denied')
            channel=row['channel_id'];seen.add(channel)
            info=_custody(row,idx,mirrors[channel],realchannels[channel],
                 observer_roles[channel],notice,prev_receipts[channel],
                 prev_gens[channel],prev_ok[channel],pref,
                 actual['receiver_verified_two_channel_publication_inventory_sha256'],
                 lineage,read,anchor['trust'],anchor['authority'],
                 evaluation,cutoff,flags,protected,used_copies)
            if idx==0:first_custodians[channel]=info['signed_receipt_sha256']
            prev_receipts[channel]=info['signed_receipt_sha256'] or ZERO
            prev_gens[channel]=info.pop('_gen')
            if not info['pre_cutoff_continuous_custody'] or not noticeok:
                prev_ok[channel]=False
            info['pre_cutoff_continuous_custody']=bool(prev_ok[channel])
            if (info['pre_cutoff_continuous_custody'] and
                notice['active_corroborated_roles']==4 and
                actual['publication_epoch_reviews'][idx]['verified_two_channel_observation_pair']==1 and
                not flags[FLAGS[0]] and not flags[FLAGS[3]]):
                credit+=1
            rows.append(info)
        need(seen==set(mirrors),'TWO_DISTINCT_CUSTODIAN_CHANNELS_REQUIRED','permission_denied')
        rows.sort(key=lambda x:x['channel_id'])
        noticepublic={k:v for k,v in notice.items() if not k.startswith('_')}
        inventory_notice=cdigest(noticepublic)
        inventory_custody=cdigest(rows)
        active=notice['active_corroborated_roles'] if (not flags[FLAGS[0]] and
                 not flags[FLAGS[3]] and noticeok and
                 actual['publication_epoch_reviews'][idx]['verified_two_channel_observation_pair']==1) else 0
        if (inventory_notice!=opts[REPEAT_NAMES[0]][idx] or
            inventory_custody!=opts[REPEAT_NAMES[1]][idx] or
            active<opts[REPEAT_NAMES[2]][idx] or
            credit<opts[REPEAT_NAMES[3]][idx]):
            flags[FLAGS[1]]=True
        total_active+=active;total_reads+=credit;total_conflicts+=notice['signed_status_conflicts']
        reviews.append({'epoch_index':idx,'verified_corroborated_active_role_count':active,
            'verified_independent_three_original_custody_count':credit,
            'genuine_signed_registry_subject_conflicts':notice['signed_status_conflicts'],
            'notice_originals_inventory_sha256':inventory_notice,
            'custody_original_readback_inventory_sha256':inventory_custody})
        inventory_epochs.append({'epoch_index':idx,'notice':noticepublic,'custodians':rows})
    if ([first_source,first_notice,first_custodians.get(roster['custodians'][0]['channel_id']),
         first_custodians.get(roster['custodians'][1]['channel_id'])]!=
         [opts[NEW_SCALARS[i]] for i in range(6,10)]):
        flags[FLAGS[1]]=True
    inventory={'schema':INVENTORY_SCHEMA,'directory_lineage_id':lineage,
       'verified_live_ec397_report_sha256':verified_parent_sha,
       'true_parent_ec397_bundle_sha256':pref['sha256'],
       'true_parent_ec397_verified_inventory_sha256':
          actual['receiver_verified_two_channel_publication_inventory_sha256'],
       'outside_retained_notice_and_custodian_roster_sha256':rosterref['sha256'],
       'outside_retained_first_source_and_signatures_sha256':
          [opts[NEW_SCALARS[i]] for i in range(6,10)],
       'epochs':inventory_epochs}
    inventory_sha=cdigest(inventory)
    if not derive and inventory_sha!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    for path,(sha,cap) in late.items():
        raw=io._read({'path':path,'sha256':sha},
            'ec398_final_source_original_byte_integrity_recheck',cap,{},{},set())
        need(digest(raw)==sha,'INPUT_OR_COPY_CHANGED_DURING_EVALUATION',
             'permission_denied')
    for k in FLAGS[-3:]:flags[k]=True
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
      'command':('derive-historical-ec339-external-notice-inventory' if derive else
                 'audit-historical-ec339-external-notice'),
      'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                    OUTCOMES[-1])+'_unresolved',
      'exit_code':2,'offline_unresolved_exit_code':2,
      'verified_live_ec397_report_sha256':verified_parent_sha,
      'verified_live_ec397_inventory_sha256':
           actual['receiver_verified_two_channel_publication_inventory_sha256'],
      'original_external_notice_bundle_sha256':rootref['sha256'],
      'receiver_verified_external_notice_inventory_sha256':inventory_sha,
      'verified_corroborated_active_notice_role_count':total_active,
      'verified_two_channel_three_original_custody_count':total_reads,
      'visible_genuine_signed_registry_conflict_count':total_conflicts,
      'external_notice_epoch_reviews':reviews,
      'bounded_local_external_notice_and_custody_consistency':
                      not any(flags[k] for k in FLAGS[:6]),
      'sender_origin_path_required_or_read':False,
      'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
      **flags,**{k:False for k in NEGATIVES},
      **({'unsigned_external_notice_inventory':inventory} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
