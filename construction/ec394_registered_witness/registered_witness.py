#!/usr/bin/env python3
"""EC394: receiver-only, externally registered custody keys + third-party fork witness.

The existing *real* EC393 receiver is invoked, not fed a supplied verdict.
This component can validate original Ed25519 signatures, exact-byte RFC3161
DER tokens, offline CRLs and signed log forks; it cannot independently certify
legal entities, physical site separation, real-world cutoff authority or WORM.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec350_tsa_timestamp import timestamp as tsa
from ec353_transparency import transparency as tr
from ec372_historical_authority import authority_archive as io
from ec393_custody_anchor import custody_anchor as parent

RESULT_SCHEMA='ces.ec394.receiver_registered_custody_and_independent_fork_witness_unresolved.v1'
DERIVE_SCHEMA='ces.ec394.unsigned_registration_witness_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec394.registered_witness_denial.v1'
BUNDLE_SCHEMA='ces.ec394.original_registered_custody_and_witness_bundle.v1'
ROSTER_SCHEMA='ces.ec394.original_external_registrar_dispute_and_witness_roster.v1'
REGISTRATION_SCHEMA='ces.ec394.original_registrar_signed_site_key_registration.v1'
REGISTRATION_CLAIM_SCHEMA='ces.ec394.original_site_key_registration_claim.v1'
WITNESS_SCHEMA='ces.ec394.original_independent_signed_log_witness.v1'
WITNESS_CLAIM_SCHEMA='ces.ec394.original_independent_log_witness_claim.v1'
NOTICE_SCHEMA='ces.ec394.original_signed_dispute_notice.v1'
NOTICE_CLAIM_SCHEMA='ces.ec394.original_dispute_notice_claim.v1'
KEY_STATUS_SCHEMA='ces.ec394.original_signed_independent_key_status_snapshot.v1'
KEY_STATUS_CLAIM_SCHEMA='ces.ec394.original_independent_key_status_claim.v1'
KEY_STATUS_DOMAIN=b'CES/EC394/IndependentKeyStatusSnapshot/v1\0'
INVENTORY_SCHEMA='ces.ec394.unsigned_registration_witness_inventory.v1'
REGISTRAR_DOMAIN=b'CES/EC394/SiteKeyRegistration/IndependentRegistrar/v1\0'
OLD_KEY_DOMAIN=b'CES/EC394/SiteKeyRegistration/OldKeyConsent/v1\0'
NEW_KEY_DOMAIN=b'CES/EC394/SiteKeyRegistration/NewKeyConsent/v1\0'
WITNESS_DOMAIN=b'CES/EC394/ThirdPartySignedLogObservation/v1\0'
NOTICE_DOMAIN=b'CES/EC394/DisputeCutoffThirdPartyNotice/v1\0'
ZERO='0'*64
MAX_BUNDLE=110_000
MAX_ROSTER=20_000
MAX_ORIGINAL=18_000
MAX_CASE_FILE=100_000
PARENT_SCALARS=(*parent.PARENT_SCALARS,*parent.NEW_SCALARS,*parent.AUDIT_ONLY)
PARENT_REPEATS=(*parent.PARENT_REPEATS,*parent.REPEAT_NAMES)
NEW_SCALARS=(
 'historical_ec339_registered_witness_bundle_file',
 'expected_historical_ec339_registered_witness_bundle_sha256',
 'expected_outside_retained_ec394_trust_roster_sha256',
 'expected_outside_retained_ec394_tsa_registry_sha256',
 'expected_outside_retained_ec394_prior_witness_original_sha256',
 'expected_outside_retained_ec394_dispute_notice_original_sha256',
 'expected_outside_retained_ec394_registrar_public_hex',
 'expected_outside_retained_ec394_dispute_authority_public_hex',
)
AUDIT_ONLY=('expected_retained_historical_ec339_registered_witness_inventory_sha256',)
NEW_REPEATS=(
 ('historical_ec339_site_registration_inventory_shas',
  '--historical-ec339-site-registration-inventory-sha256'),
 ('historical_ec339_third_party_witness_inventory_shas',
  '--historical-ec339-third-party-witness-inventory-sha256'),
 ('minimum_historical_ec339_pre_handoff_registered_site_counts',
  '--minimum-historical-ec339-pre-handoff-registered-site-count'),
 ('minimum_historical_ec339_pre_cutoff_witness_counts',
  '--minimum-historical-ec339-pre-cutoff-witness-count'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
FLAGS=(
 'inherited_real_ec393_counter_signatures_or_timestamp_disputed',
 'outside_retained_registration_witness_original_pins_or_floors_disagree',
 'registered_site_key_generation_or_original_missing',
 'site_key_rotation_history_or_signed_handoff_window_inconsistent',
 'third_party_signed_same_sequence_log_fork_visible',
 'independent_witness_timestamp_missing_late_or_disagrees_with_signed_head',
 'offline_notary_or_witness_tsa_crl_stale_revoked_or_unavailable',
 'externally_accredited_registrar_real_custody_site_or_cutoff_authority_unproven',
 'independent_offsite_original_retention_qualified_tsa_worm_unproven',
 'global_forks_full_key_revocation_ocsp_and_final_acceptance_unproven',
)
OUTCOMES=(
 'ec394_inherited_ec393_custody_and_crossview_history_disputed',
 'ec394_outside_retained_registered_originals_or_epoch_floors_disagree',
 'ec394_original_site_key_registration_missing',
 'ec394_registered_key_rotation_or_original_handoff_window_inconsistent',
 'ec394_genuinely_signed_and_third_party_witnessed_log_fork_visible',
 'ec394_witness_time_or_claim_disagrees_with_authentic_signed_log_head',
 'ec394_furnished_notarial_crl_revocation_or_freshness_unresolved',
 'ec394_real_legal_site_registrar_and_cutoff_authority_not_certified',
 'ec394_actual_prior_offsite_storage_and_accredited_tsa_not_proven',
 'ec394_complete_global_fork_revocation_or_product_acceptance_not_proven',
)
NEGATIVES=(
 'self_supplied_registrar_roster_is_official_legal_site_registration',
 'distinct_ed25519_signers_establish_legal_organizational_independence',
 'registrar_signed_key_chain_proves_exhaustive_unrevoked_key_history',
 'third_party_witness_signature_proves_global_absence_of_hidden_log_forks',
 'caller_sha_pin_proves_prior_outside_retention_or_valid_dispute_notice',
 'rfc3161_timestamp_and_supplied_crls_prove_qualified_utc_or_live_ocsp',
 'signed_notice_establishes_externally_verified_judicial_dispute_cutoff',
 'receipt_or_registration_claimed_utc_establishes_real_world_signing_time',
 'remote_cas_worm_physical_custody_site_checked_by_receiver',
 'receiver_created_registrar_receipt_witness_signature_or_rfc3161_token',
 'receiver_performed_network_provider_git_ci_powershell_or_evidence_write',
 'underlying_ec339_issuer_authority_or_final_product_quality_was_promoted',
 'unmocked_ec390_to_ec317_production_corpus_and_final_acceptance_proven',
)
BUNDLE_FIELDS={'schema','claimed_directory_lineage_id','parent_ec393_custody_bundle_original',
 'external_trust_roster_original','witness_tsa_registry_original',
 'original_dispute_case_file','signed_dispute_notice_original',
 'dispute_notice_rfc3161_token_original','key_status_snapshot_original',
 'key_status_snapshot_rfc3161_token_original','witness_tsa_authority_id',
 'site_key_histories','epochs'}
ROSTER_FIELDS={'schema','claimed_directory_lineage_id','registrar','dispute_authority','witnesses'}
ROLE_FIELDS={'role_id','site_id','public_hex','public_key_original'}
HISTORY_FIELDS={'observer_id','role','party_id','site_id','registered_site_identity_original',
 'generations'}
GENERATION_FIELDS={'signed_site_key_registration_original','registered_public_key_original',
 'rfc3161_registration_token_original'}
REG_FIELDS={'schema','claim','registrar_signature_ed25519',
 'previous_key_signature_ed25519','new_key_signature_ed25519'}
REG_CLAIM_FIELDS={'schema','directory_lineage_id','parent_ec393_roster_original_sha256',
 'registrar_id','observer_id','role','party_id','site_id','site_registry_reference_sha256',
 'registration_sequence','registered_public_hex','previous_registration_original_sha256',
 'claimed_registered_utc','effective_from_utc','effective_until_utc'}
NOTICE_FIELDS={'schema','claim','authority_signature_ed25519'}
KEY_STATUS_FIELDS={'schema','claim','authority_signature_ed25519'}
KEY_STATUS_CLAIM_FIELDS={'schema','directory_lineage_id','authority_id',
 'external_trust_roster_original_sha256','ec393_custody_roster_original_sha256',
 'signed_dispute_notice_original_sha256','declared_status_utc','key_statuses'}
KEY_STATUS_ROW_FIELDS={'subject_id','public_hex','status','claimed_change_utc'}
NOTICE_CLAIM_FIELDS={'schema','directory_lineage_id','authority_id',
 'parent_ec393_custody_bundle_original_sha256','external_dispute_case_file_original_sha256',
 'declared_dispute_cutoff_utc','claimed_notice_issued_utc'}
EPOCH_FIELDS={'epoch_index','witnesses'}
WITNESS_GROUP_FIELDS={'witness_id','observations'}
OBS_FIELDS={'signed_witness_observation_original','rfc3161_witness_token_original',
 'observed_signed_log_head_original'}
WITNESS_FIELDS={'schema','claim','witness_signature_ed25519'}
WITNESS_CLAIM_FIELDS={'schema','directory_lineage_id','witness_id','witness_site_id',
 'parent_ec393_roster_original_sha256','signed_dispute_notice_original_sha256',
 'epoch_index','observed_log_id','observed_signed_log_head_original_sha256',
 'observed_log_tree_size','observed_log_merkle_root_sha256','claimed_observed_utc'}


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC394_'+code,status)


def exact(obj,fields,code):
    need(type(obj) is dict and set(obj)==set(fields),code+'_EXACT_FIELDS_REQUIRED')


def _ident(x):
    return type(x) is str and parent.prior.prior.IDENT.fullmatch(x) is not None


def _sha(x):return tr._sha(x)


def _hexkey(x):
    return type(x) is str and parent.prior.prior.HEX64.fullmatch(x) is not None and x!='00'*32


def _utc(x):
    need(type(x) is str and parent.prior.prior.old338._utc(x),
         'CANONICAL_UTC_REQUIRED')
    return tsa._utc(x)


def _signed(pub,signature,domain,claim,role):
    need(_hexkey(pub) and type(signature) is str and len(signature)==128 and
         all(ch in '0123456789abcdef' for ch in signature),
         role+'_SIGNATURE_FORMAT_INVALID','permission_denied')
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(
            bytes.fromhex(signature),domain+canonical.canonical(claim))
    except (InvalidSignature,TypeError,ValueError) as exc:
        raise errors.AnchorError('EC394_'+role+'_INVALID_GENUINE_SIGNATURE',
                                 'permission_denied') from exc


def _inputs(opts,derive):
    expected=set((*PARENT_SCALARS,*PARENT_REPEATS,*NEW_SCALARS,*REPEAT_NAMES))
    if not derive:expected.update(AUDIT_ONLY)
    need(set(opts)==expected,'EXACT_PARENT_AND_EC394_INPUTS_REQUIRED')
    inherited={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    parent._inputs(inherited,False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                           'EC394_BUNDLE')
    for k in NEW_SCALARS[2:6]:need(_sha(opts[k]),'RETAINED_ORIGINAL_SHA_REQUIRED')
    for k in NEW_SCALARS[6:]:need(_hexkey(opts[k]),'OUTSIDE_REGISTERED_KEY_PIN_INVALID')
    if not derive:need(_sha(opts[AUDIT_ONLY[0]]),'RETAINED_WHOLE_INVENTORY_SHA_INVALID')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'ONE_TO_THREE_HISTORICAL_EPOCHS_REQUIRED')
    for k in REPEAT_NAMES:
        vals=opts[k]
        need(type(vals) is list and len(vals)==n,'ONE_REGISTERED_ORIGINAL_INVENTORY_PER_EPOCH')
        if k.startswith('minimum_'):
            need(all(type(x) is int and 0<=x<=(4 if 'site' in k else 2) for x in vals),
                 'PER_EPOCH_REGISTRATION_OR_WITNESS_MINIMUM_INVALID')
        else:need(all(_sha(x) for x in vals),'ORIGINAL_EPOCH_INVENTORY_SHA_INVALID')
    return inherited


def _parent_report(doc,opts):
    fields={'schema','command','status','exit_code','offline_unresolved_exit_code',
      'verified_live_ec392_report_sha256','verified_live_ec392_inventory_sha256',
      'historical_custody_anchor_original_sha256',
      'receiver_verified_custody_anchor_inventory_sha256',
      'cryptographically_bounded_pre_cutoff_handoff_count',
      'valid_distinct_dual_countersigned_conflict_count',
      'signed_log_prior_and_current_sha256',
      'signed_rfc6962_append_only_extension_verified',
      'custody_anchor_epoch_reviews','visible_custody_conflict_cases',
      'local_custody_counter_signatures_log_and_timestamps_consistent',
      'sender_origin_path_required_or_read',
      'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
      *parent.FLAGS,*parent.NEGATIVES}
    need(type(doc) is dict and set(doc)==fields and doc.get('schema')==parent.RESULT_SCHEMA and
        doc.get('command')=='audit-historical-ec339-custody-anchor' and
        doc.get('exit_code')==2 and doc.get('offline_unresolved_exit_code')==2 and
        doc.get('historical_custody_anchor_original_sha256')==opts[parent.NEW_SCALARS[1]] and
        doc.get('sender_origin_path_required_or_read') is False and
        doc.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
        all(doc.get(k) is False for k in parent.NEGATIVES) and
        all(type(doc.get(k)) is bool for k in parent.FLAGS) and
        all(doc[k] is True for k in parent.FLAGS[-2:]) and
        type(doc.get('local_custody_counter_signatures_log_and_timestamps_consistent')) is bool and
        doc['local_custody_counter_signatures_log_and_timestamps_consistent']==(
            not any(doc[k] for k in parent.FLAGS[:8])) and
        type(doc.get('signed_rfc6962_append_only_extension_verified')) is bool and
        doc.get('status')==next((parent.OUTCOMES[i] for i,k in enumerate(parent.FLAGS)
           if doc[k]),parent.OUTCOMES[-1])+'_unresolved' and
        all(_sha(doc.get(k)) for k in ('verified_live_ec392_report_sha256',
          'verified_live_ec392_inventory_sha256','receiver_verified_custody_anchor_inventory_sha256')),
        'ACTUAL_FULL_EC393_SIGNED_CUSTODY_AUDIT_REQUIRED','unavailable')
    n=len(opts['historical_directory_root_shas'])
    heads=doc['signed_log_prior_and_current_sha256']
    reviews=doc['custody_anchor_epoch_reviews'];cases=doc['visible_custody_conflict_cases']
    need(type(heads) is list and len(heads)==2 and
        all(h is None or _sha(h) for h in heads) and
        type(reviews) is list and len(reviews)==n and
        type(cases) is list and len(cases)<=4*n and
        all(type(r) is dict and set(r)=={
             'epoch_index','pre_cutoff_log_anchored_handoff_count',
             'genuine_double_countersigned_conflict_cases',
             'countersigned_receipt_inventory_sha256','rfc6962_inclusion_inventory_sha256'} and
             r['epoch_index']==i and type(r['epoch_index']) is int and
             all(type(r[x]) is int and 0<=r[x]<=4 for x in (
                 'pre_cutoff_log_anchored_handoff_count',
                 'genuine_double_countersigned_conflict_cases')) and
             all(_sha(r[x]) for x in ('countersigned_receipt_inventory_sha256',
                                    'rfc6962_inclusion_inventory_sha256'))
             for i,r in enumerate(reviews)) and
        doc['cryptographically_bounded_pre_cutoff_handoff_count']==sum(
          r['pre_cutoff_log_anchored_handoff_count'] for r in reviews) and
        doc['valid_distinct_dual_countersigned_conflict_count']==sum(
          r['genuine_double_countersigned_conflict_cases'] for r in reviews),
        'EC393_SOURCE_EPOCH_COUNTS_OR_HEADS_INVALID','unavailable')
    return parent.sha(canonical.canonical(doc))


def _readers():
    read,doc,late=parent._reader()
    return read,doc,late


def _roster(roster,roster_ref,opts,lineage,read,parent_keys):
    exact(roster,ROSTER_FIELDS,'EXTERNAL_ROLE_ROSTER')
    need(roster['schema']==ROSTER_SCHEMA and
         roster['claimed_directory_lineage_id']==lineage and
         roster_ref['sha256']==opts[NEW_SCALARS[2]],
         'OUTSIDE_INDEPENDENT_ROSTER_PIN_DISAGREES','permission_denied')
    roles={};keys=set(parent_keys);ids=set();sites=set();paths=set()
    for name,entry in [('registrar',roster['registrar']),
                       ('dispute_authority',roster['dispute_authority'])]:
        exact(entry,ROLE_FIELDS,'REGISTERED_'+name.upper())
        roles[name]=entry
    need(type(roster['witnesses']) is list and len(roster['witnesses'])==2,
         'EXACTLY_TWO_INDEPENDENT_FORK_WITNESSES_REQUIRED')
    for w in roster['witnesses']:
        exact(w,ROLE_FIELDS,'FORK_WITNESS')
        need(_ident(w['role_id']) and w['role_id'] not in ids and
             _ident(w['site_id']) and w['site_id'] not in sites and
             _hexkey(w['public_hex']) and w['public_hex'] not in keys,
             'WITNESS_IDENTITIES_SITES_AND_PUBLIC_KEYS_MUST_DIFFER',
             'permission_denied')
        raw=read(w['public_key_original'],'signed_external_role_key',32)
        need(len(raw)==32 and raw.hex()==w['public_hex'] and
             w['public_key_original']['path'] not in paths,
             'ROLE_RAW_PUBLIC_KEY_COPY_DISAGREES_OR_PATH_ALIASES',
             'permission_denied')
        keys.add(w['public_hex']);ids.add(w['role_id']);sites.add(w['site_id'])
        paths.add(w['public_key_original']['path'])
    for name in ('registrar','dispute_authority'):
        w=roles[name]
        need(_ident(w['role_id']) and w['role_id'] not in ids and
             _ident(w['site_id']) and w['site_id'] not in sites and
             _hexkey(w['public_hex']) and w['public_hex'] not in keys,
             'REGISTERED_AUTHORITY_ID_SITE_AND_KEY_MUST_BE_INDEPENDENT',
             'permission_denied')
        raw=read(w['public_key_original'],'independent_authority_key',32)
        need(len(raw)==32 and raw.hex()==w['public_hex'] and
             w['public_key_original']['path'] not in paths,
             'REGISTERED_AUTHORITY_RAW_KEY_ORIGINAL_INVALID',
             'permission_denied')
        keys.add(w['public_hex']);ids.add(w['role_id']);sites.add(w['site_id'])
        paths.add(w['public_key_original']['path'])
    need(roles['registrar']['public_hex']==opts[NEW_SCALARS[6]] and
         roles['dispute_authority']['public_hex']==opts[NEW_SCALARS[7]],
         'RETAINED_REGISTRAR_AND_DISPUTE_PUBLIC_KEY_PINS_DISAGREE',
         'permission_denied')
    return {**roles,'witnesses':{w['role_id']:w for w in roster['witnesses']},
            'sites':sites,'key_paths':paths}


def _timestamp(raw,token_ref,trust,aid,read,evaluation,cutoff,claimed,flags):
    if token_ref is None:
        flags[FLAGS[5]]=True
        return None
    need(aid in trust,'INDEPENDENT_WITNESS_TSA_AUTHORITY_NOT_REGISTERED',
         'permission_denied')
    data=read(token_ref,'original_rfc3161_timestamp_token_der',parent.prior.MAX_DER)
    authority=trust[aid]
    verified=tsa._tsa_token(data,raw,authority['root'],authority['policy'])
    crl=tsa._check_crls(verified['certificate_path'],authority['crls'],
                         verified['token_gen_time'],evaluation)
    gen=verified['token_gen_time']
    clean=(not crl['revoked_at_or_before_gen_time'] and
           crl['all_chain_edges_have_single_fresh_crl_as_furnished'])
    if not clean:flags[FLAGS[6]]=True
    if gen>evaluation or gen<claimed or (cutoff is not None and gen>cutoff):
        flags[FLAGS[5]]=True
    return {'sha256':token_ref['sha256'],'gen':gen,'clean':clean,
            'gen_utc':gen.isoformat(timespec='seconds').replace('+00:00','Z')}


def _notice(bundle,roles,read,doc,lineage,parent_bundle_sha,cutoff,trust,aid,evaluation,flags):
    ref=bundle['signed_dispute_notice_original']
    source=bundle['original_dispute_case_file']
    if ref is None or source is None:
        flags[FLAGS[5]]=True
        return None
    raw=read(ref,'original_signed_dispute_cutoff_notice',MAX_ORIGINAL)
    obj=tr.strict_json(raw,'EC394_DISPUTE_NOTICE')
    exact(obj,NOTICE_FIELDS,'SIGNED_DISPUTE_CUTOFF_NOTICE')
    claim=obj['claim'];exact(claim,NOTICE_CLAIM_FIELDS,'NOTICE_CLAIM')
    need(obj['schema']==NOTICE_SCHEMA and claim['schema']==NOTICE_CLAIM_SCHEMA and
         claim['directory_lineage_id']==lineage and
         claim['authority_id']==roles['dispute_authority']['role_id'] and
         claim['parent_ec393_custody_bundle_original_sha256']==parent_bundle_sha and
         _sha(claim['external_dispute_case_file_original_sha256']) and
         _utc(claim['declared_dispute_cutoff_utc'])==cutoff and
         claim['external_dispute_case_file_original_sha256']==source['sha256'] and
         ref['sha256']==bundle['_notice_pin'],
         'SIGNED_DISPUTE_NOTICE_ORIGINAL_BOUND_TO_DIFFERENT_CUTOFF',
         'permission_denied')
    issued=_utc(claim['claimed_notice_issued_utc'])
    _signed(roles['dispute_authority']['public_hex'],obj['authority_signature_ed25519'],
            NOTICE_DOMAIN,claim,'DISPUTE_AUTHORITY')
    read(source,'untrusted_external_case_file_opaque_bytes',MAX_CASE_FILE)
    token=_timestamp(raw,bundle['dispute_notice_rfc3161_token_original'],
       trust,aid,read,evaluation,None,issued,flags)
    return {'sha256':ref['sha256'],'claim':claim,'issued':issued,'token':token}


def _registration(ref,pubref,registrar,read,lineage,roster_sha,expect,sequence,prev,site_sha=None):
    raw=read(ref,'original_signed_registered_site_key',MAX_ORIGINAL)
    obj=tr.strict_json(raw,'EC394_SITE_REGISTRATION')
    exact(obj,REG_FIELDS,'SITE_REGISTRAR_SIGNED_REGISTRATION')
    claim=obj['claim'];exact(claim,REG_CLAIM_FIELDS,'SITE_KEY_REGISTRATION_CLAIM')
    need(obj['schema']==REGISTRATION_SCHEMA and
         claim['schema']==REGISTRATION_CLAIM_SCHEMA and
         claim['directory_lineage_id']==lineage and
         claim['parent_ec393_roster_original_sha256']==roster_sha and
         claim['registrar_id']==registrar['role_id'] and
         all(claim[k]==expect[k] for k in ('observer_id','role','party_id','site_id')) and
         _sha(claim['site_registry_reference_sha256']) and
         (site_sha is None or site_sha==claim['site_registry_reference_sha256']) and
         type(claim['registration_sequence']) is int and
         claim['registration_sequence']==sequence and
         claim['previous_registration_original_sha256']==(
             prev['sha256'] if prev else ZERO) and
         _hexkey(claim['registered_public_hex']),
         'REGISTERED_KEY_IDENTITY_PREDECESSOR_OR_ORIGINAL_INVALID',
         'permission_denied')
    pub=read(pubref,'original_registered_raw_key_generation',32)
    need(len(pub)==32 and pub.hex()==claim['registered_public_hex'],
         'REGISTERED_GENERATION_RAW_KEY_MISMATCH','permission_denied')
    registered=_utc(claim['claimed_registered_utc'])
    start=_utc(claim['effective_from_utc']);end=_utc(claim['effective_until_utc'])
    need(registered<=start<end,
         'KEY_REGISTRATION_CLAIMED_TIME_AND_EFFECTIVE_WINDOW_INVALID',
         'permission_denied')
    _signed(registrar['public_hex'],obj['registrar_signature_ed25519'],
            REGISTRAR_DOMAIN,claim,'INDEPENDENT_REGISTRAR')
    if prev is None:
        need(obj['previous_key_signature_ed25519'] is None and
             obj['new_key_signature_ed25519'] is None,
             'GENESIS_REGISTRATION_MUST_NOT_FORGE_ROTATION_CONSENTS',
             'permission_denied')
    else:
        need(prev['key']!=claim['registered_public_hex'] and
             start>=prev['start'] and registered>=prev['registered'] and
             start==prev['end'],
             'KEY_ROTATION_REUSES_KEY_OR_ROLLS_BACK_REGISTRATION_WINDOW',
             'permission_denied')
        _signed(prev['key'],obj['previous_key_signature_ed25519'],
                OLD_KEY_DOMAIN,claim,'PREVIOUS_KEY_ROTATION_CONSENT')
        _signed(claim['registered_public_hex'],obj['new_key_signature_ed25519'],
                NEW_KEY_DOMAIN,claim,'NEW_KEY_ROTATION_CONSENT')
    return {'sha256':ref['sha256'],'key':claim['registered_public_hex'],
       'registered':registered,'start':start,'end':end,
       'ref':ref,'claim':claim,'raw':raw}


def _histories(bundle,roster,roles,read,lineage,flags,trust,aid,evaluation,cutoff,forbidden_keys):
    histories=bundle['site_key_histories']
    need(type(histories) is list and len(histories)==4,
         'ALL_FOUR_EC393_CUSTODY_PARTIES_REQUIRE_HISTORY')
    mapping={};allrefs=[];seen_generation_keys=set()
    expected={(p['observer_id'],p['role']):p for p in roster['custody_parties']}
    for entry in histories:
        exact(entry,HISTORY_FIELDS,'SITE_CUSTODY_HISTORY')
        ident=(entry['observer_id'],entry['role'])
        need(ident in expected and ident not in mapping,
             'SITE_REGISTRATION_ROLES_NOT_DISTINCT','permission_denied')
        party=expected[ident]
        need(entry['party_id']==party['party_id'] and
             entry['site_id']==party['site_id'] and
             type(entry['generations']) is list and
             0<=len(entry['generations'])<=3,
             'SITE_HISTORY_ID_OR_KEY_GENERATION_COUNT_INVALID',
             'permission_denied')
        identityref=entry['registered_site_identity_original']
        need(identityref is not None,'INDEPENDENT_SITE_IDENTITY_ORIGINAL_REQUIRED',
             'permission_denied')
        read(identityref,'untrusted_opaque_original_site_registration',MAX_CASE_FILE)
        allrefs.append(identityref)
        prev=None;generations=[]
        for seq,link in enumerate(entry['generations'],1):
            exact(link,GENERATION_FIELDS,'SITE_KEY_HISTORY_GENERATION')
            regref=link['signed_site_key_registration_original']
            pubref=link['registered_public_key_original']
            tokref=link['rfc3161_registration_token_original']
            need(regref is not None and pubref is not None,
                 'MISSING_GENUINE_REGISTERED_SITE_KEY_GENERATION',
                 'permission_denied')
            rec=_registration(regref,pubref,roles['registrar'],read,lineage,
                               bundle['_roster_sha'],party,seq,prev,identityref['sha256'])
            stamp=_timestamp(rec['raw'],tokref,trust,aid,read,evaluation,cutoff,
                             rec['registered'],flags)
            rec['token']=stamp
            need(rec['key'] not in seen_generation_keys and rec['key'] not in forbidden_keys,
                 'KEY_GENERATION_REUSED_ACROSS_A_DIFFERENT_OR_INDEPENDENT_SIGNER_ROLE',
                 'permission_denied')
            seen_generation_keys.add(rec['key'])
            if prev is not None and stamp and prev['token'] and stamp['gen']<prev['token']['gen']:
                flags[FLAGS[3]]=True
            generations.append(rec)
            allrefs.extend((regref,pubref))
            if tokref is not None:allrefs.append(tokref)
            prev=rec
        if prev is None:
            flags[FLAGS[2]]=True
        elif prev['key']!=party['public_hex']:
            flags[FLAGS[3]]=True
        mapping[ident]=generations
    need(set(mapping)==set(expected),'ALL_EC393_PARTY_KEYS_REQUIRE_REGISTERED_HISTORY')
    return mapping,allrefs


def _key_status(bundle,roles,read,lineage,trust,aid,evaluation,cutoff,
                roster_sha,parent_roster_sha,notice_sha,histories,flags):
    """Check a separately signed, RFC3161-stamped finite key-status snapshot.

    A signed ACTIVE row is a *furnished observation*, never a complete
    external CRL/OCSP census. Signed REVOKED rows remain adverse evidence.
    """
    sref=bundle['key_status_snapshot_original']
    tref=bundle['key_status_snapshot_rfc3161_token_original']
    if sref is None:
        need(tref is None,'ORPHAN_STATUS_SNAPSHOT_RFC3161_TOKEN',
             'permission_denied')
        flags[FLAGS[6]]=True
        return {'sha256':None,'clean':False,'token_sha256':None,'revoked_subject_ids':[]}
    raw=read(sref,'genuine_original_independent_key_status_snapshot',MAX_ORIGINAL)
    obj=tr.strict_json(raw,'EC394_KEY_STATUS')
    exact(obj,KEY_STATUS_FIELDS,'INDEPENDENT_KEY_STATUS_SNAPSHOT')
    claim=obj['claim'];exact(claim,KEY_STATUS_CLAIM_FIELDS,'SIGNED_KEY_STATUS_CLAIM')
    need(obj['schema']==KEY_STATUS_SCHEMA and
         claim['schema']==KEY_STATUS_CLAIM_SCHEMA and
         claim['directory_lineage_id']==lineage and
         claim['authority_id']==roles['dispute_authority']['role_id'] and
         claim['external_trust_roster_original_sha256']==roster_sha and
         claim['ec393_custody_roster_original_sha256']==parent_roster_sha and
         claim['signed_dispute_notice_original_sha256']==notice_sha and
         type(claim['key_statuses']) is list and len(claim['key_statuses'])<=20,
         'KEY_STATUS_MUST_BIND_REAL_ORIGINALS_AND_INDEPENDENT_AUTHORITY',
         'permission_denied')
    asof=_utc(claim['declared_status_utc'])
    _signed(roles['dispute_authority']['public_hex'],obj['authority_signature_ed25519'],
            KEY_STATUS_DOMAIN,claim,'INDEPENDENT_KEY_STATUS_AUTHORITY')
    known={w['role_id']:w['public_hex'] for name,w in roles.items()
           if name in ('registrar','dispute_authority')}
    known.update({w['role_id']:w['public_hex'] for w in roles['witnesses'].values()})
    required_active=set(known)
    for (observer,role),history in histories.items():
        for seq,record in enumerate(history,1):
            subject=record['claim']['party_id']+':'+str(seq)
            need(subject not in known,'STATUS_SUBJECT_IDENTIFIER_REUSED',
                 'permission_denied')
            known[subject]=record['key']
            if seq==len(history):required_active.add(subject)
    seen={};revoked=[]
    for row in claim['key_statuses']:
        exact(row,KEY_STATUS_ROW_FIELDS,'SIGNED_STATUS_ROW')
        subject=row['subject_id']
        need(subject in known and subject not in seen and
             row['public_hex']==known[subject] and
             row['status'] in ('active','revoked') and
             _utc(row['claimed_change_utc'])<=asof,
             'SIGNED_KEY_STATUS_SUBJECT_KEY_OR_TIME_DISAGREES',
             'permission_denied')
        seen[subject]=row['status']
        if row['status']=='revoked':revoked.append(subject)
    need(set(seen)==set(known),'COMPLETE_FURNISHED_KEY_STATUS_SUBJECT_SET_REQUIRED',
         'permission_denied')
    stamp=_timestamp(raw,tref,trust,aid,read,evaluation,cutoff,asof,flags)
    clean=bool(stamp and stamp['clean'] and stamp['gen']<=cutoff and
               not set(revoked).intersection(required_active))
    if not clean:flags[FLAGS[6]]=True
    return {'sha256':sref['sha256'],'clean':clean,
            'token_sha256':stamp['sha256'] if stamp else None,
            'revoked_subject_ids':revoked}


def _witness(ref,headref,w,read,log,lineage,roster_sha,notice_sha,epoch,flags):
    raw=read(ref,'original_third_party_log_witness_signature',MAX_ORIGINAL)
    obj=tr.strict_json(raw,'EC394_SIGNED_FORK_OBSERVATION')
    exact(obj,WITNESS_FIELDS,'THIRD_PARTY_WITNESS_ORIGINAL')
    claim=obj['claim'];exact(claim,WITNESS_CLAIM_FIELDS,'SIGNED_WITNESS_CLAIM')
    head=parent._log_head(headref,read,log,lineage,1)
    need(obj['schema']==WITNESS_SCHEMA and claim['schema']==WITNESS_CLAIM_SCHEMA and
         claim['directory_lineage_id']==lineage and
         claim['witness_id']==w['role_id'] and
         claim['witness_site_id']==w['site_id'] and
         claim['parent_ec393_roster_original_sha256']==roster_sha and
         claim['signed_dispute_notice_original_sha256']==notice_sha and
         type(claim['epoch_index']) is int and claim['epoch_index']==epoch and
         claim['observed_log_id']==log['log_id'] and
         claim['observed_signed_log_head_original_sha256']==head['sha256'] and
         claim['observed_log_tree_size']==head['size'] and
         claim['observed_log_merkle_root_sha256']==head['claim']['merkle_root_sha256'],
         'SIGNED_WITNESS_IS_NOT_BOUND_TO_GENUINE_LOG_HEAD',
         'permission_denied')
    observed=_utc(claim['claimed_observed_utc'])
    _signed(w['public_hex'],obj['witness_signature_ed25519'],
            WITNESS_DOMAIN,claim,'THIRD_PARTY_LOG_WITNESS')
    return {'sha256':ref['sha256'],'claim':claim,'head':head,
           'raw':raw,'observed':observed}


def _engine(derive,**opts):
    inherited=_inputs(opts,derive)
    actual=parent.audit(**inherited)  # Immutable real EC393 -> actual EC392 -> two EC391.
    parent_sha=_parent_report(actual,opts)
    lineage=opts['claimed_historical_directory_lineage_id']
    evaluation=_utc(opts['ec391_tsa_evaluation_utc'])
    cutoff=_utc(opts[parent.NEW_SCALARS[5]])
    read,doc,late=_readers()
    original={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    bundle=doc(original,'original_registration_witness_bundle',MAX_BUNDLE)
    exact(bundle,BUNDLE_FIELDS,'REGISTERED_WITNESS_BUNDLE')
    parentref={'path':opts[parent.NEW_SCALARS[0]],'sha256':opts[parent.NEW_SCALARS[1]]}
    need(bundle['schema']==BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id']==lineage and
         bundle['parent_ec393_custody_bundle_original']==parentref and
         type(bundle['epochs']) is list and
         len(bundle['epochs'])==len(opts['historical_directory_root_shas']),
         'REGISTERED_BUNDLE_MUST_BIND_ACTUAL_EC393_ORIGINAL',
         'permission_denied')
    parentbundle=doc(parentref,'authentic_parent_ec393_bundle_original',parent.MAX_BUNDLE)
    exact(parentbundle,parent.BUNDLE_FIELDS,'ACTUAL_PARENT_EC393_BUNDLE')
    crossref=parentbundle['parent_ec392_crossview_bundle_original']
    cross=doc(crossref,'actual_ec392_crossview_source',parent.parent.MAX_BUNDLE)
    exact(cross,parent.parent.BUNDLE_FIELDS,'EC392_ORIGINAL')
    observer_ids=(cross['primary_observer_id'],cross['secondary_observer_id'])
    parentrosterref=parentbundle['custody_log_roster_original']
    parentroster=doc(parentrosterref,'actual_ec393_custody_site_roster',parent.MAX_ROSTER)
    exact(parentroster,parent.ROSTER_FIELDS,'EC393_ROSTER')
    ec393_keys={p['public_hex'] for p in parentroster['custody_parties']}
    ec393_keys.add(parentroster['log_public_hex'])
    # Include authenticated EC392 observer Ed25519 keys in the anti-reuse boundary.
    keeper_keys=set()
    for side,ref in (('primary',cross['primary_ec391_offsite_bundle_original']),
                     ('secondary',cross['secondary_ec391_offsite_bundle_original'])):
        viewer=doc(ref,'original_ec391_observer_bundle',parent.prior.MAX_BUNDLE)
        exact(viewer,parent.prior.BUNDLE_FIELDS,'REOPENED_EC391_BUNDLE')
        keeper=doc(viewer['offsite_log_keeper_roster_original'],
                   'original_ec391_keeper_roster',parent.prior.MAX_ROSTER)
        for obj in keeper.get('log_keepers',[]):
            if type(obj) is dict and _hexkey(obj.get('public_hex')):
                keeper_keys.add(obj['public_hex'])
    rosterref=bundle['external_trust_roster_original']
    roles=_roster(doc(rosterref,'retained_independent_signer_roster',MAX_ROSTER),
                  rosterref,opts,lineage,read,ec393_keys|keeper_keys)
    need(not roles['sites'].intersection(p['site_id'] for p in parentroster['custody_parties']) and
         not ({r['role_id'] for r in (roles['registrar'],roles['dispute_authority'],
              *roles['witnesses'].values())} &
              {p['party_id'] for p in parentroster['custody_parties']}),
         'EXTERNAL_ROLE_METADATA_COLLIDES_WITH_EC393_CUSTODY_SITE_OR_PARTY',
         'permission_denied')
    tsaref=bundle['witness_tsa_registry_original']
    trust=parent.prior._trust_registry(
       doc(tsaref,'independent_witness_timestamp_trust_registry',parent.prior.MAX_TRUST),
       tsaref,opts[NEW_SCALARS[3]],lineage,read)
    oldtrust=parent.prior._trust_registry(
       doc(parentbundle['tsa_trust_registry_original'],'parent_ec393_tsa_roots',
           parent.prior.MAX_TRUST),
       parentbundle['tsa_trust_registry_original'],
       opts[parent.NEW_SCALARS[3]],lineage,read)
    used_roots={e['root_sha'] for e in oldtrust.values()}
    for ref in (cross['primary_ec391_offsite_bundle_original'],
                cross['secondary_ec391_offsite_bundle_original']):
        ec391=doc(ref,'prior_tsa_roots',parent.prior.MAX_BUNDLE)
        trustref=ec391['tsa_trust_registry_original']
        old=doc(trustref,'authentic_ec391_tsa_roster',parent.prior.MAX_TRUST)
        for a in old['authorities']:
            used_roots.add(a['root_certificate_der_sha256'])
    need(not used_roots.intersection(x['root_sha'] for x in trust.values()),
         'WITNESS_TSA_MUST_NOT_REUSE_EC391_OR_EC393_TSA_ROOT',
         'permission_denied')
    aid=bundle['witness_tsa_authority_id']
    need(_ident(aid) and aid in trust,'WITNESS_TSA_AUTHORITY_ID_REQUIRED',
         'permission_denied')
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not actual['local_custody_counter_signatures_log_and_timestamps_consistent']
    # Strict, purpose-limited outside notice source; its content is *not*
    # parsed as an official judicial mandate.
    notice_bundle={**bundle,'_notice_pin':opts[NEW_SCALARS[5]]}
    notice=_notice(notice_bundle,roles,read,doc,lineage,parentref['sha256'],
                   cutoff,trust,aid,evaluation,flags)
    parent_log={'log_id':parentroster['log_id'],'log_key':parentroster['log_public_hex']}
    old_head=parentbundle['prior_signed_log_head_original']
    need((old_head is None and actual['signed_log_prior_and_current_sha256'][0] is None) or
         (old_head is not None and
          old_head['sha256']==actual['signed_log_prior_and_current_sha256'][0]),
         'ACTUAL_PRIOR_SIGNED_LOG_HEAD_AND_PARENT_REPORT_MUST_MATCH',
         'permission_denied')
    if old_head is None:flags[FLAGS[5]]=True
    # No field may accidentally reinterpret the old signed Head as an
    # independent third-party *signature*. Witnesses need their own keys.
    histories,history_refs=_histories(
       {**bundle,'_roster_sha':parentrosterref['sha256']},
       parentroster,roles,read,lineage,flags,trust,aid,evaluation,cutoff,
       keeper_keys|{parentroster['log_public_hex']}|
       {v['public_hex'] for v in (roles['registrar'],roles['dispute_authority'],
                                 *roles['witnesses'].values())})
    status=_key_status(bundle,roles,read,lineage,trust,aid,evaluation,cutoff,
         rosterref['sha256'],parentrosterref['sha256'],notice['sha256'] if notice else ZERO,
         histories,flags)
    results=[];epoch_reviews=[];fork_cases=[];site_count=0;witness_count=0
    prior_witness_sha=None
    observed_forks={}
    prior_sources=set(roles['key_paths'])
    prior_sources.update(x['path'] for x in (original,parentref,crossref,parentrosterref,
                   rosterref,tsaref,parentbundle['tsa_trust_registry_original']))
    prior_sources.update(x for x in opts.values() if type(x) is str and x.startswith('/')
                         and len(x)<=4000)
    def add_parent_refs(obj):
        if type(obj) is dict:
            if set(obj)=={'path','sha256'} and type(obj['path']) is str:
                prior_sources.add(obj['path'])
            else:
                for value in obj.values():add_parent_refs(value)
        elif type(obj) is list:
            for item in obj:add_parent_refs(item)
    add_parent_refs(parentbundle);add_parent_refs(cross);add_parent_refs(parentroster)
    for ref in (cross['primary_ec391_offsite_bundle_original'],
                cross['secondary_ec391_offsite_bundle_original']):
        add_parent_refs(doc(ref,'ec391_preexisting_anti_alias_bundle',parent.prior.MAX_BUNDLE))
    original_paths=set(prior_sources)
    original_paths.update([original['path'],parentref['path'],rosterref['path'],tsaref['path']])
    for h in history_refs:
        need(h['path'] not in original_paths,
             'REGISTERED_SITE_GENERATIONS_MUST_HAVE_DISTINCT_ORIGINAL_PATHS',
             'permission_denied')
        original_paths.add(h['path'])
    for idx,entry in enumerate(bundle['epochs']):
        exact(entry,EPOCH_FIELDS,'EXTERNAL_WITNESS_EPOCH')
        need(type(entry['epoch_index']) is int and entry['epoch_index']==idx and
             type(entry['witnesses']) is list and len(entry['witnesses'])==2,
             'BOTH_DISTINCT_LOG_WITNESSES_PER_EPOCH_REQUIRED',
             'permission_denied')
        # Match *genuine* signed EC393 handoff claims, not supplied timestamps.
        claims={}
        for c in parentbundle['epochs'][idx]['channels']:
            for side in ('primary','secondary'):
                ref=c[side]['signed_custody_handoff_original']
                if ref is None:continue
                r=doc(ref,'actual_ec393_signed_handoff',parent.MAX_RECEIPT)
                exact(r,parent.RECEIPT_FIELDS,'PARENT_COUNTERSIGNED_HANDOFF')
                claim=r['claim']
                who=observer_ids[0 if side=='primary' else 1]
                need(claim['observer_id']==who and
                     claim['tsa_channel_id']==c['tsa_channel_id'],
                     'PARENT_SIGNED_HANDOFF_ROW_ID_MISMATCH',
                     'permission_denied')
                claims.setdefault(who,[]).append(_utc(claim['claimed_handoff_utc']))
        site_rows=[];scount=0
        for party in parentroster['custody_parties']:
            who=party['observer_id'];role=party['role']
            generations=histories[(who,role)]
            latest=generations[-1] if generations else None
            source_times=claims.get(who,[])
            bounded=bool(source_times and latest is not None and latest['token'] is not None and
                latest['token']['clean'] and latest['key']==party['public_hex'] and
                all(latest['start']<=t<latest['end'] and
                    latest['token']['gen']<=t for t in source_times) and
                latest['token']['gen']<=cutoff and status['clean'])
            if not bounded:flags[FLAGS[3]]=True
            scount+=int(bounded)
            site_rows.append({'observer_id':who,'role':role,'party_id':party['party_id'],
               'current_ec393_key_sha256':parent.sha(bytes.fromhex(party['public_hex'])),
               'signed_registration_history_original_shas':[x['sha256'] for x in generations],
               'registered_key_lineage_serial':len(generations),
               'claimed_handoff_window_bounded_by_real_registration_token':bounded})
        site_digest=parent.sha(canonical.canonical(site_rows))
        witnesses=[];wcount=0;seen=set();seen_heads={}
        for group in entry['witnesses']:
            exact(group,WITNESS_GROUP_FIELDS,'SIGNED_LOG_WITNESS_EPOCH_GROUP')
            wid=group['witness_id']
            need(wid in roles['witnesses'] and wid not in seen and
                 type(group['observations']) is list and 0<=len(group['observations'])<=2,
                 'REAL_DISTINCT_WITNESS_IDS_AND_BOUNDED_SIGNED_ORIGINALS_REQUIRED',
                 'permission_denied')
            seen.add(wid)
            case_ids=set();observations=[];has_bounded=False;original_shas=set()
            if not group['observations']:flags[FLAGS[5]]=True
            for obs in group['observations']:
                exact(obs,OBS_FIELDS,'ORIGINAL_WITNESS_OBSERVATION')
                h_ref=obs['observed_signed_log_head_original']
                o_ref=obs['signed_witness_observation_original']
                t_ref=obs['rfc3161_witness_token_original']
                if o_ref is None or h_ref is None:
                    flags[FLAGS[5]]=True
                    continue
                need(o_ref['sha256'] not in original_shas,
                     'DUPLICATE_SIGNED_WITNESS_ORIGINAL_IN_SAME_GROUP',
                     'permission_denied')
                original_shas.add(o_ref['sha256'])
                if old_head is not None and h_ref['sha256']==old_head['sha256']:
                    need(h_ref==old_head,'OLD_SIGNED_HEAD_MUST_USE_ACTUAL_ORIGINAL_REFERENCE',
                         'permission_denied')
                else:
                    need(h_ref['path'] not in prior_sources and
                         (h_ref['path'] not in observed_forks or observed_forks[h_ref['path']]==h_ref['sha256']),
                         'FORK_HEAD_PATH_ALIASES_OLDER_SOURCE_OR_CHANGED_SHA',
                         'permission_denied')
                    observed_forks[h_ref['path']]=h_ref['sha256']
                for r in (o_ref,t_ref):
                    if r is not None:
                        need(r['path'] not in original_paths,
                             'THIRD_PARTY_SIGNED_WITNESS_OR_TOKEN_ORIGINAL_PATH_REUSED',
                             'permission_denied')
                        original_paths.add(r['path'])
                signed=_witness(o_ref,h_ref,roles['witnesses'][wid],read,parent_log,
                   lineage,parentrosterref['sha256'],notice['sha256'] if notice else ZERO,
                   idx,flags)
                if prior_witness_sha is None:prior_witness_sha=signed['sha256']
                stamp=_timestamp(signed['raw'],t_ref,trust,aid,read,evaluation,cutoff,
                                signed['observed'],flags)
                matches_old=(old_head is not None and
                             signed['head']['sha256']==old_head['sha256'])
                bounded=bool(stamp is not None and stamp['clean'] and
                    stamp['gen']<=cutoff and stamp['gen']>=signed['observed'] and
                    signed['observed']>=signed['head']['claimed'] and
                    signed['observed']<=cutoff and matches_old and notice is not None and
                    notice['token'] is not None and notice['token']['clean'] and
                    status['clean'])
                if not bounded:flags[FLAGS[5]]=True
                has_bounded|=bounded
                case=(signed['head']['size'],signed['head']['claim']['log_sequence'])
                if case in case_ids and signed['head']['sha256'] in seen_heads.get(case,set()):
                    flags[FLAGS[4]]=True
                case_ids.add(case)
                seen_heads.setdefault(case,set()).add(signed['head']['sha256'])
                observations.append({'signed_observation_sha256':signed['sha256'],
                   'timestamp_token_sha256':stamp['sha256'] if stamp else None,
                   'observed_signed_log_head_sha256':signed['head']['sha256'],
                   'matches_actual_ec393_prior_signed_head':matches_old,
                   'witnessed_before_declared_cutoff_with_clean_crl':bounded})
            wcount+=int(has_bounded)
            witnesses.append({'witness_id':wid,'observations':observations,
                             'at_least_one_pre_cutoff_ec393_head_observed':has_bounded})
        need(set(seen)==set(roles['witnesses']),
             'EACH_EPOCH_REQUIRES_BOTH_EXTERNAL_WITNESS_IDS',
             'permission_denied')
        for key,heads in seen_heads.items():
            if len(heads)>1:
                flags[FLAGS[4]]=True
                fork_cases.append({'epoch_index':idx,'log_tree_size':key[0],
                   'log_sequence':key[1],
                   'valid_log_operator_signed_conflicting_head_original_shas':sorted(heads)})
        witness_digest=parent.sha(canonical.canonical(witnesses))
        if (site_digest!=opts[NEW_REPEATS[0][0]][idx] or
            witness_digest!=opts[NEW_REPEATS[1][0]][idx] or
            scount<opts[NEW_REPEATS[2][0]][idx] or
            wcount<opts[NEW_REPEATS[3][0]][idx]):flags[FLAGS[1]]=True
        site_count+=scount;witness_count+=wcount
        epoch_reviews.append({'epoch_index':idx,
          'pre_handoff_registered_site_roles':scount,
          'pre_cutoff_independent_log_witnesses':wcount,
          'site_key_registration_inventory_sha256':site_digest,
          'third_party_witness_inventory_sha256':witness_digest,
          'visible_valid_signed_log_fork_count':sum(x['epoch_index']==idx for x in fork_cases)})
        results.append({'epoch_index':idx,'site_key_history_rows':site_rows,
                        'independent_witness_observations':witnesses})
    if prior_witness_sha!=opts[NEW_SCALARS[4]]:
        flags[FLAGS[1]]=True
    if notice is None or notice['sha256']!=opts[NEW_SCALARS[5]]:
        flags[FLAGS[1]]=True
    # Audit external notice/role/TSA originals cannot alias new signed originals.
    extra=[bundle['original_dispute_case_file'],bundle['signed_dispute_notice_original'],
           bundle['dispute_notice_rfc3161_token_original'],
           bundle['key_status_snapshot_original'],
           bundle['key_status_snapshot_rfc3161_token_original']]
    for r in extra:
        if r is None:continue
        need(r['path'] not in original_paths,
             'DISPUTE_ORIGINAL_MUST_BE_DISTINCT_FROM_WITNESSES_AND_REGISTRATIONS',
             'permission_denied')
        original_paths.add(r['path'])
    inventory={'schema':INVENTORY_SCHEMA,'claimed_directory_lineage_id':lineage,
       'actual_parent_ec393_report_sha256':parent_sha,
       'actual_parent_ec393_inventory_sha256':actual['receiver_verified_custody_anchor_inventory_sha256'],
       'actual_parent_ec393_custody_original_sha256':parentref['sha256'],
       'registered_witness_bundle_original_sha256':original['sha256'],
       'outside_retained_trust_roster_sha256':rosterref['sha256'],
       'outside_retained_witness_tsa_roster_sha256':tsaref['sha256'],
       'outside_retained_dispute_notice_sha256':opts[NEW_SCALARS[5]],
       'outside_retained_prior_witness_sha256':opts[NEW_SCALARS[4]],
       'outside_retained_registrar_public_hex':opts[NEW_SCALARS[6]],
       'outside_retained_dispute_authority_public_hex':opts[NEW_SCALARS[7]],
       'dispute_cutoff_utc_from_ec393':opts[parent.NEW_SCALARS[5]],
       'genuine_signed_dispute_notice_sha256':notice['sha256'] if notice else None,
       'independent_signed_key_status_snapshot':status,
       'registration_and_fork_witness_epoch_histories':results,
       'visible_genuine_operator_signed_conflicting_prior_log_heads':fork_cases}
    digest=parent.sha(canonical.canonical(inventory))
    if not derive and digest!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    # Visible reread only. Does not provide OS openat atomicity or remote WORM.
    for path,(pin,cap) in late.items():
        data=io._read({'path':path,'sha256':pin},'ec394_final_readback',
                      cap,{}, {},set())
        need(parent.sha(data)==pin,'REGISTERED_WITNESS_SOURCE_CHANGED_DURING_AUDIT',
             'permission_denied')
    flags[FLAGS[7]]=True;flags[FLAGS[8]]=True;flags[FLAGS[9]]=True
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
      'command':('derive-historical-ec339-registered-witness-inventory' if derive else
                 'audit-historical-ec339-registered-witness'),
      'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                    OUTCOMES[-1])+'_unresolved',
      'exit_code':2,'offline_unresolved_exit_code':2,
      'verified_live_ec393_report_sha256':parent_sha,
      'verified_live_ec393_inventory_sha256':actual['receiver_verified_custody_anchor_inventory_sha256'],
      'historical_registered_witness_original_sha256':original['sha256'],
      'receiver_verified_registered_witness_inventory_sha256':digest,
      'cryptographically_timestamped_pre_handoff_registered_site_role_count':site_count,
      'cryptographically_timestamped_pre_cutoff_independent_witness_count':witness_count,
      'visible_genuine_signed_log_fork_count':len(fork_cases),
      'signed_key_status_snapshot_sha256':status['sha256'],
      'furnished_signed_key_revocation_count':len(status['revoked_subject_ids']),
      'registered_witness_epoch_reviews':epoch_reviews,
      'visible_signed_log_fork_cases':fork_cases,
      'local_registered_key_and_independent_witness_consistency':not any(flags[k] for k in FLAGS[:7]),
      'sender_origin_path_required_or_read':False,
      'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
      **flags,**{k:False for k in NEGATIVES},
      **({'unsigned_registered_witness_inventory':inventory} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
