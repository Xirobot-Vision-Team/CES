#!/usr/bin/env python3
"""EC391 receiver-only replay of previously signed offsite log heads and RFC3161 tokens.

A historic offsite head signs only authentic EC389 signed source SHA triples,
not a later EC390 report. The timestamp hashes that *original signed head*.
Its CMS signature, ESS signer certificate, X509 path, constrained EKU and
supplied CRLs are verified by the existing EC350 offline RFC3161 verifier.
No trust root, CRL, signing key, token or prior retention is manufactured here.
A caller-supplied trust-registry hash/root is NOT proof of an independent TSA.
"""
from __future__ import annotations

from datetime import timezone
import re

from cryptography.hazmat.primitives import hashes, serialization
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as tsa
from historical_authority import authority_archive as originals
from transparency import transparency as transparency
from independent_archive import retained_heads as prior

RESULT_SCHEMA='ces.ec391.receiver_prior_offsite_head_rfc3161_unresolved.v1'
DERIVE_SCHEMA='ces.ec391.unsigned_prior_offsite_head_time_unresolved.v1'
DENIAL_SCHEMA='ces.ec391.receiver_prior_offsite_head_rfc3161_denial.v1'
BUNDLE_SCHEMA='ces.ec391.receiver_prior_offsite_signed_heads_timestamp_bundle.v1'
ROSTER_SCHEMA='ces.ec391.outside_retained_offsite_log_keeper_roster.v1'
TRUST_SCHEMA='ces.ec391.outside_retained_offline_tsa_trust_registry.v1'
SIGNED_SCHEMA='ces.ec391.signed_prior_offsite_log_head_original.v1'
CLAIM_SCHEMA='ces.ec391.prior_offsite_log_head_claim.v1'
INVENTORY_SCHEMA='ces.ec391.receiver_unsigned_prior_offsite_head_timestamp_inventory.v1'
DOMAIN=b'CES/EC391/IndependentOldEC339Revocation/PriorOffsiteLogHead/v1\0'
ZERO='0'*64
MAX_BUNDLE=140_000
MAX_ROSTER=16_000
MAX_TRUST=26_000
MAX_SIGNED=16_000
MAX_DER=tsa.MAX_DER_BYTES
MAX_CRL=tsa.MAX_CRL_BYTES
NEW_SCALARS=(
 'historical_ec339_prior_offsite_time_bundle_file',
 'expected_historical_ec339_prior_offsite_time_bundle_sha256',
 'expected_outside_retained_ec391_log_keeper_roster_sha256',
 'expected_outside_retained_ec391_tsa_trust_registry_sha256',
 'ec391_tsa_evaluation_utc',
)
AUDIT_ONLY=('expected_retained_historical_ec339_prior_time_inventory_sha256',)
NEW_REPEATS=(
 ('historical_ec339_prior_signed_head_inventory_shas','--historical-ec339-prior-signed-head-inventory-sha256'),
 ('historical_ec339_prior_rfc3161_token_inventory_shas','--historical-ec339-prior-rfc3161-token-inventory-sha256'),
 ('minimum_historical_ec339_prior_timestamped_head_counts','--minimum-historical-ec339-prior-timestamped-head-count'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
PARENT_SCALARS=(*prior.PARENT_SCALARS,*prior.NEW_SCALARS,*prior.AUDIT_ONLY)
PARENT_REPEATS=(*prior.PARENT_REPEATS,*prior.REPEAT_NAMES)
BUNDLE_FIELDS={'schema','parent_ec390_independent_archive_original_sha256',
 'parent_ec390_canonical_result_sha256','claimed_directory_lineage_id',
 'offsite_log_keeper_roster_original','tsa_trust_registry_original','epochs'}
ROSTER_FIELDS={'schema','claimed_directory_lineage_id','log_keepers'}
KEEPER_FIELDS={'signer_id','public_hex','public_key_original'}
TRUST_FIELDS={'schema','claimed_directory_lineage_id','authorities'}
AUTHORITY_FIELDS={'authority_id','root_certificate_original','root_certificate_der_sha256',
 'expected_tsa_policy_oid','crl_originals'}
EPOCH_FIELDS={'epoch_index','channels'}
CHANNEL_FIELDS={'tsa_channel_id','signed_prior_offsite_head_original',
 'rfc3161_timestamp_original','tsa_authority_id'}
CLAIM_FIELDS={'schema','directory_lineage_id','tsa_channel_id','epoch_index',
 'offsite_keeper_id','log_sequence','previous_signed_offsite_head_original_sha256',
 'ec389_signed_source_pairs','claimed_logged_utc'}
FLAGS=(
 'inherited_live_ec390_through_ec369_signed_historical_dispute',
 'outside_retained_prior_signed_head_rfc3161_sha_or_floor_disagrees',
 'prior_offsite_head_or_timestamp_missing_for_visible_signed_source',
 'valid_prior_signed_head_disagrees_with_authentic_ec389_original_pairs',
 'valid_prior_signed_head_disagrees_with_later_ec390_signed_snapshot',
 'signed_prior_offsite_log_epoch_predecessor_or_prefix_rollback',
 'authenticated_tsa_gen_time_vs_claim_or_epoch_order_disagreement',
 'tsa_crl_missing_stale_ambiguous_or_reports_prior_revocation',
 'independently_authenticated_prior_custody_and_real_tsa_identity_not_proven',
 'unseen_forks_global_crl_ocsp_and_physical_retention_not_proven',
)
OUTCOMES=(
 'ec391_inherited_live_historical_signed_original_dispute',
 'ec391_prior_offsite_retention_inventory_or_minimum_disagrees',
 'ec391_prior_signed_head_or_rfc3161_timestamp_missing',
 'ec391_valid_prior_head_conflicts_with_authentic_ec389_signed_history',
 'ec391_valid_prior_head_conflicts_with_ec390_signed_snapshot',
 'ec391_prior_signed_offsite_head_epoch_rollback_or_broken_chain',
 'ec391_real_cms_signed_gen_time_vs_claimed_order_disagrees',
 'ec391_bounded_offline_crl_not_current_or_revoked',
 'ec391_external_tsa_identity_and_earlier_offsite_custody_not_proven',
 'ec391_global_revocation_hidden_forks_and_immutable_custody_not_proven',
)
NEGATIVES=(
 'caller_supplied_trust_registry_or_root_is_independently_authenticated_tsa',
 'signed_timestamp_gen_time_alone_proves_calibrated_external_utc',
 'signed_offsite_head_claimed_utc_proves_actual_prior_physical_retention',
 'single_valid_timestamp_proves_legal_qualified_tsa_or_institutional_separation',
 'locally_generated_ed25519_public_key_proves_legitimate_offsite_operator',
 'presented_crl_list_is_exhaustive_revocation_ocsp_and_current_online_status',
 'signed_prior_head_or_token_selects_globally_authoritative_fork_winner',
 'older_signed_head_extends_ec339_issuer_authorization',
 'receiver_ec353_sender_origin_is_accepted_as_independent_prior_head',
 'unsigned_derived_prior_inventory_self_proves_prior_independent_retention',
 'private_key_tsa_issue_network_provider_cas_worm_git_ci_or_powershell_write_performed',
 'full_unmocked_ec317_ec318_production_and_final_user_acceptance_proven',
)
OID=re.compile(r'[0-2](?:\.(?:0|[1-9][0-9]{0,12})){2,20}\Z')


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC391_'+code,status)


def exact(value,keys,label):
    need(type(value) is dict and set(value)==set(keys),label+'_EXACT_FIELDS_REQUIRED')


def sha(data):return prior.sha(data)


def _inputs(opts,derive):
    expected=set((*PARENT_SCALARS,*PARENT_REPEATS,*NEW_SCALARS,*REPEAT_NAMES))
    if not derive:expected.update(AUDIT_ONLY)
    need(set(opts)==expected,'EXACT_PARENT_EC390_AND_EC391_ARGS_REQUIRED')
    older={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    prior._inputs(older,False)   # All old pins / min counts remain mandatory.
    originals.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                                 'EC391_PRIOR_OFFSITE_BUNDLE')
    for name in NEW_SCALARS[2:4]:
        need(transparency._sha(opts[name]),'OUTSIDE_RETAINED_'+name.upper()+'_REQUIRED')
    evaluation=tsa._utc(opts['ec391_tsa_evaluation_utc'])
    if not derive:
        need(transparency._sha(opts[AUDIT_ONLY[0]]),
             'OUTSIDE_RETAINED_WHOLE_PRIOR_INVENTORY_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'ONE_TO_THREE_HISTORIC_EPOCHS_REQUIRED')
    for name in REPEAT_NAMES:
        values=opts[name]
        need(type(values) is list and len(values)==n,
             'PER_EPOCH_PRIOR_HEAD_TOKEN_SHA_AND_COUNT_REQUIRED')
        if name.startswith('minimum_'):
            need(all(type(v) is int and 0<=v<=2 for v in values),
                 'TWO_PRIOR_ANCHORS_MAX_PER_EPOCH')
        else:
            need(all(transparency._sha(v) for v in values),
                 'OFFSITE_INVENTORY_SHA_INVALID')
    return older,evaluation


def _parent(report,n):
    need(type(report) is dict and report.get('schema')==prior.RESULT_SCHEMA and
         report.get('command')=='audit-historical-ec339-independent-archive-heads' and
         report.get('exit_code')==2 and report.get('offline_unresolved_exit_code')==2 and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         type(report.get('historical_independent_archive_epoch_reviews')) is list and
         len(report['historical_independent_archive_epoch_reviews'])==n and
         all(type(report.get(k)) is bool for k in prior.FLAGS) and
         all(report[k] is True for k in prior.FLAGS[-2:]) and
         all(report.get(k) is False for k in prior.NEGATIVES) and
         type(report.get('local_independent_signed_archive_heads_and_receipts_consistent')) is bool and
         report['local_independent_signed_archive_heads_and_receipts_consistent']==(
             not any(report[k] for k in prior.FLAGS[:7])) and
         report.get('status')==next((prior.OUTCOMES[i] for i,k in enumerate(prior.FLAGS)
             if report[k]),prior.OUTCOMES[-1])+'_unresolved' and
         all(transparency._sha(report.get(k)) for k in (
             'verified_live_parent_ec389_canonical_result_sha256',
             'historical_independent_archive_original_sha256',
             'receiver_verified_independent_archive_inventory_sha256')),
         'ACTUAL_EC390_TO_EC369_PARENT_AUDIT_REQUIRED','unavailable')
    return sha(canonical.canonical(report))


def _keeper_roster(roster,ref,retained,read,excluded_ids,excluded_keys):
    exact(roster,ROSTER_FIELDS,'OFFSITE_LOG_KEEPER_ROSTER')
    need(roster['schema']==ROSTER_SCHEMA and ref['sha256']==retained and
         type(roster['claimed_directory_lineage_id']) is str and
         prior.IDENT.fullmatch(roster['claimed_directory_lineage_id']) is not None,
         'OUTSIDE_RETAINED_KEEPER_ROSTER_SCHEMA_LINEAGE_SHA','permission_denied')
    people=roster['log_keepers']
    need(type(people) is list and 1<=len(people)<=2,'ONE_OR_TWO_LOG_KEEPERS_REQUIRED')
    result={};seen_path=set()
    for row in people:
        exact(row,KEEPER_FIELDS,'OFFSITE_KEEPER_KEY')
        sid=row['signer_id'];hexkey=row['public_hex'];refkey=row['public_key_original']
        need(type(sid) is str and prior.IDENT.fullmatch(sid) is not None and
             type(hexkey) is str and prior.HEX64.fullmatch(hexkey) is not None and
             sid not in excluded_ids and sid not in result and hexkey not in excluded_keys and
             hexkey not in result.values() and hexkey!='00'*32,
             'KEEPER_MUST_NOT_REUSE_OLD_ROLES_OR_KEYS','permission_denied')
        raw=read(refkey,'offsite_log_keeper_ed25519_raw_key',32)
        need(len(raw)==32 and raw.hex()==hexkey and refkey['path'] not in seen_path,
             'LOG_KEEPER_32BYTE_RAW_KEY_AND_DISTINCT_FILE_REQUIRED','permission_denied')
        seen_path.add(refkey['path']);result[sid]=hexkey
    return result


def _trust_registry(doc,ref,retained,lineage,read):
    exact(doc,TRUST_FIELDS,'TSA_TRUST_REGISTRY')
    need(doc['schema']==TRUST_SCHEMA and doc['claimed_directory_lineage_id']==lineage and
         ref['sha256']==retained,'TSA_TRUST_REGISTRY_OUTSIDE_SHA_AND_LINEAGE_REQUIRED',
         'permission_denied')
    items=doc['authorities']
    need(type(items) is list and 1<=len(items)<=2,
         'ONE_OR_TWO_EXTERNALLY_PINNED_TSA_AUTHORITIES_REQUIRED')
    found={};roots=set();seen_crl_paths=set()
    for row in items:
        exact(row,AUTHORITY_FIELDS,'TSA_AUTHORITY_RECORD')
        authority=row['authority_id'];policy=row['expected_tsa_policy_oid']
        need(type(authority) is str and prior.IDENT.fullmatch(authority) is not None and
             authority not in found and type(policy) is str and OID.fullmatch(policy) is not None and
             transparency._sha(row['root_certificate_der_sha256']),
             'TSA_AUTHORITY_ID_POLICY_AND_ROOT_DER_PIN_REQUIRED')
        rref=row['root_certificate_original']
        certificate=tsa._certificate(read(rref,'outside_pinned_tsa_x509_root',tsa.MAX_CERT_BYTES))
        digest=certificate.fingerprint(hashes.SHA256()).hex()
        need(digest==row['root_certificate_der_sha256'] and digest not in roots,
             'TSA_ROOT_DER_SHA_MUST_MATCH_DISTINCT_OUTSIDE_AUTHORITY',
             'permission_denied')
        roots.add(digest)
        refs=row['crl_originals']
        need(type(refs) is list and len(refs)<=4,'MAX_FOUR_CRL_PER_TSA_AUTHORITY')
        crls=[]
        for crlref in refs:
            need(type(crlref) is dict and crlref.get('path') not in seen_crl_paths,
                 'DUPLICATE_OFFLINE_CRL_ORIGINAL_DENIED')
            seen_crl_paths.add(crlref['path'])
            crls.append(tsa._crl(read(crlref,'outside_signed_tsa_crl',MAX_CRL)))
        found[authority]={'root':certificate,'root_sha':digest,'policy':policy,
                          'crls':crls,'crl_refs':refs}
    return found


def _old_exclusions(opts,ec389_bundle,ec390_bundle,read,doc,n):
    """Re-open old public signer original roster material, including EC338-341."""
    excluded_ids=set();excluded_keys=set()
    for bundle,key,cap in ((ec389_bundle,'external_verifier_roster_original',prior.parent.MAX_ROSTER),
                           (ec390_bundle,'independent_archive_roster_original',prior.MAX_ROSTER)):
        roster=doc(bundle[key],'reopen_authenticated_old_roster',cap)
        groups=('witnesses','custodians') if bundle is ec389_bundle else ('archivists','receipt_attestors')
        for group in groups:
            for r in roster[group]:
                excluded_ids.add(r['signer_id']);excluded_keys.add(r['public_hex'])
    old388=doc({'path':opts[prior.parent.parent.NEW_SCALARS[0]],
                'sha256':opts[prior.parent.parent.NEW_SCALARS[1]]},
               'authenticated_ec388_old_actor_bundle',prior.parent.parent.MAX_BUNDLE)
    old387=doc({'path':opts[prior.parent.parent.parent.NEW_SCALARS[0]],
                'sha256':opts[prior.parent.parent.parent.NEW_SCALARS[1]]},
               'authenticated_ec387_old_issuer_bundle',prior.parent.parent.parent.MAX_BUNDLE)
    old386=doc({'path':opts[prior.parent.parent.parent.parent.NEW_SCALARS[0]],
                'sha256':opts[prior.parent.parent.parent.parent.NEW_SCALARS[1]]},
               'authenticated_ec386_old_root_bundle',prior.parent.parent.parent.parent.MAX_BUNDLE)
    for ep388,ep387,ep386 in zip(old388['epochs'],old387['epochs'],old386['epochs'],strict=True):
        for ch in ep388['channels']:
            if ch['ec338_policy_original'] is not None:
                policy=prior.old339.io.parse(read(ch['ec338_policy_original'],'old_actor_policy',
                                              prior.old338.MAX_POLICY),prior.old338.MAX_POLICY)
                excluded_keys.update(row['public_hex'] for row in policy['actors'])
        for ch in ep387['channels']:
            if ch['ec339_predecessor_authority_roster_original'] is not None:
                roster=prior.old339.io.parse(read(ch['ec339_predecessor_authority_roster_original'],
                  'old_issuer_roster',prior.old339.MAX_ROSTER),prior.old339.MAX_ROSTER)
                excluded_keys.update(row['issuer_public_hex'] for row in roster['issuers'])
            excluded_keys.update(row['public_hex'] for row in ch['ec340_original_public_key_sources'])
        for ch in ep386['channels']:
            excluded_keys.update(row['public_hex'] for row in ch['ec341_signer_public_key_copies'])
    need(all(len(e['channels'])<=2 for e in old388['epochs']) and
         len(old387['epochs'])==len(old386['epochs'])==n,
         'OLD_SIGNER_KEY_EPOCH_BOUNDS_REQUIRED','permission_denied')
    return excluded_ids,excluded_keys


def _channel(row,src,ec390_row,keepers,authorities,read,lineage,idx,previous,
             flags,evaluation):
    exact(row,CHANNEL_FIELDS,'OFFSITE_HEAD_TSA_CHANNEL')
    cid=row['tsa_channel_id'];href=row['signed_prior_offsite_head_original']
    tokenref=row['rfc3161_timestamp_original'];aid=row['tsa_authority_id']
    need((href is None and tokenref is None and aid is None) or
         (href is not None and (tokenref is None and aid is None or
                                 tokenref is not None and aid in authorities)),
         'TOKEN_MUST_HAVE_SIGNED_HEAD_AND_REGISTERED_TSA_AUTHORITY',
         'permission_denied')
    status={'tsa_channel_id':cid,'authentic_ec389_source_pair_count':len(src['pairs']),
        'prior_signed_head_sha256':None,'prior_signed_snapshot_sha256':None,
        'rfc3161_token_sha256':None,'rfc3161_gen_time_utc':None,
        'rfc3161_chain_verified_under_supplied_root':False,
        'tsa_cert_path_count':0,'tsa_signer_der_sha256':None,
        'tsa_root_der_sha256':None,'bounded_crl_current_and_not_revoked':False,
        'prior_head_matches_authentic_ec389_sources':False,
        'prior_head_matches_ec390_signed_snapshot':None,
        'claimed_prior_logged_utc':None}
    if href is None:
        if src['pairs']:flags[FLAGS[2]]=True
        return status,previous
    raw=read(href,'signed_prior_offsite_log_head',MAX_SIGNED)
    signed=transparency.strict_json(raw,'EC391_SIGNED_PRIOR_OFFSITE_HEAD')
    exact(signed,prior.SIGNED_FIELDS,'PRIOR_OFFSITE_SIGNED_HEAD')
    claim=signed['claim']
    need(type(claim) is dict and claim.get('offsite_keeper_id') in keepers,
         'SIGNED_LOG_KEEPER_MUST_BE_IN_OUTSIDE_ROSTER','permission_denied')
    claim=prior._signed(signed,SIGNED_SCHEMA,CLAIM_SCHEMA,CLAIM_FIELDS,
              keepers[claim['offsite_keeper_id']],DOMAIN,'PRIOR_OFFSITE_HEAD')
    pairs=claim['ec389_signed_source_pairs']
    need(type(pairs) is list and len(pairs)<=8 and
         all(type(p) is dict and set(p)==prior.PAIR_FIELDS and
             all(transparency._sha(v) for v in p.values()) for p in pairs) and
         len({p['ec389_signed_witness_original_sha256'] for p in pairs})==len(pairs) and
         len({p['ec389_signed_custody_original_sha256'] for p in pairs})==len(pairs),
         'PRIOR_OFFSITE_LOG_HEAD_EXACT_SOURCE_SHA_TRIPLES_REQUIRED','permission_denied')
    need(claim['directory_lineage_id']==lineage and claim['tsa_channel_id']==cid and
         type(claim['epoch_index']) is int and claim['epoch_index']==idx and
         type(claim['log_sequence']) is int and claim['log_sequence']==idx+1 and
         prior.old338._utc(claim['claimed_logged_utc']),
         'SIGNED_PRIOR_OFFSITE_HEAD_LINEAGE_EPOCH_SEQUENCE_UTC_MISMATCH',
         'permission_denied')
    predecessor=previous['head'] if previous else ZERO
    if claim['previous_signed_offsite_head_original_sha256']!=predecessor:
        flags[FLAGS[5]]=True
    if previous and (len(pairs)<len(previous['pairs']) or
                     pairs[:len(previous['pairs'])]!=previous['pairs']):
        flags[FLAGS[5]]=True
    claimed=tsa._utc(claim['claimed_logged_utc'])
    if previous and claimed<previous['claimed']:
        flags[FLAGS[6]]=True
    if src['last_deposit'] is not None and claimed<src['last_deposit']:
        flags[FLAGS[6]]=True
    match_authentic=pairs==src['pairs']
    if not match_authentic:flags[FLAGS[3]]=True
    snapshot_sha=sha(canonical.canonical(pairs))
    status.update({'prior_signed_head_sha256':href['sha256'],
       'prior_signed_snapshot_sha256':snapshot_sha,
       'prior_head_matches_authentic_ec389_sources':match_authentic,
       'claimed_prior_logged_utc':claim['claimed_logged_utc']})
    later=ec390_row['signed_archive_head_original']
    if later is not None:
        later_signed=transparency.strict_json(read(later,'verified_later_ec390_head',prior.MAX_SIGNED),
                                               'EC391_REOPEN_EC390_SIGNED_HEAD')
        later_claim=later_signed['claim']
        need(type(later_claim) is dict and later_claim.get('ec389_signed_source_pairs') is not None,
             'REOPENED_EC390_SIGNED_SNAPSHOT_REQUIRED','permission_denied')
        # Parent EC390 already verified this exact SHA-pinned signature, its
        # original source SHA pairs, signer key and lineage. Reopen it and
        # compare; a new prior signed disagreement is adverse, not discarded.
        same=pairs==later_claim['ec389_signed_source_pairs']
        status['prior_head_matches_ec390_signed_snapshot']=same
        if not same:flags[FLAGS[4]]=True
    newprev={'head':href['sha256'],'pairs':pairs,'claimed':claimed,
             'signed_gen':previous['signed_gen'] if previous else None}
    if tokenref is None:
        flags[FLAGS[2]]=True
        return status,newprev
    trust=authorities[aid]
    token=read(tokenref,'original_rfc3161_prior_head_timestamp',MAX_DER)
    verification=tsa._tsa_token(token,raw,trust['root'],trust['policy'])
    crls=tsa._check_crls(verification['certificate_path'],trust['crls'],
                         verification['token_gen_time'],evaluation)
    gen=verification['token_gen_time']
    signed_gen=gen.isoformat(timespec='seconds').replace('+00:00','Z')
    if gen>evaluation or (previous and previous['signed_gen'] and
          gen<previous['signed_gen']) or gen<claimed or (
          src['last_deposit'] is not None and
          gen<src['last_deposit']):
        flags[FLAGS[6]]=True
    if later is not None:
        later_claim=later_signed['claim']
        # A *claimed* EC390 archive UTC is not an authenticated historic cutoff.
        # This finding is comparison only, not a trusted proof of backdating.
        if gen>tsa._utc(later_claim['claimed_archived_utc']):flags[FLAGS[6]]=True
    if crls['revoked_at_or_before_gen_time'] or not crls[
          'all_chain_edges_have_single_fresh_crl_as_furnished']:
        flags[FLAGS[7]]=True
    status.update({'rfc3161_token_sha256':tokenref['sha256'],
        'rfc3161_gen_time_utc':signed_gen,
        'rfc3161_chain_verified_under_supplied_root':True,
        'tsa_cert_path_count':verification['signed_certificate_path_count'],
        'tsa_signer_der_sha256':verification['tsa_signer_cert_sha256'],
        'tsa_root_der_sha256':verification['tsa_root_cert_der_sha256'],
        'bounded_crl_current_and_not_revoked':crls[
            'all_chain_edges_have_single_fresh_crl_as_furnished'],
        'tsa_authority_id':aid,'signed_token_policy_oid':verification['token_policy_oid']})
    newprev['signed_gen']=gen
    return status,newprev


def _engine(derive,**opts):
    older,evaluation=_inputs(opts,derive)
    real=prior.audit(**older) # Required UNMODIFIED live EC390 -> EC369 chain.
    n=len(opts['historical_directory_root_shas']);parent_sha=_parent(real,n)
    pins={};categories={};forbidden=set();read_cache={};late={}
    old_paths={v for k,v in opts.items() if k.endswith('_file') and type(v) is str}
    def read(ref,label,cap):
        originals.prior.lineage.parent.ref_check(ref,'EC391_'+label)
        path=ref['path'];pin=ref['sha256']
        need(path not in forbidden,'PROTECTED_SENDER_OR_PREVIOUS_ORIGINAL_REUSED',
             'permission_denied')
        if path in read_cache:
            previous,raw=read_cache[path]
            need(pin==previous and len(raw)<=cap,'PATH_OR_SHA_REUSE_MISMATCH','permission_denied')
            return raw
        raw=originals._read(ref,'ec391_'+label,cap,pins,categories,forbidden)
        read_cache[path]=(pin,raw)
        late[path]=(pin,cap)
        return raw
    def doc(ref,label,cap):
        return transparency.strict_json(read(ref,label,cap),'EC391_'+label)
    old390ref={'path':opts[prior.NEW_SCALARS[0]],'sha256':opts[prior.NEW_SCALARS[1]]}
    old389ref={'path':opts[prior.parent.NEW_SCALARS[0]],
               'sha256':opts[prior.parent.NEW_SCALARS[1]]}
    newref={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    old390=doc(old390ref,'verified_ec390_archive',prior.MAX_BUNDLE)
    old389=doc(old389ref,'authentic_ec389_archive',prior.parent.MAX_BUNDLE)
    new=doc(newref,'prior_offsite_bundle',MAX_BUNDLE)
    exact(old390,prior.BUNDLE_FIELDS,'AUTHENTIC_EC390_ARCHIVE')
    exact(old389,prior.parent.BUNDLE_FIELDS,'AUTHENTIC_EC389_ARCHIVE')
    exact(new,BUNDLE_FIELDS,'NEW_PRIOR_OFFSITE_BUNDLE')
    lineage=opts['claimed_historical_directory_lineage_id']
    need(old390['schema']==prior.BUNDLE_SCHEMA and
         old389['schema']==prior.parent.BUNDLE_SCHEMA and
         new['schema']==BUNDLE_SCHEMA and
         old390['claimed_directory_lineage_id']==lineage==old389['claimed_directory_lineage_id']==
             new['claimed_directory_lineage_id'] and
         real['historical_independent_archive_original_sha256']==old390ref['sha256'] and
         new['parent_ec390_independent_archive_original_sha256']==old390ref['sha256'] and
         new['parent_ec390_canonical_result_sha256']==parent_sha and
         type(new['epochs']) is list and len(new['epochs'])==n and
         len(old390['epochs'])==len(old389['epochs'])==n,
         'LIVE_EC390_PARENT_OR_ARCHIVE_SHA_LINEAGE_MISMATCH','permission_denied')
    # Forbid sender-origin paths and any sharing with antecedent bundle paths.
    senderref={'path':opts['historical_transparency_archive_bundle_file'],
              'sha256':opts['expected_historical_transparency_archive_bundle_sha256']}
    sender=doc(senderref,'old_ec377_sender_origin_index',prior.oldindex.MAX_BUNDLE)
    exact(sender,prior.oldindex.BUNDLE_FIELDS,'OLD_SENDER_ORIGIN_INDEX')
    for ep in sender['epochs']:
        origin=ep['ec353_publication_bundle_original']
        payload=doc(origin,'old_ec353_untrusted_sender_origin',transparency.MAX_BUNDLE)
        prior.oldsource._old_sender_labels(payload,forbidden)
        forbidden.add(origin['path'])
    forbidden.add(senderref['path'])
    excluded_ids,excluded_keys=_old_exclusions(opts,old389,old390,read,doc,n)
    rosterref=new['offsite_log_keeper_roster_original']
    trustref=new['tsa_trust_registry_original']
    need(rosterref['path']!=trustref['path'] and
         rosterref['path'] not in old_paths and trustref['path'] not in old_paths,
         'NEW_LOG_ROSTER_AND_TRUST_REGISTRY_DISTINCT_FROM_PARENT','permission_denied')
    roster=doc(rosterref,'outside_keeper_roster',MAX_ROSTER)
    trustdoc=doc(trustref,'outside_tsa_trust_registry',MAX_TRUST)
    need(roster['claimed_directory_lineage_id']==lineage,'KEEPER_ROSTER_LINEAGE',
         'permission_denied')
    keepers=_keeper_roster(roster,rosterref,opts[NEW_SCALARS[2]],read,
                            excluded_ids,excluded_keys)
    authorities=_trust_registry(trustdoc,trustref,opts[NEW_SCALARS[3]],lineage,read)
    # New signed originals must be independent files, not old bundles/rosters,
    # raw key copies, trust roots, or legacy EC353 transmitter labels.
    new_origins=set()
    new_material={rosterref['path'],trustref['path']}
    new_material.update(r['public_key_original']['path'] for r in roster['log_keepers'])
    new_material.update(a['root_certificate_original']['path'] for a in trustdoc['authorities'])
    new_material.update(crl['path'] for a in trustdoc['authorities'] for crl in a['crl_originals'])
    need(not new_material.intersection(old_paths),
         'NEW_OFFSITE_KEYS_TSA_TRUST_AND_CRL_NOT_PARENT_INPUT_ORIGINALS',
         'permission_denied')
    reserved=set(old_paths)|new_material
    for ep in new['epochs']:
        exact(ep,EPOCH_FIELDS,'PRIOR_TIME_EPOCH')
        for row in ep['channels']:
            exact(row,CHANNEL_FIELDS,'PRIOR_TIME_CHANNEL')
            for key in ('signed_prior_offsite_head_original','rfc3161_timestamp_original'):
                ref=row[key]
                if ref is not None:
                    originals.prior.lineage.parent.ref_check(ref,'EC391_'+key)
                    need(ref['path'] not in reserved and ref['path'] not in new_origins,
                         'NEW_SIGNED_HEAD_OR_TSA_MUST_HAVE_UNIQUE_ORIGINAL_PATH',
                         'permission_denied')
                    new_origins.add(ref['path'])
    # An authentic EC389 source is rederived from the original signed witnesses
    # and custodians; not from the caller's new retrospective log itself.
    oldrosterref=old389['external_verifier_roster_original']
    oldroster=doc(oldrosterref,'real_ec389_external_verifier_roster',prior.parent.MAX_ROSTER)
    oldparties=prior.parent._roster(oldroster,oldrosterref,
                      opts[prior.parent.NEW_SCALARS[2]],read,set())
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not real['local_independent_signed_archive_heads_and_receipts_consistent']
    source_epochs=[]
    for idx,ep in enumerate(old389['epochs']):
        source,_,_,count=prior._source_epoch(ep,oldparties,read,idx,lineage)
        review=real['historical_independent_archive_epoch_reviews'][idx]
        need(count==review['visible_authentic_ec389_revocation_pair_count'],
             'EC389_REOPENED_ORIGINAL_PAIR_COUNT_CHANGED_AFTER_LIVE_EC390',
             'permission_denied')
        source_epochs.append(source)
    reviews=[];inventory=[];previous={};verified_tokens=0
    for idx,ep in enumerate(new['epochs']):
        need(type(ep['epoch_index']) is int and ep['epoch_index']==idx and
             type(ep['channels']) is list and
             [r.get('tsa_channel_id') for r in ep['channels']]==list(source_epochs[idx]) and
             [r['tsa_channel_id'] for r in old390['epochs'][idx]['channels']]==list(source_epochs[idx]),
             'PRIORTIME_EXACT_AUTHENTIC_CHANNELS_EPOCH_ORDER_REQUIRED',
             'permission_denied')
        rows=[];head_rows=[];token_rows=[]
        for row,oldrow in zip(ep['channels'],old390['epochs'][idx]['channels'],strict=True):
            cid=row['tsa_channel_id']
            after,before=_channel(row,source_epochs[idx][cid],oldrow,keepers,authorities,
                                 read,lineage,idx,previous.get(cid),flags,evaluation)
            rows.append(after)
            if before is not None:previous[cid]=before
            verified_tokens+=int(after['rfc3161_chain_verified_under_supplied_root'])
            head_rows.append({'tsa_channel_id':cid,
               'signed_prior_offsite_head_sha256':after['prior_signed_head_sha256'],
               'signed_prior_source_snapshot_sha256':after['prior_signed_snapshot_sha256']})
            token_rows.append({'tsa_channel_id':cid,
               'rfc3161_timestamp_sha256':after['rfc3161_token_sha256'],
               'tsa_root_der_sha256':after['tsa_root_der_sha256']})
        heads=sha(canonical.canonical(head_rows));tokens=sha(canonical.canonical(token_rows))
        count=sum(int(r['rfc3161_chain_verified_under_supplied_root']) for r in rows)
        flags[FLAGS[1]]|=(heads!=opts[NEW_REPEATS[0][0]][idx] or
                         tokens!=opts[NEW_REPEATS[1][0]][idx] or
                         count<opts[NEW_REPEATS[2][0]][idx])
        if any(r['authentic_ec389_source_pair_count']>0 and not
                r['rfc3161_chain_verified_under_supplied_root'] for r in rows):
            flags[FLAGS[2]]=True
        reviews.append({'epoch_index':idx,'prior_timestamped_signed_head_count':count,
            'prior_offsite_signed_head_inventory_sha256':heads,
            'prior_rfc3161_token_inventory_sha256':tokens,
            'missing_prior_head_or_timestamp_channels':sum(
                bool(r['authentic_ec389_source_pair_count'] and not
                     r['rfc3161_chain_verified_under_supplied_root']) for r in rows)})
        inventory.append({'epoch_index':idx,'prior_offsite_signed_time_channels':rows,
                          'prior_offsite_signed_head_inventory_sha256':heads,
                          'prior_rfc3161_timestamp_inventory_sha256':tokens})
    derived={'schema':INVENTORY_SCHEMA,'parent_live_ec390_canonical_result_sha256':parent_sha,
        'parent_original_ec390_archive_sha256':old390ref['sha256'],
        'prior_offsite_original_bundle_sha256':newref['sha256'],
        'outside_log_keeper_roster_original_sha256':rosterref['sha256'],
        'outside_tsa_trust_registry_original_sha256':trustref['sha256'],
        'claimed_directory_lineage_id':lineage,'prior_offsite_epoch_reviews':inventory}
    digest=sha(canonical.canonical(derived))
    if not derive and digest!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    # Detect a path/file mutation during the actual parent + new independent
    # audit, not only on early input SHA checks. All observed paths are reopened.
    for path,(pin,cap) in late.items():
        raw=originals._read({'path':path,'sha256':pin},'ec391_late_original',
                             cap,{}, {},set())
        need(sha(raw)==pin,'SIGNED_SOURCE_CHANGED_AFTER_PRIOR_TIMESTAMP_CHECK',
             'permission_denied')
    flags[FLAGS[8]]=True;flags[FLAGS[9]]=True
    local=not any(flags[k] for k in FLAGS[:8])
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
        'command':('derive-historical-ec339-prior-offsite-time-inventory' if derive else
                   'audit-historical-ec339-prior-offsite-time'),
        'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                      OUTCOMES[-1])+'_unresolved',
        'exit_code':2,'offline_unresolved_exit_code':2,
        'verified_live_parent_ec390_canonical_result_sha256':parent_sha,
        'historical_prior_offsite_time_original_sha256':newref['sha256'],
        'receiver_verified_prior_offsite_time_inventory_sha256':digest,
        'cryptographically_verified_timestamped_prior_head_count':verified_tokens,
        'historical_prior_offsite_time_epoch_reviews':reviews,
        'local_prior_offsite_signatures_timestamp_chain_consistent':local,
        'sender_origin_path_required_or_read':False,
        'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
        **flags,**{name:False for name in NEGATIVES},
        **({'unsigned_prior_offsite_time_inventory':derived} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
