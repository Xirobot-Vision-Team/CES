#!/usr/bin/env python3
"""EC380. Verify received original EC350 RFC3161 token/EC349 receipt bytes and
issuer CRL/OCSP, grafted to live EC379->EC369 signed history.

The verifier neither issues timestamps nor certifies outside TSA identity.
Every input original is receiver-local, SHA-pinned, role-isolated and late-read.
No historic EC349->EC337 parent result is manufactured; lawful exit is 2.
"""
from __future__ import annotations

from datetime import timedelta
import re

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec350_tsa_timestamp import timestamp as old350
from ec351_tsa_provenance import provenance as old351
from ec352_key_registry import registry as old352
from ec353_transparency import transparency as old353
from ec349_dual_channel_anchor import anchor as old349
from ec343_hold_receipts import timeline as old343
from ec295_delivery_anchor import anchor as signer_check
from ec372_historical_authority import authority_archive as p372
from ec376_historical_disclosure import disclosure_archive as p376
from ec378_historical_registry import registry_archive as p378
from ec379_historical_source import source_archive as previous

RESULT_SCHEMA='ces.ec380.receiver_original_rfc3161_token_revocation_unresolved.v1'
DERIVE_SCHEMA='ces.ec380.unsigned_original_rfc3161_token_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec380.receiver_rfc3161_original_denial.v1'
BUNDLE_SCHEMA='ces.ec380.receiver_old_ec350_timestamp_original_archive.v1'
INVENTORY_SCHEMA='ces.ec380.receiver_verified_ec350_timestamp_original_inventory.v1'
MAX_BUNDLE=120_000
MAX_RECEIPTS=4
MAX_INTERMEDIATES=old350.MAX_CERT_PATH-2
MAX_CRL=old350.MAX_CRLS
MAX_OCSP=8
NEW_SCALARS=('historical_timestamp_archive_bundle_file',
             'expected_historical_timestamp_archive_bundle_sha256')
AUDIT_ONLY=('expected_retained_historical_timestamp_inventory_sha256',)
NEW_REPEATS=(
 ('historical_timestamp_evidence_inventory_shas','--historical-timestamp-evidence-inventory-sha256'),
 ('historical_timestamp_revocation_inventory_shas','--historical-timestamp-revocation-inventory-sha256'),
 ('minimum_historical_verified_timestamp_counts','--minimum-historical-verified-timestamp-count'),
 ('minimum_historical_signed_revocation_edge_counts','--minimum-historical-signed-revocation-edge-count'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
PARENT_SCALARS=(*previous.PARENT_SCALARS,*previous.NEW_SCALARS,*previous.AUDIT_ONLY)
PARENT_REPEATS=(*previous.PARENT_REPEATS,*previous.REPEAT_NAMES)
BUNDLE_FIELDS={'schema','parent_ec379_canonical_result_sha256',
               'ec379_historical_source_archive_original_sha256',
               'claimed_directory_lineage_id','epochs'}
EPOCH_FIELDS={'epoch_index','timestamps'}
TIMESTAMP_FIELDS={'tsa_channel_id','ec349_receipt_original',
 'rfc3161_timestamp_original','tsa_signer_certificate_original',
 'tsa_intermediate_certificate_originals','issuer_crl_originals',
 'issuer_ocsp_originals'}
OCSP_FIELDS={'signed_ocsp_original','expected_nonce_hex'}
FLAGS=(
 'inherited_live_ec379_through_ec369_signed_source_or_registry_dispute',
 'independently_retained_timestamp_or_revocation_inventory_floor_disagrees',
 'old_ec350_token_or_ec349_receipt_original_missing_for_source_channel',
 'signed_ec350_gen_time_outside_ec351_source_or_ec352_registry_authorization',
 'real_ec350_signed_crl_missing_stale_ambiguous_or_revoked',
 'real_ec351_signed_ocsp_missing_stale_unknown_revoked_or_conflicting',
 'old_ec350_signed_timestamp_epoch_rollback_or_double_binding',
 'complete_old_ec349_through_ec337_original_canonical_parents_not_rebuilt',
 'outside_tsa_identity_calibrated_utc_and_global_revocation_not_proven',
)
OUTCOMES=(
 'ec380_inherited_live_historical_source_dispute',
 'ec380_retained_signed_timestamp_or_revocation_floor_disagrees',
 'ec380_historical_token_or_receipt_originals_missing',
 'ec380_signed_time_or_issuer_authorization_window_dispute',
 'ec380_signed_crl_evidence_absent_stale_ambiguous_or_revoked',
 'ec380_signed_ocsp_evidence_absent_stale_conflicting_or_revoked',
 'ec380_signed_timestamp_cross_epoch_or_double_receipt_dispute',
 'ec380_historical_ec349_through_ec337_canonical_originals_incomplete',
 'ec380_outside_time_and_issuer_independence_unproven',
)
NEGATIVES=(
 'ec349_through_ec337_complete_canonical_parent_replay_performed',
 'old_ec349_receipt_signature_and_full_channel_ancestry_rebuilt',
 'signed_tsa_gen_time_proves_independently_trusted_calibrated_utc',
 'furnished_root_ca_or_policy_proves_official_qualified_tsa',
 'supplied_crl_and_ocsp_prove_complete_external_revocation_census',
 'signed_timestamp_selects_winner_of_hidden_ec349_forks',
 'locally_signed_token_proves_receipt_was_physically_delivered',
 'same_channel_root_or_attester_establishes_distinct_issuer_institutions',
 'old_ec353_sender_origin_path_used_as_receiver_original',
 'unsigned_caller_report_substituted_for_verified_parent_or_signed_token',
 'remote_aia_ocsp_fetch_os_trust_store_or_private_tsa_signer_invoked',
 'network_cas_worm_powershell_or_external_issuer_action_invoked',
 'mock_ec366_to_ec337_removed_or_final_acceptance_granted',
)


def need(ok, code, status='invalid_input'):
    if ok is not True:raise errors.AnchorError('EC380_'+code,status)


def exact(value, keys, name):
    need(type(value) is dict and set(value)==set(keys),name+'_EXACT_FIELDS_REQUIRED')


def sha(raw):return previous.sha(raw)


def _inputs(opts,derive):
    expected=set(PARENT_SCALARS)|set(PARENT_REPEATS)|set(NEW_SCALARS)|set(REPEAT_NAMES)
    if not derive:expected.update(AUDIT_ONLY)
    need(set(opts)==expected,'EXACT_PARENT_AND_TIMESTAMP_INPUTS_REQUIRED')
    p={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    previous._inputs(p,False)
    p372.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                             'EC380_RECEIVER_TIMESTAMP_ARCHIVE')
    if not derive:
        need(old353._sha(opts[AUDIT_ONLY[0]]),
             'EXTERNAL_TIMESTAMP_INVENTORY_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'HISTORICAL_EPOCH_COUNT_INVALID')
    for k in REPEAT_NAMES:
        values=opts[k]
        need(type(values) is list and len(values)==n,
             k.upper()+'_ONE_VALUE_PER_EPOCH_REQUIRED')
        if k.startswith('minimum_'):
            maximum=4 if 'timestamp' in k else 16
            need(all(type(x) is int and 0<=x<=maximum for x in values),
                 k.upper()+'_BOUNDED_FLOOR_REQUIRED')
        else:
            need(all(old353._sha(x) for x in values),k.upper()+'_SHA_INVALID')
    return p


def _trusted_parent(parent, n):
    need(type(parent) is dict and parent.get('schema')==previous.RESULT_SCHEMA and
         parent.get('exit_code')==2 and
         parent.get('sender_origin_path_required_or_read') is False and
         parent.get('ec350_through_ec337_full_historical_parent_replay_performed') is False and
         type(parent.get('historical_source_epoch_reviews')) is list and
         len(parent['historical_source_epoch_reviews'])==n,
         'REAL_EC379_THROUGH_EC369_PRODUCTION_PARENT_REQUIRED','unavailable')
    return sha(canonical.canonical(parent))


def _timestamp(token, source, read, evaluation):
    """Revalidate full RFC3161 CMS, ESSCertID, signed attributes, signer
    certificate path, full receipt imprint and all furnished revocation bytes.
    Broken crypto is denied. No revocation evidence is never assumed good.
    """
    exact(token,TIMESTAMP_FIELDS,'HISTORICAL_EC350_TIMESTAMP')
    channel=token['tsa_channel_id']
    need(old353._ident(channel) and channel==source['channel'],
         'TOKEN_CHANNEL_DOES_NOT_MATCH_ACTUAL_SIGNED_EC351_SOURCE',
         'permission_denied')
    intermediates=token['tsa_intermediate_certificate_originals']
    crlrefs=token['issuer_crl_originals']
    ocsprefs=token['issuer_ocsp_originals']
    need(type(intermediates) is list and len(intermediates)<=MAX_INTERMEDIATES and
         type(crlrefs) is list and len(crlrefs)<=MAX_CRL and
         type(ocsprefs) is list and len(ocsprefs)<=MAX_OCSP,
         'TIMESTAMP_CERTIFICATE_OR_REVOCATION_LIST_BOUNDS_INVALID')
    for item in ocsprefs:exact(item,OCSP_FIELDS,'HISTORICAL_OCSP_RESPONSE')
    receiptref=token['ec349_receipt_original']
    raw_receipt=read(receiptref,'exact_ec349_receipt_original',old350.MAX_RECEIPT_BYTES)
    need(len(raw_receipt)>0,'EMPTY_EC349_RECEIPT_NOT_ACCEPTED','permission_denied')
    # Treat signed historic receipt bytes as the object to be time stamped;
    # full old EC349 channel-authority reconstruction is separately missing.
    receipt=old353.strict_json(raw_receipt,'EC380_HISTORIC_EC349_RECEIPT')
    exact(receipt,{'schema','claim','signature_ed25519'},'OLD_EC349_SIGNED_RECEIPT')
    claim=receipt['claim']
    exact(claim,old349.RECEIPT_FIELDS,'OLD_EC349_ORIGINAL_SIGNED_CLAIM')
    need(receipt['schema']==old349.RECEIPT_SCHEMA and
         claim['schema']==old349.RECEIPT_CLAIM and
         claim['channel_id']==channel and
         signer_check.valid_pub(claim['receipt_signer_public_hex']) and
         claim['statement_kind'] in old349.KINDS and
         type(claim['sequence']) is int and 1<=claim['sequence']<=old349.MAX_SEQUENCES and
         (claim['sequence']!=1 or claim['statement_kind']==old349.KINDS[0]) and
         (claim['sequence']==1 or claim['statement_kind']!=old349.KINDS[0]) and
         claim['scope']=='signed_out_of_band_keeper_heads_claim_only' and
         claim['no_remote_custody_or_external_time_authority'] is True and
         old353._sha(claim['channel_directory_original_raw_sha256']) and
         old353._sha(claim['statement_nonce_sha256']),
         'EC349_ORIGINAL_RECEIPT_SIGNED_CLAIM_FIELDS_INVALID',
         'permission_denied')
    if claim['sequence']==1:
        need(claim['previous_statement_file'] is None and
             claim['previous_statement_original_raw_sha256'] is None,
             'EC349_INITIAL_RECEIPT_PREDECESSOR_FORBIDDEN',
             'permission_denied')
    else:
        need(type(claim['previous_statement_file']) is str and
             old353._sha(claim['previous_statement_original_raw_sha256']),
             'EC349_LATER_RECEIPT_CLAIMS_PINNED_PREDECESSOR',
             'permission_denied')
    need(old350._utc(claim['claimed_received_utc'])<=
         old350._utc(claim['expires_utc']),
         'EC349_SIGNED_RECEIPT_CLAIMED_TIME_WINDOW_INVALID',
         'permission_denied')
    old343._signed(receipt,old349.RECEIPT_SCHEMA,old349.D_RECEIPT,
                   claim['receipt_signer_public_hex'],
                   'EC380_REPLAY_TRUE_OLD_EC349_RECEIPT_SIGNATURE')
    need(sha(bytes.fromhex(claim['receipt_signer_public_hex']))!=source['attester_sha'],
         'EC349_RECEIPT_SIGNER_MUST_NOT_REUSE_EC351_SOURCE_ATTESTER',
         'permission_denied')
    root=old350._certificate(read(source['root_ref'],'ec351_actual_tsa_root_certificate',
                                   old350.MAX_CERT_BYTES))
    rawtoken=read(token['rfc3161_timestamp_original'],'ec350_actual_rfc3161_signed_der',
                  old350.MAX_DER_BYTES)
    verification=old350._tsa_token(rawtoken,raw_receipt,root,
                                   source['binding']['tsa_policy_oid'])
    signed_time=verification['token_gen_time']
    need(signed_time<=evaluation+timedelta(seconds=old350.MAX_SKEW_SECONDS),
         'TOKEN_SIGNED_TIME_AHEAD_OF_EVALUATION_OUTSIDE_CLOCK_SKEW',
         'permission_denied')
    path=verification['certificate_path']
    signer_bytes=read(token['tsa_signer_certificate_original'],
                      'ec350_signer_certificate_original',old350.MAX_CERT_BYTES)
    signer=old350._certificate(signer_bytes)
    need(signer.public_bytes(encoding=Encoding.DER)==
         path[0].public_bytes(encoding=Encoding.DER),
         'EXTERNALLY_PINNED_TSA_SIGNER_CERTIFICATE_NOT_CMS_SIGNER',
         'permission_denied')
    need(len(intermediates)==len(path)-2,
         'EXPLICIT_INTERMEDIATE_CERTIFICATES_NOT_FULL_EXACT_PATH',
         'permission_denied')
    for ref,verified_cert in zip(intermediates,path[1:-1],strict=True):
        original=old350._certificate(read(ref,'ec350_explicit_intermediate_original',
                                       old350.MAX_CERT_BYTES))
        need(original.fingerprint(hashes.SHA256())==verified_cert.fingerprint(hashes.SHA256()),
             'PINNED_INTERMEDIATE_NOT_CMS_SIGNED_CERTIFICATE_PATH',
             'permission_denied')
    crls=[];seen_crls=set()
    for ref in crlrefs:
        need(ref['sha256'] not in seen_crls,'DUPLICATED_CRL_ORIGINAL_DENIED',
             'permission_denied')
        seen_crls.add(ref['sha256'])
        crl=old350._crl(read(ref,'ec351_signed_issuer_crl_original',old350.MAX_CRL_BYTES))
        candidates=[i for i in path[1:] if i.subject==crl.issuer]
        need(len(candidates)==1,'CRL_NOT_ASSOCIATED_WITH_UNIQUE_CERT_PATH_ISSUER',
             'permission_denied')
        old350._crl_signed_by(crl,candidates[0])  # all supplied, even conflicting
        crls.append(crl)
    crl_result=old350._check_crls(path,crls,signed_time,evaluation)
    ocsp_docs=[];seen_ocsp=set()
    for row in ocsprefs:
        ref=row['signed_ocsp_original']
        need(ref['sha256'] not in seen_ocsp,
             'DUPLICATE_SIGNED_OCSP_ORIGINAL_DENIED','permission_denied')
        seen_ocsp.add(ref['sha256'])
        response,nonce=old351._signed_ocsp(
            read(ref,'ec351_signed_ocsp_response_original',old351.MAX_OCSP_SIZE),
            row['expected_nonce_hex'])
        ocsp_docs.append((ref['sha256'],response,nonce))
    edge_rows=[];signed_edges=0;adverse_crl=False;adverse_ocsp=False
    for subject,issuer in zip(path[:-1],path[1:],strict=True):
        edge=old351._crl_status_at_eval(crls,subject,issuer,evaluation)
        matching=[]
        for identifier,response,nonce in ocsp_docs:
            singles=[s for s in response.responses if old351._match_single(s,subject,issuer)]
            if singles:
                need(len(singles)==1,'DUPLICATED_OCSP_CERTID_IN_SIGNED_RESPONSE',
                     'permission_denied')
                signer=old351._verify_response_signer(response,issuer,evaluation)
                info=old351._single_evaluation(singles[0],response.produced_at_utc,evaluation)
                info.update(signer);info.update(nonce)
                info['signed_response_original_sha256']=identifier
                info['status_revoked_at_signed_tsa_time']=(
                    info['ocsp_signed_status']=='signed_revoked' and
                    singles[0].revocation_time_utc<=signed_time)
                matching.append(info)
        status_crl=next(x['bounded_crl_status'] for x in crl_result[
            'certificate_revocation_rows'] if x['certificate_sha256']==
                              subject.fingerprint(hashes.SHA256()).hex())
        if len(matching)!=1:adverse_ocsp=True
        if (status_crl!='signed_crl_bounded_window_and_no_prior_revocation' or
            edge!='signed_good'):adverse_crl=True
        if matching:
            signed_edges+=1
            if any(x['ocsp_signed_status']!='signed_good' or
                   not x['fresh_for_caller_evaluation'] for x in matching):
                adverse_ocsp=True
        if status_crl=='signed_crl_reports_revoked_at_or_before_tst_gen_time':
            adverse_crl=True
        if any(x['status_revoked_at_signed_tsa_time'] for x in matching):
            adverse_ocsp=True
        if (matching and matching[0]['ocsp_signed_status']=='signed_good' and
            edge=='signed_revoked'):
            adverse_ocsp=True
        edge_rows.append({
          'subject_certificate_der_sha256':subject.fingerprint(hashes.SHA256()).hex(),
          'issuer_certificate_der_sha256':issuer.fingerprint(hashes.SHA256()).hex(),
          'signed_crl_bounded_status':status_crl,
          'signed_crl_status_at_caller_evaluation':edge,
          'matching_signed_ocsp_originals':matching,
          'crl_ocsp_conflict_or_missing':len(matching)!=1 or
             edge!='signed_good' or any(x['ocsp_signed_status']!='signed_good' or
                                  not x['fresh_for_caller_evaluation'] for x in matching),
        })
    # All furnished signed OCSP SingleResponses MUST be applicable. A signed
    # but irrelevant response cannot count, and a malformed signature cannot
    # hide by being out of scope.
    need(all(any(old351._match_single(single,subj,issuer)
                 for subj,issuer in zip(path[:-1],path[1:],strict=True))
                 for _,response,_ in ocsp_docs for single in response.responses),
         'SIGNED_OCSP_CERTID_OUTSIDE_VERIFIED_TSA_CERTIFICATE_PATH',
         'permission_denied')
    need(all(any(identifier==e['signed_response_original_sha256']
                 for edge in edge_rows for e in edge['matching_signed_ocsp_originals'])
                 for identifier,_,_ in ocsp_docs),
         'UNUSED_OCSP_NOT_SIGNED_FOR_TSA_CERTIFICATE_PATH',
         'permission_denied')
    if crl_result['revoked_at_or_before_gen_time']:adverse_crl=True
    signed_utc=signed_time.isoformat().replace('+00:00','Z')
    signed_receipt_claim_close_to_tst_gen_time=(abs((signed_time-old350._utc(
                 claim['claimed_received_utc'])).total_seconds())<=
                 old350.MAX_SKEW_SECONDS)
    return {
      'tsa_channel_id':channel,
      'ec349_receipt_original_sha256':receiptref['sha256'],
      'actual_ec349_receipt_ed25519_self_claim_signature_verified':True,
      'ec349_receipt_signer_public_sha256':sha(bytes.fromhex(claim['receipt_signer_public_hex'])),
      'ec349_receipt_sequence':claim['sequence'],
      'signed_ec349_receipt_claim_close_to_tst_gen_time':signed_receipt_claim_close_to_tst_gen_time,
      'real_rfc3161_signed_token_original_sha256':token['rfc3161_timestamp_original']['sha256'],
      'rfc3161_signed_gen_time_utc_untrusted_clock':signed_utc,
      'real_cms_signed_attributes_esscertid_and_receipt_imprint_verified':True,
      'imprint_digest_algorithm':verification['imprint_digest_algorithm'],
      'policy_oid_signed_in_tstinfo':verification['token_policy_oid'],
      'actual_tsa_signer_der_sha256':verification['tsa_signer_cert_sha256'],
      'original_ec351_authenticated_root_der_sha256':verification['tsa_root_cert_der_sha256'],
      'explicit_original_certificate_path_der_shas':[
          c.fingerprint(hashes.SHA256()).hex() for c in path],
      'signed_issuer_crl_original_shas':[r['sha256'] for r in crlrefs],
      'signed_ocsp_original_shas':[r['signed_ocsp_original']['sha256'] for r in ocsprefs],
      'signed_crl_status':crl_result,
      'signed_revocation_edges':edge_rows,
      'signed_ocsp_matching_certificate_edge_count':signed_edges,
      'adverse_or_missing_crl_evidence':adverse_crl,
      'adverse_or_missing_ocsp_evidence':adverse_ocsp,
      'source_signed_issue_utc':source['document']['issued_utc'],
      'source_signed_expiry_utc':source['document']['expires_utc'],
      'signed_token_within_original_source_window':source['issued']<=signed_time<=
                old350._utc(source['document']['expires_utc']),
    }


def _engine(derive, **opts):
    parent_opts=_inputs(opts,derive)
    # Inherited result is calculated LIVE; never accept a reported success or
    # a caller-selected prior output as parent evidence.
    parent=previous.audit(**parent_opts)
    n=len(opts['historical_directory_root_shas'])
    parent_sha=_trusted_parent(parent,n)
    evaluation=old350._utc(opts['detached_evaluation_utc'])
    pins={};categories={};forbidden=set();cache={}
    def read(ref,role,cap):
        key=ref.get('path') if type(ref) is dict else None
        if key in cache:
            digest,raw,roles=cache[key]
            need(key not in forbidden and ref.get('sha256')==digest and
                 len(raw)<=cap and role in roles,
                 'PINNED_ORIGINAL_REUSED_AS_DIFFERENT_ROLE','permission_denied')
            return raw
        raw=p372._read(ref,'ec380_'+role,cap,pins,categories,forbidden)
        cache[key]=(ref['sha256'],raw,{role})
        return raw
    parentref={'path':opts['historical_source_archive_bundle_file'],
               'sha256':opts['expected_historical_source_archive_bundle_sha256']}
    signedsource=old353.strict_json(read(parentref,'verified_ec379_parent_archive',
                                     previous.MAX_BUNDLE),'EC380_EC379_PARENT_SOURCE')
    exact(signedsource,previous.BUNDLE_FIELDS,'TRUE_EC379_SOURCE_ARCHIVE')
    need(signedsource['schema']==previous.BUNDLE_SCHEMA and
         type(signedsource['epochs']) is list and len(signedsource['epochs'])==n and
         signedsource['claimed_directory_lineage_id']==opts[
             'claimed_historical_directory_lineage_id'],
         'ACTUAL_EC379_SIGNED_SOURCE_PARENT_ARCHIVE_CHANGED',
         'permission_denied')
    bundle_ref={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    bundle=old353.strict_json(read(bundle_ref,'independently_pinned_ec380_receiver_archive',
                                     MAX_BUNDLE),'EC380_TRUE_RFC3161_RECEIVER_ARCHIVE')
    exact(bundle,BUNDLE_FIELDS,'EC380_RECEIVER_ARCHIVE')
    need(bundle['schema']==BUNDLE_SCHEMA and
         bundle['parent_ec379_canonical_result_sha256']==parent_sha and
         bundle['ec379_historical_source_archive_original_sha256']==parentref['sha256'] and
         bundle['claimed_directory_lineage_id']==signedsource[
             'claimed_directory_lineage_id'] and
         type(bundle['epochs']) is list and len(bundle['epochs'])==n,
         'R380_ARCHIVE_DOES_NOT_BIND_LIVE_EC379_SOURCE_RESULT',
         'permission_denied')
    # Historic EC353 sender paths must never be dereferenced, including by an
    # attacker placing a valid signed-looking EC349 receipt at such a path.
    old377=old353.strict_json(read({
      'path':opts['historical_transparency_archive_bundle_file'],
      'sha256':opts['expected_historical_transparency_archive_bundle_sha256']},
      'verified_old_ec377_receiver_archive',previous.p377.MAX_BUNDLE),
      'EC380_VERIFIED_EC377_ARCHIVE')
    exact(old377,previous.p377.BUNDLE_FIELDS,'EC380_VERIFIED_EC377')
    need(old377['schema']==previous.p377.BUNDLE_SCHEMA and
         len(old377['epochs'])==n,'EC377_ORIGINAL_ARCHIVE_MISSING','permission_denied')
    for epoch in old377['epochs']:
        manifest=old353.strict_json(read(epoch['ec353_publication_bundle_original'],
          'old_ec353_unsigned_sender_path_label_manifest',old353.MAX_BUNDLE),
          'EC380_OLD_EC353_PUBLICATION')
        previous._old_sender_labels(manifest,forbidden)
    authenticated_registries=old353.strict_json(read({
       'path':opts['historical_registry_archive_bundle_file'],
       'sha256':opts['expected_historical_registry_archive_bundle_sha256']},
       'verified_ec378_registry_archive',p378.MAX_BUNDLE),
       'EC380_AUTHENTIC_EC378_PARENT_REGISTRIES')
    exact(authenticated_registries,p378.BUNDLE_FIELDS,'EC380_VERIFIED_EC378_REGISTRIES')
    need(authenticated_registries['schema']==p378.BUNDLE_SCHEMA and
         len(authenticated_registries['epochs'])==n and
         authenticated_registries['claimed_directory_lineage_id']==bundle[
           'claimed_directory_lineage_id'],
         'OLD_EC352_PARENT_REGISTRY_ARCHIVE_CHANGED','permission_denied')
    forbidden.update(x for k,x in opts.items() if k.endswith('_file') and type(x) is str)
    flags={key:False for key in FLAGS}
    flags[FLAGS[0]]=not parent['local_pinned_ec351_source_signatures_and_old_registry_binding_consistent']
    total_verified=total_signed_edges=missing_count=0
    used_receipts={};used_tokens={};last_token_claims={}
    rows=[];inventory_rows=[]
    for i,(epoch,src_epoch) in enumerate(zip(bundle['epochs'],signedsource['epochs'],strict=True)):
        exact(epoch,EPOCH_FIELDS,'EC380_EPOCH')
        exact(src_epoch,previous.EPOCH_FIELDS,'ORIGINAL_EC379_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==i and
             src_epoch['epoch_index']==i,'HISTORIC_EPOCH_ORDER_INVALID')
        source_info={}
        for src in src_epoch['sources']:
            parsed=previous._source(src,read,evaluation,set())
            parsed['root_ref']=src['tsa_root_certificate_original']
            need(parsed['channel'] not in source_info,
                 'DUPLICATED_EC379_SIGNED_SOURCE_CHANNEL','permission_denied')
            source_info[parsed['channel']]=parsed
        timestamps=epoch['timestamps']
        need(type(timestamps) is list and len(timestamps)<=MAX_RECEIPTS,
             'PER_EPOCH_TIMESTAMP_EVIDENCE_BOUNDED')
        need(all(type(t) is dict and type(t.get('tsa_channel_id')) is str
                 for t in timestamps),'TIMESTAMP_CHANNEL_RECORD_INVALID')
        need([t['tsa_channel_id'] for t in timestamps]==sorted(set(
                   t['tsa_channel_id'] for t in timestamps)),
             'HISTORICAL_TIMESTAMP_CHANNELS_UNIQUE_SORTED')
        tokenrows=[];revocations=[]
        for token in timestamps:
            channel=token['tsa_channel_id']
            need(channel in source_info,
                 'TOKEN_WITHOUT_ACTUAL_SIGNED_EC351_SOURCE_ORIGINAL',
                 'permission_denied')
            verified=_timestamp(token,source_info[channel],read,evaluation)
            signedtime=old350._utc(verified['rfc3161_signed_gen_time_utc_untrusted_clock'])
            # Authenticated but *claimed* issued/expiry are cross-compared to
            # cryptographically signed TSTInfo time. They aren't a trusted UTC.
            source=source_info[channel]
            reg_rows=[]
            # The parent has verified all old EC352 signatures and their
            # bindings. For genTime, replay exact signer history, not a
            # caller-authored authorization flag.
            registry_docs=authenticated_registries
            regs=registry_docs['epochs'][i]['registries']
            need(len(regs)==2,'TWO_REAL_OLD_EC352_SIGNED_REGISTRIES_REQUIRED')
            for reg in regs:
                # Verified prior parent signed history: require real source
                # authorized at timestamp time, not just at detached eval.
                checked=p378._registry(reg,read,evaluation,set(registry_docs['epochs'][i]['claimed_tsa_channel_ids']),forbidden,set())
                status=previous._claim_status(checked,source,signedtime)
                reg_rows.append({'registry_channel_id':checked['id'],
                                 'authorization_at_signed_tst_gen_time':status})
            reg_rows.sort(key=lambda r:r['registry_channel_id'])
            need(len({r['registry_channel_id'] for r in reg_rows})==2,
                 'SIGNED_REGISTRY_IDS_NOT_DISTINCT')
            verified['original_ec352_registry_status_at_token_signed_time']=reg_rows
            signed_ok=(verified['signed_token_within_original_source_window'] and
                       verified['signed_ec349_receipt_claim_close_to_tst_gen_time'] and
                       all(r['authorization_at_signed_tst_gen_time']==
                           'authorized_claim_exact_binding' for r in reg_rows))
            if not signed_ok:flags[FLAGS[3]]=True
            if verified['adverse_or_missing_crl_evidence']:flags[FLAGS[4]]=True
            if verified['adverse_or_missing_ocsp_evidence']:flags[FLAGS[5]]=True
            for dct,field in ((used_receipts,'ec349_receipt_original_sha256'),
                              (used_tokens,'real_rfc3161_signed_token_original_sha256')):
                owner=dct.get(verified[field])
                need(owner is None or owner==channel,
                     'ONE_ORIGINAL_SIGNED_TIMESTAMP_OR_RECEIPT_SHARED_BY_CHANNELS',
                     'permission_denied')
                dct[verified[field]]=channel
            previous_row=last_token_claims.get(channel)
            # A new epoch must not masquerade an old signed receipt/token as
            # newly captured. Sequence rollback and verbatim duplicate bytes
            # are disputes even when a fresh timestamp raises the genTime.
            if previous_row is not None and (
                 signedtime<=previous_row['signedtime'] or
                 verified['ec349_receipt_sequence']<=previous_row['receipt_sequence'] or
                 verified['ec349_receipt_original_sha256']==previous_row['receipt'] or
                 verified['real_rfc3161_signed_token_original_sha256']==previous_row['token']):
                flags[FLAGS[6]]=True
            last_token_claims[channel]={'signedtime':signedtime,
                'receipt_sequence':verified['ec349_receipt_sequence'],
                'receipt':verified['ec349_receipt_original_sha256'],
                'token':verified['real_rfc3161_signed_token_original_sha256']}
            total_signed_edges+=verified['signed_ocsp_matching_certificate_edge_count']
            tokenrows.append({k:verified[k] for k in (
              'tsa_channel_id','ec349_receipt_original_sha256',
              'real_rfc3161_signed_token_original_sha256',
              'rfc3161_signed_gen_time_utc_untrusted_clock',
              'actual_ec349_receipt_ed25519_self_claim_signature_verified',
              'ec349_receipt_signer_public_sha256','ec349_receipt_sequence',
              'signed_ec349_receipt_claim_close_to_tst_gen_time',
              'actual_tsa_signer_der_sha256','original_ec351_authenticated_root_der_sha256',
              'imprint_digest_algorithm','policy_oid_signed_in_tstinfo',
              'signed_token_within_original_source_window',
              'original_ec352_registry_status_at_token_signed_time')})
            revocations.append({'tsa_channel_id':channel,
              'signed_issuer_crl_original_shas':verified['signed_issuer_crl_original_shas'],
              'signed_ocsp_original_shas':verified['signed_ocsp_original_shas'],
              'signed_revocation_edges':verified['signed_revocation_edges'],
              'adverse_or_missing_crl_evidence':verified['adverse_or_missing_crl_evidence'],
              'adverse_or_missing_ocsp_evidence':verified['adverse_or_missing_ocsp_evidence']})
        missing=set(source_info)-{t['tsa_channel_id'] for t in timestamps}
        missing_count+=len(missing)
        flags[FLAGS[2]]|=bool(missing)
        flags[FLAGS[6]]|=bool(missing) and i>0
        total_verified+=len(tokenrows)
        tokhash=sha(canonical.canonical(tokenrows))
        revhash=sha(canonical.canonical(revocations))
        flags[FLAGS[1]]|=(tokhash!=opts['historical_timestamp_evidence_inventory_shas'][i] or
                         revhash!=opts['historical_timestamp_revocation_inventory_shas'][i] or
                         len(tokenrows)<opts['minimum_historical_verified_timestamp_counts'][i] or
                         sum(len(r['signed_revocation_edges']) for r in revocations
                             if not (r['adverse_or_missing_crl_evidence'] or
                                     r['adverse_or_missing_ocsp_evidence']))<
                         opts['minimum_historical_signed_revocation_edge_counts'][i])
        rows.append({'epoch_index':i,
          'real_signed_rfc3161_token_and_ec349_receipt_imprint_count':len(tokenrows),
          'missing_ec350_signed_token_for_authenticated_source_count':len(missing),
          'signed_ocsp_matching_certificate_edge_count':sum(
             sum(bool(e['matching_signed_ocsp_originals']) for e in
                 r['signed_revocation_edges']) for r in revocations),
          'timestamp_original_inventory_sha256':tokhash,
          'signed_revocation_original_inventory_sha256':revhash,
          'source_or_registry_signed_time_window_dispute':any(
             not r['signed_token_within_original_source_window'] or
             not r['signed_ec349_receipt_claim_close_to_tst_gen_time'] or any(
                 x['authorization_at_signed_tst_gen_time']!=
                 'authorized_claim_exact_binding' for x in
                 r['original_ec352_registry_status_at_token_signed_time']) for r in tokenrows),
          'signed_crl_revocation_or_missing_evidence':any(
             r['adverse_or_missing_crl_evidence'] for r in revocations),
          'signed_ocsp_revocation_or_missing_evidence':any(
             r['adverse_or_missing_ocsp_evidence'] for r in revocations),
          'complete_ec349_to_ec337_historic_parent_rebuilt':False})
        inventory_rows.append({'epoch_index':i,
           'signed_rfc3161_token_and_receipt_byte_evidence':tokenrows,
           'signed_issuer_revocation_evidence':revocations,
           'authenticated_source_channels_without_token':sorted(missing),
           'timestamp_original_inventory_sha256':tokhash,
           'revocation_original_inventory_sha256':revhash})
    p376.prior.tsa._check_late(pins)
    p376.prior.ec357._late_identity_check(pins,set())
    flags[FLAGS[7]]=True;flags[FLAGS[8]]=True
    inventory={'schema':INVENTORY_SCHEMA,
      'live_ec379_through_ec369_canonical_parent_sha256':parent_sha,
      'authenticated_ec379_source_archive_original_sha256':parentref['sha256'],
      'receiver_ec380_timestamp_archive_original_sha256':bundle_ref['sha256'],
      'claimed_directory_lineage_id':bundle['claimed_directory_lineage_id'],
      'historical_timestamp_epoch_original_reviews':inventory_rows}
    digest=sha(canonical.canonical(inventory))
    if not derive and digest!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    local=not any(flags[x] for x in FLAGS[:7])
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
      'command':'derive-historical-timestamp-inventory' if derive else
                'audit-historical-timestamp-archive',
      'status':next((OUTCOMES[i] for i,key in enumerate(FLAGS) if flags[key]),
                    OUTCOMES[-1])+'_unresolved',
      'exit_code':2,'offline_unresolved_exit_code':2,
      'historical_timestamp_archive_bundle_original_sha256':bundle_ref['sha256'],
      'verified_live_parent_ec379_canonical_result_sha256':parent_sha,
      'receiver_verified_historical_timestamp_inventory_sha256':digest,
      'verified_real_rfc3161_timestamp_receipt_imprint_count':total_verified,
      'signed_ocsp_matching_certificate_edge_count':total_signed_edges,
      'missing_authenticated_source_tsa_timestamp_count':missing_count,
      'historical_timestamp_epoch_reviews':rows,
      'local_signed_timestamp_and_revocation_inputs_consistent':local,
      'sender_origin_path_required_or_read':False,
      'ec349_through_ec337_full_historical_parent_replay_performed':False,
      **flags,**{k:False for k in NEGATIVES},
      **({'unsigned_verified_historical_timestamp_inventory':inventory,
          'caller_external_inventory_pin_created_or_certified':False} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
