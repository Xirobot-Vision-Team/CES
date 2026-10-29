#!/usr/bin/env python3
"""EC351: offline authenticated *claims* about TSA origin + actual OCSP signatures.

Verify the exact EC350->EC337 source and signed RFC3161 bytes again.  A separately
SHA-pinned public key authenticates a signed source statement, not the worldly
identity of whoever selected that key.  No caller-supplied material is a trust
registry, proof of an independent institution, calibrated time or exhaustive
revocation. No network, key generation, signer, trust store or persisted output.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, OCSPExtensionOID, SignatureAlgorithmOID

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as reg
from ec321_fork_case_transport import case
from ec343_hold_receipts import timeline as prior
from ec349_dual_channel_anchor import anchor as old349
from ec350_tsa_timestamp import timestamp as old350

RESULT_SCHEMA='ces.ec351.offline_tsa_source_and_ocsp_evidence_unresolved.v1'
DENIAL_SCHEMA='ces.ec351.offline_tsa_source_and_ocsp_evidence_denial.v1'
CHECKLIST_SCHEMA='ces.ec351.unsigned_external_source_and_ocsp_handoff.v1'
ATTESTATION_SCHEMA='ces.ec351.signed_tsa_root_policy_source_attestation.v1'
DOMAIN=b'CES/EC351/TSA-RootPolicySource/v1\x00'
MAX_ATTESTATION=24_000
MAX_SOURCE=1_000_000
MAX_PUBLIC_KEY=64
MAX_OCSP=8
MAX_OCSP_SIZE=512_000
MAX_OCSP_SINGLES=8
MAX_OCSP_RESPONDER_CERTS=6
MAX_WINDOW_DAYS=7
SKEW=timedelta(minutes=5)
OUTCOMES=(
    'ec350_missing_or_forked_signed_head_unresolved',
    'ec350_timestamp_token_not_furnished',
    'ec350_inherited_ancestry_time_or_crl_unresolved',
    'ec351_ocsp_revocation_or_crl_ocsp_conflict_unresolved',
    'ec351_signed_source_attestation_not_furnished',
    'ec351_ocsp_missing_stale_or_ambiguous_unresolved',
    'ec351_signed_sources_and_revocation_consistent_external_authority_unproven',
)
PRIORITY=(0,2,3,1,4,5,6)
NEGATIVES=(
    'caller_pinned_attester_public_key_proves_independent_real_organization',
    'signed_policy_source_document_proves_qualified_legal_tsa_status',
    'caller_reported_source_uri_proves_official_publisher_or_custody',
    'signed_ocsp_response_proves_complete_current_worldwide_revocation',
    'ocsp_good_status_overrides_signed_crl_revocation_or_conflict',
    'unsigned_or_nonprecommitted_nonce_proves_live_ocsp_exchange',
    'source_statement_supersedes_ec350_parent_ancestry_or_forks',
    'valid_tsa_origin_statement_proves_trusted_calibrated_utc',
    'distinct_statement_files_prove_independent_real_institutions',
    'offline_audit_connects_to_responders_writes_or_freezes_remote_cas',
    'ec317_ec318_original_production_and_final_acceptance_proven',
)


def need(ok: Any, reason: str, status: str='invalid_input')->None:
    if ok is not True:
        raise errors.AnchorError('EC351_'+reason,status)


def _sha(b:bytes)->str:
    return hashlib.sha256(b).hexdigest()


def _json_pairs(pairs):
    out={}
    for k,v in pairs:
        if k in out:
            raise ValueError('duplicate JSON key')
        out[k]=v
    return out


def _read_statement(raw:bytes)->dict:
    try:
        doc=json.loads(raw.decode('utf-8'),object_pairs_hook=_json_pairs,
                       parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
    except (ValueError,UnicodeError,TypeError) as exc:
        raise errors.AnchorError('EC351_ATTESTATION_JSON_INVALID','invalid_input') from exc
    need(type(doc) is dict and reg.canonical(doc)==raw,
         'ATTESTATION_MUST_BE_CANONICAL_UTF8_JSON')
    return doc


def _check_attestation(*,channel:str,statement:bytes,public_key:bytes,
                       public_key_sha:str,source_sha:str,root_sha:str,
                       root_der_sha:str,policy:str,evaluation:datetime,
                       token_time:datetime)->dict:
    doc=_read_statement(statement)
    fields={'schema','channel_id','tsa_root_original_sha256',
            'tsa_root_certificate_der_sha256','tsa_policy_oid',
            'source_document_original_sha256','attester_public_key_original_sha256',
            'claimed_source_organization','claimed_source_uri',
            'issued_utc','expires_utc','signature_ed25519_hex'}
    need(set(doc)==fields and all(type(v) is str for v in doc.values()),
         'ATTESTATION_SCHEMA_EXACT_FIELDS_REQUIRED')
    required={'schema':ATTESTATION_SCHEMA,'channel_id':channel,
              'tsa_root_original_sha256':root_sha,
              'tsa_root_certificate_der_sha256':root_der_sha,
              'tsa_policy_oid':policy,
              'source_document_original_sha256':source_sha,
              'attester_public_key_original_sha256':public_key_sha}
    need(all(doc[k]==v for k,v in required.items()),
         'ATTESTATION_SOURCE_ROOT_POLICY_OR_KEY_BINDING_MISMATCH','permission_denied')
    need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 .,_()&/-]{2,119}',
                      doc['claimed_source_organization']) is not None and
         re.fullmatch(r'https://[A-Za-z0-9][A-Za-z0-9._~:/?#@!$&()*+,;=%-]{4,999}',
                      doc['claimed_source_uri']) is not None,
         'ATTESTATION_DECLARED_ORGANIZATION_AND_SOURCE_URI_REQUIRED')
    issued=old350._utc(doc['issued_utc']);expires=old350._utc(doc['expires_utc'])
    need(issued<=evaluation<=expires and expires-issued<=timedelta(days=366),
         'ATTESTATION_OUTSIDE_DECLARED_EVALUATION_WINDOW','permission_denied')
    sig=doc['signature_ed25519_hex']
    need(re.fullmatch(r'[0-9a-f]{128}',sig) is not None and len(public_key)==32,
         'ATTESTATION_SIGNATURE_OR_PUBLIC_KEY_BYTES_INVALID')
    body={k:v for k,v in doc.items() if k!='signature_ed25519_hex'}
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(sig),DOMAIN+reg.canonical(body))
    except (InvalidSignature,ValueError) as exc:
        raise errors.AnchorError('EC351_ATTESTATION_ED25519_SIGNATURE_INVALID',
                                 'permission_denied') from exc
    return {'signed_source_statement_original_sha256':_sha(statement),
            'attester_public_key_original_sha256':public_key_sha,
            'source_document_original_sha256':source_sha,
            'root_cert_der_sha256_bound_by_signature':root_der_sha,
            'claimed_source_organization':doc['claimed_source_organization'],
            'claimed_source_uri_unfetched':doc['claimed_source_uri'],
            'attestation_signed_after_tsa_gen_time':issued>token_time,
            'source_byte_pin_and_ed25519_signature_verified':True,
            'issuer_key_out_of_band_independently_authorized':False,
            'real_world_source_provenance_authenticated':False,
            'qualified_tsa_policy_or_clock_independently_proven':False}


def _signature_algorithm_allowed(oid,hash_algorithm,public_key)->None:
    """Only supported unambiguous OCSP signature OIDs (no opaque RSA-PSS params)."""
    from cryptography.hazmat.primitives.asymmetric import rsa,ec,ed25519 as ed
    rsa_oids={SignatureAlgorithmOID.RSA_WITH_SHA256:'sha256',
              SignatureAlgorithmOID.RSA_WITH_SHA384:'sha384',
              SignatureAlgorithmOID.RSA_WITH_SHA512:'sha512'}
    ec_oids={SignatureAlgorithmOID.ECDSA_WITH_SHA256:'sha256',
             SignatureAlgorithmOID.ECDSA_WITH_SHA384:'sha384',
             SignatureAlgorithmOID.ECDSA_WITH_SHA512:'sha512'}
    if isinstance(public_key,rsa.RSAPublicKey):allowed=rsa_oids
    elif isinstance(public_key,ec.EllipticCurvePublicKey):allowed=ec_oids
    elif isinstance(public_key,ed.Ed25519PublicKey):
        need(oid==SignatureAlgorithmOID.ED25519 and hash_algorithm is None,
             'OCSP_SIGNATURE_ALGORITHM_AND_KEY_MISMATCH','permission_denied')
        return
    else:
        need(False,'UNSUPPORTED_OCSP_RESPONDER_PUBLIC_KEY','permission_denied')
    need(oid in allowed and hash_algorithm is not None and
         hash_algorithm.name==allowed[oid],
         'OCSP_SIGNATURE_ALGORITHM_AND_KEY_MISMATCH','permission_denied')


def _responder_id_match(response,cert:x509.Certificate)->bool:
    name=response.responder_name
    kh=response.responder_key_hash
    # responderID is either byName OR SHA1 public-key byKey per RFC6960.
    return ((name is not None and cert.subject==name) or
            (kh is not None and
             x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest==kh))


def _verify_response_signer(response,issuer:x509.Certificate,
                            evaluation:datetime)->dict:
    candidates=[issuer,*response.certificates]
    need(len(response.certificates)<=MAX_OCSP_RESPONDER_CERTS,
         'OCSP_TOO_MANY_RESPONDER_CERTIFICATES')
    by_fp={c.fingerprint(hashes.SHA256()):c for c in candidates}
    matches=[c for c in by_fp.values() if _responder_id_match(response,c)]
    need(len(matches)==1,'OCSP_SIGNER_MISSING_OR_AMBIGUOUS','permission_denied')
    signer=matches[0]
    delegated=signer.fingerprint(hashes.SHA256())!=issuer.fingerprint(hashes.SHA256())
    produced=response.produced_at_utc
    need(produced is not None and produced<=evaluation and
         issuer.not_valid_before_utc<=produced<=issuer.not_valid_after_utc and
         issuer.not_valid_before_utc<=evaluation<=issuer.not_valid_after_utc,
         'OCSP_PRODUCED_AT_AFTER_CALLER_EVALUATION','permission_denied')
    if delegated:
        old350._cert_signed_by(signer,issuer)
        try:
            bc=signer.extensions.get_extension_for_class(x509.BasicConstraints).value
            ku=signer.extensions.get_extension_for_class(x509.KeyUsage).value
            eku=signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound as exc:
            raise errors.AnchorError('EC351_OCSP_DELEGATE_CONSTRAINTS_MISSING',
                                     'permission_denied') from exc
        need(bc.ca is False and ku.digital_signature and
             ExtendedKeyUsageOID.OCSP_SIGNING in eku and
             signer.issuer==issuer.subject and
             signer.not_valid_before_utc<=produced<=signer.not_valid_after_utc and
             signer.not_valid_before_utc<=evaluation<=signer.not_valid_after_utc and
             all(not e.critical or e.oid in (
                 ExtensionOID.BASIC_CONSTRAINTS,ExtensionOID.KEY_USAGE,
                 ExtensionOID.EXTENDED_KEY_USAGE,ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                 ExtensionOID.SUBJECT_KEY_IDENTIFIER,ExtensionOID.OCSP_NO_CHECK)
                 for e in signer.extensions),
             'OCSP_DELEGATED_RESPONDER_NOT_AUTHORIZED_FOR_ISSUER','permission_denied')
    else:
        # OCSP delegated response signature may be by the issuing CA itself.
        try:
            ku=issuer.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound as exc:
            raise errors.AnchorError('EC351_OCSP_CA_KEY_USAGE_REQUIRED',
                                     'permission_denied') from exc
        need(ku.digital_signature and
             issuer.not_valid_before_utc<=produced<=issuer.not_valid_after_utc,
             'OCSP_ISSUER_NOT_AUTHORIZED_TO_SIGN_RESPONSE','permission_denied')
    key=signer.public_key()
    _signature_algorithm_allowed(response.signature_algorithm_oid,
                                 response.signature_hash_algorithm,key)
    old350._verify_signature(key,response.tbs_response_bytes,
                             response.signature,response.signature_hash_algorithm)
    return {'responder_cert_sha256':signer.fingerprint(hashes.SHA256()).hex(),
            'delegated_ocsp_signer':delegated,
            'responder_certificate_revocation_proven':False}


def _match_single(single,subject:x509.Certificate,issuer:x509.Certificate)->bool:
    # Compute RFC6960 CertID using cryptography's DER Name+BIT STRING
    # implementation, not a guessed hash of whole SubjectPublicKeyInfo.
    alg=single.hash_algorithm
    if alg is None or alg.name not in ('sha1','sha256','sha384','sha512'):
        return False
    request=ocsp.OCSPRequestBuilder().add_certificate(subject,issuer,alg).build()
    return (single.serial_number==request.serial_number and
            single.issuer_name_hash==request.issuer_name_hash and
            single.issuer_key_hash==request.issuer_key_hash)


def _extract_nonce(response,expected:str)->dict:
    need(expected=='NONE' or
         (type(expected) is str and re.fullmatch(r'[0-9a-f]{32,64}',expected) is not None),
         'OCSP_EXPECTED_NONCE_MUST_BE_NONE_OR_16_TO_32_BYTES_HEX')
    need(all(not ext.critical or ext.oid==OCSPExtensionOID.NONCE
             for ext in response.extensions),
         'UNKNOWN_CRITICAL_OCSP_RESPONSE_EXTENSION','permission_denied')
    try:nonce=response.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
    except x509.ExtensionNotFound:nonce=None
    if expected!='NONE':
        need(nonce==bytes.fromhex(expected),
             'OCSP_SIGNED_NONCE_MISMATCH_OR_MISSING','permission_denied')
    return {'nonce_present':nonce is not None,
            'nonce_matches_independently_provided_expected_bytes':expected!='NONE',
            'caller_precommitment_itself_externally_authenticated':False}


def _single_evaluation(single,generated:datetime,evaluation:datetime)->dict:
    start=single.this_update_utc;end=single.next_update_utc
    fresh=(start is not None and end is not None and
           start<=generated+SKEW and generated<=evaluation and
           start<=evaluation<=end and end>start and
           evaluation-start<=timedelta(days=MAX_WINDOW_DAYS) and
           end-start<=timedelta(days=MAX_WINDOW_DAYS))
    status=single.certificate_status
    if status==ocsp.OCSPCertStatus.REVOKED:
        need(single.revocation_time_utc is not None and
             single.revocation_time_utc<=generated and
             single.revocation_time_utc<=evaluation,
             'OCSP_SIGNED_REVOCATION_TIME_AFTER_PRODUCED_OR_EVALUATED',
             'permission_denied')
    if status==ocsp.OCSPCertStatus.GOOD:code='signed_good'
    elif status==ocsp.OCSPCertStatus.REVOKED:code='signed_revoked'
    else:code='signed_unknown'
    return {'ocsp_signed_status':code,'fresh_for_caller_evaluation':fresh,
            'this_update_utc':start.isoformat().replace('+00:00','Z') if start else None,
            'next_update_utc':end.isoformat().replace('+00:00','Z') if end else None,
            'revocation_time_utc':single.revocation_time_utc.isoformat().replace(
                '+00:00','Z') if single.revocation_time_utc else None,
            'nonce_does_not_establish_live_official_responder':True}


def _signed_ocsp(raw:bytes,expected_nonce:str)->tuple[Any,dict]:
    try:
        doc=ocsp.load_der_ocsp_response(raw)
        need(doc.response_status==ocsp.OCSPResponseStatus.SUCCESSFUL,
             'OCSP_RESPONSE_NOT_SUCCESSFUL','permission_denied')
        singles=list(doc.responses)
        need(1<=len(singles)<=MAX_OCSP_SINGLES,
             'OCSP_SIGNED_CERTIFICATE_RESPONSES_COUNT_INVALID')
        # cryptography exposes single_extensions only for the legacy
        # single-response view. Inspect *each* signed SingleResponse in DER,
        # including multi-CertID responses, to refuse unsupported criticals.
        from asn1crypto import ocsp as der_ocsp
        raw_asn=der_ocsp.OCSPResponse.load(raw,strict=True)
        basic=raw_asn['response_bytes']['response'].parsed
        asn_singles=basic['tbs_response_data']['responses']
        need(len(asn_singles)==len(singles),'OCSP_PARSED_RESPONSE_COUNT_MISMATCH')
        for sr in asn_singles:
            extensions=sr['single_extensions']
            if extensions.native is not None:
                need(all(not e['critical'].native for e in extensions),
                     'UNIMPLEMENTED_CRITICAL_OCSP_SINGLE_EXTENSION',
                     'permission_denied')
        nonce=_extract_nonce(doc,expected_nonce)
        return doc,nonce
    except errors.AnchorError:
        raise
    except (ValueError,TypeError,OverflowError) as exc:
        raise errors.AnchorError('EC351_OCSP_DER_MALFORMED_OR_UNSUPPORTED',
                                 'invalid_input') from exc


def _crl_status_at_eval(crls,subject,issuer,evaluation)->str:
    # Parent EC350 has already verified every supplied CRL signature on each
    # applicable path.  Never choose a winner among multiple issuer CRLs.
    relevant=[c for c in crls if c.issuer==issuer.subject]
    if len(relevant)!=1:return 'missing_or_multiple_signed_crls'
    crl=relevant[0]
    if (crl.last_update_utc>evaluation or crl.next_update_utc is None or
        crl.next_update_utc<evaluation or
        evaluation-crl.last_update_utc>timedelta(days=MAX_WINDOW_DAYS) or
        crl.next_update_utc-crl.last_update_utc>timedelta(days=MAX_WINDOW_DAYS) or
        any(e.oid in (ExtensionOID.DELTA_CRL_INDICATOR,
                      ExtensionOID.ISSUING_DISTRIBUTION_POINT)
            for e in crl.extensions)):
        return 'stale_or_limited_signed_crl'
    entry=crl.get_revoked_certificate_by_serial_number(subject.serial_number)
    return ('signed_revoked' if entry is not None and
            entry.revocation_date_utc<=evaluation else 'signed_good')


def audit(*,provenance_evaluation_utc:str,authority_channel_ids:list[str],
          authority_statement_files:list[str],authority_statement_shas:list[str],
          authority_key_files:list[str],authority_key_shas:list[str],
          authority_source_files:list[str],authority_source_shas:list[str],
          ocsp_files:list[str],ocsp_shas:list[str],ocsp_expected_nonces:list[str],
          **ec350_inputs)->dict:
    evaluation=old350._utc(provenance_evaluation_utc)
    need(evaluation>=old350._utc(ec350_inputs.get('tsa_evaluation_utc')),
         'PROVENANCE_EVALUATION_PRECEDES_EC350')
    seq=(authority_channel_ids,authority_statement_files,
         authority_statement_shas,authority_key_files,authority_key_shas,
         authority_source_files,authority_source_shas)
    need(all(type(v) is list for v in (*seq,ocsp_files,ocsp_shas,ocsp_expected_nonces))
         and len({len(v) for v in seq})==1 and len(seq[0])<=2 and
         authority_channel_ids==sorted(set(authority_channel_ids)) and
         len(ocsp_files)==len(ocsp_shas)==len(ocsp_expected_nonces)<=MAX_OCSP,
         'TWO_ALIGNED_AUTHORITY_OR_EIGHT_OCSP_ORIGINALS_REQUIRED')
    new_files=[*authority_statement_files,*authority_key_files,
               *authority_source_files,*ocsp_files]
    parent_files=[]
    for k,v in ec350_inputs.items():
        if k.endswith('_file') and type(v) is str:parent_files.append(v)
        if k.endswith('_files') and type(v) is list:parent_files.extend(v)
    need(len(set(new_files))==len(new_files) and
         not set(new_files).intersection(parent_files),
         'EC351_NEW_ORIGINAL_FILES_MUST_BE_DISTINCT_FROM_PARENT_AND_EACH_OTHER')
    # A successful parent report is obtained by *executing*, never accepting a
    # caller's JSON status or an opaque prerecorded success digest.
    parent=old350.audit(**ec350_inputs)
    need(parent.get('exit_code')==2 and
         parent.get('ec349_full_signed_history_replayed') is True,
         'FULL_EC350_THROUGH_EC337_REPLAY_REQUIRED','permission_denied')
    tokens=dict(zip(ec350_inputs['tsa_channel_ids'],zip(
        ec350_inputs['tsa_token_files'],ec350_inputs['tsa_token_shas'],
        ec350_inputs['tsa_root_files'],ec350_inputs['tsa_root_shas'],
        ec350_inputs['tsa_policy_oids'],strict=True),strict=True))
    need(set(authority_channel_ids)<=set(tokens),
         'AUTHORITY_STATEMENT_WITHOUT_PRESENTED_TIMESTAMP_TOKEN')
    authority=dict(zip(authority_channel_ids,zip(authority_statement_files,
        authority_statement_shas,authority_key_files,authority_key_shas,
        authority_source_files,authority_source_shas,strict=True),strict=True))
    pins={}
    crls=[old350._crl(old350._read_pinned(f,s,old350.MAX_CRL_BYTES,
        'EC351_RECHECK_CRL',pins)) for f,s in zip(
        ec350_inputs['tsa_crl_files'],ec350_inputs['tsa_crl_shas'],strict=True)]
    responses=[]
    for f,h,expected in zip(ocsp_files,ocsp_shas,ocsp_expected_nonces,strict=True):
        raw=old350._read_pinned(f,h,MAX_OCSP_SIZE,'OCSP',pins)
        doc,nonce=_signed_ocsp(raw,expected)
        responses.append((h,doc,nonce))
    old_receipts={}
    for f,h in zip(ec350_inputs['channel_receipt_files'],
                   ec350_inputs['channel_receipt_shas'],strict=True):
        actual=h if h!=old349.UNPINNED else prior.digest(f)
        need(actual not in old_receipts,'DUPLICATE_PARENT_RECEIPT_DIGEST')
        old_receipts[actual]=(f,h)
    rows=[];all_paths=[];used_ocsp=set();used_attesters=[]
    for oldrow in parent['channel_evidence']:
        channel=oldrow['channel_id']
        row={'channel_id':channel,'ec350_original_outcome':oldrow['outcome'],
             'ec350_unique_head_sha256':oldrow['selected_unique_head_original_raw_sha256'],
             'ec350_all_ancestry_externally_pinned':oldrow['ec349_whole_ancestry_pinned'],
             'tsa_token_verified_by_parent':oldrow['token_presented'],
             'source_attestation':None,'revocation_edge_evidence':[],
             'outcome':OUTCOMES[1]}
        if not oldrow['selected_unique_head_original_raw_sha256']:
            row['outcome']=OUTCOMES[0]
        elif not oldrow['token_presented']:
            row['outcome']=OUTCOMES[1]
        else:
            tokenfile,tokensha,rootfile,rootsha,policy=tokens[channel]
            head=oldrow['selected_unique_head_original_raw_sha256']
            need(head in old_receipts,'EC350_REPORTED_HEAD_BYTES_NOT_PRESENTED',
                 'permission_denied')
            receiptfile,receiptpin=old_receipts[head]
            receipt=old350._read_pinned(receiptfile,head,
                old350.MAX_RECEIPT_BYTES,'EC351_RECEIPT',pins)
            if receiptpin==old349.UNPINNED:
                need(_sha(receipt)==head,'UNPINNED_RECEIPT_BYTE_DRIFT',
                     'permission_denied')
            root=old350._certificate(old350._read_pinned(rootfile,rootsha,
                old350.MAX_CERT_BYTES,'TSA_ROOT',pins))
            verified=old350._tsa_token(old350._read_pinned(tokenfile,tokensha,
                old350.MAX_DER_BYTES,'TSA_TOKEN',pins),receipt,root,policy)
            need(verified['tsa_signer_cert_sha256']==oldrow['token_signer_certificate_sha256']
                 and verified['token_gen_time'].isoformat().replace('+00:00','Z')==
                 oldrow['signed_tsa_gen_time_utc'],
                 'EC350_SIGNER_OR_TIMESTAMP_REPLAY_CHANGED','permission_denied')
            if channel in authority:
                f,sha,keyf,keysha,srcf,srcsha=authority[channel]
                src=old350._read_pinned(srcf,srcsha,MAX_SOURCE,'POLICY_SOURCE',pins)
                need(len(src)>0,'EMPTY_ATTESTED_POLICY_SOURCE_DOCUMENT')
                key=old350._read_pinned(keyf,keysha,MAX_PUBLIC_KEY,'ATTESTER_KEY',pins)
                statement=old350._read_pinned(f,sha,MAX_ATTESTATION,
                                               'AUTHORITY_STATEMENT',pins)
                row['source_attestation']=_check_attestation(
                    channel=channel,statement=statement,public_key=key,
                    public_key_sha=keysha,source_sha=srcsha,root_sha=rootsha,
                    root_der_sha=verified['tsa_root_cert_der_sha256'],policy=policy,
                    evaluation=evaluation,token_time=verified['token_gen_time'])
                used_attesters.append(keysha)
            for idx,(subject,issuer) in enumerate(zip(
                    verified['certificate_path'][:-1],
                    verified['certificate_path'][1:],strict=True)):
                all_paths.append((subject,issuer))
                relevant=[]
                for num,(rawsha,response,nonce) in enumerate(responses):
                    if any(_match_single(s,subject,issuer) for s in response.responses):
                        relevant.append((num,rawsha,response,nonce))
                edge={'certificate_sha256':subject.fingerprint(hashes.SHA256()).hex(),
                      'issuer_sha256':issuer.fingerprint(hashes.SHA256()).hex(),
                      'signed_crl_status_at_evaluation':_crl_status_at_eval(
                          crls,subject,issuer,evaluation),
                      'matching_ocsp_original_shas':[r[1] for r in relevant],
                      'signed_ocsp':None,'crl_ocsp_consistency':'not_comparable'}
                if len(relevant)>1:
                    # Multiple signed answers do not establish which is newest.
                    # Still VERIFY every supplied signature; a fraudulent one
                    # must be denied, not counted as a legitimate ambiguity.
                    for num,rawsha,response,nonce in relevant:
                        singles=[s for s in response.responses
                                 if _match_single(s,subject,issuer)]
                        need(len(singles)==1,
                             'DUPLICATE_CERT_ID_INSIDE_SIGNED_OCSP_RESPONSE',
                             'permission_denied')
                        _verify_response_signer(response,issuer,evaluation)
                        used_ocsp.add(num)
                    edge['crl_ocsp_consistency']='multiple_matching_ocsp_snapshots_no_winner'
                elif len(relevant)==1:
                    num,rawsha,response,nonce=relevant[0]
                    used_ocsp.add(num)
                    singles=[s for s in response.responses if _match_single(s,subject,issuer)]
                    need(len(singles)==1,'DUPLICATE_CERT_ID_INSIDE_SIGNED_OCSP_RESPONSE',
                         'permission_denied')
                    signer=_verify_response_signer(response,issuer,evaluation)
                    info=_single_evaluation(singles[0],response.produced_at_utc,evaluation)
                    info.update(signer);info.update(nonce)
                    if info['ocsp_signed_status']=='signed_revoked':
                        info['revoked_at_or_before_tsa_gen_time']=(
                            singles[0].revocation_time_utc is not None and
                            singles[0].revocation_time_utc<=verified['token_gen_time'])
                    else:info['revoked_at_or_before_tsa_gen_time']=False
                    edge['signed_ocsp']=info
                    crlstate=edge['signed_crl_status_at_evaluation']
                    if crlstate in ('signed_good','signed_revoked') and info[
                            'fresh_for_caller_evaluation']:
                        edge['crl_ocsp_consistency']=(
                            'signed_crl_ocsp_agree' if crlstate==info['ocsp_signed_status']
                            else 'signed_ocsp_unknown_incomplete' if
                            info['ocsp_signed_status']=='signed_unknown'
                            else 'signed_crl_ocsp_conflict')
                    elif not info['fresh_for_caller_evaluation']:
                        edge['crl_ocsp_consistency']='signed_ocsp_stale_or_incomplete_window'
                    else:
                        edge['crl_ocsp_consistency']='crl_not_fresh_or_absent'
                row['revocation_edge_evidence'].append(edge)
            edges=row['revocation_edge_evidence']
            revoked_or_conflict=any(
                e['crl_ocsp_consistency']=='signed_crl_ocsp_conflict' or
                (e['signed_ocsp'] is not None and
                 e['signed_ocsp']['revoked_at_or_before_tsa_gen_time']) or
                e['signed_crl_status_at_evaluation']=='signed_revoked'
                for e in edges)
            missing_or_stale=any(
                e['crl_ocsp_consistency']!='signed_crl_ocsp_agree' or
                e['signed_ocsp'] is None or
                e['signed_ocsp']['ocsp_signed_status']!='signed_good'
                for e in edges)
            if not row['ec350_all_ancestry_externally_pinned'] or oldrow[
                    'outcome']!=old350.OUTCOMES[6]:
                row['outcome']=OUTCOMES[2]
            elif revoked_or_conflict:row['outcome']=OUTCOMES[3]
            elif row['source_attestation'] is None:row['outcome']=OUTCOMES[4]
            elif missing_or_stale:row['outcome']=OUTCOMES[5]
            else:row['outcome']=OUTCOMES[6]
        rows.append(row)
    need(all(any(_match_single(single,subj,issuer) for subj,issuer in all_paths)
                 for _,response,_ in responses for single in response.responses),
         'OCSP_CONTAINS_CERT_ID_OUTSIDE_PRESENTED_VERIFIED_TSA_PATH',
         'permission_denied')
    need(len(used_ocsp)==len(responses),
         'OCSP_CERT_ID_NOT_BOUND_TO_ANY_VERIFIED_EC350_CERTIFICATE_PATH',
         'permission_denied')
    # Restore negative authority facts even when two separate signer keys exist.
    old350._check_late(pins)
    counts={s:sum(r['outcome']==s for r in rows) for s in OUTCOMES}
    status=next(OUTCOMES[i] for i in PRIORITY if counts[OUTCOMES[i]])+'_unresolved'
    return {'schema':RESULT_SCHEMA,'command':'audit-provenance-evidence',
            'status':status,'exit_code':2,'case_id':parent['case_id'],
            'ec350_to_ec337_actual_originals_replayed':True,
            'ec350_verified_result_canonical_sha256':case.sha(reg.canonical(parent)),
            'provenance_evaluation_utc_as_caller_claim':provenance_evaluation_utc,
            'authority_statement_count':len(authority),
            'signed_ocsp_original_count':len(responses),
            'attesters_share_pinned_public_key':(len(used_attesters)>1 and
                                                len(set(used_attesters))<len(used_attesters)),
            'channel_evidence':rows,'outcome_counts':counts,
            'real_external_tsa_institution_or_policy_authority_still_unproven':True,
            'offline_unresolved_exit_code':2,
            **{k:False for k in NEGATIVES}}


def checklist(**ec350_inputs)->dict:
    doc=old350.audit(**ec350_inputs)
    need(doc.get('exit_code')==2 and
         doc.get('ec349_full_signed_history_replayed') is True,
         'FULL_EC350_HISTORY_REPLAY_REQUIRED','permission_denied')
    return {'schema':CHECKLIST_SCHEMA,'command':'derive-provenance-handoff',
            'status':'externally_authenticated_source_and_signed_ocsp_needed',
            'exit_code':2,'case_id':doc['case_id'],
            'ec350_verified_result_canonical_sha256':case.sha(reg.canonical(doc)),
            'channel_tsa_receipt_root_policy':[
                {'channel_id':r['channel_id'],
                 'receipt_sha256':r['selected_unique_head_original_raw_sha256'],
                 'root_sha256':r['tsa_root_original_raw_sha256'],
                 'signed_gen_time_utc':r['signed_tsa_gen_time_utc'],
                 'tsa_policy_oid':r['policy_oid_as_caller_required']}
                for r in doc['channel_evidence']],
            'no_network_or_signing':True,
            'offline_unresolved_exit_code':2,
            **{k:False for k in NEGATIVES}}
