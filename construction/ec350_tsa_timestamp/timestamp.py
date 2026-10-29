#!/usr/bin/env python3
"""EC350: verify externally furnished RFC3161 token original(s), offline.

Security boundaries:
- This is a *verifier*, never a TSA client or local token issuer; no network,
  signing/private-key, filesystem write, OCSP download or remote CAS action.
- The caller must furnish and pin EACH token/root/CRL ORIGINAL separately.
- Full EC349 -> EC337 source/original verification runs first. A token's imprint
  is recomputed from the exact unique present EC349 latest receipt's raw bytes.
- A cryptographically sound token under a caller-supplied certificate root is
  NOT certification of actual outside TSA identity, root provenance, clock UTC,
  independent custody, exhaustive revocation or global fork absence.
- Optional asn1crypto is required to parse actual DER CMS/TSTInfo; never fall
  back to trusting raw JSON or a prior purported successful report.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as reg
from ec321_fork_case_transport import case
from ec338_independent_custody import ceremony
from ec343_hold_receipts import timeline as prior
from ec349_dual_channel_anchor import anchor as inherited

RESULT_SCHEMA = 'ces.ec350.offline_rfc3161_tsa_evidence_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec350.offline_rfc3161_tsa_evidence_denial.v1'
CHECKLIST_SCHEMA = 'ces.ec350.unsigned_rfc3161_tsa_handoff.v1'
MAX_TOKENS = 2
MAX_CRLS = 8
MAX_DER_BYTES = 512_000
MAX_CERT_BYTES = 128_000
MAX_CRL_BYTES = 2_000_000
MAX_RECEIPT_BYTES = 2_000_000
MAX_CERTS_IN_TOKEN = 12
MAX_CERT_PATH = 6
MAX_SKEW_SECONDS = 300
ALGORITHMS = {
    'sha256': (hashes.SHA256, hashlib.sha256),
    'sha384': (hashes.SHA384, hashlib.sha384),
    'sha512': (hashes.SHA512, hashlib.sha512),
}
OUTCOMES = (
    'ec349_channel_receipt_absent_or_fork_unresolved',
    'rfc3161_token_not_furnished',
    'rfc3161_token_with_unpinned_ec349_ancestry',
    'rfc3161_tsa_revoked_at_signed_gen_time',
    'rfc3161_offline_crl_missing_stale_or_ambiguous',
    'rfc3161_signed_time_vs_claim_or_peer_discrepancy',
    'rfc3161_token_signature_chain_imprint_and_bounded_crl_valid_but_external_trust_unproven',
)
PRIORITY = (0,3,1,2,4,5,6)
NEGATIVES = (
    'caller_furnished_tsa_root_proves_real_outside_trust_anchor',
    'valid_signed_gen_time_proves_independently_trusted_utc',
    'furnished_crls_prove_exhaustive_global_revocation_or_ocsp',
    'caller_supplied_policy_oid_proves_qualified_tsa_legal_status',
    'separate_token_files_prove_physically_independent_tsa_institutions',
    'valid_tsa_token_proves_receipt_was_physically_delivered_at_gen_time',
    'verified_token_selects_a_winner_among_visible_or_hidden_ec349_forks',
    'valid_tsa_token_repairs_ec349_unpinned_revoked_or_expired_ancestors',
    'offline_verifier_executes_remote_provider_cas_worm_action',
    'old_ec317_ec318_production_and_final_user_acceptance_proven',
)


def need(condition: Any, code: str, status: str='invalid_input') -> None:
    if condition is not True:
        raise errors.AnchorError('EC350_' + code, status)


def _utc(s: str) -> datetime:
    need(type(s) is str and re.fullmatch(
        r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ',s) is not None,
        'STRICT_UTC_SECONDS_REQUIRED')
    try:
        return datetime.strptime(s,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise errors.AnchorError('EC350_INVALID_UTC_CALENDAR_DATE','invalid_input') from exc


def _read_pinned(path: str, sha: str, cap: int, role: str, late: dict[str,tuple[str,int]]) -> bytes:
    need(type(path) is str and os.path.isabs(path) and
         os.path.normpath(path)==path and not path.startswith('//') and
         '\\' not in path and '\x00' not in path and len(path)<=4000 and
         type(sha) is str and re.fullmatch('[0-9a-f]{64}',sha) is not None and
         sha!='0'*64,
         'SHA_PIN_OR_PATH_INVALID_'+role)
    if path in late:
        need(role=='TSA_ROOT' and late[path]==(sha,cap),
             'ONLY_EXACT_SAME_SHA_TRUST_ROOT_MAY_BE_SHARED')
    try:
        need(not Path(path).is_symlink(), 'SYMLINK_PINNED_ORIGINAL_DENIED_'+role,
             'permission_denied')
        with open(path,'rb') as f:
            data=f.read(cap+1)
        need(len(data)<=cap, 'OVERSIZED_ORIGINAL_'+role)
        need(hashlib.sha256(data).hexdigest()==sha,
             'WHOLE_ORIGINAL_SHA_MISMATCH_'+role,'permission_denied')
    except errors.AnchorError:
        raise
    except (OSError, ValueError) as exc:
        raise errors.AnchorError('EC350_UNREADABLE_ORIGINAL_'+role,'unavailable') from exc
    late[path]=(sha,cap)
    return data


def _check_late(pins: dict[str,tuple[str,int]]) -> None:
    # Double read after the full verification: explicitly presented paths only.
    for p,(sha,cap) in pins.items():
        try:
            with open(p,'rb') as f:data=f.read(cap+1)
            need(not Path(p).is_symlink() and len(data)<=cap and
                 hashlib.sha256(data).hexdigest()==sha,
                 'ORIGINAL_CHANGED_DURING_AUDIT','permission_denied')
        except OSError as exc:
            raise errors.AnchorError('EC350_ORIGINAL_UNAVAILABLE_AT_LATE_READ','unavailable') from exc


def _hash_name(name: str):
    need(name in ALGORITHMS, 'WEAK_OR_UNSUPPORTED_DIGEST_ALGORITHM')
    return ALGORITHMS[name][0]()


def _certificate(raw: bytes) -> x509.Certificate:
    try:
        if raw.startswith(b'-----BEGIN CERTIFICATE-----'):
            need(raw.count(b'-----BEGIN CERTIFICATE-----')==1 and
                 raw.count(b'-----END CERTIFICATE-----')==1,
                 'SINGLE_EXTERNALLY_PINNED_ROOT_REQUIRED')
            return x509.load_pem_x509_certificate(raw)
        return x509.load_der_x509_certificate(raw)
    except errors.AnchorError:
        raise
    except ValueError as exc:
        raise errors.AnchorError('EC350_BAD_TRUST_ROOT_CERTIFICATE','invalid_input') from exc


def _crl(raw: bytes) -> x509.CertificateRevocationList:
    try:
        if raw.startswith(b'-----BEGIN X509 CRL-----'):
            need(raw.count(b'-----BEGIN X509 CRL-----')==1,
                 'ONLY_ONE_CRL_PER_ORIGINAL')
            return x509.load_pem_x509_crl(raw)
        return x509.load_der_x509_crl(raw)
    except errors.AnchorError:
        raise
    except ValueError as exc:
        raise errors.AnchorError('EC350_BAD_EXTERNALLY_PINNED_CRL','invalid_input') from exc


def _verify_signature(pub, signed: bytes, signature: bytes,
                      algorithm, *, pad=None) -> None:
    need(algorithm is None or algorithm.name in ALGORITHMS,
         'WEAK_CERTIFICATE_OR_CRL_SIGNATURE_DIGEST_DENIED','permission_denied')
    if isinstance(pub,rsa.RSAPublicKey):
        need(pub.key_size>=2048,'RSA_PUBLIC_KEY_BELOW_2048_BITS_DENIED',
             'permission_denied')
    elif isinstance(pub,ec.EllipticCurvePublicKey):
        need(pub.curve.key_size>=256,'EC_PUBLIC_KEY_BELOW_256_BITS_DENIED',
             'permission_denied')
    try:
        if isinstance(pub,rsa.RSAPublicKey):
            need(algorithm is not None,'RSA_HASH_ALGORITHM_REQUIRED')
            pub.verify(signature,signed,pad or padding.PKCS1v15(),algorithm)
        elif isinstance(pub,ec.EllipticCurvePublicKey):
            need(algorithm is not None,'ECDSA_HASH_ALGORITHM_REQUIRED')
            pub.verify(signature,signed,ec.ECDSA(algorithm))
        elif isinstance(pub,(ed25519.Ed25519PublicKey,ed448.Ed448PublicKey)):
            need(algorithm is None,'EDDSA_SIGNATURE_HASH_MUST_BE_ABSENT')
            pub.verify(signature,signed)
        else:
            need(False,'UNSUPPORTED_PUBLIC_KEY_ALGORITHM')
    except errors.AnchorError:
        raise
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise errors.AnchorError('EC350_SIGNED_CERTIFICATE_OR_TOKEN_SIGNATURE_INVALID',
                                 'permission_denied') from exc


def _cert_signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    need(cert.issuer == issuer.subject, 'CERTIFICATE_ISSUER_SUBJECT_CHAIN_MISMATCH',
         'permission_denied')
    _verify_signature(issuer.public_key(),cert.tbs_certificate_bytes,
                      cert.signature,cert.signature_hash_algorithm,
                      pad=cert.signature_algorithm_parameters if
                      isinstance(issuer.public_key(),rsa.RSAPublicKey) else None)


def _crl_signed_by(crl: x509.CertificateRevocationList,
                   issuer: x509.Certificate) -> None:
    need(crl.issuer==issuer.subject,'CRL_ISSUER_NOT_IN_CERTIFICATE_PATH')
    _verify_signature(issuer.public_key(),crl.tbs_certlist_bytes,
                      crl.signature,crl.signature_hash_algorithm,
                      pad=crl.signature_algorithm_parameters if
                      isinstance(issuer.public_key(),rsa.RSAPublicKey) else None)


def _cert_key_usage(cert,*,must_ca: bool) -> None:
    implemented_critical={ExtensionOID.BASIC_CONSTRAINTS,ExtensionOID.KEY_USAGE,
        ExtensionOID.EXTENDED_KEY_USAGE,ExtensionOID.SUBJECT_KEY_IDENTIFIER,
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER}
    need(all(not ext.critical or ext.oid in implemented_critical
             for ext in cert.extensions),
         'UNIMPLEMENTED_CRITICAL_CERTIFICATE_EXTENSION_DENIED',
         'permission_denied')
    try:
        bc=cert.extensions.get_extension_for_class(x509.BasicConstraints)
        ku=cert.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound as exc:
        raise errors.AnchorError('EC350_BASIC_CONSTRAINTS_AND_KEY_USAGE_REQUIRED',
                                 'permission_denied') from exc
    need(bc.value.ca is must_ca and bc.critical is True,
         'INVALID_CRITICAL_CA_CONSTRAINT','permission_denied')
    need(ku.value.key_cert_sign is must_ca and
         (ku.value.crl_sign if must_ca else ku.value.digital_signature),
         'UNSUITABLE_TSA_OR_CA_KEY_USAGE','permission_denied')
    if must_ca:
        try:
            eku=cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            need(ExtendedKeyUsageOID.TIME_STAMPING in eku or
                 ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in eku,
                 'CA_EKU_EXCLUDES_TIME_STAMPING','permission_denied')
        except x509.ExtensionNotFound:pass
    else:
        try:
            eku=cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        except x509.ExtensionNotFound as exc:
            raise errors.AnchorError('EC350_TSA_EXCLUSIVE_TIME_STAMPING_EKU_REQUIRED',
                                     'permission_denied') from exc
        need(eku.critical and list(eku.value)==[ExtendedKeyUsageOID.TIME_STAMPING],
             'TSA_EKU_MUST_BE_CRITICAL_AND_TIME_STAMPING_ONLY',
             'permission_denied')


def _cert_path(signer: x509.Certificate, embedded: list[x509.Certificate],
               root: x509.Certificate, gen_time:datetime) -> list[x509.Certificate]:
    # A caller-pinned root is the *only* anchor. Never read an OS trust store,
    # fetch an AIA issuer or let signed CMS contents supply their own root.
    _cert_key_usage(root,must_ca=True)
    root_sha=root.fingerprint(hashes.SHA256())
    pool={c.fingerprint(hashes.SHA256()):c for c in embedded if
          c.fingerprint(hashes.SHA256())!=root_sha}
    path=[signer]; visited={signer.fingerprint(hashes.SHA256())}
    for _ in range(MAX_CERT_PATH):
        current=path[-1]
        if current.fingerprint(hashes.SHA256())==root_sha:
            break
        possibles=[c for c in [*pool.values(),root] if
                   c.subject==current.issuer and
                   c.fingerprint(hashes.SHA256()) not in visited]
        # Multiple plausible issuers are not resolved by arbitrary ordering.
        need(len(possibles)==1,'MISSING_OR_AMBIGUOUS_TSA_CERTIFICATE_ISSUER',
             'permission_denied')
        issuer=possibles[0]
        _cert_key_usage(issuer,must_ca=True)
        _cert_signed_by(current,issuer)
        path.append(issuer)
        visited.add(issuer.fingerprint(hashes.SHA256()))
    need(path[-1].fingerprint(hashes.SHA256())==root_sha and
         2<=len(path)<=MAX_CERT_PATH,
         'TSA_CERTIFICATE_PATH_NOT_ANCHORED_IN_PINNED_ROOT',
         'permission_denied')
    _cert_signed_by(root,root)
    for i,cert in enumerate(path):
        need(cert.not_valid_before_utc <= gen_time <= cert.not_valid_after_utc,
             'TOKEN_GENERATION_OUTSIDE_CERTIFICATE_VALIDITY','permission_denied')
        if i==0:_cert_key_usage(cert,must_ca=False)
        # BasicConstraints.path_length counts subordinate intermediate CAs.
        if i>0:
            bc=cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            subordinate_cas=sum(1 for c in path[1:i] if
                                c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            need(bc.path_length is None or subordinate_cas<=bc.path_length,
                 'CERTIFICATE_CHAIN_CA_PATH_LENGTH_EXCEEDED','permission_denied')
    return path


def _tsa_token(raw: bytes, receipt_raw: bytes, pinned_root: x509.Certificate,
               expected_policy_oid: str) -> dict:
    try:
        from asn1crypto import cms, tsp
    except ImportError as exc:
        raise errors.AnchorError('EC350_ASN1CRYPTO_REQUIRED_FOR_REAL_DER_CMS','unavailable') from exc
    try:
        # Some TSA providers furnish a full TimeStampResp; some the CMS token.
        # Only granted replies with an actual signed token are acceptable.
        try:
            ci=cms.ContentInfo.load(raw,strict=True)
            if ci['content_type'].native!='signed_data':raise ValueError('not CMS')
        except (ValueError,TypeError,KeyError):
            resp=tsp.TimeStampResp.load(raw,strict=True)
            need(resp['status']['status'].native in ('granted','granted_with_mods') and
                 resp['time_stamp_token'].native is not None,
                 'RFC3161_RESPONSE_NOT_GRANTED_OR_TOKEN_MISSING')
            ci=resp['time_stamp_token']
        need(ci['content_type'].native=='signed_data','ONLY_CMS_SIGNED_TIMESTAMP')
        cms_doc=ci['content']
        signer_infos=cms_doc['signer_infos']
        need(len(signer_infos)==1,'EXACT_ONE_CMS_TSA_SIGNER_REQUIRED')
        si=signer_infos[0]
        need(cms_doc['encap_content_info']['content_type'].dotted ==
             '1.2.840.113549.1.9.16.1.4',
             'CMS_CONTENT_MUST_BE_ID_CT_TSTINFO')
        econtent=cms_doc['encap_content_info']['content'].contents
        need(type(econtent) is bytes,'TSTINFO_ECONTENT_OCTETS_REQUIRED')
        info=tsp.TSTInfo.load(econtent,strict=True)
        need(info['version'].native=='v1' and
             info['policy'].dotted==expected_policy_oid,
             'TIMESTAMP_TSTINFO_POLICY_OR_VERSION_MISMATCH',
             'permission_denied')
        digest_name=info['message_imprint']['hash_algorithm']['algorithm'].native
        _hash_name(digest_name)
        need(info['message_imprint']['hashed_message'].native ==
             ALGORITHMS[digest_name][1](receipt_raw).digest(),
             'TSTINFO_IMPRINT_DOES_NOT_MATCH_ACTUAL_EC349_RECEIPT_BYTES',
             'permission_denied')
        gen_time=info['gen_time'].native
        need(type(gen_time) is datetime and gen_time.tzinfo is not None and
             gen_time.year>=1970,'INVALID_TSA_SIGNED_GENERATION_TIME')
        gen_time=gen_time.astimezone(timezone.utc)
        signer_digest=si['digest_algorithm']['algorithm'].native
        _hash_name(signer_digest)
        digests=[a['algorithm'].native for a in cms_doc['digest_algorithms']]
        need(len(digests)==1 and digests[0]==signer_digest,
             'CMS_SIGNER_DIGEST_ALGORITHM_SET_MISMATCH')
        cert_choices=cms_doc['certificates']
        need(cert_choices.native is not None and 1<=len(cert_choices)<=MAX_CERTS_IN_TOKEN,
             'CMS_SIGNER_CERTIFICATES_REQUIRED')
        need(all(c.name=='certificate' for c in cert_choices),
             'CMS_CERT_CHOICES_MUST_BE_X509_CERTIFICATES')
        embedded_asn=[c.chosen for c in cert_choices]
        embedded=[x509.load_der_x509_certificate(c.dump()) for c in embedded_asn]
        sid=si['sid']
        if sid.name=='issuer_and_serial_number':
            sid_obj=sid.chosen
            matched=[c for c,ac in zip(embedded,embedded_asn,strict=True) if
                     ac.issuer==sid_obj['issuer'] and
                     c.serial_number==sid_obj['serial_number'].native]
        elif sid.name=='subject_key_identifier':
            wanted=sid.chosen.native
            matched=[]
            for cert in embedded:
                try:
                    key=cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
                    if key==wanted:matched.append(cert)
                except x509.ExtensionNotFound:pass
        else:
            need(False,'UNSUPPORTED_CMS_TSA_SIGNER_IDENTIFIER')
        need(len(matched)==1,'AMBIGUOUS_OR_MISSING_TSA_SIGNER_CERTIFICATE',
             'permission_denied')
        signer=matched[0]
        attrs=si['signed_attrs']
        need(attrs.native is not None and len(attrs)>0,
             'CMS_SIGNED_ATTRIBUTES_MANDATORY','permission_denied')
        def one_attr(attr_name):
            matches=[a for a in attrs if a['type'].native==attr_name]
            need(len(matches)==1 and len(matches[0]['values'])==1,
                 'CMS_SIGNED_ATTRIBUTE_MISSING_OR_DUPLICATE_'+attr_name.upper(),
                 'permission_denied')
            return matches[0]['values'][0]
        need(one_attr('content_type').native=='tst_info',
             'SIGNED_CONTENT_TYPE_NOT_TSTINFO','permission_denied')
        need(one_attr('message_digest').native==
             ALGORITHMS[signer_digest][1](econtent).digest(),
             'CMS_SIGNED_ATTRIBUTES_ECONTENT_DIGEST_MISMATCH',
             'permission_denied')
        ess_attrs=[a for a in attrs if a['type'].native in
                   ('signing_certificate_v2','signing_certificate')]
        need(len(ess_attrs)==1 and len(ess_attrs[0]['values'])==1,
             'ESS_CERT_BINDING_ATTRIBUTE_REQUIRED','permission_denied')
        ess_name=ess_attrs[0]['type'].native
        ess=ess_attrs[0]['values'][0]['certs']
        need(len(ess)==1,'ONE_EXPLICIT_SIGNING_CERT_HASH_REQUIRED',
             'permission_denied')
        cert_hash_name=(ess[0]['hash_algorithm']['algorithm'].native if
                        ess_name=='signing_certificate_v2' else 'sha1')
        # ESSCertID (v1) is SHA1 for cert *identity*, not as a token imprint or
        # signature digest; RFC3161 legacy support is intentionally limited.
        need(cert_hash_name in (*ALGORITHMS,'sha1'),
             'ESS_SIGNER_CERT_HASH_UNSUPPORTED')
        ess_hash=(getattr(hashlib,cert_hash_name)(signer.public_bytes(
            encoding=serialization.Encoding.DER))
            .digest())
        need(ess[0]['cert_hash'].native==ess_hash,
             'ESS_SIGNING_CERTIFICATE_HASH_MISMATCH','permission_denied')
        issuer_serial=ess[0]['issuer_serial']
        if issuer_serial.native is not None:
            need(issuer_serial['serial_number'].native==signer.serial_number,
                 'ESS_ISSUER_SERIAL_NUMBER_WRONG','permission_denied')
        signed_source=attrs.dump()
        need(signed_source[0]==0xa0,'CMS_SIGNED_ATTRS_MUST_USE_IMPLICIT_SET_TAG')
        signed_source=b'\x31'+signed_source[1:]
        need(signed_source==b'\x31'+attrs.dump(force=True)[1:],
             'CMS_SIGNED_ATTRS_NOT_CANONICAL_DER','permission_denied')
        sig_algo=si['signature_algorithm']['algorithm'].native
        h=_hash_name(signer_digest)
        public=signer.public_key()
        if isinstance(public,rsa.RSAPublicKey):
            if sig_algo=='rsassa_pss':
                pss=si['signature_algorithm']['parameters']
                need(pss['hash_algorithm']['algorithm'].native==signer_digest and
                     pss['mask_gen_algorithm']['algorithm'].native=='mgf1' and
                     pss['mask_gen_algorithm']['parameters']['algorithm'].native==signer_digest and
                     pss['trailer_field'].native=='trailer_field_bc' and
                     type(pss['salt_length'].native) is int and
                     0<=pss['salt_length'].native<=h.digest_size,
                     'CMS_PSS_PARAMETERS_UNSAFE_OR_INCONSISTENT','permission_denied')
                sigpad=padding.PSS(mgf=padding.MGF1(h),salt_length=pss['salt_length'].native)
            else:
                need(sig_algo in ('rsassa_pkcs1v15',signer_digest+'_rsa'),
                     'UNSUPPORTED_CMS_RSA_SIGNATURE_ALGORITHM','permission_denied')
                sigpad=padding.PKCS1v15()
            _verify_signature(public,signed_source,si['signature'].native,h,pad=sigpad)
        elif isinstance(public,ec.EllipticCurvePublicKey):
            need(sig_algo in ('ecdsa',signer_digest+'_ecdsa'),
                 'UNSUPPORTED_CMS_ECDSA_SIGNATURE_ALGORITHM','permission_denied')
            _verify_signature(public,signed_source,si['signature'].native,h)
        else:
            need(False,'UNSUPPORTED_CMS_TSA_SIGNING_KEY','permission_denied')
        path=_cert_path(signer,embedded,pinned_root,gen_time)
        return {'token_gen_time':gen_time,
                'token_policy_oid':info['policy'].dotted,
                'imprint_digest_algorithm':digest_name,
                'cms_signer_digest_algorithm':signer_digest,
                'tsa_signer_cert_sha256':signer.fingerprint(hashes.SHA256()).hex(),
                'tsa_root_cert_der_sha256':pinned_root.fingerprint(hashes.SHA256()).hex(),
                'signed_certificate_path_count':len(path),
                'certificate_path':path,
                'cms_signed_attribute_and_signature_verified':True,
                'full_receipt_byte_imprint_verified':True}
    except errors.AnchorError:
        raise
    except (ValueError,TypeError,KeyError,IndexError,OverflowError,AttributeError) as exc:
        raise errors.AnchorError('EC350_MALFORMED_OR_UNSUPPORTED_RFC3161_CMS_TOKEN',
                                 'invalid_input') from exc


def _check_crls(path: list[x509.Certificate], crls: list[x509.CertificateRevocationList],
                gen_time:datetime, evaluation:datetime) -> dict:
    per_issuer=[]
    any_revoked=False; any_missing=False; any_stale=False; any_ambiguous=False
    for subject,issuer in zip(path[:-1],path[1:],strict=True):
        candidates=[c for c in crls if c.issuer==issuer.subject]
        if len(candidates)>1:
            state='multiple_issuer_crls_no_authoritative_latest';any_ambiguous=True
        elif not candidates:
            state='no_signed_crl_presented';any_missing=True
        else:
            crl=candidates[0]
            _crl_signed_by(crl,issuer)
            # A delta CRL, indirectly issued CRL, or distribution-restricted
            # CRL is not by itself a complete issuer revocation snapshot.
            limited_crl_scope=False
            for ext in crl.extensions:
                if ext.critical and ext.oid not in (
                        ExtensionOID.CRL_NUMBER,
                        ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                        ExtensionOID.ISSUING_DISTRIBUTION_POINT,
                        ExtensionOID.DELTA_CRL_INDICATOR):
                    need(False,'UNKNOWN_CRITICAL_CRL_EXTENSION',
                         'permission_denied')
                if ext.oid in (ExtensionOID.DELTA_CRL_INDICATOR,
                               ExtensionOID.ISSUING_DISTRIBUTION_POINT):
                    limited_crl_scope=True
            if limited_crl_scope:
                state='signed_crl_delta_or_restricted_distribution_scope';any_stale=True
            elif crl.last_update_utc>evaluation or crl.next_update_utc is None or \
               crl.next_update_utc<evaluation:
                state='signed_crl_outside_caller_evaluation_window';any_stale=True
            else:
                state='signed_crl_bounded_window_and_no_prior_revocation'
            for revoked in crl:
                if revoked.serial_number==subject.serial_number:
                    if revoked.revocation_date_utc<=gen_time:
                        state='signed_crl_reports_revoked_at_or_before_tst_gen_time'
                        any_revoked=True
                    else:
                        state='signed_crl_reports_revocation_after_tst_gen_time'
                    break
        per_issuer.append({'certificate_sha256':subject.fingerprint(hashes.SHA256()).hex(),
                           'issuer_sha256':issuer.fingerprint(hashes.SHA256()).hex(),
                           'bounded_crl_status':state})
    return {'certificate_revocation_rows':per_issuer,
            'revoked_at_or_before_gen_time':any_revoked,
            'crl_missing':any_missing,'crl_stale':any_stale,
            'crl_multiple_for_issuer':any_ambiguous,
            'all_chain_edges_have_single_fresh_crl_as_furnished':not (
                any_revoked or any_missing or any_stale or any_ambiguous),
            'exhaustive_worldwide_revocation_proven':False}


def checklist(**ec349_inputs)->dict:
    report=inherited.audit_dual_anchors(**ec349_inputs)
    need(report.get('exit_code')==2 and
         report.get('ec348_full_signed_source_replayed') is True,
         'EC349_EC337_REAL_REPLAY_REQUIRED','permission_denied')
    return {'schema':CHECKLIST_SCHEMA,'command':'derive-tsa-handoff',
            'status':'separately_furnished_external_rfc3161_tsa_originals_needed',
            'exit_code':2,'case_id':report['case_id'],
            'ec349_verified_result_canonical_sha256':case.sha(reg.canonical(report)),
            'channel_latest_signed_receipt_heads':[
                {'channel_id':r['channel_id'],
                 'visible_signed_head_original_raw_sha256s':r['visible_signed_head_original_raw_sha256s'],
                 'multiple_heads_no_winner':r['multiple_signed_heads_no_winner'],
                 'ec349_outcome':r['outcome']} for r in report['channel_outcomes']],
            'needed_external_originals':'RFC3161_DER_TOKEN_ROOT_X509_AND_OPTIONAL_PINNED_CRL',
            'offline_unresolved_exit_code':2,
            **{k:False for k in NEGATIVES}}


def audit(*,tsa_evaluation_utc:str,tsa_channel_ids:list[str],
          tsa_token_files:list[str],tsa_token_shas:list[str],
          tsa_root_files:list[str],tsa_root_shas:list[str],
          tsa_policy_oids:list[str],tsa_crl_files:list[str],
          tsa_crl_shas:list[str],**ec349_inputs)->dict:
    evaluation=_utc(tsa_evaluation_utc)
    need(evaluation>=_utc(ec349_inputs.get('dual_evaluation_utc')),
         'TSA_EVALUATION_PRECEDES_EC349_EVALUATION')
    seqs=(tsa_channel_ids,tsa_token_files,tsa_token_shas,
          tsa_root_files,tsa_root_shas,tsa_policy_oids)
    need(all(type(x) is list for x in (*seqs,tsa_crl_files,tsa_crl_shas)) and
         len({len(x) for x in seqs})==1 and
         0<=len(tsa_channel_ids)<=MAX_TOKENS and
         len(tsa_crl_files)==len(tsa_crl_shas)<=MAX_CRLS and
         len(set(tsa_channel_ids))==len(tsa_channel_ids) and
         tsa_channel_ids==sorted(tsa_channel_ids) and
         all(type(s) is str and re.fullmatch(r'[0-2](?:\.\d+)+',s)
             for s in tsa_policy_oids),
         'TWO_CHANNEL_ALIGNED_TSA_TOKEN_AND_POLICY_ARGS_REQUIRED')
    # Two TSA channels may legitimately chain to the same externally pinned
    # CA root. Disclose that overlap; never call the two TSA issuers independent.
    # A repeated root *path* must carry the exact same raw SHA.
    other_files=[*tsa_token_files,*tsa_crl_files]
    need(len(set(other_files))==len(other_files) and
         not set(tsa_root_files).intersection(other_files),
         'TOKEN_TRUST_ROOT_AND_CRL_PATHS_CANNOT_ALIAS')
    for path in set(tsa_root_files):
        need(len({h for p,h in zip(tsa_root_files,tsa_root_shas,strict=True)
                  if p==path})==1,'REPEATED_TRUST_ROOT_MUST_HAVE_SAME_PIN')
    old_files=[]
    for k,v in ec349_inputs.items():
        if k.endswith('_file') and type(v) is str:old_files.append(v)
        if k.endswith('_files') and type(v) is list:old_files.extend(v)
    need(not set((*other_files,*tsa_root_files)).intersection(old_files),
         'TSA_NEW_EVIDENCE_ORIGINALS_CANNOT_ALIAS_EC349_TO_EC337_SOURCE')
    pins={}
    # No file is searched or taken from an operating-system trust repository.
    crls=[_crl(_read_pinned(f,s,MAX_CRL_BYTES,'CRL',pins))
          for f,s in zip(tsa_crl_files,tsa_crl_shas,strict=True)]
    source=inherited.audit_dual_anchors(**ec349_inputs)
    need(source.get('exit_code')==2 and
         source.get('ec348_full_signed_source_replayed') is True and
         source.get('two_channel_directory_signatures_verified') is True,
         'EC349_THROUGH_EC337_VERIFIED_ORIGINAL_REPLAY_REQUIRED',
         'permission_denied')
    channels={r['channel_id']:r for r in source['channel_outcomes']}
    need(set(tsa_channel_ids)<=set(channels),'TOKEN_CHANNEL_NOT_AN_EC349_CHANNEL')
    source_paths={}
    for file,sha in zip(ec349_inputs['channel_receipt_files'],
                        ec349_inputs['channel_receipt_shas'],strict=True):
        actual=sha if sha!=inherited.UNPINNED else prior.digest(file)
        need(actual not in source_paths,'DUPLICATE_EC349_RECEIPT_SHA')
        source_paths[actual]=(file,sha)
    mapped=dict(zip(tsa_channel_ids,zip(tsa_token_files,tsa_token_shas,
              tsa_root_files,tsa_root_shas,tsa_policy_oids,strict=True),strict=True))
    rows=[]; chronological=[]
    seen_root_certs=[];seen_tsa_signers=[]
    for channel_id,old in channels.items():
        heads=old['visible_signed_head_original_raw_sha256s']
        pinned_ancestry=old['latest_head_ancestry_all_externally_pinned']
        row={'channel_id':channel_id,'ec349_channel_outcome':old['outcome'],
             'visible_signed_head_original_raw_sha256s':heads,
             'selected_unique_head_original_raw_sha256':heads[0] if len(heads)==1 else None,
             'ec349_whole_ancestry_pinned':pinned_ancestry,
             'token_presented':channel_id in mapped,'signed_tsa_gen_time_utc':None,
             'token_original_raw_sha256':None,
             'tsa_root_original_raw_sha256':None,
             'token_signer_certificate_sha256':None,
             'verified_tsa_path_certificate_count':0,
             'policy_oid_as_caller_required':None,
             'imprint_algorithm':None,'signed_gen_time_minus_receipt_claim_seconds':None,
             'signed_gen_time_after_caller_evaluation':None,
             'revocation_evidence':None,'outcome':OUTCOMES[1]}
        if len(heads)!=1:
            need(channel_id not in mapped,
                 'CANNOT_BIND_TSA_TOKEN_TO_ABSENT_OR_FORKED_EC349_HEAD',
                 'permission_denied')
            row['outcome']=OUTCOMES[0]
        elif channel_id in mapped:
            token_file,token_sha,root_file,root_sha,policy=mapped[channel_id]
            need(heads[0] in source_paths,'EC349_HEAD_RECEIPT_BYTES_NOT_PRESENTED',
                 'permission_denied')
            receipt_file,receipt_pin=source_paths[heads[0]]
            # The digest for an EC349 UNPINNED receipt here is measured, NOT
            # treated as independently sourced; its lack of pin is preserved.
            if receipt_pin==inherited.UNPINNED:
                try:
                    with open(receipt_file,'rb') as f:
                        receipt_raw=f.read(MAX_RECEIPT_BYTES+1)
                except OSError as exc:
                    raise errors.AnchorError('EC350_UNPINNED_RECEIPT_FILE_UNAVAILABLE',
                                             'unavailable') from exc
                need(len(receipt_raw)<=MAX_RECEIPT_BYTES and
                     hashlib.sha256(receipt_raw).hexdigest()==heads[0],
                     'UNPINNED_RECEIPT_BYTES_CHANGED','permission_denied')
                # A locally measured digest allows a late byte drift check,
                # NEVER upgrades the inherited external UNPINNED fact.
                pins[receipt_file]=(heads[0],MAX_RECEIPT_BYTES)
            else:
                receipt_raw=_read_pinned(receipt_file,receipt_pin,
                    MAX_RECEIPT_BYTES,'EC349_RECEIPT',pins)
            receipt_doc=prior.read(receipt_file,heads[0],'EC349_TSA_BOUND_RECEIPT')
            token_raw=_read_pinned(token_file,token_sha,MAX_DER_BYTES,'TSA_TOKEN',pins)
            root_raw=_read_pinned(root_file,root_sha,MAX_CERT_BYTES,'TSA_ROOT',pins)
            root=_certificate(root_raw)
            verified=_tsa_token(token_raw,receipt_raw,root,policy)
            gen_time=verified['token_gen_time']
            time_claim=_utc(receipt_doc['claim']['claimed_received_utc'])
            gap=(gen_time-time_claim).total_seconds()
            after_eval=gen_time>evaluation
            rev=_check_crls(verified['certificate_path'],crls,gen_time,evaluation)
            row.update(token_original_raw_sha256=token_sha,
                       tsa_root_original_raw_sha256=root_sha,
                       token_signer_certificate_sha256=verified['tsa_signer_cert_sha256'],
                       verified_tsa_path_certificate_count=verified['signed_certificate_path_count'],
                       policy_oid_as_caller_required=policy,
                       signed_tsa_gen_time_utc=gen_time.isoformat().replace('+00:00','Z'),
                       imprint_algorithm=verified['imprint_digest_algorithm'],
                       signed_gen_time_minus_receipt_claim_seconds=gap,
                       signed_gen_time_after_caller_evaluation=after_eval,
                       revocation_evidence=rev)
            seen_root_certs.append(verified['tsa_root_cert_der_sha256'])
            seen_tsa_signers.append(verified['tsa_signer_cert_sha256'])
            chronological.append(row)
            if rev['revoked_at_or_before_gen_time']:row['outcome']=OUTCOMES[3]
            elif not pinned_ancestry:row['outcome']=OUTCOMES[2]
            elif not rev['all_chain_edges_have_single_fresh_crl_as_furnished']:
                row['outcome']=OUTCOMES[4]
            elif abs(gap)>MAX_SKEW_SECONDS or after_eval:
                row['outcome']=OUTCOMES[5]
            else:row['outcome']=OUTCOMES[6]
        rows.append(row)
    peer=[]
    if len(chronological)==2:
        a,b=chronological
        diff=abs((datetime.fromisoformat(a['signed_tsa_gen_time_utc'].replace('Z','+00:00'))-
                  datetime.fromisoformat(b['signed_tsa_gen_time_utc'].replace('Z','+00:00'))).total_seconds())
        peer=[{'left_channel_id':a['channel_id'],'right_channel_id':b['channel_id'],
               'absolute_signed_gen_time_difference_seconds':diff,
               'within_five_minutes':diff<=MAX_SKEW_SECONDS,
               'common_tsa_root_der_fingerprint':len(set(seen_root_certs))==1,
               'common_tsa_signer_certificate':len(set(seen_tsa_signers))==1,
               'two_different_tokens_not_proof_of_independent_institutions':True}]
        if diff>MAX_SKEW_SECONDS:
            for r in chronological:
                if r['outcome']==OUTCOMES[6]:r['outcome']=OUTCOMES[5]
    _check_late(pins)
    counts={k:sum(r['outcome']==k for r in rows) for k in OUTCOMES}
    status=next(OUTCOMES[i] for i in PRIORITY if counts[OUTCOMES[i]])+'_unresolved'
    return {'schema':RESULT_SCHEMA,'command':'audit-tsa-evidence',
            'status':status,'exit_code':2,'case_id':source['case_id'],
            'ec349_full_signed_history_replayed':True,
            'ec349_verified_result_canonical_sha256':case.sha(reg.canonical(source)),
            'ec349_channel_directory_original_raw_sha256s':source['channel_directory_original_raw_sha256s'],
            'tsa_evaluation_utc_as_caller_claim':tsa_evaluation_utc,
            'token_original_count':len(mapped),'crl_original_count':len(crls),
            'channel_evidence':rows,'cross_token_time_comparison':peer,
            'outcome_counts':counts,
            'cryptographic_verification_is_not_external_root_provenance_or_trusted_utc':True,
            'offline_unresolved_exit_code':2,
            **{k:False for k in NEGATIVES}}
