#!/usr/bin/env python3
"""EC399 offline X.509 two-root publisher attestation and historical CRL receiver.

Strictly re-runs unchanged EC398 audit. It verifies the actual EC398 notice's
original opaque source via two independent, externally pinned X.509 chains and
original detached signatures plus historical and evaluation-time issuer CRLs.
Signature/PKI proof is NOT a proof that an entity is a government's legal issuer,
that the file was actually published, or that a global revocation record is complete.
No network, credentials, key creation, signature creation, subprocess, or writes.
"""
from __future__ import annotations

import base64
import re
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa, padding
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier, SignatureAlgorithmOID
from ec295_delivery_anchor import anchor as errors
from ec372_historical_authority import authority_archive as io
from ec398_official_notice import protocol as parent

RESULT_SCHEMA='ces.ec399.receiver_two_root_gazette_certificate_revocation_unresolved.v1'
DERIVE_SCHEMA='ces.ec399.unsigned_two_root_gazette_certificate_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec399.gazette_certificate_revocation_denial.v1'
INVENTORY_SCHEMA='ces.ec399.unsigned_two_root_gazette_certificate_inventory.v1'
BUNDLE_SCHEMA='ces.ec399.two_root_gazette_certificate_originals_bundle.v1'
ROSTER_SCHEMA='ces.ec399.two_independently_pinned_publisher_x509_roster.v1'
ATTEST_SCHEMA='ces.ec399.detached_publisher_gazette_signature_original.v1'
CLAIM_SCHEMA='ces.ec399.detached_publisher_gazette_signature_claim.v1'
DOMAIN=b'CES/EC399/OfflineX509GazettePublisherOriginal/v1\0'
ZERO='0'*64
MAX_BUNDLE=240_000
MAX_ROSTER=30_000
MAX_SIGNED=25_000
MAX_CERT=24_000
MAX_CRL=2_000_000
OID_RE=re.compile(r'(?:[0-2])(?:\.(?:0|[1-9][0-9]*)){2,14}\Z')

PARENT_SCALARS=(*parent.PARENT_SCALARS,*parent.NEW_SCALARS,*parent.AUDIT_ONLY)
PARENT_REPEATS=(*parent.PARENT_REPEATS,*parent.REPEAT_NAMES)
NEW_SCALARS=(
 'historical_ec339_official_certificate_bundle_file',
 'expected_historical_ec339_official_certificate_bundle_sha256',
 'expected_outside_retained_ec399_publisher_roster_sha256',
 'expected_outside_retained_ec399_publisher_a_trust_root_der_sha256',
 'expected_outside_retained_ec399_publisher_b_trust_root_der_sha256',
 'expected_outside_retained_ec399_publisher_a_leaf_spki_sha256',
 'expected_outside_retained_ec399_publisher_b_leaf_spki_sha256',
 'expected_outside_retained_ec399_publisher_policy_oid',
 'expected_outside_retained_ec399_first_publisher_a_signature_sha256',
 'expected_outside_retained_ec399_first_publisher_b_signature_sha256',
)
AUDIT_ONLY=('expected_retained_historical_ec339_official_certificate_inventory_sha256',)
NEW_REPEATS=(
 ('historical_ec339_official_publisher_signed_original_inventory_shas',
   '--historical-ec339-official-publisher-signed-original-inventory-sha256'),
 ('historical_ec339_official_publisher_crl_inventory_shas',
   '--historical-ec339-official-publisher-crl-inventory-sha256'),
 ('minimum_historical_ec339_two_root_certificate_publisher_counts',
   '--minimum-historical-ec339-two-root-certificate-publisher-count'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
FLAGS=(
 'inherited_real_ec398_notice_or_parent_registry_consistency_disputed',
 'outside_held_certificate_original_sha_or_epoch_count_floor_disagrees',
 'two_independent_original_publisher_signatures_or_chain_unavailable',
 'historical_and_evaluation_signed_crl_coverage_incomplete_or_revoked',
 'signed_publisher_predecessor_or_certificate_time_unbounded',
 'official_real_world_legal_authorization_and_primary_source_format_not_proven',
 'independent_pre_dispute_public_archive_and_global_revocation_not_proven',
 'qualified_tsa_physical_worm_unmocked_full_chain_and_final_acceptance_not_proven',
)
OUTCOMES=(
 'ec399_real_parent_notice_or_registry_status_disputed',
 'ec399_external_certificate_original_sha_or_count_floor_disagrees',
 'ec399_independent_x509_signed_gazette_original_or_chain_incomplete',
 'ec399_historical_or_current_signed_issuer_crl_incomplete_or_revoked',
 'ec399_signed_certificate_predecessor_or_time_unbounded',
 'ec399_official_legal_issuer_authorization_and_native_primary_format_not_proven',
 'ec399_actual_historical_public_availability_and_global_revocation_not_proven',
 'ec399_qualified_time_worm_unmocked_history_and_final_acceptance_not_proven',
)
NEGATIVES=(
 'externally_supplied_pinned_roots_establish_actual_government_or_court_authority',
 'custom_detached_x509_signature_is_official_cms_pades_xmldsig_or_government_gazette',
 'two_root_signature_consensus_proves_official_publication_before_dispute',
 'furnished_historical_crls_prove_global_ocsp_or_complete_later_revocations',
 'certificates_with_custom_policy_oid_alone_prove_legal_issuer_accreditation',
 'claimed_signed_utc_is_independently_qualified_legal_signing_timestamp',
 'caller_provided_evaluation_utc_proves_actual_today_or_complete_reliance_time',
 'dual_x509_signatures_prove_physical_worm_or_independent_legal_organizations',
 'receiver_issued_keys_private_signatures_crls_timestamps_or_written_evidence',
 'receiver_used_network_ocsp_government_provider_git_ci_or_online_trust_store',
 'original_powershell_and_unmocked_external_history_or_final_acceptance_passed',
)
BUNDLE_FIELDS={'schema','claimed_directory_lineage_id',
 'parent_ec398_external_notice_bundle_original','outside_publisher_roster_original','epochs'}
ROSTER_FIELDS={'schema','claimed_directory_lineage_id','publishers'}
ROLE_FIELDS={'publisher_id','site_id','certificate_chain_originals','required_policy_oid',
             'required_publisher_eku_oid'}
EPOCH_FIELDS={'epoch_index','publishers'}
PUBLISHER_FIELDS={'publisher_id','signed_gazette_attestation_original','issuer_crl_coverage'}
CRL_ROW_FIELDS={'issuer_certificate_sha256','historical_crl_original','evaluation_crl_original'}
ATTEST_FIELDS={'schema','claim','signature_base64'}
CLAIM_FIELDS={'schema','directory_lineage_id','epoch_index','publisher_id',
 'parent_ec398_bundle_sha256','parent_ec398_verified_inventory_sha256',
 'parent_signed_notice_original_sha256','parent_ec396_signed_registry_snapshot_sha256',
 'source_gazette_original_sha256','leaf_certificate_der_sha256',
 'certificate_chain_sha256','previous_signed_attestation_original_sha256',
 'claimed_published_utc','required_policy_oid'}


def need(condition,code,status='invalid_input'):
    if condition is not True:
        raise errors.AnchorError('EC399_'+code,status)


def exact(obj,keys,code):need(type(obj) is dict and set(obj)==keys,code+'_EXACT_FIELDS_REQUIRED')
def ref(obj):return parent.rawref(obj)
def valid_sha(obj):return parent.valid_sha(obj)
def sha(raw):return parent.digest(raw)
def cdigest(obj):return parent.cdigest(obj)
def _utc(obj):return parent._utc(obj)


def _id(obj):return type(obj) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_.:-]{0,95}',obj) is not None


def _oid(obj):
    if type(obj) is not str or len(obj)>90 or not OID_RE.fullmatch(obj):return False
    try:return ObjectIdentifier(obj).dotted_string==obj
    except ValueError:return False


def _inputs(opts,derive):
    needed=set((*PARENT_SCALARS,*PARENT_REPEATS,*NEW_SCALARS,*REPEAT_NAMES))
    if not derive:needed.update(AUDIT_ONLY)
    need(set(opts)==needed,'EXACT_REAL_EC398_AND_NEW_INPUTS_REQUIRED')
    inherited={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    parent._inputs(inherited,False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],'EC399_BUNDLE')
    for key in (*NEW_SCALARS[2:7],*NEW_SCALARS[8:]):
        need(valid_sha(opts[key]),'EXTERNAL_ORIGINAL_DIGEST_PIN_INVALID')
    need(opts[NEW_SCALARS[3]]!=opts[NEW_SCALARS[4]] and
         opts[NEW_SCALARS[5]]!=opts[NEW_SCALARS[6]],
         'INDEPENDENT_ROOT_AND_LEAF_PINS_MUST_DIFFER','permission_denied')
    need(_oid(opts[NEW_SCALARS[7]]),'OUTSIDE_AUTHORIZED_POLICY_OID_INVALID')
    if not derive:need(valid_sha(opts[AUDIT_ONLY[0]]),'INDEPENDENT_WHOLE_INVENTORY_SHA_REQUIRED')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'ONE_TO_THREE_EPOCHS_REQUIRED')
    for k in REPEAT_NAMES:
        vals=opts[k]
        need(type(vals) is list and len(vals)==n,'ONE_EXTERNAL_ORIGINAL_CONSTRAINT_PER_EPOCH')
        if k.startswith('minimum_'):
            need(all(type(v) is int and 0<=v<=2 for v in vals),
                 'PUBLISHER_FLOOR_OUT_OF_RANGE')
        else:need(all(valid_sha(v) for v in vals),'INDEPENDENT_EPOCH_DIGEST_INVALID')
    return inherited


def _parent_report(report,opts):
    fields={'schema','command','status','exit_code','offline_unresolved_exit_code',
      'verified_live_ec397_report_sha256','verified_live_ec397_inventory_sha256',
      'original_external_notice_bundle_sha256',
      'receiver_verified_external_notice_inventory_sha256',
      'verified_corroborated_active_notice_role_count',
      'verified_two_channel_three_original_custody_count',
      'visible_genuine_signed_registry_conflict_count','external_notice_epoch_reviews',
      'bounded_local_external_notice_and_custody_consistency',
      'sender_origin_path_required_or_read',
      'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
      *parent.FLAGS,*parent.NEGATIVES}
    n=len(opts['historical_directory_root_shas'])
    need(type(report) is dict and set(report)==fields and
         report.get('schema')==parent.RESULT_SCHEMA and
         report.get('command')=='audit-historical-ec339-external-notice' and
         report.get('exit_code')==2 and report.get('offline_unresolved_exit_code')==2 and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         report.get('original_external_notice_bundle_sha256')==opts[parent.NEW_SCALARS[1]] and
         report.get('receiver_verified_external_notice_inventory_sha256')==opts[parent.AUDIT_ONLY[0]] and
         all(valid_sha(report.get(k)) for k in (
             'verified_live_ec397_report_sha256','verified_live_ec397_inventory_sha256')) and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         all(report[k] is True for k in parent.FLAGS[-3:]) and
         report.get('bounded_local_external_notice_and_custody_consistency') is
              (not any(report[k] for k in parent.FLAGS[:6])) and
         report.get('status')==next((parent.OUTCOMES[i] for i,k in enumerate(parent.FLAGS)
              if report[k]),parent.OUTCOMES[-1])+'_unresolved',
         'EC398_REAL_PARENT_REPORT_SHA_STATUS_INVALID','unavailable')
    reviews=report.get('external_notice_epoch_reviews')
    keys={'epoch_index','verified_corroborated_active_role_count',
     'verified_independent_three_original_custody_count',
     'genuine_signed_registry_subject_conflicts',
     'notice_originals_inventory_sha256','custody_original_readback_inventory_sha256'}
    need(type(reviews) is list and len(reviews)==n and all(
         type(r) is dict and set(r)==keys and type(r['epoch_index']) is int and
         r['epoch_index']==i and all(type(r[k]) is int and 0<=r[k]<=cap for k,cap in (
             ('verified_corroborated_active_role_count',4),
             ('verified_independent_three_original_custody_count',2),
             ('genuine_signed_registry_subject_conflicts',4))) and
         all(valid_sha(r[k]) for k in ('notice_originals_inventory_sha256',
                                      'custody_original_readback_inventory_sha256'))
         for i,r in enumerate(reviews)) and
         all(type(report.get(name)) is int and report[name]==sum(r[field] for r in reviews)
           for name,field in (
               ('verified_corroborated_active_notice_role_count',
                'verified_corroborated_active_role_count'),
               ('verified_two_channel_three_original_custody_count',
                'verified_independent_three_original_custody_count'),
               ('visible_genuine_signed_registry_conflict_count',
                'genuine_signed_registry_subject_conflicts'))),
         'EC398_REAL_PARENT_COUNT_OR_EPOCH_REVIEW_MISMATCH','unavailable')
    return cdigest(report)


def _verify_signature(pub,signature,data,signature_oid=None):
    """Whitelist strong algorithms; no unsupported PSS/DSA/SHA1 fallback."""
    need(type(signature) is bytes and len(signature)>0 and len(signature)<=1024,
         'UNBOUNDED_OR_MISSING_SIGNATURE','permission_denied')
    try:
        if isinstance(pub,ed25519.Ed25519PublicKey):
            if signature_oid is not None:need(signature_oid==SignatureAlgorithmOID.ED25519,
                                              'CERT_SIGNATURE_ALGORITHM_UNSUPPORTED','permission_denied')
            pub.verify(signature,data)
        elif isinstance(pub,ec.EllipticCurvePublicKey):
            need(isinstance(pub.curve,(ec.SECP256R1,ec.SECP384R1)),
                 'WEAK_OR_UNSUPPORTED_EC_CURVE','permission_denied')
            if signature_oid is None:
                digest=hashes.SHA256() if isinstance(pub.curve,ec.SECP256R1) else hashes.SHA384()
            else:
                need(signature_oid in (SignatureAlgorithmOID.ECDSA_WITH_SHA256,
                      SignatureAlgorithmOID.ECDSA_WITH_SHA384),
                     'EC_CERT_SIGNATURE_DIGEST_UNSUPPORTED','permission_denied')
                digest=(hashes.SHA256() if signature_oid==SignatureAlgorithmOID.ECDSA_WITH_SHA256
                        else hashes.SHA384())
            pub.verify(signature,data,ec.ECDSA(digest))
        elif isinstance(pub,rsa.RSAPublicKey):
            need(pub.key_size>=2048 and pub.key_size<=8192 and pub.public_numbers().e==65537,
                 'WEAK_OR_UNSUPPORTED_RSA_KEY','permission_denied')
            if signature_oid is not None:
                need(signature_oid in (SignatureAlgorithmOID.RSA_WITH_SHA256,
                     SignatureAlgorithmOID.RSA_WITH_SHA384,
                     SignatureAlgorithmOID.RSA_WITH_SHA512),
                     'RSA_CERT_SIGNATURE_DIGEST_UNSUPPORTED','permission_denied')
            algorithm={SignatureAlgorithmOID.RSA_WITH_SHA384:hashes.SHA384,
                       SignatureAlgorithmOID.RSA_WITH_SHA512:hashes.SHA512}.get(
                         signature_oid,hashes.SHA256)()
            pub.verify(signature,data,padding.PKCS1v15(),algorithm)
        else:need(False,'UNSUPPORTED_SIGNING_PUBLIC_KEY','permission_denied')
    except (InvalidSignature,ValueError,TypeError,OverflowError) as exc:
        raise errors.AnchorError('EC399_INVALID_GENUINE_SIGNATURE','permission_denied') from exc


def _strong_pub(pub):
    if isinstance(pub,ed25519.Ed25519PublicKey):return
    if isinstance(pub,ec.EllipticCurvePublicKey) and isinstance(pub.curve,(ec.SECP256R1,ec.SECP384R1)):return
    if isinstance(pub,rsa.RSAPublicKey) and 2048<=pub.key_size<=8192 and pub.public_numbers().e==65537:return
    need(False,'UNSUPPORTED_OR_WEAK_CHAIN_PUBLIC_KEY','permission_denied')


def _ext(cert,oid,required=True):
    try:return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        need(not required,'MISSING_REQUIRED_CERTIFICATE_EXTENSION','permission_denied')
        return None


def _chain(role,opts,read):
    exact(role,ROLE_FIELDS,'PUBLISHER_CERTIFICATE_ROLE')
    need(_id(role['publisher_id']) and _id(role['site_id']) and
         _oid(role['required_policy_oid']) and _oid(role['required_publisher_eku_oid']) and
         role['required_policy_oid']==opts[NEW_SCALARS[7]],
         'EXTERNALLY_PINNED_PUBLISHER_ROLE_OR_POLICY_MISMATCH','permission_denied')
    refs=role['certificate_chain_originals']
    need(type(refs) is list and len(refs) in (2,3),
         'EXACT_LEAF_OPTIONAL_INTERMEDIATE_ROOT_CHAIN_REQUIRED','permission_denied')
    refs=[ref(r) for r in refs]
    need(len({r['path'] for r in refs})==len(refs) and
         len({r['sha256'] for r in refs})==len(refs),
         'PUBLISHER_CERTIFICATE_CHAIN_PATH_OR_SHA_ALIASED','permission_denied')
    certs=[];spkis=[]
    supported_cert_critical={ExtensionOID.BASIC_CONSTRAINTS,ExtensionOID.KEY_USAGE,
      ExtensionOID.EXTENDED_KEY_USAGE,ExtensionOID.CERTIFICATE_POLICIES,
      ExtensionOID.SUBJECT_KEY_IDENTIFIER,ExtensionOID.AUTHORITY_KEY_IDENTIFIER}
    for r in refs:
        raw=read(r,'ec399_verified_original_der_certificate',MAX_CERT)
        try:
            cert=x509.load_der_x509_certificate(raw)
            need(cert.public_bytes(serialization.Encoding.DER)==raw,
                 'CERTIFICATE_NOT_EXACT_DER','permission_denied')
        except (ValueError,TypeError) as exc:
            raise errors.AnchorError('EC399_MALFORMED_CERTIFICATE_DER','permission_denied') from exc
        need(all(not x.critical or x.oid in supported_cert_critical for x in cert.extensions),
             'UNKNOWN_CRITICAL_CERTIFICATE_EXTENSION','permission_denied')
        need(all(x.oid not in (ExtensionOID.NAME_CONSTRAINTS,ExtensionOID.POLICY_MAPPINGS,
                              ExtensionOID.POLICY_CONSTRAINTS) for x in cert.extensions),
             'UNIMPLEMENTED_CERTIFICATE_PATH_CONSTRAINT','permission_denied')
        pub=cert.public_key();_strong_pub(pub)
        certs.append(cert)
        spkis.append(sha(pub.public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)))
        need(cert.signature_algorithm_oid not in (SignatureAlgorithmOID.RSA_WITH_SHA1,
              SignatureAlgorithmOID.ECDSA_WITH_SHA1),
             'WEAK_CERTIFICATE_SIGNATURE','permission_denied')
    need(len(set(spkis))==len(spkis),'SAME_PUBLIC_KEY_USED_IN_CERTIFICATE_CHAIN','permission_denied')
    leaf,root=certs[0],certs[-1]
    need(leaf.issuer==certs[1].subject and root.issuer==root.subject and
         root.subject!=leaf.subject and
         leaf.serial_number>0,
         'CHAIN_ISSUER_NAME_OR_ROOT_SELF_ISSUE_MISMATCH','permission_denied')
    for i,cert in enumerate(certs):
        pub=cert.public_key()
        ca=i>0
        basic=_ext(cert,ExtensionOID.BASIC_CONSTRAINTS)
        usage=_ext(cert,ExtensionOID.KEY_USAGE)
        need((basic.ca is False and usage.digital_signature is True and
              usage.key_cert_sign is False and usage.crl_sign is False) if not ca else
             (basic.ca is True and usage.key_cert_sign is True and usage.crl_sign is True),
             'CA_OR_LEAF_BASIC_CONSTRAINTS_AND_KEY_USAGE_WRONG','permission_denied')
        if ca and basic.path_length is not None:
            need(basic.path_length>=i-1,
                 'INTERMEDIATE_OR_ROOT_CA_PATH_LENGTH_EXCEEDED','permission_denied')
        if ca:
            capolicy=_ext(cert,ExtensionOID.CERTIFICATE_POLICIES,False)
            if capolicy is not None:
                need(role['required_policy_oid'] in
                     {p.policy_identifier.dotted_string for p in capolicy},
                     'INTERMEDIATE_POLICY_MUST_AUTHORIZE_PINNED_LEAF_POLICY',
                     'permission_denied')
        if i<len(certs)-1:
            issuer=certs[i+1]
            need(cert.issuer==issuer.subject,'CHAIN_ISSUER_SUBJECT_MISMATCH','permission_denied')
            _verify_signature(issuer.public_key(),cert.signature,cert.tbs_certificate_bytes,
                              cert.signature_algorithm_oid)
            ski=_ext(issuer,ExtensionOID.SUBJECT_KEY_IDENTIFIER,False)
            aki=_ext(cert,ExtensionOID.AUTHORITY_KEY_IDENTIFIER,False)
            if ski is not None and aki is not None and aki.key_identifier is not None:
                need(ski.digest==aki.key_identifier,'CERT_AUTHORITY_KEY_ID_MISMATCH','permission_denied')
    _verify_signature(root.public_key(),root.signature,root.tbs_certificate_bytes,
                      root.signature_algorithm_oid)
    policy=_ext(leaf,ExtensionOID.CERTIFICATE_POLICIES)
    need(role['required_policy_oid'] in {p.policy_identifier.dotted_string for p in policy},
         'LEAF_CERTIFICATE_OFFICIAL_POLICY_OID_MISSING','permission_denied')
    eku=_ext(leaf,ExtensionOID.EXTENDED_KEY_USAGE)
    need(ObjectIdentifier(role['required_publisher_eku_oid']) in eku,
         'LEAF_CERTIFICATE_PUBLISHER_EKU_MISSING','permission_denied')
    need(_ext(leaf,ExtensionOID.BASIC_CONSTRAINTS).ca is False,
         'LEAF_MUST_NOT_BE_CA','permission_denied')
    return {'role':role,'refs':refs,'certs':certs,'spkis':spkis,
            'chain_sha256':cdigest([r['sha256'] for r in refs])}


def _certificate_time(chain,when):
    return all(c.not_valid_before_utc<=when<=c.not_valid_after_utc for c in chain['certs'])


def _crl(refobj,issuer,subject,when,read):
    if refobj is None:return {'sha256':None,'covered':False,'revoked':False,
                               'this_update':None,'crl_number':None}
    r=ref(refobj);raw=read(r,'ec399_independently_collected_original_der_crl',MAX_CRL)
    try:
        crl=x509.load_der_x509_crl(raw)
        need(crl.public_bytes(serialization.Encoding.DER)==raw,'CRL_NOT_EXACT_DER','permission_denied')
    except (ValueError,TypeError) as exc:
        raise errors.AnchorError('EC399_MALFORMED_ISSUER_CRL','permission_denied') from exc
    need(crl.issuer==issuer.subject and crl.next_update_utc is not None,
         'CRL_WRONG_ISSUER_OR_NO_NEXT_UPDATE','permission_denied')
    need(all(not x.critical or x.oid in (ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
         ExtensionOID.ISSUING_DISTRIBUTION_POINT,ExtensionOID.CRL_NUMBER)
         for x in crl.extensions),
         'UNKNOWN_CRITICAL_CRL_EXTENSION','permission_denied')
    # Offline indirect/delta/partitioned CRLs are not complete revocation coverage.
    delta=None
    try:delta=crl.extensions.get_extension_for_oid(ExtensionOID.DELTA_CRL_INDICATOR)
    except x509.ExtensionNotFound:pass
    need(delta is None,'DELTA_CRL_NOT_COMPLETE_REVOCATION_EVIDENCE','permission_denied')
    try:
        idp=crl.extensions.get_extension_for_oid(ExtensionOID.ISSUING_DISTRIBUTION_POINT).value
        need(not idp.indirect_crl and idp.only_contains_user_certs is False and
             idp.only_contains_ca_certs is False and idp.only_some_reasons is None and
             idp.full_name is None and idp.relative_name is None,
             'PARTIAL_OR_INDIRECT_CRL_NOT_COMPLETE','permission_denied')
    except x509.ExtensionNotFound:pass
    ski=_ext(issuer,ExtensionOID.SUBJECT_KEY_IDENTIFIER,False)
    try:
        aki=crl.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
        if ski is not None and aki.key_identifier is not None:
            need(ski.digest==aki.key_identifier,'CRL_ISSUER_KEY_ID_DISAGREES','permission_denied')
    except x509.ExtensionNotFound:pass
    _verify_signature(issuer.public_key(),crl.signature,crl.tbs_certlist_bytes,
                      crl.signature_algorithm_oid)
    revoked=False
    for revoked_cert in crl:
        if revoked_cert.serial_number==subject.serial_number and revoked_cert.revocation_date_utc<=when:
            revoked=True
    crlnumber=None
    try:crlnumber=crl.extensions.get_extension_for_oid(ExtensionOID.CRL_NUMBER).value.crl_number
    except x509.ExtensionNotFound:pass
    return {'sha256':r['sha256'],
            'covered':crl.last_update_utc<=when<=crl.next_update_utc,
            'revoked':revoked,'this_update':crl.last_update_utc.isoformat(),
            'crl_number':crlnumber}


def _crl_coverage(rows,chain,claimed,evaluation,read):
    certs=chain['certs'];refs=chain['refs']
    if rows is None:return {'complete':False,'revoked':False,'crl_originals':[]}
    need(type(rows) is list and len(rows)==len(certs)-1,
         'ONE_ISSUER_HISTORICAL_AND_EVALUATION_CRL_PAIR_PER_CHAIN_LINK_REQUIRED',
         'permission_denied')
    summaries=[];seen=set();allgood=True;anyrevoked=False
    for idx,row in enumerate(rows):
        exact(row,CRL_ROW_FIELDS,'ISSUER_SIGNED_CRL_PAIR')
        need(row['issuer_certificate_sha256']==refs[idx+1]['sha256'],
             'CRL_ISSUER_OR_CHAIN_ROW_WRONG_ORDER','permission_denied')
        h,e=row['historical_crl_original'],row['evaluation_crl_original']
        for orig in (h,e):
            if orig is not None:
                rr=ref(orig)
                need(rr['path'] not in seen,'SAME_ORIGINAL_USED_AS_BOTH_CRL_PROOFS',
                     'permission_denied')
                seen.add(rr['path'])
        hv=_crl(h,certs[idx+1],certs[idx],claimed,read)
        ev=_crl(e,certs[idx+1],certs[idx],evaluation,read)
        if hv['this_update'] is not None and ev['this_update'] is not None:
            need(ev['this_update']>=hv['this_update'],
                 'EVALUATION_CRL_PRECEDES_HISTORICAL_CRL','permission_denied')
        if hv['crl_number'] is not None and ev['crl_number'] is not None:
            need(ev['crl_number']>=hv['crl_number'],
                 'EVALUATION_CRL_NUMBER_ROLLED_BACK','permission_denied')
        complete=hv['covered'] and ev['covered']
        allgood=allgood and complete
        anyrevoked=anyrevoked or hv['revoked'] or ev['revoked']
        summaries.append({'issuer_certificate_sha256':refs[idx+1]['sha256'],
         'subject_certificate_sha256':refs[idx]['sha256'],
         'historical_crl':hv,'evaluation_crl':ev})
    return {'complete':bool(allgood),'revoked':bool(anyrevoked),'crl_originals':summaries}


def _signed(row,chain,idx,source_ref,notice_ref,registry_sha,pref,parent_sha,lineage,
            prior_sha,prior_time,prior_good,read,claimed):
    if row['signed_gazette_attestation_original'] is None:
        need(row['issuer_crl_coverage'] is None,
             'ABSENT_PUBLISHER_SIGNATURE_CANNOT_CLAIM_ISSUER_CRLS','permission_denied')
        return {'signed_attestation_sha256':None,'signature_cryptographically_valid':False,
                'claimed_published_utc':None,'certificate_chain_time_bounded':False,
                'predecessor_continuous':False,'source_gazette_original_sha256':source_ref['sha256']
                     if source_ref else None},None
    need(source_ref is not None and notice_ref is not None and registry_sha is not None,
         'PUBLISHER_NEEDS_REAL_SIGNED_PARENT_NOTICE_AND_SOURCE','permission_denied')
    r=ref(row['signed_gazette_attestation_original'])
    raw=read(r,'ec399_original_x509_detached_gazette_signature',MAX_SIGNED)
    try:
        import json
        def no_duplicate_fields(pairs):
            result={}
            for key,value in pairs:
                if key in result:raise ValueError('duplicate signed field')
                result[key]=value
            return result
        signed=json.loads(raw.decode('utf-8'),object_pairs_hook=no_duplicate_fields)
    except (UnicodeError,ValueError) as exc:
        raise errors.AnchorError('EC399_INVALID_SIGNED_ATTESTATION_JSON','permission_denied') from exc
    exact(signed,ATTEST_FIELDS,'DETACHED_GAZETTE_SIGNATURE')
    claim=signed['claim'];exact(claim,CLAIM_FIELDS,'DETACHED_GAZETTE_SIGNATURE_CLAIM')
    need(signed['schema']==ATTEST_SCHEMA and claim['schema']==CLAIM_SCHEMA and
         claim['directory_lineage_id']==lineage and
         claim['epoch_index']==idx and type(claim['epoch_index']) is int and
         claim['publisher_id']==chain['role']['publisher_id'] and
         claim['parent_ec398_bundle_sha256']==pref['sha256'] and
         claim['parent_ec398_verified_inventory_sha256']==parent_sha and
         claim['parent_signed_notice_original_sha256']==notice_ref['sha256'] and
         claim['parent_ec396_signed_registry_snapshot_sha256']==registry_sha and
         claim['source_gazette_original_sha256']==source_ref['sha256'] and
         claim['leaf_certificate_der_sha256']==chain['refs'][0]['sha256'] and
         claim['certificate_chain_sha256']==chain['chain_sha256'] and
         claim['previous_signed_attestation_original_sha256']==prior_sha and
         claim['required_policy_oid']==chain['role']['required_policy_oid'],
         'DETACTED_X509_CLAIM_NOT_BOUND_TO_REAL_PARENT_AND_CHAIN','permission_denied')
    signed_at=_utc(claim['claimed_published_utc'])
    need(claim['claimed_published_utc']==claimed,
         'PUBLISHER_CANNOT_MOVE_REAL_PARENT_SIGNED_NOTICE_TIME','permission_denied')
    s=signed['signature_base64']
    need(type(s) is str and 0<len(s)<=1500,'X509_SIGNATURE_BASE64_INVALID','permission_denied')
    try:sig=base64.b64decode(s,validate=True)
    except (ValueError,base64.binascii.Error) as exc:
        raise errors.AnchorError('EC399_INVALID_SIGNATURE_BASE64','permission_denied') from exc
    from ec319_offline_transfer_registry import registry as registry_canonical
    message=DOMAIN+registry_canonical.canonical(claim)
    _verify_signature(chain['certs'][0].public_key(),sig,message)
    dategood=_certificate_time(chain,signed_at)
    continuity=bool(prior_good and (prior_time is None or signed_at>=prior_time))
    return {'signed_attestation_sha256':r['sha256'],'signature_cryptographically_valid':True,
            'claimed_published_utc':claim['claimed_published_utc'],
            'certificate_chain_time_bounded':dategood,
            'predecessor_continuous':continuity,
            'source_gazette_original_sha256':source_ref['sha256']},signed_at


def _engine(derive,**opts):
    inherited=_inputs(opts,derive)
    live=parent.audit(**inherited)   # REQUIRED real EC398, full ancestor chain.
    live_sha=_parent_report(live,opts)
    n=len(opts['historical_directory_root_shas'])
    lineage=opts['claimed_historical_directory_lineage_id']
    evaluated=_utc(opts['ec391_tsa_evaluation_utc'])
    read,doc,late=parent.parent.parent.parent.prior._readers()
    rootref={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    bundle=doc(rootref,'ec399_independent_official_publisher_certificate_bundle',MAX_BUNDLE)
    exact(bundle,BUNDLE_FIELDS,'TWO_PUBLISHER_CERTIFICATE_BUNDLE')
    pref={'path':opts[parent.NEW_SCALARS[0]],'sha256':opts[parent.NEW_SCALARS[1]]}
    need(bundle['schema']==BUNDLE_SCHEMA and bundle['claimed_directory_lineage_id']==lineage and
         bundle['parent_ec398_external_notice_bundle_original']==pref and
         type(bundle['epochs']) is list and len(bundle['epochs'])==n,
         'CERTIFICATE_BUNDLE_DOES_NOT_BIND_TRUE_PARENT','permission_denied')
    parentbundle=doc(pref,'authentic_parent_ec398_external_notice_source',parent.MAX_BUNDLE)
    exact(parentbundle,parent.BUNDLE_FIELDS,'REAL_EC398_PARENT_ORIGINAL')
    need(parentbundle['claimed_directory_lineage_id']==lineage,
         'REAL_PARENT_ORIGINAL_LINEAGE_MISMATCH','permission_denied')
    rosterref=ref(bundle['outside_publisher_roster_original'])
    roster=doc(rosterref,'external_two_publisher_certificate_roster',MAX_ROSTER)
    exact(roster,ROSTER_FIELDS,'TWO_INDEPENDENT_TRUST_ROOT_ROSTER')
    need(roster['schema']==ROSTER_SCHEMA and roster['claimed_directory_lineage_id']==lineage and
         rosterref['sha256']==opts[NEW_SCALARS[2]] and
         type(roster['publishers']) is list and len(roster['publishers'])==2,
         'OUTSIDE_PINNED_PUBLISHER_CERTIFICATE_ROSTER_INVALID','permission_denied')
    chains=[_chain(r,opts,read) for r in roster['publishers']]
    need(len({c['role']['publisher_id'] for c in chains})==2 and
         len({c['role']['site_id'] for c in chains})==2 and
         len({r['path'] for c in chains for r in c['refs']})==sum(len(c['refs']) for c in chains) and
         len({s for c in chains for s in c['spkis']})==sum(len(c['spkis']) for c in chains),
         'PUBLISHER_ROLE_SITE_CERTIFICATE_OR_PUBLIC_KEY_REUSED','permission_denied')
    for i,chain in enumerate(chains):
        need(chain['refs'][-1]['sha256']==opts[NEW_SCALARS[3+i]] and
             chain['spkis'][0]==opts[NEW_SCALARS[5+i]],
             'EXTERNALLY_PINNED_TRUST_ROOT_OR_LEAF_PUBLIC_KEY_NOT_MATCHED',
             'permission_denied')
    # Parent audited all source bytes; nevertheless reopen its actual signed
    # notice and referenced gazette so no caller-supplied SHA substitutes for it.
    parent_roster_ref=ref(parentbundle['outside_notice_roster_original'])
    parent_roster=doc(parent_roster_ref,'real_ec398_registrar_identity',parent.MAX_ROSTER)
    exact(parent_roster,parent.ROSTER_FIELDS,'REAL_EC398_SIGNER_ROSTER')
    publisher_der_keys={s for c in chains for s in c['spkis']}
    for role in (parent_roster['registrar'],*parent_roster['custodians']):
        need(sha(ed25519.Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(role['public_hex'])).public_bytes(
                serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))
             not in publisher_der_keys,
             'CERTIFICATE_PUBLISHER_KEY_REUSED_FROM_PARENT_ED25519','permission_denied')
    protected=set()
    parent._collect_sources(parentbundle,protected)
    parent._collect_sources(parent_roster,protected)
    # Ancestor manifests were genuinely audited by EC398; additionally reopen
    # their raw references so a new CRL/certificate cannot alias a parent
    # registry/log/signature/custody original hidden behind a bundle pointer.
    old_bundle_ref=ref(parentbundle['parent_ec397_publication_bundle_original'])
    old397=doc(old_bundle_ref,'real_ec397_original_for_ec399_path_separation',
               parent.parent.MAX_BUNDLE)
    old396ref=ref(old397['parent_ec396_public_integrity_bundle_original'])
    old396=doc(old396ref,'real_ec396_original_for_ec399_path_separation',
               parent.parent.parent.MAX_BUNDLE)
    old395ref=ref(old396['parent_ec395_credential_gossip_bundle_original'])
    old395=doc(old395ref,'real_ec395_original_for_ec399_path_separation',
               parent.parent.parent.parent.MAX_BUNDLE)
    for obj in (old397,old396,old395):parent._collect_sources(obj,protected)
    for old_ref in (old_bundle_ref,old396ref,old395ref):protected.add(old_ref['path'])
    for roster_original in (old397.get('outside_observer_roster_original'),
            old396.get('outside_authority_roster_original'),
            old395.get('external_role_roster_original')):
        if roster_original is not None:
            rr=ref(roster_original)
            parent._collect_sources(doc(rr,'real_ancestor_signer_roster',parent.MAX_ROSTER),protected)
            protected.add(rr['path'])
    protected.update((rootref['path'],pref['path'],rosterref['path']))
    for chain in chains:
        for certref in chain['refs']:
            need(certref['path'] not in protected,
                 'NEW_CERTIFICATE_OR_ROOT_PATH_ALIASES_GENUINE_PARENT_ORIGINAL',
                 'permission_denied')
            protected.add(certref['path'])
    # Cross-epoch/new-source aliasing and root/parent aliasing are prohibited.
    used=set()
    for epoch in bundle['epochs']:
        exact(epoch,EPOCH_FIELDS,'OFFICIAL_CERTIFICATE_EPOCH_PREFLIGHT')
        need(type(epoch['publishers']) is list and len(epoch['publishers'])==2,
             'TWO_INDEPENDENT_PUBLISHER_ROWS_REQUIRED','permission_denied')
        for item in epoch['publishers']:
            exact(item,PUBLISHER_FIELDS,'PUBLISHER_ORIGINAL_EPOCH')
            paths=[]
            if item['signed_gazette_attestation_original'] is not None:
                paths.append(ref(item['signed_gazette_attestation_original'])['path'])
            if item['issuer_crl_coverage'] is not None:
                need(type(item['issuer_crl_coverage']) is list and
                     len(item['issuer_crl_coverage'])<=2,'CRL_PAIR_COUNT_UNBOUNDED','permission_denied')
                for crlrow in item['issuer_crl_coverage']:
                    exact(crlrow,CRL_ROW_FIELDS,'EXTERNAL_ISSUER_CRL_ROW_PREFLIGHT')
                    for key in ('historical_crl_original','evaluation_crl_original'):
                        if crlrow[key] is not None:paths.append(ref(crlrow[key])['path'])
            for path in paths:
                need(path not in used and path not in protected,
                     'NEW_CERTIFICATE_SIGNATURE_OR_CRL_ALIASES_PARENT_OR_OTHER_ORIGINAL',
                     'permission_denied')
                used.add(path)
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=not live['bounded_local_external_notice_and_custody_consistency']
    previous={c['role']['publisher_id']:ZERO for c in chains}
    prev_time={c['role']['publisher_id']:None for c in chains}
    preceding_ok={c['role']['publisher_id']:True for c in chains}
    first={};epoch_inventory=[];reviews=[];credited_total=0;revoked_total=0
    for idx,ep in enumerate(bundle['epochs']):
        need(type(ep['epoch_index']) is int and ep['epoch_index']==idx,
             'NONCONTIGUOUS_CERTIFICATE_EPOCH_INDEX','permission_denied')
        actual_ep=parentbundle['epochs'][idx]
        exact(actual_ep,parent.EPOCH_FIELDS,'REOPENED_EC398_EPOCH_ORIGINAL')
        notice_entry=actual_ep['notice']
        exact(notice_entry,parent.STAMP_FIELDS,'REOPENED_EC398_SIGNED_NOTICE')
        notice_ref=ref(notice_entry['signed_original']) if notice_entry['signed_original'] else None
        source_ref=ref(actual_ep['source_notice_original']) if actual_ep['source_notice_original'] else None
        claimed=None;registry_sha=None
        if notice_ref is not None:
            need(source_ref is not None,'EC398_SIGNED_NOTICE_WITHOUT_GAZETTE_SOURCE','permission_denied')
            raw,claim,sig=parent._signed(notice_ref,read,parent.NOTICE_SCHEMA,
                         parent.NOTICE_CLAIM,parent.NOTICE_CLAIM_FIELDS,
                         'REOPENED_AUTHENTIC_PARENT_SIGNED_NOTICE')
            parent._sign(parent_roster['registrar'],sig,parent.NOTICE_DOMAIN,claim,
                         'REOPENED_AUTHENTIC_PARENT_NOTICE_REGISTRAR')
            need(claim['source_notice_original_sha256']==source_ref['sha256'] and
                 claim['directory_lineage_id']==lineage and
                 type(claim['epoch_index']) is int and claim['epoch_index']==idx,
                 'SIGNED_EC398_NOTICE_SOURCE_OR_EPOCH_MISMATCH','permission_denied')
            gazette_bytes=read(source_ref,'original_real_ec398_gazette_opaque_bytes',parent.MAX_SOURCE)
            need(sha(gazette_bytes)==claim['source_notice_original_sha256'],
                 'REOPENED_SIGNED_SOURCE_SHA_MISMATCH','permission_denied')
            registry_sha=claim['parent_ec396_signed_registry_snapshot_sha256']
            claimed=claim['claimed_published_utc']
        report_ep=live['external_notice_epoch_reviews'][idx]
        parentok=bool(not flags[FLAGS[0]] and
            report_ep['verified_corroborated_active_role_count']==4 and
            report_ep['verified_independent_three_original_custody_count']==2 and
            report_ep['genuine_signed_registry_subject_conflicts']==0)
        if not parentok:flags[FLAGS[0]]=True
        results=[];crlresults=[];seen=set();credit=0
        for item in ep['publishers']:
            pid=item['publisher_id']
            need(pid in previous and pid not in seen,
                 'PUBLISHER_EPOCH_UNKNOWN_DUPLICATE_OR_MISSING','permission_denied')
            seen.add(pid);chain=next(c for c in chains if c['role']['publisher_id']==pid)
            signed,sign_time=_signed(item,chain,idx,source_ref,notice_ref,registry_sha,
                  pref,live['receiver_verified_external_notice_inventory_sha256'],lineage,
                  previous[pid],prev_time[pid],preceding_ok[pid],read,claimed)
            if idx==0:first[pid]=signed['signed_attestation_sha256']
            previous[pid]=signed['signed_attestation_sha256'] or ZERO
            prev_time[pid]=sign_time
            preceding_ok[pid]=bool(preceding_ok[pid] and signed['predecessor_continuous'] and
                                     signed['certificate_chain_time_bounded'] and sign_time is not None)
            if signed['signed_attestation_sha256'] is None:flags[FLAGS[2]]=True
            if (not signed['predecessor_continuous'] or
                not signed['certificate_chain_time_bounded'] or
                (sign_time is not None and sign_time>evaluated)):
                flags[FLAGS[4]]=True
            if signed['signed_attestation_sha256'] is None:
                crls={'complete':False,'revoked':False,'crl_originals':[]}
            else:
                crls=_crl_coverage(item['issuer_crl_coverage'],chain,sign_time,evaluated,read)
            if not crls['complete'] or crls['revoked']:flags[FLAGS[3]]=True
            if crls['revoked']:revoked_total+=1
            credited=bool(parentok and preceding_ok[pid] and crls['complete'] and not crls['revoked']
                          and sign_time is not None and sign_time<=evaluated)
            if credited:credit+=1
            signed['local_x509_issuer_crl_and_parent_consistent']=credited
            results.append({'publisher_id':pid,**signed})
            crlresults.append({'publisher_id':pid,**crls})
        need(seen==set(previous),'TWO_PUBLISHER_ROLES_PER_EPOCH_REQUIRED','permission_denied')
        results.sort(key=lambda x:x['publisher_id'])
        crlresults.sort(key=lambda x:x['publisher_id'])
        sd=cdigest(results);rd=cdigest(crlresults)
        if (sd!=opts[REPEAT_NAMES[0]][idx] or rd!=opts[REPEAT_NAMES[1]][idx] or
              credit<opts[REPEAT_NAMES[2]][idx]):flags[FLAGS[1]]=True
        credited_total+=credit
        reviews.append({'epoch_index':idx,'locally_verified_x509_publisher_count':credit,
          'signed_original_inventory_sha256':sd,'historical_current_crl_inventory_sha256':rd,
          'visible_revoked_publisher_certificates':sum(int(c['revoked']) for c in crlresults)})
        epoch_inventory.append({'epoch_index':idx,'publisher_signatures':results,
                                'historical_and_evaluation_crls':crlresults})
    if [first.get(c['role']['publisher_id']) for c in chains]!=[opts[NEW_SCALARS[8]],opts[NEW_SCALARS[9]]]:
        flags[FLAGS[1]]=True
    inventory={'schema':INVENTORY_SCHEMA,'directory_lineage_id':lineage,
       'live_true_ec398_parent_report_sha256':live_sha,
       'live_true_ec398_verified_inventory_sha256':
              live['receiver_verified_external_notice_inventory_sha256'],
       'real_ec398_external_notice_bundle_sha256':pref['sha256'],
       'official_certificate_bundle_sha256':rootref['sha256'],
       'external_publisher_certificate_roster_sha256':rosterref['sha256'],
       'first_two_signed_originals':[opts[NEW_SCALARS[8]],opts[NEW_SCALARS[9]]],
       'externally_pinned_roots':[opts[NEW_SCALARS[3]],opts[NEW_SCALARS[4]]],
       'externally_pinned_leaf_spki':[opts[NEW_SCALARS[5]],opts[NEW_SCALARS[6]]],
       'externally_pinned_certificate_policy_oid':opts[NEW_SCALARS[7]],
       'epochs':epoch_inventory}
    invsha=cdigest(inventory)
    if not derive and invsha!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    for path,(fsha,cap) in late.items():
        raw=io._read({'path':path,'sha256':fsha},
             'ec399_final_all_originals_byte_integrity_recheck',cap,{},{},set())
        need(sha(raw)==fsha,'ORIGINAL_CHANGED_AFTER_READING','permission_denied')
    for k in FLAGS[-3:]:flags[k]=True
    return {'schema':DERIVE_SCHEMA if derive else RESULT_SCHEMA,
       'command':'derive-historical-ec339-official-certificate-inventory' if derive else
                 'audit-historical-ec339-official-certificate',
       'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),OUTCOMES[-1])+'_unresolved',
       'exit_code':2,'offline_unresolved_exit_code':2,
       'verified_live_ec398_report_sha256':live_sha,
       'verified_live_ec398_inventory_sha256':live['receiver_verified_external_notice_inventory_sha256'],
       'original_two_root_certificate_bundle_sha256':rootref['sha256'],
       'receiver_verified_certificate_inventory_sha256':invsha,
       'verified_independent_x509_publisher_count':credited_total,
       'visible_historically_revoked_certificate_count':revoked_total,
       'certificate_epoch_reviews':reviews,
       'bounded_local_gazette_certificate_crl_parent_consistency':not any(flags[k] for k in FLAGS[:5]),
       'sender_origin_path_required_or_read':False,
       'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
       **flags,**{k:False for k in NEGATIVES},
       **({'unsigned_two_root_certificate_inventory':inventory} if derive else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
