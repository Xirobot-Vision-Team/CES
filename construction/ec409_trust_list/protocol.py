#!/usr/bin/env python3
"""EC409: read-only cryptographic verification of bounded ETSI-TSL original XML.

A trust-list *signing certificate* supplied with an outside SHA pin is only
cryptographically identified, NOT authenticated as an official trust-list
operator. This verifier is deliberately a strict, documented subset of ETSI
TS 119 612 XMLDSig (including optional XAdES SignedProperties): fail closed on
unsupported signature transforms, service types, or complex service policies.
Production calls the unchanged real EC408 audit before using any new original.
"""
from __future__ import annotations

import base64
import binascii
from copy import deepcopy
from datetime import timezone
import hashlib
import re

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.x509.oid import ExtensionOID
from ec295_delivery_anchor import anchor as errors
from ec372_historical_authority import authority_archive as io
from ec394_registered_witness import registered_witness as readers
from ec407_institutional_cms import protocol as cms
from ec408_institutional_ocsp import protocol as parent

RESULT_SCHEMA='ces.ec409.original_historical_signed_tsl_unresolved.v1'
DERIVE_SCHEMA='ces.ec409.unsigned_historical_tsl_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec409.signed_tsl_denial.v1'
BUNDLE_SCHEMA='ces.ec409.original_historical_signed_tsl_bundle.v1'
ROSTER_SCHEMA='ces.ec409.outside_pinned_tsl_signers.v1'
INVENTORY_SCHEMA='ces.ec409.unsigned_historical_signed_tsl_inventory.v1'
PARENT_SCALARS=(*parent.PARENT_SCALARS,*parent.NEW_SCALARS,*parent.AUDIT_ONLY)
PARENT_REPEATS=(*parent.PARENT_REPEATS,*parent.REPEAT_NAMES)
NEW_SCALARS=(
    'historical_ec339_signed_tsl_bundle_file',
    'expected_historical_ec339_signed_tsl_bundle_sha256',
    'expected_outside_ec409_tsl_signer_roster_sha256',
    'expected_outside_ec409_a_tsl_signer_certificate_der_sha256',
    'expected_outside_ec409_b_tsl_signer_certificate_der_sha256',
    'expected_outside_ec409_first_a_historical_tsl_sha256',
    'expected_outside_ec409_first_b_historical_tsl_sha256',
    'expected_outside_ec409_first_a_evaluation_tsl_sha256',
    'expected_outside_ec409_first_b_evaluation_tsl_sha256',
)
AUDIT_ONLY=('expected_retained_historical_ec339_signed_tsl_inventory_sha256',)
NEW_REPEATS=(
    ('historical_ec339_signed_tsl_epoch_inventory_shas',
     '--historical-ec339-signed-tsl-epoch-inventory-sha256'),
    ('minimum_historical_ec339_joint_signed_tsl_publisher_counts',
     '--minimum-historical-ec339-joint-signed-tsl-publisher-count'),
)
REPEAT_NAMES=tuple(k for k,_ in NEW_REPEATS)
FLAGS=(
    'real_ec408_ec407_and_earlier_original_ancestry_adverse',
    'outside_signed_tsl_certificate_first_epoch_or_whole_inventory_pin_disagrees',
    'one_or_more_later_original_historical_or_evaluation_signed_tsls_missing',
    'signed_tsl_window_or_service_status_is_not_granted_at_required_time',
    'actual_institutional_issuer_and_tsl_joint_parent_coverage_incomplete',
    'independently_verified_official_tsl_operator_authority_not_proven',
    'historical_independent_public_delivery_and_qualified_time_not_proven',
    'unmocked_external_history_full_trust_chain_worm_and_acceptance_not_proven',
)
OUTCOMES=(
    'ec409_real_ec408_and_all_earlier_parent_originals_disputed',
    'ec409_external_tsl_original_certificate_or_inventory_pins_disagree',
    'ec409_later_signed_tsl_original_pair_missing',
    'ec409_signed_tsl_issuer_service_historical_or_evaluation_grant_incomplete',
    'ec409_signed_tsl_and_actual_institutional_issuer_joint_coverage_incomplete',
    'ec409_official_independent_tsl_authority_not_authenticated',
    'ec409_independent_prior_public_distribution_and_qualified_time_not_proven',
    'ec409_full_external_ancestry_worm_and_native_acceptance_not_proven',
)
NEGATIVES=(
    'outside_pinned_signer_certificate_is_official_etsi_eu_or_supervising_authority',
    'synthetically_signed_or_self_supplied_tsl_proves_jurisdictional_accreditation',
    'signed_tsl_issuance_time_is_an_independent_qualified_timestamp',
    'signed_service_granted_covers_unlisted_certificates_or_other_service_types',
    'later_signed_tsl_backfills_independent_prior_historical_publication',
    'read_only_subset_supports_all_etsi_xmlschema_xades_lotl_and_policies',
    'trust_list_crypto_repairs_adverse_real_parent_cms_crl_or_ocsp',
    'outside_original_sha_proves_third_party_storage_or_live_public_provenance',
    'receiver_minted_trust_list_signatures_private_keys_or_official_roots',
    'receiver_accessed_network_provider_git_ci_powershell_or_worm_writer',
    'receiver_performed_full_unmocked_external_history_or_final_acceptance',
)
BUNDLE_FIELDS={'schema','claimed_directory_lineage_id',
               'parent_ec408_original_institutional_ocsp_bundle_original',
               'outside_tsl_signer_roster_original','epochs'}
ROSTER_FIELDS={'schema','claimed_directory_lineage_id','assignments'}
ASSIGNMENT_FIELDS={'publisher_id','tsl_signer_certificate_original',
                   'scheme_territory','required_service_type_uri'}
EPOCH_FIELDS={'epoch_index','publishers'}
ROLE_FIELDS={'publisher_id','original_historical_signed_tsl_xml',
             'original_evaluation_signed_tsl_xml'}
TSL='http://uri.etsi.org/02231/v2#'
DS='http://www.w3.org/2000/09/xmldsig#'
XADES='http://uri.etsi.org/01903/v1.3.2#'
EXC='http://www.w3.org/2001/10/xml-exc-c14n#'
ENV='http://www.w3.org/2000/09/xmldsig#enveloped-signature'
SHA256_URI='http://www.w3.org/2001/04/xmlenc#sha256'
RSA_SHA256='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
ECDSA_SHA256='http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256'
EU_GENERIC='http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric'
GRANTED='http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted'
SVC_TYPES={
    'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
    'http://uri.etsi.org/TrstSvc/Svctype/CA/PKC',
}
MAX_BUNDLE=160_000
MAX_ROSTER=30_000
MAX_CERT=40_000
MAX_XML=12_000_000
MAX_XML_NODES=140_000
IDENT=re.compile(r'[A-Za-z][A-Za-z0-9_.:-]{0,100}\Z')
TERRITORY=re.compile(r'[A-Z]{2}\Z')
SHA=re.compile(r'[0-9a-f]{64}\Z')


def need(ok,code,status='invalid_input'):
    if ok is not True:
        raise errors.AnchorError('EC409_'+code,status)


def exact(value,fields,code):
    need(type(value) is dict and set(value)==fields,
         code+'_EXACT_FIELDS_REQUIRED','permission_denied')


def sha(raw):return hashlib.sha256(raw).hexdigest()
def cdigest(obj):return parent.cdigest(obj)
def ref(obj):return parent.ref(obj)
def good_sha(obj):return type(obj) is str and SHA.fullmatch(obj) is not None and obj!='0'*64


def _inputs(opts,deriving):
    expected=set((*PARENT_SCALARS,*PARENT_REPEATS,*NEW_SCALARS,*REPEAT_NAMES))
    if not deriving:expected.update(AUDIT_ONLY)
    need(set(opts)==expected,'COMPLETE_EC408_AND_NEW_TSL_ARGUMENTS_REQUIRED')
    inherited={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    parent._inputs(inherited,False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                           'EC409_SIGNED_TSL_ORIGINAL_BUNDLE')
    for k in (*NEW_SCALARS[2:], *(() if deriving else AUDIT_ONLY)):
        need(good_sha(opts[k]),'EXTERNAL_TSL_SOURCE_SHA_PIN_REQUIRED')
    need(len({opts[k] for k in NEW_SCALARS[2:]})==7,
         'SEVEN_INDEPENDENT_ROSTER_CERTIFICATE_AND_FIRST_TSL_PINS_REQUIRED',
         'permission_denied')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'ONE_TO_THREE_EPOCHS_REQUIRED')
    for k in REPEAT_NAMES:
        vals=opts[k]
        need(type(vals) is list and len(vals)==n,
             'PER_EPOCH_ORIGINAL_SHA_AND_JOINT_FLOOR_REQUIRED')
        if k.startswith('minimum_'):
            need(all(type(v) is int and 0<=v<=2 for v in vals),
                 'TWO_ROLE_JOINT_FLOOR_INVALID')
        else:
            need(all(good_sha(v) for v in vals),'EPOCH_TSL_SHA_INVALID')
    return inherited


def _parent_report(report,opts):
    fields={'schema','command','status','exit_code','offline_unresolved_exit_code',
            'verified_live_ec407_report_sha256','verified_live_ec407_inventory_sha256',
            'original_institutional_ocsp_bundle_sha256',
            'receiver_verified_institutional_ocsp_inventory_sha256',
            'verified_joint_institutional_ocsp_and_real_parent_publishers',
            'institutional_ocsp_epoch_reviews',
            'bounded_local_signed_ocsp_and_real_ec407_parent_consistency',
            'sender_origin_path_required_or_read',
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
            *parent.FLAGS,*parent.NEGATIVES}
    need(type(report) is dict and set(report)==fields and
         report.get('schema')==parent.RESULT_SCHEMA and
         report.get('command')=='audit-historical-ec339-institutional-ocsp' and
         report.get('exit_code')==report.get('offline_unresolved_exit_code')==2 and
         report.get('original_institutional_ocsp_bundle_sha256')==opts[parent.NEW_SCALARS[1]] and
         report.get('receiver_verified_institutional_ocsp_inventory_sha256')==
              opts[parent.AUDIT_ONLY[0]] and
         all(good_sha(report.get(x)) for x in ('verified_live_ec407_report_sha256',
                      'verified_live_ec407_inventory_sha256')) and
         all(type(report.get(x)) is bool for x in parent.FLAGS) and
         all(report[x] is True for x in parent.FLAGS[-3:]) and
         all(report.get(x) is False for x in parent.NEGATIVES) and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         report.get('bounded_local_signed_ocsp_and_real_ec407_parent_consistency') is
             (not any(report[x] for x in parent.FLAGS[:6])) and
         report.get('status')==next((parent.OUTCOMES[i] for i,x in enumerate(parent.FLAGS)
                                      if report[x]),parent.OUTCOMES[-1])+'_unresolved',
         'UNCHANGED_REAL_EC408_REPORT_NOT_VALID','unavailable')
    fields={'epoch_index','verified_signed_dual_ocsp_pair_count',
            'signed_good_contemporaneous_dual_window_count',
            'joint_real_ec407_parent_and_ocsp_count',
            'institutional_ocsp_epoch_inventory_sha256',
            'real_ec407_parent_joint_cms_count'}
    rows=report.get('institutional_ocsp_epoch_reviews')
    n=len(opts['historical_directory_root_shas'])
    need(type(rows) is list and len(rows)==n and all(
         type(r) is dict and set(r)==fields and
         type(r['epoch_index']) is int and r['epoch_index']==i and
         all(type(r[x]) is int and 0<=r[x]<=2 for x in (
           'verified_signed_dual_ocsp_pair_count',
           'signed_good_contemporaneous_dual_window_count',
           'joint_real_ec407_parent_and_ocsp_count',
           'real_ec407_parent_joint_cms_count')) and
         r['signed_good_contemporaneous_dual_window_count']<=r['verified_signed_dual_ocsp_pair_count'] and
         r['joint_real_ec407_parent_and_ocsp_count']<=r['signed_good_contemporaneous_dual_window_count'] and
         r['joint_real_ec407_parent_and_ocsp_count']<=r['real_ec407_parent_joint_cms_count'] and
         good_sha(r['institutional_ocsp_epoch_inventory_sha256'])
         for i,r in enumerate(rows)) and
         type(report.get('verified_joint_institutional_ocsp_and_real_parent_publishers')) is int and
         report['verified_joint_institutional_ocsp_and_real_parent_publishers']==sum(
               r['joint_real_ec407_parent_and_ocsp_count'] for r in rows),
         'REAL_EC408_OCSP_PARENT_EPOCH_COUNTS_MISMATCH','unavailable')
    return cdigest(report)


def _b64(text,limit,label):
    need(type(text) is str and 0<len(text)<=limit and
         re.fullmatch(r'[A-Za-z0-9+/=\s]+',text) is not None,
         label+'_BASE64_FORMAT','permission_denied')
    compact=''.join(text.split())
    try:raw=base64.b64decode(compact,validate=True)
    except (ValueError,binascii.Error) as exc:
        raise errors.AnchorError('EC409_'+label+'_BASE64_INVALID','permission_denied') from exc
    need(base64.b64encode(raw).decode('ascii')==compact,
         label+'_NONCANONICAL_BASE64','permission_denied')
    return raw


def _one(node,tag,*,required=True):
    matches=node.findall(tag)
    need(len(matches)<=1 and (not required or len(matches)==1),
         'TSL_REQUIRED_SINGLE_CHILD_OR_DUPLICATE_'+tag.rsplit('}',1)[-1].upper(),
         'permission_denied')
    return matches[0] if matches else None


def _text(node,tag,*,required=True):
    x=_one(node,tag,required=required)
    if x is None:return None
    need(len(x)==0 and type(x.text) is str and x.text.strip() and
         x.text==x.text.strip(),
         'TSL_TEXT_ELEMENT_REQUIRED_'+tag.rsplit('}',1)[-1].upper(),
         'permission_denied')
    return x.text


def _utc(value):
    # Delegate to the same strict UTC parser used for actual EC407 CMS claim.
    return cms.utc(value)


def _cert(raw,at):
    need(type(raw) is bytes and 100<len(raw)<=MAX_CERT,
         'TSL_SIGNER_ORIGINAL_DER_SIZE_INVALID','permission_denied')
    try:
        cert=x509.load_der_x509_certificate(raw)
        need(cert.public_bytes(serialization.Encoding.DER)==raw,
             'TSL_SIGNER_CERT_DER_NOT_EXACT','permission_denied')
        ku=cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        need(ku.digital_signature,'TSL_SIGNER_KEY_USAGE_MUST_SIGN','permission_denied')
        need(cert.not_valid_before_utc<=at<=cert.not_valid_after_utc,
             'TSL_SIGNER_CERT_NOT_VALID_AT_ORIGINAL_ISSUE','permission_denied')
        key=cert.public_key()
        need((isinstance(key,rsa.RSAPublicKey) and key.key_size>=2048) or
             (isinstance(key,ec.EllipticCurvePublicKey) and
              isinstance(key.curve,ec.SECP256R1)),
             'TSL_SIGNER_RSA2048_OR_P256_PROFILE_REQUIRED','permission_denied')
        return cert
    except (ValueError,TypeError,x509.ExtensionNotFound,OverflowError) as exc:
        raise errors.AnchorError('EC409_UNSUPPORTED_OR_INVALID_TSL_SIGNER_CERT',
                                 'permission_denied') from exc


def _signed_tsl(original, signer_raw, root_der, territory,service_type,at,read):
    """Verify original XMLDSig bytes and exact listed EC407 root/time status.

    No ID resolver, network URI, detached reference or XSLT/XPath executes.
    Exactly one root enveloped Signature is accepted; any XAdES signed-property
    reference must be explicitly verified, with all signed data inside root.
    """
    raw=read(original,'ec409_original_signed_tsl_xml',MAX_XML)
    need(type(raw) is bytes and 100<len(raw)<=MAX_XML,
         'TL_ORIGINAL_XML_BYTES_INVALID','permission_denied')
    need(not re.search(rb'<!\s*(?:DOCTYPE|ENTITY)\b',raw,re.I),
         'TL_DTD_OR_ENTITY_PROHIBITED','permission_denied')
    try:
        from lxml import etree
        parser=etree.XMLParser(resolve_entities=False,no_network=True,
                               load_dtd=False,huge_tree=False,remove_comments=False)
        root=etree.fromstring(raw,parser=parser)
    except (Exception,) as exc:
        raise errors.AnchorError('EC409_TL_XML_PARSE_INVALID','permission_denied') from exc
    need(root.tag=='{%s}TrustServiceStatusList'%TSL and
         len(root)<=4 and len(list(root.iter()))<=MAX_XML_NODES and
         not any(isinstance(e,(etree._Comment,etree._ProcessingInstruction))
                 for e in root.iter()),
         'TSL_XML_DOCUMENT_ROOT_SIZE_OR_COMMENT_POLICY_INVALID','permission_denied')
    identifier=root.get('Id')
    need(type(identifier) is str and IDENT.fullmatch(identifier) is not None,
         'TSL_ROOT_ID_REQUIRED','permission_denied')
    # Reject alternate ID attributes anywhere in the tree, except one valid
    # SignedProperties ID (verified only if a Reference explicitly targets it).
    sigs=root.xpath('.//ds:Signature',namespaces={'ds':DS})
    need(len(sigs)==1 and sigs[0].getparent() is root,
         'ONE_DIRECT_ENVELOPED_TSL_SIGNATURE_REQUIRED','permission_denied')
    sig=sigs[0]
    need(root[-1] is sig and
         len(root.findall('{%s}SchemeInformation'%TSL))==1 and
         len(root.findall('{%s}TrustServiceProviderList'%TSL))==1,
         'TSL_EXPECTED_SCHEME_PROVIDERS_AND_LAST_SIGNATURE_REQUIRED',
         'permission_denied')
    need({x.tag for x in root}=={'{%s}SchemeInformation'%TSL,
                                 '{%s}TrustServiceProviderList'%TSL,
                                 '{%s}Signature'%DS},
         'TL_ROOT_HAS_UNSUPPORTED_NODES','permission_denied')
    info=_one(sig,'{%s}SignedInfo'%DS)
    canon=_one(info,'{%s}CanonicalizationMethod'%DS)
    sm=_one(info,'{%s}SignatureMethod'%DS)
    need(canon.get('Algorithm')==EXC and len(canon)==0 and len(sm)==0,
         'TL_EXCLUSIVE_CANONICALIZATION_SIGNATURE_ALGORITHM_REQUIRED',
         'permission_denied')
    method=sm.get('Algorithm')
    need(method in (RSA_SHA256,ECDSA_SHA256),
         'TL_SIGNATURE_ALGORITHM_UNSUPPORTED','permission_denied')
    refs=info.findall('{%s}Reference'%DS)
    need(len(refs) in (1,2) and len(info)==2+len(refs),
         'TL_REFERENCE_COUNT_MUST_BE_ONE_ROOT_AND_OPTIONAL_XADES',
         'permission_denied')
    sv=_one(sig,'{%s}SignatureValue'%DS)
    ki=_one(sig,'{%s}KeyInfo'%DS)
    x509data=_one(ki,'{%s}X509Data'%DS)
    need(len(ki)==1 and len(x509data)==1 and
         x509data[0].tag=='{%s}X509Certificate'%DS,
         'TL_EXACT_ONE_EXTERNALLY_PINNED_SIGNER_CERT_IN_KEYINFO',
         'permission_denied')
    need(_b64(x509data[0].text,100000,'SIGNER_KEYINFO')==signer_raw,
         'TL_EMBEDDED_SIGNER_NOT_OUTSIDE_PINNED_DER','permission_denied')
    obj=_one(sig,'{%s}Object'%DS,required=False)
    need(len(sig)==3+(1 if obj is not None else 0),
         'TL_ONLY_SIGNEDINFO_SIGNATUREVALUE_KEYINFO_OPTIONAL_OBJECT',
         'permission_denied')
    signed_props=None
    if obj is not None:
        need(len(obj)==1 and obj[0].tag=='{%s}QualifyingProperties'%XADES and
             obj[0].get('Target') in ('#'+(sig.get('Id') or ''),) and
             type(sig.get('Id')) is str and IDENT.fullmatch(sig.get('Id')) is not None,
             'TL_XADES_OBJECT_TARGET_MUST_BE_OWN_SIGNATURE','permission_denied')
        signed_props=_one(obj[0],'{%s}SignedProperties'%XADES)
        need(len(obj[0])==1 and type(signed_props.get('Id')) is str and
             IDENT.fullmatch(signed_props.get('Id')) is not None,
             'TL_ONLY_ONE_LOCAL_XADES_SIGNED_PROPERTIES_ALLOWED','permission_denied')
    expected_ids={identifier}
    if sig.get('Id'):expected_ids.add(sig.get('Id'))
    if signed_props is not None:expected_ids.add(signed_props.get('Id'))
    ids=[]
    for el in root.iter():
        for k,v in el.attrib.items():
            if k=='Id' or k=='ID' or k=='id' or k.endswith('}Id'):
                need(k=='Id' and v in expected_ids,
                     'TL_AMBIGUOUS_UNVERIFIED_ID_ATTRIBUTE','permission_denied')
                ids.append(v)
    need(len(ids)==len(expected_ids) and set(ids)==expected_ids,
         'TL_ID_COLLISION_OR_UNSIGNED_ID_ALIAS','permission_denied')
    # Exact DSig transforms. Reference to the complete real root is evaluated
    # by removing only the one verified direct Signature from a deep copy.
    digest_target_count=0;properties_count=0
    for r in refs:
        need(set(r.attrib) in ({'URI'},{'URI','Type'}),
             'TL_REFERENCE_UNSUPPORTED_ATTRIBUTES','permission_denied')
        uri=r.get('URI')
        transforms=_one(r,'{%s}Transforms'%DS)
        dm=_one(r,'{%s}DigestMethod'%DS)
        dv=_one(r,'{%s}DigestValue'%DS)
        need(len(r)==3 and dm.get('Algorithm')==SHA256_URI and
             len(dm)==0 and len(dv)==0,
             'TL_ONLY_SHA256_REFERENCE_DIGEST','permission_denied')
        methods=[x.get('Algorithm') for x in transforms]
        need(all(x.tag=='{%s}Transform'%DS and len(x)==0 and
                 set(x.attrib)=={'Algorithm'} for x in transforms),
             'TL_INVALID_TRANSFORM_GRAMMAR','permission_denied')
        if uri in ('','#'+identifier):
            need(digest_target_count==0 and r.get('Type') is None and
                 methods==[ENV,EXC],
                 'TL_EXACT_ENVELOPED_ROOT_REFERENCE_REQUIRED','permission_denied')
            clone=deepcopy(root)
            clone.remove(clone[-1])
            target=etree.tostring(clone,method='c14n',exclusive=True,
                                  with_comments=False)
            digest_target_count+=1
        elif (signed_props is not None and uri=='#'+signed_props.get('Id')):
            need(properties_count==0 and r.get('Type')==
                     'http://uri.etsi.org/01903#SignedProperties' and
                 methods in ([EXC],[]),
                 'TL_XADES_SIGNED_PROPERTIES_REFERENCE_REQUIRED',
                 'permission_denied')
            target=etree.tostring(signed_props,method='c14n',exclusive=True,
                                  with_comments=False)
            properties_count+=1
        else:
            need(False,'TL_DETACHED_UNSAFE_REFERENCE_NOT_SUPPORTED',
                 'permission_denied')
        need(_b64(dv.text,100,'REFERENCE_DIGEST')==hashlib.sha256(target).digest(),
             'TL_ACTUAL_SIGNED_REFERENCE_DIGEST_MISMATCH','permission_denied')
    need(digest_target_count==1 and
         ((signed_props is None and properties_count==0 and len(refs)==1) or
          (signed_props is not None and properties_count==1 and len(refs)==2)),
         'TL_XADES_PROPERTIES_MUST_BE_SIGNED_IF_PRESENT','permission_denied')
    signed_bytes=etree.tostring(info,method='c14n',exclusive=True,
                                with_comments=False)
    signature=_b64(sv.text,12000,'SIGNATURE_VALUE')
    # cryptographic public-key verification with *externally supplied original*
    # DER bytes; unsigned KeyInfo content is never a source of trust itself.
    issue=_utc(_text(_one(root,'{%s}SchemeInformation'%TSL),
                     '{%s}ListIssueDateTime'%TSL))
    cert=_cert(signer_raw,issue)
    key=cert.public_key()
    try:
        if method==RSA_SHA256 and isinstance(key,rsa.RSAPublicKey):
            key.verify(signature,signed_bytes,padding.PKCS1v15(),hashes.SHA256())
        elif method==ECDSA_SHA256 and isinstance(key,ec.EllipticCurvePublicKey):
            need(len(signature)==64,'TL_ECDSA_RAW_RS_SIZE','permission_denied')
            r=int.from_bytes(signature[:32],'big');s=int.from_bytes(signature[32:],'big')
            need(r>0 and s>0,'TL_ECDSA_NONZERO_RS_REQUIRED','permission_denied')
            key.verify(utils.encode_dss_signature(r,s),signed_bytes,
                       ec.ECDSA(hashes.SHA256()))
        else:need(False,'TL_SIGNER_KEY_AND_ALGORITHM_MISMATCH','permission_denied')
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise errors.AnchorError('EC409_TL_INVALID_REAL_XMLDSIG_SIGNATURE',
                                 'permission_denied') from exc
    scheme=_one(root,'{%s}SchemeInformation'%TSL)
    need(_text(scheme,'{%s}TSLType'%TSL)==EU_GENERIC and
         _text(scheme,'{%s}SchemeTerritory'%TSL)==territory,
         'TL_SCHEME_TYPE_OR_TERRITORY_MISMATCH','permission_denied')
    raw_sequence=_text(scheme,'{%s}TSLSequenceNumber'%TSL)
    need(raw_sequence.isdecimal() and len(raw_sequence)<=12 and
         str(int(raw_sequence))==raw_sequence,
         'TL_UNSIGNED_SEQUENCE_NONCANONICAL','permission_denied')
    nextnode=_one(scheme,'{%s}NextUpdate'%TSL)
    nextutc=_utc(_text(nextnode,'{%s}dateTime'%TSL))
    need(issue<nextutc,'TL_ISSUE_NOT_BEFORE_NEXTUPDATE','permission_denied')
    if signed_props is not None:
        signed_signature_props=_one(signed_props,'{%s}SignedSignatureProperties'%XADES)
        claimed_signing_time=_text(signed_signature_props,'{%s}SigningTime'%XADES)
        when=_utc(claimed_signing_time)
        need(issue<=when<nextutc,
             'TL_XADES_CLAIMED_SIGNING_TIME_OUTSIDE_ISSUED_WINDOW',
             'permission_denied')
    # Inventory identity/authorization is bound only to the EXACT original
    # EC407 root DER, not a name match, subject string, or arbitrary new CA.
    plist=_one(root,'{%s}TrustServiceProviderList'%TSL)
    matches=[]
    for provider in plist.findall('{%s}TrustServiceProvider'%TSL):
        services=_one(provider,'{%s}TSPServices'%TSL)
        for svc in services.findall('{%s}TSPService'%TSL):
            service_info=_one(svc,'{%s}ServiceInformation'%TSL)
            typ=_text(service_info,'{%s}ServiceTypeIdentifier'%TSL)
            if typ!=service_type:continue
            identity=_one(service_info,'{%s}ServiceDigitalIdentity'%TSL)
            ids=[x for x in identity.iter('{%s}X509Certificate'%TSL)]
            certbytes=[_b64(x.text,100000,'SERVICE_CERTIFICATE') for x in ids]
            if root_der not in certbytes:continue
            need(certbytes.count(root_der)==1,
                 'TL_DUPLICATE_TARGET_ISSUER_IDENTITY','permission_denied')
            current=(_utc(_text(service_info,'{%s}StatusStartingTime'%TSL)),
                     _text(service_info,'{%s}ServiceStatus'%TSL))
            timeline=[current]
            history=_one(svc,'{%s}ServiceHistory'%TSL,required=False)
            if history is not None:
                for event in history.findall('{%s}ServiceHistoryInstance'%TSL):
                    need(_text(event,'{%s}ServiceTypeIdentifier'%TSL)==service_type,
                         'TL_HISTORY_SERVICE_TYPE_CHANGED','permission_denied')
                    prior_id=_one(event,'{%s}ServiceDigitalIdentity'%TSL)
                    prior_certs=[_b64(x.text,100000,'HISTORY_CERT') for x in
                                 prior_id.iter('{%s}X509Certificate'%TSL)]
                    need(root_der in prior_certs and prior_certs.count(root_der)==1,
                         'TL_HISTORY_EXACT_ISSUER_CERT_REQUIRED','permission_denied')
                    timeline.append((_utc(_text(event,'{%s}StatusStartingTime'%TSL)),
                                     _text(event,'{%s}ServiceStatus'%TSL)))
            need(len(timeline)==len({d for d,_ in timeline}) and
                 all(d<current[0] for d,_ in timeline[1:]),
                 'TL_SERVICE_HISTORY_TIMELINE_AMBIGUOUS','permission_denied')
            active=[(d,status) for d,status in timeline if d<=at]
            status=max(active,key=lambda x:x[0])[1] if active else None
            matches.append({'service_type':typ,'status':status,
                            'status_start_utc':max(active,key=lambda x:x[0])[0].strftime(
                                  '%Y-%m-%dT%H:%M:%SZ') if active else None})
    need(len(matches)==1,'TL_TARGET_EC407_ROOT_MUST_HAVE_EXACT_ONE_TYPED_SERVICE',
         'permission_denied')
    m=matches[0]
    return {'original_signed_tsl_sha256':original['sha256'],
            'original_tsl_signer_der_sha256':sha(signer_raw),
            'tsl_sequence_number':int(raw_sequence),
            'signed_tsl_list_issue_utc':issue.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'signed_tsl_next_update_utc':nextutc.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'matched_real_ec407_issuer_root_der_sha256':sha(root_der),
            'matched_service_type_identifier':service_type,
            'signed_service_status_at_claimed_window':m['status'],
            'signed_status_start_utc':m['status_start_utc'],
            'claimed_snapshot_window_covers_required_time':issue<=at<nextutc,
            'signed_granted_and_in_claimed_window':bool(issue<=at<nextutc and
                                                      m['status']==GRANTED),
            'xmlsig_reference_count':len(refs),
            'xades_signed_properties_verified':signed_props is not None}


def _engine(deriving,**opts):
    inherited=_inputs(opts,deriving)
    live=parent.audit(**inherited)   # PRODUCTION: unchanged REAL EC408->all ancestors
    live_sha=_parent_report(live,opts)
    lineage=opts['claimed_historical_directory_lineage_id']
    n=len(opts['historical_directory_root_shas'])
    read,doc,late=readers._readers()
    new={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    p408={'path':opts[parent.NEW_SCALARS[0]],'sha256':opts[parent.NEW_SCALARS[1]]}
    p407={'path':opts[parent.parent.NEW_SCALARS[0]],
          'sha256':opts[parent.parent.NEW_SCALARS[1]]}
    bundle=doc(new,'ec409_original_signed_tsl_bundle',MAX_BUNDLE)
    exact(bundle,BUNDLE_FIELDS,'ORIGINAL_TSL_BUNDLE')
    need(bundle['schema']==BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id']==lineage and
         bundle['parent_ec408_original_institutional_ocsp_bundle_original']==p408 and
         type(bundle['epochs']) is list and len(bundle['epochs'])==n,
         'TL_BUNDLE_MUST_BIND_ACTUAL_EC408_AND_EPOCHS','permission_denied')
    prior408=doc(p408,'ec409_reopen_original_ec408_dual_window_ocsp_bundle',
                 parent.MAX_BUNDLE)
    exact(prior408,parent.BUNDLE_FIELDS,'REAL_EC408_ORIGINAL')
    need(prior408['schema']==parent.BUNDLE_SCHEMA and
         prior408['claimed_directory_lineage_id']==lineage and
         prior408['parent_ec407_original_institutional_cms_bundle_original']==p407,
         'TL_BUNDLE_ACTUAL_EC408_EC407_CHAIN_MISMATCH','permission_denied')
    prior407=doc(p407,'ec409_reopen_original_ec407_institutional_cms_bundle',
                 cms.MAX_BUNDLE)
    exact(prior407,cms.BUNDLE_FIELDS,'REAL_EC407_ORIGINAL')
    need(prior407['schema']==cms.BUNDLE_SCHEMA and
         prior407['claimed_directory_lineage_id']==lineage and
         type(prior407['epochs']) is list and len(prior407['epochs'])==n,
         'TL_PARENT_EC407_ORIGINAL_LINEAGE_OR_EPOCH_MISMATCH','permission_denied')
    roster407ref=ref(prior407['outside_institutional_certificate_roster_original'])
    need(roster407ref['sha256']==opts[cms.NEW_SCALARS[2]],
         'TL_EC407_SIGNER_ROSTER_NOT_OUTSIDE_PIN','permission_denied')
    roster407=doc(roster407ref,'ec409_reopen_actual_ec407_certificate_roster',
                  cms.MAX_ROSTER)
    used={new['path'],p408['path'],p407['path'],roster407ref['path']}
    for k in PARENT_SCALARS:
        if k.endswith('_file') and type(opts.get(k)) is str:used.add(opts[k])
    # Protect every reference in immediate parent original manifests and their
    # actual original EC407 roster (including signed statement/cert/OCSP files).
    for origin in (prior408,prior407,roster407):
        parent.parent.parent.parent._find_ref_paths(origin,used)
    pair,keys=parent._roles(roster407,opts,read,set())
    roles=sorted(pair)
    need(len(roles)==2,'EXACT_TWO_EC407_ACTUAL_INSTITUTIONAL_ROLES',
         'permission_denied')
    rosterref=ref(bundle['outside_tsl_signer_roster_original'])
    need(rosterref['sha256']==opts[NEW_SCALARS[2]] and rosterref['path'] not in used,
         'TL_OUTSIDE_SIGNER_ROSTER_PIN_OR_PATH_ALIAS','permission_denied')
    used.add(rosterref['path'])
    roster=doc(rosterref,'ec409_reopen_outside_signed_tsl_signer_roster',MAX_ROSTER)
    exact(roster,ROSTER_FIELDS,'ORIGINAL_TSL_SIGNER_ROSTER')
    need(roster['schema']==ROSTER_SCHEMA and
         roster['claimed_directory_lineage_id']==lineage and
         type(roster['assignments']) is list and len(roster['assignments'])==2,
         'TSL_ROSTER_TWO_SIGNER_ASSIGNMENTS_REQUIRED','permission_denied')
    signers={};cert_paths=set();spkis=set()
    for row in roster['assignments']:
        exact(row,ASSIGNMENT_FIELDS,'ORIGINAL_TSL_SIGNER_ASSIGNMENT')
        role=row['publisher_id']
        need(role in pair and role not in signers and
             type(row['scheme_territory']) is str and
             TERRITORY.fullmatch(row['scheme_territory']) is not None and
             row['required_service_type_uri'] in SVC_TYPES,
             'TSL_OUTSIDE_SIGNER_ROLE_TERRITORY_OR_SERVICE_INVALID',
             'permission_denied')
        cr=ref(row['tsl_signer_certificate_original'])
        need(cr['path'] not in used and cr['path'] not in cert_paths,
             'TSL_SIGNER_ORIGINAL_ALIASES_PARENT_OR_OTHER_ORIGINAL',
             'permission_denied')
        used.add(cr['path']);cert_paths.add(cr['path'])
        cert_raw=read(cr,'ec409_original_tsl_signer_der',MAX_CERT)
        # Defer temporal validity to actual signed TL ListIssueDateTime; still
        # insist DER, algorithm and digitalSignature usage at roster intake.
        try:cert=x509.load_der_x509_certificate(cert_raw)
        except ValueError as exc:
            raise errors.AnchorError('EC409_TSL_SIGNER_CERT_DER_INVALID',
                                     'permission_denied') from exc
        need(cert.public_bytes(serialization.Encoding.DER)==cert_raw,
             'TSL_SIGNER_CERT_CANONICAL_DER_REQUIRED','permission_denied')
        spki=cert.public_key().public_bytes(serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)
        need(spki not in keys and spki not in spkis,
             'TSL_SIGNERS_MUST_USE_DISTINCT_EXTERNAL_KEYS_NOT_EC407_ISSUERS',
             'permission_denied')
        spkis.add(spki)
        signers[role]={'raw':cert_raw,'ref':cr,'territory':row['scheme_territory'],
                       'service':row['required_service_type_uri']}
    need(set(signers)==set(roles) and
         [signers[r]['ref']['sha256'] for r in roles]==
         [opts[NEW_SCALARS[3]],opts[NEW_SCALARS[4]]],
         'TSL_TWO_EXACT_OUTSIDE_SIGNER_ORIGINAL_DER_PINS_REQUIRED',
         'permission_denied')
    first={};records=[];reviews=[];total=0;missing=set();prior_versions={}
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=(not live['bounded_local_signed_ocsp_and_real_ec407_parent_consistency'] or
                     any(row['joint_real_ec407_parent_and_ocsp_count']!=2
                         for row in live['institutional_ocsp_epoch_reviews']))
    evalutc=_utc(opts['ec407_institutional_evaluation_utc'])
    used_shas=set()
    for i,epoch in enumerate(bundle['epochs']):
        exact(epoch,EPOCH_FIELDS,'TSL_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==i and
             type(epoch['publishers']) is list and len(epoch['publishers'])==2,
             'TSL_EXACT_TWO_PUBLISHERS_PER_EPOCH','permission_denied')
        old=prior407['epochs'][i]
        exact(old,cms.EPOCH_FIELDS,'REAL_EC407_SIGNED_EPOCH')
        need(old['epoch_index']==i and type(old['publishers']) is list and
             len(old['publishers'])==2,
             'TSL_REAL_EC407_EPOCH_NOT_ALIGNED','permission_denied')
        old_roles={row['publisher_id']:row for row in old['publishers']}
        need(set(old_roles)==set(roles),'TSL_PARENT_REAL_SIGNER_ROLE_MISMATCH',
             'permission_denied')
        new_roles={}
        for entry in epoch['publishers']:
            exact(entry,ROLE_FIELDS,'ORIGINAL_TSL_PUBLISHER')
            role=entry['publisher_id']
            need(type(role) is str and role in pair and role not in new_roles,
                 'TSL_DUPLICATE_OR_UNKNOWN_PUBLISHER_ROLE','permission_denied')
            new_roles[role]=entry
        need(set(new_roles)==set(roles),'TSL_EPOCH_TWO_REAL_ROLES_REQUIRED',
             'permission_denied')
        members=[];verified=0;good=0
        for role in roles:
            entry=new_roles[role]
            oldrow=old_roles[role]
            exact(oldrow,cms.ROLE_FIELDS,'REAL_SIGNED_EC407_ROLE')
            need(oldrow['institutional_signer_id']==pair[role]['id'],
                 'TSL_REAL_EC407_SIGNER_ID_MISMATCH','permission_denied')
            hraw=entry['original_historical_signed_tsl_xml']
            vraw=entry['original_evaluation_signed_tsl_xml']
            if hraw is None or vraw is None:
                need(i>0 and hraw is None and vraw is None,
                     'TSL_FIRST_PAIR_REQUIRED_LATER_PAIR_MUST_NOT_BE_PARTIAL',
                     'permission_denied')
                missing.add(role);flags[FLAGS[2]]=True
                members.append({'publisher_id':role,'original_historical_tsl_sha256':None,
                                'original_evaluation_tsl_sha256':None,
                                'historical_original_tsl_verified':None,
                                'evaluation_original_tsl_verified':None,
                                'signed_granted_at_both_windows':None})
                continue
            need(role not in missing,'TSL_MISSING_ROLE_CANNOT_REAPPEAR',
                 'permission_denied')
            stmtref=ref(oldrow['original_custody_statement'])
            statement=doc(stmtref,'ec409_reopen_actual_signed_ec407_claim',
                          cms.MAX_STATEMENT)
            exact(statement,cms.STATEMENT_FIELDS,'EC407_ACTUAL_SIGNED_CUSTODY_CLAIM')
            need(statement['schema']==cms.STATEMENT_SCHEMA and
                 statement['directory_lineage_id']==lineage and
                 statement['publisher_id']==role and
                 statement['institutional_signer_id']==pair[role]['id'] and
                 statement['epoch_index']==i,
                 'TSL_ORIGINAL_TIME_NOT_FROM_REAL_EC407_SIGNED_CMS',
                 'permission_denied')
            claimed=_utc(statement['claimed_custody_utc'])
            hr=ref(hraw);vr=ref(vraw)
            for r in (hr,vr):
                need(r['path'] not in used and r['sha256'] not in used_shas,
                     'TSL_ORIGINAL_REPLAY_OR_PARENT_PATH_ALIAS','permission_denied')
                used.add(r['path']);used_shas.add(r['sha256'])
            signer=signers[role]
            root_der=pair[role]['root'].public_bytes(serialization.Encoding.DER)
            h=_signed_tsl(hr,signer['raw'],root_der,signer['territory'],
                          signer['service'],claimed,read)
            v=_signed_tsl(vr,signer['raw'],root_der,signer['territory'],
                          signer['service'],evalutc,read)
            need(h['tsl_sequence_number']<=v['tsl_sequence_number'] and
                 h['signed_tsl_list_issue_utc']<=v['signed_tsl_list_issue_utc'],
                 'TSL_HISTORICAL_TO_EVALUATION_SEQUENCE_ROLLBACK',
                 'permission_denied')
            prev=prior_versions.get(role)
            if prev is not None:
                need(prev[0]<=h['tsl_sequence_number'] and
                     prev[1]<=h['signed_tsl_list_issue_utc'] and
                     prev[2]<=v['tsl_sequence_number'] and
                     prev[3]<=v['signed_tsl_list_issue_utc'],
                     'TSL_CROSS_EPOCH_HISTORICAL_OR_EVALUATION_ROLLBACK',
                     'permission_denied')
            prior_versions[role]=(h['tsl_sequence_number'],
                                  h['signed_tsl_list_issue_utc'],
                                  v['tsl_sequence_number'],
                                  v['signed_tsl_list_issue_utc'])
            verified+=1
            is_granted=h['signed_granted_and_in_claimed_window'] and\
                       v['signed_granted_and_in_claimed_window']
            if is_granted:good+=1
            else:flags[FLAGS[3]]=True
            if i==0:first[role]=(hr['sha256'],vr['sha256'])
            members.append({'publisher_id':role,
                            'original_historical_tsl_sha256':hr['sha256'],
                            'original_evaluation_tsl_sha256':vr['sha256'],
                            'historical_original_tsl_verified':h,
                            'evaluation_original_tsl_verified':v,
                            'signed_granted_at_both_windows':bool(is_granted)})
        parent_joint=live['institutional_ocsp_epoch_reviews'][i][
                    'joint_real_ec407_parent_and_ocsp_count']
        joint=good if not flags[FLAGS[0]] and parent_joint==2 else 0
        if joint!=2:flags[FLAGS[4]]=True
        inv={'epoch_index':i,'publishers':members,
             'verified_signed_tsl_dual_window_pair_count':verified,
             'signed_granted_both_window_pair_count':good,
             'joint_actual_ec408_ocsp_and_signed_tsl_count':joint}
        digest=cdigest(inv)
        if digest!=opts[REPEAT_NAMES[0]][i] or joint<opts[REPEAT_NAMES[1]][i]:
            flags[FLAGS[1]]=True
        records.append(inv)
        reviews.append({'epoch_index':i,
                        'verified_signed_tsl_dual_window_pair_count':verified,
                        'signed_granted_both_window_pair_count':good,
                        'joint_actual_ec408_ocsp_and_signed_tsl_count':joint,
                        'signed_tsl_epoch_inventory_sha256':digest,
                        'genuine_ec408_parent_joint_ocsp_count':parent_joint})
        total+=joint
    need(len(first)==2,'FIRST_SIGNED_TSL_ORIGINALS_BOTH_ROLES_REQUIRED',
         'permission_denied')
    pinned=[first[roles[0]][0],first[roles[1]][0],
            first[roles[0]][1],first[roles[1]][1]]
    if pinned!=[opts[k] for k in NEW_SCALARS[5:]]:flags[FLAGS[1]]=True
    inventory={'schema':INVENTORY_SCHEMA,'directory_lineage_id':lineage,
               'verified_genuine_ec408_report_sha256':live_sha,
               'verified_genuine_ec408_inventory_sha256':live[
                   'receiver_verified_institutional_ocsp_inventory_sha256'],
               'ec408_original_ocsp_bundle_sha256':p408['sha256'],
               'ec409_original_signed_tsl_bundle_sha256':new['sha256'],
               'outside_original_tsl_signer_roster_sha256':rosterref['sha256'],
               'original_tsl_signer_certificate_shas':[
                   signers[role]['ref']['sha256'] for role in roles],
               'first_outside_historical_and_evaluation_tsl_original_shas':pinned,
               'ec407_original_evaluation_utc':opts['ec407_institutional_evaluation_utc'],
               'epochs':records}
    invsha=cdigest(inventory)
    if not deriving and invsha!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    for path,(digest,limit) in late.items():
        raw=io._read({'path':path,'sha256':digest},
                     'ec409_final_original_reopen',limit,{},{},set())
        need(sha(raw)==digest,'TL_ORIGINAL_CHANGED_DURING_READBACK',
             'permission_denied')
    for k in FLAGS[-3:]:flags[k]=True
    return {'schema':DERIVE_SCHEMA if deriving else RESULT_SCHEMA,
            'command':('derive-historical-ec339-signed-tsl-inventory' if deriving
                       else 'audit-historical-ec339-signed-tsl'),
            'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                          OUTCOMES[-1])+'_unresolved',
            'exit_code':2,'offline_unresolved_exit_code':2,
            'verified_live_ec408_report_sha256':live_sha,
            'verified_live_ec408_inventory_sha256':live[
                'receiver_verified_institutional_ocsp_inventory_sha256'],
            'original_signed_tsl_bundle_sha256':new['sha256'],
            'receiver_verified_signed_tsl_inventory_sha256':invsha,
            'verified_joint_signed_tsl_and_real_ec408_parent_publishers':total,
            'signed_tsl_epoch_reviews':reviews,
            'bounded_local_signed_tsl_and_real_ec408_parent_consistency':
                 not any(flags[k] for k in FLAGS[:5]),
            'sender_origin_path_required_or_read':False,
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
            **flags,**{k:False for k in NEGATIVES},
            **({'unsigned_signed_tsl_original_inventory':inventory} if deriving else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
