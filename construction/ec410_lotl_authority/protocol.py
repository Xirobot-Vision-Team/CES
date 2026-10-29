#!/usr/bin/env python3
"""EC410 original signed EU LOTL pointer and pinned three-certificate path receiver.

Offline subset, not an EU authority discovery mechanism. Production ALWAYS runs
unchanged real EC409 audit (and its entire genuine older source chain) first.
Trust-anchor ownership, OJEU publication, independent historical availability,
legal qualification and public distribution remain OUTSIDE cryptographic proof.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from copy import deepcopy
from datetime import timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.x509.oid import ExtensionOID
from ec295_delivery_anchor import anchor as errors
from ec372_historical_authority import authority_archive as io
from ec394_registered_witness import registered_witness as readers
from ec407_institutional_cms import protocol as cms
from ec409_trust_list import protocol as parent

RESULT_SCHEMA='ces.ec410.original_signed_lotl_authority_unresolved.v1'
DERIVE_SCHEMA='ces.ec410.unsigned_signed_lotl_inventory_unresolved.v1'
DENIAL_SCHEMA='ces.ec410.signed_lotl_denial.v1'
BUNDLE_SCHEMA='ces.ec410.original_signed_lotl_bundle.v1'
ROSTER_SCHEMA='ces.ec410.outside_pinned_lotl_operator_roster.v1'
INVENTORY_SCHEMA='ces.ec410.unsigned_signed_lotl_authority_inventory.v1'
PARENT_SCALARS=(*parent.PARENT_SCALARS,*parent.NEW_SCALARS,*parent.AUDIT_ONLY)
PARENT_REPEATS=(*parent.PARENT_REPEATS,*parent.REPEAT_NAMES)
NEW_SCALARS=(
    'historical_ec339_signed_lotl_bundle_file',
    'expected_historical_ec339_signed_lotl_bundle_sha256',
    'expected_outside_ec410_lotl_operator_roster_sha256',
    'expected_outside_ec410_lotl_trust_anchor_der_sha256',
    'expected_outside_ec410_lotl_intermediate_ca_der_sha256',
    'expected_outside_ec410_lotl_signer_der_sha256',
    'expected_outside_ec410_first_historical_lotl_xml_sha256',
    'expected_outside_ec410_first_evaluation_lotl_xml_sha256',
)
AUDIT_ONLY=('expected_retained_historical_ec339_signed_lotl_inventory_sha256',)
NEW_REPEATS=(
    ('historical_ec339_signed_lotl_epoch_inventory_shas',
     '--historical-ec339-signed-lotl-epoch-inventory-sha256'),
    ('minimum_historical_ec339_joint_signed_lotl_publisher_counts',
     '--minimum-historical-ec339-joint-signed-lotl-publisher-count'),
)
REPEAT_NAMES=tuple(x for x,_ in NEW_REPEATS)
FLAGS=(
    'real_ec409_and_all_older_original_ancestry_adverse',
    'outside_lotl_chain_first_epoch_or_whole_inventory_pin_disagrees',
    'one_or_more_later_original_signed_lotl_windows_missing',
    'signed_lotl_pointer_identity_or_historical_time_window_incomplete',
    'signed_lotl_pointer_and_real_ec409_tsl_parent_joint_coverage_incomplete',
    'independent_official_lotl_trust_anchor_and_operator_provenance_not_proven',
    'original_historical_public_lotl_distribution_and_qualified_time_not_proven',
    'full_unmocked_external_ancestry_worm_native_and_final_acceptance_not_proven',
)
OUTCOMES=(
    'ec410_real_ec409_and_older_parent_origins_disputed',
    'ec410_original_lotl_chain_or_inventory_pins_disagree',
    'ec410_later_original_signed_lotl_windows_missing',
    'ec410_signed_lotl_national_pointer_or_window_unresolved',
    'ec410_signed_lotl_and_real_ec409_joint_coverage_incomplete',
    'ec410_independent_official_lotl_authority_not_authenticated',
    'ec410_historical_public_distribution_and_qualified_time_not_proven',
    'ec410_full_external_ancestry_and_acceptance_not_proven',
)
NEGATIVES=(
    'out_of_band_trust_anchor_sha_alone_authenticates_an_official_eu_lotl_operator',
    'locally_signed_lotl_or_certificate_path_establishes_official_ojeu_publication',
    'signed_tsl_location_https_uri_proves_network_delivery_or_public_availability',
    'signed_lotl_pointer_automatically_qualifies_institutional_services',
    'locally_signed_issuance_dates_are_independent_qualified_timestamps',
    'limited_enveloped_xmlsig_subprofile_covers_all_real_etsi_lotl_revisions',
    'trusted_list_child_retroactively_repairs_adverse_real_ec409_parent',
    'externally_supplied_root_is_automatically_a_government_or_commission_root',
    'receiver_downloaded_lotl_or_executed_external_xml_references',
    'receiver_generated_certificates_keys_signatures_or_original_business_writes',
    'receiver_performed_full_unmocked_external_ancestry_or_final_acceptance',
)
BUNDLE_FIELDS={'schema','claimed_directory_lineage_id',
               'parent_ec409_original_signed_tsl_bundle_original',
               'outside_lotl_operator_roster_original','epochs'}
ROSTER_FIELDS={'schema','claimed_directory_lineage_id',
               'lotl_trust_anchor_certificate_original',
               'lotl_intermediate_ca_certificate_original',
               'lotl_signer_certificate_original',
               'expected_lotl_distribution_https_uri','assignments'}
ASSIGNMENT_FIELDS={'publisher_id','scheme_territory',
                   'expected_national_tsl_location_https_uri'}
EPOCH_FIELDS={'epoch_index','original_historical_signed_lotl_xml',
              'original_evaluation_signed_lotl_xml'}
TSL=parent.TSL; DS=parent.DS; XADES=parent.XADES; EXC=parent.EXC
ENV=parent.ENV; SHA256_URI=parent.SHA256_URI
RSA_SHA256=parent.RSA_SHA256; ECDSA_SHA256=parent.ECDSA_SHA256
LOTL_TYPE='http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists'
EU_GENERIC=parent.EU_GENERIC
MAX_BUNDLE=135_000; MAX_ROSTER=32_000; MAX_XML=12_000_000
MAX_CERT=40_000; MAX_NODES=180_000
SHA=re.compile(r'[0-9a-f]{64}\Z')
IDENT=parent.IDENT
TERRITORY=parent.TERRITORY
TAG=lambda name:'{%s}%s'%(TSL,name)
DSTAG=lambda name:'{%s}%s'%(DS,name)
XTAG=lambda name:'{%s}%s'%(XADES,name)


def need(test,code,status='invalid_input'):
    if test is not True:
        raise errors.AnchorError('EC410_'+code,status)


def exact(obj,fields,label):
    need(type(obj) is dict and set(obj)==fields,
         label+'_EXACT_FIELDS_REQUIRED','permission_denied')


def good_sha(value):return type(value) is str and SHA.fullmatch(value) is not None and value!='0'*64

def sha(value):return hashlib.sha256(value).hexdigest()

def digest(obj):return parent.cdigest(obj)

def ref(obj):return parent.ref(obj)

def utc(s):return cms.utc(s)


def _source_url(value):
    need(type(value) is str and 13<=len(value)<=1024 and
         not any(ord(c)<33 or ord(c)>126 for c in value),
         'SIGNED_HTTPS_DISTRIBUTION_URI_FORMAT','permission_denied')
    try:
        p=urlsplit(value)
        hostname=p.hostname
        port=p.port
    except ValueError as exc:
        raise errors.AnchorError(
            'EC410_SIGNED_HTTPS_DISTRIBUTION_URI_INVALID',
            'permission_denied') from exc
    need(p.scheme=='https' and p.netloc and hostname and not p.username and
         not p.password and port in (None,443) and not p.fragment and
         p.path.startswith('/') and not p.query and not p.path.startswith('//') and
         '\\' not in value and '%' not in value and
         all(x not in ('.','..') for x in p.path.split('/')) and
         hostname==hostname.lower() and value==p.geturl(),
         'SIGNED_HTTPS_DISTRIBUTION_URI_MUST_BE_CANONICAL','permission_denied')
    try:ipaddress.ip_address(hostname)
    except ValueError:pass
    else:need(False,'LOTL_DISTRIBUTION_IP_LITERAL_NOT_ALLOWED','permission_denied')
    need('.' in hostname and re.fullmatch(r'[a-z0-9.-]+',hostname) is not None and
         all(z and not z.startswith('-') and not z.endswith('-') for z in hostname.split('.')),
         'SIGNED_HTTPS_HOSTNAME_INVALID','permission_denied')
    return value


def _inputs(opts,deriving):
    expected=set((*PARENT_SCALARS,*PARENT_REPEATS,*NEW_SCALARS,*REPEAT_NAMES))
    if not deriving:expected.update(AUDIT_ONLY)
    need(set(opts)==expected,'COMPLETE_UNMODIFIED_EC409_AND_LOTL_ARGUMENTS_REQUIRED')
    old={k:opts[k] for k in (*PARENT_SCALARS,*PARENT_REPEATS)}
    parent._inputs(old,False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]],opts[NEW_SCALARS[1]],
                           'EC410_SIGNED_LOTL_ORIGINAL_BUNDLE')
    for k in (*NEW_SCALARS[2:],*(() if deriving else AUDIT_ONLY)):
        need(good_sha(opts[k]),'OUTSIDE_LOTL_ORIGINAL_SHA_PIN_REQUIRED')
    need(len({opts[k] for k in NEW_SCALARS[2:]})==6,
         'SIX_INDEPENDENT_ROSTER_CERTIFICATE_AND_FIRST_LOTL_PINS_REQUIRED',
         'permission_denied')
    n=len(opts['historical_directory_root_shas'])
    need(1<=n<=3,'ONE_TO_THREE_EPOCHS_REQUIRED')
    for k in REPEAT_NAMES:
        v=opts[k]
        need(type(v) is list and len(v)==n,'LOTL_PER_EPOCH_PIN_AND_FLOOR_REQUIRED')
        if k.startswith('minimum_'):
            need(all(type(x) is int and 0<=x<=2 for x in v),
                 'TWO_ROLE_LOTL_FLOOR_INVALID')
        else:
            need(all(good_sha(x) for x in v),'LOTL_EPOCH_OUTSIDE_SHA_INVALID')
    return old


def _parent_report(report,opts):
    common={'schema','command','status','exit_code','offline_unresolved_exit_code',
            'verified_live_ec408_report_sha256','verified_live_ec408_inventory_sha256',
            'original_signed_tsl_bundle_sha256',
            'receiver_verified_signed_tsl_inventory_sha256',
            'verified_joint_signed_tsl_and_real_ec408_parent_publishers',
            'signed_tsl_epoch_reviews',
            'bounded_local_signed_tsl_and_real_ec408_parent_consistency',
            'sender_origin_path_required_or_read',
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
            *parent.FLAGS,*parent.NEGATIVES}
    need(type(report) is dict and set(report)==common and
         report.get('schema')==parent.RESULT_SCHEMA and
         report.get('command')=='audit-historical-ec339-signed-tsl' and
         report.get('exit_code')==report.get('offline_unresolved_exit_code')==2 and
         report.get('original_signed_tsl_bundle_sha256')==opts[parent.NEW_SCALARS[1]] and
         report.get('receiver_verified_signed_tsl_inventory_sha256')==opts[parent.AUDIT_ONLY[0]] and
         all(good_sha(report.get(k)) for k in ('verified_live_ec408_report_sha256',
                             'verified_live_ec408_inventory_sha256')) and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report[k] is True for k in parent.FLAGS[-3:]) and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         report.get('bounded_local_signed_tsl_and_real_ec408_parent_consistency') is
           (not any(report[k] for k in parent.FLAGS[:5])) and
         report.get('status')==next((parent.OUTCOMES[i] for i,k in enumerate(parent.FLAGS)
                          if report[k]),parent.OUTCOMES[-1])+'_unresolved',
         'UNCHANGED_REAL_EC409_PARENT_REPORT_INVALID','unavailable')
    fields={'epoch_index','verified_signed_tsl_dual_window_pair_count',
            'signed_granted_both_window_pair_count',
            'joint_actual_ec408_ocsp_and_signed_tsl_count',
            'signed_tsl_epoch_inventory_sha256','genuine_ec408_parent_joint_ocsp_count'}
    rows=report.get('signed_tsl_epoch_reviews')
    n=len(opts['historical_directory_root_shas'])
    need(type(rows) is list and len(rows)==n and all(
         type(r) is dict and set(r)==fields and
         type(r['epoch_index']) is int and r['epoch_index']==i and
         all(type(r[k]) is int and 0<=r[k]<=2 for k in (
            'verified_signed_tsl_dual_window_pair_count',
            'signed_granted_both_window_pair_count',
            'joint_actual_ec408_ocsp_and_signed_tsl_count',
            'genuine_ec408_parent_joint_ocsp_count')) and
         r['joint_actual_ec408_ocsp_and_signed_tsl_count']<=
            r['signed_granted_both_window_pair_count']<=
            r['verified_signed_tsl_dual_window_pair_count'] and
         r['joint_actual_ec408_ocsp_and_signed_tsl_count']<=
            r['genuine_ec408_parent_joint_ocsp_count'] and
         good_sha(r['signed_tsl_epoch_inventory_sha256'])
         for i,r in enumerate(rows)) and
         type(report.get('verified_joint_signed_tsl_and_real_ec408_parent_publishers')) is int and
         report['verified_joint_signed_tsl_and_real_ec408_parent_publishers']==sum(
             r['joint_actual_ec408_ocsp_and_signed_tsl_count'] for r in rows),
         'EC409_REAL_PARENT_EPOCH_COUNTS_NOT_CONSISTENT','unavailable')
    return digest(report)


def _key_spki(key):
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def _cert(raw,label):
    need(type(raw) is bytes and 100<len(raw)<=MAX_CERT,
         label+'_ORIGINAL_DER_SIZE','permission_denied')
    try:
        cert=x509.load_der_x509_certificate(raw)
        need(cert.public_bytes(serialization.Encoding.DER)==raw,
             label+'_CERTIFICATE_NOT_CANONICAL_DER','permission_denied')
        return cert
    except (ValueError,TypeError) as exc:
        raise errors.AnchorError('EC410_'+label+'_X509_ORIGINAL_DER_INVALID',
                                 'permission_denied') from exc


def _ext(cert,oid,label):
    try:return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound as exc:
        raise errors.AnchorError('EC410_'+label+'_MANDATORY_EXTENSION_MISSING',
                                 'permission_denied') from exc


def _public_key_allowed(key):
    need((isinstance(key,rsa.RSAPublicKey) and key.key_size>=2048) or
         (isinstance(key,ec.EllipticCurvePublicKey) and
          isinstance(key.curve,ec.SECP256R1)),
         'LOTL_CERTIFICATE_PUBLIC_KEY_NOT_RSA2048_OR_P256','permission_denied')


def _verify_certificate_signature(child,issuer,label):
    need(child.issuer==issuer.subject,label+'_ISSUER_NAME_MISMATCH',
         'permission_denied')
    key=issuer.public_key();_public_key_allowed(key)
    try:
        if isinstance(key,rsa.RSAPublicKey):
            need(child.signature_algorithm_oid==x509.SignatureAlgorithmOID.RSA_WITH_SHA256,
                 label+'_ONLY_RSA_SHA256_PKCS1_CERT_SIGNATURE_SUPPORTED',
                 'permission_denied')
            key.verify(child.signature,child.tbs_certificate_bytes,
                       padding.PKCS1v15(),hashes.SHA256())
        else:
            need(child.signature_algorithm_oid==x509.SignatureAlgorithmOID.ECDSA_WITH_SHA256,
                 label+'_ONLY_ECDSA_SHA256_CERT_SIGNATURE_SUPPORTED',
                 'permission_denied')
            key.verify(child.signature,child.tbs_certificate_bytes,
                       ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise errors.AnchorError('EC410_'+label+'_REAL_ISSUER_SIGNATURE_INVALID',
                                 'permission_denied') from exc
    # If the extensions exist, they must positively bind the actual issuer key.
    try:aki=child.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
    except x509.ExtensionNotFound:aki=None
    try:ski=issuer.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
    except x509.ExtensionNotFound:ski=None
    if aki is not None and aki.key_identifier is not None:
        need(ski is not None and aki.key_identifier==ski.digest,
             label+'_AUTHORITY_KEY_IDENTIFIER_MISMATCH','permission_denied')
    if aki is not None and aki.authority_cert_serial_number is not None:
        need(aki.authority_cert_serial_number==issuer.serial_number,
             label+'_AUTHORITY_CERT_SERIAL_MISMATCH','permission_denied')


def _chain(raws,windows):
    """Verify a *pinned* root -> intermediate -> LOTL signer, no trust discovery."""
    root,mid,leaf=(_cert(raws[k],k.upper()) for k in ('root','mid','signer'))
    keys=[_key_spki(cert.public_key()) for cert in (root,mid,leaf)]
    need(len(set(keys))==3,'LOTL_CERTIFICATION_PATH_KEYS_MUST_BE_DISTINCT',
         'permission_denied')
    for name,cert in (('ROOT',root),('INTERMEDIATE',mid),('SIGNER',leaf)):
        _public_key_allowed(cert.public_key())
        allowed={ExtensionOID.BASIC_CONSTRAINTS,ExtensionOID.KEY_USAGE,
                 ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                 ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                 ExtensionOID.EXTENDED_KEY_USAGE,ExtensionOID.CERTIFICATE_POLICIES}
        need(all(not e.critical or e.oid in allowed for e in cert.extensions),
             name+'_UNSUPPORTED_CRITICAL_CERTIFICATE_EXTENSION',
             'permission_denied')
        for at in windows:
            need(cert.not_valid_before_utc<=at<=cert.not_valid_after_utc,
                 name+'_CERTIFICATE_NOT_VALID_AT_SOURCE_WINDOW',
                 'permission_denied')
        constraints=_ext(cert,ExtensionOID.BASIC_CONSTRAINTS,name)
        ku=_ext(cert,ExtensionOID.KEY_USAGE,name)
        if name in ('ROOT','INTERMEDIATE'):
            need(constraints.ca and ku.key_cert_sign and
                 (name!='ROOT' or constraints.path_length is None or
                  constraints.path_length>=1),
                 name+'_CA_KEY_USAGE_OR_PATH_LENGTH_INVALID',
                 'permission_denied')
        else:
            need(not constraints.ca and ku.digital_signature and not ku.key_cert_sign,
                 'LOTL_END_ENTITY_MUST_HAVE_DIGITAL_SIGNATURE_NOT_CA',
                 'permission_denied')
    need(root.issuer==root.subject,'LOTL_ROOT_MUST_BE_SELF_ISSUED',
         'permission_denied')
    _verify_certificate_signature(root,root,'LOTL_ROOT_SELF_SIGNED')
    _verify_certificate_signature(mid,root,'LOTL_INTERMEDIATE_SIGNED')
    _verify_certificate_signature(leaf,mid,'LOTL_SIGNER_SIGNED')
    return {'root':root,'mid':mid,'signer':leaf,'keys':keys}


def _one(node,tag,required=True):
    matches=node.findall(tag)
    need(len(matches)<=1 and (not required or len(matches)==1),
         'LOTL_EXACT_ONE_CHILD_'+tag.rsplit('}',1)[-1].upper(),
         'permission_denied')
    return matches[0] if matches else None


def _text(node,tag):
    x=_one(node,tag)
    need(len(x)==0 and type(x.text) is str and bool(x.text.strip()) and
         x.text==x.text.strip(),
         'LOTL_SIGNED_TEXT_INVALID_'+tag.rsplit('}',1)[-1].upper(),
         'permission_denied')
    return x.text


def _b64(s,label,cap=100000):
    return parent._b64(s,cap,label)


def _verify_lotl(refobj,raw_signer,chain,assignments,required_times,
                 expected_lotl_location,read):
    """Bounded real ETSI-shaped EU list-of-lists with root XMLDSig and pointers."""
    raw=read(refobj,'ec410_original_signed_lotl_xml',MAX_XML)
    need(type(raw) is bytes and 100<len(raw)<=MAX_XML and
         re.search(rb'<!\s*(?:DOCTYPE|ENTITY)\b',raw,re.I) is None,
         'SIGNED_LOTL_ORIGINAL_SIZE_DTD_OR_ENTITY_INVALID','permission_denied')
    try:
        from lxml import etree
        parser=etree.XMLParser(resolve_entities=False,load_dtd=False,no_network=True,
                               huge_tree=False,remove_comments=False)
        root=etree.fromstring(raw,parser=parser)
    except Exception as exc:
        raise errors.AnchorError('EC410_SIGNED_LOTL_ORIGINAL_XML_PARSE_INVALID',
                                 'permission_denied') from exc
    need(root.tag==TAG('TrustServiceStatusList') and
         not root.getroottree().docinfo.doctype and
         len(list(root.iter()))<=MAX_NODES and len(root)<=3 and
         not any(isinstance(e,(etree._Comment,etree._ProcessingInstruction))
                 for e in root.iter()),
         'LOTL_ROOT_TYPE_NODE_BOUND_OR_DTD_REJECTED','permission_denied')
    identifier=root.get('Id')
    need(type(identifier) is str and IDENT.fullmatch(identifier) is not None,
         'LOTL_ROOT_ID_MISSING','permission_denied')
    sigs=root.xpath('.//ds:Signature',namespaces={'ds':DS})
    need(len(sigs)==1 and sigs[0].getparent() is root and root[-1] is sigs[0],
         'ONE_DIRECT_LAST_ENVELOPED_LOTL_XML_SIGNATURE_REQUIRED',
         'permission_denied')
    sig=sigs[0]
    need({x.tag for x in root} in (
          {TAG('SchemeInformation'),DSTAG('Signature')},
          {TAG('SchemeInformation'),TAG('TrustServiceProviderList'),DSTAG('Signature')}),
         'LOTL_UNSIGNED_ROOT_CONTENT_OR_DUPLICATE_STRUCTURE','permission_denied')
    scheme=_one(root,TAG('SchemeInformation'))
    need(_text(scheme,TAG('TSLType'))==LOTL_TYPE and
         _text(scheme,TAG('SchemeTerritory'))=='EU',
         'SIGNED_LOTL_TYPE_EU_TERRITORY_REQUIRED','permission_denied')
    issue=utc(_text(scheme,TAG('ListIssueDateTime')))
    nextutc=utc(_text(_one(scheme,TAG('NextUpdate')),TAG('dateTime')))
    need(issue<nextutc,'SIGNED_LOTL_ISSUE_NEXTUPDATE_ORDER','permission_denied')
    sequence=_text(scheme,TAG('TSLSequenceNumber'))
    need(sequence.isdecimal() and len(sequence)<=12 and str(int(sequence))==sequence,
         'SIGNED_LOTL_NONCANONICAL_SEQUENCE','permission_denied')
    for cert in (chain['root'],chain['mid'],chain['signer']):
        need(cert.not_valid_before_utc<=issue<=cert.not_valid_after_utc,
             'SIGNED_LOTL_CERTIFICATION_PATH_NOT_VALID_AT_ISSUE',
             'permission_denied')
    info=_one(sig,DSTAG('SignedInfo'))
    canon=_one(info,DSTAG('CanonicalizationMethod'))
    method=_one(info,DSTAG('SignatureMethod'))
    need(canon.get('Algorithm')==EXC and len(canon)==len(method)==0,
         'LOTL_EXCLUSIVE_SIGNEDINFO_CANONICALIZATION_REQUIRED',
         'permission_denied')
    algorithm=method.get('Algorithm')
    key=chain['signer'].public_key()
    need((algorithm==RSA_SHA256 and isinstance(key,rsa.RSAPublicKey)) or
         (algorithm==ECDSA_SHA256 and isinstance(key,ec.EllipticCurvePublicKey)),
         'LOTL_XML_SIGNATURE_ALGORITHM_AND_PINNED_SIGNER_MISMATCH',
         'permission_denied')
    refs=info.findall(DSTAG('Reference'))
    need(len(refs) in (1,2) and len(info)==2+len(refs),
         'LOTL_ROOT_AND_OPTIONAL_XADES_REFERENCE_ONLY','permission_denied')
    sv=_one(sig,DSTAG('SignatureValue'))
    ki=_one(sig,DSTAG('KeyInfo'))
    data=_one(ki,DSTAG('X509Data'))
    need(len(ki)==len(data)==1 and data[0].tag==DSTAG('X509Certificate') and
         _b64(data[0].text,'EC410_LOTL_SIGNER_KEYINFO')==raw_signer,
         'LOTL_KEYINFO_MUST_MATCH_EXACT_OUTSIDE_ORIGINAL_DER',
         'permission_denied')
    obj=_one(sig,DSTAG('Object'),False)
    need(len(sig)==3+(obj is not None),
         'LOTL_SIGNEDINFO_SIGNATURE_KEYINFO_OPTIONAL_XADES_ONLY',
         'permission_denied')
    props=None
    if obj is not None:
        sid=sig.get('Id')
        need(type(sid) is str and IDENT.fullmatch(sid) is not None and
             len(obj)==1 and obj[0].tag==XTAG('QualifyingProperties') and
             obj[0].get('Target')=='#'+sid,
             'LOTL_XADES_OBJECT_SIGNATURE_ID_MISMATCH','permission_denied')
        props=_one(obj[0],XTAG('SignedProperties'))
        need(len(obj[0])==1 and type(props.get('Id')) is str and
             IDENT.fullmatch(props.get('Id')) is not None,
             'LOTL_ONLY_ONE_SIGNED_PROPERTIES_ALLOWED','permission_denied')
    identifiers={identifier}
    if sig.get('Id') is not None:identifiers.add(sig.get('Id'))
    if props is not None:identifiers.add(props.get('Id'))
    ids=[]
    for el in root.iter():
        for attr,val in el.attrib.items():
            if attr in ('Id','ID','id') or attr.endswith('}Id'):
                need(attr=='Id' and val in identifiers,
                     'LOTL_UNSIGNED_OR_AMBIGUOUS_ID_ATTRIBUTE',
                     'permission_denied')
                ids.append(val)
    need(len(ids)==len(identifiers) and set(ids)==identifiers,
         'LOTL_ID_WRAPPING_DUPLICATE_OR_UNVERIFIED_ID','permission_denied')
    seen_root=0;seen_props=0
    for r in refs:
        need(set(r.attrib) in ({'URI'},{'URI','Type'}) and len(r)==3,
             'LOTL_REFERENCE_EXACT_GRAMMAR_REQUIRED','permission_denied')
        uri=r.get('URI')
        transforms=_one(r,DSTAG('Transforms'))
        dm=_one(r,DSTAG('DigestMethod'))
        dv=_one(r,DSTAG('DigestValue'))
        need(len(dm)==len(dv)==0 and dm.get('Algorithm')==SHA256_URI and
             all(x.tag==DSTAG('Transform') and len(x)==0 and
                 set(x.attrib)=={'Algorithm'} for x in transforms),
             'LOTL_SHA256_TRANSFORMS_GRAMMAR_REQUIRED','permission_denied')
        methods=[x.get('Algorithm') for x in transforms]
        if uri in ('','#'+identifier):
            need(seen_root==0 and r.get('Type') is None and methods==[ENV,EXC],
                 'LOTL_ONLY_ENVELOPED_C14N_ROOT_REFERENCE',
                 'permission_denied')
            clone=deepcopy(root);clone.remove(clone[-1]);seen_root+=1
            canonical=etree.tostring(clone,method='c14n',exclusive=True,
                                     with_comments=False)
        elif props is not None and uri=='#'+props.get('Id'):
            need(seen_props==0 and
                 r.get('Type')=='http://uri.etsi.org/01903#SignedProperties' and
                 methods in ([],[EXC]),
                 'LOTL_XADES_SIGNED_PROPERTIES_REFERENCE_REQUIRED',
                 'permission_denied')
            canonical=etree.tostring(props,method='c14n',exclusive=True,
                                     with_comments=False)
            seen_props+=1
        else:need(False,'LOTL_EXTERNAL_OR_DETACHED_XML_REFERENCE_REJECTED',
                  'permission_denied')
        need(_b64(dv.text,'EC410_LOTL_REFERENCE_DIGEST',100)==
             hashlib.sha256(canonical).digest(),
             'LOTL_REAL_SIGNED_REFERENCE_DIGEST_INVALID','permission_denied')
    need(seen_root==1 and seen_props==(1 if props is not None else 0) and
         len(refs)==1+seen_props,
         'LOTL_XADES_MUST_BE_EXPLICITLY_SHA256_SIGNED','permission_denied')
    if props is not None:
        t=utc(_text(_one(props,XTAG('SignedSignatureProperties')),
                    XTAG('SigningTime')))
        need(issue<=t<nextutc,'LOTL_XADES_SIGNING_TIME_OUTSIDE_LIST_WINDOW',
             'permission_denied')
    signature=_b64(sv.text,'EC410_LOTL_SIGNATURE_VALUE',12000)
    signedinfo=etree.tostring(info,method='c14n',exclusive=True,
                             with_comments=False)
    try:
        if algorithm==RSA_SHA256:
            key.verify(signature,signedinfo,padding.PKCS1v15(),hashes.SHA256())
        else:
            need(len(signature)==64,'LOTL_ECDSA_P256_RAW_RS_SIZE','permission_denied')
            rn=int.from_bytes(signature[:32],'big')
            sn=int.from_bytes(signature[32:],'big')
            need(rn>0 and sn>0,'LOTL_ECDSA_RS_MUST_BE_NONZERO','permission_denied')
            key.verify(utils.encode_dss_signature(rn,sn),signedinfo,
                       ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise errors.AnchorError('EC410_ACTUAL_ORIGINAL_LOTL_XML_SIGNATURE_INVALID',
                                 'permission_denied') from exc
    pointers=_one(scheme,TAG('PointersToOtherTSL'))
    entries=pointers.findall(TAG('OtherTSLPointer'))
    need(3<=len(entries)<=45 and len(pointers)==len(entries),
         'SIGNED_LOTL_POINTERS_BOUNDED_EU_SUBPROFILE_REQUIRED',
         'permission_denied')
    observed={r:[] for r in assignments}
    observed_self=[]
    # The entire pointer section is authenticated by the root XML signature.
    for pointer in entries:
        territory=None;listed_type=None
        additional=_one(pointer,TAG('AdditionalInformation'))
        for info in additional.findall(TAG('OtherInformation')):
            for child in info.iter():
                if child.tag==TAG('SchemeTerritory'):
                    need(territory is None,'LOTL_DUPLICATE_POINTER_TERRITORY',
                         'permission_denied')
                    territory=child.text
                if child.tag==TAG('TSLType'):
                    need(listed_type is None,'LOTL_DUPLICATE_POINTER_TYPE',
                         'permission_denied')
                    listed_type=child.text
        if territory not in ('EU',*[x['scheme_territory'] for x in assignments.values()]):
            continue
        loc=_source_url(_text(pointer,TAG('TSLLocation')))
        identities=_one(pointer,TAG('ServiceDigitalIdentities'))
        certs=[]
        for identity in identities.findall(TAG('ServiceDigitalIdentity')):
            digital=_one(identity,TAG('DigitalId'))
            for el in digital.findall(TAG('X509Certificate')):
                certs.append(_b64(el.text,'EC410_LOTL_POINTER_CERT'))
        need(bool(certs),'LOTL_POINTER_SIGNER_IDENTITY_MISSING',
             'permission_denied')
        if territory=='EU':
            need(listed_type==LOTL_TYPE and loc==expected_lotl_location and
                 certs.count(raw_signer)==1 and len(certs)==1,
                 'LOTL_SIGNED_SELF_DISTRIBUTION_LOCATION_AND_OPERATOR_CERT_MISMATCH',
                 'permission_denied')
            observed_self.append(loc)
            continue
        for role,assigned in assignments.items():
            if territory!=assigned['scheme_territory']:continue
            need(listed_type==EU_GENERIC and
                 loc==assigned['expected_national_tsl_location_https_uri'] and
                 certs.count(assigned['signer_raw'])==1 and
                 len(certs)==1,
                 'LOTL_SIGNED_POINTER_MUST_BIND_ACTUAL_EC409_SIGNER_AND_URL',
                 'permission_denied')
            observed[role].append(loc)
    need(len(observed_self)==1 and all(len(v)==1 for v in observed.values()),
         'SIGNED_LOTL_MUST_HAVE_ONE_SELF_AND_TWO_NATIONAL_POINTERS',
         'permission_denied')
    perrole={}
    for role,at in required_times.items():
        perrole[role]=bool(issue<=at<nextutc and
                           chain['signer'].not_valid_before_utc<=at<=
                           chain['signer'].not_valid_after_utc)
    return {'original_signed_lotl_sha256':refobj['sha256'],
            'original_lotl_signer_certificate_sha256':sha(raw_signer),
            'lotl_signed_sequence_number':int(sequence),
            'lotl_signed_issue_utc':issue.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'lotl_signed_next_update_utc':nextutc.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'exact_original_ec409_tsl_signer_pointers_authenticated':2,
            'signed_pointer_locations':{r:observed[r][0] for r in sorted(observed)},
            'signed_original_lotl_self_distribution_https_uri':observed_self[0],
            'signed_snapshot_covers_real_ec407_claim_or_evaluation_utc':perrole,
            'xmlsig_reference_count':len(refs),
            'xades_signed_properties_verified':props is not None}


def _engine(deriving,**opts):
    inherited=_inputs(opts,deriving)
    live=parent.audit(**inherited)  # PRODUCTION: REAL EC409 -> all older audits
    live_sha=_parent_report(live,opts)
    lineage=opts['claimed_historical_directory_lineage_id']
    n=len(opts['historical_directory_root_shas'])
    read,doc,late=readers._readers()
    new={'path':opts[NEW_SCALARS[0]],'sha256':opts[NEW_SCALARS[1]]}
    old={'path':opts[parent.NEW_SCALARS[0]],'sha256':opts[parent.NEW_SCALARS[1]]}
    older={'path':opts[parent.parent.parent.NEW_SCALARS[0]],
           'sha256':opts[parent.parent.parent.NEW_SCALARS[1]]}  # original EC407
    bundle=doc(new,'ec410_signed_lotl_bundle',MAX_BUNDLE)
    exact(bundle,BUNDLE_FIELDS,'LOTL_BUNDLE')
    need(bundle['schema']==BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id']==lineage and
         bundle['parent_ec409_original_signed_tsl_bundle_original']==old and
         type(bundle['epochs']) is list and len(bundle['epochs'])==n,
         'LOTL_BUNDLE_MUST_BIND_ACTUAL_EC409_AND_EPOCHS',
         'permission_denied')
    p409=doc(old,'ec410_reopen_actual_original_ec409_signed_tsl',parent.MAX_BUNDLE)
    exact(p409,parent.BUNDLE_FIELDS,'REAL_EC409_SIGNED_TSL')
    need(p409['schema']==parent.BUNDLE_SCHEMA and
         p409['claimed_directory_lineage_id']==lineage and
         type(p409['epochs']) is list and len(p409['epochs'])==n,
         'LOTL_REAL_EC409_SOURCE_PARENT_MISMATCH','permission_denied')
    p407=doc(older,'ec410_reopen_real_ec407_signed_custody',cms.MAX_BUNDLE)
    exact(p407,cms.BUNDLE_FIELDS,'REAL_EC407_SIGNED_STATEMENTS')
    need(p407['schema']==cms.BUNDLE_SCHEMA and
         p407['claimed_directory_lineage_id']==lineage and
         type(p407['epochs']) is list and len(p407['epochs'])==n,
         'LOTL_EC407_SIGNED_STATEMENT_SOURCE_MISMATCH',
         'permission_denied')
    p409rosterref=ref(p409['outside_tsl_signer_roster_original'])
    need(p409rosterref['sha256']==opts[parent.NEW_SCALARS[2]],
         'EC409_SIGNER_ROSTER_ORIGINAL_OUTSIDE_SHA_MISMATCH',
         'permission_denied')
    p409roster=doc(p409rosterref,'ec410_reopen_original_ec409_tsl_signers',
                   parent.MAX_ROSTER)
    exact(p409roster,parent.ROSTER_FIELDS,'REAL_EC409_TSL_SIGNERS')
    need(p409roster['schema']==parent.ROSTER_SCHEMA and
         p409roster['claimed_directory_lineage_id']==lineage and
         type(p409roster['assignments']) is list and
         len(p409roster['assignments'])==2,
         'EC409_TWO_OUTSIDE_SOURCE_SIGNER_ASSIGNMENTS_REQUIRED',
         'permission_denied')
    allused={new['path'],old['path'],older['path'],p409rosterref['path']}
    for k in PARENT_SCALARS:
        if k.endswith('_file') and type(opts.get(k)) is str:allused.add(opts[k])
    # Reopen the complete immediate source manifests; never hide a source path
    # collision under an apparent new LOTL pointer or operator certificate.
    for src in (p409,p409roster,p407):
        parent.parent.parent.parent.parent._find_ref_paths(src,allused)
    roles={};parent_keys=set()
    for row in p409roster['assignments']:
        exact(row,parent.ASSIGNMENT_FIELDS,'REAL_EC409_SIGNER_ASSIGNMENT')
        role=row['publisher_id']
        need(role not in roles and type(role) is str,
             'DUPLICATE_REAL_EC409_ROLE','permission_denied')
        certref=ref(row['tsl_signer_certificate_original'])
        signer_raw=read(certref,'ec410_reopen_ec409_original_tsl_der',MAX_CERT)
        signer=_cert(signer_raw,'PARENT_TSL_SIGNER')
        spki=_key_spki(signer.public_key());parent_keys.add(spki)
        roles[role]={'signer_raw':signer_raw,'territory':row['scheme_territory'],
                     'signer_sha':certref['sha256']}
    need(len(roles)==2 and len(parent_keys)==2,
         'TWO_ACTUAL_EC409_DISTINCT_ORIGINAL_ROLE_SIGNERS_REQUIRED',
         'permission_denied')
    rosterref=ref(bundle['outside_lotl_operator_roster_original'])
    need(rosterref['sha256']==opts[NEW_SCALARS[2]] and
         rosterref['path'] not in allused,
         'LOTL_ORIGINAL_OPERATOR_ROSTER_PIN_OR_PATH_ALIAS',
         'permission_denied')
    allused.add(rosterref['path'])
    roster=doc(rosterref,'ec410_reopen_independently_pinned_lotl_operator_roster',
               MAX_ROSTER)
    exact(roster,ROSTER_FIELDS,'OUTSIDE_LOTL_OPERATOR_ROSTER')
    need(roster['schema']==ROSTER_SCHEMA and
         roster['claimed_directory_lineage_id']==lineage and
         type(roster['assignments']) is list and len(roster['assignments'])==2,
         'LOTL_TWO_POINTER_ASSIGNMENTS_REQUIRED','permission_denied')
    _source_url(roster['expected_lotl_distribution_https_uri'])
    certificates={};certpaths=set()
    for index,(key,field) in enumerate((
          ('root','lotl_trust_anchor_certificate_original'),
          ('mid','lotl_intermediate_ca_certificate_original'),
          ('signer','lotl_signer_certificate_original'))):
        certref=ref(roster[field])
        need(certref['path'] not in allused and certref['path'] not in certpaths,
             'LOTL_OPERATOR_CERT_ORIGINAL_ALIASES_EXISTING_SOURCE',
             'permission_denied')
        allused.add(certref['path']);certpaths.add(certref['path'])
        certificates[key]=read(certref,'ec410_original_lotl_'+key+'_x509_der',MAX_CERT)
        need(certref['sha256']==opts[NEW_SCALARS[3+index]],
             'LOTL_OPERATOR_X509_ORIGINAL_OUTSIDE_PIN_MISMATCH',
             'permission_denied')
    role_assignments={};territories=set();urls=set()
    for row in roster['assignments']:
        exact(row,ASSIGNMENT_FIELDS,'LOTL_OPERATOR_POINTER_ASSIGNMENT')
        role=row['publisher_id']
        territory=row['scheme_territory']
        loc=_source_url(row['expected_national_tsl_location_https_uri'])
        need(role in roles and role not in role_assignments and
             type(territory) is str and TERRITORY.fullmatch(territory) is not None and
             territory!='EU' and territory not in territories and loc not in urls and
             roles[role]['territory']==territory,
             'LOTL_POINTER_ROLE_TERRITORY_OR_URL_NOT_UNIQUE_TO_EC409',
             'permission_denied')
        territories.add(territory);urls.add(loc)
        role_assignments[role]={**row,'signer_raw':roles[role]['signer_raw']}
    need(set(role_assignments)==set(roles),
         'LOTL_MUST_MAP_EXACT_TWO_EC409_ORIGINAL_ROLES',
         'permission_denied')
    # Avoid cert-key masquerade as any national trusted-list signer. The
    # independently pinned CA chain still has NO official provenance proof.
    chain=_chain(certificates,[])
    need(not any(k in parent_keys for k in chain['keys']),
         'LOTL_OPERATOR_ROOT_INTERMEDIATE_OR_SIGNER_REUSES_NATIONAL_TSL_KEY',
         'permission_denied')
    claims={}
    for i,epoch in enumerate(p407['epochs']):
        exact(epoch,cms.EPOCH_FIELDS,'REAL_EC407_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==i and
             type(epoch['publishers']) is list and len(epoch['publishers'])==2,
             'LOTL_REAL_EC407_TWO_ROLE_EPOCH_REQUIRED','permission_denied')
        oldroles={r['publisher_id']:r for r in epoch['publishers']}
        need(set(oldroles)==set(roles),'LOTL_REAL_CMS_SOURCE_ROLE_MISMATCH',
             'permission_denied')
        claims[i]={}
        for role,entry in oldroles.items():
            exact(entry,cms.ROLE_FIELDS,'REAL_EC407_SIGNED_CUSTODY_ROLE')
            statement=doc(ref(entry['original_custody_statement']),
                          'ec410_reopen_actual_ec407_cms_signed_claim',cms.MAX_STATEMENT)
            exact(statement,cms.STATEMENT_FIELDS,'REAL_EC407_CMS_STATEMENT')
            need(statement['schema']==cms.STATEMENT_SCHEMA and
                 statement['directory_lineage_id']==lineage and
                 statement['publisher_id']==role and
                 statement['epoch_index']==i,
                 'LOTL_CLAIM_MUST_BE_FROM_SAME_EC407_ACTUAL_SIGNED_ROLE',
                 'permission_denied')
            claims[i][role]=utc(statement['claimed_custody_utc'])
    evalutc=utc(opts['ec407_institutional_evaluation_utc'])
    prior_sequence=None;missing=False;first=[];records=[];reviews=[];total=0
    flags={k:False for k in FLAGS}
    flags[FLAGS[0]]=(not live['bounded_local_signed_tsl_and_real_ec408_parent_consistency'] or
        any(x['joint_actual_ec408_ocsp_and_signed_tsl_count']!=2
            for x in live['signed_tsl_epoch_reviews']))
    used_shas=set()
    for i,entry in enumerate(bundle['epochs']):
        exact(entry,EPOCH_FIELDS,'SIGNED_LOTL_EPOCH')
        need(type(entry['epoch_index']) is int and entry['epoch_index']==i,
             'SIGNED_LOTL_EPOCH_ALIGNMENT_REQUIRED','permission_denied')
        hr=entry['original_historical_signed_lotl_xml']
        vr=entry['original_evaluation_signed_lotl_xml']
        parent_count=live['signed_tsl_epoch_reviews'][i][
                      'joint_actual_ec408_ocsp_and_signed_tsl_count']
        if hr is None or vr is None:
            need(i>0 and hr is None and vr is None,
                 'FIRST_LOTL_PAIR_REQUIRED_NO_LATER_HALF_PAIR',
                 'permission_denied')
            missing=True;flags[FLAGS[2]]=True;flags[FLAGS[4]]=True
            rec={'epoch_index':i,'historical_lotl_original_sha256':None,
                 'evaluation_lotl_original_sha256':None,
                 'verified_original_signed_lotl_pair':False,
                 'matched_two_ec409_original_signer_pointers':0,
                 'joint_real_ec409_and_original_lotl_publisher_count':0,
                 'historical_review':None,'evaluation_review':None}
        else:
            need(not missing,'LOTL_AFTER_MISSING_PAIR_REAPPEARS',
                 'permission_denied')
            h_ref=ref(hr);v_ref=ref(vr)
            for r in (h_ref,v_ref):
                need(r['path'] not in allused and r['sha256'] not in used_shas,
                     'LOTL_REPLAY_OR_PARENT_ORIGINAL_PATH_ALIAS',
                     'permission_denied')
                allused.add(r['path']);used_shas.add(r['sha256'])
            hist=_verify_lotl(h_ref,certificates['signer'],chain,role_assignments,
                              claims[i],roster['expected_lotl_distribution_https_uri'],read)
            eva=_verify_lotl(v_ref,certificates['signer'],chain,role_assignments,
                             {role:evalutc for role in roles},
                             roster['expected_lotl_distribution_https_uri'],read)
            need(hist['lotl_signed_sequence_number']<=
                   eva['lotl_signed_sequence_number'] and
                 hist['lotl_signed_issue_utc']<=eva['lotl_signed_issue_utc'],
                 'LOTL_HISTORICAL_TO_EVALUATION_ROLLBACK',
                 'permission_denied')
            if prior_sequence is not None:
                need(prior_sequence[0]<=hist['lotl_signed_sequence_number'] and
                     prior_sequence[1]<=hist['lotl_signed_issue_utc'] and
                     prior_sequence[2]<=eva['lotl_signed_sequence_number'] and
                     prior_sequence[3]<=eva['lotl_signed_issue_utc'],
                     'LOTL_CROSS_EPOCH_SIGNED_SEQUENCE_OR_ISSUE_ROLLBACK',
                     'permission_denied')
            prior_sequence=(hist['lotl_signed_sequence_number'],
                            hist['lotl_signed_issue_utc'],
                            eva['lotl_signed_sequence_number'],
                            eva['lotl_signed_issue_utc'])
            count=sum(hist['signed_snapshot_covers_real_ec407_claim_or_evaluation_utc'][r]
                       and eva['signed_snapshot_covers_real_ec407_claim_or_evaluation_utc'][r]
                       for r in roles)
            if count!=2:flags[FLAGS[3]]=True
            joint=count if not flags[FLAGS[0]] and parent_count==2 else 0
            if joint!=2:flags[FLAGS[4]]=True
            if i==0:first=[h_ref['sha256'],v_ref['sha256']]
            rec={'epoch_index':i,'historical_lotl_original_sha256':h_ref['sha256'],
                 'evaluation_lotl_original_sha256':v_ref['sha256'],
                 'verified_original_signed_lotl_pair':True,
                 'matched_two_ec409_original_signer_pointers':count,
                 'joint_real_ec409_and_original_lotl_publisher_count':joint,
                 'historical_review':hist,'evaluation_review':eva}
        inventory_sha=digest(rec)
        if (inventory_sha!=opts[REPEAT_NAMES[0]][i] or
           rec['joint_real_ec409_and_original_lotl_publisher_count']<
                  opts[REPEAT_NAMES[1]][i]):
            flags[FLAGS[1]]=True
        records.append(rec)
        reviews.append({'epoch_index':i,
             'verified_signed_lotl_dual_window_pair_count':int(
                 rec['verified_original_signed_lotl_pair']),
             'matched_signed_national_pointer_dual_window_publisher_count':
                 rec['matched_two_ec409_original_signer_pointers'],
             'joint_real_ec409_and_signed_lotl_publisher_count':
                 rec['joint_real_ec409_and_original_lotl_publisher_count'],
             'signed_lotl_epoch_inventory_sha256':inventory_sha,
             'genuine_ec409_parent_joint_tsl_count':parent_count})
        total+=rec['joint_real_ec409_and_original_lotl_publisher_count']
    need(len(first)==2,'FIRST_HISTORICAL_AND_EVALUATION_LOTL_ORIGINALS_REQUIRED',
         'permission_denied')
    if first!=[opts[NEW_SCALARS[6]],opts[NEW_SCALARS[7]]]:flags[FLAGS[1]]=True
    inventory={'schema':INVENTORY_SCHEMA,'directory_lineage_id':lineage,
       'verified_genuine_ec409_parent_report_sha256':live_sha,
       'verified_genuine_ec409_parent_inventory_sha256':live[
           'receiver_verified_signed_tsl_inventory_sha256'],
       'ec409_original_signed_tsl_bundle_sha256':old['sha256'],
       'ec410_original_signed_lotl_bundle_sha256':new['sha256'],
       'outside_original_lotl_operator_roster_sha256':rosterref['sha256'],
       'independently_pinned_original_lotl_chain_certificate_shas':[
           opts[k] for k in NEW_SCALARS[3:6]],
       'first_historical_and_evaluation_lotl_original_shas':first,
       'expected_lotl_distribution_https_uri':roster['expected_lotl_distribution_https_uri'],
       'signed_evaluation_utc':opts['ec407_institutional_evaluation_utc'],
       'epochs':records}
    invsha=digest(inventory)
    if not deriving and invsha!=opts[AUDIT_ONLY[0]]:flags[FLAGS[1]]=True
    # Hardened reader retains original reference digests; reopen ALL originals.
    for path,(expect,limit) in late.items():
        raw=io._read({'path':path,'sha256':expect},
                     'ec410_final_original_readback',limit,{},{},set())
        need(sha(raw)==expect,'LOTL_ORIGINAL_CHANGED_BETWEEN_CHECKS',
             'permission_denied')
    for k in FLAGS[-3:]:flags[k]=True
    return {'schema':DERIVE_SCHEMA if deriving else RESULT_SCHEMA,
        'command':('derive-historical-ec339-signed-lotl-inventory' if deriving
                   else 'audit-historical-ec339-signed-lotl'),
        'status':next((OUTCOMES[j] for j,k in enumerate(FLAGS) if flags[k]),
                      OUTCOMES[-1])+'_unresolved',
        'exit_code':2,'offline_unresolved_exit_code':2,
        'verified_live_ec409_report_sha256':live_sha,
        'verified_live_ec409_inventory_sha256':live[
            'receiver_verified_signed_tsl_inventory_sha256'],
        'original_signed_lotl_bundle_sha256':new['sha256'],
        'receiver_verified_signed_lotl_inventory_sha256':invsha,
        'verified_joint_signed_lotl_and_real_ec409_parent_publishers':total,
        'signed_lotl_epoch_reviews':reviews,
        'bounded_original_lotl_and_real_ec409_parent_consistency':
            not any(flags[k] for k in FLAGS[:5]),
        'sender_origin_path_required_or_read':False,
        'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
        **flags,**{k:False for k in NEGATIVES},
        **({'unsigned_signed_lotl_original_inventory':inventory} if deriving else {})}


def derive_inventory(**opts):return _engine(True,**opts)
def audit(**opts):return _engine(False,**opts)
