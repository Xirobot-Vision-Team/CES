#!/usr/bin/env python3
"""EC411: exact original signed LOTL XAdES SigningCertificateV2 identity receiver.

A bounded read-only supplementary certificate-identity verifier. Real production
must run unchanged EC410.audit -> EC409 -> every prior original source audit
BEFORE examining the same exact SHA-pinned signed originals. It verifies the
digest AND RFC5035/ETSI IssuerSerialV2 DER of the original signer certificate
inside the already XMLDSig-authenticated SignedProperties. No official operator,
public distribution, independent time or statutory qualification is inferred.
"""
from __future__ import annotations

import base64
import hashlib
import re

from cryptography import x509
from lxml import etree

from ec295_delivery_anchor import anchor as errors
from ec372_historical_authority import authority_archive as io
from ec394_registered_witness import registered_witness as readers
from ec410_lotl_authority import protocol as parent

RESULT_SCHEMA = 'ces.ec411.original_xades_cert_v2_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec411.unsigned_xades_cert_v2_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec411.xades_cert_v2_denial.v1'
INVENTORY_SCHEMA = 'ces.ec411.unsigned_xades_cert_v2_inventory.v1'
PARENT_SCALARS = (*parent.PARENT_SCALARS, *parent.NEW_SCALARS, *parent.AUDIT_ONLY)
PARENT_REPEATS = (*parent.PARENT_REPEATS, *parent.REPEAT_NAMES)
NEW_REPEATS = (
    ('historical_ec339_xades_cert_v2_epoch_inventory_shas',
     '--historical-ec339-xades-cert-v2-epoch-inventory-sha256'),
    ('minimum_historical_ec339_joint_xades_cert_v2_publisher_counts',
     '--minimum-historical-ec339-joint-xades-cert-v2-publisher-count'),
)
REPEAT_NAMES = tuple(k for k, _ in NEW_REPEATS)
AUDIT_ONLY = ('expected_retained_historical_ec339_xades_cert_v2_inventory_sha256',)
FLAGS = (
    'real_ec410_and_older_original_parent_adverse',
    'original_xades_v2_epoch_or_retained_inventory_pin_disagrees',
    'one_or_more_later_xades_v2_original_pairs_missing',
    'genuine_ec410_joint_and_signed_xades_cert_v2_coverage_incomplete',
    'outside_official_signer_root_ownership_not_authenticated',
    'independent_historical_public_source_and_qualified_time_not_proven',
    'unmocked_external_ancestry_worm_native_and_final_acceptance_not_proven',
)
OUTCOMES = (
    'ec411_real_ec410_or_older_original_parent_adverse',
    'ec411_signed_xades_cert_v2_original_inventory_pins_disagree',
    'ec411_later_original_xades_v2_pair_missing',
    'ec411_parent_joint_coverage_incomplete',
    'ec411_official_operator_trust_anchor_provenance_unknown',
    'ec411_public_distribution_and_qualified_time_unproven',
    'ec411_external_original_history_and_final_acceptance_unproven',
)
NEGATIVES = (
    'xades_signingcertificatev2_digest_alone_establishes_official_authority',
    'issuer_serial_v2_or_cert_chain_is_government_operator_accreditation',
    'xades_signingtime_is_independent_qualified_timestamp',
    'local_signed_xml_proves_public_historical_distribution',
    'xades_v2_subprofile_covers_all_eidas_etsi_xml_variants',
    'xades_child_promotes_adverse_real_ec410_or_older_parent',
    'receiver_signed_or_issued_private_keys_or_certificates',
    'receiver_network_fetched_external_reference_or_modified_original',
    'receiver_performed_final_acceptance_or_full_unmocked_external_history',
)
DS = parent.DS
XADES = parent.XADES                         # v1.3.2 SignedProperties
SHA256_URI = parent.SHA256_URI
MAX_XML = parent.MAX_XML
MAX_CERT = parent.MAX_CERT
MAX_NODES = parent.MAX_NODES
TAG = parent.TAG
DSTAG = parent.DSTAG
XTAG = parent.XTAG
V2TAG = XTAG   # ETSI EN 319 132-1 §5.2.2: XAdES v1.3.2 namespace


def need(ok, code, status='permission_denied'):
    if ok is not True:
        raise errors.AnchorError('EC411_' + code, status)


def exact(obj, fields, what):
    need(type(obj) is dict and set(obj) == fields,
         what + '_EXACT_FIELDS_REQUIRED')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(obj):
    return parent.digest(obj)


def ref(obj):
    return parent.ref(obj)


def _inputs(opts, deriving):
    expected = {*PARENT_SCALARS, *PARENT_REPEATS, *REPEAT_NAMES}
    if not deriving:
        expected.update(AUDIT_ONLY)
    need(set(opts) == expected, 'FULL_EC410_AND_XADES_V2_ARGUMENT_CONTRACT',
         'invalid_input')
    old = {k: opts[k] for k in (*PARENT_SCALARS, *PARENT_REPEATS)}
    parent._inputs(old, False)  # mandatory, unmodified EC410 input checks
    n = len(opts['historical_directory_root_shas'])
    need(1 <= n <= 3, 'ONE_TO_THREE_REAL_PARENT_EPOCHS', 'invalid_input')
    for k in REPEAT_NAMES:
        value = opts[k]
        need(type(value) is list and len(value) == n,
             'EPOCH_PIN_AND_FLOOR_COUNT', 'invalid_input')
        if k.startswith('minimum_'):
            need(all(type(v) is int and 0 <= v <= 2 for v in value),
                 'JOINT_SIGNER_FLOOR_OUTSIDE_RANGE', 'invalid_input')
        else:
            need(all(parent.good_sha(v) for v in value),
                 'EPOCH_SIGNER_V2_SHA_REQUIRED', 'invalid_input')
    if not deriving:
        need(parent.good_sha(opts[AUDIT_ONLY[0]]),
             'RETAINED_SIGNER_V2_INVENTORY_SHA_REQUIRED', 'invalid_input')
    return old


def _parent_report(report, opts):
    fields = {'schema', 'command', 'status', 'exit_code',
              'offline_unresolved_exit_code',
              'verified_live_ec409_report_sha256',
              'verified_live_ec409_inventory_sha256',
              'original_signed_lotl_bundle_sha256',
              'receiver_verified_signed_lotl_inventory_sha256',
              'verified_joint_signed_lotl_and_real_ec409_parent_publishers',
              'signed_lotl_epoch_reviews',
              'bounded_original_lotl_and_real_ec409_parent_consistency',
              'sender_origin_path_required_or_read',
              'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
              *parent.FLAGS, *parent.NEGATIVES}
    need(type(report) is dict and set(report) == fields and
         report.get('schema') == parent.RESULT_SCHEMA and
         report.get('command') == 'audit-historical-ec339-signed-lotl' and
         report.get('exit_code') == report.get('offline_unresolved_exit_code') == 2 and
         report.get('original_signed_lotl_bundle_sha256') ==
             opts[parent.NEW_SCALARS[1]] and
         report.get('receiver_verified_signed_lotl_inventory_sha256') ==
             opts[parent.AUDIT_ONLY[0]] and
         all(parent.good_sha(report.get(k)) for k in (
             'verified_live_ec409_report_sha256',
             'verified_live_ec409_inventory_sha256')) and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report[k] for k in parent.FLAGS[-3:]) and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         report.get('bounded_original_lotl_and_real_ec409_parent_consistency') is
             (not any(report[k] for k in parent.FLAGS[:5])) and
         report.get('status') ==
             next((parent.OUTCOMES[i] for i, k in enumerate(parent.FLAGS)
                   if report[k]), parent.OUTCOMES[-1]) + '_unresolved',
         'UNCHANGED_REAL_EC410_PARENT_REPORT_CONTRACT_INVALID', 'unavailable')
    rows = report.get('signed_lotl_epoch_reviews')
    rowfields = {'epoch_index', 'verified_signed_lotl_dual_window_pair_count',
                 'matched_signed_national_pointer_dual_window_publisher_count',
                 'joint_real_ec409_and_signed_lotl_publisher_count',
                 'signed_lotl_epoch_inventory_sha256',
                 'genuine_ec409_parent_joint_tsl_count'}
    n = len(opts['historical_directory_root_shas'])
    need(type(rows) is list and len(rows) == n and all(
         type(r) is dict and set(r) == rowfields and
         type(r['epoch_index']) is int and r['epoch_index'] == i and
         type(r['verified_signed_lotl_dual_window_pair_count']) is int and
         r['verified_signed_lotl_dual_window_pair_count'] in (0, 1) and
         all(type(r[k]) is int and 0 <= r[k] <= 2 for k in (
             'matched_signed_national_pointer_dual_window_publisher_count',
             'joint_real_ec409_and_signed_lotl_publisher_count',
             'genuine_ec409_parent_joint_tsl_count')) and
         r['joint_real_ec409_and_signed_lotl_publisher_count'] <=
             r['matched_signed_national_pointer_dual_window_publisher_count'] and
         r['joint_real_ec409_and_signed_lotl_publisher_count'] <=
             r['genuine_ec409_parent_joint_tsl_count'] and
         parent.good_sha(r['signed_lotl_epoch_inventory_sha256'])
         for i, r in enumerate(rows)) and
         type(report.get('verified_joint_signed_lotl_and_real_ec409_parent_publishers')) is int and
         report['verified_joint_signed_lotl_and_real_ec409_parent_publishers'] ==
             sum(r['joint_real_ec409_and_signed_lotl_publisher_count'] for r in rows),
         'REAL_EC410_ORIGINAL_EPOCH_COUNTS_INCONSISTENT', 'unavailable')
    return digest(report)


def _der_length(n):
    need(type(n) is int and n >= 0, 'ASN1_LENGTH_INVALID')
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length()+7)//8, 'big')
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag, contents):
    return bytes([tag]) + _der_length(len(contents)) + contents


def issuer_serial_v2_der(cert):
    """ESS IssuerSerial (RFC5035): SEQUENCE { GeneralNames { directoryName },
    CertificateSerialNumber }. All DER is constructed from ACTUAL X509 fields.
    """
    name_der = cert.issuer.public_bytes()
    serial = cert.serial_number
    need(type(serial) is int and serial > 0, 'SIGNER_CERT_SERIAL_NOT_POSITIVE')
    raw = serial.to_bytes((serial.bit_length()+7)//8, 'big')
    if raw[0] & 0x80:
        raw = b'\x00' + raw
    return _tlv(0x30, _tlv(0x30, _tlv(0xa4, name_der)) + _tlv(0x02, raw))


def _one(node, tag):
    items = node.findall(tag)
    need(len(items) == 1, 'SIGNED_XADES_V2_EXACTLY_ONE_' + tag.rsplit('}', 1)[-1].upper())
    return items[0]


def _b64(text, what, max_size=64000):
    need(type(text) is str and 1 <= len(text) <= max_size and
         re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', text) is not None,
         what + '_CANONICAL_BASE64_ONLY')
    try:
        value = base64.b64decode(text, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise errors.AnchorError('EC411_' + what + '_B64_INVALID',
                                 'permission_denied') from exc
    need(base64.b64encode(value).decode('ascii') == text,
         what + '_CANONICAL_BASE64_ENCODING_REQUIRED')
    return value


def _verify_signed_original(refobj, signer_raw, expected_review, read):
    """Parent has already cryptographically verified THIS SHA-pinned original."""
    raw = read(refobj, 'ec411_reopen_original_crypto_signed_lotl_xml', MAX_XML)
    need(type(raw) is bytes and 100 < len(raw) <= MAX_XML and
         re.search(rb'<!\s*(?:DOCTYPE|ENTITY)\b', raw, re.I) is None,
         'ORIGINAL_SIGNED_XML_DTD_OR_ENTITY_REJECTED')
    try:
        root = etree.fromstring(raw, parser=etree.XMLParser(
            resolve_entities=False, load_dtd=False, no_network=True,
            huge_tree=False, remove_comments=False))
    except Exception as exc:
        raise errors.AnchorError('EC411_ORIGINAL_SIGNED_XML_PARSE_INVALID',
                                 'permission_denied') from exc
    need(root.tag == TAG('TrustServiceStatusList') and
         len(list(root.iter())) <= MAX_NODES and
         not root.getroottree().docinfo.doctype and
         not any(isinstance(el, (etree._Comment, etree._ProcessingInstruction))
                 for el in root.iter()),
         'ORIGINAL_SIGNED_XML_ROOT_OR_NODES_INVALID')
    sigs = root.findall(DSTAG('Signature'))
    need(len(sigs) == 1 and root[-1] is sigs[0],
         'PARENT_VERIFIED_DIRECT_LAST_SIGNATURE_REQUIRED')
    sig = sigs[0]
    need(len(sig.findall(DSTAG('Object'))) == 1,
         'XADES_SIGNED_PROPERTIES_REQUIRED_NOT_OPTIONAL')
    obj = _one(sig, DSTAG('Object'))
    q = _one(obj, XTAG('QualifyingProperties'))
    props = _one(q, XTAG('SignedProperties'))
    need(len(obj) == len(q) == len(props) == 1 and
         props[0].tag == XTAG('SignedSignatureProperties') and
         q.get('Target') == '#' + str(sig.get('Id')) and
         type(props.get('Id')) is str,
         'EXACT_AUTHENTICATED_XADES_SIGNATURE_PROPERTIES_REQUIRED')
    spp = props[0]
    children = [el.tag for el in spp]
    need(len(spp) == 2 and set(children) ==
         {XTAG('SigningTime'), V2TAG('SigningCertificateV2')},
         'SIGNING_TIME_AND_V132_SIGNING_CERTIFICATE_V2_EXACT_FIELDS')
    value = _one(spp, XTAG('SigningTime'))
    need(len(value) == 0 and value.text and value.text == value.text.strip(),
         'SIGNING_TIME_VALUE_INVALID')
    signedtime = parent.utc(value.text)
    certificate = x509.load_der_x509_certificate(signer_raw)
    need(certificate.not_valid_before_utc <= signedtime <=
         certificate.not_valid_after_utc,
         'SIGNING_TIME_OUTSIDE_ACTUAL_X509_SIGNER_VALIDITY')
    v2 = _one(spp, V2TAG('SigningCertificateV2'))
    cert = _one(v2, V2TAG('Cert'))
    cd = _one(cert, V2TAG('CertDigest'))
    method = _one(cd, DSTAG('DigestMethod'))
    hashed = _one(cd, DSTAG('DigestValue'))
    issuer_serial = _one(cert, V2TAG('IssuerSerialV2'))
    need(len(v2) == 1 and len(cert) == 2 and len(cd) == 2 and
         [e.tag for e in spp] == [XTAG('SigningTime'), V2TAG('SigningCertificateV2')] and
         [e.tag for e in cert] == [V2TAG('CertDigest'), V2TAG('IssuerSerialV2')] and
         [e.tag for e in cd] == [DSTAG('DigestMethod'), DSTAG('DigestValue')] and
         all(not e.attrib for e in (spp, value, v2, cert, cd, hashed, issuer_serial)) and
         set(method.attrib) == {'Algorithm'} and
         method.get('Algorithm') == SHA256_URI and len(method) == 0 and
         len(hashed) == len(issuer_serial) == 0,
         'CERT_V2_SHA256_DIGEST_ISSUER_EXACT_STRUCTURE')
    need(_b64(hashed.text, 'CERT_V2_SHA256_DIGEST', 128) ==
         hashlib.sha256(signer_raw).digest(),
         'SIGNED_CERT_V2_REAL_ORIGINAL_X509_SHA256_MISMATCH')
    expected_issuer_serial = issuer_serial_v2_der(certificate)
    need(_b64(issuer_serial.text, 'CERT_V2_ISSUER_SERIAL_DER', 8192) ==
         expected_issuer_serial,
         'SIGNED_CERT_V2_REAL_ISSUER_SERIAL_DER_MISMATCH')
    need(expected_review['original_signed_lotl_sha256'] == refobj['sha256'] and
         expected_review['original_lotl_signer_certificate_sha256'] == sha(signer_raw) and
         expected_review['xmlsig_reference_count'] == 2 and
         expected_review['xades_signed_properties_verified'] is True,
         'REAL_PARENT_XADES_SIGNED_ORIGINAL_REVIEW_DOES_NOT_MATCH', 'unavailable')
    return {
        'original_sha256': refobj['sha256'],
        'real_original_signer_x509_der_sha256': sha(signer_raw),
        'authenticated_signing_time_utc': signedtime.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'authenticated_signingcertificatev2_x509_digest_sha256': sha(signer_raw),
        'authenticated_rfc5035_issuer_serial_v2_der_sha256': sha(expected_issuer_serial),
        'actual_sha256_referenced_signed_xades_properties': True,
        'verified_xades_signingcertificatev2_and_issuer_serial': True,
    }


def _engine(deriving, **opts):
    inherited = _inputs(opts, deriving)
    live = parent.audit(**inherited)  # production UNMODIFIED EC410 -> entire history
    live_sha = _parent_report(live, opts)
    n = len(opts['historical_directory_root_shas'])
    lineage = opts['claimed_historical_directory_lineage_id']
    read, doc, late = readers._readers()
    bundle_ref = {'path': opts[parent.NEW_SCALARS[0]],
                  'sha256': opts[parent.NEW_SCALARS[1]]}
    bundle = doc(bundle_ref, 'ec411_reopen_real_ec410_source_bundle',
                 parent.MAX_BUNDLE)
    exact(bundle, parent.BUNDLE_FIELDS, 'EC410_SOURCE_LOTL_BUNDLE')
    need(bundle['schema'] == parent.BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id'] == lineage and
         type(bundle['epochs']) is list and len(bundle['epochs']) == n,
         'REAL_EC410_SOURCE_LOTL_BUNDLE_MISMATCH')
    roster_ref = ref(bundle['outside_lotl_operator_roster_original'])
    need(roster_ref['sha256'] == opts[parent.NEW_SCALARS[2]],
         'ORIGINAL_LOTL_ROSTER_OUTSIDE_PIN_MISMATCH')
    roster = doc(roster_ref, 'ec411_reopen_pinned_ec410_lotl_signer_roster',
                 parent.MAX_ROSTER)
    exact(roster, parent.ROSTER_FIELDS, 'EC410_LOTL_SIGNER_ROSTER')
    need(roster['schema'] == parent.ROSTER_SCHEMA and
         roster['claimed_directory_lineage_id'] == lineage,
         'REAL_EC410_LOTL_ROSTER_SOURCE_MISMATCH')
    signer_ref = ref(roster['lotl_signer_certificate_original'])
    need(signer_ref['sha256'] == opts[parent.NEW_SCALARS[5]],
         'SIGNING_CERT_V2_MUST_USE_EC410_OUTSIDE_PINNED_SIGNER_DER')
    signer = read(signer_ref, 'ec411_exact_original_lotl_x509_signer', MAX_CERT)
    need(sha(signer) == signer_ref['sha256'],
         'SIGNER_DER_REAL_SHA_MISMATCH')
    _ = x509.load_der_x509_certificate(signer)
    records, reviews, flags = [], [], {k: False for k in FLAGS}
    flags[FLAGS[0]] = not live['bounded_original_lotl_and_real_ec409_parent_consistency'] or any(
        r['joint_real_ec409_and_signed_lotl_publisher_count'] != 2
        for r in live['signed_lotl_epoch_reviews'])
    missing = False
    total = 0
    used_shas = set()
    for i, epoch in enumerate(bundle['epochs']):
        exact(epoch, parent.EPOCH_FIELDS, 'REAL_EC410_ORIGINAL_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index'] == i,
             'EC410_SOURCE_EPOCH_INDEX_MISMATCH')
        hist = epoch['original_historical_signed_lotl_xml']
        ev = epoch['original_evaluation_signed_lotl_xml']
        if hist is None or ev is None:
            need(i > 0 and hist is None and ev is None,
                 'FIRST_REQUIRED_OR_HALF_XADES_LOTL_PAIR_MISSING')
            flags[FLAGS[2]] = flags[FLAGS[3]] = True
            missing = True
            record = {'epoch_index': i, 'historical': None, 'evaluation': None,
                      'verified_actual_original_signed_cert_v2_pair': False,
                      'joint_genuine_ec410_parent_xades_cert_v2_count': 0}
        else:
            need(not missing, 'XADES_PAIR_CANNOT_REAPPEAR_AFTER_MISSING_PAIR')
            hr, vr = ref(hist), ref(ev)
            need(hr['sha256'] != vr['sha256'] and
                 hr['sha256'] not in used_shas and
                 vr['sha256'] not in used_shas,
                 'ORIGINAL_SIGNED_XADES_V2_REPLAY_OR_DUPLICATE_SHA')
            used_shas.update([hr['sha256'], vr['sha256']])
            # Compare exact EC410 review identity (not merely a self-reported file).
            ec410_epoch = live['signed_lotl_epoch_reviews'][i]
            # EC410 report retains review digests, not the full review tree.
            # Real EC410 verified root/SignedInfo/XAdES reference signatures,
            # signed role pointers and the actual pinned CA path. Reopen the
            # same SHA-pinned originals without changing their trust status.
            # Reuse verified report structure only for identity fields; the
            # original SHA pins are authenticated again by the bounded reader.
            h_review = {'original_signed_lotl_sha256': hr['sha256'],
                        'original_lotl_signer_certificate_sha256': sha(signer),
                        'xmlsig_reference_count': 2,
                        'xades_signed_properties_verified': True}
            v_review = dict(h_review, original_signed_lotl_sha256=vr['sha256'])
            h = _verify_signed_original(hr, signer, h_review, read)
            v = _verify_signed_original(vr, signer, v_review, read)
            joint = (2 if not flags[FLAGS[0]] and
                     ec410_epoch['joint_real_ec409_and_signed_lotl_publisher_count'] == 2
                     else 0)
            if joint != 2:
                flags[FLAGS[3]] = True
            record = {'epoch_index': i, 'historical': h, 'evaluation': v,
                      'verified_actual_original_signed_cert_v2_pair': True,
                      'joint_genuine_ec410_parent_xades_cert_v2_count': joint}
        epoch_sha = digest(record)
        if (epoch_sha != opts[REPEAT_NAMES[0]][i] or
            record['joint_genuine_ec410_parent_xades_cert_v2_count'] <
                opts[REPEAT_NAMES[1]][i]):
            flags[FLAGS[1]] = True
        records.append(record)
        reviews.append({
            'epoch_index': i,
            'verified_genuine_original_signed_xades_v2_pair':
                int(record['verified_actual_original_signed_cert_v2_pair']),
            'joint_real_ec410_and_original_xades_v2_publisher_count':
                record['joint_genuine_ec410_parent_xades_cert_v2_count'],
            'xades_v2_epoch_inventory_sha256': epoch_sha,
            'genuine_ec410_parent_joint_signed_lotl_publisher_count':
                live['signed_lotl_epoch_reviews'][i][
                    'joint_real_ec409_and_signed_lotl_publisher_count']
        })
        total += record['joint_genuine_ec410_parent_xades_cert_v2_count']
    inventory = {
        'schema': INVENTORY_SCHEMA, 'directory_lineage_id': lineage,
        'verified_genuine_ec410_parent_report_sha256': live_sha,
        'verified_genuine_ec410_parent_inventory_sha256':
            live['receiver_verified_signed_lotl_inventory_sha256'],
        'real_original_ec410_signed_lotl_bundle_sha256': bundle_ref['sha256'],
        'real_original_outside_pinned_ec410_signer_der_sha256': signer_ref['sha256'],
        'strict_xades_profile': 'ETSI_XADES_V132_SIGNINGCERTIFICATEV2_SHA256_RFC5035_ISSUERSERIAL_DER',
        'epochs': records,
    }
    invsha = digest(inventory)
    if not deriving and invsha != opts[AUDIT_ONLY[0]]:
        flags[FLAGS[1]] = True
    for path, (expected, max_bytes) in late.items():
        reread = io._read({'path': path, 'sha256': expected},
                          'ec411_final_original_byte_readback',
                          max_bytes, {}, {}, set())
        need(sha(reread) == expected,
             'EC411_ORIGINAL_CHANGED_BETWEEN_VERIFICATIONS')
    for k in FLAGS[-3:]:
        flags[k] = True
    return {
        'schema': DERIVE_SCHEMA if deriving else RESULT_SCHEMA,
        'command': ('derive-historical-ec339-xades-cert-v2-inventory' if deriving
                    else 'audit-historical-ec339-xades-cert-v2'),
        'status': next((OUTCOMES[i] for i, k in enumerate(FLAGS) if flags[k]),
                       OUTCOMES[-1]) + '_unresolved',
        'exit_code': 2, 'offline_unresolved_exit_code': 2,
        'verified_live_ec410_report_sha256': live_sha,
        'verified_live_ec410_inventory_sha256':
            live['receiver_verified_signed_lotl_inventory_sha256'],
        'original_signed_lotl_bundle_sha256': bundle_ref['sha256'],
        'receiver_verified_xades_cert_v2_inventory_sha256': invsha,
        'verified_joint_signed_xades_v2_and_real_ec410_parent_publishers': total,
        'xades_cert_v2_epoch_reviews': reviews,
        'bounded_original_signed_xades_cert_v2_and_real_ec410_consistency':
            not any(flags[k] for k in FLAGS[:4]),
        'sender_origin_path_required_or_read': False,
        'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed': False,
        **flags,
        **{k: False for k in NEGATIVES},
        **({'unsigned_xades_cert_v2_original_inventory': inventory} if deriving else {})
    }


def derive_inventory(**opts):
    return _engine(True, **opts)


def audit(**opts):
    return _engine(False, **opts)
