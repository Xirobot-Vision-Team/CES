#!/usr/bin/env python3
"""EC403 original read-only, sharply bounded XMLDSig evidence receiver.

Only one same-document ds:Object, exclusive canonicalization, one genuine
reference and exact byte-for-byte EC398 gazette source are supported. The real
unchanged EC402 PDF audit and every ancestor run first in production. No XML
network resolution, signer, private key, certificate issue, XML rewrite, or
legal/government trust assertion is implemented.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ed25519, ec, rsa, padding, utils,
)
from delivery_anchor import anchor as errors
from historical_authority import authority_archive as io
from official_certificate import protocol as x509core
from official_notice import protocol as gazette
from signed_pdf import protocol as parent

RESULT_SCHEMA = 'ces.ec403.original_xmldsig_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec403.unsigned_original_xmldsig_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec403.original_xmldsig_denial.v1'
BUNDLE_SCHEMA = 'ces.ec403.original_xmldsig_bundle.v1'
INVENTORY_SCHEMA = 'ces.ec403.unsigned_original_xmldsig_inventory.v1'
NS = 'http://www.w3.org/2000/09/xmldsig#'
CNS = 'urn:ces:ec403:original-gazette-claim:v1'
C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#'
SHA256_URI = 'http://www.w3.org/2001/04/xmlenc#sha256'
METHOD_ED25519 = 'http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519'
METHOD_P256 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256'
METHOD_P384 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384'
METHOD_RSA = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
MAX_BUNDLE = 160_000
MAX_XML = 750_000
MAX_CERT_B64 = 40_000
MAX_SIGNATURE_B64 = 15_000
OBJECT_ID = 'ces-ec403-original-gazette'

PARENT_SCALARS = (*parent.PARENT_SCALARS, *parent.NEW_SCALARS,
                  *parent.AUDIT_ONLY)
PARENT_REPEATS = (*parent.PARENT_REPEATS, *parent.REPEAT_NAMES)
NEW_SCALARS = (
    'historical_ec339_original_xmldsig_bundle_file',
    'expected_historical_ec339_original_xmldsig_bundle_sha256',
    'expected_outside_retained_ec403_first_a_xml_sha256',
    'expected_outside_retained_ec403_first_b_xml_sha256',
)
AUDIT_ONLY = ('expected_retained_historical_ec339_original_xmldsig_inventory_sha256',)
NEW_REPEATS = (
    ('historical_ec339_original_xmldsig_epoch_inventory_shas',
     '--historical-ec339-original-xmldsig-epoch-inventory-sha256'),
    ('minimum_historical_ec339_joint_xmldsig_publisher_counts',
     '--minimum-historical-ec339-joint-xmldsig-publisher-count'),
)
REPEAT_NAMES = tuple(k for k, _ in NEW_REPEATS)
FLAGS = (
    'inherited_real_ec402_pdf_ocsp_crl_cms_parent_disputed',
    'outside_original_xml_epoch_or_whole_inventory_or_count_pin_disagrees',
    'one_or_more_real_publisher_xmlsig_originals_missing',
    'joint_two_publisher_xmlsig_and_pdf_parent_coverage_incomplete',
    'actual_official_issuer_and_legally_authorized_xml_publication_not_proven',
    'generic_xmlsig_xades_qualified_timestamp_and_visible_pdf_truth_not_proven',
    'independent_prior_public_custody_global_revocation_worm_acceptance_not_proven',
)
OUTCOMES = (
    'ec403_real_parent_ec402_original_pdf_and_ancestors_disputed',
    'ec403_external_xml_origins_inventory_or_floor_disagrees',
    'ec403_original_xmldsig_publisher_missing',
    'ec403_joint_real_parent_pdf_and_xmlsig_coverage_incomplete',
    'ec403_official_original_legal_publisher_authority_not_established',
    'ec403_generic_xmlsig_xades_qualified_time_or_visual_pdf_truth_not_established',
    'ec403_independent_public_history_worm_global_revocation_acceptance_not_established',
)
NEGATIVES = (
    'local_xmldsig_leaf_and_digest_prove_government_or_court_legal_authorization',
    'this_strict_one_object_xml_profile_supports_arbitrary_references_or_transforms',
    'xml_embedded_gazette_proves_the_visible_pdf_page_represents_its_semantics',
    'claimed_published_time_is_independent_qualified_legal_timestamp',
    'source_xmlsig_proves_general_xades_full_etsi_or_long_term_validation',
    'xml_signature_restores_failed_ec402_ec401_ocsp_ec399_crl_or_cms_credit',
    'locally_read_xml_proves_independent_pre_dispute_public_archive',
    'two_local_xml_signatures_prove_complete_global_revocation_or_fork_census',
    'receiver_generated_xml_signatures_keys_certificates_or_timestamps',
    'receiver_accessed_network_provider_or_mutated_ps1_pdf_xml_git_worm_or_ci',
    'unmocked_external_ancestor_history_native_ps7_or_final_acceptance_passed',
)
BUNDLE_FIELDS = {'schema', 'claimed_directory_lineage_id',
                 'parent_ec402_signed_pdf_bundle_original', 'epochs'}
EPOCH_FIELDS = {'epoch_index', 'publishers'}
ROLE_FIELDS = {'publisher_id', 'signed_xml_original'}
CLAIM_ATTRS = {'PublisherId', 'DirectoryLineageId', 'EpochIndex',
               'PublishedUTC', 'SourceSHA256', 'ParentPDFSHA256', 'Encoding'}


def need(test, code, status='invalid_input'):
    if test is not True:
        raise errors.AnchorError('EC403_' + code, status)


def exact(obj, fields, code):
    need(type(obj) is dict and set(obj) == fields,
         code + '_EXACT_FIELDS_REQUIRED', 'permission_denied')


def ref(v):
    return parent.ref(v)


def sha(v):
    return parent.sha(v)


def cdigest(v):
    return parent.cdigest(v)


def _inputs(opts, deriving):
    keys = set((*PARENT_SCALARS, *PARENT_REPEATS, *NEW_SCALARS, *REPEAT_NAMES))
    if not deriving:
        keys.update(AUDIT_ONLY)
    need(set(opts) == keys, 'INCOMPLETE_REAL_EC402_PARENT_AND_XML_ARGUMENTS')
    inherited = {k: opts[k] for k in (*PARENT_SCALARS, *PARENT_REPEATS)}
    parent._inputs(inherited, False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]], opts[NEW_SCALARS[1]],
                           'EC403_XML_ORIGINAL_BUNDLE')
    for k in (*NEW_SCALARS[2:], *(() if deriving else AUDIT_ONLY)):
        need(x509core.valid_sha(opts[k]), 'EXTERNALLY_HELD_XML_SHA_INVALID')
    need(opts[NEW_SCALARS[2]] != opts[NEW_SCALARS[3]],
         'FIRST_A_B_XML_ORIGINAL_SHA_MUST_DIFFER', 'permission_denied')
    n = len(opts['historical_directory_root_shas'])
    need(1 <= n <= 3, 'ONE_TO_THREE_EPOCHS_REQUIRED')
    for k in REPEAT_NAMES:
        vals = opts[k]
        need(type(vals) is list and len(vals) == n,
             'XML_EPOCH_SHA_OR_JOINT_MINIMUM_MISSING')
        if k.startswith('minimum_'):
            need(all(type(v) is int and 0 <= v <= 2 for v in vals),
                 'XML_JOINT_PUBLISHER_FLOOR_INVALID')
        else:
            need(all(x509core.valid_sha(v) for v in vals),
                 'XML_EPOCH_SHA_INVALID')
    return inherited


def _parent_report(report, opts):
    fields = {'schema', 'command', 'status', 'exit_code',
              'offline_unresolved_exit_code', 'verified_live_ec401_report_sha256',
              'verified_live_ec401_inventory_sha256',
              'original_signed_pdf_bundle_sha256',
              'receiver_verified_signed_pdf_inventory_sha256',
              'verified_joint_parent_ocsp_and_signed_pdf_publishers',
              'signed_pdf_epoch_reviews',
              'bounded_local_signed_pdf_and_real_ec401_parent_consistency',
              'sender_origin_path_required_or_read',
              'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
              *parent.FLAGS, *parent.NEGATIVES}
    n = len(opts['historical_directory_root_shas'])
    need(type(report) is dict and set(report) == fields and
         report.get('schema') == parent.RESULT_SCHEMA and
         report.get('command') == 'audit-historical-ec339-signed-pdf' and
         report.get('exit_code') == report.get('offline_unresolved_exit_code') == 2 and
         report.get('original_signed_pdf_bundle_sha256') == opts[parent.NEW_SCALARS[1]] and
         report.get('receiver_verified_signed_pdf_inventory_sha256') == opts[parent.AUDIT_ONLY[0]] and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         all(x509core.valid_sha(report.get(k)) for k in (
             'verified_live_ec401_report_sha256',
             'verified_live_ec401_inventory_sha256')) and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         all(report[k] is True for k in parent.FLAGS[-3:]) and
         report.get('bounded_local_signed_pdf_and_real_ec401_parent_consistency') is
             (not any(report[k] for k in parent.FLAGS[:4])) and
         report.get('status') == next((parent.OUTCOMES[i] for i, k in enumerate(parent.FLAGS)
                                       if report[k]), parent.OUTCOMES[-1]) + '_unresolved',
         'UNCHANGED_REAL_EC402_PARENT_STATUS_SHA_OR_FLAGS_INVALID', 'unavailable')
    rows = report.get('signed_pdf_epoch_reviews')
    expected = {'epoch_index', 'verified_actual_signed_pdf_count',
                'joint_verified_signed_pdf_and_ocsp_count',
                'signed_pdf_epoch_inventory_sha256', 'genuine_parent_joint_ocsp_count'}
    need(type(rows) is list and len(rows) == n and all(
         type(row) is dict and set(row) == expected and
         type(row['epoch_index']) is int and row['epoch_index'] == i and
         all(type(row[k]) is int and 0 <= row[k] <= 2 for k in (
             'verified_actual_signed_pdf_count', 'joint_verified_signed_pdf_and_ocsp_count',
             'genuine_parent_joint_ocsp_count')) and
         row['joint_verified_signed_pdf_and_ocsp_count'] <= row['verified_actual_signed_pdf_count'] and
         x509core.valid_sha(row['signed_pdf_epoch_inventory_sha256'])
         for i, row in enumerate(rows)) and
         type(report.get('verified_joint_parent_ocsp_and_signed_pdf_publishers')) is int and
         report['verified_joint_parent_ocsp_and_signed_pdf_publishers'] == sum(
             row['joint_verified_signed_pdf_and_ocsp_count'] for row in rows),
         'REAL_EC402_PARENT_EPOCH_OR_JOINT_COUNTS_INVALID', 'unavailable')
    return cdigest(report)


def _base64(text, max_encoded, code):
    need(type(text) is str and 0 < len(text) <= max_encoded and
         text.isascii() and not any(c.isspace() for c in text),
         code + '_BOUNDED_CANONICAL_BASE64_REQUIRED', 'permission_denied')
    try:
        decoded = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise errors.AnchorError('EC403_' + code + '_BASE64_INVALID',
                                 'permission_denied') from exc
    need(base64.b64encode(decoded).decode('ascii') == text,
         code + '_NONCANONICAL_BASE64', 'permission_denied')
    return decoded


def _verify_xml(original, role, chain, source_bytes, source_sha, pdf_sha,
                published_utc, lineage, epoch_index, read):
    try:
        from lxml import etree
    except ImportError as exc:
        raise errors.AnchorError('EC403_LXML_NOT_INSTALLED', 'unavailable') from exc
    raw = read(original, 'ec403_read_actual_original_xmlsig_bytes', MAX_XML)
    need(raw.lstrip().startswith(b'<') and not raw.startswith(b'\xef\xbb\xbf'),
         'XML_ORIGINAL_UTF8_ENCODING_REQUIRED', 'permission_denied')
    try:
        parser = etree.XMLParser(resolve_entities=False, load_dtd=False,
                                 no_network=True, huge_tree=False,
                                 remove_comments=False, remove_pis=False,
                                 recover=False)
        tree = etree.ElementTree(etree.fromstring(raw, parser=parser))
        root = tree.getroot()
        info = tree.docinfo
        need(info.doctype == '' and info.internalDTD is None and
             info.externalDTD is None and
             info.xml_version == '1.0' and info.encoding.upper() == 'UTF-8' and
             root.getprevious() is None and root.getnext() is None,
             'XML_DTD_OR_NON_UTF8_OR_OUTSIDE_ROOT_NODES_FORBIDDEN',
             'permission_denied')
        # The deliberately small grammar cannot contain any unsigned nested
        # signatures, alternative ID lookups, comments, XSLT, XPath or entity.
        elements = list(root.iter())
        need(len(elements) == 16 and all(type(node) is etree._Element for node in elements),
             'XML_EXACT_SIGNATURE_ELEMENT_GRAMMAR_REQUIRED', 'permission_denied')
        def tag(name):
            return '{%s}%s' % (NS, name)
        def child(node, expected, attributes=None):
            need(node.tag == tag(expected) and
                 (attributes is None or set(node.attrib) == attributes),
                 'XML_UNEXPECTED_TAG_OR_ATTRIBUTE_' + expected.upper(),
                 'permission_denied')
        child(root, 'Signature', set())
        need(len(root) == 4 and all(n.tail is None or not n.tail.strip() for n in root),
             'XML_SIGNATURE_FOUR_EXACT_CHILDREN_REQUIRED', 'permission_denied')
        signed_info, sig_value, key_info, obj = root
        child(signed_info, 'SignedInfo', set())
        child(sig_value, 'SignatureValue', set())
        child(key_info, 'KeyInfo', set())
        child(obj, 'Object', {'Id'})
        need(obj.get('Id') == OBJECT_ID and len(obj) == 1 and
             len(signed_info) == 3 and len(key_info) == 1,
             'XML_SINGLE_ID_AND_REFERENCE_GRAMMAR_REQUIRED', 'permission_denied')
        canon, sig_method, reference = signed_info
        child(canon, 'CanonicalizationMethod', {'Algorithm'})
        child(sig_method, 'SignatureMethod', {'Algorithm'})
        child(reference, 'Reference', {'URI'})
        need(canon.get('Algorithm') == C14N and reference.get('URI') == '#' + OBJECT_ID and
             len(reference) == 3, 'XML_ONLY_EXCLUSIVE_C14N_LOCAL_REFERENCE_ALLOWED',
             'permission_denied')
        transforms, digest_method, digest_value = reference
        child(transforms, 'Transforms', set())
        child(digest_method, 'DigestMethod', {'Algorithm'})
        child(digest_value, 'DigestValue', set())
        need(len(transforms) == 1 and digest_method.get('Algorithm') == SHA256_URI,
             'XML_EXACT_ONE_STRONG_REFERENCE_DIGEST_REQUIRED', 'permission_denied')
        transform = transforms[0]
        child(transform, 'Transform', {'Algorithm'})
        need(transform.get('Algorithm') == C14N and len(transform) == 0,
             'XML_ONLY_EXCLUSIVE_CANONICALIZATION_TRANSFORM_ALLOWED',
             'permission_denied')
        x509_data = key_info[0]
        child(x509_data, 'X509Data', set())
        need(len(x509_data) == 1, 'XML_EXACT_ONE_PINNED_X509_CERT_REQUIRED',
             'permission_denied')
        cert_node = x509_data[0]
        child(cert_node, 'X509Certificate', set())
        need(len(cert_node) == 0, 'XML_CERTIFICATE_MUST_BE_TEXT', 'permission_denied')
        claim = obj[0]
        need(claim.tag == '{%s}GazetteClaim' % CNS and
             set(claim.attrib) == CLAIM_ATTRS and len(claim) == 1 and
             (claim.text is None or not claim.text.strip()),
             'XML_SIGNED_CES_CLAIM_EXACT_ATTRIBUTES_REQUIRED', 'permission_denied')
        source_node = claim[0]
        need(source_node.tag == '{%s}SourceBytes' % CNS and
             not source_node.attrib and len(source_node) == 0,
             'XML_ONE_EMBEDDED_SOURCE_BYTES_REQUIRED', 'permission_denied')
        # No signed value is obtained via XPath/ID heuristics. Exactly one
        # fixed Reference URI selects the one fixed Object in the one Signature.
        need(claim.get('PublisherId') == role and
             claim.get('DirectoryLineageId') == lineage and
             claim.get('EpochIndex') == str(epoch_index) and
             claim.get('PublishedUTC') == published_utc and
             claim.get('SourceSHA256') == source_sha and
             claim.get('ParentPDFSHA256') == pdf_sha and
             claim.get('Encoding') == 'base64',
             'XML_SIGNED_CLAIM_NOT_ACTUAL_PARENT_ROLE_TIME_OR_ORIGINALS',
             'permission_denied')
        source = _base64(source_node.text, 4 * ((len(source_bytes) + 2)//3),
                         'XML_EMBEDDED_GAZETTE')
        need(source == source_bytes and sha(source) == source_sha,
             'XML_EMBEDDED_SOURCE_DIFFERS_FROM_GENUINE_EC398_BYTES',
             'permission_denied')
        cert_der = _base64(cert_node.text, MAX_CERT_B64, 'XML_PINNED_CERTIFICATE')
        need(sha(cert_der) == chain['refs'][0]['sha256'] and
             cert_der == chain['certs'][0].public_bytes(serialization.Encoding.DER),
             'XML_SIGNER_CERT_NOT_REAL_EXTERNAL_EC399_LEAF', 'permission_denied')
        # Restrict all unsigned text and attributes before C14N to make the
        # accepted XML profile easy to audit and resistant to wrapping.
        text_nodes = {sig_value, digest_value, cert_node, source_node}
        for node in elements:
            if node not in text_nodes and node is not claim:
                need(node.text is None or not node.text.strip(),
                     'XML_NONLEAF_MIXED_CONTENT_FORBIDDEN', 'permission_denied')
            need(node.tail is None or not node.tail.strip(),
                 'XML_MIXED_CONTENT_TAIL_FORBIDDEN', 'permission_denied')
        obj_bytes = etree.tostring(obj, method='c14n', exclusive=True,
                                   with_comments=False)
        signed_bytes = etree.tostring(signed_info, method='c14n', exclusive=True,
                                      with_comments=False)
        digest = _base64(digest_value.text, 44, 'XML_REFERENCE_DIGEST')
        need(len(digest) == 32 and digest == hashlib.sha256(obj_bytes).digest(),
             'XML_REFERENCE_DIGEST_DOES_NOT_MATCH_EXACT_OBJECT', 'permission_denied')
        signature = _base64(sig_value.text, MAX_SIGNATURE_B64,
                            'XML_SIGNATURE_VALUE')
        pub = chain['certs'][0].public_key()
        method = sig_method.get('Algorithm')
        try:
            if method == METHOD_ED25519 and isinstance(pub, ed25519.Ed25519PublicKey):
                need(len(signature) == 64, 'ED25519_SIGNATURE_LENGTH_INVALID',
                     'permission_denied')
                pub.verify(signature, signed_bytes)
            elif method in (METHOD_P256, METHOD_P384) and isinstance(pub, ec.EllipticCurvePublicKey):
                curve = ec.SECP256R1 if method == METHOD_P256 else ec.SECP384R1
                need(isinstance(pub.curve, curve) and len(signature) == (64 if method == METHOD_P256 else 96),
                     'XML_ECDSA_CURVE_OR_RAW_RS_LENGTH_INVALID', 'permission_denied')
                half = len(signature) // 2
                r, s = (int.from_bytes(signature[:half], 'big'),
                        int.from_bytes(signature[half:], 'big'))
                need(r != 0 and s != 0, 'XML_ECDSA_RS_ZERO_INVALID', 'permission_denied')
                der = utils.encode_dss_signature(r, s)
                pub.verify(der, signed_bytes,
                           ec.ECDSA(hashes.SHA256() if method == METHOD_P256 else hashes.SHA384()))
            elif method == METHOD_RSA and isinstance(pub, rsa.RSAPublicKey):
                need(2048 <= pub.key_size <= 8192 and pub.public_numbers().e == 65537 and
                     len(signature) == (pub.key_size + 7) // 8,
                     'XML_RSA_PUBLIC_KEY_OR_SIGNATURE_WEAK', 'permission_denied')
                pub.verify(signature, signed_bytes, padding.PKCS1v15(), hashes.SHA256())
            else:
                need(False, 'XML_UNSUPPORTED_SIGNATURE_METHOD_OR_SIGNER_KEY',
                     'permission_denied')
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise errors.AnchorError('EC403_REAL_XML_SIGNATURE_CRYPTOGRAPHY_INVALID',
                                     'permission_denied') from exc
        return {'signed_xml_original_sha256': original['sha256'],
                'source_ec398_original_sha256': source_sha,
                'bound_parent_ec402_pdf_original_sha256': pdf_sha,
                'pinned_publisher_leaf_der_sha256': chain['refs'][0]['sha256'],
                'exclusive_c14n_signed_info_sha256': sha(signed_bytes),
                'exclusive_c14n_referenced_object_sha256': sha(obj_bytes),
                'signature_method_uri': method,
                'actual_xmldsig_signature_and_reference_verified': True,
                'exact_real_ec398_original_gazette_bytes_embedded': True}
    except errors.AnchorError:
        raise
    except (etree.XMLSyntaxError, etree.LxmlError, ValueError, TypeError,
            AttributeError, KeyError, IndexError, UnicodeError, OverflowError,
            RecursionError, OSError) as exc:
        raise errors.AnchorError('EC403_XML_STRUCTURE_OR_CANONICALIZATION_INVALID',
                                 'permission_denied') from exc


def _engine(deriving, **opts):
    inherited = _inputs(opts, deriving)
    live = parent.audit(**inherited)  # PRODUCTION: unchanged, real EC402/401/... chain
    live_sha = _parent_report(live, opts)
    n = len(opts['historical_directory_root_shas'])
    lineage = opts['claimed_historical_directory_lineage_id']
    read, doc, late = parent.parent.parent.parent.parent.parent.parent.parent.prior._readers()
    b403 = {'path': opts[NEW_SCALARS[0]], 'sha256': opts[NEW_SCALARS[1]]}
    b402 = {'path': opts[parent.NEW_SCALARS[0]], 'sha256': opts[parent.NEW_SCALARS[1]]}
    b401 = {'path': opts[parent.parent.NEW_SCALARS[0]], 'sha256': opts[parent.parent.NEW_SCALARS[1]]}
    b400 = {'path': opts[parent.parent.parent.NEW_SCALARS[0]],
            'sha256': opts[parent.parent.parent.NEW_SCALARS[1]]}
    b399 = {'path': opts[x509core.NEW_SCALARS[0]], 'sha256': opts[x509core.NEW_SCALARS[1]]}
    b398 = {'path': opts[gazette.NEW_SCALARS[0]], 'sha256': opts[gazette.NEW_SCALARS[1]]}
    bundle = doc(b403, 'ec403_actual_original_xml_bundle', MAX_BUNDLE)
    exact(bundle, BUNDLE_FIELDS, 'SIGNED_XML_BUNDLE')
    need(bundle['schema'] == BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id'] == lineage and
         bundle['parent_ec402_signed_pdf_bundle_original'] == b402 and
         type(bundle['epochs']) is list and len(bundle['epochs']) == n,
         'XML_BUNDLE_PARENT_PDF_OR_EPOCH_LINK_INVALID', 'permission_denied')
    p402 = doc(b402, 'ec403_reopen_genuine_ec402_signed_pdf_bundle', parent.MAX_BUNDLE)
    p401 = doc(b401, 'ec403_reopen_genuine_ec401_ocsp_bundle', parent.parent.MAX_BUNDLE)
    p400 = doc(b400, 'ec403_reopen_genuine_ec400_cms_bundle', parent.parent.parent.MAX_BUNDLE)
    p399 = doc(b399, 'ec403_reopen_genuine_ec399_certificate_bundle', x509core.MAX_BUNDLE)
    p398 = doc(b398, 'ec403_reopen_genuine_ec398_gazette_bundle', gazette.MAX_BUNDLE)
    for item, fields, schema in (
        (p402, parent.BUNDLE_FIELDS, parent.BUNDLE_SCHEMA),
        (p401, parent.parent.BUNDLE_FIELDS, parent.parent.BUNDLE_SCHEMA),
        (p400, parent.parent.parent.BUNDLE_FIELDS, parent.parent.parent.BUNDLE_SCHEMA),
        (p399, x509core.BUNDLE_FIELDS, x509core.BUNDLE_SCHEMA),
        (p398, gazette.BUNDLE_FIELDS, gazette.BUNDLE_SCHEMA),
    ):
        exact(item, fields, 'REOPEN_REAL_PARENT_BUNDLE')
        need(item['schema'] == schema and
             item['claimed_directory_lineage_id'] == lineage and
             len(item['epochs']) == n, 'REOPEN_REAL_PARENT_EPOCHS_INVALID',
             'permission_denied')
    need(p402['parent_ec401_issuer_ocsp_bundle_original'] == b401 and
         p401['parent_ec400_native_cms_bundle_original'] == b400 and
         p400['parent_ec399_official_certificate_bundle_original'] == b399 and
         p399['parent_ec398_external_notice_bundle_original'] == b398,
         'XML_REAL_PARENT_SHA_LINKS_DISAGREE', 'permission_denied')
    rr = ref(p399['outside_publisher_roster_original'])
    roster = doc(rr, 'ec403_reopen_true_issuer_publisher_roster', x509core.MAX_ROSTER)
    exact(roster, x509core.ROSTER_FIELDS, 'EC399_ORIGINAL_ISSUER_ROSTER')
    need(roster['schema'] == x509core.ROSTER_SCHEMA and
         roster['claimed_directory_lineage_id'] == lineage and
         rr['sha256'] == opts[x509core.NEW_SCALARS[2]] and
         len(roster['publishers']) == 2,
         'REAL_EC399_INDEPENDENT_ROSTER_PIN_INVALID', 'permission_denied')
    chains = [x509core._chain(role, opts, read) for role in roster['publishers']]
    ids = [chain['role']['publisher_id'] for chain in chains]
    need(len(set(ids)) == 2 and len({c['role']['site_id'] for c in chains}) == 2 and
         all(chains[i]['refs'][-1]['sha256'] == opts[x509core.NEW_SCALARS[3+i]] and
             chains[i]['spkis'][0] == opts[x509core.NEW_SCALARS[5+i]]
             for i in range(2)),
         'XML_CHAIN_NOT_TWO_REAL_EXTERNALLY_PINNED_EC399_PUBLISHERS',
         'permission_denied')
    nr = ref(p398['outside_notice_roster_original'])
    notice_roster = doc(nr, 'ec403_reopen_true_ec398_notice_registrar_roster',
                        gazette.MAX_ROSTER)
    protected = {b['path'] for b in (b403, b402, b401, b400, b399, b398, rr, nr)}
    for value in (p402, p401, p400, p399, p398, roster, notice_roster):
        gazette._collect_sources(value, protected)
    # Reopen the same three deep inherited bundles EC402 uses for alias defense.
    p397r = ref(p398['parent_ec397_publication_bundle_original'])
    p397 = doc(p397r, 'ec403_reopen_real_ec397', gazette.parent.MAX_BUNDLE)
    p396r = ref(p397['parent_ec396_public_integrity_bundle_original'])
    p396 = doc(p396r, 'ec403_reopen_real_ec396', gazette.parent.parent.MAX_BUNDLE)
    p395r = ref(p396['parent_ec395_credential_gossip_bundle_original'])
    p395 = doc(p395r, 'ec403_reopen_real_ec395', gazette.parent.parent.parent.MAX_BUNDLE)
    for pathref, value in ((p397r, p397), (p396r, p396), (p395r, p395)):
        protected.add(pathref['path'])
        gazette._collect_sources(value, protected)
    for item, name in ((p397, 'outside_observer_roster_original'),
                       (p396, 'outside_authority_roster_original'),
                       (p395, 'external_role_roster_original')):
        if item.get(name) is not None:
            r = ref(item[name])
            protected.add(r['path'])
            gazette._collect_sources(doc(r, 'ec403_true_deep_ancestral_roster',
                                         gazette.MAX_ROSTER), protected)
    protected.update(r['path'] for c in chains for r in c['refs'])
    used = set(protected)
    flags = {k: False for k in FLAGS}
    flags[FLAGS[0]] = (
        not live['bounded_local_signed_pdf_and_real_ec401_parent_consistency'] or
        any(row['joint_verified_signed_pdf_and_ocsp_count'] != 2
            for row in live['signed_pdf_epoch_reviews']))
    reviews, epoch_inv, first = [], [], {}
    total = 0
    for i, epoch in enumerate(bundle['epochs']):
        exact(epoch, EPOCH_FIELDS, 'XML_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index'] == i and
             type(epoch['publishers']) is list and len(epoch['publishers']) == 2,
             'XML_EPOCH_EXACT_TWO_PUBLISHERS_REQUIRED', 'permission_denied')
        parent_epoch = p402['epochs'][i]
        exact(parent_epoch, parent.EPOCH_FIELDS, 'PARENT_EC402_EPOCH')
        need(type(parent_epoch['epoch_index']) is int and
             parent_epoch['epoch_index'] == i and
             type(parent_epoch['publishers']) is list and
             len(parent_epoch['publishers']) == 2,
             'REAL_PARENT_PDF_ROLE_COUNT_OR_ORDER_INVALID', 'permission_denied')
        pdf_roles = {}
        for pe in parent_epoch['publishers']:
            exact(pe, parent.PUBLISHER_FIELDS, 'PARENT_EC402_PDF_PUBLISHER')
            need(pe['publisher_id'] in ids and pe['publisher_id'] not in pdf_roles,
                 'REAL_PARENT_SIGNED_PDF_ROLE_INVALID', 'permission_denied')
            pdf_roles[pe['publisher_id']] = ref(pe['signed_pdf_original']) if pe['signed_pdf_original'] else None
        gazette_epoch = p398['epochs'][i]
        exact(gazette_epoch, gazette.EPOCH_FIELDS, 'REAL_EC398_SOURCE_EPOCH')
        need(type(gazette_epoch['epoch_index']) is int and
             gazette_epoch['epoch_index'] == i,
             'REAL_EC398_SOURCE_EPOCH_ORDER_INVALID', 'permission_denied')
        sr = ref(gazette_epoch['source_notice_original']) if gazette_epoch['source_notice_original'] else None
        stamp = gazette_epoch['notice']
        exact(stamp, gazette.STAMP_FIELDS, 'GENUINE_EC398_SIGNED_STAMP')
        nsr = ref(stamp['signed_original']) if stamp['signed_original'] else None
        need(sr is not None and nsr is not None,
             'XML_REQUIRES_ACTUAL_EC398_SIGNED_NOTICE_AND_OPAQUE_SOURCE',
             'permission_denied')
        _, claim, sig = gazette._signed(
            nsr, read, gazette.NOTICE_SCHEMA, gazette.NOTICE_CLAIM,
            gazette.NOTICE_CLAIM_FIELDS, 'EC403_RECHECK_GENUINE_EC398_REGISTRAR')
        gazette._sign(notice_roster['registrar'], sig,
                      gazette.NOTICE_DOMAIN, claim,
                      'EC403_REVERIFY_ACTUAL_EC398_REGISTRAR_SIGNATURE')
        need(claim['directory_lineage_id'] == lineage and
             type(claim['epoch_index']) is int and claim['epoch_index'] == i and
             claim['source_notice_original_sha256'] == sr['sha256'],
             'XML_SIGNED_PARENT_NOTICE_SOURCE_MISMATCH', 'permission_denied')
        published = x509core._utc(claim['claimed_published_utc']).isoformat().replace('+00:00', 'Z')
        source = read(sr, 'ec403_real_parent_ec398_source_original', gazette.MAX_SOURCE)
        seen, members, verified = set(), [], 0
        for entry in epoch['publishers']:
            exact(entry, ROLE_FIELDS, 'SIGNED_XML_PUBLISHER')
            role = entry['publisher_id']
            need(role in ids and role not in seen,
                 'XML_ROLE_UNKNOWN_OR_REPEATED', 'permission_denied')
            seen.add(role)
            xmlref = ref(entry['signed_xml_original']) if entry['signed_xml_original'] else None
            pdfref = pdf_roles[role]
            if xmlref is None:
                flags[FLAGS[2]] = True
                member = {'publisher_id': role,
                          'signed_xml_original_sha256': None,
                          'verified_original_xmlsig': None}
            else:
                need(pdfref is not None and xmlref['path'] not in used and
                     xmlref['path'] not in late,
                     'XML_ORIGINAL_ALIASES_ANCESTOR_OR_HAS_NO_PARENT_PDF',
                     'permission_denied')
                used.add(xmlref['path'])
                chain = next(c for c in chains if c['role']['publisher_id'] == role)
                proof = _verify_xml(xmlref, role, chain, source, sr['sha256'],
                                    pdfref['sha256'], published, lineage, i, read)
                member = {'publisher_id': role,
                          'signed_xml_original_sha256': xmlref['sha256'],
                          'verified_original_xmlsig': proof}
                verified += 1
            if i == 0:
                first[role] = member['signed_xml_original_sha256']
            members.append(member)
        need(seen == set(ids) and set(pdf_roles) == set(ids),
             'XML_MISSING_ORIGINAL_REAL_PUBLISHER', 'permission_denied')
        members.sort(key=lambda r: r['publisher_id'])
        joint = (verified if live['bounded_local_signed_pdf_and_real_ec401_parent_consistency']
                 and live['signed_pdf_epoch_reviews'][i][
                     'joint_verified_signed_pdf_and_ocsp_count'] == 2 else 0)
        if joint != 2:
            flags[FLAGS[3]] = True
        invrow = {'epoch_index': i, 'publishers': members,
                  'verified_original_xmlsig_count': verified,
                  'joint_verified_xmlsig_and_parent_pdf_count': joint}
        digest = cdigest(invrow)
        if digest != opts[REPEAT_NAMES[0]][i] or joint < opts[REPEAT_NAMES[1]][i]:
            flags[FLAGS[1]] = True
        epoch_inv.append(invrow)
        reviews.append({'epoch_index': i, 'actual_verified_xmlsig_count': verified,
                        'joint_verified_xmlsig_and_parent_pdf_count': joint,
                        'original_xmlsig_epoch_inventory_sha256': digest,
                        'real_ec402_parent_joint_pdf_ocsp_count': live[
                            'signed_pdf_epoch_reviews'][i][
                                'joint_verified_signed_pdf_and_ocsp_count']})
        total += joint
    need(len(first) == 2 and all(first.get(role) is not None for role in ids),
         'FIRST_TWO_PINNED_TRUE_XML_ORIGINALS_REQUIRED', 'permission_denied')
    if (first[ids[0]], first[ids[1]]) != (
            opts[NEW_SCALARS[2]], opts[NEW_SCALARS[3]]):
        flags[FLAGS[1]] = True
    inventory = {'schema': INVENTORY_SCHEMA,
                 'directory_lineage_id': lineage,
                 'verified_real_ec402_report_sha256': live_sha,
                 'verified_real_ec402_inventory_sha256': live[
                     'receiver_verified_signed_pdf_inventory_sha256'],
                 'parent_original_signed_pdf_bundle_sha256': b402['sha256'],
                 'original_xmldsig_bundle_sha256': b403['sha256'],
                 'outside_retained_first_xml_original_shas': [
                     opts[NEW_SCALARS[2]], opts[NEW_SCALARS[3]]],
                 'epochs': epoch_inv}
    inventory_sha = cdigest(inventory)
    if not deriving and inventory_sha != opts[AUDIT_ONLY[0]]:
        flags[FLAGS[1]] = True
    # The earlier readers open originals read-only with content SHA checks.
    # Close the TOCTOU window as far as this Python readback profile allows.
    for path, (digest, cap) in late.items():
        raw = io._read({'path': path, 'sha256': digest},
                       'ec403_final_original_byte_readback', cap, {}, {}, set())
        need(sha(raw) == digest, 'XML_OR_PARENT_ORIGINAL_MUTATED', 'permission_denied')
    for key in FLAGS[-3:]:
        flags[key] = True
    return {'schema': DERIVE_SCHEMA if deriving else RESULT_SCHEMA,
            'command': ('derive-historical-ec339-original-xmldsig-inventory'
                        if deriving else 'audit-historical-ec339-original-xmldsig'),
            'status': next((OUTCOMES[i] for i, key in enumerate(FLAGS) if flags[key]),
                           OUTCOMES[-1]) + '_unresolved',
            'exit_code': 2, 'offline_unresolved_exit_code': 2,
            'verified_live_ec402_report_sha256': live_sha,
            'verified_live_ec402_inventory_sha256': live[
                'receiver_verified_signed_pdf_inventory_sha256'],
            'original_xmldsig_bundle_sha256': b403['sha256'],
            'receiver_verified_original_xmldsig_inventory_sha256': inventory_sha,
            'verified_joint_parent_pdf_and_xmlsig_publishers': total,
            'original_xmldsig_epoch_reviews': reviews,
            'bounded_local_original_xmldsig_and_real_ec402_parent_consistency':
                not any(flags[k] for k in FLAGS[:4]),
            'sender_origin_path_required_or_read': False,
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed': False,
            **flags, **{k: False for k in NEGATIVES},
            **({'unsigned_original_xmldsig_evidence_inventory': inventory} if deriving else {})}


def derive_inventory(**opts):
    return _engine(True, **opts)


def audit(**opts):
    return _engine(False, **opts)
