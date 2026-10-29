#!/usr/bin/env python3
"""EC402 read-only signed PDF/CMS originals, chained to the real EC401 audit.

A *restricted* PDF CMS/ByteRange original verifier, not a general PDF renderer,
full ETSI PAdES conformity evaluator or official state/legal trust provider.
The unchanged EC401->EC400->EC399->EC398->... audits are always run in
production, before any EC402 credit. No network, PDF rewriting or signing.
"""
from __future__ import annotations

from io import BytesIO
import hashlib
import re

from cryptography.hazmat.primitives import serialization
from delivery_anchor import anchor as errors
from historical_authority import authority_archive as io
from ocsp_evidence import protocol as parent

RESULT_SCHEMA = 'ces.ec402.signed_pdf_original_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec402.unsigned_signed_pdf_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec402.signed_pdf_original_denial.v1'
BUNDLE_SCHEMA = 'ces.ec402.signed_pdf_originals_bundle.v1'
INVENTORY_SCHEMA = 'ces.ec402.unsigned_signed_pdf_inventory.v1'
MAX_BUNDLE = 140_000
MAX_PDF = 18_000_000
MAX_SIGNATURE_GAP = 1_200_000
ATTACHMENT_NAME = 'CES_EC398_GAZETTE_ORIGINAL.bin'
PARENT_SCALARS = (*parent.PARENT_SCALARS, *parent.NEW_SCALARS, *parent.AUDIT_ONLY)
PARENT_REPEATS = (*parent.PARENT_REPEATS, *parent.REPEAT_NAMES)
NEW_SCALARS = (
    'historical_ec339_signed_pdf_bundle_file',
    'expected_historical_ec339_signed_pdf_bundle_sha256',
    'expected_outside_retained_ec402_first_a_pdf_sha256',
    'expected_outside_retained_ec402_first_b_pdf_sha256',
)
AUDIT_ONLY = ('expected_retained_historical_ec339_signed_pdf_inventory_sha256',)
NEW_REPEATS = (
    ('historical_ec339_signed_pdf_epoch_inventory_shas',
     '--historical-ec339-signed-pdf-epoch-inventory-sha256'),
    ('minimum_historical_ec339_joint_signed_pdf_publisher_counts',
     '--minimum-historical-ec339-joint-signed-pdf-publisher-count'),
)
REPEAT_NAMES = tuple(k for k, _ in NEW_REPEATS)
FLAGS = (
    'inherited_real_ec401_ocsp_cms_x509_crl_parent_disputed',
    'outside_original_pdf_epoch_or_whole_inventory_or_count_pin_disagrees',
    'one_or_more_original_publisher_signed_pdfs_missing',
    'joint_two_publisher_ocsp_and_signed_pdf_coverage_incomplete',
    'actual_official_government_or_court_pdf_issuer_not_proven',
    'complete_etsi_pades_qualified_timestamp_and_visible_document_semantics_not_proven',
    'prior_public_independent_archive_worm_global_revocation_and_acceptance_not_proven',
)
OUTCOMES = (
    'ec402_inherited_real_ec401_parent_crypto_or_original_disputed',
    'ec402_independently_retained_pdf_hash_or_joint_floor_disagrees',
    'ec402_original_signed_pdf_missing',
    'ec402_joint_parent_ocsp_and_signed_pdf_coverage_incomplete',
    'ec402_official_legally_authorized_original_issuer_not_established',
    'ec402_full_pades_qualified_timestamp_or_pdf_visual_truth_not_established',
    'ec402_pre_dispute_custody_worm_global_revocation_acceptance_not_established',
)
NEGATIVES = (
    'pdf_native_cms_signature_alone_proves_official_issuer_or_legal_authority',
    'pdf_embedded_original_implies_visual_content_or_page_semantics_match_source',
    'signing_time_claim_is_an_independent_qualified_legal_timestamp',
    'a_locally_read_original_proves_pre_dispute_independent_public_availability',
    'restricted_pdf_cms_equals_full_etsi_pades_b_t_lt_lta_conformance',
    'pdf_cms_repairs_failed_ec401_ocsp_ec399_crl_or_ec400_cms',
    'locally_verified_two_pdfs_prove_complete_global_revocation_or_fork_census',
    'receiver_created_certificates_private_signatures_network_or_provider_writes',
    'receiver_modified_original_pdf_ps1_cas_worm_git_or_ci_state',
    'full_unmocked_external_history_native_ps7_or_user_acceptance_passed',
)
BUNDLE_FIELDS = {'schema', 'claimed_directory_lineage_id',
                 'parent_ec401_issuer_ocsp_bundle_original', 'epochs'}
EPOCH_FIELDS = {'epoch_index', 'publishers'}
PUBLISHER_FIELDS = {'publisher_id', 'signed_pdf_original'}


def need(condition, code, status='invalid_input'):
    if condition is not True:
        raise errors.AnchorError('EC402_' + code, status)


def exact(obj, keys, code):
    need(type(obj) is dict and set(obj) == keys, code + '_EXACT_FIELDS_REQUIRED',
         'permission_denied')


def ref(obj):
    return parent.ref(obj)


def sha(raw):
    return parent.sha(raw)


def cdigest(obj):
    return parent.cdigest(obj)


def _inputs(opts, deriving):
    keys = set((*PARENT_SCALARS, *PARENT_REPEATS, *NEW_SCALARS, *REPEAT_NAMES))
    if not deriving:
        keys.update(AUDIT_ONLY)
    need(set(opts) == keys, 'INCOMPLETE_PARENT_AND_SIGNED_PDF_ARGUMENTS')
    inherited = {key: opts[key] for key in (*PARENT_SCALARS, *PARENT_REPEATS)}
    parent._inputs(inherited, False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]], opts[NEW_SCALARS[1]],
                           'EC402_SIGNED_PDF_BUNDLE')
    for key in (*NEW_SCALARS[2:], *(() if deriving else AUDIT_ONLY)):
        need(parent.parent.parent.parent.valid_sha(opts[key]),
             'EXTERNAL_SIGNED_PDF_SHA_INVALID')
    need(opts[NEW_SCALARS[2]] != opts[NEW_SCALARS[3]],
         'FIRST_TWO_PDF_ORIGINALS_MUST_BE_DIFFERENT', 'permission_denied')
    n = len(opts['historical_directory_root_shas'])
    need(1 <= n <= 3, 'ONE_TO_THREE_EPOCHS_REQUIRED')
    for key in REPEAT_NAMES:
        values = opts[key]
        need(type(values) is list and len(values) == n,
             'PDF_OUTSIDE_EPOCH_PIN_COUNT_INVALID')
        if key.startswith('minimum_'):
            need(all(type(v) is int and 0 <= v <= 2 for v in values),
                 'PDF_JOINT_PUBLISHER_FLOOR_INVALID')
        else:
            need(all(parent.parent.parent.parent.valid_sha(v) for v in values),
                 'PDF_EPOCH_SHA_INVALID')
    return inherited


def _parent_report(report, opts):
    keys = {'schema', 'command', 'status', 'exit_code',
            'offline_unresolved_exit_code', 'verified_live_ec400_report_sha256',
            'verified_live_ec400_inventory_sha256', 'original_ocsp_bundle_sha256',
            'receiver_verified_ocsp_inventory_sha256',
            'verified_joint_parent_cms_crl_and_local_good_ocsp_publishers',
            'ocsp_epoch_reviews', 'bounded_local_issuer_ocsp_and_real_parent_consistency',
            'sender_origin_path_required_or_read',
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
            *parent.FLAGS, *parent.NEGATIVES}
    n = len(opts['historical_directory_root_shas'])
    need(type(report) is dict and set(report) == keys and
         report.get('schema') == parent.RESULT_SCHEMA and
         report.get('command') == 'audit-historical-ec339-issuer-ocsp' and
         report.get('exit_code') == report.get('offline_unresolved_exit_code') == 2 and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         report.get('original_ocsp_bundle_sha256') == opts[parent.NEW_SCALARS[1]] and
         report.get('receiver_verified_ocsp_inventory_sha256') == opts[parent.AUDIT_ONLY[0]] and
         all(parent.parent.parent.parent.valid_sha(report.get(k)) for k in (
             'verified_live_ec400_report_sha256', 'verified_live_ec400_inventory_sha256')) and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         all(report[k] is True for k in parent.FLAGS[-3:]) and
         report.get('bounded_local_issuer_ocsp_and_real_parent_consistency') is
             (not any(report[k] for k in parent.FLAGS[:5])) and
         report.get('status') == next((parent.OUTCOMES[i] for i, k in enumerate(parent.FLAGS)
              if report[k]), parent.OUTCOMES[-1]) + '_unresolved',
         'REAL_EC401_PARENT_STATUS_OR_ORIGINAL_SHA_INVALID', 'unavailable')
    rows = report.get('ocsp_epoch_reviews')
    fields = {'epoch_index', 'joint_verified_ocsp_publisher_count',
              'ocsp_original_inventory_sha256', 'authentic_parent_cms_joint_signer_count'}
    need(type(rows) is list and len(rows) == n and all(
          type(row) is dict and set(row) == fields and
          type(row['epoch_index']) is int and row['epoch_index'] == i and
          type(row['joint_verified_ocsp_publisher_count']) is int and
          0 <= row['joint_verified_ocsp_publisher_count'] <= 2 and
          type(row['authentic_parent_cms_joint_signer_count']) is int and
          row['authentic_parent_cms_joint_signer_count'] in (0, 2) and
          parent.parent.parent.parent.valid_sha(row['ocsp_original_inventory_sha256'])
          for i, row in enumerate(rows)) and
          type(report.get('verified_joint_parent_cms_crl_and_local_good_ocsp_publishers')) is int and
          report['verified_joint_parent_cms_crl_and_local_good_ocsp_publishers'] == sum(
              row['joint_verified_ocsp_publisher_count'] for row in rows),
         'REAL_EC401_PARENT_EPOCHS_OR_COUNTS_INVALID', 'unavailable')
    return cdigest(report)


def _der_with_null_padding(original):
    """A PDF /Contents hex string may zero-pad one DER CMS object, nothing else."""
    need(2 <= len(original) <= MAX_SIGNATURE_GAP and original[0] == 0x30,
         'PDF_CONTENTS_IS_NOT_BOUNDED_DER_CMS', 'permission_denied')
    first = original[1]
    if first < 128:
        length, start = first, 2
    else:
        octets = first & 0x7f
        need(1 <= octets <= 4 and 2 + octets <= len(original),
             'DER_LENGTH_NOT_BOUNDED', 'permission_denied')
        size = original[2:2 + octets]
        length, start = int.from_bytes(size, 'big'), 2 + octets
        need(size[0] != 0 and length >= 128 and
             length >= 1 << (8 * (octets - 1)),
             'DER_LENGTH_NOT_MINIMALLY_ENCODED', 'permission_denied')
    end = start + length
    need(end <= len(original) and all(b == 0 for b in original[end:]),
         'PDF_CONTENTS_HAS_NONZERO_OR_TRUNCATED_CMS_PADDING', 'permission_denied')
    return original[:end]


def _verify_pdf(original, expected_role, chain, source_bytes, source_sha,
                signing_time, read):
    """Verify actual original file bytes, never pypdf's re-serialized bytes."""
    try:
        from pypdf import PdfReader
        from pypdf.errors import PdfReadError
        from pypdf.generic import DictionaryObject
        from asn1crypto import cms, x509 as asn1_x509
        from native_cms import protocol as cms_core
    except ImportError as exc:
        raise errors.AnchorError('EC402_PYPDF_OR_ASN1CRYPTO_NOT_INSTALLED',
                                 'unavailable') from exc
    raw = read(original, 'ec402_actual_original_signed_pdf', MAX_PDF)
    need(raw.startswith(b'%PDF-') and b'%%EOF' in raw[-128:],
         'PDF_ORIGINAL_HEADER_OR_FINAL_EOF_INVALID', 'permission_denied')
    try:
        reader = PdfReader(BytesIO(raw), strict=True)
        need(not reader.is_encrypted, 'ENCRYPTED_PDF_NOT_IN_SUPPORTED_PROFILE',
             'permission_denied')
        root = reader.trailer['/Root'].get_object()
        need('/AcroForm' in root and '/Names' in root and
             '/OpenAction' not in root and '/AA' not in root,
             'PDF_EXPECTED_ACROFORM_ATTACHMENT_AND_NO_ACTIVE_OPEN_ACTION',
             'permission_denied')
        name_tree = root['/Names'].get_object()
        need(set(name_tree) == {'/EmbeddedFiles'},
             'PDF_UNSUPPORTED_ACTIVE_OR_EXTRA_NAME_TREES', 'permission_denied')
        forms = root['/AcroForm'].get_object()
        need('/XFA' not in forms and '/Fields' in forms,
             'PDF_XFA_OR_MISSING_SIGNATURE_FIELDS', 'permission_denied')
        fields = forms['/Fields']
        need(1 <= len(fields) <= 20, 'PDF_FIELD_COUNT_UNSUPPORTED',
             'permission_denied')
        signatures = []
        seen = set()
        def visit(field, inherited=None, depth=0):
            need(depth <= 4, 'PDF_FORM_TREE_DEPTH_UNSUPPORTED', 'permission_denied')
            identity = getattr(field, 'idnum', None)
            if identity is not None:
                need(identity not in seen, 'PDF_FORM_REFERENCE_CYCLE', 'permission_denied')
                seen.add(identity)
            field = field.get_object()
            need(isinstance(field, DictionaryObject), 'PDF_FIELD_NOT_DICTIONARY',
                 'permission_denied')
            kind = field.get('/FT', inherited)
            kids = field.get('/Kids', [])
            if kids:
                need(len(kids) <= 20, 'PDF_FORM_KID_COUNT_UNSUPPORTED',
                     'permission_denied')
                for kid in kids:
                    visit(kid, kind, depth + 1)
            elif str(kind) == '/Sig':
                need('/V' in field, 'PDF_UNSIGNED_SIGNATURE_FIELD',
                     'permission_denied')
                signatures.append(field['/V'].get_object())
        for field in fields:
            visit(field)
        need(len(signatures) == 1, 'PDF_EXACTLY_ONE_SIGNED_FIELD_REQUIRED',
             'permission_denied')
        sig = signatures[0]
        need(isinstance(sig, DictionaryObject) and
             str(sig.get('/Filter')) == '/Adobe.PPKLite' and
             str(sig.get('/SubFilter')) in ('/ETSI.CAdES.detached',
                                           '/adbe.pkcs7.detached') and
             '/ByteRange' in sig and '/Contents' in sig,
             'PDF_SIGNATURE_DICTIONARY_OR_SUBFILTER_UNSUPPORTED',
             'permission_denied')
        ranges = sig['/ByteRange']
        need(len(ranges) == 4 and all(isinstance(v, int) and not isinstance(v, bool) for v in ranges),
             'PDF_BYTERANGE_NOT_FOUR_INTEGERS', 'permission_denied')
        first, left, right, size = (int(v) for v in ranges)
        need(first == 0 and 0 < left < right < len(raw) and
             0 < size and right + size == len(raw) and
             right - left <= MAX_SIGNATURE_GAP * 2 + 2,
             'PDF_BYTERANGE_MUST_COVER_EXACTLY_ALL_ORIGINAL_BYTES',
             'permission_denied')
        gap = raw[left:right]
        need(len(gap) >= 4 and gap[0:1] == b'<' and gap[-1:] == b'>' and
             re.fullmatch(rb'[0-9A-Fa-f]+', gap[1:-1]) is not None and
             (len(gap) - 2) % 2 == 0,
             'PDF_EXCLUDED_REGION_NOT_EXACT_HEX_CONTENTS',
             'permission_denied')
        contents = bytes.fromhex(gap[1:-1].decode('ascii'))
        need(contents == bytes(sig['/Contents']),
             'PDF_PARSED_CONTENTS_DIFFERS_FROM_EXCLUDED_ORIGINAL_BYTES',
             'permission_denied')
        signed_bytes = raw[:left] + raw[right:]
        signed_digest = sha(signed_bytes)
        attachments = list(reader.attachment_list)
        need(len(attachments) == 1 and attachments[0].name == ATTACHMENT_NAME,
             'PDF_MUST_EMBED_EXACTLY_ONE_NAMED_REAL_GAZETTE_SOURCE',
             'permission_denied')
        # Reject compression before decoding the attachment: otherwise a small
        # hostile PDF could inflate an unbounded embedded-file stream in RAM.
        # This intentionally narrows the supported signed-PDF profile.
        attachment_stream = attachments[0]._embedded_file
        need('/Filter' not in attachment_stream and
             len(getattr(attachment_stream, '_data', b'')) <= len(source_bytes),
             'PDF_COMPRESSED_OR_OVERSIZE_EMBEDDED_SOURCE_UNSUPPORTED',
             'permission_denied')
        embedded = attachments[0].content
        need(len(embedded) == len(source_bytes) and embedded == source_bytes and
             sha(embedded) == source_sha,
             'PDF_EMBEDDED_SOURCE_NOT_AUTHENTIC_EC398_ORIGINAL_BYTES',
             'permission_denied')
        der = _der_with_null_padding(contents)
        content = cms.ContentInfo.load(der, strict=True)
        need(content.dump(force=True) == der and
             content['content_type'].native == 'signed_data',
             'PDF_CMS_NOT_CANONICAL_DER_SIGNED_DATA', 'permission_denied')
        signed = content['content']
        need(signed['version'].native in ('v1', 'v3') and
             signed['encap_content_info']['content_type'].native == 'data' and
             signed['encap_content_info']['content'].native is None and
             signed['crls'].native is None and len(signed['signer_infos']) == 1,
             'PDF_EXPECTS_ONE_DETACHED_CMS_SIGNER_AND_NO_UNCHECKED_CRLS',
             'permission_denied')
        signer = signed['signer_infos'][0]
        need(signed['version'].native == signer['version'].native and
             signer['unsigned_attrs'].native is None and
             signer['signed_attrs'].native is not None and
             len(signer['signed_attrs']) == 3 and
             {a['type'].native for a in signer['signed_attrs']} == {
                 'content_type', 'message_digest', 'signing_time'},
             'PDF_CMS_HAS_UNSUPPORTED_ATTRIBUTES_OR_VERSION',
             'permission_denied')
        alg = signer['digest_algorithm']['algorithm'].native
        need(len(signed['digest_algorithms']) == 1 and
             signed['digest_algorithms'][0]['algorithm'].native == alg,
             'PDF_CMS_DIGEST_ALGORITHM_LIST_MISMATCH', 'permission_denied')
        certs = signed['certificates']
        need(certs.native is not None and len(certs) == 1 and
             certs[0].name == 'certificate' and
             sha(certs[0].chosen.dump()) == chain['refs'][0]['sha256'],
             'PDF_CMS_EMBEDDED_CERT_MUST_BE_EXACT_PINNED_PUBLISHER_LEAF',
             'permission_denied')
        cert = chain['certs'][0]
        native = asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
        signature = cms_core._verify_signer(
            signer, [chain], signed_bytes, signing_time,
            {chain['refs'][0]['sha256']: native})
        need(signature['publisher_id'] == expected_role,
             'PDF_CMS_SIGNER_NOT_CLAIMED_PUBLISHER', 'permission_denied')
        return {'signed_pdf_original_sha256': original['sha256'],
                'source_ec398_original_sha256': source_sha,
                'signed_pdf_byterange_content_sha256': signed_digest,
                'pdf_subfilter': str(sig['/SubFilter'])[1:],
                'cms_der_original_sha256': sha(der),
                'signature': signature,
                'actual_pdf_byte_range_and_cms_signature_valid': True,
                'exact_ec398_original_attached': True}
    except errors.AnchorError:
        raise
    except (ValueError, TypeError, KeyError, IndexError, AttributeError,
            OverflowError, RecursionError, OSError, PdfReadError) as exc:
        raise errors.AnchorError('EC402_PDF_STRUCTURE_OR_CMS_INVALID',
                                 'permission_denied') from exc


def _engine(deriving, **opts):
    inherited = _inputs(opts, deriving)
    live = parent.audit(**inherited)  # mandatory unchanged full EC401 -> all ancestors
    live_sha = _parent_report(live, opts)
    n = len(opts['historical_directory_root_shas'])
    lineage = opts['claimed_historical_directory_lineage_id']
    read, doc, late = parent.parent.parent.parent.parent.parent.parent.prior._readers()
    b402 = {'path': opts[NEW_SCALARS[0]], 'sha256': opts[NEW_SCALARS[1]]}
    b401 = {'path': opts[parent.NEW_SCALARS[0]], 'sha256': opts[parent.NEW_SCALARS[1]]}
    b400 = {'path': opts[parent.parent.NEW_SCALARS[0]],
            'sha256': opts[parent.parent.NEW_SCALARS[1]]}
    b399 = {'path': opts[parent.parent.parent.NEW_SCALARS[0]],
            'sha256': opts[parent.parent.parent.NEW_SCALARS[1]]}
    b398 = {'path': opts[parent.parent.parent.parent.NEW_SCALARS[0]],
            'sha256': opts[parent.parent.parent.parent.NEW_SCALARS[1]]}
    bundle = doc(b402, 'ec402_actual_original_pdf_bundle', MAX_BUNDLE)
    exact(bundle, BUNDLE_FIELDS, 'SIGNED_PDF_BUNDLE')
    need(bundle['schema'] == BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id'] == lineage and
         bundle['parent_ec401_issuer_ocsp_bundle_original'] == b401 and
         type(bundle['epochs']) is list and len(bundle['epochs']) == n,
         'PDF_BUNDLE_PARENT_OCSP_OR_EPOCHS_MISMATCH', 'permission_denied')
    p401 = doc(b401, 'ec402_reopen_ec401_real_original', parent.MAX_BUNDLE)
    p400 = doc(b400, 'ec402_reopen_ec400_real_original', parent.parent.MAX_BUNDLE)
    p399 = doc(b399, 'ec402_reopen_ec399_real_original', parent.parent.parent.MAX_BUNDLE)
    p398 = doc(b398, 'ec402_reopen_ec398_real_original', parent.parent.parent.parent.MAX_BUNDLE)
    for value, keys in ((p401, parent.BUNDLE_FIELDS),
                        (p400, parent.parent.BUNDLE_FIELDS),
                        (p399, parent.parent.parent.BUNDLE_FIELDS),
                        (p398, parent.parent.parent.parent.BUNDLE_FIELDS)):
        exact(value, keys, 'REOPEN_AUTHENTIC_PARENT_BUNDLE')
        need(value['claimed_directory_lineage_id'] == lineage and
             len(value['epochs']) == n, 'REOPEN_PARENT_LINEAGE_OR_EPOCHS_INVALID',
             'permission_denied')
    need(p401['schema'] == parent.BUNDLE_SCHEMA and
         p401['parent_ec400_native_cms_bundle_original'] == b400 and
         p400['schema'] == parent.parent.BUNDLE_SCHEMA and
         p400['parent_ec399_official_certificate_bundle_original'] == b399 and
         p399['schema'] == parent.parent.parent.BUNDLE_SCHEMA and
         p399['parent_ec398_external_notice_bundle_original'] == b398 and
         p398['schema'] == parent.parent.parent.parent.BUNDLE_SCHEMA,
         'ORIGINAL_ANCESTOR_CHAIN_SHA_LINK_MISMATCH', 'permission_denied')
    rosterref = ref(p399['outside_publisher_roster_original'])
    roster = doc(rosterref, 'ec402_actual_ec399_issuer_roster',
                 parent.parent.parent.MAX_ROSTER)
    exact(roster, parent.parent.parent.ROSTER_FIELDS, 'PINNED_EC399_PUBLISHER_ROSTER')
    need(roster['schema'] == parent.parent.parent.ROSTER_SCHEMA and
         roster['claimed_directory_lineage_id'] == lineage and
         len(roster['publishers']) == 2 and
         rosterref['sha256'] == opts[parent.parent.parent.NEW_SCALARS[2]],
         'EC399_TWO_REAL_PUBLISHER_ROSTER_INVALID', 'permission_denied')
    chains = [parent.parent.parent._chain(role, opts, read)
              for role in roster['publishers']]
    ids = [c['role']['publisher_id'] for c in chains]
    need(len(set(ids)) == 2 and len({c['role']['site_id'] for c in chains}) == 2 and
         all(chains[i]['refs'][-1]['sha256'] ==
             opts[parent.parent.parent.NEW_SCALARS[3+i]] and
             chains[i]['spkis'][0] == opts[parent.parent.parent.NEW_SCALARS[5+i]]
             for i in range(2)),
         'PDF_SIGNER_ROSTER_NOT_TWO_INDEPENDENT_EXTERNALLY_PINNED_CHAINS',
         'permission_denied')
    notice_roster_ref = ref(p398['outside_notice_roster_original'])
    notice_roster = doc(notice_roster_ref, 'ec402_reopen_ec398_registrar',
                        parent.parent.parent.parent.MAX_ROSTER)
    protected = {v['path'] for v in (b402, b401, b400, b399, b398,
                                    rosterref, notice_roster_ref)}
    for value in (p401, p400, p399, p398, roster, notice_roster):
        parent.parent.parent.parent._collect_sources(value, protected)
    # Preserve EC401's protection against aliasing with deep EC397-EC395 roles.
    p397ref = ref(p398['parent_ec397_publication_bundle_original'])
    p397 = doc(p397ref, 'ec402_reopen_ec397',
               parent.parent.parent.parent.parent.MAX_BUNDLE)
    p396ref = ref(p397['parent_ec396_public_integrity_bundle_original'])
    p396 = doc(p396ref, 'ec402_reopen_ec396',
               parent.parent.parent.parent.parent.parent.MAX_BUNDLE)
    p395ref = ref(p396['parent_ec395_credential_gossip_bundle_original'])
    p395 = doc(p395ref, 'ec402_reopen_ec395',
               parent.parent.parent.parent.parent.parent.parent.MAX_BUNDLE)
    for rr, item in ((p397ref, p397), (p396ref, p396), (p395ref, p395)):
        protected.add(rr['path'])
        parent.parent.parent.parent._collect_sources(item, protected)
    for item, label in ((p397, 'outside_observer_roster_original'),
                        (p396, 'outside_authority_roster_original'),
                        (p395, 'external_role_roster_original')):
        if item.get(label) is not None:
            rr = ref(item[label])
            protected.add(rr['path'])
            parent.parent.parent.parent._collect_sources(doc(
                rr, 'ec402_actual_deep_ancestral_roster',
                parent.parent.parent.parent.MAX_ROSTER), protected)
    protected.update(r['path'] for chain in chains for r in chain['refs'])
    used = set(protected)
    flags = {key: False for key in FLAGS}
    flags[FLAGS[0]] = (not live['bounded_local_issuer_ocsp_and_real_parent_consistency'] or
                       any(r['joint_verified_ocsp_publisher_count'] != 2
                           for r in live['ocsp_epoch_reviews']))
    reviews, inventory, first = [], [], {}
    total = 0
    for i, epoch in enumerate(bundle['epochs']):
        exact(epoch, EPOCH_FIELDS, 'PDF_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index'] == i and
             type(epoch['publishers']) is list and len(epoch['publishers']) == 2,
             'PDF_EPOCH_MUST_HAVE_TWO_REAL_PUBLISHERS', 'permission_denied')
        old = p398['epochs'][i]
        exact(old, parent.parent.parent.parent.EPOCH_FIELDS,
              'AUTHENTIC_PARENT_SIGNED_NOTICE_EPOCH')
        need(type(old['epoch_index']) is int and old['epoch_index'] == i,
             'AUTHENTIC_PARENT_EPOCH_REORDERED', 'permission_denied')
        source_ref = ref(old['source_notice_original']) if old['source_notice_original'] else None
        notice = old['notice']
        exact(notice, parent.parent.parent.parent.STAMP_FIELDS,
              'AUTHENTIC_PARENT_NOTICE_STAMP')
        notice_ref = ref(notice['signed_original']) if notice['signed_original'] else None
        need(source_ref is not None and notice_ref is not None,
             'SIGNED_PDF_REQUIRES_EXISTING_GENUINE_EC398_GAZETTE_SOURCE_AND_NOTICE',
             'permission_denied')
        _, claim, signature = parent.parent.parent.parent._signed(
            notice_ref, read, parent.parent.parent.parent.NOTICE_SCHEMA,
            parent.parent.parent.parent.NOTICE_CLAIM,
            parent.parent.parent.parent.NOTICE_CLAIM_FIELDS,
            'EC402_REOPEN_GENUINELY_SIGNED_EC398_NOTICE')
        parent.parent.parent.parent._sign(
            notice_roster['registrar'], signature,
            parent.parent.parent.parent.NOTICE_DOMAIN, claim,
            'EC402_RECHECK_TRUE_GAZETTE_REGISTRAR_SIGNATURE')
        need(claim['directory_lineage_id'] == lineage and
             type(claim['epoch_index']) is int and claim['epoch_index'] == i and
             claim['source_notice_original_sha256'] == source_ref['sha256'],
             'SIGNED_NOTICE_NOT_ACTUAL_EC398_SOURCE', 'permission_denied')
        expected_time = parent.parent.parent._utc(claim['claimed_published_utc'])
        source_bytes = read(source_ref, 'ec402_reopen_actual_parent_gazette_bytes',
                            parent.parent.parent.parent.MAX_SOURCE)
        seen, members = set(), []
        verified = 0
        for entry in epoch['publishers']:
            exact(entry, PUBLISHER_FIELDS, 'PDF_PUBLISHER')
            role = entry['publisher_id']
            need(role in ids and role not in seen,
                 'PDF_UNKNOWN_OR_REPEATED_PUBLISHER', 'permission_denied')
            seen.add(role)
            pdfref = ref(entry['signed_pdf_original']) if entry['signed_pdf_original'] else None
            if pdfref is None:
                flags[FLAGS[2]] = True
                row = {'publisher_id': role, 'signed_pdf_original_sha256': None,
                       'signed_pdf': None}
            else:
                need(pdfref['path'] not in used,
                     'PDF_ORIGINAL_PATH_ALIASES_PARENT_OR_OTHER_PUBLISHER',
                     'permission_denied')
                used.add(pdfref['path'])
                chain = next(c for c in chains if c['role']['publisher_id'] == role)
                signed = _verify_pdf(pdfref, role, chain, source_bytes,
                                     source_ref['sha256'], expected_time, read)
                row = {'publisher_id': role,
                       'signed_pdf_original_sha256': pdfref['sha256'],
                       'signed_pdf': signed}
                verified += 1
            if i == 0:
                first[role] = row['signed_pdf_original_sha256']
            members.append(row)
        need(seen == set(ids), 'PDF_MISSING_REAL_EC399_PUBLISHER_ROLE',
             'permission_denied')
        members.sort(key=lambda x: x['publisher_id'])
        jointly = verified if live['ocsp_epoch_reviews'][i][
            'joint_verified_ocsp_publisher_count'] == 2 and not flags[FLAGS[0]] else 0
        if jointly != 2:
            flags[FLAGS[3]] = True
        inv_row = {'epoch_index': i, 'publishers': members,
                   'verified_signed_pdf_count': verified,
                   'joint_verified_signed_pdf_and_parent_ocsp_count': jointly}
        digest = cdigest(inv_row)
        if (digest != opts[REPEAT_NAMES[0]][i] or
                jointly < opts[REPEAT_NAMES[1]][i]):
            flags[FLAGS[1]] = True
        inventory.append(inv_row)
        reviews.append({'epoch_index': i,
                        'verified_actual_signed_pdf_count': verified,
                        'joint_verified_signed_pdf_and_ocsp_count': jointly,
                        'signed_pdf_epoch_inventory_sha256': digest,
                        'genuine_parent_joint_ocsp_count': live[
                            'ocsp_epoch_reviews'][i]['joint_verified_ocsp_publisher_count']})
        total += jointly
    need(len(first) == 2 and first.get(ids[0]) is not None and
         first.get(ids[1]) is not None,
         'FIRST_TWO_PINNED_PDF_ORIGINALS_REQUIRED', 'permission_denied')
    if (first[ids[0]], first[ids[1]]) != (
            opts[NEW_SCALARS[2]], opts[NEW_SCALARS[3]]):
        flags[FLAGS[1]] = True
    inv = {'schema': INVENTORY_SCHEMA,
           'directory_lineage_id': lineage,
           'verified_real_ec401_report_sha256': live_sha,
           'verified_real_ec401_inventory_sha256': live[
               'receiver_verified_ocsp_inventory_sha256'],
           'parent_original_ocsp_bundle_sha256': b401['sha256'],
           'original_signed_pdf_bundle_sha256': b402['sha256'],
           'outside_retained_first_pdf_original_shas': [
               opts[NEW_SCALARS[2]], opts[NEW_SCALARS[3]]],
           'epochs': inventory}
    invsha = cdigest(inv)
    if not deriving and invsha != opts[AUDIT_ONLY[0]]:
        flags[FLAGS[1]] = True
    for path, (digest, cap) in late.items():
        actual = io._read({'path': path, 'sha256': digest},
                          'ec402_final_original_byte_readback', cap, {}, {}, set())
        need(sha(actual) == digest, 'PDF_OR_ANCESTOR_ORIGINAL_MUTATED',
             'permission_denied')
    for key in FLAGS[-3:]:
        flags[key] = True
    return {'schema': DERIVE_SCHEMA if deriving else RESULT_SCHEMA,
            'command': 'derive-historical-ec339-signed-pdf-inventory'
                       if deriving else 'audit-historical-ec339-signed-pdf',
            'status': next((OUTCOMES[i] for i, k in enumerate(FLAGS) if flags[k]),
                           OUTCOMES[-1]) + '_unresolved',
            'exit_code': 2, 'offline_unresolved_exit_code': 2,
            'verified_live_ec401_report_sha256': live_sha,
            'verified_live_ec401_inventory_sha256': live[
                'receiver_verified_ocsp_inventory_sha256'],
            'original_signed_pdf_bundle_sha256': b402['sha256'],
            'receiver_verified_signed_pdf_inventory_sha256': invsha,
            'verified_joint_parent_ocsp_and_signed_pdf_publishers': total,
            'signed_pdf_epoch_reviews': reviews,
            'bounded_local_signed_pdf_and_real_ec401_parent_consistency':
                not any(flags[k] for k in FLAGS[:4]),
            'sender_origin_path_required_or_read': False,
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed': False,
            **flags, **{key: False for key in NEGATIVES},
            **({'unsigned_signed_pdf_evidence_inventory': inv} if deriving else {})}


def derive_inventory(**opts):
    return _engine(True, **opts)


def audit(**opts):
    return _engine(False, **opts)
