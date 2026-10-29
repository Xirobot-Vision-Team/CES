#!/usr/bin/env python3
"""EC400: read-only real DER CMS/PKCS#7 SignedData on the EC398 gazette bytes.

The authentic, unchanged EC399 audit (and all of its ancestor audits) is a
mandatory production dependency. Two native CMS SignerInfos must verify using
exactly the two externally pinned EC399 X.509 leaf originals. Both CMS signatures
are checked over DER authenticated attributes; both messageDigest attributes
must hash the *actual reopened EC398 gazette original*. EC399, not a caller flag,
controls historical and evaluation CRL credit. Neither the CMS signingTime nor
locally pinned roots establish official authorization, qualified time or actual
pre-dispute publication. The receiver never signs, writes, spawns or uses network.

Requires asn1crypto for bounded ASN.1 DER decoding and cryptography for actual
signature, certificate chain and original CRL validation.
"""
from __future__ import annotations

import hashlib
from datetime import timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa, padding
from cryptography.x509.oid import ExtensionOID

from ec295_delivery_anchor import anchor as errors
from ec372_historical_authority import authority_archive as io
from ec399_official_certificate import protocol as parent

RESULT_SCHEMA = 'ces.ec400.native_cms_signed_gazette_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec400.unsigned_native_cms_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec400.native_cms_gazette_denial.v1'
BUNDLE_SCHEMA = 'ces.ec400.native_cms_gazette_original_bundle.v1'
INVENTORY_SCHEMA = 'ces.ec400.native_cms_gazette_inventory.v1'
ZERO = '0' * 64
MAX_BUNDLE = 90_000
MAX_CMS = 1_500_000

PARENT_SCALARS = (*parent.PARENT_SCALARS, *parent.NEW_SCALARS, *parent.AUDIT_ONLY)
PARENT_REPEATS = (*parent.PARENT_REPEATS, *parent.REPEAT_NAMES)
NEW_SCALARS = (
    'historical_ec339_native_cms_bundle_file',
    'expected_historical_ec339_native_cms_bundle_sha256',
    'expected_outside_retained_ec400_first_native_cms_original_sha256',
)
AUDIT_ONLY = ('expected_retained_historical_ec339_native_cms_inventory_sha256',)
NEW_REPEATS = (
    ('historical_ec339_native_cms_epoch_inventory_shas',
     '--historical-ec339-native-cms-epoch-inventory-sha256'),
    ('minimum_historical_ec339_native_cms_verified_signer_counts',
     '--minimum-historical-ec339-native-cms-verified-signer-count'),
)
REPEAT_NAMES = tuple(k for k, _ in NEW_REPEATS)
FLAGS = (
    'inherited_real_ec399_certificate_parent_or_crl_consistency_disputed',
    'outside_original_cms_or_epoch_inventory_and_count_pin_disagrees',
    'native_cms_original_or_two_signer_original_unavailable',
    'native_cms_parent_source_or_leaf_certificate_binding_incomplete',
    'historically_bounded_native_cms_signed_time_not_qualified',
    'real_world_official_issuer_and_public_trust_anchor_not_proven',
    'complete_historical_ocsp_public_publication_and_fork_census_not_proven',
    'manufacturer_worm_unmocked_ancestors_and_final_acceptance_not_proven',
)
OUTCOMES = (
    'ec400_real_ec399_parent_x509_crl_or_original_disputed',
    'ec400_external_native_cms_original_epoch_or_count_pin_disagrees',
    'ec400_native_cms_two_authentic_signatures_unavailable',
    'ec400_real_gazette_or_leaf_bound_native_cms_incomplete',
    'ec400_native_cms_signing_time_not_qualified',
    'ec400_official_issuer_legal_authorization_not_established',
    'ec400_global_historical_ocsp_publication_and_forks_not_established',
    'ec400_manufacturer_worm_unmocked_history_and_final_acceptance_not_proven',
)
NEGATIVES = (
    'a_locally_pinned_x509_root_proves_official_government_or_court_authority',
    'valid_native_cms_signatures_prove_legally_authorized_official_publication',
    'cms_signed_attribute_signing_time_is_a_qualified_trusted_timestamp',
    'attached_or_detached_signed_data_is_pades_pdf_or_xmldsig',
    'cms_certificates_repair_missing_or_revoked_parent_ec399_crls',
    'furnished_signed_crls_prove_globally_complete_ocsp_or_public_revocations',
    'offline_source_signatures_prove_independent_pre_dispute_public_access',
    'one_cms_with_two_signers_proves_independent_legal_organizations',
    'cms_origins_or_new_public_trust_roots_were_discovered_online',
    'receiver_minted_certificates_signatures_private_keys_or_legal_timestamps',
    'receiver_used_network_provider_git_ci_or_wrote_cas_worm_powershell',
    'unmocked_full_production_history_native_ps7_or_final_acceptance_passed',
)
BUNDLE_FIELDS = {'schema', 'claimed_directory_lineage_id',
                 'parent_ec399_official_certificate_bundle_original', 'epochs'}
EPOCH_FIELDS = {'epoch_index', 'cms_signed_data_original'}


def need(condition, code, status='invalid_input'):
    if condition is not True:
        raise errors.AnchorError('EC400_' + code, status)


def exact(obj, fields, role):
    need(type(obj) is dict and set(obj) == fields,
         role + '_EXACT_FIELDS_REQUIRED')


def sha(data):
    return parent.sha(data)


def cdigest(obj):
    return parent.cdigest(obj)


def ref(obj):
    return parent.ref(obj)


def _inputs(opts, deriving):
    expected = set((*PARENT_SCALARS, *PARENT_REPEATS,
                    *NEW_SCALARS, *REPEAT_NAMES))
    if not deriving:
        expected.update(AUDIT_ONLY)
    need(set(opts) == expected, 'EXACT_EC399_ANCESTOR_AND_NEW_ARGUMENTS_REQUIRED')
    inherited = {key: opts[key] for key in (*PARENT_SCALARS, *PARENT_REPEATS)}
    parent._inputs(inherited, False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]], opts[NEW_SCALARS[1]],
                           'EC400_NATIVE_CMS_BUNDLE')
    need(parent.valid_sha(opts[NEW_SCALARS[2]]),
         'EXTERNAL_FIRST_CMS_ORIGINAL_PIN_INVALID')
    if not deriving:
        need(parent.valid_sha(opts[AUDIT_ONLY[0]]),
             'OUTSIDE_WHOLE_CMS_INVENTORY_PIN_INVALID')
    count = len(opts['historical_directory_root_shas'])
    need(1 <= count <= 3, 'ONE_TO_THREE_EPOCHS_REQUIRED')
    for key in REPEAT_NAMES:
        values = opts[key]
        need(type(values) is list and len(values) == count,
             'OUTSIDE_PER_EPOCH_CMS_CONSTRAINT_COUNT_INVALID')
        if key.startswith('minimum_'):
            need(all(type(v) is int and 0 <= v <= 2 for v in values),
                 'OUTSIDE_CMS_SIGNER_FLOOR_INVALID')
        else:
            need(all(parent.valid_sha(v) for v in values),
                 'OUTSIDE_CMS_EPOCH_INVENTORY_SHA_INVALID')
    return inherited


def _parent_report(report, opts):
    common = {'schema', 'command', 'status', 'exit_code',
        'offline_unresolved_exit_code',
        'verified_live_ec398_report_sha256',
        'verified_live_ec398_inventory_sha256',
        'original_two_root_certificate_bundle_sha256',
        'receiver_verified_certificate_inventory_sha256',
        'verified_independent_x509_publisher_count',
        'visible_historically_revoked_certificate_count',
        'certificate_epoch_reviews',
        'bounded_local_gazette_certificate_crl_parent_consistency',
        'sender_origin_path_required_or_read',
        'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
        *parent.FLAGS, *parent.NEGATIVES}
    count = len(opts['historical_directory_root_shas'])
    need(type(report) is dict and set(report) == common and
         report.get('schema') == parent.RESULT_SCHEMA and
         report.get('command') == 'audit-historical-ec339-official-certificate' and
         report.get('exit_code') == 2 and
         report.get('offline_unresolved_exit_code') == 2 and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         report.get('original_two_root_certificate_bundle_sha256') == opts[parent.NEW_SCALARS[1]] and
         report.get('receiver_verified_certificate_inventory_sha256') == opts[parent.AUDIT_ONLY[0]] and
         all(parent.valid_sha(report.get(key)) for key in
             ('verified_live_ec398_report_sha256', 'verified_live_ec398_inventory_sha256')) and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         all(report[k] is True for k in parent.FLAGS[-3:]) and
         report.get('bounded_local_gazette_certificate_crl_parent_consistency') is
             (not any(report[k] for k in parent.FLAGS[:5])) and
         report.get('status') == next((parent.OUTCOMES[i]
             for i, k in enumerate(parent.FLAGS) if report[k]),
             parent.OUTCOMES[-1]) + '_unresolved',
         'REAL_EC399_PARENT_REPORT_NOT_AN_AUTHENTIC_UNRESOLVED_AUDIT',
         'unavailable')
    rows = report.get('certificate_epoch_reviews')
    fields = {'epoch_index', 'locally_verified_x509_publisher_count',
              'signed_original_inventory_sha256',
              'historical_current_crl_inventory_sha256',
              'visible_revoked_publisher_certificates'}
    need(type(rows) is list and len(rows) == count and all(
         type(row) is dict and set(row) == fields and
         type(row['epoch_index']) is int and row['epoch_index'] == i and
         all(type(row[key]) is int and 0 <= row[key] <= 2 for key in
             ('locally_verified_x509_publisher_count',
              'visible_revoked_publisher_certificates')) and
         parent.valid_sha(row['signed_original_inventory_sha256']) and
         parent.valid_sha(row['historical_current_crl_inventory_sha256'])
         for i, row in enumerate(rows)) and
         type(report.get('verified_independent_x509_publisher_count')) is int and
         type(report.get('visible_historically_revoked_certificate_count')) is int and
         report['verified_independent_x509_publisher_count'] == sum(
             r['locally_verified_x509_publisher_count'] for r in rows) and
         report['visible_historically_revoked_certificate_count'] == sum(
             r['visible_revoked_publisher_certificates'] for r in rows),
         'REAL_EC399_PARENT_EPOCH_OR_COUNT_MISMATCH', 'unavailable')
    return cdigest(report)


def _asn1():
    try:
        from asn1crypto import cms, x509 as asn1_x509
    except ImportError as exc:
        raise errors.AnchorError('EC400_ASN1CRYPTO_DEPENDENCY_NOT_AVAILABLE',
                                 'unavailable') from exc
    return cms, asn1_x509


def _one_attribute(attrs, name):
    matching = [item for item in attrs if item['type'].native == name]
    need(len(matching) == 1 and len(matching[0]['values']) == 1,
         'CMS_REQUIRED_SIGNED_ATTRIBUTE_NOT_UNIQUE_' + name.upper(),
         'permission_denied')
    return matching[0]['values'][0].native


def _verify_signer(signer, chains, attached_bytes, parent_time, asn1certs):
    """Verify signature over *DER SET* of authenticated attributes, not eContent.

    CMS SignerInfo signed_attrs is tagged IMPLICIT [0] inside the SignerInfo;
    RFC 5652 requires the signature to cover the DER SET OF (tag 0x31).
    """
    version = signer['version'].native
    sid = signer['sid']
    need((sid.name == 'issuer_and_serial_number' and version == 'v1') or
         (sid.name == 'subject_key_identifier' and version == 'v3'),
         'CMS_SIGNER_IDENTIFIER_OR_VERSION_UNSUPPORTED', 'permission_denied')
    chain = None
    for candidate in chains:
        cert = candidate['certs'][0]
        original = asn1certs[candidate['refs'][0]['sha256']]
        if sid.name == 'issuer_and_serial_number':
            matched = (sid.chosen['serial_number'].native == cert.serial_number and
                       sid.chosen['issuer'].dump() ==
                       original['tbs_certificate']['issuer'].dump())
        else:
            ski = parent._ext(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER, False)
            matched = ski is not None and sid.chosen.native == ski.digest
        if matched:
            need(chain is None, 'CMS_SIGNER_ID_AMBIGUOUS', 'permission_denied')
            chain = candidate
    need(chain is not None, 'CMS_SIGNER_NOT_AN_EC399_PINNED_LEAF', 'permission_denied')
    alg = signer['digest_algorithm']['algorithm'].native
    digests = {'sha256': hashes.SHA256, 'sha384': hashes.SHA384,
               'sha512': hashes.SHA512}
    need(alg in digests, 'CMS_WEAK_OR_UNSUPPORTED_DIGEST', 'permission_denied')
    attributes = signer['signed_attrs']
    need(attributes is not None and attributes.native is not None and
         3 <= len(attributes) <= 20,
         'CMS_SIGNED_ATTRIBUTES_REQUIRED', 'permission_denied')
    attr_encodings = [attr.dump() for attr in attributes]
    need(attr_encodings == sorted(attr_encodings) and
         len({a['type'].dotted for a in attributes}) == len(attributes),
         'CMS_NONCANONICAL_OR_DUPLICATE_SIGNED_ATTRIBUTES', 'permission_denied')
    canonical_set = attributes.untag().dump(force=True)
    need(canonical_set[:1] == b'\x31' and
         attributes.dump() == b'\xa0' + canonical_set[1:],
         'CMS_SIGNED_ATTRIBUTES_NOT_CANONICAL_DER', 'permission_denied')
    content_type = _one_attribute(attributes, 'content_type')
    need(content_type == 'data', 'CMS_SIGNED_CONTENT_TYPE_NOT_ID_DATA',
         'permission_denied')
    digest_from_signature = _one_attribute(attributes, 'message_digest')
    need(type(digest_from_signature) is bytes and
         digest_from_signature == hashlib.new(alg, attached_bytes).digest(),
         'CMS_MESSAGE_DIGEST_NOT_REAL_GAZETTE_BYTES', 'permission_denied')
    asserted = _one_attribute(attributes, 'signing_time')
    need(hasattr(asserted, 'astimezone') and asserted.tzinfo is not None,
         'CMS_SIGNING_TIME_NOT_UTC_BOUNDED', 'permission_denied')
    signed_at = asserted.astimezone(timezone.utc)
    need(signed_at.microsecond == 0 and signed_at == parent_time,
         'CMS_SIGNED_TIME_DOES_NOT_MATCH_AUTHENTIC_PARENT_NOTICE',
         'permission_denied')
    need(parent._certificate_time(chain, signed_at),
         'CMS_SIGNED_TIME_OUTSIDE_CERTIFICATE_VALIDITY', 'permission_denied')
    signature_algorithm = signer['signature_algorithm']['algorithm'].native
    signature = signer['signature'].native
    need(type(signature) is bytes and 0 < len(signature) <= 1024,
         'CMS_SIGNATURE_MISSING_OR_OVERSIZED', 'permission_denied')
    pub = chain['certs'][0].public_key()
    try:
        if isinstance(pub, ed25519.Ed25519PublicKey):
            need(signature_algorithm == 'ed25519' and alg == 'sha512',
                 'CMS_ED25519_DIGEST_OR_SIGNATURE_ALGORITHM_MISMATCH',
                 'permission_denied')
            need(signer['signature_algorithm']['parameters'].native is None,
                 'CMS_ED25519_PARAMETERS_NOT_ALLOWED', 'permission_denied')
            pub.verify(signature, canonical_set)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            need(signature_algorithm == alg + '_ecdsa' and
                 isinstance(pub.curve, (ec.SECP256R1, ec.SECP384R1)),
                 'CMS_ECDSA_ALGORITHM_MISMATCH', 'permission_denied')
            pub.verify(signature, canonical_set, ec.ECDSA(digests[alg]()))
        elif isinstance(pub, rsa.RSAPublicKey):
            allowed = ('rsassa_pkcs1v15', 'sha256_rsa', 'sha384_rsa',
                       'sha512_rsa')
            need(signature_algorithm in allowed and
                 (signature_algorithm == 'rsassa_pkcs1v15' or
                  signature_algorithm == alg + '_rsa') and
                 2048 <= pub.key_size <= 8192,
                 'CMS_RSA_PKCS1_SHA2_ALGORITHM_MISMATCH', 'permission_denied')
            pub.verify(signature, canonical_set,
                       padding.PKCS1v15(), digests[alg]())
        else:
            need(False, 'CMS_SIGNER_PUBLIC_KEY_UNSUPPORTED', 'permission_denied')
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise errors.AnchorError('EC400_CMS_ACTUAL_SIGNED_ATTRIBUTES_SIGNATURE_INVALID',
                                 'permission_denied') from exc
    return {'publisher_id': chain['role']['publisher_id'],
            'original_pinned_leaf_certificate_sha256': chain['refs'][0]['sha256'],
            'digest_algorithm': alg,
            'signature_algorithm': signature_algorithm,
            'signed_time_utc': signed_at.isoformat(),
            'signed_message_digest_hex': digest_from_signature.hex(),
            'cms_signature_valid_on_authenticated_der_attributes': True}


def _verify_cms(raw, source_bytes, signed_notice_time, chains):
    cms, asn1_x509 = _asn1()
    try:
        content = cms.ContentInfo.load(raw, strict=True)
        need(content.dump(force=True) == raw and content['content_type'].native == 'signed_data',
             'CMS_NOT_CANONICAL_DER_SIGNEDDATA', 'permission_denied')
        data = content['content']
        need(data['version'].native in ('v1', 'v3'),
             'CMS_UNSUPPORTED_SIGNEDDATA_VERSION', 'permission_denied')
        encapsulated = data['encap_content_info']
        need(encapsulated['content_type'].native == 'data',
             'CMS_ECONTENT_TYPE_MUST_BE_ID_DATA', 'permission_denied')
        econtent = encapsulated['content'].native
        mode = 'detached' if econtent is None else 'attached'
        need(econtent is None or econtent == source_bytes,
             'CMS_ATTACHED_CONTENT_DIFFERS_FROM_GENUINE_EC398_SOURCE',
             'permission_denied')
        need(data['crls'].native is None,
             'CMS_UNVALIDATED_EMBEDDED_REVOCATION_OR_CRL_NOT_ACCEPTED',
             'permission_denied')
        signers = data['signer_infos']
        need(len(signers) == 2, 'CMS_MUST_HAVE_EXACTLY_TWO_SIGNERINFOS',
             'permission_denied')
        need(data['version'].native == ('v3' if any(
              si['version'].native == 'v3' for si in signers) else 'v1'),
             'CMS_SIGNEDDATA_VERSION_INCONSISTENT_WITH_SIGNERINFOS',
             'permission_denied')
        embedded = data['certificates']
        need(embedded.native is not None and 2 <= len(embedded) <= 6,
             'CMS_PINNED_LEAF_CERTIFICATES_MUST_BE_EMBEDDED',
             'permission_denied')
        # The CMS may embed a subset of intermediates/roots, but EVERY byte must
        # equal a known original, with both original leaf DER certificates present.
        allowed = {r['sha256'] for chain in chains for r in chain['refs']}
        required = {chain['refs'][0]['sha256'] for chain in chains}
        embedded_shas = []
        for item in embedded:
            need(item.name == 'certificate',
                 'CMS_UNKNOWN_CERTIFICATE_CHOICE', 'permission_denied')
            certificate_der = item.chosen.dump()
            certificate_sha = sha(certificate_der)
            need(certificate_sha in allowed and certificate_sha not in embedded_shas,
                 'CMS_CERTIFICATE_NOT_AN_EC399_PINNED_ORIGINAL',
                 'permission_denied')
            embedded_shas.append(certificate_sha)
        need(required.issubset(set(embedded_shas)),
             'CMS_BOTH_ORIGINAL_PINNED_SIGNER_LEAVES_REQUIRED',
             'permission_denied')
        asn1certs = {chain['refs'][0]['sha256']:
                         asn1_x509.Certificate.load(chain['certs'][0].public_bytes(
                             serialization.Encoding.DER), strict=True)
                     for chain in chains}
        proofs = [_verify_signer(si, chains, source_bytes, signed_notice_time,
                                 asn1certs) for si in signers]
        ids = [p['publisher_id'] for p in proofs]
        need(len(set(ids)) == 2 and set(ids) ==
             {chain['role']['publisher_id'] for chain in chains},
             'CMS_DUPLICATE_OR_MISSING_INDEPENDENT_PINNED_SIGNER',
             'permission_denied')
        expected_digest_set = {p['digest_algorithm'] for p in proofs}
        declared = data['digest_algorithms']
        need(len(declared) == len(expected_digest_set) and
             {d['algorithm'].native for d in declared} == expected_digest_set,
             'CMS_SIGNEDDATA_DIGEST_ALGORITHMS_DO_NOT_MATCH_SIGNERS',
             'permission_denied')
        proofs.sort(key=lambda p: p['publisher_id'])
        return {'cms_encapsulated_content_mode': mode,
                'verified_native_cms_signer_count': 2,
                'real_gazette_source_sha256': sha(source_bytes),
                'embedded_original_certificate_shas': sorted(embedded_shas),
                'verified_signer_infos': proofs}
    except errors.AnchorError:
        raise
    except (ValueError, TypeError, KeyError, IndexError, OverflowError, AssertionError) as exc:
        raise errors.AnchorError('EC400_MALFORMED_OR_UNSUPPORTED_CMS_DER',
                                 'permission_denied') from exc


def _engine(deriving, **opts):
    inherited = _inputs(opts, deriving)
    live = parent.audit(**inherited)    # actual unchanged EC399/398/... audit
    live_sha = _parent_report(live, opts)
    lineage = opts['claimed_historical_directory_lineage_id']
    n = len(opts['historical_directory_root_shas'])
    read, doc, late = parent.parent.parent.parent.parent.prior._readers()
    bundleref = {'path': opts[NEW_SCALARS[0]], 'sha256': opts[NEW_SCALARS[1]]}
    bundle = doc(bundleref, 'ec400_original_native_cms_bundle', MAX_BUNDLE)
    exact(bundle, BUNDLE_FIELDS, 'NATIVE_CMS_BUNDLE')
    p399ref = {'path': opts[parent.NEW_SCALARS[0]],
               'sha256': opts[parent.NEW_SCALARS[1]]}
    need(bundle['schema'] == BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id'] == lineage and
         bundle['parent_ec399_official_certificate_bundle_original'] == p399ref and
         type(bundle['epochs']) is list and len(bundle['epochs']) == n,
         'CMS_BUNDLE_NOT_BOUND_TO_REAL_EC399_PARENT', 'permission_denied')
    p399 = doc(p399ref, 'genuine_ec399_parent_original_bundle', parent.MAX_BUNDLE)
    exact(p399, parent.BUNDLE_FIELDS, 'GENUINE_EC399_BUNDLE')
    need(p399['claimed_directory_lineage_id'] == lineage,
         'REAL_EC399_BUNDLE_LINEAGE_MISMATCH', 'permission_denied')
    p398ref = ref(p399['parent_ec398_external_notice_bundle_original'])
    need(p398ref == {'path': opts[parent.parent.NEW_SCALARS[0]],
                     'sha256': opts[parent.parent.NEW_SCALARS[1]]},
         'REAL_EC398_NOTICE_PARENT_BUNDLE_SUBSTITUTED', 'permission_denied')
    p398 = doc(p398ref, 'genuine_ec398_original_notice_bundle',
               parent.parent.MAX_BUNDLE)
    exact(p398, parent.parent.BUNDLE_FIELDS, 'GENUINE_EC398_BUNDLE')
    need(p398['claimed_directory_lineage_id'] == lineage and
         len(p398['epochs']) == n, 'REAL_EC398_EPOCH_LINEAGE_MISMATCH',
         'permission_denied')
    rosterref = ref(p399['outside_publisher_roster_original'])
    roster = doc(rosterref, 'real_ec399_two_pinned_certificate_roster',
                 parent.MAX_ROSTER)
    exact(roster, parent.ROSTER_FIELDS, 'REOPENED_EC399_ROSTER')
    need(rosterref['sha256'] == opts[parent.NEW_SCALARS[2]] and
         roster['schema'] == parent.ROSTER_SCHEMA and
         roster['claimed_directory_lineage_id'] == lineage and
         type(roster['publishers']) is list and len(roster['publishers']) == 2,
         'EC399_PINNED_ROSTER_UNEXPECTED', 'permission_denied')
    chains = [parent._chain(role, opts, read) for role in roster['publishers']]
    need(len({c['role']['publisher_id'] for c in chains}) == 2 and
         len({c['role']['site_id'] for c in chains}) == 2 and
         len({r['sha256'] for c in chains for r in c['refs']}) ==
             sum(len(c['refs']) for c in chains),
         'TWO_INDEPENDENT_LEAF_CERTIFICATE_CHAINS_REQUIRED',
         'permission_denied')
    for i, chain in enumerate(chains):
        need(chain['refs'][-1]['sha256'] == opts[parent.NEW_SCALARS[3+i]] and
             chain['spkis'][0] == opts[parent.NEW_SCALARS[5+i]],
             'REAL_EC399_EXTERNAL_TRUST_ROOT_OR_SPKI_SUBSTITUTED',
             'permission_denied')
    p398_rosterref = ref(p398['outside_notice_roster_original'])
    p398_roster = doc(p398_rosterref, 'authentic_ec398_notice_signer_roster',
                      parent.parent.MAX_ROSTER)
    exact(p398_roster, parent.parent.ROSTER_FIELDS, 'EC398_NOTICE_ROSTER')

    protected = {bundleref['path'], p399ref['path'], p398ref['path'],
                 rosterref['path'], p398_rosterref['path']}
    parent.parent._collect_sources(p398, protected)
    parent.parent._collect_sources(p399, protected)
    parent.parent._collect_sources(roster, protected)
    for chain in chains:
        protected.update(r['path'] for r in chain['refs'])
    # Reopen and path-protect the actual EC397, EC396 and EC395 bundles too:
    # any legacy signed original reused as a new CMS is a role violation.
    old397ref = ref(p398['parent_ec397_publication_bundle_original'])
    old397 = doc(old397ref, 'ec400_authentic_ec397_source_for_alias_protection',
                 parent.parent.parent.MAX_BUNDLE)
    old396ref = ref(old397['parent_ec396_public_integrity_bundle_original'])
    old396 = doc(old396ref, 'ec400_authentic_ec396_source_for_alias_protection',
                 parent.parent.parent.parent.MAX_BUNDLE)
    old395ref = ref(old396['parent_ec395_credential_gossip_bundle_original'])
    old395 = doc(old395ref, 'ec400_authentic_ec395_source_for_alias_protection',
                 parent.parent.parent.parent.parent.MAX_BUNDLE)
    for oldref, older in ((old397ref, old397), (old396ref, old396),
                          (old395ref, old395)):
        protected.add(oldref['path'])
        parent.parent._collect_sources(older, protected)
    for older, key in ((old397, 'outside_observer_roster_original'),
                       (old396, 'outside_authority_roster_original'),
                       (old395, 'external_role_roster_original')):
        roster_original = older.get(key)
        if roster_original is not None:
            rr = ref(roster_original)
            protected.add(rr['path'])
            parent.parent._collect_sources(doc(
                rr, 'ec400_original_ancestor_signer_roster',
                parent.parent.MAX_ROSTER), protected)
    # Also protect all referenced EC399 signed originals and CRLs, not just
    # certificate/roster source labels. No CMS can be its parent evidence.
    for epoch in p399['epochs']:
        parent.parent._collect_sources(epoch, protected)
    flags = {k: False for k in FLAGS}
    flags[FLAGS[0]] = not live['bounded_local_gazette_certificate_crl_parent_consistency']
    if live['verified_independent_x509_publisher_count'] != 2 * n:
        flags[FLAGS[0]] = True
    rows, inventory_epochs = [], []
    credited_total = 0
    first_cms_sha = None
    seen_cms = set()
    for i, item in enumerate(bundle['epochs']):
        exact(item, EPOCH_FIELDS, 'NATIVE_CMS_EPOCH')
        need(type(item['epoch_index']) is int and item['epoch_index'] == i,
             'CMS_EPOCH_MUST_BE_CONTIGUOUS', 'permission_denied')
        original = item['cms_signed_data_original']
        entry = p398['epochs'][i]
        exact(entry, parent.parent.EPOCH_FIELDS, 'AUTHENTIC_EC398_NOTICE_EPOCH')
        source = ref(entry['source_notice_original']) if entry['source_notice_original'] else None
        stamped = entry['notice']
        exact(stamped, parent.parent.STAMP_FIELDS, 'PARENT_EC398_NOTICE_STAMP')
        notice = ref(stamped['signed_original']) if stamped['signed_original'] else None
        source_bytes = None
        claimed = None
        if notice is not None:
            need(source is not None, 'PARENT_NOTICE_WITHOUT_REAL_SOURCE',
                 'permission_denied')
            _, claim, sig = parent.parent._signed(
                notice, read, parent.parent.NOTICE_SCHEMA,
                parent.parent.NOTICE_CLAIM, parent.parent.NOTICE_CLAIM_FIELDS,
                'REOPEN_EC398_GENUINELY_SIGNED_NOTICE')
            parent.parent._sign(p398_roster['registrar'], sig,
                                parent.parent.NOTICE_DOMAIN, claim,
                                'EC400_RECHECK_EC398_REAL_SIGNER')
            need(claim['directory_lineage_id'] == lineage and
                 type(claim['epoch_index']) is int and claim['epoch_index'] == i and
                 claim['source_notice_original_sha256'] == source['sha256'],
                 'AUTHENTIC_PARENT_NOTICE_SOURCE_OR_EPOCH_WRONG',
                 'permission_denied')
            source_bytes = read(source, 'ec400_actual_ec398_gazette_source_bytes',
                                parent.parent.MAX_SOURCE)
            claimed = parent._utc(claim['claimed_published_utc'])
        parent_credit = live['certificate_epoch_reviews'][i][
            'locally_verified_x509_publisher_count']
        verified = 0
        if original is None:
            flags[FLAGS[2]] = True
            details = {'cms_original_sha256': None, 'cms_encapsulated_content_mode': None,
                       'verified_native_cms_signer_count': 0,
                       'real_gazette_source_sha256': source['sha256'] if source else None,
                       'parent_notice_original_sha256': notice['sha256'] if notice else None,
                       'verified_signer_infos': []}
        else:
            need(source_bytes is not None and notice is not None,
                 'CMS_CANNOT_SIGN_NONEXISTENT_REAL_SIGNED_EC398_GAZETTE',
                 'permission_denied')
            cmsref = ref(original)
            need(cmsref['path'] not in protected and
                 cmsref['path'] not in seen_cms,
                 'CMS_ORIGINAL_ALIASES_PARENT_OR_ANOTHER_EPOCH',
                 'permission_denied')
            seen_cms.add(cmsref['path'])
            raw = read(cmsref, 'original_real_issuer_cms_der_signeddata', MAX_CMS)
            validated = _verify_cms(raw, source_bytes, claimed, chains)
            details = {'cms_original_sha256': cmsref['sha256'],
                       'parent_notice_original_sha256': notice['sha256'],
                       **validated}
            verified = 2 if parent_credit == 2 and not flags[FLAGS[0]] else 0
            if verified != 2:
                flags[FLAGS[3]] = True
        if i == 0:
            first_cms_sha = details['cms_original_sha256']
        invrow = {'epoch_index': i,
                  'native_cms': details,
                  'genuine_ec399_locally_credited_certificate_count': parent_credit,
                  'joint_locally_credited_native_cms_signer_count': verified}
        inventory_epochs.append(invrow)
        digest = cdigest(invrow)
        if (digest != opts[REPEAT_NAMES[0]][i] or
                verified < opts[REPEAT_NAMES[1]][i]):
            flags[FLAGS[1]] = True
        rows.append({'epoch_index': i,
                     'cms_original_sha256': details['cms_original_sha256'],
                     'verified_native_cms_signer_count': verified,
                     'genuine_parent_certificates_and_crls_credited': parent_credit,
                     'cms_original_inventory_sha256': digest})
        credited_total += verified
    if first_cms_sha != opts[NEW_SCALARS[2]]:
        flags[FLAGS[1]] = True
    inventory = {'schema': INVENTORY_SCHEMA,
                 'directory_lineage_id': lineage,
                 'real_ec399_report_sha256': live_sha,
                 'real_ec399_verified_inventory_sha256':
                     live['receiver_verified_certificate_inventory_sha256'],
                 'real_ec399_bundle_sha256': p399ref['sha256'],
                 'original_native_cms_bundle_sha256': bundleref['sha256'],
                 'outside_first_cms_original_sha256': opts[NEW_SCALARS[2]],
                 'epochs': inventory_epochs}
    inventory_sha = cdigest(inventory)
    if not deriving and inventory_sha != opts[AUDIT_ONLY[0]]:
        flags[FLAGS[1]] = True
    # Original paths are finally reopened, hashed and rechecked after all
    # signature/chain comparisons to detect changes occurring during the audit.
    for path, (original_sha, cap) in late.items():
        reopened = io._read({'path': path, 'sha256': original_sha},
              'ec400_final_all_original_evidence_byte_integrity', cap, {}, {}, set())
        need(sha(reopened) == original_sha,
             'ORIGINAL_EVIDENCE_MUTATED_AFTER_READING', 'permission_denied')
    for key in FLAGS[-4:]:
        flags[key] = True
    return {'schema': DERIVE_SCHEMA if deriving else RESULT_SCHEMA,
            'command': 'derive-historical-ec339-native-cms-inventory'
                       if deriving else 'audit-historical-ec339-native-cms',
            'status': next((OUTCOMES[i] for i, k in enumerate(FLAGS)
                            if flags[k]), OUTCOMES[-1]) + '_unresolved',
            'exit_code': 2, 'offline_unresolved_exit_code': 2,
            'verified_live_ec399_report_sha256': live_sha,
            'verified_live_ec399_inventory_sha256':
                live['receiver_verified_certificate_inventory_sha256'],
            'original_native_cms_bundle_sha256': bundleref['sha256'],
            'receiver_verified_native_cms_inventory_sha256': inventory_sha,
            'verified_parent_and_native_cms_joint_signer_count': credited_total,
            'cms_epoch_reviews': rows,
            'bounded_local_native_cms_original_and_ec399_consistency':
                not any(flags[k] for k in FLAGS[:4]),
            'sender_origin_path_required_or_read': False,
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed': False,
            **flags, **{key: False for key in NEGATIVES},
            **({'unsigned_native_cms_inventory': inventory} if deriving else {})}


def derive_inventory(**opts):
    return _engine(True, **opts)


def audit(**opts):
    return _engine(False, **opts)
