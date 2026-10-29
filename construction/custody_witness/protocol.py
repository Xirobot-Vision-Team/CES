#!/usr/bin/env python3
"""EC406: read genuine original Ed25519 custodial accession and cross-witness signatures.

The real *unchanged* EC405.audit and all older audits run before new credit.
Cryptographic signatures bind immutable original bytes, not institutional
independence, real-world custody, legal TSA accreditation or qualified UTC.
Derivation is an unsigned comparison aid; no evidence or secret is issued.
All otherwise lawful outcomes remain exit 2 unresolved; never PASS.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from delivery_anchor import anchor as errors
from historical_authority import authority_archive as io
from registered_witness import registered_witness as original_readers
from warc_time import protocol as parent

RESULT_SCHEMA = 'ces.ec406.original_cross_witness_custody_unresolved.v1'
DERIVE_SCHEMA = 'ces.ec406.unsigned_cross_witness_custody_inventory_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec406.original_cross_witness_custody_denial.v1'
BUNDLE_SCHEMA = 'ces.ec406.original_custody_witness_bundle.v1'
ROSTER_SCHEMA = 'ces.ec406.outside_pinned_custody_witness_roster.v1'
ACCESSION_SCHEMA = 'ces.ec406.original_custodian_signed_accession.v1'
WITNESS_SCHEMA = 'ces.ec406.original_independent_signed_cross_witness.v1'
ACCESSION_CLAIM_SCHEMA = 'ces.ec406.custodial_accession_claim.v1'
WITNESS_CLAIM_SCHEMA = 'ces.ec406.independent_cross_witness_claim.v1'
INVENTORY_SCHEMA = 'ces.ec406.unsigned_custody_witness_inventory.v1'
ACCESSION_DOMAIN = b'CES/EC406/OriginalCustodyAccession/Ed25519/v1\x00'
WITNESS_DOMAIN = b'CES/EC406/OriginalIndependentCrossWitness/Ed25519/v1\x00'
MAX_BUNDLE = 160_000
MAX_ROSTER = 24_000
MAX_SIGNED = 16_000
PARENT_SCALARS = (*parent.PARENT_SCALARS, *parent.NEW_SCALARS, *parent.AUDIT_ONLY)
PARENT_REPEATS = (*parent.PARENT_REPEATS, *parent.REPEAT_NAMES)
NEW_SCALARS = (
    'historical_ec339_custody_witness_bundle_file',
    'expected_historical_ec339_custody_witness_bundle_sha256',
    'expected_outside_ec406_custody_witness_roster_sha256',
    'expected_outside_ec406_a_custodian_key_sha256',
    'expected_outside_ec406_b_custodian_key_sha256',
    'expected_outside_ec406_a_witness_key_sha256',
    'expected_outside_ec406_b_witness_key_sha256',
    'expected_outside_ec406_first_a_accession_sha256',
    'expected_outside_ec406_first_b_accession_sha256',
    'expected_outside_ec406_first_a_witness_sha256',
    'expected_outside_ec406_first_b_witness_sha256',
    'ec406_custody_evaluation_utc',
)
AUDIT_ONLY = ('expected_retained_historical_ec339_custody_witness_inventory_sha256',)
NEW_REPEATS = (
    ('historical_ec339_custody_witness_epoch_inventory_shas',
     '--historical-ec339-custody-witness-epoch-inventory-sha256'),
    ('minimum_historical_ec339_joint_custody_witness_publisher_counts',
     '--minimum-historical-ec339-joint-custody-witness-publisher-count'),
)
REPEAT_NAMES = tuple(k for k, _ in NEW_REPEATS)
FLAGS = (
    'real_ec405_warc_rfc3161_and_full_ancestry_disputed',
    'outside_four_keys_first_originals_epoch_or_whole_sha_or_floor_disagrees',
    'one_or_more_later_signed_accession_or_cross_witness_originals_missing',
    'signed_accession_or_witness_claim_time_conflicts_with_genuine_token_or_cutoff',
    'joint_cross_witness_and_real_warc_rfc3161_parent_coverage_incomplete',
    'original_external_custodian_and_witness_institutional_independence_not_proven',
    'real_historic_receipt_of_warc_and_qualified_legal_tsa_trust_not_proven',
    'official_court_legal_public_archive_global_worm_and_final_acceptance_not_proven',
)
OUTCOMES = (
    'ec406_real_ec405_and_earlier_signed_originals_disputed',
    'ec406_external_custody_witness_original_sha_inventory_or_floor_disagrees',
    'ec406_later_signed_custody_or_witness_original_missing',
    'ec406_custodian_or_witness_claimed_time_conflicts_with_signed_token_window',
    'ec406_dual_signature_and_real_parent_joint_coverage_incomplete',
    'ec406_institutional_independence_of_custody_and_witness_unproven',
    'ec406_actual_historical_custody_and_legally_qualified_tsa_unproven',
    'ec406_legal_authority_prior_public_worm_global_history_acceptance_unproven',
)
NEGATIVES = (
    'locally_verifiable_custody_signatures_prove_actual_third_party_possession',
    'distinct_ed25519_public_keys_prove_institutional_or_legal_independence',
    'custodian_or_witness_signed_claimed_time_is_independent_calibrated_utc',
    'signature_over_token_sha_proves_qualified_tsa_accreditation',
    'signed_archive_accession_id_proves_public_prior_third_party_archive',
    'two_cross_witness_signatures_prove_hidden_fork_absence_or_global_revocation',
    'cross_witness_repairs_any_adverse_real_ec405_or_earlier_parent',
    'cross_witness_proves_pdf_visible_semantics_government_or_court_issuer_authority',
    'receiver_created_signed_accession_witness_key_or_original_time_evidence',
    'receiver_used_network_signing_private_key_provider_git_ci_powershell_or_worm_writer',
    'full_unmocked_external_history_native_ps7_smoke_or_final_acceptance_proven',
)
BUNDLE_FIELDS = {'schema', 'claimed_directory_lineage_id',
                 'parent_ec405_original_warc_timestamp_bundle_original',
                 'outside_custody_witness_roster_original', 'epochs'}
ROSTER_FIELDS = {'schema', 'claimed_directory_lineage_id', 'assignments'}
ASSIGNMENT_FIELDS = {'publisher_id', 'custodian_id', 'witness_id',
                     'custodian_public_key_original', 'witness_public_key_original'}
EPOCH_FIELDS = {'epoch_index', 'publishers'}
ROLE_FIELDS = {'publisher_id', 'custodian_id', 'witness_id',
               'signed_accession_original', 'signed_cross_witness_original'}
SIGNED_FIELDS = {'schema', 'claim', 'signature_hex'}
ACCESSION_FIELDS = {'schema', 'directory_lineage_id', 'publisher_id', 'custodian_id',
                    'epoch_index', 'sequence', 'previous_accession_sha256',
                    'archive_record_id', 'original_ec404_signed_capture_receipt_sha256',
                    'original_warc_sha256', 'original_rfc3161_sha256',
                    'verified_token_gen_time_utc', 'claimed_accession_utc'}
WITNESS_FIELDS = {'schema', 'directory_lineage_id', 'publisher_id', 'witness_id',
                  'epoch_index', 'sequence', 'previous_witness_sha256',
                  'witness_event_id', 'signed_accession_original_sha256',
                  'original_warc_sha256', 'original_rfc3161_sha256',
                  'claimed_witness_utc'}
IDENT = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,63}\Z')
HEX_SIGNATURE = re.compile(r'[0-9a-f]{128}\Z')


def need(condition, code, status='invalid_input'):
    if condition is not True:
        raise errors.AnchorError('EC406_' + code, status)


def exact(value, fields, code):
    need(type(value) is dict and set(value) == fields,
         code + '_EXACT_FIELDS_REQUIRED', 'permission_denied')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cdigest(obj):
    return parent.cdigest(obj)


def ref(obj):
    return parent.ref(obj)


def utc(value):
    return parent.utc(value)


def stamp(value: datetime):
    return value.isoformat(timespec=('microseconds' if value.microsecond else 'seconds')).replace('+00:00', 'Z')


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _inputs(opts, deriving):
    required = set((*PARENT_SCALARS, *PARENT_REPEATS, *NEW_SCALARS, *REPEAT_NAMES))
    if not deriving:
        required.update(AUDIT_ONLY)
    need(set(opts) == required, 'COMPLETE_REAL_EC405_AND_SIGNED_CUSTODY_INPUTS_REQUIRED')
    inherited = {key: opts[key] for key in (*PARENT_SCALARS, *PARENT_REPEATS)}
    parent._inputs(inherited, False)
    io.authority.outer_pin(opts[NEW_SCALARS[0]], opts[NEW_SCALARS[1]],
                           'EC406_CUSTODY_WITNESS_BUNDLE')
    for key in NEW_SCALARS[2:11]:
        need(parent.parent.x509core.valid_sha(opts[key]),
             'OUTSIDE_CUSTODY_OR_FIRST_ORIGINAL_SHA_INVALID')
    need(len({opts[k] for k in NEW_SCALARS[3:11]}) == 8,
         'FOUR_EXTERNAL_KEYS_AND_FOUR_FIRST_ORIGINALS_MUST_DIFFER', 'permission_denied')
    if not deriving:
        need(parent.parent.x509core.valid_sha(opts[AUDIT_ONLY[0]]),
             'RETAINED_CUSTODY_WITNESS_WHOLE_INVENTORY_SHA_INVALID')
    utc(opts[NEW_SCALARS[11]])
    n = len(opts['historical_directory_root_shas'])
    need(1 <= n <= 3, 'ONE_TO_THREE_EC405_EPOCHS_REQUIRED')
    for key in REPEAT_NAMES:
        values = opts[key]
        need(type(values) is list and len(values) == n,
             'CUSTODY_EPOCH_SHA_AND_FLOOR_COUNT_REQUIRED')
        if key.startswith('minimum_'):
            need(all(type(v) is int and 0 <= v <= 2 for v in values),
                 'CUSTODY_JOINT_EPOCH_FLOOR_0_TO_2_REQUIRED')
        else:
            need(all(parent.parent.x509core.valid_sha(v) for v in values),
                 'CUSTODY_EPOCH_SHA_INVALID')
    return inherited


def _parent_report(report, opts):
    fields = {'schema', 'command', 'status', 'exit_code', 'offline_unresolved_exit_code',
              'verified_live_ec404_report_sha256', 'verified_live_ec404_inventory_sha256',
              'original_warc_timestamp_bundle_sha256',
              'receiver_verified_warc_timestamp_inventory_sha256',
              'verified_joint_warc_timestamp_and_real_parent_publishers',
              'warc_timestamp_epoch_reviews',
              'bounded_local_warc_timestamp_and_real_ec404_parent_consistency',
              'sender_origin_path_required_or_read',
              'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed',
              *parent.FLAGS, *parent.NEGATIVES}
    need(type(report) is dict and set(report) == fields and
         report.get('schema') == parent.RESULT_SCHEMA and
         report.get('command') == 'audit-historical-ec339-warc-timestamp' and
         report.get('exit_code') == report.get('offline_unresolved_exit_code') == 2 and
         report.get('sender_origin_path_required_or_read') is False and
         report.get('ec339_to_ec337_full_independent_unmocked_external_acceptance_performed') is False and
         report.get('original_warc_timestamp_bundle_sha256') == opts[parent.NEW_SCALARS[1]] and
         report.get('receiver_verified_warc_timestamp_inventory_sha256') ==
            opts[parent.AUDIT_ONLY[0]] and
         all(parent.parent.x509core.valid_sha(report.get(k)) for k in (
             'verified_live_ec404_report_sha256', 'verified_live_ec404_inventory_sha256')) and
         all(type(report.get(k)) is bool for k in parent.FLAGS) and
         all(report[k] for k in parent.FLAGS[-3:]) and
         all(report.get(k) is False for k in parent.NEGATIVES) and
         report.get('bounded_local_warc_timestamp_and_real_ec404_parent_consistency') is
            (not any(report[k] for k in parent.FLAGS[:6])) and
         report.get('status') == next((parent.OUTCOMES[i] for i,k in enumerate(parent.FLAGS)
                                     if report[k]), parent.OUTCOMES[-1])+'_unresolved',
         'UNCHANGED_REAL_EC405_PARENT_REPORT_INVALID', 'unavailable')
    rows = report.get('warc_timestamp_epoch_reviews')
    rowfields = {'epoch_index', 'actual_verified_warc_count',
                 'actual_verified_rfc3161_count', 'timestamp_and_crl_before_cutoff_count',
                 'joint_warc_timestamp_and_real_parent_count',
                 'warc_timestamp_epoch_inventory_sha256',
                 'real_ec404_parent_joint_capture_count'}
    n = len(opts['historical_directory_root_shas'])
    need(type(rows) is list and len(rows) == n and all(
        type(row) is dict and set(row) == rowfields and
        type(row['epoch_index']) is int and row['epoch_index'] == i and
        all(type(row[k]) is int and 0 <= row[k] <= 2 for k in (
          'actual_verified_warc_count', 'actual_verified_rfc3161_count',
          'timestamp_and_crl_before_cutoff_count',
          'joint_warc_timestamp_and_real_parent_count',
          'real_ec404_parent_joint_capture_count')) and
        row['joint_warc_timestamp_and_real_parent_count'] <= row['timestamp_and_crl_before_cutoff_count'] <=
          row['actual_verified_rfc3161_count'] <= row['actual_verified_warc_count'] and
        row['joint_warc_timestamp_and_real_parent_count'] <= row['real_ec404_parent_joint_capture_count'] and
        parent.parent.x509core.valid_sha(row['warc_timestamp_epoch_inventory_sha256'])
        for i,row in enumerate(rows)) and
        type(report.get('verified_joint_warc_timestamp_and_real_parent_publishers')) is int and
        report['verified_joint_warc_timestamp_and_real_parent_publishers'] == sum(
            r['joint_warc_timestamp_and_real_parent_count'] for r in rows),
        'REAL_EC405_PARENT_PER_EPOCH_COVERAGE_INVALID', 'unavailable')
    return cdigest(report)


def _sign(doc, key, domain, fields, schema, context):
    exact(doc, SIGNED_FIELDS, context)
    need(doc['schema'] == schema, context+'_SCHEMA_MISMATCH', 'permission_denied')
    claim = doc['claim']
    exact(claim, fields, context+'_CLAIM')
    need(type(doc['signature_hex']) is str and
         HEX_SIGNATURE.fullmatch(doc['signature_hex']) is not None,
         context+'_SIGNATURE_HEX_INVALID', 'permission_denied')
    try:
        key.verify(bytes.fromhex(doc['signature_hex']), domain+canonical(claim))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise errors.AnchorError('EC406_'+context+'_SIGNATURE_INVALID',
                                 'permission_denied') from exc
    return claim


def _signers(roster, roles, opts, read, protected, parent_archive_bytes,
             parent_publisher_bytes, parent_tsa_pub_bytes):
    exact(roster, ROSTER_FIELDS, 'CUSTODY_ROSTER')
    need(roster['schema'] == ROSTER_SCHEMA and
         roster['claimed_directory_lineage_id'] == opts['claimed_historical_directory_lineage_id'] and
         type(roster['assignments']) is list and len(roster['assignments']) == 2,
         'OUTSIDE_EXACT_TWO_ROLE_CUSTODY_ROSTER_REQUIRED', 'permission_denied')
    used_keys = set(parent_archive_bytes)|set(parent_publisher_bytes)|set(parent_tsa_pub_bytes)
    ids = set()
    pairs = {}
    for entry in roster['assignments']:
        exact(entry, ASSIGNMENT_FIELDS, 'CUSTODY_ASSIGNMENT')
        rid, cid, wid = entry['publisher_id'], entry['custodian_id'], entry['witness_id']
        need(type(rid) is str and rid in roles and rid not in pairs and
             all(type(x) is str and IDENT.fullmatch(x) is not None and x not in ids
                 for x in (cid,wid)) and cid != wid,
             'CUSTODIAN_WITNESS_IDS_AND_PUBLISHER_ROLES_MUST_DIFFER',
             'permission_denied')
        ids.update((cid,wid))
        public_keys = []
        for role_name, name, idx in (
             ('custodian', 'custodian_public_key_original', 3 if rid == roles[0] else 4),
             ('witness', 'witness_public_key_original', 5 if rid == roles[0] else 6)):
            key_ref = ref(entry[name])
            need(key_ref['path'] not in protected and
                 key_ref['sha256'] == opts[NEW_SCALARS[idx]],
                 'INDEPENDENT_CUSTODY_WITNESS_KEY_PATH_OR_EXTERNAL_PIN_INVALID',
                 'permission_denied')
            data = read(key_ref, 'ec406_pinned_'+role_name+'_ed25519_public_key', 32)
            need(len(data) == 32 and data not in used_keys,
                 'CUSTODY_WITNESS_PUBLIC_KEY_ALIASES_PARENT_OR_OTHER_SIGNER',
                 'permission_denied')
            try:
                public_keys.append(Ed25519PublicKey.from_public_bytes(data))
            except ValueError as exc:
                raise errors.AnchorError('EC406_INVALID_ED25519_SIGNER_KEY',
                                         'permission_denied') from exc
            used_keys.add(data)
            protected.add(key_ref['path'])
        pairs[rid] = {'custodian_id':cid,'witness_id':wid,
                      'custodian_key':public_keys[0], 'witness_key':public_keys[1]}
    need(set(pairs) == set(roles), 'CUSTODY_TWO_GENUINE_PUBLISHER_ROLE_KEYS_REQUIRED',
         'permission_denied')
    return pairs


def _engine(deriving, **opts):
    inherited = _inputs(opts, deriving)
    live = parent.audit(**inherited)   # strictly unchanged full EC405->EC404->... chain
    live_sha = _parent_report(live, opts)
    lineage = opts['claimed_historical_directory_lineage_id']
    n = len(opts['historical_directory_root_shas'])
    read, doc, late = original_readers._readers()
    b406 = {'path': opts[NEW_SCALARS[0]], 'sha256': opts[NEW_SCALARS[1]]}
    b405 = {'path': opts[parent.NEW_SCALARS[0]], 'sha256': opts[parent.NEW_SCALARS[1]]}
    b404 = {'path': opts[parent.parent.NEW_SCALARS[0]],
            'sha256': opts[parent.parent.NEW_SCALARS[1]]}
    bundle = doc(b406, 'ec406_original_custody_witness_bundle', MAX_BUNDLE)
    exact(bundle, BUNDLE_FIELDS, 'CUSTODY_WITNESS_BUNDLE')
    roster_ref = ref(bundle['outside_custody_witness_roster_original'])
    need(bundle['schema'] == BUNDLE_SCHEMA and
         bundle['claimed_directory_lineage_id'] == lineage and
         bundle['parent_ec405_original_warc_timestamp_bundle_original'] == b405 and
         roster_ref['sha256'] == opts[NEW_SCALARS[2]] and
         type(bundle['epochs']) is list and len(bundle['epochs']) == n,
         'CUSTODY_BUNDLE_REAL_EC405_LINK_OR_EXTERNAL_ROSTER_PIN_INVALID',
         'permission_denied')
    older = doc(b405, 'ec406_reopen_real_ec405_warc_bundle', parent.MAX_BUNDLE)
    exact(older, parent.BUNDLE_FIELDS, 'REAL_EC405_WARC_BUNDLE')
    need(older['schema'] == parent.BUNDLE_SCHEMA and
         older['claimed_directory_lineage_id'] == lineage and
         older['parent_ec404_original_public_access_bundle_original'] == b404 and
         len(older['epochs']) == n,
         'ACTUAL_EC405_WARC_AND_EC404_BUNDLE_MISMATCH', 'permission_denied')
    old404 = doc(b404, 'ec406_reopen_real_ec404_public_access_bundle',
                 parent.parent.MAX_BUNDLE)
    exact(old404, parent.parent.BUNDLE_FIELDS, 'REAL_EC404_ACCESS_BUNDLE')
    need(old404['schema'] == parent.parent.BUNDLE_SCHEMA and
         old404['claimed_directory_lineage_id'] == lineage and len(old404['epochs']) == n,
         'REAL_EC404_LINEAGE_EPOCH_MISMATCH', 'permission_denied')
    arref = ref(old404['outside_archive_roster_original'])
    archives = doc(arref, 'ec406_reopen_ec404_original_archive_roster',
                   parent.parent.MAX_ROSTER)
    exact(archives, parent.parent.ROSTER_FIELDS, 'REAL_ARCHIVE_ROSTER')
    need(archives['schema'] == parent.parent.ROSTER_SCHEMA and
         archives['claimed_directory_lineage_id'] == lineage and
         arref['sha256'] == opts[parent.parent.NEW_SCALARS[2]] and
         type(archives['archives']) is list and len(archives['archives']) == 2,
         'REAL_EC404_ARCHIVE_ROSTER_INVALID', 'permission_denied')
    roles = sorted(a['publisher_id'] for a in archives['archives'])
    need(len(roles) == 2 and len(set(roles)) == 2,
         'TWO_DISTINCT_EC404_PUBLISHER_IDS_REQUIRED', 'permission_denied')
    protected = {b406['path'], b405['path'], b404['path'], arref['path'], roster_ref['path']}
    for item in (older, old404, archives):
        parent._find_ref_paths(item, protected)
    for k,v in opts.items():
        if k in PARENT_SCALARS and k.endswith('_file') and type(v) is str:
            protected.add(v)
    previous_archive_keys = set()
    for row in archives['archives']:
        exact(row, parent.parent.ARCHIVE_FIELDS, 'REOPENED_REAL_ARCHIVE_ROW')
        keyref = ref(row['archive_public_key_original'])
        previous_archive_keys.add(read(keyref,'ec406_read_ec404_archive_key',32))
        protected.add(keyref['path'])
    # Reopen the actual EC399 leaf signer originals, not just key labels.  A
    # nominally independent custody key may not be a publisher's true key.
    x509 = parent.parent.x509core
    r399 = {'path':opts[x509.NEW_SCALARS[0]], 'sha256':opts[x509.NEW_SCALARS[1]]}
    p399 = doc(r399,'ec406_reopen_ec399_original_x509_bundle',x509.MAX_BUNDLE)
    exact(p399,x509.BUNDLE_FIELDS,'REOPENED_EC399_CERT_BUNDLE')
    need(p399['schema']==x509.BUNDLE_SCHEMA and
         p399['claimed_directory_lineage_id']==lineage,
         'ACTUAL_EC399_ORIGINAL_CERT_BUNDLE_INVALID','permission_denied')
    publisher_roster_ref = ref(p399['outside_publisher_roster_original'])
    publisher_roster = doc(publisher_roster_ref,'ec406_reopen_true_publisher_roster',x509.MAX_ROSTER)
    exact(publisher_roster,x509.ROSTER_FIELDS,'EC399_TRUE_PUBLISHER_ROSTER')
    need(publisher_roster['schema']==x509.ROSTER_SCHEMA and
         publisher_roster_ref['sha256']==opts[x509.NEW_SCALARS[2]] and
         type(publisher_roster['publishers']) is list and len(publisher_roster['publishers'])==2,
         'EC399_ORIGINAL_PUBLISHER_ROSTER_INVALID','permission_denied')
    publisher_keys = set()
    for r in publisher_roster['publishers']:
        cert = x509._chain(r,opts,read)['certs'][0]
        pub = cert.public_key()
        if isinstance(pub,Ed25519PublicKey):
            publisher_keys.add(pub.public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw))
    for item in (p399, publisher_roster):
        parent._find_ref_paths(item, protected)
    protected.update((r399['path'],publisher_roster_ref['path']))
    # Reopen the two genuine RFC3161 authority certificate originals for
    # token genTime verification, while protecting their CRL/root paths.
    trref = ref(older['outside_tsa_roster_original'])
    need(trref['sha256'] == opts[parent.NEW_SCALARS[2]],
         'REAL_EC405_TSA_ROSTER_EXTERNAL_PIN_MISMATCH','permission_denied')
    trustdoc = doc(trref,'ec406_reopen_real_ec405_tsa_roster',parent.MAX_TRUST)
    protected.add(trref['path'])
    tsa_roots = parent._trust(trustdoc,roles,opts,read,protected)
    tsa_pub_keys = set()
    for authority in tsa_roots.values():
        pub = authority['root'].public_key()
        if isinstance(pub,Ed25519PublicKey):
            tsa_pub_keys.add(pub.public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw))
    roster = doc(roster_ref,'ec406_externally_pinned_custody_witness_roster',MAX_ROSTER)
    pairs = _signers(roster,roles,opts,read,protected,previous_archive_keys,
                     publisher_keys,tsa_pub_keys)
    flags = {k:False for k in FLAGS}
    flags[FLAGS[0]] = (
        not live['bounded_local_warc_timestamp_and_real_ec404_parent_consistency'] or
        any(r['joint_warc_timestamp_and_real_parent_count']!=2
            for r in live['warc_timestamp_epoch_reviews']))
    cutoff = utc(opts[parent.parent.NEW_SCALARS[7]])
    evaluation = utc(opts[NEW_SCALARS[11]])
    first_accession, first_witness, previous_a, previous_w, times = {},{},{},{},{}
    missing_roles = set()
    record_ids, event_ids = set(),set()
    reviews, inventory_epochs, joint_total = [],[],0
    for i, epoch in enumerate(bundle['epochs']):
        exact(epoch,EPOCH_FIELDS,'CUSTODY_EPOCH')
        need(type(epoch['epoch_index']) is int and epoch['epoch_index']==i and
             type(epoch['publishers']) is list and len(epoch['publishers'])==2,
             'CUSTODY_EPOCH_INDEX_AND_TWO_ROLES_REQUIRED','permission_denied')
        p405_epoch, p404_epoch = older['epochs'][i],old404['epochs'][i]
        exact(p405_epoch,parent.EPOCH_FIELDS,'EC405_EPOCH')
        exact(p404_epoch,parent.parent.EPOCH_FIELDS,'EC404_EPOCH')
        need(type(p405_epoch['epoch_index']) is int and
             type(p404_epoch['epoch_index']) is int and
             p405_epoch['epoch_index']==p404_epoch['epoch_index']==i and
             len(p405_epoch['publishers'])==len(p404_epoch['publishers'])==2,
             'REAL_EC405_EC404_EPOCH_BINDING_MISMATCH','permission_denied')
        p405_roles={r['publisher_id']:r for r in p405_epoch['publishers']}
        p404_roles={r['publisher_id']:r for r in p404_epoch['publishers']}
        need(set(p405_roles)==set(p404_roles)==set(roles) and
             len(p405_roles)==len(p404_roles)==2,
             'PARENT_EPOCH_PUBLISHER_ROLES_DUPLICATE_OR_DISJOINT', 'permission_denied')
        seen, staging = set(),set()
        for row in epoch['publishers']:
            exact(row,ROLE_FIELDS,'CUSTODY_ROLE_PRECHECK')
            role = row['publisher_id']
            need(type(role) is str and role in roles and role not in seen,
                 'CUSTODY_PUBLISHER_ROLE_UNKNOWN_OR_DUPLICATE','permission_denied')
            seen.add(role)
            assignment = pairs[role]
            need(row['custodian_id']==assignment['custodian_id'] and
                 row['witness_id']==assignment['witness_id'],
                 'CUSTODY_ROLE_SIGNER_ID_MISMATCH','permission_denied')
            for field in ('signed_accession_original','signed_cross_witness_original'):
                if row[field] is None:continue
                r=ref(row[field])
                need(r['path'] not in protected and r['path'] not in staging,
                     'CUSTODY_SIGNED_ORIGINAL_PATH_REUSED_OR_PARENT_ALIASED',
                     'permission_denied')
                staging.add(r['path'])
        need(seen==set(roles),'CUSTODY_PUBLISHER_ROLES_MISSING','permission_denied')
        verified_a=verified_w=timely=0
        members=[]
        for row in epoch['publishers']:
            role=row['publisher_id']
            a_ref=ref(row['signed_accession_original']) if row['signed_accession_original'] else None
            w_ref=ref(row['signed_cross_witness_original']) if row['signed_cross_witness_original'] else None
            if a_ref is None:
                need(i>0 and w_ref is None,
                     'FIRST_TWO_SIGNED_ORIGINALS_REQUIRED_OR_ORPHAN_WITNESS',
                     'permission_denied')
                missing_roles.add(role)
                flags[FLAGS[2]]=True
                members.append({'publisher_id':role,
                                'signed_accession_original_sha256':None,
                                'signed_cross_witness_original_sha256':None,
                                'archive_record_id':None,'witness_event_id':None,
                                'verified_token_gen_time_utc':None,
                                'claimed_accession_utc':None,
                                'claimed_witness_utc':None,
                                'claimed_times_in_window':None})
                continue
            need(role not in missing_roles,
                 'SIGNED_CHAIN_CANNOT_RESUME_AFTER_MISSING_WITNESS_EPOCH',
                 'permission_denied')
            p405row,p404row=p405_roles[role],p404_roles[role]
            exact(p405row,parent.ROLE_FIELDS,'REAL_EC405_WARC_ROLE')
            exact(p404row,parent.parent.PUBLISHER_FIELDS,'REAL_EC404_SOURCE_ROLE')
            wr, tok, receipt = (ref(p405row['warc_original']) if p405row['warc_original'] else None,
                                ref(p405row['rfc3161_original']) if p405row['rfc3161_original'] else None,
                                ref(p404row['signed_archive_receipt_original']) if p404row['signed_archive_receipt_original'] else None)
            need(wr is not None and tok is not None and receipt is not None,
                 'TWO_SIGNATURES_REQUIRE_REAL_EC405_WARC_TOKEN_AND_EC404_RECEIPT',
                 'permission_denied')
            protected.add(a_ref['path'])
            if w_ref is not None:protected.add(w_ref['path'])
            warc = read(wr,'ec406_reopen_signed_warc_original',parent.MAX_WARC)
            token = read(tok,'ec406_reopen_rfc3161_token_original',parent.MAX_TOKEN)
            verification = parent._verified_tsa_token(token,warc,tsa_roots[role]['root'],
                                                       tsa_roots[role]['policy'])
            gen = verification['token_gen_time']
            genuine_gen_time = stamp(gen)
            accdoc = doc(a_ref,'ec406_original_genuine_custodian_accession',MAX_SIGNED)
            acc = _sign(accdoc,pairs[role]['custodian_key'],ACCESSION_DOMAIN,
                        ACCESSION_FIELDS,ACCESSION_SCHEMA,'ACCESSION')
            expected_acc = {'schema':ACCESSION_CLAIM_SCHEMA,
                'directory_lineage_id':lineage,'publisher_id':role,
                'custodian_id':row['custodian_id'], 'epoch_index':i, 'sequence':i+1,
                'previous_accession_sha256':previous_a.get(role),
                'original_ec404_signed_capture_receipt_sha256':receipt['sha256'],
                'original_warc_sha256':wr['sha256'], 'original_rfc3161_sha256':tok['sha256'],
                'verified_token_gen_time_utc':genuine_gen_time}
            need(all(type(acc.get(k)) is type(v) and acc.get(k)==v
                     for k,v in expected_acc.items()) and
                 type(acc['archive_record_id']) is str and
                 IDENT.fullmatch(acc['archive_record_id']) is not None and
                 acc['archive_record_id'] not in record_ids,
                 'SIGNED_ACCESSION_REAL_ORIGINAL_SHA_CHAIN_OR_RECORD_ID_MISMATCH',
                 'permission_denied')
            record_ids.add(acc['archive_record_id'])
            verified_a+=1
            if w_ref is None:
                need(i>0, 'FIRST_TWO_SIGNED_ORIGINALS_REQUIRED_OR_ORPHAN_WITNESS',
                     'permission_denied')
                # Even an unwitnessed later accession is fully checked against
                # real originals and its genuine RFC3161 signed time. It can
                # never earn joint credit, and no future epoch can hide its gap.
                missing_roles.add(role)
                flags[FLAGS[2]]=True
                accession_time=utc(acc['claimed_accession_utc'])
                if not(gen<=accession_time<=cutoff and accession_time<=evaluation):
                    flags[FLAGS[3]]=True
                previous_a[role]=a_ref['sha256']
                members.append({'publisher_id':role,
                                'signed_accession_original_sha256':a_ref['sha256'],
                                'signed_cross_witness_original_sha256':None,
                                'archive_record_id':acc['archive_record_id'],
                                'witness_event_id':None,
                                'verified_token_gen_time_utc':genuine_gen_time,
                                'claimed_accession_utc':acc['claimed_accession_utc'],
                                'claimed_witness_utc':None,
                                'claimed_times_in_window':None})
                continue
            witdoc = doc(w_ref,'ec406_original_genuine_independent_witness',MAX_SIGNED)
            wit = _sign(witdoc,pairs[role]['witness_key'],WITNESS_DOMAIN,
                        WITNESS_FIELDS,WITNESS_SCHEMA,'WITNESS')
            expected_wit = {'schema':WITNESS_CLAIM_SCHEMA,
                'directory_lineage_id':lineage,'publisher_id':role,
                'witness_id':row['witness_id'],'epoch_index':i,'sequence':i+1,
                'previous_witness_sha256':previous_w.get(role),
                'signed_accession_original_sha256':a_ref['sha256'],
                'original_warc_sha256':wr['sha256'], 'original_rfc3161_sha256':tok['sha256']}
            need(all(type(wit.get(k)) is type(v) and wit.get(k)==v
                     for k,v in expected_wit.items()) and
                 type(wit['witness_event_id']) is str and
                 IDENT.fullmatch(wit['witness_event_id']) is not None and
                 wit['witness_event_id'] not in event_ids,
                 'SIGNED_WITNESS_EXACT_ACCESSION_TOKEN_CHAIN_OR_EVENT_ID_MISMATCH',
                 'permission_denied')
            event_ids.add(wit['witness_event_id'])
            verified_w+=1
            accessor_time=utc(acc['claimed_accession_utc'])
            observer_time=utc(wit['claimed_witness_utc'])
            in_window=(gen<=accessor_time<=observer_time<=cutoff and
                       observer_time<=evaluation and
                       (role not in times or
                        (accessor_time>=times[role][0] and observer_time>=times[role][1])))
            if not in_window:flags[FLAGS[3]]=True
            else:timely+=1
            times[role]=(accessor_time,observer_time)
            previous_a[role],previous_w[role]=a_ref['sha256'],w_ref['sha256']
            if i==0:
                first_accession[role],first_witness[role]=a_ref['sha256'],w_ref['sha256']
            members.append({'publisher_id':role,
                            'signed_accession_original_sha256':a_ref['sha256'],
                            'signed_cross_witness_original_sha256':w_ref['sha256'],
                            'archive_record_id':acc['archive_record_id'],
                            'witness_event_id':wit['witness_event_id'],
                            'verified_token_gen_time_utc':genuine_gen_time,
                            'claimed_accession_utc':acc['claimed_accession_utc'],
                            'claimed_witness_utc':wit['claimed_witness_utc'],
                            'claimed_times_in_window':in_window})
        members.sort(key=lambda r:r['publisher_id'])
        parent_joint=live['warc_timestamp_epoch_reviews'][i][
            'joint_warc_timestamp_and_real_parent_count']
        # No upgrade or partial repair: the entire 2-role parent epoch must be
        # genuinely complete before any joint custody-witness credit.
        joint=timely if (not flags[FLAGS[0]] and parent_joint==2) else 0
        if joint!=2:flags[FLAGS[4]]=True
        inv={'epoch_index':i,'publishers':members,
             'verified_signed_accession_count':verified_a,
             'verified_signed_witness_count':verified_w,
             'claimed_accession_witness_times_in_window_count':timely,
             'joint_signed_custody_witness_and_parent_count':joint}
        digest=cdigest(inv)
        if digest!=opts[REPEAT_NAMES[0]][i] or joint<opts[REPEAT_NAMES[1]][i]:
            flags[FLAGS[1]]=True
        inventory_epochs.append(inv)
        reviews.append({'epoch_index':i,'verified_signed_accession_count':verified_a,
                        'verified_signed_witness_count':verified_w,
                        'claimed_times_in_window_count':timely,
                        'joint_signed_custody_witness_and_parent_count':joint,
                        'custody_witness_epoch_inventory_sha256':digest,
                        'real_ec405_parent_joint_warc_timestamp_count':parent_joint})
        joint_total+=joint
    need(len(first_accession)==len(first_witness)==2,
         'BOTH_FIRST_SIGNED_ACCESSION_AND_CROSS_WITNESS_ORIGINALS_MANDATORY',
         'permission_denied')
    for j,key in enumerate(NEW_SCALARS[7:11]):
        expected = (first_accession[roles[j]] if j<2 else first_witness[roles[j-2]])
        if opts[key]!=expected:flags[FLAGS[1]]=True
    inventory={'schema':INVENTORY_SCHEMA,'directory_lineage_id':lineage,
               'verified_real_ec405_report_sha256':live_sha,
               'verified_real_ec405_inventory_sha256':live[
                   'receiver_verified_warc_timestamp_inventory_sha256'],
               'original_ec405_warc_timestamp_bundle_sha256':b405['sha256'],
               'original_ec406_custody_witness_bundle_sha256':b406['sha256'],
               'outside_custody_witness_roster_sha256':roster_ref['sha256'],
               'outside_claimed_dispute_cutoff_utc':opts[parent.parent.NEW_SCALARS[7]],
               'ec406_custody_evaluation_utc':opts[NEW_SCALARS[11]],
               'outside_first_signed_accession_shas':[
                   opts[NEW_SCALARS[7]],opts[NEW_SCALARS[8]]],
               'outside_first_signed_witness_shas':[
                   opts[NEW_SCALARS[9]],opts[NEW_SCALARS[10]]],
               'epochs':inventory_epochs}
    invsha=cdigest(inventory)
    if not deriving and invsha!=opts[AUDIT_ONLY[0]]:
        flags[FLAGS[1]]=True
    for path,(digest,limit) in late.items():
        reread=io._read({'path':path,'sha256':digest},
                        'ec406_final_original_sha_readback',limit,{},{},set())
        need(sha(reread)==digest,'ORIGINAL_CHANGED_DURING_FINAL_READBACK',
             'permission_denied')
    for name in FLAGS[-3:]:flags[name]=True
    return {'schema':DERIVE_SCHEMA if deriving else RESULT_SCHEMA,
            'command':('derive-historical-ec339-custody-witness-inventory' if deriving else
                       'audit-historical-ec339-custody-witness'),
            'status':next((OUTCOMES[i] for i,k in enumerate(FLAGS) if flags[k]),
                          OUTCOMES[-1])+'_unresolved',
            'exit_code':2,'offline_unresolved_exit_code':2,
            'verified_live_ec405_report_sha256':live_sha,
            'verified_live_ec405_inventory_sha256':live[
                'receiver_verified_warc_timestamp_inventory_sha256'],
            'original_custody_witness_bundle_sha256':b406['sha256'],
            'receiver_verified_custody_witness_inventory_sha256':invsha,
            'verified_joint_custody_witness_and_real_parent_publishers':joint_total,
            'custody_witness_epoch_reviews':reviews,
            'bounded_local_custody_witness_and_real_ec405_parent_consistency':
                not any(flags[k] for k in FLAGS[:5]),
            'sender_origin_path_required_or_read':False,
            'ec339_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
            **flags,**{k:False for k in NEGATIVES},
            **({'unsigned_custody_witness_evidence_inventory':inventory} if deriving else {})}


def derive_inventory(**opts):
    return _engine(True,**opts)


def audit(**opts):
    return _engine(False,**opts)
