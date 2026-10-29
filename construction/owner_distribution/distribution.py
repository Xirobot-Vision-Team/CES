#!/usr/bin/env python3
"""EC359: verify imported, issuer-signed owner distribution originals offline.

These statements have verifiable *local* authority only relative to two public
key pins supplied by the caller. This module does not authenticate official
issuers, legal authority, public distribution, trusted UTC, or hidden forks.
Every legitimate audit is unresolved (exit 2). No network, signer or writer.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as tsa
from transparency import transparency as tr
from reviewer_epochs import epochs as parent

RESULT_SCHEMA = 'ces.ec359.offline_owner_distribution_claims_unresolved.v1'
DENIAL_SCHEMA = 'ces.ec359.offline_owner_distribution_denial.v1'
HANDOFF_SCHEMA = 'ces.ec359.unsigned_owner_distribution_handoff.v1'
BUNDLE_SCHEMA = 'ces.ec359.pinned_owner_distribution_bundle.v1'
RECORD_SCHEMA = 'ces.ec359.signed_owner_distribution_record.v1'
SCOPE = 'ces.reviewer_owner_distribution.v1'
SIGN_DOMAIN = b'CES/EC359/OwnerDistribution/Issuer/v1\x00'
MAX_BUNDLE = 24_000
MAX_RECORD = 6_000
MAX_RECORDS = 6
MAX_SPAN = timedelta(days=90)
MAX_FRESH = timedelta(days=30)
RECORD_FIELDS = {
    'schema', 'scope', 'slot', 'issuer_id',
    'issuer_public_key_original_sha256', 'claimed_owner_id',
    'owner_public_key_original_sha256',
    'parent_ec358_canonical_result_sha256',
    'parent_owner_head_event_original_sha256',
    'sequence', 'previous_record_original_sha256', 'operation',
    'replacement_owner_public_key_sha256', 'effective_utc', 'expires_utc',
    'signature_issuer_ed25519_hex',
}
OUTCOMES = (
    'ec359_parent_ec358_signed_owner_epochs_unresolved',
    'ec359_two_imported_distribution_sources_or_heads_missing',
    'ec359_signed_distribution_fork_or_issuer_identity_collision_visible',
    'ec359_signed_owner_deauthorization_or_replacement_visible',
    'ec359_caller_pinned_distribution_head_or_sequence_rollback_visible',
    'ec359_issuer_signed_time_window_stale_future_or_conflicting',
    'ec359_two_locally_signed_owner_distributions_official_issuer_authority_unproven',
)
NEGATIVES = (
    'two_caller_pinned_distributor_keys_are_official_trust_anchors',
    'issuer_signed_identity_claim_is_external_legal_identity_proof',
    'two_distinct_public_key_sha_prove_independent_real_organizations',
    'signed_distribution_event_proves_trusted_historical_utc',
    'presented_signed_heads_prove_no_other_branch_or_later_revocation',
    'issuer_rotate_reauthorizes_invalid_or_revoked_parent_owner_epochs',
    'locally_pinned_authentication_proves_external_public_directory_origin',
    'signature_repairs_bad_ec358_through_ec337_original_evidence',
    'offline_audit_fetches_certificates_revocations_urls_or_network',
    'offline_audit_generates_private_keys_or_writes_provider_cas_worm',
    'native_powershell_ec317_318_or_final_acceptance_proven',
)


def need(condition, reason, status='invalid_input'):
    if condition is not True:
        raise errors.AnchorError('EC359_' + reason, status)


def exact(doc, fields, role):
    need(type(doc) is dict and set(doc) == set(fields), role + '_EXACT_FIELDS_REQUIRED')


def sha(raw):
    return parent._sha(raw)


def _parent(epoch_inputs):
    result = parent.audit(**epoch_inputs)  # Replays true EC357..EC337 on every call.
    need(result.get('schema') == parent.RESULT_SCHEMA and
         result.get('exit_code') == 2 and
         result.get('actual_ec357_through_ec337_signed_originals_replayed') is True,
         'PARENT_EC358_REAL_SIGNED_REPLAY_REQUIRED', 'permission_denied')
    return result


def _prior_boundary(epoch_inputs):
    """Account for old originals and *all* old signing-role bytes.

    Parent auditor already verifies their cryptographic content. Reopening the
    EC358 manifest here gives the new issuer files a complete old-file/role
    boundary, including unused yet furnished signed siblings and reviewer keys.
    """
    pins, paths, keys = parent._old_boundary(epoch_inputs)
    # Include EC357 source reviewer keys even when EC358 does not present an
    # epoch event for that source: an unmentioned old signing role is still old.
    for slot in ('a', 'b'):
        source_path = epoch_inputs.get('source_' + slot + '_authority_public_key_file')
        source_digest = epoch_inputs.get('expected_source_' + slot + '_authority_public_key_sha256')
        if source_path is not None and source_digest is not None:
            source_bytes = parent.parent.prior._inherited(
                {'path': source_path, 'sha256': source_digest},
                'EC359_EC357_REVIEWER_ROLE', 32, pins)
            keys.add(sha(source_bytes));paths.add(source_path)
    for slot in ('a', 'b'):
        path = epoch_inputs.get('owner_' + slot + '_public_key_file')
        digest = epoch_inputs.get('expected_owner_' + slot + '_public_key_sha256')
        if path is not None and digest is not None:
            raw = parent.parent.prior._inherited({'path': path, 'sha256': digest},
                                           'EC359_PRIOR_OWNER_KEY', 32, pins)
            keys.add(sha(raw));paths.add(path)
    old_path = epoch_inputs.get('reviewer_epoch_bundle_file')
    old_sha = epoch_inputs.get('expected_reviewer_epoch_bundle_sha256')
    if old_path is not None and old_sha is not None:
        raw = parent.parent.prior._inherited({'path': old_path, 'sha256': old_sha},
                                      'EC359_PRIOR_EPOCH_BUNDLE', parent.MAX_BUNDLE, pins)
        paths.add(old_path)
        doc = tr.strict_json(raw, 'EC359_OLD_EPOCH_BUNDLE')
        exact(doc, ('schema', 'sources'), 'OLD_EPOCH_BUNDLE')
        need(doc['schema'] == parent.BUNDLE_SCHEMA, 'OLD_EPOCH_BUNDLE_SCHEMA_MISMATCH')
        for entry in doc['sources']:
            for event in entry['events']:
                for field, cap in (('event_original', parent.MAX_EVENT),
                                   ('previous_reviewer_public_key', 32),
                                   ('current_reviewer_public_key', 32)):
                    pin = event[field]
                    if pin is None:continue
                    data = parent.parent.prior._inherited(pin, 'EC359_PRIOR_' + field.upper(), cap, pins)
                    paths.add(pin['path'])
                    if field != 'event_original':keys.add(sha(data))
    return pins, paths, keys


def _pin(pair, role):
    exact(pair, ('path', 'sha256'), role + '_PIN')
    need(type(pair['path']) is str and tr._sha(pair['sha256']), role + '_PIN_INVALID')


def _load(pair, role, cap, newpins, oldpaths, categories, category):
    _pin(pair, role)
    return parent._read_new(pair, role, cap, newpins, oldpaths, categories, category)


def _verify(raw, pub, slot, issuer_sha, owner, parent_sha):
    doc = tr.strict_json(raw, 'EC359_SIGNED_DISTRIBUTION')
    exact(doc, RECORD_FIELDS, 'DISTRIBUTION_RECORD')
    need(doc['schema'] == RECORD_SCHEMA and doc['scope'] == SCOPE and
         doc['slot'] == slot and tr._ident(doc['issuer_id']) and
         doc['issuer_public_key_original_sha256'] == issuer_sha and
         doc['claimed_owner_id'] == owner['owner_id_as_signed_claim'] and
         doc['owner_public_key_original_sha256'] == owner['owner_public_key_original_sha256'] and
         doc['parent_ec358_canonical_result_sha256'] == parent_sha and
         doc['parent_owner_head_event_original_sha256'] ==
             owner['expected_head_sha256_as_caller_pin'],
         'SIGNATURE_SCOPE_OWNER_OR_REAL_PARENT_BINDING_MISMATCH', 'permission_denied')
    seq = doc['sequence']; operation = doc['operation']
    need(type(seq) is int and 0 <= seq < MAX_RECORDS and
         operation in ('authorize', 'revoke', 'rotate') and
         (doc['previous_record_original_sha256'] is None or
          tr._sha(doc['previous_record_original_sha256'])),
         'SEQUENCE_OPERATION_OR_PREDECESSOR_INVALID')
    replacement = doc['replacement_owner_public_key_sha256']
    if operation == 'authorize':
        need(replacement is None, 'AUTHORIZE_CANNOT_REPLACE_AN_OWNER', 'permission_denied')
    elif operation == 'rotate':
        need(seq > 0 and tr._sha(replacement) and
             replacement != owner['owner_public_key_original_sha256'],
             'ROTATION_MUST_DEAUTHORIZE_OLD_DISTINCT_OWNER', 'permission_denied')
    else:
        need(seq > 0 and replacement is None,
             'REVOCATION_MUST_HAVE_PRIOR_AND_NO_REPLACEMENT', 'permission_denied')
    need((seq == 0) == (doc['previous_record_original_sha256'] is None) and
         (seq != 0 or operation == 'authorize'),
         'GENESIS_OR_PREDECESSOR_SHAPE_INVALID', 'permission_denied')
    effective = tr._utc(doc['effective_utc']);expires = tr._utc(doc['expires_utc'])
    need(effective < expires and expires - effective <= MAX_SPAN,
         'SIGNED_WINDOW_INVALID', 'permission_denied')
    signature = doc['signature_issuer_ed25519_hex']
    need(type(signature) is str and tr.SIG_RE.fullmatch(signature) is not None,
         'ISSUER_SIGNATURE_FORMAT_INVALID')
    unsigned = {k: v for k, v in doc.items() if k != 'signature_issuer_ed25519_hex'}
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(
            bytes.fromhex(signature), SIGN_DOMAIN + canonical.canonical(unsigned))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise errors.AnchorError('EC359_DISTRIBUTOR_REAL_SIGNATURE_INVALID',
                                 'permission_denied') from exc
    return doc, effective, expires


def checklist(**epoch_inputs):
    p = _parent(epoch_inputs)
    return {'schema': HANDOFF_SCHEMA, 'command': 'derive-owner-distribution-handoff',
            'status': 'caller_must_furnish_two_externally_anchored_signed_distribution_histories_unresolved',
            'exit_code': 2, 'case_id': p['case_id'],
            'actual_ec358_through_ec337_signed_originals_replayed': True,
            'parent_ec358_canonical_result_sha256': sha(canonical.canonical(p)),
            'required_owner_histories': [
                {'slot': o['slot'], 'claimed_owner_id': o['owner_id_as_signed_claim'],
                 'owner_key_sha256': o['owner_public_key_original_sha256'],
                 'owner_head_sha256': o['expected_head_sha256_as_caller_pin']}
                for o in p['owner_establishments']],
            'chain_external_trust_anchor_source_and_issuer_authority_unproven': True,
            'offline_unresolved_exit_code': 2,
            **{key: False for key in NEGATIVES}}


def audit(*, distribution_evaluation_utc, distribution_bundle_file=None,
          expected_distribution_bundle_sha256=None,
          distributor_a_public_key_file=None, expected_distributor_a_public_key_sha256=None,
          distributor_b_public_key_file=None, expected_distributor_b_public_key_sha256=None,
          minimum_a_distribution_sequence=None, minimum_b_distribution_sequence=None,
          expected_a_distribution_head_sha256=None, expected_b_distribution_head_sha256=None,
          **epoch_inputs):
    evaluation = tr._utc(distribution_evaluation_utc)
    need(evaluation >= tr._utc(epoch_inputs['reviewer_epoch_evaluation_utc']),
         'DISTRIBUTION_EVALUATION_BEFORE_EC358', 'permission_denied')
    prior = _parent(epoch_inputs)
    parent_sha = sha(canonical.canonical(prior))
    oldpins, oldpaths, oldkeys = _prior_boundary(epoch_inputs)
    owners = {o['slot']: o for o in prior['owner_establishments']}
    pins = {'a': (distributor_a_public_key_file, expected_distributor_a_public_key_sha256),
            'b': (distributor_b_public_key_file, expected_distributor_b_public_key_sha256)}
    floors = {'a': minimum_a_distribution_sequence, 'b': minimum_b_distribution_sequence}
    heads = {'a': expected_a_distribution_head_sha256, 'b': expected_b_distribution_head_sha256}
    for slot in ('a', 'b'):
        path, digest = pins[slot]
        need((path, digest) == (None, None) or
             (type(path) is str and tr._sha(digest)),
             'DISTRIBUTOR_PIN_PAIR_' + slot.upper() + '_INVALID')
        need(floors[slot] is None or
             (type(floors[slot]) is int and 0 <= floors[slot] < MAX_RECORDS),
             'DISTRIBUTOR_MINIMUM_SEQUENCE_' + slot.upper() + '_INVALID')
        need(heads[slot] is None or tr._sha(heads[slot]),
             'DISTRIBUTOR_HEAD_SHA_' + slot.upper() + '_INVALID')
    if all(pins[slot] != (None, None) for slot in ('a', 'b')):
        need(pins['a'][0] != pins['b'][0] and pins['a'][1] != pins['b'][1],
             'DISTRIBUTOR_KEYS_MUST_BE_DISTINCT', 'permission_denied')
    bundle = (distribution_bundle_file, expected_distribution_bundle_sha256)
    need(bundle == (None, None) or
         (type(bundle[0]) is str and tr._sha(bundle[1])),
         'DISTRIBUTION_BUNDLE_PIN_PAIR_INVALID')
    newpins, categories = {}, {}
    rows = []
    entries = []
    if bundle != (None, None):
        raw = _load({'path': bundle[0], 'sha256': bundle[1]},
                    'DISTRIBUTION_BUNDLE', MAX_BUNDLE, newpins, oldpaths,
                    categories, 'manifest')
        doc = tr.strict_json(raw, 'EC359_BUNDLE')
        exact(doc, ('schema', 'sources'), 'DISTRIBUTION_BUNDLE')
        need(doc['schema'] == BUNDLE_SCHEMA and type(doc['sources']) is list and
             len(doc['sources']) <= 2, 'DISTRIBUTION_BUNDLE_FORMAT_INVALID')
        entries = doc['sources']
    used = set();issuer_keys = set();issuer_ids = set()
    missing = False; fork = False;deauthorized = False;rollback = False;stale = False
    for entry in entries:
        exact(entry, ('slot', 'distributor_public_key', 'records'),
              'DISTRIBUTION_SOURCE')
        slot = entry['slot']
        need(slot in ('a', 'b') and slot not in used,
             'DUPLICATE_OR_INVALID_DISTRIBUTION_SLOT', 'permission_denied')
        used.add(slot)
        need(slot in owners, 'PARENT_REPLAYED_OWNER_NOT_PRESENT', 'permission_denied')
        path, digest = pins[slot]
        need((path, digest) != (None, None),
             'SEPARATE_ISSUER_PIN_REQUIRED', 'permission_denied')
        issuer_pin = {'path': path, 'sha256': digest}
        need(entry['distributor_public_key'] == issuer_pin,
             'DISTRIBUTOR_PIN_MUST_BE_SEPARATELY_CALLER_FIXED', 'permission_denied')
        public = _load(issuer_pin, 'DISTRIBUTOR_PUBLIC_KEY', 32, newpins,
                       oldpaths, categories, 'distributor')
        need(len(public) == 32 and sha(public) == digest and
             digest not in oldkeys and digest not in issuer_keys,
             'DISTRIBUTOR_PUBLIC_KEY_REUSES_PRIOR_OR_OTHER_ROLE', 'permission_denied')
        issuer_keys.add(digest)
        record_pins = entry['records']
        need(type(record_pins) is list and len(record_pins) <= MAX_RECORDS,
             'DISTRIBUTION_RECORD_COUNT_OUT_OF_BOUNDS')
        records = {};children = defaultdict(list);genesis = [];ids = set()
        for record_pin in record_pins:
            _pin(record_pin, 'SIGNED_DISTRIBUTION_RECORD')
            raw = _load(record_pin, 'SIGNED_DISTRIBUTION_RECORD', MAX_RECORD,
                        newpins, oldpaths, categories, 'signed_record')
            digest_record = sha(raw)
            need(digest_record not in records,
                 'DUPLICATE_SIGNED_DISTRIBUTION_RECORD', 'permission_denied')
            record, frm, to = _verify(raw, public, slot, digest, owners[slot], parent_sha)
            records[digest_record] = (record, frm, to)
            ids.add(record['issuer_id'])
            if record['operation'] in ('revoke', 'rotate'):deauthorized = True
            if record['previous_record_original_sha256'] is None:
                genesis.append(digest_record)
            else:
                children[record['previous_record_original_sha256']].append(digest_record)
        for event_sha, (record, frm, to) in records.items():
            prev = record['previous_record_original_sha256']
            if prev is None:continue
            ancestor = records.get(prev)
            need(ancestor is not None, 'MISSING_REAL_SIGNED_DISTRIBUTION_PREDECESSOR',
                 'permission_denied')
            before, before_from, _ = ancestor
            need(before['operation'] == 'authorize' and
                 record['sequence'] == before['sequence'] + 1,
                 'DISTRIBUTION_SEQUENCE_OR_TERMINAL_PARENT_INVALID',
                 'permission_denied')
            if frm < before_from:stale = True
        need(not records or bool(genesis),
             'DISTRIBUTION_HISTORY_WITHOUT_GENESIS', 'permission_denied')
        if len(genesis) > 1 or any(len(branch) > 1 for branch in children.values()):
            fork = True
        if len(ids) > 1 or any(identity in issuer_ids for identity in ids):
            fork = True
        issuer_ids.update(ids)
        for rec_sha in records:
            seen = set();cursor = rec_sha
            while cursor is not None:
                need(cursor not in seen, 'DISTRIBUTION_SIGNED_ANCESTRY_CYCLE',
                     'permission_denied')
                seen.add(cursor)
                cursor = records[cursor][0]['previous_record_original_sha256']
        selected_sha = heads[slot]
        if selected_sha is not None:
            need(selected_sha in records, 'CALLER_HEAD_NOT_IN_SIGNED_DISTRIBUTION_HISTORY',
                 'permission_denied')
        selected = records.get(selected_sha)
        if not records or selected is None or floors[slot] is None:
            missing = True
        sequence = operation = None
        if selected is not None:
            record, frm, to = selected
            sequence = record['sequence'];operation = record['operation']
            if children.get(selected_sha) or (floors[slot] is not None and
                                              sequence < floors[slot]):
                rollback = True
            if operation in ('rotate', 'revoke'):deauthorized = True
            if frm > evaluation or to < evaluation or evaluation - frm > MAX_FRESH:
                stale = True
        endpoints = [x for x in records if not children.get(x)]
        if len(endpoints) > 1:fork = True
        if any(records[x][0]['operation'] in ('revoke', 'rotate') for x in endpoints):
            deauthorized = True
        rows.append({
            'slot': slot,
            'issuer_id_as_signed_claim': next(iter(ids)) if len(ids) == 1 else None,
            'issuer_public_key_original_sha256': digest,
            'parent_owner_public_key_original_sha256': owners[slot]['owner_public_key_original_sha256'],
            'parent_owner_head_event_sha256': owners[slot]['expected_head_sha256_as_caller_pin'],
            'expected_distribution_head_sha256_as_caller_pin': selected_sha,
            'minimum_sequence_as_caller_claim': floors[slot],
            'observed_signed_record_count': len(records),
            'observed_signed_endpoint_count': len(endpoints),
            'selected_head_sequence': sequence,
            'selected_head_operation': operation,
            'signed_records': [
                {'record_original_sha256': h, 'sequence': obj['sequence'],
                 'operation': obj['operation'],
                 'previous_record_original_sha256': obj['previous_record_original_sha256'],
                 'effective_utc_as_issuer_claim': obj['effective_utc'],
                 'expires_utc_as_issuer_claim': obj['expires_utc']}
                for h, (obj, _, _) in sorted(records.items(),
                      key=lambda item: (item[1][0]['sequence'], item[0]))],
        })
    if len(used) != 2:missing = True
    # After the source signatures are verified, re-open all inherited and new
    # originals, and check current inode and all path ancestor identities.
    tsa._check_late(oldpins)
    tsa._check_late(newpins)
    parent.parent._late_identity_check(newpins, oldpaths)
    parent_good = (prior['two_signed_owner_histories_locally_continuous_and_match_ec357_review']
                   is True and prior['owner_review_count'] == 2 and
                   all(r['outcome'] == parent.OUTCOMES[-1]
                       for r in prior['channel_evidence']))
    locally_matched = bool(parent_good and len(rows) == 2 and
                           not (missing or fork or deauthorized or rollback or stale))
    if not parent_good:outcome = OUTCOMES[0]
    elif missing:outcome = OUTCOMES[1]
    elif fork:outcome = OUTCOMES[2]
    elif deauthorized:outcome = OUTCOMES[3]
    elif rollback:outcome = OUTCOMES[4]
    elif stale:outcome = OUTCOMES[5]
    else:outcome = OUTCOMES[6]
    evidence = [{'tsa_channel_id': row['tsa_channel_id'],
                 'parent_ec358_outcome': row['outcome'], 'outcome': outcome}
                for row in prior['channel_evidence']]
    return {
        'schema': RESULT_SCHEMA, 'command': 'audit-owner-distribution',
        'status': outcome + '_unresolved', 'exit_code': 2, 'case_id': prior['case_id'],
        'actual_ec358_through_ec337_signed_originals_replayed': True,
        'parent_ec358_canonical_result_sha256': parent_sha,
        'parent_epoch_bundle_original_sha256': prior['reviewer_epoch_bundle_original_sha256'],
        'distribution_bundle_original_sha256': bundle[1],
        'distribution_evaluation_utc_as_caller_claim': distribution_evaluation_utc,
        'distribution_establishments': rows, 'distribution_review_count': len(rows),
        'signed_distribution_fork_or_issuer_claim_collision_visible': fork,
        'signed_owner_revocation_or_replacement_visible': deauthorized,
        'caller_pinned_distribution_rollback_visible': rollback,
        'missing_signed_distributor_head_or_separate_key_visible': missing,
        'signed_distribution_clock_claim_anomaly_visible': stale,
        'two_issuer_signed_distributions_locally_match_ec358_owner': locally_matched,
        'official_issuer_authority_external_root_distribution_trusted_utc_and_global_head_unproven': True,
        'channel_evidence': evidence,
        'outcome_counts': {kind: sum(e['outcome'] == kind for e in evidence)
                           for kind in OUTCOMES},
        'offline_unresolved_exit_code': 2,
        **{key: False for key in NEGATIVES},
    }
