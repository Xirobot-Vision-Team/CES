#!/usr/bin/env python3
"""EC312: reconcile TWO genuinely distinct signed observer histories.

For each of 2-8 different CAS issuer receipts, both observer sites must
provide their OWN EC309 Ed25519-signed readback, nonce, whole-file SHA, and
unbroken predecessor sequence/raw-SHA/revision chain. Both independently
replay the unchanged EC309 -> EC308 -> EC307 -> EC294 signed original files.
A shared signed revision with different signed heads is a genuine statement
conflict; it does NOT establish which observer saw a real physical store.

No network, signer, key-custodian, CAS API, or external storage I/O exists.
"""
from __future__ import annotations

import os
from typing import Any

from ec295_delivery_anchor import anchor as a
from ec295_delivery_anchor import operator as store
from ec302_portable_bundle import bundle as b
from ec306_registrar_epochs import epochs
from ec308_cas_receipt import receipt as cas
from ec309_cas_readback import readback as rb

MANIFEST_SCHEMA = 'ces.ec312.two_observer_signed_cas_window_manifest.v1'
REPORT_SCHEMA = 'ces.ec312.two_observer_signed_cas_window_audit.v1'
RESULT_SCHEMA = 'ces.ec312.two_observer_signed_cas_window_result.v1'
DENIAL_SCHEMA = 'ces.ec312.two_observer_signed_cas_window_denial.v1'
MIN_DECISIONS = 2
MAX_DECISIONS = 8
MAX_MANIFEST_BYTES = 70_000
MAX_REPORT_BYTES = 110_000
MANIFEST_FIELDS = frozenset({
    'schema', 'cas_authority_id', 'cas_authority_public_hex',
    'cas_store_namespace_id', 'observers', 'decisions',
})
OBSERVER_FIELDS = frozenset({'observer_id', 'observer_public_hex', 'boundary'})
BOUNDARY_FIELDS = frozenset({
    'sequence', 'raw_sha256', 'observed_revision', 'observed_head_raw_sha256',
})
DECISION_FIELDS = frozenset({
    'fork_case_file', 'expected_fork_case_sha256',
    'fork_evidence_file', 'expected_fork_evidence_sha256',
    'receipt_file', 'expected_receipt_sha256',
    'expected_request_nonce_sha256', 'expected_parent_cas_revision',
    'expected_parent_cas_head_sha256', 'readbacks',
})
READBACK_FIELDS = frozenset({
    'observer_id', 'readback_file', 'expected_readback_sha256',
    'expected_readback_request_nonce_sha256',
})
GOOD = 'two_independent_signed_observer_windows_and_issuer_chain_compatible_not_store_proof'
ROLLBACK = 'signed_observer_window_revision_rollback'
SELF_CONFLICT = 'signed_single_observer_same_revision_different_head'
CROSS_CONFLICT = 'two_signed_observers_same_revision_different_head'
BROKEN_PARENT = 'two_observer_window_signed_cas_parent_discontinuity'
DIFFERENT_REVISIONS = 'two_signed_observers_on_same_decision_report_different_revisions'
NOT_CORROBORATED = 'signed_cas_decision_not_corroborated_by_both_observers'


def need(condition: Any, code: str, status: str = 'permission_denied') -> None:
    if condition is not True:
        raise a.AnchorError('EC312_' + code, status)


def _path(value: Any) -> bool:
    return (type(value) is str and 0 < len(value) <= 4000 and
            '\x00' not in value and os.path.isabs(value))


def _boundary(value: dict, count: int) -> None:
    a.exact(value, BOUNDARY_FIELDS, 'EC312_EXACT_OBSERVER_BOUNDARY_REQUIRED')
    sequence = value['sequence']
    need(type(sequence) is int and 0 <= sequence <= rb.MAX_OBSERVER_SEQUENCE-count,
         'OBSERVER_SEQUENCE_HAS_INSUFFICIENT_WINDOW_BUDGET', 'invalid_input')
    if sequence == 0:
        need(value['raw_sha256'] == a.GENESIS and
             value['observed_revision'] is None and
             value['observed_head_raw_sha256'] is None,
             'GENESIS_BOUNDARY_MUST_HAVE_NULL_REVISION_AND_HEAD')
    else:
        need(rb._sha(value['raw_sha256']) and
             type(value['observed_revision']) is int and
             0 <= value['observed_revision'] <= cas.MAX_CAS_REVISION and
             rb._sha(value['observed_head_raw_sha256']),
             'NON_GENESIS_BOUNDARY_REQUIRES_EXTERNAL_RAW_SHA_REVISION_HEAD')


def _validate_manifest(manifest: dict) -> None:
    a.exact(manifest, MANIFEST_FIELDS, 'EC312_EXACT_MANIFEST_FIELDS_REQUIRED')
    need(manifest['schema'] == MANIFEST_SCHEMA, 'MANIFEST_SCHEMA_INVALID')
    decisions = manifest['decisions']
    observers = manifest['observers']
    need(type(decisions) is list and MIN_DECISIONS <= len(decisions) <= MAX_DECISIONS,
         'TWO_TO_EIGHT_DISTINCT_SIGNED_CAS_DECISIONS_REQUIRED', 'invalid_input')
    need(type(observers) is list and len(observers) == 2,
         'EXACTLY_TWO_INDEPENDENT_OBSERVER_WINDOWS_REQUIRED', 'invalid_input')
    # These are independent operator pins, not identities read from a claimed
    # signature. Original EC308 and EC309 validate strict source identities.
    cas._trust({
        'cas_authority_id': manifest['cas_authority_id'],
        'cas_authority_public_hex': manifest['cas_authority_public_hex'],
        'expected_request_nonce_sha256': 'f'*64,
        'expected_parent_cas_revision': 0,
        'expected_parent_cas_head_sha256': 'e'*64,
    })
    names: list[str] = []
    keys: list[str] = []
    boundaries: set[str] = set()
    for observer in observers:
        a.exact(observer, OBSERVER_FIELDS, 'EC312_EXACT_OBSERVER_FIELDS_REQUIRED')
        _boundary(observer['boundary'], len(decisions))
        rb._validate_observer_trust({
            'cas_store_namespace_id': manifest['cas_store_namespace_id'],
            'observer_id': observer['observer_id'],
            'observer_public_hex': observer['observer_public_hex'],
            'expected_readback_request_nonce_sha256': 'f'*64,
            'expected_previous_readback_sequence': 0,
            'expected_previous_readback_raw_sha256': a.GENESIS,
            'expected_previous_readback_observed_revision': None,
        }, cas_nonce='e'*64,
            cas_public=manifest['cas_authority_public_hex'])
        need(observer['observer_id'] != manifest['cas_authority_id'],
             'OBSERVER_AND_ISSUER_IDENTITIES_MUST_BE_SEPARATE')
        names.append(observer['observer_id'])
        keys.append(observer['observer_public_hex'])
        if observer['boundary']['sequence']:
            boundaries.add(observer['boundary']['raw_sha256'])
    need(names == sorted(set(names)) and len(set(keys)) == 2,
         'TWO_DISTINCT_SORTED_OBSERVER_IDENTITIES_AND_PUBLIC_KEYS_REQUIRED')

    issuer_nonces: set[str] = set()
    all_nonces: set[str] = set()
    receipts: set[str] = set()
    readback_shas: set[str] = set()
    for decision in decisions:
        a.exact(decision, DECISION_FIELDS, 'EC312_EXACT_SIGNED_DECISION_FIELDS_REQUIRED')
        for field in ('fork_case_file', 'fork_evidence_file', 'receipt_file'):
            need(_path(decision[field]),
                 'ALL_SIGNED_ORIGINAL_EVIDENCE_PATHS_MUST_BE_ABSOLUTE', 'invalid_input')
        for field in ('expected_fork_case_sha256', 'expected_fork_evidence_sha256',
                      'expected_receipt_sha256', 'expected_request_nonce_sha256',
                      'expected_parent_cas_head_sha256'):
            need(rb._sha(decision[field]), 'ORIGINAL_SHA_NONCE_PINS_REQUIRED',
                 'invalid_input')
        need(type(decision['expected_parent_cas_revision']) is int and
             0 <= decision['expected_parent_cas_revision'] < cas.MAX_CAS_REVISION,
             'PARENT_CAS_REVISION_INTEGER_INVALID', 'invalid_input')
        receipt_sha = decision['expected_receipt_sha256']
        nonce = decision['expected_request_nonce_sha256']
        need(receipt_sha not in receipts, 'SIGNED_ISSUER_RECEIPT_RAW_SHA_REUSED')
        need(nonce not in issuer_nonces, 'SIGNED_ISSUER_NONCE_REUSED')
        receipts.add(receipt_sha)
        issuer_nonces.add(nonce)
        need(nonce not in all_nonces, 'ANY_ROLE_QUERY_NONCE_REUSED')
        all_nonces.add(nonce)
        readbacks = decision['readbacks']
        need(type(readbacks) is list and len(readbacks) == 2,
             'BOTH_OBSERVERS_REQUIRED_FOR_EACH_ISSUER_DECISION', 'invalid_input')
        read_names = []
        for item in readbacks:
            a.exact(item, READBACK_FIELDS, 'EC312_EXACT_READBACK_FIELDS_REQUIRED')
            read_names.append(item['observer_id'])
            need(_path(item['readback_file']),
                 'SIGNED_READBACK_PATH_MUST_BE_ABSOLUTE', 'invalid_input')
            for field in ('expected_readback_sha256',
                          'expected_readback_request_nonce_sha256'):
                need(rb._sha(item[field]), 'SIGNED_READBACK_SHA_NONCE_PINS_REQUIRED',
                     'invalid_input')
            sha = item['expected_readback_sha256']
            nonce = item['expected_readback_request_nonce_sha256']
            need(sha not in readback_shas and sha not in boundaries,
                 'SIGNED_READBACK_RAW_SHA_REUSED_IN_ANY_WINDOW')
            need(nonce not in all_nonces, 'ANY_ROLE_QUERY_NONCE_REUSED')
            readback_shas.add(sha)
            all_nonces.add(nonce)
        need(read_names == names,
             'READBACKS_MUST_MATCH_BOTH_INDEPENDENT_OBSERVERS_IN_ORDER')


def read_manifest(*, manifest_file: str, expected_manifest_sha256: str) -> dict:
    need(_path(manifest_file), 'ABSOLUTE_PRIVATE_MANIFEST_FILE_REQUIRED',
         'invalid_input')
    need(rb._sha(expected_manifest_sha256),
         'WHOLE_MANIFEST_INDEPENDENT_RAW_SHA_REQUIRED', 'invalid_input')
    # EC306's strict private reader verifies file owner/0600/parent, nofollow,
    # canonical JSON + LF and full externally provided raw SHA.
    manifest = epochs._owner_private_read(manifest_file, expected_manifest_sha256)
    need(len(b.canonical(manifest)) + 1 <= MAX_MANIFEST_BYTES,
         'MANIFEST_EXCEEDS_SIZE_BUDGET', 'invalid_input')
    _validate_manifest(manifest)
    return manifest


def evaluate(*, manifest_file: str, expected_manifest_sha256: str) -> dict:
    manifest = read_manifest(manifest_file=manifest_file,
                             expected_manifest_sha256=expected_manifest_sha256)
    observers = manifest['observers']
    previous = {
        item['observer_id']: dict(item['boundary']) for item in observers
    }
    previous_signed_issuer: dict | None = None
    registry: str | None = None
    cas_claims: set[str] = set()
    signed_states: list[tuple[str, int, str, int]] = []
    decision_records: list[dict] = []
    regressions: list[dict] = []
    internal_conflicts: list[dict] = []
    cross_conflicts: list[dict] = []
    parent_breaks: list[int] = []
    divergent_revisions: list[int] = []
    not_corroborated: list[int] = []
    conflict_seen: set[tuple[str, str, int, int, int]] = set()
    internal_seen: set[tuple[str, int, int]] = set()

    for index, decision in enumerate(manifest['decisions'], start=1):
        issuer = {
            'cas_authority_id': manifest['cas_authority_id'],
            'cas_authority_public_hex': manifest['cas_authority_public_hex'],
            'expected_request_nonce_sha256': decision['expected_request_nonce_sha256'],
            'expected_parent_cas_revision': decision['expected_parent_cas_revision'],
            'expected_parent_cas_head_sha256': decision['expected_parent_cas_head_sha256'],
        }
        signed_issuer: dict | None = None
        recorded_observers: list[dict] = []
        for observer, item in zip(observers, decision['readbacks']):
            name = observer['observer_id']
            prior = previous[name]
            observer_trust = {
                'cas_store_namespace_id': manifest['cas_store_namespace_id'],
                'observer_id': name,
                'observer_public_hex': observer['observer_public_hex'],
                'expected_readback_request_nonce_sha256':
                    item['expected_readback_request_nonce_sha256'],
                'expected_previous_readback_sequence': prior['sequence'],
                'expected_previous_readback_raw_sha256': prior['raw_sha256'],
                'expected_previous_readback_observed_revision': prior['observed_revision'],
            }
            # Crucially, each observer replays the FULL unchanged original
            # evidence chain independently; no earlier report is an oracle.
            signed = rb.evaluate(
                fork_case_file=decision['fork_case_file'],
                expected_fork_case_sha256=decision['expected_fork_case_sha256'],
                fork_evidence_file=decision['fork_evidence_file'],
                expected_fork_evidence_sha256=decision['expected_fork_evidence_sha256'],
                receipt_file=decision['receipt_file'],
                expected_receipt_sha256=decision['expected_receipt_sha256'],
                cas_trust=issuer,
                readback_file=item['readback_file'],
                expected_readback_sha256=item['expected_readback_sha256'],
                observer_trust=observer_trust)
            # Read verified original *signed* claims. No path, key material or
            # private manifest data is exported into the portable audit.
            _, claim = rb._parse_readback(item['readback_file'],
                                          item['expected_readback_sha256'])
            if registry is None:
                registry = signed['registry_id']
            else:
                need(registry == signed['registry_id'],
                     'REGISTRY_ID_CHANGED_ACROSS_SIGNED_ORIGINAL_SOURCES')
            if signed_issuer is None:
                signed_issuer = {
                    'signed_cas_claim_raw_sha256': signed['signed_cas_claim_raw_sha256'],
                    'decision_revision': signed['decision_claimed_cas_revision'],
                    'decision_head_raw_sha256': signed['decision_claimed_head_raw_sha256'],
                    'signed_outcome': signed['decision_signed_outcome'],
                }
                need(signed_issuer['signed_cas_claim_raw_sha256'] not in cas_claims,
                     'SIGNED_CAS_CLAIM_REPLAYED_ACROSS_DECISIONS')
                cas_claims.add(signed_issuer['signed_cas_claim_raw_sha256'])
            else:
                need(signed['signed_cas_claim_raw_sha256'] ==
                     signed_issuer['signed_cas_claim_raw_sha256'] and
                     signed['decision_claimed_cas_revision'] ==
                     signed_issuer['decision_revision'] and
                     signed['decision_claimed_head_raw_sha256'] ==
                     signed_issuer['decision_head_raw_sha256'] and
                     signed['decision_signed_outcome'] == signed_issuer['signed_outcome'],
                     'OBSERVERS_DID_NOT_REPLAY_IDENTICAL_SIGNED_CAS_CLAIM')
            seq = claim['readback_sequence']
            revision = claim['observed_cas_revision']
            head = claim['observed_head_chain_raw_sha256']
            if prior['observed_revision'] is not None:
                if revision < prior['observed_revision']:
                    regressions.append({
                        'observer_id': name, 'decision_index': index, 'sequence': seq,
                    })
                elif (revision == prior['observed_revision'] and
                      head != prior['observed_head_raw_sha256']):
                    internal_conflicts.append({
                        'observer_id': name, 'decision_index': index,
                        'sequence': seq, 'revision': revision,
                    })
                    internal_seen.add((name, index, revision))
            for other_id, old_rev, old_head, other_index in signed_states:
                if old_rev == revision and old_head != head:
                    if other_id == name:
                        # Already checked immediately previous observation;
                        # also detect repeated revision across nonadjacent rows.
                        marker = (name, name, revision, other_index, index)
                        if (marker not in conflict_seen and
                                (name, index, revision) not in internal_seen):
                            internal_conflicts.append({
                                'observer_id': name, 'decision_index': index,
                                'sequence': seq, 'revision': revision,
                            })
                            internal_seen.add((name, index, revision))
                        conflict_seen.add(marker)
                    else:
                        marker = tuple(sorted((other_id, name))) + (
                            revision, other_index, index)
                        if marker not in conflict_seen:
                            cross_conflicts.append({
                                'observer_ids': sorted((other_id, name)),
                                'revision': revision,
                                'decision_indices': sorted((other_index, index)),
                            })
                            conflict_seen.add(marker)
            signed_states.append((name, revision, head, index))
            if signed['status'] != rb.SAME or signed_issuer['signed_outcome'] != \
                    'compare_exchange_committed_claim':
                if index not in not_corroborated:
                    not_corroborated.append(index)
            recorded_observers.append({
                'observer_id': name,
                'observer_public_hex': observer['observer_public_hex'],
                'readback_sequence': seq,
                'signed_readback_original_raw_sha256': item['expected_readback_sha256'],
                'signed_readback_claim_raw_sha256': signed['signed_readback_claim_raw_sha256'],
                'request_nonce_sha256': item['expected_readback_request_nonce_sha256'],
                'observed_revision': revision,
                'observed_head_raw_sha256': head,
                'observer_vs_signed_issuer_status': signed['status'],
                'recomputed_ec309_original_full_audit_sha256':
                    b.digest(b.canonical(signed)),
            })
            previous[name] = {
                'sequence': seq,
                'raw_sha256': item['expected_readback_sha256'],
                'observed_revision': revision,
                'observed_head_raw_sha256': head,
            }

        need(signed_issuer is not None, 'TWO_SIGNED_OBSERVER_REPLAYS_REQUIRED')
        if previous_signed_issuer is not None:
            if (decision['expected_parent_cas_revision'] !=
                    previous_signed_issuer['decision_revision'] or
                decision['expected_parent_cas_head_sha256'] !=
                    previous_signed_issuer['decision_head_raw_sha256']):
                parent_breaks.append(index)
            # Both observers must support the immediately preceding issuer,
            # not silently replace its state with a later or older view.
            for prev_observer in decision_records[-1]['signed_observer_records']:
                if (prev_observer['observed_revision'] !=
                        previous_signed_issuer['decision_revision'] or
                    prev_observer['observed_head_raw_sha256'] !=
                        previous_signed_issuer['decision_head_raw_sha256']):
                    parent_breaks.append(index)
                    break
        else:
            for observer in observers:
                boundary = observer['boundary']
                if boundary['sequence'] != 0 and (
                    decision['expected_parent_cas_revision'] !=
                        boundary['observed_revision'] or
                    decision['expected_parent_cas_head_sha256'] !=
                        boundary['observed_head_raw_sha256']):
                    parent_breaks.append(index)

        if (recorded_observers[0]['observed_revision'] !=
                recorded_observers[1]['observed_revision']):
            divergent_revisions.append(index)
        # Same-revision signed head disagreement is independently collected
        # above in cross_conflicts, including across different decision rows.
        decision_records.append({
            'decision_index': index,
            'signed_cas_receipt_original_raw_sha256': decision['expected_receipt_sha256'],
            'signed_cas_claim_raw_sha256': signed_issuer['signed_cas_claim_raw_sha256'],
            'original_fork_case_raw_sha256': decision['expected_fork_case_sha256'],
            'original_fork_evidence_raw_sha256': decision['expected_fork_evidence_sha256'],
            'issuer_request_nonce_sha256': decision['expected_request_nonce_sha256'],
            'issuer_parent_revision': decision['expected_parent_cas_revision'],
            'issuer_parent_head_raw_sha256': decision['expected_parent_cas_head_sha256'],
            'issuer_signed_outcome': signed_issuer['signed_outcome'],
            'issuer_signed_revision': signed_issuer['decision_revision'],
            'issuer_signed_head_raw_sha256': signed_issuer['decision_head_raw_sha256'],
            'signed_observer_records': recorded_observers,
        })
        previous_signed_issuer = signed_issuer

    parent_breaks = sorted(set(parent_breaks))
    if regressions:
        status, exit_code = ROLLBACK, 2
    elif internal_conflicts:
        status, exit_code = SELF_CONFLICT, 2
    elif cross_conflicts:
        status, exit_code = CROSS_CONFLICT, 2
    elif parent_breaks:
        status, exit_code = BROKEN_PARENT, 2
    elif divergent_revisions:
        status, exit_code = DIFFERENT_REVISIONS, 2
    elif not_corroborated:
        status, exit_code = NOT_CORROBORATED, 2
    else:
        status, exit_code = GOOD, 0
    candidate = (decision_records[-1]['issuer_signed_head_raw_sha256']
                 if exit_code == 0 else None)
    report = {
        'schema': REPORT_SCHEMA,
        'status': status, 'exit_code': exit_code,
        'manifest_original_raw_sha256': expected_manifest_sha256,
        'registry_id': registry,
        'cas_authority_id': manifest['cas_authority_id'],
        'cas_authority_public_hex': manifest['cas_authority_public_hex'],
        'cas_store_namespace_id': manifest['cas_store_namespace_id'],
        'two_observer_ids': [x['observer_id'] for x in observers],
        'two_observer_public_keys': [x['observer_public_hex'] for x in observers],
        'independent_unreplayed_boundaries': [
            {'observer_id': x['observer_id'], **x['boundary']} for x in observers],
        'both_observers_genesis_to_last_record_included': all(
            x['boundary']['sequence'] == 0 for x in observers),
        'earlier_non_genesis_observer_or_cas_records_replayed': False,
        'complete_distinct_cas_decision_count': len(decision_records),
        'complete_original_signed_readback_count': len(decision_records)*2,
        'signed_cas_and_dual_observation_records': decision_records,
        'signed_observer_revision_rollbacks': regressions,
        'same_observer_signed_head_conflicts': internal_conflicts,
        'cross_observer_same_revision_signed_head_conflicts': cross_conflicts,
        'cas_parent_discontinuity_at_decisions': parent_breaks,
        'different_observer_revisions_at_same_decisions': divergent_revisions,
        'issuer_not_corroborated_at_decisions': not_corroborated,
        'last_candidate_sha256_of_compatible_signed_claims_only': candidate,
        'each_observer_replayed_all_original_ec294_through_ec309_crypto': True,
        'both_signed_observer_identity_keys_distinct_from_each_other_and_issuer': True,
        'both_original_observer_full_SHA_sequence_and_revision_chains_replayed': True,
        'same_namespace_registry_and_original_issuer_evidence_required': True,
        'cross_observer_revision_head_consistency_checked': True,
        'cross_decision_signed_issuer_parent_continuity_checked': True,
        'all_full_original_SHA_and_role_nonces_independently_pinned': True,
        'manifest_privately_stored_and_whole_raw_SHA_independently_pinned': True,
        'external_cas_or_observer_network_request_performed': False,
        'actual_physical_same_store_identity_or_cas_commit_proven': False,
        'actual_global_latest_or_linearizable_state_proven': False,
        'external_organization_authority_key_custody_or_nonce_freshness_proven': False,
        'private_signing_key_loaded': False,
        'business_or_external_store_write_performed': False,
    }
    need(len(b.canonical(report)) + 1 <= MAX_REPORT_BYTES,
         'AUDIT_REPORT_EXCEEDS_SIZE_BUDGET', 'invalid_input')
    return report


def result_from_report(report: dict) -> dict:
    return {
        'status': report['status'], 'exit_code': report['exit_code'],
        'manifest_original_raw_sha256': report['manifest_original_raw_sha256'],
        'audit_report_raw_sha256': b.digest(b.canonical(report)),
        'audit_report_written': False,
        'complete_distinct_cas_decision_count': report['complete_distinct_cas_decision_count'],
        'complete_original_signed_readback_count': report['complete_original_signed_readback_count'],
        'both_observers_genesis_to_last_record_included':
            report['both_observers_genesis_to_last_record_included'],
        'signed_observer_revision_rollbacks': report['signed_observer_revision_rollbacks'],
        'same_observer_signed_head_conflicts': report['same_observer_signed_head_conflicts'],
        'cross_observer_same_revision_signed_head_conflicts':
            report['cross_observer_same_revision_signed_head_conflicts'],
        'cas_parent_discontinuity_at_decisions': report['cas_parent_discontinuity_at_decisions'],
        'different_observer_revisions_at_same_decisions':
            report['different_observer_revisions_at_same_decisions'],
        'issuer_not_corroborated_at_decisions':
            report['issuer_not_corroborated_at_decisions'],
        'last_candidate_sha256_of_compatible_signed_claims_only':
            report['last_candidate_sha256_of_compatible_signed_claims_only'],
        'both_independent_original_observer_signatures_and_full_issuer_chain_replayed': True,
        'actual_external_cas_or_global_latest_proven': False,
        'business_or_external_store_write_performed': False,
    }


def verify(*, manifest_file: str, expected_manifest_sha256: str,
           out: str | None = None) -> dict:
    report = evaluate(manifest_file=manifest_file,
                      expected_manifest_sha256=expected_manifest_sha256)
    if out is not None:
        store.store(out, report, MAX_REPORT_BYTES)
    result = result_from_report(report)
    result['audit_report_written'] = out is not None
    return result


def verify_report(*, manifest_file: str, expected_manifest_sha256: str,
                  audit_report_file: str, expected_audit_report_sha256: str) -> dict:
    need(_path(audit_report_file) and rb._sha(expected_audit_report_sha256),
         'ABSOLUTE_PRIVATE_AUDIT_AND_INDEPENDENT_RAW_SHA_REQUIRED', 'invalid_input')
    saved = epochs._owner_private_read(audit_report_file,
                                       expected_audit_report_sha256)
    need(len(b.canonical(saved)) + 1 <= MAX_REPORT_BYTES,
         'SAVED_AUDIT_EXCEEDS_SIZE_BUDGET', 'invalid_input')
    fresh = evaluate(manifest_file=manifest_file,
                     expected_manifest_sha256=expected_manifest_sha256)
    need(saved == fresh, 'SAVED_AUDIT_NOT_EQUAL_TO_FRESH_FULL_ORIGINAL_REPLAY')
    result = result_from_report(fresh)
    result['audit_report_raw_sha256'] = expected_audit_report_sha256
    return result
