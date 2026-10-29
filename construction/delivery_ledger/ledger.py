#!/usr/bin/env python3
"""EC315 offline cross-delivery append-only signed-source evidence ledger.

Every EC312 observer window is read from a separate owner-private, externally
raw-SHA-pinned original and *fully replayed* through EC309 -> EC294. An EC315
"delivery" is an operator-pinned envelope, NOT a new signer or CAS commit.
The old EC314 original-source intersection and global signed-state comparison
is repeated at EVERY append prefix; no future delivery repairs an earlier
ambiguous/disconnected prefix. An append may be checked against a separately
retained prior SHA + verified-originals commitment, which is never inferred
from the new manifest or from an old unauthenticated PASS report.

These checks cannot prove that an Ed25519 key belongs to an actual authority,
that observations happened on one physical linearizable store, or that an
external anchor was really stored outside the operator's control.
"""
from __future__ import annotations

import hmac
from typing import Any

from delivery_anchor import anchor as a
from delivery_anchor import operator as store
from portable_bundle import bundle as b
from receiver_ack import ack as receiver
from registrar_epochs import epochs
from cas_readback import readback as rb
from dual_observer_reconciliation import reconcile as old
from window_mesh import mesh

ROOT_SCHEMA = 'ces.ec315.signed_cas_delivery_ledger_manifest.v1'
DELIVERY_SCHEMA = 'ces.ec315.signed_cas_delivery_entry.v1'
COMMITMENT_SCHEMA = 'ces.ec315.verified_original_delivery_prefix_commitment.v1'
REPORT_SCHEMA = 'ces.ec315.signed_cas_delivery_ledger_audit.v1'
RESULT_SCHEMA = 'ces.ec315.signed_cas_delivery_ledger_result.v1'
DENIAL_SCHEMA = 'ces.ec315.signed_cas_delivery_ledger_denial.v1'
ROOT_FIELDS = frozenset({'schema', 'cas_authority_id', 'cas_authority_public_hex',
                         'cas_store_namespace_id', 'expected_registry_id', 'deliveries'})
DELIVERY_REF_FIELDS = frozenset({'sequence', 'delivery_file', 'expected_delivery_sha256'})
ENTRY_FIELDS = frozenset({'schema', 'sequence', 'previous_delivery_sha256',
                         'previous_verified_originals_commitment_sha256', 'windows'})
WINDOW_FIELDS = mesh.WINDOW_FIELDS
MAX_DELIVERIES = 4
MAX_TOTAL_WINDOWS = 12
MAX_WINDOWS_PER_APPEND = 3
MIN_GENESIS_WINDOWS = 3
MAX_GENESIS_WINDOWS = 6
MAX_MANIFEST_BYTES = 32768
MAX_REPORT_BYTES = 850000

SUCCESS = 'all_append_prefixes_signed_original_consistent_not_physical_cas_proof'
HISTORICAL_CONFLICT = 'historical_signed_original_prefix_failed_no_later_repair'
APPEND_DISCONNECTED = 'new_delivery_lacks_original_signed_receipt_bridge_to_prior'
ALL_STATUSES = (SUCCESS, HISTORICAL_CONFLICT, APPEND_DISCONNECTED)


def need(value: Any, code: str, status: str = 'permission_denied') -> None:
    if value is not True:
        raise a.AnchorError('EC315_' + code, status)


def _sha(value: Any) -> bool:
    return rb._sha(value) and value != '0'*64


def _id(value: Any) -> bool:
    return type(value) is str and receiver.ID.fullmatch(value) is not None


def _private_ref(path: Any, sha: Any, label: str) -> None:
    need(mesh._path(path), label + '_ABSOLUTE_OWNER_PRIVATE_PATH_REQUIRED', 'invalid_input')
    need(_sha(sha), label + '_INDEPENDENT_WHOLE_RAW_SHA_REQUIRED', 'invalid_input')


def _private_doc(path: str, sha: str) -> dict:
    # Old EC306's original hardened reader checks private 0700 parents,
    # 0600 single-link files, no symlinks, inode stability, canonical LF JSON,
    # a maximum size and a whole-raw-byte external SHA; no new weak parser.
    return epochs._owner_private_read(path, sha)


def read_manifest(*, manifest_file: str, expected_manifest_sha256: str) -> dict:
    _private_ref(manifest_file, expected_manifest_sha256, 'OUTER_MANIFEST')
    doc = _private_doc(manifest_file, expected_manifest_sha256)
    need(len(b.canonical(doc)) <= MAX_MANIFEST_BYTES,
         'OUTER_MANIFEST_SIZE_BUDGET_EXCEEDED', 'invalid_input')
    a.exact(doc, ROOT_FIELDS, 'EC315_OUTER_MANIFEST_FIELDS_NOT_EXACT')
    need(doc['schema'] == ROOT_SCHEMA, 'OUTER_MANIFEST_SCHEMA_INVALID', 'invalid_input')
    # Same authoritative public-key format and Ed25519 verification contract
    # as the older, independently replayed EC308 source verifier.
    mesh.cas._trust({
        'cas_authority_id': doc['cas_authority_id'],
        'cas_authority_public_hex': doc['cas_authority_public_hex'],
        'expected_request_nonce_sha256': 'f'*64,
        'expected_parent_cas_revision': 0,
        'expected_parent_cas_head_sha256': 'e'*64,
    })
    need(_id(doc['cas_store_namespace_id']) and _id(doc['expected_registry_id']),
         'EXTERNAL_NAMESPACE_OR_REGISTRY_INVALID', 'invalid_input')
    entries = doc['deliveries']
    need(type(entries) is list and 1 <= len(entries) <= MAX_DELIVERIES,
         'ONE_TO_FOUR_DELIVERIES_REQUIRED', 'invalid_input')
    seen_shas = set()
    for seq, entry in enumerate(entries, 1):
        a.exact(entry, DELIVERY_REF_FIELDS, 'EC315_DELIVERY_REFERENCE_FIELDS_NOT_EXACT')
        need(type(entry['sequence']) is int and entry['sequence'] == seq,
             'DELIVERY_REFERENCES_MUST_BE_CONTIGUOUS_FROM_ONE', 'invalid_input')
        _private_ref(entry['delivery_file'], entry['expected_delivery_sha256'],
                     'DELIVERY_ENTRY')
        need(entry['expected_delivery_sha256'] not in seen_shas,
             'DUPLICATE_DELIVERY_WHOLE_RAW_SHA', 'invalid_input')
        seen_shas.add(entry['expected_delivery_sha256'])
    return doc


def read_delivery(entry: dict, *, previous_delivery_sha256: str,
                  previous_commitment: str) -> dict:
    doc = _private_doc(entry['delivery_file'], entry['expected_delivery_sha256'])
    need(len(b.canonical(doc)) <= MAX_MANIFEST_BYTES,
         'DELIVERY_ENTRY_SIZE_BUDGET_EXCEEDED', 'invalid_input')
    a.exact(doc, ENTRY_FIELDS, 'EC315_DELIVERY_ENTRY_FIELDS_NOT_EXACT')
    need(doc['schema'] == DELIVERY_SCHEMA and
         type(doc['sequence']) is int and doc['sequence'] == entry['sequence'],
         'DELIVERY_ENTRY_SCHEMA_OR_SEQUENCE_INVALID', 'invalid_input')
    need(doc['previous_delivery_sha256'] == previous_delivery_sha256,
         'DELIVERY_PREDECESSOR_WHOLE_RAW_SHA_LINK_BROKEN')
    need(doc['previous_verified_originals_commitment_sha256'] == previous_commitment,
         'DELIVERY_PREDECESSOR_REPLAYED_ORIGINALS_COMMITMENT_MISMATCH')
    windows = doc['windows']
    if entry['sequence'] == 1:
        need(type(windows) is list and
             MIN_GENESIS_WINDOWS <= len(windows) <= MAX_GENESIS_WINDOWS,
             'GENESIS_MUST_CONTAIN_THREE_TO_SIX_WINDOWS', 'invalid_input')
    else:
        need(type(windows) is list and 1 <= len(windows) <= MAX_WINDOWS_PER_APPEND,
             'APPEND_MUST_CONTAIN_ONE_TO_THREE_NEW_WINDOWS', 'invalid_input')
    names, hashes = [], []
    for window in windows:
        a.exact(window, WINDOW_FIELDS, 'EC315_WINDOW_REFERENCE_FIELDS_NOT_EXACT')
        need(_id(window['window_id']), 'INVALID_WINDOW_ID', 'invalid_input')
        _private_ref(window['manifest_file'], window['expected_manifest_sha256'],
                     'EC312_WINDOW')
        names.append(window['window_id'])
        hashes.append(window['expected_manifest_sha256'])
    need(names == sorted(set(names)), 'WINDOW_IDS_MUST_BE_SORTED_UNIQUE', 'invalid_input')
    need(len(set(hashes)) == len(hashes), 'WINDOW_ORIGINAL_SHA_DUPLICATED', 'invalid_input')
    return doc


def _window_commitment_piece(entry: dict, report: dict) -> dict:
    # Derived from replayed originals; no report supplied by operator is
    # accepted. This commitment intentionally contains no local path, date,
    # prior unsigned PASS boolean, or private key data.
    records = report['signed_cas_and_dual_observation_records']
    return {
        'window_id': entry['window_id'],
        'original_ec312_manifest_raw_sha256': entry['expected_manifest_sha256'],
        'genuine_issuer_signed_original_shas': sorted({
            rec['signed_cas_receipt_original_raw_sha256'] for rec in records}),
        'genuine_observer_signed_original_shas': sorted({
            obs['signed_readback_original_raw_sha256'] for rec in records
            for obs in rec['signed_observer_records']}),
    }


def _commitment(external: dict, signed_deliveries: list[dict]) -> str:
    source = {
        'schema': COMMITMENT_SCHEMA,
        'cas_authority_id': external['cas_authority_id'],
        'cas_authority_public_hex': external['cas_authority_public_hex'],
        'cas_store_namespace_id': external['cas_store_namespace_id'],
        'expected_registry_id': external['expected_registry_id'],
        'deliveries': signed_deliveries,
    }
    return b.digest(b.canonical(source))


def evaluate(*, manifest_file: str, expected_manifest_sha256: str,
             expected_prior_delivery_sha256: str | None = None,
             expected_prior_originals_commitment_sha256: str | None = None) -> dict:
    """Verify genesis or an append, always replaying every prior original.

    If independent prior pins are provided, both are REQUIRED and checked
    against the entire freshly reconstructed penultimate prefix. The caller
    must obtain and retain those values OUTSIDE the proposed new delivery.
    """
    external = read_manifest(manifest_file=manifest_file,
                             expected_manifest_sha256=expected_manifest_sha256)
    pinned = (expected_prior_delivery_sha256 is not None or
              expected_prior_originals_commitment_sha256 is not None)
    need((expected_prior_delivery_sha256 is None) ==
         (expected_prior_originals_commitment_sha256 is None),
         'BOTH_INDEPENDENT_PRIOR_CHECKPOINT_PINS_REQUIRED', 'invalid_input')
    if pinned:
        need(len(external['deliveries']) >= 2,
             'APPEND_CHECK_NEEDS_PRIOR_AND_NEW_DELIVERY', 'invalid_input')
        need(_sha(expected_prior_delivery_sha256) and
             _sha(expected_prior_originals_commitment_sha256),
             'VALID_INDEPENDENT_PRIOR_RAW_SHA_AND_COMMITMENT_REQUIRED', 'invalid_input')

    seen_ids: set[str] = set()
    seen_origins: set[str] = set()
    previous_sha = 'GENESIS'
    previous_commitment = 'GENESIS'
    signed_deliveries: list[dict] = []
    replayed: list[tuple[dict, dict]] = []
    prefix_results: list[dict] = []
    failed_prefixes: list[int] = []
    last_mesh: dict | None = None
    previous_window_ids: set[str] = set()
    prior_checkpoint: dict | None = None
    for index, entry in enumerate(external['deliveries']):
        if pinned and index == len(external['deliveries'])-1:
            # This check is NOT against any prior SHA copied from the new
            # envelope. It is an independently supplied frozen checkpoint.
            need(hmac.compare_digest(previous_sha, expected_prior_delivery_sha256),
                 'EXTERNAL_PREVIOUS_TIP_PIN_DIFFERS_FROM_REPLAYED_PREFIX')
            need(hmac.compare_digest(previous_commitment,
                                     expected_prior_originals_commitment_sha256),
                 'EXTERNAL_PREVIOUS_ORIGINALS_COMMITMENT_DIFFERS_FROM_REPLAY')
        delivery = read_delivery(entry, previous_delivery_sha256=previous_sha,
                                 previous_commitment=previous_commitment)
        new_ids: set[str] = set()
        new_source_pieces: list[dict] = []
        for window in delivery['windows']:
            wid, original_sha = (window['window_id'],
                                 window['expected_manifest_sha256'])
            need(wid not in seen_ids, 'PREVIOUS_WINDOW_ID_REUSED_IN_APPEND', 'invalid_input')
            need(original_sha not in seen_origins,
                 'OLD_EC312_MANIFEST_REINSERTED_AS_NEW_WINDOW', 'invalid_input')
            seen_ids.add(wid)
            seen_origins.add(original_sha)
            new_ids.add(wid)
            need(len(seen_ids) <= MAX_TOTAL_WINDOWS,
                 'CUMULATIVE_WINDOW_BUDGET_EXCEEDED', 'invalid_input')
            original = old.read_manifest(
                manifest_file=window['manifest_file'],
                expected_manifest_sha256=original_sha)
            # Each distinct original Ed25519 chain is fully verified once at
            # this invocation, including every historical delivery; never
            # import a cached mesh/PASS/receipt summary from an old round.
            report = old.evaluate(
                manifest_file=window['manifest_file'],
                expected_manifest_sha256=original_sha)
            replayed.append(({**window, 'manifest': original}, report))
            new_source_pieces.append(_window_commitment_piece(window, report))

        signed_deliveries.append({
            'sequence': entry['sequence'],
            'delivery_original_raw_sha256': entry['expected_delivery_sha256'],
            'windows': new_source_pieces,
        })
        current_commitment = _commitment(external, signed_deliveries)
        mesh_report = mesh._compare_verified(replayed, expected_manifest_sha256, external)
        last_mesh = mesh_report
        edges = mesh_report['original_signed_issuer_receipt_intersection_edges']
        bridges = [e for e in edges
                   if ((e['window_a'] in previous_window_ids and e['window_b'] in new_ids) or
                       (e['window_b'] in previous_window_ids and e['window_a'] in new_ids))]
        # Even if all CAS revision numbers are adjacent, only a genuinely
        # shared EC308 Ed25519 original creates a cross-DELIVERY bridge.
        bridge_missing = bool(previous_window_ids) and not bridges
        # Report a cross-batch source absence specifically when the only
        # obstruction in the full signed mesh is disconnected components;
        # never mask a genuine signed issuer/observer conflict with that label.
        if bridge_missing and mesh_report['status'] == mesh.DISCONNECTED:
            status = APPEND_DISCONNECTED
        elif mesh_report['exit_code'] != 0:
            status = mesh_report['status']
        elif bridge_missing:
            status = APPEND_DISCONNECTED
        else:
            status = SUCCESS
        if status != SUCCESS:
            failed_prefixes.append(entry['sequence'])
        prefix_results.append({
            'sequence': entry['sequence'],
            'delivery_original_raw_sha256': entry['expected_delivery_sha256'],
            'cumulative_replayed_originals_commitment_sha256': current_commitment,
            'new_window_ids': sorted(new_ids),
            'total_distinct_replayed_windows': len(seen_ids),
            'new_delivery_genuine_signed_issuer_bridge_count': len(bridges),
            'new_delivery_signed_issuer_bridge_anchors': [
                {'previous_window_id': (e['window_a'] if e['window_a'] in previous_window_ids
                                        else e['window_b']),
                 'new_window_id': (e['window_a'] if e['window_a'] in new_ids
                                   else e['window_b']),
                 'shared_genuine_signed_receipt_original_sha256':
                     e['shared_signed_issuer_original_sha256']}
                for e in bridges],
            'mesh_status': mesh_report['status'],
            'prefix_status': status,
            'prefix_exit_code': 0 if status == SUCCESS else 2,
            'prefix_signed_original_intersection_component_count':
                mesh_report['connected_component_count'],
            'prefix_true_issuer_signed_original_count':
                mesh_report['unique_true_issuer_signed_original_count'],
            'prefix_real_signed_state_conflict_count': len(
                mesh_report['cross_mesh_true_signed_state_head_conflicts']),
            'prefix_true_issuer_ambiguity_count': len(
                mesh_report['different_true_issuer_originals_claim_same_revision']),
        })
        if index == len(external['deliveries']) - 2:
            prior_checkpoint = {
                'delivery_sha256': entry['expected_delivery_sha256'],
                'verified_originals_commitment_sha256': current_commitment,
            }
        previous_sha = entry['expected_delivery_sha256']
        previous_commitment = current_commitment
        previous_window_ids |= new_ids

    need(last_mesh is not None, 'EMPTY_ORIGINAL_SOURCE_REPLAY', 'unavailable')
    if failed_prefixes:
        final_status = (APPEND_DISCONNECTED if
                        len(failed_prefixes) == 1 and
                        failed_prefixes[0] == len(prefix_results) and
                        prefix_results[-1]['prefix_status'] == APPEND_DISCONNECTED
                        else HISTORICAL_CONFLICT)
    else:
        final_status = SUCCESS
    # Not even a later signed window overlap can "heal" a prior failure.
    code = 0 if final_status == SUCCESS else 2
    result = {
        'schema': REPORT_SCHEMA,
        'status': final_status,
        'exit_code': code,
        'outer_manifest_original_raw_sha256': expected_manifest_sha256,
        'cas_authority_id': external['cas_authority_id'],
        'cas_authority_public_hex': external['cas_authority_public_hex'],
        'cas_store_namespace_id': external['cas_store_namespace_id'],
        'expected_registry_id': external['expected_registry_id'],
        'delivery_count': len(prefix_results),
        'total_unique_ec312_windows_fully_original_signed_replayed': len(seen_ids),
        'each_append_prefix_full_original_signed_replay': prefix_results,
        'first_failing_append_prefix_sequence': min(failed_prefixes) if failed_prefixes else None,
        'historical_failing_append_prefixes_not_healed': failed_prefixes,
        'final_bounded_graph_status': last_mesh['status'],
        'final_bounded_connected_components':
            last_mesh['connected_components_by_actual_signed_original'],
        'final_bounded_cross_path_original_receipt_edges':
            last_mesh['original_signed_issuer_receipt_intersection_edges'],
        'final_bounded_signer_sequence_forks':
            last_mesh['cross_mesh_same_signer_sequence_double_originals'],
        'final_bounded_original_signed_head_conflicts':
            last_mesh['cross_mesh_true_signed_state_head_conflicts'],
        'final_bounded_issuer_same_revision_distinct_true_signatures':
            last_mesh['different_true_issuer_originals_claim_same_revision'],
        'final_bounded_predecessor_conflicts':
            last_mesh['cross_mesh_signed_observer_predecessor_conflicts'],
        'final_bounded_issuer_parent_chain_gaps':
            last_mesh['cross_mesh_signed_issuer_parent_or_revision_gaps'],
        'final_bounded_unique_issuer_signed_sources':
            last_mesh['unique_true_issuer_signed_original_count'],
        'final_bounded_unique_observer_signed_sources':
            last_mesh['unique_true_signed_observer_original_count'],
        'final_bounded_highest_signed_revision':
            last_mesh['highest_bounded_signed_issuer_revision'],
        'bounded_candidate_only_if_every_prefix_valid': (
            last_mesh['last_candidate_sha256_of_bounded_compatible_signed_claims_only']
            if code == 0 else None),
        'checkpoint_tip_delivery_original_raw_sha256': previous_sha,
        'checkpoint_cumulative_replayed_originals_commitment_sha256': previous_commitment,
        'previous_checkpoint_verified_for_this_append': prior_checkpoint if pinned else None,
        'external_prior_tip_and_replayed_sources_pins_supplied': pinned,
        'all_previous_delivery_raw_sha_and_cumulative_original_source_links_recomputed': True,
        'all_ec312_ec309_to_ec294_original_signatures_replayed_this_invocation': True,
        'signed_original_conflicts_checked_at_each_immutable_delivery_prefix': True,
        'external_checkpoint_proven_independently_held_or_custodied': False,
        'actual_physical_single_cas_or_global_latest_proven': False,
        'external_signer_governance_or_nonce_global_freshness_proven': False,
        'external_cas_or_network_or_host_access_performed': False,
        'private_key_loaded': False,
        'business_or_external_store_write_performed': False,
    }
    need(len(b.canonical(result)) <= MAX_REPORT_BYTES,
         'BOUNDED_DELIVERY_LEDGER_REPORT_EXCEEDS_BUDGET', 'invalid_input')
    return result


def result_from_report(report: dict) -> dict:
    return {
        'status': report['status'], 'exit_code': report['exit_code'],
        'outer_manifest_original_raw_sha256': report['outer_manifest_original_raw_sha256'],
        'audit_report_raw_sha256': b.digest(b.canonical(report)),
        'audit_report_written': False,
        'delivery_count': report['delivery_count'],
        'total_unique_ec312_windows_fully_original_signed_replayed':
            report['total_unique_ec312_windows_fully_original_signed_replayed'],
        'append_prefix_results': [{
            'sequence': r['sequence'], 'prefix_status': r['prefix_status'],
            'prefix_exit_code': r['prefix_exit_code'],
            'new_delivery_genuine_signed_issuer_bridge_count':
                r['new_delivery_genuine_signed_issuer_bridge_count'],
            'cumulative_replayed_originals_commitment_sha256':
                r['cumulative_replayed_originals_commitment_sha256']}
            for r in report['each_append_prefix_full_original_signed_replay']],
        'first_failing_append_prefix_sequence':
            report['first_failing_append_prefix_sequence'],
        'final_bounded_graph_status': report['final_bounded_graph_status'],
        'final_bounded_unique_issuer_signed_sources':
            report['final_bounded_unique_issuer_signed_sources'],
        'final_bounded_unique_observer_signed_sources':
            report['final_bounded_unique_observer_signed_sources'],
        'bounded_candidate_only_if_every_prefix_valid':
            report['bounded_candidate_only_if_every_prefix_valid'],
        'checkpoint_tip_delivery_original_raw_sha256':
            report['checkpoint_tip_delivery_original_raw_sha256'],
        'checkpoint_cumulative_replayed_originals_commitment_sha256':
            report['checkpoint_cumulative_replayed_originals_commitment_sha256'],
        'external_prior_tip_and_replayed_sources_pins_supplied':
            report['external_prior_tip_and_replayed_sources_pins_supplied'],
        'all_ec312_ec309_to_ec294_original_signatures_replayed_this_invocation': True,
        'actual_physical_single_cas_or_global_latest_proven': False,
        'business_or_external_store_write_performed': False,
    }


def verify(*, manifest_file: str, expected_manifest_sha256: str,
           expected_prior_delivery_sha256: str | None = None,
           expected_prior_originals_commitment_sha256: str | None = None,
           out: str | None = None) -> dict:
    report = evaluate(manifest_file=manifest_file,
                      expected_manifest_sha256=expected_manifest_sha256,
                      expected_prior_delivery_sha256=expected_prior_delivery_sha256,
                      expected_prior_originals_commitment_sha256=
                          expected_prior_originals_commitment_sha256)
    if out is not None:
        store.store(out, report, MAX_REPORT_BYTES)
    result = result_from_report(report)
    result['audit_report_written'] = out is not None
    return result


def verify_report(*, manifest_file: str, expected_manifest_sha256: str,
                  audit_report_file: str, expected_audit_report_sha256: str,
                  expected_prior_delivery_sha256: str | None = None,
                  expected_prior_originals_commitment_sha256: str | None = None) -> dict:
    _private_ref(audit_report_file, expected_audit_report_sha256, 'AUDIT_REPORT')
    # Reuses EC314's hardened pinned owner-private audit reader; the new
    # report limit is larger, so override ONLY via this locally bound pathless
    # reader, never by altering the trusted old package's source.
    from finding_query_host import protocol as io
    import os
    import stat
    target = b._private_parent(audit_report_file)
    before = os.lstat(target)
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
         stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
         'REPORT_OWNER_PRIVATE_SINGLE_REGULAR_LINK_REQUIRED')
    raw = io._open_regular(audit_report_file, MAX_REPORT_BYTES, private=True)
    after = os.lstat(target)
    need(tuple(getattr(before, k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')) ==
         tuple(getattr(after, k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')),
         'REPORT_CHANGED_DURING_READ', 'unavailable')
    need(hmac.compare_digest(b.digest(raw), expected_audit_report_sha256),
         'REPORT_WHOLE_RAW_BYTES_SHA_DIFFERS_FROM_EXTERNAL_PIN')
    saved = io.parse(raw, MAX_REPORT_BYTES)
    need(hmac.compare_digest(raw, b.canonical(saved)),
         'REPORT_NOT_CANONICAL_JSON_LF_BYTES')
    fresh = evaluate(manifest_file=manifest_file,
                     expected_manifest_sha256=expected_manifest_sha256,
                     expected_prior_delivery_sha256=expected_prior_delivery_sha256,
                     expected_prior_originals_commitment_sha256=
                         expected_prior_originals_commitment_sha256)
    need(saved == fresh, 'REPORTED_LEDGER_NOT_EQUAL_FRESH_FULL_ORIGINAL_REPLAY')
    result = result_from_report(fresh)
    result['audit_report_raw_sha256'] = expected_audit_report_sha256
    return result
