#!/usr/bin/env python3
"""EC313: cross-check TWO EC312 original signed CAS windows by their overlap.

The EC312 reports are NEVER accepted as input evidence. Each owner-private,
independently raw-SHA-pinned EC312 manifest and every original Ed25519 EC309,
EC308, EC307...EC294 source is replayed independently in this process.

An exact, shared original issuer receipt is the only cross-window intersection
anchor. A cryptographically signed disagreement is not resolved by choosing a
winner. Disjoint windows may be compatible but do not prove an unbroken join.
Even a compatible union does NOT establish real external CAS operations,
physical same-store identity, worldwide latest state or organizational trust.
"""
from __future__ import annotations

import hmac
import os
import stat
from typing import Any

from ec303_receiver_ack import ack as receiver
from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from ec295_delivery_anchor import operator as store
from ec302_portable_bundle import bundle as b
from ec306_registrar_epochs import epochs
from ec308_cas_receipt import receipt as cas
from ec309_cas_readback import readback as rb
from ec312_dual_observer_reconciliation import reconcile as old

MANIFEST_SCHEMA = 'ces.ec313.cross_window_signed_cas_intersection_manifest.v1'
REPORT_SCHEMA = 'ces.ec313.cross_window_signed_cas_intersection_audit.v1'
RESULT_SCHEMA = 'ces.ec313.cross_window_signed_cas_intersection_result.v1'
DENIAL_SCHEMA = 'ces.ec313.cross_window_signed_cas_intersection_denial.v1'
MANIFEST_FIELDS = frozenset({
    'schema', 'cas_authority_id', 'cas_authority_public_hex',
    'cas_store_namespace_id', 'expected_registry_id', 'windows',
})
WINDOW_FIELDS = frozenset({
    'window_id', 'manifest_file', 'expected_manifest_sha256',
})
MAX_MANIFEST_BYTES = 16_000
MAX_REPORT_BYTES = 100_000
SUCCESS = 'two_replayed_signed_windows_overlap_and_union_compatible_not_store_proof'
SIGNED_CONFLICT = 'cross_window_authentic_signed_revision_head_or_sequence_conflict'
ISSUER_AMBIGUITY = 'cross_window_distinct_signed_issuer_sources_claim_same_revision_or_nonce'
CHILD_FAILED = 'one_or_both_original_signed_observer_windows_not_compatible'
BOUNDARY_MISMATCH = 'cross_window_opaque_boundary_contradicts_replayed_signed_predecessor'
NO_OVERLAP = 'no_common_original_signed_issuer_receipt_cross_window_continuity_unproven'
BROKEN_UNION = 'cross_window_signed_issuer_union_parent_chain_discontinuous'
ALL_STATUSES = (SUCCESS, SIGNED_CONFLICT, ISSUER_AMBIGUITY, CHILD_FAILED,
                BOUNDARY_MISMATCH, NO_OVERLAP, BROKEN_UNION)


def need(condition: Any, code: str, status: str = 'permission_denied') -> None:
    if condition is not True:
        raise a.AnchorError('EC313_' + code, status)


def _path(value: Any) -> bool:
    return (type(value) is str and 0 < len(value) <= 4000 and
            '\x00' not in value and os.path.isabs(value))


def read_manifest(*, manifest_file: str, expected_manifest_sha256: str) -> dict:
    need(_path(manifest_file), 'ABSOLUTE_OWNER_PRIVATE_MANIFEST_PATH_REQUIRED',
         'invalid_input')
    need(rb._sha(expected_manifest_sha256), 'INDEPENDENT_WHOLE_MANIFEST_SHA_REQUIRED',
         'invalid_input')
    # Existing owner-private reader enforces 0700 parent / 0600 owner regular,
    # O_NOFOLLOW, nlink 1, canonical exact JSON+LF and independent raw SHA.
    doc = epochs._owner_private_read(manifest_file, expected_manifest_sha256)
    need(len(b.canonical(doc)) + 1 <= MAX_MANIFEST_BYTES,
         'OUTER_MANIFEST_EXCEEDS_BUDGET', 'invalid_input')
    a.exact(doc, MANIFEST_FIELDS, 'EC313_EXACT_OUTER_MANIFEST_FIELDS_REQUIRED')
    need(doc['schema'] == MANIFEST_SCHEMA, 'OUTER_MANIFEST_SCHEMA_INVALID')
    cas._trust({
        'cas_authority_id': doc['cas_authority_id'],
        'cas_authority_public_hex': doc['cas_authority_public_hex'],
        'expected_request_nonce_sha256': 'f'*64,
        'expected_parent_cas_revision': 0,
        'expected_parent_cas_head_sha256': 'e'*64,
    })
    for field in ('cas_store_namespace_id', 'expected_registry_id'):
        need(type(doc[field]) is str and receiver.ID.fullmatch(doc[field]) is not None,
             'EXTERNALLY_PINNED_NAMESPACE_AND_REGISTRY_IDS_INVALID', 'invalid_input')
    windows = doc['windows']
    need(type(windows) is list and len(windows) == 2,
         'EXACTLY_TWO_EC312_WINDOWS_REQUIRED', 'invalid_input')
    identifiers: list[str] = []
    manifests: list[str] = []
    for window in windows:
        a.exact(window, WINDOW_FIELDS, 'EC313_EXACT_WINDOW_FIELDS_REQUIRED')
        wid = window['window_id']
        need(type(wid) is str and receiver.ID.fullmatch(wid) is not None,
             'WINDOW_ID_INVALID', 'invalid_input')
        need(_path(window['manifest_file']),
             'EC312_MANIFEST_PATH_MUST_BE_ABSOLUTE', 'invalid_input')
        need(rb._sha(window['expected_manifest_sha256']),
             'EC312_MANIFEST_REQUIRES_ITS_OWN_EXTERNAL_RAW_SHA', 'invalid_input')
        identifiers.append(wid)
        manifests.append(window['expected_manifest_sha256'])
    need(identifiers == sorted(set(identifiers)),
         'TWO_DIFFERENT_SORTED_WINDOW_IDS_REQUIRED', 'invalid_input')
    need(len(set(manifests)) == 2,
         'TWO_DIFFERENT_EC312_MANIFEST_ORIGINALS_REQUIRED', 'invalid_input')
    return doc


def _source_witnesses(window_id: str, report: dict) -> list[dict]:
    """Project only *successfully replayed original signed* revision/head claims."""
    output: list[dict] = []
    for decision in report['signed_cas_and_dual_observation_records']:
        output.append({
            'window_id': window_id,
            'role': 'issuer',
            'source_sha256': decision['signed_cas_receipt_original_raw_sha256'],
            'revision': decision['issuer_signed_revision'],
            'head': decision['issuer_signed_head_raw_sha256'],
        })
        for obs in decision['signed_observer_records']:
            output.append({
                'window_id': window_id,
                'role': 'observer:' + obs['observer_id'],
                'source_sha256': obs['signed_readback_original_raw_sha256'],
                'revision': obs['observed_revision'],
                'head': obs['observed_head_raw_sha256'],
            })
    return output


def _compare_verified(originals: list[tuple[dict, dict]],
                      expected_manifest_sha256: str, external: dict) -> dict:
    """Compare already independently replayed facts; never a public shortcut.

    Called ONLY after old.evaluate for each separately pinned source; its
    inputs are intentionally not accepted by the CLI or the public evaluator.
    """
    manifests = [w['manifest'] for w, _ in originals]
    reports = [report for _, report in originals]
    origins: list[dict[str, dict]] = []
    by_revision: dict[int, list[dict]] = {}
    observer_sequences: dict[tuple[str, int], list[dict]] = {}
    observer_profiles: dict[str, str] = {}
    key_to_id: dict[str, str] = {}
    nonce_sources: dict[str, set[tuple[str, str]]] = {}
    window_summary: list[dict] = []
    observations: list[dict] = []
    signed_witnesses: list[list[dict]] = []

    for entry, report in originals:
        wid = entry['window_id']
        manifest = entry['manifest']
        need(report['registry_id'] == external['expected_registry_id'],
             'VERIFIED_SIGNED_REGISTRY_OUTSIDE_EXTERNAL_TRUST_ROOT')
        need(all(manifest[k] == external[k] for k in (
            'cas_authority_id', 'cas_authority_public_hex', 'cas_store_namespace_id')),
             'EC312_WINDOW_TRUST_ROOT_DIFFERS_FROM_EXTERNALLY_PINNED_ROOT')
        origins.append({rec['signed_cas_receipt_original_raw_sha256']: rec
                        for rec in report['signed_cas_and_dual_observation_records']})
        boundary_count = 0
        for observer in manifest['observers']:
            oid = observer['observer_id']
            pub = observer['observer_public_hex']
            if oid in observer_profiles:
                need(observer_profiles[oid] == pub,
                     'OBSERVER_ID_KEY_CHANGED_WITHOUT_AUTHENTICATED_ROLLOVER')
            if pub in key_to_id:
                need(key_to_id[pub] == oid,
                     'OBSERVER_PUBLIC_KEY_REUSED_UNDER_DIFFERENT_ID')
            observer_profiles[oid] = pub
            key_to_id[pub] = oid
            if observer['boundary']['sequence']:
                boundary_count += 1
        window_summary.append({
            'window_id': wid,
            'ec312_manifest_original_raw_sha256': entry['expected_manifest_sha256'],
            'recomputed_full_ec312_audit_raw_sha256': b.digest(b.canonical(report)),
            'signed_window_status': report['status'],
            'signed_window_exit_code': report['exit_code'],
            'different_signed_issuer_decisions_replayed':
                report['complete_distinct_cas_decision_count'],
            'original_ed25519_observer_readbacks_replayed':
                report['complete_original_signed_readback_count'],
            'non_genesis_opaque_observer_boundaries': boundary_count,
        })
        for rec in report['signed_cas_and_dual_observation_records']:
            by_revision.setdefault(rec['issuer_signed_revision'], []).append({
                'window_id': wid,
                'original_receipt_sha256': rec['signed_cas_receipt_original_raw_sha256'],
                'signed_claim_sha256': rec['signed_cas_claim_raw_sha256'],
                'revision': rec['issuer_signed_revision'],
                'head': rec['issuer_signed_head_raw_sha256'],
                'parent_revision': rec['issuer_parent_revision'],
                'parent_head': rec['issuer_parent_head_raw_sha256'],
                'outcome': rec['issuer_signed_outcome'],
                'fork_case_sha256': rec['original_fork_case_raw_sha256'],
                'fork_evidence_sha256': rec['original_fork_evidence_raw_sha256'],
                'request_nonce_sha256': rec['issuer_request_nonce_sha256'],
            })
            nonce_sources.setdefault(rec['issuer_request_nonce_sha256'], set()).add(
                ('issuer', rec['signed_cas_receipt_original_raw_sha256']))
            for obs in rec['signed_observer_records']:
                observation = {
                    'window_id': wid,
                    'observer_id': obs['observer_id'],
                    'sequence': obs['readback_sequence'],
                    'source_sha256': obs['signed_readback_original_raw_sha256'],
                    'revision': obs['observed_revision'],
                    'head': obs['observed_head_raw_sha256'],
                }
                observations.append(observation)
                observer_sequences.setdefault((obs['observer_id'],
                                               obs['readback_sequence']), []).append(
                    observation)
                nonce_sources.setdefault(obs['request_nonce_sha256'], set()).add(
                    ('observer', obs['signed_readback_original_raw_sha256']))
        signed_witnesses.append(_source_witnesses(wid, report))

    # The SAME Ed25519 raw receipt must retain the SAME original case, signed
    # claim, parent, nonce and outcome in every window. A prior report's status
    # is never substituted for actual original source verification.
    overlap = sorted(set(origins[0]) & set(origins[1]))
    for receipt_sha in overlap:
        a_rec, b_rec = origins[0][receipt_sha], origins[1][receipt_sha]
        source_fields = (
            'signed_cas_claim_raw_sha256', 'original_fork_case_raw_sha256',
            'original_fork_evidence_raw_sha256', 'issuer_request_nonce_sha256',
            'issuer_parent_revision', 'issuer_parent_head_raw_sha256',
            'issuer_signed_outcome', 'issuer_signed_revision',
            'issuer_signed_head_raw_sha256',
        )
        need(all(a_rec[k] == b_rec[k] for k in source_fields),
             'IDENTICAL_SIGNED_RECEIPT_HAS_DIFFERENT_REPLAYED_PROVENANCE')

    # A single (ID, Ed25519 key) cannot sign two DIFFERENT original readbacks
    # at the same sequence without a true signed fork, even if they happen to
    # contain the same CAS state. Same byte-identical source replay is allowed.
    sequence_forks: list[dict] = []
    for (oid, seq), records in sorted(observer_sequences.items()):
        if len({v['source_sha256'] for v in records}) > 1:
            sequence_forks.append({
                'observer_id': oid, 'sequence': seq,
                'signed_original_raw_sha256': sorted({v['source_sha256'] for v in records}),
            })
    # Include issuer AND observer original Ed25519-signed state claims from
    # both windows: otherwise a cross-window issuer/observer contradiction
    # could be hidden by an apparent agreement between the two issuers.
    state_conflicts: list[dict] = []
    grouped = []
    for witness_set in signed_witnesses:
        index: dict[int, dict[str, list[dict]]] = {}
        for witness in witness_set:
            index.setdefault(witness['revision'], {}).setdefault(
                witness['head'], []).append(witness)
        grouped.append(index)
    for revision in sorted(set(grouped[0]) & set(grouped[1])):
        for head_a, sources_a in sorted(grouped[0][revision].items()):
            for head_b, sources_b in sorted(grouped[1][revision].items()):
                if head_a != head_b:
                    state_conflicts.append({
                        'revision': revision,
                        'left_signed_head': head_a,
                        'right_signed_head': head_b,
                        'left_signed_sources': sorted(set(s['source_sha256'] for s in sources_a)),
                        'right_signed_sources': sorted(set(s['source_sha256'] for s in sources_b)),
                    })

    # A revision can have a single selected issuer-original in a compatible
    # merged causal line. Different genuine signed receipts for same revision
    # are NOT silently merged even when they claim the same head.
    duplicate_revisions: list[dict] = []
    union: dict[int, dict] = {}
    for revision in sorted(by_revision):
        records = by_revision[revision]
        receipts = sorted(set(rec['original_receipt_sha256'] for rec in records))
        if len(receipts) > 1:
            duplicate_revisions.append({
                'revision': revision,
                'different_signed_issuer_originals': receipts,
            })
        union[revision] = records[0]
    nonce_alias = [
        {'nonce_sha256': nonce,
         'different_signed_sources': [
             {'role': role, 'original_raw_sha256': sha} for role, sha in sorted(sources)]}
        for nonce, sources in sorted(nonce_sources.items()) if len(sources) > 1
    ]

    # Opaque boundary is compared only when an actual ORIGINAL signed record
    # from the other window exists at that exact observer sequence. Unknown
    # boundary predecessors remain explicitly unreplayed, never fabricated.
    boundary_mismatches: list[dict] = []
    boundary_verified: list[dict] = []
    for i, manifest in enumerate(manifests):
        wid = originals[i][0]['window_id']
        other_id = originals[1-i][0]['window_id']
        for observer in manifest['observers']:
            bd = observer['boundary']
            if not bd['sequence']:
                continue
            matches = [item for item in observations
                       if item['window_id'] == other_id and
                       item['observer_id'] == observer['observer_id'] and
                       item['sequence'] == bd['sequence']]
            if not matches:
                continue
            if any(item['source_sha256'] == bd['raw_sha256'] and
                   item['revision'] == bd['observed_revision'] and
                   item['head'] == bd['observed_head_raw_sha256']
                   for item in matches):
                boundary_verified.append({
                    'window_id': wid, 'observer_id': observer['observer_id'],
                    'boundary_sequence': bd['sequence'],
                    'original_signed_previous_raw_sha256': bd['raw_sha256'],
                })
            else:
                boundary_mismatches.append({
                    'window_id': wid, 'observer_id': observer['observer_id'],
                    'boundary_sequence': bd['sequence'],
                })

    discontinuity: list[dict] = []
    ordered = [union[rev] for rev in sorted(union)]
    for earlier, later in zip(ordered, ordered[1:]):
        if (later['revision'] != earlier['revision']+1 or
            later['parent_revision'] != earlier['revision'] or
            later['parent_head'] != earlier['head']):
            discontinuity.append({
                'before_signed_revision': earlier['revision'],
                'after_signed_revision': later['revision'],
                'previous_original_receipt_sha256': earlier['original_receipt_sha256'],
                'next_original_receipt_sha256': later['original_receipt_sha256'],
            })

    failed = [w['window_id'] for w in window_summary
              if w['signed_window_exit_code'] != 0]
    if state_conflicts or sequence_forks:
        status = SIGNED_CONFLICT
    elif duplicate_revisions or nonce_alias:
        status = ISSUER_AMBIGUITY
    elif failed:
        status = CHILD_FAILED
    elif boundary_mismatches:
        status = BOUNDARY_MISMATCH
    elif not overlap:
        status = NO_OVERLAP
    elif discontinuity:
        status = BROKEN_UNION
    else:
        status = SUCCESS
    rc = 0 if status == SUCCESS else 2
    latest_signed = ordered[-1] if ordered else None
    report = {
        'schema': REPORT_SCHEMA,
        'status': status, 'exit_code': rc,
        'outer_manifest_original_raw_sha256': expected_manifest_sha256,
        'expected_registry_id': external['expected_registry_id'],
        'cas_authority_id': external['cas_authority_id'],
        'cas_authority_public_hex': external['cas_authority_public_hex'],
        'cas_store_namespace_id': external['cas_store_namespace_id'],
        'window_full_original_replays': window_summary,
        'shared_original_signed_issuer_receipts': overlap,
        'shared_signed_issuer_receipt_count': len(overlap),
        'left_only_signed_issuer_receipt_count': len(origins[0])-len(overlap),
        'right_only_signed_issuer_receipt_count': len(origins[1])-len(overlap),
        'union_distinct_signed_issuer_receipt_count': len(set(origins[0]) | set(origins[1])),
        'union_signed_issuer_revision_count': len(union),
        'replayed_original_signed_observer_count_with_overlaps': len(observations),
        'independent_observer_ids_with_unique_validated_public_keys': sorted(observer_profiles),
        'cross_window_signed_revision_head_conflicts': state_conflicts,
        'same_observer_signed_sequence_double_origins': sequence_forks,
        'different_issuer_receipts_at_same_revision': duplicate_revisions,
        'cross_window_nonce_reuse_for_different_originals': nonce_alias,
        'ec312_windows_not_individually_compatible': failed,
        'non_genesis_boundary_predecessor_mismatches': boundary_mismatches,
        'non_genesis_boundaries_confirmed_by_other_window_original': boundary_verified,
        'union_signed_issuer_parent_discontinuities': discontinuity,
        'last_replayed_union_signed_revision':
            latest_signed['revision'] if latest_signed else None,
        'last_candidate_sha256_of_compatible_signed_claims_only':
            latest_signed['head'] if rc == 0 else None,
        'all_four_ec312_observer_paths_replay_original_ec309_to_ec294_signatures': True,
        'each_ec312_original_manifest_has_independent_raw_sha_pin': True,
        'original_observer_boundaries_outside_replayed_windows_proven': False,
        'physical_same_store_linearizable_cas_or_global_latest_proven': False,
        'actual_key_authority_organization_and_nonce_freshness_proven': False,
        'external_network_cas_provider_or_host_operation_performed': False,
        'private_signing_key_loaded': False,
        'business_or_external_store_write_performed': False,
    }
    need(len(b.canonical(report)) + 1 <= MAX_REPORT_BYTES,
         'AUDIT_REPORT_EXCEEDS_BOUNDED_SIZE', 'invalid_input')
    return report


def evaluate(*, manifest_file: str, expected_manifest_sha256: str) -> dict:
    external = read_manifest(manifest_file=manifest_file,
                             expected_manifest_sha256=expected_manifest_sha256)
    originals: list[tuple[dict, dict]] = []
    for entry in external['windows']:
        child_manifest = old.read_manifest(
            manifest_file=entry['manifest_file'],
            expected_manifest_sha256=entry['expected_manifest_sha256'])
        # This is the authoritative validation step: no status or raw SHA
        # inside an untrusted previously saved EC312 audit is accepted.
        child_report = old.evaluate(
            manifest_file=entry['manifest_file'],
            expected_manifest_sha256=entry['expected_manifest_sha256'])
        originals.append(({**entry, 'manifest': child_manifest}, child_report))
    return _compare_verified(originals, expected_manifest_sha256, external)


def result_from_report(report: dict) -> dict:
    return {
        'status': report['status'], 'exit_code': report['exit_code'],
        'outer_manifest_original_raw_sha256': report['outer_manifest_original_raw_sha256'],
        'audit_report_raw_sha256': b.digest(b.canonical(report)),
        'audit_report_written': False,
        'shared_signed_issuer_receipt_count': report['shared_signed_issuer_receipt_count'],
        'union_distinct_signed_issuer_receipt_count':
            report['union_distinct_signed_issuer_receipt_count'],
        'replayed_original_signed_observer_count_with_overlaps':
            report['replayed_original_signed_observer_count_with_overlaps'],
        'cross_window_signed_revision_head_conflicts':
            report['cross_window_signed_revision_head_conflicts'],
        'same_observer_signed_sequence_double_origins':
            report['same_observer_signed_sequence_double_origins'],
        'different_issuer_receipts_at_same_revision':
            report['different_issuer_receipts_at_same_revision'],
        'cross_window_nonce_reuse_for_different_originals':
            report['cross_window_nonce_reuse_for_different_originals'],
        'ec312_windows_not_individually_compatible':
            report['ec312_windows_not_individually_compatible'],
        'non_genesis_boundary_predecessor_mismatches':
            report['non_genesis_boundary_predecessor_mismatches'],
        'non_genesis_boundaries_confirmed_by_other_window_original':
            report['non_genesis_boundaries_confirmed_by_other_window_original'],
        'union_signed_issuer_parent_discontinuities':
            report['union_signed_issuer_parent_discontinuities'],
        'last_replayed_union_signed_revision':
            report['last_replayed_union_signed_revision'],
        'last_candidate_sha256_of_compatible_signed_claims_only':
            report['last_candidate_sha256_of_compatible_signed_claims_only'],
        'both_ec312_windows_original_ed25519_evidence_replayed': True,
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



def _read_private_saved_audit(path: str, external_raw_sha256: str) -> dict:
    """Read a potentially >32KiB audit under its OWN bounded O_NOFOLLOW pin.

    EC306's normal private reader caps its input to 32KiB (correct for EC306
    indexes but too small for a maximal EC313 audit). Preserve the SAME
    strict private owner, inode, whole-source SHA and canonical LF semantics.
    """
    target = b._private_parent(path)
    try:
        before = os.lstat(target)
    except OSError as exc:
        raise a.AnchorError('EC313_SAVED_AUDIT_UNAVAILABLE', 'unavailable') from exc
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
         stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
         'SAVED_AUDIT_OWNER_0600_SINGLE_REGULAR_LINK_REQUIRED')
    raw = io._open_regular(path, MAX_REPORT_BYTES, private=True)
    after = os.lstat(target)
    need((before.st_dev, before.st_ino, before.st_size,
          before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size,
          after.st_mtime_ns, after.st_ctime_ns),
         'SAVED_AUDIT_CHANGED_DURING_READ', 'unavailable')
    need(hmac.compare_digest(b.digest(raw), external_raw_sha256),
         'SAVED_AUDIT_WHOLE_BYTES_DIFFER_FROM_EXTERNAL_SHA')
    saved = io.parse(raw, MAX_REPORT_BYTES)
    need(hmac.compare_digest(raw, b.canonical(saved)),
         'SAVED_AUDIT_NOT_CANONICAL_EXACT_BYTES')
    return saved


def verify_report(*, manifest_file: str, expected_manifest_sha256: str,
                  audit_report_file: str, expected_audit_report_sha256: str) -> dict:
    need(_path(audit_report_file) and rb._sha(expected_audit_report_sha256),
         'PRIVATE_AUDIT_PATH_AND_INDEPENDENT_RAW_SHA_REQUIRED', 'invalid_input')
    saved = _read_private_saved_audit(audit_report_file,
                                      expected_audit_report_sha256)
    need(len(b.canonical(saved)) + 1 <= MAX_REPORT_BYTES,
         'SAVED_AUDIT_EXCEEDS_BUDGET', 'invalid_input')
    fresh = evaluate(manifest_file=manifest_file,
                     expected_manifest_sha256=expected_manifest_sha256)
    need(saved == fresh, 'AUDIT_NOT_EQUAL_TO_NEW_FULL_ORIGINAL_SOURCE_REPLAY')
    result = result_from_report(fresh)
    result['audit_report_raw_sha256'] = expected_audit_report_sha256
    return result
