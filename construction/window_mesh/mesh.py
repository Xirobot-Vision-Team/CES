#!/usr/bin/env python3
"""EC314: replay a bounded graph of genuine EC312 signed original windows.

An edge exists ONLY for an identical, fully replayed EC308 signed issuer receipt.
A chain of edges may connect windows without a common receipt in every window.
All issuer AND observer signed claims are checked globally, not merely along a
chosen spanning tree. In particular, adding a contradictory or disconnected
window can never turn a failing mesh into a successful one.

The operator supplies separate external raw SHA pins for every private EC312
manifest and for this outer manifest. Prior audit reports and claimed PASS
statuses are not accepted as inputs. This code never signs, performs CAS I/O,
or establishes the physical/organizational authenticity of an external store.
"""
from __future__ import annotations

from collections import defaultdict, deque
import hmac
import os
import stat
from typing import Any

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from delivery_anchor import operator as store
from portable_bundle import bundle as b
from receiver_ack import ack as receiver
from registrar_epochs import epochs
from cas_receipt import receipt as cas
from cas_readback import readback as rb
from dual_observer_reconciliation import reconcile as old

MANIFEST_SCHEMA = 'ces.ec314.multi_window_signed_cas_mesh_manifest.v1'
REPORT_SCHEMA = 'ces.ec314.multi_window_signed_cas_mesh_audit.v1'
RESULT_SCHEMA = 'ces.ec314.multi_window_signed_cas_mesh_result.v1'
DENIAL_SCHEMA = 'ces.ec314.multi_window_signed_cas_mesh_denial.v1'
MANIFEST_FIELDS = frozenset({
    'schema', 'cas_authority_id', 'cas_authority_public_hex',
    'cas_store_namespace_id', 'expected_registry_id', 'windows',
})
WINDOW_FIELDS = frozenset({'window_id', 'manifest_file', 'expected_manifest_sha256'})
MIN_WINDOWS = 3
MAX_WINDOWS = 6
MAX_MANIFEST_BYTES = 32_000
MAX_REPORT_BYTES = 450_000

SUCCESS = 'replayed_signed_window_mesh_connected_and_consistent_not_cas_store_proof'
SIGNED_CONFLICT = 'multi_window_authentic_signed_state_sequence_or_predecessor_conflict'
ISSUER_AMBIGUITY = 'multi_window_distinct_signed_issuer_or_nonce_source_ambiguity'
CHILD_FAILED = 'one_or_more_original_signed_ec312_windows_not_compatible'
BOUNDARY_MISMATCH = 'multi_window_opaque_boundary_contradicts_actual_signed_predecessor'
DISCONNECTED = 'multi_window_signed_receipt_intersection_graph_disconnected'
BROKEN_UNION = 'multi_window_issuer_original_parent_chain_discontinuous'
ALL_STATUSES = (SUCCESS, SIGNED_CONFLICT, ISSUER_AMBIGUITY, CHILD_FAILED,
                BOUNDARY_MISMATCH, DISCONNECTED, BROKEN_UNION)

SOURCE_FIELDS = (
    'signed_cas_claim_raw_sha256', 'original_fork_case_raw_sha256',
    'original_fork_evidence_raw_sha256', 'issuer_request_nonce_sha256',
    'issuer_parent_revision', 'issuer_parent_head_raw_sha256',
    'issuer_signed_outcome', 'issuer_signed_revision',
    'issuer_signed_head_raw_sha256',
)


def need(test: Any, code: str, status: str = 'permission_denied') -> None:
    if test is not True:
        raise a.AnchorError('EC314_' + code, status)


def _path(value: Any) -> bool:
    return type(value) is str and 0 < len(value) <= 4000 and '\x00' not in value and os.path.isabs(value)


def read_manifest(*, manifest_file: str, expected_manifest_sha256: str) -> dict:
    need(_path(manifest_file), 'ABSOLUTE_PRIVATE_OUTER_MANIFEST_REQUIRED', 'invalid_input')
    need(rb._sha(expected_manifest_sha256), 'EXTERNAL_OUTER_MANIFEST_RAW_SHA_REQUIRED',
         'invalid_input')
    # Original EC306 reader: 0700 private parent, 0600 single-link regular,
    # O_NOFOLLOW, inode checks, canonical LF JSON, strict external raw SHA.
    doc = epochs._owner_private_read(manifest_file, expected_manifest_sha256)
    need(len(b.canonical(doc)) <= MAX_MANIFEST_BYTES,
         'OUTER_MANIFEST_EXCEEDS_BUDGET', 'invalid_input')
    a.exact(doc, MANIFEST_FIELDS, 'EC314_OUTER_FIELDS_NOT_EXACT')
    need(doc['schema'] == MANIFEST_SCHEMA, 'MANIFEST_SCHEMA_NOT_EC314')
    cas._trust({
        'cas_authority_id': doc['cas_authority_id'],
        'cas_authority_public_hex': doc['cas_authority_public_hex'],
        'expected_request_nonce_sha256': 'f'*64,
        'expected_parent_cas_revision': 0,
        'expected_parent_cas_head_sha256': 'e'*64,
    })
    for field in ('cas_store_namespace_id', 'expected_registry_id'):
        need(type(doc[field]) is str and receiver.ID.fullmatch(doc[field]) is not None,
             'EXTERNAL_NAMESPACE_OR_REGISTRY_ID_INVALID', 'invalid_input')
    windows = doc['windows']
    need(type(windows) is list and MIN_WINDOWS <= len(windows) <= MAX_WINDOWS,
         'THREE_TO_SIX_WINDOWS_REQUIRED', 'invalid_input')
    ids, raw_shas = [], []
    for entry in windows:
        a.exact(entry, WINDOW_FIELDS, 'EC314_WINDOW_FIELDS_NOT_EXACT')
        need(type(entry['window_id']) is str and
             receiver.ID.fullmatch(entry['window_id']) is not None,
             'INVALID_WINDOW_ID', 'invalid_input')
        need(_path(entry['manifest_file']),
             'ABSOLUTE_PRIVATE_EC312_MANIFEST_REQUIRED', 'invalid_input')
        need(rb._sha(entry['expected_manifest_sha256']),
             'INDEPENDENT_EC312_MANIFEST_RAW_SHA_REQUIRED', 'invalid_input')
        ids.append(entry['window_id'])
        raw_shas.append(entry['expected_manifest_sha256'])
    need(ids == sorted(set(ids)), 'WINDOW_IDS_MUST_BE_UNIQUE_AND_SORTED', 'invalid_input')
    need(len(set(raw_shas)) == len(raw_shas),
         'EACH_EC312_MANIFEST_MUST_BE_DIFFERENT_ORIGINAL', 'invalid_input')
    return doc


def _signed_data(originals: list[tuple[dict, dict]], external: dict) -> tuple:
    """Project claims after ALL original EC312/309/308/307/294 replays.

    The caller cannot inject precomputed 'verified' data: this is only invoked
    by evaluate, which executes old.evaluate independently for each window.
    """
    window_receipts: dict[str, dict[str, dict]] = {}
    receipts: dict[str, dict] = {}
    origins: dict[str, set[str]] = defaultdict(set)
    signed_states: dict[int, dict[str, set[tuple[str, str, str]]]] = defaultdict(
        lambda: defaultdict(set))
    observer_seq: dict[tuple[str, int], dict[str, dict]] = defaultdict(dict)
    nonce_sources: dict[str, set[tuple[str, str]]] = defaultdict(set)
    signer_ids: dict[str, str] = {}
    signer_keys: dict[str, str] = {}
    boundaries: list[dict] = []
    window_summaries: list[dict] = []
    failed: list[str] = []

    def signed_state(revision: int, head: str, wid: str, role: str, sha: str) -> None:
        signed_states[revision][head].add((wid, role, sha))

    for entry, report in originals:
        wid = entry['window_id']
        manifest = entry['manifest']
        need(report['registry_id'] == external['expected_registry_id'],
             'SIGNED_REGISTRY_DIFFERS_FROM_EXTERNAL_TRUST_ROOT')
        need(all(manifest[key] == external[key] for key in (
             'cas_authority_id', 'cas_authority_public_hex', 'cas_store_namespace_id')),
             'SIGNED_WINDOW_AUTHORITY_OR_NAMESPACE_DIFFERS_FROM_EXTERNAL_TRUST_ROOT')
        if report['exit_code'] != 0:
            failed.append(wid)
        window_receipts[wid] = {}
        for observer in manifest['observers']:
            oid, pub = observer['observer_id'], observer['observer_public_hex']
            if oid in signer_ids:
                need(signer_ids[oid] == pub,
                     'OBSERVER_ID_REUSES_DIFFERENT_PUBLIC_KEY_WITHOUT_ROTATION')
            if pub in signer_keys:
                need(signer_keys[pub] == oid,
                     'OBSERVER_PUBLIC_KEY_REUSED_UNDER_DIFFERENT_ID')
            signer_ids[oid], signer_keys[pub] = pub, oid
            boundary = observer['boundary']
            if boundary['sequence']:
                boundaries.append({'window_id': wid, 'observer_id': oid,
                                   'sequence': boundary['sequence'],
                                   'original_raw_sha256': boundary['raw_sha256'],
                                   'revision': boundary['observed_revision'],
                                   'head': boundary['observed_head_raw_sha256']})
        for index, rec in enumerate(report['signed_cas_and_dual_observation_records']):
            raw = rec['signed_cas_receipt_original_raw_sha256']
            if raw in receipts:
                need(all(receipts[raw][key] == rec[key] for key in SOURCE_FIELDS),
                     'IDENTICAL_SIGNED_ISSUER_ORIGINAL_DIVERGENT_VERIFIED_PROVENANCE')
            else:
                receipts[raw] = rec
            need(raw not in window_receipts[wid],
                 'DUPLICATE_SIGNED_ISSUER_SOURCE_WITHIN_ONE_WINDOW')
            window_receipts[wid][raw] = rec
            origins[raw].add(wid)
            signed_state(rec['issuer_signed_revision'],
                         rec['issuer_signed_head_raw_sha256'], wid, 'issuer', raw)
            nonce_sources[rec['issuer_request_nonce_sha256']].add(('issuer', raw))
            # The EC312 result has already verified BOTH Ed25519 originals.
            # Re-read the pinned readback envelope only to examine its signed
            # predecessor SHA/revision for cross-WINDOW predecessor links.
            readback_items = {item['observer_id']: item
                              for item in manifest['decisions'][index]['readbacks']}
            for obs in rec['signed_observer_records']:
                oid = obs['observer_id']
                item = readback_items[oid]
                need(item['expected_readback_sha256'] ==
                     obs['signed_readback_original_raw_sha256'],
                     'EC312_REPLAY_SOURCE_NOT_IDENTICAL_TO_READBACK_MANIFEST')
                _, claim = rb._parse_readback(item['readback_file'],
                                               item['expected_readback_sha256'])
                source = obs['signed_readback_original_raw_sha256']
                need(claim['observer_id'] == oid and
                     claim['readback_sequence'] == obs['readback_sequence'] and
                     claim['observed_cas_revision'] == obs['observed_revision'] and
                     claim['observed_head_chain_raw_sha256'] ==
                         obs['observed_head_raw_sha256'] and
                     claim['ec308_cas_receipt_raw_sha256'] == raw,
                     'VERIFIED_READBACK_PROJECTION_DOES_NOT_MATCH_SIGNED_ORIGINAL')
                signed_state(obs['observed_revision'], obs['observed_head_raw_sha256'],
                             wid, 'observer:' + oid, source)
                nonce_sources[obs['request_nonce_sha256']].add(('observer', source))
                record = {
                    'window_ids': {wid}, 'observer_id': oid,
                    'sequence': obs['readback_sequence'],
                    'source_sha256': source,
                    'revision': obs['observed_revision'],
                    'head': obs['observed_head_raw_sha256'],
                    'previous_sequence': claim['readback_sequence']-1,
                    'previous_sha256': claim['previous_readback_raw_sha256'],
                    'previous_revision': claim['previous_readback_observed_revision'],
                    'issuer_receipt_sha256': raw,
                }
                marker = (oid, obs['readback_sequence'])
                if source in observer_seq[marker]:
                    old_record = observer_seq[marker][source]
                    need(all(old_record[k] == record[k] for k in record
                             if k != 'window_ids'),
                         'IDENTICAL_OBSERVER_ORIGINAL_HAS_DIFFERENT_SIGNED_PROVENANCE')
                    old_record['window_ids'].add(wid)
                else:
                    observer_seq[marker][source] = record
        window_summaries.append({
            'window_id': wid,
            'ec312_manifest_original_raw_sha256': entry['expected_manifest_sha256'],
            'recomputed_ec312_signed_audit_raw_sha256': b.digest(b.canonical(report)),
            'ec312_status': report['status'], 'ec312_exit_code': report['exit_code'],
            'real_issuer_originals_replayed': report['complete_distinct_cas_decision_count'],
            'real_observer_ed25519_originals_replayed':
                report['complete_original_signed_readback_count'],
        })
    return (window_receipts, receipts, origins, signed_states, observer_seq,
            nonce_sources, signer_ids, boundaries, window_summaries, failed)


def _graph(window_receipts: dict[str, dict[str, dict]]) -> tuple:
    ids = sorted(window_receipts)
    adj: dict[str, dict[str, list[str]]] = {wid: {} for wid in ids}
    edges: list[dict] = []
    for i, left in enumerate(ids):
        for right in ids[i+1:]:
            shared = sorted(set(window_receipts[left]) & set(window_receipts[right]))
            if shared:
                adj[left][right] = shared
                adj[right][left] = shared
                edges.append({'window_a': left, 'window_b': right,
                              'shared_signed_issuer_original_sha256': shared,
                              'shared_original_count': len(shared)})
    components: list[list[str]] = []
    paths: list[dict] = []
    tree_edges: set[tuple[str, str]] = set()
    for root in ids:
        if any(root in comp for comp in components):
            continue
        queue = deque([root])
        parent: dict[str, str | None] = {root: None}
        while queue:
            wid = queue.popleft()
            for dest in sorted(adj[wid]):
                if dest not in parent:
                    parent[dest] = wid
                    tree_edges.add(tuple(sorted((wid, dest))))
                    queue.append(dest)
        components.append(sorted(parent))
        for wid in sorted(parent):
            route = [wid]
            cursor = wid
            while parent[cursor] is not None:
                cursor = parent[cursor]
                route.append(cursor)
            route.reverse()
            paths.append({
                'root_window_id': root,
                'destination_window_id': wid,
                'verified_original_overlap_path': route,
                'each_hop_signed_original_receipt_anchor_sha256': [
                    adj[x][y][0] for x, y in zip(route, route[1:])],
            })
    # Each non-tree edge closes a cycle. Every anchor on the direct edge and
    # along the tree path is a genuinely reverified original signed receipt;
    # global signed-claim checks below examine ALL such paths for contradictions.
    redundant: list[dict] = []
    for edge in edges:
        left, right = edge['window_a'], edge['window_b']
        if (left, right) in tree_edges:
            continue
        search = deque([(left, [left])])
        seen = {left}
        tree_adj: dict[str, list[str]] = defaultdict(list)
        for x, y in tree_edges:
            tree_adj[x].append(y)
            tree_adj[y].append(x)
        found: list[str] | None = None
        while search:
            cur, path = search.popleft()
            if cur == right:
                found = path
                break
            for near in sorted(tree_adj[cur]):
                if near not in seen:
                    seen.add(near)
                    search.append((near, path + [near]))
        need(found is not None and len(found) >= 3,
             'VERIFIED_MESH_CYCLE_SPANNING_PATH_MISSING', 'unavailable')
        redundant.append({
            'direct_window_a': left, 'direct_window_b': right,
            'direct_original_overlap_sha256': edge['shared_signed_issuer_original_sha256'],
            'independent_tree_path_window_ids': found,
            'tree_path_signed_original_anchor_sha256': [
                adj[x][y][0] for x, y in zip(found, found[1:])],
        })
    return edges, components, paths, redundant


def _compare_verified(originals: list[tuple[dict, dict]],
                      expected_manifest_sha256: str, external: dict) -> dict:
    (by_window, originals_by_sha, origins, states, seqs, nonces,
     signers, boundaries, summaries, failures) = _signed_data(originals, external)
    edges, components, paths, cycles = _graph(by_window)

    # Any originally signed issuer/observer statement with same revision and
    # DIFFERENT heads is contradictory regardless of its component or path.
    signed_conflicts = []
    for revision, heads in sorted(states.items()):
        if len(heads) > 1:
            signed_conflicts.append({
                'revision': revision,
                'incompatible_original_signed_heads': [
                    {'head_raw_sha256': head,
                     'independently_replayed_window_ids': sorted({v[0] for v in proofs}),
                     'original_signed_sources': sorted({v[2] for v in proofs})}
                    for head, proofs in sorted(heads.items())],
            })
    seq_forks = [
        {'observer_id': oid, 'sequence': seq,
         'different_true_signed_readback_original_sha256': sorted(versions),
         'replaying_window_ids': sorted(set().union(*(r['window_ids'] for r in versions.values())))}
        for (oid, seq), versions in sorted(seqs.items()) if len(versions) > 1
    ]
    # Unlike EC313, also verify the SIGNED predecessor link when another
    # window actually replays the predecessor source at sequence n-1.
    predecessor_conflicts: list[dict] = []
    predecessor_confirmed: list[dict] = []
    observer_regressions: list[dict] = []
    by_observer: dict[str, dict[int, dict[str, dict]]] = defaultdict(dict)
    for (oid, seq), versions in seqs.items():
        by_observer[oid][seq] = versions
    for oid, steps in sorted(by_observer.items()):
        earlier_seq: int | None = None
        earlier_revisions: set[int] | None = None
        for sequence, signed_versions in sorted(steps.items()):
            revisions = {r['revision'] for r in signed_versions.values()}
            if earlier_revisions is not None and min(revisions) < max(earlier_revisions):
                observer_regressions.append({
                    'observer_id': oid, 'earlier_sequence': earlier_seq,
                    'later_sequence': sequence,
                    'earlier_signed_revisions': sorted(earlier_revisions),
                    'later_signed_revisions': sorted(revisions),
                })
            if sequence-1 in steps:
                predecessor_versions = steps[sequence-1]
                # If the previous sequence is equivocal, that is already a
                # seq fork. Still record any incompatible signed predecessor.
                for signed in signed_versions.values():
                    matches = [prior for prior in predecessor_versions.values()
                               if signed['previous_sequence'] == sequence-1 and
                               signed['previous_sha256'] == prior['source_sha256'] and
                               signed['previous_revision'] == prior['revision']]
                    if matches:
                        predecessor_confirmed.append({
                            'observer_id': oid, 'sequence': sequence,
                            'signed_original_raw_sha256': signed['source_sha256'],
                            'verified_previous_raw_sha256': signed['previous_sha256'],
                        })
                    else:
                        predecessor_conflicts.append({
                            'observer_id': oid, 'sequence': sequence,
                            'signed_original_raw_sha256': signed['source_sha256'],
                            'signed_previous_raw_sha256': signed['previous_sha256'],
                            'actually_replayed_previous_original_sha256':
                                sorted(predecessor_versions),
                        })
            earlier_seq, earlier_revisions = sequence, revisions

    # Distinct Ed25519 issuer originals at ONE revision cannot be merged even
    # if both signed claims happen to specify an identical revision/head.
    by_revision: dict[int, set[str]] = defaultdict(set)
    for sha, rec in originals_by_sha.items():
        by_revision[rec['issuer_signed_revision']].add(sha)
    issuer_forks = [
        {'revision': rev, 'different_true_issuer_receipt_sha256': sorted(shas),
         'replaying_window_ids': sorted(set().union(*(origins[sha] for sha in shas)))}
        for rev, shas in sorted(by_revision.items()) if len(shas) > 1
    ]
    aliases = [
        {'request_nonce_sha256': nonce, 'different_signed_origins': [
            {'role': role, 'original_raw_sha256': sha} for role, sha in sorted(sources)]}
        for nonce, sources in sorted(nonces.items()) if len(sources) > 1
    ]

    # Opaque boundary is NOT presumed true, and is not a fake signed record.
    # Compare it against ALL original signed records in every other window at
    # precisely that observer sequence; any mismatch is conclusive conflict.
    boundaries_verified: list[dict] = []
    boundaries_unverified: list[dict] = []
    boundaries_conflict: list[dict] = []
    for boundary in boundaries:
        matches = [v for v in seqs.get((boundary['observer_id'], boundary['sequence']),
                                     {}).values()
                   if any(wid != boundary['window_id'] for wid in v['window_ids'])]
        label = {'window_id': boundary['window_id'],
                 'observer_id': boundary['observer_id'],
                 'boundary_sequence': boundary['sequence']}
        if not matches:
            boundaries_unverified.append(label)
        elif all(boundary['original_raw_sha256'] == v['source_sha256'] and
                 boundary['revision'] == v['revision'] and
                 boundary['head'] == v['head'] for v in matches):
            boundaries_verified.append({**label,
                'original_signed_previous_sha256': boundary['original_raw_sha256'],
                'verified_from_other_window_ids': sorted(set().union(*(
                    v['window_ids'] - {boundary['window_id']} for v in matches)))})
        else:
            boundaries_conflict.append({**label,
                'alleged_previous_raw_sha256': boundary['original_raw_sha256'],
                'other_replayed_original_sha256': sorted({v['source_sha256'] for v in matches})})

    ordered = [(rev, originals_by_sha[min(shas)])
               for rev, shas in sorted(by_revision.items())]
    parent_breaks: list[dict] = []
    for (prev_rev, earlier), (next_rev, later) in zip(ordered, ordered[1:]):
        if (next_rev != prev_rev+1 or
            later['issuer_parent_revision'] != prev_rev or
            later['issuer_parent_head_raw_sha256'] !=
                earlier['issuer_signed_head_raw_sha256']):
            parent_breaks.append({
                'earlier_signed_revision': prev_rev,
                'later_signed_revision': next_rev,
                'earlier_original_signed_receipt_sha256':
                    earlier['signed_cas_receipt_original_raw_sha256'],
                'later_original_signed_receipt_sha256':
                    later['signed_cas_receipt_original_raw_sha256'],
            })

    if signed_conflicts or seq_forks or predecessor_conflicts or observer_regressions:
        status = SIGNED_CONFLICT
    elif issuer_forks or aliases:
        status = ISSUER_AMBIGUITY
    elif failures:
        status = CHILD_FAILED
    elif boundaries_conflict:
        status = BOUNDARY_MISMATCH
    elif len(components) != 1:
        status = DISCONNECTED
    elif parent_breaks:
        status = BROKEN_UNION
    else:
        status = SUCCESS
    code = 0 if status == SUCCESS else 2
    latest_revision, latest_receipt = ordered[-1] if ordered else (None, None)
    report = {
        'schema': REPORT_SCHEMA, 'status': status, 'exit_code': code,
        'outer_manifest_original_raw_sha256': expected_manifest_sha256,
        'cas_authority_id': external['cas_authority_id'],
        'cas_authority_public_hex': external['cas_authority_public_hex'],
        'cas_store_namespace_id': external['cas_store_namespace_id'],
        'expected_registry_id': external['expected_registry_id'],
        'each_window_full_original_ec312_ed25519_replay': summaries,
        'original_signed_issuer_receipt_intersection_edges': edges,
        'connected_components_by_actual_signed_original': components,
        'deterministic_verified_original_overlap_paths': paths,
        'extra_cycle_edges_and_independent_true_original_paths': cycles,
        'window_count': len(by_window),
        'connected_component_count': len(components),
        'exact_original_signed_intersection_edge_count': len(edges),
        'unique_true_issuer_signed_original_count': len(originals_by_sha),
        'unique_true_signed_observer_original_count': len(set().union(
            *(set(entries) for entries in seqs.values()))),
        'replayed_observer_original_occurrences': sum(
            s['real_observer_ed25519_originals_replayed'] for s in summaries),
        'validated_observer_identity_count': len(signers),
        'cross_mesh_true_signed_state_head_conflicts': signed_conflicts,
        'cross_mesh_same_signer_sequence_double_originals': seq_forks,
        'cross_mesh_signed_observer_predecessor_conflicts': predecessor_conflicts,
        'cross_mesh_signed_observer_revision_regressions': observer_regressions,
        'different_true_issuer_originals_claim_same_revision': issuer_forks,
        'cross_mesh_signed_source_nonce_reuse': aliases,
        'ec312_original_signed_windows_not_individually_compatible': failures,
        'opaque_boundaries_verified_by_other_signed_original': boundaries_verified,
        'opaque_boundaries_without_replayed_original': boundaries_unverified,
        'opaque_boundaries_contradicted_by_true_signed_original': boundaries_conflict,
        'cross_mesh_signed_issuer_parent_or_revision_gaps': parent_breaks,
        'signed_observer_cross_window_predecessor_links_verified':
            sorted(predecessor_confirmed, key=lambda v: (
                v['observer_id'], v['sequence'], v['signed_original_raw_sha256'])),
        'highest_bounded_signed_issuer_revision': latest_revision,
        'last_candidate_sha256_of_bounded_compatible_signed_claims_only': (
            latest_receipt['issuer_signed_head_raw_sha256'] if code == 0 else None),
        'all_ec312_windows_replay_real_original_ec309_to_ec294_signatures': True,
        'all_cross_path_states_and_signed_origins_globally_compared': True,
        'unseen_window_history_or_unreplayed_boundaries_proven': False,
        'actual_physical_single_linearizable_cas_or_global_latest_proven': False,
        'real_governance_custody_or_real_nonce_freshness_proven': False,
        'external_cas_or_network_provider_or_host_access_performed': False,
        'private_key_loaded': False,
        'business_or_external_store_write_performed': False,
    }
    need(len(b.canonical(report)) <= MAX_REPORT_BYTES,
         'BOUNDED_MESH_AUDIT_TOO_LARGE', 'invalid_input')
    return report


def evaluate(*, manifest_file: str, expected_manifest_sha256: str) -> dict:
    external = read_manifest(manifest_file=manifest_file,
                             expected_manifest_sha256=expected_manifest_sha256)
    originals: list[tuple[dict, dict]] = []
    for entry in external['windows']:
        private_manifest = old.read_manifest(
            manifest_file=entry['manifest_file'],
            expected_manifest_sha256=entry['expected_manifest_sha256'])
        # AUTHORITATIVE ORIGINAL SIGNATURE REPLAY; old EC312 audit not input.
        signed_report = old.evaluate(
            manifest_file=entry['manifest_file'],
            expected_manifest_sha256=entry['expected_manifest_sha256'])
        originals.append(({**entry, 'manifest': private_manifest}, signed_report))
    return _compare_verified(originals, expected_manifest_sha256, external)


def result_from_report(report: dict) -> dict:
    keys = (
        'window_count', 'connected_component_count',
        'exact_original_signed_intersection_edge_count',
        'unique_true_issuer_signed_original_count',
        'unique_true_signed_observer_original_count',
        'replayed_observer_original_occurrences',
        'validated_observer_identity_count',
        'cross_mesh_true_signed_state_head_conflicts',
        'cross_mesh_same_signer_sequence_double_originals',
        'cross_mesh_signed_observer_predecessor_conflicts',
        'cross_mesh_signed_observer_revision_regressions',
        'different_true_issuer_originals_claim_same_revision',
        'cross_mesh_signed_source_nonce_reuse',
        'ec312_original_signed_windows_not_individually_compatible',
        'opaque_boundaries_contradicted_by_true_signed_original',
        'cross_mesh_signed_issuer_parent_or_revision_gaps',
        'last_candidate_sha256_of_bounded_compatible_signed_claims_only',
    )
    return {
        'status': report['status'], 'exit_code': report['exit_code'],
        'outer_manifest_original_raw_sha256': report['outer_manifest_original_raw_sha256'],
        'audit_report_raw_sha256': b.digest(b.canonical(report)),
        'audit_report_written': False,
        'window_signed_intersection_edges': [
            {'window_a': e['window_a'], 'window_b': e['window_b'],
             'shared_original_count': e['shared_original_count']}
            for e in report['original_signed_issuer_receipt_intersection_edges']],
        'connected_components_by_actual_signed_original':
            report['connected_components_by_actual_signed_original'],
        'verified_overlap_paths': report['deterministic_verified_original_overlap_paths'],
        'independent_cycle_crosschecks': len(
            report['extra_cycle_edges_and_independent_true_original_paths']),
        **{key: report[key] for key in keys},
        'all_windows_original_ec312_ed25519_evidence_replayed': True,
        'external_cas_or_global_latest_proven': False,
        'business_or_external_store_write_performed': False,
    }


def verify(*, manifest_file: str, expected_manifest_sha256: str,
           out: str | None = None) -> dict:
    fresh = evaluate(manifest_file=manifest_file,
                     expected_manifest_sha256=expected_manifest_sha256)
    if out is not None:
        store.store(out, fresh, MAX_REPORT_BYTES)
    result = result_from_report(fresh)
    result['audit_report_written'] = out is not None
    return result


def _read_private_saved_audit(path: str, external_raw_sha256: str) -> dict:
    # Same inode/privacy/canonical SHA contract as EC313 but EC314-specific
    # max report. Always compare a distinct EXTERNAL raw report SHA pin.
    target = b._private_parent(path)
    try:
        before = os.lstat(target)
    except OSError as exc:
        raise a.AnchorError('EC314_SAVED_AUDIT_UNAVAILABLE', 'unavailable') from exc
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
         stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
         'SAVED_AUDIT_OWNER_PRIVATE_0600_SINGLE_REGULAR_LINK_REQUIRED')
    raw = io._open_regular(path, MAX_REPORT_BYTES, private=True)
    after = os.lstat(target)
    need((before.st_dev, before.st_ino, before.st_size,
          before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size,
          after.st_mtime_ns, after.st_ctime_ns),
         'SAVED_AUDIT_CHANGED_DURING_READ', 'unavailable')
    need(hmac.compare_digest(b.digest(raw), external_raw_sha256),
         'SAVED_AUDIT_WHOLE_BYTES_SHA_DOES_NOT_MATCH_INDEPENDENT_PIN')
    saved = io.parse(raw, MAX_REPORT_BYTES)
    need(hmac.compare_digest(raw, b.canonical(saved)),
         'SAVED_AUDIT_MUST_BE_CANONICAL_EXACT_JSON_LF_BYTES')
    return saved


def verify_report(*, manifest_file: str, expected_manifest_sha256: str,
                  audit_report_file: str, expected_audit_report_sha256: str) -> dict:
    need(_path(audit_report_file) and rb._sha(expected_audit_report_sha256),
         'PRIVATE_AUDIT_PATH_AND_EXTERNAL_RAW_SHA_REQUIRED', 'invalid_input')
    saved = _read_private_saved_audit(audit_report_file, expected_audit_report_sha256)
    fresh = evaluate(manifest_file=manifest_file,
                     expected_manifest_sha256=expected_manifest_sha256)
    need(saved == fresh, 'SAVED_AUDIT_NOT_EQUAL_TO_FRESH_FULL_ORIGINAL_REPLAY')
    result = result_from_report(fresh)
    result['audit_report_raw_sha256'] = expected_audit_report_sha256
    return result
