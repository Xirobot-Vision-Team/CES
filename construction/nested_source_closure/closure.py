#!/usr/bin/env python3
"""EC335: export the *observed* nested original-read closure of EC333 replay.

The source must replay EC333->EC294 through the production verifier with the
EC317 scoped ORIGINAL read observer. That observer captures guarded reads,
not a speculative search through arbitrary filesystem paths. The EC334 first-
hop inventory is required independently and must be an exact subset. Nested
SHA digests are local measurements, NOT external signatures or trust anchors.

The receiver checks only the copied bytes. In particular, reading an old signed
path-sensitive claim at a different path is not a re-verification of that claim
on the receiver. Embedded files inside signed ZIPs are transported as original
ZIP bytes and are NOT independently re-exported or asserted to be external.
"""
from __future__ import annotations

import hmac
from io import BytesIO
import os
from pathlib import Path
import stat
import tempfile
from typing import Any
import zipfile

from finding_query_host import protocol as io
from delivery_anchor import anchor
from fork_case_transport import case
from dual_channel_receipt import receipt
from replayable_delta_handoff import handoff
from portable_source_inventory import inventory as first

CLOSURE_SCHEMA = 'ces.ec335.bounded_signed_replay_observed_original_read_closure.v1'
MAP_SCHEMA = 'ces.ec335.explicit_nested_original_copy_map.v1'
RESULT_SCHEMA = 'ces.ec335.offline_nested_original_copy_preflight.v1'
DENIAL_SCHEMA = 'ces.ec335.offline_nested_original_copy_denial.v1'
INTERPRETATION = ('observed_guarded_original_reads_of_real_ec333_signed_replay_'
                  'plus_exact_ec334_first_hop_not_receiver_signed_path_rebinding')
MAX_SOURCES = 2048
MAX_SOURCE_BYTES = first.MAX_SOURCE_BYTES
MAX_TOTAL_BYTES = 512_000_000
MAX_EVENTS = 100_000
MAX_GRAPH_EDGES = 8192
MAX_JSON_GRAPH_BYTES = 1_000_000
MAX_CLOSURE_BYTES = 3_200_000
MAX_MAP_BYTES = 750_000
MAX_EMBEDDED = 4096
MAX_EMBEDDED_BYTES = 512_000_000
MAX_EMBEDDED_DEPTH = 6
MAX_ZIP_ENTRIES = 4096
KNOWN_REPLAY_TEMP_PREFIXES = (
    'ces-ec321-fork-receive-', 'ces-ec323-import-',
    'ces-ec326-roles-', 'ces-ec317-rebound-', 'ces-ec302-verify-',
)

EXTERNAL_ARGUMENT = 'caller_supplied_separate_root_sha_claim_not_custody_proof'
INHERITED_PIN = 'ec334_checked_inherited_source_digest_not_independent_custody'
MEASURED = 'locally_measured_after_signed_replay_no_independent_source_pin'
TIERS = frozenset({EXTERNAL_ARGUMENT, INHERITED_PIN, MEASURED})
FALSE_FIELDS = (
    'nested_digest_becomes_independently_entrusted_or_signed_by_creation',
    'old_path_sensitive_signatures_rebound_or_reverified_at_destination',
    'guarded_read_trace_proves_every_possible_file_or_dormant_history_exists',
    'inside_zip_originals_exported_as_separate_independent_files',
    'original_or_destination_sha_custody_independently_authenticated_by_cli',
    'remote_cas_worm_actual_nonexecution_org_authority_or_global_winner_proven',
    'any_business_store_network_or_external_cas_write_performed',
)
CLOSURE_FIELDS = frozenset({
    'schema', 'interpretation', 'first_hop_inventory_original_raw_sha256',
    'handoff_original_raw_sha256', 'left_manifest_original_raw_sha256',
    'right_manifest_original_raw_sha256', 'source_count',
    'first_hop_source_count', 'nested_source_count', 'read_event_count',
    'total_source_byte_length', 'sources', 'references',
    'unobserved_declared_path_reference_count', 'opaque_original_zip_count',
    'runtime_only_unlinked_source_count', 'offline_unresolved_exit_code',
    'embedded_original_member_count', 'embedded_total_byte_length',
    'embedded', 'excluded_replay_temporary_read_source_count',
    'excluded_replay_temporary_read_event_count',
    *FALSE_FIELDS,
})
SOURCE_FIELDS = frozenset({
    'source_path', 'source_original_raw_sha256', 'byte_length',
    'evidence_tier', 'first_hop_roles', 'original_format',
})
REF_FIELDS = frozenset({'parent_source_path', 'referenced_by_field',
                        'child_source_path', 'digest_binding'})
DIGEST_BINDINGS = frozenset({'exact_parent_declared_sha_matches',
                             'no_corresponding_parent_sha_declared'})
MAP_FIELDS = frozenset({'schema', 'closure_original_raw_sha256', 'locations'})
LOCATION_FIELDS = first.LOCATION_FIELDS
FORMATS = frozenset({'ces_json', 'original_zip', 'other_original_binary'})
EMBEDDED_FIELDS = frozenset({'owner_source_path', 'member_chain',
                             'embedded_raw_sha256', 'byte_length', 'original_format'})


def need(condition: Any, reason: str, status: str = 'permission_denied') -> None:
    if condition is not True:
        raise anchor.AnchorError('EC335_' + reason, status)


def _format(raw: bytes) -> str:
    if raw.startswith(b'{'):
        return 'ces_json'
    if raw.startswith(b'PK\x03\x04'):
        return 'original_zip'
    return 'other_original_binary'


def _capture(trace: dict[str, dict], events: list[int], path: str, raw: bytes) -> None:
    """Low-memory observer: digest the real guarded read and discard raw data."""
    need(first._path(path) and type(raw) is bytes and
         0 < len(raw) <= MAX_SOURCE_BYTES,
         'ONLY_BOUNDED_NORMALIZED_ORIGINAL_READS', 'invalid_input')
    events[0] += 1
    need(events[0] <= MAX_EVENTS, 'READ_EVENT_BUDGET_EXCEEDED', 'invalid_input')
    digest = case.sha(raw)
    old = trace.get(path)
    if old is None:
        need(len(trace) < MAX_SOURCES and
             events[1] + len(raw) <= MAX_TOTAL_BYTES,
             'DISTINCT_NESTED_ORIGINAL_READ_BUDGET_EXCEEDED', 'invalid_input')
        events[1] += len(raw)
        trace[path] = {'source_original_raw_sha256': digest,
                       'byte_length': len(raw), 'original_format': _format(raw),
                       'read_event_count': 1}
    else:
        need(old['source_original_raw_sha256'] == digest and
             old['byte_length'] == len(raw) and
             old['original_format'] == _format(raw),
             'SAME_ORIGINAL_PATH_CHANGED_DURING_SIGNED_REPLAY')
        old['read_event_count'] += 1


def _from_first(plan: dict, trace: dict[str, dict]) -> list[dict]:
    """Never drop a first-hop original or promote a locally measured SHA."""
    first_rows = {row['source_path']: row for row in plan['sources']}
    need(set(first_rows) <= set(trace),
         'FIRST_HOP_ORIGINAL_NOT_OBSERVED_BY_GUARDED_PRODUCTION_REPLAY')
    rows = []
    for path, data in sorted(trace.items()):
        original = first_rows.get(path)
        if original is not None:
            need(original['source_original_raw_sha256'] ==
                     data['source_original_raw_sha256'] and
                 original['byte_length'] == data['byte_length'],
                 'FIRST_HOP_PIN_DIFFERS_FROM_FULL_REPLAY_TRACE')
            tier = (EXTERNAL_ARGUMENT if any(role in original['roles'] for role in
                    ('handoff', 'left_manifest', 'right_manifest')) else
                    INHERITED_PIN if original['pin_basis'] ==
                    'existing_signed_history_input_or_ledger_sha' else MEASURED)
        else:
            tier = MEASURED
        rows.append({'source_path': path,
                     'source_original_raw_sha256': data['source_original_raw_sha256'],
                     'byte_length': data['byte_length'],
                     'evidence_tier': tier,
                     'first_hop_roles': (original['roles'] if original else []),
                     'original_format': data['original_format']})
    return rows



def _is_ephemeral_verified_import(path: str) -> bool:
    """Narrowly recognize deleted working files of known old ZIP verifiers.

    Their upstream whole ZIP bytes are guarded originals; these materialized
    scratch files must not be offered as nonexistent transport sources. A
    missing arbitrary source, even under /tmp, is NOT excused by this rule.
    """
    base = Path(tempfile.gettempdir())
    try:
        parts = Path(path).relative_to(base).parts
    except ValueError:
        return False
    return (len(parts) >= 2 and
            any(parts[0].startswith(prefix) and len(parts[0]) > len(prefix)
                for prefix in KNOWN_REPLAY_TEMP_PREFIXES) and
            not os.path.lexists(path))


def _persistent_trace(trace: dict[str, dict], source_root: str,
                      first_plan: dict) -> tuple[dict[str, dict], int]:
    """Do not invent relocation destinations for temporary imported ZIP rows."""
    need(first._valid_root(source_root), 'EXPLICIT_VALID_SOURCE_ROOT_REQUIRED',
         'invalid_input')
    root_paths = {row['source_path'] for row in first_plan['sources']}
    need(all(p.startswith(source_root + '/') for p in root_paths),
         'FIRST_HOP_OUTSIDE_EXPLICIT_SOURCE_ROOT', 'invalid_input')
    live = {}
    temp_count = 0
    for path, row in trace.items():
        if path in root_paths or (path.startswith(source_root + '/') and
                                  os.path.lexists(path)):
            # Retain only real private files. A missing first-hop input has
            # to fail on late repin, never silently be called ephemeral.
            live[path] = row
        elif _is_ephemeral_verified_import(path) and path not in root_paths:
            temp_count += 1
        else:
            need(False, 'UNACCOUNTED_OR_MISSING_HISTORICAL_ORIGINAL_READ_' +
                 'CANNOT_BE_DROPPED_FROM_CLOSURE', 'unavailable')
    need(len(live) <= MAX_SOURCES and len(live) >= first_plan['source_count'],
         'PERSISTENT_SOURCE_BUDGET_OR_FIRST_HOP_INVALID', 'invalid_input')
    return live, temp_count


def _embedded(rows: list[dict]) -> tuple[list[dict], int]:
    """Enumerate actual ZIP member bytes, with nested ZIPs as raw containers.

    All nested member SHA values are computed locally and subordinate to the
    original container's verified whole SHA. No member is falsely promoted to
    an independent original path or a new signature.
    """
    objects = []
    total = 0
    def walk(owner: str, chain: list[str], data: bytes, depth: int) -> None:
        nonlocal total
        need(depth <= MAX_EMBEDDED_DEPTH, 'NESTED_ARCHIVE_DEPTH_LIMIT',
             'invalid_input')
        try:
            with zipfile.ZipFile(BytesIO(data)) as z:
                infos = z.infolist()
                need(0 < len(infos) <= MAX_ZIP_ENTRIES and
                     len({i.filename for i in infos}) == len(infos) and
                     z.comment == b'', 'ARCHIVE_MEMBERSHIP_AND_COMMENT_INVALID',
                     'invalid_input')
                for item in infos:
                    name = item.filename
                    need(type(name) is str and 0 < len(name) <= 300 and
                         not name.startswith('/') and not name.endswith('/') and
                         '\\' not in name and '\x00' not in name and
                         all(part not in ('', '.', '..') for part in name.split('/')) and
                         not item.is_dir() and
                         item.compress_type == zipfile.ZIP_STORED and
                         item.file_size == item.compress_size and
                         0 < item.file_size <= MAX_SOURCE_BYTES and
                         stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG) and
                         item.flag_bits == 0,
                         'ONLY_BOUNDED_UNCOMPRESSED_REGULAR_CANONICAL_MEMBERS',
                         'invalid_input')
                    need(len(objects) < MAX_EMBEDDED and
                         total + item.file_size <= MAX_EMBEDDED_BYTES,
                         'EMBEDDED_OBJECT_COUNT_OR_BYTE_BUDGET_EXCEEDED',
                         'invalid_input')
                    raw = z.read(item)
                    need(len(raw) == item.file_size,
                         'EMBEDDED_ORIGINAL_BYTE_COUNT_MISMATCH')
                    total += len(raw)
                    member_chain = chain + [name]
                    kind = _format(raw)
                    objects.append({'owner_source_path': owner,
                                    'member_chain': member_chain,
                                    'embedded_raw_sha256': case.sha(raw),
                                    'byte_length': len(raw),
                                    'original_format': kind})
                    if kind == 'original_zip':
                        walk(owner, member_chain, raw, depth + 1)
        except (anchor.AnchorError, io.HostError):
            raise
        except (zipfile.BadZipFile, KeyError, ValueError, EOFError,
                OverflowError, RuntimeError) as exc:
            raise anchor.AnchorError('EC335_ORIGINAL_ARCHIVE_CANNOT_BE_TRAVERSED',
                                     'invalid_input') from exc
    for row in rows:
        if row['original_format'] != 'original_zip':
            continue
        raw = first._pin(row['source_path'], row['source_original_raw_sha256'],
                         row['byte_length'], 'EMBEDDED_ORIGINAL_CONTAINER')
        walk(row['source_path'], [], raw, 1)
    objects.sort(key=lambda x: (x['owner_source_path'], tuple(x['member_chain'])))
    return objects, total


def _references(rows: list[dict]) -> tuple[list[dict], int, int]:
    """Graph edges are *hints derived from typed fields*, never the authority.

    The source closure is the runtime guarded-read set. Traversing JSON is
    deliberately NOT allowed to add a file to that set, so untrusted path text
    cannot induce new filesystem reads or fabricate source authentication.
    Unobserved path declarations are counted rather than chased or asserted
    to be ancestors. ZIPs are opaque original byte boundaries.
    """
    by_path = {r['source_path']: r for r in rows}
    edges: set[tuple[str, str, str, str]] = set()
    missing: set[tuple[str, str, str]] = set()
    walks = [0]

    def visit(parent: str, value: Any, depth: int) -> None:
        need(depth <= 48, 'REFERENCE_DEPTH_BUDGET_EXCEEDED', 'invalid_input')
        walks[0] += 1
        need(walks[0] <= 100_000, 'REFERENCE_NODES_BUDGET_EXCEEDED', 'invalid_input')
        if type(value) is list:
            for child in value:
                visit(parent, child, depth + 1)
        elif type(value) is dict:
            for key, target in value.items():
                # Declared original-file relationships only; unrelated path
                # strings, branch names and identity claims are not reads.
                if (type(key) is str and
                    (key.endswith('_file') or key == 'original_absolute_path')
                    and first._path(target)):
                    if target in by_path:
                        expected = None
                        if key.endswith('_file'):
                            prefix = key[:-5]
                            for field in (f'expected_{prefix}_sha256',
                                          f'{prefix}_original_raw_sha256',
                                          f'expected_{prefix}_raw_sha256'):
                                if field in value:
                                    expected = value[field]
                                    break
                        digest_binding = 'no_corresponding_parent_sha_declared'
                        if expected is not None:
                            need(receipt._sha(expected) and
                                 hmac.compare_digest(expected,
                                     by_path[target]['source_original_raw_sha256']),
                                 'DECLARED_PARENT_CHILD_RAW_SHA_CONFLICT')
                            digest_binding = 'exact_parent_declared_sha_matches'
                        edges.add((parent, key, target, digest_binding))
                    else:
                        missing.add((parent, key, case.sha(target.encode('utf-8'))))
                    need(len(edges) + len(missing) <= MAX_GRAPH_EDGES,
                         'GRAPH_REFERENCE_BUDGET_EXCEEDED', 'invalid_input')
                visit(parent, target, depth + 1)

    for row in rows:
        if row['original_format'] != 'ces_json':
            continue
        # A large original is retained in byte-exact transfer, but not
        # heuristically parsed as a graph; its production verifier already ran.
        if row['byte_length'] > MAX_JSON_GRAPH_BYTES:
            continue
        raw = first._pin(row['source_path'], row['source_original_raw_sha256'],
                         row['byte_length'], 'REFERENCE_PARENT_RECHECK')
        try:
            doc = io.parse(raw, MAX_JSON_GRAPH_BYTES)
        except io.HostError:
            continue  # Graph is advisory, source SHA is still checked.
        if type(doc.get('schema')) is not str or not doc['schema'].startswith('ces.'):
            continue
        visit(row['source_path'], doc, 0)
    graph = [{'parent_source_path': parent, 'referenced_by_field': field,
              'child_source_path': child, 'digest_binding': basis}
             for parent, field, child, basis in sorted(edges)]
    linked = {edge['child_source_path'] for edge in graph}
    return graph, len(missing), sum(row['source_path'] not in linked and
                                   not row['first_hop_roles'] for row in rows)


def _check_closure(doc: Any, plan: dict, expected_plan_sha: str) -> list[dict]:
    need(type(doc) is dict and set(doc) == CLOSURE_FIELDS and
         doc.get('schema') == CLOSURE_SCHEMA and
         doc.get('interpretation') == INTERPRETATION and
         doc.get('first_hop_inventory_original_raw_sha256') == expected_plan_sha and
         doc.get('handoff_original_raw_sha256') ==
             plan['handoff_original_raw_sha256'] and
         doc.get('left_manifest_original_raw_sha256') ==
             plan['left_manifest_original_raw_sha256'] and
         doc.get('right_manifest_original_raw_sha256') ==
             plan['right_manifest_original_raw_sha256'] and
         doc.get('offline_unresolved_exit_code') == 2 and
         type(doc.get('offline_unresolved_exit_code')) is int and
         all(doc.get(f) is False for f in FALSE_FIELDS) and
         type(doc.get('sources')) is list and
         type(doc.get('references')) is list and
         type(doc.get('source_count')) is int and
         plan['source_count'] <= doc['source_count'] <= MAX_SOURCES and
         len(doc['sources']) == doc['source_count'] and
         type(doc.get('first_hop_source_count')) is int and
         doc['first_hop_source_count'] == plan['source_count'] and
         type(doc.get('nested_source_count')) is int and
         doc['nested_source_count'] == doc['source_count'] - plan['source_count'] and
         type(doc.get('read_event_count')) is int and
         doc['source_count'] <= doc['read_event_count'] <= MAX_EVENTS and
         type(doc.get('total_source_byte_length')) is int and
         0 < doc['total_source_byte_length'] <= MAX_TOTAL_BYTES and
         type(doc.get('opaque_original_zip_count')) is int and
         0 <= doc['opaque_original_zip_count'] <= doc['source_count'] and
         type(doc.get('unobserved_declared_path_reference_count')) is int and
         0 <= doc['unobserved_declared_path_reference_count'] <= MAX_GRAPH_EDGES and
         type(doc.get('runtime_only_unlinked_source_count')) is int and
         0 <= doc['runtime_only_unlinked_source_count'] <= doc['nested_source_count'] and
         type(doc.get('embedded')) is list and
         type(doc.get('embedded_original_member_count')) is int and
         0 <= doc['embedded_original_member_count'] <= MAX_EMBEDDED and
         len(doc['embedded']) == doc['embedded_original_member_count'] and
         type(doc.get('embedded_total_byte_length')) is int and
         0 <= doc['embedded_total_byte_length'] <= MAX_EMBEDDED_BYTES and
         type(doc.get('excluded_replay_temporary_read_source_count')) is int and
         0 <= doc['excluded_replay_temporary_read_source_count'] <= MAX_SOURCES and
         type(doc.get('excluded_replay_temporary_read_event_count')) is int and
         doc['excluded_replay_temporary_read_event_count'] >=
             doc['excluded_replay_temporary_read_source_count'] and
         doc['excluded_replay_temporary_read_event_count'] < MAX_EVENTS,
         'EXACT_BOUNDED_NESTED_CLOSURE_SCHEMA_AND_DENIAL_FLAGS_REQUIRED',
         'invalid_input')
    roots = {row['source_path']: row for row in plan['sources']}
    previous = None
    total = zip_count = first_count = 0
    source_set = set()
    for row in doc['sources']:
        need(type(row) is dict and set(row) == SOURCE_FIELDS and
             first._path(row.get('source_path')) and
             (previous is None or previous < row['source_path']) and
             receipt._sha(row.get('source_original_raw_sha256')) and
             type(row.get('byte_length')) is int and
             1 <= row['byte_length'] <= MAX_SOURCE_BYTES and
             row.get('evidence_tier') in TIERS and
             row.get('original_format') in FORMATS and
             type(row.get('first_hop_roles')) is list,
             'NESTED_SOURCE_SORT_PATH_SHA_LENGTH_OR_TIER_INVALID',
             'invalid_input')
        original = roots.get(row['source_path'])
        if original:
            first_count += 1
            want_tier = (EXTERNAL_ARGUMENT if any(role in original['roles'] for role in
                         ('handoff', 'left_manifest', 'right_manifest')) else
                         INHERITED_PIN if original['pin_basis'] ==
                         'existing_signed_history_input_or_ledger_sha' else MEASURED)
            need(row['source_original_raw_sha256'] == original['source_original_raw_sha256']
                 and row['byte_length'] == original['byte_length'] and
                 row['first_hop_roles'] == original['roles'] and
                 row['evidence_tier'] == want_tier,
                 'FIRST_HOP_SOURCE_TIER_BYTES_OR_ROLES_NOT_PRESERVED',
                 'invalid_input')
        else:
            need(row['first_hop_roles'] == [] and row['evidence_tier'] == MEASURED,
                 'NESTED_BYTES_CANNOT_CLAIM_FIRST_HOP_OR_EXTERNAL_AUTHORITY',
                 'invalid_input')
        total += row['byte_length']
        zip_count += row['original_format'] == 'original_zip'
        previous = row['source_path']
        source_set.add(previous)
    need(total == doc['total_source_byte_length'] and
         zip_count == doc['opaque_original_zip_count'] and
         first_count == len(roots),
         'NESTED_CLOSURE_TOTALS_FIRST_HOP_OR_ZIP_COUNTS_INVALID', 'invalid_input')
    prior = None
    linked = set()
    need(len(doc['references']) <= MAX_GRAPH_EDGES,
         'GRAPH_REFERENCE_BUDGET_EXCEEDED', 'invalid_input')
    for edge in doc['references']:
        need(type(edge) is dict and set(edge) == REF_FIELDS and
             edge.get('parent_source_path') in source_set and
             edge.get('child_source_path') in source_set and
             type(edge.get('referenced_by_field')) is str and
             (edge['referenced_by_field'].endswith('_file') or
              edge['referenced_by_field'] == 'original_absolute_path') and
             edge.get('digest_binding') in DIGEST_BINDINGS,
             'GRAPH_ONLY_BOUNDED_DECLARED_EXISTING_SOURCE_EDGES', 'invalid_input')
        tup = (edge['parent_source_path'], edge['referenced_by_field'],
               edge['child_source_path'], edge['digest_binding'])
        need(prior is None or tup > prior,
             'GRAPH_REFERENCES_EXACT_SORT_AND_UNIQUE_REQUIRED', 'invalid_input')
        prior = tup
        linked.add(edge['child_source_path'])
    need(sum(row['source_path'] not in linked and not row['first_hop_roles']
             for row in doc['sources']) == doc['runtime_only_unlinked_source_count'],
         'GRAPH_RUNTIME_ONLY_SOURCE_TOTAL_INVALID', 'invalid_input')
    prior_embed = None
    embed_total = 0
    for row in doc['embedded']:
        need(type(row) is dict and set(row) == EMBEDDED_FIELDS and
             row.get('owner_source_path') in source_set and
             type(row.get('member_chain')) is list and
             1 <= len(row['member_chain']) <= MAX_EMBEDDED_DEPTH and
             all(type(name) is str and 0 < len(name) <= 300 and
                 not name.startswith('/') and not name.endswith('/') and
                 '\\' not in name and '\x00' not in name and
                 all(p not in ('', '.', '..') for p in name.split('/'))
                 for name in row['member_chain']) and
             receipt._sha(row.get('embedded_raw_sha256')) and
             row.get('original_format') in FORMATS and
             type(row.get('byte_length')) is int and
             1 <= row['byte_length'] <= MAX_SOURCE_BYTES,
             'EMBEDDED_MEMBER_EXACT_FIELDS_AND_BOUNDS_INVALID', 'invalid_input')
        key = (row['owner_source_path'], tuple(row['member_chain']))
        need(prior_embed is None or prior_embed < key,
             'EMBEDDED_ORDER_AND_UNIQUE_LOCATION_REQUIRED', 'invalid_input')
        prior_embed = key
        embed_total += row['byte_length']
    need(embed_total == doc['embedded_total_byte_length'] and
         doc['read_event_count'] >= doc['source_count'] +
              doc['excluded_replay_temporary_read_source_count'],
         'EMBEDDED_ORIGINAL_TOTAL_OR_READ_EVENT_INCONSISTENT', 'invalid_input')
    return doc['sources']


def _late_repin(rows: list[dict], *, first_plan_file: str,
                expected_first_plan_sha: str) -> None:
    for row in rows:
        first._pin(row['source_path'], row['source_original_raw_sha256'],
                   row['byte_length'], 'LATE_NESTED_ORIGINAL')
    first._pin(first_plan_file, expected_first_plan_sha, None,
               'LATE_FIRST_HOP_PLAN')


def _result(command: str, doc: dict, closure_sha: str, *,
            mapping_sha: str | None = None, verified: bool = False) -> dict:
    return {
        'schema': RESULT_SCHEMA, 'command': command, 'exit_code': 2,
        'status': ('all_observed_nested_original_copy_bytes_match_unresolved'
                   if verified else 'unsigned_nested_original_closure_or_map_candidate_unresolved'),
        'closure_original_raw_sha256': closure_sha,
        'first_hop_inventory_original_raw_sha256':
            doc['first_hop_inventory_original_raw_sha256'],
        'mapping_original_raw_sha256': mapping_sha,
        'source_count': doc['source_count'],
        'first_hop_source_count': doc['first_hop_source_count'],
        'nested_source_count': doc['nested_source_count'],
        'read_event_count': doc['read_event_count'],
        'embedded_original_member_count': doc['embedded_original_member_count'],
        'excluded_replay_temporary_read_source_count':
            doc['excluded_replay_temporary_read_source_count'],
        'unobserved_declared_path_reference_count':
            doc['unobserved_declared_path_reference_count'],
        'opaque_original_zip_count': doc['opaque_original_zip_count'],
        'destination_all_observed_copy_bytes_verified': verified,
        'full_signed_source_replay_required_on_origin': True,
        'destination_replay_not_performed': True,
        'all_closure_shas_require_independent_custody': True,
        **{k: False for k in FALSE_FIELDS},
    }


def create_closure(*, out: str, first_hop_plan_file: str,
                   expected_first_hop_plan_sha256: str,
                   handoff_file: str, expected_handoff_sha256: str,
                   left_manifest_file: str, left_expected_manifest_sha256: str,
                   right_manifest_file: str, right_expected_manifest_sha256: str,
                   source_root: str) -> dict:
    """One real replay, bounded guarded-read trace, exact first-hop coverage."""
    inputs = handoff._inputs(left_manifest_file=left_manifest_file,
                              left_expected_manifest_sha256=left_expected_manifest_sha256,
                              right_manifest_file=right_manifest_file,
                              right_expected_manifest_sha256=right_expected_manifest_sha256)
    plan, _ = first._load_plan(first_hop_plan_file, expected_first_hop_plan_sha256)
    need(plan['handoff_original_raw_sha256'] == expected_handoff_sha256 and
         plan['left_manifest_original_raw_sha256'] == left_expected_manifest_sha256 and
         plan['right_manifest_original_raw_sha256'] == right_expected_manifest_sha256,
         'FIRST_HOP_ROOT_PINS_MUST_MATCH_SEPARATE_CALLER_INPUTS', 'invalid_input')
    trace: dict[str, dict] = {}
    events = [0, 0]
    with io._scoped_original_source_reads(
            observer=lambda path, raw: _capture(trace, events, path, raw)):
        verified = handoff.verify_handoff(
            handoff_file=handoff_file, expected_handoff_sha256=expected_handoff_sha256,
            **inputs)
    need(type(verified) is dict and verified.get('exit_code') == 2 and
         verified.get('handoff_original_exactly_reconstructed_from_both_original_signed_histories')
             is True and
         verified.get('both_ec331_manifests_and_all_inherited_old_signed_histories_replayed')
             is True and
         verified.get('handoff_and_both_manifest_all_inherited_original_pins_late_rechecked')
             is True and
         all(verified.get(k) is False for k in handoff.FALSE_FIELDS),
         'REAL_EC333_TO_EC294_SIGNED_REPLAY_REQUIRED')
    live_trace, transient = _persistent_trace(trace, source_root, plan)
    rows = _from_first(plan, live_trace)
    edges, missing, unlinked = _references(rows)
    embedded, embedded_total = _embedded(rows)
    doc = {
        'schema': CLOSURE_SCHEMA, 'interpretation': INTERPRETATION,
        'first_hop_inventory_original_raw_sha256': expected_first_hop_plan_sha256,
        'handoff_original_raw_sha256': expected_handoff_sha256,
        'left_manifest_original_raw_sha256': left_expected_manifest_sha256,
        'right_manifest_original_raw_sha256': right_expected_manifest_sha256,
        'source_count': len(rows), 'first_hop_source_count': plan['source_count'],
        'nested_source_count': len(rows) - plan['source_count'],
        'read_event_count': events[0],
        'total_source_byte_length': sum(r['byte_length'] for r in rows),
        'sources': rows, 'references': edges,
        'unobserved_declared_path_reference_count': missing,
        'opaque_original_zip_count': sum(r['original_format'] == 'original_zip'
                                         for r in rows),
        'runtime_only_unlinked_source_count': unlinked,
        'embedded_original_member_count': len(embedded),
        'embedded_total_byte_length': embedded_total,
        'embedded': embedded,
        'excluded_replay_temporary_read_source_count': transient,
        'excluded_replay_temporary_read_event_count':
            sum(v['read_event_count'] for p, v in trace.items()
                if p not in live_trace),
        'offline_unresolved_exit_code': 2,
        **{field: False for field in FALSE_FIELDS},
    }
    _check_closure(doc, plan, expected_first_hop_plan_sha256)
    raw = receipt._raw(doc)
    need(len(raw) <= MAX_CLOSURE_BYTES, 'NESTED_CLOSURE_DOCUMENT_BUDGET_EXCEEDED',
         'invalid_input')
    late = lambda: _late_repin(rows, first_plan_file=first_hop_plan_file,
                                expected_first_plan_sha=expected_first_hop_plan_sha256)
    late()
    first._exclusive(out, raw, {first_hop_plan_file, *live_trace}, late)
    return _result('create-closure', doc, case.sha(raw))


def _load_closure(path: str, expected: str, plan: dict,
                  expected_plan: str, plan_path: str) -> tuple[dict, bytes]:
    need(path != plan_path, 'CLOSURE_AND_FIRST_HOP_PLAN_MUST_BE_DISTINCT',
         'invalid_input')
    doc, raw = receipt._load(path, expected, MAX_CLOSURE_BYTES,
                             'EC335_SEPARATELY_PINNED_NESTED_CLOSURE')
    _check_closure(doc, plan, expected_plan)
    need(path not in {r['source_path'] for r in doc['sources']},
         'CLOSURE_FILE_CANNOT_ALIAS_ANY_ORIGINAL', 'invalid_input')
    return doc, raw


def prepare_map(*, out: str, first_hop_plan_file: str,
                expected_first_hop_plan_sha256: str,
                closure_file: str, expected_closure_sha256: str,
                source_root: str, destination_root: str) -> dict:
    need(first._valid_root(source_root) and first._valid_root(destination_root)
         and source_root != destination_root,
         'TWO_DISTINCT_NORMALIZED_ABSOLUTE_ROOTS_REQUIRED', 'invalid_input')
    plan, _ = first._load_plan(first_hop_plan_file, expected_first_hop_plan_sha256)
    doc, _ = _load_closure(closure_file, expected_closure_sha256, plan,
                           expected_first_hop_plan_sha256, first_hop_plan_file)
    rows = []
    source_paths = {source['source_path'] for source in doc['sources']}
    for source in doc['sources']:
        old = source['source_path']
        need(old.startswith(source_root + '/'),
             'ALL_NESTED_SOURCES_MUST_LIE_UNDER_EXPLICIT_SOURCE_ROOT',
             'invalid_input')
        dest = destination_root + old[len(source_root):]
        need(first._path(dest) and dest not in source_paths and dest not in (
            first_hop_plan_file, closure_file, out),
            'MAPPED_DESTINATION_INVALID_OR_ALIASES_CONTROL_FILE',
            'invalid_input')
        rows.append({'source_path': old, 'destination_path': dest})
    raw = receipt._raw({'schema': MAP_SCHEMA,
                        'closure_original_raw_sha256': expected_closure_sha256,
                        'locations': rows})
    need(len(raw) <= MAX_MAP_BYTES, 'NESTED_MAP_BUDGET_EXCEEDED', 'invalid_input')
    forbidden = {first_hop_plan_file, closure_file, *[r['source_path'] for r in rows],
                 *[r['destination_path'] for r in rows]}
    first._exclusive(out, raw, forbidden,
        lambda: (first._pin(first_hop_plan_file,
                            expected_first_hop_plan_sha256, None, 'MAP_FINAL_FIRST_HOP'),
                 first._pin(closure_file, expected_closure_sha256,
                            None, 'MAP_FINAL_CLOSURE')))
    return _result('prepare-map', doc, expected_closure_sha256,
                   mapping_sha=case.sha(raw))


def _load_map(path: str, expected: str, doc: dict,
              expected_closure: str, controls: set[str]) -> tuple[dict, bytes]:
    need(path not in controls, 'ALL_CONTROL_DOCUMENTS_MUST_BE_DISTINCT',
         'invalid_input')
    mapping, raw = receipt._load(path, expected, MAX_MAP_BYTES,
                                 'EC335_SEPARATELY_PINNED_NESTED_MAP')
    need(type(mapping) is dict and set(mapping) == MAP_FIELDS and
         mapping.get('schema') == MAP_SCHEMA and
         mapping.get('closure_original_raw_sha256') == expected_closure and
         type(mapping.get('locations')) is list and
         len(mapping['locations']) == doc['source_count'],
         'MAP_EXACT_SCHEMA_WHOLE_SHA_BINDING_AND_COVERAGE_REQUIRED',
         'invalid_input')
    olds = {row['source_path'] for row in doc['sources']}
    destinations: set[str] = set()
    changed = False
    for row, loc in zip(doc['sources'], mapping['locations']):
        need(type(loc) is dict and set(loc) == LOCATION_FIELDS and
             loc.get('source_path') == row['source_path'] and
             first._path(loc.get('destination_path')) and
             loc['destination_path'] not in destinations and
             loc['destination_path'] not in controls | {path} and
             loc['destination_path'] not in olds,
             'NESTED_MAP_ORDER_ONE_TO_ONE_NONALIAS_REQUIRED',
             'invalid_input')
        changed |= loc['destination_path'] != loc['source_path']
        destinations.add(loc['destination_path'])
    need(changed, 'RELOCATION_MUST_CHANGE_PATHS', 'invalid_input')
    return mapping, raw


def verify_copies(*, first_hop_plan_file: str,
                  expected_first_hop_plan_sha256: str,
                  closure_file: str, expected_closure_sha256: str,
                  map_file: str, expected_map_sha256: str) -> dict:
    """Receiver: no old paths available, no old signatures reverified."""
    plan, original_plan = first._load_plan(first_hop_plan_file,
                                            expected_first_hop_plan_sha256)
    doc, original_closure = _load_closure(closure_file, expected_closure_sha256,
                                          plan, expected_first_hop_plan_sha256,
                                          first_hop_plan_file)
    # The receiver also independently re-opens every nested ZIP member under
    # the copied whole-container SHA (not the old signed pathname).
    locs, original_map = _load_map(map_file, expected_map_sha256, doc,
                                   expected_closure_sha256,
                                   {first_hop_plan_file, closure_file})
    for tag in ('DESTINATION_NESTED', 'LATE_DESTINATION_NESTED'):
        for row, loc in zip(doc['sources'], locs['locations']):
            first._pin(loc['destination_path'], row['source_original_raw_sha256'],
                       row['byte_length'], tag)
    translated = [{**row, 'source_path': loc['destination_path']}
                  for row, loc in zip(doc['sources'], locs['locations'])]
    parsed, total = _embedded(translated)
    reverse = {loc['destination_path']: loc['source_path']
               for loc in locs['locations']}
    for item in parsed:
        item['owner_source_path'] = reverse[item['owner_source_path']]
    parsed.sort(key=lambda x: (x['owner_source_path'], tuple(x['member_chain'])))
    need(parsed == doc['embedded'] and total == doc['embedded_total_byte_length'],
         'RELOCATED_EMBEDDED_ORIGINALS_NOT_IDENTICAL_TO_PINNED_CLOSURE')
    for path, digest, limit, raw in (
        (first_hop_plan_file, expected_first_hop_plan_sha256,
         first.MAX_PLAN_BYTES, original_plan),
        (closure_file, expected_closure_sha256, MAX_CLOSURE_BYTES, original_closure),
        (map_file, expected_map_sha256, MAX_MAP_BYTES, original_map),
    ):
        need(hmac.compare_digest(receipt._load(path, digest, limit,
                'EC335_FINAL_CONTROL_WHOLE_SHA_REPIN')[1], raw),
             'CONTROL_DOCUMENT_CHANGED_DURING_NESTED_COPY_AUDIT')
    return _result('verify-copies', doc, expected_closure_sha256,
                   mapping_sha=expected_map_sha256, verified=True)
