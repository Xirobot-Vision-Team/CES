#!/usr/bin/env python3
"""EC334: transfer first-hop EC333 original bytes without changing old signatures.

Source-side export requires the REAL EC333->EC294 original signed replay, then
pins the raw bytes of every direct EC331/EC330/EC328 source named by the two
manifests (including ninth receipt originals). Receiver-side audit never
converts an old signed absolute path to a new signed path: it only proves that
private local copies match a separately entrusted unsigned inventory's SHA.

An inventory is NOT the full nested old EC317/318 source closure. It is not
signed and neither its source root nor its out-of-band SHA's real-world custody
is proven by the CLI. No remote activity, in-place rebind or signing occurs.
"""
from __future__ import annotations

import hmac
import os
import stat
from typing import Any

from delivery_anchor import anchor
from offline_transfer_registry import registry as reg
from fork_case_transport import case
from dual_channel_receipt import receipt
from offline_ledger_comparison import comparison
from replayable_comparison_report import report
from offline_report_set_crosscheck import crosscheck
from replayable_delta_handoff import handoff

PLAN_SCHEMA = 'ces.ec334.first_hop_private_unsigned_relocation_inventory.v1'
MAP_SCHEMA = 'ces.ec334.explicit_private_source_to_destination_map.v1'
RESULT_SCHEMA = 'ces.ec334.offline_copy_integrity_preflight.v1'
DENIAL_SCHEMA = 'ces.ec334.offline_copy_integrity_preflight_denial.v1'
INTERPRETATION = ('private_unsigned_first_hop_copy_inventory_not_a_signed_'
                  'historical_source_rebinding_or_complete_old_source_closure')
MAX_SOURCES = 1024
MAX_SOURCE_BYTES = 110_000_000
MAX_TOTAL_SOURCE_BYTES = 192_000_000
MAX_PLAN_BYTES = 950_000
MAX_MAP_BYTES = 550_000
PIN_BASIS = frozenset({'existing_signed_history_input_or_ledger_sha',
                       'measured_after_full_source_replay_only'})
ROLES = frozenset({
    'handoff', 'left_manifest', 'right_manifest', 'ec330_report',
    'branch_a_ledger', 'branch_b_ledger', 'branch_a_prior_ledger',
    'branch_b_prior_ledger', 'request', 'case', 'prior_registry',
    'left_registry', 'right_registry', 'left_capsule', 'right_capsule',
    'left_origin', 'right_origin', 'left_recipient', 'right_recipient',
    'ninth_receipt',
})
FALSE_FIELDS = (
    'path_mapping_rewrites_original_signed_or_hashed_bytes',
    'destination_replay_of_full_ec294_to_ec333_original_signatures_performed',
    'first_hop_inventory_proves_all_nested_historical_originals_present',
    'unsigned_inventory_or_mapping_is_signed_or_institutionally_authorized',
    'provided_sha_proves_independent_out_of_band_custody',
    'copy_check_proves_external_cas_worm_actual_nonexecution_or_global_winner',
    'actual_external_business_store_write_performed',
    'all_source_paths_equivalent_for_signature_context_after_relocation',
)
PLAN_FIELDS = frozenset({
    'schema', 'interpretation', 'handoff_original_raw_sha256',
    'left_manifest_original_raw_sha256', 'right_manifest_original_raw_sha256',
    'source_count', 'total_source_byte_length', 'sources',
    'offline_unresolved_exit_code', *FALSE_FIELDS,
})
SOURCE_FIELDS = frozenset({'source_path', 'source_original_raw_sha256',
                           'byte_length', 'pin_basis', 'roles'})
MAP_FIELDS = frozenset({'schema', 'inventory_original_raw_sha256', 'locations'})
LOCATION_FIELDS = frozenset({'source_path', 'destination_path'})


def need(condition: Any, code: str, status: str = 'permission_denied') -> None:
    if condition is not True:
        raise anchor.AnchorError('EC334_' + code, status)


def _path(value: Any) -> bool:
    return case.original._valid_path(value)


def _private_file(path: str, limit: int, tag: str) -> bytes:
    need(_path(path), tag + '_NORMALIZED_ABSOLUTE_PATH_REQUIRED', 'invalid_input')
    return reg._private_read(path, limit, 'EC334_' + tag)


def _pin(path: str, expected_sha: str, length: int | None, tag: str) -> bytes:
    need(receipt._sha(expected_sha), tag + '_WHOLE_RAW_SHA_REQUIRED', 'invalid_input')
    data = _private_file(path, MAX_SOURCE_BYTES, tag)
    need(hmac.compare_digest(case.sha(data), expected_sha) and
         (length is None or len(data) == length),
         tag + '_ORIGINAL_COPY_BYTES_OR_LENGTH_MISMATCH')
    return data


def _add(items: dict[str, dict], path: str, expected_sha: str | None,
         role: str) -> None:
    need(role in ROLES and _path(path), 'ONLY_DECLARED_SOURCE_ROLES_AND_PATHS',
         'invalid_input')
    data = _private_file(path, MAX_SOURCE_BYTES, 'ORIGINAL_' + role.upper())
    sha = case.sha(data)
    if expected_sha is not None:
        need(receipt._sha(expected_sha) and hmac.compare_digest(sha, expected_sha),
             'HISTORICAL_INPUT_RAW_SHA_MISMATCH_' + role.upper())
    prior = items.get(path)
    basis = ('existing_signed_history_input_or_ledger_sha' if expected_sha
             else 'measured_after_full_source_replay_only')
    if prior is None:
        need(len(items) < MAX_SOURCES, 'SOURCE_INVENTORY_CAP_EXCEEDED', 'invalid_input')
        items[path] = {
            'source_path': path, 'source_original_raw_sha256': sha,
            'byte_length': len(data), 'pin_basis': basis, 'roles': [role],
        }
    else:
        need(prior['source_original_raw_sha256'] == sha and
             prior['byte_length'] == len(data),
             'SAME_ORIGINAL_PATH_CANNOT_CLAIM_DIFFERENT_BYTES')
        if expected_sha is not None:
            prior['pin_basis'] = basis
        if role not in prior['roles']:
            prior['roles'].append(role)
    need(sum(row['byte_length'] for row in items.values()) <= MAX_TOTAL_SOURCE_BYTES,
         'TOTAL_DISTINCT_SOURCE_BYTES_EXCEED_BOUND', 'invalid_input')


def _collect(inputs: dict, handoff_file: str, handoff_sha: str) -> list[dict]:
    """Enumerate first-hop references only, after an EC333 full signed replay.

    Some capsule files lack a direct expected SHA in the old EC331 manifest;
    their original bytes were used in real replay but the digest measured
    here is NOT an independent original-signature pin. Expose that difference.
    """
    items: dict[str, dict] = {}
    _add(items, handoff_file, handoff_sha, 'handoff')
    for side in ('left', 'right'):
        mf = inputs[f'{side}_manifest_file']
        sha = inputs[f'{side}_expected_manifest_sha256']
        manifest, _ = crosscheck._manifest(mf, sha)
        _add(items, mf, sha, f'{side}_manifest')
        for entry in manifest['reports']:
            _add(items, entry['report_file'], entry['expected_report_sha256'],
                 'ec330_report')
            kw = entry['comparison_inputs']
            for branch in ('a', 'b'):
                lk = f'branch_{branch}_ledger_file'
                hk = f'expected_branch_{branch}_ledger_sha256'
                _add(items, kw[lk], kw[hk], f'branch_{branch}_ledger')
                prior_path = kw.get(f'branch_{branch}_prior_ledger_file')
                if prior_path is not None:
                    _add(items, prior_path,
                         kw[f'expected_branch_{branch}_prior_ledger_sha256'],
                         f'branch_{branch}_prior_ledger')
                # The EC328 snapshot's signed receipt SHA, not a source-map
                # field or the recipient's guess, anchors every ninth original.
                ledgers = [(kw[lk], kw[hk])]
                if prior_path is not None:
                    ledgers.append((prior_path,
                                    kw[f'expected_branch_{branch}_prior_ledger_sha256']))
                for ledger_path, ledger_sha in ledgers:
                    doc = comparison._load_snapshot(
                        ledger_path, ledger_sha, 'EC334_ENUMERATE_NINTH_RECEIPT')
                    for row in doc['entries']:
                        _add(items, row['receipt_file'],
                             row['receipt_original_raw_sha256'], 'ninth_receipt')
            _add(items, kw['request_file'], kw['expected_request_sha256'], 'request')
            _add(items, kw['case_file'], kw['expected_case_sha256'], 'case')
            if kw.get('prior_registry_file') is not None:
                _add(items, kw['prior_registry_file'],
                     kw['expected_prior_registry_sha256'], 'prior_registry')
            for branch in ('left', 'right'):
                b = kw[branch]
                for kind in ('registry', 'origin', 'recipient'):
                    _add(items, b[f'{kind}_file'], b[f'expected_{kind}_sha256'],
                         f'{branch}_{kind}')
                _add(items, b['capsule_file'], None, f'{branch}_capsule')
    result = []
    for path in sorted(items):
        row = items[path]
        row['roles'].sort()
        result.append(row)
    return result


def _validate_plan(doc: Any) -> list[dict]:
    need(type(doc) is dict and set(doc) == PLAN_FIELDS and
         doc.get('schema') == PLAN_SCHEMA and
         doc.get('interpretation') == INTERPRETATION and
         all(receipt._sha(doc.get(k)) for k in (
             'handoff_original_raw_sha256',
             'left_manifest_original_raw_sha256',
             'right_manifest_original_raw_sha256')) and
         doc.get('offline_unresolved_exit_code') == 2 and
         type(doc.get('offline_unresolved_exit_code')) is int and
         all(doc.get(field) is False for field in FALSE_FIELDS) and
         type(doc.get('sources')) is list and
         type(doc.get('source_count')) is int and
         3 <= doc['source_count'] <= MAX_SOURCES and
         len(doc['sources']) == doc['source_count'] and
         type(doc.get('total_source_byte_length')) is int and
         3 <= doc['total_source_byte_length'] <= MAX_TOTAL_SOURCE_BYTES,
         'EXACT_UNSIGNED_BOUNDED_INVENTORY_AND_NEGATIVE_FLAGS_REQUIRED',
         'invalid_input')
    prior = None
    total = 0
    role_members = {}
    for row in doc['sources']:
        need(type(row) is dict and set(row) == SOURCE_FIELDS and
             _path(row.get('source_path')) and
             receipt._sha(row.get('source_original_raw_sha256')) and
             type(row.get('byte_length')) is int and
             1 <= row['byte_length'] <= MAX_SOURCE_BYTES and
             row.get('pin_basis') in PIN_BASIS and
             type(row.get('roles')) is list and
             1 <= len(row['roles']) <= len(ROLES) and
             all(type(role) is str and role in ROLES for role in row['roles']) and
             row['roles'] == sorted(set(row['roles'])) and
             (prior is None or prior < row['source_path']),
             'INVENTORY_SOURCE_PATH_SHA_ROLE_SORT_OR_BYTES_INVALID',
             'invalid_input')
        for role in row['roles']:
            role_members.setdefault(role, []).append(row)
        total += row['byte_length']
        prior = row['source_path']
    need(total == doc['total_source_byte_length'] and
         len(role_members.get('handoff', [])) == 1 and
         len(role_members.get('left_manifest', [])) == 1 and
         len(role_members.get('right_manifest', [])) == 1 and
         role_members['handoff'][0]['source_original_raw_sha256'] ==
             doc['handoff_original_raw_sha256'] and
         role_members['left_manifest'][0]['source_original_raw_sha256'] ==
             doc['left_manifest_original_raw_sha256'] and
         role_members['right_manifest'][0]['source_original_raw_sha256'] ==
             doc['right_manifest_original_raw_sha256'],
         'INVENTORY_ROOT_OR_TOTAL_RAW_SHA_BINDING_INCONSISTENT', 'invalid_input')
    return doc['sources']


def _exclusive(out: str, raw: bytes, forbidden: set[str], late_check) -> None:
    need(_path(out) and out not in forbidden,
         'CANDIDATE_OUTPUT_NOT_A_DISTINCT_ABSOLUTE_SOURCE', 'invalid_input')
    need(not os.path.lexists(out), 'CANDIDATE_OUTPUT_ALREADY_EXISTS', 'invalid_input')
    receipt._write_exclusive(out, raw)
    created = os.lstat(out)
    try:
        got = _pin(out, case.sha(raw), len(raw), 'CREATED_CANDIDATE_READBACK')
        need(hmac.compare_digest(got, raw), 'CANDIDATE_CHANGED_DURING_READBACK')
        late_check()
        got = _pin(out, case.sha(raw), len(raw), 'FINAL_CREATED_CANDIDATE')
        need(hmac.compare_digest(got, raw), 'CANDIDATE_CHANGED_AFTER_RECHECK')
    except Exception:
        try:
            current = os.lstat(out)
            if (stat.S_ISREG(current.st_mode) and
                (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino)):
                os.unlink(out)
        except OSError:
            pass
        raise


def _result(command: str, *, plan_sha: str, plan: dict,
            copied: bool, mapping_sha: str | None = None) -> dict:
    return {
        'schema': RESULT_SCHEMA, 'command': command,
        'status': ('first_hop_relocated_private_copy_bytes_match_unsigned_pinned_inventory_unresolved'
                   if copied else 'private_unsigned_first_hop_inventory_or_map_candidate_unresolved'),
        'exit_code': 2,
        'inventory_original_raw_sha256': plan_sha,
        'mapping_original_raw_sha256': mapping_sha,
        'source_count': plan['source_count'],
        'total_source_byte_length': plan['total_source_byte_length'],
        'distinct_original_raw_sha_count': len({item['source_original_raw_sha256']
                                                for item in plan['sources']}),
        'destination_bytes_match_every_first_hop_original': copied,
        'source_side_full_signed_original_replay_required_for_plan_creation': True,
        'copy_check_is_first_hop_only_and_never_signature_rebinding': True,
        'original_and_destination_anchors_require_real_external_trust': True,
        **{field: False for field in FALSE_FIELDS},
    }


def create_plan(*, out: str, handoff_file: str, expected_handoff_sha256: str,
                left_manifest_file: str, left_expected_manifest_sha256: str,
                right_manifest_file: str, right_expected_manifest_sha256: str) -> dict:
    inputs = handoff._inputs(
        left_manifest_file=left_manifest_file,
        left_expected_manifest_sha256=left_expected_manifest_sha256,
        right_manifest_file=right_manifest_file,
        right_expected_manifest_sha256=right_expected_manifest_sha256)
    need(receipt._sha(expected_handoff_sha256),
         'HANDOFF_INDEPENDENT_WHOLE_SHA_REQUIRED', 'invalid_input')
    verified = handoff.verify_handoff(
        handoff_file=handoff_file, expected_handoff_sha256=expected_handoff_sha256,
        **inputs)
    need(verified.get('exit_code') == 2 and
         verified.get('handoff_original_exactly_reconstructed_from_both_original_signed_histories')
             is True and
         verified.get('both_ec331_manifests_and_all_inherited_old_signed_histories_replayed')
             is True and
         verified.get('handoff_and_both_manifest_all_inherited_original_pins_late_rechecked')
             is True and all(verified.get(k) is False for k in handoff.FALSE_FIELDS),
         'SOURCE_EXPORT_REQUIRES_TRUE_EC333_SIGNED_REPLAY')
    sources = _collect(inputs, handoff_file, expected_handoff_sha256)
    plan = {
        'schema': PLAN_SCHEMA, 'interpretation': INTERPRETATION,
        'handoff_original_raw_sha256': expected_handoff_sha256,
        'left_manifest_original_raw_sha256': left_expected_manifest_sha256,
        'right_manifest_original_raw_sha256': right_expected_manifest_sha256,
        'source_count': len(sources),
        'total_source_byte_length': sum(i['byte_length'] for i in sources),
        'sources': sources, 'offline_unresolved_exit_code': 2,
        **{field: False for field in FALSE_FIELDS},
    }
    _validate_plan(plan)
    raw = receipt._raw(plan)
    need(len(raw) <= MAX_PLAN_BYTES, 'SOURCE_INVENTORY_EXCEEDS_CANONICAL_LIMIT',
         'invalid_input')
    def late():
        for source in sources:
            _pin(source['source_path'], source['source_original_raw_sha256'],
                 source['byte_length'], 'LATE_SOURCE_ORIGINAL_RECHECK')
        handoff._late_repin(inputs)
        _pin(handoff_file, expected_handoff_sha256, None, 'LATE_HANDOFF_RECHECK')
    late()
    _exclusive(out, raw, {s['source_path'] for s in sources}, late)
    return _result('create-plan', plan_sha=case.sha(raw), plan=plan, copied=False)


def _load_plan(plan_file: str, expected_plan_sha256: str) -> tuple[dict, bytes]:
    plan, raw = receipt._load(plan_file, expected_plan_sha256,
                              MAX_PLAN_BYTES, 'EC334_SEPARATELY_PINNED_PRIVATE_PLAN')
    _validate_plan(plan)
    need(plan_file not in {row['source_path'] for row in plan['sources']},
         'UNSIGNED_INVENTORY_MUST_NOT_ALIAS_ANY_ORIGINAL', 'invalid_input')
    return plan, raw


def _valid_root(value: Any) -> bool:
    return _path(value) and value != '/' and not value.endswith('/')


def prepare_map(*, out: str, plan_file: str, expected_plan_sha256: str,
                source_root: str, destination_root: str) -> dict:
    """Draft one deterministic prefix translation; never create/copy sources."""
    need(_valid_root(source_root) and _valid_root(destination_root) and
         source_root != destination_root,
         'TWO_DIFFERENT_NORMALIZED_ABSOLUTE_DIRECTORY_ROOTS_REQUIRED',
         'invalid_input')
    plan, _ = _load_plan(plan_file, expected_plan_sha256)
    rows = []
    for source in plan['sources']:
        old = source['source_path']
        need(old.startswith(source_root + '/'),
             'EVERY_SOURCE_MUST_LIE_STRICTLY_UNDER_SOURCE_ROOT', 'invalid_input')
        new = destination_root + old[len(source_root):]
        need(_path(new) and new != plan_file and new != out,
             'RELOCATED_PATH_INVALID_OR_OVERLAPS_PLAN', 'invalid_input')
        rows.append({'source_path': old, 'destination_path': new})
    raw = receipt._raw({'schema': MAP_SCHEMA,
                        'inventory_original_raw_sha256': expected_plan_sha256,
                        'locations': rows})
    need(len(raw) <= MAX_MAP_BYTES, 'RELOCATION_MAP_EXCEEDS_LIMIT', 'invalid_input')
    need(out != plan_file, 'RELOCATION_MAP_MUST_NOT_OVERWRITE_PLAN', 'invalid_input')
    _exclusive(out, raw, {plan_file, *[r['source_path'] for r in rows],
                          *[r['destination_path'] for r in rows]},
               lambda: _pin(plan_file, expected_plan_sha256, None,
                            'LATE_TRANSFER_PLAN_RECHECK'))
    result = _result('prepare-map', plan_sha=expected_plan_sha256,
                     plan=plan, copied=False, mapping_sha=case.sha(raw))
    return result


def _load_map(path: str, expected_sha: str, plan: dict,
              expected_plan_sha: str, plan_file: str) -> tuple[dict, bytes]:
    need(path != plan_file, 'PLAN_AND_MAP_MUST_BE_DISTINCT', 'invalid_input')
    doc, raw = receipt._load(path, expected_sha, MAX_MAP_BYTES,
                             'EC334_SEPARATELY_PINNED_RELOCATION_MAP')
    need(type(doc) is dict and set(doc) == MAP_FIELDS and
         doc['schema'] == MAP_SCHEMA and
         doc['inventory_original_raw_sha256'] == expected_plan_sha and
         type(doc['locations']) is list and
         len(doc['locations']) == plan['source_count'],
         'MAP_SCHEMA_PLAN_BINDING_AND_FULL_COVERAGE_REQUIRED', 'invalid_input')
    dests = set()
    olds = {row['source_path'] for row in plan['sources']}
    changes = 0
    for want, row in zip(plan['sources'], doc['locations']):
        need(type(row) is dict and set(row) == LOCATION_FIELDS and
             row.get('source_path') == want['source_path'] and
             _path(row.get('destination_path')) and
             row['destination_path'] not in dests and
             row['destination_path'] not in (plan_file, path) and
             (row['destination_path'] not in olds or
              row['destination_path'] == row['source_path']),
             'MAP_SOURCE_SORT_DESTINATION_DISTINCT_AND_NO_ALIAS_REQUIRED',
             'invalid_input')
        dests.add(row['destination_path'])
        changes += row['source_path'] != row['destination_path']
    need(changes > 0, 'AT_LEAST_ONE_PATH_MUST_BE_RELOCATED', 'invalid_input')
    return doc, raw


def verify_copies(*, plan_file: str, expected_plan_sha256: str,
                  map_file: str, expected_map_sha256: str) -> dict:
    """No old paths, private keys, remote store, signer, or writer required.

    Trust in the unsigned inventory SHA must actually arrive independently.
    A local matching copy cannot attest its old signature's path-sensitive
    identity or the completeness of nested old archives.
    """
    plan, raw_plan = _load_plan(plan_file, expected_plan_sha256)
    locs, raw_map = _load_map(map_file, expected_map_sha256, plan,
                              expected_plan_sha256, plan_file)
    for spec, loc in zip(plan['sources'], locs['locations']):
        _pin(loc['destination_path'], spec['source_original_raw_sha256'],
             spec['byte_length'], 'DESTINATION_COPY')
    # Re-read *all* copies after finishing the full batch; still not a
    # transactional FS snapshot and cannot rule out an ABA between reads.
    for spec, loc in zip(plan['sources'], locs['locations']):
        _pin(loc['destination_path'], spec['source_original_raw_sha256'],
             spec['byte_length'], 'LATE_DESTINATION_COPY')
    need(hmac.compare_digest(
        receipt._load(plan_file, expected_plan_sha256, MAX_PLAN_BYTES,
                      'EC334_FINAL_INVENTORY_REPIN')[1], raw_plan) and
         hmac.compare_digest(
             receipt._load(map_file, expected_map_sha256, MAX_MAP_BYTES,
                           'EC334_FINAL_MAP_REPIN')[1], raw_map),
         'TRANSFER_PLAN_OR_MAPPING_CHANGED_DURING_COPY_CHECK')
    return _result('verify-copies', plan_sha=expected_plan_sha256,
                   plan=plan, copied=True, mapping_sha=expected_map_sha256)
