#!/usr/bin/env python3
"""EC336: receiver-side EC333->EC294 REAL original-signature replay under EC317.

This is a strictly read-only RECEIVER verifier.  Unlike EC335 byte-only copy
checking, it invokes the *unchanged* production EC333 handoff verifier with its
logical source paths exactly as originally signed.  The EC317 guarded-reader
binding redirects those old path strings only to a complete independently
SHA-pinned explicit map of owner-private byte-identical local destinations.

The producer must first perform EC334/335 source full signed replay to create
its control documents; these controls and three signed-history roots require
independent out-of-band whole-raw-SHA pins on the receiver.  The CLI does not
provide that trust.  The verifier validates the nested ZIP byte closure and
requires an exact match of all guarded persistent ORIGINAL paths actually read
in the receiver replay; unknown ORIGINALs fail closed.  Verified local imports
of *already checked* ZIP members receive narrow local ephemeral exceptions in
the old import routines, never guessed /tmp prefix exceptions.

No old absolute path, signed message, Ed25519 signature, role identity, manifest,
or ZIP source member is rewritten. The guard binds read *bytes*, not filesystem
path identity or legal custody; this does not prove the new destination path is
the independently trusted institutional/physical original, remote execution,
linearizable CAS/WORM, global latest, winner, or no-submission in the world.
"""
from __future__ import annotations

import hmac
import os
from typing import Any

from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor
from ec321_fork_case_transport import case
from ec324_dual_channel_receipt import receipt
from ec333_replayable_delta_handoff import handoff
from ec334_portable_source_inventory import inventory as first
from ec335_nested_source_closure import closure

RESULT_SCHEMA = 'ces.ec336.pinned_relocated_original_signed_history_replay.v1'
DENIAL_SCHEMA = 'ces.ec336.pinned_relocated_original_signed_history_denial.v1'
RESULT_STATUS = 'relocated_guarded_original_bytes_cryptographically_replayed_local_only_unresolved'
MAX_OBSERVED_READS = closure.MAX_EVENTS
FALSE_FIELDS = (
    'historical_signed_message_path_or_raw_original_bytes_rewritten',
    'destination_physical_path_equals_original_signed_path_or_trusted_identity',
    'mapping_or_closure_self_asserted_sha_proves_independent_custody',
    'all_unvisited_or_dormant_historical_branches_cryptographically_proven',
    'receiver_replay_is_an_atomic_immutable_filesystem_snapshot',
    'institutional_authorization_or_signer_key_custody_independently_proven',
    'remote_cas_worm_real_nonexecution_latest_winner_or_submission_proven',
    'business_host_store_network_or_signing_write_performed',
)


def need(value: Any, reason: str, status: str = 'permission_denied') -> None:
    if value is not True:
        raise anchor.AnchorError('EC336_' + reason, status)


def _root_source(plan: dict, role: str) -> dict:
    candidates = [row for row in plan['sources'] if role in row['roles']]
    need(len(candidates) == 1, 'REQUIRE_UNIQUE_' + role.upper() + '_SOURCE')
    return candidates[0]


def _observer(expected: dict[str, dict], seen: dict[str, int], counters: dict,
              path: str, raw: bytes) -> None:
    counters['total'] += 1
    need(counters['total'] <= MAX_OBSERVED_READS,
         'RECEIVER_SIGNED_REPLAY_READ_EVENT_BUDGET_EXCEEDED', 'invalid_input')
    if io._is_scoped_verified_local_import_read(path):
        # Old EC321/323/326 produced these private files from SHA-pinned ZIP
        # bytes during this very replay. They are NOT transported persistent
        # original paths; no third-party original SHA is inferred from them.
        counters['private_imports'] += 1
        return
    row = expected.get(path)
    need(row is not None, 'UNKNOWN_OR_UNMAPPED_PERSISTENT_ORIGINAL_READ')
    need(len(raw) == row['byte_length'] and
         hmac.compare_digest(case.sha(raw), row['source_original_raw_sha256']),
         'GUARDED_PERSISTENT_ORIGINAL_READ_DIFFERS_FROM_CLOSURE_SHA')
    seen[path] = seen.get(path, 0) + 1


def verify_relocated_history(*, first_hop_plan_file: str,
                             expected_first_hop_plan_sha256: str,
                             closure_file: str, expected_closure_sha256: str,
                             map_file: str, expected_map_sha256: str,
                             expected_handoff_sha256: str,
                             left_expected_manifest_sha256: str,
                             right_expected_manifest_sha256: str) -> dict:
    """Reverify all EC333->EC294 signed history using logical old source names.

    The three control SHA pins and three historical root pins are separate
    caller-provided external trust claims, NOT produced/entrusted by this code.
    Positive return remains exit2, because signing/CAS/custody are not granted.
    """
    supplied_roots = (expected_handoff_sha256,
                      left_expected_manifest_sha256,
                      right_expected_manifest_sha256)
    need(all(receipt._sha(item) and item != '0' * 64 for item in supplied_roots),
         'THREE_SEPARATE_HISTORICAL_ROOT_SHA_PINS_REQUIRED', 'invalid_input')
    controls = (first_hop_plan_file, closure_file, map_file)
    need(len(set(controls)) == 3 and all(first._path(path) for path in controls),
         'THREE_DISTINCT_CANONICAL_PRIVATE_CONTROL_FILES_REQUIRED', 'invalid_input')
    need(all(receipt._sha(value) and value != '0' * 64 for value in (
        expected_first_hop_plan_sha256, expected_closure_sha256,
        expected_map_sha256)),
        'THREE_SEPARATE_CONTROL_WHOLE_SHA_PINS_REQUIRED', 'invalid_input')

    # An EC335 byte check is a mandatory PRECONDITION, not a substitute for
    # replay. It independently checks *every* destination original and every
    # ZIP nested member chain while repinning all three pinned controls.
    copied = closure.verify_copies(
        first_hop_plan_file=first_hop_plan_file,
        expected_first_hop_plan_sha256=expected_first_hop_plan_sha256,
        closure_file=closure_file, expected_closure_sha256=expected_closure_sha256,
        map_file=map_file, expected_map_sha256=expected_map_sha256)
    need(copied.get('exit_code') == 2 and
         copied.get('destination_all_observed_copy_bytes_verified') is True and
         copied.get('destination_replay_not_performed') is True,
         'EXACT_NESTED_BYTE_COPY_PREFLIGHT_REQUIRED')
    plan, plan_raw = first._load_plan(first_hop_plan_file,
                                      expected_first_hop_plan_sha256)
    document, closure_raw = closure._load_closure(
        closure_file, expected_closure_sha256, plan,
        expected_first_hop_plan_sha256, first_hop_plan_file)
    mapping, map_raw = closure._load_map(
        map_file, expected_map_sha256, document,
        expected_closure_sha256, {first_hop_plan_file, closure_file})
    handoff_row = _root_source(plan, 'handoff')
    left_row = _root_source(plan, 'left_manifest')
    right_row = _root_source(plan, 'right_manifest')
    need(all(row['source_original_raw_sha256'] == digest for row, digest in zip(
        (handoff_row, left_row, right_row), supplied_roots)),
        'SEPARATE_HISTORICAL_ROOT_SHA_PINS_NOT_EQUAL_INHERITED_INVENTORY',
        'invalid_input')
    need(all(row['source_path'] not in controls for row in
             (handoff_row, left_row, right_row)),
         'CONTROLS_CANNOT_BE_OLD_SIGNED_ORIGINAL_PATHS', 'invalid_input')
    need(all(loc['source_path'] != loc['destination_path'] for loc in
             mapping['locations']),
         'EVERY_PERSISTENT_ORIGINAL_MUST_HAVE_A_DISTINCT_RECEIVER_PATH',
         'invalid_input')
    expected = {row['source_path']: row for row in document['sources']}
    need(not (set(controls) & set(expected)),
         'CONTROL_FILE_CANNOT_ALIAS_ORIGINAL', 'invalid_input')
    bindings = {loc['source_path']: loc['destination_path']
                for loc in mapping['locations']}
    # Old paths are logical verification domain identifiers. No raw JSON/path
    # rewrite or fallback is allowed when the verifier asks for old bytes.
    seen: dict[str, int] = {}
    counters = {'total': 0, 'private_imports': 0}
    with io._scoped_original_source_reads(
        bindings=bindings,
        observer=lambda path, raw: _observer(expected, seen, counters, path, raw)):
        verified = handoff.verify_handoff(
            handoff_file=handoff_row['source_path'],
            expected_handoff_sha256=expected_handoff_sha256,
            left_manifest_file=left_row['source_path'],
            left_expected_manifest_sha256=left_expected_manifest_sha256,
            right_manifest_file=right_row['source_path'],
            right_expected_manifest_sha256=right_expected_manifest_sha256)
        need(type(verified) is dict and verified.get('exit_code') == 2 and
             verified.get('command') == 'verify-handoff' and
             verified.get('status') ==
                 'unsigned_offline_delta_handoff_exactly_reconstructed_unresolved' and
             verified.get('handoff_original_exactly_reconstructed_from_both_original_signed_histories') is True and
             verified.get('both_ec331_manifests_and_all_inherited_old_signed_histories_replayed') is True and
             verified.get('handoff_and_both_manifest_all_inherited_original_pins_late_rechecked') is True and
             all(verified.get(field) is False for field in handoff.FALSE_FIELDS),
             'REAL_EC333_TO_EC294_ORIGINAL_SIGNATURE_REPLAY_REQUIRED')
        need(set(seen) == set(expected),
             'REPLAY_DID_NOT_OBSERVE_EXACT_EXPECTED_GUARDED_PERSISTENT_SOURCE_CLOSURE')
        # Additional late pins while the scope remains strict. Physical path
        # metadata checks in the old readers are directed at the *same* mapped
        # inode as the guarded bytes, not the absent old source path.
        for row in document['sources']:
            first._pin(row['source_path'], row['source_original_raw_sha256'],
                       row['byte_length'], 'REPLAY_FINAL_LOGICAL_SOURCE_REPIN')
    # Re-pin the destination originals after leaving the guarded verifier
    # context; these reads MUST address receiver paths literally.
    for row, loc in zip(document['sources'], mapping['locations']):
        first._pin(loc['destination_path'], row['source_original_raw_sha256'],
                   row['byte_length'], 'REPLAY_FINAL_PHYSICAL_DESTINATION_REPIN')
    for path, digest, limit, earlier in (
        (first_hop_plan_file, expected_first_hop_plan_sha256,
         first.MAX_PLAN_BYTES, plan_raw),
        (closure_file, expected_closure_sha256,
         closure.MAX_CLOSURE_BYTES, closure_raw),
        (map_file, expected_map_sha256, closure.MAX_MAP_BYTES, map_raw),
    ):
        _, late = receipt._load(path, digest, limit,
                                'EC336_POST_REPLAY_CONTROL_SHA_REPIN')
        need(hmac.compare_digest(late, earlier),
             'CONTROL_ORIGINAL_CHANGED_DURING_REPLAY')
    return {
        'schema': RESULT_SCHEMA, 'command': 'verify-signed-replay',
        'status': RESULT_STATUS, 'exit_code': 2,
        'first_hop_inventory_original_raw_sha256': expected_first_hop_plan_sha256,
        'closure_original_raw_sha256': expected_closure_sha256,
        'mapping_original_raw_sha256': expected_map_sha256,
        'handoff_original_raw_sha256': expected_handoff_sha256,
        'left_manifest_original_raw_sha256': left_expected_manifest_sha256,
        'right_manifest_original_raw_sha256': right_expected_manifest_sha256,
        'persistent_original_source_count': len(expected),
        'nested_member_byte_identity_checked_count': document['embedded_original_member_count'],
        'receiver_observed_persistent_guarded_source_count': len(seen),
        'receiver_guarded_read_event_count': counters['total'],
        'receiver_verified_temporary_import_read_event_count': counters['private_imports'],
        'every_ec335_source_was_guarded_replayed_under_its_unchanged_old_path': True,
        'ec333_to_ec294_inherited_original_signatures_replayed_locally': True,
        'ec333_complete_handoff_canonical_bytes_reconstructed': True,
        'all_receiver_destination_and_control_originals_late_rechecked': True,
        'guard_allows_no_unmapped_persistent_original_or_default_source_fallback': True,
        'independent_sha_trust_and_real_source_authority_remain_external': True,
        'offline_unresolved_exit_code': 2,
        **{field: False for field in FALSE_FIELDS},
    }
