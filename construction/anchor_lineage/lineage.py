#!/usr/bin/env python3
"""EC297 multi-epoch offline lineage for original EC295/EC296 signed evidence.

A lineage commitment contains no file paths. A proposed commitment is NOT a
trusted latest state: the verify operation requires independently retained
commitment, first/latest tip, and latest bridge digests. There are no socket,
Provider, original audit-key, key generation or signature-creation operations.
"""
from __future__ import annotations

import hmac
import os
from typing import Any

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from anchor_rotation import rotation as r

INPUT_SCHEMA = 'ces.ec297.offline_rotation_lineage_inputs.v1'
COMMITMENT_SCHEMA = 'ces.ec297.portable_rotation_lineage_commitment.v1'
RESULT_SCHEMA = 'ces.ec297.offline_rotation_lineage_verified.v1'
DENIAL_SCHEMA = 'ces.ec297.offline_rotation_lineage_denial.v1'
MAX_EPOCHS = 16
MAX_INPUT_BYTES = 500_000
MAX_COMMITMENT_BYTES = 60_000
EPOCH_FIELDS = frozenset({'policy_file', 'policy_sha256',
                          'checkpoint_files', 'checkpoint_tip_sha256'})
BRIDGE_FIELDS = frozenset({'bridge_file', 'bridge_sha256',
                           'minimum_fresh_readback_unix'})
INPUT_FIELDS = frozenset({'schema', 'epochs', 'bridges'})
COMMITMENT_FIELDS = frozenset({
    'schema', 'operation_id', 'job_sha256', 'ec294_policy_sha256',
    'ec294_host_code_sha256', 'original_ec227_code_sha256',
    'epoch_count', 'bridge_count', 'epochs', 'bridges',
    'root_checkpoint_tip_sha256', 'latest_checkpoint_tip_sha256',
    'latest_rotation_bridge_sha256',
})


def require(ok: bool, reason: str, status: str = 'invalid_input') -> None:
    if ok is not True:
        raise a.AnchorError(reason, status)


def exact(doc: Any, fields: frozenset[str], reason: str) -> dict:
    require(type(doc) is dict and set(doc) == fields, reason)
    return doc


def sha_pin(s: Any) -> bool:
    return a.valid_sha(s) and s != a.GENESIS


def absolute_file(path: Any) -> bool:
    return (type(path) is str and 1 <= len(path) <= 4096 and
            os.path.isabs(path) and '\x00' not in path)


def validate_inputs(spec: Any) -> dict:
    exact(spec, INPUT_FIELDS, 'EC297_INPUT_DOCUMENT_FIELDS_INVALID')
    require(spec['schema'] == INPUT_SCHEMA and
            len(a.canonical(spec)) <= MAX_INPUT_BYTES,
            'EC297_INPUT_SCHEMA_OR_BUDGET_INVALID')
    epochs, bridges = spec['epochs'], spec['bridges']
    require(type(epochs) is list and 3 <= len(epochs) <= MAX_EPOCHS and
            type(bridges) is list and len(bridges) == len(epochs) - 1,
            'EC297_THREE_OR_MORE_ORDERED_EPOCHS_AND_ALL_BRIDGES_REQUIRED')
    used_files: set[str] = set()
    for epoch in epochs:
        exact(epoch, EPOCH_FIELDS, 'EC297_EPOCH_FIELDS_INVALID')
        require(sha_pin(epoch['policy_sha256']) and
                sha_pin(epoch['checkpoint_tip_sha256']) and
                absolute_file(epoch['policy_file']) and
                type(epoch['checkpoint_files']) is list and
                1 <= len(epoch['checkpoint_files']) <= a.MAX_CHECKPOINTS,
                'EC297_PINNED_POLICY_AND_COMPLETE_EPOCH_REQUIRED')
        paths = [epoch['policy_file'], *epoch['checkpoint_files']]
        require(all(absolute_file(path) and path not in used_files
                    for path in paths) and len(paths) == len(set(paths)),
                'EC297_REPEATED_OR_NONABSOLUTE_EPOCH_FILES')
        used_files.update(paths)
    for bridge in bridges:
        exact(bridge, BRIDGE_FIELDS, 'EC297_BRIDGE_INPUT_FIELDS_INVALID')
        stamp = bridge['minimum_fresh_readback_unix']
        require(absolute_file(bridge['bridge_file']) and
                bridge['bridge_file'] not in used_files and
                sha_pin(bridge['bridge_sha256']) and
                (stamp is None or
                 (type(stamp) is int and 946684800 <= stamp <= 4102444800)),
                'EC297_PINNED_BRIDGE_AND_FRESHNESS_INPUT_REQUIRED')
        used_files.add(bridge['bridge_file'])
    return spec


def build_commitment(spec: dict) -> dict:
    """Verify every original signed receipt and every four-party EC296 bridge.

    All file paths are local transport locations. A path is never part of the
    portable externally pinned commitment, allowing offline remount/relocation.
    """
    validate_inputs(spec)
    verified = []
    epoch_summaries = []
    all_keys: set[str] = set()
    all_receipts: set[str] = set()
    all_policies: set[str] = set()
    all_tips: set[str] = set()
    all_bridges: set[str] = set()
    root_policy = None
    for index, desc in enumerate(spec['epochs']):
        policy_sha, tip = desc['policy_sha256'], desc['checkpoint_tip_sha256']
        require(policy_sha not in all_policies and tip not in all_tips,
                'EC297_REUSED_EPOCH_POLICY_OR_TIP', 'permission_denied')
        policy = a.load_policy(desc['policy_file'], policy_sha)
        signer_keys = {policy['keeper_public_hex'], policy['witness_public_hex']}
        require(not (signer_keys & all_keys),
                'EC297_HISTORICAL_KEEPER_OR_WITNESS_KEY_REUSED',
                'permission_denied')
        all_keys.update(signer_keys)
        all_policies.add(policy_sha)
        all_tips.add(tip)
        if root_policy is None:
            root_policy = policy
        else:
            # Recheck invariant original EC294/EC227 identity across *all* hops.
            require(all(policy[field] == root_policy[field]
                        for field in r.POLICY_CONTINUITY),
                    'EC297_ORIGINAL_AUDIT_IDENTITY_DRIFT',
                    'permission_denied')
        checkpoints = [io.read_doc(path, a.MAX_CHECKPOINT_BYTES)
                       for path in desc['checkpoint_files']]
        # The original verifier cryptographically checks the original EC294
        # signed grants, server ACK, both EC295 signatures, and whole ancestry.
        a.verify_chain(checkpoints, policy, policy_sha, tip)
        for checkpoint in checkpoints:
            reply = checkpoint['claim']['ec294_signed_reply_sha256']
            require(reply not in all_receipts,
                    'EC297_ORIGINAL_SIGNED_RECEIPT_REPLAY_ACROSS_EPOCHS',
                    'permission_denied')
            all_receipts.add(reply)
        first, last = checkpoints[0]['claim'], checkpoints[-1]['claim']
        epoch_summaries.append({
            'index': index,
            'policy_sha256': policy_sha,
            'checkpoint_tip_sha256': tip,
            'checkpoint_count': len(checkpoints),
            'keeper_public_hex': policy['keeper_public_hex'],
            'witness_public_hex': policy['witness_public_hex'],
            'first_signed_reply_sha256': first['ec294_signed_reply_sha256'],
            'last_signed_reply_sha256': last['ec294_signed_reply_sha256'],
            'first_event_count': first['audit_event_count'],
            'last_event_count': last['audit_event_count'],
            'first_reply_unix': first['ec294_reply_issued_at_unix'],
            'last_reply_unix': last['ec294_reply_issued_at_unix'],
            'first_audit_head_hmac_sha256': first['audit_head_hmac_sha256'],
            'last_audit_head_hmac_sha256': last['audit_head_hmac_sha256'],
        })
        verified.append((policy, checkpoints))
    bridge_summaries = []
    for index, desc in enumerate(spec['bridges']):
        bridge_sha = desc['bridge_sha256']
        require(bridge_sha not in all_bridges,
                'EC297_REPEATED_ROTATION_BRIDGE', 'permission_denied')
        all_bridges.add(bridge_sha)
        old_pol, old_cps = verified[index]
        new_pol, new_cps = verified[index + 1]
        # EC296 recomputes the *exact* historical claim from the two full
        # histories (including readback timestamp and original audit head),
        # rather than trusting values copied from the bridge claim.
        claim = r.claim_from_histories(
            old_policy=old_pol,
            old_policy_sha=spec['epochs'][index]['policy_sha256'],
            old_checkpoints=old_cps,
            old_expected_tip=spec['epochs'][index]['checkpoint_tip_sha256'],
            new_policy=new_pol,
            new_policy_sha=spec['epochs'][index + 1]['policy_sha256'],
            new_checkpoints=new_cps,
            new_proposed_tip=spec['epochs'][index + 1]['checkpoint_tip_sha256'],
            minimum_fresh_readback_unix=desc['minimum_fresh_readback_unix'])
        bridge = io.read_doc(desc['bridge_file'], r.MAX_BRIDGE_BYTES)
        r.verify_bridge(bridge, claim, old_pol, new_pol,
                        externally_pinned_bridge_sha=bridge_sha)
        bridge_summaries.append({
            'index': index,
            'old_policy_sha256': claim['old_policy_sha256'],
            'new_policy_sha256': claim['new_policy_sha256'],
            'old_checkpoint_tip_sha256': claim['old_checkpoint_tip_sha256'],
            'new_checkpoint_tip_sha256': claim['new_checkpoint_tip_sha256'],
            'rotation_bridge_sha256': bridge_sha,
            'bridge_claim_sha256': a.sha(claim),
            'handover_observation_mode': claim['handover_observation_mode'],
            'minimum_fresh_readback_unix': claim['minimum_fresh_readback_unix'],
            'old_last_event_count': claim['old_last_event_count'],
            'new_first_event_count': claim['new_first_event_count'],
            'old_last_hmac_head_sha256': claim['old_last_hmac_head_sha256'],
            'new_first_hmac_head_sha256': claim['new_first_hmac_head_sha256'],
        })
    assert root_policy is not None  # validated length is >= 3
    result = {
        'schema': COMMITMENT_SCHEMA,
        'operation_id': root_policy['operation_id'],
        'job_sha256': root_policy['job_sha256'],
        'ec294_policy_sha256': root_policy['ec294_policy_sha256'],
        'ec294_host_code_sha256': root_policy['ec294_host_code_sha256'],
        'original_ec227_code_sha256': root_policy['original_ec227_code_sha256'],
        'epoch_count': len(epoch_summaries),
        'bridge_count': len(bridge_summaries),
        'epochs': epoch_summaries,
        'bridges': bridge_summaries,
        'root_checkpoint_tip_sha256': epoch_summaries[0]['checkpoint_tip_sha256'],
        'latest_checkpoint_tip_sha256': epoch_summaries[-1]['checkpoint_tip_sha256'],
        'latest_rotation_bridge_sha256': bridge_summaries[-1]['rotation_bridge_sha256'],
    }
    require(len(a.canonical(result)) + 1 <= MAX_COMMITMENT_BYTES,
            'EC297_PORTABLE_COMMITMENT_EXCEEDS_BUDGET')
    return result


def check_commitment(candidate: Any, computed: dict,
                     *, expected_commitment_sha256: str,
                     expected_root_tip: str,
                     expected_latest_tip: str,
                     expected_latest_bridge_sha256: str) -> dict:
    # Never allow a missing/latest-from-local-default pin or the zero genesis.
    pins = (expected_commitment_sha256, expected_root_tip,
            expected_latest_tip, expected_latest_bridge_sha256)
    require(all(sha_pin(pin) for pin in pins),
            'EC297_FOUR_INDEPENDENT_EXTERNAL_DIGEST_INPUTS_REQUIRED',
            'permission_denied')
    exact(candidate, COMMITMENT_FIELDS,
          'EC297_PORTABLE_COMMITMENT_FIELDS_INVALID')
    require(candidate['schema'] == COMMITMENT_SCHEMA and
            len(a.canonical(candidate)) + 1 <= MAX_COMMITMENT_BYTES and
            hmac.compare_digest(a.sha(candidate), expected_commitment_sha256),
            'EC297_EXTERNAL_LINEAGE_COMMITMENT_SHA_MISMATCH_OR_ROLLBACK',
            'permission_denied')
    require(candidate == computed,
            'EC297_COMMITMENT_NOT_EQUAL_TO_ALL_VERIFIED_EPOCHS_AND_BRIDGES',
            'permission_denied')
    require(hmac.compare_digest(computed['root_checkpoint_tip_sha256'],
                                expected_root_tip) and
            hmac.compare_digest(computed['latest_checkpoint_tip_sha256'],
                                expected_latest_tip) and
            hmac.compare_digest(computed['latest_rotation_bridge_sha256'],
                                expected_latest_bridge_sha256),
            'EC297_INDEPENDENT_ROOT_LATEST_OR_BRIDGE_PIN_MISMATCH',
            'permission_denied')
    return {
        'schema': RESULT_SCHEMA,
        'status': 'verified_offline_multi_epoch_lineage_against_supplied_pins',
        'exit_code': 0,
        'epoch_count': computed['epoch_count'],
        'rotation_count': computed['bridge_count'],
        'original_ec294_signatures_every_ec295_checkpoint_verified': True,
        'all_four_ec296_signatures_each_rotation_verified': True,
        'all_epoch_signer_keys_unique': True,
        'all_historical_signed_receipts_unique': True,
        'complete_ordered_lineage_matches_pinned_commitment': True,
        'lineage_commitment_sha256': a.sha(candidate),
        'root_checkpoint_tip_sha256': computed['root_checkpoint_tip_sha256'],
        'latest_checkpoint_tip_sha256': computed['latest_checkpoint_tip_sha256'],
        'latest_rotation_bridge_sha256': computed['latest_rotation_bridge_sha256'],
        'final_historical_event_count': computed['epochs'][-1]['last_event_count'],
        'final_historical_audit_head_hmac_sha256':
            computed['epochs'][-1]['last_audit_head_hmac_sha256'],
        'actual_independent_off_host_retention_or_unique_fork_proven': False,
        'physical_independent_signers_or_trusted_utc_proven': False,
        'current_ec227_disk_state_or_production_delivery_checked': False,
        'new_provider_query_or_original_send_executed': False,
    }
