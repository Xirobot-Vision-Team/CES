#!/usr/bin/env python3
"""EC298: compare two *fully verified* EC297 signed histories, without authority.

A conflict is reported only for two authentic children sharing an exact signed
parent: either an EC295 predecessor checkpoint or an EC296 old epoch tip.
Different hashes alone are NOT evidence of a fork. All reported observations
are local to the two supplied independently pinned histories; no chronology,
revocation, signer identity, trusted UTC, immutable custody, or global latest
fork is inferred.
"""
from __future__ import annotations

import hmac
from typing import Any

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from anchor_lineage import lineage as l

REPORT_SCHEMA = 'ces.ec298.portable_signed_lineage_comparison.v1'
RESULT_SCHEMA = 'ces.ec298.signed_lineage_comparison_result.v1'
DENIAL_SCHEMA = 'ces.ec298.signed_lineage_comparison_denial.v1'
MAX_REPORT_BYTES = 96_000
IDENTITY_FIELDS = ('operation_id', 'job_sha256', 'ec294_policy_sha256',
                   'ec294_host_code_sha256', 'original_ec227_code_sha256')
LANE_KEYS = frozenset({'inputs_file', 'commitment_file',
                       'expected_commitment_sha256', 'expected_root_tip',
                       'expected_latest_tip', 'expected_latest_bridge_sha256'})


def verify_lane(options: dict) -> tuple[dict, list[dict]]:
    """Fully revalidate original EC294, EC295, EC296 signatures before comparison.

    A second EC295 checkpoint-chain validation protects the actual per-checkpoint
    material used for fork claims, even if local paths are replaced between
    EC297's pass and the later read. The independent external tips pin both
    passes to the identical signed ancestry without depending on file paths.
    """
    l.exact(options, LANE_KEYS, 'EC298_LANE_ARGUMENTS_INVALID')
    pins = [options[key] for key in ('expected_commitment_sha256',
        'expected_root_tip', 'expected_latest_tip', 'expected_latest_bridge_sha256')]
    l.require(all(l.sha_pin(p) for p in pins),
              'EC298_EIGHT_EXPLICIT_NON_GENESIS_EXTERNAL_PINS_REQUIRED',
              'permission_denied')
    l.require(all(l.absolute_file(options[k]) for k in ('inputs_file','commitment_file')),
              'EC298_LANE_ABSOLUTE_INPUT_PATHS_REQUIRED')
    candidate = io.read_doc(options['commitment_file'], l.MAX_COMMITMENT_BYTES)
    l.require(hmac.compare_digest(a.sha(candidate), pins[0]),
              'EC298_INDEPENDENT_LINEAGE_COMMITMENT_PIN_MISMATCH',
              'permission_denied')
    spec = io.read_doc(options['inputs_file'], l.MAX_INPUT_BYTES)
    computed = l.build_commitment(spec)
    l.check_commitment(candidate, computed,
        expected_commitment_sha256=pins[0], expected_root_tip=pins[1],
        expected_latest_tip=pins[2], expected_latest_bridge_sha256=pins[3])

    checkpoints_by_epoch: list[dict] = []
    for index, epoch in enumerate(spec['epochs']):
        policy = a.load_policy(epoch['policy_file'], epoch['policy_sha256'])
        signed = [io.read_doc(path, a.MAX_CHECKPOINT_BYTES)
                  for path in epoch['checkpoint_files']]
        a.verify_chain(signed, policy, epoch['policy_sha256'],
                       epoch['checkpoint_tip_sha256'])
        # A signed checkpoint tip cryptographically binds *all* ancestors; each
        # reloaded chain must also match the EC297 immutable epoch commitment.
        summary = computed['epochs'][index]
        l.require(summary['policy_sha256'] == epoch['policy_sha256'] and
                  summary['checkpoint_tip_sha256'] == a.sha(signed[-1]) and
                  summary['checkpoint_count'] == len(signed) and
                  summary['keeper_public_hex'] == policy['keeper_public_hex'] and
                  summary['witness_public_hex'] == policy['witness_public_hex'],
                  'EC298_EPOCH_SNAPSHOT_DIFFERS_FROM_VERIFIED_COMMITMENT',
                  'permission_denied')
        checkpoints_by_epoch.append({
            'policy_sha256': epoch['policy_sha256'],
            'keeper_public_hex': policy['keeper_public_hex'],
            'witness_public_hex': policy['witness_public_hex'],
            'checkpoints': [{
                'sequence': cp['claim']['sequence'],
                'previous_checkpoint_sha256': cp['claim']['previous_checkpoint_sha256'],
                'checkpoint_sha256': a.sha(cp),
                'signed_claim_sha256': a.sha(cp['claim']),
            } for cp in signed],
        })
    return computed, checkpoints_by_epoch


def _checkpoint_index(snapshots: list[dict]) -> dict[tuple[str, int, str], dict]:
    result: dict[tuple[str, int, str], dict] = {}
    for i, epoch in enumerate(snapshots):
        for cp in epoch['checkpoints']:
            key = (epoch['policy_sha256'], cp['sequence'],
                   cp['previous_checkpoint_sha256'])
            # The EC297 verifier rejects reuse of epoch policies within a lane;
            # EC295 verifier rejects repeated or discontinuous sequence values.
            l.require(key not in result, 'EC298_REPEATED_SIGNED_CHILD_IN_ONE_LANE',
                      'permission_denied')
            result[key] = {
                'epoch_index': i, 'checkpoint': cp,
                'keeper_public_hex': epoch['keeper_public_hex'],
                'witness_public_hex': epoch['witness_public_hex'],
            }
    return result


def _checkpoint_forks(a_snap: list[dict], b_snap: list[dict]) -> list[dict]:
    a_index, b_index = _checkpoint_index(a_snap), _checkpoint_index(b_snap)
    findings = []
    for key in sorted(a_index.keys() & b_index.keys()):
        one, two = a_index[key], b_index[key]
        ca, cb = one['checkpoint'], two['checkpoint']
        if ca['checkpoint_sha256'] == cb['checkpoint_sha256']:
            continue
        l.require((one['keeper_public_hex'], one['witness_public_hex']) ==
                  (two['keeper_public_hex'], two['witness_public_hex']),
                  'EC298_SAME_POLICY_HAS_DIFFERENT_SIGNER_KEYS',
                  'permission_denied')
        findings.append({
            'type': 'two_ec295_signed_checkpoint_children_of_same_parent',
            'policy_sha256': key[0],
            'sequence': key[1],
            'previous_checkpoint_sha256': key[2],
            'keeper_public_hex': one['keeper_public_hex'],
            'witness_public_hex': one['witness_public_hex'],
            'a': {'epoch_index': one['epoch_index'],
                  'checkpoint_sha256': ca['checkpoint_sha256'],
                  'signed_claim_sha256': ca['signed_claim_sha256']},
            'b': {'epoch_index': two['epoch_index'],
                  'checkpoint_sha256': cb['checkpoint_sha256'],
                  'signed_claim_sha256': cb['signed_claim_sha256']},
        })
    return findings


def _bridge_index(commitment: dict) -> dict[tuple[str, str], dict]:
    result = {}
    for bridge in commitment['bridges']:
        key = (bridge['old_policy_sha256'], bridge['old_checkpoint_tip_sha256'])
        l.require(key not in result, 'EC298_REUSED_BRIDGE_PARENT_IN_ONE_LANE',
                  'permission_denied')
        epoch = commitment['epochs'][bridge['index']]
        next_epoch = commitment['epochs'][bridge['index'] + 1]
        l.require(epoch['policy_sha256'] == key[0] and
                  epoch['checkpoint_tip_sha256'] == key[1] and
                  next_epoch['policy_sha256'] == bridge['new_policy_sha256'] and
                  next_epoch['checkpoint_tip_sha256'] == bridge['new_checkpoint_tip_sha256'],
                  'EC298_BRIDGE_COMMITMENT_PARENT_OR_TARGET_INVALID',
                  'permission_denied')
        result[key] = {'bridge': bridge, 'old': epoch, 'new': next_epoch}
    return result


def _bridge_forks(ca: dict, cb: dict) -> list[dict]:
    aa, bb = _bridge_index(ca), _bridge_index(cb)
    findings = []
    for key in sorted(aa.keys() & bb.keys()):
        x, y = aa[key], bb[key]
        ba, bc = x['bridge'], y['bridge']
        ta = (ba['new_policy_sha256'], ba['new_checkpoint_tip_sha256'])
        tb = (bc['new_policy_sha256'], bc['new_checkpoint_tip_sha256'])
        if ta == tb:
            # A different byte encoding / signature with the identical target
            # does not, by itself, establish two competing successors.
            continue
        l.require((x['old']['keeper_public_hex'], x['old']['witness_public_hex']) ==
                  (y['old']['keeper_public_hex'], y['old']['witness_public_hex']),
                  'EC298_MATCHED_BRIDGE_PARENT_HAS_DIFFERENT_SIGNER_KEYS',
                  'permission_denied')
        findings.append({
            'type': 'two_ec296_four_vote_rotation_bridges_from_same_old_tip',
            'old_policy_sha256': key[0],
            'old_checkpoint_tip_sha256': key[1],
            'old_keeper_public_hex': x['old']['keeper_public_hex'],
            'old_witness_public_hex': x['old']['witness_public_hex'],
            'a': {
                'bridge_index': ba['index'],
                'rotation_bridge_sha256': ba['rotation_bridge_sha256'],
                'bridge_claim_sha256': ba['bridge_claim_sha256'],
                'new_policy_sha256': ta[0],
                'new_checkpoint_tip_sha256': ta[1],
                'new_keeper_public_hex': x['new']['keeper_public_hex'],
                'new_witness_public_hex': x['new']['witness_public_hex'],
            },
            'b': {
                'bridge_index': bc['index'],
                'rotation_bridge_sha256': bc['rotation_bridge_sha256'],
                'bridge_claim_sha256': bc['bridge_claim_sha256'],
                'new_policy_sha256': tb[0],
                'new_checkpoint_tip_sha256': tb[1],
                'new_keeper_public_hex': y['new']['keeper_public_hex'],
                'new_witness_public_hex': y['new']['witness_public_hex'],
            },
        })
    return findings


def _ordered_prefix(short: dict, long: dict) -> bool:
    n = short['epoch_count']
    return (n <= long['epoch_count'] and
            short['epochs'] == long['epochs'][:n] and
            short['bridges'] == long['bridges'][:n-1])


def compare_verified(left_commit: dict, left_snap: list[dict],
                     right_commit: dict, right_snap: list[dict]) -> dict:
    """Pure comparison, for use ONLY after both EC297 full-history verifications."""
    l.require(all(left_commit[k] == right_commit[k] for k in IDENTITY_FIELDS),
              'EC298_TWO_HISTORIES_NOT_SAME_ORIGINAL_AUDIT_IDENTITY',
              'permission_denied')
    bridge_findings = _bridge_forks(left_commit, right_commit)
    cp_findings = _checkpoint_forks(left_snap, right_snap)
    findings = bridge_findings + cp_findings
    if findings:
        comparison, status, rc = ('competing_signed_successors_observed',
                                  'signed_competing_evidence', 2)
    elif left_commit == right_commit:
        comparison, status, rc = ('identical_lineage_evidence',
                                  'verified_no_conflict_observed_between_supplied_histories', 0)
    elif _ordered_prefix(left_commit, right_commit):
        comparison, status, rc = ('a_is_verified_prefix_of_b',
                                  'verified_no_conflict_observed_between_supplied_histories', 0)
    elif _ordered_prefix(right_commit, left_commit):
        comparison, status, rc = ('b_is_verified_prefix_of_a',
                                  'verified_no_conflict_observed_between_supplied_histories', 0)
    else:
        comparison, status, rc = ('distinct_histories_without_proven_shared_parent_fork',
                                  'inconclusive', 2)
    report = {
        'schema': REPORT_SCHEMA,
        'status': status,
        'exit_code': rc,
        'comparison': comparison,
        'operation_id': left_commit['operation_id'],
        'job_sha256': left_commit['job_sha256'],
        'ec294_policy_sha256': left_commit['ec294_policy_sha256'],
        'ec294_host_code_sha256': left_commit['ec294_host_code_sha256'],
        'original_ec227_code_sha256': left_commit['original_ec227_code_sha256'],
        'a_lineage_commitment_sha256': a.sha(left_commit),
        'b_lineage_commitment_sha256': a.sha(right_commit),
        'a_root_checkpoint_tip_sha256': left_commit['root_checkpoint_tip_sha256'],
        'b_root_checkpoint_tip_sha256': right_commit['root_checkpoint_tip_sha256'],
        'a_latest_checkpoint_tip_sha256': left_commit['latest_checkpoint_tip_sha256'],
        'b_latest_checkpoint_tip_sha256': right_commit['latest_checkpoint_tip_sha256'],
        'a_latest_rotation_bridge_sha256': left_commit['latest_rotation_bridge_sha256'],
        'b_latest_rotation_bridge_sha256': right_commit['latest_rotation_bridge_sha256'],
        'a_epochs_verified': left_commit['epoch_count'],
        'b_epochs_verified': right_commit['epoch_count'],
        'signed_bridge_fork_count': len(bridge_findings),
        'signed_checkpoint_fork_count': len(cp_findings),
        'findings': findings,
        'two_complete_original_ec294_ec295_ec296_histories_reverified': True,
        'conflicts_require_an_exact_common_signed_parent': True,
        'external_pin_source_immutability_or_real_independence_proven': False,
        'globally_unique_latest_or_preferred_fork_established': False,
        'physical_signer_identity_or_intent_proven': False,
        'current_original_ec227_disk_or_production_inbox_checked': False,
        'private_keys_hmac_token_network_or_original_send_used': False,
        'full_underlying_signed_proof_objects_embedded_in_report': False,
    }
    l.require(len(a.canonical(report))+1 <= MAX_REPORT_BYTES,
              'EC298_REPORT_EXCEEDS_PUBLIC_METADATA_BUDGET')
    return report
