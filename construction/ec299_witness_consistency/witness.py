#!/usr/bin/env python3
"""EC299: verify two offline witness chains against original signed evidence.

A witness is a *public key*, not an automatically trusted human, jurisdiction,
immutable store, trusted clock or latest-chain authority. Every historical
observation is independently reverified against original EC294/295/296/297
signatures and externally supplied EC297 digests. Every cross-witness pair is
compared so a past fork cannot disappear when only the newest tips are viewed.
No business Host, key generation, network or provider operation exists here.
"""
from __future__ import annotations

import hmac
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec279_finding_query_host import protocol as io
from ec295_delivery_anchor import anchor as a
from ec297_anchor_lineage import lineage as l
from ec298_anchor_conflicts import conflicts as c

DOMAIN = b'CES/EC299/DeliveryAudit/IndependentSignedObservation/v1\0'
DRAFT_SCHEMA = 'ces.ec299.offline_witness_observation_draft.v1'
CLAIM_SCHEMA = 'ces.ec299.offline_witness_observation_claim.v1'
RECEIPT_SCHEMA = 'ces.ec299.signed_witness_observation.v1'
MANIFEST_SCHEMA = 'ces.ec299.two_witness_observation_manifest.v1'
REPORT_SCHEMA = 'ces.ec299.two_witness_consistency_report.v1'
RESULT_SCHEMA = 'ces.ec299.two_witness_consistency_result.v1'
DENIAL_SCHEMA = 'ces.ec299.two_witness_consistency_denial.v1'
MAX_RECEIPT_BYTES = 3600
MAX_MANIFEST_BYTES = 150_000
MAX_REPORT_BYTES = 150_000
MAX_OBSERVATIONS = 8
ID_PATTERN = re.compile(r'[a-z][a-z0-9_-]{1,31}\Z')
PUB_PATTERN = re.compile(r'[0-9a-f]{64}\Z')
CLAIM_KEYS = frozenset({
    'schema', 'witness_id', 'witness_public_hex', 'sequence',
    'previous_observation_sha256', 'lineage_commitment_sha256',
    'root_checkpoint_tip_sha256', 'latest_checkpoint_tip_sha256',
    'latest_rotation_bridge_sha256', 'operation_id', 'job_sha256',
    'ec294_policy_sha256', 'ec294_host_code_sha256',
    'original_ec227_code_sha256', 'epoch_count', 'bridge_count',
})
RECEIPT_KEYS = frozenset({'schema', 'claim', 'signature_ed25519'})
DRAFT_KEYS = frozenset({'schema', 'claim'})
ENTRY_KEYS = frozenset({'signed_observation_file', *c.LANE_KEYS})
LOG_KEYS = frozenset({'witness_id', 'observations'})
MANIFEST_KEYS = frozenset({'schema', 'a', 'b'})


def valid_pub(value: Any) -> bool:
    return type(value) is str and PUB_PATTERN.fullmatch(value) is not None and a.valid_pub(value)


def valid_id(value: Any) -> bool:
    return type(value) is str and ID_PATTERN.fullmatch(value) is not None


def unsigned_claim(commitment: dict, *, witness_id: str,
                   witness_public_hex: str, sequence: int,
                   previous_observation_sha256: str) -> dict:
    """Derive *all* signed fields from a fully reverified EC297 commitment."""
    l.require(valid_id(witness_id) and valid_pub(witness_public_hex),
              'EC299_WITNESS_ID_OR_PUBLIC_KEY_INVALID')
    l.require(type(sequence) is int and 1 <= sequence <= MAX_OBSERVATIONS and
              a.valid_sha(previous_observation_sha256) and
              (sequence == 1) == (previous_observation_sha256 == a.GENESIS),
              'EC299_OBSERVATION_SEQUENCE_OR_PREDECESSOR_INVALID')
    return {
        'schema': CLAIM_SCHEMA,
        'witness_id': witness_id,
        'witness_public_hex': witness_public_hex,
        'sequence': sequence,
        'previous_observation_sha256': previous_observation_sha256,
        'lineage_commitment_sha256': a.sha(commitment),
        'root_checkpoint_tip_sha256': commitment['root_checkpoint_tip_sha256'],
        'latest_checkpoint_tip_sha256': commitment['latest_checkpoint_tip_sha256'],
        'latest_rotation_bridge_sha256': commitment['latest_rotation_bridge_sha256'],
        'operation_id': commitment['operation_id'],
        'job_sha256': commitment['job_sha256'],
        'ec294_policy_sha256': commitment['ec294_policy_sha256'],
        'ec294_host_code_sha256': commitment['ec294_host_code_sha256'],
        'original_ec227_code_sha256': commitment['original_ec227_code_sha256'],
        'epoch_count': commitment['epoch_count'],
        'bridge_count': commitment['bridge_count'],
    }


def sign_claim(claim: dict, key: Ed25519PrivateKey) -> str:
    l.exact(claim, CLAIM_KEYS, 'EC299_SIGNED_CLAIM_SHAPE_INVALID')
    return key.sign(DOMAIN + a.canonical(claim)).hex()


def verify_receipt(receipt: Any, *, expected_witness_id: str,
                   expected_public_hex: str) -> dict:
    l.exact(receipt, RECEIPT_KEYS, 'EC299_SIGNED_RECEIPT_FIELDS_INVALID')
    l.require(receipt['schema'] == RECEIPT_SCHEMA and
              len(a.canonical(receipt)) + 1 <= MAX_RECEIPT_BYTES,
              'EC299_SIGNED_RECEIPT_SCHEMA_OR_SIZE_INVALID')
    claim = l.exact(receipt['claim'], CLAIM_KEYS,
                    'EC299_SIGNED_CLAIM_FIELDS_INVALID')
    l.require(claim['schema'] == CLAIM_SCHEMA and
              valid_id(expected_witness_id) and valid_pub(expected_public_hex) and
              claim['witness_id'] == expected_witness_id and
              hmac.compare_digest(claim['witness_public_hex'], expected_public_hex),
              'EC299_WITNESS_ID_OR_PUBLIC_KEY_NOT_EXTERNALLY_PINNED',
              'permission_denied')
    sig = receipt['signature_ed25519']
    l.require(type(sig) is str and a.SIG.fullmatch(sig) is not None,
              'EC299_WITNESS_SIGNATURE_ENCODING_INVALID')
    try:
        io.pub_from_hex(expected_public_hex).verify(
            bytes.fromhex(sig), DOMAIN + a.canonical(claim))
    except (InvalidSignature, ValueError, TypeError, io.HostError) as exc:
        raise a.AnchorError('EC299_WITNESS_ED25519_SIGNATURE_INVALID',
                            'permission_denied') from exc
    return claim


def verified_claim_from_lane(lane: dict, *, witness_id: str,
                             public_hex: str, sequence: int,
                             previous_digest: str) -> tuple[dict, dict, list[dict]]:
    # EC298.verify_lane replays original EC297 plus each *actual* EC295 chain,
    # preventing substitution of different signed checkpoints post-verification.
    commitment, snapshots = c.verify_lane(lane)
    return unsigned_claim(commitment, witness_id=witness_id,
        witness_public_hex=public_hex, sequence=sequence,
        previous_observation_sha256=previous_digest), commitment, snapshots


def _same_identity(x: dict, y: dict) -> bool:
    return all(x[field] == y[field] for field in c.IDENTITY_FIELDS)


def _verified_ancestry(old: dict, old_snap: list[dict],
                       new: dict, new_snap: list[dict]) -> bool:
    """Exact checkpoint-aware prefix, also allowing final-epoch growth.

    EC298's epoch-only prefix intentionally treats a last-epoch checkpoint
    extension as inconclusive; EC299 can establish that extension from the
    full verified checkpoint SHA sequence. Once an epoch has a successor
    bridge its signed history cannot be rewritten or extended.
    """
    if not _same_identity(old, new) or len(old_snap) > len(new_snap):
        return False
    count = len(old_snap)
    if old['bridges'][:count - 1] != new['bridges'][:count - 1]:
        return False
    for i in range(count):
        before, after = old_snap[i], new_snap[i]
        if (before['policy_sha256'] != after['policy_sha256'] or
            before['keeper_public_hex'] != after['keeper_public_hex'] or
            before['witness_public_hex'] != after['witness_public_hex']):
            return False
        pre, post = before['checkpoints'], after['checkpoints']
        if len(pre) > len(post) or pre != post[:len(pre)]:
            return False
        if i < count - 1 and (len(pre) != len(post) or
                              old['epochs'][i] != new['epochs'][i]):
            return False
    return True


def relationship(x: tuple[dict, list[dict]],
                 y: tuple[dict, list[dict]]) -> tuple[str, list[dict]]:
    """Classify two *already fully verified* historical lineages."""
    xc, xs = x
    yc, ys = y
    l.require(_same_identity(xc, yc),
              'EC299_WITNESSES_OBSERVED_DIFFERENT_ORIGINAL_AUDIT_TASKS',
              'permission_denied')
    compared = c.compare_verified(xc, xs, yc, ys)
    if compared['status'] == 'signed_competing_evidence':
        return 'signed_competing_evidence', compared['findings']
    if xc == yc:
        return 'identical_signed_history', []
    if _verified_ancestry(xc, xs, yc, ys):
        return 'a_signed_checkpoint_ancestor_of_b', []
    if _verified_ancestry(yc, ys, xc, xs):
        return 'b_signed_checkpoint_ancestor_of_a', []
    return 'inconclusive_without_proven_signed_ancestry', []


def validate_manifest(doc: Any) -> dict:
    l.exact(doc, MANIFEST_KEYS, 'EC299_MANIFEST_FIELDS_INVALID')
    l.require(doc['schema'] == MANIFEST_SCHEMA and
              len(a.canonical(doc)) + 1 <= MAX_MANIFEST_BYTES,
              'EC299_MANIFEST_SCHEMA_OR_SIZE_INVALID')
    for which in ('a', 'b'):
        spec = l.exact(doc[which], LOG_KEYS, 'EC299_WITNESS_LOG_FIELDS_INVALID')
        obs = spec['observations']
        l.require(valid_id(spec['witness_id']) and type(obs) is list and
                  1 <= len(obs) <= MAX_OBSERVATIONS,
                  'EC299_BOUNDED_WITNESS_OBSERVATIONS_REQUIRED')
        for entry in obs:
            l.exact(entry, ENTRY_KEYS, 'EC299_OBSERVATION_ENTRY_FIELDS_INVALID')
            l.require(l.absolute_file(entry['signed_observation_file']),
                      'EC299_ABSOLUTE_SIGNED_OBSERVATION_PATH_REQUIRED')
            l.exact({k: entry[k] for k in c.LANE_KEYS}, c.LANE_KEYS,
                    'EC299_OBSERVATION_EC297_PINS_INVALID')
            l.require(all(l.absolute_file(entry[k]) for k in (
                'inputs_file', 'commitment_file')) and
                all(l.sha_pin(entry[k]) for k in (
                'expected_commitment_sha256','expected_root_tip',
                'expected_latest_tip','expected_latest_bridge_sha256')),
                'EC299_OBSERVATION_REQUIRES_FOUR_EXPLICIT_PINS_AND_PATHS',
                'permission_denied')
    l.require(doc['a']['witness_id'] != doc['b']['witness_id'],
              'EC299_DISTINCT_WITNESS_IDS_REQUIRED', 'permission_denied')
    return doc


def verified_log(spec: dict, *, expected_id: str, public_hex: str,
                 expected_tip: str) -> list[dict]:
    l.require(valid_id(expected_id) and valid_pub(public_hex) and
              l.sha_pin(expected_tip) and spec['witness_id'] == expected_id,
              'EC299_EXTERNALLY_PINNED_WITNESS_ID_KEY_TIP_REQUIRED',
              'permission_denied')
    seen: list[dict] = []
    previous = a.GENESIS
    for index, entry in enumerate(spec['observations']):
        lane = {key: entry[key] for key in c.LANE_KEYS}
        signed = io.read_doc(entry['signed_observation_file'], MAX_RECEIPT_BYTES)
        signed_claim = verify_receipt(signed,
            expected_witness_id=expected_id, expected_public_hex=public_hex)
        expected_claim, commit, snaps = verified_claim_from_lane(
            lane, witness_id=expected_id, public_hex=public_hex,
            sequence=index + 1, previous_digest=previous)
        l.require(signed_claim == expected_claim,
                  'EC299_SIGNED_WITNESS_CLAIM_DOES_NOT_MATCH_FULL_ORIGINAL_PROOFS',
                  'permission_denied')
        if seen:
            rel, _ = relationship((seen[-1]['commit'], seen[-1]['snaps']),
                                  (commit, snaps))
            l.require(rel == 'a_signed_checkpoint_ancestor_of_b',
                'EC299_WITNESS_OWN_LOG_NOT_STRICTLY_MONOTONIC_SIGNED_HISTORY',
                'permission_denied')
        previous = a.sha(signed)
        seen.append({'sha256': previous, 'claim_sha256': a.sha(signed_claim),
                     'commit': commit, 'snaps': snaps, 'sequence': index + 1})
    l.require(hmac.compare_digest(previous, expected_tip),
              'EC299_INDEPENDENT_WITNESS_CHAIN_TIP_MISMATCH_OR_ROLLBACK',
              'permission_denied')
    return seen


def compare_witnesses(*, manifest: dict, a_id: str, a_public_hex: str,
                      a_tip: str, b_id: str, b_public_hex: str, b_tip: str) -> dict:
    validate_manifest(manifest)
    l.require(valid_id(a_id) and valid_id(b_id) and a_id != b_id and
              valid_pub(a_public_hex) and valid_pub(b_public_hex) and
              a_public_hex != b_public_hex and l.sha_pin(a_tip) and l.sha_pin(b_tip),
              'EC299_TWO_DISTINCT_EXTERNALLY_PINNED_WITNESS_KEYS_AND_TIPS_REQUIRED',
              'permission_denied')
    left = verified_log(manifest['a'], expected_id=a_id,
                        public_hex=a_public_hex, expected_tip=a_tip)
    right = verified_log(manifest['b'], expected_id=b_id,
                         public_hex=b_public_hex, expected_tip=b_tip)
    findings: list[dict] = []
    finding_shas: set[str] = set()
    categories = {'identical_signed_history': 0,
                  'a_signed_checkpoint_ancestor_of_b': 0,
                  'b_signed_checkpoint_ancestor_of_a': 0,
                  'signed_competing_evidence': 0,
                  'inconclusive_without_proven_signed_ancestry': 0}
    for x in left:
        for y in right:
            rel, pair_findings = relationship((x['commit'], x['snaps']),
                                              (y['commit'], y['snaps']))
            categories[rel] += 1
            for item in pair_findings:
                proof = {'a_observation_sequence': x['sequence'],
                         'b_observation_sequence': y['sequence'],
                         'signed_fork': item}
                proof_sha = a.sha(proof)
                if proof_sha not in finding_shas:
                    finding_shas.add(proof_sha)
                    findings.append(proof)
    if categories['signed_competing_evidence']:
        status, rc = 'signed_competing_evidence_between_supplied_witnesses', 2
    elif categories['inconclusive_without_proven_signed_ancestry']:
        status, rc = 'witness_histories_inconclusive', 2
    else:
        status, rc = 'supplied_signed_witness_observations_compatible', 0
    reference = left[0]['commit']
    report = {
        'schema': REPORT_SCHEMA, 'status': status, 'exit_code': rc,
        'operation_id': reference['operation_id'],
        'job_sha256': reference['job_sha256'],
        'ec294_policy_sha256': reference['ec294_policy_sha256'],
        'ec294_host_code_sha256': reference['ec294_host_code_sha256'],
        'original_ec227_code_sha256': reference['original_ec227_code_sha256'],
        'witness_a': {
            'witness_id': a_id, 'witness_public_hex': a_public_hex,
            'externally_pinned_latest_observation_sha256': a_tip,
            'signed_observation_sha256_chain': [x['sha256'] for x in left],
            'lineage_commitment_sha256_chain': [a.sha(x['commit']) for x in left],
        },
        'witness_b': {
            'witness_id': b_id, 'witness_public_hex': b_public_hex,
            'externally_pinned_latest_observation_sha256': b_tip,
            'signed_observation_sha256_chain': [x['sha256'] for x in right],
            'lineage_commitment_sha256_chain': [a.sha(x['commit']) for x in right],
        },
        'all_original_ec294_ec295_ec296_ec297_proofs_reverified_per_observation': True,
        'every_observation_signed_by_its_externally_pinned_public_key': True,
        'each_witness_log_hash_linked_and_strictly_monotonic': True,
        'cross_witness_all_historical_observation_pairs_compared': True,
        'historical_pair_categories': categories,
        'signed_fork_evidence': findings,
        'physical_witness_independence_or_real_identity_proven': False,
        'out_of_band_immutable_retention_or_trusted_utc_proven': False,
        'globally_unique_latest_or_preferred_fork_proven': False,
        'unseen_third_lineage_or_witness_excluded': False,
        'original_ec227_current_disk_or_production_delivery_checked': False,
        'original_host_send_provider_network_or_private_hmac_used': False,
    }
    l.require(len(a.canonical(report)) + 1 <= MAX_REPORT_BYTES,
              'EC299_WITNESS_COMPARISON_REPORT_TOO_LARGE')
    return report
