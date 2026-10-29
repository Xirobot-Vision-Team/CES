#!/usr/bin/env python3
"""EC307: read-only evidence of two independently pinned EC306 same-parent candidates.

An EC306 index is unsigned. Its raw SHA therefore only gains *provenance*
from an actual independent external pin, not from any signature inside the
index. The ED25519 evidence is in original EC304 registrar records and EC305
governance certificates; EC307 checks those with the original verifiers and
checks the newest original EC303->EC294 ACK on EVERY append candidate.

This is a conflict handoff, never an external CAS, WORM or winner selector.
All evidence is path-independent and deterministic. Unavailable proof fails
closed, rather than silently degrading to a 'verified' fork.
"""
from __future__ import annotations

import hmac
import os
import stat
from pathlib import Path
from typing import Any

from finding_query_host import protocol as io
from delivery_anchor import anchor as a
from delivery_anchor import operator as store
from portable_bundle import bundle as b
from challenge_registry import registry
from registrar_epochs import epochs as e

REPORT_SCHEMA = 'ces.ec307.registrar_fork_cas_handoff.v1'
RESULT_SCHEMA = 'ces.ec307.registrar_fork_result.v1'
DENIAL_SCHEMA = 'ces.ec307.registrar_fork_denial.v1'
HANDOFF_SCHEMA = 'ces.ec307.external_cas_choice_request.v1'
MAX_REPORT_BYTES = 48_000
BRANCH_FIELDS = frozenset({
    'chain_file', 'expected_chain_raw_sha256', 'ledger_files',
    'certificate_files', 'ack_proof'})
ACK_FIELDS = frozenset({
    'bundle_file', 'expected_bundle_sha256', 'pins', 'acknowledgement_file',
    'expected_acknowledgement_sha256', 'sender_id', 'receiver_id',
    'receiver_public_hex', 'challenge_sha256'})


def need(condition: Any, name: str, status: str = 'permission_denied') -> None:
    if condition is not True:
        raise a.AnchorError('EC307_' + name, status)


def _branch_input(spec: dict) -> None:
    a.exact(spec, BRANCH_FIELDS, 'EC307_BRANCH_ARGUMENTS_INVALID')
    need(e._positive_sha(spec['expected_chain_raw_sha256']),
         'INDEPENDENT_CANDIDATE_RAW_SHA_REQUIRED')
    need(type(spec['ledger_files']) is list and
         all(type(f) is str for f in spec['ledger_files']) and
         type(spec['certificate_files']) is list and
         all(type(f) is str for f in spec['certificate_files']),
         'CANDIDATE_HISTORY_FILE_LISTS_REQUIRED')
    if spec['ack_proof'] is not None:
        a.exact(spec['ack_proof'], ACK_FIELDS, 'EC307_ACK_PROOF_FIELDS_INVALID')
        need(type(spec['ack_proof']['pins']) is dict and
             set(spec['ack_proof']['pins']) == set(b.PINS),
             'COMPLETE_ORIGINAL_EIGHT_ACK_PINS_REQUIRED')


def _verify_candidate(parent: dict, parent_history: list[list[dict]],
                      parent_sha: str, spec: dict) -> dict:
    """Verify precisely one EC306 commit or rotate from the pinned parent.

    IMPORTANT: all old index entries must be byte-for-byte equal; a permitted
    delta is either one signed registrar ACK append OR one governance-signed
    cutover to an empty new epoch, never an arbitrary rewrite of history.
    """
    _branch_input(spec)
    doc = e._owner_private_read(spec['chain_file'],
                                spec['expected_chain_raw_sha256'])
    e._check_structure(doc)
    for field in ('registry_id','governor_public_hex',
                  'initial_registrar_public_hex'):
        need(doc[field] == parent[field], 'CANDIDATE_ROOT_IDENTITY_CHANGED')
    need(doc['previous_chain_raw_sha256'] == parent_sha,
         'CANDIDATE_NOT_CHILD_OF_EXACT_INDEPENDENT_PARENT')
    before, after = parent['epochs'], doc['epochs']
    extension = len(after) == len(before)
    cutover = len(after) == len(before) + 1
    need(extension or cutover, 'ONLY_ONE_STEP_CHILD_CANDIDATES_ACCEPTED')
    added = after[-1]
    if extension:
        need(after[:-1] == before[:-1], 'CANDIDATE_CHANGED_FROZEN_EPOCH')
        old = before[-1]
        unchanged = {k: v for k,v in old.items()
                     if k not in ('ledger_raw_sha256','ledger_sequence')}
        need(all(added.get(k) == v for k,v in unchanged.items()) and
             added['ledger_sequence'] == old['ledger_sequence'] + 1 and
             e._positive_sha(added['ledger_raw_sha256']),
             'CANDIDATE_NOT_EXACT_ONE_RECORD_ACTIVE_APPEND')
        kind = 'signed_registrar_append'
    else:
        need(after[:-1] == before and before[-1]['ledger_sequence'] >= 1 and
             added['ordinal'] == len(before) and
             added['ledger_sequence'] == 0 and
             added['ledger_raw_sha256'] == a.GENESIS,
             'CANDIDATE_NOT_EXACT_EMPTY_CUTOVER_EXTENSION')
        kind = 'governance_signed_epoch_rotation'

    signed_history = e._verify_all_epochs(
        doc, spec['ledger_files'], spec['certificate_files'])
    if extension:
        need(signed_history[:-1] == parent_history[:-1] and
             signed_history[-1][:-1] == parent_history[-1],
             'CANDIDATE_NOT_SIGNED_PARENT_LEDGER_PREFIX')
        new_record = signed_history[-1][-1]
        claim = new_record['claim']
        need(claim['previous_ledger_raw_sha256'] ==
             before[-1]['ledger_raw_sha256'],
             'NEW_SIGNED_RECORD_DOES_NOT_REFERENCE_PARENT_LEDGER_TIP')
        proof = spec['ack_proof']
        need(proof is not None, 'LATEST_ORIGINAL_ACK_PROOF_MANDATORY')
        # Original EC304 registry.verify replays EC303->EC294, not a surrogate
        # signature assertion from the unsigned EC306 candidate index.
        verified = e._verify_latest_ack(
            doc=doc, ledger_file=spec['ledger_files'][-1], **proof)
        need(verified['exit_code'] == 0,
             'ORIGINAL_EC303_TO_EC294_LATEST_ACK_NOT_VERIFIED')
        # Bind the handoff summary to the claim actually verified by EC304.
        need(claim['acknowledgement_sha256'] ==
             proof['expected_acknowledgement_sha256'] and
             claim['external_exchange_challenge_sha256'] ==
             proof['challenge_sha256'],
             'LATEST_ACK_NOT_THE_PROPOSED_SIGNED_APPEND')
        child = {
            'signed_successor_kind': kind,
            'signed_successor_sha256': registry._signed_record_sha(new_record),
            'external_exchange_challenge_sha256':
                claim['external_exchange_challenge_sha256'],
            'acknowledgement_sha256': claim['acknowledgement_sha256'],
            'bundle_sha256': claim['bundle_sha256'],
            'original_ec301_report_sha256': verified['report_sha256'],
            'governance_certificate_raw_sha256': None,
            'governance_cutover_nonce_sha256': None,
        }
    else:
        need(signed_history[:-1] == parent_history and signed_history[-1] == [],
             'CANDIDATE_ROTATION_REWROTE_OLDER_SIGNED_HISTORY')
        need(spec['ack_proof'] is None,
             'EMPTY_CUTOVER_MUST_NOT_CLAIM_A_NEW_ACK_REPLAY')
        child = {
            'signed_successor_kind': kind,
            'signed_successor_sha256':
                added['cutover_certificate_raw_sha256'],
            'external_exchange_challenge_sha256': None,
            'acknowledgement_sha256': None,
            'bundle_sha256': None,
            'original_ec301_report_sha256': None,
            'governance_certificate_raw_sha256':
                added['cutover_certificate_raw_sha256'],
            'governance_cutover_nonce_sha256': added['cutover_nonce_sha256'],
        }
    return {
        'candidate_chain_raw_sha256': spec['expected_chain_raw_sha256'],
        'candidate_epoch_count': len(after),
        'candidate_active_registrar_public_hex': added['registrar_public_hex'],
        'candidate_active_ledger_raw_sha256': added['ledger_raw_sha256'],
        'candidate_active_ledger_sequence': added['ledger_sequence'],
        'candidate_total_signed_entries': sum(map(len, signed_history)),
        'original_ec303_latest_ack_replayed': extension,
        **child,
    }


def evaluate(*, parent_chain_file: str, parent_external: dict,
             parent_ledger_files: list[str],
             parent_certificate_files: list[str],
             candidate_a: dict, candidate_b: dict) -> dict:
    """Re-verify both children and construct the *same* unsigned report anywhere.

    The caller must obtain all three *whole-file raw SHA* pins independently;
    no index's self-declared latest SHA or locally published winning SHA counts.
    """
    need(type(parent_external) is dict, 'PARENT_EIGHT_EXTERNAL_PINS_REQUIRED')
    parent, history = e._read_active_chain(
        chain_file=parent_chain_file, external=parent_external,
        ledger_files=parent_ledger_files,
        certificate_files=parent_certificate_files)
    parent_sha = parent_external['chain_raw_sha256']
    need(candidate_a['expected_chain_raw_sha256'] !=
         candidate_b['expected_chain_raw_sha256'] and
         candidate_a['expected_chain_raw_sha256'] != parent_sha and
         candidate_b['expected_chain_raw_sha256'] != parent_sha,
         'TWO_DIFFERENT_INDEPENDENT_CHILD_PINS_REQUIRED')
    left = _verify_candidate(parent, history, parent_sha, candidate_a)
    right = _verify_candidate(parent, history, parent_sha, candidate_b)
    need(left['signed_successor_sha256'] !=
         right['signed_successor_sha256'] or
         left['signed_successor_kind'] != right['signed_successor_kind'],
         'NO_DIFFERENT_SIGNED_SUCCESSOR_PROVEN')
    # Sort by raw SHA, not arbitrary filenames or caller A/B order, so the
    # evidence SHA is stable when received on two different machines.
    children = sorted((left,right),key=lambda v:v['candidate_chain_raw_sha256'])
    handoff = {
        'schema': HANDOFF_SCHEMA,
        'expected_parent_chain_raw_sha256': parent_sha,
        'expected_parent_epoch_count': parent_external['epoch_count'],
        'expected_parent_active_registrar_public_hex':
            parent_external['active_registrar_public_hex'],
        'expected_parent_active_ledger_raw_sha256':
            parent_external['active_ledger_raw_sha256'],
        'expected_parent_active_ledger_sequence':
            parent_external['active_ledger_sequence'],
        'allowed_candidate_chain_raw_sha256': [
            c['candidate_chain_raw_sha256'] for c in children],
        'externally_authorized_selection_sha256': None,
        'external_atomic_compare_exchange_receipt_sha256': None,
        'request_is_not_a_cas_commit_or_governance_vote': True,
    }
    report = {
        'schema': REPORT_SCHEMA,
        'finding': 'two_different_originally_signed_same_parent_successors_observed',
        'registry_id': parent['registry_id'],
        'initial_registrar_public_hex': parent['initial_registrar_public_hex'],
        'governor_public_hex': parent['governor_public_hex'],
        'parent_chain_raw_sha256': parent_sha,
        'parent_epoch_count': len(parent['epochs']),
        'parent_active_ledger_raw_sha256':
            parent['epochs'][-1]['ledger_raw_sha256'],
        'parent_active_ledger_sequence':
            parent['epochs'][-1]['ledger_sequence'],
        'parent_original_signed_entry_count': sum(map(len,history)),
        'independently_pinned_candidates': children,
        'both_candidate_predecessors_equal_exact_parent_sha256': True,
        'all_original_ec304_registrar_and_ec305_governance_signatures_reverified': True,
        'all_new_registrar_appends_original_ec303_to_ec294_replayed': True,
        'latest_original_ack_proofs_replayed_count': sum(
            c['original_ec303_latest_ack_replayed'] for c in children),
        'old_historic_ec303_zip_ack_payloads_replayed': False,
        'cross_branch_reused_challenge_sha256':
            children[0]['external_exchange_challenge_sha256'] is not None and
            children[0]['external_exchange_challenge_sha256'] ==
                children[1]['external_exchange_challenge_sha256'],
        'cross_branch_reused_acknowledgement_sha256':
            children[0]['acknowledgement_sha256'] is not None and
            children[0]['acknowledgement_sha256'] ==
                children[1]['acknowledgement_sha256'],
        'external_cas_handoff': handoff,
        'external_immutable_pin_proven': False,
        'external_atomic_cas_or_worm_commit_proven': False,
        'externally_authorized_winner_or_latest_proven': False,
        'physical_operator_key_independence_or_global_revocation_proven': False,
        'network_or_original_business_write_performed': False,
        'full_underlying_signed_objects_embedded': False,
    }
    need(len(b.canonical(report)) < MAX_REPORT_BYTES,
         'BOUNDED_EVIDENCE_REPORT_TOO_LARGE')
    return report


def compare(*, parent_chain_file: str, parent_external: dict,
            parent_ledger_files: list[str],
            parent_certificate_files: list[str],
            candidate_a: dict, candidate_b: dict,
            out: str | None = None) -> dict:
    report = evaluate(
        parent_chain_file=parent_chain_file, parent_external=parent_external,
        parent_ledger_files=parent_ledger_files,
        parent_certificate_files=parent_certificate_files,
        candidate_a=candidate_a, candidate_b=candidate_b)
    if out is not None:
        # Private O_EXCL/fsync, never append a security claim to parent/child.
        store.store(out,report,MAX_REPORT_BYTES)
    return {
        'status':'two_verified_competing_candidates_observed_external_cas_required',
        'exit_code':2,
        'evidence_report_raw_sha256':b.digest(b.canonical(report)),
        'evidence_report_written': out is not None,
        'registry_id': report['registry_id'],
        'parent_chain_raw_sha256': report['parent_chain_raw_sha256'],
        'candidate_chain_raw_sha256': report['external_cas_handoff'][
            'allowed_candidate_chain_raw_sha256'],
        'candidate_signed_successor_kind': [
            c['signed_successor_kind'] for c in report['independently_pinned_candidates']],
        'original_signatures_and_new_ack_proofs_reverified': True,
        'external_atomic_cas_or_worm_commit_proven':False,
        'authorized_winner_chosen':False,
        'original_business_write_performed':False,
    }


def _read_report(file: str, sha: str) -> dict:
    need(e._positive_sha(sha), 'EXTERNAL_REPORT_RAW_SHA_PIN_REQUIRED')
    path = b._private_parent(file)
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise a.AnchorError('EC307_REPORT_NOT_PRESENT','unavailable') from exc
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
         stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
         'REPORT_MUST_BE_OWNER_0600_SINGLE_LINK_REGULAR')
    raw = io._open_regular(file, MAX_REPORT_BYTES, private=True)
    after = os.lstat(path)
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,
          before.st_ctime_ns)==
         (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,
          after.st_ctime_ns),'REPORT_CHANGED_DURING_READ','unavailable')
    need(hmac.compare_digest(b.digest(raw),sha),
         'REPORT_BYTES_NOT_EQUAL_INDEPENDENT_EXTERNAL_SHA')
    doc = io.parse(raw, MAX_REPORT_BYTES)
    need(hmac.compare_digest(raw,b.canonical(doc)),
         'REPORT_MUST_BE_CANONICAL_EXACT_BYTES')
    return doc


def verify_report(*, evidence_file: str, expected_evidence_report_sha256: str,
                  parent_chain_file: str, parent_external: dict,
                  parent_ledger_files: list[str],
                  parent_certificate_files: list[str],
                  candidate_a: dict, candidate_b: dict) -> dict:
    """Independently replay EVERYTHING, not merely trust a stored report hash."""
    saved = _read_report(evidence_file,expected_evidence_report_sha256)
    regenerated = evaluate(
        parent_chain_file=parent_chain_file, parent_external=parent_external,
        parent_ledger_files=parent_ledger_files,
        parent_certificate_files=parent_certificate_files,
        candidate_a=candidate_a,candidate_b=candidate_b)
    need(saved == regenerated,
         'EVIDENCE_CONTENT_NOT_EQUAL_FULL_ORIGINAL_SIGNATURE_REPLAY')
    return {
        'status':'externally_pinned_conflict_evidence_fully_reverified',
        'exit_code':2,
        'evidence_report_raw_sha256':expected_evidence_report_sha256,
        'registry_id':regenerated['registry_id'],
        'parent_chain_raw_sha256':regenerated['parent_chain_raw_sha256'],
        'candidate_chain_raw_sha256':regenerated['external_cas_handoff'][
            'allowed_candidate_chain_raw_sha256'],
        'original_signatures_and_new_ack_proofs_reverified':True,
        'external_atomic_cas_or_worm_commit_proven':False,
        'authorized_winner_chosen':False,
        'original_business_write_performed':False,
    }
