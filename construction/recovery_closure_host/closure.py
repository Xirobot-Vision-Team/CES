#!/usr/bin/env python3
"""EC270: ratify a completed EC269 recovery into a long-lived governance root.

This does NOT mint a replacement for a missing preauthorized EC269 charter.
The new root, two distinct original council keys and an additional witness
must approve the exact recovery anchor while that anchor and charter are LIVE.
A witness signs the complete council-approved file and its observed timestamp.
The separate EC270 host then verifies this historical ceremony, continuing
EC267 governance and all existing source/custody/session safeguards, without
requiring the historic charter to be live forever. The witness's observed time
is an identity-bound *assertion*, not a trusted external clock measurement.
"""
from __future__ import annotations

import hmac
import os
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from offline_anchor_host import checkpoint as cp
from source_provenance_host import provenance as prov
from governed_source_host import governance as gov
from root_handover_host import handover as rot
from emergency_recovery_host import recovery as rec

SCHEMA = 'ces.ec270.witnessed_emergency_recovery_closure.v1'
PURPOSE = 'RATIFY_RECOVERED_ROOT_WITH_COUNCIL_AND_INDEPENDENT_WITNESS'
ROOT_DOMAIN = b'CES/EC270/closure/recovered-root/v1\x00'
COUNCIL_DOMAIN = b'CES/EC270/closure/council/v1\x00'
WITNESS_DOMAIN = b'CES/EC270/closure/independent-witness/v1\x00'
CLAIM_FIELDS = frozenset({
    'schema', 'purpose', 'old_governance_sha256', 'anchor_governance_sha256',
    'old_root_public_sha256', 'recovered_root_public_sha256', 'charter_sha256',
    'recovery_certificate_sha256', 'witness_public_sha256', 'recovered_epoch',
    'nonce',
})
SIGNED_FIELDS = CLAIM_FIELDS | {'signature_recovered_root_ed25519', 'council_approvals'}
FINAL_FIELDS = SIGNED_FIELDS | {'witness_observed_at_unix', 'signature_witness_ed25519'}
MAX_DOCUMENT = 8192


class ClosureError(rec.RecoveryError):
    """Fixed diagnostic; never include input material or secret paths."""


def deny(code: str) -> None:
    raise ClosureError(code)


def _fields(doc: Any) -> tuple[dict[str, Any], int]:
    if type(doc) is not dict or doc.get('schema') != SCHEMA:
        deny('EC270_CLOSURE_SCHEMA_INVALID')
    names = set(doc)
    if names == CLAIM_FIELDS:
        stage = -1
    elif names == SIGNED_FIELDS or names == FINAL_FIELDS:
        approvals = doc['council_approvals']
        if type(approvals) is not list or len(approvals) > rec.QUORUM:
            deny('EC270_COUNCIL_VOTES_INVALID')
        stage = len(approvals) if names == SIGNED_FIELDS else 3
        if names == FINAL_FIELDS and len(approvals) != rec.QUORUM:
            deny('EC270_WITNESS_MUST_FOLLOW_FULL_QUORUM')
        if (type(doc['signature_recovered_root_ed25519']) is not str or
                prov.SIGNATURE_RE.fullmatch(doc['signature_recovered_root_ed25519']) is None):
            deny('EC270_ROOT_SIGNATURE_ENCODING_INVALID')
        fingerprints = []
        for vote in approvals:
            if (type(vote) is not dict or set(vote) != rec.APPROVAL_FIELDS or
                    type(vote['public_sha256']) is not str or
                    cp.SHA_RE.fullmatch(vote['public_sha256']) is None or
                    type(vote['signature_ed25519']) is not str or
                    prov.SIGNATURE_RE.fullmatch(vote['signature_ed25519']) is None):
                deny('EC270_VOTE_ENCODING_INVALID')
            fingerprints.append(vote['public_sha256'])
        if fingerprints != sorted(set(fingerprints)):
            deny('EC270_COUNCIL_VOTES_DUPLICATE_OR_UNSORTED')
        if names == FINAL_FIELDS:
            rec._integer(doc['witness_observed_at_unix'], 1, 2**40,
                         'EC270_WITNESS_TIME_INVALID')
            if (type(doc['signature_witness_ed25519']) is not str or
                    prov.SIGNATURE_RE.fullmatch(doc['signature_witness_ed25519']) is None):
                deny('EC270_WITNESS_SIGNATURE_ENCODING_INVALID')
    else:
        deny('EC270_CLOSURE_FIELDS_OR_STAGE_INVALID')
    for name in ('old_governance_sha256', 'anchor_governance_sha256',
                 'old_root_public_sha256', 'recovered_root_public_sha256',
                 'charter_sha256', 'recovery_certificate_sha256', 'witness_public_sha256'):
        rec._sha(doc[name])
    rec._integer(doc['recovered_epoch'], 2, 2**31-1, 'EC270_EPOCH_INVALID')
    if (doc['purpose'] != PURPOSE or type(doc['nonce']) is not str or
            cp.NONCE_RE.fullmatch(doc['nonce']) is None):
        deny('EC270_PURPOSE_OR_NONCE_INVALID')
    return {k: doc[k] for k in CLAIM_FIELDS}, stage


def _witness(public: str, pin: str, old: dict[str, Any], anchor: dict[str, Any],
             council: dict[str, bytes], old_pin: str, new_pin: str,
             forbidden: tuple[str, ...]) -> bytes:
    witness_pin = rec._sha(pin)
    if witness_pin in ({old_pin, new_pin} | set(council) |
                       set(old['role_public_sha256'].values()) |
                       set(anchor['role_public_sha256'].values()) |
                       set(old['revoked_public_sha256']) |
                       set(anchor['revoked_public_sha256']) |
                       set(forbidden)):
        deny('EC270_WITNESS_REUSED_REVOKED_OR_NOT_INDEPENDENT')
    return rec._public(public, witness_pin)


def _recovery_basis(*, old_governance: str, old_governance_sha256: str,
                    old_root_public: str, old_root_public_sha256: str,
                    charter: str, charter_sha256: str,
                    council_public_keys: tuple[tuple[str, str], ...],
                    anchor_governance: str, anchor_governance_sha256: str,
                    recovered_root_public: str, recovered_root_public_sha256: str,
                    recovery_certificate: str, recovery_certificate_sha256: str,
                    witness_public: str, witness_public_sha256: str,
                    forbidden_signers: tuple[str, ...] = ()) -> tuple[dict, dict, dict, dict, bytes, bytes]:
    old, anchor, charter_doc, council, new_root = rec._basis(
        old_governance=old_governance,
        old_governance_sha256=old_governance_sha256,
        old_root_public=old_root_public,
        old_root_public_sha256=old_root_public_sha256,
        charter=charter, charter_sha256=charter_sha256,
        council_public_keys=council_public_keys,
        new_governance=anchor_governance,
        new_governance_sha256=anchor_governance_sha256,
        new_root_public=recovered_root_public,
        new_root_public_sha256=recovered_root_public_sha256,
        forbidden_signers=forbidden_signers)
    witness_key = _witness(witness_public, witness_public_sha256, old, anchor,
                           council, old_root_public_sha256,
                           recovered_root_public_sha256, forbidden_signers)
    raw, recovery_doc = rec._read(recovery_certificate, rec.MAX_RECOVERY)
    rec._check_pin(raw, recovery_certificate_sha256,
                   'EC270_RECOVERY_CERTIFICATE_PIN_MISMATCH')
    recovery_claim, stage = rec._claim_fields(recovery_doc)
    if stage != rec.QUORUM:
        deny('EC270_ORIGINAL_RECOVERY_QUORUM_INCOMPLETE')
    rec._claim_binding(recovery_claim, old=old, new=anchor,
                       charter=charter_sha256, old_sha=old_governance_sha256,
                       new_sha=anchor_governance_sha256,
                       old_root_pin=old_root_public_sha256,
                       new_root_pin=recovered_root_public_sha256)
    rec._verified_votes(recovery_doc, recovery_claim, stage, council, new_root)
    return old, anchor, charter_doc, council, new_root, witness_key


def _binding(core: dict[str, Any], old: dict, anchor: dict, **basis: Any) -> None:
    expected = {
        'old_governance_sha256': basis['old_governance_sha256'],
        'anchor_governance_sha256': basis['anchor_governance_sha256'],
        'old_root_public_sha256': basis['old_root_public_sha256'],
        'recovered_root_public_sha256': basis['recovered_root_public_sha256'],
        'charter_sha256': basis['charter_sha256'],
        'recovery_certificate_sha256': basis['recovery_certificate_sha256'],
        'witness_public_sha256': basis['witness_public_sha256'],
        'recovered_epoch': anchor['epoch'],
    }
    if old['epoch'] + 1 != anchor['epoch'] or any(
            core[field] != value for field, value in expected.items()):
        deny('EC270_CLOSURE_INDEPENDENT_BASIS_MISMATCH')


def _verify_stage(doc: dict[str, Any], core: dict, stage: int,
                  council: dict[str, bytes], new_root: bytes,
                  witness: bytes, charter: dict, anchor: dict) -> None:
    if stage == -1:
        return
    payload = prov._canonical(core)
    rec._signature(new_root, ROOT_DOMAIN + payload,
                   doc['signature_recovered_root_ed25519'],
                   'EC270_RECOVERED_ROOT_SIGNATURE_INVALID')
    for vote in doc['council_approvals']:
        pin = vote['public_sha256']
        if pin not in council:
            deny('EC270_UNKNOWN_COUNCIL_VOTER')
        rec._signature(council[pin], COUNCIL_DOMAIN + pin.encode('ascii') + b'\x00' + payload,
                       vote['signature_ed25519'], 'EC270_COUNCIL_SIGNATURE_INVALID')
    if stage == 3:
        observed = doc['witness_observed_at_unix']
        if not (charter['not_before_unix'] <= observed < charter['expires_at_unix'] and
                anchor['not_before_unix'] <= observed < anchor['expires_at_unix']):
            deny('EC270_WITNESS_OBSERVATION_OUTSIDE_AUTHORIZED_WINDOW')
        notarized = {key: value for key, value in doc.items()
                     if key != 'signature_witness_ed25519'}
        rec._signature(witness, WITNESS_DOMAIN + prov._canonical(notarized),
                       doc['signature_witness_ed25519'],
                       'EC270_INDEPENDENT_WITNESS_SIGNATURE_INVALID')


def _live(charter: dict[str, Any], anchor: dict[str, Any]) -> None:
    # Only used by offline proposal/signing. Never used to expire historical
    # attestation in the new service; current EC267 policy remains live.
    now = time.time()
    if not charter['not_before_unix'] <= now < charter['expires_at_unix']:
        deny('EC270_CLOSURE_MUST_COMPLETE_BEFORE_CHARTER_EXPIRY')
    if not anchor['not_before_unix'] <= now < anchor['expires_at_unix']:
        deny('EC270_RECOVERY_ANCHOR_MUST_STILL_BE_LIVE_FOR_RATIFICATION')


def prepare_closure(*, output: str, **basis: Any) -> dict[str, Any]:
    """Ratification proposal for exact EC269 recovery anchor N+1 only."""
    old, anchor, charter, council, new_root, witness = _recovery_basis(**basis)
    _live(charter, anchor)
    doc = {
        'schema': SCHEMA, 'purpose': PURPOSE,
        'old_governance_sha256': basis['old_governance_sha256'],
        'anchor_governance_sha256': basis['anchor_governance_sha256'],
        'old_root_public_sha256': basis['old_root_public_sha256'],
        'recovered_root_public_sha256': basis['recovered_root_public_sha256'],
        'charter_sha256': basis['charter_sha256'],
        'recovery_certificate_sha256': basis['recovery_certificate_sha256'],
        'witness_public_sha256': basis['witness_public_sha256'],
        'recovered_epoch': anchor['epoch'], 'nonce': os.urandom(16).hex(),
    }
    core, stage = _fields(doc)
    _binding(core, old, anchor, **basis)
    digest = rec._save(output, doc, 'EC270_NEW_CLOSURE_PROPOSAL_REQUIRED')
    return {'status': 'partial', 'exit_code': 2,
            'closure_proposal_sha256': digest, 'ratification_anchor_epoch': anchor['epoch'],
            'required_signatures': ['recovered-root', 'council-1', 'council-2', 'witness'],
            'charter_expires_at_unix': charter['expires_at_unix'],
            'operator_must_independently_pin_output': True}


def sign_closure(*, input_path: str, input_sha256: str, role: str,
                 signing_key: str, expected_public_sha256: str, output: str,
                 **basis: Any) -> dict[str, Any]:
    """Stage-by-stage immutable files; every signer re-verifies complete history."""
    raw, doc = rec._read(input_path, MAX_DOCUMENT)
    rec._check_pin(raw, input_sha256, 'EC270_SIGNER_PREVIOUS_FILE_PIN_MISMATCH')
    core, stage = _fields(doc)
    old, anchor, charter, council, root, witness = _recovery_basis(**basis)
    _binding(core, old, anchor, **basis)
    _verify_stage(doc, core, stage, council, root, witness, charter, anchor)
    _live(charter, anchor)
    pin = rec._sha(expected_public_sha256)
    if role == 'root' and stage == -1:
        if pin != basis['recovered_root_public_sha256']:
            deny('EC270_WRONG_ROOT_SIGNER')
        signature = rec._sign(signing_key, pin, ROOT_DOMAIN + prov._canonical(core))
        result = {**core, 'signature_recovered_root_ed25519': signature,
                  'council_approvals': []}
        finished = 'recovered-root'
    elif role == 'council' and stage in (0, 1):
        if pin not in council:
            deny('EC270_SIGNER_NOT_IN_PRECOMMITTED_COUNCIL')
        votes = doc['council_approvals']
        if votes and pin <= votes[-1]['public_sha256']:
            deny('EC270_SIGNER_COUNCIL_ORDER_INVALID')
        sig = rec._sign(signing_key, pin, COUNCIL_DOMAIN + pin.encode('ascii') +
                        b'\x00' + prov._canonical(core))
        result = {**doc, 'council_approvals': [*votes,
                  {'public_sha256': pin, 'signature_ed25519': sig}]}
        finished = f'council-{stage+1}'
    elif role == 'witness' and stage == rec.QUORUM:
        if pin != basis['witness_public_sha256']:
            deny('EC270_WRONG_WITNESS_SIGNER')
        # A separately trusted witness observes the *complete* root+council
        # signatures and signs its own measured time with their exact bytes.
        observed = int(time.time())
        if not (charter['not_before_unix'] <= observed < charter['expires_at_unix'] and
                anchor['not_before_unix'] <= observed < anchor['expires_at_unix']):
            deny('EC270_WITNESS_TIME_OUTSIDE_LIVE_WINDOW')
        notarized = {**doc, 'witness_observed_at_unix': observed}
        sig = rec._sign(signing_key, pin,
                        WITNESS_DOMAIN + prov._canonical(notarized))
        result = {**notarized, 'signature_witness_ed25519': sig}
        finished = 'independent-witness'
    else:
        deny('EC270_SIGNING_ORDER_OR_ROLE_INVALID')
    _, final_stage = _fields(result)
    digest = rec._save(output, result, 'EC270_NEW_SIGNED_CLOSURE_STAGE_REQUIRED')
    return {'status': 'partial', 'exit_code': 2,
            'signed_closure_sha256': digest, 'completed_stage': finished,
            'ratification_complete': final_stage == 3,
            'operator_must_independently_pin_output': True}


def verify_closure(*, closure_certificate: str, closure_certificate_sha256: str,
                   **basis: Any) -> dict[str, Any]:
    """Verify historical signatures even AFTER charter and anchor expiry.

    Does not independently certify a trustworthy clock, personnel or storage.
    """
    old, anchor, charter, council, root, witness = _recovery_basis(**basis)
    raw, doc = rec._read(closure_certificate, MAX_DOCUMENT)
    rec._check_pin(raw, closure_certificate_sha256, 'EC270_CLOSURE_CERTIFICATE_PIN_MISMATCH')
    core, stage = _fields(doc)
    _binding(core, old, anchor, **basis)
    if stage != 3:
        deny('EC270_ALL_FOUR_RATIFICATION_SIGNATURES_REQUIRED')
    _verify_stage(doc, core, stage, council, root, witness, charter, anchor)
    return {
        'status': 'partial', 'exit_code': 2,
        'reason_code': 'EC270_RECOVERY_RATIFICATION_SIGNATURES_VERIFIED_NOT_TRUSTED_TIMESTAMP',
        'ratified_recovery_epoch': anchor['epoch'],
        'witness_observed_at_unix': doc['witness_observed_at_unix'],
        'historical_charter_validity_assumed_at_witness_observation': True,
        'real_independent_witness_and_time_verified': False,
        'external_epoch_antireplay_verified': False,
    }


class RatifiedRecoveryGate(rec.EmergencyRecoveryGate):
    """Strict additive host, with charter expiry replaced by signed closure.

    The ordinary EC269 host is not changed. Independent operator pins, minimum
    epoch, minimum witnessed time and a current EC267 24h policy are mandatory.
    """

    def __init__(self, *args: Any, closure_certificate: str,
                 closure_certificate_sha256: str, witness_public: str,
                 witness_public_sha256: str, minimum_witness_observed_at_unix: int,
                 **kwargs: Any):
        self.closure_path = prov._path(closure_certificate)
        self.closure_pin = rec._sha(closure_certificate_sha256)
        self.witness_path = prov._path(witness_public)
        self.witness_pin = rec._sha(witness_public_sha256)
        self.minimum_witness_time = rec._integer(
            minimum_witness_observed_at_unix, 1, 2**40,
            'EC270_INDEPENDENT_WITNESS_TIME_FLOOR_REQUIRED')
        self._closure_seen: dict[str, Any] | None = None
        super().__init__(*args, **kwargs)
        if len(set(self.authority_paths())) != len(self.authority_paths()):
            deny('EC270_AUTHORITY_FILE_COLLISION')

    def authority_paths(self) -> list[str]:
        return [*super().authority_paths(), self.closure_path, self.witness_path]

    def _check_recovery(self) -> None:
        # EC267 already checked CURRENT active governance and source; EC269's
        # original historical logic is reproduced without its live charter
        # check, and augmented by the witness-signed retirement certificate.
        if not self._governance_verified or self._governance_seen is None:
            deny('EC270_CURRENT_GOVERNANCE_MUST_PASS_EC267_FIRST')
        basis = dict(
            old_governance=self.old_governance, old_governance_sha256=self.old_sha,
            old_root_public=self.old_root, old_root_public_sha256=self.old_root_pin,
            charter=self.charter_path, charter_sha256=self.charter_pin,
            council_public_keys=self.council_keys,
            anchor_governance=self.anchor_governance,
            anchor_governance_sha256=self.anchor_pin,
            recovered_root_public=self.governance_public,
            recovered_root_public_sha256=self.governance_public_pin,
            recovery_certificate=self.recovery_path,
            recovery_certificate_sha256=self.recovery_pin,
            witness_public=self.witness_path, witness_public_sha256=self.witness_pin,
            forbidden_signers=tuple(self._forbidden))
        old, anchor, charter, council, root, witness = _recovery_basis(**basis)
        raw, recovery_doc = rec._read(self.recovery_path, rec.MAX_RECOVERY)
        # No historic evidence can be changed by repinning a new live file.
        rec._check_pin(raw, self.recovery_pin, 'EC270_RECOVERY_PIN_MISMATCH')
        if self._recovery_seen is not None and recovery_doc != self._recovery_seen:
            deny('EC270_RECOVERY_CHANGED_DURING_HOST')
        prev, prev_sha = anchor, self.anchor_pin
        entries = self._continuations()
        forbidden_authorities = ({self.old_root_pin, self.governance_public_pin,
                                  self.witness_pin} | set(council) | set(self._forbidden))
        for entry in entries:
            next_doc = rot._signed_governance(
                entry['governance_policy'], entry['governance_policy_sha256'], root)
            rot._transition(prev, next_doc, prev_sha)
            if (forbidden_authorities &
                    (set(next_doc['role_public_sha256'].values()) |
                     set(next_doc['revoked_public_sha256']))):
                deny('EC270_CONTINUATION_REVOKED_RATIFYING_AUTHORITY')
            prev, prev_sha = next_doc, entry['governance_policy_sha256']
        if entries and (entries[-1]['governance_policy'] != self.governance_policy or
                        prev_sha != self.governance_policy_pin):
            deny('EC270_CONTINUATION_CURRENT_PIN_MISMATCH')
        if prev != self._governance_seen:
            deny('EC270_CURRENT_GOVERNANCE_CHANGED')
        if (self._governance_seen['epoch'] < anchor['epoch'] or
                self.minimum_epoch < anchor['epoch']):
            deny('EC270_OPERATOR_EPOCH_FLOOR_BELOW_RECOVERY')
        if forbidden_authorities & set(self._governance_seen['revoked_public_sha256']):
            deny('EC270_CURRENT_GOVERNANCE_REVOKES_RATIFYING_AUTHORITY')
        # Verify the closure after all history and current chain checks. The
        # final witness attested to a moment inside BOTH historic validity
        # windows. Current service only requires its own live EC267 window.
        signed_raw, doc = rec._read(self.closure_path, MAX_DOCUMENT)
        rec._check_pin(signed_raw, self.closure_pin,
                       'EC270_CLOSURE_CERTIFICATE_PIN_MISMATCH')
        core, stage = _fields(doc)
        _binding(core, old, anchor, **basis)
        if stage != 3:
            deny('EC270_CLOSURE_INCOMPLETE')
        _verify_stage(doc, core, stage, council, root, witness, charter, anchor)
        if doc['witness_observed_at_unix'] < self.minimum_witness_time:
            deny('EC270_OPERATOR_WITNESS_TIME_FLOOR_NOT_MET')
        if self._clock_anchor is None:
            deny('EC270_PARENT_GOVERNANCE_CLOCK_ANCHOR_MISSING')
        wall, mono = gov._now()
        anchored_wall, anchored_mono = self._clock_anchor
        current_effective = max(wall, anchored_wall + mono - anchored_mono,
                                self._max_wall_seen or 0.0)
        if doc['witness_observed_at_unix'] > current_effective:
            deny('EC270_WITNESS_ATTESTATION_FROM_FUTURE')
        if self._closure_seen is not None and doc != self._closure_seen:
            deny('EC270_CLOSURE_CHANGED_DURING_HOST')
        self._recovery_seen = recovery_doc
        self._closure_seen = doc

    def summary(self) -> dict[str, Any]:
        if self._closure_seen is None:
            deny('EC270_CLOSURE_NOT_VERIFIED')
        result = gov.GovernedSourceGate.summary(self)
        result.update({
            'reason_code': 'EC270_RECOVERY_CLOSED_UNDER_INDEPENDENT_WITNESS_ASSERTION',
            'old_epoch': self._recovery_seen['old_epoch'],
            'ratified_recovery_epoch': self._closure_seen['recovered_epoch'],
            'closure_witness_observed_at_unix': self._closure_seen['witness_observed_at_unix'],
            'closure_root_and_council_signatures_verified': 3,
            'closure_independent_witness_signature_verified': True,
            'recovery_charter_live_expiry_required': False,
            'new_root_continuation_epochs': len(self._continuations()),
            'trusted_external_witness_time_verified': False,
            'trusted_external_epoch_floor_verified': False,
            'root_loss_and_real_personnel_verified': False,
        })
        return result
