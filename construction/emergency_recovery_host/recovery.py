#!/usr/bin/env python3
"""EC269: old-root-loss recovery with *precommitted* two-of-three council consent.

The OLD root must have signed the recovery charter while it was available;
emergency activation then needs the NEW root's signature and two distinct
charter-listed council signatures. A recovered epoch N+1 has a real EC267
new-root-signed document linked to old epoch N, including all revocations.
The original EC267 current-time/source/issuer and EC265 custody gates remain.
Neither loss of the old root nor independence of people can be proven here.
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

CHARTER_SCHEMA = 'ces.ec269.old_root_precommitted_recovery_charter.v1'
RECOVERY_SCHEMA = 'ces.ec269.quorum_root_recovery_certificate.v1'
CHARTER_DOMAIN = b'CES/EC269/old-root-recovery-charter/v1\x00'
CLAIM_DOMAIN = b'CES/EC269/emergency-root-claim/v1\x00'
NEW_DOMAIN = CLAIM_DOMAIN + b'new-root\x00'
COUNCIL_DOMAIN = CLAIM_DOMAIN + b'council\x00'
CHARTER_FIELDS = frozenset({
    'schema', 'old_governance_sha256', 'old_root_public_sha256',
    'old_epoch', 'council_public_sha256', 'required_approvals',
    'issued_at_unix', 'not_before_unix', 'expires_at_unix', 'nonce',
})
CLAIM_FIELDS = frozenset({
    'schema', 'charter_sha256', 'old_governance_sha256',
    'new_governance_sha256', 'old_root_public_sha256',
    'new_root_public_sha256', 'old_epoch', 'new_epoch',
    'incident', 'nonce',
})
APPROVAL_FIELDS = frozenset({'public_sha256', 'signature_ed25519'})
MAX_CHARTER = 4096
MAX_RECOVERY = 4096
MAX_CHARTER_LIFETIME = 90 * 24 * 3600
COUNCIL_COUNT = 3
QUORUM = 2
INCIDENT = 'OLD_ROOT_PRIVATE_KEY_UNAVAILABLE_SELF_DECLARED'


class RecoveryError(rot.HandoverError):
    """Fail closed with a fixed, non-secret diagnostic code."""


def deny(code: str) -> None:
    raise RecoveryError(code)


def _sha(value: Any) -> str:
    if type(value) is not str or cp.SHA_RE.fullmatch(value) is None:
        deny('EC269_SHA256_INVALID')
    return value


def _integer(value: Any, minimum: int, maximum: int, code: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        deny(code)
    return value


def _read(path: str, maximum: int) -> tuple[bytes, dict[str, Any]]:
    try:
        raw, doc = prov._parse(path, maximum)
    except (prov.ProvenanceError, cp.AnchorError) as exc:
        raise RecoveryError('EC269_PRIVATE_CANONICAL_DOCUMENT_REQUIRED') from exc
    if type(doc) is not dict:
        deny('EC269_DOCUMENT_NOT_OBJECT')
    return raw, doc


def _save(output: str, doc: dict[str, Any], code: str) -> str:
    raw = prov._canonical(doc)
    try:
        prov._new(output, raw)
    except prov.ProvenanceError as exc:
        raise RecoveryError(code) from exc
    return prov._digest(raw)


def _check_pin(raw: bytes, expected: str, code: str) -> None:
    if not hmac.compare_digest(prov._digest(raw), _sha(expected)):
        deny(code)


def _public(path: str, pin: str) -> bytes:
    try:
        return rot._read_public(path, _sha(pin))
    except (rot.HandoverError, prov.ProvenanceError) as exc:
        raise RecoveryError('EC269_PUBLIC_KEY_OR_PIN_INVALID') from exc


def _signature(pub: bytes, msg: bytes, sig: str, code: str) -> None:
    if type(sig) is not str or prov.SIGNATURE_RE.fullmatch(sig) is None:
        deny(code)
    try:
        cp.Ed25519PublicKey.from_public_bytes(pub).verify(bytes.fromhex(sig), msg)
    except (cp.InvalidSignature, ValueError, TypeError) as exc:
        raise RecoveryError(code) from exc


def _sign(secret_path: str, expected_pin: str, msg: bytes) -> str:
    cp._need_crypto()
    try:
        raw = prov._bytes(secret_path, 32)
    except prov.ProvenanceError as exc:
        raise RecoveryError('EC269_PRIVATE_SIGNER_UNAVAILABLE') from exc
    if len(raw) != 32:
        deny('EC269_PRIVATE_KEY_LENGTH_INVALID')
    try:
        pub = cp.public_bytes_from_signing_key(raw)
        if not hmac.compare_digest(prov._digest(pub), _sha(expected_pin)):
            deny('EC269_PRIVATE_SIGNER_PUBLIC_MISMATCH')
        return cp.Ed25519PrivateKey.from_private_bytes(raw).sign(msg).hex()
    except (ValueError, TypeError) as exc:
        raise RecoveryError('EC269_OFFLINE_SIGNATURE_FAILED') from exc


def _charter_fields(doc: Any, *, signed: bool) -> dict[str, Any]:
    if (type(doc) is not dict or
            set(doc) != CHARTER_FIELDS | ({'signature_old_root_ed25519'} if signed else set()) or
            doc.get('schema') != CHARTER_SCHEMA):
        deny('EC269_CHARTER_SCHEMA_INVALID')
    _sha(doc['old_governance_sha256'])
    _sha(doc['old_root_public_sha256'])
    _integer(doc['old_epoch'], 1, 2**31-2, 'EC269_CHARTER_EPOCH_INVALID')
    council = doc['council_public_sha256']
    if (type(council) is not list or len(council) != COUNCIL_COUNT or
            any(type(pin) is not str or cp.SHA_RE.fullmatch(pin) is None for pin in council) or
            council != sorted(set(council)) or doc['old_root_public_sha256'] in council):
        deny('EC269_CHARTER_COUNCIL_INVALID')
    if type(doc['required_approvals']) is not int or doc['required_approvals'] != QUORUM:
        deny('EC269_CHARTER_QUORUM_MUST_BE_TWO_OF_THREE')
    issued = _integer(doc['issued_at_unix'], 1, 2**40, 'EC269_CHARTER_TIME_INVALID')
    start = _integer(doc['not_before_unix'], 1, 2**40, 'EC269_CHARTER_TIME_INVALID')
    stop = _integer(doc['expires_at_unix'], 1, 2**40, 'EC269_CHARTER_TIME_INVALID')
    if not issued <= start < stop <= issued + MAX_CHARTER_LIFETIME:
        deny('EC269_CHARTER_VALIDITY_WINDOW_INVALID')
    if type(doc['nonce']) is not str or cp.NONCE_RE.fullmatch(doc['nonce']) is None:
        deny('EC269_CHARTER_NONCE_INVALID')
    if signed and (type(doc['signature_old_root_ed25519']) is not str or
                   prov.SIGNATURE_RE.fullmatch(doc['signature_old_root_ed25519']) is None):
        deny('EC269_CHARTER_SIGNATURE_ENCODING_INVALID')
    return {field: doc[field] for field in CHARTER_FIELDS}


def _council_keys(keys: tuple[tuple[str, str], ...] | list[tuple[str, str]]) -> dict[str, bytes]:
    if type(keys) not in (tuple, list) or len(keys) != COUNCIL_COUNT:
        deny('EC269_THREE_COUNCIL_PUBLIC_KEYS_REQUIRED')
    result: dict[str, bytes] = {}
    paths = []
    for path, pin in keys:
        pin = _sha(pin)
        pathname = prov._path(path)
        if pin in result or pathname in paths:
            deny('EC269_COUNCIL_KEY_REUSED')
        paths.append(pathname)
        result[pin] = _public(pathname, pin)
    return result


def _historic(old_governance: str, old_sha: str, old_public: str,
              old_public_sha: str) -> dict[str, Any]:
    return rot._signed_governance(old_governance, _sha(old_sha),
                                  _public(old_public, old_public_sha))


def _signed_charter(path: str, expected_sha: str,
                    old: dict[str, Any], old_sha: str,
                    old_root: bytes, old_root_pin: str,
                    council: dict[str, bytes]) -> dict[str, Any]:
    raw, doc = _read(path, MAX_CHARTER)
    _check_pin(raw, expected_sha, 'EC269_CHARTER_PIN_MISMATCH')
    unsigned = _charter_fields(doc, signed=True)
    if (doc['old_governance_sha256'] != _sha(old_sha) or
            doc['old_root_public_sha256'] != _sha(old_root_pin) or
            doc['old_epoch'] != old['epoch'] or
            doc['council_public_sha256'] != sorted(council)):
        deny('EC269_CHARTER_EXTERNAL_AUTHORITY_BINDING_MISMATCH')
    if not old['not_before_unix'] <= doc['issued_at_unix'] < old['expires_at_unix']:
        deny('EC269_CHARTER_NOT_PREAUTHORIZED_IN_OLD_EPOCH')
    _signature(old_root, CHARTER_DOMAIN + prov._canonical(unsigned),
               doc['signature_old_root_ed25519'],
               'EC269_OLD_ROOT_CHARTER_SIGNATURE_INVALID')
    return doc


def _basis(*, old_governance: str, old_governance_sha256: str,
           old_root_public: str, old_root_public_sha256: str,
           charter: str, charter_sha256: str,
           council_public_keys: tuple[tuple[str, str], ...] | list[tuple[str, str]],
           new_governance: str, new_governance_sha256: str,
           new_root_public: str, new_root_public_sha256: str,
           forbidden_signers: tuple[str, ...] = ()) -> tuple[dict[str, Any], dict[str, Any],
                                                             dict[str, Any], dict[str, bytes], bytes]:
    cp._need_crypto()
    old_pin, new_pin = _sha(old_root_public_sha256), _sha(new_root_public_sha256)
    if old_pin == new_pin:
        deny('EC269_RECOVERY_MUST_ROTATE_GOVERNANCE_ROOT')
    old_root = _public(old_root_public, old_pin)
    new_root = _public(new_root_public, new_pin)
    council = _council_keys(council_public_keys)
    old = rot._signed_governance(old_governance, old_governance_sha256, old_root)
    new = rot._signed_governance(new_governance, new_governance_sha256, new_root)
    rot._transition(old, new, _sha(old_governance_sha256))
    forbidden = set(_sha(x) for x in forbidden_signers)
    issuer_pins = set(old['role_public_sha256'].values()) | set(new['role_public_sha256'].values())
    if ({old_pin, new_pin} | set(council)) & (issuer_pins | forbidden):
        deny('EC269_AUTHORITIES_NOT_INDEPENDENT_OF_ISSUERS_OR_AUDIT')
    if ({old_pin, new_pin} | set(council)) & (
            set(old['revoked_public_sha256']) | set(new['revoked_public_sha256'])):
        deny('EC269_RECOVERY_AUTHORITY_PREVIOUSLY_REVOKED')
    if ({old_pin, new_pin} & set(council)):
        deny('EC269_ROOT_REUSED_AS_COUNCIL_MEMBER')
    charter_doc = _signed_charter(charter, charter_sha256, old,
                                  old_governance_sha256, old_root, old_pin, council)
    return old, new, charter_doc, council, new_root


def prepare_charter(*, old_governance: str, old_governance_sha256: str,
                    old_root_public: str, old_root_public_sha256: str,
                    council_public_keys: tuple[tuple[str, str], ...],
                    expires_at_unix: int, output: str,
                    issued_at_unix: int | None = None) -> dict[str, Any]:
    """Old-root preauthorization, MUST be performed before loss of old secret."""
    cp._need_crypto()
    old = _historic(old_governance, old_governance_sha256,
                    old_root_public, old_root_public_sha256)
    council = _council_keys(council_public_keys)
    if (set(council) | {_sha(old_root_public_sha256)}) & (
            set(old['role_public_sha256'].values()) | set(old['revoked_public_sha256'])):
        deny('EC269_CHARTER_COUNCIL_REVOKED_OR_SOURCE_SIGNER')
    issued = int(time.time()) if issued_at_unix is None else issued_at_unix
    doc = {
        'schema': CHARTER_SCHEMA, 'old_governance_sha256': _sha(old_governance_sha256),
        'old_root_public_sha256': _sha(old_root_public_sha256),
        'old_epoch': old['epoch'], 'council_public_sha256': sorted(council),
        'required_approvals': QUORUM, 'issued_at_unix': issued,
        'not_before_unix': issued, 'expires_at_unix': expires_at_unix,
        'nonce': os.urandom(16).hex(),
    }
    _charter_fields(doc, signed=False)
    if not old['not_before_unix'] <= issued < old['expires_at_unix']:
        deny('EC269_CHARTER_NOT_PREAUTHORIZED_IN_OLD_EPOCH')
    result = _save(output, doc, 'EC269_NEW_CHARTER_PROPOSAL_REQUIRED')
    return {'status': 'partial', 'exit_code': 2, 'charter_proposal_sha256': result,
            'requires_old_root_offline_signature_before_root_loss': True,
            'quorum': '2-of-3'}


def sign_charter(*, proposal: str, proposal_sha256: str,
                 old_governance: str, old_governance_sha256: str,
                 old_root_public: str, old_root_public_sha256: str,
                 council_public_keys: tuple[tuple[str, str], ...],
                 old_root_private: str, output: str) -> dict[str, Any]:
    """Old root signs fully independently pinned charter; never writes in place."""
    cp._need_crypto()
    raw, doc = _read(proposal, MAX_CHARTER)
    _check_pin(raw, proposal_sha256, 'EC269_CHARTER_PROPOSAL_PIN_MISMATCH')
    unsigned = _charter_fields(doc, signed=False)
    old = _historic(old_governance, old_governance_sha256,
                    old_root_public, old_root_public_sha256)
    council = _council_keys(council_public_keys)
    if (unsigned['old_governance_sha256'] != _sha(old_governance_sha256) or
            unsigned['old_root_public_sha256'] != _sha(old_root_public_sha256) or
            unsigned['old_epoch'] != old['epoch'] or
            unsigned['council_public_sha256'] != sorted(council)):
        deny('EC269_CHARTER_EXTERNAL_AUTHORITY_BINDING_MISMATCH')
    if not old['not_before_unix'] <= unsigned['issued_at_unix'] < old['expires_at_unix']:
        deny('EC269_CHARTER_NOT_PREAUTHORIZED_IN_OLD_EPOCH')
    now = time.time()
    if not old['not_before_unix'] <= now < old['expires_at_unix']:
        deny('EC269_OLD_ROOT_CHARTER_SIGNING_TIME_NOT_CURRENT')
    if not unsigned['not_before_unix'] <= now < unsigned['expires_at_unix']:
        deny('EC269_CHARTER_SIGNING_WINDOW_NOT_CURRENT')
    if (set(council) | {_sha(old_root_public_sha256)}) & (
            set(old['role_public_sha256'].values()) | set(old['revoked_public_sha256'])):
        deny('EC269_CHARTER_COUNCIL_REVOKED_OR_SOURCE_SIGNER')
    sig = _sign(old_root_private, old_root_public_sha256,
                CHARTER_DOMAIN + prov._canonical(unsigned))
    result = _save(output, {**unsigned, 'signature_old_root_ed25519': sig},
                   'EC269_NEW_SIGNED_CHARTER_REQUIRED')
    return {'status': 'partial', 'exit_code': 2, 'signed_charter_sha256': result,
            'old_root_can_be_offline_for_later_recovery': True}


def _claim_fields(doc: Any) -> tuple[dict[str, Any], int]:
    if type(doc) is not dict or doc.get('schema') != RECOVERY_SCHEMA:
        deny('EC269_RECOVERY_SCHEMA_INVALID')
    if set(doc) == CLAIM_FIELDS:
        stage = -1
    elif set(doc) == CLAIM_FIELDS | {'signature_new_root_ed25519', 'council_approvals'}:
        approvals = doc['council_approvals']
        if type(approvals) is not list or not 0 <= len(approvals) <= QUORUM:
            deny('EC269_RECOVERY_APPROVALS_INVALID')
        stage = len(approvals)
        if (type(doc['signature_new_root_ed25519']) is not str or
                prov.SIGNATURE_RE.fullmatch(doc['signature_new_root_ed25519']) is None):
            deny('EC269_RECOVERY_NEW_ROOT_SIGNATURE_ENCODING_INVALID')
        pins = []
        for a in approvals:
            if (type(a) is not dict or set(a) != APPROVAL_FIELDS or
                    type(a['public_sha256']) is not str or
                    cp.SHA_RE.fullmatch(a['public_sha256']) is None or
                    type(a['signature_ed25519']) is not str or
                    prov.SIGNATURE_RE.fullmatch(a['signature_ed25519']) is None):
                deny('EC269_RECOVERY_APPROVAL_ENCODING_INVALID')
            pins.append(a['public_sha256'])
        if pins != sorted(set(pins)):
            deny('EC269_RECOVERY_COUNCIL_APPROVAL_DUPLICATE_OR_UNSORTED')
    else:
        deny('EC269_RECOVERY_FIELDS_OR_STAGE_INVALID')
    for field in ('charter_sha256', 'old_governance_sha256',
                  'new_governance_sha256', 'old_root_public_sha256',
                  'new_root_public_sha256'):
        _sha(doc[field])
    for field in ('old_epoch', 'new_epoch'):
        _integer(doc[field], 1, 2**31-1, 'EC269_RECOVERY_EPOCH_INVALID')
    if doc['new_epoch'] != doc['old_epoch'] + 1:
        deny('EC269_RECOVERY_EPOCH_NOT_CONTIGUOUS')
    if doc['incident'] != INCIDENT:
        deny('EC269_RECOVERY_INCIDENT_MUST_BE_SELF_DECLARED')
    if type(doc['nonce']) is not str or cp.NONCE_RE.fullmatch(doc['nonce']) is None:
        deny('EC269_RECOVERY_NONCE_INVALID')
    return {key: doc[key] for key in CLAIM_FIELDS}, stage


def _claim_binding(core: dict[str, Any], *,
                   old: dict[str, Any], new: dict[str, Any],
                   charter: str, old_sha: str, new_sha: str,
                   old_root_pin: str, new_root_pin: str) -> None:
    expected = {
        'charter_sha256': _sha(charter),
        'old_governance_sha256': _sha(old_sha),
        'new_governance_sha256': _sha(new_sha),
        'old_root_public_sha256': _sha(old_root_pin),
        'new_root_public_sha256': _sha(new_root_pin),
        'old_epoch': old['epoch'], 'new_epoch': new['epoch'],
    }
    if any(core[key] != value for key, value in expected.items()):
        deny('EC269_RECOVERY_INDEPENDENT_BINDING_MISMATCH')


def _verified_votes(doc: dict[str, Any], core: dict[str, Any], stage: int,
                    council: dict[str, bytes], new_root: bytes) -> None:
    if stage < 0:
        return
    payload = prov._canonical(core)
    _signature(new_root, NEW_DOMAIN + payload, doc['signature_new_root_ed25519'],
               'EC269_NEW_ROOT_POSSESSION_SIGNATURE_INVALID')
    for vote in doc['council_approvals']:
        pin = vote['public_sha256']
        if pin not in council:
            deny('EC269_RECOVERY_UNKNOWN_COUNCIL_VOTER')
        _signature(council[pin], COUNCIL_DOMAIN + pin.encode('ascii') + b'\x00' + payload,
                   vote['signature_ed25519'], 'EC269_COUNCIL_APPROVAL_SIGNATURE_INVALID')


def _offline_window(charter: dict[str, Any], new_policy: dict[str, Any]) -> None:
    # A developer host clock is NOT a trusted witness; runtime still verifies
    # and an operator must independently review all stated times and hashes.
    now = time.time()
    if not charter['not_before_unix'] <= now < charter['expires_at_unix']:
        deny('EC269_OFFLINE_RECOVERY_CHARTER_NOT_CURRENT')
    if not new_policy['not_before_unix'] <= now < new_policy['expires_at_unix']:
        deny('EC269_OFFLINE_NEW_GOVERNANCE_NOT_CURRENT')


def prepare_recovery(*, output: str, **basis: Any) -> dict[str, Any]:
    """Create proposal only after validating both governments + signed charter."""
    old, new, charter, _, _ = _basis(**basis)
    _offline_window(charter, new)
    doc = {
        'schema': RECOVERY_SCHEMA, 'charter_sha256': _sha(basis['charter_sha256']),
        'old_governance_sha256': _sha(basis['old_governance_sha256']),
        'new_governance_sha256': _sha(basis['new_governance_sha256']),
        'old_root_public_sha256': _sha(basis['old_root_public_sha256']),
        'new_root_public_sha256': _sha(basis['new_root_public_sha256']),
        'old_epoch': old['epoch'], 'new_epoch': new['epoch'],
        'incident': INCIDENT, 'nonce': os.urandom(16).hex(),
    }
    _claim_fields(doc)
    digest = _save(output, doc, 'EC269_NEW_RECOVERY_PROPOSAL_REQUIRED')
    return {'status': 'partial', 'exit_code': 2,
            'recovery_proposal_sha256': digest,
            'required_new_root_signature': True,
            'required_independent_council_signatures': QUORUM,
            'charter_expires_at_unix': charter['expires_at_unix'],
            'old_root_signature_not_required_at_recovery_time': True}


def sign_recovery(*, input_path: str, input_sha256: str, role: str,
                  signing_key: str, expected_public_sha256: str, output: str,
                  **basis: Any) -> dict[str, Any]:
    """Ordered new-root -> ascending council-approval stages with full pins.

    Every signer independently supplies the complete signed charter and old/new
    documents, all four public authorities, and the digest of the input file.
    """
    cp._need_crypto()
    raw, doc = _read(input_path, MAX_RECOVERY)
    _check_pin(raw, input_sha256, 'EC269_RECOVERY_SIGNER_INPUT_PIN_MISMATCH')
    core, stage = _claim_fields(doc)
    old, new, _charter, council, new_root = _basis(**basis)
    _offline_window(_charter, new)
    _claim_binding(core, old=old, new=new, charter=basis['charter_sha256'],
                   old_sha=basis['old_governance_sha256'],
                   new_sha=basis['new_governance_sha256'],
                   old_root_pin=basis['old_root_public_sha256'],
                   new_root_pin=basis['new_root_public_sha256'])
    _verified_votes(doc, core, stage, council, new_root)
    pin = _sha(expected_public_sha256)
    if role == 'new' and stage == -1:
        if pin != basis['new_root_public_sha256']:
            deny('EC269_NEW_ROOT_SIGNER_PIN_MISMATCH')
        signature = _sign(signing_key, pin, NEW_DOMAIN + prov._canonical(core))
        result = {**core, 'signature_new_root_ed25519': signature,
                  'council_approvals': []}
        completed = 'new-root'
    elif role == 'council' and stage in (0, 1):
        if pin not in council:
            deny('EC269_SIGNER_NOT_PRECOMMITTED_COUNCIL')
        votes = doc['council_approvals']
        if votes and pin <= votes[-1]['public_sha256']:
            deny('EC269_APPROVALS_MUST_USE_UNIQUE_ASCENDING_COUNCIL_PINS')
        signature = _sign(signing_key, pin, COUNCIL_DOMAIN + pin.encode('ascii') +
                          b'\x00' + prov._canonical(core))
        result = {**doc, 'council_approvals': [
            *votes, {'public_sha256': pin, 'signature_ed25519': signature}]}
        completed = f'council-{stage+1}'
    else:
        deny('EC269_SIGNING_STAGE_OR_ROLE_INVALID')
    _, new_stage = _claim_fields(result)
    digest = _save(output, result, 'EC269_NEW_SIGNED_STAGE_FILE_REQUIRED')
    return {'status': 'partial', 'exit_code': 2, 'signed_recovery_sha256': digest,
            'completed_stage': completed, 'quorum_complete': new_stage == QUORUM,
            'operator_must_independently_pin_output': True}


class EmergencyRecoveryGate(gov.GovernedSourceGate):
    """Additional mandatory recovery chain over *existing* EC267+EC266 admission."""

    def __init__(self, policy_path: str, repo: str, allowlist: str,
                 receipt: str, profile_id: str, provenance_gate: str,
                 provenance_gate_sha256: str, governance_policy: str,
                 governance_policy_sha256: str, governance_public: str,
                 governance_public_sha256: str, *, minimum_epoch: int,
                 expected_previous_governance_sha256: str,
                 old_governance: str, old_governance_sha256: str,
                 old_root_public: str, old_root_public_sha256: str,
                 charter: str, charter_sha256: str,
                 council_public_keys: tuple[tuple[str, str], ...],
                 recovery_certificate: str, recovery_certificate_sha256: str,
                 anchor_governance: str | None = None,
                 anchor_governance_sha256: str | None = None,
                 continuation_chain: str | None = None,
                 continuation_chain_sha256: str | None = None,
                 forbidden_signers: tuple[str, ...] = ()):
        super().__init__(policy_path, repo, allowlist, receipt, profile_id,
                         provenance_gate, provenance_gate_sha256,
                         governance_policy, governance_policy_sha256,
                         governance_public, governance_public_sha256,
                         minimum_epoch=minimum_epoch,
                         expected_previous_governance_sha256=expected_previous_governance_sha256,
                         forbidden_signers=forbidden_signers)
        self.old_governance = prov._path(old_governance)
        self.old_sha = _sha(old_governance_sha256)
        self.old_root = prov._path(old_root_public)
        self.old_root_pin = _sha(old_root_public_sha256)
        self.charter_path = prov._path(charter)
        self.charter_pin = _sha(charter_sha256)
        self.council_keys = tuple((prov._path(path), _sha(pin))
                                  for path, pin in council_public_keys)
        self.recovery_path = prov._path(recovery_certificate)
        self.recovery_pin = _sha(recovery_certificate_sha256)
        if (anchor_governance is None) != (anchor_governance_sha256 is None):
            deny('EC269_ANCHOR_PATH_AND_SHA_REQUIRED_TOGETHER')
        self.anchor_governance = (prov._path(anchor_governance) if
                                  anchor_governance is not None else self.governance_policy)
        self.anchor_pin = (_sha(anchor_governance_sha256) if
                           anchor_governance_sha256 is not None else self.governance_policy_pin)
        if (continuation_chain is None) != (continuation_chain_sha256 is None):
            deny('EC269_CONTINUATION_PATH_AND_SHA_REQUIRED_TOGETHER')
        self.continuation_chain = (prov._path(continuation_chain) if
                                   continuation_chain is not None else None)
        self.continuation_pin = (_sha(continuation_chain_sha256) if
                                 continuation_chain_sha256 is not None else None)
        if ((self.anchor_governance != self.governance_policy or
             self.anchor_pin != self.governance_policy_pin) !=
                (self.continuation_chain is not None)):
            deny('EC269_CONTINUATION_CHAIN_REQUIRED_FOR_LATER_EPOCHS')
        entries = self._continuations()
        preceding = (entries[-2]['governance_policy_sha256'] if len(entries) > 1 else
                     self.anchor_pin) if entries else self.old_sha
        if self.expected_previous != preceding:
            deny('EC269_EXTERNAL_CURRENT_PREDECESSOR_PIN_MISMATCH')
        if len(set(self.authority_paths())) != len(self.authority_paths()):
            deny('EC269_AUTHORITY_FILE_PATH_COLLISION')
        self._recovery_seen: dict[str, Any] | None = None

    def _continuations(self) -> list[dict[str, str]]:
        return (rot._read_continuation(self.continuation_chain, self.continuation_pin)
                if self.continuation_chain is not None else [])

    def authority_paths(self) -> list[str]:
        paths = [self.governance_policy, self.governance_public, self.old_governance,
                 self.old_root, self.charter_path, self.recovery_path]
        paths.extend(path for path, _ in self.council_keys)
        if self.anchor_governance != self.governance_policy:
            paths.append(self.anchor_governance)
        if self.continuation_chain is not None:
            paths.append(self.continuation_chain)
            paths.extend(entry['governance_policy'] for entry in self._continuations()[:-1])
        return paths

    def _check_recovery(self) -> None:
        if not self._governance_verified or self._governance_seen is None:
            deny('EC269_CURRENT_GOVERNANCE_MUST_PASS_EC267_FIRST')
        old, anchor, charter, council, new_root = _basis(
            old_governance=self.old_governance, old_governance_sha256=self.old_sha,
            old_root_public=self.old_root, old_root_public_sha256=self.old_root_pin,
            charter=self.charter_path, charter_sha256=self.charter_pin,
            council_public_keys=self.council_keys,
            new_governance=self.anchor_governance, new_governance_sha256=self.anchor_pin,
            new_root_public=self.governance_public,
            new_root_public_sha256=self.governance_public_pin,
            forbidden_signers=tuple(self._forbidden))
        raw, doc = _read(self.recovery_path, MAX_RECOVERY)
        _check_pin(raw, self.recovery_pin, 'EC269_RECOVERY_CERTIFICATE_PIN_MISMATCH')
        core, stage = _claim_fields(doc)
        if stage != QUORUM:
            deny('EC269_RECOVERY_QUORUM_INCOMPLETE')
        _claim_binding(core, old=old, new=anchor, charter=self.charter_pin,
                       old_sha=self.old_sha, new_sha=self.anchor_pin,
                       old_root_pin=self.old_root_pin, new_root_pin=self.governance_public_pin)
        _verified_votes(doc, core, stage, council, new_root)

        # Revalidate each new-root-only continuation, including earlier revoked keys.
        latest, prev_sha = anchor, self.anchor_pin
        entries = self._continuations()
        for entry in entries:
            next_doc = rot._signed_governance(
                entry['governance_policy'], entry['governance_policy_sha256'], new_root)
            rot._transition(latest, next_doc, prev_sha)
            signers = set(next_doc['role_public_sha256'].values())
            if ({self.old_root_pin, self.governance_public_pin} |
                    set(council)) & (signers | self._forbidden):
                deny('EC269_LATER_EPOCH_REUSES_RECOVERY_AUTHORITY')
            latest, prev_sha = next_doc, entry['governance_policy_sha256']
        if entries and (entries[-1]['governance_policy'] != self.governance_policy or
                        prev_sha != self.governance_policy_pin):
            deny('EC269_CONTINUATION_CURRENT_PIN_MISMATCH')
        if latest != self._governance_seen:
            deny('EC269_CURRENT_GOVERNANCE_CHANGED')
        # The charter was a time-limited precommitment; a later signed renewal
        # of EC267 policy DOES NOT magically renew or extend it.
        wall, mono = gov._now()
        if self._clock_anchor is None:
            deny('EC269_PARENT_CLOCK_ANCHOR_MISSING')
        anchor_wall, anchor_mono = self._clock_anchor
        effective = max(wall, anchor_wall + mono - anchor_mono,
                        self._max_wall_seen or 0.0)
        if not (charter['not_before_unix'] <= effective < charter['expires_at_unix']):
            deny('EC269_RECOVERY_CHARTER_NOT_CURRENT')
        if self._recovery_seen is not None and doc != self._recovery_seen:
            deny('EC269_RECOVERY_CERT_CHANGED_DURING_SESSION')
        if self._recovery_seen is None:
            self._recovery_seen = doc

    def startup(self, policy: dict[str, Any], policy_sha: str) -> None:
        super().startup(policy, policy_sha)
        self._check_recovery()

    def before_begin(self, policy: dict[str, Any], policy_sha: str,
                     request: dict[str, Any]) -> None:
        super().before_begin(policy, policy_sha, request)
        self._check_recovery()

    def summary(self) -> dict[str, Any]:
        if self._recovery_seen is None:
            deny('EC269_RECOVERY_NOT_VERIFIED')
        result = super().summary()
        result.update({
            'reason_code': 'EC269_PRECOMMITTED_QUORUM_RECOVERY_NOT_EXTERNAL_IDENTITY_PROOF',
            'old_epoch': self._recovery_seen['old_epoch'],
            'recovered_new_root_epoch': self._recovery_seen['new_epoch'],
            'recovery_new_root_possession_signature_verified': True,
            'independent_council_votes_verified': QUORUM,
            'council_total_members': COUNCIL_COUNT,
            'new_root_continuation_epochs': len(self._continuations()),
            'root_loss_verified_externally': False,
            'physical_council_independence_verified': False,
            'trusted_external_clock_verified': False,
            'cross_restart_nonrollback_verified': False,
        })
        return result
