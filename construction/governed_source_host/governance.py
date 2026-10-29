#!/usr/bin/env python3
"""EC267 independently pinned offline issuer governance for EC266 source admission.

An *additional* Ed25519 governance authority signs current role identities,
revocations, immutable source gate, a short admission window and a rotation
sequence. Host reads only its public key. This is neither a live remote
provider audit nor a trusted time service. The operator must independently
raise the minimum epoch and predecessor pin on key rotations; no local file
can guarantee rollback resistance against its own owner without that anchor.
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

POLICY_SCHEMA = 'ces.ec267.source_issuer_governance.v1'
DOMAIN = b'CES/EC267/independent-issuer-governance/v1\x00'
ZERO = '0' * 64
ROLES = prov.ROLES
MAX_POLICY_BYTES = 8192
MAX_REVOKED = 128
MAX_WINDOW_SECONDS = 24 * 3600
MAX_FUTURE_START_SECONDS = 3600
MAX_CLOCK_BACKWARD_SECONDS = 2.0
POLICY_FIELDS = frozenset({
    'schema', 'epoch', 'previous_governance_sha256', 'provenance_gate_sha256',
    'subject_sha256', 'role_public_sha256', 'revoked_public_sha256',
    'issued_at_unix', 'not_before_unix', 'expires_at_unix', 'nonce',
})
SIGNED_FIELDS = POLICY_FIELDS | {'signature_ed25519'}


class GovernanceError(prov.ProvenanceError):
    """Constant error code only; never include private paths or input payloads."""


def deny(code: str) -> None:
    raise GovernanceError(code)


def _sha(value: Any) -> str:
    if type(value) is not str or cp.SHA_RE.fullmatch(value) is None:
        deny('EC267_SHA256_INVALID')
    return value


def _int(value: Any, lower: int, upper: int, code: str) -> int:
    if type(value) is not int or not lower <= value <= upper:
        deny(code)
    return value


def _canonical(obj: dict[str, Any]) -> bytes:
    return prov._canonical(obj)


def _read(path: str) -> tuple[bytes, dict[str, Any]]:
    try:
        return prov._parse(path, MAX_POLICY_BYTES)
    except (prov.ProvenanceError, cp.AnchorError) as exc:
        raise GovernanceError('EC267_PRIVATE_CANONICAL_POLICY_REQUIRED') from exc


def _validate(policy: Any, *, signed: bool) -> None:
    if (type(policy) is not dict or
            set(policy) != (SIGNED_FIELDS if signed else POLICY_FIELDS) or
            policy.get('schema') != POLICY_SCHEMA):
        deny('EC267_POLICY_SCHEMA_INVALID')
    _int(policy['epoch'], 1, 2**31-1, 'EC267_POLICY_EPOCH_INVALID')
    for field in ('previous_governance_sha256', 'provenance_gate_sha256',
                  'subject_sha256'):
        _sha(policy[field])
    if (policy['epoch'] == 1) != (policy['previous_governance_sha256'] == ZERO):
        deny('EC267_PREDECESSOR_EPOCH_INCONSISTENT')
    if (type(policy['nonce']) is not str or
            cp.NONCE_RE.fullmatch(policy['nonce']) is None):
        deny('EC267_NONCE_INVALID')
    current = policy['role_public_sha256']
    if type(current) is not dict or set(current) != set(ROLES):
        deny('EC267_ROLE_COVERAGE_INVALID')
    for key in ROLES:
        _sha(current[key])
    if len(set(current.values())) != len(ROLES):
        deny('EC267_ROLE_KEY_REUSED')
    revoked = policy['revoked_public_sha256']
    if (type(revoked) is not list or len(revoked) > MAX_REVOKED or
            any(type(x) is not str or cp.SHA_RE.fullmatch(x) is None
                for x in revoked) or revoked != sorted(set(revoked))):
        deny('EC267_REVOCATION_LIST_INVALID')
    for field in ('issued_at_unix', 'not_before_unix', 'expires_at_unix'):
        _int(policy[field], 1, 2**40, 'EC267_TIME_FIELDS_INVALID')
    issued, start, stop = (policy[field] for field in
                           ('issued_at_unix', 'not_before_unix', 'expires_at_unix'))
    if (start < issued or start > issued + MAX_FUTURE_START_SECONDS or
            stop <= start or stop - issued > MAX_WINDOW_SECONDS):
        deny('EC267_VALIDITY_WINDOW_INVALID')
    if signed and (type(policy['signature_ed25519']) is not str or
                   prov.SIGNATURE_RE.fullmatch(policy['signature_ed25519']) is None):
        deny('EC267_SIGNATURE_ENCODING_INVALID')


def _ec266_pins(gate_path: str, gate_sha256: str) -> tuple[str, dict[str, str]]:
    try:
        raw, data = prov._parse(gate_path, prov.MAX_GATE)
    except (prov.ProvenanceError, cp.AnchorError) as exc:
        raise GovernanceError('EC267_EC266_GATE_UNREADABLE') from exc
    if not hmac.compare_digest(prov._digest(raw), _sha(gate_sha256)):
        deny('EC267_EC266_GATE_PIN_MISMATCH')
    if (set(data) != prov.GATE_FIELDS or data.get('schema') != prov.GATE_SCHEMA or
            type(data.get('authorities')) is not list or
            len(data['authorities']) != len(ROLES)):
        deny('EC267_EC266_GATE_FIELDS_INVALID')
    subject = _sha(data['subject_sha256'])
    identities: dict[str, str] = {}
    for role, item in zip(ROLES, data['authorities']):
        if (type(item) is not dict or set(item) != prov.AUTH_FIELDS or
                item.get('role') != role):
            deny('EC267_EC266_ROLE_ORDER_INVALID')
        identities[role] = _sha(item['public_sha256'])
    if len(set(identities.values())) != len(ROLES):
        deny('EC267_EC266_ROLE_KEY_REUSED')
    return subject, identities


def prepare_policy(provenance_gate: str, provenance_gate_sha256: str, *,
                   epoch: int, previous_governance_sha256: str,
                   not_before_unix: int, expires_at_unix: int,
                   revoked_public_sha256: tuple[str, ...], output: str,
                   issued_at_unix: int | None = None) -> dict[str, Any]:
    """New unsigned proposal; does NOT make or validate a revocation decision."""
    subject, identities = _ec266_pins(provenance_gate, provenance_gate_sha256)
    if issued_at_unix is None:
        issued_at_unix = int(time.time())
    proposal = {
        'schema': POLICY_SCHEMA, 'epoch': epoch,
        'previous_governance_sha256': previous_governance_sha256,
        'provenance_gate_sha256': provenance_gate_sha256,
        'subject_sha256': subject, 'role_public_sha256': identities,
        'revoked_public_sha256': sorted(revoked_public_sha256),
        'issued_at_unix': issued_at_unix,
        'not_before_unix': not_before_unix, 'expires_at_unix': expires_at_unix,
        'nonce': os.urandom(16).hex(),
    }
    _validate(proposal, signed=False)
    raw = _canonical(proposal)
    try:
        prov._new(output, raw)
    except prov.ProvenanceError as exc:
        raise GovernanceError('EC267_NEW_PROPOSAL_FILE_REQUIRED') from exc
    return {'status': 'partial', 'exit_code': 2,
            'proposal_sha256': prov._digest(raw), 'epoch': epoch,
            'requires_independent_offline_governance_issuer': True,
            'actual_remote_authority_or_trusted_time_verified': False}


def sign_offline(proposal: str, proposal_sha256: str, signing_key: str,
                 expected_governance_public_sha256: str, output: str) -> dict[str, Any]:
    """Sign a separately reviewed proposal with a FOURTH, off-host authority."""
    cp._need_crypto()
    raw, unsigned = _read(proposal)
    _validate(unsigned, signed=False)
    if not hmac.compare_digest(prov._digest(raw), _sha(proposal_sha256)):
        deny('EC267_PROPOSAL_PIN_MISMATCH')
    key = prov._bytes(signing_key, 32)
    if len(key) != 32:
        deny('EC267_SIGNING_KEY_LENGTH_INVALID')
    try:
        public = cp.public_bytes_from_signing_key(key)
        if not hmac.compare_digest(prov._digest(public),
                                   _sha(expected_governance_public_sha256)):
            deny('EC267_SIGNER_PUBLIC_PIN_MISMATCH')
        signature = cp.Ed25519PrivateKey.from_private_bytes(key).sign(
            DOMAIN + _canonical(unsigned))
    except (ValueError, TypeError) as exc:
        raise GovernanceError('EC267_OFFLINE_SIGNING_FAILED') from exc
    signed_doc = {**unsigned, 'signature_ed25519': signature.hex()}
    _validate(signed_doc, signed=True)
    signed_raw = _canonical(signed_doc)
    try:
        prov._new(output, signed_raw)
    except prov.ProvenanceError as exc:
        raise GovernanceError('EC267_NEW_SIGNED_POLICY_REQUIRED') from exc
    return {'status': 'partial', 'exit_code': 2,
            'governance_sha256': prov._digest(signed_raw),
            'governance_public_sha256': prov._digest(public),
            'epoch': signed_doc['epoch'],
            'source_origin_review_ci_fact_verified': False}


def _now() -> tuple[float, float]:
    return time.time_ns()/1e9, time.monotonic_ns()/1e9


class GovernedSourceGate(prov.SignedSourceGate):
    """Opt-in *additive* root-signed key revocation + epoch + expiry gate.

    Never substitutes for EC266's three signatures or any earlier host policy.
    The independent epoch floor/predecessor is supplied by the operator,
    not copied from the governance document being authenticated.
    """

    def __init__(self, policy_path: str, repo: str, allowlist: str,
                 receipt: str, profile_id: str, provenance_gate: str,
                 provenance_gate_sha256: str, governance_policy: str,
                 governance_policy_sha256: str, governance_public: str,
                 governance_public_sha256: str, *, minimum_epoch: int,
                 expected_previous_governance_sha256: str = ZERO,
                 forbidden_signers: tuple[str, ...] = ()):
        super().__init__(policy_path, repo, allowlist, receipt, profile_id,
                         provenance_gate, provenance_gate_sha256,
                         forbidden_signers=forbidden_signers)
        self.governance_policy = prov._path(governance_policy)
        self.governance_policy_pin = _sha(governance_policy_sha256)
        self.governance_public = prov._path(governance_public)
        self.governance_public_pin = _sha(governance_public_sha256)
        self.minimum_epoch = _int(minimum_epoch, 1, 2**31-1,
                                  'EC267_MINIMUM_EPOCH_INVALID')
        self.expected_previous = _sha(expected_previous_governance_sha256)
        if self.governance_public == self.governance_policy:
            deny('EC267_GOVERNANCE_KEY_POLICY_PATH_COLLISION')
        self._governance_seen: dict[str, Any] | None = None
        self._clock_anchor: tuple[float, float] | None = None
        self._max_wall_seen: float | None = None
        self._governance_verified = False

    def authority_paths(self) -> list[str]:
        return [self.governance_policy, self.governance_public]

    def _check_governance(self) -> None:
        cp._need_crypto()
        config = self._config
        if config is None or self._subject is None or not self._verified:
            deny('EC267_SOURCE_GATE_UNVERIFIED')
        # EC266's current three signer identities are authenticated before this
        # method, and this policy also authenticates their immutable digest.
        raw, signed = _read(self.governance_policy)
        if not hmac.compare_digest(prov._digest(raw), self.governance_policy_pin):
            deny('EC267_GOVERNANCE_POLICY_PIN_MISMATCH')
        _validate(signed, signed=True)
        root_key = prov._bytes(self.governance_public, 32)
        if (len(root_key) != 32 or not hmac.compare_digest(
                prov._digest(root_key), self.governance_public_pin)):
            deny('EC267_GOVERNANCE_ROOT_PIN_MISMATCH')
        pins = {item['role']: item['public_sha256']
                for item in config['authorities']}
        if (self.governance_public_pin in set(pins.values()) | self._forbidden):
            deny('EC267_GOVERNANCE_ROOT_NOT_INDEPENDENT')
        if (signed['role_public_sha256'] != pins or
                signed['subject_sha256'] != config['subject_sha256'] or
                signed['provenance_gate_sha256'] != self.gate_pin):
            deny('EC267_SOURCE_OR_ROLE_BINDING_MISMATCH')
        if (signed['epoch'] < self.minimum_epoch or
                signed['previous_governance_sha256'] != self.expected_previous):
            deny('EC267_EPOCH_OR_PREDECESSOR_PIN_MISMATCH')
        if any(v in signed['revoked_public_sha256'] for v in pins.values()):
            deny('EC267_ACTIVE_ISSUER_REVOKED')
        try:
            unsigned = {field: signed[field] for field in POLICY_FIELDS}
            cp.Ed25519PublicKey.from_public_bytes(root_key).verify(
                bytes.fromhex(signed['signature_ed25519']),
                DOMAIN + _canonical(unsigned))
        except (cp.InvalidSignature, ValueError, TypeError) as exc:
            raise GovernanceError('EC267_GOVERNANCE_SIGNATURE_INVALID') from exc
        if self._governance_seen is not None and signed != self._governance_seen:
            deny('EC267_GOVERNANCE_CHANGED_DURING_HOST')
        wall, mono = _now()
        if self._clock_anchor is not None:
            first_wall, first_mono = self._clock_anchor
            if (mono < first_mono or
                    wall + MAX_CLOCK_BACKWARD_SECONDS < first_wall + mono - first_mono or
                    (self._max_wall_seen is not None and
                     wall + MAX_CLOCK_BACKWARD_SECONDS < self._max_wall_seen)):
                deny('EC267_CLOCK_ROLLBACK_DETECTED')
            effective = max(wall, first_wall + mono - first_mono)
        else:
            effective = wall
        if effective < signed['not_before_unix']:
            deny('EC267_GOVERNANCE_NOT_YET_VALID')
        if effective >= signed['expires_at_unix']:
            deny('EC267_GOVERNANCE_EXPIRED')
        if self._clock_anchor is None:
            self._clock_anchor = (wall, mono)
        self._max_wall_seen = max(wall, self._max_wall_seen or wall)
        if self._governance_seen is None:
            self._governance_seen = signed
        self._governance_verified = True

    def startup(self, policy: dict[str, Any], policy_sha: str) -> None:
        super().startup(policy, policy_sha)
        self._check_governance()

    def before_begin(self, policy: dict[str, Any], policy_sha: str,
                     request: dict[str, Any]) -> None:
        super().before_begin(policy, policy_sha, request)
        self._check_governance()

    def summary(self) -> dict[str, Any]:
        if not self._governance_verified or self._governance_seen is None:
            deny('EC267_GOVERNANCE_NOT_VERIFIED')
        prior = super().summary()
        prior.update({
            'governance_epoch': self._governance_seen['epoch'],
            'governance_valid_until_unix': self._governance_seen['expires_at_unix'],
            'signed_revocations_checked': len(self._governance_seen['revoked_public_sha256']),
            'independent_governance_signature_verified': True,
            'trusted_external_time_or_provider_verified': False,
            'durable_cross_restart_epoch_rollback_protected': False,
        })
        return prior
