#!/usr/bin/env python3
"""EC268: cryptographically chained EC267 governance-root handover.

This is a PERMANENT, operator-pinned certificate of a one-epoch transition:
old root + new root + separately pinned witness sign exactly the same content.
The previous signed governance is validated as historical evidence, *without*
asserting its wall-clock window still holds. The current governance must pass
ALL original EC267 checks, including its short validity window and source gate.

Does not supply remote signer identity, trusted time, unforgeable epoch storage,
or emergency recovery when the old signing private key is unavailable.
"""
from __future__ import annotations

import hmac
import os
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec263_offline_anchor_host import checkpoint as cp
from ec266_source_provenance_host import provenance as prov
from ec267_governed_source_host import governance as gov

SCHEMA = 'ces.ec268.three_party_governance_root_handover.v1'
DOMAIN = b'CES/EC268/governance-root-handover/v1\x00'
SIGNERS = ('old', 'new', 'witness')
SIG_NAMES = {role: 'signature_' + role + '_ed25519' for role in SIGNERS}
PUBLIC_FIELDS = {'old': 'old_root_public_sha256',
                 'new': 'new_root_public_sha256',
                 'witness': 'witness_public_sha256'}
FIELDS = frozenset({
    'schema', 'old_governance_sha256', 'new_governance_sha256',
    'old_root_public_sha256', 'new_root_public_sha256',
    'witness_public_sha256', 'old_epoch', 'new_epoch',
    'declared_at_unix', 'nonce',
})
MAX_DOCUMENT_BYTES = 4096
CONTINUATION_SCHEMA = 'ces.ec268.pinned_new_root_governance_continuation.v1'
CONTINUATION_FIELDS = frozenset({'schema', 'entries'})
ENTRY_FIELDS = frozenset({'governance_policy', 'governance_policy_sha256'})
MAX_CONTINUATION_BYTES = 8192
MAX_CONTINUATIONS = 32


class HandoverError(gov.GovernanceError):
    """Fail-closed diagnostic code, not a leaked path, secret or raw evidence."""


def deny(code: str) -> None:
    raise HandoverError(code)


def _pin(value: Any) -> str:
    if type(value) is not str or cp.SHA_RE.fullmatch(value) is None:
        deny('EC268_SHA256_INVALID')
    return value


def _read_doc(path: str) -> tuple[bytes, dict[str, Any]]:
    try:
        raw, doc = prov._parse(path, MAX_DOCUMENT_BYTES)
    except (prov.ProvenanceError, cp.AnchorError) as exc:
        raise HandoverError('EC268_PRIVATE_CANONICAL_DOCUMENT_REQUIRED') from exc
    if type(doc) is not dict:
        deny('EC268_DOCUMENT_NOT_AN_OBJECT')
    return raw, doc


def _read_public(path: str, expected_pin: str) -> bytes:
    try:
        raw = prov._bytes(path, 32)
    except prov.ProvenanceError as exc:
        raise HandoverError('EC268_PUBLIC_KEY_FILE_UNAVAILABLE') from exc
    if len(raw) != 32 or not hmac.compare_digest(prov._digest(raw), _pin(expected_pin)):
        deny('EC268_PUBLIC_KEY_PIN_MISMATCH')
    return raw


def _verify_sig(public: bytes, role: str, unsigned: dict[str, Any], signature: str) -> None:
    try:
        cp.Ed25519PublicKey.from_public_bytes(public).verify(
            bytes.fromhex(signature), DOMAIN + role.encode('ascii') + b'\x00' + prov._canonical(unsigned))
    except (cp.InvalidSignature, ValueError, TypeError) as exc:
        raise HandoverError('EC268_HANDOVER_SIGNATURE_INVALID') from exc


def _validate(doc: Any, stage: int) -> dict[str, Any]:
    if (not 0 <= stage <= 3 or type(doc) is not dict or
            set(doc) != FIELDS | {SIG_NAMES[s] for s in SIGNERS[:stage]} or
            doc.get('schema') != SCHEMA):
        deny('EC268_HANDOVER_SCHEMA_OR_SIGNING_ORDER_INVALID')
    for key in ('old_governance_sha256', 'new_governance_sha256',
                'old_root_public_sha256', 'new_root_public_sha256',
                'witness_public_sha256'):
        _pin(doc[key])
    if len({doc[PUBLIC_FIELDS[r]] for r in SIGNERS}) != 3:
        deny('EC268_THREE_SIGNERS_NOT_DISTINCT')
    if doc['old_governance_sha256'] == doc['new_governance_sha256']:
        deny('EC268_NO_GOVERNANCE_TRANSITION')
    for key in ('old_epoch', 'new_epoch'):
        if type(doc[key]) is not int or not 1 <= doc[key] <= 2**31-1:
            deny('EC268_EPOCH_INVALID')
    if doc['new_epoch'] != doc['old_epoch'] + 1:
        deny('EC268_EPOCH_NOT_CONTIGUOUS')
    if (type(doc['declared_at_unix']) is not int or
            not 1 <= doc['declared_at_unix'] <= 2**40):
        deny('EC268_DECLARED_TIME_INVALID')
    if type(doc['nonce']) is not str or cp.NONCE_RE.fullmatch(doc['nonce']) is None:
        deny('EC268_NONCE_INVALID')
    for role in SIGNERS[:stage]:
        signature = doc[SIG_NAMES[role]]
        if type(signature) is not str or prov.SIGNATURE_RE.fullmatch(signature) is None:
            deny('EC268_SIGNATURE_ENCODING_INVALID')
    return {key: doc[key] for key in FIELDS}


def _signed_governance(path: str, expected_sha: str,
                       root_public: bytes) -> dict[str, Any]:
    cp._need_crypto()
    try:
        raw, doc = gov._read(path)
        gov._validate(doc, signed=True)
    except (gov.GovernanceError, prov.ProvenanceError) as exc:
        raise HandoverError('EC268_SIGNED_GOVERNANCE_INVALID') from exc
    if not hmac.compare_digest(prov._digest(raw), _pin(expected_sha)):
        deny('EC268_GOVERNANCE_DOCUMENT_PIN_MISMATCH')
    try:
        cp.Ed25519PublicKey.from_public_bytes(root_public).verify(
            bytes.fromhex(doc['signature_ed25519']),
            gov.DOMAIN + prov._canonical({field: doc[field] for field in gov.POLICY_FIELDS}))
    except (cp.InvalidSignature, ValueError, TypeError) as exc:
        raise HandoverError('EC268_GOVERNANCE_ROOT_SIGNATURE_INVALID') from exc
    return doc


def _transition(old: dict[str, Any], new: dict[str, Any], old_sha: str) -> None:
    if (new['epoch'] != old['epoch'] + 1 or
            new['previous_governance_sha256'] != old_sha):
        deny('EC268_GOVERNANCE_EPOCH_OR_PREDECESSOR_MISMATCH')
    if (new['issued_at_unix'] < old['issued_at_unix'] or
            new['not_before_unix'] < old['not_before_unix']):
        deny('EC268_DECLARED_TIME_REVERSED')
    old_revoked, new_revoked = set(old['revoked_public_sha256']), set(new['revoked_public_sha256'])
    old_issuers, new_issuers = set(old['role_public_sha256'].values()), set(new['role_public_sha256'].values())
    if old_revoked & old_issuers or new_revoked & new_issuers:
        deny('EC268_HISTORIC_ACTIVE_ISSUER_REVOKED')
    if not old_revoked.issubset(new_revoked):
        deny('EC268_HISTORIC_ISSUER_REVOCATION_DROPPED')
    if not (old_issuers - new_issuers).issubset(new_revoked):
        deny('EC268_RETIRED_ISSUER_NOT_REVOKED')
    if old_revoked & new_issuers:
        deny('EC268_PREVIOUSLY_REVOKED_ISSUER_REINSTATED')


def _read_pair(*, old_governance: str, old_governance_sha256: str,
               new_governance: str, new_governance_sha256: str,
               old_root_public: str, old_root_public_sha256: str,
               new_root_public: str, new_root_public_sha256: str,
               witness_public: str, witness_public_sha256: str,
               forbidden_signers: tuple[str, ...] = ()) -> tuple[dict[str, Any], dict[str, Any]]:
    pins = [_pin(value) for value in (old_root_public_sha256,
             new_root_public_sha256, witness_public_sha256)]
    if len(set(pins)) != 3:
        deny('EC268_THREE_SIGNERS_NOT_DISTINCT')
    old_key = _read_public(old_root_public, pins[0])
    new_key = _read_public(new_root_public, pins[1])
    _read_public(witness_public, pins[2])
    old = _signed_governance(old_governance, old_governance_sha256, old_key)
    new = _signed_governance(new_governance, new_governance_sha256, new_key)
    _transition(old, new, _pin(old_governance_sha256))
    forbidden = set(_pin(x) for x in forbidden_signers)
    role_pins = set(old['role_public_sha256'].values()) | set(new['role_public_sha256'].values())
    if set(pins) & (role_pins | forbidden):
        deny('EC268_SIGNER_NOT_INDEPENDENT_OF_ISSUERS_OR_AUDIT')
    return old, new



def _read_continuation(chain_path: str, chain_sha256: str) -> list[dict[str, str]]:
    try:
        raw, config = prov._parse(chain_path, MAX_CONTINUATION_BYTES)
    except (prov.ProvenanceError, cp.AnchorError) as exc:
        raise HandoverError('EC268_CONTINUATION_CANONICAL_CONFIG_REQUIRED') from exc
    if not hmac.compare_digest(prov._digest(raw), _pin(chain_sha256)):
        deny('EC268_CONTINUATION_CONFIG_PIN_MISMATCH')
    if (type(config) is not dict or set(config) != CONTINUATION_FIELDS or
            config['schema'] != CONTINUATION_SCHEMA or
            type(config['entries']) is not list or
            not 1 <= len(config['entries']) <= MAX_CONTINUATIONS):
        deny('EC268_CONTINUATION_CONFIG_INVALID')
    paths: set[str] = set()
    seen: list[dict[str, str]] = []
    for entry in config['entries']:
        if type(entry) is not dict or set(entry) != ENTRY_FIELDS:
            deny('EC268_CONTINUATION_ENTRY_INVALID')
        pathname = prov._path(entry['governance_policy'])
        if pathname in paths:
            deny('EC268_CONTINUATION_DUPLICATE_GOVERNANCE_FILE')
        paths.add(pathname)
        seen.append({'governance_policy': pathname,
                     'governance_policy_sha256': _pin(entry['governance_policy_sha256'])})
    return seen


def prepare_continuation(*, anchor_governance: str, anchor_governance_sha256: str,
                         new_root_public: str, new_root_public_sha256: str,
                         next_governance: str, next_governance_sha256: str,
                         output: str, previous_chain: str | None = None,
                         previous_chain_sha256: str | None = None) -> dict[str, Any]:
    """Append ONLY new-root-signed governance; no old/witness re-sign required.

    The operator must separately pin each complete new config digest and the
    new current governance digest. The previous config, if any, is pinned too.
    """
    cp._need_crypto()
    public = _read_public(new_root_public, new_root_public_sha256)
    before = _signed_governance(anchor_governance, anchor_governance_sha256, public)
    if (previous_chain is None) != (previous_chain_sha256 is None):
        deny('EC268_CONTINUATION_CONFIG_PIN_REQUIRED')
    entries: list[dict[str, str]] = []
    prev_digest = _pin(anchor_governance_sha256)
    if previous_chain is not None:
        entries = _read_continuation(previous_chain, previous_chain_sha256)
        for part in entries:
            doc = _signed_governance(part['governance_policy'],
                                     part['governance_policy_sha256'], public)
            _transition(before, doc, prev_digest)
            before, prev_digest = doc, part['governance_policy_sha256']
    if len(entries) >= MAX_CONTINUATIONS:
        deny('EC268_CONTINUATION_MAX_DEPTH')
    next_path = prov._path(next_governance)
    if next_path == prov._path(anchor_governance) or any(
            entry['governance_policy'] == next_path for entry in entries):
        deny('EC268_CONTINUATION_DUPLICATE_GOVERNANCE_FILE')
    next_doc = _signed_governance(next_path, next_governance_sha256, public)
    _transition(before, next_doc, prev_digest)
    entries.append({'governance_policy': next_path,
                    'governance_policy_sha256': _pin(next_governance_sha256)})
    raw = prov._canonical({'schema': CONTINUATION_SCHEMA, 'entries': entries})
    if len(raw) > MAX_CONTINUATION_BYTES:
        deny('EC268_CONTINUATION_TOO_LARGE')
    try:
        prov._new(output, raw)
    except prov.ProvenanceError as exc:
        raise HandoverError('EC268_NEW_CONTINUATION_FILE_REQUIRED') from exc
    return {'status': 'partial', 'exit_code': 2,
            'continuation_chain_sha256': prov._digest(raw),
            'continuation_governance_count': len(entries),
            'latest_epoch': next_doc['epoch'],
            'new_root_is_only_required_governance_signer': True,
            'external_antirollback_anchor_verified': False}


def prepare_handover(*, old_governance: str, old_governance_sha256: str,
                     new_governance: str, new_governance_sha256: str,
                     old_root_public: str, old_root_public_sha256: str,
                     new_root_public: str, new_root_public_sha256: str,
                     witness_public: str, witness_public_sha256: str,
                     output: str, declared_at_unix: int | None = None) -> dict[str, Any]:
    """Create unsigned immutable proposal after verifying both signed epochs."""
    old, new = _read_pair(
        old_governance=old_governance, old_governance_sha256=old_governance_sha256,
        new_governance=new_governance, new_governance_sha256=new_governance_sha256,
        old_root_public=old_root_public, old_root_public_sha256=old_root_public_sha256,
        new_root_public=new_root_public, new_root_public_sha256=new_root_public_sha256,
        witness_public=witness_public, witness_public_sha256=witness_public_sha256)
    doc = {
        'schema': SCHEMA, 'old_governance_sha256': old_governance_sha256,
        'new_governance_sha256': new_governance_sha256,
        'old_root_public_sha256': old_root_public_sha256,
        'new_root_public_sha256': new_root_public_sha256,
        'witness_public_sha256': witness_public_sha256,
        'old_epoch': old['epoch'], 'new_epoch': new['epoch'],
        'declared_at_unix': int(time.time()) if declared_at_unix is None else declared_at_unix,
        'nonce': os.urandom(16).hex(),
    }
    _validate(doc, 0)
    raw = prov._canonical(doc)
    try:
        prov._new(output, raw)
    except prov.ProvenanceError as exc:
        raise HandoverError('EC268_NEW_PROPOSAL_FILE_REQUIRED') from exc
    return {'status': 'partial', 'exit_code': 2, 'handover_proposal_sha256': prov._digest(raw),
            'next_epoch': new['epoch'], 'requires_three_offline_independent_signatures': True}


def sign_offline(input_path: str, input_sha256: str, role: str,
                 signing_key: str, expected_signer_public_sha256: str,
                 output: str, *, previous_public_keys: dict[str, tuple[str, str]] | None = None) -> dict[str, Any]:
    """One signer at a time; each step writes a NEW private canonical file.

    The signer must pin this input's exact SHA independently. Previous stages
    must be verified with separately selected public files AND operator SHA
    pins; trusting paths/pins embedded in the unsigned draft is insufficient.
    """
    cp._need_crypto()
    if role not in SIGNERS:
        deny('EC268_SIGNER_ROLE_INVALID')
    stage = SIGNERS.index(role)
    raw, doc = _read_doc(input_path)
    unsigned = _validate(doc, stage)
    if not hmac.compare_digest(prov._digest(raw), _pin(input_sha256)):
        deny('EC268_SIGNING_INPUT_PIN_MISMATCH')
    signer_pin = _pin(expected_signer_public_sha256)
    if not hmac.compare_digest(signer_pin, doc[PUBLIC_FIELDS[role]]):
        deny('EC268_SIGNER_NOT_PINNED_FOR_STAGE')
    for previous in SIGNERS[:stage]:
        if previous_public_keys is None or previous not in previous_public_keys:
            deny('EC268_PREVIOUS_SIGNER_PROOF_MISSING')
        public_path, independent_pin = previous_public_keys[previous]
        if _pin(independent_pin) != doc[PUBLIC_FIELDS[previous]]:
            deny('EC268_PREVIOUS_SIGNER_PIN_NOT_INDEPENDENT')
        _verify_sig(_read_public(public_path, independent_pin), previous,
                    unsigned, doc[SIG_NAMES[previous]])
    try:
        secret = prov._bytes(signing_key, 32)
    except prov.ProvenanceError as exc:
        raise HandoverError('EC268_PRIVATE_SIGNING_KEY_UNAVAILABLE') from exc
    if len(secret) != 32:
        deny('EC268_SIGNING_KEY_LENGTH_INVALID')
    try:
        signer_public = cp.public_bytes_from_signing_key(secret)
        signature = cp.Ed25519PrivateKey.from_private_bytes(secret).sign(
            DOMAIN + role.encode('ascii') + b'\x00' + prov._canonical(unsigned))
    except (ValueError, TypeError) as exc:
        raise HandoverError('EC268_OFFLINE_SIGNING_FAILED') from exc
    if not hmac.compare_digest(prov._digest(signer_public), signer_pin):
        deny('EC268_SIGNER_PRIVATE_KEY_PIN_MISMATCH')
    signed = {**doc, SIG_NAMES[role]: signature.hex()}
    _validate(signed, stage + 1)
    result = prov._canonical(signed)
    try:
        prov._new(output, result)
    except prov.ProvenanceError as exc:
        raise HandoverError('EC268_SIGNING_OUTPUT_MUST_BE_NEW_PRIVATE_FILE') from exc
    return {'status': 'partial', 'exit_code': 2,
            'signed_handover_sha256': prov._digest(result),
            'completed_stage': role, 'all_signatures_complete': role == SIGNERS[-1],
            'operator_must_independently_pin_output': True}


class RootHandoverGate(gov.GovernedSourceGate):
    """Require EC267 current admission and cryptographic three-party root chain.

    `previous_governance` may be expired; it is historical authorization, not
    an additional live lease. The current EC267 gate retains sole time control.
    """

    def __init__(self, policy_path: str, repo: str, allowlist: str,
                 receipt: str, profile_id: str, provenance_gate: str,
                 provenance_gate_sha256: str, governance_policy: str,
                 governance_policy_sha256: str, governance_public: str,
                 governance_public_sha256: str, *, minimum_epoch: int,
                 expected_previous_governance_sha256: str,
                 previous_governance: str, previous_governance_sha256: str,
                 previous_governance_public: str,
                 previous_governance_public_sha256: str,
                 witness_public: str, witness_public_sha256: str,
                 handover_certificate: str, handover_certificate_sha256: str,
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
        self.previous_governance = prov._path(previous_governance)
        self.previous_governance_pin = _pin(previous_governance_sha256)
        self.previous_governance_public = prov._path(previous_governance_public)
        self.previous_governance_public_pin = _pin(previous_governance_public_sha256)
        self.witness_public = prov._path(witness_public)
        self.witness_public_pin = _pin(witness_public_sha256)
        self.handover_certificate = prov._path(handover_certificate)
        self.handover_pin = _pin(handover_certificate_sha256)
        if (anchor_governance is None) != (anchor_governance_sha256 is None):
            deny('EC268_HANDOVER_ANCHOR_PIN_REQUIRED')
        self.anchor_governance = prov._path(anchor_governance) if anchor_governance is not None else self.governance_policy
        self.anchor_governance_pin = _pin(anchor_governance_sha256) if anchor_governance_sha256 is not None else self.governance_policy_pin
        if (continuation_chain is None) != (continuation_chain_sha256 is None):
            deny('EC268_CONTINUATION_CONFIG_PIN_REQUIRED')
        self.continuation_chain = prov._path(continuation_chain) if continuation_chain is not None else None
        self.continuation_chain_pin = _pin(continuation_chain_sha256) if continuation_chain_sha256 is not None else None
        if (self.anchor_governance_pin != self.governance_policy_pin or
                self.anchor_governance != self.governance_policy) != (self.continuation_chain is not None):
            deny('EC268_CONTINUATION_REQUIRED_FOR_RENEWED_GOVERNANCE')
        continuation_entries = self._continuations()
        expected_immediate_predecessor = (
            (continuation_entries[-2]['governance_policy_sha256']
             if len(continuation_entries) > 1 else self.anchor_governance_pin)
            if self.continuation_chain is not None else self.previous_governance_pin)
        if self.expected_previous != expected_immediate_predecessor:
            deny('EC268_INDEPENDENT_PREDECESSOR_PIN_MISMATCH')
        all_paths = [self.governance_policy, self.governance_public,
                     self.previous_governance, self.previous_governance_public,
                     self.witness_public, self.handover_certificate]
        if self.anchor_governance != self.governance_policy:
            all_paths.append(self.anchor_governance)
        if self.continuation_chain is not None:
            all_paths.append(self.continuation_chain)
            all_paths.extend(item['governance_policy'] for item in self._continuations()[:-1])
        if len(set(all_paths)) != len(all_paths):
            deny('EC268_HANDOVER_AUTHORITY_PATH_COLLISION')
        self._handover_seen: dict[str, Any] | None = None

    def _continuations(self) -> list[dict[str, str]]:
        if self.continuation_chain is None:
            return []
        return _read_continuation(self.continuation_chain, self.continuation_chain_pin)

    def authority_paths(self) -> list[str]:
        paths = super().authority_paths() + [self.previous_governance,
            self.previous_governance_public, self.witness_public, self.handover_certificate]
        if self.anchor_governance != self.governance_policy:
            paths.append(self.anchor_governance)
        if self.continuation_chain is not None:
            paths.append(self.continuation_chain)
            paths.extend(part['governance_policy'] for part in self._continuations()[:-1])
        return paths

    def _check_handover(self) -> None:
        if not self._governance_verified or self._governance_seen is None:
            deny('EC268_CURRENT_GOVERNANCE_NOT_VERIFIED')
        old, new = _read_pair(
            old_governance=self.previous_governance,
            old_governance_sha256=self.previous_governance_pin,
            new_governance=self.anchor_governance,
            new_governance_sha256=self.anchor_governance_pin,
            old_root_public=self.previous_governance_public,
            old_root_public_sha256=self.previous_governance_public_pin,
            new_root_public=self.governance_public,
            new_root_public_sha256=self.governance_public_pin,
            witness_public=self.witness_public,
            witness_public_sha256=self.witness_public_pin,
            forbidden_signers=tuple(self._forbidden),
        )
        entries = self._continuations()
        if entries:
            latest = new
            latest_sha = self.anchor_governance_pin
            for entry in entries:
                current = _signed_governance(entry['governance_policy'],
                                             entry['governance_policy_sha256'],
                    _read_public(self.governance_public, self.governance_public_pin))
                _transition(latest, current, latest_sha)
                new_signer_keys = set(current['role_public_sha256'].values())
                root_keys = {self.previous_governance_public_pin,
                             self.governance_public_pin, self.witness_public_pin}
                if root_keys & (new_signer_keys | self._forbidden):
                    deny('EC268_SIGNER_NOT_INDEPENDENT_OF_ISSUERS_OR_AUDIT')
                latest, latest_sha = current, entry['governance_policy_sha256']
            if (entries[-1]['governance_policy'] != self.governance_policy or
                    latest_sha != self.governance_policy_pin):
                deny('EC268_CONTINUATION_CURRENT_PIN_MISMATCH')
            if latest != self._governance_seen:
                deny('EC268_CURRENT_GOVERNANCE_CHANGED')
        elif new != self._governance_seen:
            deny('EC268_CURRENT_GOVERNANCE_CHANGED')
        raw, signed = _read_doc(self.handover_certificate)
        unsigned = _validate(signed, 3)
        if not hmac.compare_digest(prov._digest(raw), self.handover_pin):
            deny('EC268_HANDOVER_CERTIFICATE_PIN_MISMATCH')
        expected = {
            'old_governance_sha256': self.previous_governance_pin,
            'new_governance_sha256': self.anchor_governance_pin,
            'old_root_public_sha256': self.previous_governance_public_pin,
            'new_root_public_sha256': self.governance_public_pin,
            'witness_public_sha256': self.witness_public_pin,
            'old_epoch': old['epoch'], 'new_epoch': new['epoch'],
        }
        if any(unsigned[key] != value for key, value in expected.items()):
            deny('EC268_HANDOVER_BINDING_MISMATCH')
        for role, path, pin in (
            ('old', self.previous_governance_public, self.previous_governance_public_pin),
            ('new', self.governance_public, self.governance_public_pin),
            ('witness', self.witness_public, self.witness_public_pin)):
            _verify_sig(_read_public(path, pin), role, unsigned, signed[SIG_NAMES[role]])
        if self._handover_seen is not None and signed != self._handover_seen:
            deny('EC268_HANDOVER_CHANGED_DURING_HOST')
        if self._handover_seen is None:
            self._handover_seen = signed

    def startup(self, policy: dict[str, Any], policy_sha: str) -> None:
        super().startup(policy, policy_sha)
        self._check_handover()

    def before_begin(self, policy: dict[str, Any], policy_sha: str,
                     request: dict[str, Any]) -> None:
        super().before_begin(policy, policy_sha, request)
        self._check_handover()

    def summary(self) -> dict[str, Any]:
        if self._handover_seen is None:
            deny('EC268_HANDOVER_NOT_VERIFIED')
        result = super().summary()
        result.update({
            'reason_code': 'EC268_LOCAL_THREE_SIGNATURE_HANDOVER_NOT_EXTERNAL_TRUST_PROOF',
            'handover_signatures_verified': list(SIGNERS),
            'old_governance_epoch': self._handover_seen['old_epoch'],
            'new_governance_epoch': self._handover_seen['new_epoch'],
            'governance_continuations': len(self._continuations()),
            'new_root_can_sign_later_epochs_without_old_root_or_witness': True,
            'historic_revocations_preserved': True,
            'retired_issuer_keys_explicitly_revoked': True,
            'historical_root_chain_cross_restart_nonrollback_verified': False,
            'independent_witness_machine_verified': False,
        })
        return result
