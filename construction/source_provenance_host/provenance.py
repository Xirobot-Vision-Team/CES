#!/usr/bin/env python3
"""EC266: fail-closed source-origin/review/CI signed evidence admission.

An offline signer attests a specific operator-pinned SOURCE SUBJECT plus the
exact bytes of one supporting evidence file. Verification authenticates only
those signed assertions to the operator-pinned public keys: it does NOT query
or authenticate a remote Git forge, reviewer, or CI provider. All three roles
must be operated and independently pinned outside the source host in deployment.

This is a separate opt-in gate, additive to EC253/259/260/265. It neither
changes original signed tickets nor enables any legacy Router/Provider action.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import sys
from typing import Any
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from quality_host import broker as private
from lease_host import broker as lease
from git_tar_custody import custody as git
from custody_gated_host.gate import OperatorCustodyGate, CustodyGateError
from offline_anchor_host import checkpoint as cp
from segmented_audit_host import segment as seg
import quality_run_guard as quality_guard

SUBJECT_SCHEMA = 'ces.ec266.source_admission_subject.v1'
ATTEST_SCHEMA = 'ces.ec266.signed_source_authority_assertion.v1'
GATE_SCHEMA = 'ces.ec266.pinned_three_role_admission_gate.v1'
DOMAIN = b'CES/EC266/source-role-assertion/v1\x00'
ROLES = ('origin', 'review', 'ci')
DECISIONS = {'origin': 'commit_recognized', 'review': 'approved', 'ci': 'passed'}
SUBJECT_FIELDS = frozenset({
    'schema', 'nonce', 'origin_repository', 'origin_ref', 'commit_oid',
    'git_object_format', 'tree_oid', 'allowlist_sha256',
    'source_custody_receipt_sha256', 'source_tar_sha256', 'policy_sha256',
    'authorized_source_pin_sha256', 'profile_id', 'profile_sha256',
    'approval_receipt_sha256', 'lease_receipt_sha256', 'image_sha256',
})
ATTEST_FIELDS = frozenset({
    'schema', 'role', 'subject_sha256', 'issuer_public_sha256',
    'decision', 'evidence_id', 'evidence_sha256', 'nonce',
})
GATE_FIELDS = frozenset({'schema', 'subject', 'subject_sha256',
                         'origin_repository', 'origin_ref', 'authorities'})
AUTH_FIELDS = frozenset({'role', 'public_key', 'public_sha256',
                         'assertion', 'assertion_sha256',
                         'evidence', 'evidence_sha256'})
SHA_RE = cp.SHA_RE
SIGNATURE_RE = re.compile(r'[0-9a-f]{128}\Z')
EVIDENCE_ID_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/#-]{0,127}\Z')
REPO_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/-]{7,239}\Z')
REF_RE = re.compile(r'refs/(?:heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]{0,159}\Z')
MAX_SUBJECT = 4096
MAX_ASSERTION = 2048
MAX_GATE = 8192
MAX_EVIDENCE = 1024 * 1024


class ProvenanceError(CustodyGateError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def deny(code: str) -> None:
    raise ProvenanceError(code)


def _sha(value: Any) -> str:
    if type(value) is not str or SHA_RE.fullmatch(value) is None:
        deny('EC266_SHA256_INVALID')
    return value


def _canonical(obj: dict[str, Any]) -> bytes:
    return seg._canonical(obj) + b'\n'


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _path(value: Any) -> str:
    try:
        return private._path(value)
    except (OSError, TypeError, ValueError) as exc:
        raise ProvenanceError('EC266_PRIVATE_PATH_REQUIRED') from exc


def _bytes(path: str, maximum: int) -> bytes:
    try:
        return private._private_bytes(_path(path), maximum)
    except (OSError, ValueError, TypeError) as exc:
        raise ProvenanceError('EC266_PRIVATE_FILE_UNAVAILABLE') from exc


def _parse(path: str, maximum: int) -> tuple[bytes, dict[str, Any]]:
    raw = _bytes(path, maximum)
    try:
        payload = cp._parse_canonical(raw, maximum)
    except (ValueError, TypeError) as exc:
        raise ProvenanceError('EC266_CANONICAL_JSON_REQUIRED') from exc
    return raw, payload


def _new(path: str, raw: bytes) -> None:
    try:
        cp._atomic_new_private(path, raw)
    except (OSError, ValueError) as exc:
        raise ProvenanceError('EC266_OUTPUT_MUST_BE_NEW_PRIVATE_FILE') from exc


def _identity(repository: Any, ref: Any) -> None:
    if (type(repository) is not str or REPO_RE.fullmatch(repository) is None or
            repository.startswith(('.', '/')) or '..' in repository or
            '//' in repository or repository.endswith(('.', '/'))):
        deny('EC266_REPOSITORY_ID_INVALID')
    if (type(ref) is not str or REF_RE.fullmatch(ref) is None or
            '..' in ref or '//' in ref or ref.endswith(('.', '/')) or
            ref.endswith('.lock')):
        deny('EC266_REMOTE_REF_INVALID')


def _validate_subject(obj: Any) -> None:
    if (type(obj) is not dict or set(obj) != SUBJECT_FIELDS or
            obj.get('schema') != SUBJECT_SCHEMA or
            type(obj.get('nonce')) is not str or
            cp.NONCE_RE.fullmatch(obj['nonce']) is None or
            type(obj.get('profile_id')) is not str or
            not 1 <= len(obj['profile_id']) <= 128):
        deny('EC266_SUBJECT_FIELDS_INVALID')
    _identity(obj['origin_repository'], obj['origin_ref'])
    for key in SUBJECT_FIELDS - {'schema', 'nonce', 'origin_repository',
                                 'origin_ref', 'git_object_format', 'commit_oid',
                                 'tree_oid', 'profile_id'}:
        _sha(obj[key])
    if obj['git_object_format'] not in ('sha1', 'sha256'):
        deny('EC266_GIT_FORMAT_INVALID')
    length = 40 if obj['git_object_format'] == 'sha1' else 64
    for field in ('commit_oid', 'tree_oid'):
        if type(obj[field]) is not str or re.fullmatch(
                '[0-9a-f]{' + str(length) + '}', obj[field]) is None:
            deny('EC266_GIT_OBJECT_ID_INVALID')


def _validate_assertion(obj: Any) -> None:
    if (type(obj) is not dict or set(obj) != ATTEST_FIELDS | {'signature_ed25519'} or
            obj.get('schema') != ATTEST_SCHEMA or
            type(obj.get('role')) is not str or obj['role'] not in ROLES or
            obj.get('decision') != DECISIONS[obj['role']] or
            type(obj.get('nonce')) is not str or
            cp.NONCE_RE.fullmatch(obj['nonce']) is None or
            type(obj.get('evidence_id')) is not str or
            EVIDENCE_ID_RE.fullmatch(obj['evidence_id']) is None or
            type(obj.get('signature_ed25519')) is not str or
            SIGNATURE_RE.fullmatch(obj['signature_ed25519']) is None):
        deny('EC266_ASSERTION_FIELDS_INVALID')
    for field in ('subject_sha256', 'issuer_public_sha256', 'evidence_sha256'):
        _sha(obj[field])


def _snapshot(policy: dict[str, Any], sha: str, gate: OperatorCustodyGate,
              *, repository: str, ref: str, nonce: str) -> dict[str, Any]:
    """Re-derive entire signed subject from EC258 Git + EC253 role MACs.

    The EC259 gate must have just verified the immutable TAR/receipt/repo,
    including an EC253 reread of the signed policy. Never use HEAD or remote
    fetch here. Attestation cannot substitute for original ticket validity.
    """
    _identity(repository, ref)
    if cp.NONCE_RE.fullmatch(nonce) is None:
        deny('EC266_SUBJECT_NONCE_INVALID')
    result = gate._last_result
    if result is None or result.get('content_custody_verified') is not True:
        deny('EC266_LOCAL_CUSTODY_NOT_CHECKED')
    allow = _bytes(gate.allowlist_path, git.MAX_APPROVAL)
    receipt = _bytes(gate.receipt_path, git.MAX_RECEIPT)
    try:
        local = git._decode_json(receipt)
        approved = git._allowlist(allow)
        tickets = lease._tickets(policy, gate.profile_id)
    except (git.CustodyError, lease.LeaseHostError, ValueError) as exc:
        raise ProvenanceError('EC266_LOCAL_AUTHORITY_UNAVAILABLE') from exc
    spec = quality_guard.catalog_entry(gate.profile_id)
    if (spec is None or local.get('schema') != git.RECEIPT_SCHEMA or
            _canonical(local) != receipt or
            approved['commit_oid'] != result['commit_oid'] or
            local.get('commit_oid') != result['commit_oid'] or
            local.get('source_tar_sha256') != result['source_tar_sha256'] or
            local.get('allowlist_sha256') != _digest(allow)):
        deny('EC266_LOCAL_GIT_PROOF_CHANGED')
    subject = {
        'schema': SUBJECT_SCHEMA, 'nonce': nonce,
        'origin_repository': repository, 'origin_ref': ref,
        'commit_oid': local['commit_oid'],
        'git_object_format': local['git_object_format'],
        'tree_oid': local['tree_oid'],
        'allowlist_sha256': _digest(allow),
        'source_custody_receipt_sha256': _digest(receipt),
        'source_tar_sha256': result['source_tar_sha256'],
        'policy_sha256': sha,
        'authorized_source_pin_sha256': policy['authorized_source_pin_sha256'],
        'profile_id': gate.profile_id,
        'profile_sha256': spec['profile_sha256'],
        'approval_receipt_sha256': tickets['approval_receipt_sha256'],
        'lease_receipt_sha256': tickets['lease_receipt_sha256'],
        'image_sha256': policy['image_id'][7:],
    }
    _validate_subject(subject)
    return subject


def propose(repo: str, allowlist: str, receipt: str, policy_path: str,
            profile_id: str, repository: str, ref: str, output: str) -> dict[str, Any]:
    """Create NEW unsigned snapshot only; actual remote roles sign offline."""
    _identity(repository, ref)
    policy, policy_sha = lease._policy(policy_path)
    local = OperatorCustodyGate(policy_path, repo, allowlist, receipt, profile_id)
    local.startup(policy, policy_sha)
    subject = _snapshot(policy, policy_sha, local, repository=repository,
                        ref=ref, nonce=os.urandom(16).hex())
    raw = _canonical(subject)
    _new(output, raw)
    return {'status': 'partial', 'exit_code': 2,
            'subject_sha256': _digest(raw),
            'source_tar_sha256': subject['source_tar_sha256'],
            'commit_oid': subject['commit_oid'],
            'requires_independently_verified_origin_review_ci_signers': True,
            'actual_remote_provider_verified': False,
            'overall_quality_pass_verified': False}


def sign_offline(subject_path: str, subject_pin: str, role: str,
                 evidence_path: str, evidence_pin: str, evidence_id: str,
                 signing_key: str, expected_public_sha256: str,
                 output: str) -> dict[str, Any]:
    """An authority signs a subject plus specific evidence *after own review*.

    No network/provider verification is performed by this utility. Issuing a
    truthful assertion and keeping role keys off-host are external duties.
    """
    cp._need_crypto()
    if type(role) is not str or role not in ROLES:
        deny('EC266_ROLE_INVALID')
    if type(evidence_id) is not str or EVIDENCE_ID_RE.fullmatch(evidence_id) is None:
        deny('EC266_EVIDENCE_ID_INVALID')
    raw, subject = _parse(subject_path, MAX_SUBJECT)
    _validate_subject(subject)
    if not hmac.compare_digest(_digest(raw), _sha(subject_pin)):
        deny('EC266_SUBJECT_PIN_MISMATCH')
    evidence = _bytes(evidence_path, MAX_EVIDENCE)
    if not evidence or not hmac.compare_digest(_digest(evidence), _sha(evidence_pin)):
        deny('EC266_EVIDENCE_PIN_MISMATCH')
    secret = _bytes(signing_key, 32)
    if len(secret) != 32:
        deny('EC266_SECRET_KEY_LENGTH_INVALID')
    try:
        pub = cp.public_bytes_from_signing_key(secret)
        if not hmac.compare_digest(_digest(pub), _sha(expected_public_sha256)):
            deny('EC266_OFFLINE_SIGNER_PIN_MISMATCH')
        payload = {
            'schema': ATTEST_SCHEMA, 'role': role,
            'subject_sha256': _digest(raw),
            'issuer_public_sha256': _digest(pub),
            'decision': DECISIONS[role], 'evidence_id': evidence_id,
            'evidence_sha256': _digest(evidence), 'nonce': os.urandom(16).hex(),
        }
        signature = cp.Ed25519PrivateKey.from_private_bytes(secret).sign(
            DOMAIN + role.encode('ascii') + b'\x00' + _canonical(payload))
    except (ValueError, TypeError) as exc:
        if isinstance(exc, ProvenanceError):
            raise
        raise ProvenanceError('EC266_OFFLINE_SIGNING_UNAVAILABLE') from exc
    assertion = {**payload, 'signature_ed25519': signature.hex()}
    _validate_assertion(assertion)
    signed = _canonical(assertion)
    _new(output, signed)
    return {'status': 'partial', 'exit_code': 2,
            'assertion_sha256': _digest(signed), 'role': role,
            'issuer_public_sha256': _digest(pub),
            'signature_ed25519_verified_by_host_only_when_pinned': True,
            'actual_external_origin_review_or_ci_verified': False,
            'overall_quality_pass_verified': False}


class SignedSourceGate(OperatorCustodyGate):
    """Additional fixed per-run three-authority gate, active recall enabled."""

    def __init__(self, policy_path: str, repo: str, allowlist: str,
                 receipt: str, profile_id: str, provenance_gate: str,
                 provenance_gate_sha256: str, *, forbidden_signers: tuple[str, ...] = ()):
        super().__init__(policy_path, repo, allowlist, receipt, profile_id)
        self.gate_path = _path(provenance_gate)
        self.gate_pin = _sha(provenance_gate_sha256)
        self._config: dict[str, Any] | None = None
        self._subject: dict[str, Any] | None = None
        self._pubs: dict[str, bytes] = {}
        self._forbidden = set(map(_sha, forbidden_signers))
        self._verified = False

    def _read_config(self) -> dict[str, Any]:
        raw, obj = _parse(self.gate_path, MAX_GATE)
        if not hmac.compare_digest(_digest(raw), self.gate_pin):
            deny('EC266_GATE_CONFIG_PIN_MISMATCH')
        if (set(obj) != GATE_FIELDS or obj.get('schema') != GATE_SCHEMA or
                type(obj.get('authorities')) is not list or
                len(obj['authorities']) != len(ROLES)):
            deny('EC266_GATE_CONFIG_FIELDS_INVALID')
        _identity(obj['origin_repository'], obj['origin_ref'])
        _sha(obj['subject_sha256'])
        paths = [self.gate_path, _path(obj['subject'])]
        pins = []
        for index, role in enumerate(ROLES):
            item = obj['authorities'][index]
            if (type(item) is not dict or set(item) != AUTH_FIELDS or
                    type(item.get('role')) is not str or item['role'] != role):
                deny('EC266_ROLE_COVERAGE_OR_ORDER_INVALID')
            pins.append(_sha(item['public_sha256']))
            for field in ('assertion_sha256', 'evidence_sha256'):
                _sha(item[field])
            for field in ('public_key', 'assertion', 'evidence'):
                paths.append(_path(item[field]))
        if (len(set(pins)) != len(ROLES) or any(p in self._forbidden for p in pins)):
            deny('EC266_ROLE_SIGNERS_NOT_DISTINCT')
        if len(set(paths)) != len(paths):
            deny('EC266_GATE_FILE_PATHS_NOT_DISTINCT')
        # Never let the selected source tree or active journal provide its own
        # authority files. All are supplied via separately selected private files.
        for item in paths:
            for root in (self.repo,):
                root = _path(root)
                if os.path.commonpath((item, root)) == root:
                    deny('EC266_AUTHORITY_FILE_INSIDE_SOURCE_REPOSITORY')
        return obj

    def _check_provenance(self, policy: dict[str, Any], sha: str) -> None:
        cp._need_crypto()
        config = self._read_config()
        if self._config is not None and config != self._config:
            deny('EC266_GATE_CONFIG_CHANGED')
        raw, subject = _parse(config['subject'], MAX_SUBJECT)
        if not hmac.compare_digest(_digest(raw), config['subject_sha256']):
            deny('EC266_SUBJECT_PIN_MISMATCH')
        _validate_subject(subject)
        if (subject['origin_repository'] != config['origin_repository'] or
                subject['origin_ref'] != config['origin_ref']):
            deny('EC266_OPERATOR_REMOTE_IDENTITY_MISMATCH')
        now = _snapshot(policy, sha, self,
                        repository=config['origin_repository'],
                        ref=config['origin_ref'], nonce=subject['nonce'])
        if subject != now:
            deny('EC266_SOURCE_OR_TICKET_BINDING_MISMATCH')
        new_pubs = {}
        for index, role in enumerate(ROLES):
            item = config['authorities'][index]
            public = _bytes(item['public_key'], 32)
            if (len(public) != 32 or
                    not hmac.compare_digest(_digest(public), item['public_sha256'])):
                deny('EC266_PUBLIC_KEY_PIN_MISMATCH')
            evidence = _bytes(item['evidence'], MAX_EVIDENCE)
            if not evidence or not hmac.compare_digest(_digest(evidence), item['evidence_sha256']):
                deny('EC266_EVIDENCE_BYTES_PIN_MISMATCH')
            signed_raw, assertion = _parse(item['assertion'], MAX_ASSERTION)
            if not hmac.compare_digest(_digest(signed_raw), item['assertion_sha256']):
                deny('EC266_ASSERTION_BYTES_PIN_MISMATCH')
            _validate_assertion(assertion)
            if (assertion['role'] != role or
                    assertion['subject_sha256'] != config['subject_sha256'] or
                    assertion['issuer_public_sha256'] != item['public_sha256'] or
                    assertion['evidence_sha256'] != item['evidence_sha256']):
                deny('EC266_ASSERTION_SUBJECT_OR_EVIDENCE_MISMATCH')
            unsigned = {name: assertion[name] for name in ATTEST_FIELDS}
            try:
                cp.Ed25519PublicKey.from_public_bytes(public).verify(
                    bytes.fromhex(assertion['signature_ed25519']),
                    DOMAIN + role.encode('ascii') + b'\x00' + _canonical(unsigned))
            except (cp.InvalidSignature, ValueError) as exc:
                raise ProvenanceError('EC266_ASSERTION_SIGNATURE_INVALID') from exc
            new_pubs[role] = public
        if self._config is None:
            self._config = config
            self._subject = subject
            self._pubs = new_pubs
        elif subject != self._subject or new_pubs != self._pubs:
            deny('EC266_ADMISSION_AUTHORITY_CHANGED')
        self._verified = True

    def startup(self, policy: dict[str, Any], policy_sha: str) -> None:
        super().startup(policy, policy_sha)
        self._check_provenance(policy, policy_sha)

    def recheck_startup(self, policy: dict[str, Any], policy_sha: str) -> None:
        """Host preflight was already performed before its first audit append."""
        self.before_begin(policy, policy_sha, {'profile_id': self.profile_id})

    def before_begin(self, policy: dict[str, Any], policy_sha: str,
                     request: dict[str, Any]) -> None:
        super().before_begin(policy, policy_sha, request)
        self._check_provenance(policy, policy_sha)

    def summary(self) -> dict[str, Any]:
        if not self._verified:
            deny('EC266_GATE_NOT_VERIFIED')
        return {'status': 'partial', 'exit_code': 2,
                'reason_code': 'EC266_PINNED_ROLE_SIGNATURES_NOT_REMOTE_PROVIDER_PROOF',
                'role_signatures_valid': list(ROLES),
                'source_subject_sha256': _digest(_canonical(self._subject)),
                'source_tar_sha256': self._subject['source_tar_sha256'],
                'source_commit_oid': self._subject['commit_oid'],
                'original_ec253_mac_tickets_valid_now': True,
                'independent_remote_signer_machine_verified': False,
                'remote_git_review_ci_provider_verified': False,
                'real_rootless_podman_verified': False,
                'overall_quality_pass_verified': False}
