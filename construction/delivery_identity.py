#!/usr/bin/env python3
"""EC223: verify an explicit *single* recipient/channel/audience/project route.

This is a local read-only verifier, not a directory search, credential broker,
external contact, privacy declassifier, EC224 delivery approval, or EC225 send.
Three DIFFERENT out-of-band host-pinned Ed25519 roots attest: one exact
project-scoped directory route, one recent status-of-revocation checkpoint, and
an independent operator identity-check permit bound to an EC221+EC222 result.
No trust key may be learned from a requested route, response, or Git author.

A valid route asserts identity according to the HOST'S provisioned issuer.
It cannot independently establish that an organization's directory is honest,
that its accounts belong to particular real humans, that a checkpoint remains
current after issue, or that content is eligible for external disclosure.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import re
import time
from typing import Any

try:
    from . import delivery_preview as dp
    from . import delivery_redaction as dr
except ImportError:
    import delivery_preview as dp
    import delivery_redaction as dr

SCHEMA = 'ces.delivery_identity.v1'
ROUTE_SCHEMA = 'ces.delivery_identity.route.v1'
REVOCATION_SCHEMA = 'ces.delivery_identity.revocations.v1'
PERMIT_SCHEMA = 'ces.delivery_identity.permit.v1'
ROUTE_DOMAIN = b'CES-EC223-SIGNED-EXACT-DIRECTORY-ROUTE-v1\x00'
REVOCATION_DOMAIN = b'CES-EC223-SIGNED-REVOCATION-CHECKPOINT-v1\x00'
PERMIT_DOMAIN = b'CES-EC223-SIGNED-VERIFICATION-PERMIT-v1\x00'
COMMIT_DOMAIN = b'CES-EC223-DESTINATION-IDENTITY-COMMITMENT-v1\x00'
PROJECT_DOMAIN = b'CES-EC223-PROJECT-SCOPE-v1\x00'
VERIFIED_DOMAIN = b'CES-EC223-EXACT-LOCAL-IDENTITY-VERIFICATION-v1\x00'
TRUST_DOMAIN = b'CES-EC223-HOST-TRUST-ANCHORS-v1\x00'
SHA = re.compile(r'[a-f0-9]{64}\Z', re.ASCII)
SIG = re.compile(r'[a-f0-9]{128}\Z', re.ASCII)
OPAQUE = re.compile(r'[a-z][a-z0-9_-]{7,63}\Z', re.ASCII)
ISSUER = re.compile(r'[a-z][a-z0-9_-]{7,63}\Z', re.ASCII)
PROJECT = re.compile(r'proj_[a-z0-9_-]{8,63}\Z', re.ASCII)
ROLES = frozenset(('REPORT_REVIEWER', 'SECURITY_REVIEWER', 'PROJECT_OWNER'))
RECIPIENT_KINDS = frozenset(('MANAGED_HUMAN', 'MANAGED_SERVICE'))
MAX_ROUTE_AGE_S = 300
MAX_CHECKPOINT_AGE_S = 60
MAX_PERMIT_AGE_S = 120
MAX_FUTURE_SKEW = 15
MAX_STATEMENT_BYTES = 8192
PRIVACY = dp.PRIVACY


@dataclass(frozen=True)
class TrustedIdentityRoots:
    """Provisioned by trusted host config, NEVER extracted from statements.

    Three distinct 32-byte Ed25519 public keys must belong to an independently
    vetted issuer. An arbitrary caller-configured issuer is NOT identity proof.
    """
    issuer_id: str
    directory_public_key: bytes
    revocation_public_key: bytes
    verification_public_key: bytes


@dataclass(frozen=True)
class SignedIdentityStatement:
    statement: dict[str, Any]
    signature_hex: str


@dataclass(frozen=True)
class DeliveryIdentityRequest:
    sensitive_review_request: dr.SensitiveReviewRequest
    expected_review_id: str
    expected_redacted_markdown_sha256: str
    project_id: str
    directory_route: SignedIdentityStatement
    revocation_checkpoint: SignedIdentityStatement
    verification_permit: SignedIdentityStatement
    permit_independent_identity_verification: bool


class IdentityDenied(ValueError):
    def __init__(self, code: str, status: str = 'blocked') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def need(ok: bool, code: str, status: str = 'blocked') -> None:
    if not ok:
        raise IdentityDenied(code, status)


def _exact(doc: Any, keys: set[str], code: str) -> None:
    need(type(doc) is dict and set(doc) == keys, code, 'invalid_input')


def _opaque(s: Any) -> bool:
    return type(s) is str and OPAQUE.fullmatch(s) is not None


def _epoch(s: Any) -> bool:
    return type(s) is int and 946684800 <= s <= 4102444800


def _time_window(doc: dict[str, Any], now: int, max_age: int, code: str) -> None:
    issued, expires = doc.get('issued_at'), doc.get('expires_at')
    need(_epoch(issued) and _epoch(expires) and issued < expires and
         expires - issued <= max_age and issued <= now + MAX_FUTURE_SKEW and
         issued >= now - max_age and expires > now, code)


def _bounded_values(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> bool:
    """Cheap input-size/depth gate *before* allocating canonical JSON bytes."""
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > 128 or depth > 8:
        return False
    if type(value) is dict:
        return (len(value) <= 32 and
                all(type(k) is str and len(k) <= 96 and
                    _bounded_values(v, depth=depth + 1, budget=budget)
                    for k, v in value.items()))
    if type(value) in (list, tuple):
        return (len(value) <= 32 and
                all(_bounded_values(v, depth=depth + 1, budget=budget)
                    for v in value))
    if type(value) is str:
        return len(value) <= 2048
    return value is None or type(value) in (int, bool)


def _snapshot_signed(envelope: Any, code: str) -> tuple[dict[str, Any], bytes]:
    need(type(envelope) is SignedIdentityStatement and
         type(envelope.signature_hex) is str and
         SIG.fullmatch(envelope.signature_hex) is not None,
         code + '_ENVELOPE_INVALID', 'invalid_input')
    need(_bounded_values(envelope.statement), code + '_BOUNDED_SHAPE_REQUIRED',
         'invalid_input')
    try:
        raw = dp.canonical(envelope.statement)
        need(len(raw) <= MAX_STATEMENT_BYTES, code + '_TOO_LARGE', 'invalid_input')
        obj = json.loads(raw)
        need(type(obj) is dict, code + '_NOT_OBJECT', 'invalid_input')
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        raise IdentityDenied(code + '_INVALID_JSON', 'invalid_input') from None
    return obj, bytes.fromhex(envelope.signature_hex)


def _signature(key: bytes, domain: bytes, doc: dict[str, Any], sig: bytes,
               code: str) -> None:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(key).verify(sig, domain + dp.canonical(doc))
    except ImportError:
        raise IdentityDenied('CRYPTO_VERIFIER_NOT_AVAILABLE', 'unavailable') from None
    except Exception:
        raise IdentityDenied(code) from None


def _sha(domain: bytes, doc: Any) -> str:
    return dp.sha(domain, doc)


def _commit(issuer: str, project: str, kind: str, stable_id: str) -> str:
    return _sha(COMMIT_DOMAIN, {'issuer_id': issuer, 'project_id': project,
                                'kind': kind, 'stable_id': stable_id})


def identity_commitment(issuer_id: str, project_id: str, kind: str,
                        stable_id: str) -> str:
    """Build a destination commitment from independently selected IDs.

    Public deterministic hashing is NOT recipient authentication and may be
    linkable/guessable. Call only within an approved host directory adapter.
    """
    if (type(issuer_id) is not str or ISSUER.fullmatch(issuer_id) is None or
        type(project_id) is not str or PROJECT.fullmatch(project_id) is None or
        type(kind) is not str or kind not in
            (RECIPIENT_KINDS | dp.CHANNELS | dp.AUDIENCES) or
        not _opaque(stable_id)):
        raise ValueError('INVALID_EXPLICIT_IDENTITY_COMMITMENT_INPUT')
    return _commit(issuer_id, project_id, kind, stable_id)


def _refusal(code: str, status: str) -> dict[str, Any]:
    return {'schema': SCHEMA, 'status': status,
            'exit_code': 4 if status == 'invalid_input' else 5,
            'reason_code': 'DELIVERY_IDENTITY_' + code,
            'identity_verification_id': None, 'verification': None,
            'delivery_state': 'NO_DELIVERY_OR_PUBLICATION',
            'effects': dp.effects()}


class DeliveryIdentityVerifier:
    """No automatic directory lookup; trust roots are NOT per-request input."""

    def __init__(self, trusted_roots: TrustedIdentityRoots) -> None:
        if (type(trusted_roots) is not TrustedIdentityRoots or
            type(trusted_roots.issuer_id) is not str or
            ISSUER.fullmatch(trusted_roots.issuer_id) is None or
            not all(type(k) is bytes and len(k) == 32 and k != b'\x00' * 32
                    for k in (trusted_roots.directory_public_key,
                              trusted_roots.revocation_public_key,
                              trusted_roots.verification_public_key)) or
            len({trusted_roots.directory_public_key,
                 trusted_roots.revocation_public_key,
                 trusted_roots.verification_public_key}) != 3):
            raise ValueError('INVALID_OUT_OF_BAND_IDENTITY_TRUST_ROOTS')
        self._issuer = trusted_roots.issuer_id
        self._directory_key = trusted_roots.directory_public_key
        self._revocation_key = trusted_roots.revocation_public_key
        self._verification_key = trusted_roots.verification_public_key
        self._root_pin = _sha(TRUST_DOMAIN, {
            'issuer_id': self._issuer,
            'directory_public_key_sha256': hashlib.sha256(self._directory_key).hexdigest(),
            'revocation_public_key_sha256': hashlib.sha256(self._revocation_key).hexdigest(),
            'verification_public_key_sha256': hashlib.sha256(self._verification_key).hexdigest(),
        })

    def _preflight(self, req: DeliveryIdentityRequest, now: int) -> tuple[dict[str, Any],
                                        dict[str, Any], dict[str, Any], str, str, str]:
        need(type(req) is DeliveryIdentityRequest and
             type(req.sensitive_review_request) is dr.SensitiveReviewRequest and
             type(req.sensitive_review_request.preview_request) is dp.DeliveryPreviewRequest,
             'EXACT_REVIEW_REQUEST_REQUIRED', 'invalid_input')
        need(type(req.permit_independent_identity_verification) is bool,
             'IDENTITY_CHECK_CONSENT_TYPE_INVALID', 'invalid_input')
        need(req.permit_independent_identity_verification is True,
             'INDEPENDENT_IDENTITY_CHECK_CONSENT_REQUIRED', 'unavailable')
        need(type(req.project_id) is str and PROJECT.fullmatch(req.project_id) is not None,
             'PROJECT_SCOPE_REQUIRED', 'invalid_input')
        need(type(req.expected_review_id) is str and
             re.fullmatch(r'cesdr1:[a-f0-9]{64}', req.expected_review_id) is not None and
             dp.valid_sha(req.expected_redacted_markdown_sha256),
             'EXACT_EC222_REVIEW_AND_SUMMARY_HASH_REQUIRED', 'invalid_input')
        base = req.sensitive_review_request
        need(type(base.expected_preview_id) is str and
             re.fullmatch(r'cesdp1:[a-f0-9]{64}', base.expected_preview_id) is not None and
             base.expected_policy_sha256 == dr.ACTIVE_POLICY_SHA256 and
             base.preview_request.policy_revision_sha256 == dr.ACTIVE_POLICY_SHA256,
             'REVIEW_POLICY_OR_PREVIEW_NOT_PINNED', 'invalid_input')
        dest = dp.destination_shape(base.preview_request.destination)
        need(all(dp.valid_sha(dest[k]) for k in (
            'audience_identity_sha256', 'channel_identity_sha256',
            'recipient_identity_sha256')),
            'ALL_THREE_EXPLICIT_IDENTITIES_REQUIRED', 'invalid_input')
        directory, route_sig = _snapshot_signed(req.directory_route, 'ROUTE')
        checkpoint, checkpoint_sig = _snapshot_signed(req.revocation_checkpoint, 'REVOCATION')
        permit, permit_sig = _snapshot_signed(req.verification_permit, 'PERMIT')
        # A signed singleton is deliberately NOT a list, search, group expansion,
        # Git author lookup, or arbitrary address or URL provided by the caller.
        _exact(directory, {'schema', 'issuer_id', 'project', 'recipient', 'channel',
                           'audience', 'directory_epoch', 'issued_at', 'expires_at'},
               'ROUTE_SHAPE_INVALID')
        need(directory['schema'] == ROUTE_SCHEMA and directory['issuer_id'] == self._issuer,
             'ROUTE_ISSUER_OR_SCHEMA_MISMATCH')
        _exact(directory['project'], {'id', 'status', 'max_privacy'}, 'PROJECT_SHAPE_INVALID')
        _exact(directory['recipient'], {'id', 'kind', 'project_id', 'role', 'status',
                                       'privacy_ceiling'}, 'RECIPIENT_SHAPE_INVALID')
        _exact(directory['channel'], {'id', 'kind', 'project_id', 'member_recipient_id',
                                     'membership', 'visibility', 'privacy_ceiling',
                                     'status'}, 'CHANNEL_SHAPE_INVALID')
        _exact(directory['audience'], {'id', 'kind', 'project_id', 'member_recipient_id',
                                      'selection', 'visibility', 'status'},
               'AUDIENCE_SHAPE_INVALID')
        p, r, c, a = (directory[k] for k in ('project', 'recipient', 'channel', 'audience'))
        need(p['id'] == req.project_id and
             all(x == req.project_id for x in (r['project_id'], c['project_id'],
                                                 a['project_id'])) and
             all(_opaque(x['id']) for x in (r, c, a)) and
             type(directory['directory_epoch']) is int and
             1 <= directory['directory_epoch'] <= 2**63 - 1 and
             r['kind'] in RECIPIENT_KINDS and r['role'] in ROLES and
             c['kind'] in dp.CHANNELS and a['kind'] in dp.AUDIENCES and
             all(x in PRIVACY for x in (p['max_privacy'], r['privacy_ceiling'],
                                         c['privacy_ceiling'])) and
             c['member_recipient_id'] == r['id'] == a['member_recipient_id'] and
             c['membership'] == 'DIRECT_AUTHORITY_ATTESTED' and
             a['selection'] == 'EXPLICIT_SINGLE_RECIPIENT' and
             c['visibility'] in ('PROJECT_PRIVATE', 'EXTERNAL_RESTRICTED') and
             a['visibility'] in ('PROJECT_PRIVATE', 'EXTERNAL_RESTRICTED'),
             'ROUTE_SCOPE_ROLE_OR_EXPLICIT_MEMBERSHIP_INVALID')
        _time_window(directory, now, MAX_ROUTE_AGE_S, 'ROUTE_STALE_OR_EXPIRED')
        _signature(self._directory_key, ROUTE_DOMAIN, directory, route_sig,
                   'ROUTE_SIGNATURE_INVALID')
        need(all(x['status'] == 'ACTIVE' for x in (p, r, c, a)),
             'DIRECTORY_ENTITY_INACTIVE_OR_REVOKED')
        need(dest['audience_kind'] == a['kind'] and
             dest['channel_kind'] == c['kind'] and
             hmac.compare_digest(dest['recipient_identity_sha256'], _commit(
                 self._issuer, req.project_id, r['kind'], r['id'])) and
             hmac.compare_digest(dest['channel_identity_sha256'], _commit(
                 self._issuer, req.project_id, c['kind'], c['id'])) and
             hmac.compare_digest(dest['audience_identity_sha256'], _commit(
                 self._issuer, req.project_id, a['kind'], a['id'])),
             'DESTINATION_IDENTITY_COMMITMENTS_MISMATCH')
        route_sha = _sha(ROUTE_DOMAIN, directory)
        _exact(checkpoint, {'schema', 'issuer_id', 'project_id', 'route_sha256',
                            'directory_epoch', 'revocation_epoch', 'states',
                            'issued_at', 'expires_at'}, 'REVOCATION_SHAPE_INVALID')
        _exact(checkpoint['states'], {'project', 'recipient', 'channel', 'audience'},
               'REVOCATION_SCOPE_INVALID')
        need(checkpoint['schema'] == REVOCATION_SCHEMA and
             checkpoint['issuer_id'] == self._issuer and
             checkpoint['project_id'] == req.project_id and
             checkpoint['route_sha256'] == route_sha and
             type(checkpoint['directory_epoch']) is int and
             checkpoint['directory_epoch'] == directory['directory_epoch'] and
             type(checkpoint['revocation_epoch']) is int and
             checkpoint['revocation_epoch'] >= directory['directory_epoch'],
             'REVOCATION_ROUTE_OR_EPOCH_MISMATCH')
        _time_window(checkpoint, now, MAX_CHECKPOINT_AGE_S,
                     'REVOCATION_CHECKPOINT_STALE_OR_EXPIRED')
        _signature(self._revocation_key, REVOCATION_DOMAIN, checkpoint,
                   checkpoint_sig, 'REVOCATION_SIGNATURE_INVALID')
        need(all(x == 'ACTIVE' for x in checkpoint['states'].values()),
             'REVOCATION_CHECKPOINT_NOT_ALL_ACTIVE')
        checkpoint_sha = _sha(REVOCATION_DOMAIN, checkpoint)
        _exact(permit, {'schema', 'issuer_id', 'project_id', 'route_sha256',
                        'revocation_checkpoint_sha256', 'preview_id', 'review_id',
                        'policy_revision_sha256', 'redacted_markdown_sha256',
                        'destination_binding_sha256', 'purpose', 'operator_id',
                        'operator_role', 'issued_at', 'expires_at'},
               'PERMIT_SHAPE_INVALID')
        expected_dest_binding = _sha(dp.DEST_DOMAIN, dest)
        need(permit['schema'] == PERMIT_SCHEMA and
             permit['issuer_id'] == self._issuer and
             permit['project_id'] == req.project_id and
             permit['route_sha256'] == route_sha and
             permit['revocation_checkpoint_sha256'] == checkpoint_sha and
             permit['preview_id'] == base.expected_preview_id and
             permit['review_id'] == req.expected_review_id and
             permit['policy_revision_sha256'] == dr.ACTIVE_POLICY_SHA256 and
             permit['redacted_markdown_sha256'] == req.expected_redacted_markdown_sha256 and
             permit['destination_binding_sha256'] == expected_dest_binding and
             permit['purpose'] == 'EC223_EXACT_IDENTITY_CHECK_NO_SEND' and
             _opaque(permit['operator_id']) and
             permit['operator_role'] == 'DIRECTORY_IDENTITY_VERIFIER',
             'PERMIT_EXACT_SCOPE_OR_OPERATOR_MISMATCH')
        _time_window(permit, now, MAX_PERMIT_AGE_S, 'PERMIT_STALE_OR_EXPIRED')
        _signature(self._verification_key, PERMIT_DOMAIN, permit, permit_sig,
                   'PERMIT_SIGNATURE_INVALID')
        # Identity of a signed selected target != external privacy clearance.
        # With EC221's INTERNAL+ source floor, group/public destinations and
        # external-target disclosure cannot safely be declared eligible.
        need(a['kind'] == 'INTERNAL_REVIEW' and
             a['visibility'] == 'PROJECT_PRIVATE' and
             c['visibility'] == 'PROJECT_PRIVATE',
             'EXTERNAL_OR_BROADCAST_TARGET_NOT_ELIGIBLE')
        return directory, checkpoint, permit, route_sha, checkpoint_sha, expected_dest_binding

    def verify(self, request: DeliveryIdentityRequest) -> dict[str, Any]:
        """Verify signed target, then freshly re-evaluate REAL pinned EC222.

        No persisted proof, network, discovery, send, publication or source edit.
        Source re-reads can race subsequent revocation; EC224/225 must perform
        their own fresh gate before any future external side effect.
        """
        try:
            current = time.time()
            need(type(current) in (int, float) and math.isfinite(current) and
                 946684800 <= current <= 4102444800,
                 'HOST_CLOCK_UNAVAILABLE', 'unavailable')
            now = int(current)
            route, checkpoint, permit, route_sha, checkpoint_sha, dest_sha = (
                self._preflight(request, now))
            # EC222 re-runs EC221's EXACT private source/store/version/policy
            # check. Never accept caller-submitted `SAFE` or preview JSON.
            review = dr.review_sensitive_delivery(request.sensitive_review_request)
            need(type(review) is dict and review.get('status') == 'partial' and
                 review.get('exit_code') == 2 and
                 review.get('review_id') == request.expected_review_id and
                 review.get('redacted_markdown_sha256') ==
                     request.expected_redacted_markdown_sha256 and
                 type(review.get('redacted_markdown')) is str and
                 hashlib.sha256(review['redacted_markdown'].encode('utf-8')).hexdigest() ==
                     request.expected_redacted_markdown_sha256,
                 'EXACT_SAFE_LOCAL_EC222_REVIEW_NOT_AVAILABLE', 'unavailable')
            result = review.get('review')
            need(type(result) is dict and result.get('review_id') == review['review_id'] and
                 result.get('verdict') == 'SAFE_REDACTED_SUMMARY' and
                 result.get('policy_revision_sha256') == dr.ACTIVE_POLICY_SHA256 and
                 result.get('base_preview_id') ==
                    request.sensitive_review_request.expected_preview_id and
                 result.get('destination_binding_sha256') == dest_sha and
                 result.get('source_bytes_emitted') is False and
                 result.get('safe_for_external_send') is False and
                 result.get('ready_to_send') is False and
                 type(result.get('source_assessments')) is list and
                 1 <= len(result['source_assessments']) <= dp.MAX_SOURCES and
                 all(type(row) is dict and
                     row.get('safe_under_fixed_local_policy') is True and
                     row.get('content_examined') is True and
                     dp.valid_sha(row.get('source_version_sha256')) and
                     dp.valid_sha(row.get('source_content_sha256')) and
                     dp.valid_sha(row.get('store_revision_sha256'))
                     for row in result['source_assessments']),
                 'EC222_SOURCE_OR_MANIFEST_BINDING_UNAVAILABLE', 'unavailable')
            privacy = result.get('effective_minimum_privacy_class')
            need(privacy in PRIVACY, 'CONTENT_PRIVACY_CLASS_UNKNOWN', 'unavailable')
            ceiling = min(PRIVACY.index(route[k]['privacy_ceiling']) for k in
                          ('recipient', 'channel'))
            ceiling = min(ceiling, PRIVACY.index(route['project']['max_privacy']))
            need(PRIVACY.index(privacy) <= ceiling,
                 'CONTENT_EXCEEDS_SIGNED_VISIBILITY_CEILING')
            # A report reviewer has no signed confidential/restricted role,
            # even if a compromised directory row claims high clearance.
            allowed = {'REPORT_REVIEWER': ('INTERNAL',),
                       'SECURITY_REVIEWER': ('INTERNAL', 'CONFIDENTIAL'),
                       'PROJECT_OWNER': ('INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')}
            need(privacy in allowed[route['recipient']['role']],
                 'RECIPIENT_ROLE_INSUFFICIENT_FOR_CONTENT')
            # Inspect validity again before returning; a slow private store
            # read must not turn an already-expired checkpoint into a success.
            finish = time.time()
            need(type(finish) in (int, float) and math.isfinite(finish) and
                 finish >= current and int(finish) < min(
                     route['expires_at'], checkpoint['expires_at'], permit['expires_at']) and
                 finish - checkpoint['issued_at'] <= MAX_CHECKPOINT_AGE_S,
                 'IDENTITY_EVIDENCE_EXPIRED_DURING_PRIVATE_RECHECK', 'unavailable')
            source_set = [{'kind': row['source_kind'],
                           'version_sha256': row['source_version_sha256'],
                           'content_sha256': row['source_content_sha256'],
                           'store_revision_sha256': row['store_revision_sha256']}
                          for row in result['source_assessments']]
            verification = {
                'trust_anchor_binding_sha256': self._root_pin,
                'project_binding_sha256': _sha(PROJECT_DOMAIN, {
                    'issuer_id': self._issuer, 'project_id': request.project_id}),
                'destination_binding_sha256': dest_sha,
                'route_sha256': route_sha,
                'revocation_checkpoint_sha256': checkpoint_sha,
                'verification_permit_sha256': _sha(PERMIT_DOMAIN, permit),
                'base_preview_id': result['base_preview_id'],
                'review_id': review['review_id'],
                'policy_revision_sha256': dr.ACTIVE_POLICY_SHA256,
                'redacted_markdown_sha256': review['redacted_markdown_sha256'],
                'source_set_sha256': _sha(VERIFIED_DOMAIN, source_set),
                'effective_minimum_privacy_class': privacy,
                'verified_under_host_pinned_directory_only': True,
                'recipient_verified': True, 'channel_verified': True,
                'audience_verified': True, 'project_verified': True,
                'explicit_single_recipient': True,
                'fresh_signed_revocation_checkpoint_checked': True,
                'independent_signed_check_permission_checked': True,
                'real_world_person_identity_independently_proven': False,
                'organizational_privacy_declassification': False,
                'recipient_contacted': False,
                'is_deliverable_payload': False, 'ready_to_send': False,
                'safe_for_external_send': False,
                'delivery_authorized': False, 'message_sent': False,
                'published': False, 'cross_source_atomic_snapshot': False,
            }
            proof_id = 'cesdi1:' + _sha(VERIFIED_DOMAIN, verification)
            effects = dp.effects()
            effects['recipient_identity_verified'] = True
            return {'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
                    'reason_code': 'DELIVERY_IDENTITY_HOST_PINNED_INTERNAL_ROUTE_ONLY',
                    'identity_verification_id': proof_id,
                    'verification': {'identity_verification_id': proof_id, **verification},
                    'delivery_state': 'NO_DELIVERY_OR_PUBLICATION', 'effects': effects}
        except (IdentityDenied, dp.PreviewDenied) as exc:
            return _refusal(exc.code, exc.status)
        except Exception:
            # NEVER expose source paths, identities, untrusted content or
            # underlying host exception text.
            return _refusal('PRIVATE_REVIEW_OR_IDENTITY_CHECK_UNAVAILABLE', 'unavailable')
