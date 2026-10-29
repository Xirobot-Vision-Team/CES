#!/usr/bin/env python3
"""EC224: independently signed, exact-content, exact-target LOCAL approval.

Requires the REAL EC223 verifier to re-read EC222/EC221 exact private sources.
Three independently host-pinned Ed25519 authorization keys (an individual
approver key, an organization entitlement key, a revocation key) must be
DISTINCT from all three EC223 directory/identity keys. The organization
entitlement authorizes one exact operator/content/route/privacy tuple; the
operator signs an exact short-lived grant; a fresh organization checkpoint
covers their keys/permission/grant. Nothing here creates a send capability.

Not a directory, contact resolver, organizational PKI enrollment, online
revocation oracle, declassifier, send provider, or durable single-use ledger.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
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
    from . import delivery_identity as di
except ImportError:
    import delivery_preview as dp
    import delivery_redaction as dr
    import delivery_identity as di

SCHEMA = 'ces.delivery_authorization.v1'
GRANT_SCHEMA = 'ces.delivery_authorization.grant.v1'
ENTITLEMENT_SCHEMA = 'ces.delivery_authorization.entitlement.v1'
REVOCATION_SCHEMA = 'ces.delivery_authorization.revocations.v1'
GRANT_DOMAIN = b'CES-EC224-SIGNED-EXACT-LOCAL-DELIVERY-GRANT-v1\x00'
ENTITLEMENT_DOMAIN = b'CES-EC224-SIGNED-ORG-ENTITLEMENT-v1\x00'
REVOCATION_DOMAIN = b'CES-EC224-SIGNED-GRANT-REVOCATION-v1\x00'
TRUST_DOMAIN = b'CES-EC224-OUT-OF-BAND-APPROVAL-ROOTS-v1\x00'
CODE_DOMAIN = b'CES-EC224-SOURCE-BOUND-LOCAL-APPROVAL-POLICY-v1\x00'
RECEIPT_DOMAIN = b'CES-EC224-LOCAL-EXACT-APPROVAL-RECEIPT-v1\x00'
PURPOSE = 'EXACT_INTERNAL_SINGLE_RECIPIENT_LOCAL_APPROVAL_NO_SEND'
MEDIA_TYPE = 'text/markdown; charset=utf-8'
MAX_ENTITLEMENT_AGE_S = 180
MAX_GRANT_AGE_S = 90
MAX_REVOCATION_AGE_S = 45
MAX_FUTURE_SKEW_S = 15
MAX_SIGNED_JSON_BYTES = 16384
SHA = re.compile(r'[a-f0-9]{64}\Z', re.ASCII)
SIG = re.compile(r'[a-f0-9]{128}\Z', re.ASCII)
NONCE = re.compile(r'[a-f0-9]{32}\Z', re.ASCII)
PROOF = re.compile(r'cesdi1:[a-f0-9]{64}\Z', re.ASCII)
PRIVACY = dp.PRIVACY


def _code_sha() -> str | None:
    """Approvals invalidate across changes to these shipped code boundaries."""
    try:
        folder = Path(__file__).resolve().parent
        src = {name: hashlib.sha256((folder / name).read_bytes()).hexdigest()
               for name in ('delivery_authorization.py', 'delivery_identity.py',
                            'delivery_redaction.py', 'delivery_preview.py')}
        return dp.sha(CODE_DOMAIN, {'source_sha256': src,
                                    'redaction_policy_sha256': dr.ACTIVE_POLICY_SHA256,
                                    'approval_purpose': PURPOSE,
                                    'no_delivery_side_effects': True})
    except (OSError, ValueError, TypeError):
        return None


ACTIVE_APPROVAL_CODE_SHA256 = _code_sha()


@dataclass(frozen=True)
class TrustedAuthorizationRoots:
    """Configured separately by HOST; never learned from a request's JSON.

    minimum_revocation_epoch must be advanced by a trusted host on revocation;
    checkpoint age alone cannot detect an emergency revocation after issuance.
    """
    issuer_id: str
    organization_id: str
    approver_id: str
    approval_public_key: bytes
    organization_entitlement_public_key: bytes
    organization_revocation_public_key: bytes
    minimum_revocation_epoch: int


@dataclass(frozen=True)
class SignedAuthorizationStatement:
    statement: dict[str, Any]
    signature_hex: str


@dataclass(frozen=True)
class DeliveryAuthorizationRequest:
    identity_request: di.DeliveryIdentityRequest
    expected_identity_verification_id: str
    exact_payload_bytes: bytes
    organization_entitlement: SignedAuthorizationStatement
    exact_delivery_grant: SignedAuthorizationStatement
    organization_revocation_checkpoint: SignedAuthorizationStatement
    permit_independent_delivery_authorization: bool


class AuthorizationDenied(ValueError):
    def __init__(self, code: str, status: str = 'blocked') -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def need(ok: bool, code: str, status: str = 'blocked') -> None:
    if not ok:
        raise AuthorizationDenied(code, status)


def exact(doc: Any, keys: set[str], code: str) -> None:
    need(type(doc) is dict and set(doc) == keys, code, 'invalid_input')


def sha_string(value: Any) -> bool:
    return type(value) is str and SHA.fullmatch(value) is not None


def _bounded(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> bool:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > 256 or depth > 6:
        return False
    if type(value) is dict:
        return len(value) <= 64 and all(
            type(key) is str and len(key) <= 100 and
            _bounded(val, depth=depth + 1, budget=budget)
            for key, val in value.items())
    if type(value) in (tuple, list):
        return len(value) <= 16 and all(
            _bounded(x, depth=depth + 1, budget=budget) for x in value)
    if type(value) is str:
        return len(value) <= 1024
    return value is None or type(value) in (bool, int)


def _snapshot_signed(item: Any, label: str) -> tuple[dict[str, Any], bytes]:
    need(type(item) is SignedAuthorizationStatement and
         type(item.signature_hex) is str and SIG.fullmatch(item.signature_hex) is not None,
         label + '_ENVELOPE_INVALID', 'invalid_input')
    need(_bounded(item.statement), label + '_INPUT_TOO_DEEP_OR_LARGE', 'invalid_input')
    try:
        encoded = dp.canonical(item.statement)
        need(len(encoded) <= MAX_SIGNED_JSON_BYTES, label + '_STATEMENT_TOO_LARGE',
             'invalid_input')
        obj = json.loads(encoded)
        need(type(obj) is dict, label + '_STATEMENT_NOT_OBJECT', 'invalid_input')
        return obj, bytes.fromhex(item.signature_hex)
    except (TypeError, UnicodeError, ValueError, OverflowError, RecursionError):
        raise AuthorizationDenied(label + '_INVALID_JSON', 'invalid_input') from None


def _verify_signature(pubkey: bytes, domain: bytes, doc: dict[str, Any],
                      signature: bytes, label: str) -> None:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(pubkey).verify(
            signature, domain + dp.canonical(doc))
    except ImportError:
        raise AuthorizationDenied('ED25519_VERIFIER_MISSING', 'unavailable') from None
    except Exception:
        raise AuthorizationDenied(label + '_SIGNATURE_INVALID') from None


def _clock() -> float:
    now = time.time()
    need(type(now) in (float, int) and math.isfinite(now) and
         946684800 <= now <= 4102444800, 'HOST_CLOCK_UNAVAILABLE', 'unavailable')
    return float(now)


def _window(doc: dict[str, Any], now: int, limit: int, label: str) -> None:
    start, end = doc.get('issued_at'), doc.get('expires_at')
    need(type(start) is int and type(end) is int and
         946684800 <= start < end <= 4102444800 and
         end - start <= limit and
         start <= now + MAX_FUTURE_SKEW_S and
         start >= now - limit and end > now,
         label + '_STALE_OR_EXPIRED')


def _refusal(code: str, status: str) -> dict[str, Any]:
    effect = dp.effects()
    return {'schema': SCHEMA, 'status': status,
            'exit_code': 4 if status == 'invalid_input' else 5,
            'reason_code': 'DELIVERY_AUTHORIZATION_' + code,
            'authorization_receipt_id': None, 'authorization': None,
            'delivery_state': 'NO_DELIVERY_OR_PUBLICATION', 'effects': effect}


class DeliveryAuthorizer:
    """Verify a local short-lived approval; NEVER send or persist content."""

    def __init__(self, authorization_roots: TrustedAuthorizationRoots,
                 identity_verifier: di.DeliveryIdentityVerifier) -> None:
        roots = authorization_roots
        if (type(roots) is not TrustedAuthorizationRoots or
            type(identity_verifier) is not di.DeliveryIdentityVerifier or
            type(roots.issuer_id) is not str or di.ISSUER.fullmatch(roots.issuer_id) is None or
            type(roots.organization_id) is not str or not di._opaque(roots.organization_id) or
            type(roots.approver_id) is not str or not di._opaque(roots.approver_id) or
            type(roots.minimum_revocation_epoch) is not int or
            not 1 <= roots.minimum_revocation_epoch <= 2**63 - 1):
            raise ValueError('INVALID_OUT_OF_BAND_APPROVAL_TRUST_ROOTS')
        keys = (roots.approval_public_key, roots.organization_entitlement_public_key,
                roots.organization_revocation_public_key,
                identity_verifier._directory_key, identity_verifier._revocation_key,
                identity_verifier._verification_key)
        if (not all(type(k) is bytes and len(k) == 32 and k != b'\x00' * 32
                    for k in keys) or len(set(keys)) != len(keys)):
            raise ValueError('APPROVAL_KEYS_MUST_BE_DISTINCT_FROM_EC223_KEYS')
        self._roots = roots
        self._identity = identity_verifier
        self._root_pin = dp.sha(TRUST_DOMAIN, {
            'authorization_issuer_id': roots.issuer_id,
            'organization_id': roots.organization_id,
            'approver_id': roots.approver_id,
            'approval_public_key_sha256': hashlib.sha256(keys[0]).hexdigest(),
            'entitlement_public_key_sha256': hashlib.sha256(keys[1]).hexdigest(),
            'revocation_public_key_sha256': hashlib.sha256(keys[2]).hexdigest(),
            'identity_trust_anchor_binding_sha256': identity_verifier._root_pin,
        })

    def _preflight(self, req: DeliveryAuthorizationRequest, now: int) -> dict[str, Any]:
        need(type(req) is DeliveryAuthorizationRequest and
             type(req.identity_request) is di.DeliveryIdentityRequest and
             type(req.permit_independent_delivery_authorization) is bool,
             'EXACT_AUTHORIZATION_REQUEST_REQUIRED', 'invalid_input')
        need(req.permit_independent_delivery_authorization is True,
             'INDEPENDENT_DELIVERY_APPROVAL_CONSENT_REQUIRED', 'unavailable')
        need(type(req.expected_identity_verification_id) is str and
             PROOF.fullmatch(req.expected_identity_verification_id) is not None,
             'EXACT_EC223_PROOF_ID_REQUIRED', 'invalid_input')
        payload = req.exact_payload_bytes
        need(type(payload) is bytes and 0 < len(payload) <= dr.MAX_SUMMARY_BYTES,
             'BOUNDED_EXACT_PAYLOAD_BYTES_REQUIRED', 'invalid_input')
        try:
            decoded = payload.decode('utf-8', errors='strict')
            need(decoded.encode('utf-8') == payload and '\x00' not in decoded and
                 not decoded.startswith('\ufeff'), 'NONCANONICAL_UTF8_PAYLOAD', 'invalid_input')
        except UnicodeError:
            raise AuthorizationDenied('NONCANONICAL_UTF8_PAYLOAD', 'invalid_input') from None
        payload_sha = hashlib.sha256(payload).hexdigest()
        need(ACTIVE_APPROVAL_CODE_SHA256 is not None and
             _code_sha() == ACTIVE_APPROVAL_CODE_SHA256 and
             dr.ACTIVE_POLICY_SHA256 is not None,
             'FIXED_SOURCE_BOUND_APPROVAL_POLICY_UNAVAILABLE', 'unavailable')
        # Before PRIVATE reads, validate the genuine signed EC223 singleton,
        # exact destination identities, check-only operator, and revocations.
        try:
            route, route_rev, identity_permit, route_sha, rev_sha, dest_sha = (
                self._identity._preflight(req.identity_request, now))
        except di.IdentityDenied as error:
            raise AuthorizationDenied('EC223_' + error.code, error.status) from None
        need(identity_permit['operator_id'] != self._roots.approver_id,
             'APPROVER_MUST_BE_DISTINCT_FROM_IDENTITY_CHECK_OPERATOR')
        preview_req = req.identity_request.sensitive_review_request
        dest = dp.destination_shape(preview_req.preview_request.destination)
        entitlement, entitlement_sig = _snapshot_signed(
            req.organization_entitlement, 'ENTITLEMENT')
        grant, grant_sig = _snapshot_signed(req.exact_delivery_grant, 'GRANT')
        revocation, revocation_sig = _snapshot_signed(
            req.organization_revocation_checkpoint, 'REVOCATION')

        exact(entitlement, {
            'schema', 'issuer_id', 'organization_id', 'approver_id',
            'approval_public_key_sha256', 'authorization_trust_anchor_binding_sha256',
            'project_id', 'identity_verification_id',
            'route_sha256', 'destination_binding_sha256', 'source_set_sha256',
            'payload_sha256', 'privacy_ceiling', 'purpose', 'approver_role',
            'approver_status', 'organization_status', 'may_approve_exact_internal_review',
            'authorization_epoch', 'issued_at', 'expires_at',
        }, 'ENTITLEMENT_SHAPE_INVALID')
        r = self._roots
        need(entitlement['schema'] == ENTITLEMENT_SCHEMA and
             entitlement['issuer_id'] == r.issuer_id and
             entitlement['organization_id'] == r.organization_id and
             entitlement['approver_id'] == r.approver_id and
             entitlement['approval_public_key_sha256'] == hashlib.sha256(
                 r.approval_public_key).hexdigest() and
             entitlement['authorization_trust_anchor_binding_sha256'] == self._root_pin and
             entitlement['project_id'] == req.identity_request.project_id and
             entitlement['identity_verification_id'] == req.expected_identity_verification_id and
             entitlement['route_sha256'] == route_sha and
             entitlement['destination_binding_sha256'] == dest_sha and
             sha_string(entitlement['source_set_sha256']) and
             entitlement['payload_sha256'] == payload_sha and
             entitlement['privacy_ceiling'] in PRIVACY and
             entitlement['purpose'] == PURPOSE and
             entitlement['approver_role'] == 'INTERNAL_DELIVERY_APPROVER' and
             entitlement['approver_status'] == 'ACTIVE' and
             entitlement['organization_status'] == 'ACTIVE' and
             entitlement['may_approve_exact_internal_review'] is True and
             type(entitlement['authorization_epoch']) is int and
             1 <= entitlement['authorization_epoch'] <= 2**63 - 1,
             'ORG_PERMISSION_NOT_INDEPENDENTLY_SCOPED')
        _window(entitlement, now, MAX_ENTITLEMENT_AGE_S, 'ORG_PERMISSION')
        _verify_signature(r.organization_entitlement_public_key,
                          ENTITLEMENT_DOMAIN, entitlement, entitlement_sig,
                          'ORG_PERMISSION')
        ent_sha = dp.sha(ENTITLEMENT_DOMAIN, entitlement)

        # A revocation/eligibility snapshot PRECEDES the grant. Its exact SHA
        # goes INSIDE the separately signed approver grant. This is deliberately
        # acyclic: a new ACTIVE or REVOKED checkpoint, or a changed epoch,
        # cannot be attached to an OLD approval without signing a NEW grant.
        exact(revocation, {
            'schema', 'issuer_id', 'organization_id', 'project_id',
            'identity_verification_id', 'identity_trust_anchor_binding_sha256',
            'route_sha256', 'destination_binding_sha256',
            'entitlement_sha256', 'approval_nonce', 'source_set_sha256',
            'payload_sha256', 'privacy_floor', 'policy_revision_sha256',
            'approval_code_revision_sha256',
            'authorization_trust_anchor_binding_sha256',
            'authorization_epoch', 'revocation_epoch', 'states',
            'issued_at', 'expires_at',
        }, 'REVOCATION_SHAPE_INVALID')
        exact(revocation['states'], {
            'organization', 'approver', 'approval_key', 'entitlement',
            'authorization_scope',
        }, 'REVOCATION_STATES_SHAPE_INVALID')
        r = self._roots
        need(revocation['schema'] == REVOCATION_SCHEMA and
             revocation['issuer_id'] == r.issuer_id and
             revocation['organization_id'] == r.organization_id and
             revocation['project_id'] == req.identity_request.project_id and
             revocation['identity_verification_id'] == req.expected_identity_verification_id and
             revocation['identity_trust_anchor_binding_sha256'] == self._identity._root_pin and
             revocation['route_sha256'] == route_sha and
             revocation['destination_binding_sha256'] == dest_sha and
             revocation['entitlement_sha256'] == ent_sha and
             type(revocation['approval_nonce']) is str and
             NONCE.fullmatch(revocation['approval_nonce']) is not None and
             revocation['source_set_sha256'] == entitlement['source_set_sha256'] and
             revocation['payload_sha256'] == payload_sha and
             revocation['privacy_floor'] in PRIVACY and
             PRIVACY.index(revocation['privacy_floor']) <= PRIVACY.index(
                 entitlement['privacy_ceiling']) and
             revocation['policy_revision_sha256'] == dr.ACTIVE_POLICY_SHA256 and
             revocation['approval_code_revision_sha256'] == ACTIVE_APPROVAL_CODE_SHA256 and
             revocation['authorization_trust_anchor_binding_sha256'] == self._root_pin and
             type(revocation['authorization_epoch']) is int and
             revocation['authorization_epoch'] == entitlement['authorization_epoch'] and
             type(revocation['revocation_epoch']) is int and
             revocation['revocation_epoch'] >= max(
                 entitlement['authorization_epoch'], r.minimum_revocation_epoch) and
             all(state == 'ACTIVE' for state in revocation['states'].values()),
             'APPROVAL_OR_ORG_REVOKED_OR_WRONG_CHECKPOINT')
        _window(revocation, now, MAX_REVOCATION_AGE_S, 'APPROVAL_REVOCATION')
        need(revocation['issued_at'] >= entitlement['issued_at'],
             'REVOCATION_SNAPSHOT_PREDATES_PERMISSION')
        _verify_signature(r.organization_revocation_public_key,
                          REVOCATION_DOMAIN, revocation, revocation_sig,
                          'APPROVAL_REVOCATION')
        revocation_sha = dp.sha(REVOCATION_DOMAIN, revocation)

        exact(grant, {
            'schema', 'issuer_id', 'organization_id', 'approver_id', 'approval_nonce',
            'purpose', 'project_id', 'recipient_id', 'channel_id', 'audience_id',
            'recipient_identity_sha256', 'channel_identity_sha256',
            'audience_identity_sha256', 'identity_verification_id',
            'identity_trust_anchor_binding_sha256',
            'authorization_trust_anchor_binding_sha256', 'project_binding_sha256',
            'route_sha256', 'identity_revocation_checkpoint_sha256',
            'destination_binding_sha256', 'preview_id', 'review_id',
            'policy_revision_sha256', 'approval_code_revision_sha256',
            'source_set_sha256', 'payload_sha256', 'payload_size_bytes',
            'payload_media_type', 'privacy_floor', 'entitlement_sha256',
            'organization_revocation_checkpoint_sha256', 'authorization_epoch', 'issued_at', 'expires_at',
        }, 'GRANT_SHAPE_INVALID')
        project_sha = di._sha(di.PROJECT_DOMAIN, {
            'issuer_id': self._identity._issuer,
            'project_id': req.identity_request.project_id})
        need(grant['schema'] == GRANT_SCHEMA and grant['issuer_id'] == r.issuer_id and
             grant['organization_id'] == r.organization_id and
             grant['approver_id'] == r.approver_id and
             type(grant['approval_nonce']) is str and
             NONCE.fullmatch(grant['approval_nonce']) is not None and
             grant['purpose'] == PURPOSE and
             grant['project_id'] == req.identity_request.project_id and
             grant['recipient_id'] == route['recipient']['id'] and
             grant['channel_id'] == route['channel']['id'] and
             grant['audience_id'] == route['audience']['id'] and
             grant['recipient_identity_sha256'] == dest['recipient_identity_sha256'] and
             grant['channel_identity_sha256'] == dest['channel_identity_sha256'] and
             grant['audience_identity_sha256'] == dest['audience_identity_sha256'] and
             grant['identity_verification_id'] == req.expected_identity_verification_id and
             grant['identity_trust_anchor_binding_sha256'] == self._identity._root_pin and
             grant['authorization_trust_anchor_binding_sha256'] == self._root_pin and
             grant['project_binding_sha256'] == project_sha and
             grant['route_sha256'] == route_sha and
             grant['identity_revocation_checkpoint_sha256'] == rev_sha and
             grant['destination_binding_sha256'] == dest_sha and
             grant['preview_id'] == preview_req.expected_preview_id and
             grant['review_id'] == req.identity_request.expected_review_id and
             grant['policy_revision_sha256'] == dr.ACTIVE_POLICY_SHA256 and
             grant['approval_code_revision_sha256'] == ACTIVE_APPROVAL_CODE_SHA256 and
             grant['source_set_sha256'] == entitlement['source_set_sha256'] and
             grant['payload_sha256'] == payload_sha and
             type(grant['payload_size_bytes']) is int and
             grant['payload_size_bytes'] == len(payload) and
             grant['payload_media_type'] == MEDIA_TYPE and
             grant['privacy_floor'] in PRIVACY and
             PRIVACY.index(grant['privacy_floor']) <= PRIVACY.index(
                 entitlement['privacy_ceiling']) and
             grant['entitlement_sha256'] == ent_sha and
             grant['organization_revocation_checkpoint_sha256'] == revocation_sha and
             grant['approval_nonce'] == revocation['approval_nonce'] and
             grant['privacy_floor'] == revocation['privacy_floor'] and
             grant['authorization_epoch'] == entitlement['authorization_epoch'],
             'GRANT_EXACT_CONTENT_TARGET_POLICY_OR_PERMISSION_MISMATCH')
        _window(grant, now, MAX_GRANT_AGE_S, 'APPROVAL_GRANT')
        need(entitlement['issued_at'] <= revocation['issued_at'] <= grant['issued_at'] and
             grant['issued_at'] < revocation['expires_at'] and
             grant['expires_at'] <= entitlement['expires_at'],
             'GRANT_NOT_WITHIN_INDEPENDENT_PERMISSION_WINDOW')
        _verify_signature(r.approval_public_key, GRANT_DOMAIN, grant, grant_sig,
                          'EXACT_GRANT')
        grant_sha = dp.sha(GRANT_DOMAIN, grant)

        return {'grant': grant, 'grant_sha': grant_sha,
                'entitlement': entitlement, 'entitlement_sha': ent_sha,
                'revocation': revocation, 'revocation_sha': revocation_sha,
                'route': route, 'route_revocation': route_rev,
                'identity_permit': identity_permit, 'project_sha': project_sha,
                'route_sha': route_sha, 'destination_sha': dest_sha,
                'payload_sha': payload_sha, 'payload_len': len(payload)}

    def authorize(self, request: DeliveryAuthorizationRequest) -> dict[str, Any]:
        """Return a metadata-only locally signed approval receipt, no egress.

        This method NEVER acquires Provider credentials, performs network IO,
        stores the approval, or provides EC225 with automatic send permission.
        The signed checkpoint and source content MUST be checked again before
        any later side-effect. Approval is neither one-use nor immutable proof
        against changes after this call returns.
        """
        try:
            started = _clock()
            pre = self._preflight(request, int(started))
            # Only now touch PRIVATE sources. The original EC223 verifier
            # independently rechecks its signatures, EC222 real full content,
            # EC221 exact source versions, and the post-read clock window.
            verified = self._identity.verify(request.identity_request)
            need(type(verified) is dict and verified.get('status') == 'partial' and
                 verified.get('exit_code') == 2 and
                 verified.get('identity_verification_id') ==
                     request.expected_identity_verification_id,
                 'FRESH_EXACT_EC223_IDENTITY_AND_PRIVATE_REVIEW_UNAVAILABLE',
                 'unavailable')
            v = verified.get('verification')
            g = pre['grant']
            need(type(v) is dict and
                 v.get('identity_verification_id') == verified['identity_verification_id'] and
                 v.get('trust_anchor_binding_sha256') == self._identity._root_pin and
                 v.get('project_binding_sha256') == pre['project_sha'] and
                 v.get('route_sha256') == pre['route_sha'] and
                 v.get('revocation_checkpoint_sha256') == di._sha(
                     di.REVOCATION_DOMAIN, pre['route_revocation']) and
                 v.get('destination_binding_sha256') == pre['destination_sha'] and
                 v.get('base_preview_id') == g['preview_id'] and
                 v.get('review_id') == g['review_id'] and
                 v.get('policy_revision_sha256') == g['policy_revision_sha256'] and
                 v.get('redacted_markdown_sha256') == pre['payload_sha'] and
                 v.get('source_set_sha256') == g['source_set_sha256'] and
                 v.get('effective_minimum_privacy_class') == g['privacy_floor'] and
                 all(v.get(key) is True for key in (
                     'verified_under_host_pinned_directory_only',
                     'explicit_single_recipient', 'fresh_signed_revocation_checkpoint_checked',
                     'independent_signed_check_permission_checked',
                     'recipient_verified', 'channel_verified', 'audience_verified',
                     'project_verified')) and
                 all(v.get(key) is False for key in (
                     'ready_to_send', 'safe_for_external_send',
                     'organizational_privacy_declassification', 'delivery_authorized',
                     'message_sent', 'published', 'cross_source_atomic_snapshot')),
                 'EC223_OR_PAYLOAD_SOURCE_PRIVACY_BINDING_DRIFT', 'unavailable')
            # Defense-in-depth even if EC223's signed checker is ever relaxed.
            route = pre['route']
            need(route['audience']['kind'] == 'INTERNAL_REVIEW' and
                 route['audience']['visibility'] == 'PROJECT_PRIVATE' and
                 route['channel']['visibility'] == 'PROJECT_PRIVATE' and
                 g['privacy_floor'] != 'PUBLIC',
                 'ONLY_EXACT_INTERNAL_PRIVATE_APPROVAL_SUPPORTED')
            current = _clock()
            need(_code_sha() == ACTIVE_APPROVAL_CODE_SHA256,
                 'APPROVAL_CODE_CHANGED_DURING_PRIVATE_READ', 'unavailable')
            need(current >= started and
                 current < min(pre['grant']['expires_at'],
                               pre['entitlement']['expires_at'],
                               pre['revocation']['expires_at'],
                               route['expires_at'],
                               pre['route_revocation']['expires_at'],
                               pre['identity_permit']['expires_at']) and
                 current - pre['revocation']['issued_at'] <= MAX_REVOCATION_AGE_S and
                 current - pre['route_revocation']['issued_at'] <= di.MAX_CHECKPOINT_AGE_S,
                 'AUTHORIZATION_EXPIRED_OR_CLOCK_REVERSED_AFTER_PRIVATE_READ',
                 'unavailable')
            receipt = {
                'identity_verification_id': verified['identity_verification_id'],
                'identity_trust_anchor_binding_sha256': self._identity._root_pin,
                'authorization_trust_anchor_binding_sha256': self._root_pin,
                'project_binding_sha256': pre['project_sha'],
                'destination_binding_sha256': pre['destination_sha'],
                'route_sha256': pre['route_sha'],
                'identity_revocation_checkpoint_sha256':
                    v['revocation_checkpoint_sha256'],
                'preview_id': g['preview_id'], 'review_id': g['review_id'],
                'source_set_sha256': v['source_set_sha256'],
                'redacted_markdown_sha256': pre['payload_sha'],
                'payload_bytes_sha256': pre['payload_sha'],
                'payload_size_bytes': pre['payload_len'],
                'payload_media_type': MEDIA_TYPE,
                'effective_minimum_privacy_class': g['privacy_floor'],
                'policy_revision_sha256': dr.ACTIVE_POLICY_SHA256,
                'approval_code_revision_sha256': ACTIVE_APPROVAL_CODE_SHA256,
                'organization_entitlement_sha256': pre['entitlement_sha'],
                'approver_exact_grant_sha256': pre['grant_sha'],
                'organization_revocation_checkpoint_sha256': pre['revocation_sha'],
                'expires_at': min(g['expires_at'], pre['entitlement']['expires_at'],
                                  pre['revocation']['expires_at'],
                                  route['expires_at'],
                                  pre['route_revocation']['expires_at'],
                                  pre['identity_permit']['expires_at']),
                'exact_content_and_single_target_approved_under_host_roots': True,
                'independent_organization_entitlement_verified': True,
                'independent_approver_signature_verified': True,
                'fresh_signed_grant_revocation_checked': True,
                'verified_organization_or_human_in_the_real_world': False,
                'live_provider_recipient_permission_verified': False,
                'organizational_declassification_granted': False,
                'durable_single_use_or_replay_prevention': False,
                'cross_source_atomic_snapshot': False,
                'ready_to_send': False, 'message_sent': False, 'published': False,
            }
            rid = 'cesda1:' + dp.sha(RECEIPT_DOMAIN, receipt)
            effects = dp.effects()
            effects['recipient_identity_verified'] = True
            effects['delivery_authorized'] = True  # LOCAL exact approval only.
            return {'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
                    'reason_code': 'DELIVERY_AUTHORIZATION_LOCAL_EXACT_APPROVAL_ONLY',
                    'authorization_receipt_id': rid,
                    'authorization': {'authorization_receipt_id': rid, **receipt},
                    'delivery_state': 'NO_DELIVERY_OR_PUBLICATION',
                    'effects': effects}
        except AuthorizationDenied as exc:
            return _refusal(exc.code, exc.status)
        except Exception:
            # No keys, path, raw user content or source text in error messages.
            return _refusal('PRIVATE_RECHECK_OR_APPROVAL_UNAVAILABLE', 'unavailable')
