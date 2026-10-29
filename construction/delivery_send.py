#!/usr/bin/env python3
"""EC225: one-use, signed, TEST-ONLY single-target delivery submission.

This module is an opt-in STANDALONE Python boundary, NOT a native PowerShell
DeliverySend action. It can perform real HTTPS requests only after a host has
provisioned separate send/signing authorities, a concrete sandbox destination,
credentials, a protected persistent outbox, and an explicit live-send opt-in.

Every attempt re-runs REAL EC224 -> 223 -> 222 -> 221 private source checks;
EC224 alone is NEVER an external-send grant. A separately signed <=30-second
side-effect permit binds the exact approval, content and immutable provider
account/target. The provider must return a freshly signed <=20-second sandbox
capability for the SAME recipient, account, operation, and unpredictable nonce.

A POSIX-local atomic durable, grant-keyed outbox claim is committed BEFORE any
network request; crash, replay, timeout or uncertain POST means NEVER POST again
with that approval. Any positive HTTP response is SUBMISSION_UNCONFIRMED, not
SENT, ACCEPTED or DELIVERED. EC226+ owns remote acceptance/reconciliation.
Do not use the development fake transport with real credentials or recipients.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import time
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener, HTTPRedirectHandler

try:
    from . import delivery_preview as dp, delivery_identity as di
    from . import delivery_authorization as da, delivery_redaction as dr
except ImportError:
    import delivery_preview as dp
    import delivery_identity as di
    import delivery_authorization as da
    import delivery_redaction as dr

SCHEMA = 'ces.delivery_send.v1'
SEND_PERMIT_SCHEMA = 'ces.delivery_send.side_effect_grant.v1'
CAPABILITY_SCHEMA = 'ces.delivery_send.provider_capability.v1'
PROBE_SCHEMA = 'ces.delivery_send.provider_probe.v1'
SUBMIT_SCHEMA = 'ces.delivery_send.provider_submit.v1'
PERMIT_DOMAIN = b'CES-EC225-INDEPENDENT-TEST-SIDE-EFFECT-PERMIT-v1\x00'
CAPABILITY_DOMAIN = b'CES-EC225-PROVIDER-SIGNED-SANDBOX-TARGET-CAPABILITY-v1\x00'
ROOT_DOMAIN = b'CES-EC225-HOST-SIDE-EFFECT-AND-PROVIDER-ROOTS-v1\x00'
TARGET_DOMAIN = b'CES-EC225-OUT-OF-BAND-PROVIDER-TARGET-v1\x00'
OP_DOMAIN = b'CES-EC225-GRANT-SINGLE-USE-OUTBOX-KEY-v1\x00'
CODE_DOMAIN = b'CES-EC225-SIGNED-SUBMISSION-CODE-v1\x00'
RECEIPT_DOMAIN = b'CES-EC225-ATTEMPT-ONLY-RECEIPT-v1\x00'
PURPOSE = 'SINGLE_PRIVATE_SANDBOX_TEST_DELIVERY_ONLY'
MAX_PERMIT_AGE = 30
MAX_CAPABILITY_AGE = 20
MAX_SKEW = 5
MAX_TRANSPORT_RESPONSE = 16384
MAX_BODY = 16384
IDENT = re.compile(r'[a-z][a-z0-9_-]{7,63}\Z', re.ASCII)
HEX32 = re.compile(r'[a-f0-9]{32}\Z', re.ASCII)
HOST = re.compile(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+\Z', re.ASCII)


def _code_sha() -> str | None:
    try:
        here = Path(__file__).resolve().parent
        files = {name: hashlib.sha256((here / name).read_bytes()).hexdigest()
                 for name in ('delivery_send.py', 'delivery_authorization.py',
                              'delivery_identity.py', 'delivery_redaction.py',
                              'delivery_preview.py')}
        return dp.sha(CODE_DOMAIN, {'source_sha256': files,
                                    'approval_code_sha256': da.ACTIVE_APPROVAL_CODE_SHA256,
                                    'privacy_policy_sha256': dr.ACTIVE_POLICY_SHA256,
                                    'send_scope': PURPOSE})
    except (OSError, ValueError, TypeError):
        return None


ACTIVE_SEND_CODE_SHA256 = _code_sha()


@dataclass(frozen=True)
class TrustedSideEffectRoots:
    issuer_id: str
    operator_id: str
    side_effect_public_key: bytes
    provider_capability_public_key: bytes
    minimum_send_epoch: int


@dataclass(frozen=True)
class HostTestProvider:
    """EXACT host-provisioned target; never learned from request or Git data.

    recipient_handle is an opaque, SINGLE sandbox-inbox identifier, not an
    email address, arbitrary URL or provider-recipient search query.
    credential is intentionally NOT stored in this object.
    """
    provider_id: str
    account_id: str
    endpoint: str
    recipient_handle: str
    project_id: str
    recipient_id: str
    channel_id: str
    audience_id: str
    channel_kind: str
    recipient_identity_sha256: str
    user_controlled_sandbox: bool


@dataclass(frozen=True)
class HostSendAccess:
    roots: TrustedSideEffectRoots
    target: HostTestProvider
    credential: str
    outbox_root: str
    enable_live_sandbox_send: bool
    allow_synthetic_transport_for_development: bool = False


@dataclass(frozen=True)
class DeliverySendRequest:
    authorization_request: da.DeliveryAuthorizationRequest
    exact_side_effect_grant: da.SignedAuthorizationStatement
    permit_single_sandbox_external_side_effect: bool
    permit_provider_network_egress: bool


class ControlledProvider(Protocol):
    def probe(self, target: HostTestProvider, credential: str,
              challenge: dict[str, Any]) -> da.SignedAuthorizationStatement: ...
    def submit(self, target: HostTestProvider, credential: str,
               body: bytes, operation_id: str) -> int: ...


class SendDenied(Exception):
    def __init__(self, code: str, status: str = 'blocked') -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def require(condition: bool, code: str, status: str = 'blocked') -> None:
    if not condition:
        raise SendDenied(code, status)


def _url_ok(url: Any) -> bool:
    if type(url) is not str or len(url) > 255:
        return False
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or parsed.query or parsed.fragment or
            parsed.username or parsed.password or parsed.port is not None or
            parsed.netloc != parsed.hostname or
            not parsed.path.startswith('/') or '..' in parsed.path or
            not re.fullmatch(r'/[a-z0-9_/-]{1,96}', parsed.path) or
            '//' in parsed.path):
            return False
        hostname = parsed.hostname
        if not hostname or HOST.fullmatch(hostname) is None:
            return False
        if hostname.endswith(('.local', '.localhost', '.internal', '.onion')):
            return False
        try:
            ipaddress.ip_address(hostname)
            return False
        except ValueError:
            return True
    except (ValueError, UnicodeError):
        return False


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HTTPSPrivateTestTransport:
    """Real authenticated HTTPS client for an EC225 sandbox-capable gateway.

    The host provisions URL/token + verified provider Ed25519 key separately.
    There is no arbitrary URL in the send request, no HTTP redirects or
    environment-proxy inheritance. TLS verifies the endpoint hostname.
    Provider MUST implement the documented probe/submit wire contract.
    """
    def __init__(self, timeout_seconds: float = 5.0) -> None:
        if type(timeout_seconds) not in (int, float) or not 0.5 <= timeout_seconds <= 8:
            raise ValueError('INVALID_BOUNDED_HTTPS_TIMEOUT')
        self._timeout = float(timeout_seconds)
        self._opener = build_opener(ProxyHandler({}), _NoRedirect(),
                                    HTTPSHandler(context=ssl.create_default_context()))

    def _post(self, target: HostTestProvider, credential: str, suffix: str,
              body: bytes, *, operation: str | None = None) -> tuple[int, bytes]:
        if not _url_ok(target.endpoint) or suffix not in ('/probe', '/submit'):
            raise SendDenied('HOST_PROVIDER_ENDPOINT_UNAVAILABLE', 'unavailable')
        require(0 < len(body) <= MAX_BODY, 'BOUNDED_PROVIDER_BODY_REQUIRED', 'unavailable')
        headers = {'Authorization': 'Bearer ' + credential,
                   'Content-Type': 'application/json', 'Accept': 'application/json',
                   'Cache-Control': 'no-store', 'User-Agent': 'CES-EC225/1'}
        if operation is not None:
            headers['Idempotency-Key'] = operation
        request = Request(target.endpoint.rstrip('/') + suffix, body,
                          headers=headers, method='POST')
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                raw = response.read(MAX_TRANSPORT_RESPONSE + 1)
                if len(raw) > MAX_TRANSPORT_RESPONSE:
                    raise SendDenied('PROVIDER_RESPONSE_TOO_LARGE', 'unavailable')
                return response.status, raw
        except (HTTPError, URLError, OSError, TimeoutError, ssl.SSLError,
                ConnectionError, ValueError):
            # Never return token, URL, HTTP error body or provider-supplied text.
            raise SendDenied('PROVIDER_HTTPS_OUTCOME_UNCONFIRMED', 'unavailable') from None

    def probe(self, target: HostTestProvider, credential: str,
              challenge: dict[str, Any]) -> da.SignedAuthorizationStatement:
        code, raw = self._post(target, credential, '/probe', dp.canonical(challenge))
        require(code == 200, 'PROVIDER_PROBE_NOT_VERIFIED', 'unavailable')
        try:
            parsed = json.loads(raw)
            require(type(parsed) is dict and set(parsed) == {'statement', 'signature_hex'},
                    'PROVIDER_CAPABILITY_ENVELOPE_INVALID', 'unavailable')
            return da.SignedAuthorizationStatement(parsed['statement'],
                                                   parsed['signature_hex'])
        except (ValueError, UnicodeError, TypeError):
            raise SendDenied('PROVIDER_CAPABILITY_ENVELOPE_INVALID', 'unavailable') from None

    def submit(self, target: HostTestProvider, credential: str,
               body: bytes, operation_id: str) -> int:
        code, _ = self._post(target, credential, '/submit', body, operation=operation_id)
        return code


class DurableGrantOutbox:
    """Conservative per-grant POSIX-local at-most-one SUBMIT opportunity.

    mkdir(2) with dir_fd + fsync(parent) is the first-writer-wins commit.
    The same EC224 signed grant can NEVER be claimed twice, including with a
    different EC225 side-effect grant/nonce. No payload/credentials/recipient
    identifiers stored. Keep the root and all claims permanently; loss or
    rollback of a ledger voids anti-replay. NOT supported on NFS/multi-host.
    """
    def __init__(self, root: str) -> None:
        self.root = root
        self._dirfd: int | None = None
        self._claimfd: int | None = None

    def __enter__(self) -> 'DurableGrantOutbox':
        require(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and
                type(self.root) is str and os.path.isabs(self.root) and
                len(self.root) <= 2048, 'POSIX_PRIVATE_LOCAL_OUTBOX_REQUIRED', 'unavailable')
        try:
            p = Path(self.root)
            for ancestor in (p, *p.parents):
                if ancestor.is_symlink():
                    raise OSError('symlink')
            info = os.lstat(self.root)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
                    not info.st_mode & 0o077, 'OUTBOX_OWNER_MODE_INVALID', 'unavailable')
            self._dirfd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            actual = os.fstat(self._dirfd)
            require(actual.st_dev == info.st_dev and actual.st_ino == info.st_ino and
                    actual.st_uid == os.geteuid() and not actual.st_mode & 0o077,
                    'OUTBOX_DIRECTORY_CHANGED', 'unavailable')
            return self
        except (OSError, ValueError, TypeError):
            self.__exit__(None, None, None)
            raise SendDenied('PERSISTENT_OUTBOX_UNAVAILABLE', 'unavailable') from None

    def claim(self, operation_id: str) -> None:
        require(type(operation_id) is str and da.sha_string(operation_id),
                'OPERATION_ID_INVALID', 'invalid_input')
        require(self._dirfd is not None, 'OUTBOX_NOT_READY', 'unavailable')
        slot = 'ec225-' + operation_id
        try:
            os.mkdir(slot, 0o700, dir_fd=self._dirfd)
        except FileExistsError:
            raise SendDenied('GRANT_ALREADY_USED_NO_REPLAY', 'blocked') from None
        except OSError:
            raise SendDenied('OUTBOX_ATOMIC_RESERVATION_FAILED', 'unavailable') from None
        # If durability cannot be confirmed, no network operation is allowed.
        try:
            self._claimfd = os.open(slot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=self._dirfd)
            os.fsync(self._claimfd)
            os.fsync(self._dirfd)
            self.mark('00_RESERVED_DURABLE')
        except OSError:
            raise SendDenied('OUTBOX_RESERVATION_DURABILITY_UNCONFIRMED', 'unavailable') from None

    def mark(self, marker: str) -> None:
        require(self._claimfd is not None and marker in (
            '00_RESERVED_DURABLE', '01_PROBE_REQUESTED', '02_PROBE_VERIFIED',
            '03_SUBMIT_ATTEMPTED', '04_POST_RETURNED', '05_POST_UNKNOWN'),
            'OUTBOX_MARKER_INVALID', 'unavailable')
        try:
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self._claimfd)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(self._claimfd)
        except OSError:
            raise SendDenied('OUTBOX_MARKER_DURABILITY_UNCONFIRMED', 'unavailable') from None

    def __exit__(self, exc_type, exc, tb) -> None:
        for fd in (self._claimfd, self._dirfd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._claimfd = None
        self._dirfd = None


def _clock() -> float:
    t = time.time()
    require(type(t) in (float, int) and math.isfinite(t) and
            946684800 <= t <= 4102444800,
            'TRUSTED_SEND_CLOCK_UNAVAILABLE', 'unavailable')
    return float(t)


def _window(doc: dict[str, Any], now: int, max_age: int, label: str) -> None:
    start, stop = doc.get('issued_at'), doc.get('expires_at')
    require(type(start) is int and type(stop) is int and
            946684800 <= start < stop <= 4102444800 and
            stop - start <= max_age and
            start <= now + MAX_SKEW and start >= now - max_age and
            stop > now, label + '_STALE_OR_EXPIRED')


def _snapshot(statement: da.SignedAuthorizationStatement,
              label: str) -> tuple[dict[str, Any], bytes]:
    try:
        return da._snapshot_signed(statement, label)
    except da.AuthorizationDenied as error:
        raise SendDenied(error.code, error.status) from None


def _sig(key: bytes, domain: bytes, doc: dict[str, Any],
         signature: bytes, label: str) -> None:
    try:
        da._verify_signature(key, domain, doc, signature, label)
    except da.AuthorizationDenied as error:
        raise SendDenied(error.code, error.status) from None


def _refusal(code: str, status: str, *, operation: str | None = None,
             reserved: bool = False, network: bool = False,
             attempted: bool = False, capability: bool = False) -> dict[str, Any]:
    effects = dp.effects()
    effects['external_network_requested'] = network
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': 4 if status == 'invalid_input' else 5,
        'reason_code': 'DELIVERY_SEND_' + code,
        'operation_id': operation,
        'submission_receipt_id': None,
        'submission_state': ('UNKNOWN_UNCONFIRMED' if attempted else
                             'NO_SUBMISSION_ATTEMPT'),
        'claim_committed': reserved,
        'provider_sandbox_capability_verified': capability,
        'provider_probe_requested': network,
        'submission_post_attempted': attempted,
        'ready_to_send': False,
        'message_sent': False,
        'delivery_accepted': False,
        'delivered': False,
        'published': False,
        'effects': effects,
    }


class DeliverySender:
    def __init__(self, access: HostSendAccess, authorizer: da.DeliveryAuthorizer,
                 transport: ControlledProvider | None = None) -> None:
        if type(access) is not HostSendAccess or type(authorizer) is not da.DeliveryAuthorizer:
            raise ValueError('SEND_HOST_CONFIGURATION_REQUIRED')
        r, t = access.roots, access.target
        identity = authorizer._identity
        keys = (r.side_effect_public_key, r.provider_capability_public_key,
                authorizer._roots.approval_public_key,
                authorizer._roots.organization_entitlement_public_key,
                authorizer._roots.organization_revocation_public_key,
                identity._directory_key, identity._revocation_key,
                identity._verification_key)
        if (type(r) is not TrustedSideEffectRoots or
            type(r.issuer_id) is not str or di.ISSUER.fullmatch(r.issuer_id) is None or
            type(r.operator_id) is not str or IDENT.fullmatch(r.operator_id) is None or
            type(r.minimum_send_epoch) is not int or
            not 1 <= r.minimum_send_epoch <= 2**63 - 1 or
            not all(type(k) is bytes and len(k) == 32 and k != b'\x00' * 32 for k in keys) or
            len(set(keys)) != 8 or type(t) is not HostTestProvider or
            not all(type(x) is str and IDENT.fullmatch(x) is not None for x in (
                t.provider_id, t.account_id, t.recipient_handle,
                t.recipient_id, t.channel_id, t.audience_id)) or
            type(t.project_id) is not str or di.PROJECT.fullmatch(t.project_id) is None or
            t.channel_kind not in ('EMAIL', 'CHAT') or
            not da.sha_string(t.recipient_identity_sha256) or
            not _url_ok(t.endpoint) or
            type(t.user_controlled_sandbox) is not bool or
            type(access.enable_live_sandbox_send) is not bool or
            type(access.allow_synthetic_transport_for_development) is not bool):
            raise ValueError('INVALID_HOST_PINNED_TEST_PROVIDER_AND_EIGHT_ROOTS')
        self.access = access
        self.authorizer = authorizer
        self._transport = transport if transport is not None else HTTPSPrivateTestTransport()
        if (not access.allow_synthetic_transport_for_development and
                type(self._transport) is not HTTPSPrivateTestTransport):
            raise ValueError('EXTERNAL_TRANSPORT_REQUIRES_HOST_HTTPS_ADAPTER')
        self._target_pin = dp.sha(TARGET_DOMAIN, {
            'provider_id': t.provider_id, 'account_id': t.account_id,
            'endpoint_sha256': hashlib.sha256(t.endpoint.encode()).hexdigest(),
            'recipient_handle_sha256': hashlib.sha256(t.recipient_handle.encode()).hexdigest(),
            'project_id': t.project_id, 'recipient_id': t.recipient_id,
            'channel_id': t.channel_id, 'audience_id': t.audience_id,
            'channel_kind': t.channel_kind,
            'recipient_identity_sha256': t.recipient_identity_sha256,
            'sandbox_only': t.user_controlled_sandbox})
        self._roots_pin = dp.sha(ROOT_DOMAIN, {
            'send_issuer_id': r.issuer_id, 'operator_id': r.operator_id,
            'side_effect_public_key_sha256': hashlib.sha256(keys[0]).hexdigest(),
            'provider_capability_public_key_sha256': hashlib.sha256(keys[1]).hexdigest(),
            'ec224_approval_roots_sha256': authorizer._root_pin,
            'provider_target_sha256': self._target_pin})

    def _validate_access(self, req: DeliverySendRequest) -> None:
        require(type(req) is DeliverySendRequest and
                type(req.authorization_request) is da.DeliveryAuthorizationRequest and
                type(req.permit_single_sandbox_external_side_effect) is bool and
                type(req.permit_provider_network_egress) is bool,
                'EXPLICIT_SINGLE_SEND_REQUEST_REQUIRED', 'invalid_input')
        require(req.permit_single_sandbox_external_side_effect and
                req.permit_provider_network_egress and
                self.access.enable_live_sandbox_send and
                self.access.target.user_controlled_sandbox,
                'INDEPENDENT_EXPLICIT_SANDBOX_SEND_AND_NETWORK_OPT_IN_REQUIRED',
                'unavailable')
        credential = self.access.credential
        require(type(credential) is str and 16 <= len(credential) <= 2048 and
                all(33 <= ord(c) <= 126 for c in credential),
                'HOST_SCOPED_PROVIDER_CREDENTIAL_MISSING', 'unavailable')
        require(ACTIVE_SEND_CODE_SHA256 is not None and
                _code_sha() == ACTIVE_SEND_CODE_SHA256 and
                da.ACTIVE_APPROVAL_CODE_SHA256 is not None,
                'SEND_CODE_OR_APPROVAL_REVISION_UNAVAILABLE', 'unavailable')

    def _permit(self, request: DeliverySendRequest, approved: dict[str, Any],
                now: int) -> tuple[dict[str, Any], str]:
        permit, sig = _snapshot(request.exact_side_effect_grant, 'SIDE_EFFECT')
        da.exact(permit, {'schema', 'issuer_id', 'operator_id', 'purpose',
                          'authorization_receipt_id', 'approver_exact_grant_sha256',
                          'organization_revocation_checkpoint_sha256',
                          'authorization_trust_anchor_binding_sha256',
                          'send_trust_anchor_binding_sha256', 'provider_target_binding_sha256',
                          'project_id', 'recipient_id', 'channel_id', 'audience_id',
                          'recipient_identity_sha256', 'route_sha256',
                          'destination_binding_sha256', 'source_set_sha256',
                          'payload_sha256', 'send_code_revision_sha256',
                          'permission_epoch', 'send_nonce', 'sandbox_only',
                          'issued_at', 'expires_at'}, 'SIDE_EFFECT_SCOPE_SHAPE_INVALID')
        t, r = self.access.target, self.access.roots
        grant, _ = _snapshot(request.authorization_request.exact_delivery_grant,
                             'ORIGINAL_GRANT')
        identity_permit, _ = di._snapshot_signed(
            request.authorization_request.identity_request.verification_permit,
            'ORIGINAL_IDENTITY_CHECK_PERMIT')
        ar = approved['authorization']
        require(permit['schema'] == SEND_PERMIT_SCHEMA and
                permit['issuer_id'] == r.issuer_id and
                permit['operator_id'] == r.operator_id and
                permit['operator_id'] != self.authorizer._roots.approver_id and
                permit['operator_id'] != identity_permit['operator_id'] and
                permit['purpose'] == PURPOSE and
                permit['authorization_receipt_id'] == approved['authorization_receipt_id'] and
                permit['approver_exact_grant_sha256'] == ar['approver_exact_grant_sha256'] and
                permit['organization_revocation_checkpoint_sha256'] ==
                     ar['organization_revocation_checkpoint_sha256'] and
                permit['authorization_trust_anchor_binding_sha256'] ==
                     ar['authorization_trust_anchor_binding_sha256'] and
                permit['send_trust_anchor_binding_sha256'] == self._roots_pin and
                permit['provider_target_binding_sha256'] == self._target_pin and
                permit['project_id'] == t.project_id == grant['project_id'] and
                permit['recipient_id'] == t.recipient_id == grant['recipient_id'] and
                permit['channel_id'] == t.channel_id == grant['channel_id'] and
                permit['audience_id'] == t.audience_id == grant['audience_id'] and
                permit['recipient_identity_sha256'] == t.recipient_identity_sha256 ==
                     grant['recipient_identity_sha256'] and
                permit['route_sha256'] == ar['route_sha256'] and
                permit['destination_binding_sha256'] == ar['destination_binding_sha256'] and
                permit['source_set_sha256'] == ar['source_set_sha256'] and
                permit['payload_sha256'] == ar['payload_bytes_sha256'] and
                permit['send_code_revision_sha256'] == ACTIVE_SEND_CODE_SHA256 and
                type(permit['send_nonce']) is str and
                HEX32.fullmatch(permit['send_nonce']) is not None and
                type(permit['permission_epoch']) is int and
                permit['permission_epoch'] >= r.minimum_send_epoch and
                permit['sandbox_only'] is True,
                'SIDE_EFFECT_GRANT_NOT_EXACTLY_SCOPED')
        _window(permit, now, MAX_PERMIT_AGE, 'SIDE_EFFECT_GRANT')
        require(permit['issued_at'] >= grant['issued_at'] and
                permit['expires_at'] <= ar['expires_at'],
                'SIDE_EFFECT_MUST_FOLLOW_AND_EXPIRE_WITH_EXACT_APPROVAL')
        _sig(r.side_effect_public_key, PERMIT_DOMAIN, permit, sig,
             'SIDE_EFFECT_GRANT')
        return permit, dp.sha(PERMIT_DOMAIN, permit)

    def _verify_capability(self, response: Any, challenge: dict[str, Any],
                           permit: dict[str, Any], now: int) -> tuple[dict[str, Any], str]:
        cap, sig = _snapshot(response, 'PROVIDER_CAPABILITY')
        try:
            da.exact(cap, {'schema', 'provider_id', 'account_id',
                           'provider_target_binding_sha256', 'project_id',
                           'recipient_id', 'recipient_identity_sha256',
                           'channel_id', 'audience_id', 'channel_kind',
                           'operation_id', 'challenge_nonce', 'payload_sha256',
                           'permission', 'state', 'single_recipient',
                           'user_controlled_test_destination', 'provider_supports_idempotency',
                           'issued_at', 'expires_at'},
                     'PROVIDER_CAPABILITY_SHAPE_INVALID')
        except da.AuthorizationDenied as exc:
            raise SendDenied(exc.code, exc.status) from None
        t = self.access.target
        require(cap['schema'] == CAPABILITY_SCHEMA and
                cap['provider_id'] == t.provider_id and
                cap['account_id'] == t.account_id and
                cap['provider_target_binding_sha256'] == self._target_pin and
                cap['project_id'] == t.project_id and
                cap['recipient_id'] == t.recipient_id and
                cap['recipient_identity_sha256'] == t.recipient_identity_sha256 and
                cap['channel_id'] == t.channel_id and
                cap['audience_id'] == t.audience_id and
                cap['channel_kind'] == t.channel_kind and
                cap['operation_id'] == challenge['operation_id'] and
                cap['challenge_nonce'] == challenge['challenge_nonce'] and
                cap['payload_sha256'] == permit['payload_sha256'] and
                cap['permission'] == 'SUBMIT_ONE_TEST_DELIVERY' and
                cap['state'] == 'ACTIVE' and
                cap['single_recipient'] is True and
                cap['user_controlled_test_destination'] is True and
                cap['provider_supports_idempotency'] is True,
                'PROVIDER_ACCOUNT_RECIPIENT_PERMISSION_NOT_PROVEN')
        _window(cap, now, MAX_CAPABILITY_AGE, 'PROVIDER_CAPABILITY')
        _sig(self.access.roots.provider_capability_public_key,
             CAPABILITY_DOMAIN, cap, sig, 'PROVIDER_CAPABILITY')
        return cap, sig.hex()

    def send_once(self, request: DeliverySendRequest) -> dict[str, Any]:
        operation: str | None = None
        reserved = network = attempted = capability = False
        try:
            self._validate_access(request)
            started = _clock()
            approved = self.authorizer.authorize(request.authorization_request)
            require(type(approved) is dict and approved.get('status') == 'partial' and
                    approved.get('exit_code') == 2 and
                    type(approved.get('authorization')) is dict and
                    approved['authorization'].get('exact_content_and_single_target_approved_under_host_roots') is True,
                    'FRESH_EC224_223_222_221_PRIVATE_APPROVAL_REQUIRED', 'unavailable')
            permit, permit_sha = self._permit(request, approved, int(_clock()))
            r = approved['authorization']
            route, _ = di._snapshot_signed(
                request.authorization_request.identity_request.directory_route,
                'ORIGINAL_ROUTE')
            t = self.access.target
            require(route['channel']['kind'] == t.channel_kind and
                    route['audience']['kind'] == 'INTERNAL_REVIEW' and
                    route['recipient']['kind'] in di.RECIPIENT_KINDS and
                    route['channel']['visibility'] == 'PROJECT_PRIVATE' and
                    r['effective_minimum_privacy_class'] == 'INTERNAL' and
                    r['payload_bytes_sha256'] == hashlib.sha256(
                        request.authorization_request.exact_payload_bytes).hexdigest(),
                    'ONLY_EXACT_INTERNAL_SINGLE_TEST_DESTINATION_SUPPORTED')
            operation = dp.sha(OP_DOMAIN, {
                'ec224_approver_grant_sha256': r['approver_exact_grant_sha256'],
                'organization_approval_anchor_sha256':
                    r['authorization_trust_anchor_binding_sha256'],
                'project_binding_sha256': r['project_binding_sha256'],
            })
            # This claim, shared by ALL workers for an approval, is committed
            # before even the read-only provider capability probe.
            with DurableGrantOutbox(self.access.outbox_root) as ledger:
                ledger.claim(operation)
                reserved = True
                challenge = {
                    'schema': PROBE_SCHEMA, 'provider_id': t.provider_id,
                    'account_id': t.account_id,
                    'provider_target_binding_sha256': self._target_pin,
                    'project_id': t.project_id, 'recipient_id': t.recipient_id,
                    'recipient_identity_sha256': t.recipient_identity_sha256,
                    'channel_id': t.channel_id, 'audience_id': t.audience_id,
                    'channel_kind': t.channel_kind, 'recipient_handle': t.recipient_handle,
                    'operation_id': operation, 'payload_sha256': r['payload_bytes_sha256'],
                    'challenge_nonce': secrets.token_hex(16),
                }
                ledger.mark('01_PROBE_REQUESTED')
                network = True
                evidence = self._transport.probe(t, self.access.credential, challenge)
                checked_cap, checked_sig = self._verify_capability(
                    evidence, challenge, permit, int(_clock()))
                capability = True
                ledger.mark('02_PROBE_VERIFIED')
                # Provider probe may have taken a long time or source/approval
                # may have drifted. Re-run FULL private chain before SUBMIT.
                again = self.authorizer.authorize(request.authorization_request)
                require(again.get('status') == 'partial' and
                        again.get('authorization_receipt_id') ==
                            approved['authorization_receipt_id'],
                        'EC224_PRIVATE_RECHECK_DRIFT_BEFORE_SEND', 'unavailable')
                current = _clock()
                require(current >= started and current < min(
                    permit['expires_at'], r['expires_at'],
                    checked_cap['expires_at']) and
                    _code_sha() == ACTIVE_SEND_CODE_SHA256,
                    'SIDE_EFFECT_PERMIT_OR_CODE_EXPIRED_BEFORE_POST', 'unavailable')
                body = dp.canonical({
                    'schema': SUBMIT_SCHEMA,
                    'operation_id': operation,
                    'provider_id': t.provider_id, 'account_id': t.account_id,
                    'provider_target_binding_sha256': self._target_pin,
                    'recipient_handle': t.recipient_handle,
                    'payload_sha256': r['payload_bytes_sha256'],
                    'payload_media_type': da.MEDIA_TYPE,
                    'payload_b64': base64.b64encode(
                        request.authorization_request.exact_payload_bytes).decode('ascii'),
                    'provider_capability': checked_cap,
                    'capability_signature_hex': checked_sig,
                    'side_effect_permit_sha256': permit_sha,
                })
                require(len(body) <= MAX_BODY and
                        len(request.authorization_request.exact_payload_bytes) <=
                            dr.MAX_SUMMARY_BYTES,
                        'SINGLE_BOUNDED_SUBMISSION_REQUIRED', 'unavailable')
                ledger.mark('03_SUBMIT_ATTEMPTED')  # durable BEFORE external POST
                # A slow fsync must not turn a formerly valid signed permit
                # into a post-expiry external side effect. The claim remains
                # spent even if this final edge check denies egress.
                edge = _clock()
                require(edge >= current and edge < min(
                    permit['expires_at'], r['expires_at'],
                    checked_cap['expires_at']) and
                    _code_sha() == ACTIVE_SEND_CODE_SHA256,
                    'PERMIT_EXPIRED_AT_DURABLE_SUBMIT_EDGE_NO_RETRY',
                    'unavailable')
                attempted = True
                try:
                    http_code = self._transport.submit(t, self.access.credential,
                                                       body, operation)
                except Exception:
                    # Once the POST begins, even a local error is not evidence
                    # that the remote side did not receive/process it.
                    try:
                        ledger.mark('05_POST_UNKNOWN')
                    except SendDenied:
                        pass
                    return _refusal('POST_OUTCOME_UNKNOWN_NO_RETRY', 'unavailable',
                                    operation=operation, reserved=True,
                                    network=True, attempted=True, capability=True)
                ledger.mark('04_POST_RETURNED')
                require(type(http_code) is int and http_code in (200, 201, 202, 204),
                        'PROVIDER_POST_UNCONFIRMED_NO_RETRY', 'unavailable')
                result_id = 'cesds1:' + dp.sha(RECEIPT_DOMAIN, {
                    'operation_id': operation, 'side_effect_permit_sha256': permit_sha,
                    'provider_target_binding_sha256': self._target_pin,
                    'provider_reported_http_status': http_code,
                    'attempt': 'ONCE_SUBMISSION_UNCONFIRMED',
                })
                effects = dp.effects()
                effects['external_network_requested'] = True
                # A successful HTTP code proves only that the gateway returned;
                # it DOES NOT independently prove recipient contacted/sent/accepted.
                effects['recipient_identity_verified'] = True
                effects['delivery_authorized'] = True
                return {
                    'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
                    'reason_code': 'DELIVERY_SEND_PROVIDER_HTTP_RETURN_SUBMISSION_UNCONFIRMED',
                    'operation_id': operation, 'submission_receipt_id': result_id,
                    'submission_state': 'SUBMISSION_UNCONFIRMED',
                    'claim_committed': True, 'provider_sandbox_capability_verified': True,
                    'provider_probe_requested': True, 'submission_post_attempted': True,
                    'ready_to_send': False, 'message_sent': False,
                    'delivery_accepted': False, 'delivered': False, 'published': False,
                    'effects': effects,
                }
        except da.AuthorizationDenied as exc:
            return _refusal(exc.code, exc.status, operation=operation, reserved=reserved,
                            network=network, attempted=attempted, capability=capability)
        except SendDenied as exc:
            return _refusal(exc.code, exc.status, operation=operation, reserved=reserved,
                            network=network, attempted=attempted, capability=capability)
        except Exception:
            return _refusal('HOST_OR_PROVIDER_OR_OUTBOX_UNAVAILABLE', 'unavailable',
                            operation=operation, reserved=reserved, network=network,
                            attempted=attempted, capability=capability)
