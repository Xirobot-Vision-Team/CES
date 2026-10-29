#!/usr/bin/env python3
"""EC226: scoped, independently signed status *observations*, not resend.

An EC225 durable SUBMIT_ATTEMPTED marker means only that a submission MAY
have been attempted. Historical signed EC224/225 context binds the original
source bytes, approval and private test target; it does not authorize a NEW
send or prove the current organization/recipient membership. A fresh, one-use
independent host read permit enables one bounded status-only HTTPS query.

Provider acceptance requires a fresh, challenged Ed25519 provider statement.
Actual delivery requires ALSO a fresh, challenged statement signed by the
independently host-pinned recipient inbox observer. No response code, marker,
provider-only 'DELIVERED', absent status or timeout can claim recipient delivery.
This is a standalone Python component, not a native PowerShell CLI Action.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import ssl
import stat
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, HTTPSHandler, ProxyHandler, build_opener

try:
    from . import delivery_preview as dp, delivery_authorization as da
    from . import delivery_identity as di, delivery_send as ds
except ImportError:
    import delivery_preview as dp
    import delivery_authorization as da
    import delivery_identity as di
    import delivery_send as ds

SCHEMA = 'ces.delivery_status.v1'
READ_SCHEMA = 'ces.delivery_status.read_grant.v1'
QUERY_SCHEMA = 'ces.delivery_status.query.v1'
STATUS_SCHEMA = 'ces.delivery_status.provider_state.v1'
INBOX_SCHEMA = 'ces.delivery_status.inbox_observation.v1'
READ_DOMAIN = b'CES-EC226-INDEPENDENT-ONE-USE-STATUS-READ-GRANT-v1\x00'
STATUS_DOMAIN = b'CES-EC226-PROVIDER-ACCEPTANCE-STATE-EVIDENCE-v1\x00'
INBOX_DOMAIN = b'CES-EC226-INDEPENDENT-INBOX-DELIVERY-OBSERVATION-v1\x00'
ROOT_DOMAIN = b'CES-EC226-HOST-STATUS-READ-AND-INBOX-OBSERVER-ROOTS-v1\x00'
CODE_DOMAIN = b'CES-EC226-STATUS-OBSERVATION-CODE-REVISION-v1\x00'
NONCE_DOMAIN = b'CES-EC226-ONE-USE-STATUS-READ-NONCE-v1\x00'
READ_PURPOSE = 'READ_ONE_EXISTING_PRIVATE_SANDBOX_DELIVERY_STATUS_ONLY'
INBOX_PURPOSE = 'TEST_INBOX_EXACT_MESSAGE_OBSERVED'
MAX_READ_GRANT_AGE = 60
MAX_STATUS_EVIDENCE_AGE = 20
MAX_INBOX_EVIDENCE_AGE = 20
MAX_SKEW = 5
MAX_STATUS_BODY = 8192
MAX_STATUS_RESPONSE = 16384

READ_KEYS = frozenset({
    'schema', 'issuer_id', 'reader_id', 'purpose', 'send_trust_anchor_binding_sha256',
    'status_trust_anchor_binding_sha256', 'provider_target_binding_sha256',
    'authorization_receipt_id', 'approver_exact_grant_sha256',
    'side_effect_permit_sha256', 'provider_id', 'account_id',
    'project_id', 'recipient_id', 'channel_id', 'audience_id',
    'recipient_identity_sha256', 'payload_sha256', 'source_set_sha256',
    'operation_id', 'read_nonce', 'permission_epoch', 'sandbox_only',
    'issued_at', 'expires_at',
})
QUERY_KEYS = frozenset({
    'schema', 'provider_id', 'account_id', 'provider_target_binding_sha256',
    'project_id', 'recipient_id', 'channel_id', 'audience_id',
    'recipient_identity_sha256', 'operation_id', 'payload_sha256',
    'approver_exact_grant_sha256', 'send_trust_anchor_binding_sha256',
    'read_grant_sha256', 'read_nonce', 'challenge_nonce',
})
STATUS_KEYS = frozenset({
    *QUERY_KEYS, 'state', 'provider_message_id_sha256',
    'accepted_at', 'delivered_at', 'observed_at', 'issued_at', 'expires_at',
})
INBOX_KEYS = frozenset({
    'schema', 'observer_id', 'purpose', 'provider_id', 'account_id',
    'provider_target_binding_sha256', 'operation_id',
    'approver_exact_grant_sha256', 'recipient_identity_sha256',
    'channel_id', 'audience_id', 'payload_sha256',
    'provider_message_id_sha256', 'provider_status_sha256',
    'read_grant_sha256', 'challenge_nonce', 'test_destination_only',
    'inbox_observed_at', 'issued_at', 'expires_at',
})


def _code_sha() -> str | None:
    try:
        folder = Path(__file__).resolve().parent
        digest = hashlib.sha256((folder / 'delivery_status.py').read_bytes()).hexdigest()
        return dp.sha(CODE_DOMAIN, {
            'source_sha256': digest, 'send_code_revision_sha256': ds.ACTIVE_SEND_CODE_SHA256,
            'no_submit_or_retry': True})
    except (OSError, ValueError, TypeError):
        return None


ACTIVE_STATUS_CODE_SHA256 = _code_sha()


@dataclass(frozen=True)
class TrustedStatusRoots:
    issuer_id: str
    reader_id: str
    inbox_observer_id: str
    status_read_public_key: bytes
    inbox_observation_public_key: bytes
    minimum_read_epoch: int


@dataclass(frozen=True)
class HostStatusAccess:
    roots: TrustedStatusRoots
    read_credential: str
    enable_live_private_status_read: bool
    allow_synthetic_transport_for_development: bool = False


@dataclass(frozen=True)
class DeliveryStatusRequest:
    original_send_request: ds.DeliverySendRequest
    exact_read_grant: da.SignedAuthorizationStatement
    permit_independent_status_read: bool
    permit_provider_status_network_egress: bool


class ProviderStatusPort(Protocol):
    def status(self, target: ds.HostTestProvider, credential: str,
               query: dict[str, Any]) -> dict[str, Any]: ...


class StatusDenied(Exception):
    def __init__(self, code: str, status: str = 'blocked') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def need(ok: bool, code: str, status: str = 'blocked') -> None:
    if not ok:
        raise StatusDenied(code, status)


def _signed(item: Any, label: str, key: bytes, domain: bytes,
            fields: frozenset[str] | set[str]) -> dict[str, Any]:
    try:
        doc, signature = da._snapshot_signed(item, label)
        da.exact(doc, set(fields), label + '_FIELDS_INVALID')
        da._verify_signature(key, domain, doc, signature, label)
        return doc
    except da.AuthorizationDenied as exc:
        raise StatusDenied(exc.code, exc.status) from None


def _window(doc: dict[str, Any], now: int, max_age: int, label: str) -> None:
    i, e = doc.get('issued_at'), doc.get('expires_at')
    need(type(i) is int and type(e) is int and
         946684800 <= i < e <= 4102444800 and e - i <= max_age and
         now - max_age <= i <= now + MAX_SKEW and now < e,
         label + '_STALE_OR_EXPIRED')


def _historical_window(doc: dict[str, Any], max_age: int, label: str) -> None:
    i, e = doc.get('issued_at'), doc.get('expires_at')
    need(type(i) is int and type(e) is int and
         946684800 <= i < e <= 4102444800 and e - i <= max_age,
         label + '_HISTORICAL_WINDOW_INVALID')


def _refusal(code: str, status: str, *, operation_id: str | None = None,
             marker: bool = False, read_grant: bool = False,
             network: bool = False) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': 4 if status == 'invalid_input' else 5,
        'reason_code': 'DELIVERY_STATUS_' + code,
        'operation_id': operation_id, 'provider_state': None,
        'delivery_state': 'UNKNOWN_UNCONFIRMED',
        'provider_message_id_sha256': None, 'read_grant_verified': read_grant,
        'submit_attempt_marker_verified': marker, 'status_network_requested': network,
        'provider_evidence_verified': False, 'inbox_evidence_verified': False,
        'provider_accepted': False, 'recipient_delivery_observed': False,
        'message_sent_by_status_read': False, 'resent': False, 'published': False,
        'effects': {'external_network_requested': network,
                    'provider_submit_requested': False, 'recipient_contacted_by_status_read': False,
                    'git_or_business_files_written': False,
                    'ces_business_records_written': False},
    }


class HTTPSPrivateStatusTransport:
    """Only one HTTPS POST /status. No submit, redirect, proxy or body echo."""

    def __init__(self, timeout_seconds: float = 5.0) -> None:
        if type(timeout_seconds) not in (int, float) or not 0.5 <= timeout_seconds <= 8:
            raise ValueError('BOUNDED_PRIVATE_STATUS_TIMEOUT_REQUIRED')
        self._timeout = float(timeout_seconds)
        self._opener = build_opener(ProxyHandler({}), ds._NoRedirect(),
                                    HTTPSHandler(context=ssl.create_default_context()))

    def status(self, target: ds.HostTestProvider, credential: str,
               query: dict[str, Any]) -> dict[str, Any]:
        need(ds._url_ok(target.endpoint), 'HOST_STATUS_ENDPOINT_UNAVAILABLE', 'unavailable')
        body = dp.canonical(query)
        need(0 < len(body) <= MAX_STATUS_BODY,
             'BOUNDED_STATUS_QUERY_REQUIRED', 'invalid_input')
        request = Request(target.endpoint.rstrip('/') + '/status', body, method='POST',
                          headers={'Authorization': 'Bearer ' + credential,
                                   'Accept': 'application/json',
                                   'Content-Type': 'application/json',
                                   'Cache-Control': 'no-store',
                                   'User-Agent': 'CES-EC226/1'})
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                need(response.status == 200, 'STATUS_PROVIDER_RESPONSE_UNAVAILABLE',
                     'unavailable')
                raw = response.read(MAX_STATUS_RESPONSE + 1)
                need(len(raw) <= MAX_STATUS_RESPONSE, 'STATUS_RESPONSE_TOO_LARGE',
                     'unavailable')
            parsed = json.loads(raw)
            need(type(parsed) is dict and set(parsed) == {
                'provider_status', 'inbox_observation'},
                'STATUS_ENVELOPE_INVALID', 'unavailable')
            return parsed
        except (HTTPError, URLError, OSError, TimeoutError, ssl.SSLError,
                ConnectionError, UnicodeError, ValueError):
            raise StatusDenied('STATUS_HTTPS_OUTCOME_UNCONFIRMED', 'unavailable') from None


class LocalStatusReadLedger:
    """One-use read nonce + checked EC225 marker on a trusted LOCAL POSIX FS.

    Only hash directory names and empty lock/sentinel files are written.
    Not proof of a real remote POST; no multihost/NFS/same-UID guarantees.
    """
    def __init__(self, root: str) -> None:
        self.root = root
        self._dirfd: int | None = None

    def __enter__(self) -> 'LocalStatusReadLedger':
        need(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and
             type(self.root) is str and os.path.isabs(self.root) and
             len(self.root) <= 2048,
             'POSIX_PRIVATE_LOCAL_STATUS_LEDGER_REQUIRED', 'unavailable')
        try:
            p = Path(self.root)
            if any(x.is_symlink() for x in (p, *p.parents)):
                raise OSError('symlink in path')
            st = os.lstat(self.root)
            need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
                 st.st_mode & 0o077 == 0,
                 'STATUS_LEDGER_OWNER_MODE_INVALID', 'unavailable')
            self._dirfd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fresh = os.fstat(self._dirfd)
            need(fresh.st_ino == st.st_ino and fresh.st_dev == st.st_dev and
                 fresh.st_uid == os.geteuid() and fresh.st_mode & 0o077 == 0,
                 'STATUS_LEDGER_CHANGED', 'unavailable')
            return self
        except (OSError, ValueError, TypeError, StatusDenied):
            self.__exit__(None, None, None)
            raise StatusDenied('PRIVATE_STATUS_LEDGER_UNAVAILABLE', 'unavailable') from None

    def verify_submit_marker(self, operation_id: str) -> None:
        need(da.sha_string(operation_id) and self._dirfd is not None,
             'ORIGINAL_SUBMISSION_OPERATION_INVALID', 'invalid_input')
        try:
            fd = os.open('ec225-' + operation_id,
                         os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=self._dirfd)
            try:
                st = os.fstat(fd)
                need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
                     st.st_mode & 0o077 == 0,
                     'ORIGINAL_OUTBOX_CLAIM_UNTRUSTED', 'unavailable')
                # A pre-POST attempt marker is a *necessary*, not sufficient,
                # condition to query. 00 and 03 are both durable empty files.
                for name in ('00_RESERVED_DURABLE', '03_SUBMIT_ATTEMPTED'):
                    marker = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    need(stat.S_ISREG(marker.st_mode) and marker.st_uid == os.geteuid()
                         and marker.st_nlink == 1 and marker.st_size == 0 and
                         marker.st_mode & 0o077 == 0,
                         'ORIGINAL_OUTBOX_SUBMIT_MARKER_UNTRUSTED', 'unavailable')
            finally:
                os.close(fd)
        except OSError:
            raise StatusDenied('ORIGINAL_OUTBOX_SUBMISSION_UNPROVEN', 'unavailable') from None

    def claim_read_nonce(self, nonce_key: str) -> None:
        need(da.sha_string(nonce_key) and self._dirfd is not None,
             'READ_NONCE_KEY_INVALID', 'invalid_input')
        slot = 'ec226-read-' + nonce_key
        try:
            os.mkdir(slot, 0o700, dir_fd=self._dirfd)
        except FileExistsError:
            raise StatusDenied('STATUS_READ_GRANT_REPLAY_BLOCKED') from None
        except OSError:
            raise StatusDenied('STATUS_NONCE_ATOMIC_CLAIM_FAILED', 'unavailable') from None
        try:
            fd = os.open(slot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=self._dirfd)
            try:
                os.fsync(fd)
                os.fsync(self._dirfd)
                marker = os.open('01_READ_NONCE_SPENT',
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=fd)
                try:
                    os.fsync(marker)
                finally:
                    os.close(marker)
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            raise StatusDenied('STATUS_NONCE_DURABILITY_UNCONFIRMED', 'unavailable') from None

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._dirfd is not None:
            try:
                os.close(self._dirfd)
            except OSError:
                pass
            self._dirfd = None


class DeliveryStatusReader:
    """Historically bind an EC225 attempt; verify one current independent read."""

    def __init__(self, sender: ds.DeliverySender, access: HostStatusAccess,
                 transport: ProviderStatusPort | None = None) -> None:
        if type(sender) is not ds.DeliverySender or type(access) is not HostStatusAccess:
            raise ValueError('STATUS_REQUIRES_EXACT_EC225_SENDER_AND_HOST_ACCESS')
        roots = access.roots
        keys = (
            roots.status_read_public_key, roots.inbox_observation_public_key,
            sender.access.roots.side_effect_public_key,
            sender.access.roots.provider_capability_public_key,
            sender.authorizer._roots.approval_public_key,
            sender.authorizer._roots.organization_entitlement_public_key,
            sender.authorizer._roots.organization_revocation_public_key,
            sender.authorizer._identity._directory_key,
            sender.authorizer._identity._revocation_key,
            sender.authorizer._identity._verification_key,
        ) if type(roots) is TrustedStatusRoots else ()
        if (type(roots) is not TrustedStatusRoots or
            not di._opaque(roots.issuer_id) or not di._opaque(roots.reader_id) or
            not di._opaque(roots.inbox_observer_id) or
            len({roots.reader_id, roots.inbox_observer_id,
                 sender.access.roots.operator_id,
                 sender.authorizer._roots.approver_id}) != 4 or
            type(roots.minimum_read_epoch) is not int or
            not 1 <= roots.minimum_read_epoch <= 2**63 - 1 or
            not all(type(k) is bytes and len(k) == 32 and k != b'\0' * 32
                    for k in keys) or len(set(keys)) != 10 or
            type(access.enable_live_private_status_read) is not bool or
            type(access.allow_synthetic_transport_for_development) is not bool):
            raise ValueError('STATUS_TEN_INDEPENDENT_HOST_TRUST_ROOTS_REQUIRED')
        self.sender = sender
        self.access = access
        self._transport = transport if transport is not None else HTTPSPrivateStatusTransport()
        if (not access.allow_synthetic_transport_for_development and
                type(self._transport) is not HTTPSPrivateStatusTransport):
            raise ValueError('UNTRUSTED_STATUS_TRANSPORT_NOT_ALLOWED')
        self._root_pin = dp.sha(ROOT_DOMAIN, {
            'issuer_id': roots.issuer_id, 'reader_id': roots.reader_id,
            'inbox_observer_id': roots.inbox_observer_id,
            'status_read_public_key_sha256': hashlib.sha256(keys[0]).hexdigest(),
            'inbox_observation_public_key_sha256': hashlib.sha256(keys[1]).hexdigest(),
            'send_trust_anchor_binding_sha256': sender._roots_pin,
            'provider_target_binding_sha256': sender._target_pin,
        })

    def _access(self, request: DeliveryStatusRequest) -> None:
        need(type(request) is DeliveryStatusRequest and
             type(request.original_send_request) is ds.DeliverySendRequest and
             type(request.permit_independent_status_read) is bool and
             type(request.permit_provider_status_network_egress) is bool,
             'STATUS_REQUEST_AND_EXPLICIT_PERMISSION_REQUIRED', 'invalid_input')
        need(request.permit_independent_status_read and
             request.permit_provider_status_network_egress and
             self.access.enable_live_private_status_read and
             self.sender.access.target.user_controlled_sandbox,
             'STATUS_READ_AND_NETWORK_INDEPENDENT_OPT_IN_REQUIRED', 'unavailable')
        token = self.access.read_credential
        need(type(token) is str and token != self.sender.access.credential and
             16 <= len(token) <= 2048 and
             all(33 <= ord(c) <= 126 for c in token),
             'HOST_STATUS_ONLY_CREDENTIAL_MISSING', 'unavailable')
        need(ACTIVE_STATUS_CODE_SHA256 is not None and
             _code_sha() == ACTIVE_STATUS_CODE_SHA256 and
             ds.ACTIVE_SEND_CODE_SHA256 is not None and
             ds._code_sha() == ds.ACTIVE_SEND_CODE_SHA256,
             'STATUS_OR_ORIGINAL_SEND_CODE_REVISION_UNAVAILABLE', 'unavailable')

    def _historical(self, original: ds.DeliverySendRequest) -> dict[str, Any]:
        """Read historical SIGNED bytes only, never rerun expired send approval.

        This is not current authorization to send, and an original permit
        signature is not current permission to read. The separate fresh grant
        below authorizes only the exact historical status metadata lookup.
        """
        approval = original.authorization_request
        need(type(approval) is da.DeliveryAuthorizationRequest and
             type(approval.exact_payload_bytes) is bytes and
             0 < len(approval.exact_payload_bytes) <= 16384,
             'ORIGINAL_EXACT_SOURCE_BYTES_REQUIRED', 'invalid_input')
        grant = _signed(approval.exact_delivery_grant, 'HISTORIC_EXACT_GRANT',
                        self.sender.authorizer._roots.approval_public_key,
                        da.GRANT_DOMAIN, frozenset({
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
            'organization_revocation_checkpoint_sha256', 'authorization_epoch',
            'issued_at', 'expires_at',
        }))
        _historical_window(grant, da.MAX_GRANT_AGE_S, 'HISTORIC_GRANT')
        permit = _signed(original.exact_side_effect_grant, 'HISTORIC_SEND_PERMIT',
                         self.sender.access.roots.side_effect_public_key,
                         ds.PERMIT_DOMAIN, frozenset({
            'schema', 'issuer_id', 'operator_id', 'purpose',
            'authorization_receipt_id', 'approver_exact_grant_sha256',
            'organization_revocation_checkpoint_sha256',
            'authorization_trust_anchor_binding_sha256',
            'send_trust_anchor_binding_sha256', 'provider_target_binding_sha256',
            'project_id', 'recipient_id', 'channel_id', 'audience_id',
            'recipient_identity_sha256', 'route_sha256',
            'destination_binding_sha256', 'source_set_sha256', 'payload_sha256',
            'send_code_revision_sha256', 'permission_epoch', 'send_nonce',
            'sandbox_only', 'issued_at', 'expires_at',
        }))
        _historical_window(permit, ds.MAX_PERMIT_AGE, 'HISTORIC_SEND_PERMIT')
        # Recheck original independent organization + revocation signatures
        # as HISTORICAL documents, never as current send authorization.
        org = _signed(approval.organization_entitlement,
                      'HISTORIC_ORGANIZATION_ENTITLEMENT',
                      self.sender.authorizer._roots.organization_entitlement_public_key,
                      da.ENTITLEMENT_DOMAIN, frozenset({
            'schema', 'issuer_id', 'organization_id', 'approver_id',
            'approval_public_key_sha256', 'authorization_trust_anchor_binding_sha256',
            'project_id', 'identity_verification_id', 'route_sha256',
            'destination_binding_sha256', 'source_set_sha256', 'payload_sha256',
            'privacy_ceiling', 'purpose', 'approver_role', 'approver_status',
            'organization_status', 'may_approve_exact_internal_review',
            'authorization_epoch', 'issued_at', 'expires_at',
        }))
        rev = _signed(approval.organization_revocation_checkpoint,
                      'HISTORIC_ORGANIZATION_REVOCATION',
                      self.sender.authorizer._roots.organization_revocation_public_key,
                      da.REVOCATION_DOMAIN, frozenset({
            'schema', 'issuer_id', 'organization_id', 'project_id',
            'identity_verification_id', 'identity_trust_anchor_binding_sha256',
            'route_sha256', 'destination_binding_sha256',
            'entitlement_sha256', 'approval_nonce', 'source_set_sha256',
            'payload_sha256', 'privacy_floor', 'policy_revision_sha256',
            'approval_code_revision_sha256',
            'authorization_trust_anchor_binding_sha256',
            'authorization_epoch', 'revocation_epoch', 'states',
            'issued_at', 'expires_at',
        }))
        _historical_window(org, da.MAX_ENTITLEMENT_AGE_S, 'HISTORIC_ENTITLEMENT')
        _historical_window(rev, da.MAX_REVOCATION_AGE_S, 'HISTORIC_REVOCATION')
        identity_request = approval.identity_request
        need(type(identity_request) is di.DeliveryIdentityRequest,
             'HISTORIC_IDENTITY_REQUEST_REQUIRED', 'invalid_input')
        try:
            route, route_sig = di._snapshot_signed(identity_request.directory_route,
                                                    'HISTORIC_DIRECTORY_ROUTE')
        except di.IdentityDenied as exc:
            raise StatusDenied(exc.code, exc.status) from None
        need(set(route) == {
            'schema', 'issuer_id', 'project', 'recipient', 'channel',
            'audience', 'directory_epoch', 'issued_at', 'expires_at',
        }, 'HISTORIC_ROUTE_SHAPE_INVALID')
        try:
            da._verify_signature(self.sender.authorizer._identity._directory_key,
                                 di.ROUTE_DOMAIN, route, route_sig, 'HISTORIC_DIRECTORY')
        except da.AuthorizationDenied as exc:
            raise StatusDenied(exc.code, exc.status) from None
        _historical_window(route, di.MAX_ROUTE_AGE_S, 'HISTORIC_ROUTE')
        target = self.sender.access.target
        roots = self.sender.authorizer._roots
        grant_sha = dp.sha(da.GRANT_DOMAIN, grant)
        payload_sha = hashlib.sha256(approval.exact_payload_bytes).hexdigest()
        project_sha = di._sha(di.PROJECT_DOMAIN, {
            'issuer_id': self.sender.authorizer._identity._issuer,
            'project_id': target.project_id})
        need(grant['schema'] == da.GRANT_SCHEMA and grant['purpose'] == da.PURPOSE and
             grant['issuer_id'] == roots.issuer_id and
             grant['organization_id'] == roots.organization_id and
             grant['approver_id'] == roots.approver_id and
             grant['authorization_trust_anchor_binding_sha256'] ==
                 self.sender.authorizer._root_pin and
             grant['identity_trust_anchor_binding_sha256'] ==
                 self.sender.authorizer._identity._root_pin and
             grant['project_binding_sha256'] == project_sha and
             grant['project_id'] == target.project_id and
             grant['recipient_id'] == target.recipient_id and
             grant['channel_id'] == target.channel_id and
             grant['audience_id'] == target.audience_id and
             grant['recipient_identity_sha256'] == target.recipient_identity_sha256 and
             grant['payload_sha256'] == payload_sha and
             grant['payload_size_bytes'] == len(approval.exact_payload_bytes) and
             grant['payload_media_type'] == da.MEDIA_TYPE and
             grant['privacy_floor'] == 'INTERNAL' and
             grant['entitlement_sha256'] == dp.sha(da.ENTITLEMENT_DOMAIN, org) and
             grant['organization_revocation_checkpoint_sha256'] ==
                 dp.sha(da.REVOCATION_DOMAIN, rev) and
             grant['route_sha256'] == di._sha(di.ROUTE_DOMAIN, route) and
             route['schema'] == di.ROUTE_SCHEMA and
             route['issuer_id'] == self.sender.authorizer._identity._issuer and
             route['project']['id'] == grant['project_id'] and
             route['recipient']['id'] == grant['recipient_id'] and
             route['channel']['id'] == grant['channel_id'] and
             route['audience']['id'] == grant['audience_id'] and
             route['channel']['visibility'] == 'PROJECT_PRIVATE' and
             route['audience']['kind'] == 'INTERNAL_REVIEW' and
             route['channel']['kind'] == target.channel_kind and
             route['recipient']['status'] == 'ACTIVE' and
             route['channel']['status'] == 'ACTIVE' and
             route['audience']['status'] == 'ACTIVE' and
             route['project']['status'] == 'ACTIVE' and
             route['channel']['member_recipient_id'] == grant['recipient_id'] and
             route['audience']['member_recipient_id'] == grant['recipient_id'] and
             route['audience']['selection'] == 'EXPLICIT_SINGLE_RECIPIENT' and
             route['channel']['membership'] == 'DIRECT_AUTHORITY_ATTESTED' and
             org['schema'] == da.ENTITLEMENT_SCHEMA and
             org['issuer_id'] == roots.issuer_id and
             org['organization_id'] == roots.organization_id and
             org['project_id'] == grant['project_id'] and
             org['route_sha256'] == grant['route_sha256'] and
             org['payload_sha256'] == payload_sha and
             org['source_set_sha256'] == grant['source_set_sha256'] and
             org['authorization_epoch'] == grant['authorization_epoch'] and
             org['approver_id'] == roots.approver_id and
             org['purpose'] == da.PURPOSE and
             org['approver_role'] == 'INTERNAL_DELIVERY_APPROVER' and
             org['approver_status'] == 'ACTIVE' and
             org['organization_status'] == 'ACTIVE' and
             org['may_approve_exact_internal_review'] is True and
             org['privacy_ceiling'] == 'INTERNAL' and
             rev['schema'] == da.REVOCATION_SCHEMA and
             rev['entitlement_sha256'] == grant['entitlement_sha256'] and
             rev['payload_sha256'] == payload_sha and
             rev['approval_nonce'] == grant['approval_nonce'] and
             rev['authorization_epoch'] == grant['authorization_epoch'] and
             type(rev['revocation_epoch']) is int and
             rev['revocation_epoch'] >= rev['authorization_epoch'] and
             rev['issuer_id'] == roots.issuer_id and
             rev['organization_id'] == roots.organization_id and
             rev['project_id'] == grant['project_id'] and
             rev['route_sha256'] == grant['route_sha256'] and
             rev['source_set_sha256'] == grant['source_set_sha256'] and
             rev['destination_binding_sha256'] == grant['destination_binding_sha256'] and
             rev['states'] == {k: 'ACTIVE' for k in (
                 'organization', 'approver', 'approval_key', 'entitlement',
                 'authorization_scope')} and
             org['issued_at'] <= rev['issued_at'] <= grant['issued_at'] and
             grant['expires_at'] <= org['expires_at'] and
             grant['issued_at'] < rev['expires_at'],
             'HISTORIC_APPROVAL_SOURCE_TARGET_MISMATCH')
        need(permit['schema'] == ds.SEND_PERMIT_SCHEMA and
             permit['issuer_id'] == self.sender.access.roots.issuer_id and
             permit['operator_id'] == self.sender.access.roots.operator_id and
             permit['purpose'] == ds.PURPOSE and
             type(permit['authorization_receipt_id']) is str and
             re.fullmatch(r'cesda1:[a-f0-9]{64}', permit['authorization_receipt_id']) is not None and
             permit['approver_exact_grant_sha256'] == grant_sha and
             permit['organization_revocation_checkpoint_sha256'] ==
                 grant['organization_revocation_checkpoint_sha256'] and
             permit['authorization_trust_anchor_binding_sha256'] ==
                 self.sender.authorizer._root_pin and
             permit['send_trust_anchor_binding_sha256'] == self.sender._roots_pin and
             permit['provider_target_binding_sha256'] == self.sender._target_pin and
             permit['project_id'] == grant['project_id'] and
             permit['recipient_id'] == grant['recipient_id'] and
             permit['channel_id'] == grant['channel_id'] and
             permit['audience_id'] == grant['audience_id'] and
             permit['recipient_identity_sha256'] == grant['recipient_identity_sha256'] and
             permit['route_sha256'] == grant['route_sha256'] and
             permit['destination_binding_sha256'] == grant['destination_binding_sha256'] and
             permit['source_set_sha256'] == grant['source_set_sha256'] and
             permit['payload_sha256'] == payload_sha and
             da.sha_string(permit['send_code_revision_sha256']) and
             type(permit['send_nonce']) is str and
             ds.HEX32.fullmatch(permit['send_nonce']) is not None and
             permit['sandbox_only'] is True and
             type(permit['permission_epoch']) is int and permit['permission_epoch'] >= 1 and
             grant['issued_at'] <= permit['issued_at'] < permit['expires_at'] <= grant['expires_at'],
             'HISTORIC_SIGNED_SEND_GRANT_MISMATCH')
        operation = dp.sha(ds.OP_DOMAIN, {
            'ec224_approver_grant_sha256': grant_sha,
            'organization_approval_anchor_sha256':
                grant['authorization_trust_anchor_binding_sha256'],
            'project_binding_sha256': grant['project_binding_sha256'],
        })
        return {
            'operation_id': operation, 'approver_exact_grant_sha256': grant_sha,
            'authorization_receipt_id': permit['authorization_receipt_id'],
            'side_effect_permit_sha256': dp.sha(ds.PERMIT_DOMAIN, permit),
            'payload_sha256': payload_sha,
            'source_set_sha256': grant['source_set_sha256'],
            'send_trust_anchor_binding_sha256': self.sender._roots_pin,
            'provider_target_binding_sha256': self.sender._target_pin,
        }

    def _read_grant(self, item: da.SignedAuthorizationStatement,
                    history: dict[str, Any], now: int) -> tuple[dict[str, Any], str]:
        roots = self.access.roots
        statement = _signed(item, 'STATUS_READ_GRANT', roots.status_read_public_key,
                            READ_DOMAIN, READ_KEYS)
        target = self.sender.access.target
        need(statement['schema'] == READ_SCHEMA and
             statement['issuer_id'] == roots.issuer_id and
             statement['reader_id'] == roots.reader_id and
             statement['purpose'] == READ_PURPOSE and
             statement['send_trust_anchor_binding_sha256'] == self.sender._roots_pin and
             statement['status_trust_anchor_binding_sha256'] == self._root_pin and
             statement['provider_target_binding_sha256'] == self.sender._target_pin and
             statement['provider_id'] == target.provider_id and
             statement['account_id'] == target.account_id and
             statement['project_id'] == target.project_id and
             statement['recipient_id'] == target.recipient_id and
             statement['channel_id'] == target.channel_id and
             statement['audience_id'] == target.audience_id and
             statement['recipient_identity_sha256'] == target.recipient_identity_sha256 and
             all(statement[name] == history[name] for name in (
                 'authorization_receipt_id', 'approver_exact_grant_sha256',
                 'side_effect_permit_sha256', 'payload_sha256', 'source_set_sha256',
                 'operation_id')) and
             type(statement['read_nonce']) is str and
             ds.HEX32.fullmatch(statement['read_nonce']) is not None and
             type(statement['permission_epoch']) is int and
             statement['permission_epoch'] >= roots.minimum_read_epoch and
             statement['sandbox_only'] is True,
             'INDEPENDENT_READ_PERMISSION_NOT_EXACTLY_BOUND')
        _window(statement, now, MAX_READ_GRANT_AGE, 'STATUS_READ_GRANT')
        return statement, dp.sha(READ_DOMAIN, statement)

    def _query(self, history: dict[str, Any], read_grant: dict[str, Any],
               read_sha: str) -> dict[str, Any]:
        target = self.sender.access.target
        return {
            'schema': QUERY_SCHEMA,
            'provider_id': target.provider_id, 'account_id': target.account_id,
            'provider_target_binding_sha256': self.sender._target_pin,
            'project_id': target.project_id, 'recipient_id': target.recipient_id,
            'channel_id': target.channel_id, 'audience_id': target.audience_id,
            'recipient_identity_sha256': target.recipient_identity_sha256,
            'operation_id': history['operation_id'],
            'payload_sha256': history['payload_sha256'],
            'approver_exact_grant_sha256': history['approver_exact_grant_sha256'],
            'send_trust_anchor_binding_sha256': self.sender._roots_pin,
            'read_grant_sha256': read_sha, 'read_nonce': read_grant['read_nonce'],
            'challenge_nonce': secrets.token_hex(16),
        }

    def _provider(self, envelope: dict[str, Any], query: dict[str, Any],
                  now: int) -> tuple[dict[str, Any], str]:
        signed = _envelope(envelope.get('provider_status'), 'PROVIDER_STATUS_ENVELOPE')
        doc = _signed(signed, 'PROVIDER_STATUS',
                      self.sender.access.roots.provider_capability_public_key,
                      STATUS_DOMAIN, STATUS_KEYS)
        need(doc['schema'] == STATUS_SCHEMA and
             all(doc[k] == v for k, v in query.items() if k != 'schema') and
             doc['state'] in ('UNKNOWN', 'PENDING', 'ACCEPTED', 'DELIVERED',
                              'REJECTED', 'FAILED'),
             'PROVIDER_STATUS_QUERY_BINDING_INVALID')
        _window(doc, now, MAX_STATUS_EVIDENCE_AGE, 'PROVIDER_STATUS')
        msg, accepted, delivered, seen = (
            doc['provider_message_id_sha256'], doc['accepted_at'],
            doc['delivered_at'], doc['observed_at'])
        need(type(seen) is int and 946684800 <= seen <= now + MAX_SKEW and
             seen >= doc['issued_at'] - MAX_STATUS_EVIDENCE_AGE,
             'PROVIDER_OBSERVATION_CLOCK_INVALID')
        if doc['state'] in ('ACCEPTED', 'DELIVERED'):
            need(da.sha_string(msg) and type(accepted) is int and
                 946684800 <= accepted <= seen and accepted <= now + MAX_SKEW,
                 'PROVIDER_ACCEPTANCE_EVIDENCE_INCONSISTENT')
            if doc['state'] == 'DELIVERED':
                need(type(delivered) is int and accepted <= delivered <= seen,
                     'PROVIDER_DELIVERY_SEQUENCE_INCONSISTENT')
            else:
                need(delivered is None, 'PROVIDER_ACCEPTED_CANNOT_IMPLY_DELIVERED')
        else:
            need(msg is None and accepted is None and delivered is None,
                 'PROVIDER_UNRESOLVED_OR_FAILURE_STATE_CONTRADICTORY')
        return doc, dp.sha(STATUS_DOMAIN, doc)

    def _inbox(self, item: Any, query: dict[str, Any],
               provider: dict[str, Any], provider_sha: str,
               now: int) -> bool:
        if item is None:
            return False
        ack = _signed(_envelope(item, 'INBOX_OBSERVATION_ENVELOPE'),
                      'INDEPENDENT_INBOX_OBSERVATION',
                      self.access.roots.inbox_observation_public_key,
                      INBOX_DOMAIN, INBOX_KEYS)
        need(provider['state'] == 'DELIVERED' and
             ack['schema'] == INBOX_SCHEMA and
             ack['observer_id'] == self.access.roots.inbox_observer_id and
             ack['purpose'] == INBOX_PURPOSE and
             ack['test_destination_only'] is True and
             all(ack[key] == query[key] for key in (
                 'provider_id', 'account_id', 'provider_target_binding_sha256',
                 'operation_id', 'approver_exact_grant_sha256',
                 'recipient_identity_sha256', 'channel_id', 'audience_id',
                 'payload_sha256', 'read_grant_sha256', 'challenge_nonce')) and
             ack['provider_message_id_sha256'] == provider['provider_message_id_sha256'] and
             ack['provider_status_sha256'] == provider_sha,
             'INBOX_EVIDENCE_WRONG_TARGET_OR_PROVIDER_STATUS')
        _window(ack, now, MAX_INBOX_EVIDENCE_AGE, 'INBOX_EVIDENCE')
        observed = ack['inbox_observed_at']
        need(type(observed) is int and provider['accepted_at'] <= observed <= now + MAX_SKEW and
             observed <= ack['issued_at'] + MAX_SKEW and
             provider['delivered_at'] <= observed,
             'INBOX_REAL_OBSERVATION_TIME_INVALID')
        return True

    def observe_once(self, request: DeliveryStatusRequest) -> dict[str, Any]:
        operation: str | None = None
        marker = read_grant_verified = network = False
        try:
            self._access(request)
            history = self._historical(request.original_send_request)
            operation = history['operation_id']
            now = int(ds._clock())
            read_doc, read_sha = self._read_grant(request.exact_read_grant,
                                                   history, now)
            read_grant_verified = True
            # Read-only remote lookup, but requires a durable LOCAL one-use
            # read nonce; never spends another EC225 send approval/attempt.
            with LocalStatusReadLedger(self.sender.access.outbox_root) as ledger:
                ledger.verify_submit_marker(operation)
                marker = True
                nonce_key = dp.sha(NONCE_DOMAIN, {
                    'status_read_issuer': self.access.roots.issuer_id,
                    'status_trust_anchor_binding_sha256': self._root_pin,
                    'read_nonce': read_doc['read_nonce'],
                })
                ledger.claim_read_nonce(nonce_key)
                need(int(ds._clock()) < read_doc['expires_at'],
                     'READ_GRANT_EXPIRED_BEFORE_PROVIDER_QUERY', 'unavailable')
                query = self._query(history, read_doc, read_sha)
                network = True
                envelope = self._transport.status(self.sender.access.target,
                                                   self.access.read_credential, query)
                need(type(envelope) is dict and set(envelope) == {
                    'provider_status', 'inbox_observation'},
                    'PROVIDER_STATUS_ENVELOPE_INVALID', 'unavailable')
                after = int(ds._clock())
                need(after >= now and after < read_doc['expires_at'] and
                     _code_sha() == ACTIVE_STATUS_CODE_SHA256 and
                     ds._code_sha() == ds.ACTIVE_SEND_CODE_SHA256,
                     'READ_PERMISSION_OR_CODE_EXPIRED_AFTER_PROVIDER', 'unavailable')
                provider, provider_sha = self._provider(envelope, query, after)
                inbox_verified = self._inbox(envelope['inbox_observation'], query,
                                             provider, provider_sha, after)
                pstate = provider['state']
                if pstate == 'DELIVERED' and inbox_verified:
                    state = 'DELIVERED_INBOX_OBSERVED'
                elif pstate in ('ACCEPTED', 'DELIVERED'):
                    state = 'ACCEPTED_PROVIDER_ATTESTED'
                elif pstate == 'REJECTED':
                    state = 'PROVIDER_REJECTION_ATTESTED'
                elif pstate == 'FAILED':
                    state = 'PROVIDER_FAILURE_ATTESTED'
                else:
                    state = 'UNKNOWN_UNCONFIRMED'
                return {
                    'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
                    'reason_code': 'DELIVERY_STATUS_SIGNED_READ_ONLY_OBSERVATION',
                    'operation_id': operation, 'provider_state': pstate,
                    'delivery_state': state,
                    'provider_message_id_sha256': provider['provider_message_id_sha256'],
                    'read_grant_verified': True, 'submit_attempt_marker_verified': True,
                    'status_network_requested': True,
                    'provider_evidence_verified': True,
                    'inbox_evidence_verified': inbox_verified,
                    'provider_accepted': state in (
                        'ACCEPTED_PROVIDER_ATTESTED', 'DELIVERED_INBOX_OBSERVED'),
                    'recipient_delivery_observed': state == 'DELIVERED_INBOX_OBSERVED',
                    'message_sent_by_status_read': False, 'resent': False, 'published': False,
                    'effects': {'external_network_requested': True,
                                'provider_submit_requested': False,
                                'recipient_contacted_by_status_read': False,
                                'git_or_business_files_written': False,
                                'ces_business_records_written': False},
                }
        except (da.AuthorizationDenied, di.IdentityDenied, ds.SendDenied) as exc:
            return _refusal(exc.code, exc.status, operation_id=operation,
                            marker=marker, read_grant=read_grant_verified,
                            network=network)
        except StatusDenied as exc:
            return _refusal(exc.code, exc.status, operation_id=operation,
                            marker=marker, read_grant=read_grant_verified,
                            network=network)
        except Exception:
            return _refusal('PROVIDER_OR_HOST_STATUS_UNAVAILABLE', 'unavailable',
                            operation_id=operation, marker=marker,
                            read_grant=read_grant_verified, network=network)


def _envelope(value: Any, label: str) -> da.SignedAuthorizationStatement:
    need(type(value) is dict and set(value) == {'statement', 'signature_hex'},
         label + '_INVALID', 'unavailable')
    return da.SignedAuthorizationStatement(value['statement'], value['signature_hex'])
