#!/usr/bin/env python3
"""EC228 controlled private-sandbox ReportPublish. Not a production/public publisher.

Consumes *actual immutable EC199/200 report-store bytes*, never a caller body or
file path. Six distinct host-provisioned Ed25519 trust roots authorize the
organization, exact target, current revocation, exact-content human review,
one side effect, and a challenge-bound provider capability. A durable local
claim precedes ANY network call; UNKNOWN is irreversible for that report/target.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
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
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

try:
    from . import delivery_preview as dp, delivery_authorization as da
    from . import delivery_send as ds, report_history as rh, report_render as rr
except ImportError:
    import delivery_preview as dp
    import delivery_authorization as da
    import delivery_send as ds
    import report_history as rh
    import report_render as rr

SCHEMA = 'ces.report_publish.v1'
ORG_SCHEMA = 'ces.report_publish.organization.v1'
ROUTE_SCHEMA = 'ces.report_publish.route.v1'
REVOCATION_SCHEMA = 'ces.report_publish.revocation.v1'
REVIEW_SCHEMA = 'ces.report_publish.content_review.v1'
GRANT_SCHEMA = 'ces.report_publish.single_use_grant.v1'
CAPABILITY_SCHEMA = 'ces.report_publish.provider_capability.v1'
PROBE_SCHEMA = 'ces.report_publish.probe.v1'
SUBMIT_SCHEMA = 'ces.report_publish.submit.v1'
ORG_DOMAIN = b'CES-EC228-ORG-PRIVATE-SANDBOX-REPORT-POLICY-v1\x00'
ROUTE_DOMAIN = b'CES-EC228-INDEPENDENT-PUBLISH-DESTINATION-v1\x00'
REVOCATION_DOMAIN = b'CES-EC228-CURRENT-INDEPENDENT-PUBLISH-REVOCATION-v1\x00'
REVIEW_DOMAIN = b'CES-EC228-INDEPENDENT-EXACT-REPORT-CONTENT-REVIEW-v1\x00'
GRANT_DOMAIN = b'CES-EC228-ONE-TIME-REPORT-PUBLISH-GRANT-v1\x00'
CAPABILITY_DOMAIN = b'CES-EC228-CHALLENGE-BOUND-PUBLISH-PROVIDER-v1\x00'
ROOT_DOMAIN = b'CES-EC228-HOST-PINNED-SIX-PUBLISH-TRUST-ROOTS-v1\x00'
TARGET_DOMAIN = b'CES-EC228-HOST-PINNED-SINGLE-PRIVATE-PUBLISH-TARGET-v1\x00'
OP_DOMAIN = b'CES-EC228-SAME-REPORT-VERSION-AND-TARGET-ONE-PUBLISH-v1\x00'
CODE_DOMAIN = b'CES-EC228-EXACT-PUBLISH-CODE-AND-STORE-READER-v1\x00'
RECEIPT_DOMAIN = b'CES-EC228-ATTEMPT-ONLY-PUBLISH-RECEIPT-v1\x00'
PURPOSE = 'ONE_IMMUTABLE_REPORT_TO_ONE_PRIVATE_SANDBOX_ONLY'
CONTENT_CLASS = 'INTERNAL_PRIVATE_SANDBOX'
MAX_GRANT_AGE = 45
MAX_REVOCATION_AGE = 30
MAX_CAPABILITY_AGE = 20
MAX_SKEW = 5
MAX_PUBLISH_BYTES = 262144
MAX_HTTP_BODY = 385000
MAX_RESPONSE_BYTES = 8192
SHA = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
HEX32 = re.compile(r'[0-9a-f]{32}\Z', re.ASCII)
IDENT = re.compile(r'[a-z][a-z0-9_-]{7,63}\Z', re.ASCII)


def _code_sha() -> str | None:
    try:
        root = Path(__file__).resolve().parent
        files = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                 for name in ('report_publish.py', 'report_history.py', 'report_render.py',
                              'report_prepare.py', 'report_writing_handoff.py')}
        return dp.sha(CODE_DOMAIN, {'source_sha256': files, 'purpose': PURPOSE})
    except (OSError, ValueError, TypeError):
        return None


ACTIVE_PUBLISH_CODE_SHA256 = _code_sha()


class PublishDenied(ValueError):
    def __init__(self, code: str, status: str = 'blocked') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def need(ok: bool, code: str, status: str = 'blocked') -> None:
    if not ok:
        raise PublishDenied(code, status)


def _sha(value: Any) -> bool:
    return type(value) is str and SHA.fullmatch(value) is not None


def _digest(envelope: da.SignedAuthorizationStatement) -> str:
    return hashlib.sha256(dp.canonical(envelope.statement)).hexdigest()


def _doc_sha(doc: dict[str, Any]) -> str:
    return hashlib.sha256(dp.canonical(doc)).hexdigest()


def _signed(envelope: Any, key: bytes, domain: bytes, fields: set[str],
            name: str) -> dict[str, Any]:
    try:
        doc, sig = da._snapshot_signed(envelope, name)
        da.exact(doc, fields, name + '_FIELDS_INVALID')
        da._verify_signature(key, domain, doc, sig, name)
        return doc
    except da.AuthorizationDenied as exc:
        raise PublishDenied(exc.code, exc.status) from None


def _window(doc: dict[str, Any], now: int, maximum: int, name: str) -> None:
    i, e = doc.get('issued_at'), doc.get('expires_at')
    need(type(i) is int and type(e) is int and
         946684800 <= i < e <= 4102444800 and e - i <= maximum and
         now - maximum <= i <= now + MAX_SKEW and now < e,
         name + '_EXPIRED_OR_NOT_CURRENT')


def _clock() -> float:
    t = time.time()
    need(type(t) in (int, float) and math.isfinite(t) and
         946684800 <= t <= 4102444800, 'TRUSTED_CLOCK_UNAVAILABLE', 'unavailable')
    return float(t)


@dataclass(frozen=True)
class TrustedPublishRoots:
    issuer_id: str
    operator_id: str
    organization_public_key: bytes
    route_public_key: bytes
    revocation_public_key: bytes
    content_reviewer_public_key: bytes
    side_effect_public_key: bytes
    provider_public_key: bytes
    minimum_policy_epoch: int


@dataclass(frozen=True)
class HostPrivatePublishTarget:
    provider_id: str
    account_id: str
    project_id: str
    destination_id: str
    endpoint: str  # fixed trusted base URL; adapter only appends /capability or /publish
    sandbox_private: bool
    single_destination: bool


@dataclass(frozen=True)
class HostPublishAccess:
    roots: TrustedPublishRoots
    target: HostPrivatePublishTarget
    credential: str
    outbox_root: str
    enable_private_test_publish: bool
    allow_synthetic_transport_for_development: bool = False


@dataclass(frozen=True)
class ReportPublishRequest:
    storage_root: str
    slot_key: str
    period_id: str
    slot_members: list[dict[str, str]]
    read_policy: dict[str, Any]
    version: int
    report_ref: str
    record_sha256: str
    rendered_sha256: str
    entry_sha256: str
    index_binding_sha256: str
    organization: da.SignedAuthorizationStatement
    route: da.SignedAuthorizationStatement
    revocation: da.SignedAuthorizationStatement
    content_review: da.SignedAuthorizationStatement
    side_effect_grant: da.SignedAuthorizationStatement
    explicitly_approve_exact_private_publication: bool
    permit_sandbox_network_egress: bool


class PublishPort(Protocol):
    def capability(self, target: HostPrivatePublishTarget, credential: str,
                   challenge: dict[str, Any]) -> da.SignedAuthorizationStatement: ...

    def publish(self, target: HostPrivatePublishTarget, credential: str,
                body: bytes, operation_id: str) -> int: ...


class HTTPSPrivatePublishTransport:
    """Only two allowlisted HTTPS endpoints. No proxy, redirect, arbitrary URL.

    The provider MUST sign /capability's response, including random challenge,
    report bytes SHA and pinned target, before one /publish attempt is possible.
    """
    def __init__(self, timeout_seconds: float = 5.0) -> None:
        if type(timeout_seconds) not in (int, float) or not 0.5 <= timeout_seconds <= 8:
            raise ValueError('PUBLISH_TRANSPORT_BOUNDED_TIMEOUT_REQUIRED')
        self._timeout = float(timeout_seconds)
        self._opener = build_opener(ProxyHandler({}), ds._NoRedirect(),
                                    HTTPSHandler(context=ssl.create_default_context()))

    def _post(self, target: HostPrivatePublishTarget, credential: str,
              suffix: str, body: bytes, operation_id: str | None = None) -> tuple[int, bytes]:
        need(ds._url_ok(target.endpoint) and suffix in ('/capability', '/publish') and
             type(body) is bytes and 0 < len(body) <= MAX_HTTP_BODY,
             'UNSAFE_PROVIDER_HTTP_REQUEST', 'unavailable')
        headers = {'Authorization': 'Bearer ' + credential,
                   'Content-Type': 'application/json', 'Accept': 'application/json',
                   'Cache-Control': 'no-store', 'User-Agent': 'CES-EC228/1'}
        if operation_id is not None:
            headers['Idempotency-Key'] = operation_id
        request = Request(target.endpoint.rstrip('/') + suffix, body,
                          headers=headers, method='POST')
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                need(len(raw) <= MAX_RESPONSE_BYTES, 'PROVIDER_RESPONSE_LIMIT', 'unavailable')
                return response.status, raw
        except (HTTPError, URLError, OSError, TimeoutError, ssl.SSLError,
                ConnectionError, ValueError) as exc:
            raise PublishDenied('PROVIDER_HTTP_UNCONFIRMED', 'unavailable') from None

    def capability(self, target: HostPrivatePublishTarget, credential: str,
                   challenge: dict[str, Any]) -> da.SignedAuthorizationStatement:
        status, raw = self._post(target, credential, '/capability', dp.canonical(challenge))
        need(status == 200, 'PROVIDER_CAPABILITY_NOT_CONFIRMED', 'unavailable')
        try:
            def no_duplicates(items):
                keys = [k for k, _ in items]
                if len(keys) != len(set(keys)):
                    raise ValueError('duplicate JSON keys')
                return dict(items)
            value = json.loads(raw, object_pairs_hook=no_duplicates)
            need(type(value) is dict and set(value) == {'statement', 'signature_hex'},
                 'PROVIDER_CAPABILITY_ENVELOPE_INVALID', 'unavailable')
            return da.SignedAuthorizationStatement(value['statement'], value['signature_hex'])
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise PublishDenied('PROVIDER_CAPABILITY_UNPARSEABLE', 'unavailable') from None

    def publish(self, target: HostPrivatePublishTarget, credential: str,
                body: bytes, operation_id: str) -> int:
        status, _ = self._post(target, credential, '/publish', body, operation_id)
        return status


class PrivatePublishOutbox:
    """Owner-private POSIX local: same exact report version + target can claim ONCE.

    Never reuse EC225's namespace. A single operation is spent after mkdir even
    when any subsequent step crashes or the Provider reports an error. Ledger
    persistence requires a host-managed no-rollback, local filesystem; does not
    guarantee safety across unrelated hosts, NFS or malicious same-UID actors.
    """
    def __init__(self, root: str) -> None:
        self.root = root
        self._parent: int | None = None
        self._entry: int | None = None

    def __enter__(self) -> 'PrivatePublishOutbox':
        need(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and
             type(self.root) is str and os.path.isabs(self.root) and
             len(self.root) <= 2048, 'PRIVATE_LOCAL_POSIX_OUTBOX_REQUIRED', 'unavailable')
        try:
            p = Path(self.root)
            need(not any(x.is_symlink() for x in (p, *p.parents)),
                 'OUTBOX_SYMLINK_DISALLOWED', 'unavailable')
            info = os.lstat(self.root)
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
                 stat.S_IMODE(info.st_mode) & 0o077 == 0,
                 'OUTBOX_NOT_OWNER_PRIVATE', 'unavailable')
            self._parent = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            actual = os.fstat(self._parent)
            need(actual.st_dev == info.st_dev and actual.st_ino == info.st_ino and
                 actual.st_uid == os.geteuid() and stat.S_IMODE(actual.st_mode) & 0o077 == 0,
                 'OUTBOX_CHANGED', 'unavailable')
            return self
        except PublishDenied:
            self.__exit__(None, None, None)
            raise
        except (OSError, ValueError, TypeError):
            self.__exit__(None, None, None)
            raise PublishDenied('OUTBOX_OPEN_UNAVAILABLE', 'unavailable') from None

    def claim(self, operation_id: str) -> None:
        need(_sha(operation_id) and self._parent is not None,
             'OPERATION_OUTBOX_INVALID', 'unavailable')
        try:
            os.mkdir('ec228-' + operation_id, 0o700, dir_fd=self._parent)
        except FileExistsError:
            raise PublishDenied('SAME_REPORT_TARGET_ALREADY_CLAIMED_NO_RETRY') from None
        except OSError:
            raise PublishDenied('OUTBOX_RESERVATION_UNAVAILABLE', 'unavailable') from None
        try:
            self._entry = os.open('ec228-' + operation_id,
                                  os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=self._parent)
            os.fsync(self._entry)
            os.fsync(self._parent)
            self.mark('00_RESERVED_DURABLE')
        except OSError:
            raise PublishDenied('OUTBOX_DURABILITY_UNCONFIRMED', 'unavailable') from None

    def mark(self, marker: str) -> None:
        need(self._entry is not None and marker in (
            '00_RESERVED_DURABLE', '01_CAPABILITY_REQUESTED',
            '02_CAPABILITY_VERIFIED', '03_POST_ATTEMPTED',
            '04_POST_RETURNED', '05_POST_UNKNOWN'),
            'OUTBOX_MARKER_UNAVAILABLE', 'unavailable')
        try:
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self._entry)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(self._entry)
        except OSError:
            raise PublishDenied('OUTBOX_MARKER_DURABILITY_UNCONFIRMED', 'unavailable') from None

    def __exit__(self, *_):
        for fd in (self._entry, self._parent):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._entry, self._parent = None, None


def _refused(code: str, status: str, *, operation: str | None = None,
             claimed: bool = False, network: bool = False, attempted: bool = False,
             capability: bool = False) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': 4 if status == 'invalid_input' else 5,
        'reason_code': 'REPORT_PUBLISH_' + code,
        'operation_id': operation, 'attempt_receipt_id': None,
        'publication_state': 'UNKNOWN_UNCONFIRMED' if attempted else 'NOT_ATTEMPTED',
        'claim_committed': claimed, 'provider_capability_verified': capability,
        'network_requested': network, 'publish_post_attempted': attempted,
        'published': False, 'provider_accepted': False, 'external_visibility_verified': False,
        'external_publication_confirmed': False, 'resent': False,
        'effects': {'provider_publish_post_requested': attempted,
                    'external_network_requested': network,
                    'git_or_business_files_written': False,
                    'existing_remote_content_modified': False,
                    'ces_report_store_modified': False,
                    'delivery_submit_requested': False},
    }


class ReportPublisher:
    def __init__(self, access: HostPublishAccess,
                 transport: PublishPort | None = None) -> None:
        if type(access) is not HostPublishAccess or type(access.roots) is not TrustedPublishRoots or \
                type(access.target) is not HostPrivatePublishTarget:
            raise ValueError('PINNED_PUBLISH_CONFIGURATION_REQUIRED')
        r, t = access.roots, access.target
        keys = (r.organization_public_key, r.route_public_key,
                r.revocation_public_key, r.content_reviewer_public_key,
                r.side_effect_public_key, r.provider_public_key)
        if not (all(type(k) is bytes and len(k) == 32 and k != bytes(32) for k in keys) and
                len(set(keys)) == 6 and
                all(type(x) is str and IDENT.fullmatch(x) is not None for x in (
                    r.issuer_id, r.operator_id, t.provider_id, t.account_id,
                    t.destination_id)) and
                type(t.project_id) is str and t.project_id.startswith('proj_') and
                13 <= len(t.project_id) <= 68 and
                bool(re.fullmatch(r'proj_[a-z0-9_-]{8,63}', t.project_id, re.ASCII)) and
                ds._url_ok(t.endpoint) and
                type(r.minimum_policy_epoch) is int and 1 <= r.minimum_policy_epoch < 2**63 and
                type(t.sandbox_private) is bool and t.sandbox_private and
                type(t.single_destination) is bool and t.single_destination and
                type(access.enable_private_test_publish) is bool and
                type(access.allow_synthetic_transport_for_development) is bool):
            raise ValueError('INVALID_PRIVATE_SANDBOX_PUBLISH_TARGET_OR_ROOTS')
        self.access = access
        self._transport = transport if transport is not None else HTTPSPrivatePublishTransport()
        if not access.allow_synthetic_transport_for_development and \
                type(self._transport) is not HTTPSPrivatePublishTransport:
            raise ValueError('NON_HTTPS_PUBLISH_PORT_REQUIRES_EXPLICIT_DEVELOPMENT_FLAG')
        self._target = dp.sha(TARGET_DOMAIN, {
            'provider_id': t.provider_id, 'account_id': t.account_id,
            'project_id': t.project_id, 'destination_id': t.destination_id,
            'endpoint_sha256': hashlib.sha256(t.endpoint.encode('ascii')).hexdigest(),
            'sandbox_private': t.sandbox_private, 'single_destination': t.single_destination})
        self._roots = dp.sha(ROOT_DOMAIN, {
            'issuer_id': r.issuer_id, 'operator_id': r.operator_id,
            'root_key_sha256': [hashlib.sha256(k).hexdigest() for k in keys],
            'target_sha256': self._target, 'minimum_epoch': r.minimum_policy_epoch})

    def _verify(self, req: ReportPublishRequest, now: int) -> dict[str, Any]:
        need(type(req) is ReportPublishRequest and
             req.explicitly_approve_exact_private_publication is True and
             req.permit_sandbox_network_egress is True and
             self.access.enable_private_test_publish is True and
             type(self.access.credential) is str and
             16 <= len(self.access.credential) <= 2048 and
             all(0x21 <= ord(c) <= 0x7e for c in self.access.credential) and
             not any(c in self.access.credential for c in ('\r', '\n', ' ')),
             'EXPLICIT_HOST_SANDBOX_CONSENT_AND_CREDENTIAL_REQUIRED', 'unavailable')
        need(type(req.version) is int and 1 <= req.version <= rr.MAX_VERSIONS and
             type(req.report_ref) is str and rr.REPORT.fullmatch(req.report_ref) is not None and
             all(_sha(x) for x in (req.record_sha256, req.rendered_sha256,
                                   req.entry_sha256, req.index_binding_sha256)) and
             type(req.storage_root) is str and type(req.read_policy) is dict,
             'EXACT_SAVED_REPORT_REQUIRED', 'invalid_input')
        # Signed request is validated BEFORE a single sensitive store byte is read.
        r, t = self.access.roots, self.access.target
        org = _signed(req.organization, r.organization_public_key, ORG_DOMAIN, {
            'schema', 'issuer_id', 'project_id', 'report_slot_ref', 'provider_id',
            'destination_id', 'policy_epoch', 'content_class', 'private_sandbox_only',
            'issued_at', 'expires_at'}, 'ORGANIZATION')
        route = _signed(req.route, r.route_public_key, ROUTE_DOMAIN, {
            'schema', 'project_id', 'provider_id', 'account_id', 'destination_id',
            'target_sha256', 'visibility', 'audience', 'single_destination',
            'issued_at', 'expires_at'}, 'ROUTE')
        revoke = _signed(req.revocation, r.revocation_public_key, REVOCATION_DOMAIN, {
            'schema', 'project_id', 'destination_id', 'operator_id', 'grant_nonce',
            'policy_epoch', 'state', 'issued_at', 'expires_at'}, 'REVOCATION')
        review = _signed(req.content_review, r.content_reviewer_public_key,
                         REVIEW_DOMAIN, {'schema', 'report_slot_ref', 'report_ref',
             'version', 'record_sha256', 'rendered_sha256', 'entry_sha256',
             'reviewer_id', 'content_class', 'review_state', 'issued_at', 'expires_at'},
             'CONTENT_REVIEW')
        grant = _signed(req.side_effect_grant, r.side_effect_public_key,
                        GRANT_DOMAIN, {'schema', 'issuer_id', 'operator_id', 'project_id',
             'report_slot_ref', 'report_ref', 'version', 'record_sha256',
             'rendered_sha256', 'entry_sha256', 'index_binding_sha256',
             'store_binding_sha256', 'read_policy_sha256', 'organization_sha256',
             'route_sha256', 'revocation_sha256', 'content_review_sha256',
             'target_sha256', 'trust_roots_sha256', 'code_revision_sha256',
             'policy_epoch', 'grant_nonce', 'permission', 'issued_at', 'expires_at'},
             'PUBLISH_GRANT')
        for name, doc, age in (
            ('ORGANIZATION', org, 120), ('ROUTE', route, 120),
            ('REVOCATION', revoke, MAX_REVOCATION_AGE),
            ('CONTENT_REVIEW', review, 120), ('PUBLISH_GRANT', grant, MAX_GRANT_AGE)):
            _window(doc, now, age, name)
        try:
            selection = rh._selector(req.slot_key, req.period_id, req.slot_members)
            binding = rh.local_store_binding(req.storage_root)
        except (rr.RenderError, OSError, ValueError, TypeError, UnicodeError):
            raise PublishDenied('PRIVATE_REPORT_STORE_SCOPE_UNAVAILABLE', 'unavailable') from None
        need(org['schema'] == ORG_SCHEMA and org['issuer_id'] == r.issuer_id and
             org['project_id'] == t.project_id and org['provider_id'] == t.provider_id and
             org['destination_id'] == t.destination_id and
             org['report_slot_ref'] == selection['report_slot_ref'] and
             org['content_class'] == CONTENT_CLASS and org['private_sandbox_only'] is True and
             type(org['policy_epoch']) is int and
             org['policy_epoch'] >= r.minimum_policy_epoch,
             'ORG_POLICY_SCOPE_NOT_PERMITTED')
        need(route['schema'] == ROUTE_SCHEMA and route['project_id'] == t.project_id and
             route['provider_id'] == t.provider_id and route['account_id'] == t.account_id and
             route['destination_id'] == t.destination_id and
             route['target_sha256'] == self._target and
             route['visibility'] == 'PRIVATE_TEST_ONLY' and
             route['audience'] == 'INTERNAL_TEST' and
             route['single_destination'] is True,
             'PUBLISH_TARGET_NOT_AUTHORIZED')
        need(grant['schema'] == GRANT_SCHEMA and grant['issuer_id'] == r.issuer_id and
             grant['operator_id'] == r.operator_id and grant['project_id'] == t.project_id and
             grant['report_slot_ref'] == selection['report_slot_ref'] and
             grant['report_ref'] == req.report_ref and grant['version'] == req.version and
             all(grant[k] == getattr(req, k) for k in (
                 'record_sha256', 'rendered_sha256', 'entry_sha256', 'index_binding_sha256')) and
             grant['store_binding_sha256'] == binding and
             grant['read_policy_sha256'] == hashlib.sha256(dp.canonical(req.read_policy)).hexdigest() and
             grant['organization_sha256'] == _doc_sha(org) and
             grant['route_sha256'] == _doc_sha(route) and
             grant['revocation_sha256'] == _doc_sha(revoke) and
             grant['content_review_sha256'] == _doc_sha(review) and
             grant['target_sha256'] == self._target and
             grant['trust_roots_sha256'] == self._roots and
             _sha(ACTIVE_PUBLISH_CODE_SHA256) and
             grant['code_revision_sha256'] == ACTIVE_PUBLISH_CODE_SHA256 == _code_sha() and
             grant['policy_epoch'] == org['policy_epoch'] and
             grant['permission'] == 'PUBLISH_ONCE_IMMUTABLE_PRIVATE_TEST_REPORT' and
             type(grant['grant_nonce']) is str and HEX32.fullmatch(grant['grant_nonce']) is not None,
             'SIGNED_PUBLISH_GRANT_NOT_EXACT_OR_CODE_CHANGED')
        need(revoke['schema'] == REVOCATION_SCHEMA and
             revoke['project_id'] == t.project_id and
             revoke['destination_id'] == t.destination_id and
             revoke['operator_id'] == r.operator_id and
             revoke['grant_nonce'] == grant['grant_nonce'] and
             revoke['policy_epoch'] == org['policy_epoch'] and
             revoke['state'] == 'ACTIVE', 'FRESH_REVOCATION_DENIED')
        need(review['schema'] == REVIEW_SCHEMA and
             review['report_slot_ref'] == selection['report_slot_ref'] and
             review['report_ref'] == req.report_ref and review['version'] == req.version and
             all(review[k] == getattr(req, k) for k in (
                 'record_sha256', 'rendered_sha256', 'entry_sha256')) and
             type(review['reviewer_id']) is str and IDENT.fullmatch(review['reviewer_id']) is not None and
             review['content_class'] == CONTENT_CLASS and
             review['review_state'] == 'HUMAN_REVIEWED_EXACT_BYTES_FOR_PRIVATE_TEST',
             'INDEPENDENT_CONTENT_REVIEW_REQUIRED')
        return {'selection': selection, 'binding': binding, 'grant': grant,
                'org': org, 'route': route, 'revoke': revoke, 'review': review,
                'statement_sha256s': tuple(map(_doc_sha, (org, route, revoke, review, grant))),
                'grant_sha256': _doc_sha(grant)}

    def _read_exact(self, req: ReportPublishRequest,
                    checked: dict[str, Any]) -> bytes:
        # rh._load calls EC199 _valid_index on ALL indexed immutable JSON AND
        # Markdown files; its repository-specific policy gates are NOT skipped.
        try:
            idx, docs = rh._load(req.storage_root, checked['selection'], req.read_policy)
            need(req.version == len(docs) and req.version == len(idx['versions']),
                 'REPORT_SUPERSEDED_REQUIRE_NEW_REVIEW')
            row = idx['versions'][req.version - 1]
            doc = docs[req.version - 1]
            need(idx['binding_sha256'] == req.index_binding_sha256 and
                 row['report_ref'] == req.report_ref and
                 row['record_sha256'] == req.record_sha256 and
                 row['rendered_sha256'] == req.rendered_sha256 and
                 row['entry_sha256'] == req.entry_sha256 and
                 doc['report_ref'] == req.report_ref and
                 doc['document_state'] == 'UNPUBLISHED_INTERNAL_REVIEW_ARTIFACT' and
                 doc['trust_state'] == 'DECLARED_ONLY_NOT_AUTHENTICATED',
                 'VERSIONED_REPORT_PIN_DRIFT')
            need(req.read_policy.get('permit_rendered_markdown') is True and
                 all(row.get('permit_rendered_markdown') is True
                     for row in req.read_policy.get('repository_grants', [])),
                 'REPOSITORY_MARKDOWN_READ_NOT_AUTHORIZED')
            content = doc['rendered_markdown'].encode('utf-8')
            need(0 < len(content) <= MAX_PUBLISH_BYTES and
                 hashlib.sha256(content).hexdigest() == req.rendered_sha256,
                 'REPORT_MARKDOWN_BYTES_NOT_VALID')
            # This fixed, narrow filter is defense in depth, NOT a DLP claim.
            # Human reviewer must independently inspect the identical bytes.
            need(not any(pattern.search(content) for pattern in (
                re.compile(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----', re.I),
                re.compile(rb'(?i)authorization\s*:\s*bearer\s+\S+'),
                re.compile(rb'(?i)(?:api[_-]?key|secret[_-]?token)\s*[:=]\s*[\w-]{16,}'),
            )), 'OBVIOUS_CREDENTIAL_MATERIAL_IN_REPORT')
            return content
        except PublishDenied:
            raise
        except (rr.RenderError, OSError, TypeError, ValueError, UnicodeError,
                AttributeError, KeyError, IndexError, RecursionError):
            raise PublishDenied('REPORT_PRIVATE_SOURCE_NOT_VERIFIABLE', 'unavailable') from None

    def _check_capability(self, signed: da.SignedAuthorizationStatement,
                          challenge: dict[str, Any], now: int) -> dict[str, Any]:
        doc = _signed(signed, self.access.roots.provider_public_key, CAPABILITY_DOMAIN, {
            'schema', 'provider_id', 'account_id', 'target_sha256', 'operation_id',
            'challenge_nonce', 'report_ref', 'rendered_sha256', 'permission',
            'private_sandbox', 'single_destination', 'idempotency_supported',
            'create_only',
            'issued_at', 'expires_at'}, 'PROVIDER_CAPABILITY')
        t = self.access.target
        need(doc['schema'] == CAPABILITY_SCHEMA and
             doc['provider_id'] == t.provider_id and doc['account_id'] == t.account_id and
             all(doc[k] == challenge[k] for k in ('target_sha256', 'operation_id',
                  'challenge_nonce', 'report_ref', 'rendered_sha256')) and
             doc['permission'] == 'PUBLISH_EXACT_ONE_PRIVATE_TEST_REPORT' and
             doc['private_sandbox'] is True and doc['single_destination'] is True and
             doc['idempotency_supported'] is True and doc['create_only'] is True,
             'PROVIDER_UNAUTHORIZED_PRIVATE_CAPABILITY')
        _window(doc, now, MAX_CAPABILITY_AGE, 'PROVIDER_CAPABILITY')
        return doc

    def publish_once(self, req: ReportPublishRequest) -> dict[str, Any]:
        operation: str | None = None
        claimed = network = attempted = capable = False
        try:
            begin = _clock()
            checked = self._verify(req, int(begin))
            payload = self._read_exact(req, checked)
            t = self.access.target
            operation = dp.sha(OP_DOMAIN, {
                'report_slot_ref': checked['selection']['report_slot_ref'],
                'report_ref': req.report_ref, 'rendered_sha256': req.rendered_sha256,
                'target_sha256': self._target, 'project_id': t.project_id})
            with PrivatePublishOutbox(self.access.outbox_root) as journal:
                journal.claim(operation)
                claimed = True
                challenge = {'schema': PROBE_SCHEMA,
                    'provider_id': t.provider_id, 'account_id': t.account_id,
                    'target_sha256': self._target, 'operation_id': operation,
                    'challenge_nonce': secrets.token_hex(16),
                    'report_ref': req.report_ref, 'rendered_sha256': req.rendered_sha256}
                journal.mark('01_CAPABILITY_REQUESTED')
                network = True
                capability = self._transport.capability(t, self.access.credential, challenge)
                cap = self._check_capability(capability, challenge, int(_clock()))
                journal.mark('02_CAPABILITY_VERIFIED')
                # Entire real store and all *current* signatures are rechecked
                # after the Provider probe and BEFORE the irreversible POST.
                renewed = self._verify(req, int(_clock()))
                refreshed = self._read_exact(req, renewed)
                need(refreshed == payload and
                     renewed['selection'] == checked['selection'] and
                     renewed['statement_sha256s'] == checked['statement_sha256s'],
                     'REPORT_CHANGED_DURING_PUBLISH', 'unavailable')
                now = _clock()
                need(now >= begin and now < min(
                    checked['grant']['expires_at'], checked['org']['expires_at'],
                    checked['route']['expires_at'], checked['revoke']['expires_at'],
                    checked['review']['expires_at'], cap['expires_at']) and
                     ACTIVE_PUBLISH_CODE_SHA256 == _code_sha(),
                     'PUBLISH_EDGE_PERMISSION_OR_CODE_EXPIRED', 'unavailable')
                body = dp.canonical({
                    'schema': SUBMIT_SCHEMA, 'operation_id': operation,
                    'provider_id': t.provider_id, 'account_id': t.account_id,
                    'target_sha256': self._target, 'report_slot_ref':
                        checked['selection']['report_slot_ref'],
                    'report_ref': req.report_ref, 'version': req.version,
                    'entry_sha256': req.entry_sha256,
                    'record_sha256': req.record_sha256,
                    'rendered_sha256': req.rendered_sha256,
                    'content_media_type': rr.FORMAT,
                    'create_only': True, 'overwrite_existing': False,
                    'markdown_b64': base64.b64encode(payload).decode('ascii'),
                    'side_effect_grant_sha256': checked['grant_sha256'],
                    'provider_capability': cap,
                    'provider_capability_signature_hex': capability.signature_hex,
                })
                need(len(body) <= MAX_HTTP_BODY, 'PRIVATE_PUBLICATION_BODY_TOO_LARGE',
                     'unavailable')
                journal.mark('03_POST_ATTEMPTED')  # must fsync BEFORE network
                edge = _clock()
                need(edge >= now and edge < min(
                    checked['grant']['expires_at'], checked['org']['expires_at'],
                    checked['route']['expires_at'], checked['revoke']['expires_at'],
                    checked['review']['expires_at'], cap['expires_at']) and
                     _code_sha() == ACTIVE_PUBLISH_CODE_SHA256,
                     'DURABLE_PUBLISH_EDGE_EXPIRED_NO_RETRY', 'unavailable')
                attempted = True
                try:
                    status = self._transport.publish(t, self.access.credential,
                                                     body, operation)
                except Exception:
                    try:
                        journal.mark('05_POST_UNKNOWN')
                    except PublishDenied:
                        pass
                    return _refused('PROVIDER_OUTCOME_UNKNOWN_NO_RETRY', 'unavailable',
                                    operation=operation, claimed=True, network=True,
                                    attempted=True, capability=True)
                journal.mark('04_POST_RETURNED')
                need(type(status) is int and status in (200, 201, 202, 204),
                     'PROVIDER_HTTP_NOT_PUBLICATION_PROOF_NO_RETRY', 'unavailable')
                return {
                    'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
                    'reason_code': 'REPORT_PUBLISH_HTTP_RETURNED_OUTCOME_UNCONFIRMED',
                    'operation_id': operation,
                    'attempt_receipt_id': 'cesrp1:' + dp.sha(RECEIPT_DOMAIN, {
                        'operation_id': operation, 'report_ref': req.report_ref,
                        'rendered_sha256': req.rendered_sha256,
                        'target_sha256': self._target, 'http_status': status}),
                    'publication_state': 'SUBMISSION_UNCONFIRMED',
                    'claim_committed': True, 'provider_capability_verified': True,
                    'network_requested': True, 'publish_post_attempted': True,
                    'published': False, 'provider_accepted': False,
                    'external_visibility_verified': False,
                    'external_publication_confirmed': False, 'resent': False,
                    'effects': {'provider_publish_post_requested': True,
                                'external_network_requested': True,
                                'git_or_business_files_written': False,
                                'existing_remote_content_modified': False,
                                'ces_report_store_modified': False,
                                'delivery_submit_requested': False},
                }
        except PublishDenied as exc:
            return _refused(exc.code, exc.status, operation=operation, claimed=claimed,
                            network=network, attempted=attempted, capability=capable)
        except Exception:
            return _refused('HOST_SOURCE_OR_PROVIDER_UNAVAILABLE', 'unavailable',
                            operation=operation, claimed=claimed,
                            network=network, attempted=attempted, capability=capable)
