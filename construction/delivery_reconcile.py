#!/usr/bin/env python3
"""EC227: durable, bounded, authenticated reconciliation of EC225/EC226.

An original EC225 approval/operation is permanently spent at its durable
outbox reservation. This component NEVER calls DeliverySender.send_once or an
HTTP submit method. A 'retry' here means ONLY another separately authorized
EC226 read with a new read nonce. Provider acceptance is not inbox delivery.

The local audit is an append-only sequence of per-operation HMAC-chained,
fsynced records with a POSIX advisory per-operation lock. It is NOT a remote
provider log, an independently signed receipt archive, a rollback-proof
notary, a native PowerShell Action or a cross-host/NFS transaction system.
The HMAC key must be supplied separately by the trusted host, never bundled.
"""
from __future__ import annotations

from dataclasses import dataclass, field
try:
    import fcntl  # POSIX advisory locks; Windows has no EC227 adapter.
except ImportError:
    fcntl = None
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
from typing import Any

try:
    from . import delivery_preview as dp, delivery_authorization as da
    from . import delivery_send as ds, delivery_status as st
except ImportError:
    import delivery_preview as dp
    import delivery_authorization as da
    import delivery_send as ds
    import delivery_status as st

SCHEMA = 'ces.delivery_reconcile.v1'
ENTRY_SCHEMA = 'ces.delivery_reconcile.audit_entry.v1'
SLOT_DOMAIN = b'CES-EC227-SCOPED-OPERATION-AUDIT-SLOT-v1\x00'
NONCE_DOMAIN = b'CES-EC227-HASH-STATUS-READ-NONCE-v1\x00'
MAC_DOMAIN = b'CES-EC227-LOCAL-AUDIT-HMAC-CHAIN-v1\x00'
MAX_AUDIT_ENTRIES = 64                 # max 32 complete reads; no auto-pruning
MAX_ENTRY_BYTES = 4096
GENESIS = '0' * 64
FINAL_STATES = frozenset({
    'UNKNOWN_UNCONFIRMED', 'ACCEPTED_PROVIDER_ATTESTED',
    'DELIVERED_INBOX_OBSERVED', 'PROVIDER_REJECTION_ATTESTED',
    'PROVIDER_FAILURE_ATTESTED',
})
PROVIDER_STATES = frozenset({'UNKNOWN', 'PENDING', 'ACCEPTED', 'DELIVERED',
                             'REJECTED', 'FAILED'})
KNOWN_STATES = FINAL_STATES - {'UNKNOWN_UNCONFIRMED'}
ENTRY_KEYS = frozenset({
    'schema', 'sequence', 'kind', 'operation_id', 'provider_target_binding_sha256',
    'approver_exact_grant_sha256', 'payload_sha256', 'read_grant_sha256',
    'read_nonce_sha256', 'recorded_at', 'delivery_state', 'provider_state',
    'provider_message_id_sha256', 'provider_evidence_verified',
    'inbox_evidence_verified', 'previous_hmac_sha256',
})


@dataclass(frozen=True)
class HostAuditAccess:
    """Opaque host-only local audit key; no credential, path, or key serialized."""
    hmac_secret: bytes = field(repr=False)
    enable_local_private_audit: bool


class AuditDenied(Exception):
    def __init__(self, code: str, status: str = 'unavailable') -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def require(ok: bool, code: str, status: str = 'unavailable') -> None:
    if not ok:
        raise AuditDenied(code, status)


def _mac(secret: bytes, entry: dict[str, Any]) -> str:
    return hmac.new(secret, MAC_DOMAIN + dp.canonical(entry), hashlib.sha256).hexdigest()


def _time() -> int:
    try:
        return int(ds._clock())
    except (ds.SendDenied, TypeError, ValueError):
        raise AuditDenied('HOST_AUDIT_CLOCK_UNAVAILABLE') from None


def _result(code: str, status: str, *, operation_id: str | None = None,
            state: str = 'UNKNOWN_UNCONFIRMED', historical: str | None = None,
            records: int = 0, head: str | None = None, integrity: bool = False,
            network: bool = False, conflict: bool = False,
            incomplete: bool = False, last_provider: str | None = None,
            observed: bool = False, audit_written: bool = False) -> dict[str, Any]:
    # A recorded historical state is NOT a new remote observation.
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': 2 if status == 'partial' else 4 if status == 'invalid_input' else 5,
        'reason_code': 'DELIVERY_RECONCILE_' + code,
        'operation_id': operation_id,
        'delivery_state': state,
        'last_historical_attested_state': historical,
        'last_provider_state': last_provider,
        'audit_event_count': records,
        'audit_head_hmac_sha256': head,
        'audit_chain_verified': integrity,
        'status_network_requested': network,
        'fresh_independent_status_evidence_verified': observed,
        'conflicting_historical_evidence': conflict,
        'incomplete_prior_observation': incomplete,
        'original_operation_retry_allowed': False,
        'new_delivery_authorized': False,
        'resent': False,
        'published': False,
        'effects': {
            'provider_submit_requested': False,
            'external_status_network_requested': network,
            'recipient_contacted_by_reconciler': False,
            'git_or_business_files_written': False,
            'ces_business_records_written': False,
            'local_audit_records_written': audit_written,
        },
    }


class PrivateAuditJournal:
    """Local POSIX-only per-operation append-only log, under original outbox.

    No in-place update, truncation, cleanup, replacement or reverse-merge.
    Directory flock is deliberately non-blocking: competing workers refuse
    before network lookup. No guarantee on NFS or against same-UID attackers.
    """
    def __init__(self, root: str, operation: str, target: str, secret: bytes,
                 *, create: bool) -> None:
        self.root, self.operation, self.target = root, operation, target
        self.secret, self.create = secret, create
        self.parent_fd: int | None = None
        self.fd: int | None = None
        self.present = False
        self._slot = 'ec227-' + dp.sha(SLOT_DOMAIN, {
            'operation_id': operation, 'provider_target_binding_sha256': target,
        })

    @staticmethod
    def _secure_dir(fd: int) -> None:
        s = os.fstat(fd)
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.geteuid() and
                s.st_mode & 0o077 == 0,
                'AUDIT_DIRECTORY_UNTRUSTED')

    def __enter__(self) -> 'PrivateAuditJournal':
        require(os.name == 'posix' and fcntl is not None and
                hasattr(os, 'O_NOFOLLOW') and
                type(self.root) is str and os.path.isabs(self.root) and
                len(self.root) <= 2048 and da.sha_string(self.operation) and
                da.sha_string(self.target), 'PRIVATE_POSIX_AUDIT_REQUIRED')
        try:
            p = Path(self.root)
            require(not any(x.is_symlink() for x in (p, *p.parents)),
                    'AUDIT_ROOT_SYMLINK_DENIED')
            saved = os.lstat(self.root)
            require(stat.S_ISDIR(saved.st_mode) and saved.st_uid == os.geteuid() and
                    saved.st_mode & 0o077 == 0, 'AUDIT_ROOT_NOT_PRIVATE')
            self.parent_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self._secure_dir(self.parent_fd)
            current = os.fstat(self.parent_fd)
            require((saved.st_dev, saved.st_ino) == (current.st_dev, current.st_ino),
                    'AUDIT_ROOT_CHANGED')
            if self.create:
                try:
                    os.mkdir(self._slot, 0o700, dir_fd=self.parent_fd)
                    os.fsync(self.parent_fd)
                except FileExistsError:
                    pass
            try:
                self.fd = os.open(self._slot, os.O_RDONLY | os.O_DIRECTORY |
                                  os.O_NOFOLLOW, dir_fd=self.parent_fd)
            except FileNotFoundError:
                require(not self.create, 'AUDIT_DIRECTORY_CREATE_FAILED')
                return self
            self._secure_dir(self.fd)
            fcntl.flock(self.fd, (fcntl.LOCK_EX if self.create else fcntl.LOCK_SH) |
                         fcntl.LOCK_NB)
            self.present = True
            return self
        except (OSError, ValueError, TypeError, AuditDenied):
            self.__exit__(None, None, None)
            raise AuditDenied('PRIVATE_AUDIT_LOCK_OR_STORAGE_UNAVAILABLE') from None

    def __exit__(self, exc_type, exc, tb) -> None:
        for fd in (self.fd, self.parent_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self.fd = self.parent_fd = None

    def _validate_entry(self, e: Any, expected_seq: int, previous: str,
                        operation: str, target: str, approval: str,
                        payload: str) -> None:
        require(type(e) is dict and set(e) == ENTRY_KEYS and
                e['schema'] == ENTRY_SCHEMA and
                type(e['sequence']) is int and e['sequence'] == expected_seq and
                e['kind'] in ('LOOKUP_STARTED', 'LOOKUP_RESULT') and
                e['operation_id'] == operation and
                e['provider_target_binding_sha256'] == target and
                e['approver_exact_grant_sha256'] == approval and
                e['payload_sha256'] == payload and
                da.sha_string(e['read_grant_sha256']) and
                da.sha_string(e['read_nonce_sha256']) and
                type(e['recorded_at']) is int and
                946684800 <= e['recorded_at'] <= 4102444800 and
                e['previous_hmac_sha256'] == previous and
                e['delivery_state'] in FINAL_STATES and
                type(e['provider_evidence_verified']) is bool and
                type(e['inbox_evidence_verified']) is bool,
                'AUDIT_RECORD_SCOPE_OR_SHAPE_INVALID')
        if e['kind'] == 'LOOKUP_STARTED' or not e['provider_evidence_verified']:
            require(e['delivery_state'] == 'UNKNOWN_UNCONFIRMED' and
                    e['provider_state'] is None and
                    e['provider_message_id_sha256'] is None and
                    not e['provider_evidence_verified'] and
                    not e['inbox_evidence_verified'],
                    'AUDIT_UNPROVEN_STATE_WAS_PROMOTED')
        else:
            p, s, inbox = (e['provider_state'], e['delivery_state'],
                           e['inbox_evidence_verified'])
            require(type(p) is str and p in PROVIDER_STATES and
                    (da.sha_string(e['provider_message_id_sha256'])
                     if p in ('ACCEPTED', 'DELIVERED')
                     else e['provider_message_id_sha256'] is None) and
                    ((s == 'DELIVERED_INBOX_OBSERVED' and p == 'DELIVERED' and inbox) or
                     (s == 'ACCEPTED_PROVIDER_ATTESTED' and
                      p in ('ACCEPTED', 'DELIVERED') and not inbox) or
                     (s == 'PROVIDER_REJECTION_ATTESTED' and p == 'REJECTED' and not inbox) or
                     (s == 'PROVIDER_FAILURE_ATTESTED' and p == 'FAILED' and not inbox) or
                     (s == 'UNKNOWN_UNCONFIRMED' and p in ('UNKNOWN', 'PENDING') and
                      not inbox)),
                    'AUDIT_REMOTE_EVIDENCE_CONTRADICTION')

    def read(self, history: dict[str, Any]) -> list[dict[str, Any]]:
        if not self.present:
            return []
        require(self.fd is not None, 'AUDIT_LOG_NOT_OPEN')
        try:
            names = os.listdir(self.fd)
            require(len(names) <= MAX_AUDIT_ENTRIES and
                    all(len(name) == 11 and name[:6].isdigit() and
                        name.endswith('.json') for name in names),
                    'AUDIT_UNEXPECTED_OR_EXCESS_FILES')
            expected_names = [f'{i:06d}.json' for i in range(1, len(names) + 1)]
            require(sorted(names) == expected_names, 'AUDIT_GAP_OR_REORDER')
            entries: list[dict[str, Any]] = []
            previous = GENESIS
            started: dict[str, str] = {}
            used_nonces: set[str] = set()
            previous_time = 0
            for number, name in enumerate(expected_names, 1):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=self.fd)
                try:
                    info = os.fstat(fd)
                    require(stat.S_ISREG(info.st_mode) and
                            info.st_uid == os.geteuid() and
                            info.st_nlink == 1 and info.st_mode & 0o077 == 0 and
                            0 < info.st_size <= MAX_ENTRY_BYTES,
                            'AUDIT_FILE_OWNER_SIZE_OR_LINK_INVALID')
                    content = os.read(fd, MAX_ENTRY_BYTES + 1)
                    require(len(content) == info.st_size, 'AUDIT_FILE_RACE_OR_SIZE_CHANGED')
                finally:
                    os.close(fd)
                envelope = json.loads(content)
                # The writer emits exactly one canonical JSON serialization.
                # Refuse alternate spellings and duplicate JSON keys on read.
                require(dp.canonical(envelope) == content,
                        'AUDIT_NONCANONICAL_OR_DUPLICATED_JSON_KEYS')
                require(type(envelope) is dict and set(envelope) == {'entry', 'hmac_sha256'} and
                        da.sha_string(envelope['hmac_sha256']),
                        'AUDIT_ENVELOPE_INVALID')
                entry = envelope['entry']
                self._validate_entry(entry, number, previous, history['operation_id'],
                                     history['provider_target_binding_sha256'],
                                     history['approver_exact_grant_sha256'],
                                     history['payload_sha256'])
                require(hmac.compare_digest(_mac(self.secret, entry), envelope['hmac_sha256']),
                        'AUDIT_HMAC_TAMPER_DETECTED')
                require(entry['recorded_at'] >= previous_time,
                        'AUDIT_CLOCK_ROLLBACK_DETECTED')
                previous_time = entry['recorded_at']
                read_sha = entry['read_grant_sha256']
                if entry['kind'] == 'LOOKUP_STARTED':
                    require(read_sha not in started and
                            entry['read_nonce_sha256'] not in used_nonces,
                            'AUDIT_READ_GRANT_OR_NONCE_REPLAY')
                    started[read_sha] = entry['read_nonce_sha256']
                    used_nonces.add(entry['read_nonce_sha256'])
                else:
                    require(read_sha in started and
                            started.pop(read_sha) == entry['read_nonce_sha256'],
                            'AUDIT_ORPHANED_OR_DUPLICATED_RESULT')
                previous = envelope['hmac_sha256']
                entries.append({'entry': entry, 'hmac_sha256': previous})
            return entries
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError):
            raise AuditDenied('AUDIT_UNREADABLE_OR_TAMPERED') from None

    def append(self, history: dict[str, Any], events: list[dict[str, Any]],
               *, kind: str, read_sha: str, nonce_sha: str, observed_at: int,
               delivery_state: str = 'UNKNOWN_UNCONFIRMED',
               provider_state: str | None = None,
               provider_message_id_sha256: str | None = None,
               provider_evidence_verified: bool = False,
               inbox_evidence_verified: bool = False) -> list[dict[str, Any]]:
        require(self.create and self.fd is not None and self.present,
                'AUDIT_APPEND_LOCK_REQUIRED')
        require(len(events) < MAX_AUDIT_ENTRIES,
                'AUDIT_BOUNDED_CAPACITY_EXHAUSTED')
        previous = events[-1]['hmac_sha256'] if events else GENESIS
        entry = {
            'schema': ENTRY_SCHEMA, 'sequence': len(events) + 1, 'kind': kind,
            'operation_id': history['operation_id'],
            'provider_target_binding_sha256': history['provider_target_binding_sha256'],
            'approver_exact_grant_sha256': history['approver_exact_grant_sha256'],
            'payload_sha256': history['payload_sha256'],
            'read_grant_sha256': read_sha, 'read_nonce_sha256': nonce_sha,
            'recorded_at': observed_at, 'delivery_state': delivery_state,
            'provider_state': provider_state,
            'provider_message_id_sha256': provider_message_id_sha256,
            'provider_evidence_verified': provider_evidence_verified,
            'inbox_evidence_verified': inbox_evidence_verified,
            'previous_hmac_sha256': previous,
        }
        self._validate_entry(entry, len(events) + 1, previous,
                             history['operation_id'], history['provider_target_binding_sha256'],
                             history['approver_exact_grant_sha256'], history['payload_sha256'])
        require(not events or observed_at >= events[-1]['entry']['recorded_at'],
                'AUDIT_CLOCK_ROLLBACK_DETECTED')
        signed = {'entry': entry, 'hmac_sha256': _mac(self.secret, entry)}
        raw = dp.canonical(signed)
        require(len(raw) <= MAX_ENTRY_BYTES, 'AUDIT_ENTRY_TOO_LARGE')
        name = f'{len(events)+1:06d}.json'
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self.fd)
            try:
                offset = 0
                while offset < len(raw):
                    written = os.write(fd, raw[offset:])
                    require(written > 0, 'AUDIT_ATOMIC_WRITE_UNAVAILABLE')
                    offset += written
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(self.fd)
        except (OSError, ValueError):
            # A partial file remains intentionally. Do not fix/overwrite history.
            raise AuditDenied('AUDIT_FSYNC_OR_APPEND_FAILED') from None
        return events + [signed]


def _summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Never treat a historical/unfinished status as current verified evidence."""
    history_state = None
    last_provider = None
    previous = None
    previous_message = None
    conflict = False
    pending: set[str] = set()
    for record in events:
        e = record['entry']
        if e['kind'] == 'LOOKUP_STARTED':
            pending.add(e['read_grant_sha256'])
            continue
        pending.discard(e['read_grant_sha256'])
        if not e['provider_evidence_verified'] or e['delivery_state'] not in KNOWN_STATES:
            continue
        if previous is not None:
            a, b = previous, e['delivery_state']
            # Only an accepted -> delivered promotion is consistent. All
            # failure-vs-success and delivered -> accepted reversals conflict.
            if a != b and not (a == 'ACCEPTED_PROVIDER_ATTESTED' and
                               b == 'DELIVERED_INBOX_OBSERVED'):
                conflict = True
            if previous_message is not None and e['provider_message_id_sha256'] is not None and \
                    previous_message != e['provider_message_id_sha256']:
                conflict = True
        previous = e['delivery_state']
        previous_message = e['provider_message_id_sha256']
        history_state = e['delivery_state']
        last_provider = e['provider_state']
    last = events[-1]['entry'] if events else None
    # Earlier crashed READ-only lookups remain visible as orphan START records,
    # but a later independently verified, completed read may establish a new
    # current observation. Old uncertainty NEVER permits a fresh POST.
    complete = last is not None and last['kind'] == 'LOOKUP_RESULT'
    latest = last['delivery_state'] if complete and not conflict else 'UNKNOWN_UNCONFIRMED'
    # An unknown terminal result is still UNKNOWN, even if the past was better.
    return {'historical': history_state, 'last_provider': last_provider,
            'delivery_state': latest, 'conflict': conflict,
            'incomplete': bool(pending),
            'last_verified': bool(complete and last['provider_evidence_verified'] and
                                  not conflict),
            'count': len(events),
            'head': events[-1]['hmac_sha256'] if events else None}


class DeliveryReconciler:
    """Original operation is never resubmitted; only fresh read grants are used."""

    def __init__(self, reader: st.DeliveryStatusReader, host: HostAuditAccess) -> None:
        if (type(reader) is not st.DeliveryStatusReader or
            type(host) is not HostAuditAccess or
            type(host.hmac_secret) is not bytes or len(host.hmac_secret) != 32 or
            host.hmac_secret == b'\0' * 32 or
            type(host.enable_local_private_audit) is not bool):
            raise ValueError('EXACT_STATUS_READER_AND_HOST_PRIVATE_AUDIT_KEY_REQUIRED')
        self.reader, self.host = reader, host

    def _history(self, original: ds.DeliverySendRequest) -> dict[str, Any]:
        require(self.host.enable_local_private_audit,
                'EXPLICIT_HOST_AUDIT_ENABLE_REQUIRED')
        require(type(original) is ds.DeliverySendRequest,
                'ORIGINAL_SIGNED_REQUEST_REQUIRED', 'invalid_input')
        require(st._code_sha() == st.ACTIVE_STATUS_CODE_SHA256 and
                ds._code_sha() == ds.ACTIVE_SEND_CODE_SHA256,
                'UPSTREAM_SEND_STATUS_CODE_REVISION_DRIFT')
        # No current EC224/225 permission is resurrected by a historical read.
        return self.reader._historical(original)

    def _marker(self, operation: str) -> None:
        with st.LocalStatusReadLedger(self.reader.sender.access.outbox_root) as ledger:
            ledger.verify_submit_marker(operation)

    def _journal(self, history: dict[str, Any], *, create: bool) -> PrivateAuditJournal:
        return PrivateAuditJournal(self.reader.sender.access.outbox_root,
                                   history['operation_id'],
                                   history['provider_target_binding_sha256'],
                                   self.host.hmac_secret, create=create)

    def readback(self, original: ds.DeliverySendRequest, *,
                 expected_head_hmac_sha256: str | None = None) -> dict[str, Any]:
        """Read local authenticated history ONLY; do not query Provider or send.

        The optional externally pinned head makes deletion/rollback detectable.
        Without an independent head, local chain integrity alone cannot prove
        that a same-UID actor has not removed an entire valid log tail.
        """
        operation = None
        try:
            require(expected_head_hmac_sha256 is None or
                    da.sha_string(expected_head_hmac_sha256),
                    'EXTERNAL_AUDIT_CHECKPOINT_INVALID', 'invalid_input')
            history = self._history(original)
            operation = history['operation_id']
            self._marker(operation)
            with self._journal(history, create=False) as log:
                entries = log.read(history)
                require(log.present, 'AUDIT_NOT_YET_RECORDED')
                info = _summarize(entries)
                if expected_head_hmac_sha256 is not None:
                    require(info['head'] == expected_head_hmac_sha256,
                            'AUDIT_EXTERNAL_CHECKPOINT_ROLLBACK_OR_MISMATCH', 'blocked')
            return _result('LOCAL_AUDIT_READBACK_NOT_CURRENT_DELIVERY_PROOF', 'partial',
                           operation_id=operation, historical=info['historical'],
                           records=info['count'], head=info['head'], integrity=True,
                           conflict=info['conflict'], incomplete=info['incomplete'],
                           last_provider=info['last_provider'])
        except (AuditDenied, st.StatusDenied, ds.SendDenied, da.AuthorizationDenied) as e:
            return _result(e.code, e.status, operation_id=operation)
        except Exception:
            return _result('AUDIT_READBACK_UNAVAILABLE', 'unavailable',
                           operation_id=operation)

    def retry_guard(self, original: ds.DeliverySendRequest) -> dict[str, Any]:
        """Idempotent refusal for an already attempted EC225 operation.

        A new approval/operation is NOT automatically safe to send either:
        separate independent no-duplicate proof and fresh new EC224/225
        authorization must be established outside this module. EC227 has no
        API that silently turns a denial into an HTTP POST.
        """
        existing = self.readback(original)
        if existing['status'] != 'partial':
            return existing
        return _result('ORIGINAL_APPROVAL_OPERATION_SPENT_NO_AUTOMATIC_RESEND',
                       'blocked', operation_id=existing['operation_id'],
                       historical=existing['last_historical_attested_state'],
                       records=existing['audit_event_count'],
                       head=existing['audit_head_hmac_sha256'],
                       integrity=existing['audit_chain_verified'],
                       conflict=existing['conflicting_historical_evidence'],
                       incomplete=existing['incomplete_prior_observation'],
                       last_provider=existing['last_provider_state'])

    def observe_and_record(self, request: st.DeliveryStatusRequest) -> dict[str, Any]:
        """Atomically reserve an audit event BEFORE one EC226 status-only read.

        Read grant is preverified before any journal mutation. The EC226 reader
        independently checks/consumes its own single-use nonce at query time.
        A crash after START leaves an explicit UNKNOWN and cannot authorize a
        resend; a NEW signed read nonce can later make a NEW status lookup.
        """
        operation = None
        network = False
        audit_written = False
        try:
            require(type(request) is st.DeliveryStatusRequest,
                    'SIGNED_STATUS_READ_REQUEST_REQUIRED', 'invalid_input')
            self.reader._access(request)
            history = self._history(request.original_send_request)
            operation = history['operation_id']
            now = _time()
            read_doc, read_sha = self.reader._read_grant(request.exact_read_grant,
                                                         history, now)
            nonce_sha = dp.sha(NONCE_DOMAIN, {
                'operation_id': operation,
                'read_nonce': read_doc['read_nonce'],
                'status_root': self.reader._root_pin,
            })
            self._marker(operation)
            with self._journal(history, create=True) as log:
                entries = log.read(history)
                require(len(entries) <= MAX_AUDIT_ENTRIES - 2,
                        'AUDIT_CAPACITY_EXHAUSTED_NO_NETWORK')
                require(not entries or now >= entries[-1]['entry']['recorded_at'],
                        'AUDIT_CLOCK_ROLLBACK_NO_NETWORK')
                require(not any(e['entry']['read_grant_sha256'] == read_sha or
                                e['entry']['read_nonce_sha256'] == nonce_sha
                                for e in entries),
                        'AUDIT_PREVIOUSLY_USED_READ_GRANT_OR_NONCE', 'blocked')
                self._marker(operation)  # pinned local outbox still present under lock
                entries = log.append(history, entries, kind='LOOKUP_STARTED',
                                     read_sha=read_sha, nonce_sha=nonce_sha,
                                     observed_at=now)
                audit_written = True
                # Even if this call fails, START is durable UNKNOWN; NEVER retry
                # original POST. The separately signed EC226 read nonce is still
                # consumed by EC226 itself, not by the audit.
                outcome = self.reader.observe_once(request)
                network = type(outcome) is dict and outcome.get('status_network_requested') is True
                permitted = (
                    type(outcome) is dict and outcome.get('schema') == st.SCHEMA and
                    outcome.get('status') == 'partial' and
                    outcome.get('operation_id') == operation and
                    outcome.get('read_grant_verified') is True and
                    outcome.get('submit_attempt_marker_verified') is True and
                    outcome.get('status_network_requested') is True and
                    outcome.get('provider_evidence_verified') is True and
                    outcome.get('resent') is False and
                    outcome.get('message_sent_by_status_read') is False and
                    outcome.get('published') is False and
                    type(outcome.get('effects')) is dict and
                    outcome['effects'].get('provider_submit_requested') is False and
                    outcome.get('delivery_state') in FINAL_STATES)
                provider = outcome['provider_state'] if permitted else None
                state = outcome['delivery_state'] if permitted else 'UNKNOWN_UNCONFIRMED'
                msg = outcome['provider_message_id_sha256'] if permitted else None
                inbox = outcome['inbox_evidence_verified'] if permitted else False
                if permitted:
                    # Classifications are checked against signed EC226 result.
                    # Inconsistent behavior cannot be written as success.
                    probe = {
                        'schema': ENTRY_SCHEMA, 'sequence': len(entries)+1,
                        'kind': 'LOOKUP_RESULT', 'operation_id': operation,
                        'provider_target_binding_sha256': history['provider_target_binding_sha256'],
                        'approver_exact_grant_sha256': history['approver_exact_grant_sha256'],
                        'payload_sha256': history['payload_sha256'],
                        'read_grant_sha256': read_sha, 'read_nonce_sha256': nonce_sha,
                        'recorded_at': max(now, _time()), 'delivery_state': state,
                        'provider_state': provider,
                        'provider_message_id_sha256': msg,
                        'provider_evidence_verified': True,
                        'inbox_evidence_verified': inbox,
                        'previous_hmac_sha256': entries[-1]['hmac_sha256'],
                    }
                    try:
                        log._validate_entry(probe, len(entries)+1,
                                            entries[-1]['hmac_sha256'], operation,
                                            history['provider_target_binding_sha256'],
                                            history['approver_exact_grant_sha256'],
                                            history['payload_sha256'])
                    except AuditDenied:
                        permitted = False
                entries = log.append(history, entries, kind='LOOKUP_RESULT',
                                     read_sha=read_sha, nonce_sha=nonce_sha,
                                     observed_at=max(now, _time()),
                                     delivery_state=state if permitted else 'UNKNOWN_UNCONFIRMED',
                                     provider_state=provider if permitted else None,
                                     provider_message_id_sha256=msg if permitted else None,
                                     provider_evidence_verified=permitted,
                                     inbox_evidence_verified=inbox if permitted else False)
                audit_written = True
                info = _summarize(entries)
                return _result('SIGNED_STATUS_RECONCILED_WITH_LOCAL_AUDIT'
                               if permitted and not info['conflict'] else
                               'UNKNOWN_OR_CONFLICT_NO_RESEND', 'partial',
                               operation_id=operation, state=info['delivery_state'],
                               historical=info['historical'],
                               records=info['count'], head=info['head'], integrity=True,
                               network=network, observed=bool(permitted and
                                                             not info['conflict']),
                               conflict=info['conflict'], incomplete=info['incomplete'],
                               last_provider=info['last_provider'],
                               audit_written=audit_written)
        except (AuditDenied, st.StatusDenied, ds.SendDenied, da.AuthorizationDenied) as exc:
            return _result(exc.code, exc.status, operation_id=operation,
                           network=network, audit_written=audit_written)
        except Exception:
            return _result('AUDIT_OR_REMOTE_STATUS_RECONCILIATION_FAILED',
                           'unavailable', operation_id=operation, network=network,
                           audit_written=audit_written)
