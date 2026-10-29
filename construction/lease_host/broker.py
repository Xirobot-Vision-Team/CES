#!/usr/bin/env python3
"""EC253 host-owned EC186 HMAC approval + durable one-use lease for EC252.

This is an *opt-in, independent* Linux QualityRun endpoint. Only a trusted
operator may prepare the sealed source TAR, bind it to the EC186 WorkingTree
pin, issue two separately keyed tickets, install the fixed OCI image and own
the private lease ledger. A client supplies only a scope and fixed profile;
SO_PEERCRED supplies the kernel UID. No user-provided ticket, filename,
command, image or resource override is ever accepted.

An append-only fsync'd journal consumes the lease BEFORE any Podman create.
A best-effort forked watchdog survives a killed broker process and cleans by
random container name; a fresh broker must recover every incomplete journal
before serving. SIGKILL of the whole service cgroup, host loss and bad OCI
kernel isolation cannot be certified here. EC187's callback/telemetry protocol
is still NOT bridged and all results are partial/unverified, never CI PASS.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import sys
import time
import threading
from typing import Any, Callable

CONSTRUCTION = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CONSTRUCTION))
from finding_host import broker as fio
from quality_host import broker as private
from quality_run_host import broker as runner
import quality_run_guard as guard

POLICY_SCHEMA = 'ces.ec253.quality_run_lease_host_policy.v1'
REQUEST_SCHEMA = 'ces.ec253.quality_run_lease_host_request.v1'
RESPONSE_SCHEMA = 'ces.ec253.quality_run_lease_host_response.v1'
LEDGER_SCHEMA = 'ces.ec253.durable_lease_journal.v1'
MAX_POLICY = 65536
MAX_KEY = 4096
MAX_TICKET = guard.MAX_TICKET_BYTES
MAX_REQUEST = 2048
MAX_RESPONSE = 32768
MAX_LEDGER = 16384
MAX_LEDGERS = 4096
WATCH_SECONDS = (runner.MAX_SETUP_SECONDS + runner.WALL_SECONDS +
                 runner.MAX_SETUP_SECONDS + runner.MAX_CLEANUP_SECONDS + 12)
POLICY_ADDITIONS = {'authorized_source_pin_sha256', 'approval_ticket_path',
                    'isolation_ticket_path', 'approval_hmac_key_path',
                    'broker_hmac_key_path', 'ledger_root'}
POLICY_FIELDS = runner.POLICY_FIELDS | POLICY_ADDITIONS
REQUEST_FIELDS = runner.REQUEST_FIELDS
TICKET_APPROVAL_FIELDS = {'schema', 'ticket_id', 'profile_id', 'profile_sha256',
                          'source_pin_sha256', 'issued_at_utc', 'expires_at_utc',
                          'approved_purpose'}
TICKET_LEASE_FIELDS = {'schema', 'ticket_id', 'source_pin_sha256',
                       'profile_sha256', 'approval_receipt_sha256',
                       'image_sha256', 'controls', 'issued_at_utc',
                       'expires_at_utc'}
LEASE_FILE = re.compile(r'lease-[0-9a-f]{64}\.jsonl\Z')
CONTAINER_NAME = re.compile(r'ces-ec252-[0-9a-f]{24}\Z')
TERMINAL = frozenset({'closed', 'watchdog_cleaned', 'recovered'})
EVENTS = TERMINAL | {'reserved', 'cleanup_uncertain', 'created', 'start_armed', 'cgroup_bound'}
EXIT = runner.EXIT


class LeaseHostError(runner.HostRunError):
    pass


def need(ok: bool, code: str, status: str = 'unavailable') -> None:
    if not ok:
        raise LeaseHostError(code, status)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _parse(raw: bytes, bound: int, trusted: bool = True) -> dict[str, Any]:
    try:
        return fio._json(raw, bound)
    except fio.HostError as exc:
        raise LeaseHostError('LEASE_HOST_JSON_INVALID',
                             'unavailable' if trusted else 'invalid_input') from exc


def _base_policy(policy: dict[str, Any]) -> dict[str, Any]:
    return {k: (runner.POLICY_SCHEMA if k == 'schema' else policy[k])
            for k in runner.POLICY_FIELDS}


def _policy(path: str) -> tuple[dict[str, Any], str]:
    try:
        raw = private._private_bytes(path, MAX_POLICY)
    except private.QualityHostError as exc:
        raise LeaseHostError('LEASE_HOST_POLICY_PRIVATE_FILE_REQUIRED') from exc
    obj = _parse(raw, MAX_POLICY)
    need(set(obj) == POLICY_FIELDS and obj.get('schema') == POLICY_SCHEMA,
         'LEASE_HOST_POLICY_FIELDS')
    runner._validate_policy(_base_policy(obj))
    need(type(obj['authorized_source_pin_sha256']) is str and
         runner.SHA.fullmatch(obj['authorized_source_pin_sha256']) is not None,
         'LEASE_HOST_SOURCE_PIN_REQUIRED')
    paths = [obj[k] for k in (
        'approval_ticket_path', 'isolation_ticket_path',
        'approval_hmac_key_path', 'broker_hmac_key_path')]
    for p in paths:
        try:
            private._path(p)
        except private.QualityHostError as exc:
            raise LeaseHostError('LEASE_HOST_OPERATOR_FILE_PATH_INVALID') from exc
    need(len(set(paths + [obj['source_tar_path'], path])) == len(paths) + 2,
         'LEASE_HOST_POLICY_FILES_MUST_BE_DISTINCT')
    try:
        private._path(obj['ledger_root'])
    except private.QualityHostError as exc:
        raise LeaseHostError('LEASE_HOST_LEDGER_PATH_INVALID') from exc
    ledger_root = runner._private_dir(obj['ledger_root'])
    private_roots = (obj['scratch_root'], obj['runtime_home'],
                     obj['runtime_xdg_dir'])
    need(all(os.path.commonpath((ledger_root, other)) not in
                 (ledger_root, other) for other in private_roots) and
         not any(os.path.commonpath((ledger_root, p)) == ledger_root
                 for p in paths + [obj['source_tar_path'], path]),
         'LEASE_HOST_LEDGER_MUST_BE_SEPARATE')
    return obj, hashlib.sha256(raw).hexdigest()


def _key(path: str) -> bytes:
    try:
        raw = private._private_bytes(path, MAX_KEY)
    except private.QualityHostError as exc:
        raise LeaseHostError('LEASE_HOST_KEY_PRIVATE_FILE_REQUIRED') from exc
    need(32 <= len(raw) <= MAX_KEY, 'LEASE_HOST_KEY_LENGTH')
    return raw


def _request(raw: bytes) -> dict[str, Any]:
    req = _parse(raw, MAX_REQUEST, trusted=False)
    need(set(req) == REQUEST_FIELDS and req.get('schema') == REQUEST_SCHEMA and
         type(req.get('profile_id')) is str and
         type(req.get('scope_id')) is str,
         'LEASE_HOST_REQUEST_FIELDS', 'invalid_input')
    return req


def _as_runner_request(req: dict[str, Any]) -> dict[str, Any]:
    return {'schema': runner.REQUEST_SCHEMA, 'scope_id': req['scope_id'],
            'profile_id': req['profile_id']}


def _tickets(policy: dict[str, Any], profile_id: str) -> dict[str, Any]:
    """Verify BOTH original EC186 role-specific MACs, not just JSON fields.

    Host-owned pin-to-TAR association is an *operator declaration*, not an
    independently derived Git/worktree content or enterprise attestation.
    """
    try:
        approval_key = _key(policy['approval_hmac_key_path'])
        broker_key = _key(policy['broker_hmac_key_path'])
        need(not hmac.compare_digest(approval_key, broker_key),
             'LEASE_HOST_DISTINCT_HMAC_KEYS_REQUIRED')
        approval_raw = private._private_bytes(policy['approval_ticket_path'], MAX_TICKET)
        lease_raw = private._private_bytes(policy['isolation_ticket_path'], MAX_TICKET)
    except private.QualityHostError as exc:
        raise LeaseHostError('LEASE_HOST_PRIVATE_TICKET_REQUIRED') from exc
    now = guard._now(None)
    try:
        approval = guard._verify_ticket(
            _parse(approval_raw, MAX_TICKET), schema=guard.APPROVAL_SCHEMA,
            fields=TICKET_APPROVAL_FIELDS, key=approval_key,
            domain=guard.DOMAIN_APPROVAL, now=now,
            max_age=guard.MAX_APPROVAL_AGE,
            max_lifetime=guard.MAX_APPROVAL_LIFETIME)
        lease = guard._verify_ticket(
            _parse(lease_raw, MAX_TICKET), schema=guard.LEASE_SCHEMA,
            fields=TICKET_LEASE_FIELDS, key=broker_key,
            domain=guard.DOMAIN_LEASE, now=now,
            max_age=guard.MAX_LEASE_AGE,
            max_lifetime=guard.MAX_LEASE_LIFETIME)
    except guard.GateError as exc:
        raise LeaseHostError('LEASE_HOST_EC186_' + exc.code) from exc
    spec = guard.catalog_entry(profile_id)
    need(spec is not None and approval['profile_id'] == profile_id and
         approval['profile_sha256'] == spec['profile_sha256'] and
         approval['approved_purpose'] == spec['profile']['purpose'] and
         approval['source_pin_sha256'] == policy['authorized_source_pin_sha256'],
         'LEASE_HOST_APPROVAL_NOT_BOUND_TO_POLICY')
    approval_digest = guard._digest(guard.DOMAIN_RECEIPT, approval)
    need(lease['source_pin_sha256'] == policy['authorized_source_pin_sha256'] and
         lease['profile_sha256'] == spec['profile_sha256'] and
         lease['approval_receipt_sha256'] == approval_digest and
         lease['image_sha256'] == policy['image_id'][7:] and
         type(lease['controls']) is dict and
         set(lease['controls']) == set(guard.REQUIRED_CONTROLS) and
         all(type(lease['controls'][k]) is type(value) and
             lease['controls'][k] == value
             for k, value in guard.REQUIRED_CONTROLS.items()) and
         guard._time(lease['expires_at_utc']) <=
         guard._time(approval['expires_at_utc']),
         'LEASE_HOST_LEASE_NOT_BOUND_TO_APPROVAL_IMAGE_OR_CONTROLS')
    return {'approval': approval, 'lease': lease,
            'approval_receipt_sha256': approval_digest,
            'lease_receipt_sha256': guard._digest(guard.DOMAIN_RECEIPT, lease),
            'material_sha256': hashlib.sha256(
                approval_raw + b'\x00' + lease_raw + b'\x00' +
                approval_key + b'\x00' + broker_key).hexdigest()}


def _lease_filename(lease_id: str) -> str:
    digest = hashlib.sha256(b'CES-EC253-LEASE-ID-v1\x00' +
                            lease_id.encode('ascii')).hexdigest()
    return 'lease-' + digest + '.jsonl'


def _journal_path_ok(policy: dict[str, Any], stage: str, name: str) -> bool:
    return (type(stage) is str and
            os.path.dirname(stage) == policy['scratch_root'] and
            os.path.basename(stage).startswith('ec252-') and
            re.fullmatch(r'ec252-[a-z0-9_-]{6,40}', os.path.basename(stage)) is not None and
            type(name) is str and CONTAINER_NAME.fullmatch(name) is not None)


class Ledger:
    """One service-level flock, durable O_EXCL reservation, append-only facts.

    The lock is deliberately inherited by a forked watcher, so a newly
    launched broker cannot mistakenly recover a still-active prior run.
    """
    def __init__(self, policy: dict[str, Any], policy_sha: str):
        need(os.geteuid() != 0, 'LEASE_HOST_ROOT_USER_FORBIDDEN')
        self.policy = policy
        self.policy_sha = policy_sha
        root = runner._private_dir(policy['ledger_root'])
        self.dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY |
                             os.O_NOFOLLOW | os.O_CLOEXEC)
        self.lockfd = None
        try:
            fd = os.open('leader.lock', os.O_CREAT | os.O_RDWR |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.dirfd)
            self.lockfd = fd
            st = os.fstat(fd)
            need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
                 st.st_nlink == 1 and st.st_mode & 0o077 == 0,
                 'LEASE_HOST_LOCK_NOT_PRIVATE')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError) as exc:
                raise LeaseHostError('LEASE_HOST_ALREADY_RUNNING_OR_RECOVERING') from exc
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if self.lockfd is not None:
            os.close(self.lockfd)
            self.lockfd = None
        if self.dirfd is not None:
            os.close(self.dirfd)
            self.dirfd = None

    def __enter__(self) -> Ledger:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _read(self, name: str) -> list[dict[str, Any]]:
        need(LEASE_FILE.fullmatch(name) is not None, 'LEASE_HOST_LEDGER_FILENAME')
        fd = None
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                         os.O_CLOEXEC, dir_fd=self.dirfd)
            fcntl.flock(fd, fcntl.LOCK_SH)
            raw = private._private_bytes(
                os.path.join(self.policy['ledger_root'], name), MAX_LEDGER)
        except OSError as exc:
            raise LeaseHostError('LEASE_HOST_LEDGER_READ_FAILED') from exc
        finally:
            if fd is not None:
                os.close(fd)
        return self._decode(raw)

    def _decode(self, raw: bytes) -> list[dict[str, Any]]:
        need(raw.endswith(b'\n') and len(raw.splitlines()) <= 16,
             'LEASE_HOST_LEDGER_TRUNCATED_OR_OVERSIZED')
        events = [_parse(line, 4096) for line in raw.splitlines()]
        original = {'schema', 'event', 'policy_sha256', 'lease_receipt_sha256',
                    'container_name', 'stage_parent', 'source_tar_sha256'}
        first_keys = set(events[0]) if events else set()
        valid_headers = (original, original | {'lease_label_sha256'},
                         original | {'lease_label_sha256', 'cgroup_required'})
        need(bool(events) and first_keys in valid_headers and
             events[0]['schema'] == LEDGER_SCHEMA and
             events[0]['event'] == 'reserved' and
             _journal_path_ok(self.policy, events[0]['stage_parent'],
                              events[0]['container_name']) and
             all(type(events[0][k]) is str and runner.SHA.fullmatch(events[0][k])
                 for k in ('policy_sha256', 'lease_receipt_sha256', 'source_tar_sha256')),
             'LEASE_HOST_LEDGER_FIRST_EVENT_INVALID')
        if 'lease_label_sha256' in events[0]:
            need(events[0]['lease_label_sha256'] ==
                 events[0]['lease_receipt_sha256'],
                 'LEASE_HOST_LEDGER_BINDING_MISMATCH')
        if 'cgroup_required' in events[0]:
            need(events[0]['cgroup_required'] is True,
                 'LEASE_HOST_CGROUP_MODE_INVALID')
        created_seen = armed_seen = bound_seen = False
        for index, evt in enumerate(events[1:], start=1):
            kind = evt.get('event')
            if kind == 'created':
                need('lease_label_sha256' in events[0] and index == 1 and
                     set(evt) == {'event', 'container_id'} and
                     type(evt['container_id']) is str and
                     runner.SHA.fullmatch(evt['container_id']) is not None,
                     'LEASE_HOST_LEDGER_CREATED_INVALID')
                created_seen = True
            elif kind == 'start_armed':
                need(events[0].get('cgroup_required') is True and
                     created_seen and not armed_seen and index == 2 and
                     set(evt) == {'event'}, 'LEASE_HOST_START_ARM_INVALID')
                armed_seen = True
            elif kind == 'cgroup_bound':
                need(armed_seen and not bound_seen and created_seen and
                     events[0].get('cgroup_required') is True,
                     'LEASE_HOST_CGROUP_EVENT_ORDER_INVALID')
                from cgroup_reaper import supervisor
                supervisor._recorded(events[1]['container_id'], evt)
                bound_seen = True
            else:
                need(set(evt) == {'event'} and
                     kind in EVENTS - {'reserved', 'created', 'start_armed',
                                       'cgroup_bound'},
                     'LEASE_HOST_LEDGER_FOLLOWUP_INVALID')
        # An uncertain cleanup is still pending; after a terminal event no
        # subsequent write may reopen the lease, including cgroup facts.
        for i in range(1, len(events)):
            need(events[i - 1]['event'] not in TERMINAL,
                 'LEASE_HOST_LEDGER_REOPEN_INVALID')
        return events

    def _append(self, name: str, event: dict[str, Any]) -> None:
        kind = event.get('event')
        created = kind == 'created'
        arm = kind == 'start_armed'
        cgroup = kind == 'cgroup_bound'
        if created:
            valid_event = (set(event) == {'event', 'container_id'} and
                           type(event.get('container_id')) is str and
                           runner.SHA.fullmatch(event['container_id']) is not None)
        elif cgroup:
            valid_event = set(event) == {'event', 'boot_id', 'cgroup_path',
                                         'cgroup_dev', 'cgroup_ino',
                                         'pid_starttime'}
        else:
            valid_event = (set(event) == {'event'} and
                           kind in EVENTS - {'reserved', 'created', 'cgroup_bound'})
        need(LEASE_FILE.fullmatch(name) is not None and valid_event,
             'LEASE_HOST_LEDGER_EVENT_INVALID')
        raw = _canonical(event) + b'\n'
        need(len(raw) < 4096, 'LEASE_HOST_LEDGER_EVENT_TOO_LARGE')
        fd = None
        try:
            fd = os.open(name, os.O_RDWR | os.O_APPEND |
                         os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.dirfd)
            fcntl.flock(fd, fcntl.LOCK_EX)
            st = os.fstat(fd)
            current = os.stat(name, dir_fd=self.dirfd, follow_symlinks=False)
            need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
                 st.st_nlink == 1 and st.st_mode & 0o077 == 0 and
                 (st.st_dev, st.st_ino) == (current.st_dev, current.st_ino) and
                 st.st_size + len(raw) <= MAX_LEDGER,
                 'LEASE_HOST_LEDGER_FILE_UNSAFE')
            os.lseek(fd, 0, os.SEEK_SET)
            events = self._decode(os.read(fd, MAX_LEDGER + 1))
            if events[-1]['event'] in TERMINAL:
                need(kind not in ('created', 'start_armed', 'cgroup_bound'),
                     'LEASE_HOST_FACT_AFTER_TERMINAL')
                return
            if created:
                need(len(events) == 1 and 'lease_label_sha256' in events[0],
                     'LEASE_HOST_CREATED_REQUIRES_RESERVED_BINDING')
            if arm:
                need(events[0].get('cgroup_required') is True and
                     len(events) == 2 and events[1]['event'] == 'created',
                     'LEASE_HOST_START_ARM_ORDER_INVALID')
            if cgroup:
                need(events[0].get('cgroup_required') is True and
                     len(events) >= 3 and events[1]['event'] == 'created' and
                     events[2]['event'] == 'start_armed',
                     'LEASE_HOST_CGROUP_NOT_ARMED')
                from cgroup_reaper import supervisor
                supervisor._recorded(events[1]['container_id'], event)
                prior = [v for v in events if v['event'] == 'cgroup_bound']
                if prior:
                    need(prior == [event], 'LEASE_HOST_CGROUP_REBIND_FORBIDDEN')
                    return
            need(len(events) < 16, 'LEASE_HOST_LEDGER_EVENT_LIMIT')
            written = os.write(fd, raw)  # O_APPEND, under exclusive flock
            need(written == len(raw), 'LEASE_HOST_LEDGER_PARTIAL_WRITE')
            os.fsync(fd)
        except OSError as exc:
            raise LeaseHostError('LEASE_HOST_LEDGER_WRITE_FAILED') from exc
        finally:
            if fd is not None:
                os.close(fd)

    def used(self, name: str) -> bool:
        try:
            os.stat(name, dir_fd=self.dirfd, follow_symlinks=False)
            return True  # a consumed reservation is NEVER removed/reused
        except FileNotFoundError:
            return False

    def reserve(self, name: str, lease_digest: str,
                container_name: str, stage: str,
                *, binding_sha256: str | None = None,
                cgroup_required: bool = False) -> None:
        need(type(cgroup_required) is bool and
             (not cgroup_required or binding_sha256 is not None),
             'LEASE_HOST_CGROUP_MODE_REQUIRES_SIGNED_BINDING')
        need(_journal_path_ok(self.policy, stage, container_name),
             'LEASE_HOST_RESERVED_CONTAINER_INVALID')
        need(LEASE_FILE.fullmatch(name) is not None and
             not self.used(name), 'LEASE_HOST_LEASE_ALREADY_CONSUMED',
             'permission_denied')
        need(len(os.listdir(self.policy['ledger_root'])) < MAX_LEDGERS + 1,
             'LEASE_HOST_LEDGER_CAPACITY_REACHED')
        need(type(lease_digest) is str and
             runner.SHA.fullmatch(lease_digest) is not None and
             (binding_sha256 is None or binding_sha256 == lease_digest),
             'LEASE_HOST_BINDING_DIGEST_INVALID')
        evt = {'schema': LEDGER_SCHEMA, 'event': 'reserved',
               'policy_sha256': self.policy_sha,
               'lease_receipt_sha256': lease_digest,
               'container_name': container_name, 'stage_parent': stage,
               'source_tar_sha256': self.policy['expected_source_tar_sha256']}
        if binding_sha256 is not None:
            evt['lease_label_sha256'] = binding_sha256
        if cgroup_required:
            evt['cgroup_required'] = True
        fd = None
        try:
            fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.dirfd)
            data = _canonical(evt) + b'\n'
            need(os.write(fd, data) == len(data), 'LEASE_HOST_LEDGER_PARTIAL_WRITE')
            os.fsync(fd)
            os.fsync(self.dirfd)  # O_EXCL reservation survives an ordinary crash
        except FileExistsError as exc:
            raise LeaseHostError('LEASE_HOST_LEASE_ALREADY_CONSUMED',
                                 'permission_denied') from exc
        except OSError as exc:
            raise LeaseHostError('LEASE_HOST_LEDGER_RESERVE_FAILED') from exc
        finally:
            if fd is not None:
                os.close(fd)

    def bind(self, name: str, container_id: str) -> None:
        need(type(container_id) is str and runner.SHA.fullmatch(container_id)
             is not None, 'LEASE_HOST_CREATED_ID_INVALID')
        self._append(name, {'event': 'created', 'container_id': container_id})
        # A racing watchdog must not have made a terminal cleanup statement.
        need(self._read(name)[-1] == {'event': 'created',
                                     'container_id': container_id},
             'LEASE_HOST_CREATED_NOT_DURABLE')

    def arm_start(self, name: str) -> None:
        """Fsync potential OCI start before invoking Podman start."""
        self._append(name, {'event': 'start_armed'})
        need(self._read(name)[-1] == {'event': 'start_armed'},
             'LEASE_HOST_START_NOT_DURABLE')

    def bind_cgroup(self, name: str, binding: Any) -> None:
        """One immutable kernel cgroup binding per consumed signed lease."""
        from cgroup_reaper import supervisor
        need(isinstance(binding, supervisor.Binding),
             'LEASE_HOST_CGROUP_BINDING_TYPE')
        event = binding.journal_event()
        self._append(name, event)
        need(event in self._read(name)[1:],
             'LEASE_HOST_CGROUP_NOT_DURABLE')

    def cgroup_record(self, name: str) -> dict[str, Any] | None:
        records = [x for x in self._read(name)[1:]
                   if x['event'] == 'cgroup_bound']
        need(len(records) <= 1, 'LEASE_HOST_CGROUP_REBIND_FORBIDDEN')
        return records[0] if records else None

    def finish(self, name: str, event: str) -> None:
        need(event in EVENTS - {'reserved', 'created', 'start_armed',
                                'cgroup_bound'}, 'LEASE_HOST_EVENT_INVALID')
        self._append(name, {'event': event})

    def _cleanup_record(self, filename: str, kind: str) -> None:
        events = self._read(filename)
        initial = events[0]
        if events[-1]['event'] in TERMINAL:
            return
        need(initial['policy_sha256'] == self.policy_sha and
             initial['source_tar_sha256'] == self.policy['expected_source_tar_sha256'],
             'LEASE_HOST_RECOVERY_POLICY_CHANGED_MANUAL_REQUIRED')
        runner._runtime_binary(_base_policy(self.policy))
        if 'lease_label_sha256' in initial:
            from oci_identity import binding
            bound = [evt['container_id'] for evt in events[1:]
                     if evt['event'] == 'created']
            # Discover by durable lease marker, remove by full verified ID.
            # A crash after Podman create but before the ID journal append is
            # covered by the immutable label present from create-time.
            if initial.get('cgroup_required') is True:
                from cgroup_reaper import supervisor
                supervisor.reap_before_remove(
                    _base_policy(self.policy), initial['lease_label_sha256'],
                    initial['container_name'], bound[0] if bound else None,
                    recorded=self.cgroup_record(filename),
                    on_bound=lambda proof: self.bind_cgroup(filename, proof))
            safe = binding.verified_cleanup(
                _base_policy(self.policy), initial['lease_label_sha256'],
                initial['container_name'], bound[0] if bound else None)
        else:
            # Pre-EC255 journals remain readable. They have no immutable
            # label, so the original conservative name cleanup is preserved.
            safe = runner._cleanup(_base_policy(self.policy),
                                   initial['container_name'])
        need(safe, 'LEASE_HOST_RECOVERY_CONTAINER_UNCONFIRMED')
        stage = initial['stage_parent']
        if os.path.lexists(stage):
            need(os.path.isdir(stage) and not os.path.islink(stage) and
                 os.lstat(stage).st_uid == os.geteuid(),
                 'LEASE_HOST_RECOVERY_STAGE_UNSAFE')
            try:
                runner._remove_private_stage(stage)
            except (OSError, runner.HostRunError) as exc:
                raise LeaseHostError('LEASE_HOST_RECOVERY_STAGE_UNCONFIRMED') from exc
        self.finish(filename, kind)

    def recover(self) -> int:
        names = os.listdir(self.policy['ledger_root'])
        journals = sorted(n for n in names if n != 'leader.lock')
        need(len(journals) <= MAX_LEDGERS and
             all(LEASE_FILE.fullmatch(n) is not None for n in journals),
             'LEASE_HOST_UNKNOWN_OR_TOO_MANY_LEDGER_FILES')
        count = 0
        for name in journals:
            if self._read(name)[-1]['event'] not in TERMINAL:
                self._cleanup_record(name, 'recovered')
                count += 1
        return count

    def safe(self) -> bool:
        names = os.listdir(self.policy['ledger_root'])
        return (len(names) <= MAX_LEDGERS + 1 and
                all(n == 'leader.lock' or (LEASE_FILE.fullmatch(n) is not None and
                    self._read(n)[-1]['event'] in TERMINAL)
                    for n in names))


def _recheck(policy_path: str, expected: dict[str, Any], expected_sha: str,
             req: dict[str, Any], uid: int, material_sha: str) -> None:
    fresh, digest = _policy(policy_path)
    need(digest == expected_sha and fresh == expected,
         'LEASE_HOST_POLICY_CHANGED_OR_REVOKED')
    runner._authorize(_as_runner_request(req), _base_policy(fresh), uid)
    need(_tickets(fresh, req['profile_id'])['material_sha256'] == material_sha,
         'LEASE_HOST_TICKETS_OR_KEYS_REVOKED')


def _watchdog(ledger: Ledger, filename: str, policy: dict[str, Any],
              parent_pid: int, deadline: float) -> None:
    """Fork child survives parent-only crashes, not system-wide/cgroup kills.

    It holds the inherited service flock until confirming cleanup, avoiding
    concurrent broker recovery while the preceding container may still run.
    """
    try:
        os.setsid()
    except OSError:
        pass
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, signal.SIG_IGN)
    # Drop inherited listener, client sockets and other FDs. Keep only the
    # private ledger dirfd and leader flock. Never inherit a client channel.
    keep_lock = os.dup(ledger.lockfd)
    keep_dir = os.dup(ledger.dirfd)
    os.dup2(keep_lock, 3)
    os.dup2(keep_dir, 4)
    for fd in {keep_lock, keep_dir} - {3, 4}:
        os.close(fd)
    os.closerange(5, 65536)
    ledger.lockfd, ledger.dirfd = 3, 4
    try:
        while os.getppid() == parent_pid and time.monotonic() < deadline:
            if ledger._read(filename)[-1]['event'] in TERMINAL:
                return
            time.sleep(0.25)
        if ledger._read(filename)[-1]['event'] not in TERMINAL:
            try:
                ledger._cleanup_record(filename, 'watchdog_cleaned')
            except Exception:
                try:
                    ledger.finish(filename, 'cleanup_uncertain')
                except Exception:
                    pass
    except Exception:
        pass  # journal remains pending, a future broker must recover or refuse


def _spawn_watchdog(ledger: Ledger, filename: str,
                    policy: dict[str, Any],
                    *, deadline: float | None = None) -> int:
    need(threading.current_thread() is threading.main_thread() and
         threading.active_count() == 1,
         'LEASE_HOST_FORK_REQUIRES_SINGLE_THREAD_SERVICE')
    parent = os.getpid()
    deadline = deadline if deadline is not None else time.monotonic() + WATCH_SECONDS
    need(type(deadline) is float and time.monotonic() < deadline <=
         time.monotonic() + WATCH_SECONDS, 'LEASE_HOST_WATCHDOG_DEADLINE_INVALID')
    try:
        child = os.fork()
    except OSError as exc:
        raise LeaseHostError('LEASE_HOST_WATCHDOG_FORK_FAILED') from exc
    if child == 0:
        try:
            _watchdog(ledger, filename, policy, parent, deadline)
        finally:
            os._exit(0)
    return child


def _join_watchdog(pid: int | None) -> bool:
    if pid is None:
        return False
    until = time.monotonic() + 2
    while time.monotonic() < until:
        try:
            found, _ = os.waitpid(pid, os.WNOHANG)
            if found == pid:
                return True
        except ChildProcessError:
            return True
        time.sleep(0.05)
    return False


def _reply(status: str, reason: str, *, result: dict[str, Any] | None = None,
           peer: bool = False, policy: bool = False, tickets: bool = False,
           consumed: bool = False, cleanup: bool = False) -> dict[str, Any]:
    return {'schema': RESPONSE_SCHEMA, 'status': status,
            'exit_code': EXIT[status], 'reason_code': reason,
            'kernel_peer_uid_checked': peer, 'scope_policy_checked': policy,
            'ec186_signed_tickets_verified': tickets,
            'durable_one_use_lease_reserved': consumed,
            'container_cleanup_confirmed': cleanup,
            'operator_source_pin_to_tar_binding_only': True,
            'enterprise_actor_authenticated': False,
            'independent_git_source_provenance_verified': False,
            'kernel_oci_security_independently_attested': False,
            'ci_run_independently_verified': False,
            'overall_quality_pass_verified': False,
            'ec187_host_callback_protocol_implemented': False,
            'original_router_host_required_unlocked': False,
            'business_repository_written': False, 'result': result}


def execute(raw: bytes, policy_path: str, peer_uid: int, ledger: Ledger,
            *, caller: socket.socket | None = None,
            on_session_reserved: Callable[[str, str], None] | None = None,
            on_output: Callable[[str, bytes], None] | None = None,
            on_start_invoked: Callable[[int], None] | None = None,
            on_container_created: Callable[[str, str], None] | None = None,
            watchdog_deadline: float | None = None,
            require_cgroup: bool = False,
            on_before_cgroup_cleanup: Callable[[str, str | None,
                                                dict[str, Any] | None], None] | None = None
            ) -> dict[str, Any]:
    policy_ok = tickets_ok = consumed = cleaned = False
    final_meter_failed = False
    try:
        fio._linux()
        need(os.geteuid() != 0, 'LEASE_HOST_NONROOT_REQUIRED')
        need(isinstance(ledger, Ledger) and ledger.lockfd is not None,
             'LEASE_HOST_EXCLUSIVE_LEDGER_REQUIRED')
        req = _request(raw)
        policy, policy_sha = _policy(policy_path)
        need(policy_sha == ledger.policy_sha and policy == ledger.policy,
             'LEASE_HOST_SERVICE_POLICY_CHANGED')
        grant = runner._authorize(_as_runner_request(req), _base_policy(policy), peer_uid)
        policy_ok = True
        auth = _tickets(policy, req['profile_id'])
        tickets_ok = True
        lease_name = _lease_filename(auth['lease']['ticket_id'])
        need(not ledger.used(lease_name), 'LEASE_HOST_LEASE_ALREADY_CONSUMED',
             'permission_denied')
        source = runner._source_archive(_base_policy(policy))
        material = auth['material_sha256']
        _recheck(policy_path, policy, policy_sha, req, peer_uid, material)
        child: int | None = None

        def reserved(name: str, stage: str) -> None:
            nonlocal consumed, child
            _recheck(policy_path, policy, policy_sha, req, peer_uid, material)
            runner._source_archive(_base_policy(policy))  # exact pin again
            need(not ledger.used(lease_name), 'LEASE_HOST_LEASE_ALREADY_CONSUMED',
                 'permission_denied')
            ledger.reserve(lease_name, auth['lease_receipt_sha256'], name, stage,
                           binding_sha256=auth['lease_receipt_sha256'],
                           cgroup_required=require_cgroup)
            consumed = True  # cannot roll back, including failed startup
            if watchdog_deadline is None:
                child = _spawn_watchdog(ledger, lease_name, policy)
            else:
                child = _spawn_watchdog(ledger, lease_name, policy,
                                        deadline=watchdog_deadline)
            if on_session_reserved is not None:
                try:
                    on_session_reserved(name, stage)
                except Exception as exc:
                    # No OCI create has occurred yet: recover and retain the
                    # one-use journal, never strand a staged source on IPC loss.
                    ledger._cleanup_record(lease_name, 'recovered')
                    raise LeaseHostError('LEASE_HOST_SESSION_NOTIFICATION_FAILED') from exc

        def created(name: str, container_id: str) -> None:
            need(consumed and ledger._read(lease_name)[0]['container_name'] == name,
                 'LEASE_HOST_CREATED_UNEXPECTED_NAME')
            ledger.bind(lease_name, container_id)
            if on_container_created is not None:
                on_container_created(name, container_id)

        def arm_start(name: str, container_id: str) -> None:
            if require_cgroup:
                need(consumed and container_id and
                     ledger._read(lease_name)[0]['container_name'] == name,
                     'LEASE_HOST_CGROUP_START_UNBOUND')
                ledger.arm_start(lease_name)

        def force_tree_reap(name: str, container_id: str | None) -> None:
            nonlocal final_meter_failed
            if require_cgroup:
                from cgroup_reaper import supervisor
                record = ledger.cgroup_record(lease_name)
                if on_before_cgroup_cleanup is not None:
                    # EC257 captures a final kernel resource watermark while
                    # the recorded cgroup still exists. Telemetry failure
                    # MUST NOT bypass the actual cgroup.kill and ID removal.
                    try:
                        on_before_cgroup_cleanup(name, container_id, record)
                    except Exception:
                        final_meter_failed = True
                supervisor.reap_before_remove(
                    _base_policy(policy), auth['lease_receipt_sha256'],
                    name, container_id, recorded=record,
                    on_bound=lambda proof: ledger.bind_cgroup(lease_name, proof))

        def closed(name: str, stage: str, done: bool) -> None:
            nonlocal cleaned
            if done:
                ledger.finish(lease_name, 'closed')
                cleaned = True
            else:
                ledger.finish(lease_name, 'cleanup_uncertain')
            need(_join_watchdog(child), 'LEASE_HOST_WATCHDOG_EXIT_UNCONFIRMED')

        result = runner._run_container(_base_policy(policy), req['profile_id'],
            source, recheck=lambda: _recheck(
                policy_path, policy, policy_sha, req, peer_uid, material),
            caller=caller, on_reserved=reserved, on_closed=closed,
            on_output=on_output, on_started=on_start_invoked,
            lease_label_sha256=auth['lease_receipt_sha256'],
            on_created=created,
            on_before_start=arm_start if require_cgroup else None,
            on_before_cleanup=force_tree_reap if require_cgroup else None)
        _recheck(policy_path, policy, policy_sha, req, peer_uid, material)
        need(runner._source_archive(_base_policy(policy)) == source,
             'LEASE_HOST_SOURCE_CHANGED_DURING_RUN')
        need(consumed and cleaned and ledger._read(lease_name)[-1]['event'] in TERMINAL,
             'LEASE_HOST_UNCONFIRMED_RUN_COMPLETION')
        # Cleanup has already happened, but a claimed successful run cannot
        # omit EC257's trusted final resource measurement.
        need(not final_meter_failed, 'LEASE_HOST_FINAL_KERNEL_SAMPLE_UNAVAILABLE')
        if not grant['allow_output_text']:
            result['captured_stdout'] = None
            result['captured_stderr'] = None
        result['ec186_approval_receipt_sha256'] = auth['approval_receipt_sha256']
        result['ec186_lease_receipt_sha256'] = auth['lease_receipt_sha256']
        result['authorized_source_pin_sha256_host_declared'] = (
            policy['authorized_source_pin_sha256'])
        result['durable_lease_consumed_once'] = True
        result['operator_source_tar_binding_not_git_attested'] = True
        return _reply('partial', 'LEASE_HOST_LOCAL_CONTAINER_EXIT_REPORTED',
                      result=result, peer=True, policy=True, tickets=True,
                      consumed=True, cleanup=True)
    except runner.HostRunError as exc:
        return _reply(exc.status, exc.code, peer=True, policy=policy_ok,
                      tickets=tickets_ok, consumed=consumed, cleanup=cleaned)
    except (OSError, ValueError, TypeError, RuntimeError, KeyError, OverflowError,
            MemoryError, RecursionError, UnicodeError):
        return _reply('unavailable', 'LEASE_HOST_OPERATION_UNAVAILABLE', peer=True,
                      policy=policy_ok, tickets=tickets_ok,
                      consumed=consumed, cleanup=cleaned)


def _wire(reply: dict[str, Any]) -> bytes:
    try:
        return fio._wire(reply, limit=MAX_RESPONSE)
    except fio.HostError:
        return fio._wire(_reply('unavailable', 'LEASE_HOST_REPLY_TOO_LARGE'),
                         limit=MAX_RESPONSE)


def serve(policy_path: str, socket_path: str, *, max_requests: int = 1,
          accept_timeout: float = 60.0) -> None:
    fio._linux()
    need(os.geteuid() != 0, 'LEASE_HOST_NONROOT_REQUIRED')
    need(type(max_requests) is int and 1 <= max_requests <= runner.MAX_REQUESTS and
         type(accept_timeout) in (float, int) and 1 <= accept_timeout <= 300,
         'LEASE_HOST_SERVE_ARGS_INVALID')
    policy, digest = _policy(policy_path)
    runner._source_archive(_base_policy(policy))
    runner._private_dir(policy['scratch_root'])
    target = fio._private_parent(socket_path, policy=False)
    need(len(os.fsencode(str(target))) < 100, 'LEASE_HOST_SOCKET_TOO_LONG')
    try:
        os.lstat(target)
    except FileNotFoundError:
        pass
    else:
        raise LeaseHostError('LEASE_HOST_SOCKET_EXISTS')
    with Ledger(policy, digest) as ledger:
        ledger.recover()  # NO requests until each unknown container is absent
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        created = None
        try:
            prior = os.umask(0o117)
            try:
                listener.bind(str(target))
            finally:
                os.umask(prior)
            st = os.lstat(target)
            created = (st.st_dev, st.st_ino)
            need(stat.S_ISSOCK(st.st_mode) and st.st_uid == os.geteuid() and
                 st.st_mode & 0o007 == 0, 'LEASE_HOST_SOCKET_UNSAFE')
            listener.listen(4)
            listener.settimeout(accept_timeout)
            for _ in range(max_requests):
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    break
                with conn:
                    conn.settimeout(5)
                    try:
                        uid = fio._uid_from_peer(conn)
                        raw = fio._receive(conn, MAX_REQUEST)
                        reply = execute(raw, policy_path, uid, ledger, caller=conn)
                    except fio.HostError as exc:
                        reply = _reply(exc.status, exc.code)
                    except (runner.HostRunError, OSError, socket.timeout):
                        reply = _reply('unavailable', 'LEASE_HOST_SOCKET_ERROR')
                    try:
                        conn.sendall(_wire(reply))
                    except OSError:
                        pass
                # On an unresolved cleanup, stop accepting further sessions.
                need(ledger.safe(), 'LEASE_HOST_UNRESOLVED_LEDGER_STOP_SERVICE')
        finally:
            listener.close()
            if created:
                try:
                    st = os.lstat(target)
                    if stat.S_ISSOCK(st.st_mode) and (st.st_dev, st.st_ino) == created:
                        os.unlink(target)
                except FileNotFoundError:
                    pass


def request(socket_path: str, request_path: str, expected_host_uid: int
            ) -> dict[str, Any]:
    fio._linux()
    need(type(expected_host_uid) is int and 0 <= expected_host_uid <= runner.UID_MAX,
         'LEASE_HOST_EXPECTED_UID_REQUIRED', 'invalid_input')
    with open(request_path, 'rb') as fh:
        obj = _request(fh.read(MAX_REQUEST + 1))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(WATCH_SECONDS + 4 * runner.MAX_SETUP_SECONDS +
                        3 * runner.MAX_CLEANUP_SECONDS + 10)
        conn.connect(socket_path)
        need(fio._uid_from_peer(conn) == expected_host_uid,
             'LEASE_HOST_SERVICE_UID_MISMATCH', 'permission_denied')
        conn.sendall(fio._wire(obj, limit=MAX_REQUEST))
        reply = _parse(fio._receive(conn, MAX_RESPONSE), MAX_RESPONSE)
    base = {'schema', 'status', 'exit_code', 'reason_code', 'result'}
    booleans = set(_reply('partial', 'TEST')) - base
    need(set(reply) == base | booleans and reply.get('schema') == RESPONSE_SCHEMA and
         reply.get('status') in EXIT and type(reply.get('exit_code')) is int and
         reply['exit_code'] == EXIT[reply['status']] and
         type(reply.get('reason_code')) is str and
         all(type(reply[k]) is bool for k in booleans) and
         all(reply[k] is False for k in (
             'enterprise_actor_authenticated',
             'independent_git_source_provenance_verified',
             'kernel_oci_security_independently_attested',
             'ci_run_independently_verified', 'overall_quality_pass_verified',
             'ec187_host_callback_protocol_implemented',
             'original_router_host_required_unlocked',
             'business_repository_written')) and
         (reply['result'] is None or type(reply['result']) is dict),
         'LEASE_HOST_RESPONSE_INVALID')
    return reply


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC253 Linux one-use lease QualityRun host')
    sub = parser.add_subparsers(dest='command', required=True)
    server = sub.add_parser('serve', help='operator-owned HMAC lease/OCI host')
    server.add_argument('--policy', required=True)
    server.add_argument('--socket', required=True)
    server.add_argument('--max-requests', type=int, default=1)
    server.add_argument('--accept-timeout', type=float, default=60.0)
    client = sub.add_parser('request', help='send fixed profile and scope only')
    client.add_argument('--socket', required=True)
    client.add_argument('--request-file', required=True)
    client.add_argument('--expect-host-uid', required=True, type=int)
    recovery = sub.add_parser('recover', help='exclusive, fail-closed journal recovery')
    recovery.add_argument('--policy', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'serve':
            serve(args.policy, args.socket, max_requests=args.max_requests,
                  accept_timeout=args.accept_timeout)
            return 0
        if args.command == 'recover':
            policy, sha = _policy(args.policy)
            with Ledger(policy, sha) as ledger:
                result = {'schema': 'ces.ec253.recovery.v1',
                          'recovered_journals': ledger.recover(),
                          'remaining_unresolved': not ledger.safe(),
                          'quality_pass_verified': False}
            print(json.dumps(result, sort_keys=True))
            return 0
        result = request(args.socket, args.request_file, args.expect_host_uid)
    except runner.HostRunError as exc:
        result = _reply(exc.status, exc.code)
    except (OSError, socket.timeout):
        result = _reply('unavailable', 'LEASE_HOST_COMMAND_IO_UNAVAILABLE')
    print(_wire(result).decode('ascii').rstrip('\n'))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
