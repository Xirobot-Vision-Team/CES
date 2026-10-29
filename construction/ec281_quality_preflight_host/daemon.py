#!/usr/bin/env python3
"""EC281 private AF_UNIX QualityRun preflight server (never an executor).

After kernel peer authentication and two independent offline approvals, the
host supplies all repository/ticket/key data to the unchanged EC186 gate.
Host-local callbacks enforce the exact pinned decision at every EC186 stage.
No caller-supplied paths, keys, tickets, commands or allow_* booleans exist.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hmac
import os
from pathlib import Path
import socket
import socketserver
import stat

from ec279_finding_query_host.daemon import AnchoredClock, peer_uid
from ec279_finding_query_host import protocol as io
import quality_detect as detect
import quality_run_guard as guard
from . import protocol as p


def decode_request(raw: bytes) -> dict:
    p.need(raw.endswith(b'\n') and 1 < len(raw) <= p.MAX_RPC + 1,
           'EC281_REQUEST_LENGTH_OR_TERMINATOR_INVALID')
    req = io.parse(raw[:-1], p.MAX_RPC)
    p.need(set(req) == {'schema', 'nonce', 'grant'} and
           req.get('schema') == p.REQUEST_SCHEMA and
           type(req.get('nonce')) is str and
           io.HEX_NONCE.fullmatch(req['nonce']) is not None and
           type(req.get('grant')) is dict,
           'EC281_REQUEST_FIELDS_INVALID')
    return req


def perform_preflight(server: 'PreflightServer', pol: dict,
                      subject: dict) -> dict:
    # Never load sensitive material before authenticating the connecting UID
    # and the two valid issuer signatures in the request handler.
    pin, approval, lease, policy_key, broker_key = p.load_material(pol)
    repo_root = pol['repo_root']
    profile_id = subject['profile_id']
    pin_sha = detect._sha(detect.DOMAIN_PIN, pin)
    catalog = guard.catalog_entry(profile_id)
    p.need(catalog is not None and pin.get('repo_root') == repo_root and
           pin.get('schema') == detect.PIN_SCHEMA,
           'EC281_HOST_SOURCE_OR_PROFILE_INVALID', 'unavailable')
    profile_sha = catalog['profile_sha256']
    expected_approval_id = approval.get('ticket_id')
    expected_lease_id = lease.get('ticket_id')

    def live_pins() -> bool:
        # Backend calls this multiple times, including after the final grant.
        # Hot-swapping policy/private materials revokes this preflight.
        try:
            if server.clock.now() >= subject['expires_at_unix']:
                return False
            current = p.load_policy(server.policy_path, server.policy_sha)
            if current != pol:
                return False
            for name in p.POLICY_FILES:
                p.pinned_bytes(pol, name)
            return True
        except (p.HostError, io.HostError, OSError, ValueError):
            return False

    def allow_root(facts: dict) -> bool:
        return (live_pins() and type(facts) is dict and
                set(facts) == {'purpose', 'source_mode', 'repo_root'} and
                facts['purpose'] == 'QUALITYDETECT_OBSERVE_LOCAL_ROOT' and
                facts['source_mode'] == 'WorkingTree' and
                facts['repo_root'] == repo_root)

    allowed_stages = ('BEFORE_PROFILE', 'APPROVED_PROFILE',
                      'ISOLATION_RESERVED', 'FINALIZE')
    def allow_gate(facts: dict) -> bool:
        if not live_pins() or type(facts) is not dict:
            return False
        stage = facts.get('stage')
        if stage not in allowed_stages:
            return False
        expected = {
            'schema': guard.SCHEMA, 'operation': 'QUALITYRUN_CONFIGURE',
            'stage': stage, 'source_mode': 'WorkingTree',
            'repo_root': repo_root, 'source_pin_sha256': pin_sha,
            'profile_id': profile_id, 'profile_sha256': profile_sha,
        }
        if stage != 'BEFORE_PROFILE':
            expected['approval_ticket_id'] = expected_approval_id
        if stage in ('ISOLATION_RESERVED', 'FINALIZE'):
            expected['lease_ticket_id'] = expected_lease_id
        return facts == expected

    # Host controls the three opt-ins. EC186 still independently validates the
    # original HMAC approval and broker lease and observes directory identity.
    clock = lambda: datetime.fromtimestamp(server.clock.now(), tz=timezone.utc)
    gate = guard.QualityRunSafetyGate(policy_verification_key=policy_key,
                                      broker_verification_key=broker_key,
                                      clock=clock)
    result = gate.prepare(
        repo_root=repo_root, source_pin=pin, profile_id=profile_id,
        policy_ticket=approval, isolation_ticket=lease,
        allow_prepare=True, allow_profile_approval=True,
        allow_isolation_lease=True, authorize_root=allow_root,
        authorize_gate=allow_gate, ec185_observation=None)
    if not live_pins():
        raise p.HostError('EC281_PREFLIGHT_REVOKED_DURING_PREPARE', 'unavailable')
    if (type(result) is not dict or result.get('schema') != guard.SCHEMA or
        result.get('status') != 'partial' or result.get('exit_code') != 2 or
        result.get('proof', {}).get('overall_quality_pass_verified') is not False or
        result.get('plan', {}).get('has_executable_command') is not False or
        result.get('effects', {}).get('tests_executed') is not False or
        result.get('effects', {}).get('lease_consumed') is not False):
        raise p.HostError('EC281_BACKEND_EC186_PREPARE_DENIED', 'unavailable')
    return result


class PreflightHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(8.0)
        try:
            req = decode_request(self.rfile.readline(p.MAX_RPC + 2))
        except (OSError, ValueError, TimeoutError):
            return
        server: PreflightServer = self.server
        try:
            current = p.load_policy(server.policy_path, server.policy_sha)
            p.need(current == server.policy,
                   'EC281_POLICY_REPLACED', 'unavailable')
            uid = peer_uid(self.request)
            subject = p.validate_grant(req['grant'], current, uid=uid,
                                       now=server.clock.now(),
                                       policy_sha=server.policy_sha)
            result = perform_preflight(server, current, subject)
        except p.HostError as exc:
            attempted = exc.code in (
                'EC281_BACKEND_EC186_PREPARE_DENIED',
                'EC281_PREFLIGHT_REVOKED_DURING_PREPARE')
            result = p.denial(exc.code, exc.status,
                              backend_invoked=attempted)
        except Exception:
            # Unknown failure stage: do not invent whether gate was called.
            result = p.denial('EC281_PRIVATE_PREFLIGHT_HOST_UNAVAILABLE',
                              'unavailable', backend_invoked=None)
        try:
            reply = p.signed_reply(req, result, server.policy_sha,
                                   server.policy, server.signing_key,
                                   server.clock.now())
            raw = p.canonical(reply) + b'\n'
            if len(raw) > p.MAX_REPLY:
                reply = p.signed_reply(
                    req, p.denial('EC281_SIGNED_PLAN_TOO_LARGE', 'unavailable'),
                    server.policy_sha, server.policy, server.signing_key,
                    server.clock.now())
                raw = p.canonical(reply) + b'\n'
            self.wfile.write(raw)
            self.wfile.flush()
        except (BrokenPipeError, OSError, ValueError):
            return


class PreflightServer(socketserver.UnixStreamServer):
    allow_reuse_address = False
    request_queue_size = 8

    def __init__(self, *, path: str, policy_path: str, policy_sha: str,
                 private_key_file: str):
        p.need(hasattr(socket, 'AF_UNIX') and
               (hasattr(socket, 'SO_PEERCRED') or
                hasattr(socket.socket, 'getpeereid')),
               'EC281_KERNEL_PEER_UID_UNAVAILABLE', 'unavailable')
        p.need(type(path) is str and os.path.isabs(path) and len(path) < 100,
               'EC281_SOCKET_PATH_INVALID')
        try:
            parent = os.lstat(Path(path).parent)
        except OSError as exc:
            raise p.HostError('EC281_SOCKET_DIRECTORY_UNAVAILABLE',
                              'unavailable') from exc
        p.need(stat.S_ISDIR(parent.st_mode) and parent.st_mode & 0o002 == 0,
               'EC281_SOCKET_DIRECTORY_UNTRUSTED', 'unavailable')
        try:
            os.lstat(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise p.HostError('EC281_SOCKET_PATH_UNAVAILABLE',
                              'unavailable') from exc
        else:
            raise p.HostError('EC281_SOCKET_ALREADY_EXISTS', 'unavailable')

        self.policy_path = policy_path
        self.policy_sha = policy_sha
        self.policy = p.load_policy(policy_path, policy_sha)
        p.load_material(self.policy)
        self.signing_key = io.private_from_file(private_key_file)
        p.need(hmac.compare_digest(
            p.public_hex(self.signing_key),
            self.policy['server_public_hex']),
            'EC281_SERVER_SIGNER_NOT_PINNED', 'unavailable')
        self.clock = AnchoredClock()
        self._socket_inode = None
        try:
            super().__init__(path, PreflightHandler, bind_and_activate=True)
            os.chmod(path, 0o660)
            st = os.lstat(path)
            self._socket_inode = (st.st_dev, st.st_ino)
        except Exception:
            self.server_close()
            raise

    def server_close(self):
        super().server_close()
        if self._socket_inode is not None:
            try:
                st = os.lstat(self.server_address)
                if (stat.S_ISSOCK(st.st_mode) and
                        (st.st_dev, st.st_ino) == self._socket_inode):
                    os.unlink(self.server_address)
            except FileNotFoundError:
                pass
