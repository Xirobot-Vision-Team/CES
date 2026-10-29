#!/usr/bin/env python3
"""EC252: operator-pinned, opt-in Linux container QualityRun endpoint.

An independently privileged operator owns the input TAR, policy, OCI image,
rootless Podman executable, private staging directory, and Linux account. A
client supplies ONLY a scope handle and one of the unchanged EC186 fixed
profiles. The kernel AF_UNIX peer UID is a local identity, not an enterprise
actor. No host-side project command is executed: user code runs ONLY inside a
new, rootless, no-network, read-only container with conservative limits.

This is an independent execution endpoint, NOT the EC187 signed-lease broker,
EC188 QualityShow, CI attestation, or an original Router HOST_REQUIRED unlock.
Runtime-reported exit status is not a certified Quality PASS. An unavailable
Podman/isolation configuration fails closed; there is no weaker fallback.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Callable

CONSTRUCTION = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = CONSTRUCTION.parent
sys.path.insert(0, str(CONSTRUCTION))
from finding_host import broker as fio  # stable local SO_PEERCRED + framing
from quality_host import broker as qhost  # dirfd/no-follow private files
import quality_run_guard as guard  # original EC186 immutable profile catalog

POLICY_SCHEMA = 'ces.ec252.quality_run_host_policy.v1'
REQUEST_SCHEMA = 'ces.ec252.quality_run_host_request.v1'
RESPONSE_SCHEMA = 'ces.ec252.quality_run_host_response.v1'
MAX_POLICY = 65536
MAX_REQUEST = 2048
MAX_REPLY = 32768
MAX_TAR = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_SINGLE_FILE = 8 * 1024 * 1024
MAX_TAR_MEMBERS = 2048
MAX_STDIO = 12 * 1024
MAX_CAPTURE = 4096
MAX_ENGINE_OUTPUT = 16384
MAX_REQUESTS = 20
WALL_SECONDS = 60
CPU_SECONDS = 40
MEMORY_BYTES = 256 * 1024 * 1024
MAX_PIDS = 32
TEMP_BYTES = 64 * 1024 * 1024
MAX_SETUP_SECONDS = 8
MAX_CLEANUP_SECONDS = 8
UID_MAX = 2**32 - 2
SHA = re.compile(r'[a-f0-9]{64}\Z')
IMAGE = re.compile(r'sha256:[a-f0-9]{64}\Z')
SCOPE = re.compile(r'[a-z][a-z0-9_-]{2,63}\Z')
STAGE_PATH = re.compile(r'/[a-zA-Z0-9_./-]{1,950}\Z')
PROFILE_IDS = frozenset({'python.pytest', 'python.ruff'})
EXIT = {'partial': 2, 'permission_denied': 3,
        'invalid_input': 4, 'unavailable': 5}
POLICY_FIELDS = {'schema', 'source_tar_path', 'expected_source_tar_sha256',
                 'scratch_root', 'runtime_path', 'expected_runtime_sha256',
                 'runtime_home', 'runtime_xdg_dir', 'image_id',
                 'expected_ec186_catalog_sha256', 'grants'}
GRANT_FIELDS = {'uid', 'scope_id', 'profile_ids', 'allow_output_text'}
REQUEST_FIELDS = {'schema', 'scope_id', 'profile_id'}


class HostRunError(ValueError):
    def __init__(self, code: str, status: str = 'unavailable') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def need(condition: bool, code: str, status: str = 'unavailable') -> None:
    if not condition:
        raise HostRunError(code, status)


def _parse(raw: bytes, bound: int, *, trusted: bool = False) -> dict[str, Any]:
    try:
        return fio._json(raw, bound)
    except fio.HostError as exc:
        raise HostRunError('RUN_HOST_JSON_INVALID',
                           'unavailable' if trusted else 'invalid_input') from exc


def _private_dir(path: Any) -> str:
    """Operator-private existing dir. Same-UID/root compromise is out of scope."""
    try:
        path = qhost._path(path)
        need(STAGE_PATH.fullmatch(path) is not None,
             'RUN_HOST_DIRECTORY_CHARACTERS_UNSUPPORTED')
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            parts = path[1:].split('/')
            for i, part in enumerate(parts):
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                              os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = nxt
                st = os.fstat(fd)
                need(stat.S_ISDIR(st.st_mode), 'RUN_HOST_NOT_DIRECTORY')
                if i == len(parts) - 1:
                    need(st.st_uid == os.geteuid() and st.st_mode & 0o077 == 0,
                         'RUN_HOST_DIRECTORY_NOT_OWNER_PRIVATE')
                else:
                    need(not st.st_mode & 0o022 or
                         (st.st_uid == 0 and bool(st.st_mode & stat.S_ISVTX)),
                         'RUN_HOST_DIRECTORY_WRITABLE_ANCESTOR')
            return path
        finally:
            os.close(fd)
    except HostRunError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise HostRunError('RUN_HOST_DIRECTORY_UNAVAILABLE') from exc


def _validate_policy(pol: dict[str, Any]) -> None:
    need(set(pol) == POLICY_FIELDS and pol.get('schema') == POLICY_SCHEMA,
         'RUN_HOST_POLICY_FIELDS')
    for field in ('source_tar_path', 'runtime_path'):
        try:
            qhost._path(pol[field])
        except (qhost.QualityHostError, TypeError) as exc:
            raise HostRunError('RUN_HOST_POLICY_PATH') from exc
    for field in ('scratch_root', 'runtime_home', 'runtime_xdg_dir'):
        need(type(pol[field]) is str and STAGE_PATH.fullmatch(pol[field]) is not None,
             'RUN_HOST_POLICY_DIRECTORY_INVALID')
    paths = [pol[f] for f in ('source_tar_path', 'scratch_root',
                              'runtime_path', 'runtime_home', 'runtime_xdg_dir')]
    need(len(set(paths)) == len(paths), 'RUN_HOST_POLICY_PATH_REUSE')
    need(type(pol['image_id']) is str and IMAGE.fullmatch(pol['image_id']) is not None,
         'RUN_HOST_IMAGE_NOT_IMMUTABLE')
    for name in ('expected_source_tar_sha256', 'expected_runtime_sha256',
                 'expected_ec186_catalog_sha256'):
        need(type(pol[name]) is str and SHA.fullmatch(pol[name]) is not None,
             'RUN_HOST_POLICY_HASH_INVALID')
    expected = guard.catalog_entry('python.pytest')['catalog_sha256']
    need(pol['expected_ec186_catalog_sha256'] == expected,
         'RUN_HOST_PROFILE_CATALOG_CHANGED')
    grants = pol['grants']
    need(type(grants) is list and 1 <= len(grants) <= 64,
         'RUN_HOST_GRANTS_INVALID')
    seen: set[tuple[int, str]] = set()
    for grant in grants:
        need(type(grant) is dict and set(grant) == GRANT_FIELDS,
             'RUN_HOST_GRANT_FIELDS')
        uid, scope, profiles = (grant['uid'], grant['scope_id'], grant['profile_ids'])
        need(type(uid) is int and 0 <= uid <= UID_MAX and
             type(scope) is str and SCOPE.fullmatch(scope) is not None and
             (uid, scope) not in seen,
             'RUN_HOST_GRANT_ID_INVALID')
        seen.add((uid, scope))
        need(type(profiles) is list and profiles and
             profiles == sorted(set(profiles)) and
             all(type(p) is str and p in PROFILE_IDS for p in profiles) and
             type(grant['allow_output_text']) is bool,
             'RUN_HOST_GRANT_PROFILE_INVALID')


def _policy(path: str) -> tuple[dict[str, Any], str]:
    try:
        raw = qhost._private_bytes(path, MAX_POLICY)
    except qhost.QualityHostError as exc:
        raise HostRunError('RUN_HOST_PRIVATE_POLICY_UNAVAILABLE') from exc
    pol = _parse(raw, MAX_POLICY, trusted=True)
    _validate_policy(pol)
    return pol, hashlib.sha256(raw).hexdigest()


def _authorize(req: dict[str, Any], pol: dict[str, Any], uid: int
               ) -> dict[str, Any]:
    need(set(req) == REQUEST_FIELDS and req.get('schema') == REQUEST_SCHEMA and
         type(req.get('scope_id')) is str and
         SCOPE.fullmatch(req['scope_id']) is not None and
         type(req.get('profile_id')) is str and
         req['profile_id'] in PROFILE_IDS,
         'RUN_HOST_REQUEST_FIELDS_OR_PROFILE', 'invalid_input')
    grant = next((g for g in pol['grants'] if
                  g['uid'] == uid and g['scope_id'] == req['scope_id']), None)
    need(grant is not None and req['profile_id'] in grant['profile_ids'],
         'RUN_HOST_PEER_SCOPE_PROFILE_DENIED', 'permission_denied')
    return grant


def _source_archive(pol: dict[str, Any]) -> bytes:
    try:
        raw = qhost._private_bytes(pol['source_tar_path'], MAX_TAR)
    except qhost.QualityHostError as exc:
        raise HostRunError('RUN_HOST_PRIVATE_SOURCE_UNAVAILABLE') from exc
    need(hashlib.sha256(raw).hexdigest() == pol['expected_source_tar_sha256'],
         'RUN_HOST_SOURCE_TAR_PIN_MISMATCH')
    return raw


def _runtime_binary(pol: dict[str, Any]) -> None:
    """Open root-owned Podman by no-follow dirfds and hash its original inode.

    This trusts the local administrator and cannot independently authenticate
    dynamic libraries, the OCI engine, a registry signature, or the kernel.
    """
    path = pol['runtime_path']
    need(type(path) is str and os.path.isabs(path) and
         os.path.normpath(path) == path and path.endswith('/podman'),
         'RUN_HOST_PODMAN_PATH_REQUIRED')
    parent_fd = file_fd = None
    try:
        parent_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        components = path[1:].split('/')
        for component in components[:-1]:
            nxt = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                          os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = nxt
            ancestor = os.fstat(parent_fd)
            need(stat.S_ISDIR(ancestor.st_mode) and ancestor.st_uid == 0 and
                 ancestor.st_mode & 0o022 == 0,
                 'RUN_HOST_PODMAN_PARENT_NOT_TRUSTED')
        file_fd = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW |
                          os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent_fd)
        st = os.fstat(file_fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
             st.st_mode & 0o022 == 0 and st.st_mode & 0o111 != 0 and
             0 < st.st_size <= 128 * 1024 * 1024,
             'RUN_HOST_PODMAN_BINARY_NOT_TRUSTED')
        dig = hashlib.sha256()
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            dig.update(chunk)
        after = os.fstat(file_fd)
        at_path = os.stat(components[-1], dir_fd=parent_fd,
                          follow_symlinks=False)
        need((st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size,
              after.st_mtime_ns, after.st_ctime_ns) and
             (after.st_dev, after.st_ino) == (at_path.st_dev, at_path.st_ino) and
             dig.hexdigest() == pol['expected_runtime_sha256'],
             'RUN_HOST_PODMAN_BINARY_PIN_MISMATCH')
    except HostRunError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise HostRunError('RUN_HOST_PODMAN_UNAVAILABLE') from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def _extract_source(raw: bytes, destination: str) -> tuple[int, int]:
    """Extract only regular files/directories; no tar symlink/hardlink/devices.

    No path supplied by the request; the operator must still audit the TAR
    contents for secrets and consent before enabling code execution.
    """
    count = total = 0
    names: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            for member in archive:
                count += 1
                need(count <= MAX_TAR_MEMBERS, 'RUN_HOST_SOURCE_MEMBER_LIMIT')
                name = member.name
                need(type(name) is str and 0 < len(name) <= 256 and
                     not name.startswith('/') and '\\' not in name and
                     all(32 <= ord(ch) < 127 for ch in name),
                     'RUN_HOST_SOURCE_PATH_INVALID')
                parts = name.rstrip('/').split('/')
                need(1 <= len(parts) <= 16 and
                     all(p and p not in ('.', '..', '.git', '.ssh', '.aws', '.env') and
                         len(p) <= 80 for p in parts),
                     'RUN_HOST_SOURCE_PATH_FORBIDDEN')
                normalized = '/'.join(parts)
                need(normalized not in names and
                     (member.isdir() or member.isfile()) and
                     not member.issym() and not member.islnk() and
                     not member.pax_headers,
                     'RUN_HOST_SOURCE_MEMBER_NOT_ALLOWED')
                need(not name.endswith('/') or member.isdir(),
                     'RUN_HOST_SOURCE_MEMBER_NOT_ALLOWED')
                names.add(normalized)
                output = os.path.join(destination, *parts)
                if member.isdir():
                    os.makedirs(output, mode=0o700, exist_ok=True)
                    need(os.path.isdir(output) and not os.path.islink(output),
                         'RUN_HOST_SOURCE_PATH_COLLISION')
                    continue
                need(type(member.size) is int and 0 <= member.size <= MAX_SINGLE_FILE,
                     'RUN_HOST_SOURCE_FILE_LIMIT')
                total += member.size
                need(total <= MAX_SOURCE_BYTES, 'RUN_HOST_SOURCE_TOTAL_LIMIT')
                parent = os.path.dirname(output)
                os.makedirs(parent, mode=0o700, exist_ok=True)
                fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                try:
                    src = archive.extractfile(member)
                    need(src is not None, 'RUN_HOST_SOURCE_ENTRY_UNAVAILABLE')
                    with src:
                        remaining = member.size
                        while remaining:
                            chunk = src.read(min(65536, remaining))
                            need(bool(chunk), 'RUN_HOST_SOURCE_TRUNCATED')
                            nread = len(chunk)
                            while chunk:
                                written = os.write(fd, chunk)
                                need(written > 0, 'RUN_HOST_SOURCE_WRITE_FAILED')
                                chunk = chunk[written:]
                            remaining -= nread
                    need(os.fstat(fd).st_size == member.size,
                         'RUN_HOST_SOURCE_STAGED_SIZE_MISMATCH')
                    os.fchmod(fd, 0o444)
                finally:
                    os.close(fd)
        # Freeze staged files and directory tree permissions before mounting.
        for root, dirs, files in os.walk(destination, topdown=False, followlinks=False):
            for filename in files:
                need(not os.path.islink(os.path.join(root, filename)),
                     'RUN_HOST_SOURCE_STAGE_SYMLINK')
            for dirname in dirs:
                os.chmod(os.path.join(root, dirname), 0o555)
        os.chmod(destination, 0o555)
        return count, total
    except HostRunError:
        raise
    except (OSError, tarfile.TarError, EOFError, OverflowError, ValueError) as exc:
        raise HostRunError('RUN_HOST_SOURCE_EXTRACT_UNAVAILABLE') from exc


def _env(pol: dict[str, Any]) -> dict[str, str]:
    # Do not propagate arbitrary parent env/proxy/registry credentials.
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
            'HOME': pol['runtime_home'],
            'XDG_RUNTIME_DIR': pol['runtime_xdg_dir']}


@dataclass
class CommandResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    stdout_sha256: str
    stderr_sha256: str
    total_output: int


def _child_command(argv: list[str], *, env: dict[str, str], timeout: float,
                   output_limit: int, check: Callable[[], None] | None = None,
                   caller: socket.socket | None = None,
                   on_output: Callable[[str, bytes], None] | None = None,
                   on_spawn: Callable[[int], None] | None = None) -> CommandResult:
    """Start a fixed argv; kill process group if wall/output/revoke/disconnect.

    This controls Podman's CLI process, not the daemon's container. Caller
    must *always* independently force-remove and confirm absence by name.
    """
    proc = None
    selector = selectors.DefaultSelector()
    sums = {'stdout': hashlib.sha256(), 'stderr': hashlib.sha256()}
    held = {'stdout': bytearray(), 'stderr': bytearray()}
    total = 0
    deadline = time.monotonic() + timeout
    problem: str | None = None
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd='/', env=env, close_fds=True,
                                start_new_session=True)
        assert proc.stdout is not None and proc.stderr is not None
        if on_spawn is not None:
            on_spawn(proc.pid)
        for name, stream in (('stdout', proc.stdout), ('stderr', proc.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        next_check = 0.0
        while selector.get_map() or proc.poll() is None:
            now = time.monotonic()
            if now >= deadline:
                problem = 'RUN_HOST_PROCESS_WALL_BUDGET'
                break
            if check is not None and now >= next_check:
                check()
                next_check = now + 0.4
            if caller is not None:
                try:
                    if caller.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT) == b'':
                        problem = 'RUN_HOST_CLIENT_DISCONNECTED'
                        break
                except (BlockingIOError, InterruptedError):
                    pass
                except OSError:
                    problem = 'RUN_HOST_CLIENT_DISCONNECTED'
                    break
            for key, _ in selector.select(min(0.15, deadline - now)):
                name = key.data
                raw = os.read(key.fileobj.fileno(), 4096)
                if not raw:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                sums[name].update(raw)
                total += len(raw)
                if len(held[name]) < MAX_CAPTURE:
                    held[name].extend(raw[:MAX_CAPTURE - len(held[name])])
                if total > output_limit:
                    problem = 'RUN_HOST_PROCESS_OUTPUT_BUDGET'
                    break
                if on_output is not None:
                    on_output(name, raw)
            if problem:
                break
        if problem:
            raise HostRunError(problem)
        remaining = max(0.1, deadline - time.monotonic())
        code = proc.wait(timeout=remaining)
        return CommandResult(code, bytes(held['stdout']), bytes(held['stderr']),
                             sums['stdout'].hexdigest(), sums['stderr'].hexdigest(), total)
    except HostRunError:
        raise
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise HostRunError('RUN_HOST_SUBPROCESS_UNAVAILABLE') from exc
    finally:
        selector.close()
        if proc is not None:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                pass
            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    stream.close()


def _run_command(pol: dict[str, Any], args: list[str], *, timeout: float,
                 limit: int = MAX_ENGINE_OUTPUT,
                 check: Callable[[], None] | None = None,
                 caller: socket.socket | None = None,
                 on_output: Callable[[str, bytes], None] | None = None,
                 on_spawn: Callable[[int], None] | None = None) -> CommandResult:
    return _child_command([pol['runtime_path'], *args], env=_env(pol),
                          timeout=timeout, output_limit=limit,
                          check=check, caller=caller, on_output=on_output,
                          on_spawn=on_spawn)


def _runtime_ready(pol: dict[str, Any]) -> None:
    _runtime_binary(pol)
    _private_dir(pol['runtime_home'])
    _private_dir(pol['runtime_xdg_dir'])
    rootless = _run_command(pol, ['info', '--format', '{{.Host.Security.Rootless}}'],
                            timeout=MAX_SETUP_SECONDS)
    need(rootless.exit_code == 0 and rootless.stdout.strip() == b'true',
         'RUN_HOST_ROOTLESS_PODMAN_REQUIRED')
    img = _run_command(pol, ['image', 'inspect', '--format', '{{.Id}}',
                             pol['image_id']], timeout=MAX_SETUP_SECONDS)
    need(img.exit_code == 0 and
         img.stdout.decode('ascii', 'replace').strip() == pol['image_id'],
         'RUN_HOST_LOCAL_IMAGE_PIN_REQUIRED')


def _profile_arguments(profile_id: str) -> list[str]:
    entry = guard.catalog_entry(profile_id)
    need(entry is not None and
         entry['profile']['module'] in ('pytest', 'ruff') and
         entry['profile']['entrypoint_kind'] == 'PYTHON_MODULE' and
         entry['profile']['runtime'] == 'TRUSTED_PINNED_PYTHON_IMAGE' and
         entry['profile']['allow_shell'] is False and
         entry['profile']['allow_user_arguments'] is False and
         type(entry['profile']['fixed_arguments']) is list and
         all(type(x) is str and len(x) <= 80 and not x.startswith('--rootdir=')
             for x in entry['profile']['fixed_arguments']),
         'RUN_HOST_PROFILE_CONTRACT_CHANGED')
    return ['-I', '-B', '-m', entry['profile']['module'],
            *entry['profile']['fixed_arguments']]


def _create_args(pol: dict[str, Any], stage: str, name: str,
                 profile_id: str, *, lease_label_sha256: str | None = None) -> list[str]:
    # The EC253+ lease-controlled path labels the object atomically at create.
    # A Podman name alone is never a sufficient recovery identifier.
    if lease_label_sha256 is not None:
        need(type(lease_label_sha256) is str and
             SHA.fullmatch(lease_label_sha256) is not None,
             'RUN_HOST_OCI_LABEL_INVALID')
    label_args = ([] if lease_label_sha256 is None else
                  ['--label=io.ces.lease.sha256=' + lease_label_sha256])
    return ['create', '--name', name, *label_args, '--pull=never', '--read-only',
            '--network=none', '--ipc=private', '--pid=private',
            '--cgroupns=private', '--userns=auto', '--user=65534:65534',
            '--cap-drop=all', '--security-opt=no-new-privileges',
            '--pids-limit=32', '--memory=256m', '--memory-swap=256m',
            '--cpus=1', '--ulimit=cpu=40:40',
            '--ulimit=fsize=67108864:67108864',
            '--log-driver=none',
            '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777',
            '--mount=type=bind,source=' + stage + ',destination=/workspace,readonly=true',
            '--workdir=/workspace',
            '--env=HOME=/tmp', '--env=TMPDIR=/tmp',
            '--env=PYTHONNOUSERSITE=1', '--env=PYTHONDONTWRITEBYTECODE=1',
            '--env=PYTEST_DISABLE_PLUGIN_AUTOLOAD=1',
            '--entrypoint=/usr/bin/python3', pol['image_id'],
            *_profile_arguments(profile_id)]


def _cleanup(pol: dict[str, Any], name: str) -> bool:
    """Container must be absent; failure/ambiguity is never treated as safe."""
    try:
        _run_command(pol, ['rm', '--force', '--time', '0', name],
                     timeout=MAX_CLEANUP_SECONDS)
        result = _run_command(pol, ['container', 'exists', name],
                              timeout=MAX_CLEANUP_SECONDS)
        return result.exit_code == 1
    except HostRunError:
        return False


def _remove_private_stage(path: str) -> None:
    """Restore service-owned staging directory permissions before removing it.

    Call only after the engine confirmed container absence. Tar extraction
    deliberately leaves directories 0555 and files 0444, so an ordinary
    nonroot shutil.rmtree would otherwise fail and leak the private stage.
    """
    for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
        for dirname in dirs:
            entry = os.path.join(root, dirname)
            need(not os.path.islink(entry), 'RUN_HOST_STAGE_SYMLINK_DETECTED')
            os.chmod(entry, 0o700)
        os.chmod(root, 0o700)
    shutil.rmtree(path)


def _redact_output(raw: bytes) -> str:
    text = raw.decode('utf-8', 'replace')
    return ''.join(c if c in '\n\t' or c.isprintable() else ' ' for c in text)


def _run_container(pol: dict[str, Any], profile: str, source: bytes,
                   *, recheck: Callable[[], None],
                   caller: socket.socket | None,
                   on_reserved: Callable[[str, str], None] | None = None,
                   on_closed: Callable[[str, str, bool], None] | None = None,
                   on_output: Callable[[str, bytes], None] | None = None,
                   on_started: Callable[[int], None] | None = None,
                   lease_label_sha256: str | None = None,
                   on_created: Callable[[str, str], None] | None = None,
                   on_before_start: Callable[[str, str], None] | None = None,
                   on_before_cleanup: Callable[[str, str | None], None] | None = None,
                   ) -> dict[str, Any]:
    _runtime_ready(pol)  # never fall back to bare subprocess / unshare
    scratch = _private_dir(pol['scratch_root'])
    # Each run has an independent private copy, not a live mutable Git tree.
    stage_parent = tempfile.mkdtemp(prefix='ec252-', dir=scratch)
    name = 'ces-ec252-' + secrets.token_hex(12)
    creation_attempted = False
    lifecycle_reserved = False
    created_id: str | None = None
    cleaned = True
    outcome: dict[str, Any] | None = None
    pending_error: HostRunError | None = None
    try:
        stage = os.path.join(stage_parent, 'source')
        os.mkdir(stage, 0o700)
        members, size = _extract_source(source, stage)
        recheck()
        # EC253 may durably reserve a one-use lease and arm a separate crash
        # watcher here. This callback MUST finish before any OCI create attempt.
        # The existing EC252 entry point retains its independent no-lease mode.
        if on_reserved is not None:
            on_reserved(name, stage_parent)
            lifecycle_reserved = True
        creation_attempted = True  # even timed-out create may have succeeded
        create = _run_command(pol, _create_args(
            pol, stage, name, profile, lease_label_sha256=lease_label_sha256),
            timeout=MAX_SETUP_SECONDS, check=recheck, caller=caller)
        need(create.exit_code == 0 and
             re.fullmatch(r'[0-9a-f]{64}', create.stdout.strip().decode('ascii', 'replace'))
             is not None, 'RUN_HOST_PODMAN_CREATE_FAILED')
        created_id = create.stdout.strip().decode('ascii')
        if lease_label_sha256 is not None:
            from oci_identity import binding
            # Exact, uniquely labeled ID must be confirmed *before* starting.
            # The on_created callback fsyncs this ID into the permanent lease
            # journal before any `podman start` attempt is permitted.
            binding.before_start(pol, lease_label_sha256, name, created_id)
            need(on_created is not None, 'RUN_HOST_OCI_BINDING_CALLBACK_REQUIRED')
            on_created(name, created_id)
        recheck()  # independent grant & source recheck just before execution
        if on_before_start is not None:
            # EC256 persists the possible start before the CLI process is spawned.
            on_before_start(name, created_id)
        start_target = created_id if lease_label_sha256 is not None else name
        start = _run_command(pol, ['start', '--attach', start_target],
                             timeout=WALL_SECONDS, limit=MAX_STDIO,
                             check=recheck, caller=caller, on_output=on_output,
                             on_spawn=on_started)
        # OCI runtime, rather than a subprocess return code alone, must report
        # that the new container started, stopped, and has its own exit status.
        if lease_label_sha256 is not None:
            from oci_identity import binding
            binding.verify(pol, created_id, lease_label_sha256)
        inspect = _run_command(pol, ['inspect', '--format', '{{json .State}}',
                                     start_target],
                               timeout=MAX_SETUP_SECONDS, check=recheck)
        need(inspect.exit_code == 0 and len(inspect.stdout) <= 4096,
             'RUN_HOST_PODMAN_INSPECT_UNAVAILABLE')
        state = _parse(inspect.stdout.strip(), 4096, trusted=True)
        code = state.get('ExitCode')
        started = state.get('StartedAt')
        need(state.get('Running') is False and
             type(code) is int and 0 <= code <= 255 and
             type(started) is str and started and
             not started.startswith('0001-') and
             state.get('OOMKilled') is False and
             start.exit_code == code and code < 125,
             'RUN_HOST_CONTAINER_COMPLETION_UNVERIFIED')
        recheck()
        outcome = {
            'profile_id': profile,
            'ec186_profile_sha256': guard.catalog_entry(profile)['profile_sha256'],
            'source_tar_sha256': pol['expected_source_tar_sha256'],
            'source_staged_members': members, 'source_staged_bytes': size,
            'local_container_started_and_exited_reported': True,
            'container_exit_code_reported': code,
            'local_test_outcome': 'exit_zero' if code == 0 else 'nonzero',
            'stdout_observed_sha256': start.stdout_sha256,
            'stderr_observed_sha256': start.stderr_sha256,
            'total_stdio_observed_bytes': start.total_output,
            'captured_stdout': _redact_output(start.stdout),
            'captured_stderr': _redact_output(start.stderr),
            'read_only_source_mount_requested': True,
            'no_network_requested': True,
            'runtime_security_control_independently_attested': False,
            'upstream_ci_or_source_provenance_authenticated': False,
            'overall_quality_pass_verified': False,
        }
    except HostRunError as exc:
        pending_error = exc
    finally:
        if creation_attempted:
            if lease_label_sha256 is None:
                cleaned = _cleanup(pol, name)  # legacy EC252 standalone route
            else:
                from oci_identity import binding
                # Strict EC256 host requires a cgroup-wide kill barrier before
                # *any* removal. Failure retains the private stage and journal.
                reap_ready = True
                if on_before_cleanup is not None:
                    try:
                        on_before_cleanup(name, created_id)
                    except HostRunError as exc:
                        reap_ready = False
                        pending_error = exc
                    except (OSError, ValueError, TypeError, RuntimeError):
                        reap_ready = False
                        pending_error = HostRunError('RUN_HOST_CGROUP_REAP_UNCONFIRMED')
                cleaned = (binding.verified_cleanup(pol, lease_label_sha256,
                            name, created_id) if reap_ready else False)
        # Do not claim the stage is no longer mounted unless container
        # absence was confirmed; otherwise retain the private directory for
        # operator incident response and deny all run results.
        if cleaned:
            try:
                _remove_private_stage(stage_parent)
            except (OSError, HostRunError):
                cleaned = False
        if lifecycle_reserved and on_closed is not None:
            try:
                on_closed(name, stage_parent, cleaned)
            except HostRunError as exc:
                pending_error = exc
            except (OSError, ValueError, RuntimeError):
                pending_error = HostRunError('RUN_HOST_LIFECYCLE_CLOSE_UNCONFIRMED')
        if not cleaned:
            pending_error = HostRunError('RUN_HOST_CONTAINER_OR_STAGE_CLEANUP_UNCONFIRMED')
    if pending_error:
        raise pending_error
    need(outcome is not None, 'RUN_HOST_RESULT_UNAVAILABLE')
    return outcome


def _reply(status: str, code: str, *, result: dict[str, Any] | None = None,
           peer: bool = False, policy: bool = False, archive: bool = False
           ) -> dict[str, Any]:
    return {'schema': RESPONSE_SCHEMA, 'status': status,
            'exit_code': EXIT[status], 'reason_code': code,
            'kernel_peer_uid_checked': peer, 'scope_policy_checked': policy,
            'source_archive_sha256_checked': archive,
            'enterprise_actor_authenticated': False,
            'source_provenance_independently_verified': False,
            'ci_run_independently_verified': False,
            'overall_quality_pass_verified': False,
            'original_router_host_required_unlocked': False,
            'business_repository_written': False, 'result': result}


def execute(request_raw: bytes, policy_path: str, peer_uid: int,
            *, caller: socket.socket | None = None) -> dict[str, Any]:
    policy_checked = archive_checked = False
    try:
        fio._linux()
        need(os.geteuid() != 0, 'RUN_HOST_ROOTLESS_SERVICE_REQUIRED')
        req = _parse(request_raw, MAX_REQUEST)
        pol, pin = _policy(policy_path)
        grant = _authorize(req, pol, peer_uid)
        policy_checked = True
        raw = _source_archive(pol)
        archive_checked = True

        def recheck() -> None:
            newer, new_sha = _policy(policy_path)
            need(new_sha == pin and newer == pol,
                 'RUN_HOST_POLICY_REVOKED_OR_CHANGED')
            _authorize(req, newer, peer_uid)

        recheck()
        need(_source_archive(pol) == raw, 'RUN_HOST_SOURCE_REVOKED_OR_CHANGED')
        result = _run_container(pol, req['profile_id'], raw,
                                recheck=recheck, caller=caller)
        recheck()
        need(_source_archive(pol) == raw, 'RUN_HOST_SOURCE_REVOKED_OR_CHANGED')
        if not grant['allow_output_text']:
            result['captured_stdout'] = None
            result['captured_stderr'] = None
        return _reply('partial', 'RUN_HOST_LOCAL_CONTAINER_EXIT_REPORTED',
                      result=result, peer=True, policy=True, archive=True)
    except HostRunError as exc:
        return _reply(exc.status, exc.code, peer=True, policy=policy_checked,
                      archive=archive_checked)
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, OverflowError,
            MemoryError, RecursionError, UnicodeError, subprocess.SubprocessError):
        return _reply('unavailable', 'RUN_HOST_OPERATION_UNAVAILABLE', peer=True,
                      policy=policy_checked, archive=archive_checked)


def _wire(value: dict[str, Any]) -> bytes:
    try:
        return fio._wire(value, limit=MAX_REPLY)
    except fio.HostError:
        return fio._wire(_reply('unavailable', 'RUN_HOST_RESPONSE_LIMIT'), limit=MAX_REPLY)


def serve(policy_path: str, socket_path: str, *, max_requests: int = 1,
          accept_timeout: float = 60.0) -> None:
    fio._linux()
    need(os.geteuid() != 0, 'RUN_HOST_ROOTLESS_SERVICE_REQUIRED')
    need(type(max_requests) is int and 1 <= max_requests <= MAX_REQUESTS and
         type(accept_timeout) in (int, float) and 1 <= accept_timeout <= 300,
         'RUN_HOST_SERVICE_OPTIONS_INVALID')
    pol, _ = _policy(policy_path)
    _source_archive(pol)
    _private_dir(pol['scratch_root'])
    target = fio._private_parent(socket_path, policy=False)
    need(len(os.fsencode(str(target))) < 100, 'RUN_HOST_SOCKET_PATH_TOO_LONG')
    try:
        os.lstat(target)
    except FileNotFoundError:
        pass
    else:
        raise HostRunError('RUN_HOST_SOCKET_ALREADY_EXISTS')
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    created = None
    try:
        old_umask = os.umask(0o117)
        try:
            listener.bind(str(target))
        finally:
            os.umask(old_umask)
        st = os.lstat(target)
        created = (st.st_dev, st.st_ino)
        need(stat.S_ISSOCK(st.st_mode) and st.st_uid == os.geteuid() and
             st.st_mode & 0o007 == 0,
             'RUN_HOST_SOCKET_UNSAFE')
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
                    req = fio._receive(conn, MAX_REQUEST)
                    reply = execute(req, policy_path, uid, caller=conn)
                except fio.HostError as exc:
                    reply = _reply(exc.status, exc.code)
                except (HostRunError, OSError, socket.timeout) as exc:
                    reply = _reply('unavailable', 'RUN_HOST_SOCKET_OPERATION_UNAVAILABLE')
                try:
                    conn.sendall(_wire(reply))
                except OSError:
                    pass
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
    need(type(expected_host_uid) is int and 0 <= expected_host_uid <= UID_MAX,
         'RUN_HOST_EXPECTED_SERVICE_UID_REQUIRED', 'invalid_input')
    with open(request_path, 'rb') as fh:
        req = _parse(fh.read(MAX_REQUEST + 1), MAX_REQUEST)
    need(req.get('schema') == REQUEST_SCHEMA, 'RUN_HOST_REQUEST_SCHEMA_INVALID',
         'invalid_input')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(WALL_SECONDS + 4 * MAX_SETUP_SECONDS + 2 * MAX_CLEANUP_SECONDS)
        conn.connect(socket_path)
        need(fio._uid_from_peer(conn) == expected_host_uid,
             'RUN_HOST_SERVICE_UID_MISMATCH', 'permission_denied')
        conn.sendall(fio._wire(req, limit=MAX_REQUEST))
        reply = _parse(fio._receive(conn, MAX_REPLY), MAX_REPLY, trusted=True)
    expected = {'schema', 'status', 'exit_code', 'reason_code',
                'kernel_peer_uid_checked', 'scope_policy_checked',
                'source_archive_sha256_checked', 'enterprise_actor_authenticated',
                'source_provenance_independently_verified',
                'ci_run_independently_verified', 'overall_quality_pass_verified',
                'original_router_host_required_unlocked', 'business_repository_written',
                'result'}
    need(set(reply) == expected and reply.get('schema') == RESPONSE_SCHEMA and
         reply.get('status') in EXIT and type(reply.get('exit_code')) is int and
         reply['exit_code'] == EXIT[reply['status']] and
         type(reply.get('reason_code')) is str and
         all(type(reply[k]) is bool for k in expected - {
             'schema', 'status', 'exit_code', 'reason_code', 'result'}) and
         all(reply[k] is False for k in ('enterprise_actor_authenticated',
              'source_provenance_independently_verified',
              'ci_run_independently_verified', 'overall_quality_pass_verified',
              'original_router_host_required_unlocked', 'business_repository_written')) and
         (reply['result'] is None or type(reply['result']) is dict),
         'RUN_HOST_RESPONSE_CONTRACT_INVALID')
    return reply


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC252 opt-in, rootless Podman QualityRun')
    sub = parser.add_subparsers(dest='command', required=True)
    server = sub.add_parser('serve', help='operator-owned AF_UNIX server')
    server.add_argument('--policy', required=True)
    server.add_argument('--socket', required=True)
    server.add_argument('--max-requests', type=int, default=1)
    server.add_argument('--accept-timeout', type=float, default=60.0)
    client = sub.add_parser('request', help='send an existing on-disk fixed-profile request')
    client.add_argument('--socket', required=True)
    client.add_argument('--request-file', required=True)
    client.add_argument('--expect-host-uid', required=True, type=int)
    args = parser.parse_args(argv)
    try:
        if args.command == 'serve':
            serve(args.policy, args.socket, max_requests=args.max_requests,
                  accept_timeout=args.accept_timeout)
            return 0
        result = request(args.socket, args.request_file, args.expect_host_uid)
    except HostRunError as exc:
        result = _reply(exc.status, exc.code)
    except (OSError, socket.timeout):
        result = _reply('unavailable', 'RUN_HOST_COMMAND_IO_UNAVAILABLE')
    print(_wire(result).decode('ascii').rstrip('\n'))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
