#!/usr/bin/env python3
"""EC258: offline, operator-owned Git blob -> bounded EC252 Source TAR custody.

A full, operator-reviewed commit OID and an exact-file allowlist are mandatory;
working-tree content, HEAD, branches, paths or commands from QualityRun clients
are never trusted. This is local content verification, *not* a Git author,
enterprise/remote-origin, actor, CI, or source-authorization attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import tarfile
import time
from typing import Any

CONSTRUCTION = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(CONSTRUCTION))
from ec251_quality_host import broker as private
from ec252_quality_run_host import broker as runner

ALLOW_SCHEMA = 'ces.ec258.git_source_allowlist.v1'
RECEIPT_SCHEMA = 'ces.ec258.git_source_custody_receipt.v1'
MAX_APPROVAL = 512 * 1024
MAX_RECEIPT = 1024 * 1024
MAX_TREE = 2 * 1024 * 1024
MAX_OBJECTS = 4096
SHA1 = re.compile(r'[a-f0-9]{40}\Z')
SHA256 = re.compile(r'[a-f0-9]{64}\Z')
PATH = re.compile(r'[ -~]{1,256}\Z')
# Protect against common secret material even inside an explicitly reviewed
# allowlist; the allowlist is never treated as an automated secrets audit.
FORBIDDEN_COMPONENTS = frozenset({'.git', '.ssh', '.aws', '.env', '.gnupg',
                                   '.kube', '.terraform', '.secrets'})
FORBIDDEN_SUFFIXES = ('.pem', '.key', '.p12', '.pfx', '.kdbx', '.age', '.gpg')
GIT_ENV = {'PATH': '/usr/bin:/bin', 'HOME': '/dev/null', 'LC_ALL': 'C',
           'LANG': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_ATTR_NOSYSTEM': '1',
           'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_OPTIONAL_LOCKS': '0',
           'GIT_CONFIG_COUNT': '0', 'GIT_TERMINAL_PROMPT': '0',
           'GIT_NO_LAZY_FETCH': '1', 'GIT_PROTOCOL_FROM_USER': '0',
           'GIT_ALLOW_PROTOCOL': ''}


class CustodyError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def require(ok: bool, code: str) -> None:
    if not ok:
        raise CustodyError(code)


def _json_unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in obj, 'CUSTODY_JSON_DUPLICATE_KEY')
        obj[key] = value
    return obj


def _decode_json(raw: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(raw.decode('utf-8'), object_pairs_hook=_json_unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(
                             CustodyError('CUSTODY_JSON_NONFINITE')))
    except (UnicodeError, ValueError, TypeError) as exc:
        if isinstance(exc, CustodyError):
            raise
        raise CustodyError('CUSTODY_JSON_INVALID') from exc
    require(type(obj) is dict, 'CUSTODY_JSON_NOT_OBJECT')
    return obj


def _canonical(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _relative_name(path: Any) -> str:
    require(type(path) is str and PATH.fullmatch(path) is not None and
            not path.startswith('/') and '\\' not in path and
            not path.endswith('/') and '\x7f' not in path,
            'CUSTODY_PATH_UNSAFE')
    parts = path.split('/')
    require(1 <= len(parts) <= 16 and
            all(part and part not in ('.', '..') and
                len(part) <= 80 and part.lower() not in FORBIDDEN_COMPONENTS and
                not part.lower().startswith('.env') and
                not part.lower().endswith(FORBIDDEN_SUFFIXES)
                for part in parts), 'CUSTODY_PATH_FORBIDDEN')
    # tarfile USTAR must be able to represent paths without PAX/longname.
    require(len(path.encode('ascii')) <= 256, 'CUSTODY_PATH_TOO_LONG')
    return path


def _allowlist(raw: bytes) -> dict[str, Any]:
    obj = _decode_json(raw)
    require(set(obj) == {'schema', 'commit_oid', 'source_paths'} and
            obj.get('schema') == ALLOW_SCHEMA and
            type(obj['commit_oid']) is str and
            (SHA1.fullmatch(obj['commit_oid']) is not None or
             SHA256.fullmatch(obj['commit_oid']) is not None),
            'CUSTODY_APPROVAL_FIELDS')
    paths = obj['source_paths']
    require(type(paths) is list and 1 <= len(paths) <= runner.MAX_TAR_MEMBERS and
            all(_relative_name(path) == path for path in paths) and
            paths == sorted(set(paths)), 'CUSTODY_APPROVAL_PATHS')
    return obj


def _private_file(path: str, limit: int) -> bytes:
    try:
        return private._private_bytes(path, limit)
    except private.QualityHostError as exc:
        raise CustodyError('CUSTODY_PRIVATE_FILE_REQUIRED') from exc


def _private_directory(path: str) -> str:
    try:
        return runner._private_dir(path)
    except runner.HostRunError as exc:
        raise CustodyError('CUSTODY_PRIVATE_DIRECTORY_REQUIRED') from exc


def _repo(path: str) -> tuple[str, tuple[int, int, int, int]]:
    """No symlink repo ancestors or .git; operator UID owns private checkout."""
    root = _private_directory(path)
    require(os.geteuid() != 0, 'CUSTODY_NONROOT_OPERATOR_REQUIRED')
    fd = None
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
        repo_st = os.fstat(fd)
        gitfd = os.open('.git', os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            gitst = os.fstat(gitfd)
            require(gitst.st_uid == os.geteuid() and gitst.st_mode & 0o077 == 0,
                    'CUSTODY_GIT_DIRECTORY_NOT_PRIVATE')
            try:
                os.stat('commondir', dir_fd=gitfd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise CustodyError('CUSTODY_EXTERNAL_COMMON_DIR')
            objfd = os.open('objects', os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=gitfd)
            try:
                ost = os.fstat(objfd)
                require(ost.st_uid == os.geteuid() and ost.st_mode & 0o022 == 0,
                        'CUSTODY_OBJECTS_DIRECTORY_UNTRUSTED')
                # Disallow source bytes fetched from a different repository
                # through .git/objects/info/alternates, even when hash-valid.
                infofd = os.open('info', os.O_RDONLY | os.O_DIRECTORY |
                                 os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=objfd)
                try:
                    try:
                        os.stat('alternates', dir_fd=infofd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        raise CustodyError('CUSTODY_EXTERNAL_OBJECT_ALTERNATES')
                finally:
                    os.close(infofd)
            finally:
                os.close(objfd)
            return root, (repo_st.st_dev, repo_st.st_ino,
                          gitst.st_dev, gitst.st_ino)
        finally:
            os.close(gitfd)
    except (OSError, ValueError) as exc:
        if isinstance(exc, CustodyError):
            raise
        raise CustodyError('CUSTODY_GIT_DIRECTORY_UNAVAILABLE') from exc
    finally:
        if fd is not None:
            os.close(fd)


def _same_repo(path: str, identity: tuple[int, int, int, int]) -> None:
    _, now = _repo(path)
    require(now == identity, 'CUSTODY_REPOSITORY_REPLACED')


def _git(root: str, args: list[str], limit: int = 128) -> bytes:
    """Only fixed Git commands, with bounded bytes/time and no shell/hooks."""
    cmd = ['/usr/bin/git', '-C', root, *args]
    process = None
    watch = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env=GIT_ENV, cwd='/', close_fds=True)
        assert process.stdout is not None
        os.set_blocking(process.stdout.fileno(), False)
        watch.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 10.0
        data = bytearray()
        while watch.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'CUSTODY_GIT_TIMEOUT')
            for key, _ in watch.select(min(0.2, remaining)):
                chunk = os.read(key.fileobj.fileno(),
                                min(65536, limit + 1 - len(data)))
                if not chunk:
                    watch.unregister(key.fileobj)
                    break
                data.extend(chunk)
                require(len(data) <= limit, 'CUSTODY_GIT_OUTPUT_LIMIT')
        require(process.wait(timeout=max(0.01, deadline - time.monotonic())) == 0,
                'CUSTODY_GIT_OBJECT_UNAVAILABLE')
        return bytes(data)
    except subprocess.TimeoutExpired as exc:
        raise CustodyError('CUSTODY_GIT_TIMEOUT') from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise CustodyError('CUSTODY_GIT_UNAVAILABLE') from exc
    finally:
        watch.close()
        if process is not None:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            if process.stdout is not None:
                process.stdout.close()


class GitObjects:
    def __init__(self, root: str, requested: str):
        self.root = root
        self.format = _git(root, ['rev-parse', '--show-object-format']).strip().decode('ascii')
        require(self.format in ('sha1', 'sha256'), 'CUSTODY_GIT_FORMAT_UNSUPPORTED')
        self.oid_length = 40 if self.format == 'sha1' else 64
        require(len(requested) == self.oid_length, 'CUSTODY_COMMIT_OID_FORMAT')
        self.hash_constructor = hashlib.sha1 if self.format == 'sha1' else hashlib.sha256
        self.seen = 0
        self.cache: dict[str, dict[bytes, tuple[str, str]]] = {}

    def object(self, kind: str, oid: str, size_max: int) -> bytes:
        require(kind in ('tree', 'commit', 'blob') and
                len(oid) == self.oid_length and
                re.fullmatch(r'[a-f0-9]+', oid) is not None,
                'CUSTODY_OBJECT_ID_INVALID')
        size_raw = _git(self.root, ['cat-file', '-s', oid], 32).strip()
        require(size_raw.isdigit() and len(size_raw) <= 12 and
                int(size_raw) <= size_max, 'CUSTODY_GIT_OBJECT_SIZE')
        data = _git(self.root, ['cat-file', kind, oid], int(size_raw) + 1)
        require(len(data) == int(size_raw), 'CUSTODY_GIT_OBJECT_LENGTH')
        digest = self.hash_constructor(
            kind.encode('ascii') + b' ' + str(len(data)).encode('ascii') +
            b'\x00' + data).hexdigest()
        require(digest == oid, 'CUSTODY_GIT_OBJECT_HASH')
        return data

    def commit_tree(self, oid: str) -> str:
        raw = self.object('commit', oid, 256 * 1024)
        first = raw.split(b'\n', 1)[0]
        require(first.startswith(b'tree ') and
                len(first[5:]) == self.oid_length, 'CUSTODY_COMMIT_TREE_MISSING')
        try:
            tree = first[5:].decode('ascii')
        except UnicodeError as exc:
            raise CustodyError('CUSTODY_COMMIT_TREE_INVALID') from exc
        require(re.fullmatch(r'[a-f0-9]+', tree) is not None,
                'CUSTODY_COMMIT_TREE_INVALID')
        return tree

    def tree(self, oid: str) -> dict[bytes, tuple[str, str]]:
        if oid in self.cache:
            return self.cache[oid]
        self.seen += 1
        require(self.seen <= MAX_OBJECTS, 'CUSTODY_TOO_MANY_GIT_TREES')
        data = self.object('tree', oid, MAX_TREE)
        members: dict[bytes, tuple[str, str]] = {}
        pos = 0
        byte_width = self.oid_length // 2
        while pos < len(data):
            space = data.find(b' ', pos)
            zero = data.find(b'\x00', space + 1) if space >= 0 else -1
            require(pos < space < zero and
                    len(data) - zero - 1 >= byte_width,
                    'CUSTODY_TREE_BINARY_FORMAT')
            mode = data[pos:space]
            name = data[space + 1:zero]
            require(mode in (b'40000', b'100644', b'100755', b'120000', b'160000') and
                    name and name not in (b'.', b'..') and
                    b'/' not in name and name not in members,
                    'CUSTODY_TREE_ENTRY_INVALID')
            raw_id = data[zero + 1:zero + 1 + byte_width]
            members[name] = (mode.decode('ascii'), raw_id.hex())
            pos = zero + 1 + byte_width
            require(len(members) <= runner.MAX_TAR_MEMBERS * 4,
                    'CUSTODY_TREE_MEMBER_LIMIT')
        self.cache[oid] = members
        return members

    def blob(self, tree_oid: str, path: str) -> tuple[bytes, str, str]:
        parts = path.encode('ascii').split(b'/')
        current = tree_oid
        for index, part in enumerate(parts):
            entry = self.tree(current).get(part)
            require(entry is not None, 'CUSTODY_ALLOWLIST_PATH_ABSENT')
            mode, oid = entry
            if index < len(parts) - 1:
                require(mode == '40000', 'CUSTODY_ALLOWLIST_PARENT_NOT_TREE')
                current = oid
            else:
                require(mode in ('100644', '100755'),
                        'CUSTODY_ALLOWLIST_NOT_REGULAR_FILE')
                data = self.object('blob', oid, runner.MAX_SINGLE_FILE)
                return data, oid, mode
        raise CustodyError('CUSTODY_ALLOWLIST_PATH_INVALID')


def _render_tar(files: list[tuple[str, bytes, str]]) -> bytes:
    output = io.BytesIO()
    try:
        with tarfile.open(fileobj=output, mode='w:', format=tarfile.USTAR_FORMAT) as tar:
            for path, data, mode in files:
                meta = tarfile.TarInfo(path)
                meta.size = len(data)
                meta.uid = meta.gid = meta.mtime = 0
                meta.uname = meta.gname = ''
                meta.mode = 0o755 if mode == '100755' else 0o644
                meta.type = tarfile.REGTYPE
                tar.addfile(meta, io.BytesIO(data))
    except (tarfile.TarError, ValueError, UnicodeError) as exc:
        raise CustodyError('CUSTODY_TAR_USTAR_UNREPRESENTABLE') from exc
    result = output.getvalue()
    require(len(result) <= runner.MAX_TAR, 'CUSTODY_TAR_BYTES_LIMIT')
    return result


def build(repo: str, approved: bytes) -> tuple[bytes, dict[str, Any]]:
    """Reads Git objects ONLY, never working-tree files or Git filters."""
    allow = _allowlist(approved)
    root, identity = _repo(repo)
    git = GitObjects(root, allow['commit_oid'])
    tree_oid = git.commit_tree(allow['commit_oid'])
    files: list[tuple[str, bytes, str]] = []
    records: list[dict[str, Any]] = []
    total = 0
    for name in allow['source_paths']:
        data, oid, mode = git.blob(tree_oid, name)
        total += len(data)
        require(total <= runner.MAX_SOURCE_BYTES, 'CUSTODY_SOURCE_BYTES_LIMIT')
        files.append((name, data, mode))
        records.append({'path': name, 'git_blob_oid': oid, 'git_mode': mode,
                        'sha256': _sha(data), 'bytes': len(data)})
    _same_repo(root, identity)
    tar_bytes = _render_tar(files)
    receipt = {'schema': RECEIPT_SCHEMA, 'status': 'local_git_content_verified_only',
               'commit_oid': allow['commit_oid'], 'tree_oid': tree_oid,
               'git_object_format': git.format, 'allowlist_sha256': _sha(approved),
               'source_tar_sha256': _sha(tar_bytes),
               'source_tar_bytes': len(tar_bytes),
               'source_file_count': len(files), 'source_total_bytes': total,
               'files': records,
               'independent_git_origin_attested': False,
               'enterprise_actor_authenticated': False,
               'quality_pass_verified': False}
    return tar_bytes, receipt


def _publish_one(dirfd: int, name: str, data: bytes) -> None:
    """No clobber and durable creation; incomplete pair is not an approval."""
    temp = '.' + name + '.tmp-' + os.urandom(12).hex()
    fd = None
    try:
        fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dirfd)
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            require(n > 0, 'CUSTODY_PUBLISH_WRITE')
            view = view[n:]
        os.fsync(fd)
        os.close(fd)
        fd = None
        # Atomic no-clobber publish (link then unlink): never rename over an
        # existing approved source.tar or source.custody.json.
        os.link(temp, name, src_dir_fd=dirfd, dst_dir_fd=dirfd,
                follow_symlinks=False)
        os.unlink(temp, dir_fd=dirfd)
        os.fsync(dirfd)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temp, dir_fd=dirfd)
        except FileNotFoundError:
            pass


def prepare(repo: str, allowlist_path: str, output_dir: str) -> dict[str, Any]:
    raw = _private_file(allowlist_path, MAX_APPROVAL)
    tar_bytes, receipt = build(repo, raw)
    require(_private_file(allowlist_path, MAX_APPROVAL) == raw,
            'CUSTODY_APPROVAL_CHANGED')
    dest = _private_directory(output_dir)
    require(os.path.commonpath((dest, repo)) not in (dest, repo),
            'CUSTODY_OUTPUT_MUST_BE_OUTSIDE_GIT_REPO')
    require(os.path.commonpath((dest, str(CONSTRUCTION.parent))) !=
            str(CONSTRUCTION.parent), 'CUSTODY_OUTPUT_INSIDE_CES_FORBIDDEN')
    dirfd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY |
                    os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for final in ('source.tar', 'source.custody.json'):
            try:
                os.stat(final, dir_fd=dirfd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise CustodyError('CUSTODY_OUTPUT_ALREADY_EXISTS')
        _publish_one(dirfd, 'source.tar', tar_bytes)
        try:
            _publish_one(dirfd, 'source.custody.json', _canonical(receipt))
        except Exception:
            # Leave NO apparently paired publication on a caught error.
            os.unlink('source.tar', dir_fd=dirfd)
            os.fsync(dirfd)
            raise
    except OSError as exc:
        raise CustodyError('CUSTODY_OUTPUT_PUBLISH_FAILED') from exc
    finally:
        os.close(dirfd)
    return {'status': 'partial', 'exit_code': 2,
            'source_tar_path': dest + '/source.tar',
            'receipt_path': dest + '/source.custody.json',
            'source_tar_sha256': receipt['source_tar_sha256'],
            'commit_oid': receipt['commit_oid'],
            'source_file_count': receipt['source_file_count'],
            'independent_git_origin_attested': False}


def verify(repo: str, allowlist_path: str, tar_path: str,
           receipt_path: str, policy_path: str | None = None,
           profile_id: str | None = None) -> dict[str, Any]:
    approved = _private_file(allowlist_path, MAX_APPROVAL)
    tar_bytes, expected = build(repo, approved)
    actual = _private_file(tar_path, runner.MAX_TAR)
    stored = _private_file(receipt_path, MAX_RECEIPT)
    require(_private_file(allowlist_path, MAX_APPROVAL) == approved,
            'CUSTODY_APPROVAL_CHANGED')
    require(actual == tar_bytes and _sha(actual) == expected['source_tar_sha256'],
            'CUSTODY_TAR_NOT_GIT_CONTENT')
    require(stored == _canonical(expected), 'CUSTODY_RECEIPT_NOT_GIT_CONTENT')
    # Optional pin-to-original-signed EC253 policy and TWO verified tickets;
    # original policy and ticket formats are not altered by EC258.
    if policy_path is not None:
        require(profile_id is not None, 'CUSTODY_PROFILE_ID_REQUIRED')
        from ec253_lease_host import broker as lease
        try:
            policy, _ = lease._policy(policy_path)
            require(policy['source_tar_path'] == tar_path and
                    policy['expected_source_tar_sha256'] == _sha(actual),
                    'CUSTODY_EC253_POLICY_TAR_MISMATCH')
            lease._tickets(policy, profile_id)
        except runner.HostRunError as exc:
            raise CustodyError('CUSTODY_EC253_SIGNED_BINDING_UNAVAILABLE') from exc
    else:
        require(profile_id is None, 'CUSTODY_PROFILE_WITHOUT_POLICY')
    return {'status': 'partial', 'exit_code': 2,
            'content_custody_verified': True,
            'source_tar_sha256': expected['source_tar_sha256'],
            'commit_oid': expected['commit_oid'],
            'file_count': expected['source_file_count'],
            'local_ec253_tickets_consistent': policy_path is not None,
            'independent_git_origin_attested': False,
            'enterprise_actor_authenticated': False,
            'quality_pass_verified': False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC258 offline pinned Git-to-TAR custody')
    sub = parser.add_subparsers(dest='action', required=True)
    create = sub.add_parser('prepare', help='Create immutable TAR + local receipt')
    create.add_argument('--repo', required=True)
    create.add_argument('--allowlist', required=True)
    create.add_argument('--output-dir', required=True)
    check = sub.add_parser('verify', help='Recheck TAR and receipt against Git objects')
    check.add_argument('--repo', required=True)
    check.add_argument('--allowlist', required=True)
    check.add_argument('--source-tar', required=True)
    check.add_argument('--receipt', required=True)
    check.add_argument('--ec253-policy')
    check.add_argument('--profile-id')
    args = parser.parse_args(argv)
    try:
        if args.action == 'prepare':
            outcome = prepare(args.repo, args.allowlist, args.output_dir)
        else:
            outcome = verify(args.repo, args.allowlist, args.source_tar,
                             args.receipt, args.ec253_policy, args.profile_id)
    except (CustodyError, OSError, runner.HostRunError) as exc:
        print(json.dumps({'status': 'unavailable', 'exit_code': 5,
                          'reason_code': getattr(exc, 'code',
                                                 'CUSTODY_HOST_UNAVAILABLE')},
                         sort_keys=True))
        return 5
    print(json.dumps(outcome, sort_keys=True))
    # Partial/2 deliberately NOT a trusted global Quality PASS.
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
