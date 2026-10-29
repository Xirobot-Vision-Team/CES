#!/usr/bin/env python3
"""EC181 standalone QualityDetect: authorized bounded local configuration inventory.

Read-only, never shells out, never imports code from the inspected tree, never
interprets package scripts, and never discovers paths outside an explicit list.
POSIX dirfd/O_NOFOLLOW access only. A recent root pin is a local filesystem
observation, NOT a Git/CI/actor identity, atomic tree snapshot or permission.
The host must supply separate trusted source and per-file grants on every read.
"""
from __future__ import annotations

import argparse
import configparser
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import stat
import sys
from typing import Any, Callable, Iterator

try:
    import tomllib
except ImportError:  # pragma: no cover - old Python cannot safely parse TOML
    tomllib = None

SCHEMA = 'ces.quality_detect.v1'
PIN_SCHEMA = 'ces.quality_source_pin.v1'
DOMAIN_PIN = b'CES-EC181-QUALITY-PIN-v1\x00'
DOMAIN_INVENTORY = b'CES-EC181-QUALITY-INVENTORY-v1\x00'
EXIT = {'partial': 2, 'invalid_input': 4, 'unavailable': 5}
MAX_PIN_AGE = 300
MAX_CLOCK_SKEW = 30
MAX_PATHS = 64
MAX_COMPONENTS = 4
MAX_ROOT_CHARS = 1024
MAX_FILE_BYTES = 128 * 1024
MAX_METADATA_FILE_BYTES = 128 * 1024 * 1024  # stat only; NEVER read lockfiles
MAX_TOTAL_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 192 * 1024
COMPONENT = re.compile(r'[A-Za-z0-9_.-]{1,80}\Z', re.ASCII)
WORKFLOW = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,75}\.ya?ml\Z', re.ASCII)
BLOCKED_COMPONENTS = frozenset({
    '.', '..', '.git', '.svn', '.hg', '.ssh', '.aws', '.venv', 'venv',
    'node_modules', '.cache', '.pnpm', '.next', '__pycache__', 'vendor',
    'dist', 'target', 'build', 'secrets', 'private',
})
# These are the ONLY eligible basenames. No README, arbitrary shell scripts,
# project executable, user-selected arbitrary file, or recursive walk.
PARSED = {
    'pyproject.toml': ('Python', 'toml'),
    'Cargo.toml': ('Rust', 'toml'),
    'package.json': ('JavaScript', 'json'),
    'pytest.ini': ('Python', 'ini'),
    'tox.ini': ('Python', 'ini'),
    'setup.cfg': ('Python', 'ini'),
}
METADATA_ONLY = {
    'requirements.txt': ('Python', 'dependency-list', 'python-dependencies'),
    'Pipfile': ('Python', 'dependency-list', 'pipenv'),
    'Pipfile.lock': ('Python', 'lockfile', 'pipenv'),
    'poetry.lock': ('Python', 'lockfile', 'poetry'),
    'uv.lock': ('Python', 'lockfile', 'uv'),
    'ruff.toml': ('Python', 'config', 'ruff'),
    '.ruff.toml': ('Python', 'config', 'ruff'),
    'mypy.ini': ('Python', 'config', 'mypy'),
    '.flake8': ('Python', 'config', 'flake8'),
    'setup.py': ('Python', 'executable-source-metadata-only', None),
    'Makefile': (None, 'untrusted-build-file', 'make'),
    'GNUmakefile': (None, 'untrusted-build-file', 'make'),
    'CMakeLists.txt': ('C++', 'untrusted-build-file', 'cmake'),
    'go.mod': ('Go', 'module-config', 'go'),
    'go.work': ('Go', 'workspace-config', 'go'),
    'go.sum': ('Go', 'lockfile', None),
    'Cargo.lock': ('Rust', 'lockfile', None),
    'rust-toolchain.toml': ('Rust', 'toolchain-claim', None),
    'pom.xml': ('Java', 'unparsed-xml-config', 'maven'),
    'build.gradle': ('Java', 'untrusted-build-file', 'gradle'),
    'build.gradle.kts': ('Kotlin', 'untrusted-build-file', 'gradle'),
    'settings.gradle': ('Java', 'untrusted-build-file', 'gradle'),
    'settings.gradle.kts': ('Kotlin', 'untrusted-build-file', 'gradle'),
    'gradlew': (None, 'untrusted-executable-metadata-only', None),
    'package-lock.json': ('JavaScript', 'lockfile', 'npm'),
    'pnpm-lock.yaml': ('JavaScript', 'lockfile', 'pnpm'),
    'yarn.lock': ('JavaScript', 'lockfile', 'yarn'),
    'bun.lock': ('JavaScript', 'lockfile', 'bun'),
    'bun.lockb': ('JavaScript', 'lockfile', 'bun'),
    'tsconfig.json': ('TypeScript', 'jsonc-config-metadata-only', 'typescript'),
    'eslint.config.js': ('JavaScript', 'untrusted-config-module', 'eslint'),
    'eslint.config.mjs': ('JavaScript', 'untrusted-config-module', 'eslint'),
    'eslint.config.cjs': ('JavaScript', 'untrusted-config-module', 'eslint'),
    'vitest.config.ts': ('TypeScript', 'untrusted-config-module', 'vitest'),
    'jest.config.js': ('JavaScript', 'untrusted-config-module', 'jest'),
    'playwright.config.ts': ('TypeScript', 'untrusted-config-module', 'playwright'),
    '.gitlab-ci.yml': (None, 'ci-config', 'gitlab-ci-config'),
    '.pre-commit-config.yaml': (None, 'untrusted-hook-config', 'pre-commit'),
}
SAFE_SCRIPT_KEYS = ('test', 'build', 'lint', 'typecheck', 'check', 'format')
DEPENDENCY_TO_TOOL = {
    'pytest': 'pytest', 'ruff': 'ruff', 'mypy': 'mypy', 'tox': 'tox',
    'coverage': 'coverage', 'black': 'black',
    'typescript': 'typescript', 'vitest': 'vitest', 'jest': 'jest',
    'eslint': 'eslint', 'prettier': 'prettier', 'playwright': 'playwright',
    '@playwright/test': 'playwright', 'ts-node': 'typescript',
}
TOOL_ROLES = {
    'pytest': 'test', 'ruff': 'lint', 'mypy': 'typecheck', 'tox': 'test',
    'coverage': 'coverage', 'black': 'format', 'typescript': 'typecheck',
    'vitest': 'test', 'jest': 'test', 'eslint': 'lint',
    'prettier': 'format', 'playwright': 'test', 'make': 'build',
    'cmake': 'build', 'maven': 'build', 'gradle': 'build',
    'go': 'build', 'cargo': 'build', 'npm': 'package-manager',
    'pnpm': 'package-manager', 'yarn': 'package-manager',
    'bun': 'package-manager', 'poetry': 'package-manager',
    'uv': 'package-manager', 'pipenv': 'package-manager',
    'python-dependencies': 'dependencies', 'pre-commit': 'hook-config',
    'gitlab-ci-config': 'ci-config', 'github-actions-config': 'ci-config',
    'flake8': 'lint',
}
# QualityRun/CI are later ECs. These IDs are descriptors, not runnable argv.
PROFILE_HINTS = {
    'pytest': 'python.pytest', 'ruff': 'python.ruff',
    'mypy': 'python.mypy', 'tox': 'python.tox',
    'vitest': 'node.vitest', 'jest': 'node.jest',
    'eslint': 'node.eslint', 'typescript': 'node.typescript',
    'playwright': 'node.playwright',
}
DIR_FLAGS = (os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) |
             getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0) |
             getattr(os, 'O_NONBLOCK', 0))
FILE_FLAGS = (os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
              getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0))


class QualityError(ValueError):
    def __init__(self, code: str, status: str = 'unavailable') -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def _require(condition: bool, code: str, status: str = 'invalid_input') -> None:
    if not condition:
        raise QualityError(code, status)


def _canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _sha(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + _canon(value)).hexdigest()


def _now(clock: Callable[[], datetime] | None) -> datetime:
    try:
        value = clock() if clock else datetime.now(timezone.utc)
        _require(type(value) is datetime and value.tzinfo is not None and
                 value.utcoffset() is not None, 'QUALITYDETECT_CLOCK_INVALID')
        value = value.astimezone(timezone.utc).replace(microsecond=0)
        _require(2000 <= value.year <= 9998, 'QUALITYDETECT_CLOCK_INVALID')
        return value
    except QualityError:
        raise
    except (Exception,):
        # A host-injected clock is not authority; never publish from a broken one.
        raise QualityError('QUALITYDETECT_CLOCK_UNAVAILABLE') from None


def _stamp(moment: datetime) -> str:
    return moment.isoformat(timespec='seconds').replace('+00:00', 'Z')


def _parse_time(value: Any) -> datetime:
    _require(type(value) is str and re.fullmatch(
        r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value) is not None,
        'QUALITYDETECT_PIN_TIME_INVALID')
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise QualityError('QUALITYDETECT_PIN_TIME_INVALID', 'invalid_input') from exc


def _supported() -> None:
    _require(os.name == 'posix' and all(hasattr(os, c) for c in
             ('O_NOFOLLOW', 'O_DIRECTORY', 'O_NONBLOCK')) and
             os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd,
             'QUALITYDETECT_SECURE_POSIX_NOFOLLOW_DIRFD_UNAVAILABLE', 'unavailable')


def _root_parts(root: Any) -> list[str]:
    _require(type(root) is str and 2 <= len(root) <= MAX_ROOT_CHARS and
             root.startswith('/') and not root.endswith('/') and
             '//' not in root and '\x00' not in root and
             os.path.normpath(root) == root and
             all(32 <= ord(x) < 127 for x in root),
             'QUALITYDETECT_ROOT_PATH_INVALID')
    parts = root.split('/')[1:]
    _require(all(x not in ('', '.', '..') for x in parts),
             'QUALITYDETECT_ROOT_PATH_INVALID')
    return parts


def _select_paths(paths: Any) -> list[tuple[str, str, str | None, str, str | None]]:
    _require(type(paths) is list and 0 < len(paths) <= MAX_PATHS,
             'QUALITYDETECT_PATH_ALLOWLIST_SIZE_INVALID')
    result = []
    seen = set()
    for raw in paths:
        _require(type(raw) is str and 0 < len(raw) <= 320 and '\\' not in raw and
                 '\x00' not in raw, 'QUALITYDETECT_SELECTED_PATH_INVALID')
        parts = raw.split('/')
        _require(1 <= len(parts) <= MAX_COMPONENTS and
                 all(COMPONENT.fullmatch(p) and p.casefold() not in BLOCKED_COMPONENTS
                     and p not in ('.', '..') for p in parts),
                 'QUALITYDETECT_SELECTED_PATH_INVALID')
        _require(raw.casefold() not in seen, 'QUALITYDETECT_SELECTED_PATH_COLLISION')
        seen.add(raw.casefold())
        basename = parts[-1]
        if len(parts) == 3 and parts[:2] == ['.github', 'workflows'] and WORKFLOW.fullmatch(basename):
            result.append((raw, 'ci-config', None, 'github-actions-config', None))
        elif basename in PARSED:
            language, parser = PARSED[basename]
            result.append((raw, 'parse', language, parser, None))
        elif basename in METADATA_ONLY:
            language, kind, tool = METADATA_ONLY[basename]
            result.append((raw, kind, language, 'metadata', tool))
        else:
            raise QualityError('QUALITYDETECT_UNRECOGNIZED_OR_EXECUTABLE_PATH', 'invalid_input')
    return sorted(result)


def _identity(s: os.stat_result) -> dict[str, int]:
    return {'device': int(s.st_dev), 'inode': int(s.st_ino),
            'mtime_ns': int(s.st_mtime_ns), 'ctime_ns': int(s.st_ctime_ns)}


def _stable(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_dev, a.st_ino, a.st_mode, a.st_size, a.st_mtime_ns,
            a.st_ctime_ns, a.st_nlink) == (b.st_dev, b.st_ino, b.st_mode,
                                          b.st_size, b.st_mtime_ns, b.st_ctime_ns,
                                          b.st_nlink)


@contextmanager
def _open_root(root: str) -> Iterator[int]:
    _supported()
    parts = _root_parts(root)
    fd = -1
    try:
        try:
            fd = os.open('/', DIR_FLAGS)
            for part in parts:
                child = os.open(part, DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
            _require(stat.S_ISDIR(os.fstat(fd).st_mode),
                     'QUALITYDETECT_REPOSITORY_NOT_DIRECTORY', 'unavailable')
        except OSError as exc:
            raise QualityError('QUALITYDETECT_ROOT_MISSING_UNSAFE_OR_SYMLINKED') from exc
        yield fd
    finally:
        if fd >= 0:
            os.close(fd)


def _grant(callback: Any, facts: dict[str, Any], code: str) -> None:
    _require(callable(callback), code, 'unavailable')
    try:
        allowed = callback(facts)
    except Exception as exc:
        raise QualityError(code, 'unavailable') from exc
    _require(allowed is True, code, 'unavailable')


def _read_candidate(root_fd: int, relative: str, *, read_bytes: bool) -> tuple[bool, bytes | None, os.stat_result | None]:
    """Walk only explicitly permitted components; recheck namespace and fstats."""
    pieces = relative.split('/')
    chain = []
    parent_fd = -1
    file_fd = -1
    try:
        parent_fd = os.dup(root_fd)
        for item in pieces[:-1]:
            try:
                child_fd = os.open(item, DIR_FLAGS, dir_fd=parent_fd)
            except FileNotFoundError:
                return False, None, None
            except OSError as exc:
                raise QualityError('QUALITYDETECT_SELECTED_PARENT_UNSAFE') from exc
            dstat = os.fstat(child_fd)
            _require(stat.S_ISDIR(dstat.st_mode), 'QUALITYDETECT_SELECTED_PARENT_UNSAFE', 'unavailable')
            chain.append((item, _identity(dstat)))
            os.close(parent_fd)
            parent_fd = child_fd
        try:
            if read_bytes:
                file_fd = os.open(pieces[-1], FILE_FLAGS, dir_fd=parent_fd)
                before = os.fstat(file_fd)
            else:
                # Metadata grants never create a content-readable file FD.
                before = os.stat(pieces[-1], dir_fd=parent_fd,
                                 follow_symlinks=False)
        except FileNotFoundError:
            return False, None, None
        except OSError as exc:
            raise QualityError('QUALITYDETECT_SELECTED_FILE_UNSAFE') from exc
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 0 <= before.st_size <= (MAX_FILE_BYTES if read_bytes else MAX_METADATA_FILE_BYTES),
                 'QUALITYDETECT_NONREGULAR_HARDLINK_OR_OVERSIZED_FILE', 'unavailable')
        raw = None
        if read_bytes:
            chunks = []
            remaining = MAX_FILE_BYTES + 1
            while remaining:
                part = os.read(file_fd, min(65536, remaining))
                if not part:
                    break
                chunks.append(part)
                remaining -= len(part)
            raw = b''.join(chunks)
            _require(len(raw) <= MAX_FILE_BYTES and len(raw) == before.st_size,
                     'QUALITYDETECT_FILE_SIZE_CHANGED_OR_OVER_LIMIT', 'unavailable')
        try:
            after = (os.fstat(file_fd) if read_bytes else
                     os.stat(pieces[-1], dir_fd=parent_fd, follow_symlinks=False))
        except OSError as exc:
            raise QualityError('QUALITYDETECT_FILE_DRIFT_DURING_READ') from exc
        _require(_stable(before, after), 'QUALITYDETECT_FILE_DRIFT_DURING_READ', 'unavailable')
        try:
            named = os.stat(pieces[-1], dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise QualityError('QUALITYDETECT_FILE_PATH_DRIFT') from exc
        _require(_stable(before, named), 'QUALITYDETECT_FILE_PATH_DRIFT', 'unavailable')
        # Re-walk every nested path by name after read to reject directory
        # swap/reparent during inspection; an open FD alone is not containment.
        check_fd = os.dup(root_fd)
        try:
            for part, prior_id in chain:
                try:
                    next_fd = os.open(part, DIR_FLAGS, dir_fd=check_fd)
                except OSError as exc:
                    raise QualityError('QUALITYDETECT_PARENT_DRIFT') from exc
                os.close(check_fd)
                check_fd = next_fd
                _require(_identity(os.fstat(check_fd)) == prior_id,
                         'QUALITYDETECT_PARENT_DRIFT', 'unavailable')
        finally:
            os.close(check_fd)
        return True, raw, before
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if parent_fd >= 0:
            os.close(parent_fd)


def _json_unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError('duplicate json key')
        obj[k] = v
    return obj


def _parse_config(path: str, parser: str, raw: bytes) -> tuple[str, set[str], list[str], str | None]:
    tools: set[str] = set()
    script_keys: list[str] = []
    language_override = None
    try:
        text = raw.decode('utf-8', 'strict')
        if '\x00' in text:
            raise ValueError('binary config')
        if parser == 'toml':
            if tomllib is None:
                return 'PARSER_UNAVAILABLE', tools, script_keys, language_override
            doc = tomllib.loads(text)
            if path.endswith('pyproject.toml'):
                cfg = doc.get('tool', {})
                if not isinstance(cfg, dict):
                    raise ValueError('invalid tool mapping')
                for key in ('pytest', 'ruff', 'mypy', 'tox', 'black', 'poetry', 'uv'):
                    if key in cfg and isinstance(cfg[key], dict):
                        tools.add(key)
                # Parse only package NAMES from PEP 621 requirement declarations,
                # never URL/markers, package installer hooks or backend commands.
                project = doc.get('project', {})
                if isinstance(project, dict):
                    declared = project.get('dependencies', [])
                    extras = project.get('optional-dependencies', {})
                    if isinstance(extras, dict):
                        for group in list(extras.values())[:16]:
                            if isinstance(group, list):
                                declared = (declared if isinstance(declared, list) else []) + group[:32]
                    if isinstance(declared, list):
                        for item in declared[:256]:
                            if isinstance(item, str):
                                match = re.match(r'\s*(pytest|ruff|mypy|tox|coverage|black)'
                                                 r'(?=\s|\[|[<>=!~;]|$)', item, re.I)
                                if match:
                                    tools.add(match.group(1).lower())
                # Build backend strings are inert declarations. Never import them.
                build = doc.get('build-system', {})
                if isinstance(build, dict) and isinstance(build.get('requires'), list):
                    for item in build['requires'][:32]:
                        if isinstance(item, str) and re.match(r'\s*poetry-core(?=\s|[<>=!~;]|$)', item, re.I):
                            tools.add('poetry')
            elif path.endswith('Cargo.toml'):
                tools.add('cargo')
        elif parser == 'json':
            doc = json.loads(text, object_pairs_hook=_json_unique,
                             parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
            if not isinstance(doc, dict):
                raise ValueError('manifest not object')
            scripts = doc.get('scripts', {})
            if scripts is not None and not isinstance(scripts, dict):
                raise ValueError('invalid scripts type')
            # Script names alone are inert hints. NEVER inspect, output, or run values.
            script_keys = [k for k in SAFE_SCRIPT_KEYS if k in (scripts or {})]
            for key in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
                section = doc.get(key, {})
                if section is not None and not isinstance(section, dict):
                    raise ValueError('invalid dependency section')
                for name in section or {}:
                    if name in DEPENDENCY_TO_TOOL:
                        tools.add(DEPENDENCY_TO_TOOL[name])
            manager = doc.get('packageManager')
            if isinstance(manager, str):
                key = manager.split('@', 1)[0]
                if key in ('npm', 'pnpm', 'yarn', 'bun'):
                    tools.add(key)
            if 'typescript' in tools:
                language_override = 'TypeScript'
        elif parser == 'ini':
            cfg = configparser.ConfigParser(interpolation=None, strict=True)
            cfg.read_string(text)
            if path.endswith('pytest.ini') or cfg.has_section('tool:pytest'):
                tools.add('pytest')
            if path.endswith('tox.ini') or cfg.has_section('tox'):
                tools.add('tox')
            if cfg.has_section('flake8'):
                tools.add('flake8')
            if cfg.has_section('mypy'):
                tools.add('mypy')
        else:
            raise ValueError('unsupported parser')
        return 'PARSED', tools, script_keys, language_override
    except (ValueError, UnicodeError, TypeError, OverflowError, RecursionError, configparser.Error):
        # Error details and the bytes themselves may include secrets or scripts.
        return 'MALFORMED_CONFIG', set(), [], None


def _empty(status: str, reason: str) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': status, 'exit_code': EXIT[status],
        'reason_code': reason, 'source': None, 'files': [], 'languages': [],
        'tools': [], 'profile_hints': [], 'coverage': None,
        'inventory_sha256': None, 'effects': {'executed_commands': False,
        'read_only': True, 'network_access': False, 'writes_performed': False},
        'trust_boundary': 'LOCAL_CONFIG_ONLY_NO_GIT_CI_TEST_RUN_OR_COMMAND_AVAILABILITY',
    }


class QualityDetector:
    @staticmethod
    def observe_root(repo_root: str, *, authorize_observation: Callable[[dict[str, Any]], bool],
                     clock: Callable[[], datetime] | None = None) -> dict[str, Any]:
        """Obtain recent local root identity, with separate explicit root grant."""
        _root_parts(repo_root)
        _grant(authorize_observation, {'purpose': 'QUALITYDETECT_OBSERVE_LOCAL_ROOT',
                'source_mode': 'WorkingTree', 'repo_root': repo_root},
               'QUALITYDETECT_ROOT_OBSERVATION_NOT_AUTHORIZED')
        observed = _now(clock)
        with _open_root(repo_root) as fd:
            identity = _identity(os.fstat(fd))
        return {
            'schema': PIN_SCHEMA, 'source_mode': 'WorkingTree',
            'repo_root': repo_root, 'root_identity': identity,
            'observed_at_utc': _stamp(observed),
        }

    @staticmethod
    def detect(repo_root: str, source_pin: dict[str, Any], *,
               candidate_paths: list[str],
               authorize_source: Callable[[dict[str, Any]], bool],
               authorize_path: Callable[[dict[str, Any]], bool],
               clock: Callable[[], datetime] | None = None) -> dict[str, Any]:
        """Atomic-on-refusal bounded inventory, not an atomic multi-file snapshot."""
        try:
            _root_parts(repo_root)
            selected = _select_paths(candidate_paths)
            _require(type(source_pin) is dict and set(source_pin) == {
                'schema', 'source_mode', 'repo_root', 'root_identity', 'observed_at_utc'
            } and source_pin['schema'] == PIN_SCHEMA and
                source_pin['source_mode'] == 'WorkingTree' and
                source_pin['repo_root'] == repo_root,
                'QUALITYDETECT_EXACT_WORKINGTREE_PIN_REQUIRED')
            identity = source_pin['root_identity']
            _require(type(identity) is dict and set(identity) == {
                'device', 'inode', 'mtime_ns', 'ctime_ns'} and
                all(type(v) is int and v >= 0 for v in identity.values()),
                'QUALITYDETECT_PIN_IDENTITY_INVALID')
            now = _now(clock)
            age = (now - _parse_time(source_pin['observed_at_utc'])).total_seconds()
            _require(-MAX_CLOCK_SKEW <= age <= MAX_PIN_AGE,
                     'QUALITYDETECT_PIN_NOT_FRESH', 'unavailable')
            pin_hash = _sha(DOMAIN_PIN, source_pin)
            _grant(authorize_source, {'purpose': 'QUALITYDETECT_READ_SOURCE_CONFIGURATION',
                   'source_mode': 'WorkingTree', 'repo_root': repo_root,
                   'root_identity': dict(identity), 'source_pin_sha256': pin_hash,
                   'observed_at_utc': source_pin['observed_at_utc'],
                   'candidate_paths': [r[0] for r in selected]},
                   'QUALITYDETECT_SOURCE_GRANT_DENIED')
            files = []
            by_language: dict[str, set[str]] = {}
            by_tool: dict[str, set[str]] = {}
            total = 0
            with _open_root(repo_root) as root_fd:
                first = os.fstat(root_fd)
                _require(_identity(first) == identity,
                         'QUALITYDETECT_PINNED_ROOT_DRIFT', 'unavailable')
                for path, kind, language, parser, metadata_tool in selected:
                    reading = kind == 'parse'
                    _grant(authorize_path, {'purpose': ('QUALITYDETECT_READ_CONFIG_BYTES'
                           if reading else 'QUALITYDETECT_READ_CONFIG_METADATA'),
                           'source_mode': 'WorkingTree', 'repo_root': repo_root,
                           'root_identity': dict(identity),
                           'source_pin_sha256': pin_hash, 'path': path,
                           'read_file_bytes': reading},
                           'QUALITYDETECT_FILE_GRANT_DENIED')
                    present, raw, st = _read_candidate(root_fd, path, read_bytes=reading)
                    if not present:
                        files.append({'path': path, 'state': 'ABSENT', 'bytes': None,
                                      'sha256': None, 'parse_state': 'NOT_AVAILABLE',
                                      'declared_script_keys': []})
                        continue
                    if reading:
                        total += len(raw or b'')
                        _require(total <= MAX_TOTAL_BYTES,
                                 'QUALITYDETECT_CUMULATIVE_CONTENT_SIZE_EXCEEDED', 'unavailable')
                        parse_state, recognized, script_keys, override = _parse_config(path, parser, raw or b'')
                        sha = hashlib.sha256(raw or b'').hexdigest()
                    else:
                        parse_state, recognized, script_keys, override = (
                            'METADATA_ONLY_NOT_EXECUTED_OR_PARSED', set(), [], None)
                        sha = None  # bytes were not granted, so never hash them
                    files.append({'path': path, 'state': 'PRESENT', 'bytes': st.st_size,
                                  'sha256': sha, 'parse_state': parse_state,
                                  'declared_script_keys': script_keys})
                    if language:
                        by_language.setdefault(override or language, set()).add(path)
                    if metadata_tool:
                        recognized.add(metadata_tool)
                    if kind == 'ci-config':
                        recognized.add('github-actions-config')
                    for tool in recognized:
                        by_tool.setdefault(tool, set()).add(path)
                _require(_identity(os.fstat(root_fd)) == identity,
                         'QUALITYDETECT_ROOT_CHANGED_DURING_SCAN', 'unavailable')
                # A root FD may survive after its pathname is rebound. Re-open the
                # exact named root and compare its identity before publishing.
                with _open_root(repo_root) as named_fd:
                    _require(_identity(os.fstat(named_fd)) == identity,
                             'QUALITYDETECT_NAMED_ROOT_REPLACED', 'unavailable')
            languages = [
                {'language': name, 'evidence_paths': sorted(evidence),
                 'finding': 'CONFIG_FILE_EVIDENCE_ONLY'}
                for name, evidence in sorted(by_language.items())
            ]
            tools = [
                {'tool_family': name, 'role': TOOL_ROLES.get(name, 'config-claim'),
                 'evidence_paths': sorted(evidence),
                 'discovery_state': 'CONFIG_DECLARATION_ONLY',
                 'installed': 'NOT_CHECKED', 'command_usable': 'NOT_CHECKED',
                 'executed': False}
                for name, evidence in sorted(by_tool.items())
            ]
            profile_hints = [
                {'profile_id': PROFILE_HINTS[t['tool_family']],
                 'based_on_tool': t['tool_family'],
                 'execution_state': 'NOT_RUN_AND_NOT_AUTHORIZED',
                 'runnable_command_provided': False}
                for t in tools if t['tool_family'] in PROFILE_HINTS
            ]
            malformed = sum(f['parse_state'] in ('MALFORMED_CONFIG', 'PARSER_UNAVAILABLE') for f in files)
            coverage = {
                'selected_paths': len(files),
                'present_paths': sum(f['state'] == 'PRESENT' for f in files),
                'absent_selected_paths': sum(f['state'] == 'ABSENT' for f in files),
                'parsed_configs': sum(f['parse_state'] == 'PARSED' for f in files),
                'unparsed_or_malformed_configs': malformed,
                'read_config_bytes': total,
                'inventory_complete_for_explicit_allowlist': True,
                'repository_wide_inventory_complete': False,
                'git_sha_authenticated': False,
                'source_currentness_proven': False,
                'cross_file_atomic_snapshot_proven': False,
                'dependencies_installed_verified': False,
                'commands_usable_verified': False,
                'tests_executed': False,
                'ci_results_read': False,
                'profile_execution_permitted': False,
            }
            source = {'source_mode': 'WorkingTree', 'local_root_pin_sha256': pin_hash,
                      'root_identity_matched_on_scan': True,
                      'root_observed_at_utc': source_pin['observed_at_utc'],
                      'scanned_at_utc': _stamp(now),
                      'root_path_redacted': True}
            body = {'source': source, 'files': files, 'languages': languages,
                    'tools': tools, 'profile_hints': profile_hints,
                    'coverage': coverage}
            result = _empty('partial', 'QUALITYDETECT_BOUNDED_CONFIG_DISCOVERY_NOT_COMMAND_VERIFICATION')
            result.update(body)
            result['inventory_sha256'] = _sha(DOMAIN_INVENTORY, body)
            _require(len(_canon(result)) <= MAX_OUTPUT_BYTES,
                     'QUALITYDETECT_RESULT_SIZE_BOUND', 'unavailable')
            return result
        except QualityError as exc:
            return _empty(exc.status, exc.code)
        except (OSError, ValueError, TypeError, KeyError, OverflowError,
                RecursionError, MemoryError, UnicodeError):
            return _empty('unavailable', 'QUALITYDETECT_UNSAFE_FILESYSTEM_OR_INPUT_UNAVAILABLE')


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description='EC181 authorized local config evidence only; no execution')
    ap.add_argument('--repo-root', required=True, help='exact absolute unsymlinked working-tree path')
    ap.add_argument('--path', action='append', required=True,
                    help='explicit allowlisted config path, repeatable; NO directory walk')
    ap.add_argument('--allow-root-observation', action='store_true')
    ap.add_argument('--allow-config-metadata', action='store_true')
    ap.add_argument('--allow-config-bytes', action='store_true')
    ap.add_argument('--json', action='store_true', help='emit one machine JSON response')
    args = ap.parse_args(argv)
    try:
        pin = QualityDetector.observe_root(
            args.repo_root, authorize_observation=lambda _: args.allow_root_observation)
        result = QualityDetector.detect(
            args.repo_root, pin, candidate_paths=args.path,
            authorize_source=lambda _: args.allow_config_metadata,
            authorize_path=lambda req: (args.allow_config_bytes if req['read_file_bytes']
                                        else args.allow_config_metadata))
    except QualityError as exc:
        result = _empty(exc.status, exc.code)
    except (OSError, ValueError, TypeError, KeyError):
        result = _empty('unavailable', 'QUALITYDETECT_UNSAFE_FILESYSTEM_OR_INPUT_UNAVAILABLE')
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(',', ':')))
    return result['exit_code']


if __name__ == '__main__':
    sys.exit(main())
