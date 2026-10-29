#!/usr/bin/env python3
"""EC248 opt-in, resource-bounded subprocess for the *unchanged* native CodeShow Sequence.

This does not implement the k1..56 mathematics, mutate original PowerShell, or
register a new CES Action. Linux/POSIX OS resource limits cover each executable,
not an aggregate process tree or independent sandbox. Missing support fails closed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / 'scripts' / 'ces.ps1'
LOCK = ROOT / 'construction' / 'SECURITY_SOURCE_LOCK.json'
AUDIT = ROOT / 'construction' / 'LEGACY_SEQUENCE_AUDIT.json'
NATIVE_ID = re.compile(r'ci-[0-9a-f]{64}\Z', re.ASCII)
FINDING_ID = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,31}\Z', re.ASCII)
IMPORT = re.compile(r"(?m)^\. \(Join-Path \$PSScriptRoot '([a-z0-9]+\.ps1)'\)\s*$")
# Each parameter is forwarded unchanged; avoid forwarding unrelated source/write switches.
SELECTORS = (
    ('sequence_path', 'SequencePath'),
    ('sequence_finding_record_id', 'SequenceFindingRecordId'),
    ('sequence_finding_id', 'SequenceFindingId'),
    ('sequence_anchor_index', 'SequenceAnchorIndex'),
    ('sequence_pair_index', 'SequencePairIndex'),
    ('sequence_pair_overview_index', 'SequencePairOverviewIndex'),
    ('sequence_pair_path_index', 'SequencePairPathIndex'),
    ('sequence_pair_path_anchor_index', 'SequencePairPathAnchorIndex'),
    ('sequence_pair_path_anchor_finding_side', 'SequencePairPathAnchorFindingSide'),
    ('sequence_pair_path_anchor_finding_index', 'SequencePairPathAnchorFindingIndex'),
    ('sequence_pair_path_anchor_finding_counterpart_index', 'SequencePairPathAnchorFindingCounterpartIndex'),
)
ORDINAL_LIMITS = {
    'sequence_anchor_index': 480,
    'sequence_pair_index': 66,
    'sequence_pair_overview_index': 66,
    'sequence_pair_path_index': 480,
    'sequence_pair_path_anchor_index': 480,
    'sequence_pair_path_anchor_finding_index': 40,
    'sequence_pair_path_anchor_finding_counterpart_index': 40,
}


class GuardError(Exception):
    def __init__(self, code: str, description: str):
        super().__init__(description)
        self.code = code


@dataclass(frozen=True)
class Limits:
    wall_seconds: float = 120
    cpu_seconds: int = 120
    virtual_memory_mib: int = 8192
    output_mib: int = 8

    def check(self) -> None:
        if not (5 <= self.wall_seconds <= 900):
            raise GuardError('GUARD_BUDGET_INVALID', 'wall timeout must be between 5 and 900 seconds')
        if not (5 <= self.cpu_seconds <= 900):
            raise GuardError('GUARD_BUDGET_INVALID', 'CPU limit must be between 5 and 900 seconds')
        if not (1024 <= self.virtual_memory_mib <= 32768):
            raise GuardError('GUARD_BUDGET_INVALID', 'virtual memory limit must be 1024..32768 MiB')
        if not (1 <= self.output_mib <= 16):
            raise GuardError('GUARD_BUDGET_INVALID', 'combined output limit must be 1..16 MiB')


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_profile(root: Path = ROOT) -> dict[str, Any]:
    """Reject source drift, bound all real static imports and k1..56 published shape.

    Source lock is a local provenance consistency check, never a trusted signature.
    """
    try:
        lock = json.loads((root / 'construction/SECURITY_SOURCE_LOCK.json').read_text('utf-8'))
        audit = json.loads((root / 'construction/LEGACY_SEQUENCE_AUDIT.json').read_text('utf-8'))
        pins = lock['source_sha256']
        cli_text = (root / 'scripts/ces.ps1').read_text('utf-8')
        imports = IMPORT.findall(cli_text)
        chain = audit['compatibility_invariants']['k_outputs_in_order']
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        raise GuardError('GUARD_SOURCE_UNAVAILABLE', 'local source inventory is unavailable') from exc
    if len(imports) != 124 or len(set(imports)) != 124:
        raise GuardError('GUARD_IMPORT_DRIFT', 'legacy unconditional import list changed')
    if len(chain) != 56 or [c['k'] for c in chain] != list(range(1, 57)):
        raise GuardError('GUARD_CHAIN_DRIFT', 'original k1..56 inventory changed')
    required = ['scripts/ces.ps1'] + ['scripts/' + name for name in imports]
    # The checked native import chain is deliberately exhaustive, not just 59 audit inputs.
    checked_bytes = 0
    for rel in required:
        path = root / rel
        try:
            if not path.is_file() or path.is_symlink() or _sha(path) != pins[rel]:
                raise GuardError('GUARD_SOURCE_DRIFT', 'original legacy source hash does not match local EC244 source lock')
            checked_bytes += path.stat().st_size
        except (OSError, KeyError) as exc:
            raise GuardError('GUARD_SOURCE_DRIFT', 'original legacy source is missing or not pinned') from exc
    for entry in chain:
        if entry['module'] not in required:
            raise GuardError('GUARD_CHAIN_DRIFT', 'k module not included in original source imports')
    if 'scripts/codeshow.ps1' not in required or 'scripts/codesequence.ps1' not in required:
        raise GuardError('GUARD_IMPORT_DRIFT', 'CodeShow dispatch or Sequence processor missing')
    if audit['dependency_profile']['direct_parent_replay_count'] != 19:
        raise GuardError('GUARD_CHAIN_DRIFT', 'parent replay audit no longer matches the frozen assessment')
    return {
        'schema': 'ces.ec248.load_assessment.v1',
        'route': 'CodeShow/Sequence',
        'native_cli_version': 'V4.60/R150',
        'unconditional_imports': len(imports),
        'ec154_audit_import_count_excluding_early_pathidentity': len(imports) - 1,
        'import_plus_cli_source_bytes': checked_bytes,
        'k_modules': len(chain),
        'highest_k': 56,
        'explicit_parent_replay_edges': 19,
        'lazy_loading': 'ASSESS_ONLY_NOT_ENABLED',
        'reason': 'Global function/module dependencies, positional compatibility, and dynamic calls are not proven safe for runtime lazy loading.',
        'source_hash_scope': 'EC244 pinned native main and all 124 literal imports (123 modules after early pathidentity), local only',
    }


def _validate_record_ids(value: str) -> None:
    if not isinstance(value, str) or len(value) > 815:
        raise GuardError('GUARD_SELECTORS_INVALID', 'invalid legacy selected ID list')
    parts = value.split(',')
    if not (2 <= len(parts) <= 12) or len(parts) != len(set(parts)) or any(not NATIVE_ID.fullmatch(p) for p in parts):
        raise GuardError('GUARD_SELECTORS_INVALID', 'Sequence needs 2..12 distinct canonical ci-SHA256 IDs')


def validate_request(ns: argparse.Namespace) -> None:
    if not ns.repo_path or not os.path.isabs(ns.repo_path) or '\x00' in ns.repo_path:
        raise GuardError('GUARD_SELECTORS_INVALID', 'RepoPath must be an absolute filesystem path')
    _validate_record_ids(ns.record_ids)
    if ns.top < 1 or ns.top > 20:
        raise GuardError('GUARD_SELECTORS_INVALID', 'SequenceTop must be 1..20')
    for key, _ in SELECTORS:
        value = getattr(ns, key)
        if value is None:
            continue
        if not isinstance(value, str) or not value or '\x00' in value:
            raise GuardError('GUARD_SELECTORS_INVALID', 'empty or invalid Sequence selector')
        if len(value) > 4096:
            raise GuardError('GUARD_SELECTORS_INVALID', 'Sequence selector too long')
        if key in ORDINAL_LIMITS:
            if not re.fullmatch(r'[1-9][0-9]{0,2}', value) or int(value) > ORDINAL_LIMITS[key]:
                raise GuardError('GUARD_SELECTORS_INVALID', 'invalid Sequence ordinal selector')
    if ns.sequence_finding_record_id is not None and not NATIVE_ID.fullmatch(ns.sequence_finding_record_id):
        raise GuardError('GUARD_SELECTORS_INVALID', 'invalid focused record ID')
    if ns.sequence_finding_id is not None and not FINDING_ID.fullmatch(ns.sequence_finding_id):
        raise GuardError('GUARD_SELECTORS_INVALID', 'invalid focused finding ID')
    if ns.sequence_pair_path_anchor_finding_side is not None and ns.sequence_pair_path_anchor_finding_side not in ('left', 'right'):
        raise GuardError('GUARD_SELECTORS_INVALID', 'finding side must be left or right')
    # Let the original native CLI validate the remaining cross-selector exclusivity
    # and path semantics; do not silently alter its selection rules.


def build_command(ns: argparse.Namespace, executable: str) -> list[str]:
    result = [executable, '-NoProfile', '-NonInteractive', '-File', str(CLI),
              '-Action', 'CodeShow', '-Mode', 'Sequence', '-RepoPath', ns.repo_path,
              '-SequenceRecordIds', ns.record_ids, '-SequenceTop', str(ns.top)]
    for key, native in SELECTORS:
        value = getattr(ns, key)
        if value is not None:
            result.extend(['-' + native, value])
    result.append('-Json')
    return result


def _require_supported_host() -> Any:
    if os.name != 'posix':
        raise GuardError('GUARD_UNSUPPORTED_HOST', 'OS CPU and per-process virtual memory guard is available only on POSIX')
    try:
        import resource
        if not hasattr(resource, 'RLIMIT_CPU') or not hasattr(resource, 'RLIMIT_AS'):
            raise ImportError('rlimit not implemented')
    except ImportError as exc:
        raise GuardError('GUARD_UNSUPPORTED_HOST', 'CPU/virtual-memory rlimits not available') from exc
    return resource


def _limit_child(limits: Limits, resource: Any) -> None:
    # Per-process hard caps (not whole-container quotas); executed before exec.
    cpu = int(limits.cpu_seconds)
    memory = int(limits.virtual_memory_mib) * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    os.umask(0o077)


def _terminate_group(proc: subprocess.Popen[bytes], *, force: bool = False) -> None:
    if not force and proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        proc.kill()


def run_bounded(argv: list[str], limits: Limits) -> tuple[bytes, bytes, int]:
    """Read stdout+stderr incrementally. Never release partial output on guard fault.

    Caller must run preflight validation and source pin checks first. This helper
    is kept injectable for local synthetic children without needing PowerShell.
    """
    resource = _require_supported_host()
    deadline = time.monotonic() + limits.wall_seconds
    output_cap = limits.output_mib * 1024 * 1024
    proc: subprocess.Popen[bytes] | None = None
    out = bytearray()
    err = bytearray()
    selector = selectors.DefaultSelector()
    completed = False
    try:
        proc = subprocess.Popen(
            argv, cwd=str(ROOT), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
            close_fds=True, start_new_session=True,
            preexec_fn=lambda: _limit_child(limits, resource),
        )
        assert proc.stdout is not None and proc.stderr is not None
        for stream, target in ((proc.stdout, out), (proc.stderr, err)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, target)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GuardError('GUARD_WALL_TIMEOUT', 'native CodeShow Sequence exceeded wall timeout')
            for key, _ in selector.select(timeout=min(remaining, .2)):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if len(out) + len(err) + len(data) > output_cap:
                    raise GuardError('GUARD_OUTPUT_LIMIT', 'native combined stdout/stderr budget exceeded')
                key.data.extend(data)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GuardError('GUARD_WALL_TIMEOUT', 'native CodeShow Sequence exceeded wall timeout')
        try:
            result = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise GuardError('GUARD_WALL_TIMEOUT', 'native CodeShow Sequence exceeded wall timeout') from exc
        completed = True
        return bytes(out), bytes(err), result
    except (OSError, subprocess.SubprocessError) as exc:
        raise GuardError('GUARD_LAUNCH_FAILED', 'bounded native process could not start or read pipes') from exc
    finally:
        if proc is not None:
            _terminate_group(proc, force=not completed)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            # Closing the process group after parent exit is not guaranteed;
            # independently spawned child jobs and OS namespaces need native checks.
        for key in list(selector.get_map().values()):
            selector.unregister(key.fileobj)
            key.fileobj.close()
        selector.close()


def validate_native_result(stdout: bytes, returncode: int) -> None:
    """Native CES JSON is forwarded verbatim only after a minimal shape/exit sanity check."""
    if returncode not in (0, 2, 3, 4, 5):
        raise GuardError('GUARD_NATIVE_EXIT_UNEXPECTED', 'native CLI terminated with an unexpected exit status')
    try:
        result = json.loads(stdout)
    except (UnicodeError, ValueError) as exc:
        raise GuardError('GUARD_NATIVE_RESPONSE_INVALID', 'native CLI did not provide a single JSON result') from exc
    if not isinstance(result, dict) or result.get('schema_version') != 'ces.cli.v1' or result.get('action') != 'CodeShow' or not isinstance(result.get('reason_code'), str):
        raise GuardError('GUARD_NATIVE_RESPONSE_INVALID', 'native CLI result has an unexpected envelope')
    status = result.get('status')
    expected = {'success': 0, 'partial': 2, 'denied': 3, 'invalid_input': 4, 'unavailable': 5}
    if expected.get(status) != returncode:
        raise GuardError('GUARD_NATIVE_RESPONSE_INCONSISTENT', 'native status and exit code disagree')


def _guard_report(code: str, message: str) -> dict[str, Any]:
    return {
        'schema': 'ces.ec248.guarded_sequence.error.v1',
        'status': 'unavailable' if code != 'GUARD_SELECTORS_INVALID' and code != 'GUARD_BUDGET_INVALID' else 'invalid',
        'reason_code': code,
        'message': message,
        'native_executed': False if code in ('GUARD_SOURCE_DRIFT', 'GUARD_SOURCE_UNAVAILABLE', 'GUARD_IMPORT_DRIFT', 'GUARD_CHAIN_DRIFT', 'GUARD_UNSUPPORTED_HOST', 'GUARD_SELECTORS_INVALID', 'GUARD_BUDGET_INVALID', 'GUARD_PWSH_MISSING') else 'UNKNOWN_OR_TERMINATED',
        'native_result_trusted': False,
        'business_write_authority': False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', action='store_true', help='read-only pinned loading assessment, no native subprocess')
    parser.add_argument('--repo-path', help='absolute native Git repository path')
    parser.add_argument('--record-ids', help='2..12 distinct comma-separated canonical ci-SHA256 IDs')
    parser.add_argument('--top', type=int, default=10)
    for key, _ in SELECTORS:
        parser.add_argument('--' + key.replace('_', '-'), dest=key)
    parser.add_argument('--timeout-seconds', type=int, default=120)
    parser.add_argument('--cpu-seconds', type=int, default=120)
    parser.add_argument('--virtual-memory-mib', type=int, default=8192)
    parser.add_argument('--output-mib', type=int, default=8)
    ns = parser.parse_args(argv)
    try:
        assessment = source_profile()
        if ns.plan:
            print(json.dumps(assessment, ensure_ascii=False, sort_keys=True))
            return 0
        if not ns.repo_path or not ns.record_ids:
            raise GuardError('GUARD_SELECTORS_INVALID', '--repo-path and --record-ids are required for native run')
        budgets = Limits(ns.timeout_seconds, ns.cpu_seconds, ns.virtual_memory_mib, ns.output_mib)
        budgets.check()
        validate_request(ns)
        _require_supported_host()   # fail *before* attempting anything
        executable = shutil.which('pwsh')
        if not executable or not os.path.isabs(executable):
            raise GuardError('GUARD_PWSH_MISSING', 'PowerShell 7 is not available on PATH')
        out, err, code = run_bounded(build_command(ns, executable), budgets)
        validate_native_result(out, code)
        # Preserve successful/partial/invalid/unavailable *native* JSON bytes exactly.
        sys.stdout.buffer.write(out)
        if out and not out.endswith(b'\n'):
            sys.stdout.buffer.write(b'\n')
        if err:
            # Never emit unverified native stderr that may contain source/paths.
            print('EC248: bounded native subprocess produced diagnostic stderr (suppressed).', file=sys.stderr)
        return code
    except GuardError as exc:
        print(json.dumps(_guard_report(exc.code, str(exc)), ensure_ascii=False, sort_keys=True))
        return 4 if exc.code in ('GUARD_SELECTORS_INVALID', 'GUARD_BUDGET_INVALID') else 5


if __name__ == '__main__':
    sys.exit(main())
