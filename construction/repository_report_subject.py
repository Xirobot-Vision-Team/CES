#!/usr/bin/env python3
"""EC193: explicit, read-only single-repository report subject declarations.

A declared repository key, locator, Git OID or receipt digest is NOT a trusted
source identity. This module never traverses local disks, reads Git/provider
state, collects events, writes files or promotes ProposedPR to DeliveredTarget.
It binds precisely one explicitly selected source, bounded logical path scope
and sub-interval to an EC192 replay-validated natural period.  The returned
canonical record is stable for *the same tzdb rules*, not a signed attestation.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any
import unicodedata
from urllib.parse import urlsplit

from natural_period import NaturalPeriod

SCHEMA = 'ces.repository_report_subject.v1'
MAX_JSON = 65536
MAX_SELECTORS = 64
MAX_PATH_CHARS = 512
MAX_LOCATOR = 1024
HEX64 = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
KEY = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z', re.ASCII)
SELECTOR_KEY = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}\Z', re.ASCII)
UTC_STAMP = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z', re.ASCII)
GIT_FORMATS = {'sha1': 40, 'sha256': 64}
SOURCE_KIND = {
    'WorkingTree': 'checkout_key',
    'DeliveredTarget': 'delivery_key',
    'ProposedPR': 'proposal_key',
}
LOCATOR_KINDS = {
    'WorkingTree': {'local_root'},
    'DeliveredTarget': {'local_root', 'remote_repository', 'provider_repository_id'},
    'ProposedPR': {'remote_repository', 'provider_repository_id'},
}
INVENTORY = {'unknown', 'partial_declared', 'complete_declared'}
CLAIMS = {
    'repository_identity_authenticated': False,
    'locator_existence_verified': False,
    'git_object_verified': False,
    'source_provenance_verified': False,
    'coverage_inventory_verified': False,
    'activity_in_period_verified': False,
    'remote_delivery_verified': False,
    'timezone_rules_pinned': False,
    'report_prepared_or_published': False,
    'business_repository_written': False,
    'native_powershell_report_registered': False,
}


class SubjectError(ValueError):
    """Controlled denial; user-supplied strings are never echoed in errors."""

    def __init__(self, reason: str, status: str = 'invalid_input') -> None:
        super().__init__(reason)
        self.reason, self.status = reason, status


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise SubjectError(reason)


def exact(value: Any, keys: set[str], reason: str) -> dict[str, Any]:
    need(type(value) is dict and set(value) == keys, reason)
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(',', ':'))


def _digest(domain: str, payload: Any) -> str:
    return hashlib.sha256(domain.encode('ascii') + b'\0' +
                          _canonical(payload).encode('ascii')).hexdigest()


def _key(value: Any) -> bool:
    return type(value) is str and KEY.fullmatch(value) is not None


def _utc(value: Any, reason: str) -> datetime:
    need(type(value) is str and UTC_STAMP.fullmatch(value) is not None,
         reason)
    try:
        stamp = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise SubjectError(reason) from exc
    need(stamp.strftime('%Y-%m-%dT%H:%M:%SZ') == value, reason)
    return stamp


def _locator(kind: Any, value: Any) -> None:
    """Lexical checks only; does NOT prove path/remote/repository existence."""
    need(type(value) is str and 1 <= len(value) <= MAX_LOCATOR and
         unicodedata.is_normalized('NFC', value) and
         not any(ord(c) < 32 or ord(c) == 127 for c in value) and
         value == value.strip(),
         'LOCATOR_INVALID')
    if kind == 'local_root':
        # Explicit POSIX absolute or Windows drive-absolute. No UNC, bare
        # volume root, relative paths, dot segments or ADS. Symlinks are NOT
        # checked: no os.path.realpath and absolutely no filesystem IO.
        posix = value.startswith('/') and not value.startswith('//')
        win = bool(re.fullmatch(r'[A-Za-z]:\\[^:]*', value))
        need(posix or win, 'LOCAL_ROOT_NOT_ABSOLUTE')
        sep = '/' if posix else '\\'
        need(('\\' not in value and '//' not in value) if posix else
             ('/' not in value and '\\\\' not in value),
             'LOCAL_ROOT_INVALID')
        tail = value[1:] if posix else value[3:]
        need(tail and all(p not in ('.', '..', '') for p in tail.split(sep)) and
             (posix or ':' not in tail), 'LOCAL_ROOT_TRAVERSAL_OR_ALIAS')
        need(not value.endswith(sep), 'LOCAL_ROOT_TRAILING_SEPARATOR')
        if win:
            reserved = {'CON', 'PRN', 'AUX', 'NUL'} | {
                f'{prefix}{i}' for prefix in ('COM', 'LPT') for i in range(1, 10)}
            need(all(p == p.rstrip(' .') and p.split('.')[0].upper() not in reserved
                     for p in tail.split(sep)), 'WINDOWS_LOCAL_ROOT_ALIAS')
    elif kind == 'remote_repository':
        try:
            parsed = urlsplit(value)
            parts = parsed.path.split('/')
            valid = (parsed.scheme == 'https' and bool(parsed.hostname) and
                     parsed.username is None and parsed.password is None and
                     parsed.query == '' and parsed.fragment == '' and
                     parsed.port in (None, 443) and
                     not any(c in value for c in ('\\', '%', '#', '?', '@')) and
                     len(parts) >= 3 and parts[0] == '' and
                     all(p not in ('', '.', '..') for p in parts[1:]) and
                     parsed.hostname == parsed.hostname.lower())
        except ValueError:
            valid = False
        need(valid, 'REMOTE_LOCATOR_UNSAFE')
    elif kind == 'provider_repository_id':
        # Namespace must be explicitly chosen; a bare numeric ID is ambiguous.
        need(SELECTOR_KEY.fullmatch(value) is not None and ':' in value and
             not any(s in ('.', '..', '') for s in value.split('/')),
             'PROVIDER_REPOSITORY_ID_INVALID')
    else:
        raise SubjectError('LOCATOR_KIND_INVALID')


def _raw_repository(raw: Any) -> dict[str, Any]:
    r = exact(raw, {'namespace_key', 'project_key', 'repository_key', 'locator'},
              'REPOSITORY_FIELDS_INVALID')
    need(all(_key(r[k]) for k in ('namespace_key', 'project_key', 'repository_key')),
         'REPOSITORY_KEY_INVALID')
    loc = exact(r['locator'], {'kind', 'value'}, 'LOCATOR_FIELDS_INVALID')
    need(type(loc['kind']) is str, 'LOCATOR_KIND_INVALID')
    _locator(loc['kind'], loc['value'])
    return {
        'namespace_key': r['namespace_key'],
        'project_key': r['project_key'],
        'repository_key': r['repository_key'],
        'locator_kind': loc['kind'],
        'locator_sha256': _digest('CES-EC193-LOCATOR-v1', loc),
    }


def _validate_repository(record: Any) -> dict[str, Any]:
    r = exact(record, {'namespace_key', 'project_key', 'repository_key',
                       'locator_kind', 'locator_sha256', 'repository_id',
                       'identity_state'}, 'REPOSITORY_RECORD_FIELDS_INVALID')
    need(all(_key(r[k]) for k in ('namespace_key', 'project_key', 'repository_key')),
         'REPOSITORY_KEY_INVALID')
    need(type(r['locator_kind']) is str and
         r['locator_kind'] in {'local_root', 'remote_repository', 'provider_repository_id'} and
         type(r['locator_sha256']) is str and HEX64.fullmatch(r['locator_sha256']) is not None,
         'LOCATOR_FINGERPRINT_INVALID')
    return {k: r[k] for k in ('namespace_key', 'project_key', 'repository_key',
                              'locator_kind', 'locator_sha256')}


def _source(raw: Any) -> dict[str, Any]:
    s = exact(raw, {'mode', 'selector', 'git_object', 'receipt_sha256',
                    'observed_at_utc'}, 'SOURCE_FIELDS_INVALID')
    need(type(s['mode']) is str and s['mode'] in SOURCE_KIND, 'SOURCE_MODE_INVALID')
    selector = exact(s['selector'], {'kind', 'key'}, 'SELECTOR_FIELDS_INVALID')
    need(type(selector['kind']) is str and selector['kind'] == SOURCE_KIND[s['mode']] and
         type(selector['key']) is str and SELECTOR_KEY.fullmatch(selector['key']) is not None and
         not any(p in ('', '.', '..') for p in selector['key'].split('/')),
         'SOURCE_SELECTOR_INVALID')
    obj = s['git_object']
    if obj is not None:
        obj = exact(obj, {'algorithm', 'oid'}, 'GIT_OBJECT_FIELDS_INVALID')
        need(type(obj['algorithm']) is str and obj['algorithm'] in GIT_FORMATS and
             type(obj['oid']) is str and
             re.fullmatch(r'[0-9a-f]+', obj['oid'], re.ASCII) is not None and
             len(obj['oid']) == GIT_FORMATS[obj['algorithm']],
             'GIT_OID_INVALID')
    receipt = s['receipt_sha256']
    need(receipt is None or (type(receipt) is str and HEX64.fullmatch(receipt) is not None),
         'RECEIPT_DIGEST_INVALID')
    if s['observed_at_utc'] is not None:
        _utc(s['observed_at_utc'], 'SOURCE_OBSERVED_TIME_INVALID')
    return {
        'mode': s['mode'], 'selector': dict(selector),
        'git_object': dict(obj) if obj is not None else None,
        'receipt_sha256': receipt, 'observed_at_utc': s['observed_at_utc'],
    }


def _path(item: Any) -> dict[str, str]:
    p = exact(item, {'kind', 'path'}, 'PATH_SELECTOR_FIELDS_INVALID')
    need(type(p['kind']) is str and p['kind'] in ('repository', 'directory', 'file') and
         type(p['path']) is str, 'PATH_SELECTOR_INVALID')
    if p['kind'] == 'repository':
        need(p['path'] == '', 'REPOSITORY_PATH_MUST_BE_EMPTY')
    else:
        v = p['path']
        need(1 <= len(v) <= MAX_PATH_CHARS and
             unicodedata.is_normalized('NFC', v) and
             not any(unicodedata.category(c).startswith('C') for c in v) and
             not any(c in v for c in ('\\', ':', '%', '*', '?', '[', ']')) and
             all(s not in ('', '.', '..') for s in v.split('/')) and
             not v.startswith('/') and not v.endswith('/'),
             'PATH_NOT_CANONICAL')
    return {'kind': p['kind'], 'path': p['path']}


def _covers(parent: dict[str, str], child: dict[str, str]) -> bool:
    if parent['kind'] == 'repository':
        return True
    if parent['kind'] == 'file':
        return child['kind'] == 'file' and child['path'] == parent['path']
    return (child['path'] == parent['path'] or
            child['path'].startswith(parent['path'] + '/'))


def _selectors(raw: Any, role: str) -> list[dict[str, str]]:
    need(type(raw) is list and (1 <= len(raw) <= MAX_SELECTORS if role == 'includes'
                                    else len(raw) <= MAX_SELECTORS),
         'COVERAGE_SELECTOR_COUNT_INVALID')
    items = [_path(x) for x in raw]
    # Overlapping declarations are error-prone when aggregating per-path data;
    # explicitly refuse them instead of silently deduplicating or double counting.
    for i, a in enumerate(items):
        for b in items[:i]:
            need(not (_covers(a, b) or _covers(b, a) or
                      a['path'].casefold() == b['path'].casefold()),
                 'COVERAGE_OVERLAPPING_SELECTORS')
    if role == 'excludes':
        need(all(x['kind'] != 'repository' for x in items),
             'EXCLUDE_WHOLE_REPOSITORY_FORBIDDEN')
    return sorted(items, key=lambda x: (x['path'], x['kind']))


def _coverage(raw: Any, period: dict[str, Any]) -> dict[str, Any]:
    c = exact(raw, {'window', 'includes', 'excludes', 'inventory_state'},
              'COVERAGE_FIELDS_INVALID')
    window = exact(c['window'], {'start_utc', 'end_exclusive_utc'},
                   'WINDOW_FIELDS_INVALID')
    left = _utc(window['start_utc'], 'WINDOW_START_INVALID')
    right = _utc(window['end_exclusive_utc'], 'WINDOW_END_INVALID')
    period_start = _utc(period['start_utc'], 'PERIOD_START_INVALID')
    period_end = _utc(period['end_exclusive_utc'], 'PERIOD_END_INVALID')
    need(period_start <= left < right <= period_end, 'WINDOW_OUTSIDE_PERIOD')
    includes = _selectors(c['includes'], 'includes')
    excludes = _selectors(c['excludes'], 'excludes')
    for excluded in excludes:
        need(any(_covers(parent, excluded) and parent != excluded for parent in includes),
             'EXCLUSION_OUTSIDE_SCOPE_OR_EMPTY')
    need(type(c['inventory_state']) is str and c['inventory_state'] in INVENTORY,
         'INVENTORY_STATE_INVALID')
    return {
        'window': dict(window), 'includes': includes, 'excludes': excludes,
        'inventory_state': c['inventory_state'],
    }


def _gaps(source: dict[str, Any], coverage: dict[str, Any],
          period: dict[str, Any]) -> list[str]:
    gaps = [
        'REPOSITORY_KEYS_CALLER_DECLARED',
        'REPOSITORY_LOCATOR_NOT_RESOLVED',
        'SOURCE_SELECTOR_UNATTESTED',
        'GIT_OBJECT_UNVERIFIED',
        'SOURCE_RECEIPT_UNVERIFIED' if source['receipt_sha256'] else 'SOURCE_RECEIPT_MISSING',
        'ACTIVITY_IN_WINDOW_UNVERIFIED',
        'TIMEZONE_RULESET_NOT_PINNED',
        'PATH_INVENTORY_UNVERIFIED',
    ]
    mode = source['mode']
    gaps.append({
        'WorkingTree': 'WORKING_TREE_NOT_ATOMICALLY_PINNED',
        'DeliveredTarget': 'DELIVERY_NOT_AUTHENTICATED',
        'ProposedPR': 'PROPOSED_PR_NOT_DELIVERED',
    }[mode])
    if source['git_object'] is None:
        gaps.append('GIT_OBJECT_CLAIM_MISSING')
    if coverage['window'] != {
            'start_utc': period['start_utc'],
            'end_exclusive_utc': period['end_exclusive_utc']}:
        gaps.append('WINDOW_PARTIAL_PERIOD')
    if coverage['includes'] != [{'kind': 'repository', 'path': ''}]:
        gaps.append('PATH_SCOPE_SELECTED_SUBSET')
    if coverage['excludes']:
        gaps.append('PATH_EXCLUSIONS_DECLARED')
    if coverage['inventory_state'] != 'complete_declared':
        gaps.append('PATH_INVENTORY_NOT_CLAIMED_COMPLETE')
    return sorted(gaps)


def _assemble(period: dict[str, Any], repo: dict[str, Any],
              source: dict[str, Any], coverage: dict[str, Any],
              report_key: str) -> dict[str, Any]:
    need(_key(report_key), 'REPORT_KEY_INVALID')
    need(repo['locator_kind'] in LOCATOR_KINDS[source['mode']],
         'SOURCE_LOCATOR_MODE_MISMATCH')
    ident = {key: repo[key] for key in ('namespace_key', 'project_key', 'repository_key')}
    repository_id = 'cesrepo1:' + _digest('CES-EC193-REPO-ID-v1', ident)
    report_slot = {
        'report_key': report_key,
        'repository_id': repository_id,
        'period_id': period['period_id'],
        'period_start_utc': period['start_utc'],
        'period_end_exclusive_utc': period['end_exclusive_utc'],
        'source_mode': source['mode'],
        'source_selector': source['selector'],
    }
    # Stable slot identity intentionally excludes changing claimed OID/receipt,
    # path coverage and locator; these changes produce a new binding digest.
    report_subject_id = 'cesrs1:' + _digest('CES-EC193-REPORT-SUBJECT-v1', report_slot)
    coverage_sha256 = _digest('CES-EC193-COVERAGE-v1', coverage)
    out: dict[str, Any] = {
        'schema': SCHEMA,
        'report_subject_id': report_subject_id,
        'report_key': report_key,
        'repository': {**repo, 'repository_id': repository_id,
                       'identity_state': 'CALLER_DECLARED_ONLY'},
        'period': period,
        'source': {**source, 'provenance_state': 'CALLER_DECLARED_ONLY'},
        'coverage': {**coverage, 'coverage_sha256': coverage_sha256,
                     'period_window_complete': coverage['window'] == {
                         'start_utc': period['start_utc'],
                         'end_exclusive_utc': period['end_exclusive_utc']},
                     'path_scope': ('ENTIRE_REPOSITORY_DECLARED'
                                    if coverage['includes'] == [
                                        {'kind': 'repository', 'path': ''}]
                                    else 'SELECTED_PATHS')},
        'coverage_gaps': _gaps(source, coverage, period),
        'claims': dict(CLAIMS),
    }
    out['binding_sha256'] = _digest('CES-EC193-BINDING-v1', out)
    return out


def _no_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    folded = set()
    for key, value in pairs:
        if key.casefold() in folded:
            raise SubjectError('JSON_DUPLICATE_KEY')
        folded.add(key.casefold())
        result[key] = value
    return result


def _reject_constant(_: str) -> Any:
    raise SubjectError('JSON_NONFINITE_NUMBER')


def _period_from_json(value: Any) -> dict[str, Any]:
    r = NaturalPeriod().from_json(serialized=value)
    if r['status'] != 'partial':
        raise SubjectError('UPSTREAM_' + r['reason_code'],
                           'unavailable' if r['status'] == 'unavailable'
                           else 'invalid_input')
    return r['period']


def _replay_subject(raw: Any) -> dict[str, Any]:
    need(type(raw) is str and 1 <= len(raw) <= MAX_JSON,
         'JSON_MISSING_OR_TOO_LARGE')
    try:
        data = json.loads(raw, object_pairs_hook=_no_duplicate,
                          parse_constant=_reject_constant,
                          parse_float=lambda _: (_ for _ in ()).throw(
                              SubjectError('JSON_FLOAT_FORBIDDEN')))
    except SubjectError:
        raise
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError) as exc:
        raise SubjectError('JSON_INVALID') from exc
    need(type(data) is dict and _canonical(data) == raw, 'JSON_NONCANONICAL')
    exact(data, {'schema', 'report_subject_id', 'report_key', 'repository', 'period',
                 'source', 'coverage', 'coverage_gaps', 'claims', 'binding_sha256'},
          'RECORD_FIELDS_INVALID')
    need(data['schema'] == SCHEMA, 'RECORD_SCHEMA_INVALID')
    period = _period_from_json(_canonical(data['period']))
    repo = _validate_repository(data['repository'])
    s = exact(data['source'], {'mode', 'selector', 'git_object',
                               'receipt_sha256', 'observed_at_utc',
                               'provenance_state'}, 'SOURCE_RECORD_FIELDS_INVALID')
    source = _source({k: s[k] for k in ('mode', 'selector', 'git_object',
                                      'receipt_sha256', 'observed_at_utc')})
    c = exact(data['coverage'], {'window', 'includes', 'excludes',
                                 'inventory_state', 'coverage_sha256',
                                 'period_window_complete', 'path_scope'},
              'COVERAGE_RECORD_FIELDS_INVALID')
    coverage = _coverage({k: c[k] for k in ('window', 'includes', 'excludes',
                                           'inventory_state')}, period)
    computed = _assemble(period, repo, source, coverage, data['report_key'])
    need(_canonical(computed) == raw, 'SUBJECT_BINDING_MISMATCH')
    return computed


def _envelope() -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': 'invalid_input', 'exit_code': 4,
        'reason_code': 'REPORT_SUBJECT_INPUT_INVALID',
        'subject': None, 'canonical_json': None,
        'limitations': dict(CLAIMS),
    }


def _failure(out: dict[str, Any], error: SubjectError) -> dict[str, Any]:
    out['status'] = error.status
    out['exit_code'] = 5 if error.status == 'unavailable' else 4
    out['reason_code'] = 'REPORT_SUBJECT_' + error.reason
    return out


def _success(out: dict[str, Any], record: dict[str, Any], reason: str) -> dict[str, Any]:
    canonical = _canonical(record)
    need(len(canonical) <= MAX_JSON, 'SUBJECT_RECORD_TOO_LARGE')
    out.update(status='partial', exit_code=2, reason_code=reason,
               subject=record, canonical_json=canonical)
    return out


class RepositoryReportSubject:
    """Bind or replay one declared repository report subject with zero I/O.

    Always partial/2 on a valid *declaration*: without an independent verifier,
    neither a locator, claimed Git object nor receipt digest authenticates it.
    Caller must explicitly supply all repository/source/scope choices.
    """

    def bind(self, *, period_json: str, repository: dict[str, Any],
             report_key: str, source: dict[str, Any],
             coverage: dict[str, Any]) -> dict[str, Any]:
        out = _envelope()
        try:
            period = _period_from_json(period_json)
            repo = _raw_repository(repository)
            src = _source(source)
            cov = _coverage(coverage, period)
            return _success(out, _assemble(period, repo, src, cov, report_key),
                            'REPORT_SUBJECT_DECLARATION_BOUND')
        except SubjectError as exc:
            return _failure(out, exc)

    def from_json(self, *, serialized: str) -> dict[str, Any]:
        """Check byte-canonical structure, derived hashes and current EC192 UTC.

        This is a structural replay only, NOT signature verification. The
        original raw locator is deliberately not serialized (only a digest).
        """
        out = _envelope()
        try:
            return _success(out, _replay_subject(serialized),
                            'REPORT_SUBJECT_DECLARATION_REVALIDATED')
        except SubjectError as exc:
            return _failure(out, exc)
