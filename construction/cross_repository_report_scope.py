#!/usr/bin/env python3
"""EC195: explicit cross-repository report scope and least-privilege intersection.

A deliberately *scope-only*, offline model: every repository must be named by
its EC193 logical identity, and every usable record must be independently
replayed through EC194 -> EC193 -> EC192 and matched to caller-supplied pins.
No filesystem discovery, Git, network, identity-directory access, metric
computation, report publishing or write operation is performed.

Output does not contain whole EC194 subjects, actor inventories, contribution
references or raw identities. In particular an inaccessible/unauthorized or
stale repository is represented by an individually named gap, never silently
removed. An accepted actor link is only an *explicit unverified proposal*, not
an authenticated global actor identity or an automatic merge.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from actor_report_subject import ActorReportSubject
from natural_period import NaturalPeriod

SCHEMA = 'ces.cross_repository_report_scope.v1'
MAX_REPOSITORIES = 32
MAX_LINKS = 128
MAX_LINK_MEMBERS = 16
MAX_UPSTREAM_BYTES = 262144
MAX_TOTAL_UPSTREAM_BYTES = 4194304
MAX_OUTPUT_BYTES = 1048576
MAX_JSON_BYTES = 1048576

HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
REPO_ID = re.compile(r'cesrepo1:[0-9a-f]{64}\Z', re.ASCII)
REPORT_ID = re.compile(r'cesrs1:[0-9a-f]{64}\Z', re.ASCII)
PEOPLE_ID = re.compile(r'cesprs1:[0-9a-f]{64}\Z', re.ASCII)
ACTOR_KEY = re.compile(r'cesra1:[0-9a-f]{64}\Z', re.ASCII)
LINK_ID = re.compile(r'cesrml1:[0-9a-f]{64}\Z', re.ASCII)
SCOPE_ID = re.compile(r'cesmrs1:[0-9a-f]{64}\Z', re.ASCII)
KEY = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z', re.ASCII)
LINK_KEY = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z', re.ASCII)
UTC = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z', re.ASCII)
PERMISSION_DEPENDENCIES = {
    'report.scope.read': (),
    'report.actors.read': ('report.scope.read',),
    'report.evidence.read': ('report.scope.read', 'report.actors.read'),
    'report.actors.link': ('report.scope.read', 'report.actors.read'),
}
SOURCE_SELECTORS = {
    'WorkingTree': 'checkout_key',
    'DeliveredTarget': 'delivery_key',
    'ProposedPR': 'proposal_key',
}
GAP_TYPES = frozenset({
    'REPOSITORY_MISSING', 'REPOSITORY_INACCESSIBLE', 'SUBJECT_NOT_SUPPLIED',
    'SUBJECT_REPLAY_FAILED', 'SUBJECT_REPLAY_UNAVAILABLE',
    'REPOSITORY_IDENTITY_MISMATCH', 'PERIOD_MISMATCH',
    'REPORT_SLOT_PIN_MISSING', 'REPOSITORY_BINDING_PIN_MISSING',
    'PEOPLE_BINDING_PIN_MISSING', 'REPORT_SLOT_MISMATCH',
    'STALE_REPOSITORY_BINDING', 'STALE_PEOPLE_BINDING',
    'AUTHORIZATION_MISSING', 'AUTHORIZATION_INVALID',
    'AUTHORIZATION_WINDOW_INSUFFICIENT', 'OPERATION_NOT_GRANTED',
    'PARTIAL_PERIOD_WINDOW', 'SELECTED_PATH_SCOPE', 'PATH_INVENTORY_UNVERIFIED',
})
SOFT_GAPS = frozenset({
    'PARTIAL_PERIOD_WINDOW', 'SELECTED_PATH_SCOPE',
    'PATH_INVENTORY_UNVERIFIED',
})
LINK_GAP_TYPES = frozenset({
    'LINK_NOT_PERMITTED_FOR_SET', 'LINK_REPOSITORY_NOT_READY',
    'LINK_ACTOR_NOT_ELIGIBLE', 'LINK_IDENTITY_SCOPE_MISMATCH',
})
CLAIMS = {
    'repository_universe_complete_verified': False,
    'repository_identity_authenticated': False,
    'repository_source_authenticated': False,
    'period_timezone_rules_pinned': False,
    'repository_permissions_authenticated': False,
    'cross_repository_actor_identity_authenticated': False,
    'actor_link_receipt_authenticated': False,
    'actor_contribution_ownership_verified': False,
    'report_metrics_computed': False,
    'individual_performance_assessed': False,
    'report_prepared_or_published': False,
    'native_powershell_report_registered': False,
    'git_or_business_repository_written': False,
}


class CrossScopeError(ValueError):
    """Controlled errors never echo repository/actor identifiers or raw values."""

    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise CrossScopeError(reason)


def _exact(value: Any, keys: set[str], reason: str) -> dict[str, Any]:
    _need(type(value) is dict and set(value) == keys, reason)
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(',', ':'))


def _digest(domain: str, payload: Any) -> str:
    return hashlib.sha256(domain.encode('ascii') + b'\0' +
                          _canonical(payload).encode('ascii')).hexdigest()


def _byte_len(value: str) -> int:
    try:
        return len(value.encode('utf-8'))
    except UnicodeError as exc:
        raise CrossScopeError('INVALID_TEXT_ENCODING') from exc


def _sha(value: Any) -> bool:
    return type(value) is str and HEX.fullmatch(value) is not None


def _id(value: Any, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _utc(value: Any, reason: str) -> datetime:
    _need(type(value) is str and UTC.fullmatch(value) is not None, reason)
    try:
        dt = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(
            tzinfo=timezone.utc)
    except ValueError as exc:
        raise CrossScopeError(reason) from exc
    _need(dt.strftime('%Y-%m-%dT%H:%M:%SZ') == value, reason)
    return dt


def _no_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    folded: set[str] = set()
    for k, v in pairs:
        if k.casefold() in folded:
            raise CrossScopeError('JSON_DUPLICATE_KEY')
        folded.add(k.casefold())
        result[k] = v
    return result


def _reject_constant(_: str) -> Any:
    raise CrossScopeError('JSON_NONFINITE_NUMBER')


def _reject_float(_: str) -> Any:
    raise CrossScopeError('JSON_FLOAT_FORBIDDEN')


def _parse(serialized: Any) -> dict[str, Any]:
    _need(type(serialized) is str and 1 <= _byte_len(serialized) <=
          MAX_JSON_BYTES, 'JSON_MISSING_OR_TOO_LARGE')
    try:
        value = json.loads(serialized, object_pairs_hook=_no_duplicate,
                           parse_constant=_reject_constant,
                           parse_float=_reject_float)
    except CrossScopeError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError,
            OverflowError) as exc:
        raise CrossScopeError('JSON_INVALID') from exc
    _need(type(value) is dict and _canonical(value) == serialized,
          'JSON_NONCANONICAL')
    return value


def _repository(raw: Any) -> tuple[dict[str, str], str]:
    repo = _exact(raw, {'namespace_key', 'project_key', 'repository_key'},
                  'REPOSITORY_FIELDS_INVALID')
    _need(all(type(v) is str and KEY.fullmatch(v) is not None
              for v in repo.values()), 'REPOSITORY_KEY_INVALID')
    cleaned = {k: repo[k] for k in
               ('namespace_key', 'project_key', 'repository_key')}
    return cleaned, 'cesrepo1:' + _digest('CES-EC193-REPO-ID-v1', cleaned)


def _expected(raw: Any) -> dict[str, Any]:
    v = _exact(raw, {'report_subject_id', 'repository_binding_sha256',
                     'people_binding_sha256'}, 'EXPECTED_PINS_FIELDS_INVALID')
    _need(v['report_subject_id'] is None or
          _id(v['report_subject_id'], REPORT_ID), 'EXPECTED_REPORT_ID_INVALID')
    for field in ('repository_binding_sha256', 'people_binding_sha256'):
        _need(v[field] is None or _sha(v[field]), 'EXPECTED_BINDING_INVALID')
    return dict(v)


def _operation(raw: Any) -> str:
    _need(type(raw) is str and raw in PERMISSION_DEPENDENCIES,
          'REQUESTED_OPERATION_INVALID')
    return raw


def _operations(raw: Any) -> list[str]:
    _need(type(raw) is list and len(raw) <= len(PERMISSION_DEPENDENCIES) and
          all(type(op) is str and op in PERMISSION_DEPENDENCIES for op in raw) and
          len(raw) == len(set(raw)), 'PERMISSIONS_INVALID')
    return sorted(raw)


def _dependency_closure(declared: list[str]) -> list[str]:
    """Never infer an implied permission; only REMOVE incomplete grants."""
    s = set(declared)
    return sorted(op for op in s if set(PERMISSION_DEPENDENCIES[op]) <= s)


def _authorization(raw: Any, *, repository_id: str,
                   period: dict[str, Any]) -> dict[str, Any]:
    a = _exact(raw, {'purpose', 'receipt_sha256', 'valid_from_utc',
                     'valid_until_exclusive_utc', 'granted_operations'},
               'AUTHORIZATION_FIELDS_INVALID')
    _need(a['purpose'] == 'periodic_cross_repository_report',
          'AUTHORIZATION_PURPOSE_INVALID')
    _need(_sha(a['receipt_sha256']), 'AUTHORIZATION_RECEIPT_INVALID')
    start = _utc(a['valid_from_utc'], 'AUTHORIZATION_START_INVALID')
    end = _utc(a['valid_until_exclusive_utc'], 'AUTHORIZATION_END_INVALID')
    _need(start < end, 'AUTHORIZATION_WINDOW_INVALID')
    _need(start <= _utc(period['start_utc'], 'PERIOD_TIME_INVALID') and
          end >= _utc(period['end_exclusive_utc'], 'PERIOD_TIME_INVALID'),
          'AUTHORIZATION_WINDOW_INSUFFICIENT')
    operations = _operations(a['granted_operations'])
    normalized = {
        'purpose': a['purpose'],
        'receipt_sha256': a['receipt_sha256'],
        'valid_from_utc': a['valid_from_utc'],
        'valid_until_exclusive_utc': a['valid_until_exclusive_utc'],
        'granted_operations': operations,
        'state': 'DECLARED_GRANTED_UNVERIFIED',
    }
    normalized['authorization_binding_sha256'] = _digest(
        'CES-EC195-REPOSITORY-AUTH-v1', {
            'repository_id': repository_id,
            'period_id': period['period_id'],
            **normalized,
        })
    return normalized


def _replay_authorization(raw: Any, *, repository_id: str,
                          period: dict[str, Any]) -> dict[str, Any]:
    a = _exact(raw, {'purpose', 'receipt_sha256', 'valid_from_utc',
                     'valid_until_exclusive_utc', 'granted_operations',
                     'state', 'authorization_binding_sha256'},
               'AUTHORIZATION_RECORD_FIELDS_INVALID')
    computed = _authorization({k: a[k] for k in ('purpose', 'receipt_sha256',
        'valid_from_utc', 'valid_until_exclusive_utc', 'granted_operations')},
        repository_id=repository_id, period=period)
    _need(a == computed, 'AUTHORIZATION_RECORD_BINDING_INVALID')
    return computed


def _period_from_json(serialized: Any) -> dict[str, Any]:
    _need(type(serialized) is str, 'PERIOD_JSON_INVALID')
    result = NaturalPeriod().from_json(serialized=serialized)
    if result['status'] != 'partial':
        raise CrossScopeError('UPSTREAM_' + result['reason_code'],
                              'unavailable' if result['status'] == 'unavailable'
                              else 'invalid_input')
    return result['period']


def _projection(subject: dict[str, Any]) -> dict[str, Any]:
    r = subject['repository_subject']
    return {
        'report_subject_id': r['report_subject_id'],
        'report_key': r['report_key'],
        'period_id': r['period']['period_id'],
        'source_mode': r['source']['mode'],
        'source_selector': dict(r['source']['selector']),
        'repository_binding_sha256': r['binding_sha256'],
        'coverage_sha256': r['coverage']['coverage_sha256'],
        'period_window_complete': r['coverage']['period_window_complete'],
        'path_scope': r['coverage']['path_scope'],
        'inventory_state': r['coverage']['inventory_state'],
        'people_subject_id': subject['people_subject_id'],
        'people_binding_sha256': subject['binding_sha256'],
    }


def _validate_projection(raw: Any, *, repository_id: str,
                         period: dict[str, Any]) -> dict[str, Any]:
    p = _exact(raw, {'report_subject_id', 'report_key', 'period_id',
                      'source_mode', 'source_selector',
                      'repository_binding_sha256', 'coverage_sha256',
                      'period_window_complete', 'path_scope',
                      'inventory_state', 'people_subject_id',
                      'people_binding_sha256'}, 'PROJECTION_FIELDS_INVALID')
    _need(type(p['report_key']) is str and KEY.fullmatch(p['report_key']) is not None,
          'REPORT_KEY_INVALID')
    _need(p['period_id'] == period['period_id'], 'PROJECTION_PERIOD_INVALID')
    _need(type(p['source_mode']) is str and
          p['source_mode'] in SOURCE_SELECTORS, 'SOURCE_MODE_INVALID')
    selector = _exact(p['source_selector'], {'kind', 'key'},
                      'SOURCE_SELECTOR_FIELDS_INVALID')
    _need(selector['kind'] == SOURCE_SELECTORS[p['source_mode']] and
          type(selector['key']) is str and 1 <= len(selector['key']) <= 128 and
          re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}',
                       selector['key'], re.ASCII) is not None and
          all(x not in ('', '.', '..') for x in selector['key'].split('/')),
          'SOURCE_SELECTOR_INVALID')
    _need(all(_sha(p[f]) for f in ('repository_binding_sha256',
                                  'coverage_sha256', 'people_binding_sha256')) and
          _id(p['report_subject_id'], REPORT_ID) and
          _id(p['people_subject_id'], PEOPLE_ID),
          'PROJECTION_DIGEST_INVALID')
    _need(type(p['period_window_complete']) is bool and
          p['path_scope'] in ('ENTIRE_REPOSITORY_DECLARED', 'SELECTED_PATHS') and
          p['inventory_state'] in ('unknown', 'partial_declared', 'complete_declared'),
          'COVERAGE_FLAGS_INVALID')
    expected_report_id = 'cesrs1:' + _digest('CES-EC193-REPORT-SUBJECT-v1', {
        'report_key': p['report_key'],
        'repository_id': repository_id,
        'period_id': period['period_id'],
        'period_start_utc': period['start_utc'],
        'period_end_exclusive_utc': period['end_exclusive_utc'],
        'source_mode': p['source_mode'],
        'source_selector': selector,
    })
    _need(p['report_subject_id'] == expected_report_id,
          'PROJECTION_REPORT_SLOT_INVALID')
    expected_people_id = 'cesprs1:' + _digest('CES-EC194-PEOPLE-SUBJECT-v1', {
        'report_subject_id': expected_report_id,
        'repository_id': repository_id,
        'period_id': period['period_id'],
    })
    _need(p['people_subject_id'] == expected_people_id,
          'PROJECTION_PEOPLE_SLOT_INVALID')
    return {**p, 'source_selector': dict(selector)}


def _soft_gaps(report: dict[str, Any]) -> list[str]:
    gaps = []
    if not report['period_window_complete']:
        gaps.append('PARTIAL_PERIOD_WINDOW')
    if report['path_scope'] != 'ENTIRE_REPOSITORY_DECLARED':
        gaps.append('SELECTED_PATH_SCOPE')
    if report['inventory_state'] != 'complete_declared':
        gaps.append('PATH_INVENTORY_UNVERIFIED')
    return sorted(gaps)


def _input_row(raw: Any, period: dict[str, Any],
               requested_operation: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
    v = _exact(raw, {'repository', 'expected', 'availability',
                     'people_subject_json', 'authorization'},
               'REPOSITORY_REQUEST_FIELDS_INVALID')
    repo, repo_id = _repository(v['repository'])
    expected = _expected(v['expected'])
    _need(type(v['availability']) is str and v['availability'] in
          ('SUBMITTED', 'MISSING', 'INACCESSIBLE'), 'AVAILABILITY_INVALID')
    row: dict[str, Any] = {
        'repository': repo,
        'repository_id': repo_id,
        'expected': expected,
        'availability': v['availability'],
        'status': 'GAP',
        'report': None,
        'authorization': None,
        'effective_declared_operations': [],
        'reason_codes': [],
    }
    gaps: set[str] = set()
    if v['availability'] != 'SUBMITTED':
        _need(v['people_subject_json'] is None and v['authorization'] is None,
              'NON_SUBMITTED_PAYLOAD_FORBIDDEN')
        row['reason_codes'] = [
            'REPOSITORY_MISSING' if v['availability'] == 'MISSING'
            else 'REPOSITORY_INACCESSIBLE']
        return row, None

    subject: dict[str, Any] | None = None
    if type(v['people_subject_json']) is not str or not v['people_subject_json']:
        gaps.add('SUBJECT_NOT_SUPPLIED')
    else:
        try:
            size = _byte_len(v['people_subject_json'])
            if size > MAX_UPSTREAM_BYTES:
                gaps.add('SUBJECT_NOT_SUPPLIED')
            else:
                attempt = ActorReportSubject().from_json(
                    serialized=v['people_subject_json'])
                if attempt['status'] == 'partial':
                    subject = attempt['subject']
                else:
                    gaps.add('SUBJECT_REPLAY_UNAVAILABLE' if
                             attempt['status'] == 'unavailable' else
                             'SUBJECT_REPLAY_FAILED')
        except CrossScopeError:
            gaps.add('SUBJECT_REPLAY_FAILED')

    if subject is not None:
        r = subject['repository_subject']
        if r['repository']['repository_id'] != repo_id:
            gaps.add('REPOSITORY_IDENTITY_MISMATCH')
        if r['period'] != period:
            gaps.add('PERIOD_MISMATCH')
        for field, observed, missing, stale in (
            ('report_subject_id', r['report_subject_id'],
             'REPORT_SLOT_PIN_MISSING', 'REPORT_SLOT_MISMATCH'),
            ('repository_binding_sha256', r['binding_sha256'],
             'REPOSITORY_BINDING_PIN_MISSING', 'STALE_REPOSITORY_BINDING'),
            ('people_binding_sha256', subject['binding_sha256'],
             'PEOPLE_BINDING_PIN_MISSING', 'STALE_PEOPLE_BINDING'),
        ):
            if expected[field] is None:
                gaps.add(missing)
            elif expected[field] != observed:
                gaps.add(stale)

    if v['authorization'] is None:
        gaps.add('AUTHORIZATION_MISSING')
    else:
        try:
            row['authorization'] = _authorization(
                v['authorization'], repository_id=repo_id, period=period)
        except CrossScopeError as exc:
            gaps.add('AUTHORIZATION_WINDOW_INSUFFICIENT' if
                     exc.code == 'AUTHORIZATION_WINDOW_INSUFFICIENT'
                     else 'AUTHORIZATION_INVALID')

    if subject is not None and not gaps:
        permitted = _dependency_closure(
            row['authorization']['granted_operations'])
        if requested_operation not in permitted:
            gaps.add('OPERATION_NOT_GRANTED')
        else:
            report = _projection(subject)
            _validate_projection(report, repository_id=repo_id, period=period)
            row['report'] = report
            row['status'] = 'READY'
            row['effective_declared_operations'] = permitted
            gaps.update(_soft_gaps(report))

    row['reason_codes'] = sorted(gaps)
    return row, subject if row['status'] == 'READY' else None


def _link_input(raw: Any) -> dict[str, Any]:
    v = _exact(raw, {'link_key', 'receipt_sha256', 'members'},
               'LINK_FIELDS_INVALID')
    _need(type(v['link_key']) is str and LINK_KEY.fullmatch(v['link_key']) is not None,
          'LINK_KEY_INVALID')
    _need(_sha(v['receipt_sha256']), 'LINK_RECEIPT_INVALID')
    _need(type(v['members']) is list and 2 <= len(v['members']) <= MAX_LINK_MEMBERS,
          'LINK_MEMBERS_INVALID')
    members = []
    for m in v['members']:
        m = _exact(m, {'repository_id', 'actor_key'},
                   'LINK_MEMBER_FIELDS_INVALID')
        _need(_id(m['repository_id'], REPO_ID) and
              _id(m['actor_key'], ACTOR_KEY), 'LINK_MEMBER_ID_INVALID')
        members.append(dict(m))
    _need(len({m['repository_id'] for m in members}) == len(members),
          'LINK_MEMBERS_MUST_BE_DIFFERENT_REPOSITORIES')
    members.sort(key=lambda x: (x['repository_id'], x['actor_key']))
    return {'link_key': v['link_key'], 'receipt_sha256': v['receipt_sha256'],
            'members': members}


def _link_id(period_id: str, link: dict[str, Any],
             identity_scope_sha256: str) -> str:
    return 'cesrml1:' + _digest('CES-EC195-DECLARED-ACTOR-LINK-v1', {
        'period_id': period_id,
        'link_key': link['link_key'],
        'receipt_sha256': link['receipt_sha256'],
        'identity_scope_sha256': identity_scope_sha256,
        'members': link['members'],
    })


def _links(link_inputs: Any, rows: list[dict[str, Any]],
           actors: dict[str, dict[str, Any]],
           period_id: str, effective_ops: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    _need(type(link_inputs) is list and len(link_inputs) <= MAX_LINKS,
          'LINK_LIST_INVALID')
    parsed = [_link_input(raw) for raw in link_inputs]
    keys = [v['link_key'] for v in parsed]
    _need(len(keys) == len(set(keys)), 'DUPLICATE_LINK_KEY')
    ready = {r['repository_id'] for r in rows if r['status'] == 'READY'}
    accepted, refused = [], []
    for link in parsed:
        reason: str | None = None
        if 'report.actors.link' not in effective_ops:
            reason = 'LINK_NOT_PERMITTED_FOR_SET'
        elif not all(m['repository_id'] in ready for m in link['members']):
            reason = 'LINK_REPOSITORY_NOT_READY'
        else:
            found = []
            for m in link['members']:
                actor = actors.get(m['repository_id'], {}).get(m['actor_key'])
                if actor is None or actor['identity_receipt_sha256'] is None:
                    reason = 'LINK_ACTOR_NOT_ELIGIBLE'
                    break
                found.append(actor)
            if reason is None and len({a['identity_scope_sha256'] for a in found}) != 1:
                reason = 'LINK_IDENTITY_SCOPE_MISMATCH'
        if reason is not None:
            # Never echo denied link members or their identity scope hashes.
            refused.append({'link_key': link['link_key'], 'reason_code': reason})
            continue
        identity_scope_sha = found[0]['identity_scope_sha256']
        accepted.append({
            'link_key': link['link_key'],
            'link_id': _link_id(period_id, link, identity_scope_sha),
            'receipt_sha256': link['receipt_sha256'],
            'identity_scope_sha256': identity_scope_sha,
            'members': link['members'],
            'state': 'DECLARED_SAME_SCOPE_UNVERIFIED',
        })
    return (sorted(accepted, key=lambda x: x['link_key']),
            sorted(refused, key=lambda x: x['link_key']))


def _global_gaps(rows: list[dict[str, Any]],
                 refused: list[dict[str, Any]]) -> list[str]:
    gaps = {
        'REPOSITORY_UNIVERSE_NOT_VERIFIED',
        'REPOSITORY_SOURCE_NOT_AUTHENTICATED',
        'REPOSITORY_AUTHORIZATION_NOT_AUTHENTICATED',
        'TIMEZONE_RULESET_NOT_PINNED',
    }
    if any(r['status'] != 'READY' for r in rows):
        gaps.add('EXPLICIT_REPOSITORY_SET_HAS_UNUSABLE_OR_UNAUTHORIZED_MEMBERS')
    if any(set(r['reason_codes']) & SOFT_GAPS for r in rows):
        gaps.add('EXPLICIT_REPOSITORY_SET_HAS_PARTIAL_COVERAGE')
    if refused:
        gaps.add('EXPLICIT_ACTOR_LINKS_NOT_ALL_ACCEPTED')
    return sorted(gaps)


def _assemble(period: dict[str, Any], requested_operation: str,
              rows: list[dict[str, Any]], accepted_links: list[dict[str, Any]],
              refused_links: list[dict[str, Any]]) -> dict[str, Any]:
    ids = [r['repository_id'] for r in rows]
    _need(1 <= len(rows) <= MAX_REPOSITORIES and len(ids) == len(set(ids)),
          'REPOSITORY_SET_INVALID')
    rows.sort(key=lambda r: r['repository_id'])
    current = set(PERMISSION_DEPENDENCIES)
    for row in rows:
        current &= set(row['effective_declared_operations'])
    effective = _dependency_closure(sorted(current))
    scope_id = 'cesmrs1:' + _digest('CES-EC195-SCOPE-ID-v1', {
        'period_id': period['period_id'],
        'requested_operation': requested_operation,
        'repository_ids': sorted(ids),
    })
    out: dict[str, Any] = {
        'schema': SCHEMA,
        'scope_id': scope_id,
        'period': json.loads(_canonical(period)),
        'requested_operation': requested_operation,
        'repository_set': rows,
        'effective_operations': effective,
        'requested_operation_declared_for_all': (
            requested_operation in effective and
            all(r['status'] == 'READY' for r in rows)),
        'actor_link_proposals': accepted_links,
        'actor_link_gaps': refused_links,
        'coverage_gaps': [
            {'repository': r['repository'], 'repository_id': r['repository_id'],
             'reason_codes': r['reason_codes']}
            for r in rows if r['reason_codes']
        ],
        'global_gaps': _global_gaps(rows, refused_links),
        'claims': dict(CLAIMS),
    }
    out['binding_sha256'] = _digest('CES-EC195-SCOPE-BINDING-v1', out)
    return out


def _replay_row(raw: Any, period: dict[str, Any],
                requested_operation: str) -> dict[str, Any]:
    r = _exact(raw, {'repository', 'repository_id', 'expected', 'availability',
                     'status', 'report', 'authorization',
                     'effective_declared_operations', 'reason_codes'},
               'ROW_RECORD_FIELDS_INVALID')
    repo, repo_id = _repository(r['repository'])
    _need(r['repository_id'] == repo_id, 'ROW_REPOSITORY_ID_INVALID')
    expected = _expected(r['expected'])
    _need(r['availability'] in ('SUBMITTED', 'MISSING', 'INACCESSIBLE') and
          r['status'] in ('READY', 'GAP'), 'ROW_STATUS_INVALID')
    _need(type(r['reason_codes']) is list and
          all(type(x) is str and x in GAP_TYPES for x in r['reason_codes']) and
          r['reason_codes'] == sorted(set(r['reason_codes'])),
          'ROW_GAPS_INVALID')
    auth = None if r['authorization'] is None else _replay_authorization(
        r['authorization'], repository_id=repo_id, period=period)
    permitted = _dependency_closure(auth['granted_operations']) if auth else []
    _need(r['effective_declared_operations'] ==
          (permitted if r['status'] == 'READY' else []),
          'ROW_PERMISSIONS_INVALID')
    if r['availability'] != 'SUBMITTED':
        _need(r['status'] == 'GAP' and r['report'] is None and auth is None and
              r['reason_codes'] == [
                  'REPOSITORY_MISSING' if r['availability'] == 'MISSING'
                  else 'REPOSITORY_INACCESSIBLE'],
              'UNAVAILABLE_ROW_INVALID')
    elif r['status'] == 'READY':
        _need(auth is not None and r['report'] is not None and
              requested_operation in permitted, 'READY_ROW_NOT_AUTHORIZED')
        p = _validate_projection(r['report'], repository_id=repo_id,
                                 period=period)
        _need(expected == {
            'report_subject_id': p['report_subject_id'],
            'repository_binding_sha256': p['repository_binding_sha256'],
            'people_binding_sha256': p['people_binding_sha256'],
        }, 'READY_ROW_EXPECTED_PIN_MISMATCH')
        _need(r['reason_codes'] == _soft_gaps(p), 'READY_ROW_GAPS_INVALID')
    else:
        _need(r['report'] is None and
              bool(set(r['reason_codes']) - SOFT_GAPS),
              'GAP_ROW_MUST_HAVE_HARD_REASON')
    return {**r, 'repository': repo, 'expected': expected,
            'authorization': auth}


def _replay_link(raw: Any, period_id: str,
                 repository_set: list[dict[str, Any]],
                 effective_operations: list[str]) -> dict[str, Any]:
    v = _exact(raw, {'link_key', 'link_id', 'receipt_sha256',
                     'identity_scope_sha256', 'members', 'state'},
               'LINK_RECORD_FIELDS_INVALID')
    parsed = _link_input({k: v[k] for k in
                          ('link_key', 'receipt_sha256', 'members')})
    _need(v['members'] == parsed['members'] and
          _sha(v['identity_scope_sha256']) and
          v['state'] == 'DECLARED_SAME_SCOPE_UNVERIFIED' and
          _id(v['link_id'], LINK_ID), 'LINK_RECORD_INVALID')
    _need(v['link_id'] == _link_id(period_id, parsed, v['identity_scope_sha256']),
          'LINK_BINDING_INVALID')
    _need('report.actors.link' in effective_operations and
          all(m['repository_id'] in {r['repository_id'] for r in repository_set
                                      if r['status'] == 'READY'} and
              m['actor_key'] == 'cesra1:' + _digest(
                  'CES-EC194-REPOSITORY-ACTOR-v1', {
                      'repository_id': m['repository_id'],
                      'identity_scope_sha256': v['identity_scope_sha256'],
                  }) for m in v['members']),
          'LINK_MEMBERS_OR_PERMISSIONS_INVALID')
    return v


def _replay(serialized: str) -> dict[str, Any]:
    d = _parse(serialized)
    _exact(d, {'schema', 'scope_id', 'period', 'requested_operation',
               'repository_set', 'effective_operations',
               'requested_operation_declared_for_all',
               'actor_link_proposals', 'actor_link_gaps', 'coverage_gaps',
               'global_gaps', 'claims', 'binding_sha256'},
           'RECORD_FIELDS_INVALID')
    _need(d['schema'] == SCHEMA and _id(d['scope_id'], SCOPE_ID),
          'RECORD_SCHEMA_OR_ID_INVALID')
    period = _period_from_json(_canonical(d['period']))
    operation = _operation(d['requested_operation'])
    _need(type(d['repository_set']) is list and
          1 <= len(d['repository_set']) <= MAX_REPOSITORIES,
          'REPOSITORY_SET_INVALID')
    rows = [_replay_row(r, period, operation) for r in d['repository_set']]
    _need(rows == sorted(rows, key=lambda x: x['repository_id']),
          'REPOSITORY_SET_ORDER_INVALID')
    _need(len({r['repository_id'] for r in rows}) == len(rows),
          'DUPLICATE_REPOSITORY')
    _need(type(d['actor_link_proposals']) is list and
          type(d['actor_link_gaps']) is list and
          len(d['actor_link_proposals']) + len(d['actor_link_gaps']) <= MAX_LINKS,
          'LINK_LIST_INVALID')
    all_permissions = set(PERMISSION_DEPENDENCIES)
    for r in rows:
        all_permissions &= set(r['effective_declared_operations'])
    effective = _dependency_closure(sorted(all_permissions))
    _need(d['effective_operations'] == effective, 'PERMISSION_INTERSECTION_INVALID')
    proposals = [_replay_link(v, period['period_id'], rows, effective)
                 for v in d['actor_link_proposals']]
    gaps = []
    for value in d['actor_link_gaps']:
        g = _exact(value, {'link_key', 'reason_code'},
                   'LINK_GAP_FIELDS_INVALID')
        _need(type(g['link_key']) is str and
              LINK_KEY.fullmatch(g['link_key']) is not None and
              g['reason_code'] in LINK_GAP_TYPES, 'LINK_GAP_INVALID')
        gaps.append(dict(g))
    all_keys = [x['link_key'] for x in proposals + gaps]
    _need(len(set(all_keys)) == len(all_keys) and
          proposals == sorted(proposals, key=lambda x: x['link_key']) and
          gaps == sorted(gaps, key=lambda x: x['link_key']),
          'LINK_ORDER_OR_DUPLICATE_INVALID')
    computed = _assemble(period, operation, rows, proposals, gaps)
    _need(d['scope_id'] == computed['scope_id'] and
          d['effective_operations'] == computed['effective_operations'] and
          d['requested_operation_declared_for_all'] ==
          computed['requested_operation_declared_for_all'] and
          d['coverage_gaps'] == computed['coverage_gaps'] and
          d['global_gaps'] == computed['global_gaps'] and
          d['claims'] == computed['claims'], 'SCOPE_DERIVATION_INVALID')
    _need(d['binding_sha256'] == computed['binding_sha256'] and
          _canonical(d) == _canonical(computed), 'SCOPE_BINDING_INVALID')
    return computed


def _validate_witnesses(rows: list[dict[str, Any]],
                        links: list[dict[str, Any]],
                        witnesses: dict[str, str]) -> None:
    """Optional full upstream recheck; absent witness never counts as proof."""
    _need(type(witnesses) is dict and
          all(type(k) is str and _id(k, REPO_ID) and type(v) is str
              for k, v in witnesses.items()), 'WITNESSES_INVALID')
    ready = {r['repository_id']: r for r in rows if r['status'] == 'READY'}
    _need(set(witnesses) == set(ready), 'WITNESSES_SET_MISMATCH')
    actor_map: dict[str, dict[str, dict[str, Any]]] = {}
    for repo_id, row in ready.items():
        candidate = witnesses[repo_id]
        _need(_byte_len(candidate) <= MAX_UPSTREAM_BYTES,
              'WITNESS_TOO_LARGE')
        verified = ActorReportSubject().from_json(serialized=candidate)
        _need(verified['status'] == 'partial', 'WITNESS_REPLAY_FAILED')
        subject = verified['subject']
        _need(subject['repository_subject']['repository']['repository_id'] == repo_id and
              _projection(subject) == row['report'],
              'WITNESS_BINDING_MISMATCH')
        actor_map[repo_id] = {a['actor_key']: a for a in subject['actors']}
    for link in links:
        for member in link['members']:
            actor = actor_map[member['repository_id']].get(member['actor_key'])
            _need(actor is not None and
                  actor['identity_receipt_sha256'] is not None and
                  actor['identity_scope_sha256'] == link['identity_scope_sha256'],
                  'WITNESS_LINK_MEMBERSHIP_INVALID')


def _envelope() -> dict[str, Any]:
    return {'schema': SCHEMA, 'status': 'invalid_input', 'exit_code': 4,
            'reason_code': 'CROSS_REPOSITORY_SCOPE_INPUT_INVALID',
            'subject': None, 'canonical_json': None,
            'limitations': dict(CLAIMS)}


def _failure(out: dict[str, Any], error: CrossScopeError) -> dict[str, Any]:
    out['status'] = error.status
    out['exit_code'] = 5 if error.status == 'unavailable' else 4
    out['reason_code'] = 'CROSS_REPOSITORY_SCOPE_' + error.code
    return out


def _success(out: dict[str, Any], subject: dict[str, Any],
             reason: str) -> dict[str, Any]:
    serialized = _canonical(subject)
    _need(_byte_len(serialized) <= MAX_OUTPUT_BYTES,
          'SCOPE_RECORD_TOO_LARGE')
    out.update(status='partial', exit_code=2, reason_code=reason,
               subject=subject, canonical_json=serialized)
    return out


class CrossRepositoryReportScope:
    """EC195 read-only explicit repository scope, not an authorization engine."""

    def bind(self, *, period_json: str, requested_operation: str,
             repositories: list[dict[str, Any]],
             actor_links: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        out = _envelope()
        try:
            period = _period_from_json(period_json)
            operation = _operation(requested_operation)
            _need(type(repositories) is list and
                  1 <= len(repositories) <= MAX_REPOSITORIES,
                  'REPOSITORY_SET_INVALID')
            _need(type(actor_links) is list or actor_links is None,
                  'LINK_LIST_INVALID')
            # Check exact keys/IDs and caps before touching any upstream input.
            ids = []
            total_bytes = 0
            for entry in repositories:
                v = _exact(entry, {'repository', 'expected', 'availability',
                                  'people_subject_json', 'authorization'},
                           'REPOSITORY_REQUEST_FIELDS_INVALID')
                ids.append(_repository(v['repository'])[1])
                if type(v['people_subject_json']) is str:
                    total_bytes += _byte_len(v['people_subject_json'])
            _need(len(ids) == len(set(ids)), 'DUPLICATE_REPOSITORY')
            _need(total_bytes <= MAX_TOTAL_UPSTREAM_BYTES, 'INPUT_SUBJECTS_TOO_LARGE')
            rows = []
            actors: dict[str, dict[str, Any]] = {}
            for raw in repositories:
                row, subject = _input_row(raw, period, operation)
                rows.append(row)
                if subject is not None:
                    actors[row['repository_id']] = {
                        a['actor_key']: a for a in subject['actors']
                    }
            common = set(PERMISSION_DEPENDENCIES)
            for row in rows:
                common &= set(row['effective_declared_operations'])
            links, link_gaps = _links(
                [] if actor_links is None else actor_links, rows, actors,
                period['period_id'], _dependency_closure(sorted(common)))
            return _success(out, _assemble(period, operation, rows, links, link_gaps),
                            'CROSS_REPOSITORY_SCOPE_BOUND')
        except CrossScopeError as exc:
            return _failure(out, exc)

    def from_json(self, *, serialized: str,
                  people_subject_witnesses: dict[str, str] | None = None) -> dict[str, Any]:
        """Recompute self-contained scope; optionally replay all READY witnesses.

        Without witnesses this cannot re-establish the embedded EC194/193
        origin of projections or the real-world truth of missing-repository
        claims. Even with witnesses it never authenticates providers or receipts.
        """
        out = _envelope()
        try:
            subject = _replay(serialized)
            if people_subject_witnesses is not None:
                _validate_witnesses(subject['repository_set'],
                                    subject['actor_link_proposals'],
                                    people_subject_witnesses)
            reason = ('CROSS_REPOSITORY_SCOPE_REPLAYED_WITH_WITNESSES'
                      if people_subject_witnesses is not None else
                      'CROSS_REPOSITORY_SCOPE_REPLAYED_STRUCTURAL_ONLY')
            return _success(out, subject, reason)
        except CrossScopeError as exc:
            return _failure(out, exc)
