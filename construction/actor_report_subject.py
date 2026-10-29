#!/usr/bin/env python3
"""EC194: conservative actor subjects for one EC193 repository report scope.

This module performs no filesystem, Git, provider, CI, directory-service or
network I/O.  It accepts explicitly declared immutable external subject tuples,
produces repository-scoped deterministic actor keys, and binds generic evidence
references to those keys only when an explicit report-inclusion authorization
claim covers the exact EC193 coverage window.

Names, emails and usernames are never identity.  Optional display labels are
hashed only for UI correlation and never participate in actor-key derivation.
All identity/authorization receipts remain caller-provided digests; this module
cannot authenticate them.  Consequently every valid result is conservative
``partial/2`` and no output is a personnel grade, write authorization or proof
that a contribution was actually performed by a human.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any
import unicodedata

from repository_report_subject import RepositoryReportSubject

SCHEMA = 'ces.actor_report_subject.v1'
MAX_JSON = 262144
MAX_ACTORS = 128
MAX_EVIDENCE = 1024
MAX_TEXT = 256
HEX64 = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
KEY128 = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}\Z', re.ASCII)
AUTHORITY = re.compile(r'[a-z][a-z0-9._-]{0,63}\Z', re.ASCII)
UTC_STAMP = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z', re.ASCII)
ACTOR_KEY = re.compile(r'cesra1:[0-9a-f]{64}\Z', re.ASCII)
ACTOR_SUBJECT_ID = re.compile(r'cesras1:[0-9a-f]{64}\Z', re.ASCII)
PEOPLE_SUBJECT_ID = re.compile(r'cesprs1:[0-9a-f]{64}\Z', re.ASCII)
PURPOSE = 'periodic_repository_report'

CLAIMS = {
    'repository_identity_authenticated': False,
    'source_provenance_verified': False,
    'actor_identity_authenticated': False,
    'actor_authorization_authenticated': False,
    'evidence_ownership_verified': False,
    'complete_actor_coverage_verified': False,
    'complete_contribution_coverage_verified': False,
    'cross_repository_identity_linked': False,
    'personnel_metrics_computed': False,
    'personal_performance_assessed': False,
    'report_prepared_or_published': False,
    'business_repository_written': False,
    'native_powershell_report_registered': False,
}


class ActorSubjectError(ValueError):
    """Controlled denial; no raw user identity string is included in errors."""

    def __init__(self, reason: str, status: str = 'invalid_input') -> None:
        super().__init__(reason)
        self.reason, self.status = reason, status


def need(condition: bool, reason: str, status: str = 'invalid_input') -> None:
    if not condition:
        raise ActorSubjectError(reason, status)


def exact(value: Any, keys: set[str], reason: str) -> dict[str, Any]:
    need(type(value) is dict and set(value) == keys, reason)
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(',', ':'))


def _digest(domain: str, payload: Any) -> str:
    return hashlib.sha256(domain.encode('ascii') + b'\0' +
                          _canonical(payload).encode('ascii')).hexdigest()


def _utc(value: Any, reason: str) -> datetime:
    need(type(value) is str and UTC_STAMP.fullmatch(value) is not None, reason)
    try:
        stamp = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(
            tzinfo=timezone.utc)
    except ValueError as exc:
        raise ActorSubjectError(reason) from exc
    need(stamp.strftime('%Y-%m-%dT%H:%M:%SZ') == value, reason)
    return stamp


def _text(value: Any, reason: str) -> str:
    need(type(value) is str and 1 <= len(value) <= MAX_TEXT and
         value == value.strip() and unicodedata.is_normalized('NFC', value) and
         not any(ord(c) < 32 or ord(c) == 127 for c in value), reason)
    return value


def _identity(raw: Any) -> dict[str, str]:
    ident = exact(raw, {'authority', 'tenant', 'immutable_subject_id'},
                  'IDENTITY_FIELDS_INVALID')
    need(type(ident['authority']) is str and
         AUTHORITY.fullmatch(ident['authority']) is not None,
         'IDENTITY_AUTHORITY_INVALID')
    tenant = _text(ident['tenant'], 'IDENTITY_TENANT_INVALID')
    subject = _text(ident['immutable_subject_id'],
                    'IDENTITY_SUBJECT_ID_INVALID')
    return {
        'authority': ident['authority'],
        'tenant': tenant,
        'immutable_subject_id': subject,
    }


def _identity_scope_sha256(identity: dict[str, str]) -> str:
    return _digest('CES-EC194-IDENTITY-SCOPE-v1', identity)


def _actor_key(repository_id: str, identity_scope_sha256: str) -> str:
    return 'cesra1:' + _digest('CES-EC194-REPOSITORY-ACTOR-v1', {
        'repository_id': repository_id,
        'identity_scope_sha256': identity_scope_sha256,
    })


def _actor_subject_id(report_subject_id: str, actor_key: str) -> str:
    return 'cesras1:' + _digest('CES-EC194-ACTOR-SUBJECT-v1', {
        'report_subject_id': report_subject_id,
        'actor_key': actor_key,
    })


def _authorization(raw: Any, coverage_window: dict[str, str],
                   actor_key: str, repository_id: str,
                   report_subject_id: str, period_id: str) -> dict[str, Any]:
    auth = exact(raw, {'purpose', 'receipt_sha256', 'valid_from_utc',
                       'valid_until_exclusive_utc'},
                 'AUTHORIZATION_FIELDS_INVALID')
    need(auth['purpose'] == PURPOSE, 'AUTHORIZATION_PURPOSE_INVALID')
    need(type(auth['receipt_sha256']) is str and
         HEX64.fullmatch(auth['receipt_sha256']) is not None,
         'AUTHORIZATION_RECEIPT_INVALID')
    left = _utc(auth['valid_from_utc'], 'AUTHORIZATION_START_INVALID')
    right = _utc(auth['valid_until_exclusive_utc'],
                 'AUTHORIZATION_END_INVALID')
    need(left < right, 'AUTHORIZATION_WINDOW_EMPTY')
    cov_left = _utc(coverage_window['start_utc'], 'UPSTREAM_WINDOW_INVALID')
    cov_right = _utc(coverage_window['end_exclusive_utc'],
                     'UPSTREAM_WINDOW_INVALID')
    need(left <= cov_left and right >= cov_right,
         'AUTHORIZATION_DOES_NOT_COVER_REPORT_WINDOW')
    out = {
        'purpose': PURPOSE,
        'receipt_sha256': auth['receipt_sha256'],
        'valid_from_utc': auth['valid_from_utc'],
        'valid_until_exclusive_utc': auth['valid_until_exclusive_utc'],
        'state': 'DECLARED_GRANTED_UNVERIFIED',
    }
    out['authorization_binding_sha256'] = _digest(
        'CES-EC194-AUTHORIZATION-BINDING-v1', {
            'actor_key': actor_key,
            'repository_id': repository_id,
            'report_subject_id': report_subject_id,
            'period_id': period_id,
            **out,
        })
    return out


def _actor(raw: Any, repo_subject: dict[str, Any]) -> tuple[dict[str, Any], str]:
    a = exact(raw, {'identity', 'display_label', 'identity_receipt_sha256',
                    'authorization'}, 'ACTOR_FIELDS_INVALID')
    identity = _identity(a['identity'])
    scope_sha = _identity_scope_sha256(identity)
    actor_key = _actor_key(repo_subject['repository']['repository_id'], scope_sha)
    label_sha: str | None = None
    if a['display_label'] is not None:
        label = _text(a['display_label'], 'DISPLAY_LABEL_INVALID')
        label_sha = _digest('CES-EC194-DISPLAY-LABEL-v1', label)
    receipt = a['identity_receipt_sha256']
    need(receipt is None or (type(receipt) is str and
                             HEX64.fullmatch(receipt) is not None),
         'IDENTITY_RECEIPT_INVALID')
    authorization = _authorization(
        a['authorization'], repo_subject['coverage']['window'], actor_key,
        repo_subject['repository']['repository_id'],
        repo_subject['report_subject_id'], repo_subject['period']['period_id'])
    return ({
        'actor_key': actor_key,
        'actor_subject_id': _actor_subject_id(repo_subject['report_subject_id'],
                                              actor_key),
        'identity_scope_sha256': scope_sha,
        'display_label_sha256': label_sha,
        'identity_receipt_sha256': receipt,
        'identity_state': ('DECLARED_STABLE_SCOPE_UNVERIFIED_RECEIPT'
                           if receipt is not None
                           else 'DECLARED_STABLE_SCOPE_UNVERIFIED_NO_RECEIPT'),
        'authorization': authorization,
        'evidence_refs': [],
    }, actor_key)


def _evidence(raw: Any, repo_subject: dict[str, Any],
              actor_eligibility: dict[str, bool]) -> tuple[str | None, dict[str, Any]]:
    e = exact(raw, {'evidence_id', 'identity', 'occurred_at_utc',
                    'repository_id', 'report_subject_id',
                    'source_binding_sha256', 'evidence_sha256'},
              'EVIDENCE_FIELDS_INVALID')
    need(type(e['evidence_id']) is str and
         KEY128.fullmatch(e['evidence_id']) is not None and
         not any(p in ('', '.', '..') for p in e['evidence_id'].split('/')),
         'EVIDENCE_ID_INVALID')
    need(e['repository_id'] == repo_subject['repository']['repository_id'],
         'EVIDENCE_REPOSITORY_MISMATCH')
    need(e['report_subject_id'] == repo_subject['report_subject_id'],
         'EVIDENCE_REPORT_SUBJECT_MISMATCH')
    need(e['source_binding_sha256'] == repo_subject['binding_sha256'],
         'EVIDENCE_SOURCE_BINDING_MISMATCH')
    need(type(e['evidence_sha256']) is str and
         HEX64.fullmatch(e['evidence_sha256']) is not None,
         'EVIDENCE_DIGEST_INVALID')
    stamp = _utc(e['occurred_at_utc'], 'EVIDENCE_TIME_INVALID')
    left = _utc(repo_subject['coverage']['window']['start_utc'],
                'UPSTREAM_WINDOW_INVALID')
    right = _utc(repo_subject['coverage']['window']['end_exclusive_utc'],
                 'UPSTREAM_WINDOW_INVALID')
    need(left <= stamp < right, 'EVIDENCE_OUTSIDE_REPORT_WINDOW')
    ref = {
        'evidence_id': e['evidence_id'],
        'occurred_at_utc': e['occurred_at_utc'],
        'evidence_sha256': e['evidence_sha256'],
        'source_binding_sha256': e['source_binding_sha256'],
    }
    if e['identity'] is None:
        return None, {**ref, 'reason_code': 'ACTOR_IDENTITY_MISSING'}
    ident = _identity(e['identity'])
    key = _actor_key(repo_subject['repository']['repository_id'],
                     _identity_scope_sha256(ident))
    if key not in actor_eligibility:
        # Do not serialize the unauthorized identity or its derived actor key.
        return None, {**ref, 'reason_code': 'ACTOR_NOT_AUTHORIZED_OR_DECLARED'}
    if not actor_eligibility[key]:
        # A stable caller-declared tuple without even a declared independent
        # identity receipt is not enough to attribute contribution evidence.
        return None, {**ref, 'reason_code': 'ACTOR_IDENTITY_PROOF_MISSING'}
    return key, ref


def _gaps(actors: list[dict[str, Any]], unattributed: list[dict[str, Any]],
          evidence_present: bool) -> list[str]:
    gaps = {
        'ACTOR_IDENTITY_NOT_AUTHENTICATED',
        'ACTOR_AUTHORIZATION_NOT_AUTHENTICATED',
        'REPOSITORY_SOURCE_NOT_AUTHENTICATED',
    }
    if any(a['identity_receipt_sha256'] is None for a in actors):
        gaps.add('ACTOR_IDENTITY_RECEIPT_MISSING')
    if not actors:
        gaps.add('NO_AUTHORIZED_ACTOR_SUBJECTS')
    if not evidence_present:
        gaps.add('NO_CONTRIBUTION_EVIDENCE_DECLARED')
    else:
        gaps.add('EVIDENCE_PROVENANCE_NOT_AUTHENTICATED')
    if unattributed:
        gaps.add('UNATTRIBUTED_EVIDENCE_PRESENT')
    return sorted(gaps)


def _repository_projection(repo_subject: dict[str, Any]) -> dict[str, Any]:
    # Keep the entire EC193 record so source mode, period, provenance and
    # coverage remain explicit and independently replayable in EC194.
    return json.loads(_canonical(repo_subject))


def _assemble(repo_subject: dict[str, Any], actors_raw: Any,
              evidence_raw: Any) -> dict[str, Any]:
    need(type(actors_raw) is list and len(actors_raw) <= MAX_ACTORS,
         'ACTOR_LIST_INVALID')
    need(type(evidence_raw) is list and len(evidence_raw) <= MAX_EVIDENCE,
         'EVIDENCE_LIST_INVALID')
    need(actors_raw or evidence_raw, 'EMPTY_PEOPLE_REPORT_SUBJECT')

    actors: list[dict[str, Any]] = []
    actor_keys: set[str] = set()
    for raw in actors_raw:
        actor, key = _actor(raw, repo_subject)
        need(key not in actor_keys, 'DUPLICATE_ACTOR_IDENTITY')
        actor_keys.add(key)
        actors.append(actor)
    actors.sort(key=lambda x: x['actor_key'])
    by_key = {a['actor_key']: a for a in actors}
    actor_eligibility = {
        a['actor_key']: a['identity_receipt_sha256'] is not None for a in actors
    }

    unattributed: list[dict[str, Any]] = []
    evidence_ids: set[str] = set()
    for raw in evidence_raw:
        key, ref = _evidence(raw, repo_subject, actor_eligibility)
        need(ref['evidence_id'] not in evidence_ids, 'DUPLICATE_EVIDENCE_ID')
        evidence_ids.add(ref['evidence_id'])
        if key is None:
            unattributed.append(ref)
        else:
            by_key[key]['evidence_refs'].append(ref)

    evidence_sort = lambda x: (x['occurred_at_utc'], x['evidence_id'],
                               x['evidence_sha256'])
    for actor in actors:
        actor['evidence_refs'].sort(key=evidence_sort)
    unattributed.sort(key=evidence_sort)

    report_subject_id = repo_subject['report_subject_id']
    people_subject_id = 'cesprs1:' + _digest('CES-EC194-PEOPLE-SUBJECT-v1', {
        'report_subject_id': report_subject_id,
        'repository_id': repo_subject['repository']['repository_id'],
        'period_id': repo_subject['period']['period_id'],
    })
    out: dict[str, Any] = {
        'schema': SCHEMA,
        'people_subject_id': people_subject_id,
        'repository_subject': _repository_projection(repo_subject),
        'actors': actors,
        'unattributed_evidence': unattributed,
        'coverage_gaps': _gaps(actors, unattributed, bool(evidence_raw)),
        'claims': dict(CLAIMS),
    }
    out['binding_sha256'] = _digest('CES-EC194-BINDING-v1', out)
    return out


def _validate_actor_record(raw: Any, repo_subject: dict[str, Any]) -> dict[str, Any]:
    a = exact(raw, {'actor_key', 'actor_subject_id', 'identity_scope_sha256',
                    'display_label_sha256', 'identity_receipt_sha256',
                    'identity_state', 'authorization', 'evidence_refs'},
              'ACTOR_RECORD_FIELDS_INVALID')
    need(type(a['identity_scope_sha256']) is str and
         HEX64.fullmatch(a['identity_scope_sha256']) is not None,
         'ACTOR_SCOPE_DIGEST_INVALID')
    expected_key = _actor_key(repo_subject['repository']['repository_id'],
                              a['identity_scope_sha256'])
    need(a['actor_key'] == expected_key and type(a['actor_key']) is str and
         ACTOR_KEY.fullmatch(a['actor_key']) is not None,
         'ACTOR_KEY_BINDING_INVALID')
    expected_subject = _actor_subject_id(repo_subject['report_subject_id'],
                                         a['actor_key'])
    need(a['actor_subject_id'] == expected_subject and
         type(a['actor_subject_id']) is str and
         ACTOR_SUBJECT_ID.fullmatch(a['actor_subject_id']) is not None,
         'ACTOR_SUBJECT_ID_INVALID')
    need(a['display_label_sha256'] is None or
         (type(a['display_label_sha256']) is str and
          HEX64.fullmatch(a['display_label_sha256']) is not None),
         'DISPLAY_LABEL_DIGEST_INVALID')
    need(a['identity_receipt_sha256'] is None or
         (type(a['identity_receipt_sha256']) is str and
          HEX64.fullmatch(a['identity_receipt_sha256']) is not None),
         'IDENTITY_RECEIPT_INVALID')
    expected_state = ('DECLARED_STABLE_SCOPE_UNVERIFIED_RECEIPT'
                      if a['identity_receipt_sha256'] is not None
                      else 'DECLARED_STABLE_SCOPE_UNVERIFIED_NO_RECEIPT')
    need(a['identity_state'] == expected_state, 'IDENTITY_STATE_INVALID')

    auth = exact(a['authorization'], {'purpose', 'receipt_sha256',
                                      'valid_from_utc',
                                      'valid_until_exclusive_utc', 'state',
                                      'authorization_binding_sha256'},
                 'AUTHORIZATION_RECORD_FIELDS_INVALID')
    need(auth['purpose'] == PURPOSE and
         auth['state'] == 'DECLARED_GRANTED_UNVERIFIED' and
         type(auth['receipt_sha256']) is str and
         HEX64.fullmatch(auth['receipt_sha256']) is not None and
         type(auth['authorization_binding_sha256']) is str and
         HEX64.fullmatch(auth['authorization_binding_sha256']) is not None,
         'AUTHORIZATION_RECORD_INVALID')
    left = _utc(auth['valid_from_utc'], 'AUTHORIZATION_START_INVALID')
    right = _utc(auth['valid_until_exclusive_utc'],
                 'AUTHORIZATION_END_INVALID')
    cov_left = _utc(repo_subject['coverage']['window']['start_utc'],
                    'UPSTREAM_WINDOW_INVALID')
    cov_right = _utc(repo_subject['coverage']['window']['end_exclusive_utc'],
                     'UPSTREAM_WINDOW_INVALID')
    need(left < right and left <= cov_left and right >= cov_right,
         'AUTHORIZATION_DOES_NOT_COVER_REPORT_WINDOW')
    expected_auth = _digest('CES-EC194-AUTHORIZATION-BINDING-v1', {
        'actor_key': a['actor_key'],
        'repository_id': repo_subject['repository']['repository_id'],
        'report_subject_id': repo_subject['report_subject_id'],
        'period_id': repo_subject['period']['period_id'],
        'purpose': auth['purpose'],
        'receipt_sha256': auth['receipt_sha256'],
        'valid_from_utc': auth['valid_from_utc'],
        'valid_until_exclusive_utc': auth['valid_until_exclusive_utc'],
        'state': auth['state'],
    })
    need(auth['authorization_binding_sha256'] == expected_auth,
         'AUTHORIZATION_BINDING_INVALID')

    need(type(a['evidence_refs']) is list and
         len(a['evidence_refs']) <= MAX_EVIDENCE,
         'ACTOR_EVIDENCE_LIST_INVALID')
    refs = [_validate_ref(r, repo_subject, unattributed=False)
            for r in a['evidence_refs']]
    refs_sorted = sorted(refs, key=lambda x: (x['occurred_at_utc'],
                                              x['evidence_id'],
                                              x['evidence_sha256']))
    need(refs == refs_sorted, 'ACTOR_EVIDENCE_ORDER_INVALID')
    return {
        **{k: a[k] for k in ('actor_key', 'actor_subject_id',
                             'identity_scope_sha256', 'display_label_sha256',
                             'identity_receipt_sha256', 'identity_state')},
        'authorization': dict(auth),
        'evidence_refs': refs,
    }


def _validate_ref(raw: Any, repo_subject: dict[str, Any],
                  unattributed: bool) -> dict[str, Any]:
    keys = {'evidence_id', 'occurred_at_utc', 'evidence_sha256',
            'source_binding_sha256'}
    if unattributed:
        keys.add('reason_code')
    r = exact(raw, keys, 'EVIDENCE_RECORD_FIELDS_INVALID')
    need(type(r['evidence_id']) is str and
         KEY128.fullmatch(r['evidence_id']) is not None and
         not any(p in ('', '.', '..') for p in r['evidence_id'].split('/')),
         'EVIDENCE_ID_INVALID')
    need(type(r['evidence_sha256']) is str and
         HEX64.fullmatch(r['evidence_sha256']) is not None and
         r['source_binding_sha256'] == repo_subject['binding_sha256'],
         'EVIDENCE_RECORD_BINDING_INVALID')
    stamp = _utc(r['occurred_at_utc'], 'EVIDENCE_TIME_INVALID')
    left = _utc(repo_subject['coverage']['window']['start_utc'],
                'UPSTREAM_WINDOW_INVALID')
    right = _utc(repo_subject['coverage']['window']['end_exclusive_utc'],
                 'UPSTREAM_WINDOW_INVALID')
    need(left <= stamp < right, 'EVIDENCE_OUTSIDE_REPORT_WINDOW')
    out = {k: r[k] for k in ('evidence_id', 'occurred_at_utc',
                             'evidence_sha256', 'source_binding_sha256')}
    if unattributed:
        need(r['reason_code'] in {'ACTOR_IDENTITY_MISSING',
                                  'ACTOR_NOT_AUTHORIZED_OR_DECLARED',
                                  'ACTOR_IDENTITY_PROOF_MISSING'},
             'UNATTRIBUTED_REASON_INVALID')
        out['reason_code'] = r['reason_code']
    return out


def _no_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    folded: set[str] = set()
    for key, value in pairs:
        folded_key = key.casefold()
        if folded_key in folded:
            raise ActorSubjectError('JSON_DUPLICATE_KEY')
        folded.add(folded_key)
        result[key] = value
    return result


def _reject_constant(_: str) -> Any:
    raise ActorSubjectError('JSON_NONFINITE_NUMBER')


def _repo_from_json(raw: Any) -> dict[str, Any]:
    need(type(raw) is dict, 'REPOSITORY_SUBJECT_INVALID')
    serialized = _canonical(raw)
    upstream = RepositoryReportSubject().from_json(serialized=serialized)
    if upstream['status'] != 'partial':
        status = 'unavailable' if upstream['status'] == 'unavailable' else 'invalid_input'
        raise ActorSubjectError('UPSTREAM_' + upstream['reason_code'], status)
    return upstream['subject']


def _replay(raw: Any) -> dict[str, Any]:
    need(type(raw) is str and 1 <= len(raw) <= MAX_JSON,
         'JSON_MISSING_OR_TOO_LARGE')
    try:
        data = json.loads(raw, object_pairs_hook=_no_duplicate,
                          parse_constant=_reject_constant,
                          parse_float=lambda _: (_ for _ in ()).throw(
                              ActorSubjectError('JSON_FLOAT_FORBIDDEN')))
    except ActorSubjectError:
        raise
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError) as exc:
        raise ActorSubjectError('JSON_INVALID') from exc
    need(type(data) is dict and _canonical(data) == raw, 'JSON_NONCANONICAL')
    exact(data, {'schema', 'people_subject_id', 'repository_subject', 'actors',
                 'unattributed_evidence', 'coverage_gaps', 'claims',
                 'binding_sha256'}, 'RECORD_FIELDS_INVALID')
    need(data['schema'] == SCHEMA, 'RECORD_SCHEMA_INVALID')
    repo_subject = _repo_from_json(data['repository_subject'])
    expected_people = 'cesprs1:' + _digest('CES-EC194-PEOPLE-SUBJECT-v1', {
        'report_subject_id': repo_subject['report_subject_id'],
        'repository_id': repo_subject['repository']['repository_id'],
        'period_id': repo_subject['period']['period_id'],
    })
    need(data['people_subject_id'] == expected_people and
         type(data['people_subject_id']) is str and
         PEOPLE_SUBJECT_ID.fullmatch(data['people_subject_id']) is not None,
         'PEOPLE_SUBJECT_ID_INVALID')
    need(type(data['actors']) is list and len(data['actors']) <= MAX_ACTORS,
         'ACTOR_LIST_INVALID')
    actors = [_validate_actor_record(a, repo_subject) for a in data['actors']]
    need(actors == sorted(actors, key=lambda x: x['actor_key']),
         'ACTOR_ORDER_INVALID')
    keys = [a['actor_key'] for a in actors]
    need(len(keys) == len(set(keys)), 'DUPLICATE_ACTOR_IDENTITY')

    need(type(data['unattributed_evidence']) is list and
         len(data['unattributed_evidence']) <= MAX_EVIDENCE,
         'UNATTRIBUTED_LIST_INVALID')
    unattributed = [_validate_ref(r, repo_subject, unattributed=True)
                    for r in data['unattributed_evidence']]
    order = lambda x: (x['occurred_at_utc'], x['evidence_id'],
                       x['evidence_sha256'])
    need(unattributed == sorted(unattributed, key=order),
         'UNATTRIBUTED_ORDER_INVALID')

    all_ids: list[str] = []
    for actor in actors:
        all_ids.extend(r['evidence_id'] for r in actor['evidence_refs'])
    all_ids.extend(r['evidence_id'] for r in unattributed)
    need(len(all_ids) <= MAX_EVIDENCE, 'EVIDENCE_LIST_INVALID')
    need(len(all_ids) == len(set(all_ids)), 'DUPLICATE_EVIDENCE_ID')
    need(bool(actors) or bool(all_ids), 'EMPTY_PEOPLE_REPORT_SUBJECT')

    expected_gaps = _gaps(actors, unattributed, bool(all_ids))
    need(data['coverage_gaps'] == expected_gaps,
         'COVERAGE_GAPS_INVALID')
    need(data['claims'] == CLAIMS, 'CLAIMS_INVALID')
    rebuilt: dict[str, Any] = {
        'schema': SCHEMA,
        'people_subject_id': expected_people,
        'repository_subject': _repository_projection(repo_subject),
        'actors': actors,
        'unattributed_evidence': unattributed,
        'coverage_gaps': expected_gaps,
        'claims': dict(CLAIMS),
    }
    rebuilt['binding_sha256'] = _digest('CES-EC194-BINDING-v1', rebuilt)
    need(data['binding_sha256'] == rebuilt['binding_sha256'],
         'BINDING_DIGEST_INVALID')
    need(_canonical(rebuilt) == raw, 'ACTOR_SUBJECT_BINDING_MISMATCH')
    return rebuilt


def _envelope() -> dict[str, Any]:
    return {
        'schema': SCHEMA,
        'status': 'invalid_input',
        'exit_code': 4,
        'reason_code': 'ACTOR_REPORT_SUBJECT_INPUT_INVALID',
        'subject': None,
        'canonical_json': None,
        'limitations': dict(CLAIMS),
    }


def _failure(out: dict[str, Any], error: ActorSubjectError) -> dict[str, Any]:
    out['status'] = error.status
    out['exit_code'] = 5 if error.status == 'unavailable' else 4
    out['reason_code'] = 'ACTOR_REPORT_SUBJECT_' + error.reason
    return out


def _success(out: dict[str, Any], subject: dict[str, Any], reason: str) -> dict[str, Any]:
    serialized = _canonical(subject)
    need(len(serialized) <= MAX_JSON, 'SUBJECT_RECORD_TOO_LARGE')
    out.update(status='partial', exit_code=2, reason_code=reason,
               subject=subject, canonical_json=serialized)
    return out


class ActorReportSubject:
    """Bind or replay people subjects inside exactly one EC193 repo report.

    A valid result intentionally remains ``partial/2``.  Deterministic actor
    keys are repository-scoped aggregation keys, not authenticated global human
    identities and never grant write access.
    """

    def bind(self, *, repository_subject_json: str, actors: list[dict[str, Any]],
             evidence: list[dict[str, Any]]) -> dict[str, Any]:
        out = _envelope()
        try:
            upstream = RepositoryReportSubject().from_json(
                serialized=repository_subject_json)
            if upstream['status'] != 'partial':
                status = ('unavailable' if upstream['status'] == 'unavailable'
                          else 'invalid_input')
                raise ActorSubjectError('UPSTREAM_' + upstream['reason_code'],
                                        status)
            return _success(out, _assemble(upstream['subject'], actors, evidence),
                            'ACTOR_REPORT_SUBJECT_BOUND')
        except ActorSubjectError as exc:
            return _failure(out, exc)

    def from_json(self, *, serialized: str) -> dict[str, Any]:
        """Replay structure and hashes, including full EC193 subject replay.

        This detects accidental/casual record mutation but is not a signature,
        provider attestation or directory-service verification.
        """
        out = _envelope()
        try:
            return _success(out, _replay(serialized),
                            'ACTOR_REPORT_SUBJECT_REVALIDATED')
        except ActorSubjectError as exc:
            return _failure(out, exc)
