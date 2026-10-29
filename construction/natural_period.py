#!/usr/bin/env python3
"""EC192: canonical local natural-period identity and actual UTC half-open bounds.

Read-only, deterministic for a particular runtime IANA tzdb release. Reuses
EC191's midnight/fold/gap resolution, not host-local time or UTC-duration
shortcuts. A period ID is a *calendar selector*, not an authenticated report,
project, repository or immutable timezone-rule snapshot.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
import json
import re
from typing import Any

from due_calendar import (
    DueError, PERIODS, _boundary, _instant, _load_zone, _local_text,
    _shift, _start_date, _utc_text,
)

SCHEMA = 'ces.natural_period.v1'
ID_PREFIX = 'cesnp1'
ID_LIMIT = 160
JSON_LIMIT = 4096
DAY = re.compile(r'\d{4}-\d{2}-\d{2}\Z', re.ASCII)
WEEK = re.compile(r'\d{4}-W\d{2}\Z', re.ASCII)
MONTH = re.compile(r'\d{4}-\d{2}\Z', re.ASCII)
YEAR = re.compile(r'\d{4}\Z', re.ASCII)

LIMITATIONS = {
    'timezone_database_version_pinned': False,
    'zone_key_aliases_canonicalized': False,
    'report_or_project_source_authenticated': False,
    'external_processing_history_authenticated': False,
    'scheduler_report_or_publishing_executed': False,
    'native_powershell_period_action_registered': False,
    'business_repository_or_external_system_written': False,
}


class PeriodError(ValueError):
    """Safe, machine-readable denial without input echo or partial intervals."""

    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def _require(test: bool, code: str) -> None:
    if not test:
        raise PeriodError(code)


def _canonical(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False)


def _label(cadence: str, anchor: date) -> str:
    if cadence == 'day':
        return anchor.isoformat()
    if cadence == 'week':
        iso_year, iso_week, _ = anchor.isocalendar()
        return f'{iso_year:04d}-W{iso_week:02d}'
    if cadence == 'month':
        return f'{anchor.year:04d}-{anchor.month:02d}'
    return f'{anchor.year:04d}'


def _anchor(cadence: str, label: Any) -> date:
    """Strictly parse a natural calendar label (not a UTC date/time)."""
    _require(type(label) is str and len(label) <= 10, 'LABEL_INVALID')
    try:
        if cadence == 'day' and DAY.fullmatch(label):
            answer = date.fromisoformat(label)
        elif cadence == 'week' and WEEK.fullmatch(label):
            answer = date.fromisocalendar(int(label[:4]), int(label[6:]), 1)
        elif cadence == 'month' and MONTH.fullmatch(label):
            answer = date(int(label[:4]), int(label[5:]), 1)
        elif cadence == 'year' and YEAR.fullmatch(label):
            answer = date(int(label), 1, 1)
        else:
            raise PeriodError('LABEL_INVALID')
    except (ValueError, OverflowError) as exc:
        raise PeriodError('LABEL_INVALID') from exc
    _require(_start_date(answer, cadence) == answer and
             _label(cadence, answer) == label, 'LABEL_NONCANONICAL')
    return answer


def _id_parts(raw: Any) -> tuple[str, str, str]:
    _require(type(raw) is str and 12 <= len(raw) <= ID_LIMIT,
             'PERIOD_ID_INVALID')
    parts = raw.split(':')
    _require(len(parts) == 4 and parts[0] == ID_PREFIX and
             parts[1] in PERIODS and parts[2] and parts[3],
             'PERIOD_ID_INVALID')
    return parts[1], parts[2], parts[3]


def _index(cadence: str, anchor: date) -> int:
    """Monotonic local-calendar ordinal *within one timezone+cadence lane*."""
    if cadence == 'day':
        return anchor.toordinal()
    if cadence == 'week':
        return (anchor.toordinal() - 1) // 7  # ordinal(0001-01-01) = 1, Monday
    if cadence == 'month':
        return anchor.year * 12 + anchor.month - 1
    return anchor.year


def _make(zone_key: str, cadence: str, anchor: date,
          zone: Any) -> dict[str, Any]:
    """Recalculate boundaries from calendar rules; never trust supplied UTC."""
    left = _boundary(anchor, zone)
    right = _boundary(_shift(anchor, cadence, +1), zone)
    # Deleted local days (Apia 2011-12-30) are not zero-second periods.
    _require(left < right, 'NONEXISTENT_LOCAL_PERIOD')
    first_day = left.astimezone(zone).date()
    end_day = right.astimezone(zone).date()
    # A partial local start is allowed only for a gap; whole-day deletion
    # cannot be used to fabricate the deleted daily ID.
    _require(first_day >= anchor and end_day > first_day,
             'NONEXISTENT_LOCAL_PERIOD')
    duration = right - left
    # UTC-boundary periods are second aligned with Python zoneinfo and no
    # fixed 86400-second assumption is made anywhere.
    _require(duration.microseconds == 0, 'SUBSECOND_BOUNDARY_UNAVAILABLE')
    label = _label(cadence, anchor)
    identifier = f'{ID_PREFIX}:{cadence}:{zone_key}:{label}'
    _require(len(identifier) <= ID_LIMIT, 'PERIOD_ID_INVALID')
    return {
        'schema': SCHEMA,
        'period_id': identifier,
        'project_timezone': zone_key,
        'cadence': cadence,
        'label': label,
        'week_rule': 'ISO_MONDAY',
        'period_index': _index(cadence, anchor),
        'calendar_anchor_date': anchor.isoformat(),
        'actual_start_local_date': first_day.isoformat(),
        'actual_end_exclusive_local_date': end_day.isoformat(),
        'start_local': _local_text(left, zone),
        'end_exclusive_local': _local_text(right, zone),
        'start_utc': _utc_text(left),
        'end_exclusive_utc': _utc_text(right),
        'elapsed_seconds': int(duration.total_seconds()),
    }


def _resolve(raw: Any) -> dict[str, Any]:
    cadence, zone_key, label = _id_parts(raw)
    zone = _load_zone(zone_key)
    anchor = _anchor(cadence, label)
    result = _make(zone_key, cadence, anchor, zone)
    _require(result['period_id'] == raw, 'PERIOD_ID_NONCANONICAL')
    return result


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PeriodError('JSON_DUPLICATE_KEY')
        result[key] = value
    return result


def _refuse_json_constant(raw: str) -> Any:
    raise PeriodError('JSON_INVALID')


def _parse(raw: Any) -> dict[str, Any]:
    _require(type(raw) is str and 1 <= len(raw) <= JSON_LIMIT,
             'JSON_REQUIRED_OR_TOO_LARGE')
    try:
        supplied = json.loads(raw, object_pairs_hook=_no_duplicate_keys,
                              parse_constant=_refuse_json_constant)
    except PeriodError:
        raise
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise PeriodError('JSON_INVALID') from exc
    _require(type(supplied) is dict, 'JSON_RECORD_REQUIRED')
    # Canonical, ASCII-escaped, sorted keys, no whitespace, duplicate keys,
    # NaN or non-normalized alternate textual representations.
    _require(raw == _canonical(supplied), 'JSON_NONCANONICAL')
    expected = _resolve(supplied.get('period_id'))
    _require(set(supplied) == set(expected), 'JSON_RECORD_FIELDS_INVALID')
    identity_keys = ('schema', 'period_id', 'project_timezone', 'cadence',
                     'label', 'week_rule', 'period_index', 'calendar_anchor_date')
    _require(all(type(supplied[k]) is type(expected[k]) and
                 supplied[k] == expected[k] for k in identity_keys),
             'JSON_IDENTITY_MISMATCH')
    bounds = ('start_utc', 'end_exclusive_utc', 'start_local',
              'end_exclusive_local', 'actual_start_local_date',
              'actual_end_exclusive_local_date', 'elapsed_seconds')
    _require(all(type(supplied[k]) is type(expected[k]) and
                 supplied[k] == expected[k] for k in bounds),
             'JSON_INTERVAL_MISMATCH')
    return expected


def _envelope() -> dict[str, Any]:
    return {
        'schema': SCHEMA,
        'status': 'invalid_input',
        'exit_code': 4,
        'reason_code': 'PERIOD_INPUT_INVALID',
        'period': None,
        'canonical_json': None,
        'comparison': None,
        'limitations': dict(LIMITATIONS),
    }


def _fail(result: dict[str, Any], error: Exception) -> dict[str, Any]:
    if isinstance(error, DueError):
        result['status'] = error.status
        result['reason_code'] = 'PERIOD_' + error.code
    else:
        assert isinstance(error, PeriodError)
        result['status'] = error.status
        result['reason_code'] = 'PERIOD_' + error.code
    result['exit_code'] = 5 if result['status'] == 'unavailable' else 4
    return result


def _success_period(result: dict[str, Any], record: dict[str, Any],
                    reason: str) -> dict[str, Any]:
    result.update(status='partial', exit_code=2, reason_code=reason,
                  period=record, canonical_json=_canonical(record))
    return result


class NaturalPeriod:
    """Read-only interval materialization, canonical JSON replay and ordering.

    All successful responses are partial/2: there is no authenticated
    project configuration, frozen tzdb revision, report actor or repository.
    """

    def from_instant(self, *, project_timezone: str, cadence: str,
                     observed_at: str | datetime) -> dict[str, Any]:
        out = _envelope()
        try:
            _require(type(cadence) is str and cadence in PERIODS,
                     'INVALID_CADENCE')
            zone = _load_zone(project_timezone)
            moment = _instant(observed_at, 'OBSERVED_AT_OFFSET_REQUIRED')
            anchor = _start_date(moment.astimezone(zone).date(), cadence)
            record = _make(project_timezone, cadence, anchor, zone)
            _require(_instant(record['start_utc'], 'INTERNAL_START_INVALID') <= moment <
                     _instant(record['end_exclusive_utc'], 'INTERNAL_END_INVALID'),
                     'OBSERVATION_OUTSIDE_PERIOD')
            return _success_period(out, record, 'PERIOD_INTERVAL_COMPUTED')
        except (DueError, PeriodError) as exc:
            return _fail(out, exc)
        except (ValueError, OverflowError) as exc:
            return _fail(out, PeriodError('PROJECT_TIME_CONVERSION_UNAVAILABLE',
                                          'unavailable'))

    def from_id(self, *, period_id: str) -> dict[str, Any]:
        out = _envelope()
        try:
            return _success_period(out, _resolve(period_id),
                                   'PERIOD_INTERVAL_COMPUTED')
        except (DueError, PeriodError) as exc:
            return _fail(out, exc)

    def from_json(self, *, serialized: str) -> dict[str, Any]:
        """Fail closed on noncanonical JSON, tampering or changed tzdb rules.

        Recomputing bounds at read time detects differences, but without a
        pinned tzdb version cannot distinguish authorized tzdb drift from
        forged bytes. Never quietly rewrite or accept a stale interval.
        """
        out = _envelope()
        try:
            return _success_period(out, _parse(serialized),
                                   'PERIOD_CANONICAL_REVALIDATED')
        except (DueError, PeriodError) as exc:
            return _fail(out, exc)

    def compare(self, *, left_id: str, right_id: str) -> dict[str, Any]:
        """Compare two periods in the *same* calendar timezone/cadence lane."""
        out = _envelope()
        try:
            left, right = _resolve(left_id), _resolve(right_id)
            _require((left['project_timezone'], left['cadence']) ==
                     (right['project_timezone'], right['cadence']),
                     'COMPARISON_LANE_MISMATCH')
            order = (left['period_index'] > right['period_index']) - (
                left['period_index'] < right['period_index'])
            # Distinct natural periods on one lane must not overlap even if
            # civil labels skip an entire day in the timezone's history.
            if order < 0:
                _require(left['end_exclusive_utc'] <= right['start_utc'],
                         'COMPARISON_OVERLAP_UNAVAILABLE')
            if order > 0:
                _require(right['end_exclusive_utc'] <= left['start_utc'],
                         'COMPARISON_OVERLAP_UNAVAILABLE')
            out.update(
                status='partial', exit_code=2,
                reason_code='PERIOD_ORDER_COMPUTED',
                comparison={
                    'left_id': left_id,
                    'right_id': right_id,
                    'order': order,
                    'relation': ('BEFORE' if order < 0 else
                                 'AFTER' if order > 0 else 'SAME'),
                    'touching': (order < 0 and left['end_exclusive_utc'] ==
                                 right['start_utc']) or
                                (order > 0 and right['end_exclusive_utc'] ==
                                 left['start_utc']),
                },
            )
            return out
        except (DueError, PeriodError) as exc:
            return _fail(out, exc)
