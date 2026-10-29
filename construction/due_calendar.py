#!/usr/bin/env python3
"""EC191: project-clock Due calendar and conservative recurrence eligibility.

Read-only, callable Python component. All calendar arithmetic uses an explicit
IANA project zone and aware instants; never the host's local timezone. Results
are calendar observations, not a scheduler, verified persisted acknowledgement,
ReportPrepare, EC192 natural-period ID or UTC interval export, or native CLI.
"""
from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone, tzinfo
import re
from typing import Any, Callable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

SCHEMA = 'ces.project_due_calendar.v1'
PERIODS = frozenset({'day', 'week', 'month', 'year'})
# Explicit IANA geographic/canonical aliases (not short ambiguous abbreviations).
ZONE_KEY = re.compile(r'[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)+\Z', re.ASCII)
OFFSET_TIMESTAMP = re.compile(
    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?'
    r'(?:Z|[+-](?:0\d|1[0-4]):[0-5]\d)\Z', re.ASCII)

LIMITATIONS = {
    'timezone_database_version_pinned': False,
    'native_due_action_registered': False,
    'external_acknowledgement_authenticated': False,
    'scheduler_or_report_executed': False,
    'natural_period_id_or_utc_interval_exported': False,
    'business_git_provider_or_ces_store_written': False,
}


class DueError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def require(ok: bool, code: str) -> None:
    if not ok:
        raise DueError(code)


def _load_zone(raw: Any) -> tzinfo:
    require(type(raw) is str and 1 <= len(raw) <= 96,
            'PROJECT_TIMEZONE_REQUIRED')
    if raw == 'UTC':
        # Fixed zero offset needs no tzdb; never substitute host local time.
        return timezone.utc
    if raw != 'UTC':
        require(ZONE_KEY.fullmatch(raw) is not None and
                not any(part in ('.', '..') or part.startswith('.')
                        for part in raw.split('/')) and
                not raw.startswith(('/', 'posix/', 'right/')) and
                not re.fullmatch(r'Etc/GMT[+-]\d{1,2}', raw),
                'PROJECT_TIMEZONE_MUST_BE_EXPLICIT_IANA')
    try:
        return ZoneInfo(raw)
    except ZoneInfoNotFoundError as exc:
        try:
            ZoneInfo('UTC')
        except ZoneInfoNotFoundError as utc_exc:
            raise DueError('TIMEZONE_DATABASE_UNAVAILABLE', 'unavailable') from utc_exc
        raise DueError('PROJECT_TIMEZONE_NOT_FOUND') from exc
    except (ValueError, OSError) as exc:
        raise DueError('TIMEZONE_DATABASE_UNAVAILABLE', 'unavailable') from exc


def _instant(raw: Any, code: str) -> datetime:
    """Accept only explicit-offset instants, never implicit local timestamps."""
    if type(raw) is datetime:
        stamp = raw
    elif type(raw) is str and OFFSET_TIMESTAMP.fullmatch(raw):
        try:
            stamp = datetime.fromisoformat(raw.replace('Z', '+00:00'))
        except ValueError as exc:
            raise DueError(code) from exc
    else:
        raise DueError(code)
    try:
        offset = stamp.utcoffset()
        require(offset is not None and abs(offset) <= timedelta(hours=14), code)
        utc = stamp.astimezone(timezone.utc)
        # Zone conversions around year 1 / 9999 may overflow; bound input.
        require(2 <= utc.year <= 9998, 'DATE_OUTSIDE_SAFE_CALENDAR_RANGE')
        return utc
    except DueError:
        raise
    except (ValueError, OverflowError, TypeError) as exc:
        raise DueError(code) from exc


def _utc_text(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z').replace('.000000Z', 'Z')


def _local_text(moment: datetime, zone: tzinfo) -> str:
    value = moment.astimezone(zone)
    return value.isoformat(timespec='seconds')


def _start_date(day: date, cadence: str) -> date:
    if cadence == 'day':
        return day
    if cadence == 'week':
        return day - timedelta(days=day.weekday())  # ISO week, Monday first
    if cadence == 'month':
        return day.replace(day=1)
    return day.replace(month=1, day=1)


def _shift(day: date, cadence: str, amount: int) -> date:
    """Move exactly one calendar period, never fixed UTC seconds/days for month/year."""
    require(amount in (-1, 1), 'INTERNAL_PERIOD_STEP_INVALID')
    try:
        if cadence == 'day':
            return day + timedelta(days=amount)
        if cadence == 'week':
            return day + timedelta(days=7 * amount)
        if cadence == 'month':
            m = day.year * 12 + day.month - 1 + amount
            return date(m // 12, m % 12 + 1, 1)
        return date(day.year + amount, 1, 1)
    except (ValueError, OverflowError) as exc:
        raise DueError('DATE_OUTSIDE_SAFE_CALENDAR_RANGE') from exc


def _boundary(target: date, zone: tzinfo) -> datetime:
    """First actual instant at/after project-local midnight on target date.

    A local 00:00 can be doubled (fall-back), missing (spring-forward at
    midnight), or a complete civil day can be skipped. Use UTC round-trips
    for both PEP 495 folds instead of blindly attaching tzinfo; choose the
    earliest valid midnight or earliest post-gap instant. No host-local call.
    """
    wall = datetime.combine(target, time.min)
    valid: set[datetime] = set()
    after: set[datetime] = set()
    try:
        for fold in (0, 1):
            guess = wall.replace(tzinfo=zone, fold=fold)
            instant = guess.astimezone(timezone.utc)
            back = instant.astimezone(zone).replace(tzinfo=None)
            if back == wall:
                valid.add(instant)
            elif back > wall:
                after.add(instant)
        candidates = valid or after
        if not candidates:
            raise DueError('PROJECT_MIDNIGHT_UNRESOLVABLE', 'unavailable')
        answer = min(candidates)
        require(2 <= answer.year <= 9998, 'DATE_OUTSIDE_SAFE_CALENDAR_RANGE')
        return answer
    except DueError:
        raise
    except (OverflowError, ValueError) as exc:
        raise DueError('PROJECT_MIDNIGHT_UNRESOLVABLE', 'unavailable') from exc


def _window(start_day: date, cadence: str, zone: tzinfo,
            start_utc: datetime | None = None, end_utc: datetime | None = None) -> dict[str, Any]:
    next_day = _shift(start_day, cadence, 1)
    left = start_utc if start_utc is not None else _boundary(start_day, zone)
    right = end_utc if end_utc is not None else _boundary(next_day, zone)
    if right <= left:
        raise DueError('EMPTY_OR_REVERSED_PROJECT_PERIOD', 'unavailable')
    return {
        'start_date': start_day.isoformat(),
        'end_exclusive_date': next_day.isoformat(),
        'start_local': _local_text(left, zone),
        'end_exclusive_local': _local_text(right, zone),
        'elapsed_seconds': int((right - left).total_seconds()),
    }


def _previous_nonempty(start_day: date, cadence: str, zone: tzinfo,
                       current_start: datetime) -> tuple[date, datetime]:
    previous = _shift(start_day, cadence, -1)
    # Civil dates can be skipped (e.g. Samoa 2011-12-30). Such dates must
    # never become phantom daily reports. Bound search instead of looping.
    for _ in range(32):
        bound = _boundary(previous, zone)
        if bound < current_start:
            return previous, bound
        previous = _shift(previous, cadence, -1)
    raise DueError('PREVIOUS_REAL_PERIOD_NOT_FOUND', 'unavailable')


def _ack_boundary(raw: Any, cadence: str, zone: tzinfo,
                  most_recent: datetime) -> datetime:
    ack = _instant(raw, 'LAST_PROCESSED_BOUNDARY_INVALID')
    require(ack <= most_recent, 'LAST_PROCESSED_BOUNDARY_AFTER_ELIGIBLE_PERIOD')
    project_day = ack.astimezone(zone).date()
    require(_start_date(project_day, cadence) == project_day and
            _boundary(project_day, zone) == ack,
            'LAST_PROCESSED_NOT_EXACT_PROJECT_PERIOD_BOUNDARY')
    return ack


class DueCalendar:
    """Compute local natural boundaries and caller-state-dependent due status.

    `last_processed_boundary` refers to the most recent successfully handled
    **due boundary**, not the completion wall-clock time. A system of record
    must durably bind this marker to the handled report. This API does not.
    """

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def evaluate(self, *, project_timezone: str, cadence: str,
                 observed_at: str | datetime | None = None,
                 last_processed_boundary: str | datetime | None = None,
                 never_processed: bool = False) -> dict[str, Any]:
        result = {
            'schema': SCHEMA, 'status': 'invalid_input', 'exit_code': 4,
            'reason_code': 'DUE_INPUT_INVALID', 'project_timezone': None,
            'cadence': None, 'evaluated_at_utc': None,
            'evaluated_at_local': None, 'week_rule': 'ISO_MONDAY',
            'calendar': None,
            'decision': {'state': 'UNKNOWN', 'is_due': None,
                         'basis': 'NOT_EVALUATED',
                         'last_processed_boundary_at_utc': None},
            'limitations': dict(LIMITATIONS),
        }
        try:
            require(type(cadence) is str and cadence in PERIODS, 'INVALID_CADENCE')
            require(type(never_processed) is bool, 'NEVER_PROCESSED_MUST_BE_BOOLEAN')
            require(not (never_processed and last_processed_boundary is not None),
                    'CONFLICTING_PROCESSING_HISTORY')
            zone = _load_zone(project_timezone)
            if observed_at is None:
                try:
                    now = self._clock()
                except Exception as exc:
                    raise DueError('UTC_CLOCK_UNAVAILABLE', 'unavailable') from exc
                moment = _instant(now, 'UTC_CLOCK_RETURNED_NAIVE_OR_INVALID_INSTANT')
            else:
                moment = _instant(observed_at, 'OBSERVED_AT_OFFSET_REQUIRED')
            try:
                local = moment.astimezone(zone)
            except (OverflowError, ValueError) as exc:
                raise DueError('PROJECT_TIME_CONVERSION_UNAVAILABLE', 'unavailable') from exc
            anchor_date = _start_date(local.date(), cadence)
            current_start = _boundary(anchor_date, zone)
            next_start = _boundary(_shift(anchor_date, cadence, 1), zone)
            require(current_start <= moment < next_start,
                    'PROJECT_PERIOD_DOES_NOT_CONTAIN_OBSERVATION')
            last_day, last_start = _previous_nonempty(anchor_date, cadence,
                                                      zone, current_start)
            current = _window(anchor_date, cadence, zone, current_start, next_start)
            closed = _window(last_day, cadence, zone, last_start, current_start)
            # If skipped civil dates occur, the last *nonempty* interval
            # ends at current_start; its nominal end date can differ.
            if _shift(last_day, cadence, 1) != anchor_date:
                closed['end_exclusive_date'] = anchor_date.isoformat()
            if last_processed_boundary is not None:
                ack = _ack_boundary(last_processed_boundary, cadence, zone,
                                    current_start)
                due = ack < current_start
                state = ('OVERDUE' if ack < last_start else 'DUE') if due else 'NOT_DUE'
                decision = (state, due, 'EXPLICIT_LAST_PROCESSED_BOUNDARY',
                            _utc_text(ack))
            elif never_processed:
                decision = ('DUE', True, 'CALLER_DECLARED_NEVER_PROCESSED', None)
            else:
                decision = ('UNKNOWN', None, 'PROCESSING_HISTORY_NOT_PROVIDED', None)
            result.update({
                'status': 'partial', 'exit_code': 2,
                'reason_code': ('DUE_HISTORY_REQUIRED' if decision[0] == 'UNKNOWN'
                                else 'DUE_PROJECT_PERIOD_EVALUATED'),
                'project_timezone': project_timezone, 'cadence': cadence,
                'evaluated_at_utc': _utc_text(moment),
                'evaluated_at_local': _local_text(moment, zone),
                'calendar': {
                    'current_period': current,
                    'last_closed_period': closed,
                    'most_recent_due_boundary_local': current['start_local'],
                    'next_due_boundary_local': current['end_exclusive_local'],
                },
                'decision': {
                    'state': decision[0], 'is_due': decision[1],
                    'basis': decision[2],
                    'last_processed_boundary_at_utc': decision[3],
                },
            })
        except DueError as exc:
            result['status'] = exc.status
            result['exit_code'] = 4 if exc.status == 'invalid_input' else 5
            result['reason_code'] = 'DUE_' + exc.code
        return result
