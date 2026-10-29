#!/usr/bin/env python3
"""EC191 focused time-zone and calendar tests, not system acceptance."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import jsonschema
from due_calendar import DueCalendar

HERE = Path(__file__).resolve().parent
SCHEMA = json.loads((HERE.parent / 'references' /
                     'project-due-calendar-result.v1.schema.json').read_text('utf-8'))


class DueCalendarCases(unittest.TestCase):
    def setUp(self):
        self.calc = DueCalendar(clock=lambda: datetime(2026, 10, 23, 12,
                                                      tzinfo=timezone.utc))

    def run_due(self, cadence='day', project_timezone='America/Los_Angeles',
                observed_at='2026-10-23T12:00:00Z', **options):
        result = self.calc.evaluate(project_timezone=project_timezone,
                                    cadence=cadence, observed_at=observed_at,
                                    **options)
        jsonschema.Draft202012Validator(SCHEMA).validate(result)
        return result

    def assert_refused(self, result, code):
        jsonschema.Draft202012Validator(SCHEMA).validate(result)
        self.assertIn(result['status'], ('invalid_input', 'unavailable'), result)
        self.assertEqual(result['reason_code'], code)
        self.assertIsNone(result['calendar'])
        self.assertIsNone(result['evaluated_at_local'])
        self.assertIsNone(result['decision']['is_due'])
        self.assertFalse(result['limitations']['scheduler_or_report_executed'])

    def test_distinct_timezone_same_utc_moment_cross_year(self):
        la = self.run_due('year', 'America/Los_Angeles', '2026-01-01T02:00:00Z')
        tokyo = self.run_due('year', 'Asia/Tokyo', '2026-01-01T02:00:00Z')
        self.assertEqual(la['calendar']['current_period']['start_date'], '2025-01-01')
        self.assertEqual(tokyo['calendar']['current_period']['start_date'], '2026-01-01')
        self.assertEqual(la['calendar']['last_closed_period']['start_date'], '2024-01-01')
        self.assertEqual(tokyo['calendar']['last_closed_period']['start_date'], '2025-01-01')
        self.assertEqual(la['decision']['state'], 'UNKNOWN')
        self.assertEqual(tokyo['decision']['state'], 'UNKNOWN')

    def test_march_dst_spring_forward_day_is_23_hours(self):
        r = self.run_due('day', 'America/New_York', '2026-03-08T16:00:00Z')
        self.assertEqual(r['calendar']['current_period']['elapsed_seconds'], 23*3600)
        self.assertEqual(r['calendar']['current_period']['start_local'],
                         '2026-03-08T00:00:00-05:00')
        self.assertEqual(r['calendar']['current_period']['end_exclusive_local'],
                         '2026-03-09T00:00:00-04:00')
        self.assertEqual(r['calendar']['last_closed_period']['elapsed_seconds'], 24*3600)

    def test_november_dst_fall_back_day_is_25_hours(self):
        r = self.run_due('day', 'America/New_York', '2026-11-01T18:00:00Z')
        self.assertEqual(r['calendar']['current_period']['elapsed_seconds'], 25*3600)
        self.assertEqual(r['calendar']['current_period']['start_local'],
                         '2026-11-01T00:00:00-04:00')
        self.assertEqual(r['calendar']['current_period']['end_exclusive_local'],
                         '2026-11-02T00:00:00-05:00')

    def test_week_iso_2020_cross_year_53rd_week(self):
        r = self.run_due('week', 'Europe/Berlin', '2021-01-01T12:00:00Z')
        self.assertEqual(r['calendar']['current_period']['start_date'], '2020-12-28')
        self.assertEqual(r['calendar']['current_period']['end_exclusive_date'], '2021-01-04')
        self.assertEqual(r['calendar']['last_closed_period']['start_date'], '2020-12-21')
        self.assertEqual(r['week_rule'], 'ISO_MONDAY')

    def test_week_dst_168_hours_minus_1(self):
        r = self.run_due('week', 'America/New_York', '2026-03-11T12:00:00Z')
        self.assertEqual(r['calendar']['current_period']['start_date'], '2026-03-09')
        self.assertEqual(r['calendar']['last_closed_period']['elapsed_seconds'], 167*3600)

    def test_month_dst_and_leap_february(self):
        march = self.run_due('month', 'America/New_York', '2026-03-15T12:00:00Z')
        self.assertEqual(march['calendar']['current_period']['elapsed_seconds'], 31*86400-3600)
        leap = self.run_due('month', 'UTC', '2024-02-20T12:00:00Z')
        self.assertEqual(leap['calendar']['current_period']['elapsed_seconds'], 29*86400)
        self.assertEqual(leap['calendar']['current_period']['end_exclusive_date'], '2024-03-01')

    def test_year_with_leap_and_tz_transition(self):
        leap = self.run_due('year', 'America/Los_Angeles', '2024-08-20T12:00:00Z')
        self.assertEqual(leap['calendar']['current_period']['elapsed_seconds'], 366*86400)
        self.assertEqual(leap['calendar']['current_period']['start_date'], '2024-01-01')
        self.assertEqual(leap['calendar']['last_closed_period']['start_date'], '2023-01-01')

    def test_half_hour_dst_shift(self):
        r = self.run_due('day', 'Australia/Lord_Howe', '2026-10-04T12:00:00Z')
        self.assertEqual(r['calendar']['current_period']['elapsed_seconds'],
                         23*3600+1800)

    def test_midnight_dst_gap_resolved_to_first_real_instant(self):
        r = self.run_due('day', 'America/Santiago', '2018-08-12T16:00:00Z')
        self.assertEqual(r['calendar']['current_period']['start_date'], '2018-08-12')
        self.assertEqual(r['calendar']['current_period']['start_local'],
                         '2018-08-12T01:00:00-03:00')
        self.assertEqual(r['calendar']['current_period']['elapsed_seconds'], 23*3600)

    def test_skipped_entire_civil_day_has_no_phantom_due_period(self):
        r = self.run_due('day', 'Pacific/Apia', '2011-12-30T11:00:00Z')
        self.assertEqual(r['calendar']['current_period']['start_date'], '2011-12-31')
        self.assertEqual(r['calendar']['last_closed_period']['start_date'], '2011-12-29')
        self.assertEqual(r['calendar']['last_closed_period']['end_exclusive_date'],
                         '2011-12-31')
        self.assertEqual(r['calendar']['last_closed_period']['elapsed_seconds'], 86400)

    def test_due_unknown_when_history_unspecified(self):
        r = self.run_due()
        self.assertEqual((r['status'], r['exit_code']), ('partial', 2))
        self.assertEqual(r['decision']['state'], 'UNKNOWN')
        self.assertIsNone(r['decision']['is_due'])
        self.assertEqual(r['decision']['basis'], 'PROCESSING_HISTORY_NOT_PROVIDED')

    def test_due_when_declared_never_processed(self):
        r = self.run_due(never_processed=True)
        self.assertEqual(r['decision']['state'], 'DUE')
        self.assertTrue(r['decision']['is_due'])

    def test_not_due_with_ack_for_most_recent_boundary(self):
        r = self.run_due(last_processed_boundary='2026-10-23T07:00:00Z')
        self.assertEqual(r['calendar']['most_recent_due_boundary_local'],
                         '2026-10-23T00:00:00-07:00')
        self.assertEqual(r['decision']['state'], 'NOT_DUE')
        self.assertFalse(r['decision']['is_due'])

    def test_due_when_ack_prior_boundary(self):
        r = self.run_due(last_processed_boundary='2026-10-22T07:00:00Z')
        self.assertEqual(r['decision']['state'], 'DUE')
        self.assertTrue(r['decision']['is_due'])


    def test_overdue_when_more_than_one_period_unprocessed(self):
        r = self.run_due(last_processed_boundary='2026-10-21T07:00:00Z')
        self.assertEqual(r['decision']['state'], 'OVERDUE')
        self.assertTrue(r['decision']['is_due'])

    def test_duplicated_midnight_uses_first_valid_fold(self):
        # Cuba falls back from 01:00 to 00:00 in some tzdb revisions;
        # the boundary must be the earlier midnight instant.
        zone = ZoneInfo('America/Havana')
        event = datetime(2026, 11, 1, 12, tzinfo=zone).astimezone(timezone.utc)
        r = self.run_due('day', 'America/Havana', event)
        self.assertEqual(r['calendar']['current_period']['start_date'], '2026-11-01')
        self.assertEqual(r['calendar']['current_period']['elapsed_seconds'], 25 * 3600)
        self.assertEqual(r['calendar']['current_period']['start_local'],
                         '2026-11-01T00:00:00-04:00')
        earliest = self.run_due('day', 'America/Havana', event,
                                last_processed_boundary='2026-11-01T04:00:00Z')
        self.assertEqual(earliest['decision']['state'], 'NOT_DUE')
        later = self.run_due('day', 'America/Havana', event,
                             last_processed_boundary='2026-11-01T05:00:00Z')
        self.assert_refused(later, 'DUE_LAST_PROCESSED_BOUNDARY_AFTER_ELIGIBLE_PERIOD')

    def test_ack_not_completion_timestamp(self):
        r = self.run_due(last_processed_boundary='2026-10-22T21:00:00Z')
        self.assert_refused(r, 'DUE_LAST_PROCESSED_NOT_EXACT_PROJECT_PERIOD_BOUNDARY')

    def test_ack_for_future_boundary_refused(self):
        r = self.run_due(last_processed_boundary='2026-10-24T07:00:00Z')
        self.assert_refused(r, 'DUE_LAST_PROCESSED_BOUNDARY_AFTER_ELIGIBLE_PERIOD')

    def test_ack_of_midnight_gap_accepted_at_first_instant(self):
        r = self.run_due('day','America/Santiago','2018-08-12T16:00:00Z',
                         last_processed_boundary='2018-08-12T04:00:00Z')
        self.assertEqual(r['decision']['state'], 'NOT_DUE')

    def test_ack_cross_year_iso_week_date_required(self):
        # Start of the ISO week is Dec 28, not Jan 1.
        yes = self.run_due('week', 'Europe/Berlin', '2021-01-01T12:00:00Z',
                           last_processed_boundary='2020-12-27T23:00:00Z')
        self.assertEqual(yes['decision']['state'], 'NOT_DUE')
        no = self.run_due('week', 'Europe/Berlin', '2021-01-01T12:00:00Z',
                          last_processed_boundary='2020-12-27T12:00:00Z')
        self.assert_refused(no, 'DUE_LAST_PROCESSED_NOT_EXACT_PROJECT_PERIOD_BOUNDARY')

    def test_explicit_utc_offset_normalized(self):
        r = self.run_due('day', 'Asia/Kolkata', '2026-10-23T17:30:00.123+05:30')
        self.assertEqual(r['evaluated_at_utc'], '2026-10-23T12:00:00.123000Z')
        self.assertEqual(r['calendar']['current_period']['start_local'],
                         '2026-10-23T00:00:00+05:30')

    def test_aware_datetime_observation(self):
        r = self.run_due('day', 'UTC', datetime(2026, 10, 23, 12,
                                               tzinfo=timezone(timedelta(hours=2))))
        self.assertEqual(r['evaluated_at_utc'], '2026-10-23T10:00:00Z')

    def test_utc_clock_injection_without_explicit_observed_at(self):
        r = self.calc.evaluate(project_timezone='UTC', cadence='day', never_processed=True)
        jsonschema.Draft202012Validator(SCHEMA).validate(r)
        self.assertEqual(r['evaluated_at_utc'], '2026-10-23T12:00:00Z')

    def test_clock_failure_does_not_default_host_local(self):
        bad = DueCalendar(clock=lambda: 123)
        r = bad.evaluate(project_timezone='UTC', cadence='day')
        self.assert_refused(r, 'DUE_UTC_CLOCK_RETURNED_NAIVE_OR_INVALID_INSTANT')
        raise_clock = DueCalendar(clock=lambda: 1/0)
        r = raise_clock.evaluate(project_timezone='UTC', cadence='day')
        self.assert_refused(r, 'DUE_UTC_CLOCK_UNAVAILABLE')

    def test_invalid_project_timezone_and_aliases(self):
        for name in (None, '', 'PST', 'EST', 'CST', 'GMT', 'Mars/Olympus',
                     'America/Los_Angeles ', '../UTC', '/etc/localtime',
                     'Etc/GMT+8', 'right/UTC'):
            with self.subTest(name=name):
                r = self.run_due(project_timezone=name)
                self.assertNotEqual(r['status'], 'partial', r)

    def test_timezone_case_does_not_silently_fallback(self):
        self.assert_refused(self.run_due(project_timezone='america/los_angeles'),
                            'DUE_PROJECT_TIMEZONE_NOT_FOUND')

    def test_invalid_cadence(self):
        for cadence in (None, 'Day', 'hour', '', 1, 'monthly'):
            with self.subTest(cadence=cadence):
                self.assert_refused(self.run_due(cadence=cadence), 'DUE_INVALID_CADENCE')

    def test_naive_datetime_and_local_timestamp_refused(self):
        for when in ('2026-10-23T12:00:00', '2026-10-23 12:00:00',
                     '2026-10-23T12:00:00+14:01',
                     datetime(2026, 10, 23, 12)):
            with self.subTest(value=when):
                self.assert_refused(self.run_due(observed_at=when),
                                    'DUE_OBSERVED_AT_OFFSET_REQUIRED')

    def test_conflicting_history_refused(self):
        self.assert_refused(self.run_due(never_processed=True,
                            last_processed_boundary='2026-10-23T07:00:00Z'),
                            'DUE_CONFLICTING_PROCESSING_HISTORY')

    def test_non_boolean_never_processed_refused(self):
        self.assert_refused(self.run_due(never_processed=1),
                            'DUE_NEVER_PROCESSED_MUST_BE_BOOLEAN')

    def test_week_month_year_ack_alignment(self):
        for cadence, anchor in [('week', '2026-10-19T07:00:00Z'),
                                ('month', '2026-10-01T07:00:00Z'),
                                ('year', '2026-01-01T08:00:00Z')]:
            with self.subTest(cadence=cadence):
                r = self.run_due(cadence, last_processed_boundary=anchor)
                self.assertEqual(r['decision']['state'], 'NOT_DUE', r)

    def test_large_but_supported_historical_year(self):
        r = self.run_due('day', 'UTC', '1970-01-01T00:00:00Z', never_processed=True)
        self.assertEqual(r['calendar']['last_closed_period']['start_date'], '1969-12-31')
        historic = self.run_due('month', 'Europe/Amsterdam', '1880-02-15T12:00:00Z')
        self.assertIn('+00:19:32', historic['calendar']['current_period']['start_local'])

    def test_date_extreme_refused_not_overflow(self):
        r = self.run_due('year', 'UTC', '9998-12-31T23:59:00Z')
        self.assert_refused(r, 'DUE_DATE_OUTSIDE_SAFE_CALENDAR_RANGE')

    def test_limitations_false_for_unverified_external_actions(self):
        r = self.run_due(never_processed=True)
        self.assertFalse(any(r['limitations'].values()))
        self.assertFalse(r['limitations']['natural_period_id_or_utc_interval_exported'])


if __name__ == '__main__':
    unittest.main()
