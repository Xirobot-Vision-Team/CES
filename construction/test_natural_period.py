#!/usr/bin/env python3
"""Focused EC192 behavior and schema checks, not cross-OS/live acceptance."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import jsonschema
from natural_period import NaturalPeriod
from due_calendar import DueError

HERE = Path(__file__).resolve().parent
SCHEMA = json.loads((HERE.parent / 'references' /
                     'natural-period-result.v1.schema.json').read_text('utf-8'))
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


class NaturalPeriodCases(unittest.TestCase):
    def setUp(self):
        self.api = NaturalPeriod()

    def check(self, response):
        VALIDATOR.validate(response)
        return response

    def at(self, tz='America/New_York', cadence='day',
           now='2026-03-08T12:00:00Z'):
        return self.check(self.api.from_instant(
            project_timezone=tz, cadence=cadence, observed_at=now))

    def id(self, period_id):
        return self.check(self.api.from_id(period_id=period_id))

    def read(self, raw):
        return self.check(self.api.from_json(serialized=raw))

    def refused(self, response, code=None):
        self.check(response)
        self.assertIn(response['status'], ('invalid_input', 'unavailable'))
        self.assertIsNone(response['period'])
        self.assertIsNone(response['canonical_json'])
        self.assertIsNone(response['comparison'])
        if code:
            self.assertEqual(response['reason_code'], 'PERIOD_' + code)

    def assert_roundtrip(self, result):
        self.assertEqual(result['status'], 'partial', result)
        record = result['period']
        self.assertEqual(record['schema'], 'ces.natural_period.v1')
        self.assertEqual(self.id(record['period_id'])['period'], record)
        self.assertEqual(self.read(result['canonical_json'])['period'], record)
        self.assertEqual(json.dumps(record, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True), result['canonical_json'])
        self.assertFalse(any(result['limitations'].values()))

    def test_day_spring_dst_exact_utc_half_open_23h(self):
        r = self.at()
        self.assert_roundtrip(r)
        p = r['period']
        self.assertEqual(p['period_id'], 'cesnp1:day:America/New_York:2026-03-08')
        self.assertEqual((p['start_utc'], p['end_exclusive_utc']),
                         ('2026-03-08T05:00:00Z', '2026-03-09T04:00:00Z'))
        self.assertEqual(p['elapsed_seconds'], 23 * 3600)
        self.assertEqual(p['start_local'], '2026-03-08T00:00:00-05:00')
        self.assertEqual(p['end_exclusive_local'], '2026-03-09T00:00:00-04:00')

    def test_fall_back_day_25h_two_observations_one_id(self):
        early = self.at(now='2026-11-01T05:30:00Z')
        later = self.at(now='2026-11-01T06:30:00Z')
        self.assert_roundtrip(early)
        self.assertEqual(early['period'], later['period'])
        self.assertEqual(early['period']['elapsed_seconds'], 25 * 3600)
        self.assertEqual(later['period']['start_utc'], '2026-11-01T04:00:00Z')

    def test_iso_week_53_cross_year_jan_1_2021(self):
        r = self.at('Europe/Berlin', 'week', '2021-01-01T12:00:00Z')
        self.assert_roundtrip(r)
        p = r['period']
        self.assertEqual(p['period_id'], 'cesnp1:week:Europe/Berlin:2020-W53')
        self.assertEqual(p['calendar_anchor_date'], '2020-12-28')
        self.assertEqual(p['actual_end_exclusive_local_date'], '2021-01-04')
        self.assertEqual(p['start_utc'], '2020-12-27T23:00:00Z')
        self.assertEqual(p['end_exclusive_utc'], '2021-01-03T23:00:00Z')
        self.assertEqual(self.at('UTC', 'week', '2021-01-04T00:00:00Z')
                         ['period']['label'], '2021-W01')

    def test_week_with_dst_actual_167h(self):
        r = self.at(cadence='week', now='2026-03-08T12:00:00Z')
        self.assert_roundtrip(r)
        self.assertEqual(r['period']['elapsed_seconds'], 167 * 3600)

    def test_month_leap_february_and_year(self):
        feb = self.at('UTC', 'month', '2024-02-29T23:59:59Z')
        self.assert_roundtrip(feb)
        self.assertEqual(feb['period']['period_id'], 'cesnp1:month:UTC:2024-02')
        self.assertEqual(feb['period']['elapsed_seconds'], 29 * 86400)
        year = self.at('UTC', 'year', '2024-05-20T12:00:00Z')
        self.assert_roundtrip(year)
        self.assertEqual(year['period']['elapsed_seconds'], 366 * 86400)
        self.assertEqual(year['period']['period_id'], 'cesnp1:year:UTC:2024')

    def test_year_differs_across_project_timezones_at_same_instant(self):
        a = self.at('America/Los_Angeles', 'year', '2026-01-01T02:00:00Z')
        b = self.at('Asia/Tokyo', 'year', '2026-01-01T02:00:00Z')
        self.assertEqual(a['period']['label'], '2025')
        self.assertEqual(b['period']['label'], '2026')
        self.assert_roundtrip(a)
        self.assert_roundtrip(b)

    def test_lord_howe_half_hour_dst(self):
        r = self.at('Australia/Lord_Howe', 'day', '2026-10-04T12:00:00Z')
        self.assert_roundtrip(r)
        self.assertEqual(r['period']['elapsed_seconds'], 84600)

    def test_santiago_midnight_gap_actual_start_01(self):
        r = self.at('America/Santiago', 'day', '2018-08-12T16:00:00Z')
        self.assert_roundtrip(r)
        self.assertEqual(r['period']['start_local'], '2018-08-12T01:00:00-03:00')
        self.assertEqual(r['period']['start_utc'], '2018-08-12T04:00:00Z')

    def test_havana_fold_midnight_picks_earliest(self):
        r = self.at('America/Havana', 'day', '2026-11-01T12:00:00Z')
        self.assert_roundtrip(r)
        self.assertEqual(r['period']['start_utc'], '2026-11-01T04:00:00Z')
        self.assertEqual(r['period']['elapsed_seconds'], 25 * 3600)

    def test_apia_deleted_day_refused_but_adjacent_real_dates_touch(self):
        deleted = self.id('cesnp1:day:Pacific/Apia:2011-12-30')
        self.refused(deleted, 'NONEXISTENT_LOCAL_PERIOD')
        first = self.id('cesnp1:day:Pacific/Apia:2011-12-29')
        next_ = self.id('cesnp1:day:Pacific/Apia:2011-12-31')
        self.assert_roundtrip(first)
        self.assert_roundtrip(next_)
        self.assertEqual(first['period']['actual_end_exclusive_local_date'],
                         '2011-12-31')
        self.assertEqual(first['period']['end_exclusive_utc'],
                         next_['period']['start_utc'])
        relation = self.check(self.api.compare(
            left_id=first['period']['period_id'],
            right_id=next_['period']['period_id']))
        self.assertEqual(relation['comparison']['order'], -1)
        self.assertTrue(relation['comparison']['touching'])
        self.assertEqual(next_['period']['period_index'] -
                         first['period']['period_index'], 2)

    def test_same_utc_event_no_implicit_host_local_timezone(self):
        r = self.at('UTC', now='2026-10-23T13:00:00+01:00')
        self.assert_roundtrip(r)
        self.assertEqual(r['period']['start_utc'], '2026-10-23T00:00:00Z')
        self.assertEqual(r['period']['end_exclusive_utc'], '2026-10-24T00:00:00Z')

    def test_historical_local_offset_seconds(self):
        r = self.at('Europe/Amsterdam', 'month', '1880-02-15T12:00:00Z')
        self.assert_roundtrip(r)
        self.assertEqual(r['period']['start_local'],
                         '1880-02-01T00:00:00+00:19:32')

    def test_adjacent_intervals_end_is_exclusive(self):
        current = self.at('UTC', 'day', '2026-10-23T23:59:59.999999Z')
        following = self.at('UTC', 'day', '2026-10-24T00:00:00Z')
        self.assert_roundtrip(current)
        self.assertEqual(current['period']['end_exclusive_utc'],
                         following['period']['start_utc'])
        self.assertNotEqual(current['period']['period_id'],
                            following['period']['period_id'])

    def test_local_lane_ordering_and_touching(self):
        a = 'cesnp1:month:UTC:2024-01'
        b = 'cesnp1:month:UTC:2024-02'
        ab = self.check(self.api.compare(left_id=a, right_id=b))
        ba = self.check(self.api.compare(left_id=b, right_id=a))
        aa = self.check(self.api.compare(left_id=a, right_id=a))
        self.assertEqual((ab['comparison']['order'], ab['comparison']['relation'],
                          ab['comparison']['touching']), (-1, 'BEFORE', True))
        self.assertEqual((ba['comparison']['order'], ba['comparison']['relation'],
                          ba['comparison']['touching']), (1, 'AFTER', True))
        self.assertEqual((aa['comparison']['order'], aa['comparison']['relation'],
                          aa['comparison']['touching']), (0, 'SAME', False))
        self.assertIsNone(ab['period'])
        self.assertIsNone(ab['canonical_json'])

    def test_comparison_cannot_mix_timezone_or_frequency(self):
        for b in ('cesnp1:day:UTC:2026-03-08',
                  'cesnp1:week:America/New_York:2026-W10'):
            with self.subTest(b=b):
                self.refused(self.api.compare(
                    left_id='cesnp1:day:America/New_York:2026-03-08',
                    right_id=b), 'COMPARISON_LANE_MISMATCH')

    def test_invalid_timezones_cadence_clocks(self):
        for tz in ('CST', 'PST', '', 'Etc/GMT+8', 'Mars/Never',
                   'America/New_York ', None):
            self.refused(self.api.from_instant(
                project_timezone=tz, cadence='day',
                observed_at='2026-03-08T12:00:00Z'))
        for c in ('Day', 'iso_week', 'hour', '', None, 1):
            self.refused(self.api.from_instant(
                project_timezone='UTC', cadence=c,
                observed_at='2026-03-08T12:00:00Z'), 'INVALID_CADENCE')
        for now in ('2026-03-08T12:00:00', '2026-03-08 12:00:00Z',
                    datetime(2026, 3, 8, 12), None):
            self.refused(self.api.from_instant(
                project_timezone='UTC', cadence='day', observed_at=now),
                'OBSERVED_AT_OFFSET_REQUIRED')

    def test_invalid_day_week_month_year_labels(self):
        invalid = (
            'cesnp1:day:UTC:2024-02-30',
            'cesnp1:day:UTC:2026-3-08',
            'cesnp1:week:UTC:2021-W53',
            'cesnp1:week:UTC:2024-W00',
            'cesnp1:week:UTC:2024-W54',
            'cesnp1:month:UTC:2024-13',
            'cesnp1:month:UTC:2024-2',
            'cesnp1:year:UTC:0000',
            'cesnp1:year:UTC:9998',
            'cesnp1:day:UTC:0001-01-01',
            'cesnp1:day:UTC:9999-01-01',
            'cesnp1:day:UTC:2026-03-08-extra',
            'cesnp1:day:UTC:2026-03-08:injected',
            'cesnp1:DAY:UTC:2026-03-08',
            'cesnp2:day:UTC:2026-03-08',
        )
        for item in invalid:
            with self.subTest(item=item):
                self.refused(self.id(item))

    def test_bad_json_is_rejected_without_partial_interval(self):
        r = self.at('UTC')
        raw = r['canonical_json']
        for candidate in (' ' + raw, raw + '\n', '{}', '[]', '', 'null',
                          123, b'{}', raw * 100, '{"x": NaN}',
                          '{"period_id":"a","period_id":"b"}'):
            with self.subTest(value=repr(candidate)[:30]):
                self.refused(self.read(candidate))

    def test_canonical_json_interval_tamper_is_not_silently_repaired(self):
        r = self.at('UTC')
        p = dict(r['period'])
        p['end_exclusive_utc'] = '2026-03-10T00:00:00Z'
        altered = json.dumps(p, sort_keys=True, separators=(',', ':'))
        self.refused(self.read(altered), 'JSON_INTERVAL_MISMATCH')
        p = dict(r['period'])
        p['period_index'] += 1
        self.refused(self.read(json.dumps(p, sort_keys=True,
                                          separators=(',', ':'))),
                     'JSON_IDENTITY_MISMATCH')
        p = dict(r['period'])
        p['extra'] = 1
        self.refused(self.read(json.dumps(p, sort_keys=True,
                                          separators=(',', ':'))),
                     'JSON_RECORD_FIELDS_INVALID')

    def test_timezone_database_drift_rejected_not_autorewritten(self):
        r = self.at('UTC', 'day', '2026-03-08T12:00:00Z')
        with patch('natural_period._make') as mock:
            wrong = dict(r['period'])
            wrong['end_exclusive_utc'] = '2026-03-09T01:00:00Z'
            mock.return_value = wrong
            self.refused(self.read(r['canonical_json']),
                         'JSON_INTERVAL_MISMATCH')

    def test_bare_period_id_can_recalculate_but_not_prove_old_boundaries(self):
        r = self.at()
        from_id = self.id(r['period']['period_id'])
        self.assert_roundtrip(from_id)
        self.assertEqual(from_id['period'], r['period'])
        self.assertNotIn('tzdb_version', from_id['period'])
        self.assertFalse(from_id['limitations']['timezone_database_version_pinned'])
        self.assertFalse(from_id['limitations']['report_or_project_source_authenticated'])

    def test_zone_alias_keys_have_distinct_identity(self):
        a = self.at('UTC')
        b = self.at('Etc/UTC')
        self.assert_roundtrip(b)
        self.assertNotEqual(a['period']['period_id'], b['period']['period_id'])
        self.refused(self.api.compare(left_id=a['period']['period_id'],
                                      right_id=b['period']['period_id']),
                     'COMPARISON_LANE_MISMATCH')

    def test_unavailable_timezone_propagates_safe_status(self):
        with patch('natural_period._boundary', side_effect=DueError(
                'PROJECT_MIDNIGHT_UNRESOLVABLE', 'unavailable')):
            self.refused(self.id('cesnp1:day:UTC:2026-03-08'),
                         'PROJECT_MIDNIGHT_UNRESOLVABLE')

    def test_input_types_fail_closed(self):
        for value in (None, 123, {}, [], True):
            self.refused(self.id(value), 'PERIOD_ID_INVALID')
        self.refused(self.api.compare(left_id=None, right_id='abc'))
        self.refused(self.api.from_instant(project_timezone='UTC',
                                          cadence='day', observed_at=True),
                     'OBSERVED_AT_OFFSET_REQUIRED')


if __name__ == '__main__':
    unittest.main()
