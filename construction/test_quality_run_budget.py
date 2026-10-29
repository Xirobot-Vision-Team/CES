#!/usr/bin/env python3
"""EC187 host protocol *synthetic* fixtures; no project test runs."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import tempfile
import unittest

import jsonschema
import quality_detect as detect
import quality_run_guard as guard
import quality_run_budget as budget

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
POLICY = b'ec187-policy-test-key' + b'A' * 32
BROKER_KEY = b'ec187-broker-test-key' + b'B' * 32
SCHEMA = Path(__file__).resolve().parent.parent / 'references' / 'quality-run-budget-result.v1.schema.json'


def stamp(delta=0):
    return guard._stamp(NOW + timedelta(seconds=delta))


def signed(body, key, domain):
    return dict(body, mac_sha256=hmac.new(key, domain + guard._canonical(body),
                                       hashlib.sha256).hexdigest())


def metrics(**overrides):
    x = {'cpu_ms': 1, 'memory_peak_bytes': 2 * 1024 * 1024,
         'io_bytes': 100, 'processes': 1}
    x.update(overrides)
    return x


def event(kind='heartbeat', **add):
    return {'kind':kind, 'resources':metrics(), **add}


class FakeSession:
    """Fake host; receipts and exit are untrusted claims, NEVER real execution."""
    def __init__(self, request, events=None):
        self.events = list(events or [event('exit', exit_code=0)])
        self.stops = []
        self.stop_result = {'stop_acknowledged':True,'reaped':True}
        self.advance_poll = None
        self.receipt = {
            'schema': budget.SESSION_SCHEMA, 'session_id':'fake-session-187',
            **{k:request[k] for k in (
                'profile_id','profile_sha256','source_pin_sha256',
                'approval_receipt_sha256','lease_receipt_sha256','image_sha256')},
            'sealed_source_sha256': 'a'*64,
            'limits':dict(request['limits']),
            'lease_atomically_consumed_once': True,
            'immutable_source_sealed': True,
            'kernel_isolation_rechecked': True,
            'hard_resource_limits_armed': True,
            'hard_watchdog_and_kill_armed': True,
            'output_stream_bounded': True,
        }

    def poll(self, wait_ms, max_chunk_bytes):
        if self.advance_poll is not None:
            self.advance_poll()
        if not self.events:
            raise RuntimeError('synthetic adapter ran out of events')
        raw = self.events.pop(0)
        if isinstance(raw, Exception):
            raise raw
        return raw

    def stop_and_reap(self, reason):
        self.stops.append(reason)
        if isinstance(self.stop_result, Exception):
            raise self.stop_result
        return self.stop_result


class FakeBroker:
    def __init__(self, *, events=None, alter=None):
        self.events = events
        self.alter = alter
        self.requests = []
        self.session = None
        self.fail = None

    def begin(self, request):
        self.requests.append(request)
        if self.fail:
            raise self.fail
        self.session = FakeSession(request,self.events)
        if self.alter:
            self.alter(self.session)
        return self.session


class Monotonic:
    def __init__(self, initial=1_000_000_000):
        self.ns = initial
    def __call__(self):
        return self.ns
    def advance(self,ms):
        self.ns += ms * 1_000_000


class BudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(SCHEMA.read_text('utf8'))
        jsonschema.Draft202012Validator.check_schema(cls.contract)
        cls.validator = jsonschema.Draft202012Validator(cls.contract)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)/'root'
        self.root.mkdir()
        self.pin = detect.QualityDetector.observe_root(str(self.root),
            authorize_observation=lambda _: True, clock=lambda: NOW)
        self.profile = 'python.pytest'
        self.pdigest = guard.catalog_entry(self.profile)['profile_sha256']
        self.sdigest = detect._sha(detect.DOMAIN_PIN, self.pin)
        self.policy = self.make_policy()
        self.lease = self.make_lease()
        self.mono = Monotonic()
        self.gate = guard.QualityRunSafetyGate(policy_verification_key=POLICY,
            broker_verification_key=BROKER_KEY, clock=lambda: NOW)
        self.service = budget.QualityRunBudgetController(self.gate, monotonic_ns=self.mono)
        self.fake = FakeBroker()
        self.grants = []
        self.cancel_callback = lambda: False

    def make_policy(self, **add):
        body={'schema': guard.APPROVAL_SCHEMA,'ticket_id':'policy-ec187-0001',
              'profile_id':self.profile,'profile_sha256':self.pdigest,
              'source_pin_sha256':self.sdigest,
              'approved_purpose':guard.catalog_entry(self.profile)['profile']['purpose'],
              'issued_at_utc':stamp(-5),'expires_at_utc':stamp(100)}
        body.update(add)
        return signed(body,POLICY,guard.DOMAIN_APPROVAL)

    def make_lease(self,**add):
        body={'schema': guard.LEASE_SCHEMA,'ticket_id':'lease-ec187-00001',
              'source_pin_sha256':self.sdigest,'profile_sha256':self.pdigest,
              'approval_receipt_sha256':guard._digest(guard.DOMAIN_RECEIPT,self.policy),
              'image_sha256':'b'*64, 'controls': dict(guard.REQUIRED_CONTROLS),
              'issued_at_utc':stamp(-3),'expires_at_utc':stamp(90)}
        body.update(add)
        return signed(body,BROKER_KEY,guard.DOMAIN_LEASE)

    def do(self,**changed):
        def grant(scope):
            self.grants.append(scope['stage'])
            return True
        kw={'repo_root':str(self.root),'source_pin':self.pin,
            'profile_id':self.profile,'policy_ticket':self.policy,
            'isolation_ticket':self.lease,'broker':self.fake,
            'allow_prepare':True,'allow_profile_approval':True,
            'allow_isolation_lease':True,'allow_external_execution':True,
            'allow_budget_controls':True,'authorize_root':lambda _:True,
            'authorize_gate':grant,'authorize_execute':grant,
            'cancel_requested':self.cancel_callback}
        kw.update(changed)
        result=self.service.run(**kw)
        self.validator.validate(result)
        self.assertFalse(result['effects']['commands_launched_by_ces'])
        self.assertFalse(result['effects']['tests_verified_by_ces'])
        if result['proof'] is not None:
            self.assertFalse(result['proof']['quality_pass_verified'])
        return result

    def partial(self, result,reason=None):
        self.assertEqual((result['status'],result['exit_code']),('partial',2))
        self.assertFalse(result['execution']['overall_pass_verified'])
        if reason:
            self.assertIn(reason,result['reason_code'])

    def denied(self,result,reason=None):
        self.assertIn(result['status'],('unavailable','invalid_input'))
        self.assertEqual(result['exit_code'], {'unavailable':5,'invalid_input':4}[result['status']])
        for key in ('profile_id','limits','execution','resources','output','proof'):
            self.assertIsNone(result[key])
        if reason:
            self.assertIn(reason,result['reason_code'])

    def test_01_zero_exit_remains_partial_unverified(self):
        result=self.do()
        self.partial(result,'EXIT_ZERO_UNVERIFIED')
        self.assertTrue(result['output']['complete'])
        self.assertEqual(result['execution']['host_reported_exit_code'],0)
        self.assertEqual(result['effects']['additional_root_observations'],1)
        self.assertEqual(self.grants[-2:],['BEFORE_BROKER','FINAL_BEFORE_BROKER'])
        self.assertEqual(self.fake.session.stops,[])

    def test_02_nonzero_exit_never_falsely_pass(self):
        self.fake.events=[event('exit',exit_code=12)]
        self.partial(self.do(),'NONZERO_EXIT')

    def test_03_three_events_with_progress(self):
        self.fake.events=[event('heartbeat'),event('output',stream='stdout',chunk=b'abc'),
                          event('exit',exit_code=0)]
        r=self.do()
        self.partial(r)
        self.assertEqual(r['output']['stdout_preview'],'abc')
        self.assertEqual(r['output']['captured_bytes'],3)
        self.assertEqual(r['effects']['poll_count'],3)

    def test_04_pre_cancel_no_broker_begin(self):
        self.cancel_callback=lambda:True
        r=self.do()
        self.assertEqual(r['status'],'partial')
        self.assertIsNone(r['execution'])
        self.assertEqual(len(self.fake.requests),0)

    def test_05_cancel_after_broker_session_stops(self):
        calls={'count':0}
        def cancellation():
            calls['count']+=1
            return calls['count']>=4
        self.cancel_callback=cancellation
        r=self.do()
        self.partial(r,'CANCELLED')
        self.assertTrue(r['effects']['stop_requested'])
        self.assertTrue(r['effects']['reaped_reported_by_host'])
        self.assertEqual(len(self.fake.session.stops),1)

    def test_06_wall_timeout_in_poll_hard_stop(self):
        def alter(s): s.advance_poll=lambda:self.mono.advance(500)
        self.fake.alter=alter
        self.fake.events=[event('heartbeat')]
        r=self.do(limits={'wall_ms':200})
        self.partial(r,'WALL_TIMEOUT')
        self.assertTrue(r['effects']['stop_requested'])

    def test_07_broker_begin_took_too_long(self):
        def alter(s): self.mono.advance(61000)
        self.fake.alter=alter
        r=self.do()
        self.partial(r,'WALL_TIMEOUT')
        self.assertTrue(r['effects']['stop_requested'])

    def test_08_over_capture_truncates_and_stops(self):
        self.fake.events=[event('output',stream='stdout',chunk=b'abcdef')]
        r=self.do(limits={'capture_bytes':4})
        self.partial(r,'OUTPUT_CAPTURE_BUDGET')
        self.assertEqual(r['output']['stdout_preview'],'abcd')
        self.assertEqual((r['output']['captured_bytes'],r['output']['discarded_bytes']),(4,2))
        self.assertTrue(r['output']['truncated'])
        self.assertFalse(r['output']['complete'])
        self.assertEqual(self.fake.session.stops,['OUTPUT_CAPTURE_BUDGET'])

    def test_09_capture_exact_limit_is_allowed(self):
        self.fake.events=[event('output',stream='stderr',chunk=b'1234'),event('exit',exit_code=0)]
        r=self.do(limits={'capture_bytes':4})
        self.partial(r)
        self.assertFalse(r['output']['truncated'])
        self.assertEqual(r['output']['stderr_preview'],'1234')

    def test_10_zero_capture_stops_on_first_output(self):
        self.fake.events=[event('output',stream='stdout',chunk=b'x')]
        r=self.do(limits={'capture_bytes':0})
        self.partial(r,'OUTPUT_CAPTURE_BUDGET')
        self.assertEqual(r['output']['captured_bytes'],0)
        self.assertTrue(r['output']['truncated'])

    def test_11_cpu_limit(self):
        self.fake.events=[event('heartbeat',resources=metrics(cpu_ms=200))]
        r=self.do(limits={'cpu_ms':100})
        self.partial(r,'RESOURCE_CPU_MS_LIMIT')
        self.assertEqual(self.fake.session.stops,['RESOURCE_CPU_MS_LIMIT'])

    def test_12_memory_limit(self):
        self.fake.events=[event('heartbeat',resources=metrics(memory_peak_bytes=8*1024*1024))]
        self.partial(self.do(limits={'memory_peak_bytes':4*1024*1024}),
                     'RESOURCE_MEMORY_PEAK_BYTES_LIMIT')

    def test_13_io_limit(self):
        self.fake.events=[event('heartbeat',resources=metrics(io_bytes=8192))]
        self.partial(self.do(limits={'io_bytes':4096}), 'RESOURCE_IO_BYTES_LIMIT')

    def test_14_process_count_limit(self):
        self.fake.events=[event('heartbeat',resources=metrics(processes=3))]
        self.partial(self.do(limits={'processes':2}), 'RESOURCE_PROCESSES_LIMIT')

    def test_15_untrusted_missing_telemetry_stops(self):
        self.fake.events=[{'kind':'heartbeat'}]
        self.partial(self.do(),'BROKER_EVENT_INVALID')

    def test_16_bool_as_int_telemetry_is_rejected(self):
        self.fake.events=[event('heartbeat',resources=metrics(cpu_ms=True))]
        self.partial(self.do(),'RESOURCE_TELEMETRY_INVALID')

    def test_17_counter_regression_stops(self):
        self.fake.events=[event('heartbeat',resources=metrics(cpu_ms=30)),
                          event('heartbeat',resources=metrics(cpu_ms=20))]
        self.partial(self.do(),'RESOURCE_COUNTER_REGRESSED')

    def test_18_invalid_session_scope_stops(self):
        self.fake.alter=lambda s:s.receipt.update(profile_sha256='f'*64)
        r=self.do()
        self.partial(r,'BROKER_SESSION_SCOPE_MISMATCH')
        self.assertTrue(r['effects']['stop_requested'])
        self.assertFalse(r['effects']['lease_consumed_reported_by_host'])

    def test_19_no_atomic_lease_proof_stops(self):
        self.fake.alter=lambda s:s.receipt.update(lease_atomically_consumed_once=False)
        self.partial(self.do(),'BROKER_SECURITY_INCOMPLETE')

    def test_20_no_source_seal_stops(self):
        self.fake.alter=lambda s:s.receipt.update(sealed_source_sha256='not-sha')
        self.partial(self.do(),'BROKER_CONTENT_SEAL_INVALID')

    def test_21_looser_broker_limits_stops(self):
        self.fake.alter=lambda s:s.receipt['limits'].update(wall_ms=70000)
        self.partial(self.do(),'BROKER_HARD_LIMITS_MISMATCH')

    def test_22_no_external_broker_denies_before_gate(self):
        self.denied(self.do(broker=None),'TRUSTED_BROKER_UNAVAILABLE')
        self.assertEqual(len(self.fake.requests),0)

    def test_23_two_optins_both_required(self):
        self.denied(self.do(allow_external_execution=False),'SEPARATE_EXECUTION_OPTINS')
        self.denied(self.do(allow_budget_controls=False),'SEPARATE_EXECUTION_OPTINS')

    def test_24_reject_limit_escalation_unknown_boolean(self):
        for invalid in ({'wall_ms':60001},{'foo':5},{'processes':True},
                        {'capture_bytes':-1},{'poll_wait_ms':300},'not dict'):
            with self.subTest(case=invalid):
                self.denied(self.do(limits=invalid),'LIMITS_INVALID')

    def test_25_second_host_authorization_denied(self):
        def grant(s): return s['stage']!='FINAL_BEFORE_BROKER'
        self.denied(self.do(authorize_execute=grant),'EXECUTE_AUTHORIZATION_DENIED')
        self.assertEqual(len(self.fake.requests),0)

    def test_26_directory_swapped_during_execute_authorization(self):
        def grant(s):
            if s['stage']=='FINAL_BEFORE_BROKER':
                self.root.rename(self.root.parent/'gone')
                self.root.mkdir()
            return True
        r=self.do(authorize_execute=grant)
        self.denied(r)
        self.assertEqual(len(self.fake.requests),0)

    def test_27_broker_begin_raises_no_fake_result(self):
        self.fake.fail=RuntimeError('broker failed')
        r=self.do()
        self.partial(r,'BROKER_OR_CONTROLLER_EXCEPTION')
        self.assertTrue(r['effects']['stop_requested'])
        self.assertFalse(r['effects']['external_broker_session_reported'])

    def test_28_poll_raises_cleanup(self):
        self.fake.events=[RuntimeError('poll failed')]
        r=self.do()
        self.partial(r,'BROKER_OR_CONTROLLER_EXCEPTION')
        self.assertTrue(r['effects']['reaped_reported_by_host'])

    def test_29_reap_callback_fails_uncertain_not_complete(self):
        def alter(s): s.stop_result=RuntimeError('reap fail')
        self.fake.alter=alter
        self.fake.events=[event('output',stream='stderr',chunk=b'long')]
        r=self.do(limits={'capture_bytes':1})
        self.partial(r,'OUTPUT_CAPTURE_BUDGET')
        self.assertFalse(r['effects']['reaped_reported_by_host'])
        self.assertFalse(r['output']['complete'])

    def test_30_unexpected_exit_code_type_stops(self):
        self.fake.events=[event('exit',exit_code=True)]
        self.partial(self.do(),'BROKER_EXIT_CODE_INVALID')

    def test_31_oversized_frame_stops_without_echoing(self):
        self.fake.events=[event('output',stream='stdout',chunk=b'X'*4097)]
        r=self.do()
        self.partial(r,'BROKER_OUTPUT_FRAME_INVALID')
        self.assertEqual(r['output']['captured_bytes'],0)

    def test_32_dangerous_ansi_control_sanitized(self):
        self.fake.events=[event('output',stream='stdout',chunk=b'a\x1b[31m\x00'),event('exit',exit_code=0)]
        r=self.do()
        self.partial(r)
        self.assertNotIn('\x1b',r['output']['stdout_preview'])
        self.assertNotIn('\x00',r['output']['stdout_preview'])

    def test_33_busy_heartbeats_bounded_by_poll_cap(self):
        self.fake.events=[event('heartbeat') for _ in range(budget.MAX_POLLS+3)]
        r=self.do()
        self.partial(r,'POLL_EVENT_LIMIT')
        self.assertEqual(r['effects']['poll_count'], budget.MAX_POLLS)

    def test_34_host_cancellation_source_raises(self):
        i={'n':0}
        def cancel():
            i['n']+=1
            if i['n']>=3: raise RuntimeError('lost signal')
            return False
        self.cancel_callback=cancel
        r=self.do()
        self.partial(r,'CANCELLATION_SOURCE_UNAVAILABLE')
        self.assertTrue(r['effects']['stop_requested'])

    def test_35_wrong_signed_lease_denied_before_broker(self):
        bad = dict(self.lease); bad['image_sha256']='e'*64
        self.denied(self.do(isolation_ticket=bad),'EC186_GATE_')
        self.assertEqual(len(self.fake.requests),0)

    def test_36_mock_receipt_cannot_promote_success_in_contract(self):
        out=self.do()
        out['status']='success';out['exit_code']=0
        self.assertRaises(jsonschema.ValidationError,self.validator.validate,out)

    def test_37_untrusted_extra_event_fields_rejected(self):
        self.fake.events=[event('exit', exit_code=0, override_shell='sh')]
        self.partial(self.do(),'BROKER_EVENT_INVALID')

    def test_38_ruff_profile_only_code_owned(self):
        self.profile='python.ruff'
        self.pdigest=guard.catalog_entry(self.profile)['profile_sha256']
        self.policy=self.make_policy()
        self.lease=self.make_lease()
        self.partial(self.do(),'EXIT_ZERO_UNVERIFIED')
        self.assertEqual(self.fake.requests[0]['profile_recipe']['module'],'ruff')
        self.assertNotIn('argv', self.fake.requests[0])


    def test_39_authorizer_cannot_mutate_broker_limits(self):
        def grant(s):
            if s['stage'] == 'BEFORE_BROKER':
                s['limits']['wall_ms'] = 1_000_000
                s['profile_id'] = 'injected-shell'
            return True
        r=self.do(authorize_execute=grant)
        self.partial(r)
        self.assertEqual(self.fake.requests[0]['limits']['wall_ms'],60000)
        self.assertEqual(self.fake.requests[0]['profile_id'],'python.pytest')

    def test_40_ticket_changed_during_final_authorization_rejected(self):
        def grant(s):
            if s['stage']=='FINAL_BEFORE_BROKER':
                self.lease['ticket_id']='malicious-change'
            return True
        self.denied(self.do(authorize_execute=grant),'TICKET_NOT_AUTHENTICATED')
        self.assertEqual(len(self.fake.requests),0)

    def test_41_budget_consistency_refuses_cpu_greater_than_wall_times_process_cap(self):
        r=self.do(limits={'wall_ms':100,'processes':1,'cpu_ms':200})
        self.denied(r,'LIMITS_INCONSISTENT')
        self.assertFalse(self.fake.requests)

    def test_42_unknown_broker_receipt_keys_fail_closed(self):
        self.fake.alter=lambda s:s.receipt.update(unexpected_argv=['sh'])
        self.partial(self.do(),'BROKER_SESSION_RECEIPT_INVALID')


    def test_43_regressing_monotonic_time_stops_run(self):
        self.fake.events=[event('heartbeat'),event('heartbeat')]
        def alter(s):
            def backwards(): self.mono.advance(-1)
            s.advance_poll=backwards
        self.fake.alter=alter
        self.partial(self.do(),'MONOTONIC_CLOCK_REGRESSED')
        self.assertTrue(self.fake.session.stops)

    def test_44_output_bytes_exceed_claimed_total_io(self):
        self.fake.events=[event('output',stream='stdout',chunk=b'x'*110)]
        self.partial(self.do(),'RESOURCE_IO_ACCOUNTING_INCONSISTENT')
        self.assertTrue(self.fake.session.stops)

    def test_45_keyboard_interrupt_requests_stop_and_retains_partial(self):
        self.fake.events=[KeyboardInterrupt()]
        # FakeSession only raises instances of Exception; use custom session poll.
        def alter(s):
            def interrupt(*_): raise KeyboardInterrupt()
            s.poll=interrupt
        self.fake.alter=alter
        self.partial(self.do(),'KEYBOARD_CANCELLED')
        self.assertTrue(self.fake.session.stops)


if __name__=='__main__':
    unittest.main()
