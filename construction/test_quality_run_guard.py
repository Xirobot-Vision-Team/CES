#!/usr/bin/env python3
"""EC186 small synthetic authorization/broker protocol checks; no test is run in a repo."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile
import unittest

import jsonschema

import quality_detect as detect
import quality_observation as observer
import quality_run_guard as gate

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
POLICY_KEY = b'A' * 40
BROKER_KEY = b'B' * 40
SCHEMA_FILE = Path(__file__).resolve().parent.parent / 'references' / 'quality-run-guard-result.v1.schema.json'


def when(offset: int) -> str:
    return gate._stamp(NOW + timedelta(seconds=offset))


def signed(body: dict, key: bytes, domain: bytes) -> dict:
    return {**body, 'mac_sha256': hmac.new(
        key, domain + gate._canonical(body), hashlib.sha256).hexdigest()}


class SafetyGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_FILE.read_text('utf-8'))
        jsonschema.Draft202012Validator.check_schema(cls.schema)
        cls.validator = jsonschema.Draft202012Validator(cls.schema,
            format_checker=jsonschema.FormatChecker())

    def setUp(self):
        self.working = tempfile.TemporaryDirectory()
        self.addCleanup(self.working.cleanup)
        self.root = (Path(self.working.name) / 'source')
        self.root.mkdir()
        self.pin = detect.QualityDetector.observe_root(str(self.root),
            authorize_observation=lambda _: True, clock=lambda: NOW)
        self.profile_id = 'python.pytest'
        self.pdigest = gate.catalog_entry(self.profile_id)['profile_sha256']
        self.sdigest = detect._sha(detect.DOMAIN_PIN, self.pin)
        self.approval = self.approve()
        self.lease = self.isolate()
        self.g = gate.QualityRunSafetyGate(policy_verification_key=POLICY_KEY,
             broker_verification_key=BROKER_KEY, clock=lambda: NOW)
        self.observed_stages = []

    def approve(self, **changes):
        payload = {'schema': gate.APPROVAL_SCHEMA,
                   'ticket_id': 'policygrant-001',
                   'profile_id': self.profile_id,
                   'profile_sha256': self.pdigest,
                   'source_pin_sha256': self.sdigest,
                   'approved_purpose': gate.catalog_entry(self.profile_id)['profile']['purpose'],
                   'issued_at_utc': when(-10), 'expires_at_utc': when(110)}
        payload.update(changes)
        return signed(payload, POLICY_KEY, gate.DOMAIN_APPROVAL)

    def isolate(self, **changes):
        payload = {'schema': gate.LEASE_SCHEMA,
                   'ticket_id': 'brokerlease-001',
                   'source_pin_sha256': self.sdigest,
                   'profile_sha256': self.pdigest,
                   'approval_receipt_sha256': gate._digest(gate.DOMAIN_RECEIPT, self.approval),
                   'image_sha256': 'c' * 64,
                   'controls': dict(gate.REQUIRED_CONTROLS),
                   'issued_at_utc': when(-8), 'expires_at_utc': when(100)}
        payload.update(changes)
        return signed(payload, BROKER_KEY, gate.DOMAIN_LEASE)

    def grant(self, scope):
        self.observed_stages.append(scope['stage'])
        return True

    def run_gate(self, **overrides):
        args = dict(repo_root=str(self.root), source_pin=self.pin,
                    profile_id=self.profile_id, policy_ticket=self.approval,
                    isolation_ticket=self.lease,
                    allow_prepare=True, allow_profile_approval=True,
                    allow_isolation_lease=True,
                    authorize_root=lambda _: True, authorize_gate=self.grant)
        args.update(overrides)
        value = self.g.prepare(**args)
        self.validator.validate(value)
        return value

    def denied(self, out, prefix=None):
        self.assertIn(out['status'], ('invalid_input','unavailable'))
        self.assertEqual(out['exit_code'], gate.EXIT[out['status']])
        self.assertIsNone(out['plan'])
        self.assertIsNone(out['source'])
        self.assertIsNone(out['isolation'])
        self.assertIsNone(out['plan_sha256'])
        self.assertFalse(out['effects']['commands_executed'])
        self.assertFalse(out['effects']['writes_performed'])
        if prefix:
            self.assertIn(prefix, out['reason_code'])

    def test_01_valid_gated_plan_remains_partial_not_executable(self):
        out = self.run_gate()
        self.assertEqual(out['status'], 'partial')
        self.assertEqual(out['exit_code'], 2)
        self.assertEqual(out['plan']['state'], 'PREPARED_ONLY_NOT_EXECUTABLE')
        self.assertFalse(out['plan']['has_executable_command'])
        self.assertTrue(out['proof']['approved_profile_mac_verified'])
        self.assertFalse(out['proof']['actual_isolation_verified_by_ces'])
        self.assertFalse(out['proof']['test_execution_verified'])
        self.assertFalse(out['effects']['lease_consumed'])
        self.assertEqual(out['effects']['root_observations'], 2)
        self.assertEqual(self.observed_stages, [
            'BEFORE_PROFILE','APPROVED_PROFILE','ISOLATION_RESERVED','FINALIZE'])
        self.assertNotIn(str(self.root), json.dumps(out))

    def test_02_ruff_curated_profile_is_supported(self):
        self.profile_id = 'python.ruff'
        self.pdigest = gate.catalog_entry(self.profile_id)['profile_sha256']
        self.approval = self.approve()
        self.lease = self.isolate()
        out = self.run_gate()
        self.assertEqual((out['status'],out['profile']['kind']), ('partial','LINT'))

    def test_03_no_implicit_optins(self):
        for name in ('allow_prepare','allow_profile_approval','allow_isolation_lease'):
            with self.subTest(name=name):
                self.denied(self.run_gate(**{name:False}), 'SEPARATE_OPTINS_REQUIRED')

    def test_04_unknown_profile_cannot_inject_commands(self):
        for malicious in ('python.tox', 'node.vitest', 'python -c exploit',
                          '/bin/sh', 'python.pytest; rm -rf /', '', None):
            with self.subTest(malicious=malicious):
                self.denied(self.run_gate(profile_id=malicious), 'PROFILE_NOT_IN_BUILTIN_CATALOG')

    def test_05_ticket_claims_cannot_substitute_for_signature(self):
        bad = {**self.approval, 'profile_id':'python.ruff'}
        self.denied(self.run_gate(policy_ticket=bad), 'TICKET_NOT_AUTHENTICATED')
        self.denied(self.run_gate(policy_ticket=self.approve(profile_id='python.ruff')),
                    'PROFILE_NOT_EXPLICITLY_APPROVED')
        bad = {**self.approval, 'mac_sha256': '0'*64}
        self.denied(self.run_gate(policy_ticket=bad), 'TICKET_NOT_AUTHENTICATED')

    def test_06_wrong_role_key_for_signed_broker_is_rejected(self):
        payload = {k:v for k,v in self.lease.items() if k!='mac_sha256'}
        fake = signed(payload, POLICY_KEY, gate.DOMAIN_LEASE)
        self.denied(self.run_gate(isolation_ticket=fake), 'TICKET_NOT_AUTHENTICATED')

    def test_07_untrusted_isolation_bool_claim_is_rejected(self):
        for field in ('network_access','source_mount','seccomp_enforced',
                      'host_sockets_mounted','lease_state','non_root_user'):
            changed = dict(gate.REQUIRED_CONTROLS)
            default = changed[field]
            changed[field] = ('ENABLED' if isinstance(default,str) else not default)
            with self.subTest(field=field):
                bad = self.isolate(controls=changed)
                self.denied(self.run_gate(isolation_ticket=bad), 'ISOLATION_REQUIREMENTS')

    def test_08_json_number_not_accepted_as_boolean_isolation_control(self):
        changes = dict(gate.REQUIRED_CONTROLS)
        changes['non_root_user'] = 1
        self.denied(self.run_gate(isolation_ticket=self.isolate(controls=changes)),
                    'ISOLATION_REQUIREMENTS')

    def test_09_lease_from_different_source_is_rejected(self):
        self.denied(self.run_gate(isolation_ticket=self.isolate(
            source_pin_sha256='d'*64)), 'LEASE_NOT_BOUND')

    def test_10_lease_from_other_profile_is_rejected(self):
        self.denied(self.run_gate(isolation_ticket=self.isolate(
            profile_sha256='d'*64)), 'LEASE_NOT_BOUND')

    def test_11_lease_from_other_approval_is_rejected(self):
        self.denied(self.run_gate(isolation_ticket=self.isolate(
            approval_receipt_sha256='d'*64)), 'LEASE_NOT_BOUND')

    def test_12_lease_longer_than_approval_is_rejected(self):
        self.denied(self.run_gate(isolation_ticket=self.isolate(
            expires_at_utc=when(111))), 'LEASE_OUTLASTS')

    def test_13_expired_approval_or_lease_is_rejected(self):
        self.denied(self.run_gate(policy_ticket=self.approve(
            issued_at_utc=when(-200), expires_at_utc=when(-1))), 'TICKET_EXPIRED')
        self.denied(self.run_gate(isolation_ticket=self.isolate(
            issued_at_utc=when(-50), expires_at_utc=when(-1))), 'TICKET_EXPIRED')

    def test_14_future_ticket_is_rejected(self):
        self.denied(self.run_gate(policy_ticket=self.approve(
            issued_at_utc=when(40), expires_at_utc=when(110))), 'TICKET_EXPIRED')

    def test_15_oversized_lifetime_is_rejected(self):
        self.denied(self.run_gate(policy_ticket=self.approve(
            expires_at_utc=when(610))), 'TICKET_EXPIRED')
        self.denied(self.run_gate(isolation_ticket=self.isolate(
            expires_at_utc=when(140))), 'TICKET_EXPIRED')

    def test_16_invalid_ticket_fields_fail_closed(self):
        x = dict(self.lease)
        x['extra_argv'] = ['sh','-c','anything']
        self.denied(self.run_gate(isolation_ticket=x), 'TICKET_STRUCTURE_INVALID')
        x = dict(self.approval)
        x['expires_at_utc'] = '9999-99-99T00:00:00Z'
        self.denied(self.run_gate(policy_ticket=x))

    def test_17_broker_lease_missing_denied(self):
        self.denied(self.run_gate(isolation_ticket=None), 'TICKET_STRUCTURE_INVALID')

    def test_18_role_separation_keys_enforced_at_configuration(self):
        with self.assertRaises(ValueError):
            gate.QualityRunSafetyGate(policy_verification_key=POLICY_KEY,
                broker_verification_key=POLICY_KEY)
        with self.assertRaises(ValueError):
            gate.QualityRunSafetyGate(policy_verification_key=b'short',
                broker_verification_key=BROKER_KEY)

    def test_19_host_denial_at_any_phase_erases_plan(self):
        for stage in ('BEFORE_PROFILE','APPROVED_PROFILE','ISOLATION_RESERVED','FINALIZE'):
            with self.subTest(stage=stage):
                self.denied(self.run_gate(authorize_gate=lambda d: d['stage'] != stage),
                            'HOST_AUTHORIZATION_DENIED')

    def test_20_host_root_denial_cannot_be_bypassed(self):
        self.denied(self.run_gate(authorize_root=lambda _: False))
        self.denied(self.run_gate(authorize_gate=None), 'HOST_AUTHORIZER_REQUIRED')

    def test_21_callbacks_must_return_literal_true(self):
        for value in (1, 'yes', [], None):
            with self.subTest(value=value):
                self.denied(self.run_gate(authorize_gate=lambda _: value))

    def test_22_callback_exception_fail_closed(self):
        def fail(_):
            raise RuntimeError('private details should not leak')
        self.denied(self.run_gate(authorize_gate=fail), 'HOST_AUTHORIZATION_UNAVAILABLE')

    def test_23_root_mutation_during_auth_fails(self):
        def mutate(scope):
            if scope['stage'] == 'ISOLATION_RESERVED':
                os.utime(self.root, None)
                # Ensure device/inode/timestamp drift even on coarse filesystems.
                second = self.root.parent / 'next'
                self.root.rename(second)
                self.root.mkdir()
            return True
        self.denied(self.run_gate(authorize_gate=mutate), 'WORKINGTREE_IDENTITY_DRIFT')

    def test_24_symlinked_root_refused(self):
        link = self.root.parent / 'shortcut'
        link.symlink_to(self.root, target_is_directory=True)
        self.denied(self.run_gate(repo_root=str(link)))

    def test_25_wrong_pin_refused(self):
        pin = dict(self.pin)
        pin['root_identity'] = {**pin['root_identity'],'inode':pin['root_identity']['inode']+1}
        self.denied(self.run_gate(source_pin=pin))

    def test_26_stale_pin_refused(self):
        pin = {**self.pin,'observed_at_utc':when(-400)}
        self.denied(self.run_gate(source_pin=pin),'SOURCE_PIN_STALE')

    def test_27_optional_ec185_digest_from_same_source_is_context_only(self):
        receipt = self.fake_observation()
        out = self.run_gate(ec185_observation=receipt)
        self.assertEqual(out['status'],'partial')
        self.assertTrue(out['context']['ec185_supplied'])
        self.assertTrue(out['context']['profile_hint_present'])
        self.assertFalse(out['proof']['test_execution_verified'])

    def fake_observation(self):
        payload = {'observed_at_utc':when(-4),
            'source': {'local':{'source_mode':'WorkingTree','pin_digest':self.sdigest},
                       'remote':None,'same_revision_proven':False},
            'observations':{'local_config':{
                'pin_digest':self.sdigest,
                'profile_hints':[{'profile_id': self.profile_id}]},
                'tests':{'classification':'pass'}},
            'evidence_refs':[],'execution_environment':{},'grants':{},'proof':{}}
        return {'schema': observer.SCHEMA,'status':'partial','exit_code':2,
                **payload, 'observation_sha256':observer._hash(payload)}

    def test_28_hints_are_not_preapproval(self):
        receipt = self.fake_observation()
        self.denied(self.run_gate(ec185_observation=receipt,
            policy_ticket={**self.approval, 'mac_sha256':'0'*64}),
            'TICKET_NOT_AUTHENTICATED')

    def test_29_cross_root_or_tampered_ec185_refused(self):
        x = self.fake_observation()
        x['source']['local']['pin_digest'] = '1'*64
        self.denied(self.run_gate(ec185_observation=x), 'EC185_OBSERVATION_HASH_CHANGED')
        x = self.fake_observation()
        x['source']['local']['pin_digest'] = '1'*64
        body = {k:x[k] for k in ('observed_at_utc','source','observations',
             'evidence_refs','execution_environment','grants','proof')}
        x['observation_sha256'] = observer._hash(body)
        self.denied(self.run_gate(ec185_observation=x), 'EC185_SOURCE_NOT_THIS_WORKINGTREE')

    def test_30_output_schema_rejects_forged_pass_or_commands(self):
        out = self.run_gate()
        forged = {**out,'status':'pass'}
        self.assertFalse(self.validator.is_valid(forged))
        forged = {**out,'proof':{**out['proof'],'actual_isolation_verified_by_ces':True}}
        self.assertFalse(self.validator.is_valid(forged))
        forged = {**out,'plan':{**out['plan'],'command':'sh -c evil'}}
        self.assertFalse(self.validator.is_valid(forged))
        forged = {**out,'effects':{**out['effects'],'commands_executed':True}}
        self.assertFalse(self.validator.is_valid(forged))

    def test_31_repository_scripts_never_inspected_or_started(self):
        dangerous = self.root / 'package.json'
        dangerous.write_text('{"scripts":{"test":"rm -rf /tmp/something"}}')
        # A source-directory metadata mutation invalidates the original pin.
        self.pin = detect.QualityDetector.observe_root(str(self.root),
            authorize_observation=lambda _: True, clock=lambda: NOW)
        self.sdigest = detect._sha(detect.DOMAIN_PIN, self.pin)
        self.approval = self.approve()
        self.lease = self.isolate()
        self.assertEqual(self.run_gate()['status'],'partial')
        self.assertEqual(dangerous.read_text(),
            '{"scripts":{"test":"rm -rf /tmp/something"}}')

    def test_32_lease_requires_reserved_not_executed(self):
        for state in ('RUNNING','DONE','UNRESERVED','ABORTED'):
            controls = {**gate.REQUIRED_CONTROLS,'lease_state':state}
            self.denied(self.run_gate(isolation_ticket=self.isolate(
                controls=controls)), 'ISOLATION_REQUIREMENTS')

    def test_33_expiring_during_final_host_grant_is_denied(self):
        time_state = {'now':NOW}
        g = gate.QualityRunSafetyGate(policy_verification_key=POLICY_KEY,
            broker_verification_key=BROKER_KEY, clock=lambda:time_state['now'])
        def rotate(scope):
            if scope['stage']=='ISOLATION_RESERVED':
                time_state['now'] += timedelta(seconds=110)
            return True
        out = g.prepare(repo_root=str(self.root), source_pin=self.pin,
            profile_id=self.profile_id, policy_ticket=self.approval,
            isolation_ticket=self.lease, allow_prepare=True,
            allow_profile_approval=True, allow_isolation_lease=True,
            authorize_root=lambda _: True, authorize_gate=rotate)
        self.validator.validate(out)
        self.denied(out, 'TICKET_EXPIRED')

    def test_34_final_authorization_callback_root_swap_denied(self):
        def mutate(scope):
            if scope['stage'] == 'FINALIZE':
                self.root.rename(self.root.parent / 'old-root')
                self.root.mkdir()
            return True
        self.denied(self.run_gate(authorize_gate=mutate), 'WORKINGTREE_IDENTITY_DRIFT')

    def test_35_invalid_python_types_never_parse_as_permission(self):
        self.denied(self.run_gate(allow_prepare=1),'SEPARATE_OPTINS_REQUIRED')
        self.denied(self.run_gate(policy_ticket=[]),'TICKET_STRUCTURE_INVALID')


if __name__ == '__main__':
    unittest.main()
