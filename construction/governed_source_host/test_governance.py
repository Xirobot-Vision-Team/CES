#!/usr/bin/env python3
"""EC267 real local Git/HMAC/Ed25519 key governance; mock external identities.

Test harness generates all signers in one temporary filesystem. A valid
signature here never proves genuine human review, external CI or trusted time.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lease_host import broker as lease
from offline_anchor_host import checkpoint as cp
from source_provenance_host import provenance as prov
from source_provenance_host.test_provenance import ProvenanceTests as old
from governed_source_host import governance as gov


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     Path('/usr/bin/git').is_file() and cp.Ed25519PrivateKey is not None,
                     'real nonroot Git + cryptography required')
class GovernanceTests(unittest.TestCase):
    setUp = old.setUp
    kill_host = old.kill_host
    _prepare = old._prepare
    remote = old.remote
    begin_request = old.begin_request
    prepare_base = old.prepare_base
    prepare_ec266 = old.prepare
    write_gate = old.write_gate

    def prepare(self):
        self.prepare_ec266()
        self.root_secret = self.fix.private/'ec267-root-private.key'
        self.root_public = self.fix.private/'ec267-root-public.key'
        self.root_pin = cp.generate_offline_keypair(
            str(self.root_secret), str(self.root_public))['signer_public_sha256']
        self.issued = int(time.time())
        self.policy_proposal = self.fix.private/'ec267-governance-unsigned.json'
        self.gov_policy = self.fix.private/'ec267-governance-signed.json'
        self.epoch = 1
        self.minimum_epoch = 1
        self.previous_sha = gov.ZERO
        self.valid_from = self.issued
        self.valid_until = self.issued + 300
        self.revoked = ()
        self.issue()
        self.args.governance_policy = str(self.gov_policy)
        self.args.governance_policy_sha256 = self.gov_pin
        self.args.governance_public = str(self.root_public)
        self.args.governance_public_sha256 = self.root_pin
        self.args.minimum_governance_epoch = 1
        self.args.expected_previous_governance_sha256 = gov.ZERO

    def issue(self, **changes):
        # A new immutable signed document must use new names, not overwrite old.
        for k,v in changes.items():
            setattr(self,k,v)
        if self.policy_proposal.exists():
            self.policy_proposal = self.fix.private/('proposal-'+os.urandom(4).hex()+'.json')
            self.gov_policy = self.fix.private/('signed-'+os.urandom(4).hex()+'.json')
        unsigned = gov.prepare_policy(str(self.gate_path), self.gate_pin,
            epoch=self.epoch, previous_governance_sha256=self.previous_sha,
            not_before_unix=self.valid_from, expires_at_unix=self.valid_until,
            revoked_public_sha256=tuple(self.revoked), output=str(self.policy_proposal),
            issued_at_unix=self.issued)
        result = gov.sign_offline(str(self.policy_proposal), unsigned['proposal_sha256'],
            str(self.root_secret), self.root_pin, str(self.gov_policy))
        self.gov_pin = result['governance_sha256']
        if hasattr(self.args, 'governance_policy'):
            self.args.governance_policy = str(self.gov_policy)
            self.args.governance_policy_sha256 = self.gov_pin

    def new_gate(self, *, root_pin=None, governance_pin=None,
                 min_epoch=None, previous=None):
        return gov.GovernedSourceGate(
            str(self.fix.policy_path), str(self.gitfx.repo),
            str(self.gitfx.allowpath),
            str(self.gitfx.output/'source.custody.json'), 'python.pytest',
            str(self.gate_path), self.gate_pin, str(self.gov_policy),
            governance_pin or self.gov_pin, str(self.root_public),
            root_pin or self.root_pin,
            minimum_epoch=self.minimum_epoch if min_epoch is None else min_epoch,
            expected_previous_governance_sha256=(self.previous_sha
                if previous is None else previous),
            forbidden_signers=(self.pub_pin, self.custody_pin))

    def verify(self, *, gate=None):
        gate = gate or self.new_gate()
        policy, pin = lease._policy(str(self.fix.policy_path))
        gate.startup(policy, pin)
        return gate

    def deny(self, code, *, gate=None):
        with self.assertRaises(gov.GovernanceError) as caught:
            self.verify(gate=gate)
        self.assertEqual(caught.exception.code, code)

    def test_01_signed_root_authenticates_current_live_role_keys(self):
        self.prepare()
        gate = self.verify()
        report = gate.summary()
        self.assertEqual(report['governance_epoch'], 1)
        self.assertEqual(report['role_signatures_valid'], ['origin','review','ci'])
        self.assertFalse(report['trusted_external_time_or_provider_verified'])
        policy, sha = lease._policy(str(self.fix.policy_path))
        gate.before_begin(policy, sha, {'profile_id': 'python.pytest'})

    def test_02_root_independence_from_all_old_authorities(self):
        self.prepare()
        gate = self.new_gate(root_pin=self.signers['origin']['pin'])
        self.deny('EC267_GOVERNANCE_ROOT_PIN_MISMATCH', gate=gate)
        gate = self.new_gate(root_pin=self.signers['ci']['pin'])
        gate.governance_public = str(self.signers['ci']['public'])
        self.deny('EC267_GOVERNANCE_ROOT_NOT_INDEPENDENT', gate=gate)

    def test_03_renamed_root_or_policy_unauthorized(self):
        self.prepare()
        self.deny('EC267_GOVERNANCE_POLICY_PIN_MISMATCH', gate=self.new_gate(governance_pin='f'*64))
        self.deny('EC267_GOVERNANCE_ROOT_PIN_MISMATCH', gate=self.new_gate(root_pin='f'*64))

    def test_04_forged_signer_claim_fails_even_with_reapproved_digest(self):
        self.prepare()
        self.gov_policy.write_bytes(self.gov_policy.read_bytes().replace(b'"epoch":1', b'"epoch":2'))
        self.gov_pin = cp._digest(self.gov_policy.read_bytes())
        # Changing the epoch also requires a non-genesis predecessor; only a
        # cryptographic forgery with valid structure is tested in case 05.
        self.deny('EC267_PREDECESSOR_EPOCH_INCONSISTENT')

    def test_05_forged_valid_structure_fails_signature(self):
        self.prepare()
        document = json.loads(self.gov_policy.read_bytes())
        document['revoked_public_sha256'] = ['1'*64]
        self.gov_policy.write_bytes(gov._canonical(document))
        self.gov_pin = cp._digest(self.gov_policy.read_bytes())
        self.deny('EC267_GOVERNANCE_SIGNATURE_INVALID')

    def test_06_signed_revocation_of_current_role_denies(self):
        self.prepare()
        self.issue(revoked=(self.signers['ci']['pin'],))
        self.deny('EC267_ACTIVE_ISSUER_REVOKED')

    def test_07_signed_old_key_revocation_allows_other_active_keys(self):
        self.prepare()
        self.issue(revoked=('1'*64, '2'*64))
        self.assertEqual(self.verify().summary()['signed_revocations_checked'], 2)

    def test_08_revocation_must_be_sorted_unique_not_boolean_trick(self):
        self.prepare()
        document = json.loads(self.policy_proposal.read_bytes())
        for values in (('a'*64,'a'*64), ('bad',)):
            with self.assertRaisesRegex(gov.GovernanceError, 'EC267_REVOCATION_LIST_INVALID'):
                self.issue(revoked=values)
        document['revoked_public_sha256'] = ['b'*64, 'a'*64]
        with self.assertRaisesRegex(gov.GovernanceError, 'EC267_REVOCATION_LIST_INVALID'):
            gov._validate(document, signed=False)

    def test_09_all_validity_boundaries_enforced(self):
        self.prepare()
        start = float(self.issued)
        with mock.patch.object(gov, '_now', return_value=(start-1, 200.0)):
            self.deny('EC267_GOVERNANCE_NOT_YET_VALID')
        with mock.patch.object(gov, '_now', return_value=(float(self.valid_until), 200.0)):
            self.deny('EC267_GOVERNANCE_EXPIRED')
        with mock.patch.object(gov, '_now', return_value=(start, 200.0)):
            self.verify()

    def test_10_monotonic_deadline_and_clock_rollback_recall(self):
        self.prepare()
        start = float(self.issued) + 1
        with mock.patch.object(gov, '_now', return_value=(start, 100.0)):
            gate = self.verify()
        policy, sha = lease._policy(str(self.fix.policy_path))
        with mock.patch.object(gov, '_now', return_value=(start-10, 111.0)):
            with self.assertRaisesRegex(gov.GovernanceError, 'EC267_CLOCK_ROLLBACK_DETECTED'):
                gate.before_begin(policy, sha, {'profile_id':'python.pytest'})
        with mock.patch.object(gov, '_now', return_value=(start+1, 1000.0)):
            with self.assertRaisesRegex(gov.GovernanceError, 'EC267_CLOCK_ROLLBACK_DETECTED'):
                gate.before_begin(policy, sha, {'profile_id':'python.pytest'})

    def test_11_signed_window_never_exceeds_one_day(self):
        self.prepare()
        with self.assertRaisesRegex(gov.GovernanceError, 'EC267_VALIDITY_WINDOW_INVALID'):
            self.issue(valid_until=self.issued + 86401)

    def test_12_epoch_floor_and_declared_predecessor_operator_pins(self):
        self.prepare()
        self.deny('EC267_EPOCH_OR_PREDECESSOR_PIN_MISMATCH',gate=self.new_gate(min_epoch=2))
        self.deny('EC267_EPOCH_OR_PREDECESSOR_PIN_MISMATCH',gate=self.new_gate(previous='a'*64))
        self.issue(epoch=2, previous_sha=self.gov_pin)
        self.minimum_epoch = 2
        self.assertEqual(self.verify().summary()['governance_epoch'], 2)

    def test_13_changed_source_identity_cannot_reuse_governance(self):
        self.prepare()
        self.gate_data['authorities'][0]['public_sha256'] = 'a'*64
        self.write_gate()
        # EC266 itself rejects the mismatch, even before governance trust.
        with self.assertRaises(prov.ProvenanceError):
            self.verify()

    def test_14_governance_file_missing_revokes_current_admission(self):
        self.prepare()
        gate = self.verify()
        self.gov_policy.unlink()
        policy, sha = lease._policy(str(self.fix.policy_path))
        with self.assertRaises(gov.GovernanceError):
            gate.before_begin(policy, sha, {'profile_id': 'python.pytest'})

    def test_15_invalid_minimum_epoch_denied_even_if_python_bool(self):
        self.prepare()
        with self.assertRaisesRegex(gov.GovernanceError, 'EC267_MINIMUM_EPOCH_INVALID'):
            self.new_gate(min_epoch=True)

    def test_16_unsigned_proposal_cannot_be_used_as_signed_policy(self):
        self.prepare()
        original = self.gov_policy
        self.gov_policy = self.policy_proposal
        self.gov_pin = cp._digest(self.gov_policy.read_bytes())
        try:
            self.deny('EC267_POLICY_SCHEMA_INVALID')
        finally:
            self.gov_policy = original

    def test_17_reissue_needs_independent_pinned_epoch_root_and_exact_new_bytes(self):
        self.prepare()
        old_sha = self.gov_pin
        self.issue(epoch=2, previous_sha=old_sha, revoked=('3'*64,))
        self.minimum_epoch = 2
        self.deny('EC267_GOVERNANCE_POLICY_PIN_MISMATCH',gate=self.new_gate(governance_pin=old_sha))
        self.assertEqual(self.verify().summary()['governance_epoch'], 2)


    def test_18_real_new_ci_key_rotates_while_old_key_is_revoked(self):
        self.prepare()
        old_ci_pin = self.signers['ci']['pin']
        old_governance_sha = self.gov_pin
        new_private = self.fix.private/'ci-rotated-private.key'
        new_public = self.fix.private/'ci-rotated-public.key'
        new_public_pin = cp.generate_offline_keypair(
            str(new_private), str(new_public))['signer_public_sha256']
        evidence = self.signers['ci']['evidence']
        new_assertion = self.fix.private/'ci-rotated-assertion.json'
        signed = prov.sign_offline(str(self.subject), self.proposed['subject_sha256'],
            'ci', str(evidence), cp._digest(evidence.read_bytes()),
            'ci-rotation-proof', str(new_private), new_public_pin,
            str(new_assertion))
        record = self.gate_data['authorities'][2]
        record.update(public_key=str(new_public), public_sha256=new_public_pin,
                      assertion=str(new_assertion),
                      assertion_sha256=signed['assertion_sha256'])
        self.write_gate()
        self.issue(epoch=2, previous_sha=old_governance_sha, revoked=(old_ci_pin,))
        self.minimum_epoch = 2
        report = self.verify().summary()
        self.assertEqual(report['role_signatures_valid'], ['origin', 'review', 'ci'])
        self.assertEqual(report['signed_revocations_checked'], 1)
        self.assertEqual(report['governance_epoch'], 2)

    def test_19_runtime_expiration_during_repeated_authorization_denies(self):
        self.prepare()
        start = float(self.issued)
        with mock.patch.object(gov, '_now', return_value=(start+1, 100.0)):
            gate = self.verify()
        policy, sha = lease._policy(str(self.fix.policy_path))
        with mock.patch.object(gov, '_now',
                               return_value=(start+301, 101.0)):
            with self.assertRaisesRegex(gov.GovernanceError, 'EC267_GOVERNANCE_EXPIRED'):
                gate.before_begin(policy, sha, {'profile_id': 'python.pytest'})

    def test_20_invalid_governance_snapshot_canonicality_denied(self):
        self.prepare()
        content = self.gov_policy.read_bytes()
        self.gov_policy.write_bytes(content + b' ')
        self.gov_pin = cp._digest(self.gov_policy.read_bytes())
        with self.assertRaises(gov.GovernanceError):
            self.verify()


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(GovernanceTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
