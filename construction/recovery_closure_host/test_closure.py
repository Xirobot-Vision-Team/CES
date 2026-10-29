#!/usr/bin/env python3
"""EC270 local functional regression: real Git, key signatures, governance.

Root, council, witness are co-located developers, NOT separate people or a
trusted timestamp service. No system-wide/production acceptance implied.
"""
from __future__ import annotations

import contextlib
import io
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
from governed_source_host import governance as gov
from emergency_recovery_host.test_recovery import EmergencyRecoveryTests as original
from emergency_recovery_host import recovery as rec
from recovery_closure_host import closure as rat
from recovery_closure_host import serve as service


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     Path('/usr/bin/git').is_file() and cp.Ed25519PrivateKey is not None,
                     'nonroot Git/Ed25519 required')
class RatifiedRecoveryTests(unittest.TestCase):
    setUp = original.setUp
    kill_host = original.kill_host
    _prepare = original._prepare
    remote = original.remote
    begin_request = original.begin_request
    prepare_base = original.prepare_base
    prepare_ec266 = original.prepare_ec266
    issue = original.issue
    write_gate = original.write_gate
    new_gov = original.new_gov
    make_handover = original.make_handover
    _kwargs = original._kwargs
    renew_policy = original.renew_policy
    create_chain = original.create_chain
    material = original.material
    sign_recovery = original.sign_recovery

    def prepare(self):
        original.prepare(self)
        self.closure_draft = self.fix.private/'ec270-closure-proposal.json'
        self.closure_root = self.fix.private/'ec270-closure-root.json'
        self.closure_first = self.fix.private/'ec270-closure-council-first.json'
        self.closure_second = self.fix.private/'ec270-closure-council-second.json'
        self.closure_cert = self.fix.private/'ec270-closure-witness.json'
        self.sign_closure()
        self.args.closure_certificate = str(self.closure_cert)
        self.args.closure_certificate_sha256 = self.closure_pin
        self.args.witness_public = str(self.witness_public)
        self.args.witness_public_sha256 = self.witness_pin
        self.args.minimum_closure_observed_at_unix = self.issued
        self.args.anchor_governance = str(self.new_policy)
        self.args.anchor_governance_sha256 = self.new_pin

    def closure_material(self):
        return dict(
            old_governance=str(self.prev_policy), old_governance_sha256=self.prev_pin,
            old_root_public=str(self.prev_root_public), old_root_public_sha256=self.prev_root_pin,
            charter=str(self.charter), charter_sha256=self.charter_pin,
            council_public_keys=self.council_keys,
            anchor_governance=str(self.new_policy), anchor_governance_sha256=self.new_pin,
            recovered_root_public=str(self.new_root_public),
            recovered_root_public_sha256=self.new_root_pin,
            recovery_certificate=str(self.recovery_cert),
            recovery_certificate_sha256=self.recovery_pin,
            witness_public=str(self.witness_public), witness_public_sha256=self.witness_pin)

    def sign_closure(self):
        basis = self.closure_material()
        result = rat.prepare_closure(**basis, output=str(self.closure_draft))
        result = rat.sign_closure(**basis, input_path=str(self.closure_draft),
            input_sha256=result['closure_proposal_sha256'], role='root',
            signing_key=str(self.new_root_secret), expected_public_sha256=self.new_root_pin,
            output=str(self.closure_root))
        for idx in range(2):
            pin, public, secret = self.council[idx]
            result = rat.sign_closure(**basis, input_path=str(
                self.closure_root if idx == 0 else self.closure_first),
                input_sha256=result['signed_closure_sha256'], role='council',
                signing_key=str(secret), expected_public_sha256=pin,
                output=str(self.closure_first if idx == 0 else self.closure_second))
        result = rat.sign_closure(**basis, input_path=str(self.closure_second),
            input_sha256=result['signed_closure_sha256'], role='witness',
            signing_key=str(self.witness_secret), expected_public_sha256=self.witness_pin,
            output=str(self.closure_cert))
        self.closure_pin = result['signed_closure_sha256']
        self.witness_time = json.loads(self.closure_cert.read_bytes())['witness_observed_at_unix']

    def new_gate(self, **changes):
        kwargs = dict(
            policy_path=str(self.fix.policy_path), repo=str(self.gitfx.repo),
            allowlist=str(self.gitfx.allowpath),
            receipt=str(self.gitfx.output/'source.custody.json'),
            profile_id='python.pytest', provenance_gate=str(self.gate_path),
            provenance_gate_sha256=self.gate_pin,
            governance_policy=str(self.args.governance_policy),
            governance_policy_sha256=self.args.governance_policy_sha256,
            governance_public=str(self.new_root_public),
            governance_public_sha256=self.new_root_pin,
            minimum_epoch=self.args.minimum_governance_epoch,
            expected_previous_governance_sha256=self.args.expected_previous_governance_sha256,
            old_governance=str(self.prev_policy), old_governance_sha256=self.prev_pin,
            old_root_public=str(self.prev_root_public), old_root_public_sha256=self.prev_root_pin,
            charter=str(self.charter), charter_sha256=self.charter_pin,
            council_public_keys=self.council_keys,
            recovery_certificate=str(self.recovery_cert),
            recovery_certificate_sha256=self.recovery_pin,
            anchor_governance=str(self.args.anchor_governance),
            anchor_governance_sha256=self.args.anchor_governance_sha256,
            continuation_chain=self.args.continuation_chain,
            continuation_chain_sha256=self.args.continuation_chain_sha256,
            closure_certificate=str(self.closure_cert), closure_certificate_sha256=self.closure_pin,
            witness_public=str(self.witness_public), witness_public_sha256=self.witness_pin,
            minimum_witness_observed_at_unix=self.issued,
            forbidden_signers=(self.pub_pin, self.custody_pin))
        kwargs.update(changes)
        return rat.RatifiedRecoveryGate(**kwargs)

    def verify(self, gate=None):
        gate = gate or self.new_gate()
        policy, sha = lease._policy(str(self.fix.policy_path))
        gate.startup(policy, sha)
        return gate

    def denied(self, code, gate=None):
        with self.assertRaises((rat.ClosureError, rec.RecoveryError, gov.GovernanceError)) as ctx:
            self.verify(gate)
        self.assertEqual(ctx.exception.code, code)

    def test_01_offline_root_two_council_and_witness_enable_real_git(self):
        self.prepare()
        report = self.verify().summary()
        self.assertEqual(report['closure_root_and_council_signatures_verified'],3)
        self.assertTrue(report['closure_independent_witness_signature_verified'])
        self.assertEqual(report['role_signatures_valid'],['origin','review','ci'])
        self.assertFalse(report['trusted_external_witness_time_verified'])
        self.assertFalse(report['recovery_charter_live_expiry_required'])
        self.assertEqual(rat.verify_closure(**self.closure_material(),
            closure_certificate=str(self.closure_cert),
            closure_certificate_sha256=self.closure_pin)['ratified_recovery_epoch'],2)

    def test_02_closed_host_can_run_after_charter_expiry_with_current_governance(self):
        self.prepare()
        expiry = json.loads(self.charter.read_bytes())['expires_at_unix']
        self.assertLess(expiry, self.valid_until)
        with mock.patch.object(gov,'_now',return_value=(expiry+5.0,500.0)):
            self.assertEqual(self.verify().summary()['governance_epoch'],2)
            with self.assertRaisesRegex(rec.RecoveryError,'EC269_RECOVERY_CHARTER_NOT_CURRENT'):
                original.verify(self, original.new_gate(self))

    def test_03_old_root_and_all_offline_secrets_can_disappear_after_closure(self):
        self.prepare()
        for secret in [self.prev_root_secret, self.new_root_secret,
                       self.witness_secret, *[v[2] for v in self.council]]:
            secret.unlink()
        self.assertEqual(self.verify().summary()['governance_epoch'],2)

    def test_04_charter_must_be_live_during_offline_closure(self):
        self.prepare()
        with mock.patch.object(rat.time,'time',return_value=self.issued+201):
            with self.assertRaisesRegex(rat.ClosureError,'EC270_CLOSURE_MUST_COMPLETE_BEFORE_CHARTER_EXPIRY'):
                rat.prepare_closure(**self.closure_material(),
                    output=str(self.fix.private/'too-late-proposal.json'))

    def test_05_anchor_window_does_not_extend_with_longer_charter(self):
        self.prepare()
        charter = json.loads(self.charter.read_bytes())
        anchor = json.loads(self.new_policy.read_bytes())
        # Isolate the second independent deadline, without forging a longer
        # signed charter (which EC269 correctly would reject).
        charter['expires_at_unix'] = self.valid_until + 10
        with mock.patch.object(rat.time, 'time', return_value=self.valid_until):
            with self.assertRaisesRegex(rat.ClosureError,
                                        'EC270_RECOVERY_ANCHOR_MUST_STILL_BE_LIVE_FOR_RATIFICATION'):
                rat._live(charter, anchor)

    def test_06_all_four_signatures_required_in_order(self):
        self.prepare()
        for path in (self.closure_draft,self.closure_root,self.closure_first,self.closure_second):
            with self.assertRaisesRegex(rat.ClosureError,'EC270_ALL_FOUR_RATIFICATION_SIGNATURES_REQUIRED'):
                rat.verify_closure(**self.closure_material(),
                    closure_certificate=str(path),
                    closure_certificate_sha256=prov._digest(path.read_bytes()))
        with self.assertRaisesRegex(rat.ClosureError,'EC270_SIGNING_ORDER_OR_ROLE_INVALID'):
            rat.sign_closure(**self.closure_material(),
                input_path=str(self.closure_draft),
                input_sha256=prov._digest(self.closure_draft.read_bytes()),
                role='witness',signing_key=str(self.witness_secret),
                expected_public_sha256=self.witness_pin,
                output=str(self.fix.private/'invalid-order.json'))

    def test_07_tampered_closure_claim_repin_still_breaks_root_signature(self):
        self.prepare()
        obj=json.loads(self.closure_cert.read_bytes())
        obj['nonce']='c'*32
        forged=self.fix.private/'tampered-ratification.json'
        prov._new(str(forged),prov._canonical(obj))
        self.denied('EC270_RECOVERED_ROOT_SIGNATURE_INVALID',
                    self.new_gate(closure_certificate=str(forged),
                                  closure_certificate_sha256=prov._digest(forged.read_bytes())))

    def test_08_witness_signature_binds_all_council_signatures(self):
        self.prepare()
        obj=json.loads(self.closure_cert.read_bytes())
        obj['council_approvals'][1]['signature_ed25519']='a'*128
        forged=self.fix.private/'tampered-council.json'
        prov._new(str(forged),prov._canonical(obj))
        self.denied('EC270_COUNCIL_SIGNATURE_INVALID',self.new_gate(
            closure_certificate=str(forged),
            closure_certificate_sha256=prov._digest(forged.read_bytes())))

    def test_09_witness_observed_time_signed_and_within_two_windows(self):
        self.prepare()
        obj=json.loads(self.closure_cert.read_bytes())
        obj['witness_observed_at_unix']+=1
        forged=self.fix.private/'witness-time-edited.json'
        prov._new(str(forged),prov._canonical(obj))
        self.denied('EC270_INDEPENDENT_WITNESS_SIGNATURE_INVALID',self.new_gate(
            closure_certificate=str(forged),
            closure_certificate_sha256=prov._digest(forged.read_bytes())))

    def test_10_witness_cannot_be_a_root_or_council_or_source_actor(self):
        self.prepare()
        with self.assertRaisesRegex(rat.ClosureError,'EC270_WITNESS_REUSED_REVOKED_OR_NOT_INDEPENDENT'):
            rat.prepare_closure(**{**self.closure_material(),
                'witness_public':str(self.new_root_public),
                'witness_public_sha256':self.new_root_pin},
                output=str(self.fix.private/'wrong-witness.json'))
        with self.assertRaisesRegex(rat.ClosureError,'EC270_WITNESS_REUSED_REVOKED_OR_NOT_INDEPENDENT'):
            rat.prepare_closure(**{**self.closure_material(),
                'witness_public':str(self.council[0][1]),
                'witness_public_sha256':self.council[0][0]},
                output=str(self.fix.private/'wrong-council-witness.json'))

    def test_11_previous_file_sha_is_required_and_no_output_overwrite(self):
        self.prepare()
        output=self.fix.private/'ec270-wont-write.json'
        with self.assertRaisesRegex(rec.RecoveryError,'EC270_SIGNER_PREVIOUS_FILE_PIN_MISMATCH'):
            rat.sign_closure(**self.closure_material(),input_path=str(self.closure_draft),
                input_sha256='0'*64,role='root',signing_key=str(self.new_root_secret),
                expected_public_sha256=self.new_root_pin,output=str(output))
        self.assertFalse(output.exists())
        with self.assertRaisesRegex(rec.RecoveryError,'EC270_NEW_SIGNED_CLOSURE_STAGE_REQUIRED'):
            rat.sign_closure(**self.closure_material(),input_path=str(self.closure_draft),
                input_sha256=prov._digest(self.closure_draft.read_bytes()),
                role='root',signing_key=str(self.new_root_secret),
                expected_public_sha256=self.new_root_pin,output=str(self.closure_root))

    def test_12_council_signers_must_be_sorted_unique(self):
        self.prepare()
        with self.assertRaisesRegex(rat.ClosureError,'EC270_SIGNER_COUNCIL_ORDER_INVALID'):
            rat.sign_closure(**self.closure_material(),input_path=str(self.closure_first),
                input_sha256=prov._digest(self.closure_first.read_bytes()),
                role='council',signing_key=str(self.council[0][2]),
                expected_public_sha256=self.council[0][0],
                output=str(self.fix.private/'double-vote.json'))

    def test_13_independent_witness_time_floor_does_not_accept_older_receipt(self):
        self.prepare()
        self.denied('EC270_OPERATOR_WITNESS_TIME_FLOOR_NOT_MET',
                    self.new_gate(minimum_witness_observed_at_unix=self.witness_time+1))

    def test_14_epoch_floor_cannot_be_set_below_recovery(self):
        self.prepare()
        self.denied('EC270_OPERATOR_EPOCH_FLOOR_BELOW_RECOVERY',
                    self.new_gate(minimum_epoch=1))

    def test_15_missing_old_historic_charter_denies_even_after_closure(self):
        self.prepare()
        self.charter.unlink()
        self.denied('EC269_PRIVATE_CANONICAL_DOCUMENT_REQUIRED')

    def test_16_missing_witness_public_denies(self):
        self.prepare()
        self.witness_public.unlink()
        self.denied('EC269_PUBLIC_KEY_OR_PIN_INVALID')

    def test_17_closed_root_can_sign_contiguous_later_governance(self):
        self.prepare()
        next_gov,next_pin=self.renew_policy(3,self.new_pin)
        chain,chain_pin=self.create_chain(next_gov,next_pin)
        self.args.governance_policy=str(next_gov)
        self.args.governance_policy_sha256=next_pin
        self.args.minimum_governance_epoch=3
        self.args.expected_previous_governance_sha256=self.new_pin
        self.args.continuation_chain=str(chain)
        self.args.continuation_chain_sha256=chain_pin
        self.assertEqual(self.verify().summary()['new_root_continuation_epochs'],1)

    def test_18_parent_governance_expiry_still_rejects(self):
        self.prepare()
        with mock.patch.object(gov,'_now',return_value=(self.valid_until+1.0,500.0)):
            self.denied('EC267_GOVERNANCE_EXPIRED')

    def test_19_session_recheck_rejects_lost_closure_file(self):
        self.prepare()
        gate=self.verify()
        self.closure_cert.unlink()
        policy,sha=lease._policy(str(self.fix.policy_path))
        with self.assertRaisesRegex(rec.RecoveryError,'EC269_PRIVATE_CANONICAL_DOCUMENT_REQUIRED'):
            gate.before_begin(policy,sha,{'profile_id':'python.pytest'})

    def test_20_stage_file_pin_does_not_substitute_original_recovery_signatures(self):
        self.prepare()
        doc=json.loads(self.recovery_cert.read_bytes())
        doc['signature_new_root_ed25519']='f'*128
        bad=self.fix.private/'bad-original-recovery.json'
        prov._new(str(bad),prov._canonical(doc))
        with self.assertRaisesRegex(rec.RecoveryError,'EC269_NEW_ROOT_POSSESSION_SIGNATURE_INVALID'):
            rat.verify_closure(**{**self.closure_material(),
                'recovery_certificate':str(bad),
                'recovery_certificate_sha256':prov._digest(bad.read_bytes())},
                closure_certificate=str(self.closure_cert),
                closure_certificate_sha256=self.closure_pin)

    def test_21_source_provenance_never_bypassed_by_closure(self):
        self.prepare()
        self.gate_path.unlink()
        with self.assertRaises((rat.ClosureError,rec.RecoveryError,gov.GovernanceError,
                                prov.ProvenanceError)):
            self.verify()

    def test_22_cli_offline_verifier_remains_partial_never_quality_pass(self):
        self.prepare()
        args=['verify-closure']
        for key,val in self.closure_material().items():
            if key == 'council_public_keys':
                for path,pin in val:
                    args += ['--council-public',path,'--council-public-sha256',pin]
            elif key == 'recovered_root_public':
                args += ['--governance-public',val]
            elif key == 'recovered_root_public_sha256':
                args += ['--governance-public-sha256',val]
            else:
                args += ['--'+key.replace('_','-'),str(val)]
        args += ['--closure-certificate',str(self.closure_cert),
                 '--closure-certificate-sha256',self.closure_pin]
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code=service.main(args)
        self.assertEqual(code,2)
        self.assertFalse(json.loads(out.getvalue())['real_independent_witness_and_time_verified'])

    def test_23_new_gate_construction_does_not_use_private_signers(self):
        self.prepare()
        gate=self.new_gate()
        self.assertTrue(all('secret' not in path for path in gate.authority_paths()))
        self.assertEqual(self.verify(gate).summary()['ratified_recovery_epoch'],2)

    def test_24_charter_tamper_cannot_be_laundered_by_closure(self):
        self.prepare()
        doc=json.loads(self.charter.read_bytes())
        doc['nonce']='0'*32
        fake=self.fix.private/'tampered-charter.json'
        prov._new(str(fake),prov._canonical(doc))
        self.denied('EC269_OLD_ROOT_CHARTER_SIGNATURE_INVALID',self.new_gate(
            charter=str(fake), charter_sha256=prov._digest(fake.read_bytes())))

    def test_25_valid_witness_signature_cannot_assert_future_observation_at_startup(self):
        self.prepare()
        doc=json.loads(self.closure_cert.read_bytes())
        doc['witness_observed_at_unix']+=40
        notarized={key:value for key,value in doc.items()
                   if key!='signature_witness_ed25519'}
        doc['signature_witness_ed25519']=rec._sign(
            str(self.witness_secret),self.witness_pin,
            rat.WITNESS_DOMAIN+prov._canonical(notarized))
        fake=self.fix.private/'future-attested-closure.json'
        prov._new(str(fake),prov._canonical(doc))
        self.assertEqual(rat.verify_closure(**self.closure_material(),
            closure_certificate=str(fake),
            closure_certificate_sha256=prov._digest(fake.read_bytes()))['ratified_recovery_epoch'],2)
        self.denied('EC270_WITNESS_ATTESTATION_FROM_FUTURE',self.new_gate(
            closure_certificate=str(fake),
            closure_certificate_sha256=prov._digest(fake.read_bytes())))



if __name__ == '__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(RatifiedRecoveryTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
