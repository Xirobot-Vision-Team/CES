#!/usr/bin/env python3
"""EC269 local Git + signed governance + quorum tests (mock real-world roles)."""
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
from root_handover_host.test_handover import RootHandoverTests as original
from root_handover_host import handover as rot
from emergency_recovery_host import recovery as rec
from emergency_recovery_host import serve as service


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     Path('/usr/bin/git').is_file() and cp.Ed25519PrivateKey is not None,
                     'nonroot Linux + Git + cryptography needed')
class EmergencyRecoveryTests(unittest.TestCase):
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

    def prepare(self):
        # Inherited fixture creates unrelated EC268 normal handover for
        # backward-compat evidence; EC269 gate is separately instantiated and
        # never reads that normal certificate.
        original.prepare(self)
        self.council = []
        for n in range(3):
            secret = self.fix.private/f'ec269-council-{n}.secret'
            public = self.fix.private/f'ec269-council-{n}.public'
            pin = cp.generate_offline_keypair(str(secret), str(public))['signer_public_sha256']
            self.council.append((pin, public, secret))
        self.council.sort()
        self.council_keys = tuple((str(public), pin) for pin, public, secret in self.council)
        self.charter_draft = self.fix.private/'ec269-charter-draft.json'
        self.charter = self.fix.private/'ec269-signed-charter.json'
        proposal = rec.prepare_charter(
            old_governance=str(self.prev_policy), old_governance_sha256=self.prev_pin,
            old_root_public=str(self.prev_root_public),
            old_root_public_sha256=self.prev_root_pin,
            council_public_keys=self.council_keys,
            expires_at_unix=self.issued+200, output=str(self.charter_draft),
            issued_at_unix=self.issued)
        result = rec.sign_charter(
            proposal=str(self.charter_draft),
            proposal_sha256=proposal['charter_proposal_sha256'],
            old_governance=str(self.prev_policy), old_governance_sha256=self.prev_pin,
            old_root_public=str(self.prev_root_public),
            old_root_public_sha256=self.prev_root_pin,
            council_public_keys=self.council_keys,
            old_root_private=str(self.prev_root_secret), output=str(self.charter))
        self.charter_pin = result['signed_charter_sha256']
        self.recovery_draft = self.fix.private/'ec269-recovery-draft.json'
        self.recovery_new = self.fix.private/'ec269-recovery-new-signed.json'
        self.recovery_vote1 = self.fix.private/'ec269-recovery-vote1.json'
        self.recovery_cert = self.fix.private/'ec269-recovery-complete.json'
        self.sign_recovery()
        self.args.old_governance = str(self.prev_policy)
        self.args.old_governance_sha256 = self.prev_pin
        self.args.old_root_public = str(self.prev_root_public)
        self.args.old_root_public_sha256 = self.prev_root_pin
        self.args.charter = str(self.charter)
        self.args.charter_sha256 = self.charter_pin
        self.args.council_public = [p for p, _ in self.council_keys]
        self.args.council_public_sha256 = [pin for _, pin in self.council_keys]
        self.args.recovery_certificate = str(self.recovery_cert)
        self.args.recovery_certificate_sha256 = self.recovery_pin
        self.args.anchor_governance = str(self.new_policy)
        self.args.anchor_governance_sha256 = self.new_pin
        self.args.continuation_chain = None
        self.args.continuation_chain_sha256 = None

    def material(self):
        return dict(old_governance=str(self.prev_policy),
            old_governance_sha256=self.prev_pin,
            old_root_public=str(self.prev_root_public),
            old_root_public_sha256=self.prev_root_pin,
            charter=str(self.charter), charter_sha256=self.charter_pin,
            council_public_keys=self.council_keys,
            new_governance=str(self.new_policy),
            new_governance_sha256=self.new_pin,
            new_root_public=str(self.new_root_public),
            new_root_public_sha256=self.new_root_pin)

    def sign_recovery(self):
        material = self.material()
        unsigned = rec.prepare_recovery(**material, output=str(self.recovery_draft))
        result = rec.sign_recovery(**material, input_path=str(self.recovery_draft),
            input_sha256=unsigned['recovery_proposal_sha256'],
            role='new', signing_key=str(self.new_root_secret),
            expected_public_sha256=self.new_root_pin, output=str(self.recovery_new))
        for i in range(2):
            pin, pub, secret = self.council[i]
            output = self.recovery_vote1 if i == 0 else self.recovery_cert
            result = rec.sign_recovery(**material,
                input_path=str(self.recovery_new if i == 0 else self.recovery_vote1),
                input_sha256=result['signed_recovery_sha256'],
                role='council', signing_key=str(secret),
                expected_public_sha256=pin, output=str(output))
        self.recovery_pin = result['signed_recovery_sha256']

    def new_gate(self, **changes):
        opts = dict(policy_path=str(self.fix.policy_path), repo=str(self.gitfx.repo),
            allowlist=str(self.gitfx.allowpath),
            receipt=str(self.gitfx.output/'source.custody.json'),
            profile_id='python.pytest',
            provenance_gate=str(self.gate_path), provenance_gate_sha256=self.gate_pin,
            governance_policy=str(self.new_policy), governance_policy_sha256=self.new_pin,
            governance_public=str(self.new_root_public),
            governance_public_sha256=self.new_root_pin,
            minimum_epoch=2, expected_previous_governance_sha256=self.prev_pin,
            old_governance=str(self.prev_policy), old_governance_sha256=self.prev_pin,
            old_root_public=str(self.prev_root_public),
            old_root_public_sha256=self.prev_root_pin,
            charter=str(self.charter), charter_sha256=self.charter_pin,
            council_public_keys=self.council_keys,
            recovery_certificate=str(self.recovery_cert),
            recovery_certificate_sha256=self.recovery_pin,
            forbidden_signers=(self.pub_pin, self.custody_pin))
        opts.update(changes)
        return rec.EmergencyRecoveryGate(**opts)

    def verify(self, gate=None):
        gate = gate or self.new_gate()
        policy, sha = lease._policy(str(self.fix.policy_path))
        gate.startup(policy, sha)
        return gate

    def denied(self, code: str, *, gate=None):
        with self.assertRaises((rec.RecoveryError, gov.GovernanceError)) as caught:
            self.verify(gate)
        self.assertEqual(caught.exception.code, code)

    def test_01_recovered_root_enables_source_and_three_role_signatures(self):
        self.prepare()
        report = self.verify().summary()
        self.assertEqual(report['independent_council_votes_verified'], 2)
        self.assertEqual(report['recovered_new_root_epoch'], 2)
        self.assertEqual(report['role_signatures_valid'], ['origin', 'review', 'ci'])
        self.assertFalse(report['cross_restart_nonrollback_verified'])
        self.assertFalse(report['root_loss_verified_externally'])

    def test_02_old_root_secret_not_needed_after_precommitted_charter(self):
        self.prepare()
        self.prev_root_secret.unlink()
        self.witness_secret.unlink()
        self.assertEqual(self.verify().summary()['governance_epoch'], 2)

    def test_03_new_root_possession_signature_is_mandatory(self):
        self.prepare()
        self.denied('EC269_RECOVERY_QUORUM_INCOMPLETE',
                    gate=self.new_gate(recovery_certificate=str(self.recovery_draft),
                                       recovery_certificate_sha256=prov._digest(
                                           self.recovery_draft.read_bytes())))

    def test_04_one_council_vote_not_quorum(self):
        self.prepare()
        self.denied('EC269_RECOVERY_QUORUM_INCOMPLETE',
                    gate=self.new_gate(recovery_certificate=str(self.recovery_vote1),
                                       recovery_certificate_sha256=prov._digest(
                                           self.recovery_vote1.read_bytes())))

    def test_05_duplicate_or_reversed_council_votes_fail_even_with_repin(self):
        self.prepare()
        obj = json.loads(self.recovery_cert.read_bytes())
        obj['council_approvals'][1] = obj['council_approvals'][0]
        bad = self.fix.private/'bad-votes.json'
        prov._new(str(bad), prov._canonical(obj))
        self.denied('EC269_RECOVERY_COUNCIL_APPROVAL_DUPLICATE_OR_UNSORTED',
                    gate=self.new_gate(recovery_certificate=str(bad),
                        recovery_certificate_sha256=prov._digest(bad.read_bytes())))

    def test_06_changed_claim_with_updated_sha_still_breaks_votes(self):
        self.prepare()
        obj = json.loads(self.recovery_cert.read_bytes())
        obj['nonce'] = 'f'*32
        bad = self.fix.private/'altered-claim.json'
        prov._new(str(bad), prov._canonical(obj))
        self.denied('EC269_NEW_ROOT_POSSESSION_SIGNATURE_INVALID',
                    gate=self.new_gate(recovery_certificate=str(bad),
                        recovery_certificate_sha256=prov._digest(bad.read_bytes())))

    def test_07_charter_bytes_changed_is_detected(self):
        self.prepare()
        self.charter.write_bytes(self.charter.read_bytes()+b' ')
        self.denied('EC269_PRIVATE_CANONICAL_DOCUMENT_REQUIRED')

    def test_08_forged_charter_with_recomputed_pin_is_denied(self):
        self.prepare()
        obj = json.loads(self.charter.read_bytes())
        obj['expires_at_unix'] += 1
        tampered = self.fix.private/'forged-charter.json'
        prov._new(str(tampered), prov._canonical(obj))
        self.denied('EC269_OLD_ROOT_CHARTER_SIGNATURE_INVALID',
                    gate=self.new_gate(charter=str(tampered),
                         charter_sha256=prov._digest(tampered.read_bytes())))

    def test_09_wrong_council_public_file_with_pinned_identity_denied(self):
        self.prepare()
        fake = self.fix.private/'mismatched-council-public.key'
        prov._new(str(fake), self.council[1][1].read_bytes())
        keys = [(str(fake), self.council[0][0]), *self.council_keys[1:]]
        self.denied('EC269_PUBLIC_KEY_OR_PIN_INVALID',
                    gate=self.new_gate(council_public_keys=tuple(keys)))

    def test_10_council_cannot_reuse_source_signer_or_audit_signer(self):
        self.prepare()
        with self.assertRaisesRegex(rec.RecoveryError,
                                    'EC269_AUTHORITIES_NOT_INDEPENDENT_OF_ISSUERS_OR_AUDIT'):
            rec._basis(**self.material(), forbidden_signers=(self.council[0][0],))

    def test_11_old_root_cannot_be_a_council_member(self):
        self.prepare()
        keys = ((str(self.prev_root_public), self.prev_root_pin), *self.council_keys[1:])
        with self.assertRaisesRegex(rec.RecoveryError,'EC269_ROOT_REUSED_AS_COUNCIL_MEMBER'):
            rec._basis(**{**self.material(), 'council_public_keys': keys})

    def test_12_stages_must_start_with_new_root_signature(self):
        self.prepare()
        extra = self.fix.private/'stage-bad.json'
        with self.assertRaisesRegex(rec.RecoveryError,'EC269_SIGNING_STAGE_OR_ROLE_INVALID'):
            rec.sign_recovery(**self.material(),input_path=str(self.recovery_draft),
               input_sha256=prov._digest(self.recovery_draft.read_bytes()),
               role='council',signing_key=str(self.council[0][2]),
               expected_public_sha256=self.council[0][0],output=str(extra))
        self.assertFalse(extra.exists())

    def test_13_approval_order_is_unique_and_ascending(self):
        self.prepare()
        extra = self.fix.private/'reordered.json'
        with self.assertRaisesRegex(rec.RecoveryError,
                                    'EC269_APPROVALS_MUST_USE_UNIQUE_ASCENDING_COUNCIL_PINS'):
            rec.sign_recovery(**self.material(), input_path=str(self.recovery_vote1),
                input_sha256=prov._digest(self.recovery_vote1.read_bytes()),
                role='council',signing_key=str(self.council[0][2]),
                expected_public_sha256=self.council[0][0], output=str(extra))
        self.assertFalse(extra.exists())

    def test_14_unlisted_council_signer_must_not_sign(self):
        self.prepare()
        secret = self.fix.private/'outsider.key'
        public = self.fix.private/'outsider.public'
        pin = cp.generate_offline_keypair(str(secret),str(public))['signer_public_sha256']
        with self.assertRaisesRegex(rec.RecoveryError,'EC269_SIGNER_NOT_PRECOMMITTED_COUNCIL'):
            rec.sign_recovery(**self.material(),input_path=str(self.recovery_new),
                 input_sha256=prov._digest(self.recovery_new.read_bytes()),
                 role='council',signing_key=str(secret),
                 expected_public_sha256=pin,output=str(self.fix.private/'outsider-vote.json'))

    def test_15_offline_stage_requires_independent_exact_input_pin(self):
        self.prepare()
        with self.assertRaisesRegex(rec.RecoveryError,'EC269_RECOVERY_SIGNER_INPUT_PIN_MISMATCH'):
            rec.sign_recovery(**self.material(),input_path=str(self.recovery_new),
                 input_sha256='a'*64,role='council',signing_key=str(self.council[0][2]),
                 expected_public_sha256=self.council[0][0],
                 output=str(self.fix.private/'bad-pin.json'))

    def test_16_offline_output_never_overwrites_existing_complete_vote(self):
        self.prepare()
        with self.assertRaisesRegex(rec.RecoveryError,'EC269_NEW_SIGNED_STAGE_FILE_REQUIRED'):
            rec.sign_recovery(**self.material(),input_path=str(self.recovery_new),
                 input_sha256=prov._digest(self.recovery_new.read_bytes()),role='council',
                 signing_key=str(self.council[0][2]),
                 expected_public_sha256=self.council[0][0],output=str(self.recovery_vote1))

    def test_17_new_root_must_have_matching_governance_signature(self):
        self.prepare()
        bad = self.fix.private/'other-root.key'
        other_pub = self.fix.private/'other-root.pub'
        other_pin = cp.generate_offline_keypair(str(bad),str(other_pub))['signer_public_sha256']
        with self.assertRaisesRegex(rec.RecoveryError,'EC269_NEW_ROOT_SIGNER_PIN_MISMATCH'):
            rec.sign_recovery(**self.material(),input_path=str(self.recovery_draft),
                  input_sha256=prov._digest(self.recovery_draft.read_bytes()),role='new',
                  signing_key=str(bad),expected_public_sha256=other_pin,
                  output=str(self.fix.private/'wrong-new.json'))

    def test_18_charter_expiry_denies_even_with_new_root_current(self):
        self.prepare()
        now = float(self.issued+201)
        with mock.patch.object(gov, '_now', return_value=(now, 1000.0)):
            self.denied('EC269_RECOVERY_CHARTER_NOT_CURRENT')

    def test_19_original_ec267_expiry_still_denies(self):
        self.prepare()
        with mock.patch.object(gov,'_now',return_value=(float(self.valid_until),1000.0)):
            self.denied('EC267_GOVERNANCE_EXPIRED')

    def test_20_recovery_certificate_is_required_for_every_session(self):
        self.prepare()
        gate = self.verify()
        policy, sha = lease._policy(str(self.fix.policy_path))
        self.recovery_cert.unlink()
        with self.assertRaises(rec.RecoveryError):
            gate.before_begin(policy,sha,{'profile_id':'python.pytest'})

    def test_21_subsequent_new_root_epoch_uses_exact_ec268_append_only_chain(self):
        self.prepare()
        next_policy, next_pin = self.renew_policy(3,self.new_pin)
        chain, chain_pin = self.create_chain(next_policy,next_pin)
        gate = self.new_gate(
            governance_policy=str(next_policy), governance_policy_sha256=next_pin,
            anchor_governance=str(self.new_policy), anchor_governance_sha256=self.new_pin,
            minimum_epoch=3, expected_previous_governance_sha256=self.new_pin,
            continuation_chain=str(chain),continuation_chain_sha256=chain_pin)
        self.prev_root_secret.unlink()
        self.assertEqual(self.verify(gate).summary()['new_root_continuation_epochs'],1)

    def test_22_continuation_with_wrong_immediate_predecessor_rejected(self):
        self.prepare()
        next_policy, next_pin = self.renew_policy(3,self.new_pin)
        chain, chain_pin = self.create_chain(next_policy,next_pin)
        with self.assertRaisesRegex(rec.RecoveryError,'EC269_EXTERNAL_CURRENT_PREDECESSOR_PIN_MISMATCH'):
            self.new_gate(governance_policy=str(next_policy),
                governance_policy_sha256=next_pin,
                anchor_governance=str(self.new_policy),anchor_governance_sha256=self.new_pin,
                continuation_chain=str(chain),continuation_chain_sha256=chain_pin,
                expected_previous_governance_sha256='f'*64)

    def test_23_recovery_epoch_must_be_contiguous_and_revoke_retired_roles(self):
        self.prepare()
        other = self.fix.private/'skip-governance.proposal'
        signed = self.fix.private/'skip-governance.signed'
        p = gov.prepare_policy(str(self.gate_path),self.gate_pin,epoch=3,
            previous_governance_sha256=self.prev_pin,
            issued_at_unix=self.issued,not_before_unix=self.valid_from,
            expires_at_unix=self.valid_until,revoked_public_sha256=(),output=str(other))
        s = gov.sign_offline(str(other),p['proposal_sha256'],str(self.new_root_secret),
            self.new_root_pin,str(signed))
        with self.assertRaisesRegex(rot.HandoverError,'EC268_GOVERNANCE_EPOCH_OR_PREDECESSOR_MISMATCH'):
            rec.prepare_recovery(**{**self.material(),'new_governance':str(signed),
               'new_governance_sha256':s['governance_sha256']},
               output=str(self.fix.private/'skip.json'))

    def test_24_prepare_charter_rejects_wrong_old_epoch_validity_window(self):
        self.prepare()
        with self.assertRaisesRegex(rec.RecoveryError,'EC269_CHARTER_NOT_PREAUTHORIZED_IN_OLD_EPOCH'):
            rec.prepare_charter(
               old_governance=str(self.prev_policy),old_governance_sha256=self.prev_pin,
               old_root_public=str(self.prev_root_public),old_root_public_sha256=self.prev_root_pin,
               council_public_keys=self.council_keys,issued_at_unix=self.issued+301,
               expires_at_unix=self.issued+500,
               output=str(self.fix.private/'late-charter.json'))

    def test_25_cli_gate_and_prepare_recovery_report_partial(self):
        self.prepare()
        result = service.verify_gate(self.args)
        self.assertEqual(result['status'],'partial')
        self.assertEqual(result['custody_receipts_verified'],1)
        argv = self.cli_common() + ['--output',str(self.fix.private/'cli-proposal.json')]
        stdout=io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code=service.main(['prepare-recovery',*argv])
        self.assertEqual(code,2,stdout.getvalue())
        self.assertEqual(json.loads(stdout.getvalue())['required_independent_council_signatures'],2)

    def test_26_misplaced_recovery_evidence_in_source_repo_denied(self):
        self.prepare()
        # Existing source tree file cannot be used as a trust root even if it
        # has an otherwise valid, independently signed certificate digest.
        inside=Path(self.gitfx.repo)/'recovery.json'
        inside.write_bytes(self.recovery_cert.read_bytes())
        self.args.recovery_certificate=str(inside)
        with self.assertRaisesRegex(rec.RecoveryError,'EC269_RECOVERY_FILE_INSIDE_SOURCE_OR_AUDIT_TREE'):
            service.verify_gate(self.args)

    def test_27_preflight_uses_zero_existing_authority_overwrites(self):
        self.prepare()
        self.args.charter = self.args.governance_public
        with self.assertRaisesRegex(rec.RecoveryError,'EC269_AUTHORITY_FILE_PATH_COLLISION'):
            service.verify_gate(self.args)

    def test_28_missing_charter_council_public_file_revokes_gate(self):
        self.prepare()
        self.council[2][1].unlink()
        self.denied('EC269_PUBLIC_KEY_OR_PIN_INVALID')

    def test_29_tampered_complete_council_signature_denies(self):
        self.prepare()
        obj=json.loads(self.recovery_cert.read_bytes())
        obj['council_approvals'][1]['signature_ed25519']='0'*128
        forged = self.fix.private/'bad-council.json'
        prov._new(str(forged),prov._canonical(obj))
        self.denied('EC269_COUNCIL_APPROVAL_SIGNATURE_INVALID',
                    gate=self.new_gate(recovery_certificate=str(forged),
                         recovery_certificate_sha256=prov._digest(forged.read_bytes())))

    def test_30_historic_signed_policy_remains_required(self):
        self.prepare()
        self.prev_policy.unlink()
        with self.assertRaises((rec.RecoveryError,gov.GovernanceError)):
            self.verify()

    def test_31_any_two_distinct_charter_council_members_can_form_quorum(self):
        self.prepare()
        evidence=self.material()
        proposal=self.fix.private/'alternative-quorum.json'
        stage_new=self.fix.private/'alternative-new.json'
        stage_one=self.fix.private/'alternative-vote1.json'
        stage_two=self.fix.private/'alternative-vote2.json'
        a=rec.prepare_recovery(**evidence,output=str(proposal))
        a=rec.sign_recovery(**evidence,input_path=str(proposal),
            input_sha256=a['recovery_proposal_sha256'],role='new',
            signing_key=str(self.new_root_secret),
            expected_public_sha256=self.new_root_pin,output=str(stage_new))
        for i,(pin,pub,key) in enumerate(self.council[1:]):
            result_path=stage_one if i==0 else stage_two
            a=rec.sign_recovery(**evidence,
                input_path=str(stage_new if i==0 else stage_one),
                input_sha256=a['signed_recovery_sha256'],role='council',
                signing_key=str(key),expected_public_sha256=pin,
                output=str(result_path))
        gate=self.new_gate(recovery_certificate=str(stage_two),
                           recovery_certificate_sha256=a['signed_recovery_sha256'])
        self.assertEqual(self.verify(gate).summary()['independent_council_votes_verified'],2)

    def test_32_sign_charter_checks_live_old_root_window_not_only_self_declared_time(self):
        self.prepare()
        extra=self.fix.private/'late-offline-old-sign.json'
        with mock.patch.object(rec.time,'time',return_value=self.valid_until+1):
            with self.assertRaisesRegex(rec.RecoveryError,
                                        'EC269_OLD_ROOT_CHARTER_SIGNING_TIME_NOT_CURRENT'):
                rec.sign_charter(
                    proposal=str(self.charter_draft),
                    proposal_sha256=prov._digest(self.charter_draft.read_bytes()),
                    old_governance=str(self.prev_policy),
                    old_governance_sha256=self.prev_pin,
                    old_root_public=str(self.prev_root_public),
                    old_root_public_sha256=self.prev_root_pin,
                    council_public_keys=self.council_keys,
                    old_root_private=str(self.prev_root_secret),output=str(extra))
        self.assertFalse(extra.exists())

    def test_33_a_recovery_council_key_revoked_by_new_governance_is_denied(self):
        self.prepare()
        self.new_gov(revoked=(self.council[0][0],))
        with self.assertRaisesRegex(rec.RecoveryError,
                                    'EC269_RECOVERY_AUTHORITY_PREVIOUSLY_REVOKED'):
            rec.prepare_recovery(**self.material(),
                output=str(self.fix.private/'revoked-council-proposal.json'))

    def test_34_signer_rechecks_prior_root_signature_not_just_stage_file_pin(self):
        self.prepare()
        forged=self.fix.private/'bad-new-stage.json'
        obj=json.loads(self.recovery_new.read_bytes())
        obj['signature_new_root_ed25519']='1'*128
        prov._new(str(forged),prov._canonical(obj))
        with self.assertRaisesRegex(rec.RecoveryError,
                                    'EC269_NEW_ROOT_POSSESSION_SIGNATURE_INVALID'):
            rec.sign_recovery(**self.material(),input_path=str(forged),
                input_sha256=prov._digest(forged.read_bytes()),role='council',
                signing_key=str(self.council[0][2]),
                expected_public_sha256=self.council[0][0],
                output=str(self.fix.private/'untrusted-vote.json'))

    def cli_common(self):
        fields = self.material()
        def arg(k,val): return ['--'+k.replace('_','-'),str(val)]
        out = []
        for name in ('old_governance','old_governance_sha256','old_root_public',
                     'old_root_public_sha256','charter','charter_sha256',
                     'new_governance','new_governance_sha256',
                     'new_root_public','new_root_public_sha256'):
            cli_name={'new_governance':'governance_policy',
                      'new_governance_sha256':'governance_policy_sha256',
                      'new_root_public':'governance_public',
                      'new_root_public_sha256':'governance_public_sha256'}.get(name,name)
            out.extend(arg(cli_name,fields[name]))
        for public,pin in self.council_keys:
            out += ['--council-public',public,'--council-public-sha256',pin]
        return out


if __name__ == '__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(EmergencyRecoveryTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
