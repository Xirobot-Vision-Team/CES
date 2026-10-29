#!/usr/bin/env python3
"""EC272 focused signed rollover functional cases; nonroot local signers."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
import time
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from lease_host import broker as lease
from offline_anchor_host import checkpoint as cp
from source_provenance_host import provenance as prov
from freshness_quorum_host import freshness as fresh
from emergency_recovery_host import recovery as rec
from freshness_quorum_host.test_freshness import FreshnessTests as original
from freshness_rollover_host import rollover as roll
from freshness_rollover_host import serve as service


@unittest.skipUnless(os.name=='posix' and os.geteuid()!=0 and
                     Path('/usr/bin/git').is_file() and cp.Ed25519PrivateKey is not None,
                     'nonroot Linux Git/Ed25519 required')
class RolloverTests(unittest.TestCase):
    setUp=original.setUp
    prepare_base=original.prepare_base
    prepare_ec266=original.prepare_ec266
    new_gov=original.new_gov
    make_handover=original.make_handover
    renew_policy=original.renew_policy
    create_chain=original.create_chain
    issue=original.issue
    write_gate=original.write_gate
    _kwargs=original._kwargs
    sign_recovery=original.sign_recovery
    sign_closure=original.sign_closure
    closure_material=original.closure_material
    material=original.material
    remote=original.remote
    begin_request=original.begin_request
    kill_host=original.kill_host
    _prepare=original._prepare
    historic=original.historic
    freshness_options=original.freshness_options
    sign_seal=original.sign_seal
    new_gate=original.new_gate

    def _context(self):
        return self.freshness_options()

    def _signed_checkpoint(self,segment,segment_sha,previous=None,previous_sha=None,prefix='first'):
        args=self._context()
        draft=self.fix.private/(prefix+'-cp-draft.json')
        first=self.fix.private/(prefix+'-cp-first.json')
        final=self.fix.private/(prefix+'-cp-final.json')
        result=roll.prepare_checkpoint(**args,segment=str(segment),
            segment_sha256=segment_sha,output=str(draft),
            previous_checkpoint=str(previous) if previous else None,
            previous_checkpoint_sha256=previous_sha)
        result=roll.sign_checkpoint(**args,input_path=str(draft),
            input_sha256=result['checkpoint_proposal_sha256'],
            signing_key=str(self.witnesses[0][2]),
            expected_public_sha256=self.witnesses[0][0],output=str(first))
        result=roll.sign_checkpoint(**args,input_path=str(first),
            input_sha256=result['signed_checkpoint_sha256'],
            signing_key=str(self.witnesses[1][2]),
            expected_public_sha256=self.witnesses[1][0],output=str(final))
        return final,result['signed_checkpoint_sha256']

    def prepare(self):
        original.prepare(self)
        self.old_receipt_pin=self.receipt_pin
        self.cp_file,self.cp_pin=self._signed_checkpoint(self.fresh_chain,self.fresh_chain_pin)
        self.next_draft=self.fix.private/'ec272-seal-2-draft.json'
        self.next_first=self.fix.private/'ec272-seal-2-first.json'
        self.next_receipt=self.fix.private/'ec272-seal-2-final.json'
        self.next_receipt_pin=self.sign_seal(sequence=2,draft=self.next_draft,
            first=self.next_first,complete=self.next_receipt,
            start=max(self.issued,json.loads(self.receipt.read_bytes())['approvals'][-1]['observed_at_unix']),
            expiry=self.issued+240,previous=self.receipt,
            previous_pin=self.old_receipt_pin)
        self.tail=self.fix.private/'ec272-tail-segment.json'
        self.epochs={self.args.minimum_governance_epoch:
                     self.args.governance_policy_sha256}
        self.tail_pin=roll.append_segment(checkpoint=str(self.cp_file),
            checkpoint_sha256=self.cp_pin,segment_receipt=str(self.next_receipt),
            segment_receipt_sha256=self.next_receipt_pin,
            witness_public_keys=self.witness_keys,
            closure_sha256=self.closure_pin,
            recovered_root_public_sha256=self.new_root_pin,
            allowed_governance_epochs=self.epochs,output=str(self.tail))['segment_sha256']
        self.args.checkpoint=str(self.cp_file)
        self.args.checkpoint_sha256=self.cp_pin
        self.args.freshness_chain=str(self.tail)
        self.args.freshness_chain_sha256=self.tail_pin
        self.args.minimum_freshness_sequence=2
        self.args.minimum_checkpoint_number=1
        self.args.expected_previous_receipt_sha256=self.old_receipt_pin

    def new_roll_gate(self,**changes):
        opts=dict(
            policy_path=str(self.fix.policy_path),repo=str(self.gitfx.repo),
            allowlist=str(self.gitfx.allowpath),
            receipt=str(self.gitfx.output/'source.custody.json'),
            profile_id='python.pytest',provenance_gate=str(self.gate_path),
            provenance_gate_sha256=self.gate_pin,
            governance_policy=str(self.args.governance_policy),
            governance_policy_sha256=self.args.governance_policy_sha256,
            governance_public=str(self.new_root_public),
            governance_public_sha256=self.new_root_pin,
            minimum_epoch=self.args.minimum_governance_epoch,
            expected_previous_governance_sha256=self.args.expected_previous_governance_sha256,
            old_governance=str(self.prev_policy),old_governance_sha256=self.prev_pin,
            old_root_public=str(self.prev_root_public),old_root_public_sha256=self.prev_root_pin,
            charter=str(self.charter),charter_sha256=self.charter_pin,
            council_public_keys=self.council_keys,
            recovery_certificate=str(self.recovery_cert),
            recovery_certificate_sha256=self.recovery_pin,
            anchor_governance=str(self.args.anchor_governance),
            anchor_governance_sha256=self.args.anchor_governance_sha256,
            continuation_chain=self.args.continuation_chain,
            continuation_chain_sha256=self.args.continuation_chain_sha256,
            closure_certificate=str(self.closure_cert),
            closure_certificate_sha256=self.closure_pin,
            witness_public=str(self.witness_public),
            witness_public_sha256=self.witness_pin,
            minimum_witness_observed_at_unix=self.issued,
            forbidden_signers=(self.pub_pin,self.custody_pin),
            freshness_chain=str(self.tail),freshness_chain_sha256=self.tail_pin,
            freshness_witness_public_keys=self.witness_keys,
            minimum_freshness_sequence=self.args.minimum_freshness_sequence,
            expected_previous_receipt_sha256=self.args.expected_previous_receipt_sha256,
            checkpoint=str(self.cp_file),checkpoint_sha256=self.cp_pin,
            minimum_checkpoint_number=1)
        opts.update(changes)
        return service.SignedRolloverGate(**opts)

    def verify(self,gate=None):
        gate=gate or self.new_roll_gate()
        policy,pin=lease._policy(str(self.fix.policy_path))
        gate.startup(policy,pin)
        return gate

    def denied(self,code,gate=None):
        with self.assertRaises(Exception) as ctx:
            self.verify(gate)
        self.assertEqual(getattr(ctx.exception,'code',None),code,
            f'{code}, instead {getattr(ctx.exception,"code",None)}: {ctx.exception}')

    def test_01_signed_genesis_checkpoint_and_live_segment(self):
        self.prepare()
        report=self.verify().summary()
        self.assertEqual(report['freshness_sequence'],2)
        self.assertEqual(report['sealed_checkpoint_number'],1)
        self.assertEqual(report['role_signatures_valid'],['origin','review','ci'])
        self.assertFalse(report['full_old_member_replay_after_checkpoint'])
        self.assertFalse(report['trusted_external_time_verified'])

    def test_02_first_witness_signature_only_denied(self):
        self.prepare()
        data=json.loads(self.cp_file.read_bytes())
        data['approvals']=data['approvals'][:1]
        candidate=self.fix.private/'not-quorum.json'
        prov._new(str(candidate),prov._canonical(data))
        with self.assertRaisesRegex(roll.RolloverError,
                                   'EC272_CHECKPOINT_TWO_SIGNATURES_REQUIRED'):
            roll._walk_checkpoints(checkpoint=str(candidate),
                checkpoint_sha256=prov._digest(candidate.read_bytes()),
                keys=fresh._witness_keys(self.witness_keys),
                closure_sha256=self.closure_pin,root_sha256=self.new_root_pin,
                allowed_epochs=self.epochs)

    def test_03_signature_change_even_repin_is_denied(self):
        self.prepare()
        data=json.loads(self.cp_file.read_bytes())
        data['approvals'][0]['signature_ed25519']='a'*128
        candidate=self.fix.private/'forged-quorum.json'
        prov._new(str(candidate),prov._canonical(data))
        with self.assertRaisesRegex(rec.RecoveryError, 'EC272_CHECKPOINT_SIGNATURE_INVALID'):
            self.new_roll_gate(checkpoint=str(candidate),
                checkpoint_sha256=prov._digest(candidate.read_bytes()))

    def test_04_current_segment_tamper_invalidates_host(self):
        self.prepare()
        self.next_receipt.unlink()
        self.denied('EC269_PRIVATE_CANONICAL_DOCUMENT_REQUIRED')

    def test_05_checkpoint_missing_blocks_before_admission(self):
        self.prepare()
        self.cp_file.unlink()
        with self.assertRaises(Exception):
            self.verify()

    def test_06_legacy_ec271_host_refuses_non_genesis_tail(self):
        self.prepare()
        with self.assertRaisesRegex(fresh.FreshnessError,
                                    'EC271_GENESIS_PREDECESSOR_REQUIRED'):
            fresh.verify_chain(chain=str(self.tail),chain_sha256=self.tail_pin,
                witness_public_keys=self.witness_keys,
                closure_sha256=self.closure_pin,
                recovered_root_public_sha256=self.new_root_pin,
                allowed_governance_epochs=self.epochs,
                current_governance_sha256=self.args.governance_policy_sha256,
                current_governance_epoch=self.args.minimum_governance_epoch,
                minimum_sequence=2,
                expected_previous_receipt_sha256=self.old_receipt_pin)

    def test_07_full_sealed_history_attested_not_replayed_on_live_check(self):
        self.prepare()
        self.receipt.unlink()  # Historic receipt embedded and signed into checkpoint.
        self.assertEqual(self.verify().summary()['freshness_sequence'],2)

    def test_08_operator_checkpoint_floor_denies_rollback(self):
        self.prepare()
        self.denied('EC272_OPERATOR_CHECKPOINT_FLOOR_NOT_MET',
            self.new_roll_gate(minimum_checkpoint_number=2))

    def test_09_wrong_previous_sha_rejects_even_valid_new_seal(self):
        self.prepare()
        self.denied('EC272_OPERATOR_PREDECESSOR_PIN_MISMATCH',
            self.new_roll_gate(expected_previous_receipt_sha256='f'*64))

    def test_10_signing_checkpoint_after_seal_expires_denied(self):
        self.prepare()
        output=self.fix.private/'late-checkpoint.json'
        with mock.patch.object(roll.time,'time',return_value=self.issued+241):
            with self.assertRaisesRegex(roll.RolloverError,
                                        'EC272_CHECKPOINT_CEREMONY_OUTSIDE_LIVE_SEAL'):
                roll.prepare_checkpoint(**self._context(),segment=str(self.fresh_chain),
                    segment_sha256=self.fresh_chain_pin,output=str(output))
        self.assertFalse(output.exists())

    def test_11_checkpoint_signing_key_not_in_roster_denied(self):
        self.prepare()
        output=self.fix.private/'wrong-checkpoint-signer.json'
        doc=json.loads(self.cp_file.read_bytes())
        doc.pop('approvals')
        draft=self.fix.private/'wrong-checkpoint-draft.json'
        prov._new(str(draft),prov._canonical(doc))
        with self.assertRaisesRegex(roll.RolloverError,
                                    'EC272_SIGNER_NOT_IN_INCREASING_QUORUM'):
            roll.sign_checkpoint(**self._context(),input_path=str(draft),
                input_sha256=prov._digest(draft.read_bytes()),
                signing_key=str(self.new_root_secret),
                expected_public_sha256=self.new_root_pin,output=str(output))

    def test_12_wrong_checkpoint_next_receipt_sequence_rejected(self):
        self.prepare()
        with self.assertRaisesRegex(fresh.FreshnessError,
                                    'EC271_SIGNED_CHAIN_PREDECESSOR_INVALID'):
            roll.append_segment(checkpoint=str(self.cp_file),checkpoint_sha256=self.cp_pin,
                segment_receipt=str(self.receipt),segment_receipt_sha256=self.old_receipt_pin,
                witness_public_keys=self.witness_keys,closure_sha256=self.closure_pin,
                recovered_root_public_sha256=self.new_root_pin,
                allowed_governance_epochs=self.epochs,
                output=str(self.fix.private/'bad-append.json'))

    def test_13_revoking_witness_during_gate_rechecks_signed_roster(self):
        self.prepare()
        gate=self.verify()
        self.witnesses[1][1].unlink()
        with self.assertRaises(Exception):
            gate.before_begin()

    def _roll_again(self):
        """Complete the next checkpoint, then start the third signed seal."""
        cp2,cp2pin=self._signed_checkpoint(self.tail,self.tail_pin,
            previous=self.cp_file,previous_sha=self.cp_pin,prefix='second')
        third=self.fix.private/'ec272-third-final.json'
        third_pin=self.sign_seal(sequence=3,
            draft=self.fix.private/'ec272-third-draft.json',
            first=self.fix.private/'ec272-third-first.json',
            complete=third,
            start=max(self.issued,json.loads(self.next_receipt.read_bytes())['approvals'][-1]['observed_at_unix']),
            expiry=self.issued+240,
            previous=self.next_receipt,previous_pin=self.next_receipt_pin)
        tail2=self.fix.private/'ec272-second-tail.json'
        tail2pin=roll.append_segment(checkpoint=str(cp2),checkpoint_sha256=cp2pin,
            segment_receipt=str(third),segment_receipt_sha256=third_pin,
            witness_public_keys=self.witness_keys,closure_sha256=self.closure_pin,
            recovered_root_public_sha256=self.new_root_pin,
            allowed_governance_epochs=self.epochs,output=str(tail2))['segment_sha256']
        return cp2,cp2pin,third,third_pin,tail2,tail2pin

    def test_14_second_signed_checkpoint_extends_sequence_again(self):
        self.prepare()
        cp2,pin2,third,sha3,tail2,tail2pin=self._roll_again()
        gate=self.new_roll_gate(checkpoint=str(cp2),checkpoint_sha256=pin2,
            freshness_chain=str(tail2),freshness_chain_sha256=tail2pin,
            minimum_freshness_sequence=3,
            expected_previous_receipt_sha256=self.next_receipt_pin,
            minimum_checkpoint_number=2)
        result=self.verify(gate).summary()
        self.assertEqual(result['sealed_checkpoint_number'],2)
        self.assertEqual(result['freshness_sequence'],3)

    def test_15_second_checkpoint_cannot_omit_first_signed_ancestor(self):
        self.prepare()
        cp2,pin2,third,sha3,tail2,tail2pin=self._roll_again()
        self.cp_file.unlink()
        with self.assertRaises(Exception):
            self.verify(self.new_roll_gate(checkpoint=str(cp2),
                checkpoint_sha256=pin2,freshness_chain=str(tail2),
                freshness_chain_sha256=tail2pin,minimum_freshness_sequence=3,
                expected_previous_receipt_sha256=self.next_receipt_pin,
                minimum_checkpoint_number=2))

    def test_16_sealed_manifest_change_even_repin_cannot_defeat_checkpoint(self):
        self.prepare()
        bogus=self.fix.private/'forged-sealed-config.json'
        rows=json.loads(self.fresh_chain.read_bytes())
        rows['entries'][0]['receipt_sha256']='1'*64
        prov._new(str(bogus),prov._canonical(rows))
        cert=json.loads(self.cp_file.read_bytes())
        cert['segment_path']=str(bogus)
        cert['segment_sha256']=prov._digest(bogus.read_bytes())
        fake=self.fix.private/'re-pinned-forged-checkpoint.json'
        prov._new(str(fake),prov._canonical(cert))
        with self.assertRaises(rec.RecoveryError):
            self.new_roll_gate(checkpoint=str(fake),
                checkpoint_sha256=prov._digest(fake.read_bytes()))

    def test_17_sealed_segment_attestation_can_be_fully_rechecked_offline(self):
        self.prepare()
        self.assertEqual(roll._proposed(segment=str(self.fresh_chain),
            segment_sha256=self.fresh_chain_pin,checkpoint=None,
            checkpoint_sha256=None,keys=fresh._witness_keys(self.witness_keys),
            closure_sha256=self.closure_pin,root_sha256=self.new_root_pin,
            allowed_epochs=self.epochs)[1]['sequence'],1)

    def test_18_no_overwriting_existing_checkpoint_output(self):
        self.prepare()
        original_content=self.cp_file.read_bytes()
        with self.assertRaises(rec.RecoveryError):
            roll.prepare_checkpoint(**self._context(),segment=str(self.fresh_chain),
                segment_sha256=self.fresh_chain_pin,output=str(self.cp_file))
        self.assertEqual(self.cp_file.read_bytes(),original_content)

    def test_19_unsigned_checkpoint_cannot_be_used_for_segment_append(self):
        self.prepare()
        unsigned=self.fix.private/'unsigned-cp.json'
        doc=json.loads(self.cp_file.read_bytes())
        doc.pop('approvals')
        prov._new(str(unsigned),prov._canonical(doc))
        with self.assertRaisesRegex(roll.RolloverError,'EC272_CHECKPOINT_TWO_SIGNATURES_REQUIRED'):
            roll.append_segment(checkpoint=str(unsigned),
                checkpoint_sha256=prov._digest(unsigned.read_bytes()),
                segment_receipt=str(self.next_receipt),
                segment_receipt_sha256=self.next_receipt_pin,
                witness_public_keys=self.witness_keys,
                closure_sha256=self.closure_pin,
                recovered_root_public_sha256=self.new_root_pin,
                allowed_governance_epochs=self.epochs,
                output=str(self.fix.private/'unsigned-output.json'))


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(RolloverTests)
    outcome=unittest.TextTestRunner(verbosity=2).run(suite)
