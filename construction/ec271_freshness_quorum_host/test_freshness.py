#!/usr/bin/env python3
"""EC271 real nonroot Git + Ed25519 quorum & signed chain functional tests.

All witnesses are simulated locally; no remote UTC/escrow or independent humans.
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
from ec253_lease_host import broker as lease
from ec263_offline_anchor_host import checkpoint as cp
from ec266_source_provenance_host import provenance as prov
from ec267_governed_source_host import governance as gov
from ec270_recovery_closure_host.test_closure import RatifiedRecoveryTests as previous
from ec271_freshness_quorum_host import freshness as fresh
from ec271_freshness_quorum_host import serve as service


@unittest.skipUnless(os.name=='posix' and os.geteuid()!=0 and
                     Path('/usr/bin/git').is_file() and cp.Ed25519PrivateKey is not None,
                     'nonroot Linux Git Ed25519 required')
class FreshnessTests(unittest.TestCase):
    setUp = previous.setUp
    kill_host = previous.kill_host
    _prepare = previous._prepare
    remote = previous.remote
    begin_request = previous.begin_request
    prepare_base = previous.prepare_base
    prepare_ec266 = previous.prepare_ec266
    issue = previous.issue
    write_gate = previous.write_gate
    new_gov = previous.new_gov
    make_handover = previous.make_handover
    _kwargs = previous._kwargs
    renew_policy = previous.renew_policy
    create_chain = previous.create_chain
    material = previous.material
    sign_recovery = previous.sign_recovery
    sign_closure = previous.sign_closure
    closure_material = previous.closure_material

    def historic(self):
        return {**self.closure_material(),
                'closure_certificate':str(self.closure_cert),
                'closure_certificate_sha256':self.closure_pin}

    def freshness_options(self, **changes):
        opts = dict(historic=self.historic(),
            governance_policy=self.args.governance_policy,
            governance_policy_sha256=self.args.governance_policy_sha256,
            witness_public_keys=self.witness_keys,
            continuation_chain=self.args.continuation_chain,
            continuation_chain_sha256=self.args.continuation_chain_sha256,
            forbidden_signers=(self.pub_pin,self.custody_pin))
        opts.update(changes)
        return opts

    def prepare(self):
        previous.prepare(self)
        self.witnesses = []
        for n in range(3):
            secret=self.fix.private/f'ec271-clock-{n}.key'
            public=self.fix.private/f'ec271-clock-{n}.public'
            pin=cp.generate_offline_keypair(str(secret),str(public))['signer_public_sha256']
            self.witnesses.append((pin,public,secret))
        self.witnesses.sort()
        self.witness_keys=tuple((str(public),pin) for pin,public,secret in self.witnesses)
        self.receipt_draft=self.fix.private/'ec271-proposal.json'
        self.receipt_first=self.fix.private/'ec271-first.json'
        self.receipt=self.fix.private/'ec271-complete.json'
        self.fresh_chain=self.fix.private/'ec271-chain.json'
        self.sign_seal(sequence=1, draft=self.receipt_draft, first=self.receipt_first,
                       complete=self.receipt, start=self.issued,
                       expiry=self.issued+240)
        self.fresh_chain_pin=fresh.append_chain(receipt=str(self.receipt),
            receipt_sha256=self.receipt_pin,witness_public_keys=self.witness_keys,
            output=str(self.fresh_chain))['chain_sha256']
        self.args.freshness_witness_public=[str(k[1]) for k in self.witnesses]
        self.args.freshness_witness_public_sha256=[k[0] for k in self.witnesses]
        self.args.freshness_chain=str(self.fresh_chain)
        self.args.freshness_chain_sha256=self.fresh_chain_pin
        self.args.minimum_freshness_sequence=1
        self.args.expected_previous_receipt_sha256=fresh.ZERO

    def sign_seal(self, *, sequence, draft, first, complete, start, expiry,
                  previous=None, previous_pin=None):
        opts=self.freshness_options()
        prev={'previous_receipt':str(previous) if previous else None,
              'previous_receipt_sha256':previous_pin}
        result=fresh.prepare_freshness(**opts, **prev, sequence=sequence,
            not_before_unix=start,expires_at_unix=expiry,output=str(draft))
        result=fresh.sign_freshness(**opts,**prev,input_path=str(draft),
            input_sha256=result['proposal_sha256'],
            signing_key=str(self.witnesses[0][2]),
            expected_public_sha256=self.witnesses[0][0],output=str(first))
        result=fresh.sign_freshness(**opts,**prev,input_path=str(first),
            input_sha256=result['signed_freshness_sha256'],
            signing_key=str(self.witnesses[1][2]),
            expected_public_sha256=self.witnesses[1][0],output=str(complete))
        self.receipt_pin=result['signed_freshness_sha256']
        return self.receipt_pin

    def new_gate(self,**changes):
        opts=dict(
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
            freshness_chain=str(self.fresh_chain),
            freshness_chain_sha256=self.fresh_chain_pin,
            freshness_witness_public_keys=self.witness_keys,
            minimum_freshness_sequence=self.args.minimum_freshness_sequence,
            expected_previous_receipt_sha256=self.args.expected_previous_receipt_sha256)
        opts.update(changes)
        return service.QuorumFreshnessGate(**opts)

    def verify(self,gate=None):
        gate=gate or self.new_gate()
        policy,sha=lease._policy(str(self.fix.policy_path))
        gate.startup(policy,sha)
        return gate

    def denied(self,code,gate=None):
        with self.assertRaises(Exception) as ctx:
            self.verify(gate)
        self.assertEqual(getattr(ctx.exception,'code',None),code,
            f'wrong error: {ctx.exception!r}')

    def test_01_two_witnesses_authorize_original_git_and_recovery(self):
        self.prepare()
        report=self.verify().summary()
        self.assertEqual(report['freshness_signed_witnesses'],2)
        self.assertEqual(report['freshness_sequence'],1)
        self.assertEqual(report['role_signatures_valid'],['origin','review','ci'])
        self.assertFalse(report['trusted_external_time_verified'])
        self.assertFalse(report['independent_external_time_or_off_host_escrow_proven'])

    def test_02_one_signature_cannot_authorize_even_with_correct_sha(self):
        self.prepare()
        p=self.fix.private/'one-vote-chain.json'
        firstsha=prov._digest(self.receipt_first.read_bytes())
        doc={'schema':fresh.CHAIN_SCHEMA,'entries':[
            {'receipt_path':str(self.receipt_first),'receipt_sha256':firstsha}]}
        prov._new(str(p),prov._canonical(doc))
        self.denied('EC271_TWO_INDEPENDENT_SIGNATURES_REQUIRED',
            self.new_gate(freshness_chain=str(p),
                freshness_chain_sha256=prov._digest(p.read_bytes())))

    def test_03_modified_vote_and_repin_still_breaks_signature(self):
        self.prepare()
        original=json.loads(self.receipt.read_bytes())
        original['approvals'][0]['signature_ed25519']='f'*128
        corrupted=self.fix.private/'altered-receipt.json'
        prov._new(str(corrupted),prov._canonical(original))
        chain=self.fix.private/'altered-chain.json'
        doc={'schema':fresh.CHAIN_SCHEMA,'entries':[
            {'receipt_path':str(corrupted),
             'receipt_sha256':prov._digest(corrupted.read_bytes())}]}
        prov._new(str(chain),prov._canonical(doc))
        self.denied('EC271_WITNESS_SIGNATURE_INVALID',self.new_gate(
            freshness_chain=str(chain),
            freshness_chain_sha256=prov._digest(chain.read_bytes())))

    def test_04_reject_signature_by_root_or_original_witness(self):
        self.prepare()
        pin=self.new_root_pin
        with self.assertRaisesRegex(fresh.FreshnessError,'EC271_WITNESS_REUSED_OR_FORBIDDEN'):
            fresh.prepare_freshness(**self.freshness_options(
                witness_public_keys=((str(self.new_root_public),pin),
                    *self.witness_keys[1:])),sequence=1,
                not_before_unix=self.issued,expires_at_unix=self.issued+300,
                output=str(self.fix.private/'bad-root.json'))

    def test_05_window_cannot_be_over_15_minutes(self):
        self.prepare()
        with self.assertRaisesRegex(fresh.FreshnessError,
                                    'EC271_WINDOW_TOO_LONG_OR_REVERSED'):
            fresh.prepare_freshness(**self.freshness_options(),sequence=1,
                not_before_unix=self.issued,expires_at_unix=self.issued+901,
                output=str(self.fix.private/'bad-window.json'))

    def test_06_signing_refuses_after_expiration_and_preserves_no_output(self):
        self.prepare()
        output=self.fix.private/'not-produced.json'
        with mock.patch.object(fresh.time,'time',return_value=self.issued+500):
            with self.assertRaisesRegex(fresh.FreshnessError,
                                        'EC271_SIGNING_OUTSIDE_FRESHNESS_WINDOW'):
                fresh.sign_freshness(**self.freshness_options(),
                    input_path=str(self.receipt_draft),
                    input_sha256=prov._digest(self.receipt_draft.read_bytes()),
                    signing_key=str(self.witnesses[0][2]),
                    expected_public_sha256=self.witnesses[0][0],
                    output=str(output))
        self.assertFalse(output.exists())

    def test_07_runtime_expiration_denies_even_if_parent_ec267_valid(self):
        self.prepare()
        with mock.patch.object(gov,'_now',return_value=(self.issued+241.0,600.0)):
            self.denied('EC271_QUORUM_SEAL_EXPIRED_OR_NOT_YET_VALID')

    def test_08_missing_witness_public_file_denies(self):
        self.prepare()
        self.witnesses[2][1].unlink()
        with self.assertRaises(Exception):
            self.verify()

    def test_09_missing_receipt_or_chain_denies(self):
        self.prepare()
        self.receipt.unlink()
        with self.assertRaises(Exception):
            self.verify()

    def test_10_operator_floor_rejects_old_valid_receipt(self):
        self.prepare()
        self.denied('EC271_OPERATOR_SEQUENCE_FLOOR_NOT_MET',
            self.new_gate(minimum_freshness_sequence=2))

    def test_11_wrong_previous_pin_denies_at_start(self):
        self.prepare()
        self.denied('EC271_OPERATOR_PREDECESSOR_PIN_MISMATCH',
            self.new_gate(expected_previous_receipt_sha256='1'*64))

    def test_12_second_seal_chains_and_can_renew_same_epoch(self):
        self.prepare()
        second=self.fix.private/'seal-2.json'
        first_pin=self.receipt_pin
        next_pin=self.sign_seal(sequence=2,previous=self.receipt,
            previous_pin=first_pin,
            draft=self.fix.private/'seal-2-draft.json',
            first=self.fix.private/'seal-2-first.json',complete=second,
            start=json.loads(self.receipt.read_bytes())['approvals'][-1]['observed_at_unix'],
            expiry=self.issued+290)
        chain2=self.fix.private/'chain-2.json'
        next_chain_pin=fresh.append_chain(receipt=str(second),
            receipt_sha256=next_pin,witness_public_keys=self.witness_keys,
            previous_chain=str(self.fresh_chain),
            previous_chain_sha256=self.fresh_chain_pin,
            output=str(chain2))['chain_sha256']
        report=self.verify(self.new_gate(freshness_chain=str(chain2),
            freshness_chain_sha256=next_chain_pin,minimum_freshness_sequence=2,
            expected_previous_receipt_sha256=first_pin)).summary()
        self.assertEqual(report['freshness_chain_length'],2)
        self.assertEqual(report['freshness_sequence'],2)

    def test_13_repin_cannot_skip_first_seal_or_reuse_genesis(self):
        self.prepare()
        second=self.fix.private/'renamed-genesis.json'
        second.write_bytes(self.receipt.read_bytes())
        bad=self.fix.private/'bad-chain.json'
        doc={'schema':fresh.CHAIN_SCHEMA,'entries':[
            {'receipt_path':str(self.receipt), 'receipt_sha256':self.receipt_pin},
            {'receipt_path':str(second), 'receipt_sha256':prov._digest(second.read_bytes())}]}
        prov._new(str(bad),prov._canonical(doc))
        self.denied('EC271_SIGNED_CHAIN_PREDECESSOR_INVALID',self.new_gate(
            freshness_chain=str(bad),freshness_chain_sha256=prov._digest(bad.read_bytes())))

    def test_14_signer_rejects_wrong_input_digest_without_creating_file(self):
        self.prepare()
        output=self.fix.private/'bad-input.json'
        with self.assertRaisesRegex(Exception,'EC271_SIGNER_INPUT_PIN_MISMATCH'):
            fresh.sign_freshness(**self.freshness_options(),
                input_path=str(self.receipt_draft),input_sha256='f'*64,
                signing_key=str(self.witnesses[0][2]),
                expected_public_sha256=self.witnesses[0][0],output=str(output))
        self.assertFalse(output.exists())

    def test_15_no_overwrite_existing_receipt(self):
        self.prepare()
        with self.assertRaisesRegex(Exception,'EC271_NEW_SIGNED_STAGE_REQUIRED'):
            fresh.sign_freshness(**self.freshness_options(),
                input_path=str(self.receipt_draft),
                input_sha256=prov._digest(self.receipt_draft.read_bytes()),
                signing_key=str(self.witnesses[0][2]),
                expected_public_sha256=self.witnesses[0][0],
                output=str(self.receipt_first))

    def test_16_signer_current_governance_must_be_signed_with_root(self):
        self.prepare()
        bogus=self.fix.private/'unsigned-current.json'
        obj=json.loads(self.new_policy.read_bytes())
        obj['signature_ed25519']='f'*128
        prov._new(str(bogus),prov._canonical(obj))
        with self.assertRaisesRegex(Exception,'EC268_GOVERNANCE_ROOT_SIGNATURE_INVALID'):
            fresh.prepare_freshness(**self.freshness_options(
                governance_policy=str(bogus),
                governance_policy_sha256=prov._digest(bogus.read_bytes())),
                sequence=1,not_before_unix=self.issued,
                expires_at_unix=self.issued+300,
                output=str(self.fix.private/'bad-unsigned.json'))

    def test_17_council_or_role_signer_cannot_join_quorum(self):
        self.prepare()
        wrong=((str(self.council[0][1]),self.council[0][0]),*self.witness_keys[1:])
        with self.assertRaisesRegex(Exception,'EC271_WITNESS_REUSED_OR_FORBIDDEN'):
            fresh.prepare_freshness(**self.freshness_options(witness_public_keys=wrong),
                sequence=1,not_before_unix=self.issued,
                expires_at_unix=self.issued+300,
                output=str(self.fix.private/'bad-council.json'))

    def test_18_approval_order_is_part_of_verified_signature(self):
        self.prepare()
        obj=json.loads(self.receipt.read_bytes())
        obj['approvals'].reverse()
        path=self.fix.private/'reversed.json'
        prov._new(str(path),prov._canonical(obj))
        with self.assertRaisesRegex(Exception,'EC271_WITNESSES_DUPLICATE_OUT_OF_ORDER_OR_UNKNOWN'):
            fresh._read_verified(str(path),prov._digest(path.read_bytes()),
                                 fresh._witness_keys(self.witness_keys))

    def test_19_governance_epoch_three_needs_fresh_signed_next_seal(self):
        self.prepare()
        anchor_pin=self.new_pin
        next_policy,next_sha=self.renew_policy(3,self.new_pin)
        chain,chain_pin=self.create_chain(next_policy,next_sha)
        self.args.governance_policy=str(next_policy)
        self.args.governance_policy_sha256=next_sha
        self.args.minimum_governance_epoch=3
        self.args.expected_previous_governance_sha256=anchor_pin
        self.args.continuation_chain=str(chain)
        self.args.continuation_chain_sha256=chain_pin
        self.denied('EC271_FRESHNESS_SEAL_NOT_FOR_CURRENT_GOVERNANCE')
        first_pin=self.receipt_pin
        next_certificate=self.fix.private/'epoch3-seal.json'
        next_pin=self.sign_seal(sequence=2,previous=self.receipt,
            previous_pin=first_pin,
            draft=self.fix.private/'epoch3-draft.json',
            first=self.fix.private/'epoch3-first.json',
            complete=next_certificate,
            start=json.loads(self.receipt.read_bytes())['approvals'][-1]['observed_at_unix'],
            expiry=self.issued+290)
        chain2=self.fix.private/'epoch3-chain.json'
        chain2pin=fresh.append_chain(receipt=str(next_certificate),
            receipt_sha256=next_pin,witness_public_keys=self.witness_keys,
            previous_chain=str(self.fresh_chain),
            previous_chain_sha256=self.fresh_chain_pin,
            output=str(chain2))['chain_sha256']
        result=self.verify(self.new_gate(freshness_chain=str(chain2),
            freshness_chain_sha256=chain2pin,minimum_epoch=3,
            expected_previous_governance_sha256=anchor_pin,
            expected_previous_receipt_sha256=first_pin,
            minimum_freshness_sequence=2)).summary()
        self.assertEqual(result['governance_epoch'],3)
        self.assertEqual(result['freshness_sequence'],2)

    def test_20_revoked_new_witness_cannot_sign_later_governance(self):
        self.prepare()
        retired=self.witnesses[0][0]
        next_policy,next_sha=self.renew_policy(3,self.new_pin,revoked=(retired,))
        chain,chain_pin=self.create_chain(next_policy,next_sha)
        self.args.governance_policy=str(next_policy)
        self.args.governance_policy_sha256=next_sha
        self.args.continuation_chain=str(chain)
        self.args.continuation_chain_sha256=chain_pin
        with self.assertRaisesRegex(fresh.FreshnessError,
                                    'EC271_WITNESS_REUSED_OR_FORBIDDEN'):
            fresh.prepare_freshness(**self.freshness_options(),sequence=2,
                previous_receipt=str(self.receipt),
                previous_receipt_sha256=self.receipt_pin,
                not_before_unix=self.issued,
                expires_at_unix=self.issued+290,
                output=str(self.fix.private/'revoked-quorum.json'))

    def test_21_append_chain_rejects_corrupt_old_prefix_even_if_new_valid(self):
        self.prepare()
        new_draft=self.fix.private/'next-draft.json'
        new_first=self.fix.private/'next-first.json'
        new_seal=self.fix.private/'next-final.json'
        old_pin=self.receipt_pin
        self.sign_seal(sequence=2,previous=self.receipt,previous_pin=old_pin,
            draft=new_draft,first=new_first,complete=new_seal,
            start=json.loads(self.receipt.read_bytes())['approvals'][-1]['observed_at_unix'],
            expiry=self.issued+290)
        bad_prefix=self.fix.private/'bad-prefix.json'
        wrong=self.fix.private/'wrong-certificate.json'
        raw=json.loads(self.receipt.read_bytes())
        raw['approvals'][0]['signature_ed25519']='f'*128
        prov._new(str(wrong),prov._canonical(raw))
        content={'schema':fresh.CHAIN_SCHEMA,'entries':[
            {'receipt_path':str(wrong),'receipt_sha256':prov._digest(wrong.read_bytes())}]}
        prov._new(str(bad_prefix),prov._canonical(content))
        with self.assertRaisesRegex(Exception,'EC271_WITNESS_SIGNATURE_INVALID'):
            fresh.append_chain(receipt=str(new_seal),
                receipt_sha256=self.receipt_pin,witness_public_keys=self.witness_keys,
                previous_chain=str(bad_prefix),
                previous_chain_sha256=prov._digest(bad_prefix.read_bytes()),
                output=str(self.fix.private/'unwritten-chain.json'))
        self.assertFalse((self.fix.private/'unwritten-chain.json').exists())

    def test_22_signed_future_time_is_not_a_trusted_clock(self):
        self.prepare()
        future=self.fix.private/'future-receipt.json'
        prev=self.fix.private/'future-first.json'
        draft=self.fix.private/'future-draft.json'
        with mock.patch.object(fresh.time,'time',return_value=self.issued+90):
            result=fresh.prepare_freshness(**self.freshness_options(),
                sequence=1,not_before_unix=self.issued,
                expires_at_unix=self.issued+200,output=str(draft))
            first=fresh.sign_freshness(**self.freshness_options(),
                input_path=str(draft),input_sha256=result['proposal_sha256'],
                signing_key=str(self.witnesses[0][2]),
                expected_public_sha256=self.witnesses[0][0],output=str(prev))
            second=fresh.sign_freshness(**self.freshness_options(),
                input_path=str(prev),input_sha256=first['signed_freshness_sha256'],
                signing_key=str(self.witnesses[1][2]),
                expected_public_sha256=self.witnesses[1][0],output=str(future))
        ch=self.fix.private/'future-chain.json'
        pin=fresh.append_chain(receipt=str(future),
            receipt_sha256=second['signed_freshness_sha256'],
            witness_public_keys=self.witness_keys,output=str(ch))['chain_sha256']
        with mock.patch.object(gov,'_now',return_value=(self.issued+5.0,100.0)):
            self.denied('EC271_WITNESS_TIME_UNREASONABLY_FUTURE',
                self.new_gate(freshness_chain=str(ch),freshness_chain_sha256=pin))



if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(FreshnessTests)
    outcome=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
