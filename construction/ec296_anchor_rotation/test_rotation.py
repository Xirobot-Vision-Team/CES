#!/usr/bin/env python3
"""EC296 actual original EC294/EC227 signed audit fixtures; offline four-sign seal.

No external Provider/Inbox, no actual HSM, and no real off-machine retention.
All original historical signed receipts and HMAC journal claims are checked.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec288_delivery_send_host import protocol as orig
from ec295_delivery_anchor import anchor as a
from ec295_delivery_anchor import operator as previous
from ec295_delivery_anchor.test_anchor import EC295AnchorCases
from . import rotation as r, operator as op

PROJECT = Path(__file__).resolve().parents[2]


class EC296RotationCases(unittest.TestCase):
    def setUp(self):
        self.base = EC295AnchorCases('test_02_complete_two_witness_seal_and_external_tip_verification')
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        evidence, _g, _r = self.base.initialize()
        self.old_policy = self.base.policy
        self.old_policy_sha = self.base.policysha
        self.old_cp = self.base.checkpoint(evidence)
        self.old_tip = a.sha(self.old_cp)
        next_evidence, _g, _r = self.base.receipt('record',
                         self.old_cp['claim']['audit_head_hmac_sha256'])
        self.new_keys = {role: Ed25519PrivateKey.generate() for role in a.DOMAINS}
        self.new_pubs = {role: orig.public_hex(key)
                         for role,key in self.new_keys.items()}
        self.new_policy_path = str(self.base.parent.root/'296-next-policy.json')
        res = previous.create_policy(
            original_policy_file=self.base.parent.policyfile,
            original_policy_sha256=self.base.parent.policysha,
            operation_id=self.old_policy['operation_id'],
            job_sha256=self.old_policy['job_sha256'],
            keeper_public_hex=self.new_pubs['keeper'],
            witness_public_hex=self.new_pubs['witness'],
            out=self.new_policy_path)
        self.new_policy_sha = res['policy_sha256']
        self.new_policy = a.load_policy(self.new_policy_path, self.new_policy_sha)
        prep = a.prepared_from_evidence(next_evidence, self.new_policy,
                                        self.new_policy_sha, None)
        self.new_cp = {
            'schema': a.CHECKPOINT_SCHEMA,
            'claim': prep['claim'], 'evidence': prep['evidence'],
            **{role+'_signature_ed25519': a.sign(role, prep['claim'], key)
               for role,key in self.new_keys.items()},
        }
        self.new_tip = a.sha(self.new_cp)
        self.inputs = dict(
            old_policy_file=self.base.policyfile,
            old_policy_sha256=self.old_policy_sha,
            old_checkpoint_files=[self.f('old-checkpoint',self.old_cp)],
            expected_old_tip=self.old_tip,
            new_policy_file=self.new_policy_path,
            new_policy_sha256=self.new_policy_sha,
            new_checkpoint_files=[self.f('new-checkpoint',self.new_cp)],
            proposed_new_tip=self.new_tip,
        )
        self.keyfiles = {}
        for epoch, keys in (('old',self.base.keys),('new',self.new_keys)):
            for role,key in keys.items():
                self.keyfiles[epoch+'_'+role] = self.base.parent.base.write(
                    '296-'+epoch+'-'+role+'.key',key.private_bytes_raw())

    def f(self, name: str, doc: dict) -> str:
        file = str(self.base.parent.root/('296-'+name+'.json'))
        previous.store(file, doc, a.MAX_CHECKPOINT_BYTES)
        return file

    def prepare_and_bridge(self) -> tuple[str,str,dict]:
        pre_path = str(self.base.parent.root/'296-prepared.json')
        result = op.prepare(out=pre_path,**self.inputs)
        self.assertTrue(result['four_independent_offline_votes_still_required'])
        vote_files = {}
        for role in r.ROLES:
            dest = str(self.base.parent.root/('296-vote-'+role+'.json'))
            op.offline_vote(role=role,prepared_file=pre_path,
                    private_key_file=self.keyfiles[role],out=dest,**self.inputs)
            vote_files[role] = dest
        dest = str(self.base.parent.root/'296-bridge.json')
        res = op.assemble(prepared_file=pre_path,vote_files=vote_files,
                          out=dest,**self.inputs)
        return pre_path,dest,res

    def test_01_real_audit_two_epochs_each_recheck_historical_ec294_and_seals(self):
        old,new,claim = op._data(**self.inputs)
        self.assertEqual(claim['old_last_event_count'],2)
        self.assertEqual(claim['new_first_event_count'],4)
        self.assertEqual(claim['old_checkpoint_count'],1)
        self.assertEqual(claim['new_checkpoint_count'],1)
        self.assertEqual(self.base.parent.parent.statusport.lookups,2)

    def test_02_complete_4_party_ceremony_and_external_pins(self):
        _,bridge,created = self.prepare_and_bridge()
        verified = op.verify(bridge_file=bridge,
             expected_rotation_sha256=created['rotation_bridge_sha256'],
             expected_new_tip=self.new_tip,**self.inputs)
        self.assertEqual(verified['status'],'verified_offline_two_epoch_rotation')
        self.assertTrue(verified['all_four_distinct_rotation_role_signatures_verified'])
        self.assertFalse(verified['production_delivery_proven'])
        self.assertFalse(verified['independent_off_host_latest_pin_and_real_people_proven'])
        self.assertEqual(self.base.parent.parent.statusport.lookups,2)

    def test_03_missing_old_external_pin_rejected(self):
        bad = {**self.inputs,'expected_old_tip':a.GENESIS}
        with self.assertRaisesRegex(a.AnchorError,'EXTERNALLY_RETAINED_OLD_TIP'):
            op._data(**bad)

    def test_04_wrong_old_external_tip_rejected(self):
        bad={**self.inputs,'expected_old_tip':'f'*64}
        with self.assertRaisesRegex(a.AnchorError,'TIP_MISMATCH'):
            op._data(**bad)

    def test_05_wrong_proposed_new_tip_rejected(self):
        bad={**self.inputs,'proposed_new_tip':'f'*64}
        with self.assertRaisesRegex(a.AnchorError,'TIP_MISMATCH'):
            op._data(**bad)

    def test_06_external_new_tip_explicit_at_final_verification(self):
        _,bridge,created=self.prepare_and_bridge()
        with self.assertRaisesRegex(a.AnchorError,'EXTERNALLY_PINNED_NEW_TIP'):
            op.verify(bridge_file=bridge,
                      expected_rotation_sha256=created['rotation_bridge_sha256'],
                      expected_new_tip=a.GENESIS,**self.inputs)

    def test_07_external_bridge_pin_detects_truncated_or_replaced_bridge(self):
        _,bridge,created=self.prepare_and_bridge()
        with self.assertRaisesRegex(a.AnchorError,'PIN_MISMATCH'):
            op.verify(bridge_file=bridge,expected_rotation_sha256='f'*64,
                      expected_new_tip=self.new_tip,**self.inputs)
        with self.assertRaisesRegex(a.AnchorError,'BRIDGE_DIGEST_REQUIRED'):
            op.verify(bridge_file=bridge,expected_rotation_sha256=a.GENESIS,
                      expected_new_tip=self.new_tip,**self.inputs)

    def test_08_key_reuse_across_old_and_new_epochs_denied(self):
        altered=copy.deepcopy(self.new_policy)
        altered['witness_public_hex']=self.old_policy['keeper_public_hex']
        altered_path=self.f('reused-policy',altered)
        import hashlib
        pin=hashlib.sha256(Path(altered_path).read_bytes()).hexdigest()
        with self.assertRaisesRegex(a.AnchorError,'ALL_FOUR'):
            op._data(**{**self.inputs,'new_policy_file':altered_path,
                        'new_policy_sha256':pin})

    def test_09_original_ec294_job_or_host_identity_change_denied(self):
        import hashlib
        altered=copy.deepcopy(self.new_policy)
        altered['job_sha256']='1'*64
        path=self.f('job-policy',altered)
        pin=hashlib.sha256(Path(path).read_bytes()).hexdigest()
        with self.assertRaisesRegex(a.AnchorError,'IDENTITY_OR_CODE_CHANGED'):
            op._data(**{**self.inputs,'new_policy_file':path,
                        'new_policy_sha256':pin})

    def test_10_old_checkpoint_original_ec294_signature_tamper_denied(self):
        cp=copy.deepcopy(self.old_cp)
        cp['evidence']['response']['signed_reply']['signature_ed25519']='f'*128
        file=self.f('fake-old',cp)
        with self.assertRaises(a.AnchorError):
            op._data(**{**self.inputs,'old_checkpoint_files':[file],
                        'expected_old_tip':a.sha(cp)})

    def test_11_new_checkpoint_original_ec295_signature_tamper_denied(self):
        cp=copy.deepcopy(self.new_cp)
        cp['witness_signature_ed25519']=cp['keeper_signature_ed25519']
        file=self.f('fake-new',cp)
        with self.assertRaisesRegex(a.AnchorError,'SIGNATURE_INVALID'):
            op._data(**{**self.inputs,'new_checkpoint_files':[file],
                        'proposed_new_tip':a.sha(cp)})

    def test_12_unadvanced_first_new_original_audit_evidence_denied(self):
        # The old signed EC294 receipt is still valid but must not be
        # repackaged under a new EC295 key as proof of another audit event.
        prepared=a.prepared_from_evidence(self.old_cp['evidence'],
                                           self.new_policy,self.new_policy_sha,None)
        cp={'schema':a.CHECKPOINT_SCHEMA,'claim':prepared['claim'],
            'evidence':prepared['evidence'],
            **{role+'_signature_ed25519':a.sign(role,prepared['claim'],key)
               for role,key in self.new_keys.items()}}
        path=self.f('replayed-new',cp)
        with self.assertRaisesRegex(a.AnchorError,'NEW_EPOCH_MUST_FOLLOW'):
            op._data(**{**self.inputs,'new_checkpoint_files':[path],
                        'proposed_new_tip':a.sha(cp)})

    def test_13_offline_signer_must_hold_exact_epoch_key(self):
        pre=str(self.base.parent.root/'296-prepared.json')
        op.prepare(out=pre,**self.inputs)
        with self.assertRaisesRegex(a.AnchorError,'PRIVATE_KEY_NOT_PINNED'):
            op.offline_vote(role='new_keeper',prepared_file=pre,
                private_key_file=self.keyfiles['old_keeper'],
                out=str(self.base.parent.root/'296-wrong-signer.json'),
                **self.inputs)

    def test_14_signed_proposal_cannot_be_changed_before_offline_vote(self):
        pre=str(self.base.parent.root/'296-prepared.json')
        op.prepare(out=pre,**self.inputs)
        doc=json.loads(Path(pre).read_text())
        doc['claim']['new_last_event_count']=42
        forged=self.f('proposal-tamper',doc)
        with self.assertRaisesRegex(a.AnchorError,'PREPARED_NOT_EXACT'):
            op.offline_vote(role='old_keeper',prepared_file=forged,
                private_key_file=self.keyfiles['old_keeper'],
                out=str(self.base.parent.root/'296-forged-vote.json'),
                **self.inputs)

    def test_15_four_vote_assembly_rejects_replaced_or_missing_role(self):
        pre=str(self.base.parent.root/'296-prepared.json')
        op.prepare(out=pre,**self.inputs)
        votes={}
        for role in r.ROLES:
            dest=str(self.base.parent.root/('296-vote-'+role+'.json'))
            op.offline_vote(role=role,prepared_file=pre,
                private_key_file=self.keyfiles[role],out=dest,**self.inputs)
            votes[role]=dest
        with self.assertRaisesRegex(a.AnchorError,'FOUR_VOTE_FILES_REQUIRED'):
            op.assemble(prepared_file=pre,vote_files={k:v for k,v in votes.items()
                if k!='new_witness'},out=str(self.base.parent.root/'296-incomplete.json'),
                **self.inputs)
        votes['new_witness']=votes['old_witness']
        with self.assertRaisesRegex(a.AnchorError,'VOTE_NOT_FOR'):
            op.assemble(prepared_file=pre,vote_files=votes,
                out=str(self.base.parent.root/'296-mixed.json'),**self.inputs)

    def test_16_bridge_modification_not_authenticated_even_with_new_tip(self):
        _,bridge,_ = self.prepare_and_bridge()
        doc=json.loads(Path(bridge).read_text())
        doc['new_witness_signature_ed25519']='f'*128
        tampered=self.f('wrong-bridge',doc)
        with self.assertRaisesRegex(a.AnchorError,'FOUR_PARTY_SIGNATURE_INVALID'):
            op.verify(bridge_file=tampered,
                expected_rotation_sha256=a.sha(doc),
                expected_new_tip=self.new_tip,**self.inputs)

    def test_17_output_is_owner_only_and_exclusive(self):
        pre=str(self.base.parent.root/'296-prepared.json')
        op.prepare(out=pre,**self.inputs)
        self.assertEqual(os.stat(pre).st_mode & 0o077,0)
        with self.assertRaisesRegex(a.AnchorError,'EXCLUSIVE_OUTPUT'):
            op.prepare(out=pre,**self.inputs)

    def test_18_script_cli_round_trip_and_no_external_custody_claim(self):
        _,bridge,created=self.prepare_and_bridge()
        args=['--old-policy-file',self.inputs['old_policy_file'],
              '--old-policy-sha256',self.old_policy_sha,
              '--new-policy-file',self.new_policy_path,
              '--new-policy-sha256',self.new_policy_sha,
              '--expected-old-tip',self.old_tip,
              '--proposed-new-tip',self.new_tip,
              '--old-checkpoint-file',self.inputs['old_checkpoint_files'][0],
              '--new-checkpoint-file',self.inputs['new_checkpoint_files'][0],
              '--bridge-file',bridge,
              '--expected-rotation-sha256',created['rotation_bridge_sha256'],
              '--expected-new-tip',self.new_tip]
        proc=subprocess.run([sys.executable,'-I','-B',
              str(PROJECT/'scripts'/'ces_anchor_rotate.py'),'verify-rotation',*args],
              capture_output=True,text=True,timeout=15)
        self.assertEqual(proc.returncode,0,proc.stdout+'\n'+proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['status'],
                         'verified_offline_two_epoch_rotation')
        console=subprocess.run([sys.executable,'-I','-B',
              str(PROJECT/'scripts'/'ces_next.py'), 'audit-rotate',
              'DeliveryAudit','VerifyRotation',
              *[v for i,v in enumerate(args) if i not in (
                  args.index('--proposed-new-tip'),
                  args.index('--proposed-new-tip')+1)]],
              capture_output=True,text=True,timeout=20)
        self.assertEqual(console.returncode,0,console.stdout+'\n'+console.stderr)
        self.assertFalse(json.loads(console.stdout)['production_delivery_proven'])
        self.assertEqual(self.base.parent.parent.statusport.lookups,2)

    def test_19_console_rejects_broadened_modes(self):
        proc=subprocess.run([sys.executable,'-I','-B',
              str(PROJECT/'scripts'/'ces_next.py'),'audit-rotate',
              'DeliverySend','Send',
              '--old-policy-file',self.inputs['old_policy_file'],
              '--old-policy-sha256',self.old_policy_sha,
              '--new-policy-file',self.new_policy_path,
              '--new-policy-sha256',self.new_policy_sha,
              '--old-checkpoint-file',self.inputs['old_checkpoint_files'][0],
              '--new-checkpoint-file',self.inputs['new_checkpoint_files'][0],
              '--expected-old-tip',self.old_tip,
              '--expected-new-tip',self.new_tip,
              '--bridge-file','/tmp/does-not-exist',
              '--expected-rotation-sha256','f'*64],
              capture_output=True,text=True,timeout=10)
        self.assertEqual(proc.returncode,3,proc.stdout+'\n'+proc.stderr)
        self.assertIn('EC296_ONLY_EXPLICIT',proc.stdout)

    def test_20_unpinned_new_policy_file_drift_fails_closed(self):
        altered=copy.deepcopy(self.new_policy)
        altered['operation_id']='f'*64
        path=self.f('untrusted-policy',altered)
        with self.assertRaisesRegex(a.AnchorError,'RAW_BYTES_CHANGED'):
            op._data(**{**self.inputs,'new_policy_file':path})

    def test_21_too_many_checkpoints_does_not_allocate_unbounded_history(self):
        bad={**self.inputs,'new_checkpoint_files':
             self.inputs['new_checkpoint_files']*65}
        with self.assertRaisesRegex(a.AnchorError,'ORDERED_EPOCH_CHAINS_REQUIRED'):
            op._data(**bad)

    def readback_handover(self):
        """Retire after actual second Record; rotate via a fresh local-only readback."""
        second_evidence = self.new_cp['evidence']
        old_second_prepared = a.prepared_from_evidence(
            second_evidence, self.old_policy, self.old_policy_sha, self.old_cp)
        old_second = {
            'schema': a.CHECKPOINT_SCHEMA,
            'claim': old_second_prepared['claim'],
            'evidence': old_second_prepared['evidence'],
            **{role+'_signature_ed25519':a.sign(
                role,old_second_prepared['claim'],key)
               for role,key in self.base.keys.items()},
        }
        self.old_tip = a.sha(old_second)
        old_second_path = self.f('old-second-checkpoint',old_second)
        self.inputs['old_checkpoint_files'].append(old_second_path)
        self.inputs['expected_old_tip'] = self.old_tip
        # Original host acknowledgement uses integer seconds. It is not
        # cryptographically valid to 'adjust' or forge the signed timestamps.
        time.sleep(1.08)
        observed, _grant, _read = self.base.receipt(
            'readback', old_second['claim']['audit_head_hmac_sha256'])
        new_prepared = a.prepared_from_evidence(
            observed, self.new_policy, self.new_policy_sha, None)
        self.new_cp = {
            'schema': a.CHECKPOINT_SCHEMA,
            'claim': new_prepared['claim'],
            'evidence': new_prepared['evidence'],
            **{role+'_signature_ed25519':a.sign(
                role,new_prepared['claim'],key)
               for role,key in self.new_keys.items()},
        }
        self.new_tip = a.sha(self.new_cp)
        self.inputs['new_checkpoint_files'] = [
            self.f('new-readback-checkpoint', self.new_cp)]
        self.inputs['proposed_new_tip'] = self.new_tip
        self.inputs['minimum_fresh_readback_unix'] = (
            old_second['claim']['ec294_reply_issued_at_unix']+1)
        return old_second

    def test_22_missing_final_bridge_signature_is_rejected(self):
        _,bridge,_=self.prepare_and_bridge()
        modified=json.loads(Path(bridge).read_text())
        del modified['old_keeper_signature_ed25519']
        path=self.f('bridge-minus-vote',modified)
        with self.assertRaisesRegex(a.AnchorError,'BRIDGE_FIELDS_INVALID'):
            op.verify(bridge_file=path,expected_rotation_sha256=a.sha(modified),
                      expected_new_tip=self.new_tip,**self.inputs)


    def test_23_true_local_only_readback_renews_keys_without_more_status_lookups(self):
        prior = self.readback_handover()
        self.assertEqual(self.base.parent.parent.statusport.lookups,2)
        _,bridge,created=self.prepare_and_bridge()
        result=op.verify(bridge_file=bridge,
             expected_rotation_sha256=created['rotation_bridge_sha256'],
             expected_new_tip=self.new_tip, **self.inputs)
        self.assertEqual(result['handover_observation_mode'],'readback')
        self.assertEqual(result['old_last_event_count'],
                         result['new_first_event_count'])
        self.assertEqual(result['old_last_event_count'],4)
        self.assertEqual(prior['claim']['audit_head_hmac_sha256'],
                         self.new_cp['claim']['audit_head_hmac_sha256'])
        self.assertEqual(self.base.parent.parent.statusport.lookups,2)

    def test_24_readback_requires_independently_recorded_freshness_threshold(self):
        self.readback_handover()
        bad={**self.inputs,'minimum_fresh_readback_unix':None}
        with self.assertRaisesRegex(a.AnchorError,'INDEPENDENT_FRESH_READBACK_TIME'):
            op._data(**bad)
        bad['minimum_fresh_readback_unix']=self.inputs[
            'minimum_fresh_readback_unix']+100
        with self.assertRaisesRegex(a.AnchorError,'NEW_EPOCH_MUST_FOLLOW'):
            op._data(**bad)

    def test_25_record_handover_rejects_readback_freshness_claim(self):
        bad={**self.inputs,'minimum_fresh_readback_unix':946684800}
        with self.assertRaisesRegex(a.AnchorError,'RECORD_HANDOVER_MUST_NOT'):
            op._data(**bad)

    def test_26_cli_offline_signing_actually_accepts_exact_role(self):
        pre=str(self.base.parent.root/'296-prepared.json')
        op.prepare(out=pre,**self.inputs)
        out=str(self.base.parent.root/'296-cli-signed-vote.json')
        args=['sign-old-keeper-offline',
              '--old-policy-file', self.inputs['old_policy_file'],
              '--old-policy-sha256', self.old_policy_sha,
              '--new-policy-file', self.new_policy_path,
              '--new-policy-sha256', self.new_policy_sha,
              '--old-checkpoint-file',self.inputs['old_checkpoint_files'][0],
              '--new-checkpoint-file',self.inputs['new_checkpoint_files'][0],
              '--expected-old-tip', self.old_tip,
              '--proposed-new-tip', self.new_tip,
              '--prepared-file',pre,
              '--private-key-file',str(self.keyfiles['old_keeper']),
              '--out',out]
        cmd=subprocess.run([sys.executable,'-I','-B',
                str(PROJECT/'scripts'/'ces_anchor_rotate.py'),*args],
                capture_output=True,text=True,timeout=15)
        self.assertEqual(cmd.returncode,0,cmd.stdout+'\n'+cmd.stderr)
        vote=json.loads(Path(out).read_text())
        self.assertEqual(vote['role'],'old_keeper')
        self.assertEqual(vote['schema'],r.VOTE_SCHEMA)

    def test_27_console_offline_readback_rotation_requires_same_minimum_timestamp(self):
        self.readback_handover()
        _,bridge,created=self.prepare_and_bridge()
        oldpoints = self.inputs['old_checkpoint_files']
        args=['audit-rotate','DeliveryAudit','VerifyRotation',
              '--old-policy-file',self.inputs['old_policy_file'],
              '--old-policy-sha256',self.old_policy_sha,
              '--new-policy-file',self.new_policy_path,
              '--new-policy-sha256',self.new_policy_sha,
              '--expected-old-tip',self.old_tip,
              '--expected-new-tip',self.new_tip,
              '--bridge-file',bridge,
              '--expected-rotation-sha256',created['rotation_bridge_sha256'],
              '--minimum-fresh-readback-unix',
              str(self.inputs['minimum_fresh_readback_unix'])]
        for path in oldpoints:
            args.extend(['--old-checkpoint-file',path])
        args.extend(['--new-checkpoint-file',self.inputs['new_checkpoint_files'][0]])
        cmd=subprocess.run([sys.executable,'-I','-B',
                str(PROJECT/'scripts'/'ces_next.py'),*args],
                capture_output=True,text=True,timeout=20)
        self.assertEqual(cmd.returncode,0,cmd.stdout+'\n'+cmd.stderr)
        self.assertEqual(json.loads(cmd.stdout)['handover_observation_mode'],'readback')



if __name__=='__main__':
    unittest.main()
