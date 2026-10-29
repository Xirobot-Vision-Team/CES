#!/usr/bin/env python3
"""EC344 focused real Ed25519 visibility/custody gap tests, no provider operations.

Inherited EC317/318 deep historical fixture is MOCK; any success here is only
bounded offline code evidence and never final production acceptance.
"""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

from delivery_anchor import anchor
from conflict_hold import test_hold as old_test
from hold_receipts import test_timeline as old_fixture
from . import visibility as v

ROOT=Path(__file__).resolve().parents[2]


class ReceiverVisibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        old_fixture.HoldReceiptTimelineTests.setUpClass()
        cls.f=old_fixture.HoldReceiptTimelineTests
        cls.work=tempfile.TemporaryDirectory(dir=str(cls.f.w))
        cls.root=Path(cls.work.name)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()
        old_fixture.HoldReceiptTimelineTests.tearDownClass()

    def setUp(self):
        w=tempfile.TemporaryDirectory(dir=str(self.root))
        self.addCleanup(w.cleanup)
        self.w=Path(w.name)
        f=self.f
        self.records=[
            {'item_id':'base','slot_id':'case_344',
             'snapshot_file':f.base_path,'expected_snapshot_sha256':f.base_sha,
             'ack_set_file':f.base_ack_path,'expected_ack_set_sha256':f.base_ack_sha},
            *[{'item_id':name,'slot_id':'case_344',
             'snapshot_file':obj['snapshot_file'],
             'expected_snapshot_sha256':obj['snapshot_sha'],
             'ack_set_file':obj['ack_set_file'],
             'expected_ack_set_sha256':obj['ack_set_sha']}
              for name,obj in (('rev',f.rev),('withdraw',f.withdraw))],
            {'item_id':'unpresented','slot_id':'externally_announced',
             'snapshot_file':str(self.w/'not-furnished-snapshot.json'),
             'expected_snapshot_sha256':'a1'*32,
             'ack_set_file':str(self.w/'not-furnished-ack-set.json'),
             'expected_ack_set_sha256':'b1'*32}]
        self.configure()

    def configure(self,receivers=None,records=None):
        f=self.f
        self.directory_file=str(self.w/f'directory-{len(list(self.w.glob("directory-*")))}.json')
        result=v.assemble_directory(out=self.directory_file,
            roster_file=f.rfile,expected_roster_sha256=f.rsha,
            round_nonce_sha256='e4'*32,
            receivers=receivers if receivers is not None else f.actors[2:])
        self.assertEqual(result['exit_code'],2)
        self.directory_sha=old_test.sha(self.directory_file)
        self.checkpoint_file=str(self.w/f'checkpoint-{len(list(self.w.glob("checkpoint-*")))}.json')
        result=v.assemble_checkpoint(out=self.checkpoint_file,
            roster_file=f.rfile,expected_roster_sha256=f.rsha,
            directory_file=self.directory_file,
            expected_directory_sha256=self.directory_sha,
            announcements=records if records is not None else self.records)
        self.assertEqual(result['exit_code'],2)
        self.checkpoint_sha=old_test.sha(self.checkpoint_file)
        self.views=[];self.view_shas=[]
        self.view_counter=0

    def sign(self,idx,ids,nonce=None,time='2026-10-25T13:16:00Z'):
        f=self.f
        path=str(self.w/f'view-{self.view_counter}.json')
        self.view_counter+=1
        result=v.sign_view(out=path,private_key_file=f.key_paths[idx+2],
            roster_file=f.rfile,expected_roster_sha256=f.rsha,
            directory_file=self.directory_file,expected_directory_sha256=self.directory_sha,
            checkpoint_file=self.checkpoint_file,expected_checkpoint_sha256=self.checkpoint_sha,
            observed_item_ids=ids,view_nonce_sha256=nonce or
                (f'{self.view_counter+32:02x}'*32),reported_utc=time)
        self.assertEqual(result['exit_code'],2)
        self.views.append(path);self.view_shas.append(old_test.sha(path))
        return path

    def parameters(self,presented=None):
        f=self.f
        return {**f.vargs,'head_snapshot_file':f.base_path,
            'expected_head_snapshot_sha256':f.base_sha,
            'head_ack_set_file':f.base_ack_path,
            'expected_head_ack_set_sha256':f.base_ack_sha,
            'timeline_evaluation_utc':'2026-10-25T13:20:00Z',
            'directory_file':self.directory_file,
            'expected_directory_sha256':self.directory_sha,
            'checkpoint_file':self.checkpoint_file,
            'expected_checkpoint_sha256':self.checkpoint_sha,
            'anchor_item_id':'base','view_files':self.views,
            'view_shas':self.view_shas,
            'presented_item_ids':presented if presented is not None else ['base']}

    def audit(self,presented=None):
        return v.audit_views(**self.parameters(presented))

    def test_a_real_signed_forks_seen_without_winner_or_missing_claim(self):
        self.sign(0,['base','rev','unpresented'])
        self.sign(1,['base','withdraw'])
        out=self.audit(['base','rev','withdraw'])
        self.assertEqual(out['status'],'verified_signed_same_parent_forks_unresolved')
        self.assertEqual(out['verified_signed_same_parent_sibling_item_pairs'],
                         [['rev','withdraw']])
        self.assertEqual(out['claimed_visible_but_not_presented_item_ids'],
                         ['unpresented'])
        self.assertFalse(out['signed_same_parent_fork_or_majority_selects_winner'])
        self.assertFalse(out['unpresented_original_proven_missing_from_real_world'])
        self.assertEqual(out['exit_code'],2)

    def test_b_independent_directory_disagrees_without_granting_new_authority(self):
        self.configure(receivers=[self.f.actors[2]])
        self.sign(0,['base'])
        self.sign(1,['base'])
        out=self.audit()
        self.assertEqual(out['status'],
                         'independent_receiver_directory_mismatch_unresolved')
        self.assertEqual(out['missing_in_independent_directory_receiver_ids'],
                         [self.f.actors[3]['signer_id']])
        self.assertEqual(out['distinct_receivers_with_signed_views'],2)

    def test_c_signed_visibility_disagreement_is_not_branch_confirmation(self):
        self.sign(0,['base','rev'])
        self.sign(1,['base'])
        out=self.audit()
        self.assertEqual(out['status'],'signed_cross_receiver_visibility_diff_unresolved')
        self.assertEqual(out['verified_signed_same_parent_sibling_item_pairs'],[])
        self.assertEqual(out['claimed_visible_but_not_presented_item_ids'],['rev'])

    def test_d_both_claim_unpresented_original_never_call_it_world_absence(self):
        self.sign(0,['base','unpresented'])
        self.sign(1,['base','unpresented'])
        out=self.audit()
        self.assertEqual(out['status'],'signed_claimed_originals_not_presented_unresolved')
        self.assertFalse(out['unpresented_original_proven_missing_from_real_world'])
        self.assertEqual(out['claimed_visible_but_not_presented_item_ids'],['unpresented'])

    def test_e_one_same_signer_with_two_distinct_signed_visibility_claims(self):
        self.sign(0,['base'])
        self.sign(0,['base','rev'])
        self.sign(1,['base'])
        out=self.audit()
        self.assertEqual(out['status'],
                         'same_receiver_divergent_signed_views_unresolved')
        self.assertEqual(out['same_receiver_divergent_signed_view_ids'],
                         [self.f.actors[2]['signer_id']])

    def test_f_absent_registered_receiver_view_must_be_visible_or_denied(self):
        self.sign(0,['base'])
        self.sign(0,['base'])
        with self.assertRaisesRegex(anchor.AnchorError,'TWO_DISTINCT'):
            self.audit()

    def test_g_wrong_signed_view_original_sha_and_forgery_denied(self):
        self.sign(0,['base'])
        self.sign(1,['base'])
        bad=json.loads(Path(self.views[0]).read_text())
        bad['claim']['observed_announcements']=[{
            'item_id':'base','snapshot_original_raw_sha256':'f1'*32,
            'ack_set_original_raw_sha256':self.f.base_ack_sha}]
        forged=str(self.w/'forged-claim.json')
        old_test.canonical(forged,bad)
        p=self.parameters()
        p['view_files']=[forged,self.views[1]]
        p['view_shas']=[old_test.sha(forged),self.view_shas[1]]
        with self.assertRaisesRegex(anchor.AnchorError,'VIEW_MUST_MATCH_EXACT'):
            v.audit_views(**p)

    def test_h_not_presented_is_distinct_from_claimed_present_but_missing_on_disk(self):
        self.sign(0,['base','unpresented'])
        self.sign(1,['base'])
        out=self.audit()
        self.assertEqual(out['claimed_visible_but_not_presented_item_ids'],
                         ['unpresented'])
        p=self.parameters(['base','unpresented'])
        with self.assertRaises(Exception):
            v.audit_views(**p)

    def test_i_reused_nonce_and_claimed_future_time_are_denied(self):
        self.sign(0,['base'],nonce='c4'*32)
        self.sign(1,['base'],nonce='c4'*32)
        with self.assertRaisesRegex(anchor.AnchorError,'NONCE_REUSED'):
            self.audit()
        self.views.clear();self.view_shas.clear()
        self.sign(0,['base'],time='2026-10-25T13:50:00Z')
        self.sign(1,['base'])
        with self.assertRaisesRegex(anchor.AnchorError,'AFTER_INDEPENDENT_EVALUATION'):
            self.audit()

    def test_j_checkpoint_cannot_assign_one_path_two_raw_sha(self):
        bad=copy.deepcopy(self.records)
        bad[1]['snapshot_file']=bad[0]['snapshot_file']
        with self.assertRaisesRegex(anchor.AnchorError,'ONE_ANNOUNCED_PATH'):
            v.assemble_checkpoint(out=str(self.w/'malformed.json'),
                roster_file=self.f.rfile,expected_roster_sha256=self.f.rsha,
                directory_file=self.directory_file,expected_directory_sha256=self.directory_sha,
                announcements=bad)

    def test_k_private_0600_and_no_overwrite(self):
        self.sign(0,['base'])
        self.assertEqual(stat.S_IMODE(os.stat(self.views[0]).st_mode),0o600)
        with self.assertRaises(Exception):
            v.sign_view(out=self.views[0],private_key_file=self.f.key_paths[2],
                roster_file=self.f.rfile,expected_roster_sha256=self.f.rsha,
                directory_file=self.directory_file,expected_directory_sha256=self.directory_sha,
                checkpoint_file=self.checkpoint_file,
                expected_checkpoint_sha256=self.checkpoint_sha,
                observed_item_ids=['base'],view_nonce_sha256='f2'*32,
                reported_utc='2026-10-25T13:16:00Z')

    def test_l_isolated_unified_read_only_audit_has_real_signed_output(self):
        self.sign(0,['base','rev'])
        self.sign(1,['base','withdraw'])
        args=self.parameters(['base','rev','withdraw'])
        cmd=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_next.py'),
             'audit-receiver-visibility','DeliveryAudit',
             'CompareSignedReceiverVisibility']
        for k,x in args.items():
            if k in ('view_files','view_shas','presented_item_ids'):continue
            cmd.extend(['--'+k.replace('_','-'),str(x)])
        for k,flag in (('view_files','--view-file'),
                       ('view_shas','--expected-view-sha256'),
                       ('presented_item_ids','--presented-item-id')):
            for x in args[k]:cmd.extend([flag,x])
        run=subprocess.run(cmd,capture_output=True,text=True,timeout=90)
        self.assertEqual(run.returncode,2,run.stdout[-2000:]+run.stderr[-500:])
        out=json.loads(run.stdout)
        self.assertEqual(out['status'],'verified_signed_same_parent_forks_unresolved')
        self.assertEqual(out['verified_signed_same_parent_sibling_item_pairs'],
                         [['rev','withdraw']])
        self.assertEqual(out['complete_global_receiver_census_or_branch_enumeration_proven'],
                         False)


if __name__=='__main__':
    unittest.main()
