#!/usr/bin/env python3
"""EC343 focused real Ed25519 receipts, signed transitions and fork safety.

Earlier EC317/318 historical fixture remains MOCK. No real institution,
external SHA custody, trusted clock or remote CAS freeze is represented.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec295_delivery_anchor import anchor
from ec342_conflict_hold import test_hold as previous
from ec340_issuer_root_rotation import test_rotation as keys
from scripts import ces_next
from . import timeline as t
from . import operator

ROOT=Path(__file__).resolve().parents[2]


class HoldReceiptTimelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        previous.SignedConflictHoldTests.setUpClass()
        cls.p=previous.SignedConflictHoldTests
        cls._tmp=tempfile.TemporaryDirectory(dir=str(cls.p.root))
        cls.w=Path(cls._tmp.name)
        cls.key_paths=[];cls.actors=[]
        for i in range(4):
            key=Ed25519PrivateKey.generate()
            f=cls.w/f'key343-{i}.key'
            keys.private(f,key)
            cls.key_paths.append(str(f))
            cls.actors.append({'signer_id':f'ec343_distinct_role_{i}',
                'public_hex':keys.pub(key),
                'organization_id':f'ec343_organization_{i}'})
        cls.roster={'schema':t.ROSTER_SCHEMA,'case_id':cls.p.gov['case_id'],
            'case_nonce_sha256':'8c'*32,
            'governance_roster_original_raw_sha256':cls.p.gov_sha,
            'hold_original_raw_sha256':cls.p.hold_sha,
            'review_manifest_original_raw_sha256':cls.p.review_sha,
            'approval_original_raw_sha256':cls.p.approval_sha,
            'change_proposer':cls.actors[0],
            'change_approver':cls.actors[1],
            'receivers':cls.actors[2:],
            'all_receivers_required':True,'no_remote_execution_authorized':True}
        cls.rfile=str(cls.w/'roster.json')
        cls.rsha=previous.canonical(cls.rfile,cls.roster)
        cls.rargs={'roster_file':cls.rfile,'expected_roster_sha256':cls.rsha}
        cls.base_path=str(cls.w/'base-snapshot.json')
        cls.base_args={'governance_roster_file':cls.p.gov_file,
            'hold_file':cls.p.hold_file,'review_manifest_file':cls.p.review_file,
            'approval_file':cls.p.approval_file}
        assert t.assemble_base(out=cls.base_path,**cls.rargs,**cls.base_args)['exit_code']==2
        cls.base_sha=previous.sha(cls.base_path)
        cls.base_receipts=[]
        for i in range(2):
            f=str(cls.w/f'base-ack-{i}.json')
            assert t.sign_ack(out=f,private_key_file=cls.key_paths[i+2],
                  **cls.rargs,snapshot_file=cls.base_path,
                  expected_snapshot_sha256=cls.base_sha,
                  received_utc=f'2026-10-25T13:0{i+2}:00Z')['exit_code']==2
            cls.base_receipts.append({'file':f,'sha256':previous.sha(f)})
        cls.base_ack_path=str(cls.w/'base-ack-set.json')
        cls.base_ack_sha=cls.ack_index(cls.base_path,cls.base_sha,
                                      cls.base_receipts,cls.base_ack_path)
        cls.prior_args={'previous_snapshot_file':cls.base_path,
            'expected_previous_snapshot_sha256':cls.base_sha,
            'previous_ack_set_file':cls.base_ack_path,
            'expected_previous_ack_set_sha256':cls.base_ack_sha}
        cls.rev=cls.make_change('revision','request_revision','96'*32,
                        '2026-10-25T13:04:00Z','2026-10-25T13:05:00Z')
        cls.withdraw=cls.make_change('withdraw','request_withdrawal','97'*32,
                        '2026-10-25T13:05:00Z','2026-10-25T13:06:00Z')
        cls.supersede=cls.make_change('supersede','request_supersession','98'*32,
                        '2026-10-25T13:06:00Z','2026-10-25T13:07:00Z',
                        successor='different_future_case_343')
        cls.second=cls.make_change('second','request_revision','99'*32,
                        '2026-10-25T13:11:00Z','2026-10-25T13:12:00Z',
                        parent_refs={'previous_snapshot_file':cls.rev['snapshot_file'],
                          'expected_previous_snapshot_sha256':cls.rev['snapshot_sha'],
                          'previous_ack_set_file':cls.rev['ack_set_file'],
                          'expected_previous_ack_set_sha256':cls.rev['ack_set_sha']},
                        ack_hour='13',ack_minutes=(14,15))
        cls.vargs={**cls.p.lineage,**cls.p.gov_args,
            'review_manifest_file':cls.p.review_file,
            'expected_review_manifest_sha256':cls.p.review_sha,
            'approval_file':cls.p.approval_file,
            'expected_approval_sha256':cls.p.approval_sha,
            'hold_evaluation_utc':'2026-10-25T13:00:00Z',
            **cls.rargs,'timeline_evaluation_utc':'2026-10-25T13:14:00Z'}

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()
        previous.SignedConflictHoldTests.tearDownClass()

    @classmethod
    def ack_index(cls,snapshot,sha,refs,path):
        result=t.assemble_ack_set(out=path,**cls.rargs,
                snapshot_file=snapshot,expected_snapshot_sha256=sha,
                receipt_files=[x['file'] for x in refs],
                receipt_shas=[x['sha256'] for x in refs])
        assert result['exit_code']==2
        return previous.sha(path)

    @classmethod
    def make_change(cls,name,kind,nonce,issued,approved,successor='',
                    parent_refs=None,ack_hour='13',ack_minutes=(8,9)):
        p=str(cls.w/f'{name}-change.json')
        args={**cls.rargs,**(parent_refs or cls.prior_args)}
        v=t.issue_change(out=p,private_key_file=cls.key_paths[0],**args,
              request_kind=kind,change_summary_sha256='c1'*32,
              change_nonce_sha256=nonce,requested_successor_case_id=successor,
              issued_utc=issued)
        assert v['exit_code']==2
        sh=previous.sha(p)
        approval=str(cls.w/f'{name}-approval.json')
        v=t.approve_change(out=approval,private_key_file=cls.key_paths[1],
                           **args,change_file=p,expected_change_sha256=sh,
                           approval_reported_utc=approved)
        assert v['exit_code']==2
        ash=previous.sha(approval)
        snapshot=str(cls.w/f'{name}-snapshot.json')
        v=t.assemble_snapshot(out=snapshot,**args,
             change_file=p,expected_change_sha256=sh,
             change_approval_file=approval,expected_change_approval_sha256=ash)
        assert v['exit_code']==2
        snapsha=previous.sha(snapshot)
        receipts=[]
        for i in range(2):
            f=str(cls.w/f'{name}-ack-{i}.json')
            v=t.sign_ack(out=f,private_key_file=cls.key_paths[i+2],**cls.rargs,
             snapshot_file=snapshot,expected_snapshot_sha256=snapsha,
             received_utc=f'2026-10-25T{ack_hour}:{ack_minutes[i]:02d}:00Z')
            assert v['exit_code']==2
            receipts.append({'file':f,'sha256':previous.sha(f)})
        a=str(cls.w/f'{name}-ack-set.json')
        ah=cls.ack_index(snapshot,snapsha,receipts,a)
        return {'change_file':p,'change_sha':sh,'approval_file':approval,
                'approval_sha':ash,'snapshot_file':snapshot,'snapshot_sha':snapsha,
                'acks':receipts,'ack_set_file':a,'ack_set_sha':ah}

    def setUp(self):
        x=tempfile.TemporaryDirectory(dir=str(self.w))
        self.addCleanup(x.cleanup)
        self.tmp=Path(x.name)

    def verify(self,head=None,**kw):
        head=head or self.rev
        args={**self.vargs,'head_snapshot_file':head['snapshot_file'],
            'expected_head_snapshot_sha256':head['snapshot_sha'],
            'head_ack_set_file':head['ack_set_file'],
            'expected_head_ack_set_sha256':head['ack_set_sha']}
        args.update(kw)
        return t.verify_timeline(**args)

    def test_a_two_distinct_receipts_bind_baseline_and_review(self):
        result=self.verify(head={'snapshot_file':self.base_path,
            'snapshot_sha':self.base_sha,'ack_set_file':self.base_ack_path,
            'ack_set_sha':self.base_ack_sha})
        self.assertEqual(result['status'],'baseline_acknowledged_unresolved')
        self.assertEqual(result['head_distinct_receiver_acks'],2)
        self.assertEqual(result['head_sequence'],0)
        self.assertFalse(result['acknowledgements_or_majority_execute_remote_hold'])

    def test_b_true_independent_revision_and_receipts_not_execution(self):
        result=self.verify()
        self.assertEqual(result['status'],'revision_requested_unresolved')
        self.assertEqual(result['head_sequence'],1)
        self.assertFalse(result['revision_or_supersession_changes_prior_signed_originals'])

    def test_c_withdrawal_only_request_never_actual_release(self):
        result=self.verify(head=self.withdraw)
        self.assertEqual(result['status'],'withdrawal_requested_unresolved')
        self.assertFalse(result['withdrawal_request_releases_or_deletes_actual_remote_freeze'])

    def test_d_two_genuine_signed_siblings_remain_unresolved(self):
        result=self.verify(competing_snapshot_file=self.withdraw['snapshot_file'],
               expected_competing_snapshot_sha256=self.withdraw['snapshot_sha'],
               competing_ack_set_file=self.withdraw['ack_set_file'],
               expected_competing_ack_set_sha256=self.withdraw['ack_set_sha'])
        self.assertEqual(result['status'],'competing_change_requests_unresolved')
        self.assertTrue(result['competing_signed_same_parent_requests_observed'])
        self.assertFalse(result['signed_competing_transition_selects_a_winner'])

    def test_q_supersession_is_only_signed_requested_new_case_id(self):
        result=self.verify(head=self.supersede)
        self.assertEqual(result['status'],'supersession_requested_unresolved')
        self.assertFalse(result['revision_or_supersession_changes_prior_signed_originals'])
        claim=json.loads(Path(self.supersede['change_file']).read_text())['claim']
        self.assertEqual(claim['requested_successor_case_id'],'different_future_case_343')

    def test_r_two_sequential_approved_revisions_pin_both_ack_sets(self):
        result=self.verify(head=self.second,
                           timeline_evaluation_utc='2026-10-25T13:18:00Z')
        self.assertEqual(result['status'],'revision_requested_unresolved')
        self.assertEqual(result['head_sequence'],2)
        self.assertEqual(result['head_distinct_receiver_acks'],2)
        old_approved=json.loads(Path(self.second['change_file']).read_text())['claim']
        self.assertEqual(old_approved['previous_approval_original_raw_sha256'],
                         self.rev['approval_sha'])
        self.assertEqual(old_approved['previous_ack_set_original_raw_sha256'],
                         self.rev['ack_set_sha'])

    def test_s_competing_heads_must_have_same_signed_parent(self):
        with self.assertRaisesRegex(anchor.AnchorError,'SAME_PARENT'):
            self.verify(head=self.second,
                competing_snapshot_file=self.withdraw['snapshot_file'],
                expected_competing_snapshot_sha256=self.withdraw['snapshot_sha'],
                competing_ack_set_file=self.withdraw['ack_set_file'],
                expected_competing_ack_set_sha256=self.withdraw['ack_set_sha'],
                timeline_evaluation_utc='2026-10-25T13:18:00Z')

    def test_t_wrong_successor_case_id_and_role_separation_denied(self):
        with self.assertRaises(anchor.AnchorError):
            t.issue_change(out=str(self.tmp/'bad-successor.json'),
              private_key_file=self.key_paths[0],**self.rargs,**self.prior_args,
              request_kind='request_supersession',change_summary_sha256='ae'*32,
              change_nonce_sha256='de'*32,
              requested_successor_case_id=self.roster['case_id'],
              issued_utc='2026-10-25T13:11:00Z')
        with self.assertRaises(anchor.AnchorError):
            t.approve_change(out=str(self.tmp/'same-person-approval.json'),
              private_key_file=self.key_paths[0],**self.rargs,**self.prior_args,
              change_file=self.rev['change_file'],
              expected_change_sha256=self.rev['change_sha'],
              approval_reported_utc='2026-10-25T13:11:00Z')

    def test_e_late_evaluation_audits_expired_hold_not_active(self):
        result=self.verify(timeline_evaluation_utc='2026-10-25T13:30:00Z')
        self.assertEqual(result['status'],'hold_window_expired_unresolved')
        self.assertTrue(result['hold_claim_window_expired_at_evaluation'])

    def test_f_missing_receiver_ack_never_counted_complete(self):
        ack_set=str(self.tmp/'partial.json')
        ah=self.ack_index(self.base_path,self.base_sha,
                          self.base_receipts[:1],ack_set)
        result=self.verify(head={'snapshot_file':self.base_path,'snapshot_sha':self.base_sha,
               'ack_set_file':ack_set,'ack_set_sha':ah})
        self.assertEqual(result['status'],'receiver_ack_incomplete_unresolved')
        with self.assertRaises(anchor.AnchorError):
            t.issue_change(out=str(self.tmp/'no-quorum.json'),
              private_key_file=self.key_paths[0],**self.rargs,
              previous_snapshot_file=self.base_path,
              expected_previous_snapshot_sha256=self.base_sha,
              previous_ack_set_file=ack_set,expected_previous_ack_set_sha256=ah,
              request_kind='request_revision',change_summary_sha256='a1'*32,
              change_nonce_sha256='11'*32,requested_successor_case_id='',
              issued_utc='2026-10-25T13:04:00Z')

    def test_g_tampered_ed25519_receiver_signature_denied(self):
        broken=json.loads(Path(self.base_receipts[0]['file']).read_text())
        broken['signature_ed25519']='fe'*64
        f=self.tmp/'bad-receiver.json'
        sh=previous.canonical(f,broken)
        with self.assertRaises(anchor.AnchorError):
            t.assemble_ack_set(out=str(self.tmp/'bad-ack-list.json'),
                **self.rargs,snapshot_file=self.base_path,
                expected_snapshot_sha256=self.base_sha,
                receipt_files=[str(f)],receipt_shas=[sh])

    def test_h_duplicate_receiver_and_wrong_role_private_key_denied(self):
        with self.assertRaises(anchor.AnchorError):
            t.assemble_ack_set(out=str(self.tmp/'duplicate.json'),
                 **self.rargs,snapshot_file=self.base_path,
                 expected_snapshot_sha256=self.base_sha,
                 receipt_files=[self.base_receipts[0]['file']]*2,
                 receipt_shas=[self.base_receipts[0]['sha256']]*2)
        with self.assertRaises(anchor.AnchorError):
            t.sign_ack(out=str(self.tmp/'wrong-person.json'),
                 private_key_file=self.key_paths[0],**self.rargs,
                 snapshot_file=self.base_path,expected_snapshot_sha256=self.base_sha,
                 received_utc='2026-10-25T13:04:00Z')

    def test_i_replayed_transition_nonce_across_versions_denied(self):
        with self.assertRaisesRegex(anchor.AnchorError,'NONCE'):
            t.issue_change(out=str(self.tmp/'replayed.json'),
                private_key_file=self.key_paths[0],**self.rargs,
                previous_snapshot_file=self.rev['snapshot_file'],
                expected_previous_snapshot_sha256=self.rev['snapshot_sha'],
                previous_ack_set_file=self.rev['ack_set_file'],
                expected_previous_ack_set_sha256=self.rev['ack_set_sha'],
                request_kind='request_revision',change_summary_sha256='a1'*32,
                change_nonce_sha256='96'*32,requested_successor_case_id='',
                issued_utc='2026-10-25T13:12:00Z')

    def test_j_competing_branch_cannot_reuse_other_branch_approval(self):
        with self.assertRaises(anchor.AnchorError):
            t.assemble_snapshot(out=str(self.tmp/'reused-approval.json'),
                **self.rargs,**self.prior_args,
                change_file=self.withdraw['change_file'],
                expected_change_sha256=self.withdraw['change_sha'],
                change_approval_file=self.rev['approval_file'],
                expected_change_approval_sha256=self.rev['approval_sha'])

    def test_k_early_ack_and_after_expiry_approval_rejected(self):
        with self.assertRaises(anchor.AnchorError):
            t.sign_ack(out=str(self.tmp/'early.json'),
                private_key_file=self.key_paths[2],**self.rargs,
                snapshot_file=self.rev['snapshot_file'],
                expected_snapshot_sha256=self.rev['snapshot_sha'],
                received_utc='2026-10-25T13:01:00Z')
        with self.assertRaises(anchor.AnchorError):
            t.approve_change(out=str(self.tmp/'expired.json'),
                private_key_file=self.key_paths[1],**self.rargs,**self.prior_args,
                change_file=self.rev['change_file'],
                expected_change_sha256=self.rev['change_sha'],
                approval_reported_utc='2026-10-25T13:25:00Z')

    def test_l_roster_cannot_reuse_old_ec342_signer(self):
        malicious=copy.deepcopy(self.roster)
        malicious['receivers'][0]['public_hex']=self.p.roles[0]['public_hex']
        f=self.tmp/'collide-roster.json';sh=previous.canonical(f,malicious)
        with self.assertRaises(anchor.AnchorError):
            t.assemble_base(out=str(self.tmp/'nope.json'),
              roster_file=str(f),expected_roster_sha256=sh,**self.base_args)

    def test_m_unsigned_or_wrong_head_sha_denied(self):
        with self.assertRaises(anchor.AnchorError):
            self.verify(expected_head_snapshot_sha256='bb'*32)
        with self.assertRaises(anchor.AnchorError):
            self.verify(expected_roster_sha256='cc'*32)

    def test_n_offline_candidate_private_mode_and_exclusive(self):
        self.assertEqual(Path(self.rev['change_file']).stat().st_mode&0o777,0o600)
        self.assertEqual(Path(self.rev['approval_file']).stat().st_mode&0o777,0o600)
        before=Path(self.rev['snapshot_file']).read_bytes()
        with self.assertRaises(Exception):
            t.assemble_snapshot(out=self.rev['snapshot_file'],**self.rargs,
                **self.prior_args,change_file=self.rev['change_file'],
                expected_change_sha256=self.rev['change_sha'],
                change_approval_file=self.rev['approval_file'],
                expected_change_approval_sha256=self.rev['approval_sha'])
        self.assertEqual(Path(self.rev['snapshot_file']).read_bytes(),before)

    def test_o_standalone_isolated_and_unified_readonly_real_execution(self):
        flags={**self.vargs,
            'head_snapshot_file':self.rev['snapshot_file'],
            'expected_head_snapshot_sha256':self.rev['snapshot_sha'],
            'head_ack_set_file':self.rev['ack_set_file'],
            'expected_head_ack_set_sha256':self.rev['ack_set_sha']}
        opts=[]
        for k,v in flags.items():opts.extend(['--'+k.replace('_','-'),str(v)])
        for script,front in ((ROOT/'scripts'/'ces_cas_hold_receipts.py',
                             ['verify-timeline']),
                             (ROOT/'scripts'/'ces_next.py',
                              ['audit-issuer-hold-timeline','DeliveryAudit',
                               'VerifySignedHoldReceiptTimeline'])):
            proc=subprocess.run([sys.executable,'-I','-B',str(script),*front,*opts],
                           capture_output=True,text=True,timeout=500)
            self.assertEqual(proc.returncode,2,proc.stdout[-600:]+proc.stderr[-600:])
            self.assertEqual(json.loads(proc.stdout)['status'],
                             'revision_requested_unresolved')
        self.assertEqual(ces_next.VERSION,'V6.53')
        self.assertEqual(ces_next.ROUND,'R343')
        with self.assertRaises(ces_next.ConsoleError):
            ces_next.audit_issuer_hold_timeline('DeliveryAudit','IssueChange',
                **{**flags,**{k:None for k in ces_next.EC343_COMPETING_KEYS}})

    def test_p_non_signer_cli_denied_and_no_file_appears(self):
        file=self.tmp/'forbidden-change.json'
        args={**self.rargs,**self.prior_args,'out':str(file),
              'private_key_file':self.key_paths[3],
              'request_kind':'request_withdrawal',
              'change_summary_sha256':'e1'*32,'change_nonce_sha256':'d1'*32,
              'requested_successor_case_id':'','issued_utc':'2026-10-25T13:12:00Z'}
        opts=[]
        for k,v in args.items():opts.extend(['--'+k.replace('_','-'),str(v)])
        proc=subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_cas_hold_receipts.py'),
                             'issue-change',*opts],capture_output=True,text=True,timeout=100)
        self.assertEqual(proc.returncode,3,proc.stdout+proc.stderr)
        self.assertFalse(file.exists())


if __name__=='__main__':unittest.main()
