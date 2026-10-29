#!/usr/bin/env python3
"""EC342 focused true Ed25519 hold votes, threshold and EC341->EC337 replay.

The inherited EC317/318 deep history is MOCK. Tests never claim legal custody,
remote CAS freeze, or unreported fork discovery.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec295_delivery_anchor import anchor
from ec319_offline_transfer_registry import registry as reg
from ec321_fork_case_transport import case
from ec341_root_lineage import test_lineage as ancestry
from ec340_issuer_root_rotation import test_rotation as keys
from scripts import ces_next
from . import hold as r
from . import operator as op

ROOT=Path(__file__).resolve().parents[2]


def sha(path):
    return case.sha(Path(path).read_bytes())


def canonical(path,doc):
    ancestry.prior._write_exclusive(str(path),reg.raw_doc(doc))
    return sha(path)


class SignedConflictHoldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ancestry.BoundedIssuerLineageTests.setUpClass()
        cls.parent=ancestry.BoundedIssuerLineageTests
        cls.w=Path(cls.parent.w)
        cls._temp=tempfile.TemporaryDirectory(dir=str(cls.w))
        cls.root=Path(cls._temp.name)
        _,_,alt=cls.parent.make_epoch(parent=cls.parent.h3,
            old_keys=cls.parent.k3paths,number=4,suffix='f',
            time='2026-10-25T12:31:00Z',observed='2026-10-25T12:32:00Z',
            evaluation='2026-10-25T12:36:00Z',expires='2026-10-25T13:02:00Z',
            challenge='af'*32)
        cls.alt=alt
        doc=copy.deepcopy(cls.parent.base)
        doc['forks']=[{'parent_epoch':3,'hop':alt}]
        cls.manifest_file=str(cls.root/'lineage-manifest.json')
        cls.manifest_sha=canonical(cls.manifest_file,doc)
        cls.lineage={
            'manifest_file':cls.manifest_file,
            'expected_manifest_sha256':cls.manifest_sha,
            'expected_current_root_sha256':cls.parent.h4['expected_successor_roster_sha256'],
            'expected_current_root_epoch':4,
            'minimum_acceptable_epoch':3,
            'current_root_evaluation_utc':'2026-10-25T12:39:00Z'}
        result=r.lineage.verify_lineage(**cls.lineage)
        assert result['status']=='conflict_unresolved' and len(result['fork_conflicts'])==1
        cls.priv=[];cls.priv_path=[];cls.roles=[]
        for i in range(6):
            key=Ed25519PrivateKey.generate()
            path=cls.root/f'governance-key-{i}.key'
            keys.private(path,key)
            cls.priv.append(key);cls.priv_path.append(str(path))
            cls.roles.append({'signer_id':f'ec342_person_{i}',
                 'public_hex':keys.pub(key),
                 'organization_id':f'ec342_independent_org_{i}'})
        fork=result['fork_conflicts'][0]
        gov={
            'schema':r.GOVERNANCE_SCHEMA,'case_id':'holdcase_342_one',
            'case_nonce_sha256':'ae'*32,
            'transfer_id':'ec339_transfer_001',
            'policy_original_raw_sha256':result['policy_original_raw_sha256'],
            'lineage_manifest_original_raw_sha256':cls.manifest_sha,
            'current_root_original_raw_sha256':cls.lineage['expected_current_root_sha256'],
            'current_root_epoch':4,'minimum_acceptable_epoch':3,
            'current_root_evaluation_utc':cls.lineage['current_root_evaluation_utc'],
            'parent_epoch':fork['parent_epoch'],
            'parent_root_original_raw_sha256':fork['parent_roster_original_raw_sha256'],
            'selected_successor_original_raw_sha256':fork['selected_successor_original_raw_sha256'],
            'alternative_successor_original_raw_sha256':fork['alternative_successor_original_raw_sha256'],
            'initiator':cls.roles[0], 'reviewers':cls.roles[1:5],
            'required_support_quorum':3, 'external_approver':cls.roles[5],
            'external_approval_required':True,'remote_freeze_not_performed':True}
        cls.gov=gov
        cls.gov_file=str(cls.root/'independent-governance.json')
        cls.gov_sha=canonical(cls.gov_file,gov)
        cls.gov_args={'governance_roster_file':cls.gov_file,
                      'expected_governance_roster_sha256':cls.gov_sha}
        cls.hold_file=str(cls.root/'signed-hold.json')
        out=r.issue_hold(out=cls.hold_file,
            private_key_file=cls.priv_path[0],**cls.gov_args,**cls.lineage,
            hold_challenge_sha256='ac'*32,
            issued_utc='2026-10-25T12:43:00Z',
            expires_utc='2026-10-25T13:20:00Z')
        assert out['exit_code']==2
        cls.hold_sha=sha(cls.hold_file)
        cls.hold_args={'hold_file':cls.hold_file,'expected_hold_sha256':cls.hold_sha}
        cls.votes=[]
        for i in range(4):
            path=str(cls.root/f'vote_{i}.json')
            out=r.sign_review(out=path,private_key_file=cls.priv_path[i+1],
                **cls.gov_args,**cls.hold_args,
                decision='support_hold' if i<3 else 'object_to_hold',
                reviewer_reported_utc='2026-10-25T12:50:00Z')
            assert out['exit_code']==2
            cls.votes.append({'file':path,'sha256':sha(path)})
        cls.review_file=str(cls.root/'review-full.json')
        out=r.assemble_review(out=cls.review_file,**cls.gov_args,**cls.hold_args,
           attestation_files=[v['file'] for v in cls.votes],
           attestation_shas=[v['sha256'] for v in cls.votes])
        assert out['exit_code']==2
        cls.review_sha=sha(cls.review_file)
        cls.approval_file=str(cls.root/'external-approval.json')
        out=r.issue_approval(out=cls.approval_file,
             private_key_file=cls.priv_path[5],**cls.gov_args,
             review_manifest_file=cls.review_file,
             expected_review_manifest_sha256=cls.review_sha,
             approval_reported_utc='2026-10-25T12:55:00Z')
        assert out['exit_code']==2
        cls.approval_sha=sha(cls.approval_file)
        cls.approval_args={'approval_file':cls.approval_file,
                           'expected_approval_sha256':cls.approval_sha}

    @classmethod
    def tearDownClass(cls):
        cls._temp.cleanup()
        ancestry.BoundedIssuerLineageTests.tearDownClass()

    def setUp(self):
        temp=tempfile.TemporaryDirectory(dir=str(self.root))
        self.addCleanup(temp.cleanup)
        self.tmp=Path(temp.name)

    def verify(self,**kw):
        args={**self.lineage,**self.gov_args,
              'review_manifest_file':self.review_file,
              'expected_review_manifest_sha256':self.review_sha,
              'hold_evaluation_utc':'2026-10-25T13:00:00Z'}
        args.update(kw)
        return r.verify_hold(**args)

    def review_subset(self,indices):
        path=str(self.tmp/f'subset-review-{len(list(self.tmp.iterdir()))}.json')
        chosen=[self.votes[i] for i in indices]
        r.assemble_review(out=path,**self.gov_args,**self.hold_args,
            attestation_files=[x['file'] for x in chosen],
            attestation_shas=[x['sha256'] for x in chosen])
        return {'review_manifest_file':path,
                'expected_review_manifest_sha256':sha(path)}

    def test_a_verified_hold_with_three_true_votes_one_dissent_separate_approval(self):
        result=self.verify(**self.approval_args)
        self.assertEqual(result['exit_code'],2)
        self.assertEqual(result['status'],'hold_verified_unresolved')
        self.assertEqual(result['supporting_distinct_reviewer_count'],3)
        self.assertEqual(result['objecting_distinct_reviewer_count'],1)
        self.assertTrue(result['separate_approver_signature_verified'])
        self.assertTrue(result['signed_sibling_fork_and_historical_full_replay_verified'])
        self.assertTrue(all(result[x] is False for x in r.NEGATIVES))

    def test_b_three_supporters_without_external_approval_is_not_held(self):
        result=self.verify()
        self.assertEqual(result['status'],'external_approval_missing')
        self.assertIsNone(result['external_approval_original_raw_sha256'])
        self.assertEqual(result['exit_code'],2)

    def test_c_two_supporters_and_one_dissent_remain_quorum_insufficient(self):
        result=self.verify(**self.review_subset((0,1,3)))
        self.assertEqual(result['status'],'quorum_insufficient')
        self.assertEqual(result['supporting_distinct_reviewer_count'],2)
        self.assertEqual(result['objecting_distinct_reviewer_count'],1)

    def test_d_one_and_zero_reviews_do_not_synthesize_majority(self):
        for indices in ((0,),()):
            result=self.verify(**self.review_subset(indices))
            self.assertEqual(result['status'],'quorum_insufficient')

    def test_e_duplicate_reviewer_votes_cannot_inflate_quorum(self):
        doc={'schema':r.REVIEW_MANIFEST_SCHEMA,**self.hold_args,
             'attestations':[self.votes[0],self.votes[0],self.votes[1]]}
        path=self.tmp/'duplicate.json';digest=canonical(path,doc)
        with self.assertRaises(anchor.AnchorError):
            self.verify(review_manifest_file=str(path),
                        expected_review_manifest_sha256=digest)

    def test_f_tampered_vote_signature_denied_after_whole_sha_repin(self):
        vote=json.loads(Path(self.votes[0]['file']).read_text())
        vote['signature_ed25519']='ee'*64
        path=self.tmp/'forged.json';digest=canonical(path,vote)
        doc={'schema':r.REVIEW_MANIFEST_SCHEMA,**self.hold_args,
             'attestations':[{'file':str(path),'sha256':digest},
                             *self.votes[1:3]]}
        m=self.tmp/'reindexed.json';msha=canonical(m,doc)
        with self.assertRaises(anchor.AnchorError):
            self.verify(review_manifest_file=str(m),
                        expected_review_manifest_sha256=msha)

    def test_g_wrong_approver_role_cannot_issue_signature(self):
        with self.assertRaises(anchor.AnchorError):
            r.issue_approval(out=str(self.tmp/'wrong-approval.json'),
                private_key_file=self.priv_path[1],**self.gov_args,
                review_manifest_file=self.review_file,
                expected_review_manifest_sha256=self.review_sha,
                approval_reported_utc='2026-10-25T12:55:00Z')

    def test_h_wrong_reviewer_key_cannot_vote(self):
        with self.assertRaises(anchor.AnchorError):
            r.sign_review(out=str(self.tmp/'wrong-vote.json'),
                private_key_file=self.priv_path[5],**self.gov_args,
                **self.hold_args,decision='support_hold',
                reviewer_reported_utc='2026-10-25T12:50:00Z')

    def test_i_approval_binds_exact_review_manifest_original_sha(self):
        args=self.review_subset((0,1,2))
        with self.assertRaises(anchor.AnchorError):
            self.verify(**args,**self.approval_args)

    def test_j_forged_approval_ed25519_denied_even_with_correct_file_pin(self):
        doc=json.loads(Path(self.approval_file).read_text())
        doc['signature_ed25519']='aa'*64
        path=self.tmp/'forged-approval.json';digest=canonical(path,doc)
        with self.assertRaises(anchor.AnchorError):
            self.verify(approval_file=str(path),expected_approval_sha256=digest)

    def test_k_untrusted_manifest_root_or_epoch_denied(self):
        for change in ({'expected_manifest_sha256':'aa'*32},
                       {'expected_current_root_epoch':3},
                       {'expected_current_root_sha256':'ab'*32}):
            with self.subTest(change=change):
                with self.assertRaises(anchor.AnchorError):self.verify(**change)

    def test_l_hold_window_stale_or_future_denied(self):
        for stamp in ('2026-10-25T13:20:00Z','2026-10-25T12:42:59Z'):
            with self.subTest(stamp=stamp):
                with self.assertRaises(anchor.AnchorError):
                    self.verify(hold_evaluation_utc=stamp)

    def test_m_original_pins_must_be_whole_file_exact(self):
        with self.assertRaises(anchor.AnchorError):
            self.verify(expected_review_manifest_sha256='bb'*32)
        with self.assertRaises(anchor.AnchorError):
            self.verify(expected_governance_roster_sha256='cc'*32)

    def test_n_gov_role_collision_with_chain_issuer_rejected(self):
        gov=copy.deepcopy(self.gov)
        gov['reviewers'][0]['public_hex']=json.loads(
            Path(self.parent.h4['successor_roster_file']).read_text())['issuers'][0]['issuer_public_hex']
        path=self.tmp/'colliding-gov.json';digest=canonical(path,gov)
        with self.assertRaises(anchor.AnchorError):
            r._trusted_case(r._governance(str(path),digest),self.lineage)

    def test_o_signer_private_0600_exclusive_no_overwrite(self):
        file=Path(self.hold_file)
        self.assertEqual(file.stat().st_mode & 0o777,0o600)
        self.assertEqual(Path(self.approval_file).stat().st_mode & 0o777,0o600)
        before=file.read_bytes()
        with self.assertRaises(Exception):
            r.issue_hold(out=str(file),private_key_file=self.priv_path[0],
                **self.gov_args,**self.lineage,hold_challenge_sha256='ac'*32,
                issued_utc='2026-10-25T12:43:00Z',
                expires_utc='2026-10-25T13:20:00Z')
        self.assertEqual(file.read_bytes(),before)

    def test_p_proposer_signature_is_not_self_signed_governance(self):
        bad=json.loads(Path(self.hold_file).read_text())
        bad['signature_ed25519']='cc'*64
        path=self.tmp/'fake-hold.json';hashv=canonical(path,bad)
        doc={'schema':r.REVIEW_MANIFEST_SCHEMA,'hold_file':str(path),
             'expected_hold_sha256':hashv,'attestations':[]}
        review=self.tmp/'fake-index.json';review_sha=canonical(review,doc)
        with self.assertRaises(anchor.AnchorError):
            self.verify(review_manifest_file=str(review),
                        expected_review_manifest_sha256=review_sha)

    def test_q_standalone_isolated_readonly_cli_and_unified_entry(self):
        args={**self.lineage,**self.gov_args,
              'review_manifest_file':self.review_file,
              'expected_review_manifest_sha256':self.review_sha,
              'hold_evaluation_utc':'2026-10-25T13:00:00Z'}
        def cli_flags(d):
            ret=[]
            for k,v in d.items():ret.extend(['--'+k.replace('_','-'),str(v)])
            return ret
        p=subprocess.run([sys.executable,'-I','-B',
             str(ROOT/'scripts'/'ces_cas_issuer_hold_governance.py'),'verify-hold',
             *cli_flags(args)],capture_output=True,text=True,timeout=400)
        self.assertEqual(p.returncode,2,p.stdout[-400:]+p.stderr[-400:])
        self.assertEqual(json.loads(p.stdout)['status'],'external_approval_missing')
        c=subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_next.py'),
             'audit-issuer-conflict-hold','DeliveryAudit','VerifyIssuerConflictHold',
             *cli_flags(args)],capture_output=True,text=True,timeout=400)
        self.assertEqual(c.returncode,2,c.stdout[-400:]+c.stderr[-400:])
        self.assertEqual(json.loads(c.stdout)['status'],'external_approval_missing')
        # The EC342 verifier is also regression-tested after later numbered
        # package releases. The unified console's current package version must
        # advance monotonically; it must not remain pinned to an old build.
        self.assertGreaterEqual(tuple(map(int,ces_next.VERSION[1:].split('.'))),(6,52))
        self.assertGreaterEqual(int(ces_next.ROUND[1:]),342)
        with self.assertRaises(ces_next.ConsoleError):
            ces_next.audit_issuer_conflict_hold(
                 'DeliveryAudit','IssueHold',**{**args,'approval_file':None,
                                               'expected_approval_sha256':None})

    def test_r_absent_approval_half_pair_and_unsupported_time_fail_closed(self):
        with self.assertRaises(anchor.AnchorError):
            self.verify(approval_file=self.approval_file)
        with self.assertRaises(anchor.AnchorError):
            self.verify(hold_evaluation_utc='2030-01-01T00:00:00Z')

    def test_s_external_approver_does_not_count_as_reviewer(self):
        doc=self.review_subset((0,1))
        with self.assertRaises(anchor.AnchorError):
            r.issue_approval(out=str(self.tmp/'premature.json'),
                private_key_file=self.priv_path[5],**self.gov_args,
                **doc,approval_reported_utc='2026-10-25T12:55:00Z')


    def test_t_declared_review_future_of_receiver_evaluation_is_not_counted(self):
        with self.assertRaisesRegex(anchor.AnchorError,'CANNOT_COUNT_REVIEW'):
            self.verify(hold_evaluation_utc='2026-10-25T12:45:00Z')

    def test_u_declared_approval_before_reviewers_is_rejected(self):
        with self.assertRaisesRegex(anchor.AnchorError,'APPROVAL_CANNOT_PRECEDE_REVIEWER'):
            r.issue_approval(out=str(self.tmp/'early-approval.json'),
                private_key_file=self.priv_path[5],**self.gov_args,
                review_manifest_file=self.review_file,
                expected_review_manifest_sha256=self.review_sha,
                approval_reported_utc='2026-10-25T12:44:00Z')

    def test_v_signer_cannot_hold_a_different_unsigned_or_unreported_fork(self):
        gov=copy.deepcopy(self.gov)
        gov['alternative_successor_original_raw_sha256']='ef'*32
        path=self.tmp/'fake-case.json';digest=canonical(path,gov)
        with self.assertRaisesRegex(anchor.AnchorError,'ACTUALLY_VERIFIED_SIGNED'):
            r.issue_hold(out=str(self.tmp/'fake-case-hold.json'),
                private_key_file=self.priv_path[0],
                governance_roster_file=str(path),
                expected_governance_roster_sha256=digest,**self.lineage,
                hold_challenge_sha256='ac'*32,
                issued_utc='2026-10-25T12:43:00Z',
                expires_utc='2026-10-25T13:20:00Z')

    def test_w_isolated_standalone_sign_review_and_assemble(self):
        def cli_flags(d):
            a=[]
            for k,v in d.items():a.extend(['--'+k.replace('_','-'),str(v)])
            return a
        path=self.tmp/'separate-cli-review.json'
        flags={'out':str(path),'private_key_file':self.priv_path[1],
               **self.gov_args,**self.hold_args,
               'decision':'support_hold',
               'reviewer_reported_utc':'2026-10-25T12:52:00Z'}
        proc=subprocess.run([sys.executable,'-I','-B',
            str(ROOT/'scripts'/'ces_cas_issuer_hold_governance.py'),'sign-review',
            *cli_flags(flags)],capture_output=True,text=True,timeout=60)
        self.assertEqual(proc.returncode,2,proc.stdout+proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['status'],
                         'owner_private_candidate_untrusted')
        self.assertEqual(path.stat().st_mode&0o777,0o600)
        idx=self.tmp/'cli-review-manifest.json'
        flags={'out':str(idx),**self.gov_args,**self.hold_args}
        proc=subprocess.run([sys.executable,'-I','-B',
            str(ROOT/'scripts'/'ces_cas_issuer_hold_governance.py'),'assemble-review',
            *cli_flags(flags),'--attestation-file',str(path),
            '--expected-attestation-sha256',sha(path)],
            capture_output=True,text=True,timeout=60)
        self.assertEqual(proc.returncode,2,proc.stdout+proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['status'],
                         'owner_private_candidate_untrusted')
        result=self.verify(review_manifest_file=str(idx),
                           expected_review_manifest_sha256=sha(idx))
        self.assertEqual(result['status'],'quorum_insufficient')

    def test_x_unified_verified_hold_with_real_approval_remains_exit2(self):
        args={**self.lineage,**self.gov_args,
              'review_manifest_file':self.review_file,
              'expected_review_manifest_sha256':self.review_sha,
              'hold_evaluation_utc':'2026-10-25T13:00:00Z',**self.approval_args}
        cmd=[sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_next.py'),
             'audit-issuer-conflict-hold','DeliveryAudit','VerifyIssuerConflictHold']
        for k,v in args.items():cmd.extend(['--'+k.replace('_','-'),str(v)])
        proc=subprocess.run(cmd,capture_output=True,text=True,timeout=400)
        self.assertEqual(proc.returncode,2,proc.stdout[-500:]+proc.stderr[-500:])
        self.assertEqual(json.loads(proc.stdout)['status'],'hold_verified_unresolved')



if __name__=='__main__':
    unittest.main()
