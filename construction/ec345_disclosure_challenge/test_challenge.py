#!/usr/bin/env python3
"""EC345 focused actual Ed25519 tests. Old EC317/318 deep history is MOCK."""
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

from ec295_delivery_anchor import anchor
from ec342_conflict_hold import test_hold as old_test
from ec344_receiver_visibility import test_visibility as old_fixture
from . import challenge as c

ROOT=Path(__file__).resolve().parents[2]


class DisclosureChallengeTests(unittest.TestCase):
    configure=old_fixture.ReceiverVisibilityTests.configure
    sign=old_fixture.ReceiverVisibilityTests.sign
    parameters=old_fixture.ReceiverVisibilityTests.parameters
    audit=old_fixture.ReceiverVisibilityTests.audit

    @classmethod
    def setUpClass(cls):
        old_fixture.ReceiverVisibilityTests.setUpClass()
        cls.f=old_fixture.ReceiverVisibilityTests.f
        cls.root=old_fixture.ReceiverVisibilityTests.root

    @classmethod
    def tearDownClass(cls):
        old_fixture.ReceiverVisibilityTests.tearDownClass()

    def setUp(self):
        old_fixture.ReceiverVisibilityTests.setUp(self)
        self.sign(0,['base','rev','unpresented'])
        self.sign(1,['base','rev','unpresented'])
        self.challenges=[]
        self.challenge_shas=[]
        self.responses=[]
        self.response_shas=[]

    def challenge(self,item='rev',attempt=1,previous=None,
                  nonce=None,issued='2026-10-25T13:21:00Z',**override):
        path=str(self.w/f'challenge-{len(self.challenges)}.json')
        args=dict(out=path,private_key_file=self.f.key_paths[0],
              roster_file=self.f.rfile,expected_roster_sha256=self.f.rsha,
              directory_file=self.directory_file,
              expected_directory_sha256=self.directory_sha,
              checkpoint_file=self.checkpoint_file,
              expected_checkpoint_sha256=self.checkpoint_sha,
              view_files=self.views,view_shas=self.view_shas,
              anchor_item_id='base',baseline_presented_item_ids=['base'],
              item_id=item,audience_receiver_ids=[a['signer_id'] for a in
                      self.f.actors[2:]],attempt_number=attempt,
              challenge_nonce_sha256=nonce or (f'{64+len(self.challenges):02x}'*32),
              issued_utc=issued,
              previous_challenge_file=previous[0] if previous else None,
              expected_previous_challenge_sha256=previous[1] if previous else None)
        args.update(override)
        self.assertEqual(c.issue_challenge(**args)['exit_code'],2)
        sha=old_test.sha(path)
        self.challenges.append(path);self.challenge_shas.append(sha)
        return path,sha

    def response(self,challenge,receiver=0,kind=c.OFFER,
                 nonce=None,reported='2026-10-25T13:22:00Z',**override):
        path=str(self.w/f'response-{len(self.responses)}.json')
        args=dict(out=path,private_key_file=self.f.key_paths[receiver+2],
              roster_file=self.f.rfile,expected_roster_sha256=self.f.rsha,
              directory_file=self.directory_file,
              expected_directory_sha256=self.directory_sha,
              checkpoint_file=self.checkpoint_file,
              expected_checkpoint_sha256=self.checkpoint_sha,
              challenge_file=challenge[0],expected_challenge_sha256=challenge[1],
              response_kind=kind,
              response_nonce_sha256=nonce or (f'{128+len(self.responses):02x}'*32),
              reported_utc=reported)
        args.update(override)
        self.assertEqual(c.sign_response(**args)['exit_code'],2)
        sha=old_test.sha(path)
        self.responses.append(path);self.response_shas.append(sha)
        return path,sha

    def kw(self,disclosed=None,**overrides):
        return {**self.parameters(['base']),
                'challenge_files':self.challenges,
                'challenge_shas':self.challenge_shas,
                'response_files':self.responses,
                'response_shas':self.response_shas,
                'disclosed_item_ids':disclosed or [],
                'disclosure_evaluation_utc':'2026-10-25T13:35:00Z',
                **overrides}

    def test_a_furnished_originals_full_sha_and_ec343_chain_not_signed_offer_only(self):
        q=self.challenge()
        self.response(q,kind=c.OFFER)
        out=c.audit_disclosures(**self.kw(['rev']))
        self.assertEqual(out['status'],'delivered_and_full_raw_sha_verified_unresolved')
        item=out['item_outcomes'][0]
        self.assertEqual(item['result_kind'],'delivered_and_full_raw_sha_verified')
        self.assertTrue(item['verified_furnished_originals'])
        self.assertEqual(item['verified_original_detail']['snapshot_original_raw_sha256'],
                         self.f.rev['snapshot_sha'])
        self.assertTrue(out['true_ec342_signed_fork_and_old_originals_replayed'])
        self.assertFalse(out['signed_offer_alone_proves_original_delivered'])
        self.assertEqual(out['exit_code'],2)

    def test_b_signed_unavailable_claim_is_not_absence(self):
        q=self.challenge('unpresented')
        self.response(q,receiver=1,kind=c.UNAVAILABLE)
        out=c.audit_disclosures(**self.kw())
        self.assertEqual(out['status'],'signed_unavailable_claim_unresolved')
        self.assertEqual(out['item_outcomes'][0]['result_kind'],'signed_unavailable_claim')
        self.assertFalse(out['signed_unavailable_claim_proves_global_absence'])

    def test_c_unanswered_request_is_reported_not_autofilled(self):
        self.challenge('unpresented')
        out=c.audit_disclosures(**self.kw())
        self.assertEqual(out['status'],'request_unanswered_unresolved')
        self.assertEqual(out['item_outcomes'][0]['unanswered_attempt_numbers'],[1])
        self.assertFalse(out['unanswered_request_proves_missing_original'])

    def test_d_two_distinct_receivers_contradict_and_no_winner(self):
        q=self.challenge('rev')
        self.response(q,receiver=0,kind=c.OFFER)
        self.response(q,receiver=1,kind=c.UNAVAILABLE)
        out=c.audit_disclosures(**self.kw(['rev']))
        self.assertEqual(out['status'],'two_receiver_conflicting_response_unresolved')
        row=out['item_outcomes'][0]
        self.assertTrue(row['verified_furnished_originals'])
        self.assertTrue(row['conflict_is_a_signed_claim_difference_not_fraud_or_global_absence'])
        self.assertFalse(out['two_receiver_disagreement_proves_fraud_or_selects_winner'])

    def test_e_signed_offer_without_raw_pair_stays_unverified(self):
        q=self.challenge('unpresented')
        self.response(q,kind=c.OFFER)
        out=c.audit_disclosures(**self.kw())
        self.assertEqual(out['status'],'signed_offer_but_originals_not_furnished_unresolved')
        self.assertEqual(out['verified_furnished_item_ids'],[])
        with self.assertRaises(Exception):
            c.audit_disclosures(**self.kw(['unpresented']))

    def test_f_three_attempts_are_bounded_sha_chained_and_ordered(self):
        q1=self.challenge('unpresented',issued='2026-10-25T13:21:00Z')
        q2=self.challenge('unpresented',attempt=2,previous=q1,
                          issued='2026-10-25T13:23:00Z')
        q3=self.challenge('unpresented',attempt=3,previous=q2,
                          issued='2026-10-25T13:26:00Z')
        self.response(q3,receiver=1,kind=c.UNAVAILABLE,
                      reported='2026-10-25T13:28:00Z')
        out=c.audit_disclosures(**self.kw())
        self.assertEqual(out['challenge_count'],3)
        self.assertEqual(out['item_outcomes'][0]['unanswered_attempt_numbers'],[1,2])
        self.assertEqual(out['item_outcomes'][0]['attempt_count'],3)
        with self.assertRaisesRegex(anchor.AnchorError,'ATTEMPT_NUMBER_OUT_OF_BOUNDS'):
            self.challenge('unpresented',attempt=4,previous=q3)

    def test_g_same_nonce_across_two_items_denied(self):
        self.challenge('rev',nonce='bb'*32)
        self.challenge('unpresented',nonce='bb'*32)
        with self.assertRaisesRegex(anchor.AnchorError,'CHALLENGE_NONCE_REUSED'):
            c.audit_disclosures(**self.kw())

    def test_h_noncontiguous_attempt_refused_and_ambiguous_attempt_refused(self):
        q1=self.challenge('rev')
        self.challenge('rev',attempt=2,previous=q1,
                       issued='2026-10-25T13:24:00Z')
        p=self.kw()
        p['challenge_files']=p['challenge_files'][1:]
        p['challenge_shas']=p['challenge_shas'][1:]
        with self.assertRaisesRegex(anchor.AnchorError,'CONTIGUOUS_ATTEMPTS'):
            c.audit_disclosures(**p)
        # Same item/attempt must never silently select the second branch.
        qx=self.challenge('rev',nonce='ce'*32)
        with self.assertRaisesRegex(anchor.AnchorError,'UNAMBIGUOUS'):
            c.audit_disclosures(**self.kw())

    def test_i_forged_signed_challenge_rejected(self):
        q=self.challenge()
        altered=copy.deepcopy(json.loads(Path(q[0]).read_text()))
        altered['claim']['challenge_nonce_sha256']='df'*32
        p=str(self.w/'fake-challenge.json')
        old_test.canonical(p,altered)
        args=self.kw()
        args['challenge_files']=[p];args['challenge_shas']=[old_test.sha(p)]
        with self.assertRaises(Exception):
            c.audit_disclosures(**args)

    def test_j_forged_signed_response_and_bad_sha_rejected(self):
        q=self.challenge()
        self.response(q,kind=c.UNAVAILABLE)
        altered=json.loads(Path(self.responses[0]).read_text())
        altered['claim']['response_kind']=c.OFFER
        p=str(self.w/'fake-response.json')
        old_test.canonical(p,altered)
        args=self.kw()
        args['response_files']=[p];args['response_shas']=[old_test.sha(p)]
        with self.assertRaises(Exception):
            c.audit_disclosures(**args)
        args=self.kw()
        args['response_shas']=['aa'*32]
        with self.assertRaises(Exception):
            c.audit_disclosures(**args)

    def test_k_wrong_signer_and_duplicate_receiver_vote_denied(self):
        q=self.challenge()
        with self.assertRaisesRegex(anchor.AnchorError,'ONLY_REGISTERED_EC343_RECEIVER'):
            c.sign_response(out=str(self.w/'wrong.json'),
                private_key_file=self.f.key_paths[0],roster_file=self.f.rfile,
                expected_roster_sha256=self.f.rsha,
                directory_file=self.directory_file,
                expected_directory_sha256=self.directory_sha,
                checkpoint_file=self.checkpoint_file,
                expected_checkpoint_sha256=self.checkpoint_sha,
                challenge_file=q[0],expected_challenge_sha256=q[1],
                response_kind=c.OFFER,response_nonce_sha256='91'*32,
                reported_utc='2026-10-25T13:22:00Z')
        self.response(q,receiver=0)
        self.response(q,receiver=0)
        with self.assertRaisesRegex(anchor.AnchorError,'ONE_RECEIVER_ONE_RESPONSE'):
            c.audit_disclosures(**self.kw())

    def test_l_response_replay_or_nonce_reuse_denied(self):
        q=self.challenge()
        self.response(q,receiver=0,nonce='fe'*32)
        self.response(q,receiver=1,nonce='fe'*32)
        with self.assertRaisesRegex(anchor.AnchorError,'NONCE_REUSED'):
            c.audit_disclosures(**self.kw())
        p=self.kw()
        p['response_files']=p['response_files'][:1]
        p['response_shas']=p['response_shas'][:1]
        p['challenge_shas']=['df'*32]
        with self.assertRaises(Exception):
            c.audit_disclosures(**p)

    def test_m_challenge_claimed_before_view_or_future_report_rejected(self):
        with self.assertRaisesRegex(anchor.AnchorError,'VIEW_CLAIM_TIME_AFTER'):
            self.challenge(issued='2026-10-25T13:15:00Z')
        q=self.challenge()
        self.response(q,reported='2026-10-25T14:15:00Z')
        with self.assertRaisesRegex(anchor.AnchorError,'RESPONSE_CLAIMED_UTC_AFTER'):
            c.audit_disclosures(**self.kw())

    def test_n_unsolicited_presented_item_is_never_verification(self):
        self.challenge('unpresented')
        with self.assertRaisesRegex(anchor.AnchorError,'CANNOT_VERIFY_UNSOLICITED'):
            c.audit_disclosures(**self.kw(['unpresented']))
        with self.assertRaisesRegex(anchor.AnchorError,'ONLY_BASELINE_CLAIMED'):
            c.audit_disclosures(**self.kw(['base']))

    def test_o_private_exclusive_output_and_challenge_role(self):
        q=self.challenge()
        self.assertEqual(stat.S_IMODE(os.stat(q[0]).st_mode),0o600)
        self.response(q)
        self.assertEqual(stat.S_IMODE(os.stat(self.responses[0]).st_mode),0o600)
        with self.assertRaises(Exception):
            c.sign_response(out=self.responses[0],
                private_key_file=self.f.key_paths[2],
                roster_file=self.f.rfile,expected_roster_sha256=self.f.rsha,
                directory_file=self.directory_file,
                expected_directory_sha256=self.directory_sha,
                checkpoint_file=self.checkpoint_file,
                expected_checkpoint_sha256=self.checkpoint_sha,
                challenge_file=q[0],expected_challenge_sha256=q[1],
                response_kind=c.OFFER,response_nonce_sha256='ef'*32,
                reported_utc='2026-10-25T13:23:00Z')

    def test_p_independently_signed_multitarget_summary_and_no_fabricated_files(self):
        q1=self.challenge('rev')
        q2=self.challenge('unpresented')
        self.response(q1,receiver=0,kind=c.OFFER)
        self.response(q2,receiver=1,kind=c.UNAVAILABLE)
        out=c.audit_disclosures(**self.kw(['rev']))
        self.assertEqual(out['challenge_count'],2)
        self.assertEqual(out['outcome_counts']['delivered_and_full_raw_sha_verified'],1)
        self.assertEqual(out['outcome_counts']['signed_unavailable_claim'],1)
        self.assertEqual([x['item_id'] for x in out['item_outcomes']],
                         ['rev','unpresented'])

    def test_r_second_attempt_cannot_change_its_signed_target_or_audience(self):
        original=self.challenge('rev')
        with self.assertRaisesRegex(anchor.AnchorError,'PREDECESSOR_SEQUENCE_AND_CONTEXT'):
            self.challenge('unpresented',attempt=2,previous=original,
                           issued='2026-10-25T13:24:00Z')
        with self.assertRaisesRegex(anchor.AnchorError,'REGISTERED_CHALLENGE_RECEIVERS'):
            self.challenge('rev',attempt=2,previous=original,
                           issued='2026-10-25T13:24:00Z',
                           audience_receiver_ids=[self.f.actors[3]['signer_id'],
                                                  self.f.actors[2]['signer_id']])

    def test_s_receiver_cannot_sign_challenge_and_response_cannot_fill_missing_path(self):
        with self.assertRaisesRegex(anchor.AnchorError,'ONLY_EC343_CHANGE_PROPOSER'):
            self.challenge(private_key_file=self.f.key_paths[2])
        q=self.challenge('unpresented')
        target=self.records[-1]['snapshot_file']
        with self.assertRaisesRegex(anchor.AnchorError,'RESPONSE_OUTPUT_MUST_NOT_ALIAS_TARGET'):
            self.response(q,out=target)
        self.assertFalse(Path(target).exists())

    def test_t_standalone_cli_can_issue_an_actual_signed_challenge(self):
        qfile=str(self.w/'standalone.json')
        argv=[sys.executable,'-I','-B',
              str(ROOT/'scripts/ces_cas_disclosure_challenge.py'),'issue-challenge',
              '--out',qfile,'--private-key-file',self.f.key_paths[0],
              '--roster-file',self.f.rfile,'--expected-roster-sha256',self.f.rsha,
              '--directory-file',self.directory_file,
              '--expected-directory-sha256',self.directory_sha,
              '--checkpoint-file',self.checkpoint_file,
              '--expected-checkpoint-sha256',self.checkpoint_sha,
              '--anchor-item-id','base','--item-id','rev',
              '--attempt-number','1','--challenge-nonce-sha256','a4'*32,
              '--issued-utc','2026-10-25T13:21:00Z',
              '--baseline-presented-item-id','base']
        for view,sha in zip(self.views,self.view_shas,strict=True):
            argv.extend(['--view-file',view,'--expected-view-sha256',sha])
        for actor in self.f.actors[2:]:
            argv.extend(['--audience-receiver-id',actor['signer_id']])
        p=subprocess.run(argv,capture_output=True,text=True,timeout=90)
        self.assertEqual(p.returncode,2,p.stdout[-700:]+p.stderr[-600:])
        self.assertTrue(Path(qfile).is_file())
        self.assertEqual(json.loads(p.stdout)['candidate_original_raw_sha256'],
                         old_test.sha(qfile))

    def test_q_fixed_unified_route_readonly_and_exact_originals(self):
        q=self.challenge()
        self.response(q,receiver=0,kind=c.OFFER)
        args=self.kw(['rev'])
        cmd=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_next.py'),
             'audit-disclosure-gaps','DeliveryAudit','AuditSignedDisclosureChallenges']
        arrays={
            'view_files':'--view-file','view_shas':'--expected-view-sha256',
            'presented_item_ids':'--presented-item-id',
            'challenge_files':'--challenge-file',
            'challenge_shas':'--expected-challenge-sha256',
            'response_files':'--response-file',
            'response_shas':'--expected-response-sha256',
            'disclosed_item_ids':'--disclosed-item-id'}
        for k,x in args.items():
            if k in arrays:
                for value in x:cmd.extend([arrays[k],str(value)])
            else:
                cmd.extend(['--'+k.replace('_','-'),str(x)])
        run=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
        self.assertEqual(run.returncode,2,run.stdout[-1500:]+run.stderr[-500:])
        out=json.loads(run.stdout)
        self.assertEqual(out['status'],'delivered_and_full_raw_sha_verified_unresolved')
        self.assertTrue(out['true_ec342_signed_fork_and_old_originals_replayed'])
        self.assertFalse(out['remote_cas_worm_provider_freeze_release_or_write_executed'])

if __name__=='__main__':
    unittest.main()
