#!/usr/bin/env python3
"""EC300 real inherited original EC294--299 Ed25519/HMAC/AF_UNIX fixtures.

Only the parent Provider/Inbox responses are simulated. Independent people,
site custody, unpredictable externally issued challenges and remote delivery
are NOT tested or claimed.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from cryptography.hazmat.primitives import serialization
from delivery_anchor import anchor as a
from delivery_anchor import operator as storage
from witness_consistency.test_witness import EC299WitnessCases
from . import gossip as g, operator as op

ROOT = Path(__file__).resolve().parents[2]


class EC300GossipCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        EC299WitnessCases.setUpClass()
        cls.parent = EC299WitnessCases
        cls.root = cls.parent.root
        try:
            cls.manifest1 = cls.put('manifest1', cls.parent.manifest(
                [cls.parent.a1],[cls.parent.b1]),limit=200_000)
            cls.manifest2 = cls.put('manifest2', cls.parent.manifest(
                [cls.parent.a1,cls.parent.a2],[cls.parent.b1]),limit=200_000)
            cls.manifest_both = cls.put('manifest-both', cls.parent.manifest(
                [cls.parent.a1,cls.parent.a2],
                [cls.parent.b1,cls.parent.b_extended]),limit=200_000)
            cls.manifest_fork = cls.put('manifest-fork',cls.parent.manifest(
                [cls.parent.a1,cls.parent.a2],[cls.parent.b_fork]),limit=200_000)
            cls.session1, cls.s1 = cls.create_session('first',cls.manifest1,
                cls.parent.a1['sha'],cls.parent.b1['sha'],sequence=1,
                challenge='1'*64)
            cls.history1 = cls.put('history1',cls.make_history([
                cls.entry(cls.s1,cls.session1,cls.manifest1,
                          cls.parent.a1['sha'],cls.parent.b1['sha'])]))
            cls.session2, cls.s2 = cls.create_session('second',cls.manifest2,
                cls.parent.a2['sha'],cls.parent.b1['sha'],sequence=2,
                challenge='2'*64,prior=cls.history1,previous=cls.s1)
            cls.history2 = cls.put('history2', cls.make_history([
                cls.entry(cls.s1,cls.session1,cls.manifest1,
                          cls.parent.a1['sha'],cls.parent.b1['sha']),
                cls.entry(cls.s2,cls.session2,cls.manifest2,
                          cls.parent.a2['sha'],cls.parent.b1['sha'])]))
        except BaseException:
            EC299WitnessCases.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        EC299WitnessCases.tearDownClass()

    @classmethod
    def put(cls,name,doc,limit=g.MAX_HISTORY_BYTES):
        path=str(cls.root/('300-'+name+'.json'))
        storage.store(path,doc,limit)
        return path

    @classmethod
    def pins(cls,a_tip=None,b_tip=None):
        p=cls.parent
        return dict(a_id=p.id_a,a_public_hex=p.pub_a,
                    a_tip=a_tip or p.a2['sha'],
                    b_id=p.id_b,b_public_hex=p.pub_b,
                    b_tip=b_tip or p.b1['sha'])

    @classmethod
    def build(cls,path,a_tip,b_tip,sequence,challenge,prior=None,previous=None):
        return g.build_next_claim(witness_manifest_file=path,
            sequence=sequence,independent_challenge_sha256=challenge,
            prior_history_file=prior,
            expected_previous_session_sha256=previous,
            **cls.pins(a_tip,b_tip))

    @classmethod
    def signed(cls,claim):
        return {'schema':g.SESSION_SCHEMA,'claim':claim,
                'vote_a':g.sign_vote(claim,'a',cls.parent.key_a),
                'vote_b':g.sign_vote(claim,'b',cls.parent.key_b)}

    @classmethod
    def create_session(cls,name,manifest,a_tip,b_tip,*,sequence,challenge,prior=None,previous=None):
        claim=cls.build(manifest,a_tip,b_tip,sequence,challenge,prior,previous)
        doc=cls.signed(claim)
        p=cls.put(name+'-signed-session',doc,g.MAX_SESSION_BYTES)
        return doc,a.sha(doc)

    @classmethod
    def entry(cls,sha,session,manifest,a_tip,b_tip):
        # Caller generated session under a descriptive name but the SHA is
        # globally content addressed; use a stable temp file for history.
        path=cls.put('history-session-'+str(len(list(cls.root.glob('300-history-session-*.json')))),
                     session,g.MAX_SESSION_BYTES)
        return {'signed_session_file':path,
                'expected_session_sha256':sha,
                'witness_manifest_file':manifest,
                'expected_a_tip':a_tip,'expected_b_tip':b_tip}

    @classmethod
    def make_history(cls, entries):
        p=cls.parent
        return {'schema':g.HISTORY_SCHEMA,'a_id':p.id_a,
                'a_public_hex':p.pub_a,'b_id':p.id_b,
                'b_public_hex':p.pub_b,'sessions':entries}

    def full(self, file=None, session_tip=None, a_tip=None, b_tip=None):
        return g.verify_full_history(json.loads(Path(file or self.history2).read_text()),
            expected_session_tip=session_tip or self.s2,
            **self.pins(a_tip or self.parent.a2['sha'],b_tip))

    def common_cli(self,path,sequence,challenge,a_tip,b_tip,prior=None,previous=None):
        p=self.parent
        args=['--witness-manifest-file',path,'--sequence',str(sequence),
              '--independent-challenge-sha256',challenge,
              '--expected-a-id',p.id_a,'--expected-a-public-hex',p.pub_a,
              '--expected-a-tip',a_tip,'--expected-b-id',p.id_b,
              '--expected-b-public-hex',p.pub_b,'--expected-b-tip',b_tip]
        if prior is not None:
            args+=['--prior-history-file',prior,
                   '--expected-previous-session-sha256',previous]
        return args

    def verification_cli(self, mode='verify-history'):
        p=self.parent
        return [sys.executable,'-I','-B',str(ROOT/'scripts/ces_anchor_gossip.py'),mode,
            '--history-file',self.history2,
            '--expected-a-id',p.id_a,'--expected-a-public-hex',p.pub_a,
            '--expected-a-tip',p.a2['sha'],
            '--expected-b-id',p.id_b,'--expected-b-public-hex',p.pub_b,
            '--expected-b-tip',p.b1['sha'],
            '--expected-session-tip',self.s2]

    def console_cli(self,mode='VerifyGossip'):
        p=self.parent
        return [sys.executable,'-I','-B',str(ROOT/'scripts/ces_next.py'),
            'audit-gossip','DeliveryAudit',mode,
            '--history-file',self.history2,
            '--expected-a-id',p.id_a,'--expected-a-public-hex',p.pub_a,
            '--expected-a-tip',p.a2['sha'],
            '--expected-b-id',p.id_b,'--expected-b-public-hex',p.pub_b,
            '--expected-b-tip',p.b1['sha'],
            '--expected-session-tip',self.s2]

    def test_01_genuine_two_bilateral_sessions_and_full_crypto_replayed(self):
        report,claims=self.full()
        self.assertEqual(report['exit_code'],0)
        self.assertEqual(report['history_session_count'],2)
        self.assertTrue(report['all_ec294_to_ec299_original_evidence_replayed_each_session'])
        self.assertEqual(report['full_signed_bilateral_session_sha256_chain'],[self.s1,self.s2])
        self.assertEqual(claims[1]['previous_session_sha256'],self.s1)
        self.assertEqual(claims[0]['a']['signed_observation_sha256_chain'],[self.parent.a1['sha']])

    def test_02_signature_input_binds_entire_original_comparison(self):
        report,claims=self.full()
        self.assertEqual(claims[-1]['comparison_report_sha256'],
                         report['fully_recomputed_original_ec299_comparison_sha256_per_session'][-1])
        self.assertNotIn(str(self.root),json.dumps(report))

    def test_03_cross_role_vote_swapping_is_forbidden(self):
        changed=copy.deepcopy(self.session1)
        changed['vote_a']=changed['vote_b']
        with self.assertRaisesRegex(a.AnchorError,'VOTE_ROLE_SIGNER'):
            g.verify_session(changed,expected_sha256=a.sha(changed),
                             rebuilt_claim=self.session1['claim'])

    def test_04_signature_bytes_tampering_even_with_new_file_sha_fails(self):
        changed=copy.deepcopy(self.session1)
        changed['vote_a']['signature_ed25519']='f'*128
        with self.assertRaisesRegex(a.AnchorError,'ED25519_BILATERAL_SIGNATURE'):
            g.verify_session(changed,expected_sha256=a.sha(changed),
                             rebuilt_claim=self.session1['claim'])

    def test_05_pinned_session_tip_rejects_disk_rollback(self):
        h=self.make_history([self.entry(self.s1,self.session1,self.manifest1,
                            self.parent.a1['sha'],self.parent.b1['sha'])])
        with self.assertRaisesRegex(a.AnchorError,'LATEST_SESSION'):
            g.verify_full_history(h,expected_session_tip=self.s2,
                **self.pins(self.parent.a1['sha'],self.parent.b1['sha']))

    def test_06_witness_late_observation_replacement_denied(self):
        with self.assertRaisesRegex(a.AnchorError,'NEW_SESSION_MUST_CONTAIN'):
            self.build(self.manifest1,self.parent.a1['sha'],
                self.parent.b1['sha'],2,'5'*64,self.history1,self.s1)

    def test_07_signed_receipt_chain_cannot_shrink(self):
        with self.assertRaisesRegex(a.AnchorError,'WITNESS_RECEIPT_HISTORY_ROLLBACK'):
            self.build(self.manifest1,self.parent.a1['sha'],
                self.parent.b1['sha'],3,'6'*64,self.history2,self.s2)

    def test_08_repeated_external_challenge_denied_as_session_progress(self):
        with self.assertRaisesRegex(a.AnchorError,'CHALLENGE_WAS_PREVIOUSLY_SIGNED'):
            self.build(self.manifest_both,self.parent.a2['sha'],
                self.parent.b_extended['sha'],3,'1'*64,self.history2,self.s2)

    def test_09_missing_previous_full_history_rejected(self):
        with self.assertRaisesRegex(a.AnchorError,'REQUIRES_FULL_PREVIOUS_HISTORY'):
            self.build(self.manifest2,self.parent.a2['sha'],
                self.parent.b1['sha'],2,'9'*64,None,None)

    def test_10_wrong_prior_history_tip_not_silently_derived(self):
        with self.assertRaisesRegex(a.AnchorError,'LATEST_SESSION'):
            self.build(self.manifest2,self.parent.a2['sha'],
                self.parent.b1['sha'],2,'9'*64,self.history1,'f'*64)

    def test_11_external_ec299_receipt_tip_tamper_fails(self):
        h=json.loads(Path(self.history2).read_text())
        h['sessions'][-1]['expected_a_tip']='f'*64
        with self.assertRaisesRegex(a.AnchorError,'CHAIN_TIP_MISMATCH'):
            g.verify_full_history(h,expected_session_tip=self.s2,
                **self.pins(a_tip='f'*64))

    def test_12_original_signed_evidence_drift_denied(self):
        forged=json.loads(Path(self.manifest2).read_text())
        forged['b']['observations'][0]['expected_latest_tip']='f'*64
        path=self.put('bad-ec299-witness-manifest',forged,200_000)
        h=json.loads(Path(self.history2).read_text())
        h['sessions'][1]['witness_manifest_file']=path
        with self.assertRaises(a.AnchorError):
            g.verify_full_history(h,expected_session_tip=self.s2,
                                  **self.pins())

    def test_13_reorder_sessions_is_not_signed_continuity(self):
        h=json.loads(Path(self.history2).read_text())
        h['sessions'].reverse()
        with self.assertRaises(a.AnchorError):
            g.verify_full_history(h,expected_session_tip=self.s1,
                **self.pins(self.parent.a1['sha']))

    def test_14_missing_prior_session_is_not_valid_renumbering(self):
        h=json.loads(Path(self.history2).read_text())
        h['sessions'].pop(0)
        with self.assertRaisesRegex(a.AnchorError,'NOT_EQUAL_FULLY_REPLAYED'):
            g.verify_full_history(h,expected_session_tip=self.s2,**self.pins())

    def test_15_one_key_cannot_impersonate_other_signing_role(self):
        c=self.session1['claim']
        false=g.sign_vote(c,'b',self.parent.key_a)
        with self.assertRaisesRegex(a.AnchorError,'ED25519_BILATERAL_SIGNATURE'):
            g.verify_vote(false,c,'b')

    def test_16_genesis_session_cannot_claim_already_spent_previous(self):
        with self.assertRaisesRegex(a.AnchorError,'GENESIS_MUST_NOT'):
            self.build(self.manifest1,self.parent.a1['sha'],
                self.parent.b1['sha'],1,'a'*64,self.history1,self.s1)

    def test_17_original_signed_four_vote_fork_propagated_not_green(self):
        session,sha=self.create_session('fork',self.manifest_fork,
            self.parent.a2['sha'],self.parent.b_fork['sha'],
            sequence=1,challenge='b'*64)
        h=self.make_history([self.entry(sha,session,self.manifest_fork,
                self.parent.a2['sha'],self.parent.b_fork['sha'])])
        report,_=g.verify_full_history(h,expected_session_tip=sha,
                **self.pins(self.parent.a2['sha'],self.parent.b_fork['sha']))
        self.assertEqual(report['exit_code'],2)
        self.assertTrue(report['ever_observed_signed_competing_evidence'])
        self.assertIn('signed_competing_evidence',report['status'])

    def test_18_private_report_exclusive_and_exact_replay(self):
        target=str(self.root/'300-private-report.json')
        kwargs=dict(history_file=self.history2,
                    expected_session_tip=self.s2,**self.pins())
        report=op.verify(**{**kwargs,'out':target})
        self.assertEqual(os.stat(target).st_mode & 0o077,0)
        self.assertEqual(report,op.verify(**{**kwargs,
            'old_report_file':target,'expected_report_sha256':a.sha(report)}))
        with self.assertRaisesRegex(a.AnchorError,'EXCLUSIVE_OUTPUT'):
            op.verify(**{**kwargs,'out':target})

    def test_19_self_hashed_forged_report_semantic_upgrade_rejected(self):
        report,_=self.full()
        fake=copy.deepcopy(report)
        fake['physical_independent_humans_or_off_host_worm_proven']=True
        path=self.put('untrusted-report',fake,g.MAX_REPORT_BYTES)
        with self.assertRaisesRegex(a.AnchorError,'NOT_EQUAL_RECOMPUTED'):
            op.verify(history_file=self.history2,expected_session_tip=self.s2,
                old_report_file=path,expected_report_sha256=a.sha(fake),
                **self.pins())

    def test_20_cli_prepare_sign_assemble_genuine_dual_key_vote(self):
        p=self.parent
        pref=str(self.root/'300-operator-prepare.json')
        votesa=str(self.root/'300-operator-votea.json')
        votesb=str(self.root/'300-operator-voteb.json')
        output=str(self.root/'300-operator-session.json')
        script=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_anchor_gossip.py')]
        common=self.common_cli(self.manifest2,2,'f'*64,p.a2['sha'],
                               p.b1['sha'],self.history1,self.s1)
        def run(args):
            out=subprocess.run(script+args,capture_output=True,text=True,timeout=240)
            self.assertEqual(out.returncode,0,out.stdout+out.stderr)
            return json.loads(out.stdout)
        draft=run(['prepare-session',*common,'--out',pref])
        keys=[]
        for role,key,target in (('a',p.key_a,votesa),('b',p.key_b,votesb)):
            path=str(self.root/('300-operator-'+role+'-private.key'))
            with open(path,'xb') as out:
                out.write(key.private_bytes(encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()))
            os.chmod(path,0o600)
            keys.append(run(['sign-session',*common,
                '--proposal-file',pref,'--expected-proposal-sha256',draft['proposal_sha256'],
                '--role',role,'--private-key-file',path,'--out',target]))
        assembled=run(['assemble-session',*common,
            '--proposal-file',pref,'--expected-proposal-sha256',draft['proposal_sha256'],
            '--vote-a-file',votesa,'--expected-vote-a-sha256',keys[0]['vote_sha256'],
            '--vote-b-file',votesb,'--expected-vote-b-sha256',keys[1]['vote_sha256'],
            '--out',output])
        self.assertEqual(assembled['comparison_status'],
                         'supplied_signed_witness_observations_compatible')
        actual=json.loads(Path(output).read_text())
        self.assertEqual(assembled['signed_session_sha256'],a.sha(actual))
        self.assertEqual(os.stat(output).st_mode & 0o077,0)
        with self.assertRaisesRegex(a.AnchorError,'EXCLUSIVE_OUTPUT'):
            storage.store(output,actual,g.MAX_SESSION_BYTES)

    def test_21_cli_verify_and_independent_report_sha(self):
        cmd=self.verification_cli()
        got=subprocess.run(cmd,capture_output=True,text=True,timeout=240)
        self.assertEqual(got.returncode,0,got.stdout+got.stderr)
        report=json.loads(got.stdout)['report']
        report_path=self.put('report-for-cli',report,g.MAX_REPORT_BYTES)
        report_sha=a.sha(report)
        validated=subprocess.run(self.verification_cli('verify-report')+[
            '--report-file',report_path,'--expected-report-sha256',report_sha],
            capture_output=True,text=True,timeout=240)
        self.assertEqual(validated.returncode,0,validated.stdout+validated.stderr)
        self.assertTrue(json.loads(validated.stdout)['reverified_against_independently_pinned_report_sha256'])

    def test_22_console_only_exact_readonly_and_router_not_extended(self):
        okay=subprocess.run(self.console_cli(),capture_output=True,text=True,timeout=240)
        self.assertEqual(okay.returncode,0,okay.stdout+okay.stderr)
        self.assertEqual(json.loads(okay.stdout)['schema'],g.RESULT_SCHEMA)
        denied=subprocess.run(self.console_cli('Sign'),capture_output=True,text=True,timeout=20)
        self.assertEqual(denied.returncode,3,denied.stdout)
        console=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_next.py')]
        routes=subprocess.run(console+['routes','--kind','all'],
                              capture_output=True,text=True,timeout=30)
        self.assertEqual(routes.returncode,0,routes.stdout+routes.stderr)
        registry=json.loads(routes.stdout)
        self.assertEqual(registry['route_count'],74)
        self.assertEqual(sum(x['route_kind']=='HOST_REQUIRED' for x in registry['routes']),11)
        self.assertEqual(registry['version'],'V6.10')
        doc=subprocess.run(console+['doctor'],capture_output=True,text=True,timeout=30)
        self.assertEqual(doc.returncode,0,doc.stdout+doc.stderr)
        status=json.loads(doc.stdout)
        self.assertTrue(status['ec300_offline_two_witness_bilateral_gossip_present'])
        self.assertFalse(status['ec300_real_custody_freshness_or_global_anti_rollback_proven'])

    def test_23_real_provider_status_was_not_queried_by_new_module(self):
        parent=self.parent.parent
        old=parent.x.base.parent.parent.statusport.lookups
        self.full()
        self.assertEqual(old,parent.x.base.parent.parent.statusport.lookups)

    def test_24_precise_input_shapes_no_extra_authority_fields(self):
        h=json.loads(Path(self.history2).read_text())
        h['may_write_provider']=True
        with self.assertRaisesRegex(a.AnchorError,'HISTORY_FIELDS_INVALID'):
            g.verify_full_history(h,expected_session_tip=self.s2,**self.pins())
        h=json.loads(Path(self.history2).read_text())
        h['sessions'][0]['override_policy']=True
        with self.assertRaisesRegex(a.AnchorError,'HISTORY_ENTRY_FIELDS_INVALID'):
            g.verify_full_history(h,expected_session_tip=self.s2,**self.pins())


    def test_25_three_consecutive_real_signed_sessions_are_supported(self):
        p=self.parent
        claim=self.build(self.manifest_both,p.a2['sha'],p.b_extended['sha'],
                         3,'3'*64,self.history2,self.s2)
        signed=self.signed(claim)
        history=json.loads(Path(self.history2).read_text())
        sha=a.sha(signed)
        history['sessions'].append(self.entry(sha,signed,self.manifest_both,
                                              p.a2['sha'],p.b_extended['sha']))
        report,claims=g.verify_full_history(history,
            expected_session_tip=sha,
            **self.pins(p.a2['sha'],p.b_extended['sha']))
        self.assertEqual(report['exit_code'],0)
        self.assertEqual(report['history_session_count'],3)
        self.assertEqual(claims[-1]['previous_session_sha256'],self.s2)
        self.assertEqual(report['witness_b']['verified_observation_receipt_sha256_chain'],
                         [p.b1['sha'],p.b_extended['sha']])

    def test_26_signed_claim_cannot_exploit_boolean_integer_json_equality(self):
        wrong=copy.deepcopy(self.session1)
        wrong['claim']['sequence']=True  # Python True == 1, but canonical differs
        wrong['vote_a']=g.sign_vote(wrong['claim'],'a',self.parent.key_a)
        wrong['vote_b']=g.sign_vote(wrong['claim'],'b',self.parent.key_b)
        with self.assertRaisesRegex(a.AnchorError,'NOT_EQUAL_FULLY_REPLAYED'):
            g.verify_session(wrong, expected_sha256=a.sha(wrong),
                             rebuilt_claim=self.session1['claim'])

    def test_27_report_exactness_rejects_true_instead_of_integer_one(self):
        real=op.verify(history_file=self.history1,
            expected_session_tip=self.s1,
            **self.pins(self.parent.a1['sha'],self.parent.b1['sha']))
        altered=copy.deepcopy(real)
        altered['history_session_count']=True  # True == 1 must NOT allow semantic mutation
        forged=self.put('boolean-report-forgery',altered,g.MAX_REPORT_BYTES)
        with self.assertRaisesRegex(a.AnchorError,'NOT_EQUAL_RECOMPUTED'):
            op.verify(history_file=self.history1,expected_session_tip=self.s1,
                      old_report_file=forged,expected_report_sha256=a.sha(altered),
                      **self.pins(self.parent.a1['sha'],self.parent.b1['sha']))


if __name__ == '__main__':
    unittest.main()
