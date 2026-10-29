#!/usr/bin/env python3
"""EC301: inherited genuine EC294--300 local signed source, never real remote sites."""
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
from bilateral_gossip.test_gossip import EC300GossipCases
from . import handoff as h, operator as op

ROOT=Path(__file__).resolve().parents[2]


class EC301HandoffCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        EC300GossipCases.setUpClass()
        cls.parent=EC300GossipCases
        cls.keys=cls.parent.parent
        cls.root=cls.parent.root
        try:
            cls.c1=h.build_next_claim(history_file=cls.parent.history1,
                a_tip=cls.keys.a1['sha'],b_tip=cls.keys.b1['sha'],
                session_tip=cls.parent.s1,sequence=1,sender_role='a',
                exchange_challenge_sha256='3'*64,**cls.ids())
            cls.o1=h.make_offer(cls.c1,cls.keys.key_a)
            cls.r1=h.make_receipt(cls.o1,cls.keys.key_b)
            cls.sr1=a.sha(cls.r1)
            cls.r1_path=cls.put('receipt-one',cls.r1,h.MAX_RECEIPT_BYTES)
            cls.journal1=cls.put('journal-one',cls.journal([cls.entry(
                cls.r1_path,cls.sr1,cls.parent.history1,
                cls.keys.a1['sha'],cls.keys.b1['sha'],cls.parent.s1)]),
                h.MAX_JOURNAL_BYTES)
            cls.c2=h.build_next_claim(history_file=cls.parent.history2,
                a_tip=cls.keys.a2['sha'],b_tip=cls.keys.b1['sha'],
                session_tip=cls.parent.s2,sequence=2,sender_role='b',
                exchange_challenge_sha256='4'*64,
                prior_journal_file=cls.journal1,
                expected_previous_receipt_sha256=cls.sr1,
                expected_prior_a_tip=cls.keys.a1['sha'],
                expected_prior_b_tip=cls.keys.b1['sha'],
                expected_prior_session_tip=cls.parent.s1,**cls.ids())
            cls.o2=h.make_offer(cls.c2,cls.keys.key_b)
            cls.r2=h.make_receipt(cls.o2,cls.keys.key_a)
            cls.sr2=a.sha(cls.r2)
            cls.r2_path=cls.put('receipt-two',cls.r2,h.MAX_RECEIPT_BYTES)
            cls.journal2=cls.put('journal-two',cls.journal([
                cls.entry(cls.r1_path,cls.sr1,cls.parent.history1,
                          cls.keys.a1['sha'],cls.keys.b1['sha'],cls.parent.s1),
                cls.entry(cls.r2_path,cls.sr2,cls.parent.history2,
                          cls.keys.a2['sha'],cls.keys.b1['sha'],cls.parent.s2)]),
                h.MAX_JOURNAL_BYTES)
        except BaseException:
            EC300GossipCases.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        EC300GossipCases.tearDownClass()

    @classmethod
    def ids(cls):
        k=cls.keys
        return {'a_id':k.id_a,'a_public_hex':k.pub_a,
                'b_id':k.id_b,'b_public_hex':k.pub_b}

    @classmethod
    def put(cls,name,obj,limit=h.MAX_JOURNAL_BYTES):
        path=str(cls.root/('301-'+name+'.json'))
        storage.store(path,obj,limit)
        return path

    @classmethod
    def entry(cls,receipt_file,receipt_sha,history_file,a_tip,b_tip,session_tip):
        return {'signed_receipt_file':receipt_file,
                'expected_receipt_sha256':receipt_sha,
                'ec300_history_file':history_file,
                'expected_a_tip':a_tip,'expected_b_tip':b_tip,
                'expected_session_tip':session_tip}

    @classmethod
    def journal(cls,entries):
        return {'schema':h.JOURNAL_SCHEMA,
                'a_id':cls.keys.id_a,'a_public_hex':cls.keys.pub_a,
                'b_id':cls.keys.id_b,'b_public_hex':cls.keys.pub_b,
                'entries':entries}

    def verify(self,file=None,**overrides):
        params={'a_tip':self.keys.a2['sha'],'b_tip':self.keys.b1['sha'],
                'session_tip':self.parent.s2,'receipt_tip':self.sr2,**self.ids()}
        params.update(overrides)
        return h.verify_journal(json.loads(Path(file or self.journal2).read_text()),**params)

    def new_params(self,sequence=2,history=None,**overrides):
        params=dict(history_file=history or self.parent.history2,
            a_tip=self.keys.a2['sha'],b_tip=self.keys.b1['sha'],
            session_tip=self.parent.s2,sequence=sequence,
            sender_role='b',exchange_challenge_sha256='5'*64,
            prior_journal_file=self.journal1,
            expected_previous_receipt_sha256=self.sr1,
            expected_prior_a_tip=self.keys.a1['sha'],
            expected_prior_b_tip=self.keys.b1['sha'],
            expected_prior_session_tip=self.parent.s1,**self.ids())
        params.update(overrides)
        return params

    def cli_pins(self,a_tip=None,session_tip=None):
        k=self.keys
        return ['--expected-a-id',k.id_a,
          '--expected-a-public-hex',k.pub_a,
          '--expected-a-tip',a_tip or k.a2['sha'],
          '--expected-b-id',k.id_b,'--expected-b-public-hex',k.pub_b,
          '--expected-b-tip',k.b1['sha'],
          '--expected-session-tip',session_tip or self.parent.s2]

    def test_01_real_original_history_two_way_sender_recipient_ack(self):
        report,claims=self.verify()
        self.assertEqual(report['exit_code'],0)
        self.assertEqual(report['handoff_count'],2)
        self.assertEqual(report['sender_roles_in_order'],['a','b'])
        self.assertEqual(report['signed_receipt_sha256_chain'],[self.sr1,self.sr2])
        self.assertEqual(claims[1]['previous_receipt_sha256'],self.sr1)
        self.assertTrue(report['all_original_ec294_through_ec300_sources_reverified_per_handoff'])
        self.assertFalse(report['real_two_site_handoff_or_human_independence_proven'])

    def test_02_sender_must_sign_claim_with_own_role_key(self):
        swapped=h.make_offer(self.c1,self.keys.key_b)
        with self.assertRaisesRegex(a.AnchorError,'ED25519_SENDER_OR_RECIPIENT'):
            h.verify_offer(swapped,self.c1)

    def test_03_recipient_must_sign_exact_sender_offer(self):
        wrong=h.make_receipt(self.o1,self.keys.key_a)
        with self.assertRaisesRegex(a.AnchorError,'ED25519_SENDER_OR_RECIPIENT'):
            h.verify_receipt(wrong,rebuilt_claim=self.c1,
                             expected_receipt_sha256=a.sha(wrong))

    def test_04_sender_signature_tampering_denied(self):
        changed=copy.deepcopy(self.r1)
        changed['offer']['sender_signature_ed25519']='f'*128
        with self.assertRaisesRegex(a.AnchorError,'ED25519_SENDER_OR_RECIPIENT'):
            h.verify_receipt(changed,rebuilt_claim=self.c1,
                             expected_receipt_sha256=a.sha(changed))

    def test_05_recipient_acknowledgment_mutation_denied(self):
        changed=copy.deepcopy(self.r2)
        changed['recipient_signature_ed25519']='f'*128
        with self.assertRaisesRegex(a.AnchorError,'ED25519_SENDER_OR_RECIPIENT'):
            h.verify_receipt(changed,rebuilt_claim=self.c2,
                             expected_receipt_sha256=a.sha(changed))

    def test_06_external_latest_receipt_sha_does_not_silently_rollback(self):
        with self.assertRaisesRegex(a.AnchorError,'FOUR_INDEPENDENT_LATEST'):
            self.verify(receipt_tip=self.sr1)
        with self.assertRaisesRegex(a.AnchorError,'FOUR_INDEPENDENT_LATEST'):
            self.verify(session_tip=self.parent.s1)

    def test_07_single_receipt_cannot_replace_two_receipt_journal(self):
        with self.assertRaisesRegex(a.AnchorError,'FOUR_INDEPENDENT_LATEST'):
            self.verify(file=self.journal1)

    def test_08_duplicate_signed_ec300_session_not_valid_progress(self):
        with self.assertRaisesRegex(a.AnchorError,'STRICTLY_EXTENDED'):
            h.build_next_claim(**self.new_params(history=self.parent.history1,
                a_tip=self.keys.a1['sha'],session_tip=self.parent.s1))

    def test_09_reusing_exchange_challenge_denied(self):
        with self.assertRaisesRegex(a.AnchorError,'NEW_CHALLENGE_ALREADY_USED'):
            h.build_next_claim(**self.new_params(exchange_challenge_sha256='3'*64))

    def test_10_prior_journal_requires_external_pins_no_autodiscovery(self):
        with self.assertRaisesRegex(a.AnchorError,'FOUR_EXTERNAL_PINS'):
            h.build_next_claim(**self.new_params(expected_prior_a_tip=None))
        with self.assertRaisesRegex(a.AnchorError,'FOUR_INDEPENDENT_LATEST'):
            h.build_next_claim(**self.new_params(expected_previous_receipt_sha256='f'*64))

    def test_11_missing_previous_receipts_or_reorder_denied(self):
        changed=self.journal([self.entry(self.r2_path,self.sr2,
            self.parent.history2,self.keys.a2['sha'],
            self.keys.b1['sha'],self.parent.s2)])
        with self.assertRaises(a.AnchorError):
            h.verify_journal(changed,a_tip=self.keys.a2['sha'],
                b_tip=self.keys.b1['sha'],session_tip=self.parent.s2,
                receipt_tip=self.sr2,**self.ids())
        changed=json.loads(Path(self.journal2).read_text());changed['entries'].reverse()
        with self.assertRaises(a.AnchorError):
            h.verify_journal(changed,a_tip=self.keys.a1['sha'],
                b_tip=self.keys.b1['sha'],session_tip=self.parent.s1,
                receipt_tip=self.sr1,**self.ids())

    def test_12_tamper_ec300_signatures_rejected_on_handoff_replay(self):
        changed=json.loads(Path(self.parent.history2).read_text())
        session=json.loads(Path(changed['sessions'][1]['signed_session_file']).read_text())
        session['vote_b']['signature_ed25519']='f'*128
        modified_session=self.put('tampered-ec300-session',session,h.MAX_RECEIPT_BYTES)
        changed['sessions'][1]['signed_session_file']=modified_session
        changed['sessions'][1]['expected_session_sha256']=a.sha(session)
        modified_history=self.put('tampered-ec300-history',changed,h.MAX_JOURNAL_BYTES)
        bad=json.loads(Path(self.journal2).read_text())
        bad['entries'][1]['ec300_history_file']=modified_history
        with self.assertRaises(a.AnchorError):
            h.verify_journal(bad,a_tip=self.keys.a2['sha'],
                b_tip=self.keys.b1['sha'],session_tip=self.parent.s2,
                receipt_tip=self.sr2,**self.ids())

    def test_13_no_extra_authority_or_business_write_fields(self):
        changed=copy.deepcopy(self.r1)
        changed['actual_site_custody_proven']=True
        with self.assertRaisesRegex(a.AnchorError,'RECEIPT_FIELDS_INVALID'):
            h.verify_receipt(changed,rebuilt_claim=self.c1,
                             expected_receipt_sha256=a.sha(changed))
        changed=copy.deepcopy(self.c1)
        changed['is_global_latest']=True
        with self.assertRaisesRegex(a.AnchorError,'CLAIM_FIELDS_INVALID'):
            h.verify_offer(h.make_offer(self.c1,self.keys.key_a) |
                {'claim':changed},changed)

    def test_14_forged_signed_report_with_new_self_digest_is_recomputed(self):
        report,_=self.verify()
        fake=copy.deepcopy(report)
        fake['real_two_site_handoff_or_human_independence_proven']=True
        path=self.put('fake-report',fake,h.MAX_REPORT_BYTES)
        with self.assertRaisesRegex(a.AnchorError,'NOT_EQUAL_RECOMPUTED'):
            op.verify(journal_file=self.journal2,
                a_tip=self.keys.a2['sha'],b_tip=self.keys.b1['sha'],
                session_tip=self.parent.s2,receipt_tip=self.sr2,
                old_report_file=path,expected_report_sha256=a.sha(fake),
                **self.ids())

    def test_15_report_private_exclusive_store_and_verify_report(self):
        path=str(self.root/'301-protected-report.json')
        params=dict(journal_file=self.journal2,
            a_tip=self.keys.a2['sha'],b_tip=self.keys.b1['sha'],
            session_tip=self.parent.s2,receipt_tip=self.sr2,**self.ids())
        report=op.verify(**params,out=path)
        self.assertEqual(os.stat(path).st_mode & 0o077,0)
        self.assertEqual(report,op.verify(**params,old_report_file=path,
                                         expected_report_sha256=a.sha(report)))
        with self.assertRaisesRegex(a.AnchorError,'EXCLUSIVE_OUTPUT'):
            op.verify(**params,out=path)

    def test_16_valid_signed_original_fork_returns_exit2_even_with_double_ack(self):
        parent=self.parent
        session,tip=parent.create_session('301-fork',parent.manifest_fork,
            self.keys.a2['sha'],self.keys.b_fork['sha'],
            sequence=1,challenge='8'*64)
        file=parent.put('301-fork-history',parent.make_history([
            parent.entry(tip,session,parent.manifest_fork,
                self.keys.a2['sha'],self.keys.b_fork['sha'])]))
        claim=h.build_next_claim(history_file=file,a_tip=self.keys.a2['sha'],
            b_tip=self.keys.b_fork['sha'],session_tip=tip,sequence=1,
            sender_role='b',exchange_challenge_sha256='9'*64,**self.ids())
        receipt=h.make_receipt(h.make_offer(claim,self.keys.key_b),self.keys.key_a)
        path=self.put('fork-receipt',receipt,h.MAX_RECEIPT_BYTES)
        journal=self.journal([self.entry(path,a.sha(receipt),file,
              self.keys.a2['sha'],self.keys.b_fork['sha'],tip)])
        result,_=h.verify_journal(journal,a_tip=self.keys.a2['sha'],
              b_tip=self.keys.b_fork['sha'],session_tip=tip,
              receipt_tip=a.sha(receipt),**self.ids())
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['historical_signed_competing_evidence_observed'])

    def test_17_reject_signing_with_unmatched_offline_key(self):
        other_key_path=str(self.root/'301-unrelated-private.key')
        other=self.keys.key_a
        with open(other_key_path,'xb') as f:
            f.write(other.private_bytes(encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()))
        os.chmod(other_key_path,0o600)
        with self.assertRaisesRegex(a.AnchorError,'PRIVATE_KEY_DOES_NOT_MATCH'):
            op._matching_key(other_key_path,self.keys.pub_b)

    def test_18_full_three_stage_cli_with_distinct_real_ed25519_keys(self):
        base=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_anchor_handoff.py')]
        common=['--history-file',self.parent.history2,*self.cli_pins(),
          '--sequence','2','--sender-role','b',
          '--exchange-challenge-sha256','a'*64,
          '--prior-journal-file',self.journal1,
          '--expected-previous-receipt-sha256',self.sr1,
          '--expected-prior-a-tip',self.keys.a1['sha'],
          '--expected-prior-b-tip',self.keys.b1['sha'],
          '--expected-prior-session-tip',self.parent.s1]
        draft_file=str(self.root/'301-cli-draft.json')
        offer_file=str(self.root/'301-cli-offer.json')
        receipt_file=str(self.root/'301-cli-receipt.json')
        def run(segments):
            process=subprocess.run(base+segments,capture_output=True,text=True,timeout=300)
            self.assertEqual(process.returncode,0,process.stdout+process.stderr)
            return json.loads(process.stdout)
        draft=run(['prepare-offer',*common,'--out',draft_file])
        private={}
        for role,key in (('a',self.keys.key_a),('b',self.keys.key_b)):
            name=str(self.root/('301-cli-'+role+'.key'))
            with open(name,'xb') as f:
                f.write(key.private_bytes(encoding=serialization.Encoding.Raw,
                  format=serialization.PrivateFormat.Raw,
                  encryption_algorithm=serialization.NoEncryption()))
            os.chmod(name,0o600)
            private[role]=name
        offer=run(['sign-offer',*common,'--draft-file',draft_file,
           '--expected-draft-sha256',draft['draft_sha256'],
           '--private-key-file',private['b'],'--out',offer_file])
        received=run(['accept-offer',*common,'--offer-file',offer_file,
           '--expected-offer-sha256',offer['signed_offer_sha256'],
           '--private-key-file',private['a'],'--out',receipt_file])
        self.assertTrue(received['signed_receipt_sha256'])
        self.assertEqual(received['historical_comparison_exit_code'],0)
        self.assertEqual(os.stat(receipt_file).st_mode & 0o077,0)
        self.assertEqual(a.sha(json.loads(Path(receipt_file).read_text())),
                         received['signed_receipt_sha256'])

    def test_19_cli_journal_and_report_with_external_sha(self):
        base=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_anchor_handoff.py')]
        pins=[*self.cli_pins(),'--journal-file',self.journal2,
              '--expected-receipt-tip',self.sr2]
        first=subprocess.run(base+['verify-journal',*pins],
            capture_output=True,text=True,timeout=300)
        self.assertEqual(first.returncode,0,first.stdout+first.stderr)
        report=json.loads(first.stdout)['report']
        name=self.put('cli-report',report,h.MAX_REPORT_BYTES)
        second=subprocess.run(base+['verify-report',*pins,
            '--report-file',name,'--expected-report-sha256',a.sha(report)],
            capture_output=True,text=True,timeout=300)
        self.assertEqual(second.returncode,0,second.stdout+second.stderr)
        self.assertTrue(json.loads(second.stdout)['report_reverified_against_independent_sha'])

    def test_20_unified_console_read_only_and_old_router_fixed(self):
        cmd=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_next.py')]
        args=['--journal-file',self.journal2,*self.cli_pins(),
              '--expected-receipt-tip',self.sr2]
        valid=subprocess.run(cmd+['audit-handoff','DeliveryAudit','VerifyHandoff',*args],
                  capture_output=True,text=True,timeout=300)
        self.assertEqual(valid.returncode,0,valid.stdout+valid.stderr)
        self.assertEqual(json.loads(valid.stdout)['schema'],h.RESULT_SCHEMA)
        denied=subprocess.run(cmd+['audit-handoff','DeliveryAudit','Sign',*args],
                  capture_output=True,text=True,timeout=30)
        self.assertEqual(denied.returncode,3,denied.stdout)
        routes=subprocess.run(cmd+['routes'],capture_output=True,text=True,timeout=30)
        self.assertEqual(routes.returncode,0,routes.stdout+routes.stderr)
        data=json.loads(routes.stdout)
        self.assertEqual(data['route_count'],74)
        self.assertEqual(sum(r['route_kind']=='HOST_REQUIRED' for r in data['routes']),11)
        self.assertEqual(data['version'],'1.0.0')
        doctor=subprocess.run(cmd+['doctor'],capture_output=True,text=True,timeout=30)
        self.assertEqual(doctor.returncode,0,doctor.stdout+doctor.stderr)
        self.assertTrue(json.loads(doctor.stdout)['offline_sender_receiver_handoff_client_present'])


if __name__=='__main__':unittest.main()
