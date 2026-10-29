#!/usr/bin/env python3
"""EC295 genuine EC294 signed host / original EC227 fixture; offline external pins.

No real Provider or Inbox: original EC294 fixture creates authentic local
Ed25519 signed synthetic status. Here tests verify portable/checkpoint behavior.
"""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec288_delivery_send_host import protocol as orig
from ec294_delivery_reconcile_host.test_host import EC294ReconcileCases
from . import anchor as a, operator as op


class EC295AnchorCases(unittest.TestCase):
    def setUp(self):
        self.parent=EC294ReconcileCases('test_01_record_original_ec227_real_append_and_original_ec226_read')
        self.parent.setUp()
        self.addCleanup(self.parent.doCleanups)
        self.keys={role:Ed25519PrivateKey.generate() for role in a.DOMAINS}
        self.pubs={role:orig.public_hex(key) for role,key in self.keys.items()}
        self.keyfiles={role:self.parent.base.write('295-'+role+'.key',key.private_bytes_raw())
                       for role,key in self.keys.items()}
        self.policyfile=str(self.parent.root/'295-policy.json')
        self.policysha=None
        self.checkpoints=[]
        self.outputs=[]

    def receipt(self, mode='record',head=a.GENESIS):
        grant,read=self.parent.grants(mode,head)
        rc,reply=self.parent.call(grant,read)
        self.assertEqual(rc,2,reply)
        self.assertTrue(reply['verified_server_signature'])
        ev={'schema':a.EVIDENCE_SCHEMA,'response':reply,
            'grant':json.loads(Path(grant).read_text()),
            'read_grant':json.loads(Path(read).read_text()) if read else None}
        return ev,grant,read

    def initialize(self):
        self.parent.send()
        self.parent.start()
        evidence,grant,read=self.receipt()
        operation=evidence['grant']['subject']['operation_id']
        job=evidence['grant']['subject']['job_sha256']
        result=op.create_policy(original_policy_file=self.parent.policyfile,
                 original_policy_sha256=self.parent.policysha,
                 operation_id=operation,job_sha256=job,
                 keeper_public_hex=self.pubs['keeper'],
                 witness_public_hex=self.pubs['witness'],out=self.policyfile)
        self.policysha=result['policy_sha256']
        self.policy=a.load_policy(self.policyfile,self.policysha)
        return evidence,grant,read

    def checkpoint(self,evidence,prev=None):
        claim=a.prepared_from_evidence(evidence,self.policy,self.policysha,prev)
        signatures={role+'_signature_ed25519':a.sign(role,claim['claim'],self.keys[role])
                    for role in a.DOMAINS}
        obj={'schema':a.CHECKPOINT_SCHEMA,'claim':claim['claim'],
             'evidence':claim['evidence'],**signatures}
        a.verify_checkpoint(obj,self.policy,self.policysha)
        self.checkpoints.append(obj)
        return obj

    def file(self,name,doc):
        path=str(self.parent.root/('295-'+name+'.json'))
        op.store(path,doc,57000)
        self.outputs.append(path)
        return path

    def test_01_original_ec294_signed_receipt_is_cryptographically_reconstructed(self):
        e,_,_=self.initialize()
        fields=a.verify_evidence(e,self.policy)
        self.assertEqual(fields['audit_event_count'],2)
        self.assertEqual(fields['ec294_operation_mode'],'record')
        self.assertEqual(fields['historical_delivery_state'],'UNKNOWN_UNCONFIRMED')
        self.assertEqual(self.parent.parent.statusport.lookups,1)

    def test_02_complete_two_witness_seal_and_external_tip_verification(self):
        e,_,_=self.initialize()
        cp=self.checkpoint(e)
        res=a.verify_chain([cp],self.policy,self.policysha,a.sha(cp))
        self.assertEqual(res['checkpoints_verified'],1)
        self.assertFalse(res['production_delivery_proven'])
        self.assertFalse(res['off_host_tip_actually_retained_or_immutable_proven'])
        self.assertEqual(self.parent.parent.statusport.lookups,1)

    def test_03_offline_operator_prepare_sign_assemble_and_verify_files(self):
        e,g,r=self.initialize()
        resp=self.file('response',e['response'])
        expected=op.prepare(policy_file=self.policyfile,policy_sha256=self.policysha,
            response_file=resp,grant_file=g,read_grant_file=r,
            previous_file=None,expected_previous_tip=None,
            out=str(self.parent.root/'295-prepared.json'))
        prep=str(self.parent.root/'295-prepared.json')
        self.assertEqual(expected['sequence'],1)
        votes={}
        for role in a.DOMAINS:
            vote=str(self.parent.root/('295-'+role+'-vote.json'))
            op.offline_vote(role=role,policy_file=self.policyfile,
                policy_sha256=self.policysha,prepared_file=prep,
                private_key_file=self.keyfiles[role],out=vote)
            votes[role]=vote
        cpfile=str(self.parent.root/'295-checkpoint.json')
        assembled=op.assemble(policy_file=self.policyfile,
            policy_sha256=self.policysha,prepared_file=prep,
            keeper_vote_file=votes['keeper'],witness_vote_file=votes['witness'],
            out=cpfile)
        verified=op.verify(policy_file=self.policyfile,policy_sha256=self.policysha,
                  checkpoint_files=[cpfile],expected_tip=assembled['signed_checkpoint_tip_sha256'])
        self.assertEqual(verified['status'],'verified_offline_local_history_only')
        self.assertEqual(self.parent.parent.statusport.lookups,1)
        self.assertEqual(os.stat(cpfile).st_mode & 0o077,0)

    def test_04_second_record_continuous_monotonic_sequence(self):
        e,_,_=self.initialize()
        first=self.checkpoint(e)
        second_e,_,_=self.receipt('record',first['claim']['audit_head_hmac_sha256'])
        second=self.checkpoint(second_e,first)
        verified=a.verify_chain([first,second],self.policy,self.policysha,a.sha(second))
        self.assertEqual(verified['audit_event_count'],4)
        self.assertEqual(verified['checkpoints_verified'],2)
        self.assertEqual(self.parent.parent.statusport.lookups,2)

    def test_05_stale_truncated_chain_detected_by_external_tip(self):
        e,_,_=self.initialize(); first=self.checkpoint(e)
        second_e,_,_=self.receipt('record',first['claim']['audit_head_hmac_sha256'])
        second=self.checkpoint(second_e,first)
        with self.assertRaisesRegex(a.AnchorError,'TIP_MISMATCH'):
            a.verify_chain([first],self.policy,self.policysha,a.sha(second))

    def test_06_wrong_earlier_parent_rejected_even_if_signatures_valid(self):
        e,_,_=self.initialize(); first=self.checkpoint(e)
        second_e,_,_=self.receipt('record',first['claim']['audit_head_hmac_sha256'])
        second=self.checkpoint(second_e,first)
        wrong=copy.deepcopy(second)
        wrong['claim']['previous_checkpoint_sha256']='f'*64
        for role in a.DOMAINS:
            wrong[role+'_signature_ed25519']=a.sign(role,wrong['claim'],self.keys[role])
        with self.assertRaisesRegex(a.AnchorError,'PREDECESSOR'):
            a.verify_chain([first,wrong],self.policy,self.policysha,a.sha(wrong))

    def test_07_replay_of_same_evidence_not_allowed_to_advance_chain(self):
        e,_,_=self.initialize(); first=self.checkpoint(e)
        with self.assertRaisesRegex(a.AnchorError,'NOT_ADVANCED'):
            a.prepared_from_evidence(e,self.policy,self.policysha,first)

    def test_08_forged_old_ec294_reply_denied(self):
        e,_,_=self.initialize()
        e=copy.deepcopy(e)
        e['response']['signed_reply']['signature_ed25519']='0'*128
        with self.assertRaisesRegex(a.AnchorError,'SIGNED_RECEIPT_INVALID'):
            a.verify_evidence(e,self.policy)

    def test_09_modified_original_grant_invalidates_request_sha(self):
        e,_,_=self.initialize()
        e=copy.deepcopy(e)
        e['grant']['subject']['grant_id']='b'*32
        with self.assertRaises(a.AnchorError):a.verify_evidence(e,self.policy)

    def test_10_modified_original_read_grant_invalidates_anchor(self):
        e,_,_=self.initialize()
        e=copy.deepcopy(e)
        e['read_grant']['signature_hex']='0'*128
        with self.assertRaises(a.AnchorError):a.verify_evidence(e,self.policy)

    def test_11_broken_new_keeper_signature_rejected(self):
        e,_,_=self.initialize(); cp=self.checkpoint(e)
        forged=copy.deepcopy(cp)
        forged['keeper_signature_ed25519']=forged['witness_signature_ed25519']
        with self.assertRaisesRegex(a.AnchorError,'SIGNATURE_INVALID'):
            a.verify_checkpoint(forged,self.policy,self.policysha)

    def test_12_modified_evidence_digest_rejected(self):
        e,_,_=self.initialize(); cp=self.checkpoint(e)
        forged=copy.deepcopy(cp)
        forged['evidence']['response']['result']['audit_event_count']=64
        with self.assertRaises(a.AnchorError):
            a.verify_checkpoint(forged,self.policy,self.policysha)

    def test_13_wrong_external_policy_pin_fails(self):
        self.initialize()
        with self.assertRaisesRegex(a.AnchorError,'RAW_BYTES_CHANGED'):
            a.load_policy(self.policyfile,'f'*64)

    def test_14_unpinned_chain_cannot_claim_verified(self):
        e,_,_=self.initialize();cp=self.checkpoint(e)
        with self.assertRaisesRegex(a.AnchorError,'PINNED_TIP'):
            a.verify_chain([cp],self.policy,self.policysha,a.GENESIS)

    def test_15_new_role_public_key_cannot_reuse_ec294_role(self):
        self.initialize()
        pol=copy.deepcopy(self.policy)
        pol['keeper_public_hex']=pol['ec294_server_public_hex']
        with self.assertRaisesRegex(a.AnchorError,'FIVE_DISTINCT'):
            a.validate_policy(pol)

    def test_16_offline_compare_readback_true_no_network_and_no_new_delivery(self):
        e,_,_=self.initialize(); cp=self.checkpoint(e)
        time.sleep(1.05)
        readback,grant,_=self.receipt('readback',cp['claim']['audit_head_hmac_sha256'])
        result=op.compare(policy_file=self.policyfile,policy_sha256=self.policysha,
            checkpoint_files=[self.file('checkpoint',cp)],expected_tip=a.sha(cp),
            response_file=self.file('readback-response',readback['response']),
            grant_file=grant,
            minimum_reply_unix=cp['claim']['ec294_reply_issued_at_unix']+1)
        self.assertTrue(result['fresh_ec294_local_readback_receipt_verified'])
        self.assertFalse(result['current_original_ec227_audit_storage_checked'])
        self.assertEqual(self.parent.parent.statusport.lookups,1)

    def test_17_compare_old_record_not_new_readback_refused(self):
        e,g,_=self.initialize();cp=self.checkpoint(e)
        readback,grant,_=self.receipt('readback',cp['claim']['audit_head_hmac_sha256'])
        with self.assertRaisesRegex(a.AnchorError,'FRESH_READBACK'):
            op.compare(policy_file=self.policyfile,policy_sha256=self.policysha,
                checkpoint_files=[self.file('checkpoint',cp)],expected_tip=a.sha(cp),
                response_file=self.file('same-response',readback['response']),grant_file=grant,
                minimum_reply_unix=cp['claim']['ec294_reply_issued_at_unix']+100)

    def test_18_policy_drift_cannot_be_accepted_offline(self):
        e,_,_=self.initialize()
        pol=copy.deepcopy(self.policy);pol['operation_id']='0'*64
        with self.assertRaisesRegex(a.AnchorError,'NOT_IN_ANCHOR_SCOPE'):
            a.verify_evidence(e,pol)

    def test_19_original_signed_denial_cannot_be_anchored_as_audit(self):
        e,_,_=self.initialize()
        e=copy.deepcopy(e)
        e['response']['result']['status']='unavailable'
        with self.assertRaises(a.AnchorError):a.verify_evidence(e,self.policy)

    def test_20_inserting_extra_unsigned_field_cannot_change_claim(self):
        e,_,_=self.initialize()
        e['unauthorized_note']='the operator says delivered'
        with self.assertRaisesRegex(a.AnchorError,'EVIDENCE_FIELDS'):
            a.verify_evidence(e,self.policy)

    def test_21_previous_checkpoint_needs_external_pin(self):
        e,g,r=self.initialize(); first=self.checkpoint(e)
        fresh,_,_=self.receipt('record',first['claim']['audit_head_hmac_sha256'])
        with self.assertRaisesRegex(a.AnchorError,'PREVIOUS_TIP_REQUIRED'):
            op.prepare(policy_file=self.policyfile,policy_sha256=self.policysha,
                response_file=self.file('freshresp',fresh['response']),
                grant_file=self.file('freshgrant',fresh['grant']),
                read_grant_file=self.file('freshread',fresh['read_grant']),
                previous_file=self.file('firstcp',first),expected_previous_tip=None,
                out=str(self.parent.root/'295-not-written.json'))

    def test_23_unified_console_exact_offline_action_without_router_bypass(self):
        e,_,_=self.initialize();cp=self.checkpoint(e)
        root=Path(__file__).resolve().parents[2]
        args=[sys.executable,'-I','-B',str(root/'scripts'/'ces_next.py'),
             'audit-anchor','DeliveryAudit','Verify',
             '--policy-file',self.policyfile,'--policy-sha256',self.policysha,
             '--checkpoint-file',self.file('cp-console',cp),
             '--expected-tip',a.sha(cp)]
        env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'}
        completed=subprocess.run(args,cwd=root,env=env,capture_output=True,
                                 text=True,timeout=15)
        self.assertEqual(completed.returncode,0,completed.stdout+completed.stderr)
        obj=json.loads(completed.stdout)
        self.assertEqual(obj['status'],'verified_offline_local_history_only')
        self.assertFalse(obj['new_status_query_or_original_send_requested'])
        args[5]='UnknownAction'
        denied=subprocess.run(args,cwd=root,env=env,capture_output=True,text=True,timeout=15)
        self.assertEqual(denied.returncode,3,denied.stdout+denied.stderr)
        self.assertFalse(json.loads(denied.stdout)['permissions_granted'])

    def test_22_external_checkpoint_does_not_need_original_audit_secret(self):
        e,_,_=self.initialize()
        cp=self.checkpoint(e)
        os.remove(self.parent.hmacfile)
        verified=a.verify_chain([cp],self.policy,self.policysha,a.sha(cp))
        self.assertTrue(verified['original_ec294_server_signature_verified'])
        self.assertFalse(verified['current_original_ec227_audit_storage_checked'])


if __name__=='__main__':unittest.main()
