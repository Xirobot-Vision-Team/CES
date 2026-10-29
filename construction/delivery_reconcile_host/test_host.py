#!/usr/bin/env python3
"""EC294: genuine original EC225/226/227, local fake signed Provider/inbox only.

Exercises real AF_UNIX peer UID, fresh Ed25519 roles, durable original EC227
HMAC-chained on-disk append and no-network readback. Never uses live Provider.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from delivery_status_host.test_host import EC293StatusCases
from delivery_send_host import protocol as send_proto
import delivery_reconcile as dr
import delivery_status as st
from . import protocol as p, daemon, operator as op

class EC294ReconcileCases(unittest.TestCase):
    def setUp(self):
        self.parent=EC293StatusCases('test_01_genuine_original_ec225_attempt_to_original_ec226_signed_unknown')
        self.parent.setUp()
        self.addCleanup(self.parent.doCleanups)
        self.root=self.parent.root
        self.base=self.parent.base
        self.keys={role:Ed25519PrivateKey.generate() for role in
                   ('custodian','auditor','server')}
        self.pub={role:send_proto.public_hex(key) for role,key in self.keys.items()}
        self.keyfiles={role:self.base.write('ec294-'+role+'.key',key.private_bytes_raw())
                       for role,key in self.keys.items()}
        self.hmacfile=str(self.root/'ec294-audit-secret.key')
        self.audit_key_info=op.new_audit_hmac(self.hmacfile)
        (self.root/'ec294-admission').mkdir(mode=0o700)
        self.policyfile=str(self.root/'ec294-policy.json')
        info=op.prepare_policy(ec293_policy_file=self.parent.policyfile,
             ec293_policy_sha256=self.parent.policysha,
             audit_hmac_file=self.hmacfile,
             admission_root=str(self.root/'ec294-admission'),
             allowed_uids=[os.getuid()],
             custodian_public_hex=self.pub['custodian'],
             auditor_public_hex=self.pub['auditor'],
             server_public_hex=self.pub['server'],out=self.policyfile,enable=True)
        self.policysha=info['policy_sha256']
        self.sock=str(self.root/'ec294-audit.sock')
        self.host=None;self.thread=None

    def send(self):
        return self.parent.original_send()

    def grants(self,mode='record',head=p.GENESIS):
        stem='ec294-'+str(time.monotonic_ns())
        read=None
        if mode=='record':
            template=str(self.root/(stem+'-read-template.json'))
            read=str(self.root/(stem+'-read.json'))
            op.status_op.prepare_read_template(self.parent.policyfile,
                    self.parent.policysha,35,template)
            op.status_op.sign_read_template(template,
                    self.parent.keyfiles['read'],read)
        sub=str(self.root/(stem+'-sub.json'))
        v1=str(self.root/(stem+'-vote1.json'))
        v2=str(self.root/(stem+'-vote2.json'))
        grant=str(self.root/(stem+'-grant.json'))
        op.prepare_subject(self.policyfile,self.policysha,mode,
                 read,os.getuid(),25,head,sub)
        op.vote('custodian',sub,self.keyfiles['custodian'],v1)
        op.vote('auditor',sub,self.keyfiles['auditor'],v2)
        op.assemble(sub,v1,v2,self.pub['custodian'],self.pub['auditor'],grant)
        return grant,read

    def start(self):
        self.host=daemon.ReconcileHost(path=self.sock,policy_path=self.policyfile,
                      policy_sha=self.policysha,
                      private_key_file=self.keyfiles['server'])
        self.thread=threading.Thread(target=self.host.serve_forever,
                             kwargs={'poll_interval':0.02},daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        if self.host is not None and self.thread is not None and self.thread.is_alive():
            self.host.shutdown();self.thread.join(2)
        if self.host is not None:self.host.server_close();self.host=None

    def call(self,grant,read=None):
        def status(_adapter,target,credential,query):
            self.assertEqual(credential,self.parent.credential)
            return self.parent.statusport.status(target,credential,query)
        with patch.object(st.HTTPSPrivateStatusTransport,'status',status):
            return op.submit(socket_path=self.sock,grant_file=grant,
                  read_grant_file=read,policy_sha=self.policysha,
                  server_pub=self.pub['server'],timeout=15)

    def test_01_record_original_ec227_real_append_and_original_ec226_read(self):
        self.send();self.start();g,r=self.grants()
        rc,doc=self.call(g,r)
        self.assertEqual(rc,2,doc)
        result=doc['result']
        self.assertEqual(result['schema'],dr.SCHEMA)
        self.assertTrue(doc['verified_server_signature'])
        self.assertEqual(result['audit_event_count'],2)
        self.assertTrue(result['audit_chain_verified'])
        self.assertEqual(result['delivery_state'],'UNKNOWN_UNCONFIRMED')
        self.assertTrue(result['effects']['local_audit_records_written'])
        self.assertEqual(self.parent.statusport.lookups,1)
        self.assertEqual(self.base.fx.transport.posts,1)
        self.assertEqual(len(list(self.base.outbox.glob('ec227-*'))),1)
        self.assertEqual(len(list(self.base.outbox.glob('ec226-read-*'))),1)
        self.assertEqual(len(list((self.root/'ec294-admission').iterdir())),1)

    def test_02_audited_provider_acceptance_is_not_inbox_delivery(self):
        self.send();self.parent.statusport.state='ACCEPTED';self.start()
        g,r=self.grants();rc,doc=self.call(g,r)
        self.assertEqual(rc,2,doc)
        self.assertEqual(doc['result']['delivery_state'],'ACCEPTED_PROVIDER_ATTESTED')
        self.assertTrue(doc['fresh_attested_delivery_state_this_call'])
        self.assertFalse(doc['production_inbox_delivery_proven'])

    def test_03_audited_inbox_observer_really_signed_independently(self):
        self.send();self.parent.statusport.state='DELIVERED'
        self.parent.statusport.inbox=True;self.start()
        g,r=self.grants();rc,doc=self.call(g,r)
        self.assertEqual(rc,2,doc)
        self.assertEqual(doc['result']['delivery_state'],'DELIVERED_INBOX_OBSERVED')
        self.assertEqual(doc['result']['last_provider_state'],'DELIVERED')
        self.assertFalse(doc['production_inbox_delivery_proven'])

    def test_04_readback_is_local_only_and_does_not_upgrade_historical(self):
        self.send();self.parent.statusport.state='ACCEPTED';self.start()
        g,r=self.grants();rc,doc=self.call(g,r)
        self.assertEqual(rc,2,doc)
        head=doc['audit_head_hmac_sha256']
        grant,read=self.grants('readback',head)
        with patch.object(p.prev,'read_credential',side_effect=AssertionError(
                 'EC294 READBACK MUST NOT LOAD STATUS TOKEN')):
            rc2,doc2=self.call(grant,read)
        self.assertEqual(rc2,2,doc2)
        res=doc2['result']
        self.assertEqual(res['delivery_state'],'UNKNOWN_UNCONFIRMED')
        self.assertEqual(res['last_historical_attested_state'],'ACCEPTED_PROVIDER_ATTESTED')
        self.assertFalse(res['status_network_requested'])
        self.assertFalse(res['effects']['local_audit_records_written'])
        self.assertFalse(doc2['fresh_attested_delivery_state_this_call'])
        self.assertEqual(self.parent.statusport.lookups,1)
        self.assertEqual(self.base.fx.transport.posts,1)

    def test_05_stale_external_checkpoint_cannot_start_another_network_read(self):
        self.send();self.start()
        a,b=self.grants();first,doc=self.call(a,b)
        self.assertEqual(first,2,doc)
        stale,stale_read=self.grants('record',p.GENESIS)
        rc,reply=self.call(stale,stale_read)
        self.assertEqual(rc,3,reply)
        self.assertEqual(self.parent.statusport.lookups,1)
        self.assertEqual(len(list((self.root/'ec294-admission').iterdir())),1)
        self.assertEqual(len(list(self.base.outbox.glob('ec227-*/0*.json'))),2)

    def test_06_fresh_external_head_permits_separately_authorized_new_read(self):
        self.send();self.start();a,b=self.grants()
        code,first=self.call(a,b);self.assertEqual(code,2,first)
        head=first['audit_head_hmac_sha256']
        a2,b2=self.grants('record',head)
        code2,second=self.call(a2,b2)
        self.assertEqual(code2,2,second)
        self.assertEqual(second['result']['audit_event_count'],4)
        self.assertNotEqual(second['audit_head_hmac_sha256'],head)
        self.assertEqual(self.parent.statusport.lookups,2)
        self.assertEqual(self.base.fx.transport.posts,1)

    def test_07_no_original_ec225_submit_marker_no_audit_or_host_spend(self):
        self.start();grant,read=self.grants()
        code,doc=self.call(grant,read)
        self.assertEqual(code,5,doc)
        self.assertFalse(doc['fresh_attested_delivery_state_this_call'])
        self.assertEqual(self.parent.statusport.lookups,0)
        self.assertEqual(list((self.root/'ec294-admission').iterdir()),[])
        self.assertEqual(list(self.base.outbox.glob('ec227-*')),[])

    def test_08_exact_host_grant_is_never_replayed(self):
        self.send();self.start();g,r=self.grants()
        self.assertEqual(self.call(g,r)[0],2)
        rc,doc=self.call(g,r)
        self.assertEqual(rc,3,doc)
        self.assertFalse(doc['result']['audit_or_status_outcome_unknown'])
        self.assertEqual(doc['result']['reason_code'],
                         'EC294_EXPECTED_EMPTY_AUDIT_BUT_LOG_PRESENT_OR_UNVERIFIABLE')
        self.assertEqual(self.parent.statusport.lookups,1)

    def test_09_wrong_auditor_vote_blocks_before_local_change(self):
        self.send();g,r=self.grants()
        body=json.loads(Path(g).read_text())
        body['auditor_signature_ed25519']=body['custodian_signature_ed25519']
        forged=self.base.write('ec294-missing-audit-signature.json',p.canonical(body))
        self.start();rc,doc=self.call(forged,r)
        self.assertEqual(rc,3,doc)
        self.assertEqual(self.parent.statusport.lookups,0)
        self.assertEqual(list((self.root/'ec294-admission').iterdir()),[])

    def test_10_wrong_uid_even_with_new_valid_votes_is_denied(self):
        self.send();g,r=self.grants()
        body=json.loads(Path(g).read_text())
        body['subject']['uid']=os.getuid()+1
        for role in ('custodian','auditor'):
            body[role+'_signature_ed25519']=p.sign(role,body['subject'],self.keys[role])
        forged=self.base.write('ec294-wrong-uid.json',p.canonical(body))
        self.start();rc,doc=self.call(forged,r)
        self.assertEqual(rc,3,doc)
        self.assertEqual(self.parent.statusport.lookups,0)

    def test_11_wrong_original_ec226_signed_read_is_denied(self):
        self.send();g,r=self.grants()
        read=json.loads(Path(r).read_text())
        read['signature_hex']='00'*64
        changed=self.base.write('ec294-fake-read.json',p.canonical(read))
        obj=json.loads(Path(g).read_text())
        obj['subject']['read_grant_sha256']=p.digest(p.canonical(read))
        for role in ('custodian','auditor'):
            obj[role+'_signature_ed25519']=p.sign(role,obj['subject'],self.keys[role])
        alt=self.base.write('ec294-fake-grant.json',p.canonical(obj))
        self.start();rc,doc=self.call(alt,changed)
        self.assertEqual(rc,3,doc)
        self.assertEqual(self.parent.statusport.lookups,0)
        self.assertEqual(list((self.root/'ec294-admission').iterdir()),[])

    def test_12_tampered_original_ec227_record_refuses_readback(self):
        self.send();self.start();g,r=self.grants()
        rc,first=self.call(g,r);self.assertEqual(rc,2,first)
        head=first['audit_head_hmac_sha256']
        entry=next(self.base.outbox.glob('ec227-*/000002.json'))
        content=json.loads(entry.read_text())
        content['entry']['delivery_state']='DELIVERED_INBOX_OBSERVED'
        entry.write_bytes(p.canonical(content))
        grant,read=self.grants('readback',head)
        code,doc=self.call(grant,read)
        self.assertEqual(code,3,doc)
        self.assertEqual(self.parent.statusport.lookups,1)

    def test_13_modified_audit_hmac_key_prevents_host_start(self):
        Path(self.hmacfile).write_bytes(os.urandom(32))
        with self.assertRaises(p.HostError):
            daemon.ReconcileHost(path=self.sock,policy_path=self.policyfile,
                     policy_sha=self.policysha,private_key_file=self.keyfiles['server'])

    def test_14_invalid_or_expired_readback_subject_does_not_query_provider(self):
        self.send();g,r=self.grants('readback')
        obj=json.loads(Path(g).read_text())
        obj['subject']['expires_at_unix']=obj['subject']['issued_at_unix']
        for role in ('custodian','auditor'):
            obj[role+'_signature_ed25519']=p.sign(role,obj['subject'],self.keys[role])
        forged=self.base.write('ec294-expired.json',p.canonical(obj))
        self.start()
        # Client refuses malformed subject before even connecting.
        with self.assertRaises(p.HostError):self.call(forged,None)
        self.assertEqual(self.parent.statusport.lookups,0)

    def test_15_readback_without_history_is_not_claimed_as_delivery(self):
        self.send();self.start();grant,read=self.grants('readback')
        code,doc=self.call(grant,read)
        self.assertEqual(code,5,doc)
        self.assertEqual(doc['result']['reason_code'],
                         'DELIVERY_RECONCILE_AUDIT_NOT_YET_RECORDED')
        self.assertFalse(doc['fresh_attested_delivery_state_this_call'])
        self.assertEqual(self.parent.statusport.lookups,0)

    def test_16_console_exact_action_wrapper_verifies_signed_original_result(self):
        self.send();self.start();grant,read=self.grants('readback')
        # The historical original fixture pins time to a synthetic past epoch.
        # Invoke console logic in this same frozen clock; a subprocess with the
        # live wall clock rightly rejects its expired (synthetic) signed ACK.
        sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
        import ces_next as console
        with patch.object(console,'_inventory',return_value={'routes':[
                    {'action':'DeliverySend','mode':'Send','route_kind':'HOST_REQUIRED'}]}):
            with patch.object(console,'_command',side_effect=lambda *a,**kw:
                        self.call(grant,None)):
                with patch.object(console,'_emit') as emit:
                    rc=console.host_delivery_reconcile('DeliveryReconcile','Readback',
                        socket_path=self.sock,grant_file=grant,read_grant_file=None,
                        policy_sha=self.policysha,server_public_hex=self.pub['server'])
        self.assertEqual(rc,5)
        doc=emit.call_args[0][0]
        self.assertEqual(doc['schema'],p.RESULT_SCHEMA)
        self.assertTrue(doc['verified_server_signature'])
        self.assertEqual(doc['result']['reason_code'],
                         'DELIVERY_RECONCILE_AUDIT_NOT_YET_RECORDED')
        self.assertEqual(self.parent.statusport.lookups,0)

    def test_17_offline_hmac_key_is_exclusive_owner_private_and_not_exported(self):
        self.assertEqual(Path(self.hmacfile).stat().st_mode&0o777,0o600)
        self.assertEqual(Path(self.hmacfile).stat().st_size,32)
        with self.assertRaises(p.HostError):op.new_audit_hmac(self.hmacfile)
        self.assertFalse(self.audit_key_info['private_secret_returned'])
        self.assertNotIn(Path(self.hmacfile).read_bytes().hex(),
                         json.dumps(self.audit_key_info))
        self.assertNotIn(Path(self.hmacfile).read_bytes().hex(),
                         Path(self.policyfile).read_text())
        self.assertEqual(self.parent.statusport.lookups,0)


    def test_18_interrupted_lookup_start_preserved_and_manually_reconciled(self):
        self.send();self.start();grant,read=self.grants()
        with patch.object(st.DeliveryStatusReader,'observe_once',
                          side_effect=OSError('synthetic crash after durable START')):
            rc,doc=self.call(grant,read)
        self.assertEqual(rc,5,doc)
        self.assertEqual(doc['result']['reason_code'],
                         'DELIVERY_RECONCILE_AUDIT_OR_REMOTE_STATUS_RECONCILIATION_FAILED')
        self.assertTrue(doc['result']['effects']['local_audit_records_written'])
        self.assertEqual(self.parent.statusport.lookups,0)
        entry=next(self.base.outbox.glob('ec227-*/000001.json'))
        sealed=json.loads(entry.read_text())
        key=Path(self.hmacfile).read_bytes()
        self.assertEqual(dr._mac(key,sealed['entry']),sealed['hmac_sha256'])
        # This is a simulated human-led recovery: independently authenticate
        # and anchor the existing START head before signing a new readback.
        head=sealed['hmac_sha256']
        g2,_=self.grants('readback',head)
        code,readback=self.call(g2,None)
        self.assertEqual(code,2,readback)
        self.assertTrue(readback['result']['incomplete_prior_observation'])
        self.assertEqual(readback['result']['audit_event_count'],1)
        self.assertFalse(readback['result']['status_network_requested'])
        self.assertEqual(readback['result']['delivery_state'],'UNKNOWN_UNCONFIRMED')

    def test_19_wrong_external_non_genesis_hash_blocks_audit_read(self):
        self.send();self.start();grant,read=self.grants()
        self.assertEqual(self.call(grant,read)[0],2)
        old_count=self.parent.statusport.lookups
        wrong='d'*64
        grant2,read2=self.grants('readback',wrong)
        code,doc=self.call(grant2,None)
        self.assertEqual(code,3,doc)
        self.assertEqual(doc['result']['reason_code'],
            'EC294_EXTERNAL_CHECKPOINT_MISMATCH_OR_AUDIT_UNVERIFIABLE')
        self.assertEqual(self.parent.statusport.lookups,old_count)

    def test_20_single_use_offline_readback_grant_even_without_remote_change(self):
        self.send();self.start();g,_=self.grants('readback')
        self.assertEqual(self.call(g,None)[0],5)
        code,doc=self.call(g,None)
        self.assertEqual(code,3,doc)
        self.assertTrue(doc['result']['audit_or_status_outcome_unknown'])
        self.assertEqual(doc['result']['reason_code'],
                         'EC294_EXACT_HOST_GRANT_SPENT_NO_AUTO_RETRY')
        self.assertEqual(self.parent.statusport.lookups,0)

    def test_21_untrusted_inbox_signature_never_promoted_to_observed_delivery(self):
        self.send();self.parent.statusport.state='DELIVERED'
        self.parent.statusport.inbox=True
        self.parent.statusport.ack_patch['payload_sha256']='00'*64
        self.start();grant,read=self.grants()
        rc,doc=self.call(grant,read)
        self.assertEqual(rc,2,doc)
        self.assertEqual(doc['result']['delivery_state'],'UNKNOWN_UNCONFIRMED')
        self.assertFalse(doc['fresh_attested_delivery_state_this_call'])
        self.assertFalse(doc['production_inbox_delivery_proven'])
        self.assertEqual(doc['result']['audit_event_count'],2)

if __name__=='__main__':unittest.main()
