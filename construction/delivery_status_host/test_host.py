#!/usr/bin/env python3
"""EC293 local-only original EC225/226 integration, signed provider MOCK.

Genuine original signed source, original EC225 private outbox, original EC226
status verifier, AF_UNIX peer credential, host admission, Ed25519 votes & ACK.
Provider/inbox witnesses are synthetic and on this one machine only.
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
from delivery_send_host.test_host import EC288HostCases
from delivery_send_host import protocol as old
from finding_query_host import protocol as io
import delivery_send as ds
import delivery_status as st
import test_delivery_status as statusfx
from . import protocol as p, daemon, operator as op


class EC293StatusCases(unittest.TestCase):
    def setUp(self):
        self.base=EC288HostCases('test_private_original_job_roundtrip_real_types')
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.root=self.base.root
        self.keys={role:Ed25519PrivateKey.generate() for role in (
            'read','inbox','custodian','reviewer','server')}
        self.keyfiles={role:self.base.write('ec293-'+role+'.key',
                          key.private_bytes_raw()) for role,key in self.keys.items()}
        self.pub={role:old.public_hex(key) for role,key in self.keys.items()}
        self.trust={'schema':p.TRUST_SCHEMA,'issuer_id':'status_issuer_293',
            'reader_id':'status_reader_293','inbox_observer_id':'inbox_observer_293',
            'status_read_public_hex':self.pub['read'],
            'inbox_observation_public_hex':self.pub['inbox'],
            'minimum_read_epoch':53,'enable_private_status_read':True}
        self.trustfile=self.base.write('ec293-status-trust.json',p.canonical(self.trust))
        self.credential='ec293-independent-read-only-credential'
        self.credfile=self.base.write('ec293-readonly.token',self.credential.encode())
        (self.root/'status-admission').mkdir(mode=0o700)
        self.policyfile=str(self.root/'ec293-policy.json')
        self.published=op.prepare_policy(
            ec288_policy_file=self.base.policy_path,
            ec288_policy_sha256=self.base.sha,
            status_trust_file=self.trustfile,
            read_credential_file=self.credfile,
            admission_root=str(self.root/'status-admission'),
            allowed_uids=[os.getuid()],
            custodian_public_hex=self.pub['custodian'],
            reviewer_public_hex=self.pub['reviewer'],
            server_public_hex=self.pub['server'],out=self.policyfile,enable=True)
        self.policysha=self.published['policy_sha256']
        self.sock=str(self.root/'ec293-status.sock')
        self.statusport=statusfx.SignedSyntheticStatusPort(
            self.base.fx.provider_key,self.keys['inbox'],
            self.trust['inbox_observer_id'])
        self.host=None;self.thread=None
        self.send_calls=0

    def original_send(self):
        """Only TEST setup calls original EC225 with MOCK provider; Host never does."""
        sender=old.build_sender(self.base.trust,self.base.fx.access.credential,
                                str(self.base.outbox))
        fixture=self.base.fx.transport
        with patch.object(ds.HTTPSPrivateTestTransport,'probe',
                 lambda _sender,target,credential,challenge:fixture.probe(
                     target,credential,challenge)), patch.object(
                     ds.HTTPSPrivateTestTransport,'submit',
                 lambda _sender,target,credential,body,operation:fixture.submit(
                     target,credential,body,operation)):
            original=sender.send_once(old.load_job(old.load_policy(
                self.base.policy_path,self.base.sha)))
        self.assertEqual(original['status'],'partial',original)
        self.assertTrue(original['submission_post_attempted'])
        self.send_calls+=1
        return original

    def fresh_grants(self):
        number=str(time.monotonic_ns())
        template=str(self.root/('ec293-template-'+number+'.json'))
        readfile=str(self.root/('ec293-read-'+number+'.json'))
        subject=str(self.root/('ec293-subject-'+number+'.json'))
        vote1=str(self.root/('ec293-vote-a-'+number+'.json'))
        vote2=str(self.root/('ec293-vote-b-'+number+'.json'))
        grant=str(self.root/('ec293-grant-'+number+'.json'))
        op.prepare_read_template(self.policyfile,self.policysha,35,template)
        op.sign_read_template(template,self.keyfiles['read'],readfile)
        op.prepare_subject(self.policyfile,self.policysha,readfile,
                           os.getuid(),25,subject)
        op.vote('custodian',subject,self.keyfiles['custodian'],vote1)
        op.vote('reviewer',subject,self.keyfiles['reviewer'],vote2)
        op.assemble(subject,vote1,vote2,self.pub['custodian'],
                    self.pub['reviewer'],grant)
        return grant,readfile

    def start(self):
        self.host=daemon.StatusHost(path=self.sock,policy_path=self.policyfile,
                        policy_sha=self.policysha,
                        private_key_file=self.keyfiles['server'])
        self.thread=threading.Thread(target=self.host.serve_forever,
                        kwargs={'poll_interval':0.02},daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        if self.host is not None and self.thread is not None and self.thread.is_alive():
            self.host.shutdown();self.thread.join(2)
        if self.host is not None:
            self.host.server_close()
            self.host=None

    def call(self,grant,readfile,*,patch_provider=True):
        def status(_adapter,target,credential,query):
            self.assertEqual(credential,self.credential)
            return self.statusport.status(target,credential,query)
        with patch.object(st.HTTPSPrivateStatusTransport,'status',
                          status if patch_provider else st.HTTPSPrivateStatusTransport.status):
            return op.submit(socket_path=self.sock,grant_file=grant,
                read_grant_file=readfile,policy_sha=self.policysha,
                server_pub=self.pub['server'],timeout=12)

    def test_01_genuine_original_ec225_attempt_to_original_ec226_signed_unknown(self):
        self.original_send()
        grant,read=self.fresh_grants()
        self.start()
        rc,response=self.call(grant,read)
        self.assertEqual(rc,2,response)
        self.assertTrue(response['verified_server_signature'])
        self.assertTrue(response['provider_status_attested'])
        self.assertFalse(response['inbox_delivery_observed'])
        self.assertEqual(response['result']['delivery_state'],'UNKNOWN_UNCONFIRMED')
        self.assertEqual(self.statusport.lookups,1)
        self.assertEqual(self.base.fx.transport.posts,1)
        self.assertEqual(len(list(self.base.outbox.glob('ec226-read-*'))),1)
        self.assertEqual(len(list((self.root/'status-admission').iterdir())),1)
        self.assertFalse(response['original_ec225_send_token_loaded_by_host'])

    def test_02_provider_acceptance_does_not_claim_inbox_delivery(self):
        self.original_send()
        self.statusport.state='ACCEPTED'
        grant,read=self.fresh_grants();self.start()
        rc,response=self.call(grant,read)
        self.assertEqual(rc,2,response)
        self.assertEqual(response['result']['delivery_state'],'ACCEPTED_PROVIDER_ATTESTED')
        self.assertTrue(response['result']['provider_accepted'])
        self.assertFalse(response['result']['recipient_delivery_observed'])
        self.assertEqual(self.base.fx.transport.posts,1)

    def test_03_recipient_observed_only_with_two_valid_independent_signers(self):
        self.original_send()
        self.statusport.state='DELIVERED';self.statusport.inbox=True
        grant,read=self.fresh_grants();self.start()
        rc,response=self.call(grant,read)
        self.assertEqual(rc,2,response)
        self.assertEqual(response['result']['delivery_state'],'DELIVERED_INBOX_OBSERVED')
        self.assertTrue(response['inbox_delivery_observed'])
        self.assertFalse(response['public_or_production_delivery_claimed'])

    def test_04_original_durable_post_marker_required_before_host_admission(self):
        grant,read=self.fresh_grants();self.start()
        rc,result=self.call(grant,read)
        self.assertEqual(rc,5,result)
        self.assertFalse(result['provider_status_attested'])
        self.assertEqual(self.statusport.lookups,0)
        self.assertEqual(list((self.root/'status-admission').iterdir()),[])

    def test_05_missing_original_read_signer_blocks_read_without_admission(self):
        self.original_send()
        grant,read=self.fresh_grants()
        data=json.loads(Path(read).read_text())
        data['signature_hex']='00'*64
        alternate=self.base.write('ec293-bad-read.json',p.canonical(data))
        # Rebind two new host votes to the forged original read hash so the
        # ORIGINAL EC226 signature verifier (not just SHA pin) must deny.
        g=json.loads(Path(grant).read_text())
        g['subject']['read_grant_sha256']=p.digest(p.canonical(data))
        for role in ('custodian','reviewer'):
            g[role+'_signature_ed25519']=p.sign(role,g['subject'],self.keys[role])
        forged=self.base.write('ec293-rebound-grant.json',p.canonical(g))
        self.start()
        rc,result=self.call(forged,alternate)
        self.assertEqual(rc,3,result)
        self.assertEqual(self.statusport.lookups,0)
        self.assertEqual(list((self.root/'status-admission').iterdir()),[])

    def test_06_second_host_voter_cannot_be_substituted(self):
        self.original_send()
        grant,read=self.fresh_grants()
        g=json.loads(Path(grant).read_text())
        g['reviewer_signature_ed25519']=g['custodian_signature_ed25519']
        bad=self.base.write('ec293-forged-host-vote.json',p.canonical(g))
        self.start()
        rc,_=self.call(bad,read)
        self.assertEqual(rc,3)
        self.assertEqual(list((self.root/'status-admission').iterdir()),[])

    def test_07_kernel_peer_uid_disagrees_blocks(self):
        self.original_send()
        grant,read=self.fresh_grants()
        g=json.loads(Path(grant).read_text())
        g['subject']['uid']=os.getuid()+1
        for role in ('custodian','reviewer'):
            g[role+'_signature_ed25519']=p.sign(role,g['subject'],self.keys[role])
        bad=self.base.write('ec293-wrong-uid-grant.json',p.canonical(g))
        self.start()
        rc,_=self.call(bad,read)
        self.assertEqual(rc,3)
        self.assertEqual(self.statusport.lookups,0)

    def test_08_original_and_host_one_use_blocks_exact_replay(self):
        self.original_send()
        grant,read=self.fresh_grants();self.start()
        first,doc=self.call(grant,read)
        again,second=self.call(grant,read)
        self.assertEqual(first,2,doc)
        self.assertEqual(again,3,second)
        self.assertTrue(second['status_read_outcome_unknown'])
        self.assertEqual(self.statusport.lookups,1)
        self.assertEqual(self.base.fx.transport.posts,1)

    def test_09_fresh_separately_approved_read_allowed_after_prior_read(self):
        self.original_send();self.start()
        a,b=self.fresh_grants()
        self.assertEqual(self.call(a,b)[0],2)
        a2,b2=self.fresh_grants()
        self.assertEqual(self.call(a2,b2)[0],2)
        self.assertEqual(self.statusport.lookups,2)
        self.assertEqual(self.base.fx.transport.posts,1)

    def test_10_bogus_inbox_signature_cannot_claim_delivery(self):
        self.original_send()
        self.statusport.state='DELIVERED';self.statusport.inbox=True
        self.statusport.ack_patch['payload_sha256']='00'*64
        grant,read=self.fresh_grants();self.start()
        rc,response=self.call(grant,read)
        self.assertEqual(rc,5,response)
        self.assertFalse(response['inbox_delivery_observed'])
        self.assertEqual(self.statusport.lookups,1)

    def test_11_mismatched_status_trust_denied_before_rpc_or_network(self):
        doc=json.loads(Path(self.policyfile).read_text())
        doc['status_trust_sha256']='00'*64
        with self.assertRaises((p.HostError,old.HostError)):p.build_reader(doc)
        self.assertEqual(self.statusport.lookups,0)

    def test_12_backend_code_or_job_hash_drift_denied(self):
        doc=json.loads(Path(self.policyfile).read_text())
        doc['original_ec226_code_sha256']='00'*64
        with self.assertRaises(p.HostError):p.validate_policy(doc)
        doc=json.loads(Path(self.policyfile).read_text())
        prev=json.loads(Path(self.base.policy_path).read_text())
        prev['job_sha256']='00'*64
        with self.assertRaises((p.HostError,old.HostError)):
            old.validate_policy(prev)

    def test_13_expired_original_read_template_blocks_signing(self):
        template=str(self.root/'expire-template.json')
        op.prepare_read_template(self.policyfile,self.policysha,20,template)
        obj=json.loads(Path(template).read_text())
        obj['expires_at']=obj['issued_at']
        bad=self.base.write('ec293-expired-read-template.json',p.canonical(obj))
        with self.assertRaises(p.HostError):
            op.sign_read_template(bad,self.keyfiles['read'],
                                  str(self.root/'should-not-exist-read.json'))

    def test_14_invalid_inbox_signature_rejected_and_no_second_read(self):
        self.original_send()
        self.statusport.state='DELIVERED';self.statusport.inbox=True
        self.statusport.ack_patch['observer_id']='forged_observer'
        grant,read=self.fresh_grants();self.start()
        rc,result=self.call(grant,read)
        self.assertEqual(rc,5,result)
        again,_=self.call(grant,read)
        self.assertEqual(again,3)
        self.assertEqual(self.statusport.lookups,1)

    def test_15_console_rejects_unauthorized_mode_preserves_original_router(self):
        path=Path(__file__).resolve().parents[2]/'scripts'/'ces_next.py'
        cmd=[sys.executable,'-I','-B',str(path),'host-delivery-status',
             'DeliverySend','Send','--socket',self.sock,
             '--grant-file','/not-available','--read-grant-file','/not-available',
             '--policy-sha256',self.policysha,
             '--server-public-hex',self.pub['server']]
        result=subprocess.run(cmd,capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,3,result.stdout+result.stderr)
        self.assertEqual(json.loads(result.stdout)['reason_code'],
                         'EC293_ONLY_DELIVERYSEND_READBACK_ALLOWED')

    def test_16_no_read_of_previous_write_token_during_host_start_or_status(self):
        self.original_send()
        grant,read=self.fresh_grants()
        original=old.private_file
        def inspect(path,limit):
            if path==self.base.cred_path:
                raise AssertionError('EC293 accessed original WRITE credential')
            return original(path,limit)
        with patch.object(old,'private_file',side_effect=inspect):
            self.start()
            rc,response=self.call(grant,read)
            self.assertEqual(rc,2,response)
        self.assertEqual(self.base.fx.transport.posts,1)


    def test_17_offline_keygen_cli_creates_private_key_and_public_only_reply(self):
        path=Path(__file__).resolve().parents[2]/'scripts'/'ces_delivery_status_host.py'
        out=str(self.root/'new-independent-ec293-operator.key')
        completed=subprocess.run([sys.executable,'-I','-B',str(path),
                                  'keygen-offline','--private-out',out],
                                 capture_output=True,text=True,timeout=20)
        self.assertEqual(completed.returncode,0,completed.stdout+completed.stderr)
        reply=json.loads(completed.stdout)
        self.assertEqual(reply['schema'],'ces.ec293.offline_keygen.v1')
        self.assertFalse(reply['private_key_material_returned'])
        self.assertEqual(len(reply['public_hex']),64)
        self.assertEqual(Path(out).stat().st_mode & 0o777,0o600)
        self.assertEqual(len(Path(out).read_bytes()),32)
        again=subprocess.run([sys.executable,'-I','-B',str(path),
                              'keygen-offline','--private-out',out],
                             capture_output=True,text=True,timeout=20)
        self.assertEqual(again.returncode,5)
        self.assertEqual(len(Path(out).read_bytes()),32)


if __name__=='__main__':
    unittest.main()
