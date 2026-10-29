#!/usr/bin/env python3
"""EC286 focused tests: original EC186/EC187 logic, synthetic remote session.

Run as non-root; real AF_UNIX kernel peer UID and original HMAC/Ed25519 bytes.
The EC259/Podman/cgroup control-plane is intentionally MOCKED here; its
independent EC259 tests are inherited, not an actual OCI security acceptance.
"""
from __future__ import annotations

from datetime import datetime,timedelta,timezone
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import socket
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE))
from ec286_quality_execute_host import protocol as p,daemon,operator
from ec281_quality_preflight_host import protocol as pre
from ec279_finding_query_host import protocol as signio
from ec252_quality_run_host import broker as runner
from ec253_lease_host import broker as lease
from ec259_custody_gated_host import gate as custody_gate
import quality_detect as detect
import quality_run_guard as guard
import quality_run_budget as budget
from test_quality_run_budget import FakeSession,event


def docfile(path:Path,obj:dict)->None:
    path.write_bytes(p.canonical(obj)+b'\n');path.chmod(0o600)


def bytesfile(path:Path,data:bytes)->None:
    path.write_bytes(data);path.chmod(0o600)


def signed(body:dict,key:bytes,domain:bytes)->dict:
    return {**body,'mac_sha256':hmac.new(
        key,domain+guard._canonical(body),hashlib.sha256).hexdigest()}


class ExecuteHostCases(unittest.TestCase):
    def setUp(self):
        if os.geteuid()==0:
            self.skipTest('Run EC286 focused integration as a non-root Linux UID')
        if not hasattr(socket,'SO_PEERCRED'):
            self.skipTest('Requires Linux AF_UNIX kernel peer UID')
        self.tmp=tempfile.TemporaryDirectory(prefix='ec286-')
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.repo=self.root/'checkout';self.repo.mkdir(mode=0o700)
        self.profile='python.pytest'
        catalog=guard.catalog_entry(self.profile)
        pin=detect.QualityDetector.observe_root(
            str(self.repo),authorize_observation=lambda _:True)
        pin_sha=guard._digest(detect.DOMAIN_PIN,pin)
        now=datetime.now(timezone.utc).replace(microsecond=0)
        stamp=lambda t:t.isoformat(timespec='seconds').replace('+00:00','Z')
        self.key1=os.urandom(48);self.key2=os.urandom(48)
        approve=signed({'schema':guard.APPROVAL_SCHEMA,
            'ticket_id':'approval-ec286-local-002','profile_id':self.profile,
            'profile_sha256':catalog['profile_sha256'],
            'source_pin_sha256':pin_sha,
            'issued_at_utc':stamp(now),
            'expires_at_utc':stamp(now+timedelta(seconds=100)),
            'approved_purpose':'TEST'},self.key1,guard.DOMAIN_APPROVAL)
        isolation=signed({'schema':guard.LEASE_SCHEMA,
            'ticket_id':'lease-ec286-local-00002',
            'source_pin_sha256':pin_sha,
            'profile_sha256':catalog['profile_sha256'],
            'approval_receipt_sha256':guard._digest(guard.DOMAIN_RECEIPT,approve),
            'image_sha256':'8'*64,
            'controls':dict(guard.REQUIRED_CONTROLS),
            'issued_at_utc':stamp(now),
            'expires_at_utc':stamp(now+timedelta(seconds=90))},
            self.key2,guard.DOMAIN_LEASE)
        files={'source_pin':pin,'approval_ticket':approve,'lease_ticket':isolation}
        prepol={'schema':pre.POLICY_SCHEMA,'repo_root':str(self.repo),
                'allowed_profiles':[self.profile],
                'allowed_uids':[os.geteuid()]}
        for label,value in files.items():
            path=self.root/(label+'.json');docfile(path,value)
            prepol[label+'_file']=str(path)
            prepol[label+'_sha256']=p.sha(path.read_bytes())
        for label,key in (('policy_key',self.key1),('broker_key',self.key2)):
            path=self.root/(label+'.bin');bytesfile(path,key)
            prepol[label+'_file']=str(path)
            prepol[label+'_sha256']=p.sha(path.read_bytes())
        # EC281 preflight issuers remain separate from new EC286 host signers.
        self.keys={};self.pubs={}
        for role in ('prepolicy','preisolation','preserver',
                     'custodian','executor','server'):
            path=self.root/(role+'.key')
            self.pubs[role]=operator.keygen(str(path))['public_hex']
            self.keys[role]=path
        prepol.update({'policy_issuer_public_hex':self.pubs['prepolicy'],
                       'isolation_issuer_public_hex':self.pubs['preisolation'],
                       'server_public_hex':self.pubs['preserver']})
        self.prepath=self.root/'preflight.json';docfile(self.prepath,prepol)
        self.presha=p.sha(self.prepath.read_bytes())
        archive=io.BytesIO()
        with tarfile.open(fileobj=archive,mode='w:') as tar:
            info=tarfile.TarInfo('tests/test_example.py')
            data=b'def test_works():\n  assert True\n'
            info.size=len(data);tar.addfile(info,io.BytesIO(data))
        source=self.root/'source.tar';bytesfile(source,archive.getvalue())
        private=self.root/'broker';private.mkdir(mode=0o700)
        for name in ('scratch','home','xdg','ledger'):
            (self.root/name).mkdir(mode=0o700)
        leasepol={'schema':lease.POLICY_SCHEMA,
                  'source_tar_path':str(source),
                  'expected_source_tar_sha256':p.sha(source.read_bytes()),
                  'scratch_root':str(self.root/'scratch'),
                  'runtime_path':'/usr/bin/podman',
                  'expected_runtime_sha256':'9'*64,
                  'runtime_home':str(self.root/'home'),
                  'runtime_xdg_dir':str(self.root/'xdg'),
                  'image_id':'sha256:'+'8'*64,
                  'expected_ec186_catalog_sha256':catalog['catalog_sha256'],
                  'grants':[{'uid':os.geteuid(),'scope_id':'unit-local',
                             'profile_ids':[self.profile],
                             'allow_output_text':False}],
                  'authorized_source_pin_sha256':pin_sha,
                  'approval_ticket_path':prepol['approval_ticket_file'],
                  'isolation_ticket_path':prepol['lease_ticket_file'],
                  'approval_hmac_key_path':prepol['policy_key_file'],
                  'broker_hmac_key_path':prepol['broker_key_file'],
                  'ledger_root':str(self.root/'ledger')}
        self.leasepath=self.root/'ec253-policy.json';docfile(self.leasepath,leasepol)
        self.leasesha=p.sha(self.leasepath.read_bytes())
        # Fake strict socket for *local* EC187 controller testing only.
        self.sockparent=self.root/'sock';self.sockparent.mkdir(mode=0o700)
        self.strict=self.sockparent/'strict.sock'
        self.fake_strict=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.fake_strict.bind(str(self.strict));os.chmod(self.strict,0o660);self.fake_strict.listen(2)
        self.addCleanup(self.fake_strict.close)
        self.allowlist=self.root/'allowlist.json'
        docfile(self.allowlist,{'paths':['tests/test_example.py']})
        self.receipt=self.root/'custody.json'
        docfile(self.receipt,{'synthetic_fixture':True})
        self.policyfile=self.root/'execute-policy.json'
        self.summary=operator.prepare_policy(
            preflight_file=str(self.prepath),preflight_sha=self.presha,
            lease_file=str(self.leasepath),lease_sha=self.leasesha,
            git_repo=str(self.repo),allowlist_file=str(self.allowlist),
            receipt_file=str(self.receipt),session_socket=str(self.strict),
            session_uid=os.geteuid(),scope_id='unit-local',
            profile_id=self.profile,uids=[os.geteuid()],
            custodian_pub=self.pubs['custodian'],
            executor_pub=self.pubs['executor'],server_pub=self.pubs['server'],
            out=str(self.policyfile))
        self.polsha=self.summary['policy_sha256']
        self.pol=p.load_policy(str(self.policyfile),self.polsha)
        self.subject=p.new_subject(self.pol,self.polsha,uid=os.geteuid(),ttl=40)
        self.grant=self.sign_grant(self.subject)
        self.grantfile=self.root/'grant.json';docfile(self.grantfile,self.grant)
        self.socket=str(self.sockparent/'execute.sock')

    def sign_grant(self,subject):
        return {'schema':p.GRANT_SCHEMA,'subject':subject,
          'custodian_signature_ed25519':p.sign('custodian',subject,
              signio.private_from_file(str(self.keys['custodian']))),
          'executor_signature_ed25519':p.sign('executor',subject,
              signio.private_from_file(str(self.keys['executor'])))}

    def start(self):
        service=daemon.ExecuteServer(
            path=self.socket,policy_path=str(self.policyfile),
            policy_sha=self.polsha,
            private_key_file=str(self.keys['server']))
        thread=threading.Thread(target=service.serve_forever,
                                kwargs={'poll_interval':0.05},daemon=True)
        thread.start()
        self.addCleanup(lambda:(service.shutdown(),thread.join(2),service.server_close()))
        return service

    def call(self,grant=None):
        path=self.grantfile
        if grant is not None:
            path=self.root/('grant-'+str(time.time_ns())+'.json')
            docfile(path,grant)
        return operator.execute(socket_path=self.socket,grant_file=str(path),
                  policy_sha=self.polsha,server_pub=self.pubs['server'])

    def mocked_execution(self,* ,events=None, begin_failure:bool=False):
        test=self
        class FakeTrustedBroker:
            def __init__(self, socket_path,uid,scope):
                assert socket_path==test.strict.as_posix()
                assert uid==os.geteuid() and scope=='unit-local'
            def begin(self,request):
                if begin_failure:raise ConnectionError('no transport')
                return FakeSession(request,events or [event('exit',exit_code=0)])
        patches=[mock.patch.object(custody_gate.OperatorCustodyGate,'startup',
                                   return_value=None),
                 mock.patch.object(custody_gate.OperatorCustodyGate,'before_begin',
                                   return_value=None),
                 mock.patch.object(daemon.session,'TrustedBroker',FakeTrustedBroker)]
        for patch in patches:
            patch.start();self.addCleanup(patch.stop)

    def test_original_ec187_controller_real_hmac_signed_socket_synthetic_broker(self):
        self.mocked_execution()
        self.start()
        rc,env=self.call()
        self.assertEqual(rc,2)
        self.assertTrue(env['verified_server_signature'])
        self.assertTrue(env['original_ec259_session_begin_host_reported'])
        result=env['result']
        self.assertEqual(result['schema'],budget.SCHEMA)
        self.assertIn('EXIT_ZERO_UNVERIFIED',result['reason_code'])
        self.assertEqual(result['execution']['host_reported_exit_code'],0)
        self.assertFalse(result['proof']['quality_pass_verified'])
        self.assertFalse(env['independent_kernel_or_strict_service_attestation'])
        self.assertFalse(env['remote_ci_verified'])
        self.assertIsNone(result['output']['stdout_preview'])
        self.assertIsNone(result['output']['stderr_preview'])

    def test_reported_test_failure_still_partial_no_pass(self):
        self.mocked_execution(events=[event('exit',exit_code=17)])
        self.start()
        rc,env=self.call()
        self.assertEqual(rc,2)
        self.assertEqual(env['host_reported_execution_exit'],17)
        self.assertFalse(env['quality_pass_verified'])

    def test_valid_twin_roles_wrong_uid_refused_without_ec187(self):
        self.mocked_execution()
        self.start()
        altered=dict(self.subject,uid=os.geteuid()+1)
        rc,env=self.call(self.sign_grant(altered))
        self.assertEqual(rc,3)
        self.assertFalse(env['result']['backend_invoked'])

    def test_cross_role_substitution_denied(self):
        self.mocked_execution()
        self.start()
        altered=dict(self.grant,
            custodian_signature_ed25519=self.grant['executor_signature_ed25519'])
        rc,env=self.call(altered)
        self.assertEqual(rc,3)
        self.assertFalse(env['result']['backend_invoked'])

    def test_signer_future_expiry_and_old_nonce_refused(self):
        self.mocked_execution()
        self.start()
        expired=dict(self.subject,issued_at_unix=int(time.time())-200,
                     expires_at_unix=int(time.time())-180)
        rc,env=self.call(self.sign_grant(expired))
        self.assertEqual(rc,3)
        self.assertFalse(env['quality_pass_verified'])

    def test_host_policy_change_before_run_blocks(self):
        self.mocked_execution()
        self.start()
        self.policyfile.write_bytes(b'{"schema":"forged"}\n')
        rc,env=self.call()
        self.assertEqual(rc,5)
        self.assertFalse(env['result']['backend_invoked'])

    def test_backend_pin_change_blocks_before_original_ec187(self):
        self.mocked_execution()
        self.start()
        self.allowlist.write_bytes(b'changed\n')
        rc,env=self.call()
        self.assertEqual(rc,5)
        self.assertFalse(env['result']['lease_or_container_effect_unknown'])

    def test_original_ec253_hmac_replacement_is_denied(self):
        self.mocked_execution()
        self.start()
        bytesfile(Path(self.pol['preflight_policy_file']).parent/'broker_key.bin',b'X'*48)
        rc,env=self.call()
        self.assertEqual(rc,5)
        self.assertFalse(env['result']['lease_or_container_effect_unknown'])

    def test_original_budget_session_begin_failure_never_quality_pass(self):
        self.mocked_execution(begin_failure=True)
        self.start()
        rc,env=self.call()
        self.assertEqual(rc,2)
        self.assertTrue(env['lease_or_container_effect_unknown'])
        self.assertFalse(env['quality_pass_verified'])

    def test_signed_reply_nonce_and_fake_quality_pass_cannot_pass_verifier(self):
        req={'schema':p.REQUEST_SCHEMA,'nonce':'a'*32,'grant':self.grant}
        result=p.denial('EC286_TEST_FAILURE')
        key=signio.private_from_file(str(self.keys['server']))
        reply=p.signed_reply(req,result,self.polsha,key,int(time.time()))
        self.assertEqual(p.verify_reply(reply,req,self.pubs['server'],
                                        self.polsha,int(time.time())),result)
        modified=dict(reply,nonce='b'*32)
        with self.assertRaises(p.HostError):
            p.verify_reply(modified,req,self.pubs['server'],self.polsha,int(time.time()))
        wrong=dict(result,quality_pass_verified=True)
        forged=p.signed_reply(req,wrong,self.polsha,key,int(time.time()))
        with self.assertRaises(p.HostError):
            p.verify_reply(forged,req,self.pubs['server'],self.polsha,int(time.time()))

    def test_missing_reply_is_unknown_not_unsigned_success(self):
        # An existing but unserved socket accepts nothing; connection timeout
        # test uses a promptly closed endpoint to avoid a long fixture wait.
        self.start()
        with mock.patch.object(p,'verify_reply',side_effect=p.HostError('EC286_UNTRUSTED')):
            with self.assertRaises(p.HostError) as raised:
                self.call()
        self.assertEqual(raised.exception.code,
            'EC286_UNTRUSTED_SIGNED_RESPONSE_RUN_OUTCOME_UNKNOWN')

    def test_console_literal_binding_and_router_denial(self):
        import importlib.util
        import contextlib
        import io as buffer
        source=BASE.parent/'scripts'/'ces_next.py'
        spec=importlib.util.spec_from_file_location('ec286_console',source)
        console=importlib.util.module_from_spec(spec);spec.loader.exec_module(console)
        with self.assertRaises(console.ConsoleError):
            console.host_execute('QualityRun','Preflight',socket_path=self.socket,
                 grant_file=str(self.grantfile),policy_sha=self.polsha,
                 server_public_hex=self.pubs['server'])
        with self.assertRaises(console.ConsoleError) as err:
            console.run('QualityRun','Execute',str(self.grantfile))
        self.assertEqual(err.exception.status,'permission_denied')
        routes=console._inventory()['routes']
        self.assertEqual(len(routes),74)
        self.assertEqual(sum(1 for r in routes if r['route_kind']=='HOST_REQUIRED'),11)

    def test_console_real_opt_in_client_signed_bridge(self):
        import importlib.util
        import contextlib
        import io as buffer
        spec=importlib.util.spec_from_file_location('ec286_console',
            BASE.parent/'scripts'/'ces_next.py')
        console=importlib.util.module_from_spec(spec);spec.loader.exec_module(console)
        self.mocked_execution()
        self.start()
        output=buffer.StringIO()
        with contextlib.redirect_stdout(output):
            code=console.host_execute('QualityRun','Execute',socket_path=self.socket,
                grant_file=str(self.grantfile),policy_sha=self.polsha,
                server_public_hex=self.pubs['server'])
        self.assertEqual(code,2)
        body=json.loads(output.getvalue())
        self.assertTrue(body['verified_server_signature'])
        self.assertEqual(body['result']['schema'],budget.SCHEMA)
        self.assertFalse(body['quality_pass_verified'])

    def test_console_client_timeout_or_untrusted_reply_reports_unknown(self):
        import importlib.util
        import contextlib
        import io as buffer
        spec=importlib.util.spec_from_file_location('ec286_console',
            BASE.parent/'scripts'/'ces_next.py')
        console=importlib.util.module_from_spec(spec);spec.loader.exec_module(console)
        inventory=console._inventory()
        output=buffer.StringIO()
        with mock.patch.object(console,'_inventory',return_value=inventory), \
             mock.patch.object(console,'_command',side_effect=console.ConsoleError(
                 'EC278_ROUTER_PROCESS_UNAVAILABLE',status='unavailable')), \
             contextlib.redirect_stdout(output):
            code=console.host_execute('QualityRun','Execute',socket_path=self.socket,
                grant_file=str(self.grantfile),policy_sha=self.polsha,
                server_public_hex=self.pubs['server'])
        self.assertEqual(code,5)
        result=json.loads(output.getvalue())
        self.assertTrue(result['lease_or_container_effect_unknown'])
        self.assertFalse(result['verified_server_signature'])
        self.assertFalse(result['quality_pass_verified'])

    def test_original_result_contract_only_redacted_fixed_shape(self):
        self.mocked_execution()
        self.start()
        rc,env=self.call()
        self.assertEqual(rc,2)
        result=env['result']
        self.assertTrue(p.safe_backend_result(result))
        self.assertFalse(p.safe_backend_result({**result,'fake_verified':True}))
        self.assertFalse(p.safe_backend_result({**result,'output':{
            **result['output'],'stdout_preview':'secret'}}))
        self.assertFalse(p.safe_backend_result({**result,'proof':{
            **result['proof'],'quality_pass_verified':True}}))

    def test_original_ec187_fake_pass_result_explicitly_rejected(self):
        fake={'schema':budget.SCHEMA,'status':'partial','exit_code':2,
              'proof':{'quality_pass_verified':True},
              'effects':{'tests_verified_by_ces':False,
                         'writes_performed_by_ces':False,
                         'real_kernel_isolation_verified_by_ces':False},
              'execution':{'overall_pass_verified':False,
                           'actual_process_exit_independently_verified':False}}
        self.assertFalse(p.safe_backend_result(fake))


if __name__=='__main__':
    unittest.main()
