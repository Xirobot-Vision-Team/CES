#!/usr/bin/env python3
"""Focused EC340 actual Ed25519 8-way rotation, witness and deep historic audit.

Old EC317/318 deep historical data in inherited EC337 fixture are MOCK. These
checks do not certify physical issuer independence or a trustworthy clock.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from delivery_anchor import anchor
from offline_transfer_registry import registry as reg
from fork_case_transport import case
from dual_channel_receipt import receipt as prior
from offline_authority import test_authority as inherited_tests
from finding_query_host import protocol as io
from scripts import ces_next
from . import operator as op
from . import rotation as r

ROOT=Path(__file__).resolve().parents[2]


def pub(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw).hex()


def bare(key):
    return key.private_bytes(serialization.Encoding.Raw,
             serialization.PrivateFormat.Raw,serialization.NoEncryption())


def private(path,key):
    path.write_bytes(bare(key));os.chmod(path,0o600)


class IssuerRootRotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        inherited_tests.PinnedIssuerEvidenceTests.setUpClass()
        cls.parent=inherited_tests.PinnedIssuerEvidenceTests
        cls.work=Path(inherited_tests.PinnedIssuerEvidenceTests.base)
        cls.new_keys=[]
        cls.new_keypaths=[]
        new_issuers=[]
        for role in r.ROLES:
            key=Ed25519PrivateKey.generate()
            path=cls.work/('ec340-'+role+'-new-issuer.key')
            private(path,key)
            cls.new_keys.append(key);cls.new_keypaths.append(str(path))
            new_issuers.append({'role':role,'issuer_id':'epoch2_'+role,
                'issuer_public_hex':pub(key),
                'subject_organization_id':'org_'+role})
        cls.config_file=str(cls.work/'ec340-issuer-config.json')
        prior._write_exclusive(cls.config_file,reg.raw_doc({'issuers':new_issuers}))
        cls.config_sha=case.sha(Path(cls.config_file).read_bytes())
        cls.successor_file=str(cls.work/'ec340-successor-root.json')
        cls.context={'policy_file':inherited_tests.PinnedIssuerEvidenceTests.policy_file,
            'expected_policy_sha256':inherited_tests.PinnedIssuerEvidenceTests.policy_sha,
            'authority_roster_file':inherited_tests.PinnedIssuerEvidenceTests.roster_file,
            'expected_authority_roster_sha256':inherited_tests.PinnedIssuerEvidenceTests.roster_sha}
        issued=r.create_successor_roster(out=cls.successor_file,
                 issuer_config_file=cls.config_file,
                 expected_issuer_config_sha256=cls.config_sha,
                 rotation_id='rotation_340_example',
                 rotation_nonce_sha256='77'*32,
                 effective_utc='2026-10-25T11:00:00Z',**cls.context)
        assert issued['exit_code']==2
        cls.successor_sha=case.sha(Path(cls.successor_file).read_bytes())
        cls.succ={'successor_roster_file':cls.successor_file,
                  'expected_successor_roster_sha256':cls.successor_sha}
        cls.edge_files={};cls.edge_shas={}
        for side,role in r.EDGE_KEYS:
            i=r.ROLES.index(role)
            path=str(cls.work/f'ec340-{side}-{role}-root-edge.json')
            keyfile=inherited_tests.PinnedIssuerEvidenceTests.issuer_key_files[i] if side=='old' else cls.new_keypaths[i]
            doc=r.sign_edge(out=path,private_key_file=keyfile,
                            side=side,role=role,**cls.context,**cls.succ)
            assert doc['exit_code']==2
            cls.edge_files[(side,role)]=path
            cls.edge_shas[(side,role)]=case.sha(Path(path).read_bytes())
        cls.observer_key=Ed25519PrivateKey.generate()
        cls.observer_key_path=str(cls.work/'ec340-observer.key')
        private(Path(cls.observer_key_path),cls.observer_key)
        cls.observer_file=str(cls.work/'ec340-observer-root.json')
        obs={'schema':r.OBSERVER_ROOT_SCHEMA,
             'transfer_id':'ec339_transfer_001',
             'policy_original_raw_sha256':inherited_tests.PinnedIssuerEvidenceTests.policy_sha,
             'observer_id':'root_observer_340',
             'observer_organization_id':'org_independent_observer',
             'observer_public_hex':pub(cls.observer_key),
             'independent_out_of_band_approval_required':True}
        prior._write_exclusive(cls.observer_file,reg.raw_doc(obs))
        cls.observer_sha=case.sha(Path(cls.observer_file).read_bytes())
        cls.observer={'observer_roster_file':cls.observer_file,
                      'expected_observer_roster_sha256':cls.observer_sha}
        cls.obs_file=str(cls.work/'ec340-signed-observation.json')
        obsissued=r.issue_observation(out=cls.obs_file,
             private_key_file=cls.observer_key_path,
             edge_files=cls.edge_files,edge_shas=cls.edge_shas,
             verifier_challenge_sha256='56'*32,
             observed_utc='2026-10-25T11:20:00Z',
             expires_utc='2026-10-25T12:20:00Z',
             **cls.context,**cls.succ,**cls.observer)
        assert obsissued['exit_code']==2
        cls.obs_sha=case.sha(Path(cls.obs_file).read_bytes())
        cls.base_opts={'bundle_file':inherited_tests.PinnedIssuerEvidenceTests.fixture.arch,
                       'expected_bundle_sha256':inherited_tests.PinnedIssuerEvidenceTests.fixture.bundle_sha,
                       **inherited_tests.PinnedIssuerEvidenceTests.pins,
                       'evaluation_utc':'2026-10-25T10:20:00Z',
                       'verifier_challenge_sha256':'56'*32}
        for i,role in enumerate(r.ROLES):
            for typ in ('receipt','grant','status'):
                arr=getattr(inherited_tests.PinnedIssuerEvidenceTests,typ+'_files')
                shas=getattr(inherited_tests.PinnedIssuerEvidenceTests,typ+'_shas')
                cls.base_opts[role+'_'+typ+'_file']=arr[i]
                cls.base_opts['expected_'+role+'_'+typ+'_sha256']=shas[i]

    @classmethod
    def tearDownClass(cls):
        inherited_tests.PinnedIssuerEvidenceTests.tearDownClass()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=str(self.work))
        self.addCleanup(self.temp.cleanup)
        self.tmp=Path(self.temp.name)

    def args(self):
        return {**self.context,**self.succ,**self.observer,
                'expected_current_root_sha256':self.successor_sha,
                'expected_current_root_epoch':2,
                'root_observation_file':self.obs_file,
                'expected_root_observation_sha256':self.obs_sha,
                'edge_files':self.edge_files,
                'edge_shas':self.edge_shas,
                'root_evaluation_utc':'2026-10-25T11:40:00Z',
                **self.base_opts}

    def arguments_cli(self):
        args=self.args()
        args.pop('edge_files');args.pop('edge_shas')
        for (side,role),path in self.edge_files.items():
            args[side+'_'+role+'_edge_file']=path
            args['expected_'+side+'_'+role+'_edge_sha256']=self.edge_shas[(side,role)]
        return args

    def cli(self,unified=False, **changes):
        args=self.arguments_cli();args.update(changes)
        if unified:
            base=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_next.py'),
               'audit-issuer-root-rotation','DeliveryAudit',
               'VerifyCrossSignedIssuerRootRotation']
        else:
            base=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_cas_issuer_rotation.py'),
                  'verify-rotation']
        for name in op.VERIFY_KEYS:
            base += ['--'+name.replace('_','-'),str(args[name])]
        run=subprocess.run(base,cwd=ROOT,stdin=subprocess.DEVNULL,
              stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=90)
        return run.returncode,json.loads(run.stdout)

    def test_a_full_8_genuine_ed25519_cross_signed_and_history_replay(self):
        doc=r.verify_rotation(**self.args())
        self.assertEqual(doc['exit_code'],2)
        self.assertTrue(doc['historical_ec339_to_ec337_original_full_replay_verified'])
        self.assertTrue(doc['independent_observer_challenged_signed_retirement_verified'])
        self.assertEqual(len(doc['edge_signature_original_raw_sha256s']),8)
        self.assertTrue(all(doc[k] is False for k in r.NEGATIVES))

    def test_b_every_signature_and_pin_rechecked(self):
        predecessor=json.loads(Path(self.context['authority_roster_file']).read_text())
        successor=json.loads(Path(self.successor_file).read_text())
        for side,role in r.EDGE_KEYS:
            with self.subTest(side=side,role=role):
                r._verify_edge(self.edge_files[(side,role)],self.edge_shas[(side,role)],
                     side,role,successor,predecessor,self.context['expected_authority_roster_sha256'],
                     self.successor_sha)
                with self.assertRaises(anchor.AnchorError):
                    r._verify_edge(self.edge_files[(side,role)],'e4'*32,side,role,
                         successor,predecessor,self.context['expected_authority_roster_sha256'],
                         self.successor_sha)

    def test_c_challenge_replay_rejected(self):
        opts=self.args();opts['verifier_challenge_sha256']='fe'*32
        with self.assertRaises(anchor.AnchorError): r.verify_rotation(**opts)

    def test_d_rollback_epoch_and_root_sha_fail_before_old_history(self):
        for epoch,sha in [(1,self.successor_sha),(3,self.successor_sha),
                          (2,self.context['expected_authority_roster_sha256'])]:
            opts=self.args();opts['expected_current_root_epoch']=epoch
            opts['expected_current_root_sha256']=sha
            with self.assertRaises(anchor.AnchorError):r.verify_rotation(**opts)

    def test_e_expired_or_future_observer_snapshot_rejected(self):
        for utc in ('2026-10-25T11:19:59Z','2026-10-25T12:20:00Z'):
            opts=self.args();opts['root_evaluation_utc']=utc
            with self.assertRaises(anchor.AnchorError):r.verify_rotation(**opts)

    def test_f_old_root_cannot_authorize_history_after_retirement(self):
        opts=self.args();opts['evaluation_utc']='2026-10-25T11:01:00Z'
        with self.assertRaises(anchor.AnchorError):r.verify_rotation(**opts)

    def test_g_role_private_key_isolation_and_no_overwrite(self):
        path=str(self.tmp/'edge.json')
        with self.assertRaises(anchor.AnchorError):r.sign_edge(out=path,
             private_key_file=self.new_keypaths[0],side='old',role='sender',
             **self.context,**self.succ)
        issued=r.sign_edge(out=path,private_key_file=self.new_keypaths[0],
                side='new',role='sender',**self.context,**self.succ)
        self.assertEqual(issued['exit_code'],2)
        self.assertEqual(Path(path).stat().st_mode & 0o777,0o600)
        with self.assertRaises((OSError,anchor.AnchorError)):
            r.sign_edge(out=path,private_key_file=self.new_keypaths[0],
                  side='new',role='sender',**self.context,**self.succ)

    def test_h_tampered_edge_even_re_pinned_cannot_pass_signature(self):
        tampered=json.loads(Path(self.edge_files[('new','carrier')]).read_text())
        tampered['claim']['effective_utc']='2026-10-26T11:00:00Z'
        raw=reg.raw_doc(tampered)
        path=str(self.tmp/'forged-edge.json')
        prior._write_exclusive(path,raw)
        pre=json.loads(Path(self.context['authority_roster_file']).read_text())
        suc=json.loads(Path(self.successor_file).read_text())
        with self.assertRaises(anchor.AnchorError):
            r._verify_edge(path,case.sha(raw),'new','carrier',suc,pre,
              self.context['expected_authority_roster_sha256'],self.successor_sha)

    def test_i_roster_key_reuse_aba_or_actor_key_rejected(self):
        policy=json.loads(Path(self.context['policy_file']).read_text())
        pre=json.loads(Path(self.context['authority_roster_file']).read_text())
        for pubvalue in (pre['issuers'][0]['issuer_public_hex'],
                          policy['actors'][0]['public_hex']):
            suc=json.loads(Path(self.successor_file).read_text())
            suc['issuers'][0]['issuer_public_hex']=pubvalue
            with self.assertRaises(anchor.AnchorError):r._validate_successor(
                suc,pre,self.context['expected_authority_roster_sha256'],
                policy,self.context['expected_policy_sha256'])

    def test_j_observer_key_does_not_match_issuer_key(self):
        path=str(self.tmp/'obs.json')
        with self.assertRaises(anchor.AnchorError):r.issue_observation(
            out=path,private_key_file=self.new_keypaths[0],
            edge_files=self.edge_files,edge_shas=self.edge_shas,
            verifier_challenge_sha256='56'*32,
            observed_utc='2026-10-25T11:20:00Z',
            expires_utc='2026-10-25T12:20:00Z',
            **self.context,**self.succ,**self.observer)
        self.assertFalse(Path(path).exists())

    def test_k_observer_status_signer_forgery_even_re_pinned_rejected(self):
        doc=json.loads(Path(self.obs_file).read_text())
        doc['claim']['predecessor_root_state']='active'
        raw=reg.raw_doc(doc)
        path=str(self.tmp/'fake-status.json');prior._write_exclusive(path,raw)
        opts=self.args();opts['root_observation_file']=path
        opts['expected_root_observation_sha256']=case.sha(raw)
        with self.assertRaises(anchor.AnchorError):r.verify_rotation(**opts)

    def test_l_unified_only_readonly_and_exact_reply(self):
        rc,doc=self.cli(unified=True)
        self.assertEqual(rc,2)
        self.assertEqual(doc['schema'],r.RESULT_SCHEMA)
        self.assertEqual(doc['external_current_root_epoch'],2)
        self.assertEqual(doc['root_observation_original_raw_sha256'],self.obs_sha)
        self.assertTrue(doc['historical_ec339_not_accepted_as_new_epoch_authorization'])
        fake={name:self.arguments_cli()[name] for name in op.VERIFY_KEYS}
        with self.assertRaises(ces_next.ConsoleError):
            ces_next.audit_issuer_root_rotation(
                'DeliveryAudit','IssueRootObservation',**fake)

    def test_m_symlink_or_world_readable_successor_denied(self):
        other=str(self.tmp/'symlink-root.json')
        os.symlink(self.successor_file,other)
        with self.assertRaises(anchor.AnchorError):r._read(other,self.successor_sha,
                                                           'SYMLINK_ROOT')
        other2=str(self.tmp/'loose-root.json')
        Path(other2).write_bytes(Path(self.successor_file).read_bytes())
        os.chmod(other2,0o644)
        with self.assertRaises((anchor.AnchorError,io.HostError)):
            r._read(other2,self.successor_sha,'LOOSE_ROOT')


    def test_n_three_isolated_candidate_writer_commands_are_real_and_no_overwrite(self):
        script=str(ROOT/'scripts/ces_cas_issuer_rotation.py')
        def run(subcommand,kw):
            cmd=[sys.executable,'-I','-B',script,subcommand]
            for key,value in kw.items():
                cmd.extend(['--'+key.replace('_','-'),str(value)])
            job=subprocess.run(cmd,cwd=ROOT,stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=25)
            return job.returncode,json.loads(job.stdout)
        roster_out=str(self.tmp/'roster.json')
        roster_args=dict(out=roster_out,issuer_config_file=self.config_file,
            expected_issuer_config_sha256=self.config_sha,
            rotation_id='rotation_340_example',rotation_nonce_sha256='77'*32,
            effective_utc='2026-10-25T11:00:00Z',**self.context)
        rc,doc=run('create-roster',roster_args)
        self.assertEqual(rc,2)
        self.assertEqual(doc['successor_root_original_raw_sha256_local_untrusted'],
                         self.successor_sha)
        self.assertEqual(Path(roster_out).stat().st_mode & 0o777,0o600)
        rc,denial=run('create-roster',roster_args)
        self.assertNotEqual(rc,2)
        self.assertEqual(case.sha(Path(roster_out).read_bytes()),self.successor_sha)
        edge_out=str(self.tmp/'edge.json')
        rc,doc=run('sign-edge',dict(out=edge_out,
            private_key_file=self.new_keypaths[0],side='new',role='sender',
            **self.context,**self.succ))
        self.assertEqual(rc,2)
        self.assertEqual(doc['edge_signature_original_raw_sha256_local_untrusted'],
                         self.edge_shas[('new','sender')])
        witness_out=str(self.tmp/'observation.json')
        kwargs=dict(out=witness_out,private_key_file=self.observer_key_path,
            **self.context,**self.succ,**self.observer,
            verifier_challenge_sha256='56'*32,
            observed_utc='2026-10-25T11:20:00Z',
            expires_utc='2026-10-25T12:20:00Z')
        for side,role in r.EDGE_KEYS:
            kwargs[side+'_'+role+'_edge_file']=self.edge_files[(side,role)]
            kwargs['expected_'+side+'_'+role+'_edge_sha256']=self.edge_shas[(side,role)]
        rc,doc=run('issue-observation',kwargs)
        self.assertEqual(rc,2)
        self.assertEqual(doc['root_observation_original_raw_sha256_local_untrusted'],
                         self.obs_sha)

    def test_o_observer_signature_tamper_even_with_matching_recomputed_sha(self):
        doc=json.loads(Path(self.obs_file).read_text())
        doc['signature_ed25519']=self.new_keys[0].sign(
            b'CES/EC340/IndependentRootRetirementObservation/v1\0'+
            reg.canonical(doc['claim'])).hex()
        raw=reg.raw_doc(doc)
        forged=str(self.tmp/'other-signer-observation.json')
        prior._write_exclusive(forged,raw)
        opts=self.args();opts['root_observation_file']=forged
        opts['expected_root_observation_sha256']=case.sha(raw)
        with self.assertRaises(anchor.AnchorError):r.verify_rotation(**opts)


if __name__=='__main__':
    unittest.main()
