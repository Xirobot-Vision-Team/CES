#!/usr/bin/env python3
"""EC339 genuine 4 issuer signatures/status records + real EC338->337 bytes.

Only local synthetic authority and transport credentials are constructed. The
inherited EC317/318 deep old-signature fixture remains MOCK; no physical issuer
or clock/revocation authority is being certified by these tests.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from delivery_anchor import anchor
from offline_transfer_registry import registry as reg
from fork_case_transport import case
from dual_channel_receipt import receipt as prior
from airgap_transport import test_transport as prior_transport_tests
from independent_custody import ceremony
from scripts import ces_next
from . import authority as a

ROOT=Path(__file__).resolve().parents[2]
EVAL='2026-10-25T10:20:00Z'
CHALLENGE='56'*32


def bare_key(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.Raw,
                             serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())


class PinnedIssuerEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=prior_transport_tests.OfflineOriginalTransportTests(
            methodName='test_deterministic_real_byte_export_and_canonical_bounded_zip')
        cls.fixture.setUp()
        cls.fixture.create()
        cls.base=Path(cls.fixture.base)
        cls.pins=cls.fixture.pins()
        cls.pins['expected_bundle_sha256']=cls.fixture.bundle_sha
        cls.actors=[]
        cls.keys=[]
        cls.issuer_keys=[]
        cls.issuer_key_files=[]
        cls.role_key_files=[]
        cls.grant_files=[]
        cls.grant_shas=[]
        cls.issuers=[]
        for idx,role in enumerate(a.ROLES):
            actor=Ed25519PrivateKey.generate()
            issuer=Ed25519PrivateKey.generate()
            cls.keys.append(actor);cls.issuer_keys.append(issuer)
            actor_pub=actor.public_key().public_bytes(
                serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
            issuer_pub=issuer.public_key().public_bytes(
                serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
            rolekey=cls.base/('ec339-'+role+'-role-key.bin')
            issuerkey=cls.base/('ec339-'+role+'-issuer-key.bin')
            rolekey.write_bytes(bare_key(actor));os.chmod(rolekey,0o600)
            issuerkey.write_bytes(bare_key(issuer));os.chmod(issuerkey,0o600)
            cls.role_key_files.append(str(rolekey))
            cls.issuer_key_files.append(str(issuerkey))
            grant=str(cls.base/('ec339-'+role+'-authorization.json'))
            issue=a.issue_grant(
                out=grant,private_key_file=str(issuerkey),role=role,
                issuer_id='issuer_'+role,grant_id='grant_'+role,
                transfer_id='ec339_transfer_001',
                bundle_original_raw_sha256=cls.fixture.bundle_sha,
                actor_id='custody_'+role,organization_id='org_'+role,
                subject_public_hex=actor_pub,
                issued_utc='2026-10-24T11:00:00Z',
                not_before_utc='2026-10-24T10:00:00Z',
                not_after_utc='2026-11-24T10:00:00Z')
            assert issue['exit_code']==2
            grant_sha=case.sha(Path(grant).read_bytes())
            cls.grant_files.append(grant);cls.grant_shas.append(grant_sha)
            cls.actors.append({'role':role,'actor_id':'custody_'+role,
                'organization_id':'org_'+role,'public_hex':actor_pub,
                'authorization_reference_sha256':grant_sha})
            cls.issuers.append({'role':role,'issuer_id':'issuer_'+role,
                'issuer_public_hex':issuer_pub,
                'subject_organization_id':'org_'+role})
        cls.policy_file=str(cls.base/'ec339-ec338-policy.json')
        pol={'schema':ceremony.POLICY_SCHEMA,
             'transfer_id':'ec339_transfer_001',
             'medium_identifier_sha256':'87'*32,
             'original_roots':ceremony._roots(cls.pins),'actors':cls.actors,
             'authority_and_revocation_require_external_verification':True}
        prior._write_exclusive(cls.policy_file,reg.raw_doc(pol))
        cls.policy_sha=case.sha(Path(cls.policy_file).read_bytes())
        cls.roster_file=str(cls.base/'ec339-pinned-issuer-roster.json')
        roster={'schema':a.ROSTER_SCHEMA,'transfer_id':pol['transfer_id'],
                'policy_original_raw_sha256':cls.policy_sha,
                'issuers':cls.issuers,
                'external_issuer_trust_and_rotation_required':True}
        prior._write_exclusive(cls.roster_file,reg.raw_doc(roster))
        cls.roster_sha=case.sha(Path(cls.roster_file).read_bytes())
        cls.receipt_files=[];cls.receipt_shas=[]
        for i,role in enumerate(a.ROLES):
            path=str(cls.base/('ec339-'+role+'-role-receipt.json'))
            doc=ceremony.sign_receipt(
                role=role,out=path,private_key_file=cls.role_key_files[i],
                nonce_sha256=f'{i+50:064x}',
                signer_reported_utc=f'2026-10-25T10:00:0{i}Z',
                policy_file=cls.policy_file,
                expected_policy_sha256=cls.policy_sha,
                bundle_file=cls.fixture.arch,
                prior_receipt_files=cls.receipt_files[:],
                prior_receipt_shas=cls.receipt_shas[:],**cls.pins)
            assert doc['exit_code']==2
            cls.receipt_files.append(path)
            cls.receipt_shas.append(case.sha(Path(path).read_bytes()))
        cls.status_files=[];cls.status_shas=[]
        for i,role in enumerate(a.ROLES):
            path=str(cls.base/('ec339-'+role+'-active-status.json'))
            doc=a.issue_status(
                out=path,private_key_file=cls.issuer_key_files[i],role=role,
                policy_file=cls.policy_file,expected_policy_sha256=cls.policy_sha,
                authority_roster_file=cls.roster_file,
                expected_authority_roster_sha256=cls.roster_sha,
                grant_file=cls.grant_files[i],expected_grant_sha256=cls.grant_shas[i],
                verifier_challenge_sha256=CHALLENGE,state='active',
                as_of_utc='2026-10-25T10:00:00Z',
                expires_utc='2026-10-25T11:00:00Z')
            assert doc['exit_code']==2
            cls.status_files.append(path)
            cls.status_shas.append(case.sha(Path(path).read_bytes()))

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls,'fixture'):cls.fixture.doCleanups()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=self.base)
        self.addCleanup(self.temp.cleanup)
        self.tmp=Path(self.temp.name)

    def arguments(self):
        opts={'policy_file':self.policy_file,
              'expected_policy_sha256':self.policy_sha,
              'bundle_file':self.fixture.arch,
              **self.pins,
              'authority_roster_file':self.roster_file,
              'expected_authority_roster_sha256':self.roster_sha,
              'evaluation_utc':EVAL,
              'verifier_challenge_sha256':CHALLENGE}
        for i,role in enumerate(a.ROLES):
            for typ,files,shas in (
                ('receipt',self.receipt_files,self.receipt_shas),
                ('grant',self.grant_files,self.grant_shas),
                ('status',self.status_files,self.status_shas)):
                opts[role+'_'+typ+'_file']=files[i]
                opts['expected_'+role+'_'+typ+'_sha256']=shas[i]
        return opts

    def candidate(self,typ,idx,update,*,resign=False,raw=None):
        source={'grant':self.grant_files,'status':self.status_files,
                'receipt':self.receipt_files}[typ][idx]
        doc=json.loads(Path(source).read_bytes())
        update(doc)
        if resign:
            if typ=='status':
                key=self.issuer_keys[idx];domain=a._domain('Status',a.ROLES[idx])
            elif typ=='grant':
                key=self.issuer_keys[idx];domain=a._domain('Grant',a.ROLES[idx])
            else:
                key=self.keys[idx];domain=ceremony._domain(a.ROLES[idx])
            doc['signature_ed25519']=key.sign(domain+reg.canonical(doc['claim'])).hex()
        payload=raw if raw is not None else reg.raw_doc(doc)
        path=str(self.tmp/(typ+'-'+str(idx)+'.json'))
        prior._write_exclusive(path,payload)
        options=self.arguments()
        role=a.ROLES[idx]
        options[role+'_'+typ+'_file']=path
        options['expected_'+role+'_'+typ+'_sha256']=case.sha(payload)
        return options

    def test_genuine_authority_evidence_and_full_ec338_ec337_zip_replay(self):
        doc=a.verify_authority(**self.arguments())
        self.assertEqual(doc['exit_code'],2)
        self.assertEqual(doc['issuer_approved_role_count'],4)
        self.assertEqual(doc['active_status_signed_count'],4)
        self.assertTrue(doc['ec337_complete_archive_and_nested_originals_verified'])
        self.assertTrue(doc['ec338_four_signed_receipts_verified'])
        self.assertTrue(all(doc[x] is False for x in a.FALSE_FIELDS))
        self.assertEqual(doc['grant_original_raw_sha256s']['witness'],self.grant_shas[3])

    def test_all_nine_new_separate_raw_sha_pins_fail_if_wrong(self):
        for key in ['expected_authority_roster_sha256',
                    *(f'expected_{role}_{typ}_sha256' for role in a.ROLES
                      for typ in ('grant','status'))]:
            with self.subTest(key=key):
                opts=self.arguments();opts[key]='f4'*32
                with self.assertRaises(anchor.AnchorError):a.verify_authority(**opts)

    def test_operator_challenge_replay_rejected_even_with_genuine_issuer_signature(self):
        opts=self.arguments();opts['verifier_challenge_sha256']='9a'*32
        with self.assertRaisesRegex(anchor.AnchorError,'CHALLENGE'):
            a.verify_authority(**opts)

    def test_signed_active_status_can_become_revoked_and_fail_closed(self):
        opts=self.candidate('status',2,lambda d:d['claim'].update(
            state='revoked',revoked_effective_utc='2026-10-25T10:10:00Z'),resign=True)
        with self.assertRaisesRegex(anchor.AnchorError,'REVOKED'):
            a.verify_authority(**opts)

    def test_expired_status_and_maximum_freshness_window_rejected(self):
        opts=self.arguments();opts['evaluation_utc']='2026-10-25T11:00:00Z'
        with self.assertRaisesRegex(anchor.AnchorError,'STATUS_WINDOW'):
            a.verify_authority(**opts)
        opts=self.candidate('status',0,lambda d:d['claim'].update(
            expires_utc='2026-10-27T10:00:00Z'),resign=True)
        with self.assertRaisesRegex(anchor.AnchorError,'STATUS_WINDOW'):
            a.verify_authority(**opts)

    def test_status_wrong_grant_id_even_if_signed_again_denied(self):
        opts=self.candidate('status',1,lambda d:d['claim'].__setitem__(
            'grant_id','wrong_grant_99'),resign=True)
        with self.assertRaisesRegex(anchor.AnchorError,'STATUS_MUST_BIND'):
            a.verify_authority(**opts)

    def test_unsigned_status_mutation_cannot_pass_with_self_reported_sha(self):
        opts=self.candidate('status',3,lambda d:d['claim'].__setitem__(
            'as_of_utc','2026-10-25T10:10:00Z'))
        with self.assertRaisesRegex(anchor.AnchorError,'SIGNATURE_INVALID'):
            a.verify_authority(**opts)

    def test_roster_untrusted_issuer_swap_even_when_whole_sha_changed(self):
        doc=json.loads(Path(self.roster_file).read_bytes())
        doc['issuers'][0]['issuer_public_hex']=self.issuers[1]['issuer_public_hex']
        path=str(self.tmp/'wrong-roster.json')
        payload=reg.raw_doc(doc);prior._write_exclusive(path,payload)
        opts=self.arguments();opts['authority_roster_file']=path
        opts['expected_authority_roster_sha256']=case.sha(payload)
        with self.assertRaises(anchor.AnchorError):a.verify_authority(**opts)

    def test_grant_reference_is_ec338_policy_exact_whole_signed_grant_sha(self):
        doc=json.loads(Path(self.grant_files[0]).read_bytes())
        self.assertEqual(self.actors[0]['authorization_reference_sha256'],
                         case.sha(Path(self.grant_files[0]).read_bytes()))
        self.assertEqual(doc['claim']['subject_public_hex'],self.actors[0]['public_hex'])
        opts=self.candidate('grant',0,lambda d:d['claim'].__setitem__(
            'actor_id','other_actor'),resign=True)
        with self.assertRaisesRegex(anchor.AnchorError,'AUTHORIZATION_REFERENCE'):
            a.verify_authority(**opts)

    def test_sign_grant_bad_dates_and_same_role_issuer_key_denied(self):
        role='sender';key=self.role_key_files[0]
        with self.assertRaisesRegex(anchor.AnchorError,'ITS_OWN_ROLE'):
            a.issue_grant(out=str(self.tmp/'self.json'),private_key_file=key,
              role=role,issuer_id='issuer_sender',grant_id='grant_self',
              transfer_id='ec339_transfer_001',
              bundle_original_raw_sha256=self.fixture.bundle_sha,
              actor_id='custody_sender',organization_id='org_sender',
              subject_public_hex=self.actors[0]['public_hex'],
              issued_utc='2026-10-25T10:00:00Z',
              not_before_utc='2026-10-01T10:00:00Z',
              not_after_utc='2026-11-01T10:00:00Z')
        with self.assertRaisesRegex(anchor.AnchorError,'GRANT_VALIDITY_WINDOW'):
            a.issue_grant(out=str(self.tmp/'late.json'),private_key_file=self.issuer_key_files[0],
              role=role,issuer_id='issuer_sender',grant_id='grant_self',
              transfer_id='ec339_transfer_001',
              bundle_original_raw_sha256=self.fixture.bundle_sha,
              actor_id='custody_sender',organization_id='org_sender',
              subject_public_hex=self.actors[0]['public_hex'],
              issued_utc='2026-10-25T10:00:00Z',
              not_before_utc='2026-10-01T10:00:00Z',
              not_after_utc='2027-11-01T10:00:00Z')
        self.assertFalse((self.tmp/'late.json').exists())

    def test_invalid_status_key_not_a_writer_and_no_overwrite(self):
        args=dict(out=str(self.tmp/'denied.json'),private_key_file=self.role_key_files[0],
            role='sender',policy_file=self.policy_file,
            expected_policy_sha256=self.policy_sha,
            authority_roster_file=self.roster_file,
            expected_authority_roster_sha256=self.roster_sha,
            grant_file=self.grant_files[0],expected_grant_sha256=self.grant_shas[0],
            verifier_challenge_sha256=CHALLENGE,state='active',
            as_of_utc='2026-10-25T10:00:00Z',
            expires_utc='2026-10-25T11:00:00Z')
        with self.assertRaisesRegex(anchor.AnchorError,'PRIVATE_KEY_DOES_NOT_MATCH'):
            a.issue_status(**args)
        self.assertFalse(Path(args['out']).exists())
        args['private_key_file']=self.issuer_key_files[0]
        a.issue_status(**args)
        self.assertEqual(os.stat(args['out']).st_mode&0o777,0o600)
        original=Path(args['out']).read_bytes()
        with self.assertRaisesRegex(anchor.AnchorError,'OUTPUT_ALREADY_EXISTS'):
            a.issue_status(**args)
        self.assertEqual(Path(args['out']).read_bytes(),original)

    def test_owner_private_exact_canonical_json_symlink_or_mode_rejected(self):
        path=self.tmp/'link.json';path.symlink_to(self.status_files[1])
        opts=self.arguments();opts['carrier_status_file']=str(path)
        with self.assertRaises(anchor.AnchorError):a.verify_authority(**opts)
        path=self.tmp/'world_readable.json'
        path.write_bytes(Path(self.status_files[1]).read_bytes());os.chmod(path,0o644)
        opts['carrier_status_file']=str(path)
        with self.assertRaises(anchor.AnchorError):a.verify_authority(**opts)
        opts=self.candidate('status',0,lambda d:None,
                            raw=Path(self.status_files[0]).read_bytes()+b'\n')
        with self.assertRaisesRegex(anchor.AnchorError,'CANONICAL'):
            a.verify_authority(**opts)

    def test_original_ec338_receipts_tamper_still_denied(self):
        opts=self.candidate('receipt',0,lambda d:d['claim'].__setitem__(
            'event','other'),resign=True)
        with self.assertRaises(anchor.AnchorError):a.verify_authority(**opts)

    def test_separate_isolated_receiver_cli_real_process(self):
        args=[]
        for key,value in self.arguments().items():
            args.extend(['--'+key.replace('_','-'),value])
        proc=subprocess.run([sys.executable,'-I','-B',
              str(ROOT/'scripts'/'ces_cas_issuer_authority.py'),
              'verify-authority',*args],text=True,capture_output=True,timeout=90)
        self.assertEqual(proc.returncode,2,proc.stdout[-800:]+proc.stderr[-400:])
        self.assertTrue(json.loads(proc.stdout)['issuer_sig_and_grant_actor_role_key_bound'])

    def test_separate_isolated_issuer_grant_and_status_cli_real_process(self):
        grant=str(self.tmp/'isolated-issuer-grant.json')
        args=['issue-grant','--out',grant,
          '--private-key-file',self.issuer_key_files[0],
          '--role','sender','--issuer-id','issuer_sender',
          '--grant-id','new_grant_sender','--transfer-id','ec339_transfer_001',
          '--bundle-original-raw-sha256',self.fixture.bundle_sha,
          '--actor-id','custody_sender','--organization-id','org_sender',
          '--subject-public-hex',self.actors[0]['public_hex'],
          '--issued-utc','2026-10-25T10:00:00Z',
          '--not-before-utc','2026-10-01T10:00:00Z',
          '--not-after-utc','2026-11-01T10:00:00Z']
        proc=subprocess.run([sys.executable,'-I','-B',
              str(ROOT/'scripts'/'ces_cas_issuer_authority.py'),*args],
              text=True,capture_output=True,timeout=90)
        self.assertEqual(proc.returncode,2,proc.stdout[-700:]+proc.stderr[-200:])
        self.assertTrue(Path(grant).exists())
        status=str(self.tmp/'isolated-status.json')
        args=['issue-status','--out',status,
          '--private-key-file',self.issuer_key_files[0],
          '--role','sender','--policy-file',self.policy_file,
          '--expected-policy-sha256',self.policy_sha,
          '--authority-roster-file',self.roster_file,
          '--expected-authority-roster-sha256',self.roster_sha,
          '--grant-file',self.grant_files[0],
          '--expected-grant-sha256',self.grant_shas[0],
          '--verifier-challenge-sha256',CHALLENGE,'--state','active',
          '--as-of-utc','2026-10-25T10:00:00Z',
          '--expires-utc','2026-10-25T11:00:00Z']
        proc=subprocess.run([sys.executable,'-I','-B',
              str(ROOT/'scripts'/'ces_cas_issuer_authority.py'),*args],
              text=True,capture_output=True,timeout=90)
        self.assertEqual(proc.returncode,2,proc.stdout[-700:]+proc.stderr[-200:])
        self.assertTrue(Path(status).exists())

    def test_unified_only_real_readonly_isolated_receiver(self):
        args=['DeliveryAudit','VerifyPinnedIssuerAuthorizationAndRevocation']
        for key,value in self.arguments().items():
            args.extend(['--'+key.replace('_','-'),value])
        proc=subprocess.run([sys.executable,'-I','-B',
              str(ROOT/'scripts'/'ces_next.py'),
              'audit-airgap-authority',*args],text=True,capture_output=True,timeout=90)
        self.assertEqual(proc.returncode,2,proc.stdout[-1000:]+proc.stderr[-250:])
        self.assertTrue(json.loads(proc.stdout)['ec338_four_signed_receipts_verified'])

    def test_unified_rejects_forged_success_or_writer_mode(self):
        opts=self.arguments()
        with patch.object(ces_next,'_command',return_value=(0,{'status':'success'})):
            with self.assertRaises(ces_next.ConsoleError):
                ces_next.audit_airgap_authority(
                    'DeliveryAudit','VerifyPinnedIssuerAuthorizationAndRevocation',**opts)
        with self.assertRaises(ces_next.ConsoleError):
            ces_next.audit_airgap_authority('DeliveryAudit','IssueStatus',**opts)


if __name__=='__main__':
    unittest.main()
