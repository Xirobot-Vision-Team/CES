#!/usr/bin/env python3
"""EC338 actual signed-role chain + genuine EC337 complete byte transport fixture.

The historical EC317/318 deep signature fixture inherited by EC337 is MOCK;
these tests MUST NOT be mistaken for production old-signature/physical custody.
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

from ec295_delivery_anchor import anchor
from ec319_offline_transfer_registry import registry as reg
from ec321_fork_case_transport import case
from ec324_dual_channel_receipt import receipt as prior
from ec337_airgap_transport import test_transport as prior_transport_tests
from scripts import ces_next
from . import ceremony

ROOT=Path(__file__).resolve().parents[2]


class IndependentCustodyCeremonyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=prior_transport_tests.OfflineOriginalTransportTests(
            methodName='test_deterministic_real_byte_export_and_canonical_bounded_zip')
        cls.fixture.setUp()
        cls.fixture.create()
        cls.base=Path(cls.fixture.base)
        cls.pins=cls.fixture.pins()
        cls.pins['expected_bundle_sha256']=cls.fixture.bundle_sha
        cls.policy_file=str(cls.base/'ec338-custody-trust-roster.json')
        cls.key_files=[]
        cls.keys=[]
        actors=[]
        for i,role in enumerate(ceremony.ROLES):
            private=Ed25519PrivateKey.generate()
            cls.keys.append(private)
            pub=private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw).hex()
            key_file=cls.base/('ec338-'+role+'.pem')
            key_file.write_bytes(private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()))
            os.chmod(key_file,0o600)
            cls.key_files.append(str(key_file))
            actors.append({'role':role,'actor_id':'custody_'+role,
                           'organization_id':'org_'+role,
                           'public_hex':pub,
                           'authorization_reference_sha256':f'{i+11:064x}'})
        policy={'schema':ceremony.POLICY_SCHEMA,
                'transfer_id':'ec338_trial_transfer',
                'medium_identifier_sha256':'88'*32,
                'original_roots':ceremony._roots(cls.pins),
                'actors':actors,
                'authority_and_revocation_require_external_verification':True}
        prior._write_exclusive(cls.policy_file,reg.raw_doc(policy))
        cls.policy_sha=case.sha(Path(cls.policy_file).read_bytes())
        cls.receipt_files=[]
        cls.receipt_shas=[]
        for i,role in enumerate(ceremony.ROLES):
            name=str(cls.base/(f'ec338-role-{i+1}.json'))
            result=ceremony.sign_receipt(
                role=role,out=name,private_key_file=cls.key_files[i],
                nonce_sha256=f'{i+31:064x}',
                signer_reported_utc=f'2026-10-25T10:00:0{i}Z',
                policy_file=cls.policy_file,expected_policy_sha256=cls.policy_sha,
                bundle_file=cls.fixture.arch,
                prior_receipt_files=cls.receipt_files.copy(),
                prior_receipt_shas=cls.receipt_shas.copy(),**cls.pins)
            assert result['exit_code']==2
            cls.receipt_files.append(name)
            cls.receipt_shas.append(case.sha(Path(name).read_bytes()))

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls,'fixture'):
            cls.fixture.doCleanups()

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=self.base)
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def arguments(self):
        ret={
            'policy_file':self.policy_file,
            'expected_policy_sha256':self.policy_sha,
            'bundle_file':self.fixture.arch,
            **self.pins,
        }
        for role,path,sha in zip(ceremony.ROLES,self.receipt_files,self.receipt_shas):
            ret[role+'_receipt_file']=path
            ret['expected_'+role+'_receipt_sha256']=sha
        return ret

    def changed_receipt(self,idx,update,resign=False,raw_override=None):
        name=self.root/('candidate-'+str(idx)+'.json')
        obj=json.loads(Path(self.receipt_files[idx]).read_bytes())
        update(obj)
        if resign:
            obj['signature_ed25519']=self.keys[idx].sign(
                ceremony._domain(ceremony.ROLES[idx])+
                reg.canonical(obj['claim'])).hex()
        raw=raw_override if raw_override is not None else reg.raw_doc(obj)
        prior._write_exclusive(str(name),raw)
        args=self.arguments()
        role=ceremony.ROLES[idx]
        args[role+'_receipt_file']=str(name)
        args['expected_'+role+'_receipt_sha256']=case.sha(raw)
        return args

    def console_argv(self,args=None):
        if args is None:args=self.arguments()
        options=['DeliveryAudit','VerifyIndependentAirgapCustodyChain']
        for key,value in args.items():
            options+=['--'+key.replace('_','-'),value]
        return options

    def test_true_four_role_signatures_and_all_real_ec337_zip_bytes(self):
        doc=ceremony.verify_chain(**self.arguments())
        self.assertEqual(doc['exit_code'],2)
        self.assertEqual(doc['signature_count_verified'],4)
        self.assertEqual(doc['ec337_persistent_original_source_count'],22)
        self.assertEqual(doc['ec337_verified_nested_member_count'],15)
        self.assertTrue(doc['whole_receipt_external_sha_and_previous_raw_sha_chain_verified'])
        self.assertTrue(doc['ec337_complete_archive_and_nested_originals_verified'])
        self.assertTrue(all(doc[f] is False for f in ceremony.FALSE_FIELDS))
        self.assertFalse(doc['ec336_entire_unmocked_old_signed_history_replayed_by_this_audit'])

    def test_independently_pinned_each_receipt_sha_refuses_wrong_input(self):
        for role in ceremony.ROLES:
            with self.subTest(role=role):
                a=self.arguments();a['expected_'+role+'_receipt_sha256']='ee'*32
                with self.assertRaisesRegex(anchor.AnchorError,'WHOLE_SHA'):
                    ceremony.verify_chain(**a)

    def test_seven_old_roots_and_separately_trusted_policy_sha_must_match(self):
        for field in ['expected_policy_sha256',*self.pins]:
            with self.subTest(field=field):
                a=self.arguments();a[field]='dd'*32
                with self.assertRaises(anchor.AnchorError):
                    ceremony.verify_chain(**a)

    def test_receipt_valid_signature_but_wrong_previous_link_rejected(self):
        a=self.changed_receipt(2,lambda d:d['claim'].__setitem__(
            'previous_receipt_original_raw_sha256','67'*32),resign=True)
        with self.assertRaisesRegex(anchor.AnchorError,'PREVIOUS'):
            ceremony.verify_chain(**a)

    def test_receiver_receipt_signature_tampering_detected_with_pinned_changed_raw_sha(self):
        a=self.changed_receipt(2,lambda d:d.__setitem__(
            'signature_ed25519','12'*64))
        with self.assertRaisesRegex(anchor.AnchorError,'SIGNATURE_INVALID'):
            ceremony.verify_chain(**a)

    def test_role_swap_rejected_even_if_role_signer_resigns(self):
        a=self.changed_receipt(1,lambda d:d['claim'].__setitem__('role','sender'),
                               resign=True)
        with self.assertRaisesRegex(anchor.AnchorError,'ROLE_EVENT'):
            ceremony.verify_chain(**a)

    def test_claim_must_not_claim_physical_authority_true_even_if_correctly_signed(self):
        a=self.changed_receipt(3,lambda d:d['claim'].__setitem__(
            'physical_independence_or_institutional_authority_proven_by_software',True),
            resign=True)
        with self.assertRaisesRegex(anchor.AnchorError,'ROLE_EVENT'):
            ceremony.verify_chain(**a)

    def test_reused_nonce_rejected_even_with_genuine_key(self):
        reused=json.loads(Path(self.receipt_files[0]).read_bytes())['claim']['nonce_sha256']
        a=self.changed_receipt(3,lambda d:d['claim'].__setitem__('nonce_sha256',reused),
                               resign=True)
        with self.assertRaisesRegex(anchor.AnchorError,'NONCE_REUSED'):
            ceremony.verify_chain(**a)

    def test_no_self_authorized_witness_organization_in_roster(self):
        policy=json.loads(Path(self.policy_file).read_bytes())
        policy['actors'][3]['organization_id']=policy['actors'][2]['organization_id']
        candidate=self.root/'invalid-policy.json'
        raw=reg.raw_doc(policy);prior._write_exclusive(str(candidate),raw)
        a=self.arguments();a['policy_file']=str(candidate)
        a['expected_policy_sha256']=case.sha(raw)
        with self.assertRaisesRegex(anchor.AnchorError,'WITNESS_ORG'):
            ceremony.verify_chain(**a)

    def test_roster_same_public_key_and_actor_replay_denied(self):
        policy=json.loads(Path(self.policy_file).read_bytes())
        policy['actors'][3]['public_hex']=policy['actors'][0]['public_hex']
        candidate=self.root/'dupe-key.json'
        raw=reg.raw_doc(policy);prior._write_exclusive(str(candidate),raw)
        a=self.arguments();a['policy_file']=str(candidate)
        a['expected_policy_sha256']=case.sha(raw)
        with self.assertRaisesRegex(anchor.AnchorError,'WITNESS_ORG'):
            ceremony.verify_chain(**a)

    def test_policy_with_noncanonical_json_refused_even_if_external_pin_matches(self):
        raw=Path(self.policy_file).read_bytes().rstrip(b'\n') + b'\n\n'
        candidate=self.root/'noncanonical.json'
        prior._write_exclusive(str(candidate),raw)
        a=self.arguments();a['policy_file']=str(candidate)
        a['expected_policy_sha256']=case.sha(raw)
        with self.assertRaisesRegex(anchor.AnchorError,'NONCANONICAL'):
            ceremony.verify_chain(**a)

    def test_signing_key_mismatch_denies_before_output_creation(self):
        name=str(self.root/'must-not-appear.json')
        with self.assertRaisesRegex(anchor.AnchorError,'LOCAL_SECRET_KEY'):
            ceremony.sign_receipt(
                role='sender',out=name,private_key_file=self.key_files[1],
                nonce_sha256='b5'*32,signer_reported_utc='2026-10-25T10:10:10Z',
                policy_file=self.policy_file,expected_policy_sha256=self.policy_sha,
                bundle_file=self.fixture.arch,prior_receipt_files=[],
                prior_receipt_shas=[],**self.pins)
        self.assertFalse(os.path.lexists(name))

    def test_signing_does_not_overwrite_existing_original_receipt(self):
        name=str(self.root/'already-exists.json')
        Path(name).write_bytes(b'UNTOUCHED')
        os.chmod(name,0o600)
        with self.assertRaises(anchor.AnchorError):
            ceremony.sign_receipt(
                role='sender',out=name,private_key_file=self.key_files[0],
                nonce_sha256='b6'*32,signer_reported_utc='2026-10-25T10:10:11Z',
                policy_file=self.policy_file,expected_policy_sha256=self.policy_sha,
                bundle_file=self.fixture.arch,prior_receipt_files=[],
                prior_receipt_shas=[],**self.pins)
        self.assertEqual(Path(name).read_bytes(),b'UNTOUCHED')

    def test_receiver_signed_file_symlink_refused_without_following(self):
        candidate=self.root/'symlink.json'
        candidate.symlink_to(self.receipt_files[3])
        a=self.arguments();a['witness_receipt_file']=str(candidate)
        with self.assertRaises(anchor.AnchorError):
            ceremony.verify_chain(**a)

    def test_true_isolated_standalone_receiver_process(self):
        cli=['--'+key.replace('_','-') for key in ()]
        for key,value in self.arguments().items():
            cli+=['--'+key.replace('_','-'),value]
        proc=subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_cas_custody_chain.py'),
                             'verify-chain',*cli],capture_output=True,text=True,timeout=90)
        self.assertEqual(proc.returncode,2,proc.stdout[-1000:]+proc.stderr[-300:])
        doc=json.loads(proc.stdout)
        self.assertTrue(doc['ed25519_role_scoped_independent_public_keys_verified'])

    def test_true_isolated_standalone_sender_signer_writes_private_valid_new_candidate(self):
        out=str(self.root/'isolated-sender-new.json')
        args=['sign-receipt','--role','sender','--out',out,
              '--private-key-file',self.key_files[0],
              '--nonce-sha256','90'*32,
              '--signer-reported-utc','2026-10-25T10:20:20Z',
              '--policy-file',self.policy_file,
              '--expected-policy-sha256',self.policy_sha,
              '--bundle-file',self.fixture.arch]
        for key,value in self.pins.items():
            args.extend(['--'+key.replace('_','-'),value])
        proc=subprocess.run([sys.executable,'-I','-B',
                             str(ROOT/'scripts'/'ces_cas_custody_chain.py'),
                             *args],capture_output=True,text=True,timeout=90)
        self.assertEqual(proc.returncode,2,proc.stdout[-800:]+proc.stderr[-300:])
        self.assertFalse(json.loads(proc.stdout)[
            'policy_whole_sha_or_public_keys_self_certify_real_institutional_authority'])
        self.assertEqual(os.stat(out).st_mode & 0o777,0o600)
        policy=json.loads(Path(self.policy_file).read_bytes())
        ceremony._load_receipt(out,case.sha(Path(out).read_bytes()),
                               policy,self.policy_sha,0,ceremony.ZERO)

    def test_real_unified_router_isolated_read_only_and_matches_twelve_external_pins(self):
        proc=subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_next.py'),
                             'audit-airgap-custody',*self.console_argv()],
                             capture_output=True,text=True,timeout=90)
        self.assertEqual(proc.returncode,2,proc.stdout[-1000:]+proc.stderr[-300:])
        doc=json.loads(proc.stdout)
        self.assertTrue(doc['ec337_complete_archive_and_nested_originals_verified'])
        self.assertFalse(doc['remote_cas_worm_actual_nonexecution_latest_winner_or_delivery_proven'])

    def test_unified_route_rejects_false_success_or_other_authority_claims(self):
        a=self.arguments()
        with patch.object(ces_next,'_command',return_value=(0,{'status':'success'})):
            with self.assertRaises(ces_next.ConsoleError):
                ces_next.audit_airgap_custody('DeliveryAudit',
                    'VerifyIndependentAirgapCustodyChain',**a)
        with self.assertRaises(ces_next.ConsoleError):
            ces_next.audit_airgap_custody('DeliveryAudit','SignCustody',**a)

    def test_wrong_protection_mode_and_unsupported_timestamp_rejected(self):
        candidate=self.root/'open.json'
        candidate.write_bytes(Path(self.receipt_files[0]).read_bytes())
        os.chmod(candidate,0o644)
        a=self.arguments();a['sender_receipt_file']=str(candidate)
        with self.assertRaises(anchor.AnchorError):
            ceremony.verify_chain(**a)
        self.assertFalse(ceremony._utc('2026-02-30T10:00:00Z'))
        self.assertFalse(ceremony._utc('2026-10-25T10:00:00+00:00'))


if __name__=='__main__':
    unittest.main()
