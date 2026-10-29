#!/usr/bin/env python3
"""EC306 focused REAL inherited EC294->EC305 signer/ACK integration cases."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from delivery_anchor import anchor as a
from portable_bundle import bundle as b
from receiver_ack import ack
from challenge_registry import registry as ec304
from registrar_rollover import rollover as ec305
from registrar_rollover.test_rollover import EC305RolloverCases as Base
from . import epochs as e

ROOT = Path(__file__).resolve().parents[2]


class EC306EpochCases(unittest.TestCase):
    @classmethod
    def _key(cls, name: str):
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw).hex()
        path = cls.home/(name+'.key')
        path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()))
        path.chmod(0o600)
        return key, public, str(path)

    @classmethod
    def _external(cls, response):
        return {
            'registry_id': Base.trust['registry_id'],
            'governor_public_hex': Base.governor_pub,
            'initial_registrar_public_hex': Base.base.pub,
            'chain_raw_sha256': response['chain_raw_sha256'],
            'epoch_count': response['epoch_count'],
            'active_registrar_public_hex': response['active_registrar_public_hex'],
            'active_ledger_raw_sha256': response['active_ledger_raw_sha256'],
            'active_ledger_sequence': response['active_ledger_sequence']}

    @classmethod
    def _stage(cls, index: int, result: dict, ledgers: list[str], certs: list[str]):
        return {'chain_file':str(cls.home/f'epoch-chain-{index}.json'),
                'external':cls._external(result),
                'ledger_files':ledgers, 'certificate_files':certs}

    @classmethod
    def setUpClass(cls):
        Base.setUpClass()
        try:
            cls.tmp=tempfile.TemporaryDirectory(prefix='ec306-multi-epoch-')
            cls.home=Path(cls.tmp.name)
            cls.third_key, cls.third_pub, cls.third_private=cls._key('third-registrar')
            old_files=[str(Base.base.ledger2)]
            cls.initial=e.start(
                registry_id=Base.trust['registry_id'],
                governor_public_hex=Base.governor_pub,
                initial_registrar_public_hex=Base.base.pub,
                initial_ledger_file=old_files[0],
                expected_initial_ledger_sha256=Base.base.res2['ledger_raw_sha256'],
                expected_initial_sequence=2,
                out=str(cls.home/'epoch-chain-0.json'))
            cls.s0=cls._stage(0,cls.initial,old_files,[])
            cls.first_rotate=e.rotate(**cls.s0,
                new_registrar_public_hex=Base.active_pub,
                new_certificate_file=Base.cert_path,
                expected_new_certificate_sha256=Base.cert['certificate_raw_sha256'],
                cutover_nonce_sha256=Base.trust['cutover_nonce_sha256'],
                governance_decision_sha256=Base.trust['governance_decision_sha256'],
                cutover_mode='planned',out=str(cls.home/'epoch-chain-1.json'))
            cls.s1=cls._stage(1,cls.first_rotate,old_files,[Base.cert_path])
            cls.first_commit=e.commit(**cls.s1,**Base.newctx,
                candidate_ledger_file=str(Base.first_new_path),
                expected_candidate_ledger_sha256=Base.first_new['ledger_raw_sha256'],
                expected_candidate_sequence=1,
                out=str(cls.home/'epoch-chain-2.json'))
            cls.s2=cls._stage(2,cls.first_commit,
                old_files+[str(Base.first_new_path)],[Base.cert_path])
            cls.second_commit=e.commit(**cls.s2,**Base.morectx,
                candidate_ledger_file=str(Base.second_new_path),
                expected_candidate_ledger_sha256=Base.second_new['ledger_raw_sha256'],
                expected_candidate_sequence=2,
                out=str(cls.home/'epoch-chain-3.json'))
            cls.s3=cls._stage(3,cls.second_commit,
                old_files+[str(Base.second_new_path)],[Base.cert_path])

            # Second cutover is emergency, so the retiring third party
            # signature MUST be absent; activating/governance are real keys.
            cls.t2={
                'registry_id':Base.trust['registry_id'],
                'retiring_registrar_public_hex':Base.active_pub,
                'activating_registrar_public_hex':cls.third_pub,
                'governor_public_hex':Base.governor_pub,
                'old_ledger_raw_sha256':Base.second_new['ledger_raw_sha256'],
                'old_ledger_sequence':2,
                'cutover_nonce_sha256':'c'*64,
                'governance_decision_sha256':'d'*64,
                'cutover_mode':'emergency_compromised'}
            second_old=str(Base.second_new_path)
            cls.t2_intent_path=str(cls.home/'t2-intent.json')
            intent=ec305.prepare(trust=cls.t2,old_ledger_file=second_old,
                out=cls.t2_intent_path)
            cls.v2={}
            for role,priv in (('activating',cls.third_private),
                              ('governance',Base.governor_file)):
                fp=str(cls.home/f't2-{role}.vote.json')
                ec305.sign(trust=cls.t2,old_ledger_file=second_old,
                    intent_file=cls.t2_intent_path,
                    expected_intent_sha256=intent['intent_raw_sha256'],
                    role=role,private_key_file=priv,out=fp)
                cls.v2[role]=fp
            cls.t2_cert_path=str(cls.home/'t2-cert.json')
            cls.t2_cert=ec305.assemble(trust=cls.t2,old_ledger_file=second_old,
                intent_file=cls.t2_intent_path,
                expected_intent_sha256=intent['intent_raw_sha256'],
                retiring_vote_file=None,
                activating_vote_file=cls.v2['activating'],
                governance_vote_file=cls.v2['governance'],
                out=cls.t2_cert_path)
            cls.second_rotate=e.rotate(**cls.s3,
                new_registrar_public_hex=cls.third_pub,
                new_certificate_file=cls.t2_cert_path,
                expected_new_certificate_sha256=cls.t2_cert['certificate_raw_sha256'],
                cutover_nonce_sha256=cls.t2['cutover_nonce_sha256'],
                governance_decision_sha256=cls.t2['governance_decision_sha256'],
                cutover_mode='emergency_compromised',
                out=str(cls.home/'epoch-chain-4.json'))
            cls.s4=cls._stage(4,cls.second_rotate,
                old_files+[str(Base.second_new_path)],
                [Base.cert_path,cls.t2_cert_path])
            cls.third_ack_path=cls.home/'third-epoch-ack.json'
            new_ack_ctx={**Base.base.parent.context,
                         'challenge_sha256':'e'*64}
            cls.third_ack=ack.issue_ack(**new_ack_ctx,
                imported_dir=str(Base.base.parent.imported),
                receiver_private_key_file=str(Base.base.parent.private),
                out=str(cls.third_ack_path))
            cls.thirdctx={**Base.morectx,
                          'challenge_sha256':'e'*64,
                          'acknowledgement_file':str(cls.third_ack_path),
                          'expected_acknowledgement_sha256':cls.third_ack['acknowledgement_sha256']}
            cls.third_ledger_path=cls.home/'third-epoch-ledger.json'
            cls.third_record=e.register(**cls.s4,**cls.thirdctx,
                active_private_key_file=cls.third_private,
                out=str(cls.third_ledger_path))
            cls.third_commit=e.commit(**cls.s4,**cls.thirdctx,
                candidate_ledger_file=str(cls.third_ledger_path),
                expected_candidate_ledger_sha256=cls.third_record['ledger_raw_sha256'],
                expected_candidate_sequence=1,
                out=str(cls.home/'epoch-chain-5.json'))
            cls.s5=cls._stage(5,cls.third_commit,
                cls.s4['ledger_files']+[str(cls.third_ledger_path)],
                cls.s4['certificate_files'])
        except BaseException:
            if hasattr(cls,'tmp'):cls.tmp.cleanup()
            Base.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
        Base.tearDownClass()

    def _out(self, name):
        return str(self.home/name)

    def _flags(self, ctx):
        flags=['--chain-file',ctx['chain_file']]
        for k,v in ctx['external'].items():
            flags.extend(['--expected-'+k.replace('_','-'),str(v)])
        for path in ctx['ledger_files']:
            flags.extend(['--epoch-ledger-file',path])
        for path in ctx['certificate_files']:
            flags.extend(['--cutover-certificate-file',path])
        for k,v in self.thirdctx['pins'].items():
            flags.extend(['--expected-'+k.replace('_','-'),v])
        for key,value in self.thirdctx.items():
            if key=='pins':continue
            flag={'bundle_file':'bundle-file',
                  'expected_bundle_sha256':'expected-bundle-sha256',
                  'acknowledgement_file':'acknowledgement-file',
                  'expected_acknowledgement_sha256':'expected-acknowledgement-sha256',
                  'sender_id':'expected-sender-id',
                  'receiver_id':'expected-receiver-id',
                  'receiver_public_hex':'expected-receiver-public-hex',
                  'challenge_sha256':'expected-exchange-challenge-sha256'}[key]
            flags.extend(['--'+flag,value])
        return flags

    def test_01_two_real_independently_signed_cutovers_all_epochs_and_ack(self):
        hist=e.verify_history(**self.s5)
        proof=e.verify_latest(**self.s5,**self.thirdctx)
        self.assertEqual(hist['total_signed_ack_records'],5)
        self.assertEqual(proof['epoch_count'],3)
        self.assertEqual(proof['active_ledger_sequence'],1)
        self.assertEqual(proof['exit_code'],0)
        self.assertTrue(proof['latest_original_ec303_ack_replayed'])
        self.assertFalse(proof['old_zip_ack_payloads_replayed'])
        self.assertFalse(proof['external_latest_cas_worm_proven'])
        self.assertFalse(self.third_record['candidate_committed_to_chain'])
        self.assertEqual(self.t2_cert['cutover_mode'],'emergency_compromised')
        self.assertIsNone(json.loads(Path(self.t2_cert_path).read_bytes())['votes']['retiring'])

    def test_02_all_generations_spent_challenge_ack_and_role_collision_refused(self):
        for sha in ('5'*64,'6'*64,'8'*64,'9'*64):
            with self.subTest(challenge=sha), self.assertRaisesRegex(a.AnchorError,
                    'NEW_CHALLENGE_ALREADY_SPENT_IN_ANY_EPOCH'):
                e.register(**self.s4,**{**self.thirdctx,'challenge_sha256':sha},
                           active_private_key_file=self.third_private,
                           out=self._out('bad-'+sha[0]))
        with self.assertRaisesRegex(a.AnchorError,
                'NEW_ACK_ALREADY_SPENT_IN_ANY_EPOCH'):
            e.register(**self.s4,
                **{**self.thirdctx,'expected_acknowledgement_sha256':
                   Base.base.one['expected_acknowledgement_sha256']},
                active_private_key_file=self.third_private,
                out=self._out('bad-ack'))
        with self.assertRaisesRegex(a.AnchorError,
                'REGISTRAR_OF_ANY_EPOCH_OR_GOVERNOR_REUSED'):
            e.register(**self.s4,**{**self.thirdctx,'receiver_public_hex':Base.base.pub},
                       active_private_key_file=self.third_private,
                       out=self._out('bad-role'))

    def test_03_external_chain_hash_root_and_latest_pins_cannot_drift(self):
        with self.assertRaisesRegex(a.AnchorError,'CHAIN_BYTES_DIFFER'):
            e.verify_history(**{**self.s5,'external':{
                **self.s5['external'],'chain_raw_sha256':'f'*64}})
        for key,new in [('epoch_count',2),
                        ('active_ledger_sequence',2),
                        ('active_registrar_public_hex',Base.active_pub),
                        ('initial_registrar_public_hex',Base.active_pub)]:
            with self.subTest(key=key), self.assertRaisesRegex(a.AnchorError,
                    'EXPLICIT_EXTERNAL_ROOT_EPOCH_ACTIVE_TIP_OR_SEQUENCE'):
                e.verify_history(**{**self.s5,'external':{
                    **self.s5['external'],key:new}})
        self.assertEqual(json.loads(Path(self.s5['chain_file']).read_bytes())
            ['previous_chain_raw_sha256'],self.s4['external']['chain_raw_sha256'])

    def test_04_forged_signed_index_cannot_resign_untrusted_epoch_ledger(self):
        data=json.loads(Path(self.s5['chain_file']).read_bytes())
        data['epochs'][0]['ledger_sequence']=1
        data['epochs'][0]['ledger_raw_sha256']=Base.base.res1['ledger_raw_sha256']
        forged=self.home/'rebased-root.json'
        forged.write_bytes(b.canonical(data));forged.chmod(0o600)
        with self.assertRaisesRegex(a.AnchorError,
                'LEDGER_BYTES_NOT_EQUAL_INDEPENDENT_LATEST_PIN'):
            e.verify_history(**{**self.s5,'chain_file':str(forged),
               'external':{**self.s5['external'],
                           'chain_raw_sha256':b.digest(forged.read_bytes())}})

    def test_05_registrar_key_reuse_and_future_historic_original_roles_denied(self):
        doc=json.loads(Path(self.s4['chain_file']).read_bytes())
        doc['epochs'][-1]['registrar_public_hex']=Base.base.pub
        forged=self.home/'reused-reg.json'
        forged.write_bytes(b.canonical(doc));forged.chmod(0o600)
        with self.assertRaisesRegex(a.AnchorError,'REGISTRAR_KEY_REUSED'):
            e.verify_history(**{**self.s4,'chain_file':str(forged),
                'external':{**self.s4['external'],
                    'chain_raw_sha256':b.digest(forged.read_bytes()),
                    'active_registrar_public_hex':Base.base.pub}})
        doc['epochs'][-1]['registrar_public_hex']=Base.base.parent.pins['a_public_hex']
        another=self.home/'historic-witness-key.json'
        another.write_bytes(b.canonical(doc));another.chmod(0o600)
        with self.assertRaisesRegex(a.AnchorError,
                'GOVERNANCE_OR_ANY_PAST_FUTURE_REGISTRAR_REUSED'):
            e.verify_history(**{**self.s4,'chain_file':str(another),
                'external':{**self.s4['external'],
                    'chain_raw_sha256':b.digest(another.read_bytes()),
                    'active_registrar_public_hex':Base.base.parent.pins['a_public_hex']}})

    def test_06_all_old_certificates_required_tamper_and_remap_denied(self):
        with self.assertRaisesRegex(a.AnchorError,'ALL_CUTOVER_CERTIFICATE_FILES'):
            e.verify_history(**{**self.s5,'certificate_files':self.s5['certificate_files'][:1]})
        with self.assertRaisesRegex(a.AnchorError,
                'DOCUMENT_NOT_EQUAL_INDEPENDENT_RAW_SHA_PIN'):
            doc=json.loads(Path(self.t2_cert_path).read_bytes())
            doc['votes']['governance']['signature_ed25519']='e'*128
            broken=self.home/'modified-certificate.json'
            broken.write_bytes(b.canonical(doc));broken.chmod(0o600)
            e.verify_history(**{**self.s5,
               'certificate_files':[Base.cert_path,str(broken)]})
        with self.assertRaisesRegex(a.AnchorError,'ALL_NONEMPTY_EPOCH_LEDGER_FILES'):
            e.verify_history(**{**self.s5,'ledger_files':self.s5['ledger_files'][:1]})

    def test_07_global_replay_rejected_for_a_genuinely_signed_rogue_ec304_ledger(self):
        # This ACK actually belongs to epoch 0, and a newly active signer can
        # sign it in its own EC304 GENESIS ledger if EC306 is bypassed.
        # The EC306 *commit* must reject even with correct signature + raw SHA.
        old_context={k:v for k,v in Base.base.one.items()
                     if k not in ('registry_id','registrar_public_hex')}
        replay=self.home/'raw-ec304-replay.json'
        candidate=ec304.register(**old_context,
            registry_id=Base.trust['registry_id'],
            registrar_public_hex=self.third_pub,
            registrar_private_key_file=self.third_private,
            previous_ledger_file=None,
            expected_previous_ledger_sha256=a.GENESIS,
            expected_previous_sequence=0,out=str(replay))
        with self.assertRaisesRegex(a.AnchorError,
                'CHALLENGE_REPLAY_ACROSS_ANY_HISTORIC_EPOCH|ACK_REPLAY_ACROSS_ANY_HISTORIC_EPOCH'):
            e.commit(**self.s4,**old_context,
                candidate_ledger_file=str(replay),
                expected_candidate_ledger_sha256=candidate['ledger_raw_sha256'],
                expected_candidate_sequence=1,
                out=self._out('replayed-snapshot.json'))
        self.assertFalse((self.home/'replayed-snapshot.json').exists())

    def test_08_snapshots_private_exclusive_and_no_uncommitted_newest_claim(self):
        self.assertEqual(os.stat(self.s5['chain_file']).st_mode & 0o777,0o600)
        with self.assertRaisesRegex(a.AnchorError,'EXCLUSIVE_OUTPUT_OR_FSYNC'):
            e.commit(**self.s4,**self.thirdctx,
                candidate_ledger_file=str(self.third_ledger_path),
                expected_candidate_ledger_sha256=self.third_record['ledger_raw_sha256'],
                expected_candidate_sequence=1,out=self.s5['chain_file'])
        with self.assertRaisesRegex(a.AnchorError,'ACTIVE_EPOCH_EMPTY'):
            e.verify_latest(**self.s4,**self.thirdctx)
        self.assertFalse(Path(self._out('bad-role')).exists())

    def test_09_real_latest_ack_and_candidate_prefix_cannot_be_swapped(self):
        with self.assertRaisesRegex(a.AnchorError,
                'ACKNOWLEDGEMENT_NOT_EQUAL_EXTERNAL_RAW_SHA_PIN|RECEIVER_ED25519_SIGNATURE_INVALID'):
            e.verify_latest(**self.s5,**{**self.thirdctx,
                'expected_acknowledgement_sha256':'f'*64})
        with self.assertRaisesRegex(a.AnchorError,
                'CANDIDATE_MUST_ADVANCE_ACTIVE_EPOCH_BY_EXACTLY_ONE'):
            e.commit(**self.s5,**self.thirdctx,
                candidate_ledger_file=str(self.third_ledger_path),
                expected_candidate_ledger_sha256=self.third_record['ledger_raw_sha256'],
                expected_candidate_sequence=1,out=self._out('bad-prefix.json'))

    def test_10_standalone_cli_and_console_exact_read_only_mode(self):
        cmd=[sys.executable,'-B',str(ROOT/'scripts/ces_registrar_epochs.py'),
             'verify-latest',*self._flags(self.s5)]
        completed=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
        self.assertEqual(completed.returncode,0,completed.stdout+completed.stderr)
        self.assertEqual(json.loads(completed.stdout)['epoch_count'],3)
        console=[sys.executable,'-B',str(ROOT/'scripts/ces_next.py'),
            'audit-epochs','DeliveryAudit','VerifyRegistrarEpochs',
            *self._flags(self.s5)]
        executed=subprocess.run(console,capture_output=True,text=True,timeout=140)
        self.assertEqual(executed.returncode,0,executed.stdout+executed.stderr)
        self.assertEqual(json.loads(executed.stdout)['command'],'verify-latest')
        denied=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/ces_next.py'),
            'audit-epochs','DeliveryAudit','Register',
            *self._flags(self.s5)],capture_output=True,text=True,timeout=25)
        self.assertEqual(denied.returncode,3,denied.stdout+denied.stderr)
        self.assertNotIn('--active-private-key-file',str(console))


if __name__=='__main__':
    unittest.main()
