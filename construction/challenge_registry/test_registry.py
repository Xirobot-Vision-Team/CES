#!/usr/bin/env python3
"""EC304 real EC294->303 signed fixture: only local software, not remote WORM."""
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
from receiver_ack.test_ack import EC303ReceiverAckCases as Parent
from receiver_ack import ack
from . import registry as r

ROOT = Path(__file__).resolve().parents[2]


class EC304RegistryCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Parent.setUpClass()
        try:
            cls.parent = Parent
            cls.tmp = tempfile.TemporaryDirectory(prefix='ec304-registry-')
            cls.home = Path(cls.tmp.name)
            cls.key = Ed25519PrivateKey.generate()
            cls.pub = cls.key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw).hex()
            cls.key_file = cls.home/'registrar.key'
            cls.key_file.write_bytes(cls.key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()))
            cls.key_file.chmod(0o600)
            cls.one = dict(Parent.context, registry_id='offline-audit-01',
                           registrar_public_hex=cls.pub,
                           acknowledgement_file=str(Parent.out),
                           expected_acknowledgement_sha256=Parent.sent['acknowledgement_sha256'])
            cls.ledger1=cls.home/'ledger-0001.json'
            cls.res1=r.register(**cls.one, previous_ledger_file=None,
                expected_previous_ledger_sha256=a.GENESIS,
                expected_previous_sequence=0,
                registrar_private_key_file=str(cls.key_file), out=str(cls.ledger1))
            cls.second_ack=cls.home/'receipt-2.json'
            cls.second_context={**Parent.context, 'challenge_sha256':'6'*64}
            cls.second_signed=ack.issue_ack(**cls.second_context,
                imported_dir=str(Parent.imported),
                receiver_private_key_file=str(Parent.private),
                out=str(cls.second_ack))
            cls.two={**cls.one, 'challenge_sha256':'6'*64,
                     'acknowledgement_file':str(cls.second_ack),
                     'expected_acknowledgement_sha256':cls.second_signed['acknowledgement_sha256']}
            cls.ledger2=cls.home/'ledger-0002.json'
            cls.res2=r.register(**cls.two,previous_ledger_file=str(cls.ledger1),
                expected_previous_ledger_sha256=cls.res1['ledger_raw_sha256'],
                expected_previous_sequence=1,
                registrar_private_key_file=str(cls.key_file),out=str(cls.ledger2))
        except BaseException:
            if hasattr(cls,'tmp'):cls.tmp.cleanup()
            Parent.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
        Parent.tearDownClass()

    def _verify(self, which=2, **overrides):
        if which==1:
            d=dict(self.one,ledger_file=str(self.ledger1),
                   expected_ledger_sha256=self.res1['ledger_raw_sha256'],
                   expected_sequence=1)
        else:
            d=dict(self.two,ledger_file=str(self.ledger2),
                   expected_ledger_sha256=self.res2['ledger_raw_sha256'],
                   expected_sequence=2)
        return r.verify(**{**d,**overrides})

    def _register_context(self):
        return {**self.two, 'previous_ledger_file':str(self.ledger1),
                'expected_previous_ledger_sha256':self.res1['ledger_raw_sha256'],
                'expected_previous_sequence':1,
                'registrar_private_key_file':str(self.key_file)}

    def _register(self, filename, **overrides):
        return r.register(**{**self._register_context(),
                             'out':str(self.home/filename),**overrides})

    def _cli_flags(self, which=2):
        d=self.one if which==1 else self.two
        flags=[]
        for k,v in d['pins'].items():
            flags += ['--expected-'+k.replace('_','-'),v]
        for k,v in d.items():
            if k!='pins':
                name={'bundle_file':'bundle-file',
                      'acknowledgement_file':'acknowledgement-file',
                      'challenge_sha256':'expected-exchange-challenge-sha256',
                      'sender_id':'expected-sender-id',
                      'receiver_id':'expected-receiver-id',
                      'receiver_public_hex':'expected-receiver-public-hex',
                      'registry_id':'expected-registry-id',
                      'registrar_public_hex':'expected-registrar-public-hex',
                      'expected_bundle_sha256':'expected-bundle-sha256',
                      'expected_acknowledgement_sha256':'expected-acknowledgement-sha256'}[k]
                flags += ['--'+name,v]
        return flags

    def test_01_fresh_genesis_and_second_original_signed_ack_replayed(self):
        self.assertEqual(self._verify(1)['sequence'],1)
        latest=self._verify()
        self.assertEqual(latest['exit_code'],0)
        self.assertEqual(latest['sequence'],2)
        self.assertEqual(latest['report_sha256'],self.parent.export['report_sha256'])
        self.assertEqual(os.stat(self.ledger2).st_mode & 0o777,0o600)
        doc=json.loads(self.ledger2.read_bytes())
        self.assertEqual(doc['records'][1]['claim']['previous_ledger_raw_sha256'],
                         self.res1['ledger_raw_sha256'])
        self.assertEqual(doc['records'][1]['claim']['previous_record_sha256'],
                         b.digest(b.canonical(doc['records'][0])))
        self.assertNotIn(b'private_key',self.ledger2.read_bytes())

    def test_02_consumed_challenge_and_ack_replay_denied_without_new_file(self):
        with self.assertRaisesRegex(a.AnchorError,'EXCHANGE_CHALLENGE_ALREADY_CONSUMED'):
            self._register('duplicate-challenge.json',challenge_sha256='5'*64)
        with self.assertRaisesRegex(a.AnchorError,'ACK_ALREADY_RECORDED'):
            self._register('duplicate-ack.json',
                           expected_acknowledgement_sha256=self.one['expected_acknowledgement_sha256'])
        self.assertFalse((self.home/'duplicate-challenge.json').exists())
        self.assertFalse((self.home/'duplicate-ack.json').exists())

    def test_03_external_predecessor_sha_and_sequence_are_mandatory(self):
        with self.assertRaisesRegex(a.AnchorError,'LEDGER_BYTES_NOT_EQUAL_INDEPENDENT_LATEST_PIN'):
            self._register('wrong-history-sha.json',
                           expected_previous_ledger_sha256='7'*64)
        with self.assertRaisesRegex(a.AnchorError,'EXTERNAL_PREVIOUS_SEQUENCE_NOT_EQUAL_PINNED_HISTORY'):
            self._register('wrong-history-sequence.json',expected_previous_sequence=2)
        with self.assertRaisesRegex(a.AnchorError,'GENESIS_REQUIRES_EXPLICIT_EXTERNAL_EMPTY_LEDGER_PIN'):
            self._register('bad-genesis.json',previous_ledger_file=None)
        with self.assertRaisesRegex(a.AnchorError,'LEDGER_BYTES_NOT_EQUAL_INDEPENDENT_LATEST_PIN'):
            self._verify(expected_ledger_sha256=self.res1['ledger_raw_sha256'])
        with self.assertRaisesRegex(a.AnchorError,'EXTERNAL_LATEST_SEQUENCE_NOT_EQUAL_SIGNED_HISTORY'):
            self._verify(expected_sequence=1)

    def test_04_registrar_signature_and_prior_prefix_cannot_be_rewritten(self):
        doc=json.loads(self.ledger2.read_bytes())
        doc['records'][0]['claim']['external_exchange_challenge_sha256']='7'*64
        forged=self.home/'forged-ledger.json'
        forged.write_bytes(b.canonical(doc));forged.chmod(0o600)
        with self.assertRaisesRegex(a.AnchorError,
            'REGISTRAR_SIGNATURE_INVALID|SIGNED_RECORD_CHAIN_OR_PREFIX_SHA_INVALID'):
            self._verify(ledger_file=str(forged),
                         expected_ledger_sha256=b.digest(forged.read_bytes()))
        original=self.home/'extra-ledger.json'
        original.write_bytes(self.ledger2.read_bytes()+b' ');original.chmod(0o600)
        with self.assertRaisesRegex(a.AnchorError,'LEDGER_NOT_EXACT_CANONICAL_BYTES'):
            self._verify(ledger_file=str(original),
                         expected_ledger_sha256=b.digest(original.read_bytes()))

    def test_05_latest_claim_cannot_substitute_proof_or_challenge(self):
        with self.assertRaisesRegex(a.AnchorError,'RECEIVER_ED25519_SIGNATURE_INVALID|SIGNED_ACK_NOT_EQUAL_INDEPENDENTLY_REVERIFIED_EXPECTATIONS'):
            self._verify(challenge_sha256='7'*64)
        with self.assertRaisesRegex(a.AnchorError,'ACKNOWLEDGEMENT_NOT_EQUAL_EXTERNAL_RAW_SHA_PIN'):
            self._verify(expected_acknowledgement_sha256='8'*64)
        with self.assertRaisesRegex(a.AnchorError,'LEDGER_REGISTRY_OR_EXTERNAL_KEY_IDENTITY_MISMATCH'):
            self._verify(registry_id='another-registry')

    def test_06_registrar_is_fourth_separate_role_and_private_key_matches(self):
        with self.assertRaisesRegex(a.AnchorError,'FOURTH_DISTINCT_REGISTRAR_ED25519_KEY_REQUIRED'):
            self._register('same-as-receiver.json',registrar_public_hex=self.parent.pub)
        with self.assertRaisesRegex(a.AnchorError,'FOURTH_DISTINCT_REGISTRAR_ED25519_KEY_REQUIRED'):
            self._register('same-as-witness.json',
                           registrar_public_hex=self.parent.pins['a_public_hex'])
        with self.assertRaisesRegex(a.AnchorError,'REGISTRAR_PRIVATE_KEY_NOT_EQUAL_INDEPENDENT_PUBLIC_PIN'):
            self._register('wrong-private.json',registrar_private_key_file=str(self.parent.private))
        self.assertFalse((self.home/'wrong-private.json').exists())

    def test_07_private_exclusive_history_and_no_clobber(self):
        with self.assertRaisesRegex(a.AnchorError,'LEDGER_SNAPSHOT_OUTPUT_MUST_BE_NEW'):
            self._register(self.ledger2.name)
        changed=self.home/'world-ledger.json'
        changed.write_bytes(self.ledger2.read_bytes());changed.chmod(0o644)
        with self.assertRaises((a.AnchorError,Exception)):
            self._verify(ledger_file=str(changed))
        link=self.home/'linked-ledger.json'
        link.symlink_to(self.ledger2)
        with self.assertRaises((a.AnchorError,Exception)):
            self._verify(ledger_file=str(link))

    def test_08_cli_register_verify_and_read_only_console(self):
        flags=self._cli_flags(2)
        cmd=[sys.executable,'-B',str(ROOT/'scripts/ces_challenge_registry.py'),'verify',
             *flags,'--ledger-file',str(self.ledger2),
             '--expected-ledger-sha256',self.res2['ledger_raw_sha256'],
             '--expected-sequence','2']
        completed=subprocess.run(cmd,capture_output=True,text=True,timeout=80)
        self.assertEqual(completed.returncode,0,completed.stdout+completed.stderr)
        self.assertEqual(json.loads(completed.stdout)['sequence'],2)
        console=[sys.executable,'-B',str(ROOT/'scripts/ces_next.py'),
                 'audit-registry','DeliveryAudit','VerifyChallengeRegistry',
                 *flags,'--ledger-file',str(self.ledger2),
                 '--expected-ledger-sha256',self.res2['ledger_raw_sha256'],
                 '--expected-sequence','2']
        finished=subprocess.run(console,capture_output=True,text=True,timeout=80)
        self.assertEqual(finished.returncode,0,finished.stdout+finished.stderr)
        denied=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/ces_next.py'),
                 'audit-registry','DeliveryAudit','RegisterChallenge',*flags,
                 '--ledger-file',str(self.ledger2),
                 '--expected-ledger-sha256',self.res2['ledger_raw_sha256'],
                 '--expected-sequence','2'],capture_output=True,text=True,timeout=15)
        self.assertEqual(denied.returncode,3)
        self.assertNotIn('registrar-private-key-file',str(console))

    def test_09_separate_candidate_forks_not_misrepresented_as_globally_latest(self):
        # Two different valid registrar snapshots may share one externally
        # authorized predecessor. This local software never declares a winner.
        fork_ack=self.home/'receipt-fork.json'
        fork_ctx={**self.parent.context, 'challenge_sha256':'7'*64}
        signed=ack.issue_ack(**fork_ctx,
            imported_dir=str(self.parent.imported),
            receiver_private_key_file=str(self.parent.private), out=str(fork_ack))
        fork=self.home/'fork-from-one.json'
        fork_args={**self._register_context(), 'challenge_sha256':'7'*64,
                   'acknowledgement_file':str(fork_ack),
                   'expected_acknowledgement_sha256':signed['acknowledgement_sha256'],
                   'out':str(fork)}
        fresh=r.register(**fork_args)
        self.assertEqual(fresh['sequence'],2)
        self.assertEqual(fresh['previous_ledger_raw_sha256'],self.res1['ledger_raw_sha256'])
        verified=r.verify(**{**self.two, 'challenge_sha256':'7'*64,
            'acknowledgement_file':str(fork_ack),
            'expected_acknowledgement_sha256':signed['acknowledgement_sha256'],
            'ledger_file':str(fork),
            'expected_ledger_sha256':fresh['ledger_raw_sha256'],
            'expected_sequence':2})
        self.assertEqual(verified['exit_code'],0)
        self.assertNotEqual(fresh['ledger_raw_sha256'],self.res2['ledger_raw_sha256'])


if __name__=='__main__':
    unittest.main()
