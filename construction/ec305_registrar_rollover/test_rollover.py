#!/usr/bin/env python3
"""EC305 real inherited EC294->EC304 local signed evidence, not production WORM."""
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

from ec295_delivery_anchor import anchor as a
from ec302_portable_bundle import bundle as b
from ec303_receiver_ack import ack
from ec304_challenge_registry.test_registry import EC304RegistryCases as Base
from ec304_challenge_registry import registry as ec304
from . import rollover as r

ROOT = Path(__file__).resolve().parents[2]


class EC305RolloverCases(unittest.TestCase):
    @classmethod
    def _key(cls, name):
        key=Ed25519PrivateKey.generate()
        pub=key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw).hex()
        f=cls.home/(name+'.key')
        f.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()))
        f.chmod(0o600)
        return key, pub, str(f)

    @classmethod
    def setUpClass(cls):
        Base.setUpClass()
        try:
            cls.tmp=tempfile.TemporaryDirectory(prefix='ec305-cutover-')
            cls.home=Path(cls.tmp.name)
            cls.base=Base
            cls.activating, cls.active_pub, cls.active_file=cls._key('activating')
            cls.governor, cls.governor_pub, cls.governor_file=cls._key('governor')
            cls.trust={
                'registry_id':Base.two['registry_id'],
                'retiring_registrar_public_hex':Base.pub,
                'activating_registrar_public_hex':cls.active_pub,
                'governor_public_hex':cls.governor_pub,
                'old_ledger_raw_sha256':Base.res2['ledger_raw_sha256'],
                'old_ledger_sequence':2,
                'cutover_nonce_sha256':'a'*64,
                'governance_decision_sha256':'b'*64,
                'cutover_mode':'planned'}
            cls.old_file=str(Base.ledger2)
            cls.intent_path=str(cls.home/'intent.json')
            cls.prepared=r.prepare(trust=cls.trust,
                old_ledger_file=cls.old_file,out=cls.intent_path)
            cls.votes={}
            for role,file in (
                ('retiring',str(Base.key_file)),('activating',cls.active_file),
                ('governance',cls.governor_file)):
                path=str(cls.home/(role+'.vote.json'))
                cls.votes[role]=(path,r.sign(
                    trust=cls.trust,old_ledger_file=cls.old_file,
                    intent_file=cls.intent_path,
                    expected_intent_sha256=cls.prepared['intent_raw_sha256'],
                    role=role,private_key_file=file,out=path))
            cls.cert_path=str(cls.home/'signed-cutover.json')
            cls.cert=r.assemble(
                trust=cls.trust,old_ledger_file=cls.old_file,
                intent_file=cls.intent_path,
                expected_intent_sha256=cls.prepared['intent_raw_sha256'],
                retiring_vote_file=cls.votes['retiring'][0],
                activating_vote_file=cls.votes['activating'][0],
                governance_vote_file=cls.votes['governance'][0],
                out=cls.cert_path)
            cls.certargs=dict(
                trust=cls.trust,old_ledger_file=cls.old_file,
                certificate_file=cls.cert_path,
                expected_certificate_sha256=cls.cert['certificate_raw_sha256'])
            cls.new_ack_path=cls.home/'ack-after-cutover.json'
            newcontext={**Base.parent.context, 'challenge_sha256':'8'*64}
            cls.new_ack=ack.issue_ack(
                **newcontext,imported_dir=str(Base.parent.imported),
                receiver_private_key_file=str(Base.parent.private),
                out=str(cls.new_ack_path))
            cls.newctx={
                **Base.two,
                'challenge_sha256':'8'*64,
                'acknowledgement_file':str(cls.new_ack_path),
                'expected_acknowledgement_sha256':cls.new_ack['acknowledgement_sha256']}
            cls.newctx.pop('registry_id')
            cls.newctx.pop('registrar_public_hex')
            cls.first_new_path=cls.home/'new-ledger-1.json'
            cls.first_new=r.register(
                **cls.certargs,**cls.newctx,
                previous_new_ledger_file=None,
                expected_previous_new_ledger_sha256=a.GENESIS,
                expected_previous_new_sequence=0,
                activating_private_key_file=cls.active_file,
                out=str(cls.first_new_path))
            cls.more_ack_path=cls.home/'ack-after-cutover-2.json'
            morecontext={**Base.parent.context, 'challenge_sha256':'9'*64}
            cls.more_ack=ack.issue_ack(
                **morecontext,imported_dir=str(Base.parent.imported),
                receiver_private_key_file=str(Base.parent.private),
                out=str(cls.more_ack_path))
            cls.morectx={**cls.newctx,'challenge_sha256':'9'*64,
                         'acknowledgement_file':str(cls.more_ack_path),
                         'expected_acknowledgement_sha256':cls.more_ack['acknowledgement_sha256']}
            cls.second_new_path=cls.home/'new-ledger-2.json'
            cls.second_new=r.register(
                **cls.certargs,**cls.morectx,
                previous_new_ledger_file=str(cls.first_new_path),
                expected_previous_new_ledger_sha256=cls.first_new['ledger_raw_sha256'],
                expected_previous_new_sequence=1,
                activating_private_key_file=cls.active_file,
                out=str(cls.second_new_path))
        except BaseException:
            if hasattr(cls,'tmp'):cls.tmp.cleanup()
            Base.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
        Base.tearDownClass()

    def _verify(self,**overrides):
        return r.verify(**{
            **self.certargs, **self.morectx,
            'new_ledger_file':str(self.second_new_path),
            'expected_new_ledger_sha256':self.second_new['ledger_raw_sha256'],
            'expected_new_sequence':2,**overrides})

    def _append(self, name, **overrides):
        return r.register(**{
            **self.certargs,**self.morectx,
            'previous_new_ledger_file':str(self.first_new_path),
            'expected_previous_new_ledger_sha256':self.first_new['ledger_raw_sha256'],
            'expected_previous_new_sequence':1,
            'activating_private_key_file':self.active_file,
            'out':str(self.home/name),**overrides})

    def _cli_flags(self):
        result=[]
        for k,v in self.trust.items():
            result.extend(['--expected-'+k.replace('_','-'),str(v)])
        result += ['--old-ledger-file',self.old_file,
                   '--certificate-file',self.cert_path,
                   '--expected-certificate-sha256',self.cert['certificate_raw_sha256'],
                   '--new-ledger-file',str(self.second_new_path),
                   '--expected-new-ledger-sha256',self.second_new['ledger_raw_sha256'],
                   '--expected-new-sequence','2']
        for name,value in self.morectx['pins'].items():
            result.extend(['--expected-'+name.replace('_','-'),value])
        for key,value in self.morectx.items():
            if key == 'pins':continue
            flag={'bundle_file':'bundle-file',
                  'expected_bundle_sha256':'expected-bundle-sha256',
                  'acknowledgement_file':'acknowledgement-file',
                  'expected_acknowledgement_sha256':'expected-acknowledgement-sha256',
                  'sender_id':'expected-sender-id',
                  'receiver_id':'expected-receiver-id',
                  'receiver_public_hex':'expected-receiver-public-hex',
                  'challenge_sha256':'expected-exchange-challenge-sha256'}[key]
            result.extend(['--'+flag,value])
        return result

    def test_01_planned_multisigner_governed_cutover_full_original_ack(self):
        x=self._verify()
        self.assertEqual(x['exit_code'],0)
        self.assertEqual(x['old_ledger_sequence'],2)
        self.assertEqual(x['new_ledger_sequence'],2)
        self.assertEqual(x['report_sha256'],self.base.parent.export['report_sha256'])
        self.assertFalse(x['old_key_authorizes_new_epoch'])
        self.assertFalse(x['historical_old_zip_ack_contents_replayed'])
        self.assertEqual(r.verify_certificate(**self.certargs)['exit_code'],0)

    def test_02_cert_is_bound_to_independently_pinned_old_bytes_and_sequence(self):
        for update, regex in [
            ({'old_ledger_raw_sha256':'c'*64},'LEDGER_BYTES_NOT_EQUAL_INDEPENDENT_LATEST_PIN'),
            ({'old_ledger_sequence':1},'FROZEN_OLD_LEDGER_SEQUENCE'),
            ({'governance_decision_sha256':'c'*64},'CUTOVER_INTENT_MISMATCH'),
            ({'cutover_nonce_sha256':'d'*64},'CUTOVER_INTENT_MISMATCH'),
            ({'governor_public_hex':self.active_pub},'THREE_DISTINCT')]:
            with self.subTest(update=update),self.assertRaisesRegex(
                a.AnchorError,regex):
                self._verify(trust={**self.trust,**update})
        with self.assertRaisesRegex(a.AnchorError,'DOCUMENT_NOT_EQUAL_INDEPENDENT_RAW_SHA_PIN'):
            self._verify(expected_certificate_sha256='f'*64)

    def test_03_missing_planned_old_vote_and_fake_governor_signature_rejected(self):
        with self.assertRaisesRegex(a.AnchorError,'MISSING_MANDATORY_INDEPENDENT_RETIRING_VOTE'):
            r.assemble(trust=self.trust,old_ledger_file=self.old_file,
                intent_file=self.intent_path,
                expected_intent_sha256=self.prepared['intent_raw_sha256'],
                retiring_vote_file=None,
                activating_vote_file=self.votes['activating'][0],
                governance_vote_file=self.votes['governance'][0],
                out=str(self.home/'bad-missing-sig.json'))
        cert=json.loads(Path(self.cert_path).read_bytes())
        cert['votes']['governance']['signature_ed25519']='f'*128
        forged=self.home/'forged-signature.json'
        forged.write_bytes(b.canonical(cert));forged.chmod(0o600)
        with self.assertRaisesRegex(a.AnchorError,'GOVERNANCE_SIGNATURE_INVALID'):
            self._verify(certificate_file=str(forged),
                         expected_certificate_sha256=b.digest(forged.read_bytes()))

    def test_04_emergency_compromised_old_key_not_required_or_accepted(self):
        tr={**self.trust,'cutover_mode':'emergency_compromised',
            'cutover_nonce_sha256':'c'*64,'governance_decision_sha256':'d'*64}
        intentfile=str(self.home/'emergency-intent.json')
        pres=r.prepare(trust=tr,old_ledger_file=self.old_file,out=intentfile)
        for role,key in [('activating',self.active_file),('governance',self.governor_file)]:
            r.sign(trust=tr,old_ledger_file=self.old_file,
                   intent_file=intentfile,expected_intent_sha256=pres['intent_raw_sha256'],
                   role=role,private_key_file=key,
                   out=str(self.home/('em-'+role+'.vote.json')))
        with self.assertRaisesRegex(a.AnchorError,'RETIRED_KEY_MUST_NOT_SIGN_EMERGENCY'):
            r.sign(trust=tr,old_ledger_file=self.old_file,
                   intent_file=intentfile,expected_intent_sha256=pres['intent_raw_sha256'],
                   role='retiring',private_key_file=str(self.base.key_file),
                   out=str(self.home/'bad-em-old-vote.json'))
        dest=str(self.home/'emergency-cert.json')
        assembled=r.assemble(trust=tr,old_ledger_file=self.old_file,
            intent_file=intentfile,expected_intent_sha256=pres['intent_raw_sha256'],
            retiring_vote_file=None,
            activating_vote_file=str(self.home/'em-activating.vote.json'),
            governance_vote_file=str(self.home/'em-governance.vote.json'),out=dest)
        kwargs=dict(trust=tr,old_ledger_file=self.old_file,certificate_file=dest,
                    expected_certificate_sha256=assembled['certificate_raw_sha256'])
        self.assertEqual(r.verify_certificate(**kwargs)['exit_code'],0)
        self.assertEqual(r.verify(**kwargs,**self.morectx,
            new_ledger_file=str(self.second_new_path),
            expected_new_ledger_sha256=self.second_new['ledger_raw_sha256'],
            expected_new_sequence=2)['exit_code'],0)
        with self.assertRaisesRegex(a.AnchorError,'OLD_KEY_MUST_NOT_AUTHORIZE_EMERGENCY'):
            r.assemble(trust=tr,old_ledger_file=self.old_file,
                intent_file=intentfile,expected_intent_sha256=pres['intent_raw_sha256'],
                retiring_vote_file=self.votes['retiring'][0],
                activating_vote_file=str(self.home/'em-activating.vote.json'),
                governance_vote_file=str(self.home/'em-governance.vote.json'),
                out=str(self.home/'forbid-em-old.json'))

    def test_05_old_challenge_and_ack_cannot_be_reused_after_new_key(self):
        with self.assertRaisesRegex(a.AnchorError,'CUTOVER_CANNOT_REUSE_RETIRED_EPOCH_CHALLENGE'):
            self._append('repeat-previous-challenge.json',challenge_sha256='5'*64)
        with self.assertRaisesRegex(a.AnchorError,'CUTOVER_CANNOT_REUSE_RETIRED_EPOCH_ACK'):
            self._append('repeat-previous-ack.json',
                         expected_acknowledgement_sha256=self.base.one['expected_acknowledgement_sha256'])
        self.assertFalse((self.home/'repeat-previous-challenge.json').exists())
        self.assertFalse((self.home/'repeat-previous-ack.json').exists())

    def test_06_new_epoch_own_reuse_still_rejected_by_ec304(self):
        with self.assertRaisesRegex(a.AnchorError,'EXCHANGE_CHALLENGE_ALREADY_CONSUMED'):
            self._append('new-duplicate.json',challenge_sha256='8'*64)
        with self.assertRaisesRegex(a.AnchorError,'ACK_ALREADY_RECORDED'):
            self._append('new-ack-duplicate.json',
                         expected_acknowledgement_sha256=self.new_ack['acknowledgement_sha256'])

    def test_07_detect_cross_epoch_replay_even_with_attacker_new_key_and_rehash(self):
        fake=json.loads(self.first_new_path.read_bytes())
        # A malicious active signer fabricates a historical new-epoch record
        # that repeats an old-epoch challenge; local signatures still validate.
        claim=fake['records'][0]['claim']
        claim['external_exchange_challenge_sha256']=self.base.one['challenge_sha256']
        fake['records'][0]['registrar_signature_ed25519']=self.activating.sign(
            ec304.DOMAIN+
            a.canonical(claim)).hex()
        path=self.home/'cross-epoch-signed-replay.json'
        path.write_bytes(b.canonical(fake));path.chmod(0o600)
        with self.assertRaisesRegex(a.AnchorError,'CROSS_EPOCH_CHALLENGE_REUSE_FORBIDDEN'):
            self._verify(new_ledger_file=str(path),
                         expected_new_ledger_sha256=b.digest(path.read_bytes()),
                         expected_new_sequence=1)

    def test_08_untrusted_latest_and_new_sequence_pins_rejected(self):
        with self.assertRaisesRegex(a.AnchorError,'LEDGER_BYTES_NOT_EQUAL_INDEPENDENT_LATEST_PIN'):
            self._verify(expected_new_ledger_sha256=self.first_new['ledger_raw_sha256'])
        with self.assertRaisesRegex(a.AnchorError,'NEW_EPOCH_SEQUENCE_MISMATCH'):
            self._verify(expected_new_sequence=1)
        with self.assertRaisesRegex(a.AnchorError,'LEDGER_REGISTRY_OR_EXTERNAL_KEY_IDENTITY_MISMATCH'):
            self._verify(trust={**self.trust,'registry_id':'other-registry'})
        with self.assertRaisesRegex(a.AnchorError,'NEW_EPOCH_GENESIS_REQUIRES_EXPLICIT_ZERO_EXTERNAL_PIN'):
            self._append('genesis-fail.json',previous_new_ledger_file=None)

    def test_09_fresh_signed_ack_still_replays_ec303_chain(self):
        with self.assertRaisesRegex(a.AnchorError,'RECEIVER_ED25519_SIGNATURE_INVALID|SIGNED_ACK_NOT_EQUAL_INDEPENDENTLY_REVERIFIED_EXPECTATIONS'):
            self._verify(challenge_sha256='e'*64)
        with self.assertRaisesRegex(a.AnchorError,'ACKNOWLEDGEMENT_NOT_EQUAL_EXTERNAL_RAW_SHA_PIN'):
            self._verify(expected_acknowledgement_sha256='f'*64)

    def test_10_private_no_overwrite_or_symlink_ledger_and_cert(self):
        for f in (self.intent_path,self.cert_path,str(self.first_new_path),
                  str(self.second_new_path)):
            self.assertEqual(os.stat(f).st_mode & 0o777,0o600)
        with self.assertRaisesRegex(a.AnchorError,'OUTPUT_MUST_BE_NEW|LEDGER_SNAPSHOT_OUTPUT_MUST_BE_NEW'):
            self._append(self.second_new_path.name)
        symlink=self.home/'alias-cert.json'
        symlink.symlink_to(self.cert_path)
        with self.assertRaises((a.AnchorError,Exception)):
            self._verify(certificate_file=str(symlink))
        group=self.home/'group-cert.json'
        group.write_bytes(Path(self.cert_path).read_bytes());group.chmod(0o644)
        with self.assertRaises((a.AnchorError,Exception)):
            self._verify(certificate_file=str(group))

    def test_11_cli_and_console_only_allow_explicit_readonly_verify(self):
        flags=self._cli_flags()
        cmd=[sys.executable,'-B',str(ROOT/'scripts/ces_registrar_rollover.py'),
             'verify',*flags]
        completed=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
        self.assertEqual(completed.returncode,0,completed.stdout+completed.stderr)
        self.assertEqual(json.loads(completed.stdout)['new_ledger_sequence'],2)
        cmd=[sys.executable,'-B',str(ROOT/'scripts/ces_next.py'),
             'audit-rollover','DeliveryAudit','VerifyRegistrarRollover',*flags]
        result=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(json.loads(result.stdout)['old_ledger_sequence'],2)
        denied=subprocess.run(
            [sys.executable,'-B',str(ROOT/'scripts/ces_next.py'),
             'audit-rollover','DeliveryAudit','Register',*flags],
            capture_output=True,text=True,timeout=40)
        self.assertEqual(denied.returncode,3)
        self.assertNotIn('private-key-file',str(cmd))

    def test_12_new_key_must_not_overlap_historic_original_roles(self):
        with self.assertRaisesRegex(a.AnchorError,'THREE_DISTINCT'):
            r.prepare(trust={**self.trust,'governor_public_hex':self.active_pub},
                      old_ledger_file=self.old_file,out=str(self.home/'bad-roles.json'))
        with self.assertRaisesRegex(a.AnchorError,'GOVERNOR_OR_NEW_REGISTRAR_REUSES_HISTORIC_ORIGINAL_ROLE'):
            r.prepare(trust={**self.trust,
                'governor_public_hex':self.base.parent.pub},
                old_ledger_file=self.old_file,out=str(self.home/'bad-historic-key.json'))


if __name__ == '__main__':
    unittest.main()
