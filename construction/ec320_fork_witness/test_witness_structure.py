#!/usr/bin/env python3
"""EC320 fast actual FIFTH/SIXTH Ed25519 test; old EC317/318 replay MOCKED.

Never present these tests as authentic full original EC318->EC294 fixture replay.
Uninterrupted original signed fixture verification remains an external gate.
"""
from __future__ import annotations

import json
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ec295_delivery_anchor import anchor
from ec319_offline_transfer_registry import registry as reg
from ec319_offline_transfer_registry.test_registry_structure import (
    OfflineRegistryOnlyStructureCases, public)
from . import witness as w


class EC320WitnessGenuineSignerStructureCases(unittest.TestCase):
    def setUp(self):
        # Reuse the real Ed25519 genesis and two different genuine signed
        # EC319 siblings, but deliberately replace old EC317/318 verification
        # in this focused class. EC319 full old-original test is separate.
        self.fixture = OfflineRegistryOnlyStructureCases(
            methodName='test_real_fifth_key_signatures_and_causal_prefix')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        self.site = f.site
        self.fork_file = str(self.site / 'sibling-registrar-snapshot.json')
        self.sibling = f.append(f.genesis_path, f.genesis, f.two,
                                f.material_1, self.fork_file)
        self.sixth = Ed25519PrivateKey.generate()
        self.sixth_pub = public(self.sixth)
        self.sixth_key = f.write('independent-witness-key.bin',
                                self.sixth.private_bytes_raw())
        self.witness_path = str(self.site / 'sixth-original-attestation.json')
        self.args = dict(case_id='registrar_fork_case_320',
            witness_id='ec320_sixth_independent_witness',
            witness_public_hex=self.sixth_pub,
            witness_challenge_sha256='e7'*32,
            left_file=f.first_path,
            expected_left_sha256=f.first['snapshot_original_raw_sha256'],
            left_materials_file=f.material_1,
            expected_left_head_raw_sha256=f.first['head_signed_original_raw_sha256'],
            right_file=self.fork_file,
            expected_right_sha256=self.sibling['snapshot_original_raw_sha256'],
            right_materials_file=f.material_1,
            expected_right_head_raw_sha256=self.sibling['head_signed_original_raw_sha256'],
            expected_genesis_raw_sha256=f.genesis['genesis_signed_original_raw_sha256'],
            registrar_id=f.registrar,
            registrar_public_hex=f.pub['registrar'])

    def attest(self, *, out=None, **overrides):
        params=dict(self.args,**overrides)
        return w.attest(private_key_file=self.sixth_key,
                        out=out or self.witness_path, **params)

    def signed(self):
        result=self.attest()
        return result

    def verify(self, result, **overrides):
        params=dict(self.args,**overrides)
        return w.verify(witness_file=self.witness_path,
            expected_witness_sha256=result['attestation_original_raw_sha256'],
            **params)

    def test_true_two_sibling_signatures_independently_sixth_signed_and_reverified(self):
        result=self.signed()
        self.assertEqual(result['exit_code'],2)
        self.assertEqual(result['fork_sequence'],1)
        self.assertTrue(result['sixth_witness_ed25519_signature_verified'])
        self.assertEqual(self.verify(result)['status'],
            'independent_sixth_signature_and_both_complete_original_forks_reverified')
        self.assertFalse(result['external_global_latest_or_winner_proven'])
        self.assertEqual(Path(self.witness_path).stat().st_mode & 0o777,0o600)
        self.assertTrue(Path(self.fixture.first_path).exists())
        self.assertTrue(Path(self.fork_file).exists())

    def test_same_valid_genesis_and_prefix_cannot_be_fork_attested(self):
        second_path=str(self.site/'second-signature.json')
        second=self.fixture.append(self.fixture.first_path,self.fixture.first,
                     self.fixture.two,self.fixture.material_2,second_path)
        with self.assertRaisesRegex(anchor.AnchorError,'CANNOT_ATTEST_IDENTICAL_PREFIX'):
            self.attest(out=str(self.site/'not-a-fork.json'),
                right_file=second_path,
                expected_right_sha256=second['snapshot_original_raw_sha256'],
                expected_right_head_raw_sha256=second['head_signed_original_raw_sha256'],
                right_materials_file=self.fixture.material_2)
        self.assertFalse((self.site/'not-a-fork.json').exists())

    def test_sixth_signer_cannot_reuse_any_of_five_role_keys_or_ids(self):
        for id_,pub in ((self.fixture.registrar,self.sixth_pub),
                        (self.args['witness_id'],self.fixture.pub['sender']),
                        ('independent_a',self.sixth_pub),
                        ('registrar_receiver',self.sixth_pub)):
            with self.subTest(id=id_,pub=pub[:8]):
                with self.assertRaisesRegex(anchor.AnchorError,'SIXTH_WITNESS_MUST_HAVE_NEW'):
                    self.attest(witness_id=id_,witness_public_hex=pub)
        self.assertFalse(Path(self.witness_path).exists())

    def test_sixth_challenge_must_not_reuse_any_seen_signer_challenge(self):
        with self.assertRaisesRegex(anchor.AnchorError,'WITNESS_CHALLENGE_REUSES'):
            self.attest(witness_challenge_sha256=
                        self.fixture.one['sender_exchange_challenge_sha256'])
        with self.assertRaisesRegex(anchor.AnchorError,'WITNESS_CHALLENGE_REUSES'):
            self.attest(witness_challenge_sha256=
                        self.fixture.two['registrar_entry_challenge_sha256'])
        self.assertFalse(Path(self.witness_path).exists())

    def test_signing_private_key_mismatch_fails_with_no_case_file(self):
        bad=self.fixture.write('wrong-key.bin',Ed25519PrivateKey.generate().private_bytes_raw())
        with self.assertRaisesRegex(anchor.AnchorError,'SIXTH_SIGNING_PRIVATE_KEY_NOT'):
            w.attest(private_key_file=bad,out=self.witness_path,**self.args)
        self.assertFalse(Path(self.witness_path).exists())

    def test_original_signatures_fail_closed_before_sixth_signing(self):
        with patch.object(reg.receipt,'verify',side_effect=anchor.AnchorError(
                    'EC318_REAL_SIGNATURE_NOT_VALID','permission_denied')):
            with self.assertRaisesRegex(anchor.AnchorError,'EC318_REAL_SIGNATURE_NOT_VALID'):
                self.attest()
        self.assertFalse(Path(self.witness_path).exists())

    def test_forged_witness_signature_rehash_is_still_rejected(self):
        result=self.signed()
        doc=json.loads(Path(self.witness_path).read_bytes())
        doc['signature_ed25519']='0'*128
        forged=self.fixture.write('forged-witness.json',reg.raw_doc(doc))
        with self.assertRaisesRegex(anchor.AnchorError,'SIXTH_ED25519_SIGNATURE_NOT_AUTHENTIC'):
            w.verify(witness_file=forged,
                expected_witness_sha256=reg.digest(Path(forged).read_bytes()),
                **self.args)
        self.assertEqual(self.verify(result)['exit_code'],2)

    def test_genuine_signed_case_must_match_each_external_hash_and_case_identity(self):
        result=self.signed()
        with self.assertRaisesRegex(anchor.AnchorError,'RAW_BYTES_DIFFER'):
            w.verify(witness_file=self.witness_path,
                expected_witness_sha256='f1'*32,**self.args)
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EXTERNALLY_PINNED'):
            self.verify(result,case_id='different_approved_case')
        with self.assertRaisesRegex(anchor.AnchorError,'RAW_BYTES_DIFFER'):
            self.verify(result,expected_left_sha256='d1'*32)
        with self.assertRaisesRegex(anchor.AnchorError,'RAW_BYTES_DIFFER'):
            self.verify(result,expected_right_sha256='d2'*32)
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EXTERNALLY_PINNED'):
            self.verify(result,witness_challenge_sha256='c1'*32)

    def test_swapped_but_genuine_fork_order_rejected_by_case_commitment(self):
        result=self.signed()
        with self.assertRaisesRegex(anchor.AnchorError,'NOT_EQUAL_FRESH_FULL_ORIGINAL_REPLAY'):
            self.verify(result,
                left_file=self.fork_file,
                expected_left_sha256=self.sibling['snapshot_original_raw_sha256'],
                expected_left_head_raw_sha256=self.sibling['head_signed_original_raw_sha256'],
                right_file=self.fixture.first_path,
                expected_right_sha256=self.fixture.first['snapshot_original_raw_sha256'],
                expected_right_head_raw_sha256=self.fixture.first['head_signed_original_raw_sha256'])

    def test_valid_fifth_signature_is_not_acceptance_of_forged_fifth_branch(self):
        result=self.signed()
        doc=json.loads(Path(self.fork_file).read_bytes())
        doc['records'][1]['signature_ed25519']='0'*128
        forged=self.fixture.write('fake-registrar-branch.json',reg.raw_doc(doc))
        with self.assertRaisesRegex(anchor.AnchorError,'REGISTRAR_ED25519_SIGNATURE_NOT_AUTHENTIC'):
            self.verify(result,right_file=forged,
                expected_right_sha256=reg.digest(Path(forged).read_bytes()),
                expected_right_head_raw_sha256=reg.digest(reg.raw_doc(doc['records'][-1])))

    def test_existing_output_is_never_overwritten(self):
        before=self.fixture.write('already-exists.json',b'stay unchanged')
        with self.assertRaises(anchor.AnchorError):
            self.attest(out=before)
        self.assertEqual(Path(before).read_bytes(),b'stay unchanged')

    def test_broken_local_materials_refused_even_when_witness_is_authentic(self):
        result=self.signed()
        corrupted=self.fixture.write('bad-map.json',b'{}\n')
        with self.assertRaises(anchor.AnchorError):
            self.verify(result,right_materials_file=corrupted)


if __name__ == '__main__':
    unittest.main()
