#!/usr/bin/env python3
"""EC297 functional tests with genuine original EC294/EC227/EC295/EC296 data.

One 3-epoch fixture is shared across assertions: original signed EC294 Host,
HMAC/fsync local journal, EC295 keeper/witness stamps, two full EC296 four-key
bridges, then a fresh no-provider local Readback across the second transition.
Production remote Provider and Inbox remain synthesized by the parent fixture.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from delivery_send_host import protocol as orig
from delivery_anchor import anchor as a
from delivery_anchor import operator as previous
from anchor_rotation import rotation as r
from anchor_rotation.test_rotation import EC296RotationCases
from . import lineage as l, operator as op

PROJECT = Path(__file__).resolve().parents[2]


class EC297LineageCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = EC296RotationCases(
            'test_01_real_audit_two_epochs_each_recheck_historical_ec294_and_seals')
        cls.fixture.setUp()
        try:
            cls._create_lineage()
        except BaseException:
            cls.fixture.doCleanups()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.fixture.doCleanups()

    @classmethod
    def _create_lineage(cls):
        x = cls.fixture
        _prepared0, cls.bridge0, made0 = x.prepare_and_bridge()
        cls.bridge0_sha = made0['rotation_bridge_sha256']
        # EC296's first second-epoch Record has count 4. Readback of the SAME
        # original EC227 HMAC head must be a separate later EC294 signed ACK.
        time.sleep(1.1)
        observed, _g, _r = x.base.receipt(
            'readback', x.new_cp['claim']['audit_head_hmac_sha256'])
        cls.status_lookup_count = x.base.parent.parent.statusport.lookups
        cls.keys2 = {role: Ed25519PrivateKey.generate() for role in a.DOMAINS}
        cls.policy2_file = str(x.base.parent.root/'297-third-policy.json')
        made2 = previous.create_policy(
            original_policy_file=x.base.parent.policyfile,
            original_policy_sha256=x.base.parent.policysha,
            operation_id=x.old_policy['operation_id'],
            job_sha256=x.old_policy['job_sha256'],
            keeper_public_hex=orig.public_hex(cls.keys2['keeper']),
            witness_public_hex=orig.public_hex(cls.keys2['witness']),
            out=cls.policy2_file)
        cls.policy2_sha = made2['policy_sha256']
        cls.policy2 = a.load_policy(cls.policy2_file, cls.policy2_sha)
        prepared = a.prepared_from_evidence(
            observed, cls.policy2, cls.policy2_sha, None)
        cls.cp2 = {
            'schema': a.CHECKPOINT_SCHEMA,
            'claim': prepared['claim'], 'evidence': prepared['evidence'],
            **{role+'_signature_ed25519': a.sign(role, prepared['claim'], key)
               for role, key in cls.keys2.items()}
        }
        cls.cp2_file = x.f('297-third-cp', cls.cp2)
        cls.tip2 = a.sha(cls.cp2)
        cls.minimum = x.new_cp['claim']['ec294_reply_issued_at_unix'] + 1
        cls.claim1 = r.claim_from_histories(
            old_policy=x.new_policy, old_policy_sha=x.new_policy_sha,
            old_checkpoints=[x.new_cp], old_expected_tip=x.new_tip,
            new_policy=cls.policy2, new_policy_sha=cls.policy2_sha,
            new_checkpoints=[cls.cp2], new_proposed_tip=cls.tip2,
            minimum_fresh_readback_unix=cls.minimum)
        cls.bridge1_doc = {
            'schema': r.BRIDGE_SCHEMA, 'claim': cls.claim1,
            **{role+'_signature_ed25519': r.sign(
                role, cls.claim1,
                x.new_keys[kind] if epoch == 'old' else cls.keys2[kind])
               for role in r.ROLES
               for epoch, kind in [role.split('_',1)]}
        }
        cls.bridge1_file = x.f('297-bridge1', cls.bridge1_doc)
        cls.bridge1_sha = a.sha(cls.bridge1_doc)
        cls.spec = {
            'schema': l.INPUT_SCHEMA,
            'epochs': [
                {'policy_file': x.inputs['old_policy_file'],
                 'policy_sha256': x.old_policy_sha,
                 'checkpoint_files': x.inputs['old_checkpoint_files'],
                 'checkpoint_tip_sha256': x.old_tip},
                {'policy_file': x.new_policy_path,
                 'policy_sha256': x.new_policy_sha,
                 'checkpoint_files': x.inputs['new_checkpoint_files'],
                 'checkpoint_tip_sha256': x.new_tip},
                {'policy_file': cls.policy2_file,
                 'policy_sha256': cls.policy2_sha,
                 'checkpoint_files': [cls.cp2_file],
                 'checkpoint_tip_sha256': cls.tip2},
            ],
            'bridges': [
                {'bridge_file': cls.bridge0,
                 'bridge_sha256': cls.bridge0_sha,
                 'minimum_fresh_readback_unix': None},
                {'bridge_file': cls.bridge1_file,
                 'bridge_sha256': cls.bridge1_sha,
                 'minimum_fresh_readback_unix': cls.minimum},
            ]
        }
        cls.commit = l.build_commitment(cls.spec)
        cls.commit_sha = a.sha(cls.commit)
        cls.input_file = cls._write('original-inputs',cls.spec)
        cls.commit_file = cls._write('original-commitment',cls.commit)

    @classmethod
    def _write(cls, name, doc):
        path = str(cls.fixture.base.parent.root/('297-'+name+'.json'))
        previous.store(path, doc, l.MAX_INPUT_BYTES)
        return path

    def spec_file(self, name, spec):
        return self._write(name,spec)

    def known_good(self, **patch):
        options = {
            'inputs_file': self.input_file,
            'commitment_file': self.commit_file,
            'expected_commitment_sha256': self.commit_sha,
            'expected_root_tip': self.fixture.old_tip,
            'expected_latest_tip': self.tip2,
            'expected_latest_bridge_sha256': self.bridge1_sha,
        }
        return op.verify(**{**options, **patch})

    def test_01_three_epochs_two_verified_four_party_bridges(self):
        result = self.known_good()
        self.assertEqual(result['epoch_count'], 3)
        self.assertEqual(result['rotation_count'], 2)
        self.assertEqual(self.commit['bridges'][0]['handover_observation_mode'],
                         'record')
        self.assertEqual(self.commit['bridges'][1]['handover_observation_mode'],
                         'readback')
        self.assertTrue(result['original_ec294_signatures_every_ec295_checkpoint_verified'])
        self.assertTrue(result['all_four_ec296_signatures_each_rotation_verified'])
        self.assertEqual(self.commit['epochs'][1]['last_event_count'],
                         self.commit['epochs'][2]['first_event_count'])
        self.assertFalse(result['actual_independent_off_host_retention_or_unique_fork_proven'])
        self.assertEqual(self.status_lookup_count,
                         self.fixture.base.parent.parent.statusport.lookups)

    def test_02_propose_is_exclusive_private_and_does_not_claim_external_pin(self):
        path = str(self.fixture.base.parent.root/'297-proposal-private.json')
        result = op.propose(inputs_file=self.input_file, out=path)
        self.assertEqual(result['lineage_commitment_sha256'], self.commit_sha)
        self.assertFalse(result['independent_off_host_retention_performed'])
        self.assertEqual(os.stat(path).st_mode & 0o077, 0)
        with self.assertRaisesRegex(a.AnchorError,'EXCLUSIVE_OUTPUT'):
            op.propose(inputs_file=self.input_file, out=path)

    def test_03_relocation_retains_exact_portable_commitment(self):
        changed = copy.deepcopy(self.spec)
        for i, epoch in enumerate(changed['epochs']):
            src = epoch['policy_file']
            dst = str(self.fixture.base.parent.root/f'297-relocated-policy-{i}.json')
            shutil.copyfile(src,dst)
            epoch['policy_file'] = dst
            out=[]
            for j, cp in enumerate(epoch['checkpoint_files']):
                dst = str(self.fixture.base.parent.root/f'297-relocated-cp-{i}-{j}.json')
                shutil.copyfile(cp,dst)
                out.append(dst)
            epoch['checkpoint_files']=out
        for i, bridge in enumerate(changed['bridges']):
            src = bridge['bridge_file']
            dst = str(self.fixture.base.parent.root/f'297-relocated-bridge-{i}.json')
            shutil.copyfile(src,dst)
            bridge['bridge_file']=dst
        self.assertEqual(a.sha(l.build_commitment(changed)),self.commit_sha)

    def test_04_missing_trusted_commitment_pin_rejected(self):
        with self.assertRaisesRegex(a.AnchorError,'FOUR_INDEPENDENT_EXTERNAL'):
            self.known_good(expected_commitment_sha256=a.GENESIS)

    def test_05_local_new_commitment_cannot_self_authorize_rollback(self):
        stale=copy.deepcopy(self.commit)
        stale['epochs'].pop()
        stale['bridges'].pop()
        stale['epoch_count']=2
        stale['bridge_count']=1
        stale['latest_checkpoint_tip_sha256']=stale['epochs'][-1]['checkpoint_tip_sha256']
        stale['latest_rotation_bridge_sha256']=stale['bridges'][-1]['rotation_bridge_sha256']
        file=self.spec_file('shortened-commitment',stale)
        with self.assertRaisesRegex(a.AnchorError,'COMMITMENT_SHA_MISMATCH'):
            self.known_good(commitment_file=file)

    def test_06_truncated_middle_epoch_or_bridge_denied(self):
        changed=copy.deepcopy(self.spec)
        del changed['epochs'][1]
        del changed['bridges'][0]
        with self.assertRaises(a.AnchorError):
            l.build_commitment(changed)

    def test_07_bridge_order_cannot_be_swapped(self):
        changed=copy.deepcopy(self.spec)
        changed['bridges'].reverse()
        with self.assertRaises(a.AnchorError):
            l.build_commitment(changed)

    def test_08_wrong_root_policy_raw_sha_denied(self):
        changed=copy.deepcopy(self.spec)
        changed['epochs'][0]['policy_sha256']='f'*64
        with self.assertRaisesRegex(a.AnchorError,'RAW_BYTES_CHANGED'):
            l.build_commitment(changed)

    def test_09_tamper_original_ec294_signed_reply_denied(self):
        changed=copy.deepcopy(self.spec)
        cp=copy.deepcopy(self.fixture.old_cp)
        cp['evidence']['response']['signed_reply']['signature_ed25519']='f'*128
        changed['epochs'][0]['checkpoint_files']=[self.spec_file('bad-ec294',cp)]
        changed['epochs'][0]['checkpoint_tip_sha256']=a.sha(cp)
        with self.assertRaises(a.AnchorError):
            l.build_commitment(changed)

    def test_10_tamper_third_epoch_ec295_witness_seal_denied(self):
        changed=copy.deepcopy(self.spec)
        cp=copy.deepcopy(self.cp2)
        cp['witness_signature_ed25519']='f'*128
        changed['epochs'][2]['checkpoint_files']=[self.spec_file('bad-ec295',cp)]
        changed['epochs'][2]['checkpoint_tip_sha256']=a.sha(cp)
        with self.assertRaisesRegex(a.AnchorError,'SIGNATURE_INVALID'):
            l.build_commitment(changed)

    def test_11_tamper_four_vote_bridge_rejected_even_with_self_pin(self):
        changed=copy.deepcopy(self.spec)
        br=copy.deepcopy(self.bridge1_doc)
        br['new_keeper_signature_ed25519']='0'*128
        changed['bridges'][1]['bridge_file']=self.spec_file('bad-bridge',br)
        changed['bridges'][1]['bridge_sha256']=a.sha(br)
        with self.assertRaises(a.AnchorError):
            l.build_commitment(changed)

    def test_12_readback_requires_exact_independent_minimum_timestamp(self):
        changed=copy.deepcopy(self.spec)
        changed['bridges'][1]['minimum_fresh_readback_unix']=None
        with self.assertRaisesRegex(a.AnchorError,'FRESH_READBACK_TIME'):
            l.build_commitment(changed)

    def test_13_readback_stale_minimum_unix_denied(self):
        changed=copy.deepcopy(self.spec)
        changed['bridges'][1]['minimum_fresh_readback_unix']=self.minimum+30
        with self.assertRaisesRegex(a.AnchorError,'NEW_EPOCH_MUST_FOLLOW'):
            l.build_commitment(changed)

    def test_14_record_bridge_cannot_launder_readback_minimum(self):
        changed=copy.deepcopy(self.spec)
        changed['bridges'][0]['minimum_fresh_readback_unix']=self.minimum
        with self.assertRaisesRegex(a.AnchorError,'RECORD_HANDOVER_MUST_NOT'):
            l.build_commitment(changed)

    def test_15_duplicate_epoch_receipts_and_paths_denied(self):
        changed=copy.deepcopy(self.spec)
        changed['epochs'][1]['checkpoint_files'] = (
            changed['epochs'][0]['checkpoint_files'])
        with self.assertRaisesRegex(a.AnchorError,'REPEATED_OR_NONABSOLUTE'):
            l.build_commitment(changed)

    def test_16_all_four_external_pins_must_match(self):
        for name in ('expected_root_tip','expected_latest_tip',
                     'expected_latest_bridge_sha256'):
            with self.subTest(name=name):
                with self.assertRaisesRegex(a.AnchorError,'PIN_MISMATCH'):
                    self.known_good(**{name:'f'*64})

    def test_17_not_even_correct_external_sha_licenses_modified_history(self):
        corrupted=copy.deepcopy(self.commit)
        corrupted['job_sha256']='f'*64
        file=self.spec_file('forged-commitment',corrupted)
        # Caller explicitly passes SHA of forged document, but recomputation
        # against original authenticated evidence must still detect mismatch.
        with self.assertRaisesRegex(a.AnchorError,'NOT_EQUAL_TO_ALL_VERIFIED'):
            self.known_good(commitment_file=file,
                            expected_commitment_sha256=a.sha(corrupted))

    def test_18_nonadjacent_keeper_key_reuse_is_denied(self):
        changed=copy.deepcopy(self.spec)
        reused=copy.deepcopy(self.policy2)
        reused['keeper_public_hex']=self.fixture.old_policy['keeper_public_hex']
        dst=self.spec_file('reused-nonadjacent-policy',reused)
        changed['epochs'][2]['policy_file']=dst
        changed['epochs'][2]['policy_sha256']=hashlib.sha256(Path(dst).read_bytes()).hexdigest()
        with self.assertRaisesRegex(a.AnchorError,'HISTORICAL_KEEPER_OR_WITNESS_KEY_REUSED'):
            l.build_commitment(changed)

    def test_19_cli_round_trip_from_fixed_standalone_script(self):
        draft=str(self.fixture.base.parent.root/'297-cli-proposal.json')
        subprocess_propose=subprocess.run([sys.executable,'-I','-B',
            str(PROJECT/'scripts'/'ces_anchor_lineage.py'),'propose-lineage',
            '--inputs-file',self.input_file,'--out',draft],
            capture_output=True,text=True,timeout=35)
        self.assertEqual(subprocess_propose.returncode,0,
                         subprocess_propose.stdout+subprocess_propose.stderr)
        cli=subprocess.run([sys.executable,'-I','-B',
            str(PROJECT/'scripts'/'ces_anchor_lineage.py'),'verify-lineage',
            '--inputs-file',self.input_file,
            '--commitment-file',draft,
            '--expected-commitment-sha256',self.commit_sha,
            '--expected-root-tip',self.fixture.old_tip,
            '--expected-latest-tip',self.tip2,
            '--expected-latest-bridge-sha256',self.bridge1_sha],
            capture_output=True,text=True,timeout=35)
        self.assertEqual(cli.returncode,0,cli.stdout+cli.stderr)
        self.assertFalse(json.loads(cli.stdout)[
            'current_ec227_disk_state_or_production_delivery_checked'])

    def test_20_unified_console_exact_mode_positive(self):
        console=subprocess.run([sys.executable,'-I','-B',
            str(PROJECT/'scripts'/'ces_next.py'),
            'audit-lineage','DeliveryAudit','VerifyLineage',
            '--inputs-file',self.input_file,
            '--commitment-file',self.commit_file,
            '--expected-commitment-sha256',self.commit_sha,
            '--expected-root-tip',self.fixture.old_tip,
            '--expected-latest-tip',self.tip2,
            '--expected-latest-bridge-sha256',self.bridge1_sha],
            capture_output=True,text=True,timeout=125)
        self.assertEqual(console.returncode,0,console.stdout+console.stderr)
        self.assertTrue(json.loads(console.stdout)[
            'all_four_ec296_signatures_each_rotation_verified'])

    def test_21_console_denies_broadened_action(self):
        console=subprocess.run([sys.executable,'-I','-B',
            str(PROJECT/'scripts'/'ces_next.py'),
            'audit-lineage','DeliverySend','Submit',
            '--inputs-file',self.input_file,'--commitment-file',self.commit_file,
            '--expected-commitment-sha256',self.commit_sha,
            '--expected-root-tip',self.fixture.old_tip,
            '--expected-latest-tip',self.tip2,
            '--expected-latest-bridge-sha256',self.bridge1_sha],
            capture_output=True,text=True,timeout=15)
        self.assertEqual(console.returncode,3,console.stdout)
        self.assertIn('EC297_ONLY_EXPLICIT',console.stdout)

    def test_22_malformed_epoch_count_and_extra_fields_fail_closed(self):
        broken=copy.deepcopy(self.spec)
        broken['epochs']=broken['epochs'][:2]
        broken['bridges']=broken['bridges'][:1]
        with self.assertRaisesRegex(a.AnchorError,'THREE_OR_MORE'):
            l.build_commitment(broken)
        broken=copy.deepcopy(self.spec)
        broken['privileged_approval']=True
        with self.assertRaisesRegex(a.AnchorError,'INPUT_DOCUMENT_FIELDS'):
            l.build_commitment(broken)

    def test_23_real_production_or_external_immutable_retention_not_claimed(self):
        res=self.known_good()
        self.assertFalse(res['physical_independent_signers_or_trusted_utc_proven'])
        self.assertFalse(res['actual_independent_off_host_retention_or_unique_fork_proven'])
        self.assertFalse(res['new_provider_query_or_original_send_executed'])
        self.assertEqual(self.fixture.base.parent.parent.statusport.lookups,
                         self.status_lookup_count)


if __name__ == '__main__':
    unittest.main()
