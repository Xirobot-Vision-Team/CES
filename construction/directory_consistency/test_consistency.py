#!/usr/bin/env python3
"""EC361 focused synthetic Ed25519 + RFC6962; each case replays EC360..337.

The synthetic keys, local clock and witnessed files are NOT official/public
trust anchors, independent real organizations, or globally complete records.
"""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from transparency import test_transparency as merkle
from authority_directory import authority as parent
from authority_directory import test_authority as fixtures
from . import consistency as core


class ConsistencyTests(fixtures.AuthorityTests):
    for _name in dir(fixtures.AuthorityTests):
        if _name.startswith('test_'):
            locals()[_name]=None

    def setUp(self):
        super().setUp()
        self.observers={}
        self.receipts={}
        self.evolved=[]
        self.extra_leaf=b'SYNTHETIC_APPEND_ONLY_FIFTH_DIRECTORY_LEAF'

    def setup361(self):
        self.setup360()
        self.authority_inputs=self.args360()
        old=parent.audit(**self.authority_inputs)
        self.assertTrue(old['two_sources_directory_inclusion_locally_verified'])
        self.parent_result_sha=core.sha(canonical.canonical(old))
        self.anchor=self.authority_inputs['expected_directory_checkpoint_sha256']
        self.anchor_doc=json.loads(Path(
            self.authority_inputs['directory_checkpoint_file']).read_bytes())
        self.leaves=[]
        for slot in ('a','b'):
            self.leaves.extend([Path(self.delegations[slot]['path']).read_bytes(),
               Path(next(ref for ref in self.revocations[slot]
                    if ref['sha256']==self.revoke_heads[slot])['path']).read_bytes()])
        self.leaves.append(self.extra_leaf)
        self.add_evolved_checkpoint()
        for slot in ('a','b'):
            key=ed25519.Ed25519PrivateKey.generate()
            public=self.write353('ec361-observer-'+slot,merkle.pub(key))
            self.observers[slot]={'key':key,'pub':public}
            self.make_receipt(slot,self.evolved[0])

    def add_evolved_checkpoint(self,*,changes=None,leaves=None):
        items=leaves if leaves is not None else self.leaves
        body={
            'schema':parent.DIRECTORY_SCHEMA,
            'directory_id':self.anchor_doc['directory_id'],
            'directory_public_key_original_sha256':
                self.directory_signer['pub']['sha256'],
            'tree_size':len(items),
            'root_sha256':merkle.root(items).hex(),
            'issued_utc':merkle.ut(self.now+timedelta(hours=6,minutes=48)),
            'expires_utc':merkle.ut(self.now+timedelta(days=2)),
        }
        if changes:body.update(changes)
        ref=self.signed360('ec361-signed-checkpoint-'+str(len(self.evolved)),
               body,self.directory_signer['private'],parent.DIRECTORY_DOMAIN,
               'signature_directory_ed25519_hex')
        self.evolved.append(ref)
        return ref

    def make_receipt(self,slot,checkpoint,*,changes=None,bad_key=None):
        pub=self.observers[slot]['pub']
        cp=json.loads(Path(checkpoint['path']).read_bytes())
        body={'schema':core.OBSERVER_SCHEMA,'slot':slot,
              'claimed_observer_id':'unverified_observer_'+slot,
              'observer_public_key_original_sha256':pub['sha256'],
              'directory_public_key_original_sha256':
                  self.directory_signer['pub']['sha256'],
              'directory_id':cp['directory_id'],
              'parent_ec360_canonical_result_sha256':self.parent_result_sha,
              'parent_directory_checkpoint_original_sha256':self.anchor,
              'observed_checkpoint_original_sha256':checkpoint['sha256'],
              'observed_tree_size':cp['tree_size'],
              'observed_root_sha256':cp['root_sha256'],
              'observed_utc':merkle.ut(self.now+timedelta(hours=6,minutes=53)),
              'expires_utc':merkle.ut(self.now+timedelta(days=2))}
        if changes:body.update(changes)
        receipt=self.signed360('ec361-receipt-'+slot+'-'+str(len(self.receipts)),
                 body,self.observers[slot]['key'],core.OBSERVER_DOMAIN,
                 'signature_observer_ed25519_hex',bad_key=bad_key)
        self.receipts[slot]=receipt
        return receipt

    def args361(self,*,checkpoint_refs=None,receipt_refs=None,
                consistency_proofs=None,inclusion_proofs=None,**changes):
        checkpoints=checkpoint_refs if checkpoint_refs is not None else self.evolved
        newest=self.evolved[0]
        if consistency_proofs is None:
            consistency_proofs=[{
                'older_checkpoint_sha256':self.anchor,
                'newer_checkpoint_sha256':newest['sha256'],
                'audit_path_sha256':[x.hex() for x in
                    merkle.consistency(self.leaves,4)]}]
        if inclusion_proofs is None:
            inclusion_proofs=[{
                'original_sha256':core.sha(raw),
                'leaf_index':index,
                'audit_path_sha256':[x.hex() for x in
                    merkle.inclusion(self.leaves,index)]}
                for index,raw in enumerate(self.leaves[:4])]
        doc={'schema':core.BUNDLE_SCHEMA,
             'checkpoint_originals':checkpoints,
             'consistency_proofs':consistency_proofs,
             'observer_receipt_originals':(
                 receipt_refs if receipt_refs is not None
                 else [self.receipts['a'],self.receipts['b']]),
             'head_inclusions':inclusion_proofs}
        manifest=self.write353('ec361-bundle',doc)
        return {**self.authority_inputs,
          'consistency_evaluation_utc':merkle.ut(self.now+timedelta(hours=7,minutes=15)),
          'consistency_bundle_file':manifest['path'],
          'expected_consistency_bundle_sha256':manifest['sha256'],
          'observer_a_public_key_file':self.observers['a']['pub']['path'],
          'expected_observer_a_public_key_sha256':self.observers['a']['pub']['sha256'],
          'observer_b_public_key_file':self.observers['b']['pub']['path'],
          'expected_observer_b_public_key_sha256':self.observers['b']['pub']['sha256'],
          'minimum_consistent_directory_tree_size':5,
          'expected_latest_consistent_directory_checkpoint_sha256':newest['sha256'],
          'expected_evolved_checkpoint_1_sha256':checkpoints[0]['sha256']
                  if len(checkpoints)>=1 else None,
          'expected_evolved_checkpoint_2_sha256':checkpoints[1]['sha256']
                  if len(checkpoints)>=2 else None,
          'expected_evolved_checkpoint_3_sha256':checkpoints[2]['sha256']
                  if len(checkpoints)>=3 else None,
          **changes}

    def run361(self,**changes):
        return core.audit(**self.args361(**changes))

    def test_01_genuine_append_only_and_two_independent_keys_remain_unresolved(self):
        self.setup361()
        r=self.run361()
        self.assertEqual(r['exit_code'],2)
        self.assertTrue(r['actual_ec360_through_ec337_signed_originals_replayed'])
        self.assertTrue(r['signed_directory_append_only_locally_verified'])
        self.assertTrue(r['two_distinct_observer_keys_agree_on_head_locally'])
        self.assertTrue(r['four_parent_originals_in_selected_head_locally_verified'])
        self.assertTrue(r['locally_coherent_signed_directory_evolution_and_gossip'])
        self.assertFalse(r['observer_key_diversity_proves_two_real_independent_organizations'])

    def test_02_missing_real_consistency_path_never_promoted(self):
        self.setup361()
        r=self.run361(consistency_proofs=[])
        self.assertTrue(r['rfc6962_append_only_consistency_missing_or_invalid'])
        self.assertFalse(r['locally_coherent_signed_directory_evolution_and_gossip'])

    def test_03_signed_same_size_divergent_tree_is_visible(self):
        self.setup361()
        fork=self.add_evolved_checkpoint(leaves=[*self.leaves[:-1],b'VISIBLE_DIFFERENT_FIFTH_LEAF'])
        r=self.run361(checkpoint_refs=[*self.evolved])
        self.assertTrue(r['visible_signed_same_size_checkpoint_split_view'])
        self.assertFalse(r['locally_coherent_signed_directory_evolution_and_gossip'])

    def test_04_observer_signed_old_head_must_not_claim_two_party_gossip(self):
        self.setup361()
        old={'path':self.authority_inputs['directory_checkpoint_file'],'sha256':self.anchor}
        self.make_receipt('b',old)
        r=self.run361()
        self.assertTrue(r['two_observer_signed_head_gossip_missing_or_divergent'])
        self.assertFalse(r['two_distinct_observer_keys_agree_on_head_locally'])

    def test_05_caller_floor_and_selected_older_head_reveals_rollback(self):
        self.setup361()
        self.make_receipt('a',{'path':self.authority_inputs['directory_checkpoint_file'],'sha256':self.anchor})
        self.make_receipt('b',{'path':self.authority_inputs['directory_checkpoint_file'],'sha256':self.anchor})
        r=self.run361(expected_latest_consistent_directory_checkpoint_sha256=self.anchor)
        self.assertTrue(r['caller_saved_head_or_minimum_tree_size_rollback'])
        self.assertFalse(r['locally_coherent_signed_directory_evolution_and_gossip'])

    def test_06_wrong_observer_true_signature_denied(self):
        self.setup361()
        self.make_receipt('a',self.evolved[0],bad_key=self.observers['b']['key'])
        with self.assertRaises(errors.AnchorError) as ctx:self.run361()
        self.assertIn('SIGNATURE_INVALID',ctx.exception.code)

    def test_07_forged_inclusion_path_never_verifies_new_head(self):
        self.setup361()
        p=self.args361()
        bundle=json.loads(Path(p['consistency_bundle_file']).read_bytes())
        bundle['head_inclusions'][0]['audit_path_sha256'][0]='ab'*32
        r=self.run361(inclusion_proofs=bundle['head_inclusions'])
        self.assertTrue(r['selected_signed_head_original_inclusions_missing_or_invalid'])
        self.assertFalse(r['locally_coherent_signed_directory_evolution_and_gossip'])

    def test_08_fixed_isolated_console_has_no_success_upgrade(self):
        self.setup361()
        inputs=self.args361()
        root=Path(__file__).resolve().parents[2]
        sys.path.insert(0,str(root/'scripts'))
        import ces_next as router
        argv=[sys.executable,'-I','-B',str(root/'scripts'/'ces_next.py'),
              'audit-directory-consistency','DeliveryAudit','AuditDirectoryConsistency']
        for key in router.EC361_REQUIRED:
            argv.extend(['--'+key.replace('_','-'),str(inputs[key])])
        for key in router.EC361_OPTIONAL:
            if inputs[key] is not None:
                argv.extend(['--'+key.replace('_','-'),str(inputs[key])])
        for key,flag in router.EC361_REPEATS:
            for val in inputs[key]:argv.extend([flag,str(val)])
        p=subprocess.run(argv,capture_output=True,text=True,timeout=1800)
        self.assertEqual(p.returncode,2,p.stderr+' '+p.stdout[-1600:])
        doc=json.loads(p.stdout)
        self.assertEqual(doc['schema'],core.RESULT_SCHEMA)
        self.assertTrue(doc['locally_coherent_signed_directory_evolution_and_gossip'])


    def test_09_missing_separate_caller_sha_pin_cannot_hide_manifest_selection(self):
        self.setup361()
        out=self.run361(expected_evolved_checkpoint_1_sha256=None)
        self.assertTrue(out['external_checkpoints_observers_or_saved_head_missing'])
        self.assertFalse(out['locally_coherent_signed_directory_evolution_and_gossip'])

    def test_10_true_three_checkpoint_append_only_chain(self):
        self.setup361()
        six=[*self.leaves,b'SYNTHETIC_SIXTH_APPEND_ONLY_DIRECTORY_LEAF']
        sixth=self.add_evolved_checkpoint(leaves=six)
        for slot in ('a','b'):self.make_receipt(slot,sixth)
        first=self.evolved[0]
        proofs=[
            {'older_checkpoint_sha256':self.anchor,
             'newer_checkpoint_sha256':first['sha256'],
             'audit_path_sha256':[b.hex() for b in merkle.consistency(self.leaves,4)]},
            {'older_checkpoint_sha256':first['sha256'],
             'newer_checkpoint_sha256':sixth['sha256'],
             'audit_path_sha256':[b.hex() for b in merkle.consistency(six,5)]},
        ]
        inc=[{'original_sha256':core.sha(raw),'leaf_index':i,
              'audit_path_sha256':[b.hex() for b in merkle.inclusion(six,i)]}
              for i,raw in enumerate(six[:4])]
        out=self.run361(
            consistency_proofs=proofs,inclusion_proofs=inc,
            expected_latest_consistent_directory_checkpoint_sha256=sixth['sha256'],
            minimum_consistent_directory_tree_size=6)
        self.assertEqual(out['signed_checkpoint_count_including_parent'],3)
        self.assertTrue(out['locally_coherent_signed_directory_evolution_and_gossip'])

    def test_11_well_shaped_but_false_rfc6962_path_never_verifies(self):
        self.setup361()
        forged={'older_checkpoint_sha256':self.anchor,
                'newer_checkpoint_sha256':self.evolved[0]['sha256'],
                'audit_path_sha256':['cd'*32]}
        out=self.run361(consistency_proofs=[forged])
        self.assertTrue(out['rfc6962_append_only_consistency_missing_or_invalid'])
        self.assertFalse(out['signed_directory_append_only_locally_verified'])


if __name__=='__main__':
    import unittest
    unittest.main()
