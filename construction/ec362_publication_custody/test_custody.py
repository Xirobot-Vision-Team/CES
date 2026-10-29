#!/usr/bin/env python3
"""EC362 bounded synthetic true Ed25519 publication-copy tests.

Every scenario invokes real EC361->EC337 crypto replay; fixture signers and
source names are local and do NOT prove public dissemination or true custody.
"""
from __future__ import annotations

from datetime import timedelta
import json
from pathlib import Path
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519
from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec353_transparency import test_transparency as fixture_util
from ec361_directory_consistency import consistency as parent
from ec361_directory_consistency import test_consistency as fixtures
from . import custody as core


class PublicationCustodyTests(fixtures.ConsistencyTests):
    for _name in dir(fixtures.ConsistencyTests):
        if _name.startswith('test_'):locals()[_name]=None

    def setUp(self):
        super().setUp()
        self.sources={};self.publications={}

    def setup362(self):
        self.setup361()
        self.consistency_inputs=self.args361()
        result=parent.audit(**self.consistency_inputs)
        self.assertTrue(result['locally_coherent_signed_directory_evolution_and_gossip'])
        self.ec361_sha=core.sha(canonical.canonical(result))
        originals={
            'checkpoint':self.evolved[0],
            'consistency_bundle':{
                'path':self.consistency_inputs['consistency_bundle_file'],
                'sha256':self.consistency_inputs['expected_consistency_bundle_sha256']},
            'observer_a_receipt':self.receipts['a'],
            'observer_b_receipt':self.receipts['b']}
        for slot in core.SLOTS:
            key=ed25519.Ed25519PrivateKey.generate()
            pub=self.write353('ec362-custodian-'+slot,fixture_util.pub(key))
            self.sources[slot]={'private':key,'public':pub,'copies':{
                role:self.write353('ec362-source-'+slot+'-'+role,
                                   Path(ref['path']).read_bytes())
                for role,ref in originals.items()}}
            self.make_publication(slot)

    def make_publication(self,slot,*,sequence=3,changes=None,bad_signer=None):
        src=self.sources[slot]
        cp_ref=src['copies']['checkpoint']
        cp=json.loads(Path(cp_ref['path']).read_bytes())
        body={
            'schema':core.MANIFEST_SCHEMA,'source_slot':slot,
            'claimed_source_id':'unverified_distribution_site_'+slot,
            'custodian_public_key_original_sha256':src['public']['sha256'],
            'directory_id':cp['directory_id'],
            'parent_ec361_canonical_result_sha256':self.ec361_sha,
            'parent_ec360_canonical_result_sha256':
                self.parent_result_ec360_sha(),
            'parent_directory_checkpoint_original_sha256':self.anchor,
            'advertised_checkpoint_original_sha256':cp_ref['sha256'],
            'advertised_tree_size':cp['tree_size'],
            'advertised_root_sha256':cp['root_sha256'],
            'publication_sequence':sequence,
            'issued_utc':fixture_util.ut(self.now+timedelta(hours=7,minutes=20)),
            'expires_utc':fixture_util.ut(self.now+timedelta(days=2)),
            'copies':src['copies']}
        if changes:body.update(changes)
        manifest=self.signed360('ec362-source-manifest-'+slot+'-'+str(self.file_no),
                        body,src['private'],core.DOMAIN,
                        'signature_custodian_ed25519_hex',bad_key=bad_signer)
        self.publications[slot]=manifest
        return manifest

    def parent_result_ec360_sha(self):
        # setup361 already performed real EC360 audit and bound this true SHA.
        return self.parent_result_sha

    def args362(self,**changes):
        opts={**self.consistency_inputs,
              'publication_copy_evaluation_utc':
                fixture_util.ut(self.now+timedelta(hours=7,minutes=30))}
        for slot in core.SLOTS:
            src=self.sources[slot]
            opts.update({
                'source_'+slot+'_custody_public_key_file':src['public']['path'],
                'expected_source_'+slot+'_custody_public_key_sha256':
                    src['public']['sha256'],
                'source_'+slot+'_publication_manifest_file':
                    self.publications[slot]['path'],
                'expected_source_'+slot+'_publication_manifest_sha256':
                    self.publications[slot]['sha256'],
                'minimum_source_'+slot+'_publication_sequence':3})
            for role in core.COPY_ROLES:
                opts['expected_source_'+slot+'_'+role+'_copy_sha256']=src['copies'][role]['sha256']
        return {**opts,**changes}

    def run362(self,**changes):
        return core.audit(**self.args362(**changes))

    def test_01_two_truly_signed_independent_byte_exact_copies_unresolved(self):
        self.setup362()
        out=self.run362()
        self.assertEqual(out['exit_code'],2)
        self.assertTrue(out['actual_ec361_through_ec337_signed_originals_replayed'])
        self.assertTrue(out['both_distinct_custodian_signatures_verified_locally'])
        self.assertTrue(out['each_four_original_copies_exactly_agree_with_parent'])
        self.assertTrue(out['two_offline_signed_publication_copies_locally_coherent'])
        self.assertFalse(out['two_distinct_custodian_keys_prove_real_independent_entities'])

    def test_02_caller_sha_not_supplied_never_accepted_from_signed_manifest(self):
        self.setup362()
        out=self.run362(expected_source_b_observer_b_receipt_copy_sha256=None)
        self.assertTrue(out['external_sources_or_copy_pins_missing'])
        self.assertFalse(out['two_offline_signed_publication_copies_locally_coherent'])

    def test_03_external_copy_sha_mismatch_cannot_be_satisfied_by_manifest(self):
        self.setup362()
        out=self.run362(expected_source_a_checkpoint_copy_sha256='ab'*32)
        self.assertTrue(out['original_copies_or_caller_sha_pins_mismatch'])
        self.assertFalse(out['two_offline_signed_publication_copies_locally_coherent'])

    def test_04_two_independently_signed_same_size_different_root_detected(self):
        self.setup362()
        fork=self.add_evolved_checkpoint(leaves=[*self.leaves[:-1],b'EC362_FORKED_FIFTH_LEAF'])
        self.sources['b']['copies']['checkpoint']=self.write353(
            'ec362-signed-fork-b',Path(fork['path']).read_bytes())
        self.make_publication('b')
        out=self.run362()
        self.assertTrue(out['independently_presented_signed_checkpoint_conflict'])
        self.assertTrue(out['original_copies_or_caller_sha_pins_mismatch'])
        self.assertFalse(out['two_offline_signed_publication_copies_locally_coherent'])

    def test_05_signed_newer_head_visible_while_caller_saved_old_head(self):
        self.setup362()
        newer=self.add_evolved_checkpoint(leaves=[*self.leaves,b'EC362_NEWER_LEAF'])
        self.sources['b']['copies']['checkpoint']=self.write353(
             'ec362-newer-signed-b',Path(newer['path']).read_bytes())
        self.make_publication('b')
        out=self.run362()
        self.assertTrue(out['caller_publication_floor_or_newer_head_rollback'])
        self.assertTrue(out['independently_presented_signed_checkpoint_conflict'])

    def test_06_source_publication_sequence_floor_enforced(self):
        self.setup362()
        self.make_publication('a',sequence=2)
        out=self.run362()
        self.assertTrue(out['caller_publication_floor_or_newer_head_rollback'])
        self.assertFalse(out['two_offline_signed_publication_copies_locally_coherent'])

    def test_07_distinct_keys_same_claimed_source_identity_flagged(self):
        self.setup362()
        self.make_publication('b',changes={'claimed_source_id':'unverified_distribution_site_a'})
        out=self.run362()
        self.assertTrue(out['publication_source_identity_or_role_collision'])
        self.assertFalse(out['two_offline_signed_publication_copies_locally_coherent'])

    def test_08_bad_custodian_signature_denied_permission(self):
        self.setup362()
        self.make_publication('a',bad_signer=self.sources['b']['private'])
        with self.assertRaises(errors.AnchorError) as ctx:self.run362()
        self.assertEqual(ctx.exception.status,'permission_denied')
        self.assertIn('TRUE_SIGNATURE_INVALID',ctx.exception.code)

    def test_09_custodian_key_reusing_prior_observer_denied(self):
        self.setup362()
        self.sources['b']['public']=self.observers['a']['pub']
        with self.assertRaises(errors.AnchorError) as ctx:self.run362()
        self.assertEqual(ctx.exception.status,'permission_denied')

    def test_10_altered_copy_of_merkle_consistency_bundle_detected(self):
        self.setup362()
        changed=json.loads(Path(self.consistency_inputs['consistency_bundle_file']).read_bytes())
        changed['head_inclusions']=changed['head_inclusions'][:-1]
        self.sources['a']['copies']['consistency_bundle']=self.write353(
            'ec362-divergent-proof-copy',changed)
        self.make_publication('a')
        out=self.run362()
        self.assertTrue(out['original_copies_or_caller_sha_pins_mismatch'])
        self.assertFalse(out['two_offline_signed_publication_copies_locally_coherent'])

    def test_11_signed_observer_receipt_altered_and_resigned_is_not_parent_copy(self):
        self.setup362()
        new_obs=self.make_receipt('a',self.evolved[0],changes={
            'observed_utc':fixture_util.ut(self.now+timedelta(hours=7,minutes=1))})
        self.sources['b']['copies']['observer_a_receipt']=self.write353(
            'ec362-other-true-signed-receipt',Path(new_obs['path']).read_bytes())
        self.make_publication('b')
        out=self.run362()
        self.assertTrue(out['original_copies_or_caller_sha_pins_mismatch'])
        self.assertFalse(out['two_offline_signed_publication_copies_locally_coherent'])

    def test_12_source_manifests_claim_future_invalid_clock(self):
        self.setup362()
        self.make_publication('b',changes={
            'issued_utc':fixture_util.ut(self.now+timedelta(days=1)),
            'expires_utc':fixture_util.ut(self.now+timedelta(days=2))})
        out=self.run362()
        self.assertTrue(out['source_signed_utc_claim_stale_or_future'])
        self.assertFalse(out['two_offline_signed_publication_copies_locally_coherent'])

    def test_13_genuine_python_I_B_fixed_unified_router_exit2(self):
        self.setup362()
        inputs=self.args362()
        root=Path(__file__).resolve().parents[2]
        sys.path.insert(0,str(root/'scripts'))
        import ces_next as router
        argv=[sys.executable,'-I','-B',str(root/'scripts'/'ces_next.py'),
              'audit-directory-publication-custody',
              'DeliveryAudit','AuditDirectoryPublicationCustody']
        for key in router.EC362_REQUIRED:
            argv.extend(['--'+key.replace('_','-'),str(inputs[key])])
        for key in router.EC362_OPTIONAL:
            if inputs[key] is not None:
                argv.extend(['--'+key.replace('_','-'),str(inputs[key])])
        for key,flag in router.EC362_REPEATS:
            for val in inputs[key]:argv.extend([flag,str(val)])
        p=subprocess.run(argv,capture_output=True,text=True,timeout=1800)
        self.assertEqual(p.returncode,2,p.stderr+' '+p.stdout[-1600:])
        result=json.loads(p.stdout)
        self.assertEqual(result['schema'],core.RESULT_SCHEMA)
        self.assertTrue(result['two_offline_signed_publication_copies_locally_coherent'])
        derive=[sys.executable,'-I','-B',
                str(root/'scripts'/'ces_cas_directory_publication_custody.py'),
                'derive-directory-publication-custody-handoff']
        for key in router.EC361_REQUIRED:
            derive.extend(['--'+key.replace('_','-'),str(inputs[key])])
        for key in router.EC361_OPTIONAL:
            if inputs[key] is not None:
                derive.extend(['--'+key.replace('_','-'),str(inputs[key])])
        for key,flag in router.EC361_REPEATS:
            for val in inputs[key]:derive.extend([flag,str(val)])
        handoff=subprocess.run(derive,capture_output=True,text=True,timeout=1800)
        self.assertEqual(handoff.returncode,2,handoff.stderr+handoff.stdout[-1600:])
        self.assertEqual(json.loads(handoff.stdout)['schema'],core.HANDOFF_SCHEMA)

    def test_14_same_content_or_inode_reuse_across_sources_denied(self):
        self.setup362()
        # Caller attempts to present A's physical original as B's distinct
        # source (its digest is allowed to match; its inode is NOT).
        self.sources['b']['copies']['observer_a_receipt']=self.sources['a']['copies']['observer_a_receipt']
        self.make_publication('b')
        with self.assertRaises(errors.AnchorError) as ctx:self.run362()
        self.assertEqual(ctx.exception.status,'permission_denied')


if __name__=='__main__':
    import unittest
    unittest.main()
