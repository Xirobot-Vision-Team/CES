#!/usr/bin/env python3
"""EC371 focused genuine historical signatures with genuine EC369/370 fixture.

EC366->EC337 synthetic deep parent remains MOCKED by the inherited EC367
fixture. Per-test EC370 audit is cached by a mock to focus on this new layer;
one case deliberately runs the REAL EC370 audit to exercise the full current
EC369/370 stack. The historic originals/signatures/proofs are always REAL.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ed25519
from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec360_authority_directory import authority
from ec362_publication_custody import custody
from ec365_directory_lineage import lineage
from ec370_publication_accountability import test_accountability as t370
from ec367_witness_distribution import test_distribution as util
from . import archive as core

ROOT=Path(__file__).resolve().parents[2]


class ActualHistoricalDirectoryArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pub=t370.FocusedPublicationAccountabilityTests('test_01_genuine_dual_signed_complete_history_while_sender_origins_gone')
        cls.pub.setUp()
        cls.parent_result=cls.pub.audit()  # this actually runs production EC370/EC369
        assert cls.parent_result['locally_two_party_publication_and_full_inventory_consistent']

    @classmethod
    def tearDownClass(cls):
        cls.pub.doCleanups()

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.counter=0
        self.rows=[];self.proofs=[];self.transitions=[]
        self.competitors=[];self.competing_sources=[];self.competing_handoffs=[]
        self.directories=[];self.custodians=[]
        self.lineage='ExampleHistoricDirectory'
        self.first_leaf=hashlib.sha256(b'\x00real-original-leaf-0').digest()
        self.second_leaf=hashlib.sha256(b'\x00real-original-leaf-1').digest()
        self.options0=self.pub.options()
        self.make_epoch(0)
        self.make_epoch(1)
        self.make_transition()
        self.make_bundle()

    def store(self,label,data):
        self.counter+=1
        name=str(self.counter).zfill(3)+'_'+label+'.json'
        path=self.root/name
        raw=data if type(data) is bytes else canonical.canonical(data)
        path.write_bytes(raw)
        return {'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}

    def signed(self,label,body,key,domain,field):
        return self.store(label,{**body,field:key.sign(domain+canonical.canonical(body)).hex()})

    def _root(self,n):
        if n==0:return self.first_leaf.hex()
        return hashlib.sha256(b'\x01'+self.first_leaf+self.second_leaf).hexdigest()

    def make_epoch(self,n):
        rootkey=ed25519.Ed25519PrivateKey.generate()
        rootref=self.store('real_directory_root_'+str(n),util.pub(rootkey))
        cp=self.signed('real_directory_checkpoint_'+str(n),{
             'schema':authority.DIRECTORY_SCHEMA,'directory_id':self.lineage,
             'directory_public_key_original_sha256':rootref['sha256'],
             'tree_size':n+1,'root_sha256':self._root(n),
             'issued_utc':util.UTC,'expires_utc':util.EXP},rootkey,
             authority.DIRECTORY_DOMAIN,'signature_directory_ed25519_hex')
        row={'epoch_index':n,'directory_public_key_original':rootref,
             'signed_directory_checkpoint_original':cp}
        workers={}
        for slot in ('a','b'):
            key=ed25519.Ed25519PrivateKey.generate()
            keyref=self.store('real_custodian_'+slot+'_'+str(n),util.pub(key))
            copies={k:{'path':str(self.root/('REMOVED_SENDER_'+slot+'_'+str(n)+'_'+k)),
                       'sha256':cp['sha256'] if k=='checkpoint' else '9'*64}
                    for k in custody.COPY_ROLES}
            man=self.signed('real_source_manifest_'+slot+'_'+str(n),{
                'schema':custody.MANIFEST_SCHEMA,'source_slot':slot,
                'claimed_source_id':'ExampleHistoricalSource'+slot+str(n),
                'custodian_public_key_original_sha256':keyref['sha256'],
                'directory_id':self.lineage,
                'parent_ec361_canonical_result_sha256':chr(ord('a')+n)*64,
                'parent_ec360_canonical_result_sha256':'d'*64,
                'parent_directory_checkpoint_original_sha256':'e'*64,
                'advertised_checkpoint_original_sha256':cp['sha256'],
                'advertised_tree_size':n+1,'advertised_root_sha256':self._root(n),
                'publication_sequence':n,'issued_utc':util.UTC,
                'expires_utc':util.EXP,'copies':copies},key,custody.DOMAIN,
                'signature_custodian_ed25519_hex')
            row['source_'+slot+'_manifest_original']=man
            row['source_'+slot+'_custodian_public_key_original']=keyref
            workers[slot]=(key,man,keyref)
        self.directories.append((rootkey,rootref,cp))
        self.custodians.append(workers)
        self.rows.append(row)

    def make_transition(self,changed=None,append=True):
        i=0;left=self.rows[i];right=self.rows[i+1]
        proof={'from_epoch_index':0,'to_epoch_index':1,
             'older_checkpoint_original_sha256':left['signed_directory_checkpoint_original']['sha256'],
             'newer_checkpoint_original_sha256':right['signed_directory_checkpoint_original']['sha256'],
             'audit_path_sha256':[self.second_leaf.hex()]}
        body={'schema':lineage.EVENT_SCHEMA,
             'claimed_directory_lineage_id':self.lineage,
             'from_epoch_index':0,'to_epoch_index':1,
             'event_kind':'delegate_and_retire',
             'from_root_generation':0,'to_root_generation':1,
             'from_directory_public_key_original_sha256':left['directory_public_key_original']['sha256'],
             'to_directory_public_key_original_sha256':right['directory_public_key_original']['sha256'],
             'from_parent_ec361_canonical_result_sha256':'a'*64,
             'to_parent_ec361_canonical_result_sha256':'b'*64,
             'from_checkpoint_original_sha256':proof['older_checkpoint_original_sha256'],
             'to_checkpoint_original_sha256':proof['newer_checkpoint_original_sha256'],
             'from_tree_size':1,'to_tree_size':2,
             'from_merkle_root_sha256':self._root(0),'to_merkle_root_sha256':self._root(1),
             'from_source_a_manifest_original_sha256':left['source_a_manifest_original']['sha256'],
             'from_source_b_manifest_original_sha256':left['source_b_manifest_original']['sha256'],
             'to_source_a_manifest_original_sha256':right['source_a_manifest_original']['sha256'],
             'to_source_b_manifest_original_sha256':right['source_b_manifest_original']['sha256'],
             'cross_epoch_consistency_proof_canonical_sha256':core.sha(canonical.canonical(proof)),
             'issued_utc':util.UTC,'expires_utc':util.EXP}
        if changed:body.update(changed)
        raw=lineage.EVENT_DOMAIN+canonical.canonical(body)
        k0,k1=self.directories[0][0],self.directories[1][0]
        doc={**body,'signature_old_directory_ed25519_hex':k0.sign(raw).hex(),
                     'signature_new_directory_ed25519_hex':k1.sign(raw).hex()}
        ref=self.store('real_ec365_dual_signed_handoff',doc)
        entry={'signed_directory_handoff_original':ref,
               'rfc6962_consistency_proof':proof}
        if append:self.transitions=[entry]
        return entry

    def make_bundle(self):
        self.bundle=self.store('receiver_historical_archive',{
            'schema':core.BUNDLE_SCHEMA,
            'parent_ec370_canonical_result_sha256':core.sha(canonical.canonical(self.parent_result)),
            'parent_ec365_canonical_result_sha256':self.options0['expected_parent_ec365_canonical_result_sha256'],
            'claimed_directory_lineage_id':self.lineage,
            'epochs':self.rows,'transitions':self.transitions,
            'competing_signed_checkpoints':self.competitors,
            'competing_signed_source_manifests':self.competing_sources,
            'competing_signed_handoffs':self.competing_handoffs})

    def opts(self,**kw):
        d={**self.options0,
           'historical_archive_bundle_file':self.bundle['path'],
           'expected_historical_archive_bundle_sha256':self.bundle['sha256'],
           'claimed_historical_directory_lineage_id':self.lineage,
           'expected_retained_historical_checkpoint_head_sha256':self.rows[-1][
              'signed_directory_checkpoint_original']['sha256'],
           'minimum_retained_historical_tree_size':2,
           'minimum_retained_historical_root_generation':1,
           'historical_directory_root_shas':[r['directory_public_key_original']['sha256'] for r in self.rows],
           'historical_signed_checkpoint_shas':[r['signed_directory_checkpoint_original']['sha256'] for r in self.rows],
           'historical_source_a_manifest_shas':[r['source_a_manifest_original']['sha256'] for r in self.rows],
           'historical_source_b_manifest_shas':[r['source_b_manifest_original']['sha256'] for r in self.rows],
           'historical_dual_handoff_shas':[r['signed_directory_handoff_original']['sha256']
                                             for r in self.transitions if r is not None]}
        return {**d,**kw}

    def derive(self,**change):
        with patch.object(core.prior,'audit',return_value=self.parent_result):
            return core.derive_inventory(**self.opts(**change))

    def audit(self,**change):
        opts=self.opts(**change)
        with patch.object(core.prior,'audit',return_value=self.parent_result):
            if 'expected_retained_historical_inventory_sha256' not in opts:
                digest=core.derive_inventory(**self.opts())[
                    'receiver_verified_historical_inventory_canonical_sha256']
                opts['expected_retained_historical_inventory_sha256']=digest
            return core.audit(**opts)

    def test_01_real_historic_2_directory_cp_4_custodian_and_two_old_new_signatures(self):
        r=self.audit()
        self.assertEqual(r['exit_code'],2)
        self.assertEqual(r['true_verified_directory_checkpoint_ed25519_count'],2)
        self.assertEqual(r['true_verified_source_custodian_ed25519_count'],4)
        self.assertEqual(r['true_verified_old_new_dual_handoff_pair_count'],1)
        self.assertEqual(r['true_verified_rfc6962_directory_append_edges'],1)
        self.assertTrue(r['local_pinned_historical_directory_signature_and_proof_consistency'],r)
        self.assertTrue(r['historical_archive_only_partially_recovers_ec365_to_ec337'])
        self.assertFalse(r['ec365_to_ec337_full_parent_original_replay_performed'])
        self.assertTrue(all(r[k] is False for k in core.NEGATIVES))

    def test_02_live_parent_ec370_actually_invoked(self):
        options=self.opts()
        digest=self.derive()['receiver_verified_historical_inventory_canonical_sha256']
        options['expected_retained_historical_inventory_sha256']=digest
        result=core.audit(**options)  # no mock: actual EC370 + EC369 copied signed originals
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['local_pinned_historical_directory_signature_and_proof_consistency'])

    def test_03_historical_checkpoint_original_byte_tamper_denied(self):
        Path(self.rows[1]['signed_directory_checkpoint_original']['path']).write_bytes(b'tamper')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_04_true_directory_signature_forgery_denied(self):
        r=self.rows[1]
        doc=json.loads(Path(r['signed_directory_checkpoint_original']['path']).read_text())
        doc['signature_directory_ed25519_hex']='f'*128
        fake=self.store('forged_directory_signature',doc)
        r['signed_directory_checkpoint_original']=fake
        self.make_bundle()
        with self.assertRaises(errors.AnchorError):self.derive(
             historical_signed_checkpoint_shas=[self.rows[0][
                 'signed_directory_checkpoint_original']['sha256'],fake['sha256']])

    def test_05_custodian_signature_tamper_denied(self):
        Path(self.rows[0]['source_a_manifest_original']['path']).write_bytes(b'x')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_06_fake_dual_handoff_not_accepted(self):
        entry=self.transitions[0]
        p=Path(entry['signed_directory_handoff_original']['path'])
        doc=json.loads(p.read_text());doc['signature_old_directory_ed25519_hex']='0'*128
        p.write_bytes(canonical.canonical(doc))
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_07_genuine_wrong_root_generation_is_visible(self):
        self.make_transition(changed={'to_root_generation':0})
        self.make_bundle()
        result=self.audit()
        self.assertTrue(result[core.FLAGS[6]])
        self.assertFalse(result['local_pinned_historical_directory_signature_and_proof_consistency'])

    def test_08_signer_true_terminal_retirement_not_upgraded(self):
        self.make_transition(changed={'event_kind':'terminal_retirement'})
        self.make_bundle()
        self.assertTrue(self.audit()[core.FLAGS[6]])

    def test_09_invalid_rfc6962_proof_is_not_silently_valid(self):
        p=self.transitions[0]['rfc6962_consistency_proof']
        p['audit_path_sha256']=['f'*64]
        # Signature binds exact canonical proof digest, so an altered proof
        # must be re-signed to be a *cryptographically coherent* bad proof.
        self.make_transition(changed={
            'cross_epoch_consistency_proof_canonical_sha256':core.sha(canonical.canonical(p))})
        self.transitions[0]['rfc6962_consistency_proof']=p
        self.make_bundle()
        self.assertTrue(self.audit()[core.FLAGS[4]])

    def test_10_archived_old_sender_origin_paths_absent_and_never_read(self):
        for row in self.rows:
            for slot in ('a','b'):
                man=json.loads(Path(row['source_'+slot+'_manifest_original']['path']).read_text())
                for ref in man['copies'].values():self.assertFalse(Path(ref['path']).exists())
        self.assertFalse(self.audit()['sender_origin_path_required_or_read'])

    def test_11_retained_checkpoint_head_rollback_visible(self):
        result=self.audit(expected_retained_historical_checkpoint_head_sha256='f'*64)
        self.assertTrue(result[core.FLAGS[1]])

    def test_12_independent_inventory_pin_mismatch_visible(self):
        result=self.audit(expected_retained_historical_inventory_sha256='f'*64)
        self.assertTrue(result[core.FLAGS[1]])

    def test_13_independent_old_source_manifest_sha_mismatch_denied(self):
        with self.assertRaises(errors.AnchorError):
            self.derive(historical_source_b_manifest_shas=['f'*64]*2)

    def test_14_genuine_competing_old_root_signed_checkpoint_is_visible(self):
        key=self.directories[0][0];ref=self.directories[0][1]
        fork=self.signed('genuine_directory_fork',{
            'schema':authority.DIRECTORY_SCHEMA,
            'directory_id':self.lineage,
            'directory_public_key_original_sha256':ref['sha256'],
            'tree_size':1,'root_sha256':'f'*64,
            'issued_utc':util.UTC,'expires_utc':util.EXP},key,
            authority.DIRECTORY_DOMAIN,'signature_directory_ed25519_hex')
        self.competitors=[{'epoch_index':0,'signed_directory_checkpoint_original':fork}]
        self.make_bundle()
        r=self.audit()
        self.assertTrue(r[core.FLAGS[2]])
        self.assertEqual(r['genuinely_signed_competing_directory_checkpoints'],1)

    def test_15_genuine_competing_old_new_director_signers_exposed(self):
        comp=self.make_transition(changed={'event_kind':'terminal_retirement'},append=False)
        self.competing_handoffs=[{'edge_index':0,
                                   'signed_directory_handoff_original':comp[
                                       'signed_directory_handoff_original']}]
        self.make_bundle()
        r=self.audit()
        self.assertTrue(r[core.FLAGS[5]])
        self.assertEqual(r['genuinely_dual_signed_competing_handoffs'],1)

    def test_16_parent_ec365_claim_conflict_denied(self):
        with self.assertRaises(errors.AnchorError):self.derive(**{
            'expected_parent_ec365_canonical_result_sha256':'f'*64})

    def test_17_incomplete_one_epoch_kept_explicitly_unresolved(self):
        self.rows=self.rows[:1];self.transitions=[];self.make_bundle()
        r=self.audit(historical_dual_handoff_shas=[],
            historical_directory_root_shas=[self.rows[0]['directory_public_key_original']['sha256']],
            historical_signed_checkpoint_shas=[self.rows[0]['signed_directory_checkpoint_original']['sha256']],
            historical_source_a_manifest_shas=[self.rows[0]['source_a_manifest_original']['sha256']],
            historical_source_b_manifest_shas=[self.rows[0]['source_b_manifest_original']['sha256']],
            expected_retained_historical_checkpoint_head_sha256=self.rows[0][
                'signed_directory_checkpoint_original']['sha256'])
        self.assertTrue(r[core.FLAGS[5]])
        self.assertFalse(r['local_pinned_historical_directory_signature_and_proof_consistency'])

    def test_18_unsigned_derive_is_not_publication_or_certified_pin(self):
        r=self.derive()
        self.assertEqual(r['exit_code'],2)
        self.assertFalse(r['external_inventory_pin_created_or_certified'])
        self.assertEqual(r['receiver_verified_historical_inventory_canonical_sha256'],
                         core.sha(canonical.canonical(r['unsigned_verified_historical_inventory'])))

    def test_19a_cross_source_genuine_signed_parent_ec360_divergence_visible(self):
        i=0;slot='b';row=self.rows[i]
        old=json.loads(Path(row['source_b_manifest_original']['path']).read_text())
        old.pop('signature_custodian_ed25519_hex')
        old['parent_ec360_canonical_result_sha256']='f'*64
        key=self.custodians[i][slot][0]
        man=self.signed('genuine_divergent_ancestor_claim',old,key,
            custody.DOMAIN,'signature_custodian_ed25519_hex')
        self.rows[i]['source_b_manifest_original']=man
        # Re-sign the bound EC365 dual handoff, since its endpoint SHA must be real.
        self.make_transition()
        self.make_bundle()
        result=self.audit(historical_source_b_manifest_shas=[
             self.rows[0]['source_b_manifest_original']['sha256'],
             self.rows[1]['source_b_manifest_original']['sha256']])
        self.assertTrue(result[core.FLAGS[7]])

    def test_19b_historical_directory_key_reused_from_inherited_signer_denied(self):
        # Caller falsely claims an inherited signing role is also the ancient
        # directory key. No filesystem read of any origin label is required.
        with self.assertRaises(errors.AnchorError):self.derive(
            historical_directory_root_shas=[self.options0[
                 'expected_sender_public_key_sha256'],
                 self.rows[1]['directory_public_key_original']['sha256']])

    def test_19c_source_original_path_aliasing_receiver_is_denied(self):
        i=0;slot='a';row=self.rows[i]
        old=json.loads(Path(row['source_a_manifest_original']['path']).read_text())
        old.pop('signature_custodian_ed25519_hex')
        old['copies']['checkpoint']['path']=row[
            'signed_directory_checkpoint_original']['path']
        key=self.custodians[i][slot][0]
        man=self.signed('malicious_signed_source_label_alias',old,key,
            custody.DOMAIN,'signature_custodian_ed25519_hex')
        row['source_a_manifest_original']=man
        self.make_transition();self.make_bundle()
        with self.assertRaises(errors.AnchorError):self.derive(
            historical_source_a_manifest_shas=[man['sha256'],
                self.rows[1]['source_a_manifest_original']['sha256']])

    def test_19_real_competing_custodian_signed_manifest_visible(self):
        slot='a';i=0;row=self.rows[i]
        old=json.loads(Path(row['source_a_manifest_original']['path']).read_text())
        changed={k:v for k,v in old.items() if k!='signature_custodian_ed25519_hex'}
        changed['publication_sequence']=3
        key=self.custodians[i][slot][0]
        fork=self.signed('genuine_competing_custodian_source',changed,key,
            custody.DOMAIN,'signature_custodian_ed25519_hex')
        self.competing_sources=[{'epoch_index':i,'source_slot':slot,
            'signed_source_manifest_original':fork}]
        self.make_bundle()
        doc=self.audit()
        self.assertTrue(doc[core.FLAGS[3]])
        self.assertEqual(doc['genuinely_signed_competing_source_manifests'],1)

    def child_argv(self,*,unified=True,derive=False,options=None):
        inputs=self.opts() if options is None else options
        scalar=(*core.prior.prior.SCALARS,*core.prior.NEW_SCALARS,
                *core.NEW_SCALARS)
        if not derive:scalar+=core.AUDIT_ONLY
        repeats=(*core.prior.prior.REPEATS,*core.prior.NEW_REPEATS,
                 *core.NEW_REPEATS)
        if unified:
            argv=[sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_next.py'),
                  'audit-historical-directory-archive','DeliveryAudit',
                  'AuditHistoricalDirectoryArchive']
        else:
            argv=[sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_cas_historical_directory_archive.py'),
                  'derive-historical-directory-inventory' if derive else
                  'audit-historical-directory-archive']
        for key in scalar:
            argv.extend(['--'+key.replace('_','-'),str(inputs[key])])
        for key,flag in repeats:
            for x in inputs[key]:argv.extend([flag,'none' if x is None else str(x)])
        return argv

    def test_20_actual_isolated_unified_real_historical_positive(self):
        inputs={**self.opts(),
            'expected_retained_historical_inventory_sha256':self.derive()[
               'receiver_verified_historical_inventory_canonical_sha256']}
        proc=subprocess.run(self.child_argv(options=inputs),text=True,
                   capture_output=True,timeout=75)
        self.assertEqual(proc.returncode,2,proc.stdout+proc.stderr)
        obj=json.loads(proc.stdout)
        self.assertEqual(obj['schema'],core.RESULT_SCHEMA)
        self.assertTrue(obj['local_pinned_historical_directory_signature_and_proof_consistency'])
        self.assertFalse(obj['full_ec365_to_ec337_historical_parent_audit_replayed'])

    def test_21_actual_isolated_unified_signature_tamper_denied(self):
        inputs={**self.opts(),
            'expected_retained_historical_inventory_sha256':self.derive()[
               'receiver_verified_historical_inventory_canonical_sha256']}
        Path(self.rows[0]['source_b_manifest_original']['path']).write_bytes(b'bad signature bytes')
        proc=subprocess.run(self.child_argv(options=inputs),text=True,
                            capture_output=True,timeout=75)
        self.assertEqual(proc.returncode,3,proc.stdout+proc.stderr)
        obj=json.loads(proc.stdout)
        self.assertEqual(obj['schema'],core.DENIAL_SCHEMA)
        self.assertFalse(obj['full_ec365_to_ec337_historical_parent_audit_replayed'])

    def test_22_actual_isolated_unsigned_derive(self):
        proc=subprocess.run(self.child_argv(unified=False,derive=True),
            text=True,capture_output=True,timeout=75)
        self.assertEqual(proc.returncode,2,proc.stdout+proc.stderr)
        obj=json.loads(proc.stdout)
        self.assertEqual(obj['schema'],core.DERIVE_SCHEMA)
        self.assertFalse(obj['external_inventory_pin_created_or_certified'])

    def test_23_child_isolated_help_with_new_command(self):
        proc=subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_cas_historical_directory_archive.py'),
                   '--help'],text=True,capture_output=True,timeout=20)
        self.assertEqual(proc.returncode,0)
        self.assertIn('audit-historical-directory-archive',proc.stdout)

if __name__=='__main__':unittest.main()
