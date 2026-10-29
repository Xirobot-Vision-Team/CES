#!/usr/bin/env python3
"""EC373 focused genuine old Ed25519 EC359 + EC360 RFC6962 inclusion.

EC371/372 signed checkpoints, custodians, roots, witnesses and issuer records
are really signed, not fake Merkle roots. The much older EC366->EC337 test
parent is still DELIBERATELY MOCKED by the EC367 fixture; no case here can
claim a complete EC365->EC337 historical original-parent-inclusive success.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519
from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec353_transparency import test_transparency as merkle
from ec359_owner_distribution import distribution as distr
from ec360_authority_directory import authority
from ec362_publication_custody import custody
from ec365_directory_lineage import lineage
from ec367_witness_distribution import test_distribution as util
from ec372_historical_authority import test_authority_archive as t372
from . import inclusion_archive as core

ROOT=Path(__file__).resolve().parents[2]


class ReceiverHistoricalRealInclusionAndIssuerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        t372.GenuineRootSignedHistoricalAuthorityTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        t372.GenuineRootSignedHistoricalAuthorityTests.tearDownClass()

    def setUp(self):
        self.base=t372.GenuineRootSignedHistoricalAuthorityTests(
            'test_01_real_historical_signatures_and_rfc6962')
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.old=self.base.old
        self.distribution={}
        self.construct_ec359_and_resign_root_authority()
        self.build_signed_historical_inclusion_checkpoints()
        self.parent=self.base.audit()
        self.build_archive()

    def stored(self,name,data):return self.old.store(name,data)

    def signed(self,name,body,priv,domain,field):
        return self.old.signed(name,body,priv,domain,field)

    def construct_ec359_and_resign_root_authority(self):
        for slot in ('a','b'):
            role=self.base.roles[slot]
            delegate=json.loads(Path(role['delegation']['path']).read_text())
            owner=ed25519.Ed25519PrivateKey.generate()
            ownerref=self.stored('historic_ec359_owner_'+slot,util.pub(owner))
            event=self.signed('historic_ec359_issuer_authorization_'+slot,{
                'schema':distr.RECORD_SCHEMA,'scope':distr.SCOPE,
                'slot':slot,'issuer_id':delegate['issuer_id_as_signed_claim'],
                'issuer_public_key_original_sha256':role['issuer_ref']['sha256'],
                'claimed_owner_id':'HistoricOwner'+slot.upper(),
                'owner_public_key_original_sha256':ownerref['sha256'],
                'parent_ec358_canonical_result_sha256':'f'*64,
                'parent_owner_head_event_original_sha256':delegate[
                    'parent_owner_head_event_sha256'],
                'sequence':0,'previous_record_original_sha256':None,
                'operation':'authorize','replacement_owner_public_key_sha256':None,
                'effective_utc':util.UTC,'expires_utc':util.EXP},
                role['issuer'],distr.SIGN_DOMAIN,'signature_issuer_ed25519_hex')
            self.distribution[slot]={'owner':ownerref,'event0':event,
                                     'issuer':role['issuer']}
            delegate.pop('signature_root_ed25519_hex')
            delegate['owner_public_key_original_sha256']=ownerref['sha256']
            delegate['parent_distribution_head_original_sha256']=event['sha256']
            delegation=self.signed('rebuilt_genuine_root_delegation_'+slot,
                    delegate,role['root'],authority.DELEGATION_DOMAIN,
                    'signature_root_ed25519_hex')
            origin=json.loads(Path(role['origin']['path']).read_text())
            origin.pop('signature_witness_ed25519_hex')
            origin['delegation_original_sha256']=delegation['sha256']
            witnessed=self.signed('rebuilt_true_witness_origin_'+slot,origin,
                 role['witness'],authority.ORIGIN_DOMAIN,
                 'signature_witness_ed25519_hex')
            snap0=self.base.make_snapshot(slot,role['root'],role['root_ref'],
                                delegation,role['issuer_ref'],0,None)
            snap1=self.base.make_snapshot(slot,role['root'],role['root_ref'],
                                delegation,role['issuer_ref'],1,snap0['sha256'])
            role.update(delegation=delegation,origin=witnessed,
                        snapshot_0=snap0,snapshot_1=snap1)
            for n,authority_row in enumerate(self.base.authority_rows):
                row=authority_row['source_'+slot]
                row['root_signed_delegation_original']=delegation
                row['witness_signed_origin_original']=witnessed
                row['root_signed_revocation_snapshot_originals']=(
                     [snap0] if n==0 else [snap0,snap1])
                row['selected_revocation_head_sha256']=(
                     snap0 if n==0 else snap1)['sha256']

    def leaves(self):
        a,b=(self.base.roles[slot] for slot in ('a','b'))
        return [Path(r['path']).read_bytes() for r in (
            a['delegation'],b['delegation'],a['snapshot_0'],b['snapshot_0'],
            a['snapshot_1'],b['snapshot_1'])]

    def build_signed_historical_inclusion_checkpoints(self):
        leaves=self.leaves()
        cpheads=[]
        for n,count in enumerate((4,6)):
            oldrow=self.old.rows[n]
            rootkey=self.old.directories[n][0]
            cp_doc=json.loads(Path(oldrow[
                         'signed_directory_checkpoint_original']['path']).read_text())
            cp_doc.pop('signature_directory_ed25519_hex')
            cp_doc['tree_size']=count
            cp_doc['root_sha256']=merkle.root(leaves[:count]).hex()
            cp=self.signed('ec373_real_merkle_ec360_checkpoint_'+str(n),
                     cp_doc,rootkey,authority.DIRECTORY_DOMAIN,
                     'signature_directory_ed25519_hex')
            oldrow['signed_directory_checkpoint_original']=cp
            cpheads.append(cp)
            for slot in ('a','b'):
                oldref=oldrow['source_'+slot+'_manifest_original']
                m=json.loads(Path(oldref['path']).read_text())
                m.pop('signature_custodian_ed25519_hex')
                m['advertised_checkpoint_original_sha256']=cp['sha256']
                m['advertised_tree_size']=count
                m['advertised_root_sha256']=cp_doc['root_sha256']
                m['copies']['checkpoint']['sha256']=cp['sha256']
                key=self.old.custodians[n][slot][0]
                signed_manifest=self.signed('ec373_true_old_custodian_'+slot+'_'+str(n),
                    m,key,custody.DOMAIN,'signature_custodian_ed25519_hex')
                oldrow['source_'+slot+'_manifest_original']=signed_manifest
                # EC372 authority must continue to reference exact changed
                # EC362 custodian-signed manifest SHA, not the previous file.
                auth=self.base.authority_rows[n]['source_'+slot]
                auth['source_manifest_original_sha256']=signed_manifest['sha256']
        left,right=self.old.rows
        p={'from_epoch_index':0,'to_epoch_index':1,
           'older_checkpoint_original_sha256':cpheads[0]['sha256'],
           'newer_checkpoint_original_sha256':cpheads[1]['sha256'],
           'audit_path_sha256':[node.hex() for node in merkle.consistency(leaves,4)]}
        event=json.loads(Path(self.old.transitions[0][
                         'signed_directory_handoff_original']['path']).read_text())
        event.pop('signature_old_directory_ed25519_hex')
        event.pop('signature_new_directory_ed25519_hex')
        event.update(from_checkpoint_original_sha256=cpheads[0]['sha256'],
               to_checkpoint_original_sha256=cpheads[1]['sha256'],
               from_tree_size=4,to_tree_size=6,
               from_merkle_root_sha256=merkle.root(leaves[:4]).hex(),
               to_merkle_root_sha256=merkle.root(leaves).hex(),
               from_source_a_manifest_original_sha256=left[
                   'source_a_manifest_original']['sha256'],
               from_source_b_manifest_original_sha256=left[
                   'source_b_manifest_original']['sha256'],
               to_source_a_manifest_original_sha256=right[
                   'source_a_manifest_original']['sha256'],
               to_source_b_manifest_original_sha256=right[
                   'source_b_manifest_original']['sha256'],
               cross_epoch_consistency_proof_canonical_sha256=core.sha(
                   canonical.canonical(p)))
        raw=lineage.EVENT_DOMAIN+canonical.canonical(event)
        k0,k1=(self.old.directories[n][0] for n in range(2))
        signed={**event,'signature_old_directory_ed25519_hex':k0.sign(raw).hex(),
                  'signature_new_directory_ed25519_hex':k1.sign(raw).hex()}
        ref=self.stored('ec373_real_old_new_dual_sig_merkle_handoff',signed)
        self.old.transitions=[{'signed_directory_handoff_original':ref,
                               'rfc6962_consistency_proof':p}]
        self.old.make_bundle()
        self.base.parent=self.old.audit()
        self.base.old_options=self.old.opts(
            expected_retained_historical_inventory_sha256=self.old.derive()[
               'receiver_verified_historical_inventory_canonical_sha256'])
        self.base.make_bundle()

    def make_proof(self,ref,leaves):
        index=self.leaves().index(Path(ref['path']).read_bytes())
        return {'original_sha256':ref['sha256'],'leaf_index':index,
                'audit_path_sha256':[x.hex() for x in merkle.inclusion(leaves,index)]}

    def build_archive(self):
        all_leaves=self.leaves()
        self.rows=[]
        for n,count in enumerate((4,6)):
            row={'epoch_index':n,
                 'signed_directory_checkpoint_original_sha256':self.old.rows[n][
                    'signed_directory_checkpoint_original']['sha256']}
            for slot in ('a','b'):
                refs=self.base.authority_rows[n]['source_'+slot]
                m=self.distribution[slot]
                row['source_'+slot]={
                   'delegation_inclusion':self.make_proof(refs[
                                   'root_signed_delegation_original'],all_leaves[:count]),
                   'snapshot_inclusions':[self.make_proof(ref,all_leaves[:count])
                       for ref in refs['root_signed_revocation_snapshot_originals']],
                   'owner_public_key_original':m['owner'],
                   'claimed_owner_id':'HistoricOwner'+slot.upper(),
                   'signed_parent_ec358_canonical_result_sha256':'f'*64,
                   'issuer_signed_owner_distribution_originals':[m['event0']],
                   'selected_owner_distribution_head_sha256':m['event0']['sha256']}
            self.rows.append(row)
        self.rebuild_bundle()

    def rebuild_bundle(self):
        self.bundle=self.stored('ec373_receiver_true_historical_inclusion',{
          'schema':core.BUNDLE_SCHEMA,
          'parent_ec372_canonical_result_sha256':core.sha(canonical.canonical(self.parent)),
          'ec371_historical_archive_original_sha256':self.old.bundle['sha256'],
          'ec372_historical_authority_original_sha256':self.base.bundle['sha256'],
          'claimed_directory_lineage_id':self.old.lineage,
          'epochs':self.rows})

    def options(self,**kw):
        d={**self.base.opts(),
           'expected_retained_historical_authority_inventory_sha256':self.base.derive()[
                        'receiver_verified_historical_authority_inventory_sha256'],
           'historical_inclusion_bundle_file':self.bundle['path'],
           'expected_historical_inclusion_bundle_sha256':self.bundle['sha256'],
           'historical_distribution_a_head_shas':[self.distribution['a']['event0']['sha256']]*2,
           'historical_distribution_b_head_shas':[self.distribution['b']['event0']['sha256']]*2,
           'minimum_historical_distribution_a_sequences':[0,0],
           'minimum_historical_distribution_b_sequences':[0,0],
           'minimum_historical_inclusion_tree_sizes':[4,6]}
        return {**d,**kw}

    def derive(self,**kw):
        with patch.object(core.parent,'audit',return_value=self.parent):
            return core.derive_inventory(**self.options(**kw))

    def audit(self,**kw):
        digest=self.derive()['receiver_verified_historical_inclusion_inventory_sha256']
        opts=self.options(expected_retained_historical_inclusion_inventory_sha256=digest)
        opts.update(kw)
        with patch.object(core.parent,'audit',return_value=self.parent):
            return core.audit(**opts)

    def test_01_genuine_ec360_merkle_and_ec359_signatures(self):
        doc=self.audit()
        self.assertEqual(doc['exit_code'],2)
        self.assertEqual(doc['verified_exact_ec371_signed_checkpoint_count'],2)
        self.assertEqual(doc['recomputed_actual_rfc6962_inclusion_proof_count'],10)
        self.assertEqual(doc['replayed_genuine_ec359_issuer_signed_record_count'],4)
        self.assertTrue(doc['local_pinned_historical_inclusion_and_issuer_slice_consistent'],doc)
        self.assertFalse(doc['ec365_to_ec337_full_parent_original_replay_performed'])
        self.assertTrue(all(doc[k] is False for k in core.NEGATIVES))

    def test_02_parent_ec372_ec371_ec370_ec369_live_replayed(self):
        opts=self.options()
        opts['expected_retained_historical_inclusion_inventory_sha256']=self.derive()[
               'receiver_verified_historical_inclusion_inventory_sha256']
        doc=core.audit(**opts)
        self.assertEqual(doc['exit_code'],2)
        self.assertTrue(doc['local_pinned_historical_inclusion_and_issuer_slice_consistent'])

    def test_03_wrong_real_merkle_path_visible(self):
        self.rows[1]['source_a']['snapshot_inclusions'][1]['audit_path_sha256'][0]='f'*64
        self.rebuild_bundle()
        doc=self.audit()
        self.assertTrue(doc[core.FLAGS[2]])
        self.assertFalse(doc['local_pinned_historical_inclusion_and_issuer_slice_consistent'])

    def test_04_inclusion_proof_omission_denied(self):
        self.rows[1]['source_b']['snapshot_inclusions'].pop()
        self.rebuild_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_05_delegation_leaf_replaced_with_snapshot_denied(self):
        self.rows[0]['source_a']['delegation_inclusion']=copy.deepcopy(
                            self.rows[0]['source_a']['snapshot_inclusions'][0])
        self.rebuild_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_06_duplicate_leaf_index_both_roles_denied(self):
        self.rows[0]['source_b']['delegation_inclusion']['leaf_index']=0
        self.rebuild_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_07_wrong_signed_directory_checkpoint_sha_denied(self):
        self.rows[0]['signed_directory_checkpoint_original_sha256']='f'*64
        self.rebuild_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_08_true_ec359_original_byte_tamper_denied(self):
        Path(self.distribution['a']['event0']['path']).write_bytes(b'FORGED_OLD_EC359')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_09_wrong_old_ec359_issuer_signature_denied(self):
        old=self.distribution['b']['event0']
        doc=json.loads(Path(old['path']).read_text())
        doc['signature_issuer_ed25519_hex']='f'*128
        forged=self.stored('forged_old_issuer_signature',doc)
        for row in self.rows:
            row['source_b']['issuer_signed_owner_distribution_originals']=[forged]
        self.rebuild_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_10_unmatched_ec360_delegated_ec359_head_denied(self):
        self.rows[0]['source_a']['selected_owner_distribution_head_sha256']='f'*64
        self.rebuild_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_11_independent_ec359_head_rollback_visible(self):
        doc=self.audit(historical_distribution_a_head_shas=['f'*64]*2)
        self.assertTrue(doc[core.FLAGS[1]])

    def test_12_sequence_floor_not_met_visible(self):
        doc=self.audit(minimum_historical_distribution_b_sequences=[1,1])
        self.assertTrue(doc[core.FLAGS[1]])

    def test_13_directory_tree_floor_rollback_visible(self):
        doc=self.audit(minimum_historical_inclusion_tree_sizes=[5,7])
        self.assertTrue(doc[core.FLAGS[1]])

    def test_14_inventory_external_digest_mismatch_visible(self):
        doc=self.audit(expected_retained_historical_inclusion_inventory_sha256='f'*64)
        self.assertTrue(doc[core.FLAGS[1]])

    def new_issuer_event(self,slot,operation,after=None,label=None):
        role=self.base.roles[slot]
        prev=self.distribution[slot]['event0'] if after is None else after
        parent=json.loads(Path(prev['path']).read_text())
        parent.pop('signature_issuer_ed25519_hex')
        parent.update(sequence=1,
                      previous_record_original_sha256=self.distribution[slot]['event0']['sha256'],
                      operation=operation,
                      replacement_owner_public_key_sha256=(
                          'a'*64 if operation=='rotate' else None))
        return self.signed(label or 'valid_real_issuer_'+operation, parent,
               role['issuer'],distr.SIGN_DOMAIN,'signature_issuer_ed25519_hex')

    def test_15_genuine_issuer_signed_revoke_cannot_be_ignored(self):
        revoke=self.new_issuer_event('a','revoke')
        for row in self.rows:
            row['source_a']['issuer_signed_owner_distribution_originals'].append(revoke)
        self.rebuild_bundle()
        doc=self.audit()
        self.assertTrue(doc[core.FLAGS[3]])

    def test_16_genuine_issuer_signed_rotation_cannot_reauthorize(self):
        rotate=self.new_issuer_event('b','rotate')
        for row in self.rows:
            row['source_b']['issuer_signed_owner_distribution_originals'].append(rotate)
        self.rebuild_bundle()
        self.assertTrue(self.audit()[core.FLAGS[3]])

    def test_17_genuine_signed_revoke_and_rotate_fork_visible(self):
        revoked=self.new_issuer_event('a','revoke',label='fork_revoke')
        rotated=self.new_issuer_event('a','rotate',label='fork_rotate')
        for row in self.rows:
            row['source_a']['issuer_signed_owner_distribution_originals'].extend([revoked,rotated])
        self.rebuild_bundle()
        self.assertTrue(self.audit()[core.FLAGS[3]])

    def test_18_missing_signed_predecessor_denied(self):
        revoked=self.new_issuer_event('a','revoke')
        for row in self.rows:
            row['source_a']['issuer_signed_owner_distribution_originals']=[revoked]
        self.rebuild_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_19_real_ec359_signed_id_different_delegated_claim_denied(self):
        role=self.base.roles['a']
        source=self.distribution['a']['event0']
        doc=json.loads(Path(source['path']).read_text())
        doc.pop('signature_issuer_ed25519_hex')
        doc['issuer_id']='AnotherGenuineIssuer'
        signed=self.signed('real_signature_wrong_delegated_issuer',doc,
           role['issuer'],distr.SIGN_DOMAIN,'signature_issuer_ed25519_hex')
        for row in self.rows:
            row['source_a']['issuer_signed_owner_distribution_originals']=[signed]
        self.rebuild_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_20_owner_original_key_not_bound_to_delegation_denied(self):
        new=ed25519.Ed25519PrivateKey.generate()
        self.rows[0]['source_a']['owner_public_key_original']=self.stored(
                        'impostor_owner_key',util.pub(new))
        self.rebuild_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_21_alias_to_old_unopened_source_copy_label_denied(self):
        label=json.loads(Path(self.old.rows[0][
               'source_a_manifest_original']['path']).read_text())['copies']['checkpoint']['path']
        self.rows[0]['source_a']['owner_public_key_original']={
                   'path':label,'sha256':self.distribution['a']['owner']['sha256']}
        self.rebuild_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()
        self.assertFalse(Path(label).exists())

    def test_22_parent_canonical_sha_mismatch_denied(self):
        old=json.loads(Path(self.bundle['path']).read_text())
        old['parent_ec372_canonical_result_sha256']='f'*64
        self.bundle=self.stored('false_parent_ec372_sha',old)
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_23_unsigned_inventory_is_not_external_pin(self):
        doc=self.derive()
        self.assertFalse(doc['caller_external_inventory_pin_created_or_certified'])
        self.assertEqual(doc['receiver_verified_historical_inclusion_inventory_sha256'],
           core.sha(canonical.canonical(doc['unsigned_verified_historical_inclusion_inventory'])))

    def test_24_original_unopened_sender_labels_absent(self):
        for row in self.old.rows:
            for slot in ('a','b'):
                m=json.loads(Path(row[
                    'source_'+slot+'_manifest_original']['path']).read_text())
                for x in m['copies'].values():self.assertFalse(Path(x['path']).exists())
        self.assertFalse(self.audit()['sender_origin_path_required_or_read'])

    def argv(self,unified=False,derive=False):
        from ec370_publication_accountability import accountability as p370
        from ec371_historical_archive import archive as p371
        from ec372_historical_authority import authority_archive as p372
        opts=self.options()
        opts['expected_retained_historical_inclusion_inventory_sha256']=self.derive()[
                         'receiver_verified_historical_inclusion_inventory_sha256']
        name='derive-historical-inclusion-inventory' if derive else 'audit-historical-inclusion-archive'
        argv=[sys.executable,'-I','-B',str(ROOT/'scripts'/(
              'ces_next.py' if unified else 'ces_cas_historical_inclusion_archive.py')),name]
        if unified:argv+=['DeliveryAudit','AuditHistoricalInclusionArchive']
        scalars=(*p370.prior.SCALARS,*p370.NEW_SCALARS,*p371.NEW_SCALARS,
                *p371.AUDIT_ONLY,*p372.NEW_SCALARS,*p372.AUDIT_ONLY,
                *core.NEW_SCALARS)
        if not derive:scalars+=core.AUDIT_ONLY
        for name in scalars:argv.extend(['--'+name.replace('_','-'),str(opts[name])])
        for key,flag in (*p370.prior.REPEATS,*p370.NEW_REPEATS,*p371.NEW_REPEATS,
                         *p372.NEW_REPEATS,*core.NEW_REPEATS):
            for val in opts[key]:argv.extend([flag,'none' if val is None else str(val)])
        return argv

    def test_25_actual_isolated_unified_true_signature_audit(self):
        proc=subprocess.run(self.argv(unified=True),capture_output=True,text=True,timeout=180)
        self.assertEqual(proc.returncode,2,proc.stderr+' '+proc.stdout[:1200])
        doc=json.loads(proc.stdout)
        self.assertTrue(doc['local_pinned_historical_inclusion_and_issuer_slice_consistent'])

    def test_26_actual_isolated_standalone_unsigned_derive(self):
        proc=subprocess.run(self.argv(derive=True),capture_output=True,text=True,timeout=180)
        self.assertEqual(proc.returncode,2,proc.stderr+' '+proc.stdout[:1200])
        self.assertEqual(json.loads(proc.stdout)['schema'],core.DERIVE_SCHEMA)

    def test_27_actual_isolated_unified_signed_original_denial(self):
        argv=self.argv(unified=True)
        Path(self.distribution['a']['event0']['path']).write_bytes(b'forged')
        proc=subprocess.run(argv,capture_output=True,text=True,timeout=180)
        self.assertIn(proc.returncode,(3,4,5),proc.stderr+' '+proc.stdout[:1200])
        doc=json.loads(proc.stdout)
        self.assertEqual(doc['schema'],core.DENIAL_SCHEMA)
        self.assertFalse(doc['sender_origin_path_required_or_read'])

if __name__=='__main__':unittest.main()
