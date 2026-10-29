#!/usr/bin/env python3
"""EC372 focused real Ed25519 revocation/origin/delegation originals.

The EC371 parent fixture is real for historic signatures and live EC370/369
signatures; its EC366->EC337 old deep original chain is DELIBERATELY MOCKED.
This test suite claims ZERO complete true EC365->EC337 parent-inclusive cases.
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
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from authority_directory import authority
from witness_distribution import test_distribution as util
from historical_archive import test_archive as t371
from . import authority_archive as core

ROOT=Path(__file__).resolve().parents[2]


class GenuineRootSignedHistoricalAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        t371.ActualHistoricalDirectoryArchiveTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        t371.ActualHistoricalDirectoryArchiveTests.tearDownClass()

    def setUp(self):
        self.old=t371.ActualHistoricalDirectoryArchiveTests('test_01_real_historic_2_directory_cp_4_custodian_and_two_old_new_signatures')
        self.old.setUp()
        self.addCleanup(self.old.doCleanups)
        self.parent=self.old.audit()
        self.old_options=self.old.opts(
            expected_retained_historical_inventory_sha256=self.old.derive()[
                'receiver_verified_historical_inventory_canonical_sha256'])
        self.authority_rows=[]
        self.roles={}
        self.make_authority()
        self.make_bundle()

    def sign(self,label,body,private,domain,field):
        return self.old.signed(label,body,private,domain,field)

    def new_role(self,slot):
        root=ed25519.Ed25519PrivateKey.generate()
        witness=ed25519.Ed25519PrivateKey.generate()
        issuer=ed25519.Ed25519PrivateKey.generate()
        r=self.old.store('authority_'+slot+'_root',util.pub(root))
        wref=self.old.store('authority_'+slot+'_witness',util.pub(witness))
        i=self.old.store('authority_'+slot+'_issuer',util.pub(issuer))
        body={'schema':authority.DELEGATION_SCHEMA,'slot':slot,
          'authority_id':'HistoricAuthority'+slot.upper(),
          'root_public_key_original_sha256':r['sha256'],
          'issuer_public_key_original_sha256':i['sha256'],
          'issuer_id_as_signed_claim':'HistoricIssuer'+slot.upper(),
          'owner_public_key_original_sha256':'a'*64,
          'parent_owner_head_event_sha256':'b'*64,
          'parent_distribution_head_original_sha256':'c'*64,
          'parent_ec359_canonical_result_sha256':'d'*64,
          'authorized_jurisdictions':['HistoricJurisdiction'],
          'authorized_scopes':[authority.TARGET_SCOPE],
          'valid_from_utc':util.UTC,'expires_utc':util.EXP}
        d=self.sign('ec360_delegation_'+slot,body,root,
                    authority.DELEGATION_DOMAIN,'signature_root_ed25519_hex')
        origin=self.sign('ec360_origin_'+slot,{
          'schema':authority.ORIGIN_SCHEMA,'slot':slot,
          'authority_id':'HistoricAuthority'+slot.upper(),
          'claimed_jurisdiction':'HistoricJurisdiction',
          'origin_reference_id':'SourceClaim'+slot.upper(),
          'root_public_key_original_sha256':r['sha256'],
          'delegation_original_sha256':d['sha256'],
          'origin_witness_public_key_original_sha256':wref['sha256'],
          'observed_utc':util.UTC,'expires_utc':util.EXP},witness,
          authority.ORIGIN_DOMAIN,'signature_witness_ed25519_hex')
        s0=self.make_snapshot(slot,root,r,d,i,0,None)
        s1=self.make_snapshot(slot,root,r,d,i,1,s0['sha256'])
        self.roles[slot]={'root':root,'witness':witness,'issuer':issuer,'root_ref':r,
              'witness_ref':wref,'issuer_ref':i,'delegation':d,'origin':origin,
              'snapshot_0':s0,'snapshot_1':s1}

    def make_snapshot(self,slot,root,rootref,delegation,issuer,sequence,previous,
                      revoked=False,covered=True,issued=None):
        body={'schema':authority.SNAPSHOT_SCHEMA,'slot':slot,
          'authority_id':'HistoricAuthority'+slot.upper(),
          'root_public_key_original_sha256':rootref['sha256'],
          'delegation_original_sha256':delegation['sha256'],
          'scope':authority.TARGET_SCOPE,
          'sequence':sequence,
          'previous_snapshot_original_sha256':previous,
          'inventory_issuer_key_shas':[issuer['sha256']] if covered else [],
          'revoked_issuer_key_shas':[issuer['sha256']] if revoked else [],
          'issued_utc':util.UTC if issued is None else issued,
          'valid_until_utc':util.EXP}
        return self.sign('ec360_root_signed_revocation_'+slot+'_'+str(sequence),
              body,root,authority.SNAPSHOT_DOMAIN,'signature_root_ed25519_hex')

    def make_authority(self):
        self.roles={}
        for slot in ('a','b'):self.new_role(slot)
        self.authority_rows=[]
        for e in range(len(self.old.rows)):
            row={'epoch_index':e}
            for slot in ('a','b'):
                role=self.roles[slot]
                manifest=json.loads(Path(self.old.rows[e][
                    'source_'+slot+'_manifest_original']['path']).read_text())
                row['source_'+slot]={
                   'authority_root_public_key_original':role['root_ref'],
                   'origin_witness_public_key_original':role['witness_ref'],
                   'issuer_public_key_original':role['issuer_ref'],
                   'root_signed_delegation_original':role['delegation'],
                   'witness_signed_origin_original':role['origin'],
                   'root_signed_revocation_snapshot_originals':[
                       role['snapshot_0']] if e==0 else [
                       role['snapshot_0'],role['snapshot_1']],
                   'selected_revocation_head_sha256':role[
                       'snapshot_0' if e==0 else 'snapshot_1']['sha256'],
                   'source_manifest_original_sha256':self.old.rows[e][
                       'source_'+slot+'_manifest_original']['sha256'],
                   'source_custodian_key_original_sha256':self.old.rows[e][
                       'source_'+slot+'_custodian_public_key_original']['sha256'],
                   'signed_parent_ec360_canonical_result_sha256':manifest[
                       'parent_ec360_canonical_result_sha256']}
            self.authority_rows.append(row)

    def make_bundle(self):
        self.bundle=self.old.store('ec372_receiver_authority_archive',{
          'schema':core.BUNDLE_SCHEMA,
          'parent_ec371_canonical_result_sha256':core.sha(canonical.canonical(self.parent)),
          'historical_directory_archive_original_sha256':self.old.bundle['sha256'],
          'claimed_directory_lineage_id':self.old.lineage,
          'epochs':self.authority_rows})

    def opts(self,**kw):
        d={**self.old_options,
          'historical_authority_bundle_file':self.bundle['path'],
          'expected_historical_authority_bundle_sha256':self.bundle['sha256']}
        for slot in ('a','b'):
            d['historical_authority_'+slot+'_root_shas']=[r[
                'source_'+slot]['authority_root_public_key_original']['sha256']
                for r in self.authority_rows]
            d['historical_authority_'+slot+'_head_shas']=[(r[
                'source_'+slot]['selected_revocation_head_sha256'] or
                self.roles[slot]['snapshot_1']['sha256'])
                for r in self.authority_rows]
            d['minimum_authority_'+slot+'_revocation_sequences']=[0,1]
            d['minimum_authority_'+slot+'_publication_sequences']=[0,1]
        return {**d,**kw}

    def derive(self,**kw):
        with patch.object(core.prior,'audit',return_value=self.parent):
            return core.derive_inventory(**self.opts(**kw))

    def audit(self,**kw):
        with patch.object(core.prior,'audit',return_value=self.parent):
            args={**self.opts(),
                'expected_retained_historical_authority_inventory_sha256':self.derive()[
                    'receiver_verified_historical_authority_inventory_sha256'],**kw}
            return core.audit(**args)

    def test_01_real_historical_signatures_and_rfc6962(self):
        r=self.audit()
        self.assertEqual(r['exit_code'],2)
        self.assertEqual(r['verified_original_root_signed_delegation_count'],4)
        self.assertEqual(r['verified_original_witness_signed_origin_count'],4)
        self.assertEqual(r['verified_original_root_signed_revocation_snapshot_count'],6)
        self.assertTrue(r['local_pinned_historical_authority_slice_consistent'])
        self.assertTrue(r[core.FLAGS[-1]])
        self.assertTrue(all(r[k] is False for k in core.NEGATIVES))

    def test_02_parent_ec371_real_audit_replayed(self):
        opts=self.opts(expected_retained_historical_authority_inventory_sha256=
            self.derive()['receiver_verified_historical_authority_inventory_sha256'])
        r=core.audit(**opts)  # NO mock: genuine EC371 -> EC370 -> EC369
        self.assertEqual(r['exit_code'],2)
        self.assertTrue(r['local_pinned_historical_authority_slice_consistent'])

    def test_03_original_root_signed_revocation_signature_forgery_denied(self):
        ref=self.roles['a']['snapshot_1']
        bad=json.loads(Path(ref['path']).read_text())
        bad['signature_root_ed25519_hex']='f'*128
        new=self.old.store('forged_snapshot',bad)
        self.authority_rows[1]['source_a'][
                  'root_signed_revocation_snapshot_originals'][-1]=new
        self.authority_rows[1]['source_a']['selected_revocation_head_sha256']=new['sha256']
        self.make_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_04_true_root_signed_revocation_never_authorizes(self):
        role=self.roles['a']
        snap=self.make_snapshot('a',role['root'],role['root_ref'],
              role['delegation'],role['issuer_ref'],1,role['snapshot_0']['sha256'],
              revoked=True)
        self.authority_rows[1]['source_a']['root_signed_revocation_snapshot_originals'][-1]=snap
        self.authority_rows[1]['source_a']['selected_revocation_head_sha256']=snap['sha256']
        self.make_bundle()
        self.assertTrue(self.audit()[core.FLAGS[2]])

    def test_05_authentic_root_signed_fork_preserved(self):
        role=self.roles['a']
        fork=self.make_snapshot('a',role['root'],role['root_ref'],
              role['delegation'],role['issuer_ref'],1,role['snapshot_0']['sha256'],
              revoked=True)
        self.authority_rows[1]['source_a']['root_signed_revocation_snapshot_originals'].append(fork)
        self.make_bundle()
        r=self.audit()
        self.assertTrue(r[core.FLAGS[2]])
        self.assertTrue(r[core.FLAGS[3]])

    def test_06_signed_revocation_head_rollback_visible(self):
        self.assertTrue(self.audit(historical_authority_a_head_shas=['f'*64]*2)[core.FLAGS[1]])

    def test_07_signed_snapshot_sequence_floor_visible(self):
        # EC360 MAX_SNAPSHOTS is 5; a caller-retained floor 2 exceeds real head1.
        self.assertTrue(self.audit(minimum_authority_a_revocation_sequences=[0,2])[core.FLAGS[1]])

    def test_08_signed_source_publication_floor_visible(self):
        self.assertTrue(self.audit(minimum_authority_b_publication_sequences=[1,2])[core.FLAGS[6]])

    def test_09_real_witness_signature_forgery_denied(self):
        ref=self.roles['b']['origin']
        old=json.loads(Path(ref['path']).read_text())
        old['signature_witness_ed25519_hex']='f'*128
        new=self.old.store('forged_witness',old)
        for r in self.authority_rows:r['source_b']['witness_signed_origin_original']=new
        self.make_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_10_real_delegation_signature_forgery_denied(self):
        ref=self.roles['a']['delegation']
        old=json.loads(Path(ref['path']).read_text())
        old['signature_root_ed25519_hex']='0'*128
        new=self.old.store('forged_delegation',old)
        for r in self.authority_rows:r['source_a']['root_signed_delegation_original']=new
        self.make_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_11_source_manifest_sha_custody_mismatch_denied(self):
        self.authority_rows[0]['source_a']['source_manifest_original_sha256']='f'*64
        self.make_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_12_root_alias_directory_signer_denied(self):
        self.authority_rows[0]['source_a']['authority_root_public_key_original']=self.old.rows[0]['directory_public_key_original']
        self.make_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_13_receiver_path_cannot_alias_old_source_label(self):
        manifest=json.loads(Path(self.old.rows[0]['source_a_manifest_original']['path']).read_text())
        sender=manifest['copies']['observer_a_receipt']['path']
        self.authority_rows[0]['source_a']['root_signed_delegation_original']={
              'path':sender,'sha256':self.roles['a']['delegation']['sha256']}
        self.make_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()
        self.assertFalse(Path(sender).exists())

    def test_14_no_snapshots_missing_explicitly_unresolved(self):
        self.authority_rows[1]['source_b']['root_signed_revocation_snapshot_originals']=[]
        self.authority_rows[1]['source_b']['selected_revocation_head_sha256']=None
        self.make_bundle()
        r=self.audit()
        self.assertTrue(r[core.FLAGS[1]])
        self.assertFalse(r['local_pinned_historical_authority_slice_consistent'])

    def test_15_snapshot_missing_signed_predecessor_denied(self):
        self.authority_rows[1]['source_a']['root_signed_revocation_snapshot_originals']=[
                      self.roles['a']['snapshot_1']]
        self.make_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_16_genuine_unwitnessed_scope_exclusion_flagged(self):
        role=self.roles['a']
        doc=json.loads(Path(role['delegation']['path']).read_text())
        del doc['signature_root_ed25519_hex']
        doc['authorized_scopes']=['OtherScope']
        new=self.sign('genuinely_limited_delegation',doc,role['root'],
              authority.DELEGATION_DOMAIN,'signature_root_ed25519_hex')
        # Now the old witness and revocation signatures refer to old delegation
        # and must be reissued with actual signatures; no unsanctioned bypass.
        w=json.loads(Path(role['origin']['path']).read_text())
        del w['signature_witness_ed25519_hex']
        w['delegation_original_sha256']=new['sha256']
        origin=self.sign('limited_witness',w,role['witness'],
              authority.ORIGIN_DOMAIN,'signature_witness_ed25519_hex')
        for e in (0,1):
            row=self.authority_rows[e]['source_a']
            row['root_signed_delegation_original']=new
            row['witness_signed_origin_original']=origin
            snaps=[];prev=None
            for k in range(e+1):
                d=json.loads(Path(role['snapshot_'+str(k)]['path']).read_text())
                del d['signature_root_ed25519_hex']
                d['delegation_original_sha256']=new['sha256']
                d['previous_snapshot_original_sha256']=prev
                snap=self.sign('limited_revocation_'+str(e)+'_'+str(k),d,role['root'],
                     authority.SNAPSHOT_DOMAIN,'signature_root_ed25519_hex')
                snaps.append(snap);prev=snap['sha256']
            row['root_signed_revocation_snapshot_originals']=snaps
            row['selected_revocation_head_sha256']=prev
        # To demonstrate real history with a common predecessor across epochs:
        self.authority_rows[1]['source_a']['root_signed_revocation_snapshot_originals'][0]=\
            self.authority_rows[0]['source_a']['root_signed_revocation_snapshot_originals'][0]
        role0=self.authority_rows[0]['source_a']['selected_revocation_head_sha256']
        d=json.loads(Path(self.authority_rows[1]['source_a'][
             'root_signed_revocation_snapshot_originals'][1]['path']).read_text())
        del d['signature_root_ed25519_hex'];d['previous_snapshot_original_sha256']=role0
        new1=self.sign('limited_seq1_handoff',d,role['root'],
               authority.SNAPSHOT_DOMAIN,'signature_root_ed25519_hex')
        self.authority_rows[1]['source_a']['root_signed_revocation_snapshot_originals'][1]=new1
        self.authority_rows[1]['source_a']['selected_revocation_head_sha256']=new1['sha256']
        self.make_bundle()
        self.assertTrue(self.audit()[core.FLAGS[4]])

    def test_17_cross_epoch_unproven_root_rotation_visible(self):
        # Producing a fake authority-rebind by copying old signature under a
        # new key cannot pass as a genuine rotation; the key collision/crypto
        # boundary DENIES it rather than returning local positive.
        new=ed25519.Ed25519PrivateKey.generate()
        self.authority_rows[1]['source_b']['authority_root_public_key_original']=\
            self.old.store('fake_new_root',util.pub(new))
        self.make_bundle()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_18_inherited_dispute_remains_adverse(self):
        parent=copy.deepcopy(self.parent)
        parent['local_pinned_historical_directory_signature_and_proof_consistency']=False
        with patch.object(core.prior,'audit',return_value=parent):
            # Exact archive parent hash must be recomputed; a falsely amended
            # audit parent cannot be smuggled under the true bundle SHA.
            with self.assertRaises(errors.AnchorError):
                core.derive_inventory(**self.opts())

    def test_19_receiver_archive_exact_parent_sha_denied(self):
        raw=json.loads(Path(self.bundle['path']).read_text())
        raw['parent_ec371_canonical_result_sha256']='f'*64
        self.bundle=self.old.store('fake_parent_link',raw)
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_20_unsigned_derive_not_independent_pin(self):
        doc=self.derive()
        self.assertEqual(doc['exit_code'],2)
        self.assertFalse(doc['caller_external_inventory_pin_created_or_certified'])
        self.assertEqual(doc['receiver_verified_historical_authority_inventory_sha256'],
                         core.sha(canonical.canonical(
                             doc['unsigned_verified_historical_authority_inventory'])))

    def test_21_outside_signed_inventory_digest_mismatch_visible(self):
        self.assertTrue(self.audit(
            expected_retained_historical_authority_inventory_sha256='f'*64)[core.FLAGS[1]])

    def test_22_true_old_parent_signed_manifest_labels_not_opened(self):
        for epoch in self.old.rows:
            for slot in ('a','b'):
                signed=json.loads(Path(epoch[
                      'source_'+slot+'_manifest_original']['path']).read_text())
                for label in signed['copies'].values():
                    self.assertFalse(Path(label['path']).exists())
        self.assertFalse(self.audit()['sender_origin_path_required_or_read'])

    def test_26_real_signed_witness_rotation_requires_separate_handoff(self):
        # A new valid witness signature does not, by itself, authenticate an
        # old-to-new witness handoff; the cross-epoch change stays adverse.
        witness=ed25519.Ed25519PrivateKey.generate()
        keyref=self.old.store('rotated_historic_witness_key',util.pub(witness))
        origin=json.loads(Path(self.roles['b']['origin']['path']).read_text())
        del origin['signature_witness_ed25519_hex']
        origin['origin_witness_public_key_original_sha256']=keyref['sha256']
        new_origin=self.sign('rotated_witness_genuine_origin',origin,witness,
              authority.ORIGIN_DOMAIN,'signature_witness_ed25519_hex')
        self.authority_rows[1]['source_b'][
              'origin_witness_public_key_original']=keyref
        self.authority_rows[1]['source_b'][
              'witness_signed_origin_original']=new_origin
        self.make_bundle()
        r=self.audit()
        self.assertTrue(r[core.FLAGS[5]])
        self.assertFalse(r['local_pinned_historical_authority_slice_consistent'])

    def cli_argv(self,command,unified=False):
        opts=self.opts()
        digest=self.derive()['receiver_verified_historical_authority_inventory_sha256']
        opts['expected_retained_historical_authority_inventory_sha256']=digest
        from publication_accountability import accountability as p370
        from historical_archive import archive as p371
        scalars=(*p370.prior.SCALARS,*p370.NEW_SCALARS,*p371.NEW_SCALARS,
                 *p371.AUDIT_ONLY,*core.NEW_SCALARS)
        if command=='audit-historical-authority-archive':scalars+=core.AUDIT_ONLY
        repeats=(*p370.prior.REPEATS,*p370.NEW_REPEATS,*p371.NEW_REPEATS,
                 *core.NEW_REPEATS)
        entry=('ces_next.py' if unified else 'ces_cas_historical_authority_archive.py')
        command_args=[sys.executable,'-I','-B',str(ROOT/'scripts'/entry),command]
        if unified:command_args.extend(['DeliveryAudit','AuditHistoricalAuthorityArchive'])
        for s in scalars:command_args.extend(['--'+s.replace('_','-'),str(opts[s])])
        for key,flag in repeats:
            for val in opts[key]:command_args.extend([flag,'none' if val is None else str(val)])
        return command_args

    def test_23_real_isolated_unified_child_audit(self):
        cp=subprocess.run(self.cli_argv('audit-historical-authority-archive',True),
             capture_output=True,text=True,timeout=180)
        self.assertEqual(cp.returncode,2,cp.stderr+' '+cp.stdout[:600])
        response=json.loads(cp.stdout)
        self.assertEqual(response['schema'],core.RESULT_SCHEMA)
        self.assertTrue(response['local_pinned_historical_authority_slice_consistent'])

    def test_24_real_isolated_standalone_unsigned_derive(self):
        cp=subprocess.run(self.cli_argv('derive-historical-authority-inventory'),
             capture_output=True,text=True,timeout=180)
        self.assertEqual(cp.returncode,2,cp.stderr+' '+cp.stdout[:600])
        self.assertEqual(json.loads(cp.stdout)['schema'],core.DERIVE_SCHEMA)

    def test_25_real_isolated_unified_signed_original_denial(self):
        argv=self.cli_argv('audit-historical-authority-archive',True)
        p=Path(self.roles['a']['snapshot_1']['path'])
        p.write_bytes(b'TAMPER_SNAPSHOT')
        cp=subprocess.run(argv,
               capture_output=True,text=True,timeout=180)
        self.assertIn(cp.returncode,(3,4,5),cp.stderr)
        doc=json.loads(cp.stdout)
        self.assertEqual(doc['schema'],core.DENIAL_SCHEMA)
        self.assertFalse(doc['sender_origin_path_required_or_read'])


if __name__=='__main__':unittest.main()
