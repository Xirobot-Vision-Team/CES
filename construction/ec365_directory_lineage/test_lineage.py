#!/usr/bin/env python3
"""Focused EC365 real-Ed25519 directory authority signer transition cases.

All private keys are generated exclusively here in synthetic temporary
fixtures. The product code is a strictly read-only offline evidence auditor.
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
from ec353_transparency import test_transparency as util
from ec360_authority_directory import authority as ec360
from ec361_directory_consistency import consistency as ec361
from ec362_publication_custody import custody as ec362
from ec363_source_history import history as ec363
from ec364_cross_epoch import continuity as ec364
from ec364_cross_epoch import test_continuity as fixtures
from . import lineage as core


class DirectoryAuthorityLineageTests(fixtures.CrossEpochTests):
    for _name in dir(fixtures.CrossEpochTests):
        if _name.startswith('test_'):locals()[_name]=None

    def setup365(self):
        # Source signatures, original copies and parent EC361 checkpoint are
        # truly verified for a first 5-leaf directory epoch under OLD root.
        self.setup362()
        self.old_directory_signer=dict(self.directory_signer)
        for slot in core.parent.SLOTS:self.make_publication(slot,sequence=1)
        self.old_inputs=self.args362(
          minimum_source_a_publication_sequence=1,
          minimum_source_b_publication_sequence=1)
        self.old_sources={slot:dict(self.sources[slot]) for slot in core.parent.SLOTS}
        self.old_manifests=dict(self.publications)
        old=ec362.audit(**self.old_inputs)
        self.assertTrue(old['two_offline_signed_publication_copies_locally_coherent'])
        self.old_result_sha=core.sha(canonical.canonical(old))
        self.old_ec361_sha=self.ec361_sha
        self.old_head=self.evolved[0]

        # NEW directory authority signer. Rebuild a genuine EC360 *base*
        # checkpoint using a distinct Ed25519 signer and the same four original
        # RFC6962 leaves; then append two actual leaves under that new signer.
        # Thus even inside EC361 all current parent signatures remain valid.
        key=ed25519.Ed25519PrivateKey.generate()
        pub=self.write353('ec365-fresh-directory-root',util.pub(key))
        self.directory_signer={'private':key,'pub':pub}
        self.authority_inputs=self.args360()
        ec360_result=ec360.audit(**self.authority_inputs)
        self.assertTrue(ec360_result['two_sources_directory_inclusion_locally_verified'])
        self.parent_result_sha=core.sha(canonical.canonical(ec360_result))
        self.anchor=self.authority_inputs['expected_directory_checkpoint_sha256']
        self.anchor_doc=json.loads(Path(
            self.authority_inputs['directory_checkpoint_file']).read_bytes())
        self.leaves.append(b'EC365_REAL_SIXTH_DIRECTORY_LEAF_ACROSS_SIGNER_ROTATION')
        newest=self.add_evolved_checkpoint(leaves=self.leaves)
        self.evolved=[newest]
        for slot in core.parent.SLOTS:
            self.make_receipt(slot,newest,changes={
              'observed_utc':util.ut(self.now+timedelta(hours=7,minutes=1))})
        self.consistency_inputs=self.args361()
        r=ec361.audit(**self.consistency_inputs)
        self.assertTrue(r['locally_coherent_signed_directory_evolution_and_gossip'],r['status'])
        self.ec361_sha=core.sha(canonical.canonical(r))
        for slot in core.parent.SLOTS:
            old_src=self.old_sources[slot]
            private=ed25519.Ed25519PrivateKey.generate()
            newkey=self.write353('ec365-new-custodian-'+slot,util.pub(private))
            originals={'checkpoint':newest,'consistency_bundle':{
              'path':self.consistency_inputs['consistency_bundle_file'],
              'sha256':self.consistency_inputs['expected_consistency_bundle_sha256']},
              'observer_a_receipt':self.receipts['a'],
              'observer_b_receipt':self.receipts['b']}
            self.sources[slot]={'private':private,'public':newkey,'copies':{
              role:self.write353('ec365-new-original-copy-'+slot+'-'+role,
                          Path(ref['path']).read_bytes())
              for role,ref in originals.items()}}
            self.make_publication(slot,sequence=3,changes={
              'issued_utc':util.ut(self.now+timedelta(hours=7,minutes=20))})
        self.parent_inputs=self.args362()
        actual=ec362.audit(**self.parent_inputs)
        self.assertTrue(actual['two_offline_signed_publication_copies_locally_coherent'],actual['status'])
        self._parent_hash=core.sha(canonical.canonical(actual))
        self.history_now=util.ut(self.now+timedelta(hours=7,minutes=40))
        for slot in core.parent.SLOTS:
            latest=self.publications[slot]
            earlier=self.make_publication(slot,sequence=2)
            self.publications[slot]=latest
            challenger=ed25519.Ed25519PrivateKey.generate()
            challenger_pub=self.write353('ec365-challenger-'+slot,util.pub(challenger))
            self.challengers[slot]={'private':challenger,'public':challenger_pub}
            self.histories[slot]=[earlier]
            self.disclosure_requests[slot]=[]
            self.disclosure_responses[slot]=[]
            for n,role in enumerate(ec363.ROLES):
                req=self.make_challenge(slot,earlier,role,n)
                self.make_response(slot,req)
            self.rebundle(slot)
        ec363_result=ec363.audit(**self.args363())
        self.assertTrue(ec363_result['bounded_signed_history_and_disclosures_locally_coherent'])
        self.current_ec363_sha=core.sha(canonical.canonical(ec363_result))
        self.snapshot=self.write353('ec365-old-ec362-inputs',{
          'schema':ec364.SNAPSHOT_SCHEMA,'epoch_index':0,
          'ec362_audit_inputs':self.old_inputs})
        self.bridge_events=[]
        for slot in core.parent.SLOTS:self.make_bridge(slot)
        self.cross_proofs=[{'from_epoch_index':0,'to_epoch_index':1,
          'older_checkpoint_original_sha256':self.old_head['sha256'],
          'newer_checkpoint_original_sha256':newest['sha256'],
          'audit_path_sha256':[v.hex() for v in util.consistency(self.leaves,5)]}]
        self.rebundle364()
        parent_audit=ec364.audit(**self.args364())
        self.assertTrue(parent_audit['cross_window_consistency_proof_missing_or_invalid'])
        self.assertFalse(parent_audit['locally_coherent_cross_epoch_signed_publication'])
        for k in ec364.FLAG_MAP:
            if k[0]!='cross_window_consistency_proof_missing_or_invalid':
                self.assertFalse(parent_audit[k[0]],k[0])
        self.parent_ec364_sha=core.sha(canonical.canonical(parent_audit))
        self.root_refs=[self.old_directory_signer['pub'],self.directory_signer['pub']]
        self.checkpoint_refs=[self.old_head,newest]
        self.source_manifest_refs={slot:[self.old_manifests[slot],
             self.publications[slot]] for slot in core.parent.SLOTS}
        self.signed_directory_handoffs=[]
        self.make_handoff()
        self.rebundle365()

    def make_handoff(self,*,kind='delegate_and_retire',change=None,
                     old_signer=None,new_signer=None):
        body={'schema':core.EVENT_SCHEMA,
          'claimed_directory_lineage_id':self.anchor_doc['directory_id'],
          'from_epoch_index':0,'to_epoch_index':1,'event_kind':kind,
          'from_root_generation':0,'to_root_generation':1,
          'from_directory_public_key_original_sha256':self.root_refs[0]['sha256'],
          'to_directory_public_key_original_sha256':self.root_refs[1]['sha256'],
          'from_parent_ec361_canonical_result_sha256':self.old_ec361_sha,
          'to_parent_ec361_canonical_result_sha256':self.ec361_sha,
          'from_checkpoint_original_sha256':self.checkpoint_refs[0]['sha256'],
          'to_checkpoint_original_sha256':self.checkpoint_refs[1]['sha256'],
          'from_tree_size':5,'to_tree_size':6,
          'from_merkle_root_sha256':json.loads(Path(self.old_head['path']).read_bytes())['root_sha256'],
          'to_merkle_root_sha256':json.loads(Path(self.checkpoint_refs[1]['path']).read_bytes())['root_sha256'],
          'from_source_a_manifest_original_sha256':self.source_manifest_refs['a'][0]['sha256'],
          'from_source_b_manifest_original_sha256':self.source_manifest_refs['b'][0]['sha256'],
          'to_source_a_manifest_original_sha256':self.source_manifest_refs['a'][1]['sha256'],
          'to_source_b_manifest_original_sha256':self.source_manifest_refs['b'][1]['sha256'],
          'cross_epoch_consistency_proof_canonical_sha256':
              core.sha(canonical.canonical(self.cross_proofs[0])),
          'issued_utc':util.ut(self.now+timedelta(hours=7,minutes=10)),
          'expires_utc':util.ut(self.now+timedelta(days=1))}
        if change:body.update(change)
        data=core.EVENT_DOMAIN+canonical.canonical(body)
        doc={**body,
          'signature_old_directory_ed25519_hex':(
            old_signer or self.old_directory_signer['private']).sign(data).hex(),
          'signature_new_directory_ed25519_hex':(
            new_signer or self.directory_signer['private']).sign(data).hex()}
        ref=self.write353('ec365-true-directory-handoff-'+str(self.file_no),doc)
        self.signed_directory_handoffs.append(ref)
        return ref

    def args364_effective(self):
        return self.args364(**getattr(self,'triple_epoch_364_changes',{}))

    def rebundle365(self):
        result=ec364.audit(**self.args364_effective())
        self.parent_ec364_sha=core.sha(canonical.canonical(result))
        self.directory_authority_bundle=self.write353('ec365-authority-bundle-'+str(self.file_no),{
          'schema':core.BUNDLE_SCHEMA,
          'parent_ec364_canonical_result_sha256':self.parent_ec364_sha,
          'claimed_directory_lineage_id':self.anchor_doc['directory_id'],
          'signed_directory_handoffs':self.signed_directory_handoffs})

    def args365(self,**change):
        current={**self.args364_effective(),
          'directory_lineage_evaluation_utc':util.ut(self.now+timedelta(hours=7,minutes=50)),
          'directory_authority_bundle_file':self.directory_authority_bundle['path'],
          'expected_directory_authority_bundle_sha256':self.directory_authority_bundle['sha256'],
          'minimum_retained_directory_root_generation':1,
          'expected_retained_initial_directory_root_sha256':self.root_refs[0]['sha256'],
          'expected_retained_current_directory_root_sha256':self.root_refs[-1]['sha256'],
          'minimum_retained_latest_directory_tree_size':6,
          'epoch_directory_root_shas':[x['sha256'] for x in self.root_refs],
          'epoch_source_a_manifest_shas':[x['sha256'] for x in self.source_manifest_refs['a']],
          'epoch_source_b_manifest_shas':[x['sha256'] for x in self.source_manifest_refs['b']],
          'epoch_signed_checkpoint_shas':[x['sha256'] for x in self.checkpoint_refs],
          'signed_directory_handoff_shas':[x['sha256'] for x in self.signed_directory_handoffs]}
        return {**current,**change}

    def _bridge_three(self,edge,old_sources,new_sources,old_docs,new_docs,
                      old_sha,new_sha):
        for slot in core.parent.SLOTS:
            a=json.loads(Path(old_docs[slot]['path']).read_bytes())
            b=json.loads(Path(new_docs[slot]['path']).read_bytes())
            body={'schema':ec364.TRANSITION_SCHEMA,'source_slot':slot,
              'claimed_source_id':a['claimed_source_id'],
              'from_epoch_index':edge,'to_epoch_index':edge+1,
              'event_kind':'rotate',
              'from_parent_ec361_canonical_result_sha256':old_sha,
              'to_parent_ec361_canonical_result_sha256':new_sha,
              'from_manifest_original_sha256':old_docs[slot]['sha256'],
              'to_manifest_original_sha256':new_docs[slot]['sha256'],
              'from_custodian_public_key_original_sha256':old_sources[slot]['public']['sha256'],
              'to_custodian_public_key_original_sha256':new_sources[slot]['public']['sha256'],
              'from_checkpoint_original_sha256':a['copies']['checkpoint']['sha256'],
              'to_checkpoint_original_sha256':b['copies']['checkpoint']['sha256'],
              'issued_utc':util.ut(self.now+timedelta(hours=7,minutes=20)),
              'expires_utc':util.ut(self.now+timedelta(days=1))}
            raw=ec364.TRANSITION_DOMAIN+canonical.canonical(body)
            body['signature_old_custodian_ed25519_hex']=old_sources[slot]['private'].sign(raw).hex()
            body['signature_new_custodian_ed25519_hex']=new_sources[slot]['private'].sign(raw).hex()
            self.bridge_events.append(self.write353('ec365-three-source-'+str(edge)+'-'+slot,body))

    def _handoff_three(self,edge):
        a,b=self.root_signer_sequence[edge:edge+2]
        c,d=self.checkpoint_refs[edge:edge+2]
        cp_a=json.loads(Path(c['path']).read_bytes())
        cp_b=json.loads(Path(d['path']).read_bytes())
        body={'schema':core.EVENT_SCHEMA,
          'claimed_directory_lineage_id':self.anchor_doc['directory_id'],
          'from_epoch_index':edge,'to_epoch_index':edge+1,
          'event_kind':'delegate_and_retire',
          'from_root_generation':edge,'to_root_generation':edge+1,
          'from_directory_public_key_original_sha256':a['pub']['sha256'],
          'to_directory_public_key_original_sha256':b['pub']['sha256'],
          'from_parent_ec361_canonical_result_sha256':self.parent_ec361_shas[edge],
          'to_parent_ec361_canonical_result_sha256':self.parent_ec361_shas[edge+1],
          'from_checkpoint_original_sha256':c['sha256'],
          'to_checkpoint_original_sha256':d['sha256'],
          'from_tree_size':cp_a['tree_size'],'to_tree_size':cp_b['tree_size'],
          'from_merkle_root_sha256':cp_a['root_sha256'],
          'to_merkle_root_sha256':cp_b['root_sha256'],
          'from_source_a_manifest_original_sha256':self.source_manifest_refs['a'][edge]['sha256'],
          'from_source_b_manifest_original_sha256':self.source_manifest_refs['b'][edge]['sha256'],
          'to_source_a_manifest_original_sha256':self.source_manifest_refs['a'][edge+1]['sha256'],
          'to_source_b_manifest_original_sha256':self.source_manifest_refs['b'][edge+1]['sha256'],
          'cross_epoch_consistency_proof_canonical_sha256':
             core.sha(canonical.canonical(self.cross_proofs[edge])),
          'issued_utc':util.ut(self.now+timedelta(hours=7,minutes=10)),
          'expires_utc':util.ut(self.now+timedelta(days=1))}
        raw=core.EVENT_DOMAIN+canonical.canonical(body)
        body['signature_old_directory_ed25519_hex']=a['private'].sign(raw).hex()
        body['signature_new_directory_ed25519_hex']=b['private'].sign(raw).hex()
        self.signed_directory_handoffs.append(self.write353(
          'ec365-three-authority-'+str(edge),body))

    def setup_three_distinct_roots(self,*,reuse_retired_old_root=False):
        self.setup365()
        middle_root=dict(self.directory_signer)
        middle_ec361_sha=self.ec361_sha
        middle_sources={slot:dict(self.sources[slot]) for slot in core.parent.SLOTS}
        middle_manifests={slot:self.histories[slot][0] for slot in core.parent.SLOTS}
        middle_inputs=dict(self.parent_inputs)
        for slot in core.parent.SLOTS:
            middle_inputs['source_'+slot+'_publication_manifest_file']=middle_manifests[slot]['path']
            middle_inputs['expected_source_'+slot+'_publication_manifest_sha256']=middle_manifests[slot]['sha256']
            middle_inputs['minimum_source_'+slot+'_publication_sequence']=2
        self.assertTrue(ec362.audit(**middle_inputs)[
          'two_offline_signed_publication_copies_locally_coherent'])
        middle_cp=self.checkpoint_refs[1]

        newest_root_priv=(self.old_directory_signer['private'] if
            reuse_retired_old_root else ed25519.Ed25519PrivateKey.generate())
        newest_root_pub=(self.old_directory_signer['pub'] if
            reuse_retired_old_root else self.write353(
                'ec365-third-directory-key',util.pub(newest_root_priv)))
        self.directory_signer={'private':newest_root_priv,'pub':newest_root_pub}
        self.authority_inputs=self.args360()
        ec360_actual=ec360.audit(**self.authority_inputs)
        self.assertTrue(ec360_actual['two_sources_directory_inclusion_locally_verified'])
        self.parent_result_sha=core.sha(canonical.canonical(ec360_actual))
        self.anchor=self.authority_inputs['expected_directory_checkpoint_sha256']
        self.anchor_doc=json.loads(Path(self.authority_inputs['directory_checkpoint_file']).read_bytes())
        self.leaves.append(b'EC365_REAL_SEVENTH_RFC6962_DIRECTORY_LEAF')
        newest=self.add_evolved_checkpoint(leaves=self.leaves)
        self.evolved=[newest]
        for slot in core.parent.SLOTS:
            self.make_receipt(slot,newest,changes={
               'observed_utc':util.ut(self.now+timedelta(hours=7,minutes=1))})
        self.consistency_inputs=self.args361()
        ec361_actual=ec361.audit(**self.consistency_inputs)
        self.assertTrue(ec361_actual['locally_coherent_signed_directory_evolution_and_gossip'])
        self.ec361_sha=core.sha(canonical.canonical(ec361_actual))
        self.sources={};self.publications={}
        for slot in core.parent.SLOTS:
            key=ed25519.Ed25519PrivateKey.generate()
            pub=self.write353('ec365-third-custodian-'+slot,util.pub(key))
            originals={'checkpoint':newest,'consistency_bundle':{
              'path':self.consistency_inputs['consistency_bundle_file'],
              'sha256':self.consistency_inputs['expected_consistency_bundle_sha256']},
              'observer_a_receipt':self.receipts['a'],
              'observer_b_receipt':self.receipts['b']}
            self.sources[slot]={'private':key,'public':pub,'copies':{
              role:self.write353('ec365-third-copy-'+slot+'-'+role,
                                 Path(ref['path']).read_bytes())
              for role,ref in originals.items()}}
            self.make_publication(slot,sequence=4)
        self.parent_inputs=self.args362()
        self._parent_hash=core.sha(canonical.canonical(ec362.audit(**self.parent_inputs)))
        for slot in core.parent.SLOTS:
            newest_manifest=self.publications[slot]
            history_manifest=self.make_publication(slot,sequence=3)
            self.publications[slot]=newest_manifest
            challenger=ed25519.Ed25519PrivateKey.generate()
            pub=self.write353('ec365-third-challenger-'+slot,util.pub(challenger))
            self.challengers[slot]={'private':challenger,'public':pub}
            self.histories[slot]=[history_manifest]
            self.disclosure_requests[slot]=[];self.disclosure_responses[slot]=[]
            for n,role in enumerate(ec363.ROLES):
                req=self.make_challenge(slot,history_manifest,role,n)
                self.make_response(slot,req)
            self.rebundle(slot)
        latest=ec363.audit(**self.args363())
        self.assertTrue(latest['bounded_signed_history_and_disclosures_locally_coherent'])
        self.current_ec363_sha=core.sha(canonical.canonical(latest))
        second_snapshot=self.write353('ec365-second-historical-ec362-inputs',{
          'schema':ec364.SNAPSHOT_SCHEMA,'epoch_index':1,
          'ec362_audit_inputs':middle_inputs})
        self.bridge_events=[]
        self._bridge_three(0,self.old_sources,middle_sources,
          self.old_manifests,middle_manifests,self.old_ec361_sha,middle_ec361_sha)
        self._bridge_three(1,middle_sources,self.sources,
          middle_manifests,self.publications,middle_ec361_sha,self.ec361_sha)
        self.cross_proofs=[self.cross_proofs[0],{
          'from_epoch_index':1,'to_epoch_index':2,
          'older_checkpoint_original_sha256':middle_cp['sha256'],
          'newer_checkpoint_original_sha256':newest['sha256'],
          'audit_path_sha256':[x.hex() for x in util.consistency(self.leaves,6)]}]
        self.snapshot_shas_three=[self.snapshot['sha256'],second_snapshot['sha256']]
        parent_bundle=self.write353('ec365-three-ec364-history',{
          'schema':ec364.BUNDLE_SCHEMA,
          'current_ec363_canonical_result_sha256':self.current_ec363_sha,
          'historical_parent_snapshots':[self.snapshot,second_snapshot],
          'signed_source_transitions':self.bridge_events,
          'directory_window_proofs':self.cross_proofs})
        self.triple_epoch_364_changes={
          'cross_epoch_bundle_file':parent_bundle['path'],
          'expected_cross_epoch_bundle_sha256':parent_bundle['sha256'],
          'minimum_retained_historical_epoch_count':2,
          'expected_retained_current_ec362_result_sha256':self._parent_hash,
          'minimum_retained_directory_tree_size':7,
          'historical_ec362_snapshot_shas':self.snapshot_shas_three,
          'signed_source_epoch_transition_shas':[v['sha256'] for v in self.bridge_events]}
        self.root_signer_sequence=[self.old_directory_signer,middle_root,
                                   dict(self.directory_signer)]
        self.root_refs=[d['pub'] for d in self.root_signer_sequence]
        self.checkpoint_refs=[self.old_head,middle_cp,newest]
        self.parent_ec361_shas=[self.old_ec361_sha,middle_ec361_sha,self.ec361_sha]
        self.source_manifest_refs={slot:[self.old_manifests[slot],
             middle_manifests[slot],self.publications[slot]]
             for slot in core.parent.SLOTS}
        self.signed_directory_handoffs=[]
        self._handoff_three(0)
        self._handoff_three(1)
        self.rebundle365()

    def test_01_true_cross_directory_root_dual_signatures_and_append_proof(self):
        self.setup365()
        result=core.audit(**self.args365())
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['actual_ec364_through_ec337_signed_originals_replayed'])
        self.assertFalse(result['parent_ec364_locally_coherent'])
        self.assertTrue(result['locally_authorized_directory_signer_transition'],result['status'])
        self.assertEqual(result['actual_cross_root_rfc6962_proofs_verified'],1)
        self.assertEqual(result['true_signed_directory_handoff_originals_verified'],1)
        self.assertFalse(result['caller_pinned_directory_roots_are_official_public_trust_anchors'])

    def test_02_new_directory_key_cannot_self_authorize_the_old_root(self):
        self.setup365()
        self.signed_directory_handoffs=[]
        self.make_handoff(old_signer=self.directory_signer['private'])
        self.rebundle365()
        with self.assertRaises(errors.AnchorError) as e:
            core.audit(**self.args365())
        self.assertEqual(e.exception.status,'permission_denied')
        self.assertIn('OLD_DIRECTORY_TRUE_SIGNATURE_INVALID',e.exception.code)

    def test_03_missing_authentic_handoff_never_approved_by_parent_replay(self):
        self.setup365()
        self.signed_directory_handoffs=[]
        self.rebundle365()
        result=core.audit(**self.args365())
        self.assertTrue(result['directory_handoff_missing_or_unpinned'])
        self.assertFalse(result['locally_authorized_directory_signer_transition'])

    def test_04_independently_retained_old_root_sha_cannot_be_replaced(self):
        self.setup365()
        result=core.audit(**self.args365(epoch_directory_root_shas=['a9'*32,
            self.root_refs[1]['sha256']]))
        self.assertTrue(result['separately_retained_epoch_or_root_rollback'])
        self.assertFalse(result['locally_authorized_directory_signer_transition'])

    def test_05_authentic_contradictory_second_signed_retirement_is_visible(self):
        self.setup365()
        self.make_handoff(kind='terminal_retirement')
        self.rebundle365()
        result=core.audit(**self.args365())
        self.assertTrue(result['genuine_double_signed_directory_handoff_fork'])
        self.assertTrue(result['signed_directory_terminal_retirement_visible'])
        self.assertFalse(result['locally_authorized_directory_signer_transition'])

    def test_06_invalid_true_rfc6962_append_evidence_cannot_be_signed_into_truth(self):
        self.setup365()
        self.cross_proofs[0]['audit_path_sha256'][0]='aa'*32
        self.rebundle364()
        self.signed_directory_handoffs=[]
        self.make_handoff()
        self.rebundle365()
        result=core.audit(**self.args365())
        self.assertTrue(result['cross_root_rfc6962_proof_missing_or_invalid'])
        self.assertFalse(result['locally_authorized_directory_signer_transition'])

    def test_07_terminal_retirement_blocks_successor_even_if_both_signed(self):
        self.setup365()
        self.signed_directory_handoffs=[]
        self.make_handoff(kind='terminal_retirement')
        self.rebundle365()
        result=core.audit(**self.args365())
        self.assertTrue(result['signed_directory_terminal_retirement_visible'])
        self.assertFalse(result['locally_authorized_directory_signer_transition'])

    def test_08_authority_replacement_must_bind_actual_signed_source_manifests(self):
        self.setup365()
        self.signed_directory_handoffs=[]
        self.make_handoff(change={'to_source_b_manifest_original_sha256':'fa'*32})
        self.rebundle365()
        with self.assertRaises(errors.AnchorError) as e:core.audit(**self.args365())
        self.assertEqual(e.exception.status,'permission_denied')

    def test_09_true_signed_handoff_with_false_generation_not_locally_coherent(self):
        self.setup365()
        self.signed_directory_handoffs=[]
        self.make_handoff(change={'to_root_generation':2})
        self.rebundle365()
        r=core.audit(**self.args365())
        self.assertTrue(r['directory_key_lineage_or_role_collision'])
        self.assertFalse(r['locally_authorized_directory_signer_transition'])

    def test_10_caller_root_generation_floor_not_silently_regressed(self):
        self.setup365()
        r=core.audit(**self.args365(minimum_retained_directory_root_generation=2))
        self.assertTrue(r['separately_retained_epoch_or_root_rollback'])
        self.assertFalse(r['locally_authorized_directory_signer_transition'])

    def test_11_claimed_directory_handoff_utc_is_not_a_trusted_clock(self):
        self.setup365()
        self.signed_directory_handoffs=[]
        self.make_handoff(change={
          'issued_utc':util.ut(self.now+timedelta(days=1,hours=7)),
          'expires_utc':util.ut(self.now+timedelta(days=2))})
        self.rebundle365()
        r=core.audit(**self.args365())
        self.assertTrue(r['directory_claimed_utc_timeline_anomaly'])
        self.assertFalse(r['locally_authorized_directory_signer_transition'])

    def test_12_true_fixed_isolated_unified_deliveryaudit_route(self):
        self.setup365()
        args=self.args365()
        root=Path(__file__).resolve().parents[2]
        sys.path.insert(0,str(root/'scripts'))
        import ces_next as router
        argv=[sys.executable,'-I','-B',str(root/'scripts'/'ces_next.py'),
              'audit-directory-authority','DeliveryAudit','AuditDirectoryAuthority']
        for key in router.EC365_REQUIRED:
            argv.extend(['--'+key.replace('_','-'),str(args[key])])
        for key in router.EC365_OPTIONAL:
            if args[key] is not None:
                argv.extend(['--'+key.replace('_','-'),str(args[key])])
        for key,flag in router.EC365_REPEATS:
            for value in args[key]:argv.extend([flag,value])
        p=subprocess.run(argv,text=True,capture_output=True,timeout=1800)
        self.assertEqual(p.returncode,2,p.stdout[-1500:]+p.stderr[-1500:])
        result=json.loads(p.stdout)
        self.assertTrue(result['locally_authorized_directory_signer_transition'])

    def test_13_derivation_replays_genuine_ec364_and_remains_unsigned(self):
        self.setup365()
        out=core.checklist(**self.args364())
        self.assertEqual(out['exit_code'],2)
        self.assertTrue(out['actual_ec364_through_ec337_signed_originals_replayed'])
        self.assertFalse(out['caller_pinned_directory_roots_are_official_public_trust_anchors'])

    def test_14_unauthorized_wrong_directory_key_claim_cannot_repair_true_parent(self):
        self.setup365()
        self.signed_directory_handoffs=[]
        self.make_handoff(change={'to_directory_public_key_original_sha256':'cb'*32})
        self.rebundle365()
        with self.assertRaises(errors.AnchorError) as e:core.audit(**self.args365())
        self.assertEqual(e.exception.status,'permission_denied')

    def test_15_signed_source_bridge_termination_remains_ec364_blocker(self):
        self.setup365()
        self.bridge_events=[]
        self.make_bridge('a',kind='terminate')
        self.make_bridge('b')
        self.rebundle364()
        self.rebundle365()
        r=core.audit(**self.args365())
        self.assertTrue(r['parent_ec364_non_directory_defect_visible'])
        self.assertFalse(r['locally_authorized_directory_signer_transition'])

    def test_16_changed_external_epoch_source_sha_is_detected_even_when_signed(self):
        self.setup365()
        r=core.audit(**self.args365(epoch_source_b_manifest_shas=[
            self.source_manifest_refs['b'][0]['sha256'],'e3'*32]))
        self.assertTrue(r['separately_retained_epoch_or_root_rollback'])

    def test_17_three_genuine_signed_directory_epochs_two_cascading_rotations(self):
        self.setup_three_distinct_roots()
        r=core.audit(**self.args365(minimum_retained_directory_root_generation=2,
            minimum_retained_latest_directory_tree_size=7))
        self.assertTrue(r['locally_authorized_directory_signer_transition'],r['status'])
        self.assertEqual(r['true_directory_root_generation'],2)
        self.assertEqual(r['actual_cross_root_rfc6962_proofs_verified'],2)
        self.assertEqual(r['true_signed_directory_handoff_originals_verified'],2)
        self.assertEqual(len(r['epoch_lineage_reviews']),3)

    def test_18_cryptographically_signed_retired_root_reappearance_blocked(self):
        self.setup_three_distinct_roots(reuse_retired_old_root=True)
        r=core.audit(**self.args365())
        self.assertTrue(r['directory_key_lineage_or_role_collision'])
        self.assertFalse(r['locally_authorized_directory_signer_transition'])

    def test_19_bundle_cannot_substitute_for_external_signed_handoff_sha(self):
        self.setup365()
        r=core.audit(**self.args365(signed_directory_handoff_shas=['a1'*32]))
        self.assertTrue(r['separately_retained_epoch_or_root_rollback'])
        self.assertFalse(r['locally_authorized_directory_signer_transition'])

    def test_20_source_custodian_signature_cannot_authorize_directory_rotation(self):
        self.setup365()
        self.signed_directory_handoffs=[]
        self.make_handoff(old_signer=self.old_sources['a']['private'])
        self.rebundle365()
        with self.assertRaises(errors.AnchorError) as e:
            core.audit(**self.args365())
        self.assertEqual(e.exception.status,'permission_denied')

    def test_21_newest_signed_tree_size_external_floor_not_overridden(self):
        self.setup365()
        r=core.audit(**self.args365(minimum_retained_latest_directory_tree_size=7))
        self.assertTrue(r['separately_retained_epoch_or_root_rollback'])
        self.assertFalse(r['locally_authorized_directory_signer_transition'])

    def test_22_original_same_directory_signer_cannot_masquerade_as_rotation(self):
        self.setup364()
        self.old_directory_signer=dict(self.directory_signer)
        self.root_refs=[self.directory_signer['pub'],self.directory_signer['pub']]
        self.checkpoint_refs=[self.old_head,self.evolved[0]]
        self.source_manifest_refs={slot:[self.old_manifests[slot],
              self.publications[slot]] for slot in core.parent.SLOTS}
        self.signed_directory_handoffs=[]
        self.make_handoff(kind='carry',change={'to_root_generation':0})
        self.rebundle365()
        r=core.audit(**self.args365())
        self.assertTrue(r['no_actual_directory_root_change_demonstrated'])
        self.assertFalse(r['locally_authorized_directory_signer_transition'])
        self.assertTrue(r['parent_ec364_locally_coherent'])

    def test_23_real_isolated_standalone_audit_command(self):
        self.setup365()
        args=self.args365()
        root=Path(__file__).resolve().parents[2]
        sys.path.insert(0,str(root/'scripts'))
        import ces_next as router
        cmd=[sys.executable,'-I','-B',str(root/'scripts'/'ces_cas_directory_authority.py'),
             'audit-directory-authority']
        for key in router.EC365_REQUIRED:
            cmd.extend(['--'+key.replace('_','-'),str(args[key])])
        for key in router.EC365_OPTIONAL:
            if args[key] is not None:
                cmd.extend(['--'+key.replace('_','-'),str(args[key])])
        for key,flag in router.EC365_REPEATS:
            for v in args[key]:cmd.extend([flag,v])
        result=subprocess.run(cmd,text=True,capture_output=True,timeout=1800)
        self.assertEqual(result.returncode,2,result.stdout[-1000:]+result.stderr[-1000:])
        self.assertTrue(json.loads(result.stdout)[
           'locally_authorized_directory_signer_transition'])

if __name__=='__main__':
    import unittest
    unittest.main()
