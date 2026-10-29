#!/usr/bin/env python3
"""EC364 synthetic Ed25519: true old EC362 and current EC363 replay tests.

Fixtures generate ephemeral local keys only. No product signer or remote writer.
"""
from __future__ import annotations

from datetime import timedelta
import json
from pathlib import Path
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from transparency import test_transparency as util
from directory_consistency import consistency as ec361
from publication_custody import custody as ec362
from source_history import history as ec363
from source_history import test_history as fixtures
from . import continuity as core


class CrossEpochTests(fixtures.HistoryTests):
    for _name in dir(fixtures.HistoryTests):
        if _name.startswith('test_'):locals()[_name]=None

    def setUp(self):
        super().setUp()
        self.old_sources={};self.bridge_events=[];self.cross_proofs=[]

    def setup364(self):
        # Historical EC361 window actually has a genuinely signed five-leaf
        # head, two observer receipts and two source manifests (sequence 1).
        self.setup362()
        for slot in core.SLOTS:self.make_publication(slot,sequence=1)
        self.old_inputs=self.args362(
            minimum_source_a_publication_sequence=1,
            minimum_source_b_publication_sequence=1)
        self.old_sources={slot:dict(self.sources[slot]) for slot in core.SLOTS}
        self.old_manifests=dict(self.publications)
        old_result=ec362.audit(**self.old_inputs)
        self.assertTrue(old_result['two_offline_signed_publication_copies_locally_coherent'])
        self.old_result_sha=core.sha(canonical.canonical(old_result))
        self.old_ec361_sha=self.ec361_sha
        self.old_head=self.evolved[0]

        # A DIFFERENT, newer true directory-signed EC361 head: six RFC6962
        # leaves and two new observer-signed receipts, with full 4->6 proof.
        self.leaves.append(b'EC364_REAL_SIXTH_SYNTHETIC_DIRECTORY_LEAF')
        newest=self.add_evolved_checkpoint(leaves=self.leaves)
        self.evolved=[newest]
        for slot in core.SLOTS:
            self.make_receipt(slot,newest,changes={
              'observed_utc':util.ut(self.now+timedelta(hours=7,minutes=1))})
        self.consistency_inputs=self.args361()
        current_ec361=ec361.audit(**self.consistency_inputs)
        self.assertTrue(current_ec361['locally_coherent_signed_directory_evolution_and_gossip'])
        self.ec361_sha=core.sha(canonical.canonical(current_ec361))
        self.assertNotEqual(self.old_ec361_sha,self.ec361_sha)
        self.sources={};self.publications={}
        copies={'checkpoint':newest,
            'consistency_bundle':{'path':self.consistency_inputs['consistency_bundle_file'],
               'sha256':self.consistency_inputs['expected_consistency_bundle_sha256']},
            'observer_a_receipt':self.receipts['a'],
            'observer_b_receipt':self.receipts['b']}
        for slot in core.SLOTS:
            key=ed25519.Ed25519PrivateKey.generate()
            pub=self.write353('ec364-current-custodian-'+slot,util.pub(key))
            self.sources[slot]={'private':key,'public':pub,'copies':{
                role:self.write353('ec364-current-'+slot+'-'+role,
                       Path(ref['path']).read_bytes()) for role,ref in copies.items()}}
            self.make_publication(slot,sequence=3,changes={
                'issued_utc':util.ut(self.now+timedelta(hours=7,minutes=20))})
        self.parent_inputs=self.args362()
        self._parent_hash=core.sha(canonical.canonical(ec362.audit(**self.parent_inputs)))
        self.history_now=util.ut(self.now+timedelta(hours=7,minutes=40))
        for slot in core.SLOTS:
            current=self.publications[slot]
            history_manifest=self.make_publication(slot,sequence=2)
            self.publications[slot]=current
            challenger=ed25519.Ed25519PrivateKey.generate()
            pub=self.write353('ec364-challenger-'+slot,util.pub(challenger))
            self.challengers[slot]={'private':challenger,'public':pub}
            self.histories[slot]=[history_manifest]
            self.disclosure_requests[slot]=[];self.disclosure_responses[slot]=[]
            for n,role in enumerate(core.history.ROLES):
                req=self.make_challenge(slot,history_manifest,role,n)
                self.make_response(slot,req)
            self.rebundle(slot)
        cur=ec363.audit(**self.args363())
        self.assertTrue(cur['bounded_signed_history_and_disclosures_locally_coherent'])
        self.current_ec363_sha=core.sha(canonical.canonical(cur))
        self.snapshot=self.write353('ec364-historic-snapshot',{
            'schema':core.SNAPSHOT_SCHEMA,'epoch_index':0,
            'ec362_audit_inputs':self.old_inputs})
        self.bridge_events=[]
        for slot in core.SLOTS:self.make_bridge(slot)
        self.cross_proofs=[{'from_epoch_index':0,'to_epoch_index':1,
             'older_checkpoint_original_sha256':self.old_head['sha256'],
             'newer_checkpoint_original_sha256':newest['sha256'],
             'audit_path_sha256':[v.hex() for v in util.consistency(self.leaves,5)]}]
        self.rebundle364()

    def make_bridge(self,slot,*,kind='rotate',override=None,old_signer=None,new_signer=None):
        earlier=json.loads(Path(self.old_manifests[slot]['path']).read_bytes())
        later=json.loads(Path(self.publications[slot]['path']).read_bytes())
        body={'schema':core.TRANSITION_SCHEMA,'source_slot':slot,
          'claimed_source_id':earlier['claimed_source_id'],
          'from_epoch_index':0,'to_epoch_index':1,'event_kind':kind,
          'from_parent_ec361_canonical_result_sha256':self.old_ec361_sha,
          'to_parent_ec361_canonical_result_sha256':self.ec361_sha,
          'from_manifest_original_sha256':self.old_manifests[slot]['sha256'],
          'to_manifest_original_sha256':self.publications[slot]['sha256'],
          'from_custodian_public_key_original_sha256':
              self.old_sources[slot]['public']['sha256'],
          'to_custodian_public_key_original_sha256':
              self.sources[slot]['public']['sha256'],
          'from_checkpoint_original_sha256':earlier['copies']['checkpoint']['sha256'],
          'to_checkpoint_original_sha256':later['copies']['checkpoint']['sha256'],
          'issued_utc':util.ut(self.now+timedelta(hours=7,minutes=20)),
          'expires_utc':util.ut(self.now+timedelta(days=1))}
        if override:body.update(override)
        message=core.TRANSITION_DOMAIN+canonical.canonical(body)
        body['signature_old_custodian_ed25519_hex']=(old_signer or
            self.old_sources[slot]['private']).sign(message).hex()
        body['signature_new_custodian_ed25519_hex']=(new_signer or
            self.sources[slot]['private']).sign(message).hex()
        ref=self.write353('ec364-signed-transition-'+slot+'-'+str(self.file_no),body)
        self.bridge_events.append(ref)
        return ref

    def rebundle364(self):
        self.bundle=self.write353('ec364-all-window-bundle-'+str(self.file_no),{
            'schema':core.BUNDLE_SCHEMA,
            'current_ec363_canonical_result_sha256':self.current_ec363_sha,
            'historical_parent_snapshots':[self.snapshot],
            'signed_source_transitions':self.bridge_events,
            'directory_window_proofs':self.cross_proofs})

    def args364(self,**changes):
        args={**self.args363(),
          'cross_epoch_evaluation_utc':util.ut(self.now+timedelta(hours=7,minutes=45)),
          'cross_epoch_bundle_file':self.bundle['path'],
          'expected_cross_epoch_bundle_sha256':self.bundle['sha256'],
          'minimum_retained_historical_epoch_count':1,
          'expected_retained_oldest_ec362_result_sha256':self.old_result_sha,
          'expected_retained_current_ec362_result_sha256':self._parent_hash,
          'minimum_retained_directory_tree_size':6,
          'historical_ec362_snapshot_shas':[self.snapshot['sha256']],
          'signed_source_epoch_transition_shas':[x['sha256'] for x in self.bridge_events]}
        return {**args,**changes}

    def test_01_true_two_window_replay_real_append_only_and_dual_rotation(self):
        self.setup364()
        res=core.audit(**self.args364())
        self.assertEqual(res['exit_code'],2)
        self.assertTrue(res['actual_ec363_through_ec337_signed_originals_replayed'])
        self.assertTrue(res['locally_coherent_cross_epoch_signed_publication'],res['status'])
        self.assertEqual(res['true_historical_parent_replays'],1)
        self.assertEqual(res['true_signed_transition_originals_verified'],2)
        self.assertEqual(res['adjacent_directory_consistency_proofs_verified'],1)
        self.assertFalse(res['dual_signatures_establish_real_legal_or_physical_independence'])

    def test_02_missing_actual_historical_epoch_is_not_inferred_from_ec363(self):
        self.setup364();self.bundle=self.write353('ec364-empty-bundle',{
          'schema':core.BUNDLE_SCHEMA,
          'current_ec363_canonical_result_sha256':self.current_ec363_sha,
          'historical_parent_snapshots':[],
          'signed_source_transitions':[],
          'directory_window_proofs':[]})
        res=core.audit(**self.args364(historical_ec362_snapshot_shas=[],
                                      signed_source_epoch_transition_shas=[]))
        self.assertTrue(res['caller_pinned_epoch_or_transition_material_missing'])
        self.assertFalse(res['locally_coherent_cross_epoch_signed_publication'])

    def test_03_caller_retained_historical_result_rollback(self):
        self.setup364()
        res=core.audit(**self.args364(
            expected_retained_oldest_ec362_result_sha256='ab'*32))
        self.assertTrue(res['caller_retained_epoch_or_tree_regression'])

    def test_04_invalid_real_old_custodian_signature_is_denied(self):
        self.setup364()
        self.bridge_events.pop(0)
        self.make_bridge('a',old_signer=self.sources['a']['private'])
        self.rebundle364()
        with self.assertRaises(errors.AnchorError) as e:
            core.audit(**self.args364())
        self.assertEqual(e.exception.status,'permission_denied')

    def test_05_signed_source_termination_blocks_future_epoch(self):
        self.setup364()
        self.bridge_events.pop(0);self.make_bridge('a',kind='terminate')
        self.rebundle364()
        result=core.audit(**self.args364())
        self.assertTrue(result['signed_terminal_source_event_visible'])
        self.assertFalse(result['locally_coherent_cross_epoch_signed_publication'])

    def test_06_two_valid_signed_conflicting_transitions_no_winner(self):
        self.setup364()
        self.make_bridge('a',kind='terminate')
        self.rebundle364()
        result=core.audit(**self.args364())
        self.assertTrue(result['dual_signed_transition_or_epoch_fork'])
        self.assertFalse(result['locally_coherent_cross_epoch_signed_publication'])

    def test_07_wrong_consistency_proof_blocks_append_claim(self):
        self.setup364()
        self.cross_proofs[0]['audit_path_sha256'][0]='ef'*32
        self.rebundle364()
        result=core.audit(**self.args364())
        self.assertTrue(result['cross_window_consistency_proof_missing_or_invalid'])

    def test_08_true_old_history_snapshot_must_replay_and_verify_signature(self):
        self.setup364()
        bad=dict(self.old_inputs)
        bad['expected_source_a_publication_manifest_sha256']='ab'*32
        self.snapshot=self.write353('ec364-bad-true-parent-snapshot',{
            'schema':core.SNAPSHOT_SCHEMA,'epoch_index':0,
            'ec362_audit_inputs':bad})
        self.rebundle364()
        with self.assertRaises(errors.AnchorError) as e:
            core.audit(**self.args364())
        self.assertIn(e.exception.status,('permission_denied','invalid_input'))

    def test_09_independent_per_original_pin_does_not_take_bundle_word(self):
        self.setup364()
        result=core.audit(**self.args364(historical_ec362_snapshot_shas=['cd'*32]))
        self.assertTrue(result['caller_retained_epoch_or_tree_regression'])

    def test_10_true_isolated_fixed_unified_child_exit2(self):
        self.setup364()
        inputs=self.args364()
        root=Path(__file__).resolve().parents[2]
        sys.path.insert(0,str(root/'scripts'))
        import ces_next as router
        argv=[sys.executable,'-I','-B',str(root/'scripts'/'ces_next.py'),
              'audit-cross-epoch','DeliveryAudit','AuditCrossEpoch']
        for key in router.EC364_REQUIRED:
            argv.extend(['--'+key.replace('_','-'),str(inputs[key])])
        for key in router.EC364_OPTIONAL:
            if inputs[key] is not None:
                argv.extend(['--'+key.replace('_','-'),str(inputs[key])])
        for key,flag in router.EC364_REPEATS:
            for v in inputs[key]:argv.extend([flag,str(v)])
        p=subprocess.run(argv,text=True,capture_output=True,timeout=1800)
        self.assertEqual(p.returncode,2,p.stderr+' '+p.stdout[-1300:])
        data=json.loads(p.stdout)
        self.assertEqual(data['schema'],core.RESULT_SCHEMA)
        self.assertTrue(data['locally_coherent_cross_epoch_signed_publication'])

    def test_11_signer_name_collision_denied_even_with_valid_signatures(self):
        self.setup364()
        self.bridge_events.pop(0)
        self.make_bridge('a',override={'claimed_source_id':'forged-name'})
        self.rebundle364()
        with self.assertRaises(errors.AnchorError) as e:core.audit(**self.args364())
        self.assertEqual(e.exception.status,'permission_denied')

    def test_12_signed_publisher_clock_out_of_order_is_not_credible_history(self):
        self.setup364()
        self.bridge_events.pop(0)
        self.make_bridge('a',override={'issued_utc':
            util.ut(self.now+timedelta(hours=7,minutes=19))})
        self.rebundle364()
        res=core.audit(**self.args364())
        self.assertTrue(res['signed_witness_or_publisher_timeline_anomaly'])

    def test_13_historical_snapshot_must_be_contiguous_epoch_zero(self):
        self.setup364()
        self.snapshot=self.write353('ec364-skipped-epoch-one',{
            'schema':core.SNAPSHOT_SCHEMA,'epoch_index':1,
            'ec362_audit_inputs':self.old_inputs})
        self.rebundle364()
        with self.assertRaises(errors.AnchorError) as e:
            core.audit(**self.args364())
        self.assertEqual(e.exception.status,'permission_denied')

    def test_14_signed_carry_cannot_hide_actual_key_replacement(self):
        self.setup364()
        self.bridge_events.pop(0)
        self.make_bridge('a',kind='carry')
        self.rebundle364()
        res=core.audit(**self.args364())
        self.assertTrue(res['publisher_signer_role_collision'])
        self.assertFalse(res['locally_coherent_cross_epoch_signed_publication'])

    def test_15_no_cross_window_rfc6962_edge_is_not_a_proof(self):
        self.setup364()
        self.cross_proofs=[]
        self.rebundle364()
        res=core.audit(**self.args364())
        self.assertTrue(res['cross_window_consistency_proof_missing_or_invalid'])
        self.assertEqual(res['adjacent_directory_consistency_proofs_verified'],0)

    def test_16_readonly_handoff_derives_only_from_actual_ec363_replay(self):
        self.setup364()
        parent=self.args363()
        handoff=core.checklist(**parent)
        self.assertEqual(handoff['exit_code'],2)
        self.assertEqual(handoff['parent_ec363_canonical_result_sha256'],
                         self.current_ec363_sha)
        self.assertTrue(handoff['actual_ec363_through_ec337_signed_originals_replayed'])
        root=Path(__file__).resolve().parents[2]
        sys.path.insert(0,str(root/'scripts'))
        import ces_next as router
        argv=[sys.executable,'-I','-B',
              str(root/'scripts'/'ces_cas_cross_epoch.py'),
              'derive-cross-epoch-handoff']
        for key in router.EC363_REQUIRED:
            argv.extend(['--'+key.replace('_','-'),str(parent[key])])
        for key in router.EC363_OPTIONAL:
            if parent[key] is not None:
                argv.extend(['--'+key.replace('_','-'),str(parent[key])])
        for key,flag in router.EC363_REPEATS:
            for v in parent[key]:argv.extend([flag,str(v)])
        out=subprocess.run(argv,text=True,capture_output=True,timeout=1800)
        self.assertEqual(out.returncode,2,out.stderr+' '+out.stdout[-1800:])
        self.assertEqual(json.loads(out.stdout)['schema'],core.HANDOFF_SCHEMA)

    def test_17_three_distinct_true_parent_windows_and_two_direct_rfc_edges(self):
        # Exercise the maximum of two independently pinned old input epochs.
        # This creates *three* true different EC361 parents, and the EC363
        # same-parent disclosure manifest fills sequence 3 between the second
        # real historical epoch (sequence 2) and current sequence 4.
        self.setup364()
        middle_ec361_sha=self.ec361_sha
        middle_sources={slot:dict(self.sources[slot]) for slot in core.SLOTS}
        middle_manifests={slot:self.histories[slot][0] for slot in core.SLOTS}
        middle_inputs=dict(self.parent_inputs)
        for slot in core.SLOTS:
            middle_inputs['source_'+slot+'_publication_manifest_file']=middle_manifests[slot]['path']
            middle_inputs['expected_source_'+slot+'_publication_manifest_sha256']=middle_manifests[slot]['sha256']
            middle_inputs['minimum_source_'+slot+'_publication_sequence']=2
        middle_result=ec362.audit(**middle_inputs)
        self.assertTrue(middle_result['two_offline_signed_publication_copies_locally_coherent'])
        middle_cp=self.evolved[0]

        # Next distinct true EC361 parent; not merely a new EC362 signature.
        self.leaves.append(b'EC364_SEVENTH_ACTUAL_APPEND_ONLY_DIRECTORY_LEAF')
        newest=self.add_evolved_checkpoint(leaves=self.leaves)
        self.evolved=[newest]
        for slot in core.SLOTS:
            self.make_receipt(slot,newest,changes={
                'observed_utc':util.ut(self.now+timedelta(hours=7,minutes=1))})
        self.consistency_inputs=self.args361()
        true_current_parent=ec361.audit(**self.consistency_inputs)
        self.assertTrue(true_current_parent['locally_coherent_signed_directory_evolution_and_gossip'])
        self.ec361_sha=core.sha(canonical.canonical(true_current_parent))
        self.assertNotIn(self.ec361_sha,(self.old_ec361_sha,middle_ec361_sha))
        self.sources={};self.publications={}
        copies={'checkpoint':newest,
           'consistency_bundle':{'path':self.consistency_inputs['consistency_bundle_file'],
              'sha256':self.consistency_inputs['expected_consistency_bundle_sha256']},
           'observer_a_receipt':self.receipts['a'],
           'observer_b_receipt':self.receipts['b']}
        for slot in core.SLOTS:
            key=ed25519.Ed25519PrivateKey.generate()
            pub=self.write353('ec364-triple-current-key-'+slot,util.pub(key))
            self.sources[slot]={'private':key,'public':pub,'copies':{
                role:self.write353('ec364-triple-current-'+slot+'-'+role,
                  Path(ref['path']).read_bytes()) for role,ref in copies.items()}}
            self.make_publication(slot,sequence=4)
        self.parent_inputs=self.args362()
        self._parent_hash=core.sha(canonical.canonical(ec362.audit(**self.parent_inputs)))
        for slot in core.SLOTS:
            current=self.publications[slot]
            historic=self.make_publication(slot,sequence=3)
            self.publications[slot]=current
            challenger=ed25519.Ed25519PrivateKey.generate()
            pub=self.write353('ec364-triple-challenger-'+slot,util.pub(challenger))
            self.challengers[slot]={'private':challenger,'public':pub}
            self.histories[slot]=[historic]
            self.disclosure_requests[slot]=[];self.disclosure_responses[slot]=[]
            for n,role in enumerate(core.history.ROLES):
                request=self.make_challenge(slot,historic,role,n)
                self.make_response(slot,request)
            self.rebundle(slot)
        latest_audit=ec363.audit(**self.args363())
        self.assertTrue(latest_audit['bounded_signed_history_and_disclosures_locally_coherent'])
        self.current_ec363_sha=core.sha(canonical.canonical(latest_audit))
        extra_snapshot=self.write353('ec364-triple-middle-snapshot',{
            'schema':core.SNAPSHOT_SCHEMA,'epoch_index':1,
            'ec362_audit_inputs':middle_inputs})

        bridges=[]
        for i,from_sources,to_sources,from_docs,to_docs,from_sha,to_sha in (
            (0,self.old_sources,middle_sources,self.old_manifests,middle_manifests,
                self.old_ec361_sha,middle_ec361_sha),
            (1,middle_sources,self.sources,middle_manifests,self.publications,
                middle_ec361_sha,self.ec361_sha)):
            for slot in core.SLOTS:
                olddoc=json.loads(Path(from_docs[slot]['path']).read_bytes())
                newdoc=json.loads(Path(to_docs[slot]['path']).read_bytes())
                body={'schema':core.TRANSITION_SCHEMA,'source_slot':slot,
                   'claimed_source_id':olddoc['claimed_source_id'],
                   'from_epoch_index':i,'to_epoch_index':i+1,
                   'event_kind':'rotate',
                   'from_parent_ec361_canonical_result_sha256':from_sha,
                   'to_parent_ec361_canonical_result_sha256':to_sha,
                   'from_manifest_original_sha256':from_docs[slot]['sha256'],
                   'to_manifest_original_sha256':to_docs[slot]['sha256'],
                   'from_custodian_public_key_original_sha256':
                        from_sources[slot]['public']['sha256'],
                   'to_custodian_public_key_original_sha256':
                        to_sources[slot]['public']['sha256'],
                   'from_checkpoint_original_sha256':
                        olddoc['copies']['checkpoint']['sha256'],
                   'to_checkpoint_original_sha256':
                        newdoc['copies']['checkpoint']['sha256'],
                   'issued_utc':util.ut(self.now+timedelta(hours=7,minutes=20)),
                   'expires_utc':util.ut(self.now+timedelta(days=1))}
                data=core.TRANSITION_DOMAIN+canonical.canonical(body)
                body['signature_old_custodian_ed25519_hex']=\
                    from_sources[slot]['private'].sign(data).hex()
                body['signature_new_custodian_ed25519_hex']=\
                    to_sources[slot]['private'].sign(data).hex()
                bridges.append(self.write353('ec364-triple-transition-'+slot+'-'+str(i),body))
        proofs=[self.cross_proofs[0],{
           'from_epoch_index':1,'to_epoch_index':2,
           'older_checkpoint_original_sha256':middle_cp['sha256'],
           'newer_checkpoint_original_sha256':newest['sha256'],
           'audit_path_sha256':[x.hex() for x in util.consistency(self.leaves,6)]}]
        full=self.write353('ec364-triple-window-bundle',{
           'schema':core.BUNDLE_SCHEMA,
           'current_ec363_canonical_result_sha256':self.current_ec363_sha,
           'historical_parent_snapshots':[self.snapshot,extra_snapshot],
           'signed_source_transitions':bridges,
           'directory_window_proofs':proofs})
        args=self.args364(cross_epoch_bundle_file=full['path'],
           expected_cross_epoch_bundle_sha256=full['sha256'],
           minimum_retained_historical_epoch_count=2,
           minimum_retained_directory_tree_size=7,
           historical_ec362_snapshot_shas=[self.snapshot['sha256'],extra_snapshot['sha256']],
           signed_source_epoch_transition_shas=[x['sha256'] for x in bridges])
        result=core.audit(**args)
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['locally_coherent_cross_epoch_signed_publication'],result['status'])
        self.assertEqual(result['true_historical_parent_replays'],2)
        self.assertEqual(result['true_signed_transition_originals_verified'],4)
        self.assertEqual(result['adjacent_directory_consistency_proofs_verified'],2)
        self.assertEqual(len(result['epoch_reviews']),3)
