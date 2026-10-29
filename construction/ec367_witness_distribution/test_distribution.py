#!/usr/bin/env python3
"""Focused EC367 Ed25519 checks with an EXPLICIT mocked EC366 parent result.

The fixture cryptographically verifies every new witness/source original for
real. It does *not* claim that the inherited EC366..EC337 replay completed.
The full EC366 parent can be exercised separately with the same new API.
"""
from __future__ import annotations

import copy
from datetime import datetime,timezone,timedelta
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec366_root_provenance import provenance as parent
from . import distribution as core


UTC='2026-10-26T12:00:00Z'
EV='2026-10-26T12:30:00Z'
EXP='2026-10-28T12:00:00Z'


def pub(priv):
    return priv.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)


class FocusedWitnessCryptoTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)
        self.index=0
        self.parent365='a'*64
        self.institutions=[];self.witnesses=[]
        self.statuses=[[],[]];self.att_shas=['b'*64,'c'*64]
        for i,role in enumerate(core.SOURCES):
            priv=ed25519.Ed25519PrivateKey.generate()
            key=self.write('source-key-'+role,pub(priv))
            self.institutions.append({'private':priv,'public':key,
                                     'name':'ExampleSource'+str(i)})
            self.source_status(i,0,'activate')
        for i,path in enumerate(core.PATHS):
            priv=ed25519.Ed25519PrivateKey.generate()
            self.witnesses.append({'private':priv,
              'public':self.write('witness-key-'+path,pub(priv)),
              'name':'ExampleWitness'+str(i), 'records':[]})
        self.root_bundle()
        self.parent_result()
        self.make_witness(0)
        self.make_witness(1)
        self.distribution_bundle()

    def write(self,name,data):
        self.index+=1
        p=self.base/('%03d_'%self.index+name+'.json')
        p.write_bytes(data if type(data) is bytes else canonical.canonical(data))
        return {'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}

    def source_status(self,i,seq,action='renew',previous=None,changes=None):
        src=self.institutions[i]
        if seq>0 and previous is None:previous=self.statuses[i][-1]['sha256']
        body={'schema':parent.STATUS_SCHEMA,
          'claimed_institution_id':src['name'],
          'claimed_institution_role':core.SOURCES[i],
          'institution_public_key_original_sha256':src['public']['sha256'],
          'parent_ec365_canonical_result_sha256':self.parent365,
          'sequence':seq,'previous_status_original_sha256':previous,
          'action':action,'successor_public_key_original_sha256':None,
          'issued_utc':UTC,'expires_utc':EXP}
        if changes:body.update(changes)
        signed={**body,'signature_institution_ed25519_hex':
              src['private'].sign(parent.STATUS_DOMAIN+canonical.canonical(body)).hex()}
        ref=self.write('source-status-'+str(i),signed)
        self.statuses[i].append(ref)
        return ref

    def root_bundle(self):
        b={'schema':parent.BUNDLE_SCHEMA,
           'parent_ec365_canonical_result_sha256':self.parent365,
           'claimed_directory_lineage_id':'ExampleDirectory',
           'institutions':[
            {'claimed_institution_id':self.institutions[i]['name'],
             'claimed_institution_role':core.SOURCES[i],
             'institution_public_key_original_sha256':self.institutions[i]['public']['sha256'],
             'signed_status_events':self.statuses[i],
             'signed_provenance_attestations':[]}
              for i in range(2)],
           'additional_signed_checkpoints':[]}
        self.root=self.write('ec366-root-bundle',b)

    def parent_result(self):
        self.prior={'schema':parent.RESULT_SCHEMA,'exit_code':2,
           'case_id':'synthetic-parent-only',
           'actual_ec365_through_ec337_signed_originals_replayed':True,
           'parent_ec365_canonical_result_sha256':self.parent365,
           'locally_two_institutions_correlate_on_same_real_directory_lineage':True,
           'actual_epoch_directory_original_reviews':[
               {'actual_directory_key_original_sha256':'f'*64}],
           'two_institution_original_reviews':[
              {'actual_status_head_sha256':self.statuses[i][-1]['sha256'],
               'actual_attestation_head_sha256':self.att_shas[i]}
               for i in range(2)],
           'channel_evidence':[
               {'tsa_channel_id':'ExampleTsa'+str(i),
                'outcome':parent.OUTCOMES[-1]} for i in range(2)]}
        self.parent_sha=core.sha(canonical.canonical(self.prior))

    def obs(self,i,ref=None,att=None,action_override=None):
        src=self.institutions[i]
        ref=ref or self.statuses[i][-1]
        doc=json.loads(Path(ref['path']).read_bytes())
        action=action_override or doc['action']
        return {'claimed_source_role':core.SOURCES[i],
         'claimed_institution_id':src['name'],
         'institution_public_key_original_sha256':src['public']['sha256'],
         'source_status_head_original_sha256':ref['sha256'],
         'source_status_sequence':doc['sequence'],
         'source_status_action':action,
         'previous_source_status_original_sha256':doc['previous_status_original_sha256'],
         'source_attestation_head_original_sha256':att or self.att_shas[i],
         'source_revocation_proof_original_sha256':ref['sha256'] if action in
             ('revoke','rotate') else None}

    def make_witness(self,i,*,seq=0,previous=None,disclosure='published',
                     observations=None,changes=None,signer=None):
        wt=self.witnesses[i]
        if seq and previous is None:previous=wt['records'][-1]['sha256']
        body={'schema':core.RECORD_SCHEMA,
           'distribution_path':core.PATHS[i],
           'claimed_witness_id':wt['name'],
           'witness_public_key_original_sha256':wt['public']['sha256'],
           'parent_ec366_canonical_result_sha256':self.parent_sha,
           'sequence':seq,'previous_witness_original_sha256':previous,
           'disclosure_state':disclosure,
           'source_observations':observations or [self.obs(k) for k in range(2)],
           'issued_utc':UTC,'expires_utc':EXP}
        if changes:body.update(changes)
        signing=signer or wt['private']
        record={**body,'signature_witness_ed25519_hex':
            signing.sign(core.RECORD_DOMAIN+canonical.canonical(body)).hex()}
        ref=self.write('witness-record-'+str(i),record)
        wt['records'].append(ref)
        return ref

    def distribution_bundle(self,extra=None):
        self.extra=extra or []
        b={'schema':core.BUNDLE_SCHEMA,
            'parent_ec366_canonical_result_sha256':self.parent_sha,
            'distribution_paths':[
              {'distribution_path':core.PATHS[i],
               'claimed_witness_id':self.witnesses[i]['name'],
               'witness_public_key_original_sha256':self.witnesses[i]['public']['sha256'],
               'signed_witness_observations':self.witnesses[i]['records']}
                for i in range(2)],
            'additional_source_status_originals':self.extra}
        self.bundle=self.write('witness-bundle',b)

    def args367(self,**change):
        a={'root_provenance_evaluation_utc':UTC,
           'root_provenance_bundle_file':self.root['path'],
           'expected_root_provenance_bundle_sha256':self.root['sha256'],
           'institution_root_public_key_files':[x['public']['path'] for x in self.institutions],
           'institution_root_public_key_shas':[x['public']['sha256'] for x in self.institutions],
           'institution_claimed_ids':[x['name'] for x in self.institutions],
           'witness_distribution_evaluation_utc':EV,
           'witness_distribution_bundle_file':self.bundle['path'],
           'expected_witness_distribution_bundle_sha256':self.bundle['sha256'],
           'witness_public_key_files':[x['public']['path'] for x in self.witnesses],
           'witness_public_key_shas':[x['public']['sha256'] for x in self.witnesses],
           'witness_claimed_ids':[x['name'] for x in self.witnesses],
           'signed_witness_record_shas':[r['sha256'] for x in self.witnesses
                                         for r in x['records']],
           'additional_source_status_shas':[x['original']['sha256'] for x in self.extra]}
        for i,p in enumerate(core.PATHS):
            a['minimum_retained_'+p+'_sequence']=0
            a['expected_retained_'+p+'_witness_head_sha256']=self.witnesses[i]['records'][-1]['sha256']
        return {**a,**change}

    def run_audit(self,**change):
        with patch.object(core.parent,'audit',return_value=self.prior):
            return core.audit(**self.args367(**change))

    def test_01_valid_real_ed25519_witnesses_correlate_mock_parent_only(self):
        r=self.run_audit()
        self.assertTrue(r['locally_two_independently_retained_paths_correlate_on_verified_source_heads'],r['status'])
        self.assertEqual(r['true_verified_witness_distribution_signatures'],2)
        self.assertEqual(r['true_verified_additional_source_signed_status_originals'],0)
        self.assertFalse(r[core.NEGATIVES[0]])

    def test_02_forged_witness_signature_denied(self):
        self.witnesses[1]['records']=[]
        self.make_witness(1,signer=self.institutions[0]['private'])
        self.distribution_bundle()
        with self.assertRaises(errors.AnchorError) as got:self.run_audit()
        self.assertEqual(got.exception.status,'permission_denied')

    def test_03_source_revocation_proof_cannot_be_cleared_by_active_witnesses(self):
        ref=self.source_status(0,1,'revoke')
        self.distribution_bundle([{'source_role':core.SOURCES[0],'original':ref}])
        r=self.run_audit()
        self.assertTrue(r['genuinely_source_signed_revocation_or_rotation_proof_visible'])
        self.assertEqual(r['true_source_signed_terminal_status_original_shas'][0][
                       'terminal_original_shas'],[ref['sha256']])
        self.assertFalse(r['locally_two_independently_retained_paths_correlate_on_verified_source_heads'])

    def test_04_forged_additional_revocation_signature_denied(self):
        ref=self.source_status(0,1,'revoke',changes={'issued_utc':'2026-10-26T13:00:00Z'})
        forged=json.loads(Path(ref['path']).read_bytes())
        forged['signature_institution_ed25519_hex']=self.institutions[1]['private'].sign(
                parent.STATUS_DOMAIN+canonical.canonical({k:v for k,v in forged.items()
                    if k!='signature_institution_ed25519_hex'})).hex()
        bad=self.write('forged-revocation',forged)
        self.distribution_bundle([{'source_role':core.SOURCES[0],'original':bad}])
        with self.assertRaises(errors.AnchorError) as got:self.run_audit()
        self.assertEqual(got.exception.status,'permission_denied')

    def test_05_witness_declares_withheld_distribution(self):
        self.witnesses[0]['records']=[]
        self.make_witness(0,disclosure='withheld')
        self.distribution_bundle()
        r=self.run_audit()
        self.assertTrue(r['signed_witness_withheld_or_disputed_distribution_visible'])
        self.assertFalse(r['locally_two_independently_retained_paths_correlate_on_verified_source_heads'])

    def test_06_actual_signed_witness_fork_visible(self):
        self.make_witness(0,seq=0,changes={'disclosure_state':'disputed'})
        self.distribution_bundle()
        r=self.run_audit()
        self.assertTrue(r['genuinely_signed_witness_chain_fork_gap_or_epoch_replay_visible'])
        self.assertTrue(r['signed_witness_withheld_or_disputed_distribution_visible'])

    def test_07_signed_misrepresentation_of_source_action_detected(self):
        self.witnesses[1]['records']=[]
        views=[self.obs(k) for k in range(2)]
        views[0]['source_status_action']='revoke'
        views[0]['source_revocation_proof_original_sha256']=views[0]['source_status_head_original_sha256']
        self.make_witness(1,observations=views)
        self.distribution_bundle()
        r=self.run_audit()
        self.assertTrue(r['witness_signed_status_claim_mismatches_verified_source_original_visible'])

    def test_08_missing_externally_retained_exact_witness_original_sha_stream(self):
        r=self.run_audit(signed_witness_record_shas=[])
        self.assertTrue(r['retained_witness_original_head_or_sequence_rollback_visible'])

    def test_09_witness_record_claims_wrong_parent_canonical_sha(self):
        self.witnesses[1]['records']=[]
        self.make_witness(1,changes={'parent_ec366_canonical_result_sha256':'e'*64})
        self.distribution_bundle()
        r=self.run_audit()
        self.assertTrue(r['witness_signed_status_claim_mismatches_verified_source_original_visible'])

    def test_10_two_path_signed_source_head_disagreement_is_not_hidden(self):
        extra=self.source_status(0,1,'renew')
        self.witnesses[1]['records']=[]
        self.make_witness(1,observations=[self.obs(0,extra),self.obs(1)])
        self.distribution_bundle([{'source_role':core.SOURCES[0],'original':extra}])
        r=self.run_audit()
        self.assertTrue(r['genuinely_signed_cross_path_source_view_conflict_or_lag_visible'])
        self.assertTrue(r['extra_source_signed_status_fork_or_parent_head_staleness_visible'])

    def test_11_both_witness_heads_must_be_caller_retained(self):
        r=self.run_audit(expected_retained_archive_distribution_witness_head_sha256='d'*64)
        self.assertTrue(r['retained_witness_original_head_or_sequence_rollback_visible'])
        self.assertFalse(r['locally_two_independently_retained_paths_correlate_on_verified_source_heads'])

    def test_12_witness_can_chain_forward_on_exact_same_source_shas(self):
        self.make_witness(0,seq=1)
        self.make_witness(1,seq=1)
        self.distribution_bundle()
        r=self.run_audit(minimum_retained_registry_distribution_sequence=1,
                         minimum_retained_archive_distribution_sequence=1)
        self.assertTrue(r['locally_two_independently_retained_paths_correlate_on_verified_source_heads'],r['status'])
        self.assertEqual(r['true_verified_witness_distribution_signatures'],4)

    def test_13_unknown_source_status_not_promoted_by_signed_witness(self):
        self.witnesses[0]['records']=[]
        views=[self.obs(k) for k in range(2)]
        views[1]['source_status_head_original_sha256']='d'*64
        self.make_witness(0,observations=views)
        self.distribution_bundle()
        r=self.run_audit()
        self.assertTrue(r['witness_signed_status_claim_mismatches_verified_source_original_visible'])

    def test_14_signed_forked_source_proofs_are_visible(self):
        original=self.statuses[0][-1]['sha256']
        self.source_status(0,1,'renew',previous=original)
        sibling=self.source_status(0,1,'revoke',previous=original)
        first=self.statuses[0][-2]
        self.distribution_bundle([{'source_role':core.SOURCES[0],'original':first},
                                  {'source_role':core.SOURCES[0],'original':sibling}])
        r=self.run_audit()
        self.assertTrue(r['extra_source_signed_status_fork_or_parent_head_staleness_visible'])
        self.assertTrue(r['genuinely_source_signed_revocation_or_rotation_proof_visible'])

    def test_15_signed_witness_expiry_is_caller_clock_only(self):
        self.witnesses[0]['records']=[]
        self.make_witness(0,changes={'expires_utc':'2026-10-26T12:05:00Z'})
        self.distribution_bundle()
        r=self.run_audit()
        self.assertTrue(r['witness_self_claimed_time_untrusted_or_anomalous'])

    def test_16_parent_not_locally_correlated_cannot_be_repaired(self):
        self.prior['locally_two_institutions_correlate_on_same_real_directory_lineage']=False
        self.parent_sha=core.sha(canonical.canonical(self.prior))
        # Old witnesses still bind the earlier SHA: additional contradiction
        # must be visible, never interpreted as upgraded parent status.
        r=self.run_audit()
        self.assertTrue(r['inherited_ec366_institution_provenance_unresolved'])
        self.assertFalse(r['locally_two_independently_retained_paths_correlate_on_verified_source_heads'])


    def test_17_unified_fixed_route_validates_exact_mock_child_reply_contract(self):
        # Only the new isolated-child RETURN CONTRACT is simulated here. This
        # does not execute an inherited parent CLI or assert a full replay.
        import contextlib
        import io
        import sys
        scripts=str(Path(__file__).resolve().parents[2]/'scripts')
        sys.path.insert(0,scripts)
        self.addCleanup(lambda:sys.path.remove(scripts))
        import ces_next
        doc=self.run_audit()
        a={}
        for k in ces_next.EC367_REQUIRED:
            a[k]=(1 if k in ('expected_current_root_epoch',
                              'minimum_acceptable_epoch') else
                  UTC if k.endswith('_evaluation_utc') else
                  '/tmp/inherited-original' if k.endswith('_file') else
                  'a'*64 if k.endswith('_sha256') else 'SafeInheritedValue')
        for k in ces_next.EC367_OPTIONAL:a[k]=None
        for k,_ in ces_next.EC367_REPEATS:a[k]=[]
        a.update(self.args367())
        called=[]
        def child(cmd,**kwargs):
            called.append(cmd)
            return 2,doc
        output=io.StringIO()
        with patch.object(ces_next,'_command',side_effect=child), \
             contextlib.redirect_stdout(output):
            rc=ces_next.audit_witness_distribution(
                'DeliveryAudit','AuditWitnessDistribution',**a)
        self.assertEqual(rc,2)
        self.assertTrue(called)
        self.assertEqual(Path(called[0][3]).name,'ces_cas_witness_distribution.py')
        self.assertEqual(json.loads(output.getvalue())['outcome_counts'][
                          core.OUTCOMES[-1]],2)


if __name__=='__main__':
    unittest.main()
