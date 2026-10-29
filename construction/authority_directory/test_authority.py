#!/usr/bin/env python3
"""EC360 true Ed25519/RFC6962 local fixtures; NO official key provenance.

Each case really replays the parent's EC359->EC337 originals and signatures.
Synthetic keys do NOT establish legal/official identity or global freshness.
"""
from __future__ import annotations
from datetime import timedelta
from pathlib import Path
import os
import json
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from transparency import test_transparency as tr
from owner_distribution import distribution as previous
from owner_distribution import test_distribution as old_tests
from . import authority as core


class AuthorityTests(old_tests.DistributionTests):
    for _name in dir(old_tests.DistributionTests):
        if _name.startswith('test_'):locals()[_name]=None

    def setUp(self):
        super().setUp()
        self.anchors={};self.origins={};self.delegations={}
        self.revocations={'a':[],'b':[]};self.revoke_heads={};self.revoke_min={'a':0,'b':0}
        self.extra_proofs={};self.directory_signer=None
        self.directory_override=None

    def signed360(self,name,body,key,domain,sigfield,bad_key=None):
        who=bad_key if bad_key else key
        return self.write353(name,{**body,sigfield:who.sign(domain+canonical.canonical(body)).hex()})

    def setup360(self,*,make_directory=True):
        self.setup359()
        self.distribution_inputs=self.args359()
        actual=previous.audit(**self.distribution_inputs)
        self.assertTrue(actual['two_issuer_signed_distributions_locally_match_ec358_owner'])
        self.parent_sha=core.sha(canonical.canonical(actual))
        for slot in ('a','b'):
            root=ed25519.Ed25519PrivateKey.generate()
            witness=ed25519.Ed25519PrivateKey.generate()
            rootpin=self.write353('ec360-authority-root-'+slot,tr.pub(root))
            witnesspin=self.write353('ec360-witness-'+slot,tr.pub(witness))
            self.anchors[slot]={'root_priv':root,'root':rootpin,
                                'witness_priv':witness,'witness':witnesspin}
            self.make_delegation(slot)
            self.make_origin(slot)
            self.make_snapshot(slot,0)
        if make_directory:
            key=ed25519.Ed25519PrivateKey.generate()
            pub=self.write353('ec360-directory-key',tr.pub(key))
            self.directory_signer={'private':key,'pub':pub}

    def make_delegation(self,slot,*,changes=None,bad_signature=False):
        a=self.anchors[slot]
        body={'schema':core.DELEGATION_SCHEMA,'slot':slot,
              'authority_id':'claimed_external_authority_'+slot,
              'root_public_key_original_sha256':a['root']['sha256'],
              'issuer_public_key_original_sha256':self.distributors[slot]['pub']['sha256'],
              'issuer_id_as_signed_claim':'external_distributor_'+slot,
              'owner_public_key_original_sha256':self.owners[slot]['pub']['sha256'],
              'parent_owner_head_event_sha256':self.my_heads[slot],
              'parent_distribution_head_original_sha256':self.distribution_heads[slot],
              'parent_ec359_canonical_result_sha256':self.parent_sha,
              'authorized_jurisdictions':['claimed_region_'+slot],
              'authorized_scopes':[core.TARGET_SCOPE],
              'valid_from_utc':tr.ut(self.now+timedelta(hours=5,minutes=15)),
              'expires_utc':tr.ut(self.now+timedelta(days=2))}
        if changes:body.update(changes)
        signed=self.signed360('ec360-delegate-'+slot,body,a['root_priv'],
                       core.DELEGATION_DOMAIN,'signature_root_ed25519_hex',
                       bad_key=(a['witness_priv'] if bad_signature else None))
        self.delegations[slot]=signed
        return signed

    def make_origin(self,slot,*,changes=None,bad_signature=False):
        a=self.anchors[slot]
        body={'schema':core.ORIGIN_SCHEMA,'slot':slot,
              'authority_id':'claimed_external_authority_'+slot,
              'claimed_jurisdiction':'claimed_region_'+slot,
              'origin_reference_id':'claimed_offline_origin_'+slot,
              'root_public_key_original_sha256':a['root']['sha256'],
              'delegation_original_sha256':self.delegations[slot]['sha256'],
              'origin_witness_public_key_original_sha256':a['witness']['sha256'],
              'observed_utc':tr.ut(self.now+timedelta(hours=6,minutes=5)),
              'expires_utc':tr.ut(self.now+timedelta(days=2))}
        if changes:body.update(changes)
        signed=self.signed360('ec360-origin-'+slot,body,a['witness_priv'],
                 core.ORIGIN_DOMAIN,'signature_witness_ed25519_hex',
                 bad_key=(a['root_priv'] if bad_signature else None))
        self.origins[slot]=signed
        return signed

    def make_snapshot(self,slot,sequence,*,predecessor=None,changes=None,
                      bad_signature=False):
        a=self.anchors[slot]
        body={'schema':core.SNAPSHOT_SCHEMA,'slot':slot,
              'authority_id':'claimed_external_authority_'+slot,
              'root_public_key_original_sha256':a['root']['sha256'],
              'delegation_original_sha256':self.delegations[slot]['sha256'],
              'scope':core.TARGET_SCOPE,'sequence':sequence,
              'previous_snapshot_original_sha256':predecessor,
              'inventory_issuer_key_shas':[self.distributors[slot]['pub']['sha256']],
              'revoked_issuer_key_shas':[],
              'issued_utc':tr.ut(self.now+timedelta(hours=6,minutes=10+sequence)),
              'valid_until_utc':tr.ut(self.now+timedelta(days=2))}
        if changes:body.update(changes)
        pin=self.signed360('ec360-revoke-'+slot+'-'+str(len(self.revocations[slot])),
               body,a['root_priv'],core.SNAPSHOT_DOMAIN,'signature_root_ed25519_hex',
               bad_key=(a['witness_priv'] if bad_signature else None))
        self.revocations[slot].append(pin)
        self.revoke_heads[slot]=pin['sha256']
        return pin

    def build_directory360(self):
        if self.directory_signer is None:return None,None,{'a':[],'b':[]}
        objects=[];order=[]
        for slot in ('a','b'):
            if slot in self.delegations and slot in self.revoke_heads:
                source=[self.delegations[slot],next(
                    p for p in self.revocations[slot] if p['sha256']==self.revoke_heads[slot])]
                for pin in source:
                    objects.append(Path(pin['path']).read_bytes());order.append((slot,pin))
        proofs={'a':[],'b':[]}
        root=tr.root(objects)
        for i,(slot,pin) in enumerate(order):
            proofs[slot].append({'original_sha256':pin['sha256'],
                'leaf_index':i,'audit_path_sha256':[x.hex() for x in tr.inclusion(objects,i)]})
        if self.directory_override is not None:
            proofs=self.directory_override(proofs)
        key=self.directory_signer
        body={'schema':core.DIRECTORY_SCHEMA,
              'directory_id':'unofficial_synthetic_directory',
              'directory_public_key_original_sha256':key['pub']['sha256'],
              'tree_size':len(objects),'root_sha256':root.hex(),
              'issued_utc':tr.ut(self.now+timedelta(hours=6,minutes=40)),
              'expires_utc':tr.ut(self.now+timedelta(days=2))}
        pin=self.signed360('ec360-directory-checkpoint',body,key['private'],
                         core.DIRECTORY_DOMAIN,'signature_directory_ed25519_hex')
        return pin,key['pub'],proofs

    def args360(self,**changes):
        cp,pub,proofs=self.build_directory360()
        doc={'schema':core.BUNDLE_SCHEMA,
             'sources':[{'slot':slot,
                 'authority_root_public_key':a['root'],
                 'origin_witness_public_key':a['witness'],
                 'origin_original':self.origins[slot],
                 'delegation_original':self.delegations[slot],
                 'revocation_snapshot_originals':self.revocations[slot],
                 'directory_inclusions':proofs[slot]}
                for slot,a in self.anchors.items()]}
        manifest=self.write353('ec360-bundle',doc)
        a=self.anchors.get('a');b=self.anchors.get('b')
        inputs={**self.distribution_inputs,
            'authority_evaluation_utc':tr.ut(self.now+timedelta(hours=7)),
            'authority_bundle_file':manifest['path'],
            'expected_authority_bundle_sha256':manifest['sha256'],
            'authority_a_root_public_key_file':a['root']['path'] if a else None,
            'expected_authority_a_root_public_key_sha256':a['root']['sha256'] if a else None,
            'authority_b_root_public_key_file':b['root']['path'] if b else None,
            'expected_authority_b_root_public_key_sha256':b['root']['sha256'] if b else None,
            'origin_a_witness_public_key_file':a['witness']['path'] if a else None,
            'expected_origin_a_witness_public_key_sha256':a['witness']['sha256'] if a else None,
            'origin_b_witness_public_key_file':b['witness']['path'] if b else None,
            'expected_origin_b_witness_public_key_sha256':b['witness']['sha256'] if b else None,
            'minimum_a_revocation_sequence':self.revoke_min['a'],
            'minimum_b_revocation_sequence':self.revoke_min['b'],
            'expected_a_revocation_head_sha256':self.revoke_heads.get('a'),
            'expected_b_revocation_head_sha256':self.revoke_heads.get('b'),
            'directory_public_key_file':pub['path'] if pub else None,
            'expected_directory_public_key_sha256':pub['sha256'] if pub else None,
            'directory_checkpoint_file':cp['path'] if cp else None,
            'expected_directory_checkpoint_sha256':cp['sha256'] if cp else None,
            'minimum_directory_tree_size':4 if cp else None,
            'expected_directory_head_sha256':cp['sha256'] if cp else None,
            **changes}
        return inputs

    def run360(self,**changes):return core.audit(**self.args360(**changes))

    def deny360(self,part,**changes):
        with self.assertRaises(errors.AnchorError) as ctx:self.run360(**changes)
        self.assertIn(part,ctx.exception.code)

    def test_01_two_roots_witnesses_signed_revocations_and_rfc6962_directory(self):
        self.setup360()
        out=self.run360()
        self.assertEqual(out['exit_code'],2)
        self.assertEqual(out['channel_evidence'][0]['outcome'],core.OUTCOMES[-1])
        self.assertTrue(out['actual_ec359_through_ec337_signed_originals_replayed'])
        self.assertTrue(out['two_sources_scope_and_revocation_locally_coherent'])
        self.assertTrue(out['two_sources_directory_inclusion_locally_verified'])
        self.assertTrue(out['official_trust_anchor_origin_legal_identity_trusted_time_and_global_revocation_unproven'])
        self.assertFalse(out['caller_pinned_root_or_witness_is_officially_authenticated'])

    def test_02_true_root_signature_but_wrong_jurisdiction_excluded(self):
        self.setup360()
        self.make_delegation('a',changes={'authorized_jurisdictions':['other_region']})
        self.make_origin('a')
        self.revocations['a']=[]
        self.make_snapshot('a',0)
        out=self.run360()
        self.assertTrue(out['valid_signatures_but_scope_jurisdiction_issuer_excluded'])
        self.assertFalse(out['two_sources_scope_and_revocation_locally_coherent'])

    def test_03_signed_revocation_never_promotes_issuer(self):
        self.setup360()
        old=self.revocations['a'][0]['sha256']
        self.make_snapshot('a',1,predecessor=old,changes={
            'revoked_issuer_key_shas':[self.distributors['a']['pub']['sha256']]})
        out=self.run360()
        self.assertTrue(out['signed_issuer_revocation_or_coverage_gap_visible'])
        self.assertEqual(out['channel_evidence'][0]['outcome'],core.OUTCOMES[3])

    def test_04_branch_cannot_hide_signed_revocation(self):
        self.setup360();head=self.revocations['a'][0]['sha256']
        self.make_snapshot('a',1,predecessor=head,changes={
            'revoked_issuer_key_shas':[self.distributors['a']['pub']['sha256']]})
        self.make_snapshot('a',1,predecessor=head,changes={
            'valid_until_utc':tr.ut(self.now+timedelta(days=3))})
        out=self.run360()
        self.assertTrue(out['signed_revocation_fork_or_authority_identity_collision'])
        self.assertTrue(out['signed_issuer_revocation_or_coverage_gap_visible'])

    def test_05_external_saved_minimum_detects_rollback(self):
        self.setup360();genesis=self.revocations['a'][0]['sha256']
        self.make_snapshot('a',1,predecessor=genesis)
        self.revoke_heads['a']=genesis
        self.revoke_min['a']=1
        out=self.run360()
        self.assertTrue(out['caller_pinned_revocation_or_directory_rollback'])

    def test_06_wrong_root_signature_is_hard_denial(self):
        self.setup360();self.make_delegation('b',bad_signature=True)
        self.deny360('DELEGATION_ROOT_TRUE_SIGNATURE_INVALID')

    def test_07_origin_witness_forgery_is_hard_denial(self):
        self.setup360();self.make_origin('a',bad_signature=True)
        self.deny360('ORIGIN_WITNESS_TRUE_SIGNATURE_INVALID')

    def test_08_false_parent_sha_cannot_be_root_delegated(self):
        self.setup360();self.make_delegation('a',changes={
            'parent_ec359_canonical_result_sha256':'a'*64})
        self.deny360('ROOT_DELEGATION_MUST_BIND_TRUE_EC359')

    def test_09_dir_witness_wrong_merkle_inclusion_is_unresolved(self):
        self.setup360()
        def tamper(proofs):
            proofs['b'][0]['audit_path_sha256'][0]='e'*64
            return proofs
        self.directory_override=tamper
        out=self.run360()
        self.assertTrue(out['independent_signed_directory_inclusion_missing_or_invalid'])
        self.assertFalse(out['two_sources_directory_inclusion_locally_verified'])

    def test_10_no_directory_never_equates_local_attestation_with_publication(self):
        self.setup360(make_directory=False)
        out=self.run360()
        self.assertTrue(out['two_sources_scope_and_revocation_locally_coherent'])
        self.assertFalse(out['two_sources_directory_inclusion_locally_verified'])
        self.assertEqual(out['channel_evidence'][0]['outcome'],core.OUTCOMES[7])

    def test_11_root_reused_from_parent_issuer_denied(self):
        self.setup360()
        old=self.distributors['a']['pub']
        self.deny360('ROLE_KEYS_MUST_MATCH_SEPARATE_CALLER_PINS',
             authority_a_root_public_key_file=old['path'],
             expected_authority_a_root_public_key_sha256=old['sha256'])

    def test_12_signed_clock_future_claim_not_trusted(self):
        self.setup360()
        self.make_origin('a',changes={'observed_utc':tr.ut(self.now+timedelta(hours=8))})
        out=self.run360()
        self.assertTrue(out['signed_utc_claim_stale_or_future'])

    def test_13_caller_directory_head_rollback_blocks_local_directory(self):
        self.setup360()
        out=self.run360(expected_directory_head_sha256='c'*64)
        self.assertTrue(out['caller_pinned_revocation_or_directory_rollback'])
        self.assertFalse(out['two_sources_directory_inclusion_locally_verified'])

    def test_14_signed_inventory_missing_issuer_does_not_prove_no_revocation(self):
        self.setup360()
        self.revocations['b']=[]
        self.make_snapshot('b',0,changes={'inventory_issuer_key_shas':[]})
        out=self.run360()
        self.assertTrue(out['signed_issuer_revocation_or_coverage_gap_visible'])
        self.assertTrue(out['authority_reviews'][1]['signed_issuer_inventory_coverage_missing'])

    def test_15_hardlink_new_witness_to_old_issuer_file_denied(self):
        self.setup360()
        witness=self.anchors['b']['witness']
        Path(witness['path']).unlink()
        os.link(self.distributors['b']['pub']['path'],witness['path'])
        self.deny360('WHOLE_ORIGINAL_SHA_MISMATCH')

    def test_16_fixed_isolated_unified_route_no_false_success(self):
        self.setup360()
        inputs=self.args360()
        root=Path(__file__).resolve().parents[2]
        sys.path.insert(0,str(root/'scripts'))
        import ces_next as router
        argv=[sys.executable,'-I','-B',str(root/'scripts'/'ces_next.py'),
              'audit-authority-directory','DeliveryAudit','AuditAuthorityDirectory']
        for key in router.EC360_REQUIRED:
            argv.extend(['--'+key.replace('_','-'),str(inputs[key])])
        for key in router.EC360_OPTIONAL:
            if inputs[key] is not None:
                argv.extend(['--'+key.replace('_','-'),str(inputs[key])])
        for key,flag in router.EC360_REPEATS:
            for v in inputs[key]:argv.extend([flag,str(v)])
        proc=subprocess.run(argv,capture_output=True,text=True,timeout=1800)
        self.assertEqual(proc.returncode,2,proc.stderr+' '+proc.stdout[-1300:])
        doc=json.loads(proc.stdout)
        self.assertEqual(doc['schema'],core.RESULT_SCHEMA)
        self.assertTrue(doc['two_sources_directory_inclusion_locally_verified'])

    def test_17_monotone_signed_revocation_cannot_be_later_unrevoked(self):
        self.setup360();root=self.revocations['a'][0]['sha256']
        self.make_snapshot('a',1,predecessor=root,changes={
            'revoked_issuer_key_shas':[self.distributors['a']['pub']['sha256']]})
        prev=self.revocations['a'][-1]['sha256']
        self.make_snapshot('a',2,predecessor=prev)
        out=self.run360()
        self.assertTrue(out['signed_revocation_fork_or_authority_identity_collision'])
        self.assertTrue(out['signed_issuer_revocation_or_coverage_gap_visible'])

    def test_18_both_source_signed_authority_labels_collide(self):
        self.setup360()
        self.make_delegation('b',changes={'authority_id':'claimed_external_authority_a'})
        self.make_origin('b',changes={'authority_id':'claimed_external_authority_a'})
        self.revocations['b']=[]
        self.make_snapshot('b',0,changes={'authority_id':'claimed_external_authority_a'})
        out=self.run360()
        self.assertTrue(out['signed_revocation_fork_or_authority_identity_collision'])

if __name__=='__main__':
    import unittest
    unittest.main()
