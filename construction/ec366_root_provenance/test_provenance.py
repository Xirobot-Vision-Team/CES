#!/usr/bin/env python3
"""EC366 actual Ed25519 synthetic two-institution evidence cases.

Only local fixture code generates private keys. Production provenance.py
is verification-only, and each audit genuinely invokes EC365->EC337.
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
from ec360_authority_directory import authority as directory
from ec365_directory_lineage import lineage as ec365
from ec365_directory_lineage import test_lineage as fixture
from . import provenance as core


class IndependentInstitutionProvenanceTests(fixture.DirectoryAuthorityLineageTests):
    # Do not rerun inherited EC365 (or its ancestors') separate full suites.
    for _name in dir(fixture.DirectoryAuthorityLineageTests):
        if _name.startswith('test_'):locals()[_name]=None

    def setup366(self):
        self.setup365()
        prior=ec365.audit(**self.args365())
        self.assertTrue(prior['locally_authorized_directory_signer_transition'])
        self.ec365_parent=prior
        self.ec365_parent_sha=core.sha(canonical.canonical(prior))
        self.institutions=[]
        self.claimed_ids=['ExampleOriginRegistry','ExampleIndependentArchive']
        self.status_originals=[[],[]];self.provenance_originals=[[],[]]
        self.additional_checkpoints=[]
        for i,role in enumerate(core.ROLES):
            priv=ed25519.Ed25519PrivateKey.generate()
            pub=self.write353('ec366-institution-key-'+role,util.pub(priv))
            self.institutions.append({'private':priv,'pub':pub})
            self.make_status(i,sequence=0,action='activate')
            self.make_attestation(i,sequence=1)
        self.rebundle366()

    def sign_status(self,i,body):
        role=core.ROLES[i]
        raw=core.STATUS_DOMAIN+canonical.canonical(body)
        doc={**body,'signature_institution_ed25519_hex':
             self.institutions[i]['private'].sign(raw).hex()}
        return self.write353('ec366-signed-status-'+role+'-'+str(self.file_no),doc)

    def make_status(self,i,*,sequence,action='renew',prior=None,changes=None):
        role=core.ROLES[i]
        if prior is None and sequence:
            prior=self.status_originals[i][-1]['sha256']
        body={'schema':core.STATUS_SCHEMA,
          'claimed_institution_id':self.claimed_ids[i],
          'claimed_institution_role':role,
          'institution_public_key_original_sha256':self.institutions[i]['pub']['sha256'],
          'parent_ec365_canonical_result_sha256':self.ec365_parent_sha,
          'sequence':sequence,
          'previous_status_original_sha256':prior,
          'action':action,
          'successor_public_key_original_sha256':None,
          'issued_utc':util.ut(self.now+timedelta(hours=7,minutes=55)),
          'expires_utc':util.ut(self.now+timedelta(days=2))}
        if changes:body.update(changes)
        ref=self.sign_status(i,body)
        self.status_originals[i].append(ref)
        return ref

    def sign_attestation(self,i,body):
        role=core.ROLES[i]
        raw=core.ATTEST_DOMAIN+canonical.canonical(body)
        doc={**body,'signature_institution_ed25519_hex':
             self.institutions[i]['private'].sign(raw).hex()}
        return self.write353('ec366-signed-provenance-'+role+'-'+str(self.file_no),doc)

    def make_attestation(self,i,*,sequence,prior=None,kind='corroborate',changes=None):
        role=core.ROLES[i]
        if prior is None and sequence>1:
            prior=self.provenance_originals[i][-1]['sha256']
        last=self.ec365_parent['epoch_lineage_reviews'][-1]
        cp=self.checkpoint_refs[-1]
        body={'schema':core.ATTEST_SCHEMA,
          'claimed_institution_id':self.claimed_ids[i],
          'claimed_institution_role':role,
          'institution_public_key_original_sha256':self.institutions[i]['pub']['sha256'],
          'parent_ec365_canonical_result_sha256':self.ec365_parent_sha,
          'institution_status_original_sha256':self.status_originals[i][-1]['sha256'],
          'sequence':sequence,
          'previous_attestation_original_sha256':prior,
          'directory_lineage_id':last['signed_claimed_directory_id'],
          'attestation_kind':kind,
          'directory_root_generation':self.ec365_parent['true_directory_root_generation'],
          'epoch_signed_directory_observations':core._claimed_observations(self.ec365_parent),
          'signed_directory_handoff_original_shas':[
             r['handoff_original_sha256'] for r in
             self.ec365_parent['signed_directory_handoff_reviews']],
          'observed_checkpoint_original_sha256':cp['sha256'],
          'observed_tree_size':last['signed_tree_size'],
          'observed_merkle_root_sha256':last['signed_merkle_root_sha256'],
          'issued_utc':util.ut(self.now+timedelta(hours=8,minutes=2)),
          'expires_utc':util.ut(self.now+timedelta(days=2))}
        if changes:body.update(changes)
        ref=self.sign_attestation(i,body)
        self.provenance_originals[i].append(ref)
        return ref

    def rebundle366(self):
        document={'schema':core.BUNDLE_SCHEMA,
          'parent_ec365_canonical_result_sha256':self.ec365_parent_sha,
          'claimed_directory_lineage_id':self.ec365_parent[
              'epoch_lineage_reviews'][0]['signed_claimed_directory_id'],
          'institutions':[
            {'claimed_institution_id':self.claimed_ids[i],
             'claimed_institution_role':core.ROLES[i],
             'institution_public_key_original_sha256':self.institutions[i]['pub']['sha256'],
             'signed_status_events':self.status_originals[i],
             'signed_provenance_attestations':self.provenance_originals[i]}
            for i in range(2)],
          'additional_signed_checkpoints':self.additional_checkpoints}
        self.provenance_bundle=self.write353('ec366-root-provenance-bundle-'+str(self.file_no),document)

    def args366(self,**change):
        data={**self.args365(),
          'root_provenance_evaluation_utc':util.ut(self.now+timedelta(hours=8,minutes=20)),
          'root_provenance_bundle_file':self.provenance_bundle['path'],
          'expected_root_provenance_bundle_sha256':self.provenance_bundle['sha256'],
          'minimum_retained_origin_registry_sequence':1,
          'minimum_retained_independent_archive_sequence':1,
          'expected_retained_origin_registry_status_head_sha256':self.status_originals[0][-1]['sha256'],
          'expected_retained_independent_archive_status_head_sha256':self.status_originals[1][-1]['sha256'],
          'expected_retained_origin_registry_attestation_head_sha256':self.provenance_originals[0][-1]['sha256'],
          'expected_retained_independent_archive_attestation_head_sha256':self.provenance_originals[1][-1]['sha256'],
          'institution_root_public_key_files':[x['pub']['path'] for x in self.institutions],
          'institution_root_public_key_shas':[x['pub']['sha256'] for x in self.institutions],
          'institution_claimed_ids':list(self.claimed_ids),
          'signed_institution_status_shas':[r['sha256'] for t in self.status_originals for r in t],
          'signed_institution_attestation_shas':[r['sha256'] for t in self.provenance_originals for r in t],
          'additional_signed_checkpoint_shas':[x['original']['sha256'] for x in self.additional_checkpoints]}
        return {**data,**change}

    def test_01_real_two_institution_corroboration_remains_officially_unproven(self):
        self.setup366()
        r=core.audit(**self.args366())
        self.assertEqual(r['exit_code'],2)
        self.assertTrue(r['actual_ec365_through_ec337_signed_originals_replayed'])
        self.assertTrue(r['locally_two_institutions_correlate_on_same_real_directory_lineage'],r['status'])
        self.assertEqual(r['true_verified_institution_status_signatures'],2)
        self.assertEqual(r['true_verified_institution_provenance_signatures'],2)
        self.assertFalse(r['two_caller_pinned_public_keys_prove_legally_independent_institutions'])

    def test_02_real_root_signed_revocation_cannot_be_ignored(self):
        self.setup366()
        self.make_status(0,sequence=1,action='revoke')
        self.rebundle366()
        r=core.audit(**self.args366())
        self.assertTrue(r['signed_institution_root_revocation_or_rotation_visible'])
        self.assertFalse(r['locally_two_institutions_correlate_on_same_real_directory_lineage'])

    def test_03_genuine_signed_competing_provenance_views_remain_visible(self):
        self.setup366()
        self.make_attestation(0,sequence=1,prior=None,changes={
            'observed_merkle_root_sha256':'a'*64})
        self.rebundle366()
        r=core.audit(**self.args366())
        self.assertTrue(r['genuine_signed_institution_provenance_fork_or_dispute_visible'])
        self.assertTrue(r['signed_institution_provenance_contradicts_actual_directory_originals'])

    def test_04_attestation_forged_by_other_institution_denied(self):
        self.setup366()
        doc=json.loads(Path(self.provenance_originals[1][0]['path']).read_bytes())
        doc['signature_institution_ed25519_hex']=self.institutions[0]['private'].sign(
             core.ATTEST_DOMAIN+canonical.canonical({k:v for k,v in doc.items()
                   if k!='signature_institution_ed25519_hex'})).hex()
        self.provenance_originals[1]=[self.write353('ec366-forged-attestation',doc)]
        self.rebundle366()
        with self.assertRaises(errors.AnchorError) as error:
            core.audit(**self.args366())
        self.assertEqual(error.exception.status,'permission_denied')

    def test_05_swapped_retained_institution_root_pin_denied(self):
        self.setup366()
        args=self.args366()
        args['institution_root_public_key_shas']=list(reversed(args[
            'institution_root_public_key_shas']))
        with self.assertRaises(errors.AnchorError):core.audit(**args)

    def test_06_missing_caller_retained_attestation_digest_is_not_good(self):
        self.setup366()
        args=self.args366(signed_institution_attestation_shas=[])
        r=core.audit(**args)
        self.assertTrue(r['independent_institution_head_or_sequence_rollback_visible'])
        self.assertFalse(r['locally_two_institutions_correlate_on_same_real_directory_lineage'])

    def test_07_two_genuine_signed_status_children_produce_visible_fork(self):
        self.setup366()
        self.make_status(0,sequence=1,action='renew')
        self.make_status(0,sequence=1,action='revoke',prior=self.status_originals[0][0]['sha256'])
        self.rebundle366()
        r=core.audit(**self.args366())
        self.assertTrue(r['genuine_institution_status_history_fork_or_gap_visible'])
        self.assertTrue(r['signed_institution_root_revocation_or_rotation_visible'])

    def test_08_provenance_claimed_utc_future_is_not_trusted(self):
        self.setup366()
        self.provenance_originals[1]=[]
        self.make_attestation(1,sequence=1,changes={
            'issued_utc':util.ut(self.now+timedelta(days=1)),
            'expires_utc':util.ut(self.now+timedelta(days=2))})
        self.rebundle366()
        r=core.audit(**self.args366())
        self.assertTrue(r['institution_self_claimed_utc_anomaly_visible'])

    def test_09_genuinely_directory_signed_same_size_fork_not_silent(self):
        self.setup366()
        latest=self.ec365_parent['epoch_lineage_reviews'][-1]
        body={'schema':directory.DIRECTORY_SCHEMA,
          'directory_id':latest['signed_claimed_directory_id'],
          'directory_public_key_original_sha256':latest['actual_directory_key_original_sha256'],
          'tree_size':latest['signed_tree_size'],
          'root_sha256':'a'*64,
          'issued_utc':util.ut(self.now+timedelta(hours=7,minutes=5)),
          'expires_utc':util.ut(self.now+timedelta(days=2))}
        ref=self.signed360('ec366-authentic-signed-split',body,
          self.directory_signer['private'],directory.DIRECTORY_DOMAIN,
          'signature_directory_ed25519_hex')
        self.additional_checkpoints=[{'signer_epoch_index':1,'original':ref}]
        self.rebundle366()
        r=core.audit(**self.args366())
        self.assertTrue(r['genuine_directory_signed_checkpoint_split_view_visible'])
        self.assertEqual(len(r['extra_genuine_directory_signed_checkpoint_reviews']),1)

    def test_10_true_extra_checkpoint_signature_forged_denied(self):
        self.setup366()
        latest=self.ec365_parent['epoch_lineage_reviews'][-1]
        body={'schema':directory.DIRECTORY_SCHEMA,
          'directory_id':latest['signed_claimed_directory_id'],
          'directory_public_key_original_sha256':latest['actual_directory_key_original_sha256'],
          'tree_size':latest['signed_tree_size'],
          'root_sha256':'b'*64,
          'issued_utc':util.ut(self.now+timedelta(hours=7,minutes=5)),
          'expires_utc':util.ut(self.now+timedelta(days=2))}
        ref=self.signed360('ec366-wrong-key-signed-cp',body,
          self.institutions[0]['private'],directory.DIRECTORY_DOMAIN,
          'signature_directory_ed25519_hex')
        self.additional_checkpoints=[{'signer_epoch_index':1,'original':ref}]
        self.rebundle366()
        with self.assertRaises(errors.AnchorError) as err:core.audit(**self.args366())
        self.assertEqual(err.exception.status,'permission_denied')

    def test_11_role_alias_to_actual_directory_signer_is_not_an_independent_root(self):
        self.setup366()
        self.institutions[0]['pub']=self.root_refs[1]
        self.rebundle366()
        args=self.args366()
        with self.assertRaises(errors.AnchorError):core.audit(**args)

    def test_12_real_standalone_isolated_and_unified_cli_semantics(self):
        self.setup366()
        args=self.args366()
        script=Path(__file__).resolve().parents[2]/'scripts'/'ces_cas_root_provenance.py'
        cmd=[sys.executable,'-I','-B',str(script),'audit-root-provenance']
        for k,v in args.items():
            opt='--'+k.replace('_','-')
            if type(v) is list:
                flags=dict(core.NEW_REPEATS)
                flags.update(dict(ec365.NEW_REPEATS))
                # Inherited EC364 and older repeated aliases are generated
                # from the parser's actual action mapping below.
                parser_actions=__import__('ec366_root_provenance.operator',
                    fromlist=['parser']).parser()._actions
                import argparse
                choices=next(a for a in parser_actions if isinstance(a,
                      argparse._SubParsersAction)).choices['audit-root-provenance']
                matching=next((a.option_strings[0] for a in choices._actions
                              if a.dest==k and a.option_strings),None)
                if matching is None:continue
                for item in v:cmd.extend([matching,str(item)])
            elif v is not None:cmd.extend([opt,str(v)])
        child=subprocess.run(cmd,capture_output=True,text=True,timeout=180,
                             check=False)
        self.assertEqual(child.returncode,2,child.stderr+child.stdout[-1000:])
        self.assertTrue(json.loads(child.stdout)['locally_two_institutions_correlate_on_same_real_directory_lineage'])

if __name__=='__main__':
    import unittest
    unittest.main()
