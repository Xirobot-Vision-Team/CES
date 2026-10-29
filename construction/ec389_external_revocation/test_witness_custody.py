#!/usr/bin/env python3
"""EC389 independent local Ed25519 witness/custody cases.

Old EC338/339/340 fixtures sign real local originals. Outer EC388->EC369
receiver engine calls in these tests are explicitly MOCKED, as is the
inherited EC317/318 deep ancestor: not third-party production acceptance.
"""
from __future__ import annotations
import copy
import json
import subprocess
import sys
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec388_historical_revocation import test_revocation_archive as prior_tests
from ec388_historical_revocation import revocation_archive as prior
from . import witness_custody as core


def ref(p):
    p=Path(p)
    return {'path':str(p),'sha256':core.sha(p.read_bytes())}


class LocallySignedExternalRevocationWitnessTests(TestCase):
    @classmethod
    def setUpClass(cls):
        prior_tests.AuthenticHistoricalGrantRetirementTests.setUpClass()
        cls.f=prior_tests.AuthenticHistoricalGrantRetirementTests
        cls.root=cls.f.root
        cls.h=cls.f.h
        cls.p386=copy.deepcopy(cls.f.true386)
        cls.p387=copy.deepcopy(cls.f.true387)
        cls.real_row=copy.deepcopy(cls.f.base_row)

    @classmethod
    def tearDownClass(cls):
        prior_tests.AuthenticHistoricalGrantRetirementTests.tearDownClass()

    def _archive(self,name,doc):
        p=self.root/name
        p.write_bytes(canonical.canonical(doc))
        return ref(p)

    def setUp(self):
        self.h.role_paths={}
        self.row=copy.deepcopy(self.real_row)
        self.p388=copy.deepcopy(self.real_row)
        self.p388_history=prior._channel(self.p388,self.p387,self.p386,self.read)
        self.old=copy.deepcopy(self.p388_history['ec339_verified_role_histories'][0])
        self.revoked=self.old['additional_signed_statuses'][1]
        self.witness_priv=Ed25519PrivateKey.generate()
        self.custody_priv=Ed25519PrivateKey.generate()
        self.pub_w=self.witness_priv.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.pub_c=self.custody_priv.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        wkey=self.root/('ec389-witness-'+self._testMethodName+'.raw')
        ckey=self.root/('ec389-custodian-'+self._testMethodName+'.raw')
        wkey.write_bytes(self.pub_w);ckey.write_bytes(self.pub_c)
        self.roster_doc={'schema':core.ROSTER_SCHEMA,
            'claimed_directory_lineage_id':'Lineage388',
            'witnesses':[{'signer_id':'ExternalWitness1','public_hex':self.pub_w.hex(),
                          'public_key_original':ref(wkey)}],
            'custodians':[{'signer_id':'ExternalCustodian1','public_hex':self.pub_c.hex(),
                           'public_key_original':ref(ckey)}]}
        self.roster_ref=self._archive('ec389-verifier-roster-'+self._testMethodName+'.json',
                                    self.roster_doc)
        self.keys=core._roster(self.roster_doc,self.roster_ref,self.roster_ref['sha256'],
                               self.read,set())
        self.channel={'tsa_channel_id':self.p388['tsa_channel_id'],
            'external_revocation_publication_and_custody_originals':[]}
        self.wclaim={'schema':core.WITNESS_CLAIM_SCHEMA,
            'directory_lineage_id':'Lineage388','tsa_channel_id':self.channel['tsa_channel_id'],
            'first_published_epoch_index':0,'role':self.old['role'],
            'ec338_actor_receipt_original_sha256':self.old['actor_receipt_sha256'],
            'ec339_issuer_grant_original_sha256':self.old['issuer_grant_sha256'],
            'ec339_signed_revoked_status_original_sha256':self.revoked['sha256'],
            'ec339_verifier_challenge_sha256':self.revoked['verifier_challenge_sha256'],
            'ec339_signed_as_of_utc':self.revoked['as_of_utc'],
            'ec339_revoked_effective_utc':self.revoked['revoked_effective_utc'],
            'witness_id':'ExternalWitness1','publication_sequence':1,
            'previous_signed_witness_original_sha256':core.ZERO,
            'claimed_published_utc':'2026-10-25T11:20:00Z'}
        self.cclaim={'schema':core.CUSTODY_CLAIM_SCHEMA,
            'directory_lineage_id':'Lineage388','tsa_channel_id':self.channel['tsa_channel_id'],
            'first_published_epoch_index':0,'role':self.old['role'],
            'ec339_signed_revoked_status_original_sha256':self.revoked['sha256'],
            'signed_witness_original_sha256':'ff'*32,
            'custodian_id':'ExternalCustodian1','custody_sequence':1,
            'previous_signed_custody_original_sha256':core.ZERO,
            'claimed_deposited_utc':'2026-10-25T11:25:00Z'}
        self.pair=self.make_pair()
        self.channel['external_revocation_publication_and_custody_originals']=[self.pair]

    def read(self,ref_dict,label,cap):
        p=Path(ref_dict['path'])
        raw=p.read_bytes()
        core.need(len(raw)<=cap and core.sha(raw)==ref_dict['sha256'],
                  'TEST_ORIGINAL_SHA_MISMATCH','permission_denied')
        return raw

    def make_pair(self,w=None,c=None,tag=None,wpriv=None,cpriv=None):
        w=copy.deepcopy(self.wclaim if w is None else w)
        c=copy.deepcopy(self.cclaim if c is None else c)
        tag=tag or self._testMethodName+'-'+str(len(self.channel['external_revocation_publication_and_custody_originals']))
        doc={'schema':core.WITNESS_SCHEMA,'claim':w,
             'signature_ed25519':(wpriv or self.witness_priv).sign(
                  core.WITNESS_DOMAIN+canonical.canonical(w)).hex()}
        wref=self._archive('ec389-signed-witness-'+tag+'.json',doc)
        c['signed_witness_original_sha256']=wref['sha256'] if c.get('signed_witness_original_sha256')=='ff'*32 else c['signed_witness_original_sha256']
        doc={'schema':core.CUSTODY_SCHEMA,'claim':c,
             'signature_ed25519':(cpriv or self.custody_priv).sign(
                  core.CUSTODY_DOMAIN+canonical.canonical(c)).hex()}
        cref=self._archive('ec389-signed-custody-'+tag+'.json',doc)
        return {'signed_witness_original':wref,'signed_custody_original':cref}

    def result(self,idx=0,channel=None):
        return core._channel(channel or self.channel,self.p388,self.p388_history,
                             self.keys,self.read,idx,'Lineage388')

    def denied(self,idx=0):
        with self.assertRaises(errors.AnchorError):self.result(idx)

    def replace(self,w=None,c=None):
        self.channel['external_revocation_publication_and_custody_originals']=[
            self.make_pair(w,c,tag=self._testMethodName+'-replacement')]

    def test_01_real_external_signed_witness_and_custodian_bind_old_revocation(self):
        r=self.result()
        self.assertEqual(r['genuine_signed_external_publication_custody_pair_count'],1)
        self.assertEqual(r['authentic_parent_ec339_old_revoked_status_count'],1)
        self.assertFalse(r['missing_external_signed_witness_custody_for_visible_revocations'])
        self.assertFalse(r['signed_claimed_clock_order_disagreement'])

    def test_02_visible_revoked_status_without_custody_remains_gap(self):
        self.channel['external_revocation_publication_and_custody_originals']=[]
        self.assertTrue(self.result()['missing_external_signed_witness_custody_for_visible_revocations'])

    def test_03_witness_must_bind_original_revoked_sha(self):
        w=copy.deepcopy(self.wclaim);w['ec339_signed_revoked_status_original_sha256']='ab'*32
        self.replace(w);self.denied()

    def test_04_witness_cannot_substitute_grant_original_sha(self):
        w=copy.deepcopy(self.wclaim);w['ec339_issuer_grant_original_sha256']='ac'*32
        self.replace(w);self.denied()

    def test_05_witness_cannot_substitute_actor_receipt(self):
        w=copy.deepcopy(self.wclaim);w['ec338_actor_receipt_original_sha256']='ad'*32
        self.replace(w);self.denied()

    def test_06_witness_challenge_must_match_verified_old_ec339(self):
        w=copy.deepcopy(self.wclaim);w['ec339_verifier_challenge_sha256']='af'*32
        self.replace(w);self.denied()

    def test_07_witness_signed_status_as_of_must_match(self):
        w=copy.deepcopy(self.wclaim);w['ec339_signed_as_of_utc']='2026-10-25T11:12:00Z'
        self.replace(w);self.denied()

    def test_08_witness_revocation_effective_must_match(self):
        w=copy.deepcopy(self.wclaim);w['ec339_revoked_effective_utc']='2026-10-25T11:03:00Z'
        self.replace(w);self.denied()

    def test_09_external_signed_lineage_cannot_change(self):
        w=copy.deepcopy(self.wclaim);w['directory_lineage_id']='IndependentLineage'
        self.replace(w);self.denied()

    def test_10_external_signed_channel_cannot_change(self):
        w=copy.deepcopy(self.wclaim);w['tsa_channel_id']='replaced-channel'
        self.replace(w);self.denied()

    def test_11_external_witness_role_cannot_be_swapped(self):
        w=copy.deepcopy(self.wclaim);w['role']='carrier'
        self.replace(w);self.denied()

    def test_12_witness_must_have_real_ed25519_signature(self):
        doc=json.loads(Path(self.pair['signed_witness_original']['path']).read_bytes())
        doc['signature_ed25519']='a1'*64
        self.pair['signed_witness_original']=self._archive('ec389-tampered-w-signature.json',doc)
        self.denied()

    def test_13_custody_must_have_distinct_valid_ed25519_signature(self):
        doc=json.loads(Path(self.pair['signed_custody_original']['path']).read_bytes())
        doc['signature_ed25519']='a2'*64
        self.pair['signed_custody_original']=self._archive('ec389-tampered-c-signature.json',doc)
        self.denied()

    def test_14_custody_cannot_bind_unrelated_witness(self):
        c=copy.deepcopy(self.cclaim);c['signed_witness_original_sha256']='aa'*32
        self.replace(c=c);self.denied()

    def test_15_witness_and_custodian_key_reuse_denied(self):
        roster=copy.deepcopy(self.roster_doc)
        roster['custodians'][0]['public_hex']=self.pub_w.hex()
        roster['custodians'][0]['public_key_original']=roster['witnesses'][0]['public_key_original']
        with self.assertRaises(errors.AnchorError):core._roster(roster,self.roster_ref,
            self.roster_ref['sha256'],self.read,set())

    def test_16_external_witness_cannot_reuse_old_issuer_key(self):
        roster=copy.deepcopy(self.roster_doc)
        with self.assertRaises(errors.AnchorError):core._roster(roster,self.roster_ref,
            self.roster_ref['sha256'],self.read,{self.pub_w.hex()})

    def test_17_pinned_verifier_key_raw_copy_must_equal_signed_roster(self):
        roster=copy.deepcopy(self.roster_doc)
        roster['witnesses'][0]['public_hex']='12'*32
        with self.assertRaises(errors.AnchorError):core._roster(roster,self.roster_ref,
            self.roster_ref['sha256'],self.read,set())

    def test_18_duplicate_witness_custody_pair_is_denied(self):
        self.channel['external_revocation_publication_and_custody_originals'].append(
             copy.deepcopy(self.pair))
        self.denied()

    def test_19_noncanonical_witness_json_is_denied(self):
        src=Path(self.pair['signed_witness_original']['path'])
        other=self.root/'ec389-witness-noncanonical.json'
        other.write_bytes(src.read_bytes()+b' ')
        self.pair['signed_witness_original']=ref(other)
        self.denied()

    def test_20_chained_witness_previous_sha_must_be_genuine(self):
        w=copy.deepcopy(self.wclaim);w['previous_signed_witness_original_sha256']='bd'*32
        self.replace(w);self.denied()

    def test_21_chained_custody_previous_sha_must_be_genuine(self):
        c=copy.deepcopy(self.cclaim);c['previous_signed_custody_original_sha256']='ce'*32
        self.replace(c=c);self.denied()

    def test_22_signed_external_publication_sequence_cannot_jump(self):
        w=copy.deepcopy(self.wclaim);w['publication_sequence']=2
        self.replace(w);self.denied()

    def test_23_signed_external_custody_sequence_cannot_jump(self):
        c=copy.deepcopy(self.cclaim);c['custody_sequence']=2
        self.replace(c=c);self.denied()

    def test_24_future_epoch_claim_must_not_be_accepted_as_past(self):
        w=copy.deepcopy(self.wclaim);w['first_published_epoch_index']=2
        self.replace(w);self.denied()

    def test_25_witness_claimed_time_before_old_status_as_of_is_adverse(self):
        w=copy.deepcopy(self.wclaim);w['claimed_published_utc']='2026-10-25T11:08:00Z'
        self.replace(w)
        self.assertTrue(self.result()['signed_claimed_clock_order_disagreement'])

    def test_26_custody_claimed_earlier_than_publication_is_adverse(self):
        c=copy.deepcopy(self.cclaim);c['claimed_deposited_utc']='2026-10-25T11:19:00Z'
        self.replace(c=c)
        self.assertTrue(self.result()['signed_claimed_clock_order_disagreement'])

    def test_27_external_publication_cannot_point_to_old_active_status(self):
        w=copy.deepcopy(self.wclaim)
        w['ec339_signed_revoked_status_original_sha256']=self.old['additional_signed_statuses'][0]['sha256']
        self.replace(w);self.denied()

    def test_28_reused_old_original_in_later_epoch_is_observable_not_new_issue(self):
        r=self.result(idx=1)
        self.assertEqual(r['verified_signed_external_publication_custody'][0][
            'first_published_epoch_index'],0)
        self.assertEqual(r['signed_external_witness_head_sha256'],self.pair[
            'signed_witness_original']['sha256'])

    def test_29_outside_roster_sha_is_required_for_verifier_identity(self):
        with self.assertRaises(errors.AnchorError):core._roster(self.roster_doc,self.roster_ref,
             'a8'*32,self.read,set())

    def test_30_external_custody_must_match_true_old_channel(self):
        c=copy.deepcopy(self.cclaim);c['tsa_channel_id']='other-channel'
        self.replace(c=c);self.denied()

    def test_31_receiver_archive_does_not_accept_unlisted_extra_fields(self):
        self.channel['attested_institution']='FalseTrust'
        self.denied()

    def test_32_real_parent_ec388_contract_rejects_caller_fabricated_pass(self):
        with self.assertRaises(errors.AnchorError):core._parent({'schema':prior.RESULT_SCHEMA,
            'status':'passed','exit_code':2},1)

    def _outer(self):
        report387,opts=prior_tests.AuthenticHistoricalGrantRetirementTests._outer(self)
        a=patch.object(prior,'_inputs',return_value={})
        b=patch.object(prior.parent,'audit',return_value=report387)
        c=patch.object(prior.p379,'_old_sender_labels')
        with a,b,c:
            derived=prior.derive_inventory(**opts)
            ep=derived['historical_ec339_retirement_epoch_reviews'][0]
            opts['historical_ec339_retirement_role_inventory_shas']=[ep[
                  'old_ec339_role_original_inventory_sha256']]
            opts['historical_ec339_revocation_transition_inventory_shas']=[ep[
                  'old_ec339_revocation_transition_inventory_sha256']]
            opts['expected_retained_historical_ec339_retirement_revocation_inventory_sha256']=(
                 derived['receiver_verified_old_ec339_retirement_inventory_sha256'])
            actual=prior.audit(**opts)
        archive=self._archive('ec389-test-receiver-bundle-'+self._testMethodName+'.json',{
            'schema':core.BUNDLE_SCHEMA,
            'parent_ec388_canonical_result_sha256':core.sha(canonical.canonical(actual)),
            'ec388_historical_revocation_archive_original_sha256':opts[
                'expected_historical_ec339_retirement_revocation_archive_bundle_sha256'],
            'claimed_directory_lineage_id':'Lineage388',
            'external_verifier_roster_original':self.roster_ref,
            'epochs':[{'epoch_index':0,'channels':[copy.deepcopy(self.channel)]}]})
        opts.update({'historical_ec339_external_witness_custody_archive_bundle_file':archive['path'],
           'expected_historical_ec339_external_witness_custody_archive_bundle_sha256':archive['sha256'],
           'expected_outside_retained_ec389_external_verifier_roster_sha256':self.roster_ref['sha256'],
           'historical_ec339_external_publication_inventory_shas':['ad'*32],
           'historical_ec339_external_custody_inventory_shas':['af'*32],
           'minimum_historical_ec339_external_witness_custody_pair_counts':[1]})
        return actual,opts

    def _patch_outer(self,actual):
        return (patch.object(core,'_inputs',return_value={}),
                patch.object(core.parent,'audit',return_value=actual),
                patch.object(core.p379,'_old_sender_labels'))

    def test_33_outer_parent_mocked_derive_real_two_external_signatures(self):
        actual,opts=self._outer();a,b,c=self._patch_outer(actual)
        with a,b,c:res=core.derive_inventory(**opts)
        self.assertEqual(res['exit_code'],2)
        self.assertEqual(res['genuine_external_signed_witness_custody_pair_count'],1)
        self.assertTrue(res[core.FLAGS[1]])
        self.assertFalse(res[core.FLAGS[3]])
        self.assertFalse(res['caller_roster_and_sha_independently_offsite_certified'])

    def test_34_exact_external_sha_pins_remain_unresolved_not_pass(self):
        actual,opts=self._outer();a,b,c=self._patch_outer(actual)
        with a,b,c:
            d=core.derive_inventory(**opts)
            ep=d['historical_ec339_external_witness_epoch_reviews'][0]
            opts['historical_ec339_external_publication_inventory_shas']=[ep[
                'external_publication_inventory_sha256']]
            opts['historical_ec339_external_custody_inventory_shas']=[ep[
                'external_custody_inventory_sha256']]
            opts['expected_retained_historical_ec339_external_witness_custody_inventory_sha256']=(
                d['receiver_verified_external_revocation_witness_custody_inventory_sha256'])
            audited=core.audit(**opts)
        self.assertEqual(audited['exit_code'],2)
        self.assertTrue(audited['local_external_signed_revocation_publication_custody_consistent'])
        self.assertTrue(audited[core.FLAGS[7]] and audited[core.FLAGS[8]])
        self.assertNotIn('unsigned_external_ec339_revocation_witness_custody_inventory',audited)

    def test_35_signatures_not_a_proof_of_external_trust_or_current_issuer_grant(self):
        actual,opts=self._outer();a,b,c=self._patch_outer(actual)
        with a,b,c:r=core.derive_inventory(**opts)
        self.assertTrue(all(r[k] is False for k in core.NEGATIVES))
        self.assertEqual(r['status'],core.OUTCOMES[1]+'_unresolved')
        self.assertFalse(r['ec339_to_ec337_full_independent_unmocked_external_acceptance_performed'])

    def _outer_two_epoch(self,drop_second=False):
        actual,opts=self._outer()
        def rewrite(key_file,key_sha,mutate,tag):
            source=json.loads(Path(opts[key_file]).read_bytes())
            mutate(source)
            new=self._archive('ec389-2epoch-'+tag+'-'+self._testMethodName+'.json',source)
            opts[key_file]=new['path'];opts[key_sha]=new['sha256']
            return new
        parent_root=rewrite(
            'historical_ec341_signed_root_conflict_archive_bundle_file',
            'expected_historical_ec341_signed_root_conflict_archive_bundle_sha256',
            lambda doc:doc['epochs'].append({'epoch_index':1,
                'channels':copy.deepcopy(doc['epochs'][0]['channels'])}),'ec386')
        def mut_rot(doc):
            doc['ec386_historical_root_archive_original_sha256']=parent_root['sha256']
            doc['epochs'].append({'epoch_index':1,
                'channels':copy.deepcopy(doc['epochs'][0]['channels'])})
        rotated=rewrite('historical_ec340_signed_rotation_archive_bundle_file',
            'expected_historical_ec340_signed_rotation_archive_bundle_sha256',
            mut_rot,'ec387')
        def mut_old(doc):
            doc['ec387_historical_rotation_archive_original_sha256']=rotated['sha256']
            doc['epochs'].append({'epoch_index':1,
                'channels':copy.deepcopy(doc['epochs'][0]['channels'])})
        old=rewrite('historical_ec339_retirement_revocation_archive_bundle_file',
            'expected_historical_ec339_retirement_revocation_archive_bundle_sha256',
            mut_old,'ec388')
        def mut_sender_index(doc):
            epoch=copy.deepcopy(doc['epochs'][0])
            # Each epoch's sender-label index original remains a separate
            # bounded source (EC388 rejects reopening a forbidden sender path).
            label=self._archive('ec389-2epoch-sender-label-'+self._testMethodName+'.json',
                                {'schema':'dummy','epoch_index':1})
            epoch['ec353_publication_bundle_original']=label
            doc['epochs'].append(epoch)
        rewrite('historical_transparency_archive_bundle_file',
            'expected_historical_transparency_archive_bundle_sha256',
            mut_sender_index,'ec377')
        actual=copy.deepcopy(actual)
        actual['historical_ec339_retirement_archive_original_sha256']=old['sha256']
        copy_epoch=copy.deepcopy(actual['historical_ec339_retirement_epoch_reviews'][0])
        copy_epoch['epoch_index']=1
        actual['historical_ec339_retirement_epoch_reviews'].append(copy_epoch)
        original_external=json.loads(Path(opts[
            'historical_ec339_external_witness_custody_archive_bundle_file']).read_bytes())
        original_external['parent_ec388_canonical_result_sha256']=core.sha(canonical.canonical(actual))
        original_external['ec388_historical_revocation_archive_original_sha256']=old['sha256']
        epoch1=copy.deepcopy(original_external['epochs'][0])
        epoch1['epoch_index']=1
        if drop_second:
            epoch1['channels'][0]['external_revocation_publication_and_custody_originals']=[]
        original_external['epochs'].append(epoch1)
        new=self._archive('ec389-2epoch-external-'+self._testMethodName+'.json',original_external)
        opts['historical_ec339_external_witness_custody_archive_bundle_file']=new['path']
        opts['expected_historical_ec339_external_witness_custody_archive_bundle_sha256']=new['sha256']
        opts['historical_directory_root_shas']=['aa'*32,'ab'*32]
        opts['historical_ec339_external_publication_inventory_shas']=['ad'*32,'ad'*32]
        opts['historical_ec339_external_custody_inventory_shas']=['af'*32,'af'*32]
        opts['minimum_historical_ec339_external_witness_custody_pair_counts']=[1,1]
        return actual,opts

    def test_37_outer_two_epoch_signed_original_prefix_is_preserved(self):
        actual,opts=self._outer_two_epoch();a,b,c=self._patch_outer(actual)
        with a,b,c:r=core.derive_inventory(**opts)
        self.assertEqual(r['exit_code'],2)
        self.assertEqual(r['genuine_external_signed_witness_custody_pair_count'],2)
        self.assertFalse(r[core.FLAGS[6]])
        self.assertFalse(r[core.FLAGS[3]])

    def test_38_outer_two_epoch_rollback_is_adverse_not_silent(self):
        actual,opts=self._outer_two_epoch(drop_second=True);a,b,c=self._patch_outer(actual)
        with a,b,c:r=core.derive_inventory(**opts)
        self.assertEqual(r['exit_code'],2)
        self.assertTrue(r[core.FLAGS[6]])
        self.assertTrue(r[core.FLAGS[3]])
        self.assertFalse(r['local_external_signed_revocation_publication_custody_consistent'])

    def test_39_outer_parent_signed_inventory_drift_after_audit_is_denied(self):
        actual,opts=self._outer();actual['historical_ec339_retirement_epoch_reviews'][0][
            'old_ec339_role_original_inventory_sha256']='b2'*32
        a,b,c=self._patch_outer(actual)
        with a,b,c:
            with self.assertRaises(errors.AnchorError):core.derive_inventory(**opts)

    def test_40_second_channel_must_have_its_own_channel_bound_signed_pair(self):
        other=copy.deepcopy(self.p388)
        other['tsa_channel_id']=self.p388['tsa_channel_id']+'-z'
        p387=copy.deepcopy(self.p387);p387['tsa_channel_id']=other['tsa_channel_id']
        p386=copy.deepcopy(self.p386);p386['tsa_channel_id']=other['tsa_channel_id']
        other_result=prior._channel(other,p387,p386,self.read)
        w=copy.deepcopy(self.wclaim);c=copy.deepcopy(self.cclaim)
        w['tsa_channel_id']=c['tsa_channel_id']=other['tsa_channel_id']
        witness_custody=self.make_pair(w,c,tag=self._testMethodName+'-second')
        alt={'tsa_channel_id':other['tsa_channel_id'],
             'external_revocation_publication_and_custody_originals':[witness_custody]}
        r=core._channel(alt,other,other_result,self.keys,self.read,0,'Lineage388')
        self.assertEqual(r['genuine_signed_external_publication_custody_pair_count'],1)
        self.assertFalse(r['missing_external_signed_witness_custody_for_visible_revocations'])
        alt['external_revocation_publication_and_custody_originals']=[self.pair]
        with self.assertRaises(errors.AnchorError):core._channel(
             alt,other,other_result,self.keys,self.read,0,'Lineage388')

    def test_36_fixed_isolated_standalone_help_has_no_private_signing_controls(self):
        base=Path(__file__).resolve().parents[2]
        for file_name,cmd in (
            ('ces_cas_historical_ec339_external_witness_archive.py',
             'audit-historical-ec339-external-witness-archive'),
            ('ces_next.py','audit-historical-ec339-external-witness-archive')):
            p=subprocess.run([sys.executable,'-I','-B',str(base/'scripts'/file_name),cmd,
                '--help'],capture_output=True,text=True,timeout=40)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn('--expected-outside-retained-ec389-external-verifier-roster-sha256',p.stdout)
            self.assertNotIn('--private-key',p.stdout)

if __name__=='__main__':main()
