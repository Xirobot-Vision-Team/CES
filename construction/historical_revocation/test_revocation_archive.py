#!/usr/bin/env python3
"""EC388 original-format signature tests (old EC317/318 ancestry MOCKED).

Real locally issued Ed25519 EC338 actor, EC339 issuer and EC340 retirement
originals. Only the explicitly labelled outer receiver cases mock the live
EC387->EC369 parent; never treat those cases as production acceptance.
"""
from __future__ import annotations
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from offline_authority import authority as old339
from historical_rotation import test_rotation_archive as ancestor
from . import revocation_archive as core


def ref(p):
    p=Path(p)
    return {'path':str(p),'sha256':core.sha(p.read_bytes())}


class AuthenticHistoricalGrantRetirementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ancestor.AuthenticOldEpochRotationTests.setUpClass()
        cls.f=ancestor.AuthenticOldEpochRotationTests
        cls.root=cls.f.root
        cls.h=cls.f.h
        cls.true387=copy.deepcopy(cls.f.base_row)
        cls.true386=copy.deepcopy(cls.f.source)
        cls.manifest=copy.deepcopy(cls.f.manifest)
        cls.context=cls.manifest['context']
        cls.first=cls.manifest['hops'][0]
        cls.hist=cls.manifest['history']
        cls.role_rows=[]
        cls.boundary_status=[]
        for i,role in enumerate(old339.ROLES):
            entry=cls.true387['ec339_original_signed_role_history'][i]
            cfg={'role':role,'policy_file':cls.context['policy_file'],
                 'expected_policy_sha256':cls.context['expected_policy_sha256'],
                 'authority_roster_file':cls.context['authority_roster_file'],
                 'expected_authority_roster_sha256':cls.context['expected_authority_roster_sha256'],
                 'grant_file':entry['grant_original']['path'],
                 'expected_grant_sha256':entry['grant_original']['sha256'],
                 'private_key_file':str(Path(cls.context['policy_file']).parent /
                                        ('ec339-'+role+'-issuer-key.bin'))}
            assert Path(cfg['private_key_file']).is_file()
            name=cls.root/('ec388-'+role+'-original-boundary-active.json')
            result=old339.issue_status(out=str(name),
                verifier_challenge_sha256=f'{i+121:064x}',state='active',
                as_of_utc='2026-10-25T10:45:00Z',expires_utc='2026-10-25T11:20:00Z',
                **cfg)
            assert result['exit_code']==2
            status={'signed_status_original':ref(name),
                    'verifier_challenge_sha256':f'{i+121:064x}',
                    'evaluation_utc':'2026-10-25T11:00:00Z'}
            cls.boundary_status.append(status)
            cls.role_rows.append({'role':role,
                'actor_receipt_original':copy.deepcopy(entry['receipt_original']),
                'issuer_grant_original':copy.deepcopy(entry['grant_original']),
                'baseline_status_original':copy.deepcopy(entry['status_original']),
                'additional_challenged_status_originals':[status]})
        # A genuine, separately signed 'revoked' status, claimed AFTER root
        # retirement, is historical evidence only, never new-root authority.
        later=cls.root/'ec388-sender-historical-revoked-status.json'
        result=old339.issue_status(out=str(later),
            verifier_challenge_sha256='b2'*32,state='revoked',
            as_of_utc='2026-10-25T11:10:00Z',expires_utc='2026-10-25T11:50:00Z',
            revoked_effective_utc='2026-10-25T11:05:00Z',
            private_key_file=str(Path(cls.context['policy_file']).parent /
                                   'ec339-sender-issuer-key.bin'),
            policy_file=cls.context['policy_file'],
            expected_policy_sha256=cls.context['expected_policy_sha256'],
            authority_roster_file=cls.context['authority_roster_file'],
            expected_authority_roster_sha256=cls.context['expected_authority_roster_sha256'],
            grant_file=cls.role_rows[0]['issuer_grant_original']['path'],
            expected_grant_sha256=cls.role_rows[0]['issuer_grant_original']['sha256'],
            role='sender')
        assert result['exit_code']==2
        cls.later_ref=ref(later)
        cls.role_rows[0]['additional_challenged_status_originals'].append({
            'signed_status_original':cls.later_ref,
            'verifier_challenge_sha256':'b2'*32,
            'evaluation_utc':'2026-10-25T11:15:00Z'})
        cls.base_row={
            'tsa_channel_id':cls.true387['tsa_channel_id'],
            'ec338_policy_original':copy.deepcopy(cls.true387['ec340_legacy_policy_original']),
            'ec339_issuer_roster_original':copy.deepcopy(
                cls.true387['ec339_predecessor_authority_roster_original']),
            'ec340_successor_roster_original':copy.deepcopy(
                cls.true387['ec340_epoch2_successor_roster_original']),
            'ec340_retirement_observation_original':copy.deepcopy(
                cls.true387['ec340_signed_retirement_observation_original']),
            'ec339_role_retirement_reviews':cls.role_rows}

    @classmethod
    def tearDownClass(cls):
        ancestor.AuthenticOldEpochRotationTests.tearDownClass()

    def setUp(self):
        self.row=copy.deepcopy(self.base_row)
        self.p387=copy.deepcopy(self.true387)
        self.p386=copy.deepcopy(self.true386)
        self.h.role_paths={}

    def tearDown(self):self.h.role_paths={}

    def run_channel(self):
        self.h.role_paths={}
        return core._channel(self.row,self.p387,self.p386,self.h.read_original)

    def denied(self):
        with self.assertRaises(errors.AnchorError):self.run_channel()

    def _issue(self,role,*,name,challenge,state,as_of,expires,revoked=None):
        i=old339.ROLES.index(role)
        grant=self.true387['ec339_original_signed_role_history'][i]['grant_original']
        out=self.root/name
        result=old339.issue_status(out=str(out),
            private_key_file=str(Path(self.context['policy_file']).parent /
                                   ('ec339-'+role+'-issuer-key.bin')),
            role=role,policy_file=self.context['policy_file'],
            expected_policy_sha256=self.context['expected_policy_sha256'],
            authority_roster_file=self.context['authority_roster_file'],
            expected_authority_roster_sha256=self.context['expected_authority_roster_sha256'],
            grant_file=grant['path'],expected_grant_sha256=grant['sha256'],
            verifier_challenge_sha256=challenge,state=state,
            as_of_utc=as_of,expires_utc=expires,revoked_effective_utc=revoked)
        self.assertEqual(result['exit_code'],2)
        return {'signed_status_original':ref(out),'verifier_challenge_sha256':challenge,
                'evaluation_utc':as_of}

    def test_01_true_four_actor_receipts_issuer_grants_active_boundary_and_revocation(self):
        r=self.run_channel()
        self.assertTrue(r['full_original_ec339_role_retirement_replay'])
        self.assertEqual(r['ec338_signed_actor_receipt_count'],4)
        self.assertEqual(r['ec339_challenged_retirement_status_count'],4)
        self.assertEqual(r['ec339_signed_revocation_transition_count'],1)
        self.assertFalse(r['visible_role_revocation_conflict'])
        self.assertFalse(r['missing_retirement_boundary_status'])
        self.assertEqual(r['ec339_verified_role_histories'][0]['additional_signed_statuses'][1]['state'],
                         'revoked')

    def test_02_issuer_grant_must_reuse_true_ec387_original(self):
        self.row['ec339_role_retirement_reviews'][0]['issuer_grant_original']['sha256']='bc'*32
        self.denied()

    def test_03_old_actor_receipt_must_reuse_true_ec387_original(self):
        self.row['ec339_role_retirement_reviews'][2]['actor_receipt_original']['sha256']='bd'*32
        self.denied()

    def test_04_baseline_challenged_status_must_reuse_true_parent(self):
        self.row['ec339_role_retirement_reviews'][3]['baseline_status_original']=(
            copy.deepcopy(self.row['ec339_role_retirement_reviews'][0]['baseline_status_original']))
        self.denied()

    def test_05_root_successor_cannot_be_substituted_by_claimed_epoch(self):
        self.row['ec340_successor_roster_original']['sha256']='be'*32
        self.denied()

    def test_06_history_must_be_from_real_ec386_manifest(self):
        self.p386['ec341_lineage_manifest_original']['sha256']='cf'*32
        self.denied()

    def test_07_role_order_cannot_be_rearranged(self):
        rows=self.row['ec339_role_retirement_reviews'];rows[0],rows[1]=rows[1],rows[0]
        self.denied()

    def test_08_independently_signed_boundary_status_sha_tamper_denied(self):
        self.row['ec339_role_retirement_reviews'][1]['additional_challenged_status_originals'][0][
            'signed_status_original']['sha256']='af'*32
        self.denied()

    def test_09_challenge_from_another_status_cannot_authorize_this_status(self):
        self.row['ec339_role_retirement_reviews'][1]['additional_challenged_status_originals'][0][
            'verifier_challenge_sha256']='a2'*32
        self.denied()

    def test_10_wrong_evaluation_utc_outside_signed_window_denied(self):
        self.row['ec339_role_retirement_reviews'][1]['additional_challenged_status_originals'][0][
            'evaluation_utc']='2026-10-25T12:00:00Z'
        self.denied()

    def test_11_baseline_replay_cannot_be_framed_as_new_boundary_evidence(self):
        a=self.row['ec339_role_retirement_reviews'][1]
        a['additional_challenged_status_originals'][0]['signed_status_original']=copy.deepcopy(
            a['baseline_status_original'])
        self.denied()

    def test_12_reused_challenge_even_with_new_signature_denied(self):
        a=self.row['ec339_role_retirement_reviews'][1]
        a['additional_challenged_status_originals'][0]['verifier_challenge_sha256']=self.first['verifier_challenge_sha256']
        self.denied()

    def test_13_missing_boundary_is_unresolved_not_fabricated(self):
        self.row['ec339_role_retirement_reviews'][2]['additional_challenged_status_originals']=[]
        r=self.run_channel()
        self.assertTrue(r['missing_retirement_boundary_status'])
        self.assertEqual(r['ec339_challenged_retirement_status_count'],3)

    def test_14_future_only_revocation_cannot_substitute_for_boundary_status(self):
        self.row['ec339_role_retirement_reviews'][0]['additional_challenged_status_originals'].pop(0)
        r=self.run_channel()
        self.assertTrue(r['missing_retirement_boundary_status'])
        self.assertEqual(r['ec339_signed_revocation_transition_count'],1)

    def test_15_revoked_then_active_status_is_visible_conflict_not_reauthorization(self):
        signed=self._issue('receiver',name='ec388-receiver-boundary-revoked.json',
            challenge='c3'*32,state='revoked',as_of='2026-10-25T10:50:00Z',
            expires='2026-10-25T11:15:00Z',revoked='2026-10-25T10:48:00Z')
        self.row['ec339_role_retirement_reviews'][2]['additional_challenged_status_originals']=[signed]
        late=self._issue('receiver',name='ec388-receiver-post-active.json',
            challenge='c4'*32,state='active',as_of='2026-10-25T11:30:00Z',
            expires='2026-10-25T12:00:00Z')
        self.row['ec339_role_retirement_reviews'][2]['additional_challenged_status_originals'].append(late)
        r=self.run_channel()
        self.assertTrue(r['visible_role_revocation_conflict'])
        self.assertEqual(r['ec339_challenged_retirement_status_count'],4)

    def test_27_boundary_signed_revocation_is_one_real_transition(self):
        signed=self._issue('receiver',name='ec388-receiver-boundary-revoked-counted.json',
            challenge='d7'*32,state='revoked',as_of='2026-10-25T10:50:00Z',
            expires='2026-10-25T11:15:00Z',revoked='2026-10-25T10:48:00Z')
        self.row['ec339_role_retirement_reviews'][2]['additional_challenged_status_originals']=[signed]
        r=self.run_channel()
        self.assertEqual(r['ec339_challenged_retirement_status_count'],4)
        self.assertEqual(r['ec339_signed_revocation_transition_count'],2)
        self.assertFalse(r['visible_role_revocation_conflict'])

    def test_16_future_effective_revocation_is_rejected_even_if_signed(self):
        signed=self._issue('receiver',name='ec388-receiver-future-revocation.json',
            challenge='c5'*32,state='revoked',as_of='2026-10-25T10:50:00Z',
            expires='2026-10-25T11:15:00Z',revoked='2026-10-25T11:01:00Z')
        self.row['ec339_role_retirement_reviews'][2]['additional_challenged_status_originals']=[signed]
        self.denied()

    def test_17_stale_status_expired_before_retirement_cannot_fill_evidence(self):
        signed=self._issue('carrier',name='ec388-carrier-stale-status.json',
            challenge='c6'*32,state='active',as_of='2026-10-25T10:21:00Z',
            expires='2026-10-25T10:59:59Z')
        self.row['ec339_role_retirement_reviews'][1]['additional_challenged_status_originals']=[signed]
        self.denied()

    def test_18_out_of_order_additional_status_cannot_rewrite_claimed_history(self):
        a=self.row['ec339_role_retirement_reviews'][0]['additional_challenged_status_originals']
        a[0],a[1]=a[1],a[0]
        self.denied()

    def test_19_signed_status_original_byte_change_denied(self):
        p=Path(self.boundary_status[1]['signed_status_original']['path']);before=p.read_bytes()
        try:
            p.write_bytes(before+b' ')
            self.denied()
        finally:p.write_bytes(before)

    def test_20_absent_parent_cannot_be_replaced_with_signed_history(self):
        self.p387['ec340_legacy_policy_original']=None
        self.denied()

    def test_21_true_missing_parent_sources_returns_explicit_gap(self):
        self.p387={k:(self.p387['tsa_channel_id'] if k=='tsa_channel_id' else
                 [] if k in ('ec340_signed_role_edges','ec339_original_signed_role_history',
                             'ec340_original_public_key_sources') else None)
                   for k in core.parent.CHANNEL_FIELDS}
        self.p386={k:(self.p386['tsa_channel_id'] if k=='tsa_channel_id' else
                 [] if k in ('ec341_manifest_dependency_originals',
                             'ec341_signer_public_key_copies') else None)
                   for k in core.parent.parent.CHANNEL_FIELDS}
        self.row={k:(self.row['tsa_channel_id'] if k=='tsa_channel_id' else
                  [] if k=='ec339_role_retirement_reviews' else None)
                  for k in core.CHANNEL_FIELDS}
        r=self.run_channel()
        self.assertFalse(r['full_original_ec339_role_retirement_replay'])
        self.assertEqual(r['ec338_signed_actor_receipt_count'],0)

    def _archive(self,name,doc):
        p=self.root/name;p.write_bytes(canonical.canonical(doc));return ref(p)

    def _outer(self):
        flags={k:(i in (7,8)) for i,k in enumerate(core.parent.FLAGS)}
        report={'schema':core.parent.RESULT_SCHEMA,'exit_code':2,
            'sender_origin_path_required_or_read':False,
            'ec340_to_ec337_full_independent_unmocked_external_acceptance_performed':False,
            'historical_ec340_rotation_epoch_reviews':[{'epoch_index':0}],
            'local_old_ec340_signed_rotation_ec341_conflict_parent_originals_consistent':True,
            'status':core.parent.OUTCOMES[7]+'_unresolved',**flags,
            **{k:False for k in core.parent.NEGATIVES}}
        psha=core.sha(canonical.canonical(report))
        root=self._archive('ec388-test-authentic-ec386-archive.json',{
            'schema':core.parent.parent.BUNDLE_SCHEMA,
            'parent_ec385_canonical_result_sha256':'cd'*32,
            'ec385_historical_change_archive_original_sha256':'ce'*32,
            'claimed_directory_lineage_id':'Lineage388',
            'epochs':[{'epoch_index':0,'channels':[self.p386]}]})
        prior=self._archive('ec388-test-authentic-ec387-archive.json',{
            'schema':core.parent.BUNDLE_SCHEMA,
            'parent_ec386_canonical_result_sha256':'cf'*32,
            'ec386_historical_root_archive_original_sha256':root['sha256'],
            'claimed_directory_lineage_id':'Lineage388',
            'epochs':[{'epoch_index':0,'channels':[self.p387]}]})
        curr=self._archive('ec388-test-receiver-archive.json',{
            'schema':core.BUNDLE_SCHEMA,
            'parent_ec387_canonical_result_sha256':psha,
            'ec387_historical_rotation_archive_original_sha256':prior['sha256'],
            'claimed_directory_lineage_id':'Lineage388',
            'epochs':[{'epoch_index':0,'channels':[self.row]}]})
        sender=self._archive('ec388-test-sender-labels.json',{'schema':'dummy'})
        index=self._archive('ec388-test-ec377-index.json',{
            'schema':core.p377.BUNDLE_SCHEMA,
            'epochs':[{'ec353_publication_bundle_original':sender}],
            **{k:'cc'*32 for k in core.p377.BUNDLE_FIELDS if k not in ('schema','epochs')}})
        opts={'historical_directory_root_shas':['aa'*32],
            'claimed_historical_directory_lineage_id':'Lineage388',
            'historical_ec341_signed_root_conflict_archive_bundle_file':root['path'],
            'expected_historical_ec341_signed_root_conflict_archive_bundle_sha256':root['sha256'],
            'historical_ec340_signed_rotation_archive_bundle_file':prior['path'],
            'expected_historical_ec340_signed_rotation_archive_bundle_sha256':prior['sha256'],
            'historical_ec339_retirement_revocation_archive_bundle_file':curr['path'],
            'expected_historical_ec339_retirement_revocation_archive_bundle_sha256':curr['sha256'],
            'historical_transparency_archive_bundle_file':index['path'],
            'expected_historical_transparency_archive_bundle_sha256':index['sha256'],
            'historical_ec339_retirement_role_inventory_shas':['aa'*32],
            'historical_ec339_revocation_transition_inventory_shas':['bb'*32],
            'minimum_historical_ec338_signed_actor_receipt_counts':[4],
            'minimum_historical_ec339_retirement_status_counts':[4],
            'minimum_historical_ec339_signed_revocation_transition_counts':[1]}
        return report,opts

    def _patched(self,report):
        return (patch.object(core,'_inputs',return_value={}),
                patch.object(core.parent,'audit',return_value=report),
                patch.object(core.p379,'_old_sender_labels'))

    def test_22_derived_inventory_uses_real_signed_originals_mocked_outer_only(self):
        report,opts=self._outer();a,b,c=self._patched(report)
        with a,b,c:res=core.derive_inventory(**opts)
        self.assertEqual(res['exit_code'],2)
        self.assertEqual(res['genuine_old_ec338_signed_actor_receipt_count'],4)
        self.assertEqual(res['genuine_old_ec339_retirement_window_signed_status_count'],4)
        self.assertEqual(res['genuine_old_ec339_signed_revoked_transition_count'],1)
        self.assertTrue(res[core.FLAGS[1]])
        self.assertFalse(res['caller_retained_inventory_sha_independently_certified'])
        self.assertFalse(res['ec339_old_root_signed_grants_are_new_epoch_authorizations'])

    def test_23_matching_external_shas_still_only_unresolved(self):
        report,opts=self._outer();a,b,c=self._patched(report)
        with a,b,c:
            derived=core.derive_inventory(**opts)
            ep=derived['historical_ec339_retirement_epoch_reviews'][0]
            opts['historical_ec339_retirement_role_inventory_shas']=[ep['old_ec339_role_original_inventory_sha256']]
            opts['historical_ec339_revocation_transition_inventory_shas']=[ep['old_ec339_revocation_transition_inventory_sha256']]
            opts['expected_retained_historical_ec339_retirement_revocation_inventory_sha256']=(
                derived['receiver_verified_old_ec339_retirement_inventory_sha256'])
            audited=core.audit(**opts)
        self.assertEqual(audited['exit_code'],2)
        self.assertTrue(audited['local_old_ec339_signed_grant_revocation_retirement_originals_consistent'])
        self.assertTrue(audited[core.FLAGS[7]] and audited[core.FLAGS[8]])
        self.assertNotIn('unsigned_verified_old_ec339_retirement_inventory',audited)

    def test_24_external_floor_or_inventory_mismatch_adverse_but_no_forge(self):
        report,opts=self._outer();a,b,c=self._patched(report)
        opts['minimum_historical_ec339_signed_revocation_transition_counts']=[3]
        with a,b,c:res=core.derive_inventory(**opts)
        self.assertTrue(res[core.FLAGS[1]])
        self.assertEqual(res['exit_code'],2)

    def test_25_reject_parent_report_merely_claiming_pass_without_contract(self):
        report,opts=self._outer()
        report['status']='passed'
        with self.assertRaises(errors.AnchorError):core._parent(report,1)

    def test_28_two_channels_revoked_then_later_active_is_adverse(self):
        # Two locally signed fragments are each internally monotonic, but
        # combined order shows a revoked->active ABA across channel copies.
        report,opts=self._outer()
        active=self._issue('sender',name='ec388-cross-channel-active-after-revoked.json',
            challenge='e8'*32,state='active',as_of='2026-10-25T11:30:00Z',
            expires='2026-10-25T11:50:00Z')
        other=copy.deepcopy(self.row)
        other['tsa_channel_id']=self.row['tsa_channel_id']+'-2'
        other['ec339_role_retirement_reviews'][0]['additional_challenged_status_originals'][1]=active
        p387_other=copy.deepcopy(self.p387)
        p387_other['tsa_channel_id']=other['tsa_channel_id']
        p386_other=copy.deepcopy(self.p386)
        p386_other['tsa_channel_id']=other['tsa_channel_id']
        root_doc=json.loads(Path(opts['historical_ec341_signed_root_conflict_archive_bundle_file']).read_bytes())
        root_doc['epochs'][0]['channels'].append(p386_other)
        root_ref=self._archive('ec388-2ch-parent-ec386.json',root_doc)
        parent_doc=json.loads(Path(opts['historical_ec340_signed_rotation_archive_bundle_file']).read_bytes())
        parent_doc['ec386_historical_root_archive_original_sha256']=root_ref['sha256']
        parent_doc['epochs'][0]['channels'].append(p387_other)
        parent_ref=self._archive('ec388-2ch-parent-ec387.json',parent_doc)
        current_doc=json.loads(Path(opts['historical_ec339_retirement_revocation_archive_bundle_file']).read_bytes())
        current_doc['ec387_historical_rotation_archive_original_sha256']=parent_ref['sha256']
        current_doc['epochs'][0]['channels'].append(other)
        current_ref=self._archive('ec388-2ch-authentic-signed-statuses.json',current_doc)
        for name,refval in (
            ('historical_ec341_signed_root_conflict_archive_bundle_file',root_ref['path']),
            ('expected_historical_ec341_signed_root_conflict_archive_bundle_sha256',root_ref['sha256']),
            ('historical_ec340_signed_rotation_archive_bundle_file',parent_ref['path']),
            ('expected_historical_ec340_signed_rotation_archive_bundle_sha256',parent_ref['sha256']),
            ('historical_ec339_retirement_revocation_archive_bundle_file',current_ref['path']),
            ('expected_historical_ec339_retirement_revocation_archive_bundle_sha256',current_ref['sha256'])):
            opts[name]=refval
        a,b,c=self._patched(report)
        with a,b,c:res=core.derive_inventory(**opts)
        self.assertEqual(res['exit_code'],2)
        self.assertTrue(res[core.FLAGS[4]])
        self.assertFalse(res['local_old_ec339_signed_grant_revocation_retirement_originals_consistent'])

    def test_26_readonly_fixed_entrypoints_have_no_signing_commands(self):
        root=Path(__file__).resolve().parents[2]
        for file_name,cmd in (
            ('ces_cas_historical_retirement_archive.py',
             'audit-historical-ec339-retirement-archive'),
            ('ces_next.py','audit-historical-ec339-retirement-archive')):
            p=subprocess.run([sys.executable,'-I','-B',str(root/'scripts'/file_name),cmd,
                '--help'],capture_output=True,text=True,timeout=40)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn('--expected-retained-historical-ec339-retirement-revocation-inventory-sha256',p.stdout)
            self.assertNotIn('--private-key',p.stdout)

if __name__=='__main__':unittest.main()
