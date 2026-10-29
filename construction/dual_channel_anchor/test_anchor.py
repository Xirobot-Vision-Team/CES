#!/usr/bin/env python3
"""EC349 genuine Ed25519 fixture coverage, inherited EC317/318 still MOCK."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from delivery_anchor import anchor as errors
from external_custody import test_custody as old_test
from . import anchor as core
from . import operator as op

ROOT=Path(__file__).resolve().parents[2]


class DualChannelTests(unittest.TestCase):
    # Borrow historical fixture construction, NOT the 31 inherited test methods.
    # Its deep EC317/318 originals remain explicitly synthetic MOCK history.
    @classmethod
    def setUpClass(cls):
        old_test.ExternalKeeperImportTests.setUpClass()
        cls.f=old_test.ExternalKeeperImportTests.f
        cls.root=old_test.ExternalKeeperImportTests.root

    @classmethod
    def tearDownClass(cls):
        old_test.ExternalKeeperImportTests.tearDownClass()

    def setUp(self):
        old_test.ExternalKeeperImportTests.setUp(self)
        self.record(0);self.record(1)
        self.ec348_source=self.options()
        self.context=core._replay(self.ec348_source)
        self.channel_keys=[{
            'root':Ed25519PrivateKey.generate(),
            'anchor':Ed25519PrivateKey.generate(),
            'time':Ed25519PrivateKey.generate()} for _ in range(2)]
        self.directories=[self.make_channel_directory(i) for i in range(2)]
        self.channel_receipts=[]
        self.time_receipts=[]

    def actor(self, channel: int, kind: str):
        return {'signer_id':f'channel_{channel}_{kind}',
                'public_hex':old_test.pub(self.channel_keys[channel][kind]),
                'organization_id':f'org_{channel}_{kind}'}

    def make_channel_directory(self, idx, **updates):
        claim={'schema':core.DIRECTORY_CLAIM,
            'case_id':self.context['report']['case_id'],
            'ec348_inputs_canonical_sha256':self.context['source_sha'],
            'ec348_verified_result_canonical_sha256':self.context['result_sha'],
            'ec348_keeper_directory_original_raw_sha256':self.ec348_source['expected_keeper_directory_sha256'],
            'channel_id':f'channel_{idx}',
            'channel_role':'independent_out_of_band_sha_anchor_claim',
            'root_authority':self.actor(idx,'root'),
            'receipt_actor':self.actor(idx,'anchor'),
            'time_actor':self.actor(idx,'time'),
            'valid_from_utc':'2026-10-25T14:30:00Z',
            'valid_until_utc':'2026-10-25T15:30:00Z',
            'scope':'bounded_offline_sha_anchor_and_time_witness_only',
            'no_independence_or_trusted_clock_authority':True}
        claim.update(updates)
        path,sha=self.write('channel-directory',self.sign_document(
            core.DIRECTORY_SCHEMA,claim,core.D_DIRECTORY,self.channel_keys[idx]['root']))
        return (path,sha,claim)

    def sign_anchor(self, idx=0, *,seq=1, prev=None, kind='capture_claim',
                    signed_by=None, pinned=True, updates=None,
                    received='2026-10-25T14:35:00Z',expires='2026-10-25T15:10:00Z'):
        signer=self.actor(idx,'anchor')
        claim={'schema':core.RECEIPT_CLAIM,
            'case_id':self.context['report']['case_id'],
            'ec348_inputs_canonical_sha256':self.context['source_sha'],
            'ec348_verified_result_canonical_sha256':self.context['result_sha'],
            'channel_id':f'channel_{idx}',
            'channel_directory_original_raw_sha256':self.directories[idx][1],
            'receipt_signer_id':signer['signer_id'],
            'receipt_signer_public_hex':signer['public_hex'],
            'receipt_signer_organization_id':signer['organization_id'],
            'keeper_visible_heads':self.context['keepers'],
            'keeper_signed_originals':self.context['originals'],
            'statement_kind':kind,'sequence':seq,
            'previous_statement_file':prev[0] if prev else None,
            'previous_statement_original_raw_sha256':prev[1] if prev else None,
            'statement_nonce_sha256':self.nonce_sha(),
            'claimed_received_utc':received,'expires_utc':expires,
            'scope':'signed_out_of_band_keeper_heads_claim_only',
            'no_remote_custody_or_external_time_authority':True}
        if updates:claim.update(updates)
        obj=self.sign_document(core.RECEIPT_SCHEMA,claim,core.D_RECEIPT,
            signed_by or self.channel_keys[idx]['anchor'])
        path,sha=self.write('channel-receipt',obj)
        row=(path,sha,claim,pinned)
        self.channel_receipts.append(row)
        return row

    def sign_time(self, receipt, idx=0, *, pinned=True,
                  observed='2026-10-25T14:35:07Z', uncertainty=30,
                  signed_by=None, updates=None):
        actor=self.actor(idx,'time')
        claim={'schema':core.TIME_CLAIM,
            'case_id':self.context['report']['case_id'],
            'channel_id':f'channel_{idx}',
            'channel_directory_original_raw_sha256':self.directories[idx][1],
            'receipt_original_raw_sha256':receipt[1],
            'receipt_sequence':receipt[2]['sequence'],
            'time_actor_id':actor['signer_id'],
            'time_actor_public_hex':actor['public_hex'],
            'time_actor_organization_id':actor['organization_id'],
            'time_provenance_kind':'separately_signed_local_clock_claim',
            'claimed_observed_utc':observed,'uncertainty_seconds':uncertainty,
            'time_nonce_sha256':self.nonce_sha(),
            'scope':'receipt_sha_time_provenance_claim_only',
            'not_a_trusted_utc_or_legal_timestamp':True}
        if updates:claim.update(updates)
        obj=self.sign_document(core.TIME_SCHEMA,claim,core.D_TIME,
            signed_by or self.channel_keys[idx]['time'])
        path,sha=self.write('channel-time',obj)
        row=(path,sha,claim,pinned)
        self.time_receipts.append(row)
        return row

    def capture_both(self):
        left=self.sign_anchor(0);right=self.sign_anchor(1)
        self.sign_time(left,0);self.sign_time(right,1)
        return left,right

    def dual_arguments(self,**overrides):
        a={**self.ec348_source,'dual_evaluation_utc':'2026-10-25T14:45:00Z',
            'channel_directory_files':[d[0] for d in self.directories],
            'channel_directory_shas':[d[1] for d in self.directories],
            'channel_root_public_hexes':[old_test.pub(keys['root'])
                                         for keys in self.channel_keys]}
        signed=sorted(self.channel_receipts,key=lambda r:(
            r[2]['channel_id'],r[2]['sequence'],r[1]))
        stamps=sorted(self.time_receipts,key=lambda r:(
            r[2]['channel_id'],r[2]['receipt_sequence'],
            r[2]['receipt_original_raw_sha256']))
        a.update(channel_receipt_files=[r[0] for r in signed],
                 channel_receipt_shas=[r[1] if r[3] else core.UNPINNED for r in signed],
                 time_witness_files=[r[0] for r in stamps],
                 time_witness_shas=[r[1] if r[3] else core.UNPINNED for r in stamps])
        a.update(overrides)
        return a

    def run_audit(self, **changes):
        return core.audit_dual_anchors(**self.dual_arguments(**changes))

    def test_a_two_real_signatures_and_independent_witness_keys_still_no_offsite_proof(self):
        self.capture_both()
        out=self.run_audit()
        self.assertEqual(out['exit_code'],2)
        self.assertEqual(out['outcome_counts'][core.OUTCOMES[8]],2)
        self.assertEqual(out['status'],core.OUTCOMES[8]+'_unresolved')
        self.assertTrue(out['ec348_full_signed_source_replayed'])
        self.assertTrue(out['two_channel_directory_signatures_verified'])
        self.assertFalse(out['signature_on_time_claim_proves_trusted_utc_or_receipt_delivery_time'])
        self.assertFalse(out['caller_supplied_channel_sha_pins_prove_external_out_of_band_custody'])

    def test_b_unsigned_exact_handoff_never_signs_or_reports_custody(self):
        d=core.derive_handoff(**self.ec348_source)
        self.assertEqual(d['keeper_visible_heads'],self.context['keepers'])
        self.assertEqual(d['keeper_signed_originals'],self.context['originals'])
        self.assertEqual(d['unverified_external_channel_count'],2)
        self.assertNotIn('signature_ed25519',str(d))

    def test_c_both_channels_unpresented_are_unresolved(self):
        out=self.run_audit()
        self.assertEqual(out['outcome_counts'][core.OUTCOMES[0]],2)

    def test_d_partial_presentation_not_upgraded_to_double(self):
        r=self.sign_anchor(0);self.sign_time(r,0)
        out=self.run_audit()
        self.assertEqual(out['outcome_counts'][core.OUTCOMES[0]],1)
        self.assertEqual(out['outcome_counts'][core.OUTCOMES[8]],1)

    def test_e_unpinned_current_anchor_never_becomes_independently_pinned(self):
        self.sign_anchor(0,pinned=False)
        result=self.run_audit()
        self.assertEqual(result['channel_outcomes'][0]['outcome'],core.OUTCOMES[3])

    def test_f_unpinned_ancestor_not_repaired_by_later_pinned_version(self):
        start=self.sign_anchor(0,pinned=False)
        newer=self.sign_anchor(0,seq=2,kind='renewal_claim',prev=start,
                               received='2026-10-25T14:37:00Z')
        self.sign_time(newer,0,observed='2026-10-25T14:37:06Z')
        out=self.run_audit()
        self.assertFalse(out['channel_outcomes'][0]['latest_head_ancestry_all_externally_pinned'])
        self.assertEqual(out['channel_outcomes'][0]['outcome'],core.OUTCOMES[3])

    def test_g_signed_fork_visible_without_winner_or_automatic_timestamp_selection(self):
        first=self.sign_anchor(0)
        self.sign_anchor(0,seq=2,kind='renewal_claim',prev=first,
                         received='2026-10-25T14:37:00Z')
        self.sign_anchor(0,seq=2,kind='revocation_claim',prev=first,
                         received='2026-10-25T14:38:00Z')
        out=self.run_audit()
        self.assertEqual(out['channel_outcomes'][0]['outcome'],core.OUTCOMES[1])
        self.assertEqual(len(out['channel_outcomes'][0]['visible_signed_head_original_raw_sha256s']),2)
        self.assertIsNone(out['channel_outcomes'][0]['latest_head_kind'])

    def test_h_signed_revocation_claim_is_not_physical_deletion(self):
        first=self.sign_anchor(0)
        self.sign_anchor(0,seq=2,kind='revocation_claim',prev=first,
                         received='2026-10-25T14:37:00Z')
        out=self.run_audit()
        self.assertEqual(out['channel_outcomes'][0]['outcome'],core.OUTCOMES[2])
        self.assertFalse(out['signed_revocation_erases_previous_offsite_originals'])

    def test_i_missing_time_witness_is_not_a_trusted_receipt_time(self):
        self.sign_anchor(0)
        out=self.run_audit()
        self.assertEqual(out['channel_outcomes'][0]['outcome'],core.OUTCOMES[4])

    def test_j_unpinned_time_witness_is_not_pinned_by_its_local_sha(self):
        a=self.sign_anchor(0);self.sign_time(a,0,pinned=False)
        out=self.run_audit()
        self.assertEqual(out['channel_outcomes'][0]['outcome'],core.OUTCOMES[4])

    def test_k_genuine_signed_time_disagreement_is_visible(self):
        a=self.sign_anchor(0)
        self.sign_time(a,0,observed='2026-10-25T14:42:00Z',uncertainty=40)
        out=self.run_audit()
        self.assertEqual(out['channel_outcomes'][0]['outcome'],core.OUTCOMES[5])
        self.assertFalse(out['channel_outcomes'][0]['latest_time_witness'][
            'signed_claims_agree_within_claimed_uncertainty'])

    def test_l_cross_channel_claimed_utc_skew_is_reported_not_trusted(self):
        left,right=self.capture_both()
        self.time_receipts.pop()
        self.sign_time(right,1,observed='2026-10-25T14:42:00Z',uncertainty=420)
        result=self.run_audit()
        self.assertEqual(result['outcome_counts'][core.OUTCOMES[5]],2)
        self.assertFalse(result['cross_channel_signed_time_comparison'][0][
            'within_five_minute_claim_comparison_window'])

    def test_m_renewal_with_true_signed_sha_previous_and_time_claim(self):
        first=self.sign_anchor(0)
        new=self.sign_anchor(0,seq=2,kind='renewal_claim',prev=first,
                             received='2026-10-25T14:37:00Z')
        self.sign_time(new,0,observed='2026-10-25T14:37:12Z')
        self.assertEqual(self.run_audit()['channel_outcomes'][0]['outcome'],core.OUTCOMES[8])

    def test_n_signed_claim_expiry_gap_is_not_masked_by_valid_renewal(self):
        first=self.sign_anchor(0,expires='2026-10-25T14:36:00Z')
        new=self.sign_anchor(0,seq=2,kind='renewal_claim',prev=first,
                             received='2026-10-25T14:37:00Z')
        self.sign_time(new,0,observed='2026-10-25T14:37:04Z')
        out=self.run_audit()
        self.assertTrue(out['channel_outcomes'][0]['signed_ancestry_has_self_reported_expiry_gap'])
        self.assertEqual(out['channel_outcomes'][0]['outcome'],core.OUTCOMES[6])

    def test_o_forged_anchor_with_recomputed_sha_rejected_by_signature(self):
        a=self.sign_anchor(0)
        raw=json.loads(Path(a[0]).read_text())
        raw['claim']['keeper_signed_originals']=[]
        p,s=self.write('forged-anchor',raw)
        with self.assertRaises(errors.AnchorError):
            self.run_audit(channel_receipt_files=[p],channel_receipt_shas=[s])

    def test_p_wrong_root_pin_and_signing_key_rejected(self):
        self.sign_anchor(0,signed_by=self.channel_keys[1]['anchor'])
        with self.assertRaises(errors.AnchorError):self.run_audit()
        with self.assertRaises(errors.AnchorError):self.run_audit(
            channel_root_public_hexes=['cc'*32,old_test.pub(self.channel_keys[1]['root'])])

    def test_q_true_new_signed_receipt_cannot_hide_changed_ec348_parent(self):
        self.capture_both()
        with self.assertRaises(errors.AnchorError):self.run_audit(
            keeper_receipt_shas=['ff'*32,*self.ec348_source['keeper_receipt_shas'][1:]])

    def test_r_separate_time_witness_cannot_self_sign_as_receipt_actor(self):
        a=self.sign_anchor(0)
        self.sign_time(a,0,signed_by=self.channel_keys[0]['anchor'])
        with self.assertRaises(errors.AnchorError):self.run_audit()

    def test_s_actor_role_key_or_org_reuse_between_channels_rejected(self):
        shared=copy.deepcopy(self.directories[1][2])
        shared['time_actor']=self.directories[0][2]['receipt_actor']
        self.directories[1]=self.make_channel_directory(1,time_actor=shared['time_actor'])
        with self.assertRaisesRegex(errors.AnchorError,'ACTOR_REUSE'):
            self.run_audit()

    def test_t_reused_original_ec348_root_identity_rejected(self):
        borrowed=copy.deepcopy(self.directories[0][2]['root_authority'])
        borrowed['public_hex']=old_test.pub(self.root_key)
        self.directories[0]=self.make_channel_directory(0,root_authority=borrowed)
        with self.assertRaises(errors.AnchorError):self.run_audit()

    def test_u_old_signed_keeper_uncertain_stays_visible_in_new_double_claim(self):
        self.ec348_source['keeper_receipt_shas'][0]='UNPINNED'
        self.context=core._replay(self.ec348_source)
        self.directories=[self.make_channel_directory(i) for i in range(2)]
        self.capture_both()
        out=self.run_audit()
        self.assertTrue(out['ec348_keeper_heads_still_unresolved'])
        self.assertEqual(out['outcome_counts'][core.OUTCOMES[7]],2)

    def test_v_anchor_receipt_and_time_paths_cannot_reuse_source_originals(self):
        with self.assertRaisesRegex(errors.AnchorError,'PATH_CANNOT_REUSE'):
            self.run_audit(time_witness_files=[self.ec348_source['keeper_directory_file']],
                time_witness_shas=[self.ec348_source['expected_keeper_directory_sha256']])

    def test_w_standalone_fixed_isolated_auditor_verifies_true_signed_channels(self):
        self.capture_both()
        params=self.dual_arguments()
        args=[sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_cas_dual_channel_anchor.py'),
              'audit-dual-anchors']
        for k in op.SCALARS:args.extend(['--'+k.replace('_','-'),str(params[k])])
        args.extend(['--dual-evaluation-utc',params['dual_evaluation_utc']])
        for k in op.PARENT_REPEATS:
            for value in params[k]:
                args.extend(['--'+old_test.cli.FLAGS[k].replace('_','-'),value])
        for k,flag in op.ADDED_REPEATS:
            for v in params[k]:args.extend(['--'+flag.replace('_','-'),v])
        result=subprocess.run(args,cwd=ROOT,capture_output=True,text=True,timeout=300)
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertEqual(json.loads(result.stdout)['outcome_counts'][core.OUTCOMES[8]],2)
        self.assertNotIn('--private-key-file',op.parser().format_help())

    def test_x_unified_fixed_audit_is_read_only_without_exported_signer(self):
        self.capture_both()
        from scripts import ces_next
        params=self.dual_arguments()
        cmd=[sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_next.py'),
             'audit-dual-channel-anchors','DeliveryAudit','AuditOutOfBandDualSHAAndTime']
        for k in ces_next.EC349_KEYS:
            cmd.extend(['--'+k.replace('_','-'),str(params[k])])
        for k,flag in ces_next.EC349_REPEATS:
            for v in params[k]:cmd.extend([flag,v])
        result=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=300)
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertEqual(json.loads(result.stdout)['outcome_counts'][core.OUTCOMES[8]],2)
        bad=cmd[:]
        bad[5]='KeyRotation'
        denial=subprocess.run(bad,cwd=ROOT,capture_output=True,text=True,timeout=300)
        self.assertEqual(denial.returncode,3,denial.stdout+denial.stderr)
        self.assertFalse(json.loads(denial.stdout)['permissions_granted'])
        keys={o for act in ces_next.build_parser()._subparsers._group_actions[0]
              .choices['audit-dual-channel-anchors']._actions for o in act.option_strings}
        for invalid in ('--private-key-file','--out','--write','--provider','--cas','--worm'):
            self.assertNotIn(invalid,keys)


# Reuse ONLY fixture helpers from the inherited test class. This avoids
# silently re-counting the older 31 cases as EC349's new suite.
for method in ('configure','sign','parameters','audit','copies','observation',
               'show','challenge','response','kw','nonce_sha','issue','reply','params',
               'write','sign_document','make_directory','record','options','present','arguments'):
    setattr(DualChannelTests,method,getattr(old_test.ExternalKeeperImportTests,method))

if __name__ == '__main__':
    unittest.main()
