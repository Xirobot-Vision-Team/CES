#!/usr/bin/env python3
"""EC348 Ed25519 import/replay tests. Historical EC317/318 data remains MOCK."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from delivery_anchor import anchor
from offline_transfer_registry import registry as reg
from conflict_hold import test_hold as old_test
from readback_challenge import test_readback as inherited
from . import custody as c
from . import operator as cli

ROOT=Path(__file__).resolve().parents[2]


def pub(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw).hex()


class ExternalKeeperImportTests(unittest.TestCase):
    configure=inherited.ChallengedReadbackTests.configure
    sign=inherited.ChallengedReadbackTests.sign
    parameters=inherited.ChallengedReadbackTests.parameters
    audit=inherited.ChallengedReadbackTests.audit
    copies=inherited.ChallengedReadbackTests.copies
    observation=inherited.ChallengedReadbackTests.observation
    arguments=inherited.ChallengedReadbackTests.arguments
    show=inherited.ChallengedReadbackTests.show
    challenge=inherited.ChallengedReadbackTests.challenge
    response=inherited.ChallengedReadbackTests.response
    kw=inherited.ChallengedReadbackTests.kw
    nonce_sha=inherited.ChallengedReadbackTests.nonce_sha
    issue=inherited.ChallengedReadbackTests.issue
    reply=inherited.ChallengedReadbackTests.reply
    params=inherited.ChallengedReadbackTests.params

    @classmethod
    def setUpClass(cls):
        inherited.ChallengedReadbackTests.setUpClass()
        cls.f=inherited.ChallengedReadbackTests.f
        cls.root=inherited.ChallengedReadbackTests.root

    @classmethod
    def tearDownClass(cls):
        inherited.ChallengedReadbackTests.tearDownClass()

    def setUp(self):
        inherited.ChallengedReadbackTests.setUp(self)
        ch=self.issue();self.reply(ch,0);self.reply(ch,1)
        self.old=self.params()
        self.ctx=c._context(self.old)
        self.root_key=Ed25519PrivateKey.generate()
        self.keeper_keys=[Ed25519PrivateKey.generate() for _ in range(2)]
        self.actors=[{
            'signer_id':f'external_keeper{i}', 'public_hex':pub(key),
            'organization_id':f'external_org{i}', 'ledger_id':f'external_ledger{i}',
            'subject_receiver_id':subject}
            for i,(key,subject) in enumerate(zip(self.keeper_keys,
                   self.ctx['report']['latest_challenge_audience_receiver_ids']))]
        self.serial=0
        self.receipts=[]
        self.ledger_by_receipt={}
        self.directory=self.make_directory()

    def write(self, name, doc):
        self.serial+=1
        path=str(self.w/f'ec348-{self.serial}-{name}.json')
        old_test.canonical(path,doc)
        return (path,old_test.sha(path))

    def sign_document(self, schema, claim, domain, key):
        return {'schema':schema, 'claim':claim,
                'signature_ed25519':key.sign(domain+reg.canonical(claim)).hex()}

    def make_directory(self, **overrides):
        claim={'schema':c.DIRECTORY_CLAIM,
            'case_id':self.ctx['report']['case_id'],
            'ec347_audit_inputs_canonical_sha256':self.ctx['context_sha'],
            'ec347_latest_challenge_original_raw_sha256':self.old['readback_challenge_shas'][-1],
            'source_snapshot_original_raw_sha256':self.ctx['report']['source_snapshot_original_raw_sha256'],
            'source_ack_set_original_raw_sha256':self.ctx['report']['source_ack_set_original_raw_sha256'],
            'directory_authority':{'signer_id':'external_root',
                'public_hex':pub(self.root_key),'organization_id':'external_root_org'},
            'custodians':self.actors,
            'valid_from_utc':'2026-10-25T14:10:00Z',
            'valid_until_utc':'2026-10-25T15:10:00Z',
            'scope':'independently_furnished_offline_keeper_sha_inventory_only',
            'no_physical_or_external_identity_authority':True}
        claim.update(overrides)
        path,sha=self.write('keeper-directory',self.sign_document(
            c.DIRECTORY_SCHEMA,claim,c.D_DIRECTORY,self.root_key))
        return path,sha,claim

    def record(self, keeper=0, *, kind=c.STORE, seq=1, prev=None,
               snapshot_sha=None, ack_sha=None, ledger_sha=None,
               signature_key=None, expires='2026-10-25T14:50:00Z',
               overrides=None, pinned=True):
        actor=self.actors[keeper]
        latest=self.ctx['latest'][actor['subject_receiver_id']]
        original=next(x[2] for x in reversed(self.replies)
                      if x[2]['receiver_id']==actor['subject_receiver_id'])
        if kind==c.REVOKE:
            snap_sha=ack_digest=snap_len=ack_len=None
        else:
            snap_sha=snapshot_sha or latest['signed_snapshot_raw_sha256']
            ack_digest=ack_sha or latest['signed_ack_set_raw_sha256']
            snap_len=original['copy_snapshot_byte_length']
            ack_len=original['copy_ack_set_byte_length']
        claim={'schema':c.RECEIPT_CLAIM,
            'case_id':self.ctx['report']['case_id'],
            'ec347_audit_inputs_canonical_sha256':self.ctx['context_sha'],
            'directory_original_raw_sha256':self.directory[1],
            'custodian_id':actor['signer_id'],
            'custodian_public_hex':actor['public_hex'],
            'custodian_organization_id':actor['organization_id'],
            'ledger_id':actor['ledger_id'],
            'subject_receiver_id':actor['subject_receiver_id'],
            'latest_ec347_round':self.ctx['report']['challenge_round_count'],
            'latest_challenge_original_raw_sha256':self.old['readback_challenge_shas'][-1],
            'latest_receiver_reply_original_raw_sha256':latest['response_original_raw_sha256'],
            'whole_original_inventory':c._inventory(self.ctx,actor['subject_receiver_id']),
            'claimed_snapshot_original_raw_sha256':snap_sha,
            'claimed_snapshot_byte_length':snap_len,
            'claimed_ack_set_original_raw_sha256':ack_digest,
            'claimed_ack_set_byte_length':ack_len,
            'ledger_original_raw_sha256':'ab'*32,
            'statement_kind':kind,'sequence':seq,
            'previous_statement_file':prev[0] if prev else None,
            'previous_statement_original_raw_sha256':prev[1] if prev else None,
            'statement_nonce_sha256':self.nonce_sha(),
            'reported_utc':f'2026-10-25T14:{10+seq:02d}:00Z',
            'expires_utc':expires,
            'scope':'keeper_signed_local_sha_inventory_claim_not_independent_site_proof',
            'no_actual_site_custody_or_remote_authority':True}
        ledger=self.write('keeper-ledger',c._ledger_fields(claim))
        claim['ledger_original_raw_sha256']=ledger_sha or ledger[1]
        if overrides:claim.update(overrides)
        p,s=self.write('keeper-receipt',self.sign_document(
            c.RECEIPT_SCHEMA,claim,c.D_RECEIPT,signature_key or self.keeper_keys[keeper]))
        entry=(p,s,claim,pinned)
        self.receipts.append(entry)
        self.ledger_by_receipt[p]=ledger
        return entry

    def options(self, *, presented=(), **overrides):
        data={**self.old,'external_evaluation_utc':'2026-10-25T14:30:00Z',
              'keeper_directory_file':self.directory[0],
              'expected_keeper_directory_sha256':self.directory[1],
              'expected_directory_root_public_hex':pub(self.root_key)}
        sorted_receipts=sorted(self.receipts,key=lambda entry:(
            self.actors.index(next(a for a in self.actors
                if a['signer_id']==entry[2]['custodian_id'])),
            entry[2]['sequence'],entry[1]))
        data.update(keeper_receipt_files=[x[0] for x in sorted_receipts],
                    keeper_receipt_shas=[x[1] if x[3] else c.UNPINNED
                                         for x in sorted_receipts])
        data.update(presented_keeper_ids=[a[0] for a in presented],
                    presented_ledger_files=[a[1] for a in presented],
                    presented_ledger_shas=[a[2] for a in presented],
                    presented_copy_snapshot_files=[a[3] for a in presented],
                    presented_copy_ack_set_files=[a[4] for a in presented])
        data.update(overrides)
        return data

    def present(self, receipt, keeper=0, *, mutate=False):
        actor=self.actors[keeper]
        obs=next(x[2] for x in reversed(self.events)
                 if x[2]['receiver_id']==actor['subject_receiver_id'])
        srcs=(obs['copy_snapshot_file'],obs['copy_ack_set_file'])
        new=[]
        for i,p in enumerate(srcs):
            dest=self.w/f'keeper-present-{self.serial}-{keeper}-{i}.raw'
            self.serial+=1
            dest.write_bytes(Path(p).read_bytes() if not mutate or i else b'CHANGED_SINCE_SIGNED_KEEPER')
            dest.chmod(0o600)
            new.append(str(dest))
        ledger=self.ledger_by_receipt[receipt[0]]
        return (actor['signer_id'],*ledger,*new)

    def test_a_two_independent_keys_signed_inventory_import_no_custody_overclaim(self):
        self.record(0);self.record(1)
        report=c.audit_external_custody(**self.options())
        self.assertEqual(report['exit_code'],2)
        self.assertEqual(report['outcome_counts'][c.OUTCOMES[7]],2)
        self.assertTrue(report['ec347_full_signed_source_and_readback_replayed'])
        self.assertFalse(report['caller_supplied_pins_prove_independently_custodied_external_shas'])
        self.assertTrue(report['external_physical_identity_pin_provenance_clock_and_site_all_not_proven'])

    def test_b_derive_exact_signed_ec347_sha_checklist_never_signs(self):
        data=c.derive_checklist(**self.old)
        self.assertEqual(data['exit_code'],2)
        self.assertEqual(len(data['eligible_receiver_inventories']),2)
        self.assertEqual(data['ec347_audit_inputs_canonical_sha256'],self.ctx['context_sha'])
        self.assertEqual(data['eligible_receiver_inventories'][0]['whole_original_inventory'],
                         c._inventory(self.ctx,self.actors[0]['subject_receiver_id']))

    def test_c_no_external_receipts_stays_missing_evidence(self):
        report=c.audit_external_custody(**self.options())
        self.assertEqual(report['outcome_counts'][c.OUTCOMES[0]],2)
        self.assertEqual(report['status'],c.OUTCOMES[0]+'_unresolved')

    def test_d_unpinned_latest_receipt_never_upgraded(self):
        self.record(0,pinned=False);self.record(1)
        out=c.audit_external_custody(**self.options())
        self.assertEqual(out['outcome_counts'][c.OUTCOMES[1]],1)
        self.assertFalse(out['keeper_outcomes'][0]['latest_head_entire_history_caller_sha_pins_present'])

    def test_e_missing_predecessor_pin_cannot_hide_behind_pinned_new_receipt(self):
        a=self.record(0,pinned=False)
        self.record(0,kind=c.RENEW,seq=2,prev=a)
        out=c.audit_external_custody(**self.options())
        self.assertEqual(out['outcome_counts'][c.OUTCOMES[1]],1)

    def test_f_current_expiration_is_explicit_and_no_trusted_clock_claim(self):
        self.record(0,expires='2026-10-25T14:20:00Z');self.record(1)
        out=c.audit_external_custody(**self.options())
        self.assertEqual(out['outcome_counts'][c.OUTCOMES[4]],1)
        self.assertFalse(out['self_reported_signed_expiry_is_a_trusted_clock'])

    def test_g_signed_revocation_is_not_physical_deletion(self):
        original=self.record(0)
        self.record(0,kind=c.REVOKE,seq=2,prev=original)
        out=c.audit_external_custody(**self.options())
        self.assertEqual(out['outcome_counts'][c.OUTCOMES[3]],1)
        self.assertFalse(out['signed_revocation_erases_any_bytes_or_remote_storage'])

    def test_h_two_same_parent_genuinely_signed_forks_no_winner_selected(self):
        original=self.record(0)
        self.record(0,kind=c.RENEW,seq=2,prev=original)
        self.record(0,kind=c.REVOKE,seq=2,prev=original)
        out=c.audit_external_custody(**self.options())
        self.assertEqual(out['outcome_counts'][c.OUTCOMES[2]],1)
        self.assertEqual(len(out['keeper_outcomes'][0]['signed_head_original_raw_sha256s']),2)
        self.assertIsNone(out['keeper_outcomes'][0]['latest_single_head_kind'])

    def test_i_fork_cannot_select_any_head_for_local_retest(self):
        a=self.record(0);b=self.record(0,kind=c.RENEW,seq=2,prev=a)
        self.record(0,kind=c.RENEW,seq=2,prev=a)
        with self.assertRaisesRegex(anchor.AnchorError,'CANNOT_PICK_A_FORK'):
            c.audit_external_custody(**self.options(presented=[self.present(b)]))

    def test_j_same_signed_bytes_new_explicit_ledgers_and_copy_retest(self):
        a=self.record(0);self.record(1)
        out=c.audit_external_custody(**self.options(presented=[self.present(a)]))
        self.assertTrue(out['keeper_outcomes'][0]['local_explicit_retest'][
            'matches_signed_keeper_claimed_bytes'])
        self.assertEqual(out['explicitly_presented_ledger_and_copy_pair_count'],1)

    def test_k_later_mutated_local_bytes_retest_detects_actual_drift(self):
        a=self.record(0)
        out=c.audit_external_custody(**self.options(presented=[self.present(a,mutate=True)]))
        self.assertEqual(out['outcome_counts'][c.OUTCOMES[6]],1)
        self.assertFalse(out['keeper_outcomes'][0]['local_explicit_retest'][
            'matches_signed_keeper_claimed_bytes'])

    def test_l_wrong_ledger_original_digest_is_not_implicitly_repaired(self):
        a=self.record(0)
        bad=self.present(a)
        with self.assertRaises(anchor.AnchorError):
            c.audit_external_custody(**self.options(presented=[(bad[0],bad[1],
                'cc'*32,*bad[3:])]))

    def test_m_claim_differs_from_prior_receiver_but_signed_and_visible(self):
        self.record(0,snapshot_sha='ee'*32)
        result=c.audit_external_custody(**self.options())
        self.assertEqual(result['outcome_counts'][c.OUTCOMES[5]],1)

    def test_n_reusing_ec343_original_signing_key_or_org_denied(self):
        bad=copy.deepcopy(self.actors)
        bad[0]['public_hex']=self.f.actors[2]['public_hex']
        self.directory=self.make_directory(custodians=bad)
        with self.assertRaisesRegex(anchor.AnchorError,'ROOT_KEEPER_MUST_NOT_RECYCLE'):
            c.audit_external_custody(**self.options())

    def test_o_forged_receipt_with_whole_sha_repin_still_fails_ed25519(self):
        a=self.record(0)
        fake=json.loads(Path(a[0]).read_text())
        fake['claim']['claimed_snapshot_original_raw_sha256']='bb'*32
        p,s=self.write('forged-keeper',fake)
        args=self.options(keeper_receipt_files=[p],keeper_receipt_shas=[s])
        with self.assertRaises(anchor.AnchorError):
            c.audit_external_custody(**args)

    def test_p_wrong_keeper_private_key_denied(self):
        self.record(0,signature_key=self.keeper_keys[1])
        with self.assertRaises(anchor.AnchorError):
            c.audit_external_custody(**self.options())

    def test_q_signed_parent_mutation_denies_regardless_of_external_report(self):
        self.record(0)
        with self.assertRaises(anchor.AnchorError):
            c.audit_external_custody(**self.options(readback_response_shas=['aa'*32,
                *self.old['readback_response_shas'][1:]]))

    def test_r_reused_nonce_from_ec347_parent_denied(self):
        self.record(0,overrides={'statement_nonce_sha256':self.challenges[0][2]['challenge_nonce_sha256']})
        with self.assertRaisesRegex(anchor.AnchorError,'REPEATED_KEEPER_SIGNATURE_OR_NONCE'):
            c.audit_external_custody(**self.options())

    def test_s_noncontiguous_predecessor_is_not_silently_fetched(self):
        self.record(0,kind=c.RENEW,seq=2,overrides={
            'previous_statement_file':str(self.w/'hidden-previous.json'),
            'previous_statement_original_raw_sha256':'cc'*32})
        with self.assertRaisesRegex(anchor.AnchorError,'SUCCESSOR_NEEDS_EXPLICIT_PREVIOUS'):
            c.audit_external_custody(**self.options())

    def test_t_shared_external_ledger_original_downgrades_independence(self):
        first=self.record(0)
        self.record(1,ledger_sha=first[2]['ledger_original_raw_sha256'])
        out=c.audit_external_custody(**self.options())
        self.assertEqual(len(out['shared_ledger_original_raw_sha256s']),1)
        self.assertTrue(all(row['shares_same_ledger_original_with_another_keeper']
                            for row in out['keeper_outcomes']))
        self.assertFalse(out['distinct_keys_or_ledger_ids_prove_distinct_machines'])

    def test_u_both_distinct_root_and_custody_ed25519_domains_checked(self):
        bogus=copy.deepcopy(self.directory[2])
        bogus['valid_until_utc']='2026-10-25T16:00:00Z'
        self.directory=(*self.write('tampered-directory',
                          {'schema':c.DIRECTORY_SCHEMA,'claim':bogus,
                           'signature_ed25519':json.loads(Path(self.directory[0]).read_text())['signature_ed25519']}),bogus)
        with self.assertRaises(anchor.AnchorError):
            c.audit_external_custody(**self.options())

    def test_v_standalone_fixed_isolated_no_private_key_audit(self):
        self.record(0);self.record(1)
        args=self.options()
        cmd=[sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_cas_external_keeper_custody.py'),
             'audit-external-custody']
        for key in (*cli.SCALARS,*cli.EXTRA_SCALARS):
            cmd.extend(('--'+key.replace('_','-'),str(args[key])))
        for key in (*cli.PARENT_REPEATS,*cli.EXTRA_REPEATS):
            for value in args[key]:
                cmd.extend(('--'+cli.FLAGS[key].replace('_','-'),value))
        out=subprocess.run(cmd,cwd=str(ROOT),capture_output=True,text=True,timeout=150)
        self.assertEqual(out.returncode,2,out.stderr+out.stdout)
        self.assertEqual(json.loads(out.stdout)['outcome_counts'][c.OUTCOMES[7]],2)
        self.assertNotIn('--private-key-file',cli.parser().format_help())
        self.assertNotIn('private_key_file',json.loads(out.stdout))

    def test_w_unified_fixed_route_accepts_true_pins_and_has_no_writer(self):
        self.record(0);self.record(1)
        args=self.options()
        cmd=[sys.executable,'-I','-B',str(ROOT/'scripts'/'ces_next.py'),
             'audit-external-keeper-custody','DeliveryAudit','AuditExternalKeeperCustody']
        for key in (*cli.SCALARS,*cli.EXTRA_SCALARS):
            cmd.extend(('--'+key.replace('_','-'),str(args[key])))
        for key in (*cli.PARENT_REPEATS,*cli.EXTRA_REPEATS):
            for val in args[key]:
                cmd.extend(('--'+cli.FLAGS[key].replace('_','-'),val))
        out=subprocess.run(cmd,cwd=str(ROOT),capture_output=True,text=True,timeout=150)
        self.assertEqual(out.returncode,2,out.stderr+out.stdout)
        result=json.loads(out.stdout)
        self.assertEqual(result['outcome_counts'][c.OUTCOMES[7]],2)
        self.assertFalse(result['remote_provider_cas_worm_or_legal_action_executed'])
        cmd[6]='IssuerRootRotation'  # cannot gain signing capability by choosing another mode
        reject=subprocess.run(cmd,cwd=str(ROOT),capture_output=True,text=True,timeout=150)
        self.assertEqual(reject.returncode,3,reject.stderr+reject.stdout)
        self.assertFalse(json.loads(reject.stdout)['permissions_granted'])
        from scripts import ces_next
        parser=ces_next.build_parser()
        flags={f for opt in parser._subparsers._group_actions[0].choices[
               'audit-external-keeper-custody']._actions for f in opt.option_strings}
        for forbidden in ('--private-key-file','--out','--copy-file','--write',
                          '--provider','--cas','--worm'):
            self.assertNotIn(forbidden,flags)

    def test_x_directory_source_and_independently_supplied_root_pins_are_mandatory(self):
        self.record(0)
        with self.assertRaises(anchor.AnchorError):
            c.audit_external_custody(**self.options(
                expected_keeper_directory_sha256='ab'*32))
        with self.assertRaisesRegex(anchor.AnchorError,'SEPARATE_EXTERNALLY_SUPPLIED_ROOT'):
            c.audit_external_custody(**self.options(
                expected_directory_root_public_hex=pub(self.keeper_keys[0])))

    def test_y_presented_keeper_raw_byte_paths_cannot_alias_ec346_original_copies(self):
        a=self.record(0)
        actual=self.present(a)
        observer=next(x[2] for x in reversed(self.events)
                      if x[2]['receiver_id']==self.actors[0]['subject_receiver_id'])
        with self.assertRaisesRegex(anchor.AnchorError,'KEEPER_AND_PRESENTED_BYTE_PATHS_MUST_NOT_ALIAS'):
            c.audit_external_custody(**self.options(presented=[
                (actual[0],actual[1],actual[2],observer['copy_snapshot_file'],actual[4])]))

    def test_z_noncanonical_keeper_receipt_order_refused_not_resorted_silently(self):
        a=self.record(0);b=self.record(1)
        with self.assertRaisesRegex(anchor.AnchorError,'KEEPER_RECEIPTS_MUST_BE_IN_CANONICAL_ORDER'):
            c.audit_external_custody(**self.options(
                keeper_receipt_files=[b[0],a[0]],
                keeper_receipt_shas=[b[1],a[1]]))

    def test_za_alleged_ledger_reference_cannot_equal_this_signed_receipt(self):
        first=self.record(0)
        # Rebind and *resign* an invalid ledger that loops to an older signed receipt.
        self.record(1,ledger_sha=first[1])
        with self.assertRaisesRegex(anchor.AnchorError,'LEDGER_CLAIM_CANNOT_SELF_LOOP'):
            c.audit_external_custody(**self.options())

    def test_zc_forward_reference_to_later_receipt_as_ledger_denied(self):
        later=self.record(1)
        self.record(0,ledger_sha=later[1])
        with self.assertRaisesRegex(anchor.AnchorError,'LEDGER_CLAIM_CANNOT_SELF_LOOP'):
            c.audit_external_custody(**self.options())

    def test_zd_only_explicitly_presented_ledger_is_opened(self):
        a=self.record(0)
        bogus=self.ledger_by_receipt[a[0]][0]
        Path(bogus).write_bytes(b'NOT_A_LEDGER_AFTER_SIGNING')
        # Unpresented ledger bytes are never opened, even though its SHA is claimed.
        out=c.audit_external_custody(**self.options())
        self.assertEqual(out['outcome_counts'][c.OUTCOMES[7]],1)
        presented=self.present(a)
        with self.assertRaises(anchor.AnchorError):
            c.audit_external_custody(**self.options(presented=[presented]))

    def test_ze_renewal_after_previous_signed_expiry_gap_is_visible(self):
        first=self.record(0,expires='2026-10-25T14:11:30Z')
        self.record(0,kind=c.RENEW,seq=2,prev=first)
        result=c.audit_external_custody(**self.options())
        row=result['keeper_outcomes'][0]
        self.assertTrue(row['signed_keeper_ancestry_has_self_reported_expiry_gap'])
        self.assertEqual(row['outcome'],c.OUTCOMES[4])
        self.assertTrue(row['latest_head_entire_history_caller_sha_pins_present'])
        self.assertFalse(result['self_reported_signed_expiry_is_a_trusted_clock'])

    def test_zb_external_directory_key_reuse_with_ec342_custodian_denied(self):
        gov=self.ctx['old_governance']
        fake=copy.deepcopy(self.actors)
        fake[0]['public_hex']=gov['reviewers'][0]['public_hex']
        self.directory=self.make_directory(custodians=fake)
        with self.assertRaisesRegex(anchor.AnchorError,'ROOT_KEEPER_MUST_NOT_RECYCLE'):
            c.audit_external_custody(**self.options())


if __name__=='__main__':
    unittest.main()
