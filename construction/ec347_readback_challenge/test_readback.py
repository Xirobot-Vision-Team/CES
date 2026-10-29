#!/usr/bin/env python3
"""EC347 focused actual Ed25519 signer/re-reader; inherited EC317/318 MOCK."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest

from ec295_delivery_anchor import anchor
from ec342_conflict_hold import test_hold as old_test
from ec346_disclosure_custody import test_custody as inherited
from . import readback as r
from . import operator

ROOT = Path(__file__).resolve().parents[2]


class ChallengedReadbackTests(unittest.TestCase):
    configure = inherited.ReceiverCopyCustodyTests.configure
    sign = inherited.ReceiverCopyCustodyTests.sign
    parameters = inherited.ReceiverCopyCustodyTests.parameters
    audit = inherited.ReceiverCopyCustodyTests.audit
    copies = inherited.ReceiverCopyCustodyTests.copies
    observation = inherited.ReceiverCopyCustodyTests.observation
    arguments = inherited.ReceiverCopyCustodyTests.arguments
    show = inherited.ReceiverCopyCustodyTests.show
    challenge = inherited.ReceiverCopyCustodyTests.challenge
    response = inherited.ReceiverCopyCustodyTests.response
    kw = inherited.ReceiverCopyCustodyTests.kw

    @classmethod
    def setUpClass(cls):
        inherited.ReceiverCopyCustodyTests.setUpClass()
        cls.f = inherited.ReceiverCopyCustodyTests.f
        cls.root = inherited.ReceiverCopyCustodyTests.root

    @classmethod
    def tearDownClass(cls):
        inherited.ReceiverCopyCustodyTests.tearDownClass()

    def setUp(self):
        inherited.ReceiverCopyCustodyTests.setUp(self)
        self.observation(0)
        self.observation(1)
        base = self.arguments()
        self.source = {k: v for k, v in base.items() if k in r.PARENT_KEYS}
        self.challenges = []
        self.replies = []
        self.nonce = 225

    def nonce_sha(self):
        self.nonce += 1
        return f'{self.nonce:02x}'*32

    def issue(self, *, round_number=1, previous=None, **overrides):
        path = str(self.w/f'readback-challenge-{len(self.challenges)}.json')
        args = {'out': path, 'private_key_file': self.f.key_paths[0],
                'audience_receiver_ids': [a['signer_id'] for a in self.f.actors[2:]],
                'round_number': round_number,
                'challenge_nonce_sha256': self.nonce_sha(),
                'issued_utc': f'2026-10-25T13:{50+round_number:02d}:00Z',
                'previous_challenge_file': previous[0] if previous else None,
                'expected_previous_challenge_sha256': previous[1] if previous else None,
                **self.source}
        args.update(overrides)
        result = r.issue_challenge(**args)
        self.assertEqual(result['exit_code'], 2)
        self.assertEqual(stat.S_IMODE(Path(path).stat().st_mode), 0o600)
        row = (path, old_test.sha(path), json.loads(Path(path).read_text())['claim'])
        self.challenges.append(row)
        return row

    def reply(self, challenge, receiver=0, kind=r.MEASURED, **overrides):
        path = str(self.w/f'readback-reply-{len(self.replies)}.json')
        row = next(e for e in reversed(self.events)
                   if e[2]['receiver_id'] == self.f.actors[receiver+2]['signer_id'])
        args = {'out': path, 'private_key_file': self.f.key_paths[receiver+2],
                'challenge_file': challenge[0],
                'expected_challenge_sha256': challenge[1],
                'response_kind': kind, 'response_nonce_sha256': self.nonce_sha(),
                'reported_utc': f'2026-10-25T13:{53+challenge[2]["round_number"]:02d}:00Z',
                'copy_snapshot_file': row[2]['copy_snapshot_file'] if kind == r.MEASURED else None,
                'copy_ack_set_file': row[2]['copy_ack_set_file'] if kind == r.MEASURED else None,
                **self.source}
        args.update(overrides)
        result = r.sign_readback(**args)
        self.assertEqual(result['exit_code'], 2)
        data = (path, old_test.sha(path), json.loads(Path(path).read_text())['claim'])
        self.replies.append(data)
        return data

    def params(self, *, presented=(), **overrides):
        replies = sorted(self.replies, key=lambda p: (
            p[2]['round_number'], next(i for i,a in enumerate(self.f.actors[2:])
                if a['signer_id'] == p[2]['receiver_id'])))
        return {**self.source,
            'readback_evaluation_utc': '2026-10-25T14:00:00Z',
            'readback_challenge_files': [x[0] for x in self.challenges],
            'readback_challenge_shas': [x[1] for x in self.challenges],
            'readback_response_files': [x[0] for x in replies],
            'readback_response_shas': [x[1] for x in replies],
            'presented_receiver_ids': [x[0] for x in presented],
            'presented_snapshot_files': [x[1] for x in presented],
            'presented_ack_set_files': [x[2] for x in presented],
            **overrides}

    def test_a_real_signed_challenge_two_independent_receiver_reopens(self):
        c = self.issue()
        self.reply(c, 0)
        self.reply(c, 1)
        report = r.audit_readbacks(**self.params())
        self.assertEqual(report['exit_code'], 2)
        self.assertEqual(report['signed_response_count'], 2)
        self.assertEqual(report['outcome_counts'][r.OUTCOMES[0]], 2)
        self.assertTrue(report['ec345_through_ec346_original_signed_history_replayed'])
        self.assertFalse(report['separate_ed25519_keys_prove_different_physical_machines'])
        self.assertEqual(report['explicitly_presented_latest_round_copy_count'], 0)

    def test_b_auditor_uses_only_explicit_represented_last_round_paths(self):
        c = self.issue(); self.reply(c, 0); self.reply(c, 1)
        report = r.audit_readbacks(**self.params(presented=self.show(0,1)))
        self.assertEqual(report['explicitly_presented_latest_round_copy_count'], 2)
        self.assertTrue(all(x['auditor_actual_byte_measurement']['matches_signed_remeasurement']
            for x in report['per_receiver_round_outcomes']))

    def test_c_challenge_with_no_reply_stays_unanswered_not_globally_missing(self):
        self.issue()
        report = r.audit_readbacks(**self.params())
        self.assertEqual(report['outcome_counts'][r.OUTCOMES[4]], 2)
        self.assertEqual(report['status'], 'challenged_receiver_unanswered_unresolved')
        self.assertFalse(report['unavailable_claim_or_unanswered_challenge_proves_global_loss'])

    def test_d_signed_unavailable_does_not_claim_read_any_bytes(self):
        c = self.issue(); unavailable = self.reply(c, 0, r.UNAVAILABLE)
        self.reply(c, 1)
        report = r.audit_readbacks(**self.params())
        self.assertFalse(unavailable[2]['bytes_reopened_after_challenge'])
        self.assertIsNone(unavailable[2]['copy_snapshot_original_raw_sha256'])
        self.assertEqual(report['outcome_counts'][r.OUTCOMES[3]], 1)

    def test_e_mutation_after_response_requires_explicit_presented_read(self):
        c = self.issue(); event = self.reply(c, 0); self.reply(c, 1)
        Path(event[2]['copy_snapshot_file']).write_bytes(b'CHANGED_AFTER_EC347_RESPONSE')
        no_read = r.audit_readbacks(**self.params())
        self.assertEqual(no_read['outcome_counts'][r.OUTCOMES[5]], 0)
        report = r.audit_readbacks(**self.params(presented=self.show(0,1)))
        self.assertEqual(report['outcome_counts'][r.OUTCOMES[5]], 1)
        self.assertEqual(report['status'], r.STATUS_ORDER[0])

    def test_f_mutation_before_reopen_explicitly_disagrees_with_older_sha(self):
        c = self.issue()
        row = self.events[0][2]
        Path(row['copy_ack_set_file']).write_bytes(b'ALTERED_BEFORE_READBACK')
        self.reply(c, 0); self.reply(c, 1)
        report = r.audit_readbacks(**self.params())
        self.assertEqual(report['outcome_counts'][r.OUTCOMES[1]], 1)
        self.assertEqual(report['status'], r.STATUS_ORDER[1])

    def test_g_two_challenge_rounds_chained_and_same_bytes_claim(self):
        q1 = self.issue(); self.reply(q1,0); self.reply(q1,1)
        q2 = self.issue(round_number=2, previous=q1)
        self.reply(q2,0); self.reply(q2,1)
        out = r.audit_readbacks(**self.params())
        self.assertEqual(out['challenge_round_count'], 2)
        self.assertEqual(out['outcome_counts'][r.OUTCOMES[0]], 4)
        self.assertEqual(out['claimed_same_bytes_on_two_or_more_distinct_signed_rounds_receiver_ids'],
                         [a['signer_id'] for a in self.f.actors[2:]])
        self.assertFalse(out['unchanged_repeated_reads_prove_future_physical_durability'])

    def test_h_wrong_proposer_key_denied_even_with_matching_claimed_org(self):
        with self.assertRaisesRegex(anchor.AnchorError, 'ONLY_INDEPENDENT_EC343_CHANGE_PROPOSER'):
            self.issue(private_key_file=self.f.key_paths[2])

    def test_i_wrong_receiver_key_and_unlisted_role_denied(self):
        c = self.issue()
        with self.assertRaisesRegex(anchor.AnchorError, 'ONLY_CHALLENGED_ORIGINAL_RECEIVER'):
            self.reply(c, 0, private_key_file=self.f.key_paths[0])

    def test_j_tampered_signed_challenge_fails_even_with_new_whole_sha(self):
        c = self.issue()
        edited = json.loads(Path(c[0]).read_text())
        edited['claim']['issued_utc'] = '2026-10-25T13:59:00Z'
        path = str(self.w/'tampered-challenge.json')
        old_test.canonical(path, edited)
        with self.assertRaisesRegex(anchor.AnchorError, 'ED25519_INVALID'):
            self.reply(c, 0, challenge_file=path,
                       expected_challenge_sha256=old_test.sha(path))

    def test_k_tampered_signed_readback_fails_even_with_new_sha(self):
        c = self.issue(); entry = self.reply(c,0); self.reply(c,1)
        forged = json.loads(Path(entry[0]).read_text())
        forged['claim']['matches_ec346_signed_bytes'] = False
        path = str(self.w/'forged-reply.json'); old_test.canonical(path, forged)
        args = self.params()
        args['readback_response_files'][0] = path
        args['readback_response_shas'][0] = old_test.sha(path)
        with self.assertRaises(anchor.AnchorError):
            r.audit_readbacks(**args)

    def test_l_parent_original_sha_drift_denies_new_challenge(self):
        with self.assertRaises(anchor.AnchorError):
            self.issue(**{'observation_shas': ['bb'*32,*self.source['observation_shas'][1:]]})

    def test_m_nonce_colliding_with_ec346_older_signature_rejected(self):
        with self.assertRaisesRegex(anchor.AnchorError, 'AUDIENCE_MUST_BE_ACTIVE_CANONICAL_AND_NONCE_NEW'):
            self.issue(challenge_nonce_sha256=self.events[0][2]['event_nonce_sha256'])

    def test_n_noncanonical_audience_and_absent_receiver_rejected(self):
        with self.assertRaisesRegex(anchor.AnchorError, 'AUDIENCE_MUST_BE_ACTIVE_CANONICAL'):
            self.issue(audience_receiver_ids=[a['signer_id'] for a in reversed(self.f.actors[2:])])

    def test_o_second_challenge_must_reference_real_first_sha_and_contiguous_round(self):
        q1 = self.issue()
        with self.assertRaises(anchor.AnchorError):
            self.issue(round_number=2, previous=q1,
                       expected_previous_challenge_sha256='aa'*32)
        with self.assertRaisesRegex(anchor.AnchorError, 'SUCCESSOR_CHALLENGE_CHAIN_ROUND'):
            self.issue(round_number=3, previous=q1)

    def test_p_audit_must_explicitly_present_all_previous_challenges(self):
        q1 = self.issue(); q2 = self.issue(round_number=2, previous=q1)
        params = self.params()
        params['readback_challenge_files'] = [q2[0]]
        params['readback_challenge_shas'] = [q2[1]]
        with self.assertRaisesRegex(anchor.AnchorError, 'EVERY_SIGNED_CHALLENGE_ROUND'):
            r.audit_readbacks(**params)

    def test_q_reused_response_nonce_from_challenge_or_other_signer_denied(self):
        c = self.issue()
        with self.assertRaisesRegex(anchor.AnchorError, 'REPLY_NONCE_MUST_BE_NEW'):
            self.reply(c, 0, response_nonce_sha256=c[2]['challenge_nonce_sha256'])
        first = self.reply(c, 0)
        self.reply(c, 1, response_nonce_sha256=first[2]['response_nonce_sha256'])
        with self.assertRaisesRegex(anchor.AnchorError, 'REPLIES_MUST_BE_CANONICAL_UNIQUE_NO_NONCE'):
            r.audit_readbacks(**self.params())

    def test_r_two_receivers_cannot_replay_same_response_or_out_of_order(self):
        c = self.issue(); self.reply(c,0); self.reply(c,1)
        args = self.params()
        args['readback_response_files'].reverse(); args['readback_response_shas'].reverse()
        with self.assertRaisesRegex(anchor.AnchorError, 'REPLIES_MUST_BE_CANONICAL_UNIQUE'):
            r.audit_readbacks(**args)

    def test_s_presentation_only_latest_signed_replies_and_matching_paths(self):
        c = self.issue(); self.reply(c,0); self.reply(c,1)
        wrong = self.params(presented=self.show(0,1))
        wrong['presented_snapshot_files'][0] = self.source['head_snapshot_file']
        with self.assertRaises(anchor.AnchorError):
            r.audit_readbacks(**wrong)

    def test_t_unavailable_does_not_authorize_audit_copy_open(self):
        c = self.issue(); self.reply(c,0,r.UNAVAILABLE); self.reply(c,1)
        with self.assertRaisesRegex(anchor.AnchorError, 'ONLY_LATEST_MEASURED_SIGNER'):
            r.audit_readbacks(**self.params(presented=self.show(0)))

    def test_u_isolated_standalone_readonly_cli_with_actual_old_signatures(self):
        c = self.issue(); self.reply(c,0); self.reply(c,1)
        opts = self.params()
        cmd = [sys.executable, '-I','-B', str(ROOT/'scripts'/'ces_cas_readback_challenge.py'),
               'audit-readbacks']
        for k in operator.SCALARS + ('readback_evaluation_utc',):
            cmd.extend(('--'+k.replace('_','-'), str(opts[k])))
        for k in operator.PARENT_REPEATS + operator.AUDIT_REPEATS:
            for v in opts[k]:
                cmd.extend(('--'+operator.FLAGS[k].replace('_','-'),v))
        p = subprocess.run(cmd,cwd=str(ROOT),capture_output=True,text=True,timeout=150)
        self.assertEqual(p.returncode,2, p.stderr+p.stdout)
        result=json.loads(p.stdout)
        self.assertEqual(result['outcome_counts'][r.OUTCOMES[0]],2)
        self.assertFalse(result['readback_claim_executes_remote_cas_worm_provider_actions'])


    def test_v_unified_console_fixed_readonly_invocation(self):
        c = self.issue(); self.reply(c,0); self.reply(c,1)
        opts = self.params(presented=self.show(0,1))
        cmd = [sys.executable, '-I', '-B', str(ROOT/'scripts'/'ces_next.py'),
               'audit-readback-challenges', 'DeliveryAudit',
               'AuditChallengedReceiverReadbacks']
        for k in operator.SCALARS + ('readback_evaluation_utc',):
            cmd.extend(('--'+k.replace('_','-'),str(opts[k])))
        for k in operator.PARENT_REPEATS + operator.AUDIT_REPEATS:
            for val in opts[k]:
                cmd.extend(('--'+operator.FLAGS[k].replace('_','-'),val))
        out=subprocess.run(cmd,cwd=str(ROOT),capture_output=True,text=True,timeout=150)
        self.assertEqual(out.returncode,2,out.stderr+out.stdout)
        result=json.loads(out.stdout)
        self.assertEqual(result['explicitly_presented_latest_round_copy_count'],2)
        self.assertEqual(result['outcome_counts'][r.OUTCOMES[0]],2)
        self.assertTrue(result['all_actual_byte_checks_are_local_and_explicit_only'])
        cmd[5]='AuditSignedReceiverCopies'  # incorrect mode has no signing escape
        out=subprocess.run(cmd,cwd=str(ROOT),capture_output=True,text=True,timeout=150)
        self.assertNotEqual(out.returncode,2)
        self.assertFalse(json.loads(out.stdout)['permissions_granted'])

    def test_w_unified_route_has_no_private_key_or_candidate_writer_flag(self):
        from scripts import ces_next
        from io import StringIO
        from contextlib import redirect_stdout
        with self.assertRaises(ces_next.ConsoleError):
            ces_next.audit_readback_challenges('DeliveryAudit','WrongMode')
        p=ces_next.build_parser()
        isolated=[a for a in p._subparsers._group_actions[0].choices[
            'audit-readback-challenges']._actions if a.option_strings]
        opts={x for a in isolated for x in a.option_strings}
        self.assertNotIn('--private-key-file', opts)
        self.assertNotIn('--out', opts)
        self.assertNotIn('--response-kind', opts)


    def test_x_revoked_receiver_cannot_be_challenged_as_active_copy(self):
        from ec346_disclosure_custody import custody as parent
        self.observation(0,parent.REVOCATION,predecessor=self.events[0])
        base=self.arguments()
        self.source={k: v for k,v in base.items() if k in r.PARENT_KEYS}
        with self.assertRaisesRegex(anchor.AnchorError,'AUDIENCE_MUST_BE_ACTIVE_CANONICAL'):
            self.issue()

    def test_y_changed_or_undeclared_copy_paths_rejected_by_signer(self):
        c=self.issue()
        oldpath=self.events[0][2]['copy_snapshot_file']
        with self.assertRaisesRegex(anchor.AnchorError,'REMEASUREMENT_EXACT_TWO_EXPLICIT'):
            self.reply(c,0,copy_snapshot_file=self.events[1][2]['copy_snapshot_file'])
        with self.assertRaisesRegex(anchor.AnchorError,'UNAVAILABLE_CLAIM_MUST_NOT_ACCESS'):
            self.reply(c,0,r.UNAVAILABLE,copy_snapshot_file=oldpath)

    def test_z_signer_may_not_issue_fourth_round_or_skip_round_two(self):
        first=self.issue()
        with self.assertRaisesRegex(anchor.AnchorError,'SUCCESSOR_CHALLENGE_CHAIN_ROUND'):
            self.issue(round_number=3,previous=first)
        second=self.issue(round_number=2,previous=first)
        third=self.issue(round_number=3,previous=second)
        self.assertEqual(third[2]['round_number'],3)
        with self.assertRaisesRegex(anchor.AnchorError,'CHALLENGE_INPUT_TYPES_INVALID'):
            self.issue(round_number=4,previous=third)

    def test_za_reused_response_nonce_across_challenge_rounds_fails_audit(self):
        first=self.issue(); reply=self.reply(first,0)
        second=self.issue(round_number=2,previous=first)
        self.reply(second,0,response_nonce_sha256=reply[2]['response_nonce_sha256'])
        with self.assertRaisesRegex(anchor.AnchorError,'REPLIES_MUST_BE_CANONICAL_UNIQUE_NO_NONCE'):
            r.audit_readbacks(**self.params())

    def test_zb_same_receiver_cannot_sign_two_distinct_replies_to_one_round(self):
        first=self.issue(); self.reply(first,0); self.reply(first,0)
        with self.assertRaisesRegex(anchor.AnchorError,'REPLIES_MUST_BE_CANONICAL_UNIQUE'):
            r.audit_readbacks(**self.params())


if __name__ == '__main__':
    unittest.main()
