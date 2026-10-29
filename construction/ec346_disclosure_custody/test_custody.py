#!/usr/bin/env python3
"""EC346 focused true receiver signatures & SHA comparisons; deep EC317/318 MOCK."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import unittest

from ec295_delivery_anchor import anchor
from ec342_conflict_hold import test_hold as old_test
from ec345_disclosure_challenge import test_challenge as inherited
from . import custody as c

ROOT = Path(__file__).resolve().parents[2]


class ReceiverCopyCustodyTests(unittest.TestCase):
    configure = inherited.DisclosureChallengeTests.configure
    sign = inherited.DisclosureChallengeTests.sign
    parameters = inherited.DisclosureChallengeTests.parameters
    audit = inherited.DisclosureChallengeTests.audit
    challenge = inherited.DisclosureChallengeTests.challenge
    response = inherited.DisclosureChallengeTests.response
    kw = inherited.DisclosureChallengeTests.kw

    @classmethod
    def setUpClass(cls):
        inherited.DisclosureChallengeTests.setUpClass()
        cls.f = inherited.DisclosureChallengeTests.f
        cls.root = inherited.DisclosureChallengeTests.root

    @classmethod
    def tearDownClass(cls):
        inherited.DisclosureChallengeTests.tearDownClass()

    def setUp(self):
        inherited.DisclosureChallengeTests.setUp(self)
        q = self.challenge()
        self.response(q, receiver=0, kind='offer_disclosure')
        self.response(q, receiver=1, kind='offer_disclosure')
        self.b = self.kw(['rev'])
        self.events = []
        self.counter = 0
        self.nonce_counter = 200

    def copies(self, signer: int, *, altered: bool = False):
        self.counter += 1
        snap = self.w / f'copy-{signer}-{self.counter}-snapshot.json'
        ack = self.w / f'copy-{signer}-{self.counter}-ack.json'
        shutil.copyfile(self.f.rev['snapshot_file'], snap)
        shutil.copyfile(self.f.rev['ack_set_file'], ack)
        os.chmod(snap, 0o600)
        os.chmod(ack, 0o600)
        if altered:
            ack.write_bytes(ack.read_bytes() + b'\nDIFFERENT_COPY_RAW_BYTES\n')
        return str(snap), str(ack)

    def observation(self, signer: int, kind: str = c.RECEIPT,
                    predecessor=None, files=None, **override):
        index = len(self.events)
        path = str(self.w / f'copy-event-{index}.json')
        sequence = 1 if predecessor is None else predecessor[2]['sequence'] + 1
        if kind == c.REVOCATION:
            files = (None, None)
        elif files is None:
            files = self.copies(signer)
        self.nonce_counter += 1
        args = {
            'out': path, 'private_key_file': self.f.key_paths[signer + 2],
            'item_id': 'rev', 'copy_id': f'copy_receiver_{signer}',
            'claimed_storage_id': f'storage_{signer}',
            'event_kind': kind, 'sequence': sequence,
            'event_nonce_sha256': f'{self.nonce_counter:02x}'*32,
            'reported_utc': f'2026-10-25T13:{39+sequence:02d}:00Z',
            'copy_snapshot_file': files[0], 'copy_ack_set_file': files[1],
            'previous_event_file': predecessor[0] if predecessor else None,
            'expected_previous_event_sha256': predecessor[1] if predecessor else None,
            **self.b,
        }
        args.update(override)
        result = c.sign_observation(**args)
        self.assertEqual(result['exit_code'], 2)
        self.assertEqual(stat.S_IMODE(Path(path).stat().st_mode), 0o600)
        sha = old_test.sha(path)
        event = (path, sha, json.loads(Path(path).read_text())['claim'])
        self.events.append(event)
        return event

    def arguments(self, presented=(), *, item='rev', **override):
        events = sorted(self.events, key=lambda event:
            (next(i for i, a in enumerate(self.f.actors[2:])
                  if a['signer_id'] == event[2]['receiver_id']), event[2]['sequence']))
        pairs = sorted(presented, key=lambda pair:
            next(i for i, a in enumerate(self.f.actors[2:])
                 if a['signer_id'] == pair[0]))
        return {
            **self.b, 'item_id': item,
            'custody_evaluation_utc': '2026-10-25T13:50:00Z',
            'observation_files': [event[0] for event in events],
            'observation_shas': [event[1] for event in events],
            'presented_receiver_ids': [p[0] for p in pairs],
            'presented_snapshot_files': [p[1] for p in pairs],
            'presented_ack_set_files': [p[2] for p in pairs],
            **override,
        }

    def show(self, *signer_ids):
        pairs = []
        for idx in signer_ids:
            who = self.f.actors[idx+2]['signer_id']
            event = next(e for e in reversed(self.events)
                         if e[2]['receiver_id'] == who)
            pairs.append((who, event[2]['copy_snapshot_file'],
                          event[2]['copy_ack_set_file']))
        return pairs

    def test_a_two_distinct_actual_receiver_signatures_two_verified_byte_pairs(self):
        self.observation(0)
        self.observation(1)
        result = c.audit_copies(**self.arguments(self.show(0, 1)))
        self.assertEqual(result['status'], 'multiple_identical_local_copies_unresolved')
        self.assertEqual(result['distinct_registered_receiver_signatures'], 2)
        self.assertEqual(result['copy_outcome_counts'][c.OUTCOMES[3]], 2)
        self.assertEqual(result['explicitly_presented_copy_count'], 2)
        self.assertTrue(result['verified_disclosed_source_replayed_ec345_through_ec337'])
        self.assertEqual(result['signed_copy_sha_difference_receiver_pairs'], [])
        self.assertFalse(result['signed_receipt_alone_proves_physical_inter_machine_transfer'])

    def test_b_signed_copies_without_explicit_audit_paths_are_not_verified_now(self):
        self.observation(0)
        self.observation(1)
        out = c.audit_copies(**self.arguments())
        self.assertEqual(out['status'], 'signed_copy_not_presented_in_this_audit_unresolved')
        self.assertEqual(out['explicitly_presented_copy_count'], 0)
        self.assertEqual(out['copy_outcome_counts'][c.OUTCOMES[2]], 2)

    def test_c_measured_destination_differs_from_source_not_hidden(self):
        self.observation(0)
        self.observation(1, files=self.copies(1, altered=True))
        out = c.audit_copies(**self.arguments(self.show(0, 1)))
        self.assertEqual(out['status'], 'presented_copy_differs_from_verified_source_unresolved')
        self.assertEqual(out['copy_outcome_counts'][c.OUTCOMES[1]], 1)
        self.assertEqual(len(out['signed_copy_sha_difference_receiver_pairs']), 1)
        self.assertEqual(len(out['explicitly_measured_copy_sha_difference_receiver_pairs']), 1)

    def test_d_copy_changed_after_signature_detected_without_lying_about_sha(self):
        first = self.observation(0)
        self.observation(1)
        Path(first[2]['copy_snapshot_file']).write_bytes(b'CHANGED_AFTER_RECEIPT')
        result = c.audit_copies(**self.arguments(self.show(0, 1)))
        self.assertEqual(result['status'],
                         'presented_copy_changed_since_signed_observation_unresolved')
        a = result['receiver_copies'][0]['presented_copy_measurement']
        self.assertFalse(a['matches_signed_observation'])
        self.assertFalse(a['matches_verified_disclosed_source'])

    def test_e_signed_replacement_is_a_new_event_not_mutation_of_previous(self):
        first = self.observation(0)
        replaced = self.observation(0, c.REPLACEMENT,
            predecessor=first, files=self.copies(0, altered=True))
        self.observation(1)
        out = c.audit_copies(**self.arguments(self.show(0, 1)))
        self.assertEqual(out['signed_event_count'], 3)
        self.assertEqual(out['receiver_copies'][0]['signed_event_kinds'],
                         [c.RECEIPT, c.REPLACEMENT])
        self.assertEqual(out['receiver_copies'][0]['signed_event_original_raw_sha256s'],
                         [first[1], replaced[1]])
        self.assertTrue(out['receiver_copies'][0]
                            ['replacement_is_claim_only_not_change_to_prior_original'])
        self.assertEqual(out['status'], 'presented_copy_differs_from_verified_source_unresolved')

    def test_f_signed_revocation_does_not_claim_bytes_were_deleted(self):
        first = self.observation(0)
        self.observation(0, c.REVOCATION, predecessor=first)
        self.observation(1)
        out = c.audit_copies(**self.arguments(self.show(0,1)))
        self.assertEqual(out['status'], 'revocation_or_replacement_claim_unresolved')
        self.assertTrue(out['receiver_copies'][0]
                            ['revocation_is_claim_only_not_physical_deletion'])
        self.assertTrue(Path(first[2]['copy_snapshot_file']).is_file())
        self.assertFalse(out['signed_revocation_claim_deletes_or_erases_any_original'])

    def test_g_revocation_cannot_have_new_measured_file_fields(self):
        first = self.observation(0)
        a, b = self.copies(0)
        with self.assertRaisesRegex(anchor.AnchorError, 'REVOCATION_IS_CLAIM_ONLY'):
            c.sign_observation(out=str(self.w/'bad-rev.json'),
                private_key_file=self.f.key_paths[2], item_id='rev',
                copy_id='copy_receiver_0', claimed_storage_id='storage_0',
                event_kind=c.REVOCATION, sequence=2,
                event_nonce_sha256='df'*32, reported_utc='2026-10-25T13:42:00Z',
                previous_event_file=first[0],
                expected_previous_event_sha256=first[1],
                copy_snapshot_file=a, copy_ack_set_file=b, **self.b)

    def test_h_fake_issuer_or_other_receiver_key_cannot_sign_custody(self):
        with self.assertRaisesRegex(anchor.AnchorError, 'ONLY_EC343_REGISTERED_RECEIVER'):
            c.sign_observation(out=str(self.w/'issuer.json'),
                private_key_file=self.f.key_paths[0], item_id='rev',
                copy_id='bad', claimed_storage_id='other', event_kind=c.RECEIPT,
                sequence=1, event_nonce_sha256='d1'*32,
                reported_utc='2026-10-25T13:40:00Z',
                **dict(zip(('copy_snapshot_file','copy_ack_set_file'),self.copies(0))),
                **self.b)

    def test_i_without_original_source_or_ec345_offer_signature_no_receipt(self):
        p = self.b.copy()
        p['disclosed_item_ids'] = []
        with self.assertRaisesRegex(anchor.AnchorError, 'SOURCE_MUST_BE_EXPLICITLY_FURNISHED'):
            c.sign_observation(out=str(self.w/'no-source.json'),
                private_key_file=self.f.key_paths[2], item_id='rev',
                copy_id='bad', claimed_storage_id='storage', event_kind=c.RECEIPT,
                sequence=1, event_nonce_sha256='d2'*32,
                reported_utc='2026-10-25T13:40:00Z',
                **dict(zip(('copy_snapshot_file','copy_ack_set_file'),self.copies(0))),
                **p)

    def test_j_forged_signature_with_new_file_sha_still_rejected(self):
        first = self.observation(0)
        self.observation(1)
        forged = copy.deepcopy(json.loads(Path(first[0]).read_text()))
        forged['claim']['copy_id'] = 'counterfeit'
        fake_path = str(self.w/'forged-observation.json')
        old_test.canonical(fake_path, forged)
        fake_sha = old_test.sha(fake_path)
        a = self.arguments()
        a['observation_files'][0] = fake_path
        a['observation_shas'][0] = fake_sha
        with self.assertRaisesRegex(anchor.AnchorError, 'ED25519_INVALID'):
            c.audit_copies(**a)

    def test_k_wrong_externally_pinned_event_sha_fails_before_acceptance(self):
        self.observation(0)
        self.observation(1)
        a = self.arguments()
        a['observation_shas'][0] = 'c1'*32
        with self.assertRaises(anchor.AnchorError):
            c.audit_copies(**a)

    def test_l_two_real_receivers_cannot_reuse_same_nonce(self):
        a = self.observation(0)
        self.observation(1, event_nonce_sha256=a[2]['event_nonce_sha256'])
        with self.assertRaisesRegex(anchor.AnchorError, 'REUSED_NONCE'):
            c.audit_copies(**self.arguments())

    def test_m_missing_or_noncontiguous_predecessor_is_not_silent(self):
        first = self.observation(0)
        self.observation(0, c.REPLACEMENT, predecessor=first)
        self.observation(1)
        a = self.arguments()
        a['observation_files'] = a['observation_files'][1:]
        a['observation_shas'] = a['observation_shas'][1:]
        with self.assertRaisesRegex(anchor.AnchorError,
                                    'ALL_SIGNED_PREDECESSOR_EVENTS'):
            c.audit_copies(**a)

    def test_n_noncanonical_order_and_duplicate_receipt_for_same_actor_denied(self):
        self.observation(0)
        self.observation(1)
        args = self.arguments()
        args['observation_files'].reverse(); args['observation_shas'].reverse()
        with self.assertRaisesRegex(anchor.AnchorError, 'EVENTS_MUST_BE_GROUPED'):
            c.audit_copies(**args)
        self.observation(0)
        with self.assertRaisesRegex(anchor.AnchorError, 'ALL_SIGNED_PREDECESSOR'):
            c.audit_copies(**self.arguments())

    def test_o_explicitly_presented_paths_cannot_be_spoofed_or_aliased(self):
        self.observation(0)
        self.observation(1)
        a = self.arguments(self.show(0, 1))
        a['presented_snapshot_files'][0] = a['presented_snapshot_files'][1]
        with self.assertRaisesRegex(anchor.AnchorError,
                                    'PRESENTED_COPY_CANNOT_ALIAS'):
            c.audit_copies(**a)

    def test_p_future_or_pre_disclosure_self_reported_times_denied(self):
        with self.assertRaisesRegex(anchor.AnchorError,
                                    'EVENT_ARGS_AND_SELF_REPORTED_TIME_INVALID'):
            self.observation(0, reported_utc='2026-10-25T13:30:00Z')
        self.observation(0, reported_utc='2026-10-25T13:55:00Z')
        self.observation(1)
        with self.assertRaisesRegex(anchor.AnchorError,
                                    'REUSED_NONCE_DUPLICATE_EVENT_OR_FUTURE_SIGNED_TIME'):
            c.audit_copies(**self.arguments())

    def test_q_revoked_chain_cannot_restart_and_max_three_real_events(self):
        first = self.observation(0)
        revoked = self.observation(0, c.REVOCATION, predecessor=first)
        with self.assertRaisesRegex(anchor.AnchorError, 'SUCCESSOR_MUST_MATCH_OWN_NONREVOKED'):
            self.observation(0, c.REPLACEMENT, predecessor=revoked)
        first = self.observation(1)
        second = self.observation(1, c.REPLACEMENT, predecessor=first)
        self.observation(1, c.REPLACEMENT, predecessor=second)
        with self.assertRaisesRegex(anchor.AnchorError, 'EVENT_ARGS_AND_SELF_REPORTED_TIME_INVALID'):
            self.observation(1, c.REPLACEMENT, predecessor=self.events[-1])

    def test_r_revocation_claims_do_not_conceal_altered_presented_copy(self):
        first = self.observation(0)
        self.observation(0, c.REVOCATION, predecessor=first)
        self.observation(1)
        Path(first[2]['copy_ack_set_file']).write_bytes(b'LOST_CUSTODY_CONTENT')
        out = c.audit_copies(**self.arguments(self.show(0, 1)))
        self.assertEqual(out['status'],
                         'presented_copy_changed_since_signed_observation_unresolved')
        self.assertTrue(out['receiver_copies'][0]['revocation_is_claim_only_not_physical_deletion'])

    def test_s_tampered_ec345_source_cannot_be_made_valid_by_copy_signatures(self):
        # This scenario must use a copied controlled snapshot, not mutate the
        # class-shared original fixture used by other tests.
        self.observation(0)
        self.observation(1)
        wrong = self.arguments()
        wrong['challenge_shas'] = ['e1'*32]
        with self.assertRaises(anchor.AnchorError):
            c.audit_copies(**wrong)

    def test_t_exclusive_signing_file_and_no_original_output_alias(self):
        first = self.observation(0)
        with self.assertRaises(anchor.AnchorError):
            self.observation(0, out=first[0])
        self.observation(1)
        self.assertEqual(c.audit_copies(**self.arguments())['exit_code'], 2)

    def test_u_actual_standalone_and_unified_readonly_subprocess(self):
        first = self.observation(0)
        self.observation(1)
        cmd = [sys.executable, '-I', '-B', str(ROOT/'scripts'/'ces_cas_disclosure_custody.py'),
               'audit-copies']
        args = self.arguments(self.show(0,1))
        from . import operator as op
        for k in op.BASELINE:
            cmd.extend(['--'+k.replace('_','-'),str(args[k])])
        for k in ('item_id','custody_evaluation_utc'):
            cmd.extend(['--'+k.replace('_','-'),args[k]])
        for key, option in op.REPEAT.items():
            for value in args[key]: cmd.extend(['--'+option.replace('_','-'),value])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 2, result.stderr+'\n'+result.stdout)
        self.assertEqual(json.loads(result.stdout)['schema'], c.RESULT_SCHEMA)
        other = [sys.executable, '-I', '-B', str(ROOT/'scripts'/'ces_next.py'),
                 'audit-disclosure-copies', 'DeliveryAudit',
                 'AuditPostDisclosureReceiverCopies', *cmd[5:]]
        # cmd[5:] starts after python/-I/-B/script/audit-copies
        result = subprocess.run(other, capture_output=True, text=True, timeout=180)
        self.assertEqual(result.returncode, 2, result.stderr+'\n'+result.stdout)
        data = json.loads(result.stdout)
        self.assertEqual(data['status'], 'multiple_identical_local_copies_unresolved')
        self.assertFalse(data['claimed_storage_id_proves_distinct_machine_or_organization'])
        deny = subprocess.run(other[:5]+['--private-key-file','/tmp/invalid']+other[5:],
                              capture_output=True, text=True, timeout=20)
        self.assertEqual(deny.returncode, 2)
        self.assertIn('unrecognized arguments', deny.stderr)
        self.assertFalse(deny.stdout.strip())

    def test_v_full_original_pair_with_real_ec345_signed_conflict_still_replays(self):
        # Signed EC345 'unavailable' by second party can coexist with later copy.
        # Rebuild EC345 response list from true originals; no fabricated overwrite.
        q = (self.challenges[0], self.challenge_shas[0])
        other = self.response(q, receiver=1, kind=c.previous.UNAVAILABLE,
                              nonce='f7'*32)
        self.b = self.kw(['rev'])
        self.b['response_files'] = [self.responses[0], other[0]]
        self.b['response_shas'] = [self.response_shas[0], other[1]]
        self.observation(0)
        self.observation(1)
        out = c.audit_copies(**self.arguments(self.show(0,1)))
        self.assertEqual(out['status'], 'multiple_identical_local_copies_unresolved')
        self.assertEqual(out['distinct_registered_receiver_signatures'], 2)


    def test_w_true_signer_cli_creates_private_sha_pinned_bytes_receipt(self):
        files = self.copies(0)
        out = str(self.w / 'real-cli-receipt.json')
        cmd = [sys.executable, '-I', '-B', str(ROOT/'scripts'/'ces_cas_disclosure_custody.py'),
               'sign-observation']
        from . import operator as op
        for k in op.BASELINE:
            cmd.extend(['--'+k.replace('_','-'),str(self.b[k])])
        for name, value in (
            ('out', out), ('private_key_file', self.f.key_paths[2]),
            ('item_id', 'rev'), ('copy_id', 'cli_copied_original'),
            ('claimed_storage_id', 'no_machine_claim'),
            ('event_kind', 'receipt'), ('sequence', '1'),
            ('event_nonce_sha256', 'b7'*32),
            ('reported_utc', '2026-10-25T13:40:00Z'),
            ('copy_snapshot_file', files[0]), ('copy_ack_set_file', files[1])):
            cmd.extend(['--'+name.replace('_','-'),str(value)])
        for key, option in op.REPEAT.items():
            if key in self.b:
                for value in self.b[key]:
                    cmd.extend(['--'+option.replace('_','-'), value])
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 2, proc.stdout+'\n'+proc.stderr)
        info = json.loads(proc.stdout)
        self.assertEqual(info['candidate_original_raw_sha256'], old_test.sha(out))
        self.assertEqual(stat.S_IMODE(Path(out).stat().st_mode), 0o600)
        claim = json.loads(Path(out).read_text())['claim']
        self.events.append((out,old_test.sha(out),claim))
        self.observation(1)
        verified = c.audit_copies(**self.arguments(self.show(0,1)))
        self.assertEqual(verified['status'],'multiple_identical_local_copies_unresolved')

    def test_x_signed_audit_rejects_ec345_nonce_reuse_even_with_genuine_signature(self):
        first = self.observation(0)
        self.observation(1)
        original = json.loads(Path(first[0]).read_text())
        claim = original['claim']
        from ec319_offline_transfer_registry import registry as reg
        from ec340_issuer_root_rotation import rotation
        claim['event_nonce_sha256'] = json.loads(Path(self.challenges[0]).read_text())[
            'claim']['challenge_nonce_sha256']
        signer, _ = rotation._private_key_public(self.f.key_paths[2])
        original['signature_ed25519'] = signer.sign(c.EVENT_DOMAIN+reg.canonical(claim)).hex()
        path = str(self.w/'newly-signed-reused-nonce.json')
        old_test.canonical(path,original)
        a = self.arguments()
        a['observation_files'][0] = path
        a['observation_shas'][0] = old_test.sha(path)
        with self.assertRaisesRegex(anchor.AnchorError,'REUSED_NONCE'):
            c.audit_copies(**a)
        with self.assertRaisesRegex(anchor.AnchorError, 'EC346_EVENT_NONCE'):
            self.observation(0,event_nonce_sha256=claim['event_nonce_sha256'])

    def test_y_same_claimed_storage_label_is_reported_not_two_physical_machines(self):
        self.observation(0)
        self.observation(1, claimed_storage_id='storage_0')
        out = c.audit_copies(**self.arguments(self.show(0,1)))
        ids = [a['signer_id'] for a in self.f.actors[2:]]
        self.assertEqual(out['same_claimed_storage_label_receiver_pairs'], [ids])
        self.assertFalse(out['claimed_storage_id_proves_distinct_machine_or_organization'])

    def test_z_copy_paths_must_not_alias_verified_original_or_other_evidence(self):
        _, ack = self.copies(0)
        with self.assertRaises(anchor.AnchorError):
            self.observation(0, files=(self.f.rev['snapshot_file'], ack))
        self.assertFalse((self.w/'copy-event-0.json').exists())


if __name__ == '__main__':
    unittest.main()
