#!/usr/bin/env python3
"""EC324 focused functional scenarios with actual 5th/6th/7th Ed25519.

The inherited lightweight EC321 fixture mocks deeper EC317/318 replay. These
local tests are NOT production EC294->EC324 full-original-chain evidence.
"""
from __future__ import annotations

from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from ec295_delivery_anchor import anchor
from ec319_offline_transfer_registry import registry as reg
from ec323_composite_fork_capsule import test_capsule_structure as fixture
from scripts import ces_next as console
from . import operator, receipt as r


class TwoChannelImmutableLocalReceiptTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.CompositeOriginalCaseAndAckCases(
            methodName='test_seal_preserves_both_exact_original_bytes_and_successful_replay')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.sealed = self.f.seal()
        self.dir = self.f.f.f.dir
        self.registry_id = 'receiving_registry'
        self.handoff = 'handoff_001'
        self.head = str(self.dir / 'receiving-snapshot-1.json')
        self.origin_file = str(self.dir / 'origin-pin.json')
        self.recipient_file = str(self.dir / 'recipient-pin.json')
        self.base = dict(self.f.trust)
        self.base['expected_capsule_sha256'] = self.sealed['capsule_original_raw_sha256']
        self.base['handoff_id'] = self.handoff
        self.base['registry_id'] = self.registry_id
        self.base['expected_sequence'] = 1
        self.base['expected_prior_registry_raw_sha256'] = r.ZERO
        self.origin_sha = None
        self.recipient_sha = None

    def prepare(self, **overrides):
        for role, path, operator_id in (
            ('origin', self.origin_file, 'origin_operator'),
            ('recipient', self.recipient_file, 'receiving_operator')):
            values = dict(self.base, channel_role=role,
                          operator_id=operator_id, out=path)
            values.update(overrides.get(role, {}))
            result = r.prepare_channel(**values)
            setattr(self, role + '_sha', result['channel_original_raw_sha256'])
        return self.origin_sha, self.recipient_sha

    def receive(self, **overrides):
        values = dict(out=self.head, capsule_file=self.f.outer,
                      origin_file=self.origin_file,
                      expected_origin_sha256=self.origin_sha,
                      recipient_file=self.recipient_file,
                      expected_recipient_sha256=self.recipient_sha,
                      registry_id=self.registry_id, expected_sequence=1,
                      expected_prior_registry_sha256=r.ZERO)
        values.update(overrides)
        return r.receive(**values)

    def verify(self, **overrides):
        values = dict(registry_file=self.head,
                      expected_registry_sha256=r.case.sha(Path(self.head).read_bytes()),
                      capsule_file=self.f.outer, origin_file=self.origin_file,
                      expected_origin_sha256=self.origin_sha,
                      recipient_file=self.recipient_file,
                      expected_recipient_sha256=self.recipient_sha,
                      registry_id=self.registry_id, expected_sequence=1,
                      expected_prior_registry_sha256=r.ZERO)
        values.update(overrides)
        return r.verify(**values)

    def test_genesis_two_pins_and_crypto_replay_and_private_receipt(self):
        self.prepare()
        made = self.receive()
        self.assertEqual(made['exit_code'], 2)
        self.assertEqual(made['sequence'], 1)
        self.assertTrue(made['both_external_raw_sha_pinned_channel_documents_agree'])
        self.assertFalse(made['physical_independence_organizational_authority_external_worm_cas_latest_or_winner_proven'])
        self.assertEqual(Path(self.head).stat().st_mode & 0o777, 0o600)
        self.assertEqual(made['registry_snapshot_original_raw_sha256'],
                         r.case.sha(Path(self.head).read_bytes()))
        doc = json.loads(Path(self.head).read_bytes())
        self.assertEqual(doc['records'][0]['previous_snapshot_raw_sha256'], r.ZERO)
        self.assertEqual(self.verify()['exit_code'], 2)
        self.assertFalse(self.verify()['registry_snapshot_is_an_external_cryptographic_signature'])

    def test_command_line_preparation_is_not_signed_receipt(self):
        args = self.prepare()
        self.assertEqual(len(args), 2)
        self.assertNotEqual(*args)
        document = json.loads(Path(self.origin_file).read_bytes())
        self.assertFalse(document['physical_channel_independence_or_organization_authority_proven'])
        self.assertEqual(document['channel_role'], 'origin')
        self.assertEqual(set(document), r.CHANNEL_FIELDS)
        self.assertFalse(self.receive()['physical_independence_organizational_authority_external_worm_cas_latest_or_winner_proven'])

    def test_mismatch_of_known_historic_pins_even_if_separately_re_sha_pinned(self):
        self.prepare(recipient={'expected_witness_sha256': 'cc'*32})
        with self.assertRaisesRegex(anchor.AnchorError, 'CHANNELS_DISAGREE'):
            self.receive()
        self.assertFalse(Path(self.head).exists())

    def test_mismatch_capsule_or_ack_sha_refused_even_with_new_channel_sha(self):
        for slot in ('expected_capsule_sha256', 'expected_ack_sha256'):
            with self.subTest(slot=slot):
                path = str(self.dir / ('wrong-' + slot + '.json'))
                doc = json.loads(Path(self.recipient_file).read_bytes()) if Path(self.recipient_file).exists() else None
                if doc is None:
                    self.prepare(origin={})
                doc = json.loads(Path(self.recipient_file).read_bytes())
                item = ('capsule_original_raw_sha256' if slot ==
                        'expected_capsule_sha256' else 'seventh_ack_original_raw_sha256')
                doc[item] = 'ab'*32
                Path(path).write_bytes(reg.raw_doc(doc))
                Path(path).chmod(0o600)
                with self.assertRaisesRegex(anchor.AnchorError, 'CHANNELS_DISAGREE'):
                    self.receive(recipient_file=path,
                        expected_recipient_sha256=r.case.sha(Path(path).read_bytes()))
                Path(path).unlink()
        self.assertFalse(Path(self.head).exists())

    def test_wrong_out_of_band_document_pin_fails_closed(self):
        self.prepare()
        with self.assertRaisesRegex(anchor.AnchorError, 'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            self.receive(expected_origin_sha256='dd'*32)
        self.assertFalse(Path(self.head).exists())

    def test_same_operator_or_reversed_roles_cannot_claim_two_channels(self):
        self.prepare(recipient={'operator_id': 'origin_operator'})
        with self.assertRaisesRegex(anchor.AnchorError, 'TWO_DIFFERENT_OPERATOR_IDENTITIES'):
            self.receive()
        self.assertFalse(Path(self.head).exists())
        with self.assertRaisesRegex(anchor.AnchorError, 'CHANNEL_ROLE_SCHEMA'):
            self.receive(origin_file=self.recipient_file,
                         expected_origin_sha256=self.recipient_sha,
                         recipient_file=self.origin_file,
                         expected_recipient_sha256=self.origin_sha)

    def test_originator_self_assertion_is_not_authenticated_operator(self):
        self.prepare()
        doc = json.loads(Path(self.origin_file).read_bytes())
        doc['physical_channel_independence_or_organization_authority_proven'] = True
        changed = str(self.dir / 'lying-operator.json')
        Path(changed).write_bytes(reg.raw_doc(doc))
        Path(changed).chmod(0o600)
        with self.assertRaisesRegex(anchor.AnchorError, 'UNSUPPORTED_AUTHORITY_CLAIM'):
            self.receive(origin_file=changed,
                         expected_origin_sha256=r.case.sha(Path(changed).read_bytes()))
        self.assertFalse(Path(self.head).exists())

    def test_existing_receipt_never_overwritten(self):
        self.prepare()
        Path(self.head).write_bytes(b'existing owner file')
        Path(self.head).chmod(0o600)
        with self.assertRaisesRegex(anchor.AnchorError, 'OUTPUT_ALREADY_EXISTS'):
            self.receive()
        self.assertEqual(Path(self.head).read_bytes(), b'existing owner file')

    def test_receipt_never_created_if_old_signature_verification_denied(self):
        self.prepare()
        with patch.object(r.capsule, 'verify', side_effect=anchor.AnchorError(
                'EC321_OLD_GENUINE_SIGNATURE_BROKEN', 'permission_denied')):
            with self.assertRaisesRegex(anchor.AnchorError, 'OLD_GENUINE_SIGNATURE'):
                self.receive()
        self.assertFalse(Path(self.head).exists())

    def test_noncanonical_duplicate_keys_and_wrong_0600_channel_denied(self):
        self.prepare()
        raw = Path(self.origin_file).read_bytes()
        with open(self.origin_file, 'ab') as stream:
            stream.write(b' ')
        with self.assertRaises(anchor.AnchorError):
            self.receive()
        Path(self.origin_file).write_bytes(raw)
        Path(self.origin_file).chmod(0o644)
        with self.assertRaisesRegex(anchor.AnchorError, 'OWNER_0600_ONE_REGULAR_LINK'):
            self.receive()
        self.assertFalse(Path(self.head).exists())

    def test_symlink_or_same_file_paths_rejected(self):
        self.prepare()
        link = str(self.dir / 'external-link.json')
        os.symlink(self.origin_file, link)
        with self.assertRaises(anchor.AnchorError):
            self.receive(origin_file=link)
        with self.assertRaisesRegex(anchor.AnchorError, 'PATHS_NORMALIZED_ABSOLUTE_AND_DISTINCT'):
            self.receive(out=self.recipient_file)
        self.assertFalse(Path(self.head).exists())

    def test_registry_wrong_independent_head_and_outdated_expected_sequence(self):
        self.prepare()
        self.receive()
        with self.assertRaisesRegex(anchor.AnchorError, 'NOT_EQUAL_INDEPENDENT_RAW_SHA'):
            self.verify(expected_registry_sha256='ab'*32)
        with self.assertRaises(anchor.AnchorError):
            self.verify(expected_sequence=2)

    def test_changed_channel_after_signatures_replay_blocks_commit(self):
        self.prepare()
        orig = r._replay
        def corrupt(*args):
            result = orig(*args)
            Path(self.origin_file).write_bytes(b'changed')
            return result
        with patch.object(r, '_replay', side_effect=corrupt):
            with self.assertRaisesRegex(anchor.AnchorError, 'RECHECKED_ORIGIN_CHANNEL'):
                self.receive()
        self.assertFalse(Path(self.head).exists())

    def test_tampered_registry_row_even_with_new_head_pin_rejected(self):
        self.prepare()
        self.receive()
        doc = json.loads(Path(self.head).read_bytes())
        doc['records'][0]['origin_channel_original_raw_sha256'] = 'a'*64
        Path(self.head).write_bytes(reg.raw_doc(doc))
        new_sha = r.case.sha(Path(self.head).read_bytes())
        with self.assertRaisesRegex(anchor.AnchorError, 'LATEST_RECORD_NOT_BOUND_EXACTLY'):
            self.verify(expected_registry_sha256=new_sha)

    def test_appending_requires_prior_original_plus_externally_pinned_head(self):
        self.prepare()
        self.receive()
        with self.assertRaisesRegex(anchor.AnchorError, 'GENESIS_ZERO_OR_NONZERO_PRIOR'):
            r.prepare_channel(**dict(self.base, out=str(self.dir/'bad-append.json'),
                channel_role='origin', operator_id='new_operator',
                expected_sequence=2))
        with self.assertRaisesRegex(anchor.AnchorError, 'SNAPSHOT_NOT_THE_EXPECTED_SEQUENCE'):
            r._load_snapshot(self.head, r.case.sha(Path(self.head).read_bytes()),
                             self.registry_id, 2)

    def test_real_two_entry_prefix_commit_and_structural_hash_replay(self):
        self.prepare()
        first=self.receive()
        old = self.head
        second_fixture = fixture.CompositeOriginalCaseAndAckCases(
            methodName='test_seal_preserves_both_exact_original_bytes_and_successful_replay')
        second_fixture.setUp()
        self.addCleanup(second_fixture.doCleanups)
        other_sealed=second_fixture.seal()
        # Second independent genuine original signed ACK generates different
        # whole bytes; the original fifth/sixth/seventh roles genuinely sign.
        self.assertNotEqual(other_sealed['capsule_original_raw_sha256'],
                            self.sealed['capsule_original_raw_sha256'])
        self.origin_file=str(self.dir/'origin-pin-2.json')
        self.recipient_file=str(self.dir/'recipient-pin-2.json')
        self.head=str(self.dir/'receiving-snapshot-2.json')
        self.base=dict(second_fixture.trust)
        self.base.update(expected_capsule_sha256=other_sealed['capsule_original_raw_sha256'],
            handoff_id='handoff_002', registry_id=self.registry_id,
            expected_sequence=2,
            expected_prior_registry_raw_sha256=first['registry_snapshot_original_raw_sha256'])
        self.prepare()
        made=self.receive(capsule_file=second_fixture.outer,
            expected_sequence=2, prior_registry_file=old,
            expected_prior_registry_sha256=first['registry_snapshot_original_raw_sha256'])
        self.assertEqual(made['sequence'], 2)
        self.assertEqual(len(json.loads(Path(self.head).read_bytes())['records']), 2)
        self.assertEqual(self.verify(capsule_file=second_fixture.outer,
            expected_sequence=2,
            expected_prior_registry_sha256=first['registry_snapshot_original_raw_sha256'])['exit_code'], 2)
        with self.assertRaisesRegex(anchor.AnchorError, 'SNAPSHOT_NOT_THE_EXPECTED_SEQUENCE'):
            self.verify(capsule_file=second_fixture.outer,
                registry_file=old,
                expected_registry_sha256=first['registry_snapshot_original_raw_sha256'],
                expected_sequence=2,
                expected_prior_registry_sha256=first['registry_snapshot_original_raw_sha256'])
        # Changing a prefix breaks its reconstructed prior SHA, even if the
        # adversary re-pins the new outer snapshot SHA.
        doc=json.loads(Path(self.head).read_bytes())
        doc['records'][0]['handoff_id']='other_handoff'
        Path(self.head).write_bytes(reg.raw_doc(doc))
        with self.assertRaisesRegex(anchor.AnchorError, 'RECORD_SHAPE_LINKAGE'):
            self.verify(capsule_file=second_fixture.outer, expected_sequence=2,
                expected_prior_registry_sha256=first['registry_snapshot_original_raw_sha256'])

    def test_duplicate_capsule_or_handoff_same_prior_refused_before_replay(self):
        self.prepare()
        first=self.receive()
        self.origin_file=str(self.dir/'origin-again.json')
        self.recipient_file=str(self.dir/'recipient-again.json')
        self.base['expected_sequence']=2
        self.base['expected_prior_registry_raw_sha256']=first['registry_snapshot_original_raw_sha256']
        self.base['handoff_id']='handoff_002'
        self.prepare()
        with self.assertRaisesRegex(anchor.AnchorError, 'DUPLICATE_HANDOFF_OR_ORIGINAL_CAPSULE'):
            self.receive(out=str(self.dir/'new-snapshot.json'), expected_sequence=2,
                prior_registry_file=self.head,
                expected_prior_registry_sha256=first['registry_snapshot_original_raw_sha256'])

    def test_cli_production_only_has_preparation_and_commit_outside_console(self):
        self.prepare()
        result = self.receive()
        args=['audit-fork-receipt','DeliveryAudit','VerifyDualChannelLocalForkReceipt',
            '--registry-file',self.head,'--expected-registry-sha256',
            result['registry_snapshot_original_raw_sha256'],
            '--capsule-file',self.f.outer,
            '--origin-file',self.origin_file,
            '--expected-origin-sha256',self.origin_sha,
            '--recipient-file',self.recipient_file,
            '--expected-recipient-sha256',self.recipient_sha,
            '--registry-id',self.registry_id,
            '--expected-sequence','1',
            '--expected-prior-registry-sha256',r.ZERO]
        # The inherited EC317/318 fixture mocks only in THIS process.
        # Check the console's fixed child contract using the real in-process
        # verified result, rather than claiming an unmocked subprocess pass.
        verified=self.verify()
        reply={'schema':r.RESULT_SCHEMA,'command':'verify',**verified}
        captured=StringIO()
        with patch.object(console,'_command',return_value=(2,reply)) as child:
            with redirect_stdout(captured):
                rc=console.main(args)
        self.assertEqual(rc,2)
        self.assertEqual(json.loads(captured.getvalue())['command'],'verify')
        cmd=child.call_args.args[0]
        self.assertEqual(cmd[1:5],['-I','-B',str(console.FORK_RECEIPT),'verify'])
        self.assertNotIn('--out',cmd)
        self.assertNotIn('--private-key-file',cmd)
        self.assertEqual(console.FORK_RECEIPT.name, 'ces_cas_fork_receipt.py')
        with redirect_stdout(StringIO()):
            self.assertEqual(console.main(args[:1]+['DeliveryAudit','receive']+args[3:]),3)
        self.assertNotIn('prepare-channel', console.build_parser()._subparsers._group_actions[0].choices)

    def test_console_subprocess_fake_success_denied(self):
        self.prepare()
        result=self.receive()
        kwargs=dict(action='DeliveryAudit', mode='VerifyDualChannelLocalForkReceipt',
            registry_file=self.head,
            expected_registry_sha256=result['registry_snapshot_original_raw_sha256'],
            capsule_file=self.f.outer, origin_file=self.origin_file,
            expected_origin_sha256=self.origin_sha,
            recipient_file=self.recipient_file,
            expected_recipient_sha256=self.recipient_sha,
            registry_id=self.registry_id, expected_sequence=1,
            expected_prior_registry_sha256=r.ZERO)
        with patch.object(console,'_command',return_value=(2,{'exit_code':2,'status':'PASS'})):
            with self.assertRaisesRegex(console.ConsoleError, 'REPLY_INCONSISTENT'):
                console.audit_fork_receipt(**kwargs)

    def test_standalone_main_receive_then_verify_roundtrip_and_arg_exclusion(self):
        self.prepare()
        base=['--capsule-file',self.f.outer,'--origin-file',self.origin_file,
              '--expected-origin-sha256',self.origin_sha,
              '--recipient-file',self.recipient_file,
              '--expected-recipient-sha256',self.recipient_sha,
              '--registry-id',self.registry_id,'--expected-sequence','1',
              '--expected-prior-registry-sha256',r.ZERO]
        output=StringIO()
        with redirect_stdout(output):
            self.assertEqual(operator.main(['receive',*base,'--out',self.head]),2)
        made=json.loads(output.getvalue())
        self.assertEqual(made['command'],'receive')
        self.assertEqual(made['schema'],r.RESULT_SCHEMA)
        self.assertEqual(made['registry_snapshot_original_raw_sha256'],
                         r.case.sha(Path(self.head).read_bytes()))
        valid=['verify',*base,'--registry-file',self.head,
               '--expected-registry-sha256',made['registry_snapshot_original_raw_sha256']]
        output=StringIO()
        with redirect_stdout(output):
            self.assertEqual(operator.main(valid),2)
        self.assertEqual(json.loads(output.getvalue())['command'],'verify')
        for excluded in ('--out','--private-key-file'):
            with self.subTest(excluded=excluded):
                with self.assertRaises(SystemExit) as err:
                    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                        operator.parser().parse_args(valid + [excluded, '/tmp/forbidden'])
                self.assertEqual(err.exception.code,2)

    def test_standalone_denial_makes_no_unsigned_receipt(self):
        self.prepare()
        args=['receive','--capsule-file',self.f.outer,
              '--origin-file',self.origin_file,
              '--expected-origin-sha256','a'*64,
              '--recipient-file',self.recipient_file,
              '--expected-recipient-sha256',self.recipient_sha,
              '--registry-id',self.registry_id,'--expected-sequence','1',
              '--expected-prior-registry-sha256',r.ZERO,
              '--out',self.head]
        output=StringIO()
        with redirect_stdout(output):
            self.assertEqual(operator.main(args),3)
        failure=json.loads(output.getvalue())
        self.assertFalse(failure['signed_fork_full_history_accepted'])
        self.assertFalse(Path(self.head).exists())


if __name__ == '__main__':
    unittest.main()
