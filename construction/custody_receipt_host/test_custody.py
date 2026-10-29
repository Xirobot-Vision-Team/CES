#!/usr/bin/env python3
"""EC265 focused offline file/signature/host-gate checks, no OCI claims."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from offline_anchor_host import checkpoint as cp
from segmented_audit_host import segment as seg
from segmented_audit_host import test_segment as base_test
from custody_receipt_host import custody as cust


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     cp.Ed25519PrivateKey is not None,
                     'nonroot Linux and cryptography Ed25519 required')
class CustodyTests(unittest.TestCase):
    setUp = base_test.SegmentedAuditTests.setUp
    mkkey = base_test.SegmentedAuditTests.mkkey
    write_events = base_test.SegmentedAuditTests.write_events
    sign_checkpoint = base_test.SegmentedAuditTests.sign_checkpoint
    sign_continuation = base_test.SegmentedAuditTests.sign_continuation
    archive_entry = base_test.SegmentedAuditTests.archive_entry
    configuration = base_test.SegmentedAuditTests.configuration
    init = base_test.SegmentedAuditTests.init

    def prepare(self):
        self.init()
        self.outside = self.root/'transfers'
        self.outside.mkdir(mode=0o700)
        self.bundle = self.outside/'archive0'
        self.custody_secret = self.secure/'custodian.key'
        self.custody_public = self.secure/'custodian.pub'
        self.custody_pin = cp.generate_offline_keypair(str(self.custody_secret),
                                                       str(self.custody_public))['signer_public_sha256']
        self.vault = self.root/'vault'
        self.vault.mkdir(mode=0o700)
        self.exported = cust.export_archive(str(self.config), self.chain_pin, 0,
                                            str(self.bundle))

    def accept(self, bundle=None, **changes):
        kw = dict(expected_index=0, expected_checkpoint_pin=self.cp0_pin,
                  expected_continuation_pin=self.transition0_pin,
                  expected_parent_pin=seg.ZERO, expected_signer_pin=self.pub_pin)
        kw.update(changes)
        return cust.receive_archive(str(bundle or self.bundle), str(self.vault),
                                    str(self.custody_secret), self.custody_pin, **kw)

    def deposit(self):
        self.prepare()
        return self.accept()

    def gate(self, receipt_path):
        receipt = self.secure/'external-receipt.json'
        shutil.copyfile(receipt_path, receipt)
        receipt.chmod(0o600)
        config = self.secure/'gate.json'
        config.write_bytes(seg._canonical({
            'schema': cust.GATE_SCHEMA,
            'custody_public_key': str(self.custody_public),
            'custody_public_sha256': self.custody_pin,
            'receipts': [{'archive_index': 0, 'receipt': str(receipt),
                          'receipt_sha256': cp._digest(receipt.read_bytes())}],
        }) + b'\n')
        config.chmod(0o600)
        return config, cp._digest(config.read_bytes()), receipt

    def test_01_export_contains_only_expected_six_files_without_host_keys(self):
        self.prepare()
        self.assertEqual(set(x.name for x in self.bundle.iterdir()),
                         {'manifest.json', 'events.jsonl', 'head.json',
                          'checkpoint.json', 'continuation.json', 'signer.pub'})
        self.assertEqual(self.exported['archive_index'], 0)
        self.assertEqual(self.exported['bundle_manifest_sha256'],
                         cp._digest((self.bundle/'manifest.json').read_bytes()))
        self.assertEqual((self.bundle/'events.jsonl').read_bytes(),
                         (self.old/'events.jsonl').read_bytes())
        self.assertNotIn(self.oldkey.read_bytes(),
                         b''.join(f.read_bytes() for f in self.bundle.iterdir()))

    def test_02_receive_pins_signatures_deposit_reverify_and_gate_live(self):
        d = self.deposit()
        self.assertTrue(d['receipt_is_deposit_only_not_retention_or_worm_proof'])
        ret = cust.verify_deposit(str(self.vault), d['deposit_id'],
            str(self.custody_public), self.custody_pin,
            expected_index=0, expected_checkpoint_pin=self.cp0_pin,
            expected_continuation_pin=self.transition0_pin,
            expected_parent_pin=seg.ZERO, expected_signer_pin=self.pub_pin,
            receipt_pin=d['receipt_sha256'])
        self.assertTrue(ret['deposit_bytes_present_and_match_at_check'])
        self.assertFalse(ret['physical_external_custody_worm_retention_verified'])
        config, pin, _ = self.gate(d['receipt_path'])
        with cust.CustodyAudit(str(self.config), self.chain_pin,
                               str(config), pin) as audit:
            self.assertEqual(audit.summary()['custody_receipts_verified'], 1)
            audit.record('service_start')
            audit.record('service_closed')
            self.assertEqual(audit.summary()['active_local_event_count'], 2)

    def test_03_bundle_byte_tamper_denied_without_deposit(self):
        self.prepare()
        p = self.bundle/'events.jsonl'
        p.write_bytes(p.read_bytes().replace(b'service_start', b'service_stArT', 1))
        with self.assertRaisesRegex(cust.CustodyError,
                                    'EC265_BUNDLE_FILE_DIGEST_MISMATCH'):
            self.accept()
        self.assertEqual(list(self.vault.iterdir()), [])

    def test_04_wrong_operator_checkpoint_pin_denied_without_deposit(self):
        self.prepare()
        with self.assertRaisesRegex(cust.CustodyError,
                                    'EC265_BUNDLE_INDEPENDENT_PIN_MISMATCH'):
            self.accept(expected_checkpoint_pin='a'*64)
        self.assertEqual(list(self.vault.iterdir()), [])

    def test_05_missing_private_file_or_extra_file_denied(self):
        self.prepare()
        p = self.bundle/'evil.json'
        p.write_text('ignored')
        p.chmod(0o600)
        with self.assertRaisesRegex(cust.CustodyError,
                                    'EC265_BUNDLE_UNEXPECTED_OR_MISSING_FILES'):
            self.accept()

    def test_06_never_reuse_same_deposit_directory(self):
        self.deposit()
        with self.assertRaisesRegex(cust.CustodyError,
                                    'EC265_NEW_OUTPUT_DIRECTORY_UNAVAILABLE'):
            self.accept()

    def test_07_receipt_tamper_during_running_host_poisoned(self):
        d = self.deposit()
        config, pin, receipt = self.gate(d['receipt_path'])
        with cust.CustodyAudit(str(self.config), self.chain_pin,
                               str(config), pin) as audit:
            audit.record('service_start')
            receipt.write_bytes(receipt.read_bytes().replace(b'"nonce":', b'"other":', 1))
            with self.assertRaisesRegex(cust.CustodyError, 'EC265_RECEIPT_BYTES_PIN_MISMATCH'):
                audit.record('service_closed')
            self.assertTrue(audit.poisoned)
            self.assertEqual(audit.journal.count, 1)

    def test_08_missing_coverage_prevents_open(self):
        d = self.deposit()
        config, pin, receipt = self.gate(d['receipt_path'])
        obj = json.loads(config.read_bytes())
        obj['receipts'] = []
        config.write_bytes(seg._canonical(obj) + b'\n')
        with self.assertRaisesRegex(cust.CustodyError, 'EC265_GATE_RECEIPT_COVERAGE_INVALID'):
            cust.CustodyAudit(str(self.config), self.chain_pin, str(config),
                              cp._digest(config.read_bytes()))

    def test_09_export_requires_full_signed_and_no_existing_target(self):
        self.prepare()
        with self.assertRaisesRegex(cust.CustodyError,
                                    'EC265_NEW_OUTPUT_DIRECTORY_UNAVAILABLE'):
            cust.export_archive(str(self.config), self.chain_pin, 0, str(self.bundle))
        with self.assertRaisesRegex(cust.CustodyError,
                                    'EC265_OUTPUT_OVERLAPS_AUDIT_OR_SOURCE'):
            cust.export_archive(str(self.config), self.chain_pin, 0,
                                str(self.old/'subfolder'))

    def test_10_receiver_does_not_accept_identical_custody_signer(self):
        self.prepare()
        with self.assertRaisesRegex(cust.CustodyError,
                                    'EC265_CUSTODY_SIGNER_MUST_BE_DISTINCT'):
            cust.receive_archive(str(self.bundle), str(self.vault),
                str(self.secret), self.pub_pin,
                expected_index=0, expected_checkpoint_pin=self.cp0_pin,
                expected_continuation_pin=self.transition0_pin,
                expected_parent_pin=seg.ZERO, expected_signer_pin=self.pub_pin)

    def test_11_storage_tamper_detected_at_verification(self):
        d = self.deposit()
        p = Path(d['receipt_path']).parent/'head.json'
        p.write_bytes(p.read_bytes().replace(b'"schema":', b'"schemaX":', 1))
        with self.assertRaisesRegex(cust.CustodyError,
                                    'EC265_BUNDLE_FILE_DIGEST_MISMATCH'):
            cust.verify_deposit(str(self.vault), d['deposit_id'],
                str(self.custody_public), self.custody_pin,
                expected_index=0, expected_checkpoint_pin=self.cp0_pin,
                expected_continuation_pin=self.transition0_pin,
                expected_parent_pin=seg.ZERO, expected_signer_pin=self.pub_pin,
                receipt_pin=d['receipt_sha256'])

    def test_12_host_detects_changed_archived_head_even_if_receipt_present(self):
        d = self.deposit()
        config, pin, _ = self.gate(d['receipt_path'])
        with cust.CustodyAudit(str(self.config), self.chain_pin,
                               str(config), pin) as audit:
            head = self.old/'head.json'
            raw = head.read_bytes()
            head.write_bytes(raw.replace(b'"mac":', b'"mAc":', 1))
            with self.assertRaises((seg.SegmentError, cp.AnchorError)):
                audit.record('service_start')
            self.assertTrue(audit.poisoned)

    def test_13_two_segment_manifest_includes_original_genesis(self):
        self.init()
        with seg.SegmentAudit(str(self.config), self.chain_pin) as audit:
            audit.record('service_start')
            audit.record('service_closed')
        cp1 = self.secure/'cp1.json'
        cp1_pin = self.sign_checkpoint(self.current, self.livekey, cp1)
        key2 = self.mkkey('third.key')
        transition1 = self.secure/'transition1.json'
        transition1_pin, id1 = self.sign_continuation(
            self.current, self.livekey, cp1, cp1_pin, key2,
            self.transition0_pin, transition1)
        third = self.root/'third'
        third.mkdir(mode=0o700)
        old_entry = self.archive_entry(self.old, self.oldkey,
            self.cp0, self.cp0_pin, self.transition0, self.transition0_pin)
        middle_entry = self.archive_entry(self.current, self.livekey,
            cp1, cp1_pin, transition1, transition1_pin)
        chain1 = self.configuration(self.secure/'chain1.json',
            [old_entry, middle_entry], third, key2, id1)
        pin1 = cp._digest(chain1.read_bytes())
        self.init(chain1, pin1)
        output = self.root/'newbundle'
        res = cust.export_archive(str(chain1), pin1, 1, str(output))
        self.assertTrue((output/'genesis.json').exists())
        self.assertEqual(res['archive_index'], 1)
        secret = self.secure/'receiver.key'
        public = self.secure/'receiver.pub'
        cust_pin = cp.generate_offline_keypair(str(secret), str(public))['signer_public_sha256']
        vault = self.root/'newvault'
        vault.mkdir(mode=0o700)
        accepted = cust.receive_archive(str(output), str(vault), str(secret),
            cust_pin, expected_index=1, expected_checkpoint_pin=cp1_pin,
            expected_continuation_pin=transition1_pin,
            expected_parent_pin=self.transition0_pin, expected_signer_pin=self.pub_pin)
        self.assertEqual(accepted['archive_index'], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
