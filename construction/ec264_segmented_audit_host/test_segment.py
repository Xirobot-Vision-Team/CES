#!/usr/bin/env python3
"""EC264 focused REAL nonroot disk/key/signature/chain cases; no OCI."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec262_signed_audit_host import audit as baseline
from ec263_offline_anchor_host import checkpoint as cp
from ec264_segmented_audit_host import segment as seg


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     cp.Ed25519PrivateKey is not None,
                     'nonroot Linux and Ed25519 cryptography required')
class SegmentedAuditTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='ces264-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.secure = self.root/'private'
        self.secure.mkdir(mode=0o700)
        self.old = self.root/'old'
        self.old.mkdir(mode=0o700)
        self.current = self.root/'current'
        self.current.mkdir(mode=0o700)
        self.oldkey = self.mkkey('old.key')
        self.livekey = self.mkkey('next.key')
        self.secret = self.secure/'signer.key'
        self.public = self.secure/'signer.pub'
        self.pub_pin = cp.generate_offline_keypair(str(self.secret),
                                                    str(self.public))['signer_public_sha256']
        self.cp0 = self.secure/'cp0.json'
        self.transition0 = self.secure/'transition0.json'
        self.write_events(self.old, self.oldkey)
        self.cp0_pin = self.sign_checkpoint(self.old, self.oldkey, self.cp0)
        self.transition0_pin, self.seg0_id = self.sign_continuation(
            self.old, self.oldkey, self.cp0, self.cp0_pin, self.livekey,
            seg.ZERO, self.transition0)
        self.config = self.configuration(self.root/'config0.json',
                                         [self.archive_entry(self.old, self.oldkey,
                                            self.cp0, self.cp0_pin,
                                            self.transition0, self.transition0_pin)],
                                         self.current, self.livekey, self.seg0_id)
        self.chain_pin = seg.cp._digest(self.config.read_bytes())

    def mkkey(self, name, data=None):
        path = self.secure/name
        path.write_bytes(data or os.urandom(32))
        path.chmod(0o600)
        return path

    def write_events(self, root, key):
        with baseline.AuditLog(str(root), str(key)) as log:
            log.record('service_start')
            log.record('session_open', 'a'*24)
            log.record('service_closed')

    def sign_checkpoint(self, root, key, destination):
        proposal = self.secure/('p-' + destination.name)
        cp.propose(str(root), str(key), self.pub_pin, str(proposal))
        return cp.sign_offline(str(proposal), str(self.secret),
                               str(destination))['checkpoint_sha256']

    def sign_continuation(self, root, key, checkpoint, checkpoint_pin,
                          successor_key, parent_pin, destination):
        proposal = self.secure/('p-' + destination.name)
        meta = seg.propose_transition(str(root), str(key), str(checkpoint),
            checkpoint_pin, str(self.public), self.pub_pin, str(successor_key),
            parent_pin, str(proposal))
        result = seg.sign_transition_offline(str(proposal), str(self.secret),
                                              str(destination))
        return result['continuation_sha256'], meta['next_segment_id']

    def archive_entry(self, root, key, checkpoint, checkpoint_pin,
                      transition, transition_pin):
        return {'audit_root': str(root), 'audit_key': str(key),
                'checkpoint': str(checkpoint), 'checkpoint_sha256': checkpoint_pin,
                'continuation': str(transition),
                'continuation_sha256': transition_pin}

    def configuration(self, output, archives, live_root, live_key, segment_id):
        obj = {'schema': seg.CONFIG_SCHEMA,
               'signer_public_key': str(self.public),
               'signer_public_sha256': self.pub_pin,
               'archives': archives,
               'active': {'audit_root': str(live_root),
                          'audit_key': str(live_key), 'segment_id': segment_id}}
        output.write_bytes(seg._canonical(obj) + b'\n')
        output.chmod(0o600)
        return output

    def init(self, config=None, pin=None):
        with seg.SegmentAudit(str(config or self.config), pin or self.chain_pin,
                              initialize=True):
            pass

    def verify(self, config=None, pin=None):
        return seg.SegmentAudit(str(config or self.config),
                                pin or self.chain_pin, writable=False)

    def test_01_sign_verify_initialize_once_and_use_live_audit(self):
        self.init()
        self.assertEqual((self.current/'events.jsonl').stat().st_size, 0)
        with seg.SegmentAudit(str(self.config), self.chain_pin) as audit:
            report = audit.summary()
            self.assertEqual(report['sealed_archive_count'], 1)
            self.assertEqual(report['sealed_archive_event_count'], 3)
            self.assertEqual(report['active_local_event_count'], 0)
            audit.record('service_start')
            audit.record('service_closed')
            self.assertEqual(audit.summary()['active_events_not_offline_signed'], 2)
        with self.verify() as audit:
            self.assertEqual(audit.summary()['active_local_event_count'], 2)
        self.assertEqual((self.current/'genesis.json').stat().st_mode & 0o777, 0o600)
        self.assertTrue((self.old/'events.jsonl').exists())

    def test_02_early_checkpoint_does_not_seal_unsigned_tail(self):
        with baseline.AuditLog(str(self.old), str(self.oldkey)) as old:
            old.record('service_closed')
        proposal = self.secure/'cannot-propose.json'
        with self.assertRaisesRegex(seg.SegmentError,
                                    'EC264_ARCHIVE_MUST_BE_SIGNED_TO_FINAL_BYTE'):
            seg.propose_transition(str(self.old), str(self.oldkey),
                str(self.cp0), self.cp0_pin, str(self.public), self.pub_pin,
                str(self.livekey), seg.ZERO, str(proposal))
        with self.assertRaises(seg.SegmentError):
            self.init()  # previous checkpoint is now an unsigned prefix
        self.assertFalse((self.current/'events.jsonl').exists())

    def test_03_transition_signature_tamper_even_with_rebound_pin(self):
        obj = json.loads(self.transition0.read_bytes())
        obj['next_segment_id'] = 'e'*32
        self.transition0.write_bytes(seg._canonical(obj) + b'\n')
        newpin = seg.cp._digest(self.transition0.read_bytes())
        alternative = self.secure/'config1.json'
        entry = self.archive_entry(self.old, self.oldkey, self.cp0,
                                   self.cp0_pin, self.transition0, newpin)
        self.configuration(alternative, [entry], self.current, self.livekey, 'e'*32)
        with self.assertRaisesRegex(seg.SegmentError,
                                    'EC264_TRANSITION_SIGNATURE_INVALID'):
            self.init(alternative, seg.cp._digest(alternative.read_bytes()))
        self.assertFalse((self.current/'genesis.json').exists())

    def test_04_public_and_chain_pins_reject_substitution(self):
        with self.assertRaisesRegex(seg.SegmentError, 'EC264_CHAIN_CONFIG_PIN_MISMATCH'):
            self.init(pin='f'*64)
        obj = json.loads(self.config.read_bytes())
        obj['signer_public_sha256'] = 'b'*64
        self.config.write_bytes(seg._canonical(obj) + b'\n')
        with self.assertRaisesRegex(seg.SegmentError, 'EC264_PUBLIC_SIGNER_PIN_MISMATCH'):
            self.init(pin=seg.cp._digest(self.config.read_bytes()))

    def test_05_signed_archive_rewritten_same_size_prevents_append(self):
        self.init()
        with seg.SegmentAudit(str(self.config), self.chain_pin) as audit:
            original = (self.old/'events.jsonl').read_bytes()
            self.assertEqual(len(original.replace(b'service_start', b'service_stArT')),
                             len(original))
            (self.old/'events.jsonl').write_bytes(original.replace(
                b'service_start', b'service_stArT', 1))
            with self.assertRaises(cp.AnchorError):
                audit.record('service_start')
            self.assertTrue(audit.poisoned)
            self.assertEqual(audit.journal.count, 0)

    def test_06_new_segment_must_not_rebootstrap_or_overwrite_genesis(self):
        self.init()
        with self.assertRaisesRegex(seg.SegmentError, 'EC264_NEW_SEGMENT_NOT_EMPTY'):
            self.init()
        (self.current/'events.jsonl').unlink()
        with self.assertRaisesRegex(seg.SegmentError, 'EC264_NEW_SEGMENT_NOT_EMPTY'):
            self.init()
        with self.assertRaises(baseline.AuditError):
            self.verify()
        self.assertFalse((self.current/'events.jsonl').exists())

    def test_07_crash_after_genesis_only_refuses_empty_reset(self):
        obj = seg._genesis_for(json.loads(self.transition0.read_bytes()),
                               self.transition0_pin)
        p = self.current/'genesis.json'
        p.write_bytes(seg._canonical(obj) + b'\n')
        p.chmod(0o600)
        with self.assertRaisesRegex(seg.SegmentError, 'EC264_NEW_SEGMENT_NOT_EMPTY'):
            self.init()
        with self.assertRaises(baseline.AuditError):
            self.verify()

    def test_08_hmac_key_reuse_even_with_different_key_path_denied(self):
        same = self.mkkey('duplicate.key', self.oldkey.read_bytes())
        alternative = self.secure/'config1.json'
        self.configuration(alternative,
            [self.archive_entry(self.old, self.oldkey, self.cp0,
                self.cp0_pin, self.transition0, self.transition0_pin)],
            self.current, same, self.seg0_id)
        with self.assertRaisesRegex(seg.SegmentError, 'EC264_AUDIT_KEY_REUSED'):
            self.init(alternative, seg.cp._digest(alternative.read_bytes()))

    def test_09_tampered_chain_genesis_or_signed_history_denied(self):
        self.init()
        p = self.current/'genesis.json'
        obj = json.loads(p.read_bytes())
        obj['segment_id'] = 'f'*32
        p.write_bytes(seg._canonical(obj) + b'\n')
        with self.assertRaisesRegex(seg.SegmentError,
                                    'EC264_SEGMENT_GENESIS_MISMATCH'):
            self.verify()

    def test_10_live_same_size_rehmac_forgery_denied_while_running(self):
        self.init()
        with seg.SegmentAudit(str(self.config), self.chain_pin) as audit:
            audit.record('session_denied', 'b'*24, 'DENIED')
            rows = [json.loads(raw) for raw in
                    (self.current/'events.jsonl').read_bytes().splitlines()]
            rows[0]['reason_code'] = 'FORGED'
            key = self.livekey.read_bytes()
            data = {name: rows[0][name] for name in baseline.PAYLOAD_KEYS}
            rows[0]['mac'] = baseline._mac(key, data)
            body = baseline._canonical(rows[0]) + b'\n'
            self.assertEqual(len(body), audit.journal.size)
            (self.current/'events.jsonl').write_bytes(body)
            payload = {'schema': baseline.HEAD_SCHEMA,
                       'event_count': 1, 'journal_size': len(body),
                       'last_mac': rows[0]['mac']}
            payload['mac'] = hmac.new(key,
                baseline.HEAD_DOMAIN + baseline._canonical(payload),
                hashlib.sha256).hexdigest()
            (self.current/'head.json').write_bytes(baseline._canonical(payload) + b'\n')
            with self.assertRaisesRegex(seg.SegmentError,
                                        'EC264_ACTIVE_AUDIT_REWRITTEN'):
                audit.record('service_closed')
            self.assertTrue(audit.poisoned)

    def test_11_multi_segment_chain_usable_and_predecessor_link_verified(self):
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
        hash1 = seg.cp._digest(chain1.read_bytes())
        self.init(chain1, hash1)
        with seg.SegmentAudit(str(chain1), hash1) as audit:
            self.assertEqual(audit.summary()['sealed_archive_count'], 2)
            audit.record('service_start')
        with self.verify(chain1, hash1) as audit:
            self.assertEqual(audit.summary()['active_local_event_count'], 1)
        # Signed transition1 refers exactly to transition0. Omitting old
        # segment cannot preserve this chain without a new offline signature.
        bad = self.configuration(self.secure/'truncated.json', [middle_entry],
                                 third, key2, id1)
        with self.assertRaisesRegex(seg.SegmentError,
                                    'EC264_ARCHIVE_CONTINUATION_BROKEN'):
            self.verify(bad, seg.cp._digest(bad.read_bytes()))

    def test_12_missing_archived_file_prevents_live_start(self):
        self.init()
        (self.old/'head.json').unlink()
        with self.assertRaises(baseline.AuditError):
            self.verify()

    def test_13_unsigned_temporary_old_events_prohibit_init(self):
        with baseline.AuditLog(str(self.old), str(self.oldkey)) as log:
            log.record('service_start')
        with self.assertRaises(seg.SegmentError):
            self.init()
        self.assertEqual(list(self.current.iterdir()), [])

    def test_14_canonical_transition_proposal_and_no_secret_leaks(self):
        proposal = self.secure/'p-transition0.json'
        obj = json.loads(proposal.read_bytes())
        obj['archive_event_count'] = True
        proposal.write_bytes(seg._canonical(obj) + b'\n')
        with self.assertRaisesRegex(seg.SegmentError, 'EC264_TRANSITION_FIELDS_INVALID'):
            seg.sign_transition_offline(str(proposal), str(self.secret),
                                         str(self.secure/'unwanted.json'))
        self.assertNotIn(self.secret.read_bytes().hex().encode(),
                         self.transition0.read_bytes())
        self.assertNotIn(str(self.old).encode(), self.transition0.read_bytes())

    def test_15_permissions_and_path_nested_audit_denied(self):
        self.init()
        self.transition0.chmod(0o644)
        with self.assertRaises(cp.AnchorError):
            self.verify()
        self.transition0.chmod(0o600)
        nested = self.old/'nested'
        nested.mkdir(mode=0o700)
        bad = self.configuration(self.secure/'nested.json',
            [self.archive_entry(self.old, self.oldkey, self.cp0,
                self.cp0_pin, self.transition0, self.transition0_pin)],
            nested, self.livekey, self.seg0_id)
        with self.assertRaisesRegex(seg.SegmentError,
                                    'EC264_SEGMENT_ROOTS_OVERLAP'):
            self.verify(bad, seg.cp._digest(bad.read_bytes()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
