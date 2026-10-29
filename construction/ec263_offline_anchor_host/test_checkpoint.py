#!/usr/bin/env python3
"""EC263 real nonroot Ed25519 offline-signed checkpoint cases; no OCI."""
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


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     cp.Ed25519PrivateKey is not None,
                     'nonroot Linux and cryptography Ed25519 required')
class OfflineCheckpointTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='ces263-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.audit = self.root/'audit'
        self.secure = self.root/'private'
        self.audit.mkdir(mode=0o700)
        self.secure.mkdir(mode=0o700)
        self.key = self.secure/'audit.key'
        self.key.write_bytes(os.urandom(32))
        self.key.chmod(0o600)
        self.secret = self.secure/'signing.key'
        self.pub = self.secure/'signer.pub'
        self.proposal = self.secure/'unsigned.json'
        self.signed = self.secure/'checkpoint.json'
        self.make_journal()
        self.public_pin = cp.generate_offline_keypair(str(self.secret),
                                                        str(self.pub))['signer_public_sha256']

    def make_journal(self):
        with baseline.AuditLog(str(self.audit), str(self.key)) as log:
            log.record('service_start')
            log.record('session_open', 'a'*24)
            log.record('session_denied', 'a'*24, 'EC260_REVOKED')
            log.record('service_closed')

    def sign(self):
        cp.propose(str(self.audit), str(self.key), self.public_pin, str(self.proposal))
        return cp.sign_offline(str(self.proposal), str(self.secret), str(self.signed))

    def verify(self, *, sha=None, signer_hash=None, checkpoint=None, pub=None):
        return cp.AnchoredAudit(str(self.audit), str(self.key),
                                str(checkpoint or self.signed), str(pub or self.pub),
                                signer_hash or self.public_pin,
                                sha or cp._digest(self.signed.read_bytes()))

    def test_01_real_offline_signature_and_append_only_unanchored_suffix(self):
        meta = self.sign()
        self.assertEqual(meta['attested_event_count'], 4)
        with self.verify() as log:
            self.assertTrue(log.summary()['ed25519_offline_checkpoint_signature_verified'])
            self.assertEqual(log.summary()['post_checkpoint_unattested_events'], 0)
            log.record('service_start')
            log.record('service_closed')
            self.assertEqual(log.summary()['post_checkpoint_unattested_events'], 2)
        with self.verify() as log:
            self.assertEqual(log.summary()['current_event_count'], 6)
            self.assertEqual(log.summary()['attested_event_count'], 4)
        self.assertTrue(self.signed.read_bytes().endswith(b'\n'))
        self.assertEqual(self.pub.stat().st_mode & 0o777, 0o600)

    def test_02_rewritten_valid_hmac_chain_and_head_cannot_forge_ed25519(self):
        self.sign()
        records = [json.loads(row) for row in (self.audit/'events.jsonl').read_bytes().splitlines()]
        key = self.key.read_bytes()
        records[1]['reason_code'] = 'EVIL'
        previous = baseline.ZERO
        forged = []
        for rec in records:
            payload = {k: rec[k] for k in baseline.PAYLOAD_KEYS}
            payload['prev_mac'] = previous
            tag = baseline._mac(key, payload)
            forged.append(baseline._canonical({**payload, 'mac': tag}) + b'\n')
            previous = tag
        raw = b''.join(forged)
        (self.audit/'events.jsonl').write_bytes(raw)
        head = {'schema': baseline.HEAD_SCHEMA, 'event_count': len(records),
                'journal_size': len(raw), 'last_mac': previous}
        head['mac'] = hmac.new(key, baseline.HEAD_DOMAIN + baseline._canonical(head),
                               hashlib.sha256).hexdigest()
        (self.audit/'head.json').write_bytes(baseline._canonical(head) + b'\n')
        # EC262 HMAC+local head now accept the same-key forged history.
        with baseline.AuditLog(str(self.audit), str(self.key), create=False):
            pass
        with self.assertRaisesRegex(cp.AnchorError, 'EC263_SIGNED_PREFIX_CHANGED'):
            self.verify()

    def test_03_signed_checkpoint_tamper_with_rebound_sha_refused(self):
        self.sign()
        signed = json.loads(self.signed.read_bytes())
        signed['nonce'] = 'b'*32
        raw = cp._canonical(signed) + b'\n'
        self.signed.write_bytes(raw)
        with self.assertRaisesRegex(cp.AnchorError, 'EC263_CHECKPOINT_SIGNATURE_INVALID'):
            self.verify(sha=cp._digest(raw))

    def test_04_checkpoint_file_sha_pin_denies_rollback_or_replacement(self):
        previous = self.sign()['checkpoint_sha256']
        self.signed.write_bytes(self.signed.read_bytes()[:-1] + b' ')
        with self.assertRaisesRegex(cp.AnchorError, 'EC263_CHECKPOINT_PIN_MISMATCH'):
            self.verify(sha=previous)

    def test_05_public_key_pin_refuses_key_substitution(self):
        self.sign()
        alternate = self.secure/'alternate.secret'
        alternate_pub = self.secure/'alternate.pub'
        cp.generate_offline_keypair(str(alternate), str(alternate_pub))
        with self.assertRaisesRegex(cp.AnchorError, 'EC263_PUBLIC_KEY_PIN_MISMATCH'):
            self.verify(pub=alternate_pub)

    def test_06_checkpoint_different_signer_signed_bytes_not_allowed(self):
        self.sign()
        alternate = self.secure/'alternate.secret'
        alternate_pub = self.secure/'alternate.pub'
        cp.generate_offline_keypair(str(alternate), str(alternate_pub))
        with self.assertRaisesRegex(cp.AnchorError, 'EC263_PROPOSAL_WRONG_SIGNER'):
            cp.sign_offline(str(self.proposal), str(alternate),
                            str(self.secure/'illegitimate.json'))

    def test_07_symlink_hardlink_and_writable_checkpoint_rejected(self):
        self.sign()
        self.signed.chmod(0o644)
        with self.assertRaisesRegex(cp.AnchorError, 'EC263_PRIVATE_INPUT_UNAVAILABLE'):
            self.verify()
        self.signed.chmod(0o600)
        alias = self.secure/'alias.json'
        os.link(self.signed, alias)
        with self.assertRaisesRegex(cp.AnchorError, 'EC263_PRIVATE_INPUT_UNAVAILABLE'):
            self.verify()
        alias.unlink()
        self.signed.rename(alias)
        self.signed.symlink_to(alias)
        with self.assertRaisesRegex(cp.AnchorError, 'EC263_PRIVATE_INPUT_UNAVAILABLE'):
            self.verify()

    def test_08_in_place_signed_prefix_tamper_blocks_next_append(self):
        self.sign()
        with self.verify() as log:
            p = self.audit/'events.jsonl'
            raw = p.read_bytes()
            p.write_bytes(raw.replace(b'EC260_REVOKED', b'EC260_RVVVKED'))
            with self.assertRaisesRegex(cp.AnchorError, 'EC263_SIGNED_PREFIX_CHANGED'):
                log.record('service_start')
            self.assertTrue(log.poisoned)
            with self.assertRaisesRegex(cp.AnchorError, 'EC263_CHECKPOINT_OR_JOURNAL_POISONED'):
                log.record('service_start')

    def test_09_capacity_empty_journal_does_not_get_silent_anchor(self):
        (self.audit/'events.jsonl').unlink()
        (self.audit/'head.json').unlink()
        with baseline.AuditLog(str(self.audit), str(self.key)):
            pass
        with self.assertRaisesRegex(cp.AnchorError, 'EC263_EMPTY_JOURNAL_CANNOT_BE_ATTESTED'):
            cp.propose(str(self.audit), str(self.key), self.public_pin, str(self.proposal))

    def test_10_no_unreviewed_signing_key_secret_on_host_input(self):
        self.sign()
        body = self.signed.read_bytes()
        self.assertNotIn(self.secret.read_bytes().hex().encode(), body)
        self.assertNotIn(str(self.root).encode(), body)
        self.assertNotIn(b'EC260_REVOKED', body)
        self.assertEqual(len(self.secret.read_bytes()), 32)

    def test_11_existing_key_or_checkpoint_cannot_be_overwritten(self):
        with self.assertRaisesRegex(cp.AnchorError, 'EC263_PRIVATE_OUTPUT_UNAVAILABLE'):
            cp.generate_offline_keypair(str(self.secret), str(self.pub))
        self.sign()
        with self.assertRaisesRegex(cp.AnchorError, 'EC263_PRIVATE_OUTPUT_UNAVAILABLE'):
            cp.sign_offline(str(self.proposal), str(self.secret), str(self.signed))

    def test_12_readonly_validation_never_bootstraps_deleted_audit(self):
        self.sign()
        (self.audit/'events.jsonl').unlink()
        with self.assertRaises(baseline.AuditError):
            self.verify()
        self.assertFalse((self.audit/'events.jsonl').exists())

    def test_13_proposal_noncanonical_or_boolean_count_is_refused(self):
        self.sign()
        obj = json.loads(self.proposal.read_bytes())
        obj['event_count'] = True
        invalid = self.secure/'invalid.json'
        invalid.write_bytes(cp._canonical(obj) + b'\n')
        invalid.chmod(0o600)
        with self.assertRaisesRegex(cp.AnchorError, 'EC263_CHECKPOINT_PAYLOAD_INVALID'):
            cp.sign_offline(str(invalid), str(self.secret), str(self.secure/'out.json'))
        invalid.write_bytes(json.dumps(obj, indent=4).encode()+b'\n')
        with self.assertRaisesRegex(cp.AnchorError, 'EC263_CHECKPOINT_NOT_CANONICAL'):
            cp.sign_offline(str(invalid), str(self.secret), str(self.secure/'out2.json'))


if __name__ == '__main__':
    unittest.main()
