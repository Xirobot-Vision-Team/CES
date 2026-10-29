#!/usr/bin/env python3
"""EC316 genuine inherited EC315->EC294 Ed25519 replay + NEW independent signers.

Local fixture-generated custodians are not independently governed people;
these cases exercise actual Ed25519 signatures, not mock PASS reports.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from ec295_delivery_anchor import anchor as a
from ec302_portable_bundle import bundle as b
from ec311_cas_decision_history import test_decisions as decisions_fixture
from ec315_delivery_ledger import test_ledger as ledger_fixture
from . import checkpoint as c

ROOT = Path(__file__).resolve().parents[2]


class EC316DualSignedOriginalCheckpointCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ledger_fixture.EC315SignedDeliveryLedgerCases.setUpClass()
        try:
            cls.owner = decisions_fixture.EC311SignedDecisionHistoryCases.home
            cls.root1 = ledger_fixture.EC315SignedDeliveryLedgerCases.root1
            cls.root2 = ledger_fixture.EC315SignedDeliveryLedgerCases.root2
            cls.keys = {role: Ed25519PrivateKey.generate() for role in c.ROLES}
            cls.trust = {}
            for role in c.ROLES:
                cls.trust['custodian_' + role + '_id'] = 'ec316_offline_' + role
                cls.trust['custodian_' + role + '_public_hex'] = cls.keys[role].public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw).hex()
                raw = cls.keys[role].private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption())
                cls._private('fixture-key-' + role + '.bin', raw)
            cls.challenge1 = '91' * 32
            cls.challenge2 = '92' * 32
            cls.one = cls._context(cls.root1, cls.challenge1)
        except BaseException:
            ledger_fixture.EC315SignedDeliveryLedgerCases.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        ledger_fixture.EC315SignedDeliveryLedgerCases.tearDownClass()

    @classmethod
    def _private(cls, name: str, raw: bytes) -> str:
        path = cls.owner / ('ec316-' + name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
        return str(path)

    @classmethod
    def _out(cls, name: str) -> str:
        return str(cls.owner / ('ec316-' + name))

    @classmethod
    def _pin(cls, path: str) -> str:
        return b.digest(Path(path).read_bytes())

    @classmethod
    def _context(cls, ledger: tuple[str, str], challenge: str,
                 prior: tuple[str, str] | None = None,
                 prior_cert_sha: str = 'GENESIS') -> dict:
        return {
            'ledger_manifest_file': ledger[0],
            'expected_ledger_manifest_sha256': ledger[1],
            'trust': cls.trust,
            'external_unique_challenge_sha256': challenge,
            'prior_chain_file': prior[0] if prior else None,
            'expected_prior_chain_sha256': prior[1] if prior else None,
            'expected_prior_certificate_sha256': prior_cert_sha,
        }

    @classmethod
    def _seal(cls, label: str, ctx: dict) -> tuple[tuple[str, str], tuple[str, str]]:
        p = cls._out(label + '-claim.json')
        assert c.prepare(**ctx, out=p)['exit_code'] == 0
        claim_pin = cls._pin(p)
        votes = {}
        for role in c.ROLES:
            vote = cls._out(label + '-vote-' + role + '.json')
            result = c.sign(**ctx, claim_file=p, expected_claim_sha256=claim_pin,
                role=role, private_key_file=cls._out('fixture-key-' + role + '.bin'),
                out=vote)
            assert result['exit_code'] == 0
            votes[role] = vote
        cert = cls._out(label + '-cert.json')
        result = c.assemble(**ctx, claim_file=p, expected_claim_sha256=claim_pin,
                            custodian_a_vote_file=votes['a'],
                            custodian_b_vote_file=votes['b'], out=cert)
        assert result['exit_code'] == 0
        cert_pin = cls._pin(cert)
        chain = cls._out(label + '-chain.json')
        result = c.seal_chain(**ctx, certificate_file=cert,
                              expected_certificate_sha256=cert_pin, out=chain)
        assert result['exit_code'] == 0
        return (chain, cls._pin(chain)), (cert, cert_pin)

    def test_01_two_distinct_keys_sign_replayed_real_original_genesis(self):
        chain, cert = self._seal('genesis', self.one)
        self.__class__.chain1, self.__class__.certificate1 = chain, cert
        report = c.verify(chain_file=chain[0], expected_chain_sha256=chain[1],
            ledger_manifest_file=self.root1[0],
            expected_ledger_manifest_sha256=self.root1[1],
            trust=self.trust, expected_latest_certificate_sha256=cert[1],
            expected_latest_challenge_sha256=self.challenge1)
        self.assertEqual(report['exit_code'], 0)
        self.assertEqual(report['checkpoint_count'], 1)
        self.assertTrue(report['all_ec315_prefixes_and_ec312_to_ec294_originals_replayed'])
        self.assertFalse(report['actual_external_worm_anchor_or_linearizable_cas_latest_proven'])
        self.assertEqual(report['latest_certificate_original_raw_sha256'], cert[1])

    def test_02_wrong_role_key_or_signature_does_not_issue_certificate(self):
        claim = self._out('negative-claim.json')
        c.prepare(**self.one, out=claim)
        sha = self._pin(claim)
        with self.assertRaisesRegex(a.AnchorError, 'PRIVATE_KEY_DOES_NOT_MATCH'):
            c.sign(**self.one, claim_file=claim, expected_claim_sha256=sha,
                   role='a', private_key_file=self._out('fixture-key-b.bin'),
                   out=self._out('wrong-key-vote.json'))
        vote_a = self._out('negative-a.json')
        c.sign(**self.one, claim_file=claim, expected_claim_sha256=sha,
               role='a', private_key_file=self._out('fixture-key-a.bin'), out=vote_a)
        malformed = c._read_unpinned_vote(vote_a)
        malformed['signature_ed25519'] = '00'*64
        wrong = self._out('invalid-signature-vote.json')
        self._private('invalid-signature-vote.json', b.canonical(malformed))
        good_b = self._out('negative-b.json')
        c.sign(**self.one, claim_file=claim, expected_claim_sha256=sha,
               role='b', private_key_file=self._out('fixture-key-b.bin'), out=good_b)
        with self.assertRaisesRegex(a.AnchorError, 'ED25519_SIGNATURE_INVALID'):
            c.assemble(**self.one, claim_file=claim, expected_claim_sha256=sha,
                       custodian_a_vote_file=wrong,
                       custodian_b_vote_file=good_b,
                       out=self._out('should-not-exist.json'))
        self.assertFalse(Path(self._out('should-not-exist.json')).exists())

    def test_03_append_requires_old_pinned_dual_signature_and_fresh_origins(self):
        # Each EC315 source prefix must be real: the second batch shares a
        # genuinely signed CAS issuer receipt with an already signed old window.
        chain1 = getattr(self.__class__, 'chain1', None)
        cert1 = getattr(self.__class__, 'certificate1', None)
        if chain1 is None:
            chain1, cert1 = self._seal('prior-for-append', self.one)
        context = self._context(self.root2, self.challenge2,
                                prior=chain1, prior_cert_sha=cert1[1])
        chain2, cert2 = self._seal('append', context)
        report = c.verify(chain_file=chain2[0], expected_chain_sha256=chain2[1],
            ledger_manifest_file=self.root2[0],
            expected_ledger_manifest_sha256=self.root2[1],
            trust=self.trust, expected_latest_certificate_sha256=cert2[1],
            expected_latest_challenge_sha256=self.challenge2)
        self.assertEqual(report['checkpoint_count'], 2)
        self.assertEqual(report['latest_certificate_original_raw_sha256'], cert2[1])
        self.assertEqual(report['latest_verified_originals_commitment_sha256'],
                         ledger_fixture.EC315SignedDeliveryLedgerCases._evaluate(
                             self.root2)['checkpoint_cumulative_replayed_originals_commitment_sha256'])
        with self.assertRaisesRegex(a.AnchorError, 'LATEST_CERTIFICATE_NOT_EQUAL'):
            c.verify(chain_file=chain2[0], expected_chain_sha256=chain2[1],
                ledger_manifest_file=self.root2[0],
                expected_ledger_manifest_sha256=self.root2[1],
                trust=self.trust, expected_latest_certificate_sha256=cert1[1])
        with self.assertRaisesRegex(a.AnchorError, 'NEW_CHALLENGE_REUSES'):
            c._create_claim(**{**context, 'external_unique_challenge_sha256':self.challenge1})

    def test_04_console_no_privileged_signing_route(self):
        # The fixed read-only console cannot forward private key paths, out,
        # another mode, or the standalone sign/assemble subcommands.
        cmd = [sys.executable, '-I', '-B', str(ROOT / 'scripts' / 'ces_next.py'),
               'audit-custody', 'DeliveryAudit', 'NotSign',
               '--chain-file', self.root1[0],
               '--expected-chain-sha256', self.root1[1],
               '--ledger-manifest-file', self.root1[0],
               '--expected-ledger-manifest-sha256', self.root1[1],
               '--expected-latest-certificate-sha256', 'a1'*32,
               '--expected-latest-challenge-sha256', self.challenge1,
               '--custodian-a-id', self.trust['custodian_a_id'],
               '--custodian-a-public-hex', self.trust['custodian_a_public_hex'],
               '--custodian-b-id', self.trust['custodian_b_id'],
               '--custodian-b-public-hex', self.trust['custodian_b_public_hex']]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode,3)
        self.assertIn('EC316_ONLY_DELIVERYAUDIT',proc.stdout)
        extra = subprocess.run([*cmd, '--out', '/tmp/deny'],
                               capture_output=True, text=True, timeout=30)
        self.assertNotEqual(extra.returncode,0)
