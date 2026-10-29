#!/usr/bin/env python3
"""EC266 focused real Git + HMAC + Ed25519 signed admission assertions.

Authorities, evidence and a receiver are co-located for this development
fixture; remote platform authenticity is deliberately NOT claimed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec253_lease_host import broker as lease
from ec263_offline_anchor_host import checkpoint as cp
from ec264_segmented_audit_host import segment as seg
from ec264_segmented_audit_host import test_host as legacy_host
from ec265_custody_receipt_host import test_host as custody_host
from ec266_source_provenance_host import provenance as prov


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     Path('/usr/bin/git').exists() and cp.Ed25519PrivateKey is not None,
                     'nonroot real Git and Ed25519 required')
class ProvenanceTests(unittest.TestCase):
    setUp = legacy_host.SegmentedRealGitSessionTests.setUp
    kill_host = legacy_host.SegmentedRealGitSessionTests.kill_host
    _prepare = legacy_host.SegmentedRealGitSessionTests._prepare
    remote = legacy_host.SegmentedRealGitSessionTests.remote
    begin_request = legacy_host.SegmentedRealGitSessionTests.begin_request
    prepare_base = custody_host.RealGitCustodyGateTests.prepare

    def prepare(self):
        self.prepare_base()
        self.subject = self.fix.private/'ec266-subject.json'
        self.proposed = prov.propose(
            str(self.gitfx.repo), str(self.gitfx.allowpath),
            str(self.gitfx.output/'source.custody.json'),
            str(self.fix.policy_path), 'python.pytest',
            'git.example.test/group/repository', 'refs/heads/release', str(self.subject))
        self.signers = {}
        authorities = []
        for role in prov.ROLES:
            secret = self.fix.private/(role+'.private')
            public = self.fix.private/(role+'.public')
            pin = cp.generate_offline_keypair(str(secret), str(public))['signer_public_sha256']
            evidence = self.fix.private/(role+'-external-evidence.json')
            # This fixture data is NOT fetched from an actual remote provider.
            evidence.write_bytes(prov._canonical({
                'fixture': 'no external source proof', 'role': role,
                'subject': self.proposed['subject_sha256'],
            }))
            evidence.chmod(0o600)
            signed = self.fix.private/(role+'-signed.json')
            result = prov.sign_offline(str(self.subject), self.proposed['subject_sha256'],
                role, str(evidence), cp._digest(evidence.read_bytes()),
                role+'-fixture-record', str(secret), pin, str(signed))
            self.signers[role] = dict(secret=secret, public=public, evidence=evidence,
                                      signed=signed, pin=pin)
            authorities.append({
                'role': role, 'public_key': str(public), 'public_sha256': pin,
                'evidence': str(evidence),
                'evidence_sha256': cp._digest(evidence.read_bytes()),
                'assertion': str(signed),
                'assertion_sha256': result['assertion_sha256'],
            })
        self.gate_path = self.fix.private/'ec266-gate.json'
        self.gate_data = {
            'schema': prov.GATE_SCHEMA, 'subject': str(self.subject),
            'subject_sha256': self.proposed['subject_sha256'],
            'origin_repository': 'git.example.test/group/repository',
            'origin_ref': 'refs/heads/release', 'authorities': authorities,
        }
        self.write_gate()
        self.args.provenance_gate = str(self.gate_path)
        self.args.provenance_gate_sha256 = self.gate_pin

    def write_gate(self):
        self.gate_path.write_bytes(prov._canonical(self.gate_data))
        self.gate_path.chmod(0o600)
        self.gate_pin = cp._digest(self.gate_path.read_bytes())
        if hasattr(self, 'args'):
            self.args.provenance_gate_sha256 = self.gate_pin

    def new_gate(self, *, pin=None):
        return prov.SignedSourceGate(
            str(self.fix.policy_path), str(self.gitfx.repo),
            str(self.gitfx.allowpath),
            str(self.gitfx.output/'source.custody.json'), 'python.pytest',
            str(self.gate_path), pin or self.gate_pin,
            forbidden_signers=(self.pub_pin, self.custody_pin),
        )

    def verify(self, gate=None):
        gate = gate or self.new_gate()
        policy, sha = lease._policy(str(self.fix.policy_path))
        gate.startup(policy, sha)
        return gate

    def deny(self, code: str, *, gate=None):
        with self.assertRaises(prov.ProvenanceError) as err:
            self.verify(gate)
        self.assertEqual(err.exception.code, code)

    def test_01_fully_pinned_distinct_signatures_match_git_and_tickets(self):
        self.prepare()
        gate = self.verify()
        report = gate.summary()
        self.assertEqual(report['role_signatures_valid'], ['origin', 'review', 'ci'])
        self.assertEqual(report['source_commit_oid'], self.gitfx.commit)
        self.assertFalse(report['remote_git_review_ci_provider_verified'])
        policy, sha = lease._policy(str(self.fix.policy_path))
        gate.before_begin(policy, sha, {'profile_id': 'python.pytest'})

    def test_02_changed_evidence_is_denied_even_if_assertion_unchanged(self):
        self.prepare()
        self.signers['ci']['evidence'].write_bytes(b'tampered fake passing result')
        self.deny('EC266_EVIDENCE_BYTES_PIN_MISMATCH')

    def test_03_missing_review_role_and_duplicate_signing_identity_denied(self):
        self.prepare()
        self.gate_data['authorities'].pop(1)
        self.write_gate()
        self.deny('EC266_GATE_CONFIG_FIELDS_INVALID')
        self.prepare_repair()
        self.gate_data['authorities'][2]['public_sha256'] = self.signers['review']['pin']
        self.write_gate()
        self.deny('EC266_ROLE_SIGNERS_NOT_DISTINCT')

    def prepare_repair(self):
        self.gate_data = {
            **self.gate_data,
            'authorities': [
                {'role': role, 'public_key': str(self.signers[role]['public']),
                 'public_sha256': self.signers[role]['pin'],
                 'evidence': str(self.signers[role]['evidence']),
                 'evidence_sha256': cp._digest(self.signers[role]['evidence'].read_bytes()),
                 'assertion': str(self.signers[role]['signed']),
                 'assertion_sha256': cp._digest(self.signers[role]['signed'].read_bytes())}
                for role in prov.ROLES],
        }
        self.write_gate()

    def test_04_wrong_decision_with_reapproved_file_pins_fails_signature(self):
        self.prepare()
        doc = self.signers['ci']['signed']
        assertion = json.loads(doc.read_bytes())
        assertion['decision'] = 'failed'
        doc.write_bytes(prov._canonical(assertion))
        self.gate_data['authorities'][2]['assertion_sha256'] = cp._digest(doc.read_bytes())
        self.write_gate()
        self.deny('EC266_ASSERTION_FIELDS_INVALID')
        assertion['decision'] = 'passed'
        assertion['evidence_id'] = 'modified-provider-ci-id'
        doc.write_bytes(prov._canonical(assertion))
        self.gate_data['authorities'][2]['assertion_sha256'] = cp._digest(doc.read_bytes())
        self.write_gate()
        self.deny('EC266_ASSERTION_SIGNATURE_INVALID')

    def test_05_role_replay_with_valid_signature_rejected(self):
        self.prepare()
        replay = self.fix.private/'replayed-origin-as-review.json'
        replay.write_bytes(self.signers['origin']['signed'].read_bytes())
        replay.chmod(0o600)
        self.gate_data['authorities'][1]['assertion'] = str(replay)
        self.gate_data['authorities'][1]['assertion_sha256'] = cp._digest(
            replay.read_bytes())
        self.write_gate()
        self.deny('EC266_ASSERTION_SUBJECT_OR_EVIDENCE_MISMATCH')

    def test_06_subject_pin_mismatch_or_op_identity_substitution_rejected(self):
        self.prepare()
        self.subject.write_bytes(self.subject.read_bytes().replace(
            b'"refs/heads/release"', b'"refs/heads/not-release"'))
        self.deny('EC266_SUBJECT_PIN_MISMATCH')

    def test_07_external_operator_pin_still_required(self):
        self.prepare()
        self.deny('EC266_GATE_CONFIG_PIN_MISMATCH', gate=self.new_gate(pin='a'*64))

    def test_08_altered_policy_or_local_git_source_cannot_reuse_approval(self):
        self.prepare()
        doc = self.gitfx.allowpath
        orig = doc.read_bytes()
        self.assertIn(self.gitfx.commit.encode(), orig)
        doc.write_bytes(orig.replace(self.gitfx.commit.encode(), b'f'*len(self.gitfx.commit)))
        with self.assertRaises((prov.CustodyGateError, prov.ProvenanceError)):
            self.verify()

    def test_09_signer_key_does_not_match_operator_pin(self):
        self.prepare()
        role = 'ci'
        doc = self.signers[role]
        with self.assertRaisesRegex(prov.ProvenanceError, 'EC266_OFFLINE_SIGNER_PIN_MISMATCH'):
            prov.sign_offline(str(self.subject), self.proposed['subject_sha256'],
                role, str(doc['evidence']), cp._digest(doc['evidence'].read_bytes()),
                'ci-negative-record', str(doc['secret']), self.signers['review']['pin'],
                str(self.fix.private/'bad-assertion.json'))

    def test_10_new_subject_nonce_not_replayable_against_old_assertions(self):
        self.prepare()
        other = self.fix.private/'other-subject.json'
        new = prov.propose(str(self.gitfx.repo), str(self.gitfx.allowpath),
            str(self.gitfx.output/'source.custody.json'), str(self.fix.policy_path),
            'python.pytest', 'git.example.test/group/repository',
            'refs/heads/release', str(other))
        self.assertNotEqual(self.proposed['subject_sha256'], new['subject_sha256'])
        self.gate_data['subject'] = str(other)
        self.gate_data['subject_sha256'] = new['subject_sha256']
        self.write_gate()
        self.deny('EC266_ASSERTION_SUBJECT_OR_EVIDENCE_MISMATCH')

    def test_11_changed_live_signed_evidence_revokes_admission(self):
        self.prepare()
        gate = self.verify()
        self.signers['review']['signed'].unlink()
        policy, sha = lease._policy(str(self.fix.policy_path))
        with self.assertRaisesRegex(prov.ProvenanceError, 'EC266_PRIVATE_FILE_UNAVAILABLE'):
            gate.before_begin(policy, sha, {'profile_id': 'python.pytest'})

    def test_12_signer_cannot_reuse_audit_or_custody_key(self):
        self.prepare()
        self.gate_data['authorities'][0]['public_sha256'] = self.custody_pin
        self.write_gate()
        self.deny('EC266_ROLE_SIGNERS_NOT_DISTINCT')

    def test_13_wrong_external_repository_or_ref_denied(self):
        self.prepare()
        self.gate_data['origin_ref'] = 'refs/heads/other'
        self.write_gate()
        self.deny('EC266_OPERATOR_REMOTE_IDENTITY_MISMATCH')

    def test_14_wrong_profile_no_longer_meets_signed_policy(self):
        self.prepare()
        gate = self.verify()
        policy, sha = lease._policy(str(self.fix.policy_path))
        with self.assertRaisesRegex(prov.CustodyGateError, 'EC259_UNAPPROVED_PROFILE'):
            gate.before_begin(policy, sha, {'profile_id': 'different-profile'})


    def test_15_evidence_repin_cannot_erase_old_signer_digest_binding(self):
        self.prepare()
        evidence = self.signers['ci']['evidence']
        evidence.write_bytes(b'new but never approved external CI evidence')
        self.gate_data['authorities'][2]['evidence_sha256'] = cp._digest(evidence.read_bytes())
        self.write_gate()
        self.deny('EC266_ASSERTION_SUBJECT_OR_EVIDENCE_MISMATCH')

    def test_16_noncanonical_assertion_rejected_despite_config_repin(self):
        self.prepare()
        doc = self.signers['origin']['signed']
        doc.write_text(json.dumps(json.loads(doc.read_bytes()), indent=2) + '\n')
        self.gate_data['authorities'][0]['assertion_sha256'] = cp._digest(doc.read_bytes())
        self.write_gate()
        self.deny('EC266_CANONICAL_JSON_REQUIRED')

    def test_17_source_repository_cannot_contain_own_verifying_authority(self):
        self.prepare()
        pub = self.gitfx.repo/'self-authorizing-pub'
        pub.write_bytes(self.signers['origin']['public'].read_bytes())
        pub.chmod(0o600)
        self.gate_data['authorities'][0]['public_key'] = str(pub)
        self.write_gate()
        self.deny('EC266_AUTHORITY_FILE_INSIDE_SOURCE_REPOSITORY')

    def test_18_attestation_sha_must_match_pinned_exact_bytes(self):
        self.prepare()
        doc = self.signers['review']['signed']
        doc.write_bytes(doc.read_bytes() + b' ')
        self.deny('EC266_CANONICAL_JSON_REQUIRED')


if __name__ == '__main__':
    unittest.main(verbosity=2)
