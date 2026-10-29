#!/usr/bin/env python3
"""EC268 nonroot real Git/HMAC/Ed25519 handover exercises.

All roots and the witness are co-located fixtures. No remote issuer ownership,
hardware trust, production OCI or clock service is asserted by these tests.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ec253_lease_host import broker as lease
from ec263_offline_anchor_host import checkpoint as cp
from ec266_source_provenance_host import provenance as prov
from ec267_governed_source_host import governance as gov
from ec267_governed_source_host.test_governance import GovernanceTests as old
from ec268_root_handover_host import handover as rot
from ec268_root_handover_host import serve as service


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0 and
                     Path('/usr/bin/git').is_file() and cp.Ed25519PrivateKey is not None,
                     'nonroot Linux + real Git and cryptography required')
class RootHandoverTests(unittest.TestCase):
    setUp = old.setUp
    kill_host = old.kill_host
    _prepare = old._prepare
    remote = old.remote
    begin_request = old.begin_request
    prepare_base = old.prepare_base
    prepare_ec266 = old.prepare_ec266
    write_gate = old.write_gate
    issue = old.issue

    def prepare(self):
        old.prepare(self)
        self.prev_policy, self.prev_pin = self.gov_policy, self.gov_pin
        self.prev_root_secret, self.prev_root_public = self.root_secret, self.root_public
        self.prev_root_pin = self.root_pin
        self.new_root_secret = self.fix.private/'ec268-new-root-secret.key'
        self.new_root_public = self.fix.private/'ec268-new-root-public.key'
        self.new_root_pin = cp.generate_offline_keypair(
            str(self.new_root_secret), str(self.new_root_public))['signer_public_sha256']
        self.witness_secret = self.fix.private/'ec268-witness-secret.key'
        self.witness_public = self.fix.private/'ec268-witness-public.key'
        self.witness_pin = cp.generate_offline_keypair(
            str(self.witness_secret), str(self.witness_public))['signer_public_sha256']
        self.new_policy_proposal = self.fix.private/'ec268-next-epoch-proposal.json'
        self.new_policy = self.fix.private/'ec268-next-epoch-signed.json'
        self.new_gov(revoked=())
        self.handover_proposal = self.fix.private/'ec268-handover-unsigned.json'
        self.old_step = self.fix.private/'ec268-handover-old-signed.json'
        self.new_step = self.fix.private/'ec268-handover-new-signed.json'
        self.handover_cert = self.fix.private/'ec268-handover-3-signed.json'
        self.make_handover()
        self.args.governance_policy = str(self.new_policy)
        self.args.governance_policy_sha256 = self.new_pin
        self.args.governance_public = str(self.new_root_public)
        self.args.governance_public_sha256 = self.new_root_pin
        self.args.minimum_governance_epoch = 2
        self.args.expected_previous_governance_sha256 = self.prev_pin
        self.args.previous_governance_policy = str(self.prev_policy)
        self.args.previous_governance_policy_sha256 = self.prev_pin
        self.args.previous_governance_public = str(self.prev_root_public)
        self.args.previous_governance_public_sha256 = self.prev_root_pin
        self.args.witness_public = str(self.witness_public)
        self.args.witness_public_sha256 = self.witness_pin
        self.args.handover_certificate = str(self.handover_cert)
        self.args.handover_certificate_sha256 = self.handover_pin
        self.args.anchor_governance = str(self.new_policy)
        self.args.anchor_governance_sha256 = self.new_pin
        self.args.continuation_chain = None
        self.args.continuation_chain_sha256 = None

    def new_gov(self, *, revoked: tuple[str, ...], epoch: int = 2, previous: str | None = None):
        # Reissue as a distinct signed byte sequence when testing changes.
        if self.new_policy_proposal.exists():
            self.new_policy_proposal = self.fix.private/('proposal-'+os.urandom(6).hex()+'.json')
            self.new_policy = self.fix.private/('next-'+os.urandom(6).hex()+'.json')
        record = gov.prepare_policy(str(self.gate_path), self.gate_pin,
            epoch=epoch, previous_governance_sha256=previous or self.prev_pin,
            issued_at_unix=self.issued, not_before_unix=self.valid_from,
            expires_at_unix=self.valid_until, revoked_public_sha256=revoked,
            output=str(self.new_policy_proposal))
        signed = gov.sign_offline(str(self.new_policy_proposal), record['proposal_sha256'],
            str(self.new_root_secret), self.new_root_pin, str(self.new_policy))
        self.new_pin = signed['governance_sha256']
        if hasattr(self.args, 'governance_policy'):
            self.args.governance_policy = str(self.new_policy)
            self.args.governance_policy_sha256 = self.new_pin

    def _kwargs(self):
        return dict(old_governance=str(self.prev_policy), old_governance_sha256=self.prev_pin,
            new_governance=str(self.new_policy), new_governance_sha256=self.new_pin,
            old_root_public=str(self.prev_root_public), old_root_public_sha256=self.prev_root_pin,
            new_root_public=str(self.new_root_public), new_root_public_sha256=self.new_root_pin,
            witness_public=str(self.witness_public), witness_public_sha256=self.witness_pin)

    def make_handover(self):
        proposal = rot.prepare_handover(**self._kwargs(), output=str(self.handover_proposal),
            declared_at_unix=self.issued)
        a = rot.sign_offline(str(self.handover_proposal), proposal['handover_proposal_sha256'],
            'old', str(self.prev_root_secret), self.prev_root_pin, str(self.old_step))
        b = rot.sign_offline(str(self.old_step), a['signed_handover_sha256'],
            'new', str(self.new_root_secret), self.new_root_pin, str(self.new_step),
            previous_public_keys={'old':(str(self.prev_root_public), self.prev_root_pin)})
        c = rot.sign_offline(str(self.new_step), b['signed_handover_sha256'],
            'witness', str(self.witness_secret), self.witness_pin, str(self.handover_cert),
            previous_public_keys={'old':(str(self.prev_root_public), self.prev_root_pin),
                                  'new':(str(self.new_root_public), self.new_root_pin)})
        self.handover_pin = c['signed_handover_sha256']
        if hasattr(self.args, 'handover_certificate'):
            self.args.handover_certificate = str(self.handover_cert)
            self.args.handover_certificate_sha256 = self.handover_pin
        self.args.anchor_governance = str(self.new_policy)
        self.args.anchor_governance_sha256 = self.new_pin
        self.args.continuation_chain = None
        self.args.continuation_chain_sha256 = None

    def new_gate(self, **overrides):
        args = dict(
            policy_path=str(self.fix.policy_path), repo=str(self.gitfx.repo),
            allowlist=str(self.gitfx.allowpath),
            receipt=str(self.gitfx.output/'source.custody.json'),
            profile_id='python.pytest', provenance_gate=str(self.gate_path),
            provenance_gate_sha256=self.gate_pin,
            governance_policy=str(self.new_policy), governance_policy_sha256=self.new_pin,
            governance_public=str(self.new_root_public), governance_public_sha256=self.new_root_pin,
            minimum_epoch=2, expected_previous_governance_sha256=self.prev_pin,
            previous_governance=str(self.prev_policy),
            previous_governance_sha256=self.prev_pin,
            previous_governance_public=str(self.prev_root_public),
            previous_governance_public_sha256=self.prev_root_pin,
            witness_public=str(self.witness_public), witness_public_sha256=self.witness_pin,
            handover_certificate=str(self.handover_cert),
            handover_certificate_sha256=self.handover_pin,
            anchor_governance=str(self.new_policy),
            anchor_governance_sha256=self.new_pin,
            forbidden_signers=(self.pub_pin, self.custody_pin),
        )
        args.update(overrides)
        return rot.RootHandoverGate(**args)

    def verify(self, gate=None):
        gate = gate or self.new_gate()
        policy, sha = lease._policy(str(self.fix.policy_path))
        gate.startup(policy, sha)
        return gate

    def deny(self, code, gate=None):
        with self.assertRaises(rot.HandoverError) as caught:
            self.verify(gate)
        self.assertEqual(caught.exception.code, code)

    def test_01_three_distinct_signatures_authorize_current_real_git(self):
        self.prepare()
        gate = self.verify()
        report = gate.summary()
        self.assertEqual(report['handover_signatures_verified'], ['old', 'new', 'witness'])
        self.assertEqual(report['governance_epoch'], 2)
        self.assertEqual(report['old_governance_epoch'], 1)
        self.assertEqual(report['new_governance_epoch'], 2)
        self.assertEqual(report['role_signatures_valid'], ['origin', 'review', 'ci'])
        self.assertFalse(report['historical_root_chain_cross_restart_nonrollback_verified'])
        policy, sha = lease._policy(str(self.fix.policy_path))
        gate.before_begin(policy, sha, {'profile_id':'python.pytest'})

    def test_02_each_missing_signature_denied_even_if_file_pinned(self):
        self.prepare()
        for path in (self.handover_proposal, self.old_step, self.new_step):
            self.deny('EC268_HANDOVER_SCHEMA_OR_SIGNING_ORDER_INVALID',
                self.new_gate(handover_certificate=str(path),
                          handover_certificate_sha256=cp._digest(path.read_bytes())))

    def test_03_forged_payload_with_recalculated_pin_fails_signatures(self):
        self.prepare()
        forged = json.loads(self.handover_cert.read_bytes())
        forged['declared_at_unix'] += 1
        self.handover_cert.write_bytes(prov._canonical(forged))
        self.deny('EC268_HANDOVER_SIGNATURE_INVALID',
                  self.new_gate(handover_certificate_sha256=cp._digest(self.handover_cert.read_bytes())))

    def test_04_wrong_certificate_sha_is_rejected(self):
        self.prepare()
        self.deny('EC268_HANDOVER_CERTIFICATE_PIN_MISMATCH',
                  self.new_gate(handover_certificate_sha256='f'*64))

    def test_05_wrong_old_root_pin_or_wrong_old_key_denied(self):
        self.prepare()
        self.deny('EC268_PUBLIC_KEY_PIN_MISMATCH',
                  self.new_gate(previous_governance_public_sha256='f'*64))
        with self.assertRaisesRegex(rot.HandoverError,'EC268_HANDOVER_AUTHORITY_PATH_COLLISION'):
            self.new_gate(previous_governance_public=str(self.new_root_public),
                          previous_governance_public_sha256=self.new_root_pin)

    def test_06_wrong_new_root_pin_or_public_file_denied_by_parent(self):
        self.prepare()
        with self.assertRaisesRegex(gov.GovernanceError,'EC267_GOVERNANCE_ROOT_PIN_MISMATCH'):
            self.verify(self.new_gate(governance_public_sha256='a'*64))

    def test_07_witness_public_key_loss_recalls_active_gate(self):
        self.prepare()
        gate = self.verify()
        self.witness_public.unlink()
        policy, sha = lease._policy(str(self.fix.policy_path))
        with self.assertRaisesRegex(rot.HandoverError, 'EC268_PUBLIC_KEY_FILE_UNAVAILABLE'):
            gate.before_begin(policy, sha, {'profile_id':'python.pytest'})

    def test_08_replaced_historic_policy_with_recomputed_pin_denied(self):
        self.prepare()
        doc = json.loads(self.prev_policy.read_bytes())
        doc['revoked_public_sha256'] = ['9'*64]
        self.prev_policy.write_bytes(prov._canonical(doc))
        with self.assertRaisesRegex(gov.GovernanceError,'EC267_EPOCH_OR_PREDECESSOR_PIN_MISMATCH'):
            self.verify(self.new_gate(
                previous_governance_sha256=cp._digest(self.prev_policy.read_bytes()),
                expected_previous_governance_sha256=cp._digest(self.prev_policy.read_bytes())))

    def test_09_dropped_historic_revocations_forbidden(self):
        self.prepare()
        # The previous policy must be signed by the old root to count.
        unsigned = self.fix.private/'retired-old-proposal.json'
        signed = self.fix.private/'retired-old-signed.json'
        result = gov.prepare_policy(str(self.gate_path), self.gate_pin,
            epoch=1, previous_governance_sha256=gov.ZERO,
            issued_at_unix=self.issued, not_before_unix=self.valid_from,
            expires_at_unix=self.valid_until, revoked_public_sha256=('1'*64,),
            output=str(unsigned))
        pinned = gov.sign_offline(str(unsigned),result['proposal_sha256'],
            str(self.prev_root_secret), self.prev_root_pin, str(signed))['governance_sha256']
        self.new_gov(revoked=(),previous=pinned)
        with self.assertRaisesRegex(rot.HandoverError,'EC268_HISTORIC_ISSUER_REVOCATION_DROPPED'):
            rot.prepare_handover(**{**self._kwargs(),
                'old_governance':str(signed),'old_governance_sha256':pinned},
                output=str(self.fix.private/'drop-proposal.json'))

    def test_10_old_root_not_reused_as_new_root(self):
        self.prepare()
        with self.assertRaisesRegex(rot.HandoverError,'EC268_THREE_SIGNERS_NOT_DISTINCT'):
            rot.prepare_handover(**{**self._kwargs(),
                'new_root_public':str(self.prev_root_public),
                'new_root_public_sha256':self.prev_root_pin},
                output=str(self.fix.private/'same-root.json'))

    def test_11_witness_must_not_match_ec266_or_custody_authority(self):
        self.prepare()
        self.deny('EC268_SIGNER_NOT_INDEPENDENT_OF_ISSUERS_OR_AUDIT', self.new_gate(
            witness_public=str(self.signers['ci']['public']),
            witness_public_sha256=self.signers['ci']['pin']))
        self.deny('EC268_SIGNER_NOT_INDEPENDENT_OF_ISSUERS_OR_AUDIT', self.new_gate(
            witness_public=str(self.custody_public),
            witness_public_sha256=self.custody_pin))

    def test_12_stage_cannot_be_skipped_or_reordered(self):
        self.prepare()
        with self.assertRaisesRegex(rot.HandoverError,'EC268_HANDOVER_SCHEMA_OR_SIGNING_ORDER_INVALID'):
            rot.sign_offline(str(self.handover_proposal),cp._digest(self.handover_proposal.read_bytes()),
                'new',str(self.new_root_secret),self.new_root_pin,
                str(self.fix.private/'wrong-stage.json'))

    def test_13_wrong_offline_signer_private_identity_denied(self):
        self.prepare()
        with self.assertRaisesRegex(rot.HandoverError,'EC268_SIGNER_PRIVATE_KEY_PIN_MISMATCH'):
            rot.sign_offline(str(self.handover_proposal),cp._digest(self.handover_proposal.read_bytes()),
                'old',str(self.new_root_secret),self.prev_root_pin,
                str(self.fix.private/'wrong-signer.json'))

    def test_14_signer_must_pin_exact_input_bytes_independently(self):
        self.prepare()
        with self.assertRaisesRegex(rot.HandoverError,'EC268_SIGNING_INPUT_PIN_MISMATCH'):
            rot.sign_offline(str(self.handover_proposal),'f'*64,
                'old',str(self.prev_root_secret),self.prev_root_pin,
                str(self.fix.private/'wrong-input.json'))

    def test_15_signer_must_verify_previous_signature_and_external_pub_pin(self):
        self.prepare()
        forged = json.loads(self.old_step.read_bytes())
        forged['signature_old_ed25519'] = 'f'*128
        self.old_step.write_bytes(prov._canonical(forged))
        with self.assertRaisesRegex(rot.HandoverError,'EC268_HANDOVER_SIGNATURE_INVALID'):
            rot.sign_offline(str(self.old_step),cp._digest(self.old_step.read_bytes()),
                'new',str(self.new_root_secret),self.new_root_pin,
                str(self.fix.private/'forged-old.json'),
                previous_public_keys={'old':(str(self.prev_root_public),self.prev_root_pin)})

    def test_16_signing_outputs_cannot_overwrite_immutable_prior_stage(self):
        self.prepare()
        with self.assertRaisesRegex(rot.HandoverError,'EC268_SIGNING_OUTPUT_MUST_BE_NEW_PRIVATE_FILE'):
            rot.sign_offline(str(self.handover_proposal),cp._digest(self.handover_proposal.read_bytes()),
                'old',str(self.prev_root_secret),self.prev_root_pin,
                str(self.old_step))

    def test_17_current_epoch_must_have_exact_external_predecessor(self):
        self.prepare()
        with self.assertRaisesRegex(rot.HandoverError,'EC268_INDEPENDENT_PREDECESSOR_PIN_MISMATCH'):
            self.new_gate(expected_previous_governance_sha256='f'*64)

    def test_18_current_short_governance_expiry_is_still_enforced(self):
        self.prepare()
        with mock.patch.object(gov,'_now',return_value=(float(self.valid_until)+1,200)):
            with self.assertRaisesRegex(gov.GovernanceError,'EC267_GOVERNANCE_EXPIRED'):
                self.verify()

    def test_19_historic_governance_expiry_does_not_block_valid_new_lease(self):
        self.prepare()
        # A signed historical predecessor can have expired already. Build an
        # expired predecessor and a fresh valid successor, not forged timestamps.
        issued = self.issued - 1000
        old_unsigned = self.fix.private/'expired-old-proposal.json'
        old_signed = self.fix.private/'expired-old-governance.json'
        p = gov.prepare_policy(str(self.gate_path), self.gate_pin,
            epoch=1, previous_governance_sha256=gov.ZERO,
            issued_at_unix=issued, not_before_unix=issued,
            expires_at_unix=issued+100, revoked_public_sha256=(),
            output=str(old_unsigned))
        old_pin = gov.sign_offline(str(old_unsigned), p['proposal_sha256'],
            str(self.prev_root_secret),self.prev_root_pin,str(old_signed))['governance_sha256']
        self.prev_policy, self.prev_pin = old_signed, old_pin
        self.new_gov(revoked=(), previous=old_pin)
        self.handover_proposal = self.fix.private/'expired-old-handover-proposal.json'
        self.old_step = self.fix.private/'expired-old-step.json'
        self.new_step = self.fix.private/'expired-new-step.json'
        self.handover_cert = self.fix.private/'expired-witness-step.json'
        self.make_handover()
        self.assertEqual(self.verify().summary()['old_governance_epoch'], 1)

    def test_20_noncanonical_certificate_denied(self):
        self.prepare()
        self.handover_cert.write_bytes(self.handover_cert.read_bytes() + b' ')
        with self.assertRaisesRegex(rot.HandoverError,'EC268_PRIVATE_CANONICAL_DOCUMENT_REQUIRED'):
            self.verify(self.new_gate(handover_certificate_sha256=cp._digest(self.handover_cert.read_bytes())))

    def test_21_older_root_proposal_with_skipped_epoch_denied(self):
        self.prepare()
        self.new_gov(revoked=(),epoch=3)
        with self.assertRaisesRegex(rot.HandoverError,'EC268_GOVERNANCE_EPOCH_OR_PREDECESSOR_MISMATCH'):
            rot.prepare_handover(**self._kwargs(), output=str(self.fix.private/'skip-epoch.json'))

    def test_22_all_key_pins_different_from_old_and_new_roles(self):
        self.prepare()
        pins = set(self.signers[r]['pin'] for r in prov.ROLES)
        self.assertTrue(pins.isdisjoint({self.prev_root_pin,self.new_root_pin,self.witness_pin}))
        self.assertEqual(len({self.prev_root_pin,self.new_root_pin,self.witness_pin}),3)

    def test_23_broken_current_signature_fails_even_with_new_file_pin(self):
        self.prepare()
        forged = json.loads(self.new_policy.read_bytes())
        forged['revoked_public_sha256'] = ['e'*64]
        self.new_policy.write_bytes(prov._canonical(forged))
        self.new_pin = cp._digest(self.new_policy.read_bytes())
        with self.assertRaisesRegex(gov.GovernanceError,'EC267_GOVERNANCE_SIGNATURE_INVALID'):
            self.verify()

    def test_24_certificate_or_witness_path_cannot_be_same_as_root(self):
        self.prepare()
        with self.assertRaisesRegex(rot.HandoverError,'EC268_HANDOVER_AUTHORITY_PATH_COLLISION'):
            self.new_gate(handover_certificate=str(self.new_policy))

    def test_25_cli_preparation_signing_and_gating_return_partial_not_full(self):
        self.prepare()
        cli = self.fix.private/'cli-propose-handover.json'
        options = []
        mapping = {
            'previous-governance-policy':str(self.prev_policy),
            'previous-governance-policy-sha256':self.prev_pin,
            'previous-governance-public':str(self.prev_root_public),
            'previous-governance-public-sha256':self.prev_root_pin,
            'governance-policy':str(self.new_policy),
            'governance-policy-sha256':self.new_pin,
            'governance-public':str(self.new_root_public),
            'governance-public-sha256':self.new_root_pin,
            'witness-public':str(self.witness_public),
            'witness-public-sha256':self.witness_pin,
            'output':str(cli),
        }
        for flag, value in mapping.items():
            options.extend(['--'+flag,value])
        with mock.patch('sys.stdout') as out:
            self.assertEqual(service.main(['prepare-handover',*options]),2)
            self.assertIn('requires_three_offline_independent_signatures',''.join(x.args[0] for x in out.write.call_args_list))
        self.assertTrue(cli.exists())
        with mock.patch('sys.stdout') as out:
            self.assertEqual(service.main(['verify-gate',*self._args_cli()]),2)
            self.assertIn('handover_signatures_verified',''.join(x.args[0] for x in out.write.call_args_list))

    def renew_policy(self, epoch: int, previous_pin: str, *, revoked=()):
        unsigned = self.fix.private/('renew-'+str(epoch)+'-'+os.urandom(3).hex()+'.json')
        signed = self.fix.private/('renew-signed-'+str(epoch)+'-'+os.urandom(3).hex()+'.json')
        proposed = gov.prepare_policy(str(self.gate_path), self.gate_pin,
            epoch=epoch, previous_governance_sha256=previous_pin,
            issued_at_unix=self.issued, not_before_unix=self.valid_from,
            expires_at_unix=self.valid_until, revoked_public_sha256=revoked,
            output=str(unsigned))
        result = gov.sign_offline(str(unsigned), proposed['proposal_sha256'],
            str(self.new_root_secret), self.new_root_pin, str(signed))
        return signed, result['governance_sha256']

    def create_chain(self, next_path, next_pin, *, previous_chain=None, previous_pin=None):
        output = self.fix.private/('new-root-chain-'+os.urandom(4).hex()+'.json')
        result = rot.prepare_continuation(
            anchor_governance=str(self.new_policy),
            anchor_governance_sha256=self.new_pin,
            new_root_public=str(self.new_root_public),
            new_root_public_sha256=self.new_root_pin,
            next_governance=str(next_path), next_governance_sha256=next_pin,
            previous_chain=str(previous_chain) if previous_chain else None,
            previous_chain_sha256=previous_pin, output=str(output))
        return output, result['continuation_chain_sha256']

    def test_26_new_root_can_renew_without_old_private_key_or_witness_signer(self):
        self.prepare()
        newer, newer_pin = self.renew_policy(3, self.new_pin)
        chain_path, chain_pin = self.create_chain(newer, newer_pin)
        self.assertEqual(self.verify(self.new_gate(
            governance_policy=str(newer), governance_policy_sha256=newer_pin,
            anchor_governance=str(self.new_policy), anchor_governance_sha256=self.new_pin,
            continuation_chain=str(chain_path), continuation_chain_sha256=chain_pin,
            expected_previous_governance_sha256=self.new_pin)).summary()['governance_continuations'],1)
        # Signing private keys for old root AND witness are not needed after
        # the three signature ceremony; live admission reads only public keys.
        self.prev_root_secret.unlink()
        self.witness_secret.unlink()
        self.assertEqual(self.verify(self.new_gate(
            governance_policy=str(newer), governance_policy_sha256=newer_pin,
            anchor_governance=str(self.new_policy), anchor_governance_sha256=self.new_pin,
            continuation_chain=str(chain_path), continuation_chain_sha256=chain_pin,
            expected_previous_governance_sha256=self.new_pin)).summary()['governance_epoch'],3)

    def test_27_two_serial_renewals_chain_each_predecessor_and_revocations(self):
        self.prepare()
        after1, pin1 = self.renew_policy(3, self.new_pin, revoked=('4'*64,))
        chain1, chain1_pin = self.create_chain(after1,pin1)
        after2, pin2 = self.renew_policy(4, pin1, revoked=('4'*64,'5'*64))
        chain2, chain2_pin = self.create_chain(after2,pin2,
            previous_chain=chain1, previous_pin=chain1_pin)
        verified = self.verify(self.new_gate(
            governance_policy=str(after2), governance_policy_sha256=pin2,
            anchor_governance=str(self.new_policy), anchor_governance_sha256=self.new_pin,
            continuation_chain=str(chain2), continuation_chain_sha256=chain2_pin,
            expected_previous_governance_sha256=pin1))
        self.assertEqual(verified.summary()['governance_continuations'],2)
        self.assertEqual(verified.summary()['governance_epoch'],4)
        with self.assertRaisesRegex(rot.HandoverError,'EC268_INDEPENDENT_PREDECESSOR_PIN_MISMATCH'):
            self.new_gate(governance_policy=str(after2),governance_policy_sha256=pin2,
                anchor_governance=str(self.new_policy),anchor_governance_sha256=self.new_pin,
                continuation_chain=str(chain2),continuation_chain_sha256=chain2_pin,
                expected_previous_governance_sha256=self.new_pin)

    def test_28_renewal_cannot_discard_previous_revocations(self):
        self.prepare()
        after1, pin1 = self.renew_policy(3, self.new_pin, revoked=('6'*64,))
        chain1, chain_pin = self.create_chain(after1,pin1)
        after2, pin2 = self.renew_policy(4, pin1, revoked=())
        with self.assertRaisesRegex(rot.HandoverError,'EC268_HISTORIC_ISSUER_REVOCATION_DROPPED'):
            self.create_chain(after2,pin2,previous_chain=chain1,previous_pin=chain_pin)

    def test_29_renewal_without_pinned_continuation_or_changed_chain_denied(self):
        self.prepare()
        later, later_pin = self.renew_policy(3,self.new_pin)
        with self.assertRaisesRegex(rot.HandoverError,'EC268_CONTINUATION_REQUIRED_FOR_RENEWED_GOVERNANCE'):
            self.new_gate(governance_policy=str(later),governance_policy_sha256=later_pin,
                anchor_governance=str(self.new_policy),anchor_governance_sha256=self.new_pin,
                expected_previous_governance_sha256=self.new_pin)
        chain, chain_pin = self.create_chain(later,later_pin)
        pinning = self.new_gate(governance_policy=str(later),governance_policy_sha256=later_pin,
            anchor_governance=str(self.new_policy),anchor_governance_sha256=self.new_pin,
            continuation_chain=str(chain),continuation_chain_sha256=chain_pin,
            expected_previous_governance_sha256=self.new_pin)
        policy, policy_pin = lease._policy(str(self.fix.policy_path))
        pinning.startup(policy,policy_pin)
        chain.unlink()
        with self.assertRaisesRegex(rot.HandoverError,'EC268_CONTINUATION_CANONICAL_CONFIG_REQUIRED'):
            pinning.before_begin(policy,policy_pin,{'profile_id':'python.pytest'})

    def test_30_continuation_config_wrong_digest_rejected(self):
        self.prepare()
        later, later_pin = self.renew_policy(3,self.new_pin)
        chain, _ = self.create_chain(later,later_pin)
        with self.assertRaisesRegex(rot.HandoverError,'EC268_CONTINUATION_CONFIG_PIN_MISMATCH'):
            self.new_gate(governance_policy=str(later),governance_policy_sha256=later_pin,
                anchor_governance=str(self.new_policy),anchor_governance_sha256=self.new_pin,
                continuation_chain=str(chain),continuation_chain_sha256='f'*64,
                expected_previous_governance_sha256=self.new_pin)

    def test_31_rotated_ci_signer_must_be_explicitly_revoked_in_handover(self):
        self.prepare()
        previous_ci = self.signers['ci']['pin']
        key = self.fix.private/'ec268-new-ci.key'
        pub = self.fix.private/'ec268-new-ci.pub'
        pin = cp.generate_offline_keypair(str(key),str(pub))['signer_public_sha256']
        evidence = self.signers['ci']['evidence']
        signed_file = self.fix.private/'ec268-new-ci-assertion.json'
        statement = prov.sign_offline(str(self.subject),self.proposed['subject_sha256'],
            'ci',str(evidence),cp._digest(evidence.read_bytes()),
            'new-ci-witness',str(key),pin,str(signed_file))
        role = self.gate_data['authorities'][2]
        role.update(public_key=str(pub),public_sha256=pin,assertion=str(signed_file),
            assertion_sha256=statement['assertion_sha256'])
        self.write_gate()
        self.new_gov(revoked=())
        with self.assertRaisesRegex(rot.HandoverError,'EC268_RETIRED_ISSUER_NOT_REVOKED'):
            rot.prepare_handover(**self._kwargs(),
                output=str(self.fix.private/'no-revocation.json'))
        self.new_gov(revoked=(previous_ci,))
        self.handover_proposal = self.fix.private/'ec268-rotated-ci-handover.json'
        self.old_step = self.fix.private/'ec268-rotated-ci-old.json'
        self.new_step = self.fix.private/'ec268-rotated-ci-new.json'
        self.handover_cert = self.fix.private/'ec268-rotated-ci-witness.json'
        self.make_handover()
        result=self.verify().summary()
        self.assertEqual(result['signed_revocations_checked'],1)
        self.assertEqual(result['handover_signatures_verified'],['old','new','witness'])

    def test_32_source_repository_cannot_host_certificate(self):
        self.prepare()
        self.args.handover_certificate=str(self.gitfx.repo/'untrusted-handover.json')
        with self.assertRaisesRegex(rot.HandoverError,'EC268_HANDOVER_FILE_INSIDE_TRUSTED_SOURCE_OR_AUDIT'):
            service.verify_gate(self.args)

    def test_33_cli_three_offline_signer_stages_exact_paths_and_pins(self):
        self.prepare()
        input_path, input_pin = self.handover_proposal, cp._digest(self.handover_proposal.read_bytes())
        for role, private, public_pin in (
            ('old',self.prev_root_secret,self.prev_root_pin),
            ('new',self.new_root_secret,self.new_root_pin),
            ('witness',self.witness_secret,self.witness_pin)):
            result_path = self.fix.private/('cli-'+role+'-signed.json')
            args = ['sign-offline','--role',role,'--input',str(input_path),
                    '--input-sha256',input_pin,'--signing-key',str(private),
                    '--expected-public-sha256',public_pin,'--output',str(result_path)]
            if role in ('new','witness'):
                args += ['--previous-governance-public',str(self.prev_root_public),
                         '--previous-governance-public-sha256',self.prev_root_pin]
            if role == 'witness':
                args += ['--governance-public',str(self.new_root_public),
                         '--governance-public-sha256',self.new_root_pin]
            with mock.patch('sys.stdout'):
                self.assertEqual(service.main(args),2)
            self.assertTrue(result_path.exists())
            input_path, input_pin = result_path, cp._digest(result_path.read_bytes())
        verified=self.verify(self.new_gate(handover_certificate=str(input_path),
                                           handover_certificate_sha256=input_pin))
        self.assertEqual(verified.summary()['handover_signatures_verified'],['old','new','witness'])

    def test_34_cli_new_root_can_create_first_continuation(self):
        self.prepare()
        next_doc,next_pin=self.renew_policy(3,self.new_pin)
        path=self.fix.private/'cli-epoch3-chain.json'
        cmd=['prepare-continuation','--anchor-governance',str(self.new_policy),
             '--anchor-governance-sha256',self.new_pin,
             '--governance-public',str(self.new_root_public),
             '--governance-public-sha256',self.new_root_pin,
             '--next-governance',str(next_doc),'--next-governance-sha256',next_pin,
             '--output',str(path)]
        with mock.patch('sys.stdout') as out:
            self.assertEqual(service.main(cmd),2)
            self.assertIn('continuation_chain_sha256',
                ''.join(call.args[0] for call in out.write.call_args_list))
        pin=cp._digest(path.read_bytes())
        self.assertEqual(self.verify(self.new_gate(
            governance_policy=str(next_doc),governance_policy_sha256=next_pin,
            anchor_governance=str(self.new_policy),anchor_governance_sha256=self.new_pin,
            continuation_chain=str(path),continuation_chain_sha256=pin,
            expected_previous_governance_sha256=self.new_pin)).summary()['governance_epoch'],3)

    def _args_cli(self):
        fields = ('chain','chain_sha256','custody_gate','custody_gate_sha256',
                  'provenance_gate','provenance_gate_sha256',
                  'governance_policy','governance_policy_sha256',
                  'governance_public','governance_public_sha256',
                  'previous_governance_policy','previous_governance_policy_sha256',
                  'previous_governance_public','previous_governance_public_sha256',
                  'witness_public','witness_public_sha256',
                  'handover_certificate','handover_certificate_sha256',
                  'anchor_governance','anchor_governance_sha256',
                  'policy','repo','allowlist','receipt','profile_id',
                  'minimum_governance_epoch','expected_previous_governance_sha256')
        result = []
        for key in fields:
            result.extend(['--'+key.replace('_','-'),str(getattr(self.args,key))])
        return result


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RootHandoverTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
