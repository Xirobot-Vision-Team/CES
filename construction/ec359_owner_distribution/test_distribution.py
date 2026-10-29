#!/usr/bin/env python3
"""EC359 real local Ed25519 signatures over genuinely replayed EC358..337.

All issuer/owner keys here are generated synthetic fixtures, NOT official roots.
Never interpret local cryptographic test success as real identity attestation.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import json
import os
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519
from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec353_transparency import test_transparency as tr
from ec358_reviewer_epochs import epochs as prior
from ec358_reviewer_epochs import test_epochs as parent_cases
from . import distribution as core


class DistributionTests(parent_cases.EpochTests):
    for _method in dir(parent_cases.EpochTests):
        if _method.startswith('test_'):locals()[_method] = None

    def setUp(self):
        super().setUp()
        self.distributors = {}
        self.distribution_records = {'a':[], 'b':[]}
        self.distribution_heads = {}
        self.distribution_floors = {'a':0, 'b':0}

    def setup359(self):
        self.setup358()
        self.epoch_inputs = self.args358()
        self.actual358 = prior.audit(**self.epoch_inputs)
        self.assertTrue(self.actual358['two_signed_owner_histories_locally_continuous_and_match_ec357_review'])
        self.actual358_sha = core.sha(canonical.canonical(self.actual358))
        for slot in ('a', 'b'):
            priv = ed25519.Ed25519PrivateKey.generate()
            public = self.write353('ec359-distributor-' + slot, tr.pub(priv))
            self.distributors[slot] = {'private': priv, 'pub': public}
            self.distribution_record(slot, 'authorize', 0)

    def distribution_record(self, slot, operation, sequence, *, predecessor=None,
               changes=None, bad_signature=False,
               claimed_issuer_id=None, effective_offset=timedelta(hours=5, minutes=10)):
        issuer = self.distributors[slot]
        body = {
            'schema': core.RECORD_SCHEMA, 'scope': core.SCOPE, 'slot': slot,
            'issuer_id': claimed_issuer_id or 'external_distributor_' + slot,
            'issuer_public_key_original_sha256': issuer['pub']['sha256'],
            'claimed_owner_id': 'claimed_owner_' + slot,
            'owner_public_key_original_sha256': self.owners[slot]['pub']['sha256'],
            'parent_ec358_canonical_result_sha256': self.actual358_sha,
            'parent_owner_head_event_original_sha256': self.my_heads[slot],
            'sequence': sequence, 'previous_record_original_sha256': predecessor,
            'operation': operation,
            'replacement_owner_public_key_sha256': ('e' * 64 if operation == 'rotate'
                                                     else None),
            'effective_utc': tr.ut(self.now + effective_offset),
            'expires_utc': tr.ut(self.now + timedelta(days=2)),
        }
        if changes:body.update(changes)
        sign_key = (self.owners[slot]['private'] if bad_signature
                    else issuer['private'])
        signature = sign_key.sign(core.SIGN_DOMAIN + canonical.canonical(body)).hex()
        pin = self.write353('ec359-signed-distribution-' + slot + '-' +
                            str(len(self.distribution_records[slot])),
                            {**body, 'signature_issuer_ed25519_hex': signature})
        self.distribution_records[slot].append(pin)
        self.distribution_heads[slot] = pin['sha256']
        return pin

    def args359(self, **changes):
        manifest = self.write353('ec359-signed-distribution-bundle', {
            'schema': core.BUNDLE_SCHEMA,
            'sources': [
                {'slot':slot, 'distributor_public_key': self.distributors[slot]['pub'],
                 'records': self.distribution_records[slot]}
                for slot in ('a', 'b') if slot in self.distributors],
        })
        a=self.distributors.get('a');b=self.distributors.get('b')
        return {**self.epoch_inputs,
            'distribution_evaluation_utc':tr.ut(self.now+timedelta(hours=6)),
            'distribution_bundle_file':manifest['path'],
            'expected_distribution_bundle_sha256':manifest['sha256'],
            'distributor_a_public_key_file':a['pub']['path'] if a else None,
            'expected_distributor_a_public_key_sha256':a['pub']['sha256'] if a else None,
            'distributor_b_public_key_file':b['pub']['path'] if b else None,
            'expected_distributor_b_public_key_sha256':b['pub']['sha256'] if b else None,
            'minimum_a_distribution_sequence':self.distribution_floors['a'],
            'minimum_b_distribution_sequence':self.distribution_floors['b'],
            'expected_a_distribution_head_sha256':self.distribution_heads.get('a'),
            'expected_b_distribution_head_sha256':self.distribution_heads.get('b'),
            **changes}

    def run359(self, **changes):return core.audit(**self.args359(**changes))

    def denied(self, fragment, **changes):
        with self.assertRaises(errors.AnchorError) as caught:self.run359(**changes)
        self.assertIn(fragment, caught.exception.code)

    def test_01_two_true_distributor_signatures_not_official_roots(self):
        self.setup359();result=self.run359()
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['actual_ec358_through_ec337_signed_originals_replayed'])
        self.assertTrue(result['two_issuer_signed_distributions_locally_match_ec358_owner'])
        self.assertEqual(result['channel_evidence'][0]['outcome'],core.OUTCOMES[-1])
        self.assertTrue(result['official_issuer_authority_external_root_distribution_trusted_utc_and_global_head_unproven'])
        self.assertFalse(result['two_caller_pinned_distributor_keys_are_official_trust_anchors'])

    def test_02_signed_terminal_revocation_never_reauthorizes(self):
        self.setup359()
        self.distribution_record('a','revoke',1,predecessor=self.distribution_records['a'][0]['sha256'])
        result=self.run359()
        self.assertTrue(result['signed_owner_revocation_or_replacement_visible'])
        self.assertEqual(result['channel_evidence'][0]['outcome'],core.OUTCOMES[3])

    def test_03_signed_owner_replacement_only_deauthorizes_old(self):
        self.setup359()
        self.distribution_record('b','rotate',1,predecessor=self.distribution_records['b'][0]['sha256'])
        result=self.run359()
        self.assertTrue(result['signed_owner_revocation_or_replacement_visible'])
        self.assertFalse(result['two_issuer_signed_distributions_locally_match_ec358_owner'])

    def test_04_two_signed_sibling_authorizations_cannot_hide_fork(self):
        self.setup359();root=self.distribution_records['a'][0]['sha256']
        self.distribution_record('a','authorize',1,predecessor=root)
        chosen=self.distribution_heads['a']
        self.distribution_record('a','authorize',1,predecessor=root,
                    changes={'expires_utc':tr.ut(self.now+timedelta(days=3))})
        self.distribution_heads['a']=chosen
        result=self.run359()
        self.assertTrue(result['signed_distribution_fork_or_issuer_claim_collision_visible'])
        self.assertEqual(result['channel_evidence'][0]['outcome'],core.OUTCOMES[2])

    def test_05_external_sequence_floor_detects_rollback(self):
        self.setup359();root=self.distribution_records['a'][0]['sha256']
        self.distribution_record('a','authorize',1,predecessor=root)
        self.distribution_heads['a']=root;self.distribution_floors['a']=1
        result=self.run359()
        self.assertTrue(result['caller_pinned_distribution_rollback_visible'])
        self.assertEqual(result['channel_evidence'][0]['outcome'],core.OUTCOMES[4])

    def test_06_forged_issuer_signature_is_hard_denial(self):
        self.setup359();self.distribution_records['a']=[]
        self.distribution_record('a','authorize',0,bad_signature=True)
        self.denied('DISTRIBUTOR_REAL_SIGNATURE_INVALID')

    def test_07_parent_owner_key_cannot_be_independent_issuer(self):
        self.setup359()
        old=self.owners['a']['pub']
        self.denied('DISTRIBUTOR_PIN_MUST_BE_SEPARATELY_CALLER_FIXED',
            distributor_a_public_key_file=old['path'],
            expected_distributor_a_public_key_sha256=old['sha256'])

    def test_08_false_parent_sha_even_when_signed_is_denied(self):
        self.setup359();self.distribution_records['b']=[]
        self.distribution_record('b','authorize',0,
                    changes={'parent_ec358_canonical_result_sha256':'f'*64})
        self.denied('SIGNATURE_SCOPE_OWNER_OR_REAL_PARENT_BINDING_MISMATCH')

    def test_09_absent_external_distribution_cannot_imply_identity(self):
        self.setup359()
        result=self.run359(distribution_bundle_file=None,
                           expected_distribution_bundle_sha256=None)
        self.assertEqual(result['channel_evidence'][0]['outcome'],core.OUTCOMES[1])
        self.assertFalse(result['two_issuer_signed_distributions_locally_match_ec358_owner'])

    def test_10_missing_signed_predecessor_denied(self):
        self.setup359();self.distribution_records['b']=[]
        self.distribution_record('b','authorize',1,predecessor='d'*64)
        self.denied('MISSING_REAL_SIGNED_DISTRIBUTION_PREDECESSOR')

    def test_11_distinct_signers_same_signed_claimed_issuer_visible(self):
        self.setup359();self.distribution_records['b']=[]
        self.distribution_record('b','authorize',0,claimed_issuer_id='external_distributor_a')
        result=self.run359()
        self.assertTrue(result['signed_distribution_fork_or_issuer_claim_collision_visible'])

    def test_12_untrusted_future_signed_utc_is_not_history_proof(self):
        self.setup359();self.distribution_records['a']=[]
        self.distribution_record('a','authorize',0,effective_offset=timedelta(hours=7))
        result=self.run359()
        self.assertTrue(result['signed_distribution_clock_claim_anomaly_visible'])
        self.assertEqual(result['channel_evidence'][0]['outcome'],core.OUTCOMES[5])

    def test_13_cannot_revive_after_signed_deauthorization(self):
        self.setup359();root=self.distribution_records['a'][0]['sha256']
        death=self.distribution_record('a','revoke',1,predecessor=root)
        self.distribution_record('a','authorize',2,predecessor=death['sha256'])
        self.denied('DISTRIBUTION_SEQUENCE_OR_TERMINAL_PARENT_INVALID')

    def test_14_fixed_isolated_unified_readonly_entry(self):
        self.setup359();inp=self.args359()
        root=Path(__file__).resolve().parents[2]
        sys.path.insert(0,str(root/'scripts'))
        import ces_next as console
        argv=[sys.executable,'-I','-B',str(root/'scripts'/'ces_next.py'),
              'audit-owner-distribution','DeliveryAudit','AuditOwnerDistribution']
        for key in console.EC359_REQUIRED:
            argv.extend(['--'+key.replace('_','-'),str(inp[key])])
        for key in console.EC359_OPTIONAL:
            if inp[key] is not None:
                argv.extend(['--'+key.replace('_','-'),str(inp[key])])
        for key,flag in console.EC359_REPEATS:
            for value in inp[key]:argv.extend([flag,str(value)])
        proc=subprocess.run(argv,capture_output=True,text=True,timeout=1800)
        self.assertEqual(proc.returncode,2,proc.stderr+' '+proc.stdout[-1400:])
        reply=json.loads(proc.stdout)
        self.assertEqual(reply['schema'],core.RESULT_SCHEMA)
        self.assertTrue(reply['two_issuer_signed_distributions_locally_match_ec358_owner'])

    def test_15_hardlinked_new_issuer_to_parent_owner_file_denied(self):
        self.setup359()
        issuer=self.distributors['a']['pub']
        Path(issuer['path']).unlink()
        os.link(self.owners['a']['pub']['path'],issuer['path'])
        self.denied('WHOLE_ORIGINAL_SHA_MISMATCH')
