#!/usr/bin/env python3
"""EC298 actual signed EC294/EC295/EC296/EC297 history comparison tests.

Use the original EC297 3-epoch fixture, then create independently signed
successors (same old rotation parent, distinct keys or distinct EC295 child).
All cryptographic evidence uses the original EC294 signed local Host, EC227
HMAC/fsync and EC295/EC296 real Ed25519, not synthetic claims. Provider/Inbox
stay parent-test simulators; real off-host SHA custody and independent people
are NOT asserted.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec288_delivery_send_host import protocol as orig
from ec295_delivery_anchor import anchor as a
from ec295_delivery_anchor import operator as storage
from ec296_anchor_rotation import rotation as r
from ec297_anchor_lineage import lineage as l
from ec297_anchor_lineage.test_lineage import EC297LineageCases
from . import conflicts as c, operator as op

PROJECT = Path(__file__).resolve().parents[2]


class EC298ConflictCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        EC297LineageCases.setUpClass()
        cls.parent = EC297LineageCases
        cls.x = cls.parent.fixture
        cls.root = Path(cls.x.base.parent.root)
        try:
            cls._make_forks_and_extensions()
        except BaseException:
            EC297LineageCases.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        EC297LineageCases.tearDownClass()

    @classmethod
    def write(cls, name: str, obj: dict) -> str:
        file = str(cls.root / ('298-'+name+'.json'))
        storage.store(file, obj, l.MAX_INPUT_BYTES)
        return file

    @classmethod
    def new_epoch(cls, name, evidence, keys):
        path = str(cls.root / ('298-'+name+'-policy.json'))
        res = storage.create_policy(
            original_policy_file=cls.x.base.parent.policyfile,
            original_policy_sha256=cls.x.base.parent.policysha,
            operation_id=cls.x.old_policy['operation_id'],
            job_sha256=cls.x.old_policy['job_sha256'],
            keeper_public_hex=orig.public_hex(keys['keeper']),
            witness_public_hex=orig.public_hex(keys['witness']), out=path)
        sha = res['policy_sha256']
        pol = a.load_policy(path, sha)
        cp = cls.sign_checkpoint(evidence, pol, sha, keys)
        return {'policy_file':path, 'policy_sha256':sha,
                'checkpoint_files':[cls.write(name+'-checkpoint', cp)],
                'checkpoint_tip_sha256':a.sha(cp)}, pol, cp

    @staticmethod
    def sign_checkpoint(evidence, policy, policy_sha, keys):
        prepared = a.prepared_from_evidence(evidence, policy, policy_sha, None)
        return {'schema':a.CHECKPOINT_SCHEMA,
                'claim':prepared['claim'], 'evidence':prepared['evidence'],
                **{role+'_signature_ed25519':a.sign(role, prepared['claim'], key)
                   for role,key in keys.items()}}

    @classmethod
    def bridge(cls, name, old_policy, old_sha, old_cp, old_tip, old_keys,
               new_policy, new_sha, new_cp, new_tip, new_keys, minimum):
        claim = r.claim_from_histories(
            old_policy=old_policy,old_policy_sha=old_sha,
            old_checkpoints=[old_cp],old_expected_tip=old_tip,
            new_policy=new_policy,new_policy_sha=new_sha,
            new_checkpoints=[new_cp],new_proposed_tip=new_tip,
            minimum_fresh_readback_unix=minimum)
        votes = {}
        for role in r.ROLES:
            epoch, kind = role.split('_', 1)
            votes[role+'_signature_ed25519'] = r.sign(
                role,claim,(old_keys if epoch == 'old' else new_keys)[kind])
        doc = {'schema':r.BRIDGE_SCHEMA,'claim':claim,**votes}
        return {'bridge_file':cls.write(name+'-bridge', doc),
                'bridge_sha256':a.sha(doc),
                'minimum_fresh_readback_unix':minimum}

    @classmethod
    def lane(cls, spec:dict, name:str) -> dict:
        commit = l.build_commitment(spec)
        return {
            'inputs_file': cls.write(name+'-inputs', spec),
            'commitment_file': cls.write(name+'-commitment', commit),
            'expected_commitment_sha256': a.sha(commit),
            'expected_root_tip':commit['root_checkpoint_tip_sha256'],
            'expected_latest_tip':commit['latest_checkpoint_tip_sha256'],
            'expected_latest_bridge_sha256':commit['latest_rotation_bridge_sha256'],
        }

    @classmethod
    def _make_forks_and_extensions(cls):
        base = cls.parent
        cls.lane_a = cls.lane(base.spec, 'base')
        cls.original_lookups = cls.x.base.parent.parent.statusport.lookups
        # Real EC294 signed Readback evidence from lane A is usable in another
        # independently key-rotated third epoch; the old two signers must sign
        # both bridge claims to create objectively competing successors.
        other_keys = {role:Ed25519PrivateKey.generate() for role in a.DOMAINS}
        new_desc, new_policy, new_cp = cls.new_epoch(
            'distinct-key-successor',base.cp2['evidence'],other_keys)
        new_bridge = cls.bridge('distinct-key-successor',
            cls.x.new_policy,cls.x.new_policy_sha,cls.x.new_cp,cls.x.new_tip,
            cls.x.new_keys,new_policy,new_desc['policy_sha256'],new_cp,
            new_desc['checkpoint_tip_sha256'],other_keys,base.minimum)
        spec = copy.deepcopy(base.spec)
        spec['epochs'][-1] = new_desc
        spec['bridges'][-1] = new_bridge
        cls.lane_bridge_fork = cls.lane(spec, 'bridge-fork')
        # Same third-epoch keeper/witness policy, new original EC294 readback:
        # two authentically signed EC295 sequence=1 children of GENESIS.
        next_evidence, _, _ = cls.x.base.receipt(
            'readback',cls.x.new_cp['claim']['audit_head_hmac_sha256'])
        fork_cp = cls.sign_checkpoint(next_evidence,base.policy2,
                                      base.policy2_sha,base.keys2)
        fork_desc = copy.deepcopy(base.spec['epochs'][-1])
        fork_desc['checkpoint_files'] = [cls.write('same-policy-fork-cp',fork_cp)]
        fork_desc['checkpoint_tip_sha256'] = a.sha(fork_cp)
        fork_bridge = cls.bridge('same-policy-fork',
            cls.x.new_policy,cls.x.new_policy_sha,cls.x.new_cp,cls.x.new_tip,
            cls.x.new_keys,base.policy2,base.policy2_sha,fork_cp,
            fork_desc['checkpoint_tip_sha256'],base.keys2,base.minimum)
        spec = copy.deepcopy(base.spec)
        spec['epochs'][-1],spec['bridges'][-1] = fork_desc,fork_bridge
        cls.lane_checkpoint_fork = cls.lane(spec,'checkpoint-fork')
        # One legitimate fourth epoch appended to A: identical first three
        # signed epochs and their two bridges are a verified prefix, not a fork.
        earliest = base.cp2['claim']['ec294_reply_issued_at_unix']+1
        if int(time.time()) < earliest:
            time.sleep(earliest-int(time.time())+0.1)
        further,_,_ = cls.x.base.receipt(
            'readback',base.cp2['claim']['audit_head_hmac_sha256'])
        fourth_keys = {role:Ed25519PrivateKey.generate() for role in a.DOMAINS}
        fourth_desc,fourth_pol,fourth_cp = cls.new_epoch('fourth',further,fourth_keys)
        fourth_min = base.cp2['claim']['ec294_reply_issued_at_unix']+1
        fourth_bridge = cls.bridge('fourth',base.policy2,base.policy2_sha,
            base.cp2,base.tip2,base.keys2,fourth_pol,fourth_desc['policy_sha256'],
            fourth_cp,fourth_desc['checkpoint_tip_sha256'],fourth_keys,fourth_min)
        extended = copy.deepcopy(base.spec)
        extended['epochs'].append(fourth_desc)
        extended['bridges'].append(fourth_bridge)
        cls.lane_extension = cls.lane(extended,'four-epochs')
        # Neither competing checker is permitted to query the remote status
        # service; all 3 receipt creations above were local-only Readback.
        assert cls.original_lookups == cls.x.base.parent.parent.statusport.lookups

    def compare(self, other=None, first=None, **overrides):
        return op.compare(a_lane=first or self.lane_a,
                          b_lane=other or self.lane_bridge_fork, **overrides)

    def test_01_two_fully_verified_histories_give_competing_four_vote_bridges(self):
        report=self.compare()
        self.assertEqual(report['status'],'signed_competing_evidence')
        self.assertEqual(report['exit_code'],2)
        self.assertEqual(report['signed_bridge_fork_count'],1)
        self.assertEqual(report['signed_checkpoint_fork_count'],0)
        finding=report['findings'][0]
        self.assertEqual(finding['type'],'two_ec296_four_vote_rotation_bridges_from_same_old_tip')
        self.assertEqual(finding['old_checkpoint_tip_sha256'],self.x.new_tip)
        self.assertNotEqual(finding['a']['new_policy_sha256'],finding['b']['new_policy_sha256'])
        self.assertEqual(finding['old_keeper_public_hex'],self.x.new_policy['keeper_public_hex'])
        self.assertFalse(report['globally_unique_latest_or_preferred_fork_established'])

    def test_02_same_policy_signed_checkpoint_children_are_detected(self):
        report=self.compare(self.lane_checkpoint_fork)
        self.assertEqual(report['signed_bridge_fork_count'],1)
        self.assertEqual(report['signed_checkpoint_fork_count'],1)
        item=report['findings'][1]
        self.assertEqual(item['type'],'two_ec295_signed_checkpoint_children_of_same_parent')
        self.assertEqual(item['sequence'],1)
        self.assertEqual(item['previous_checkpoint_sha256'],a.GENESIS)
        self.assertEqual(item['keeper_public_hex'],self.parent.policy2['keeper_public_hex'])
        self.assertNotEqual(item['a']['checkpoint_sha256'],item['b']['checkpoint_sha256'])

    def test_03_same_lineage_is_not_a_fork(self):
        report=self.compare(self.lane_a)
        self.assertEqual(report['comparison'],'identical_lineage_evidence')
        self.assertEqual(report['findings'],[])
        self.assertEqual(report['exit_code'],0)
        self.assertFalse(report['globally_unique_latest_or_preferred_fork_established'])

    def test_04_valid_fourth_epoch_is_forward_extension_not_fork(self):
        report=self.compare(self.lane_extension)
        self.assertEqual(report['comparison'],'a_is_verified_prefix_of_b')
        self.assertEqual(report['exit_code'],0)
        self.assertEqual(report['findings'],[])
        self.assertEqual(report['b_epochs_verified'],4)

    def test_05_reverse_valid_prefix_is_not_fork(self):
        report=self.compare(self.lane_a, first=self.lane_extension)
        self.assertEqual(report['comparison'],'b_is_verified_prefix_of_a')
        self.assertEqual(report['exit_code'],0)

    def test_06_no_common_signed_parent_is_inconclusive_even_if_hashes_differ(self):
        # Classification-only model: real entrypoint always verifies both
        # underlying cryptographic histories before calling this pure helper.
        left=l.build_commitment(self.parent.spec)
        right=copy.deepcopy(left)
        right['epochs'][0]['policy_sha256']='d'*64
        right['epochs'][0]['checkpoint_tip_sha256']='e'*64
        right['epochs'][0]['keeper_public_hex']='a'*64
        right['epochs'][0]['witness_public_hex']='b'*64
        right['bridges'][0]['old_policy_sha256']='d'*64
        right['bridges'][0]['old_checkpoint_tip_sha256']='e'*64
        right['root_checkpoint_tip_sha256']='e'*64
        # Same original operation identity, but no identical signed parent in
        # the synthetic comparison model; hashing different is insufficient.
        result=c.compare_verified(left,[],right,[])
        self.assertEqual(result['status'],'inconclusive')
        self.assertEqual(result['signed_bridge_fork_count'],0)

    def test_07_two_different_original_audit_operations_must_not_compare(self):
        original=l.build_commitment(self.parent.spec)
        mutated=copy.deepcopy(original)
        mutated['operation_id']='1'*64
        with self.assertRaisesRegex(a.AnchorError,'NOT_SAME_ORIGINAL_AUDIT_IDENTITY'):
            c.compare_verified(original,[],mutated,[])

    def test_08_wrong_independent_lineage_commitment_sha_denied(self):
        bad={**self.lane_bridge_fork,'expected_commitment_sha256':'f'*64}
        with self.assertRaisesRegex(a.AnchorError,'COMMITMENT_PIN_MISMATCH'):
            self.compare(bad)

    def test_09_missing_latest_external_bridge_sha_denied(self):
        bad={**self.lane_bridge_fork,'expected_latest_bridge_sha256':a.GENESIS}
        with self.assertRaisesRegex(a.AnchorError,'EIGHT_EXPLICIT'):
            self.compare(bad)

    def test_10_wrong_root_tip_pin_denied(self):
        bad={**self.lane_a,'expected_root_tip':'f'*64}
        with self.assertRaisesRegex(a.AnchorError,'ROOT_LATEST_OR_BRIDGE_PIN_MISMATCH'):
            self.compare(first=bad)

    def test_11_tampered_local_signed_checkpoint_denied(self):
        spec=copy.deepcopy(self.parent.spec)
        cp=copy.deepcopy(self.parent.cp2)
        cp['witness_signature_ed25519']='f'*128
        spec['epochs'][-1]['checkpoint_files']=[self.write('tampered-sig',cp)]
        bad={**self.lane_a,'inputs_file':self.write('tampered-inputs',spec)}
        with self.assertRaises(a.AnchorError):
            self.compare(first=bad)

    def test_12_missing_bridge_or_epoch_denied_before_report(self):
        spec=copy.deepcopy(self.parent.spec)
        del spec['bridges'][-1]
        bad={**self.lane_a,'inputs_file':self.write('missing-bridge-inputs',spec)}
        with self.assertRaisesRegex(a.AnchorError,'ORDERED_EPOCHS_AND_ALL_BRIDGES'):
            self.compare(first=bad)

    def test_13_reproducible_report_is_path_free(self):
        report=self.compare()
        self.assertNotIn(str(self.root),json.dumps(report))
        self.assertNotIn('policy_file',json.dumps(report))
        self.assertEqual(report,self.compare())
        self.assertFalse(report['full_underlying_signed_proof_objects_embedded_in_report'])

    def test_14_private_exclusive_output_and_exact_report_sha_reverification(self):
        dest=str(self.root/'298-private-conflict-report.json')
        first=self.compare(out=dest)
        self.assertEqual(os.stat(dest).st_mode & 0o077,0)
        self.assertEqual(a.sha(first),a.sha(json.loads(Path(dest).read_text())))
        second=self.compare(report_file=dest,expected_report_sha256=a.sha(first))
        self.assertEqual(first,second)
        with self.assertRaisesRegex(a.AnchorError,'EXCLUSIVE_OUTPUT'):
            self.compare(out=dest)

    def test_15_wrong_or_missing_external_report_sha_is_denied(self):
        path=str(self.root/'298-report-pin-test.json')
        report=self.compare(out=path)
        with self.assertRaisesRegex(a.AnchorError,'EXTERNALLY_PINNED_REPORT_SHA_MISMATCH'):
            self.compare(report_file=path,expected_report_sha256='f'*64)
        with self.assertRaisesRegex(a.AnchorError,'REPORT_REVERIFICATION_REQUIRES'):
            self.compare(report_file=path,expected_report_sha256=None)

    def test_16_report_tamper_even_with_self_calculated_digest_is_rejected(self):
        saved=self.compare()
        saved['globally_unique_latest_or_preferred_fork_established']=True
        path=self.write('false-verified',saved)
        with self.assertRaisesRegex(a.AnchorError,'NOT_EQUAL_TO_CURRENT_REVERIFIED'):
            self.compare(report_file=path,expected_report_sha256=a.sha(saved))

    def test_17_script_cli_outputs_conflict_exit_two_and_report_sha(self):
        argv=[sys.executable,'-I','-B',str(PROJECT/'scripts/ces_anchor_conflicts.py'),
              'compare-lineages']
        for key,lane in (('a',self.lane_a),('b',self.lane_bridge_fork)):
            for field,value in lane.items():
                argv += ['--'+key+'-'+field.replace('_','-'),value]
        got=subprocess.run(argv,capture_output=True,text=True,timeout=180)
        self.assertEqual(got.returncode,2,got.stderr)
        parsed=json.loads(got.stdout)
        self.assertEqual(parsed['schema'],c.RESULT_SCHEMA)
        self.assertEqual(parsed['report_sha256'],a.sha(parsed['report']))
        self.assertFalse(parsed['external_custody_or_unique_latest_proven'])

    def test_18_cli_verify_report_against_external_digest(self):
        out=str(self.root/'298-cli-verify-report.json')
        rep=self.compare(out=out)
        argv=[sys.executable,'-I','-B',str(PROJECT/'scripts/ces_anchor_conflicts.py'),
              'verify-report','--report-file',out,
              '--expected-report-sha256',a.sha(rep)]
        for key,lane in (('a',self.lane_a),('b',self.lane_bridge_fork)):
            for field,value in lane.items():argv+=['--'+key+'-'+field.replace('_','-'),value]
        got=subprocess.run(argv,capture_output=True,text=True,timeout=180)
        self.assertEqual(got.returncode,2,got.stderr)
        self.assertTrue(json.loads(got.stdout)['verified_against_explicit_report_sha'])

    def test_19_unified_console_exact_comparison_allowed_and_bound(self):
        argv=[sys.executable,'-I','-B',str(PROJECT/'scripts/ces_next.py'),
              'audit-conflicts','DeliveryAudit','CompareLineages']
        for key,lane in (('a',self.lane_a),('b',self.lane_bridge_fork)):
            for field,value in lane.items():argv+=['--'+key+'-'+field.replace('_','-'),value]
        good=subprocess.run(argv,capture_output=True,text=True,timeout=180)
        self.assertEqual(good.returncode,2,good.stderr+good.stdout[:900])
        self.assertEqual(json.loads(good.stdout)['report']['signed_bridge_fork_count'],1)
        denied=argv.copy();denied[denied.index('CompareLineages')]='Run'
        bad=subprocess.run(denied,capture_output=True,text=True,timeout=180)
        self.assertEqual(bad.returncode,3)
        self.assertEqual(json.loads(bad.stdout)['status'],'permission_denied')

    def test_20_console_original_router_is_still_74_and_host_required_11(self):
        inv=subprocess.run([sys.executable,'-I','-B',str(PROJECT/'scripts/ces_next.py'),
                            'routes','--kind','all'],capture_output=True,text=True,timeout=30)
        self.assertEqual(inv.returncode,0)
        doc=json.loads(inv.stdout)
        self.assertEqual(doc['route_count'],74)
        self.assertEqual(sum(r['route_kind']=='HOST_REQUIRED' for r in doc['routes']),11)
        self.assertEqual(doc['version'],'V6.08')

    def test_21_doctor_tells_truth_about_availability_not_custody(self):
        got=subprocess.run([sys.executable,'-I','-B',str(PROJECT/'scripts/ces_next.py'),
                            'doctor'],capture_output=True,text=True,timeout=30)
        self.assertEqual(got.returncode,0)
        doc=json.loads(got.stdout)
        self.assertTrue(doc['ec298_offline_signed_fork_comparison_client_present'])
        self.assertFalse(doc['ec298_external_custody_global_fork_adjudication_or_real_signers_verified'])

    def test_22_no_status_provider_lookup_added_during_offline_comparison(self):
        before=self.x.base.parent.parent.statusport.lookups
        self.compare()
        self.compare(self.lane_checkpoint_fork)
        self.assertEqual(before,self.x.base.parent.parent.statusport.lookups)
        self.assertEqual(before,self.original_lookups)


if __name__=='__main__':
    unittest.main()
