#!/usr/bin/env python3
"""EC299 signed two-witness chains using real original EC294/295/296/297.

Only the old fixture's external Provider/Inbox are simulated locally. Tests
cannot establish real independent persons/sites, true WORM or trusted UTC.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec288_delivery_send_host import protocol as orig
from ec295_delivery_anchor import anchor as a
from ec295_delivery_anchor import operator as storage
from ec297_anchor_lineage import lineage as l
from ec298_anchor_conflicts.test_conflicts import EC298ConflictCases
from . import witness as w, operator as op

ROOT = Path(__file__).resolve().parents[2]


class EC299WitnessCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        EC298ConflictCases.setUpClass()
        cls.parent = EC298ConflictCases
        cls.root = cls.parent.root
        cls.key_a = Ed25519PrivateKey.generate()
        cls.key_b = Ed25519PrivateKey.generate()
        cls.id_a = 'separate_site_alpha'
        cls.id_b = 'separate_site_beta'
        cls.pub_a = orig.public_hex(cls.key_a)
        cls.pub_b = orig.public_hex(cls.key_b)
        try:
            cls.a1 = cls.receipt('a1', cls.parent.lane_a, cls.id_a, cls.key_a)
            cls.a2 = cls.receipt('a2', cls.parent.lane_extension,
                cls.id_a, cls.key_a, previous=cls.a1)
            cls.b1 = cls.receipt('b1', cls.parent.lane_a, cls.id_b, cls.key_b)
            cls.b_extended = cls.receipt('b-ext', cls.parent.lane_extension,
                                         cls.id_b, cls.key_b, previous=cls.b1)
            cls.b_fork = cls.receipt('b-fork', cls.parent.lane_bridge_fork,
                                     cls.id_b, cls.key_b)
            cls.b_cp_fork = cls.receipt('b-cp-fork',
                                       cls.parent.lane_checkpoint_fork,
                                       cls.id_b, cls.key_b)
        except BaseException:
            EC298ConflictCases.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        EC298ConflictCases.tearDownClass()

    @classmethod
    def put(cls, name, obj, size=w.MAX_MANIFEST_BYTES):
        path = str(cls.root/('299-'+name+'.json'))
        storage.store(path, obj, size)
        return path

    @classmethod
    def receipt(cls, name, lane, who, key, previous=None):
        pub = orig.public_hex(key)
        previous_digest = previous['sha'] if previous is not None else a.GENESIS
        sequence = previous['sequence'] + 1 if previous else 1
        claim, _, _ = w.verified_claim_from_lane(lane,
            witness_id=who, public_hex=pub, sequence=sequence,
            previous_digest=previous_digest)
        signed = {'schema': w.RECEIPT_SCHEMA, 'claim': claim,
                  'signature_ed25519': w.sign_claim(claim, key)}
        file = cls.put(name, signed, w.MAX_RECEIPT_BYTES)
        return {'path': file, 'sha': a.sha(signed), 'lane': lane,
                'sequence': sequence, 'signed': signed}

    @classmethod
    def manifest(cls, a_obs, b_obs):
        return {'schema':w.MANIFEST_SCHEMA,
                'a':{'witness_id':cls.id_a,
                     'observations':[{'signed_observation_file':ob['path'],
                                       **ob['lane']} for ob in a_obs]},
                'b':{'witness_id':cls.id_b,
                     'observations':[{'signed_observation_file':ob['path'],
                                       **ob['lane']} for ob in b_obs]}}

    def compare(self, a_obs=None, b_obs=None, manifest=None, **overrides):
        doc = manifest if manifest is not None else self.manifest(
            a_obs if a_obs is not None else [self.a1, self.a2],
            b_obs if b_obs is not None else [self.b1])
        params = dict(manifest=doc,
            a_id=self.id_a, a_public_hex=self.pub_a,
            a_tip=(a_obs or [self.a1,self.a2])[-1]['sha'],
            b_id=self.id_b, b_public_hex=self.pub_b,
            b_tip=(b_obs or [self.b1])[-1]['sha'])
        params.update(overrides)
        return w.compare_witnesses(**params)

    def compare_file(self, name, a_obs=None, b_obs=None, **overrides):
        x = a_obs if a_obs is not None else [self.a1,self.a2]
        y = b_obs if b_obs is not None else [self.b1]
        file = self.put(name, self.manifest(x,y))
        args = dict(manifest_file=file, a_id=self.id_a,
            a_public_hex=self.pub_a, a_tip=x[-1]['sha'],
            b_id=self.id_b, b_public_hex=self.pub_b, b_tip=y[-1]['sha'])
        args.update(overrides)
        return op.compare(**args), file, args

    def console_args(self, path, args, *, action='DeliveryAudit', mode='VerifyWitnesses'):
        return [sys.executable, '-I', '-B', str(ROOT/'scripts/ces_next.py'),
            'audit-witness', action, mode, '--manifest-file', path,
            '--expected-a-id', args['a_id'],
            '--expected-a-public-hex', args['a_public_hex'],
            '--expected-a-tip', args['a_tip'],
            '--expected-b-id', args['b_id'],
            '--expected-b-public-hex', args['b_public_hex'],
            '--expected-b-tip', args['b_tip']]

    def cli_args(self, path, args, *, mode='compare-witnesses'):
        return [sys.executable,'-I','-B',str(ROOT/'scripts/ces_anchor_witness.py'),
            mode, '--manifest-file', path,
            '--expected-a-id', args['a_id'],
            '--expected-a-public-hex', args['a_public_hex'],
            '--expected-a-tip', args['a_tip'],
            '--expected-b-id', args['b_id'],
            '--expected-b-public-hex', args['b_public_hex'],
            '--expected-b-tip', args['b_tip']]

    def test_01_identical_pins_and_legitimate_fourth_epoch_are_compatible(self):
        doc = self.compare()
        self.assertEqual(doc['status'],'supplied_signed_witness_observations_compatible')
        self.assertEqual(doc['exit_code'],0)
        self.assertEqual(doc['historical_pair_categories']['identical_signed_history'],1)
        self.assertEqual(doc['historical_pair_categories']['b_signed_checkpoint_ancestor_of_a'],1)
        self.assertTrue(doc['all_original_ec294_ec295_ec296_ec297_proofs_reverified_per_observation'])
        self.assertFalse(doc['globally_unique_latest_or_preferred_fork_proven'])

    def test_02_both_witnesses_express_normal_monotonic_three_to_four_epochs(self):
        doc=self.compare(b_obs=[self.b1,self.b_extended])
        self.assertEqual(doc['status'],'supplied_signed_witness_observations_compatible')
        self.assertEqual(sum(doc['historical_pair_categories'].values()),4)

    def test_03_two_genuine_signed_four_vote_rotation_successors_detected(self):
        doc=self.compare(b_obs=[self.b_fork])
        self.assertEqual(doc['status'],'signed_competing_evidence_between_supplied_witnesses')
        self.assertEqual(doc['exit_code'],2)
        self.assertEqual(doc['historical_pair_categories']['signed_competing_evidence'],2)
        self.assertTrue(any(f['signed_fork']['type'].startswith('two_ec296')
                            for f in doc['signed_fork_evidence']))

    def test_04_real_same_policy_two_signed_checkpoint_children_detected(self):
        doc=self.compare(b_obs=[self.b_cp_fork])
        self.assertTrue(any(f['signed_fork']['type'].startswith('two_ec295')
                            for f in doc['signed_fork_evidence']))
        self.assertEqual(doc['exit_code'],2)

    def test_05_observer_log_rollback_rejected_by_independent_tip(self):
        doc=self.manifest([self.a1],[self.b1])
        with self.assertRaisesRegex(a.AnchorError,'CHAIN_TIP_MISMATCH'):
            self.compare(manifest=doc, a_tip=self.a2['sha'])

    def test_06_wrong_external_pub_key_or_duplicate_witness_key_denied(self):
        with self.assertRaisesRegex(a.AnchorError,'DISTINCT_EXTERNALLY_PINNED'):
            self.compare(b_public_hex=self.pub_a)
        with self.assertRaisesRegex(a.AnchorError,'NOT_EXTERNALLY_PINNED'):
            self.compare(b_public_hex=orig.public_hex(Ed25519PrivateKey.generate()))

    def test_07_distinct_witness_ids_and_explicit_tips_are_mandatory(self):
        wrong=self.manifest([self.a1],[self.b1]);wrong['b']['witness_id']=self.id_a
        with self.assertRaisesRegex(a.AnchorError,'DISTINCT_WITNESS_IDS_REQUIRED'):
            self.compare(manifest=wrong)
        with self.assertRaisesRegex(a.AnchorError,'DISTINCT_EXTERNALLY_PINNED'):
            self.compare(b_tip=a.GENESIS)

    def test_08_wrong_sha_pin_of_any_ec297_entry_denied_before_any_claim(self):
        bad=self.manifest([self.a1],[self.b1])
        bad['b']['observations'][0]['expected_latest_tip']='f'*64
        with self.assertRaises(a.AnchorError):
            self.compare(manifest=bad, a_tip=self.a1['sha'])

    def test_09_fake_observer_signature_even_with_self_calculated_tip_fails(self):
        changed=copy.deepcopy(self.a1['signed'])
        changed['signature_ed25519']='f'*128
        file=self.put('forged',changed,w.MAX_RECEIPT_BYTES)
        bad=self.manifest([self.a1],[self.b1])
        bad['a']['observations'][0]['signed_observation_file']=file
        with self.assertRaisesRegex(a.AnchorError,'ED25519_SIGNATURE_INVALID'):
            self.compare(manifest=bad, a_tip=a.sha(changed))

    def test_10_predecessor_chain_reordering_without_resealing_denied(self):
        bad=self.manifest([self.a2,self.a1],[self.b1])
        with self.assertRaises(a.AnchorError):
            self.compare(manifest=bad, a_tip=self.a1['sha'])

    def test_11_same_witness_must_not_observe_competing_branch_as_progress(self):
        forged=self.receipt('a-branch-after-base',self.parent.lane_bridge_fork,
                            self.id_a,self.key_a,previous=self.a1)
        with self.assertRaisesRegex(a.AnchorError,'NOT_STRICTLY_MONOTONIC'):
            self.compare(a_obs=[self.a1,forged])

    def test_12_same_witness_repeated_identical_observation_rejected(self):
        repeated=self.receipt('a-repeated-base',self.parent.lane_a,
                              self.id_a,self.key_a,previous=self.a1)
        with self.assertRaisesRegex(a.AnchorError,'NOT_STRICTLY_MONOTONIC'):
            self.compare(a_obs=[self.a1,repeated])

    def test_13_claim_cannot_be_swapped_with_another_signed_source(self):
        wrong=self.manifest([self.a1],[self.b1])
        wrong['a']['observations'][0].update(self.parent.lane_extension)
        with self.assertRaisesRegex(a.AnchorError,'CLAIM_DOES_NOT_MATCH'):
            self.compare(manifest=wrong,a_tip=self.a1['sha'])

    def test_14_receipts_have_canonical_path_independent_sha_report(self):
        x=self.compare()
        self.assertEqual(x,self.compare())
        self.assertNotIn(str(self.root),json.dumps(x))
        self.assertNotIn('private',json.dumps(x['signed_fork_evidence']))
        self.assertTrue(all(len(k)==64 for k in x['witness_a']['signed_observation_sha256_chain']))

    def test_15_private_exclusive_report_and_external_sha_reverification(self):
        report,file,args=self.compare_file('verify-inputs')
        report_path=str(self.root/'299-private-report.json')
        matched=op.compare(**{**args,'out':report_path})
        self.assertEqual(report,matched)
        self.assertEqual(os.stat(report_path).st_mode & 0o077,0)
        self.assertEqual(op.compare(**{**args,'report_file':report_path,
                'expected_report_sha256':a.sha(report)}),report)
        with self.assertRaisesRegex(a.AnchorError,'EXCLUSIVE_OUTPUT'):
            op.compare(**{**args,'out':report_path})

    def test_16_laundered_report_bool_rejected_even_with_self_sha(self):
        doc,manifest,args=self.compare_file('tamper-report-inputs')
        altered=copy.deepcopy(doc)
        altered['out_of_band_immutable_retention_or_trusted_utc_proven']=True
        p=self.put('tampered-report',altered,w.MAX_REPORT_BYTES)
        with self.assertRaisesRegex(a.AnchorError,'NOT_IDENTICAL'):
            op.compare(**{**args,'report_file':p,
                          'expected_report_sha256':a.sha(altered)})

    def test_17_verify_report_requires_independent_sha(self):
        report,manifest,args=self.compare_file('report-pin-inputs')
        path=self.put('preexisting-report',report,w.MAX_REPORT_BYTES)
        with self.assertRaisesRegex(a.AnchorError,'EXPLICIT_EXTERNAL_SHA'):
            op.compare(**{**args,'report_file':path})
        with self.assertRaisesRegex(a.AnchorError,'INDEPENDENT_REPORT_SHA_MISMATCH'):
            op.compare(**{**args,'report_file':path,'expected_report_sha256':'f'*64})

    def test_18_real_original_provider_status_not_queried(self):
        before=self.parent.x.base.parent.parent.statusport.lookups
        self.compare()
        self.compare(b_obs=[self.b_fork])
        self.assertEqual(before,self.parent.x.base.parent.parent.statusport.lookups)

    def test_19_standalone_compare_cli_success_and_genuine_conflict_exit_two(self):
        report,path,args=self.compare_file('standalone-input')
        good=subprocess.run(self.cli_args(path,args),capture_output=True,text=True,timeout=180)
        self.assertEqual(good.returncode,0,good.stdout+good.stderr)
        self.assertEqual(json.loads(good.stdout)['report_sha256'],a.sha(report))
        _,fork_path,fork_args=self.compare_file('standalone-fork',b_obs=[self.b_fork])
        bad=subprocess.run(self.cli_args(fork_path,fork_args),capture_output=True,text=True,timeout=180)
        self.assertEqual(bad.returncode,2,bad.stdout+bad.stderr)
        self.assertEqual(json.loads(bad.stdout)['status'],
                         'signed_competing_evidence_between_supplied_witnesses')

    def test_20_offline_prepare_sign_produces_real_observation_and_private_0600(self):
        keypath=str(self.root/'299-operator-witness.key')
        with open(keypath,'xb') as f:
            f.write(self.key_b.private_bytes(encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()))
        os.chmod(keypath,0o600)
        draftpath=str(self.root/'299-operator-draft.json')
        signedpath=str(self.root/'299-operator-signed.json')
        lane=self.parent.lane_a
        prepare=op.prepare(witness_id=self.id_b,witness_public_hex=self.pub_b,
            sequence=1,previous_receipt_file=None,
            expected_previous_receipt_sha256=None,lane=lane,out=draftpath)
        sign=op.sign_observation(draft_file=draftpath,
            expected_draft_sha256=prepare['draft_sha256'],
            private_key_file=keypath,previous_receipt_file=None,
            expected_previous_receipt_sha256=None,lane=lane,out=signedpath)
        self.assertEqual(sign['signed_observation_sha256'],
                         a.sha(json.loads(Path(signedpath).read_text())))
        self.assertEqual(os.stat(draftpath).st_mode&0o077,0)
        self.assertEqual(os.stat(signedpath).st_mode&0o077,0)
        self.assertFalse(sign['real_organization_independence_or_external_pin_saved'])

    def test_21_offline_sign_refuses_wrong_key_or_forged_draft(self):
        lane=self.parent.lane_a
        p=str(self.root/'299-negative-draft.json')
        prepared=op.prepare(witness_id=self.id_b,witness_public_hex=self.pub_b,
            sequence=1,previous_receipt_file=None,
            expected_previous_receipt_sha256=None,lane=lane,out=p)
        badkey=str(self.root/'299-wrong-private.key')
        with open(badkey,'xb') as f:
            f.write(self.key_a.private_bytes(encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()))
        os.chmod(badkey,0o600)
        with self.assertRaisesRegex(a.AnchorError,'PRIVATE_KEY_NOT_EXTERNALLY'):
            op.sign_observation(draft_file=p,
                expected_draft_sha256=prepared['draft_sha256'],
                private_key_file=badkey,previous_receipt_file=None,
                expected_previous_receipt_sha256=None,lane=lane,
                out=str(self.root/'299-should-not-exist.json'))
        self.assertFalse((self.root/'299-should-not-exist.json').exists())
        with self.assertRaisesRegex(a.AnchorError,'DRAFT_SHA'):
            op.sign_observation(draft_file=p,
                expected_draft_sha256='f'*64,
                private_key_file=badkey,previous_receipt_file=None,
                expected_previous_receipt_sha256=None,lane=lane,
                out=str(self.root/'299-should-not-exist-other.json'))

    def test_22_cli_prepare_and_sign_and_report_verification(self):
        report,manifest,args=self.compare_file('cli-verification-manifest')
        output=str(self.root/'299-cli-report.json')
        argv=self.cli_args(manifest,args)+['--out',output]
        got=subprocess.run(argv,capture_output=True,text=True,timeout=180)
        self.assertEqual(got.returncode,0,got.stdout+got.stderr)
        cli=self.cli_args(manifest,args,mode='verify-report') + [
            '--report-file',output,'--expected-report-sha256',a.sha(report)]
        validated=subprocess.run(cli,capture_output=True,text=True,timeout=180)
        self.assertEqual(validated.returncode,0,validated.stdout+validated.stderr)
        self.assertTrue(json.loads(validated.stdout)['report_reverified_against_explicit_external_sha'])

    def test_23_console_exact_allowlist_only_read_only_and_exit_two_fork(self):
        report,path,args=self.compare_file('console-input')
        got=subprocess.run(self.console_args(path,args),capture_output=True,text=True,timeout=180)
        self.assertEqual(got.returncode,0,got.stdout+got.stderr)
        self.assertEqual(json.loads(got.stdout)['schema'],w.RESULT_SCHEMA)
        denial=subprocess.run(self.console_args(path,args,mode='Sign'),
                              capture_output=True,text=True,timeout=180)
        self.assertEqual(denial.returncode,3,denial.stdout)
        self.assertIn('EC299_ONLY_EXPLICIT',denial.stdout)
        _,forkpath,forkargs=self.compare_file('console-fork-input',b_obs=[self.b_fork])
        fork=subprocess.run(self.console_args(forkpath,forkargs),
                            capture_output=True,text=True,timeout=180)
        self.assertEqual(fork.returncode,2,fork.stdout+fork.stderr)

    def test_24_doctor_router_and_original_permissions_unmodified(self):
        console=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_next.py')]
        inv=subprocess.run(console+['routes','--kind','all'],
                           capture_output=True,text=True,timeout=30)
        self.assertEqual(inv.returncode,0,inv.stdout+inv.stderr)
        document=json.loads(inv.stdout)
        self.assertEqual(document['route_count'],74)
        self.assertEqual(sum(x['route_kind']=='HOST_REQUIRED' for x in document['routes']),11)
        self.assertEqual(document['version'],'V6.09')
        doc=subprocess.run(console+['doctor'],capture_output=True,text=True,timeout=30)
        self.assertEqual(doc.returncode,0,doc.stdout+doc.stderr)
        body=json.loads(doc.stdout)
        self.assertTrue(body['ec299_offline_two_witness_observation_client_present'])
        self.assertFalse(body['ec299_real_two_site_immutable_custody_or_global_latest_verified'])

    def test_25_noncanonical_manifest_and_entry_privilege_fields_denied(self):
        malformed=self.manifest([self.a1],[self.b1]); malformed['auto_send']=True
        with self.assertRaisesRegex(a.AnchorError,'MANIFEST_FIELDS_INVALID'):
            self.compare(manifest=malformed,a_tip=self.a1['sha'])
        altered=self.manifest([self.a1],[self.b1]); altered['a']['observations'][0]['key_path']='secret'
        with self.assertRaisesRegex(a.AnchorError,'ENTRY_FIELDS_INVALID'):
            self.compare(manifest=altered,a_tip=self.a1['sha'])

    def test_26_signed_claim_parent_and_signature_domain_are_immutable(self):
        doc=copy.deepcopy(self.a2['signed'])
        doc['claim']['previous_observation_sha256']='f'*64
        with self.assertRaisesRegex(a.AnchorError,'ED25519_SIGNATURE_INVALID'):
            w.verify_receipt(doc,expected_witness_id=self.id_a,
                             expected_public_hex=self.pub_a)

    def test_27_checkpoint_aware_verified_prefix_on_same_epoch_real_signed_shas(self):
        # This is a pure ancestry helper test: the endpoints must already
        # have passed the complete EC297 / EC295 proofs before use.
        actual,actual_snaps=w.c.verify_lane(self.parent.lane_a)
        extended=copy.deepcopy(actual)
        extended_snaps=copy.deepcopy(actual_snaps)
        fake_cp=copy.deepcopy(extended_snaps[-1]['checkpoints'][-1])
        fake_cp['sequence']+=1
        fake_cp['previous_checkpoint_sha256']=fake_cp['checkpoint_sha256']
        fake_cp['checkpoint_sha256']='f'*64
        extended_snaps[-1]['checkpoints'].append(fake_cp)
        self.assertTrue(w._verified_ancestry(actual,actual_snaps,extended,extended_snaps))
        extended_snaps[-1]['checkpoints'][0]['checkpoint_sha256']='e'*64
        self.assertFalse(w._verified_ancestry(actual,actual_snaps,extended,extended_snaps))


    def test_28_second_observation_offline_preparation_replays_prior_lane(self):
        earlier = self.parent.lane_a
        later = self.parent.lane_extension
        draft_path = str(self.root/'299-second-observation-draft.json')
        private_key = str(self.root/'299-second-observation-private.key')
        receipt_path = str(self.root/'299-second-observation-signed.json')
        with open(private_key,'xb') as output:
            output.write(self.key_a.private_bytes(encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()))
        os.chmod(private_key,0o600)
        prepared=op.prepare(witness_id=self.id_a,
            witness_public_hex=self.pub_a,sequence=2,
            previous_receipt_file=self.a1['path'],
            expected_previous_receipt_sha256=self.a1['sha'],
            lane=later,previous_lane=earlier,out=draft_path)
        result=op.sign_observation(draft_file=draft_path,
            expected_draft_sha256=prepared['draft_sha256'],
            private_key_file=private_key,
            previous_receipt_file=self.a1['path'],
            expected_previous_receipt_sha256=self.a1['sha'],
            lane=later,previous_lane=earlier,out=receipt_path)
        rec=json.loads(Path(receipt_path).read_text())
        self.assertEqual(rec['claim']['previous_observation_sha256'],self.a1['sha'])
        self.assertEqual(result['signed_observation_sha256'],a.sha(rec))
        w.verify_receipt(rec,expected_witness_id=self.id_a,
                         expected_public_hex=self.pub_a)

    def test_29_offline_signer_denies_divergence_even_with_valid_prior_receipt(self):
        with self.assertRaisesRegex(a.AnchorError,
                                    'OPERATOR_CANNOT_SIGN_NONMONOTONIC'):
            op.prepare(witness_id=self.id_a,witness_public_hex=self.pub_a,
                sequence=2,previous_receipt_file=self.a1['path'],
                expected_previous_receipt_sha256=self.a1['sha'],
                previous_lane=self.parent.lane_a,
                lane=self.parent.lane_bridge_fork,
                out=str(self.root/'299-divergent-prep-should-not-exist.json'))
        with self.assertRaisesRegex(a.AnchorError,
                                    'PREVIOUS_FULL_SIGNED_EVIDENCE_REQUIRED'):
            op.prepare(witness_id=self.id_a,witness_public_hex=self.pub_a,
                sequence=2,previous_receipt_file=self.a1['path'],
                expected_previous_receipt_sha256=self.a1['sha'],
                lane=self.parent.lane_extension,
                out=str(self.root/'299-missing-prev-should-not-exist.json'))
        self.assertFalse((self.root/'299-divergent-prep-should-not-exist.json').exists())
        self.assertFalse((self.root/'299-missing-prev-should-not-exist.json').exists())

    def test_30_standalone_offline_prepare_sign_commands(self):
        lane=self.parent.lane_a
        script=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_anchor_witness.py')]
        flags=[]
        for k,v in lane.items():
            flags+=['--'+k.replace('_','-'),v]
        draft=str(self.root/'299-cli-new-draft.json')
        signed=str(self.root/'299-cli-new-signed.json')
        p=subprocess.run(script+['prepare-observation','--witness-id',self.id_a,
            '--witness-public-hex',self.pub_a,'--sequence','1',*flags,'--out',draft],
            capture_output=True,text=True,timeout=180)
        self.assertEqual(p.returncode,0,p.stdout+p.stderr)
        proposal=json.loads(p.stdout)
        key=str(self.root/'299-cli-new-private.key')
        with open(key,'xb') as out:
            out.write(self.key_a.private_bytes(encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()))
        os.chmod(key,0o600)
        signed_run=subprocess.run(script+['sign-observation',
            '--draft-file',draft,'--expected-draft-sha256',proposal['draft_sha256'],
            '--private-key-file',key,*flags,'--out',signed],
            capture_output=True,text=True,timeout=180)
        self.assertEqual(signed_run.returncode,0,signed_run.stdout+signed_run.stderr)
        result=json.loads(signed_run.stdout)
        self.assertEqual(result['signed_observation_sha256'],
                         a.sha(json.loads(Path(signed).read_text())))
        self.assertFalse(result['real_organization_independence_or_external_pin_saved'])



if __name__ == '__main__':
    unittest.main()
