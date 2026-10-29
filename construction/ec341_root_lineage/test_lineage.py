#!/usr/bin/env python3
"""EC341 true 1->2->...->8 Ed25519 and unchanged EC340 historical replay.

The inherited EC337 fixture keeps old EC317/318 MOCK evidence, not a claim
about actual multiple institutions, current authorization or trusted time.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec295_delivery_anchor import anchor
from ec319_offline_transfer_registry import registry as reg
from ec321_fork_case_transport import case
from ec324_dual_channel_receipt import receipt as prior
from ec340_issuer_root_rotation import rotation as one
from ec340_issuer_root_rotation import test_rotation as old_tests
from . import lineage as r
from . import operator as op

ROOT=Path(__file__).resolve().parents[2]


def file_sha(path):
    return case.sha(Path(path).read_bytes())


def canonical(path,doc):
    prior._write_exclusive(str(path),reg.raw_doc(doc))
    return file_sha(path)


class BoundedIssuerLineageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        old_tests.IssuerRootRotationTests.setUpClass()
        cls.old=old_tests.IssuerRootRotationTests
        cls.w=Path(cls.old.work)
        cls.policy=cls.old.context
        cls.pconf={k:cls.policy[k] for k in ('policy_file','expected_policy_sha256')}
        cls.hist={k:cls.old.base_opts[k] for k in r.HISTORY_FIELDS}
        cls.first={'epoch':2,
            'successor_roster_file':cls.old.successor_file,
            'expected_successor_roster_sha256':cls.old.successor_sha,
            'observer_roster_file':cls.old.observer_file,
            'expected_observer_roster_sha256':cls.old.observer_sha,
            'root_observation_file':cls.old.obs_file,
            'expected_root_observation_sha256':cls.old.obs_sha,
            'edge_signatures':[{'side':side,'role':role,
                'file':cls.old.edge_files[(side,role)],
                'sha256':cls.old.edge_shas[(side,role)]}
                for side,role in one.EDGE_KEYS],
            'evaluation_utc':'2026-10-25T11:40:00Z',
            'verifier_challenge_sha256':'56'*32}
        cls.keys2=cls.old.new_keys
        cls.keys2paths=cls.old.new_keypaths
        cls.k3,cls.k3paths,cls.h3=cls.make_epoch(
            parent=cls.first,old_keys=cls.keys2paths,number=3,
            time='2026-10-25T12:00:00Z',observed='2026-10-25T12:05:00Z',
            evaluation='2026-10-25T12:20:00Z',expires='2026-10-25T12:40:00Z',
            challenge='78'*32)
        cls.k4,cls.k4paths,cls.h4=cls.make_epoch(
            parent=cls.h3,old_keys=cls.k3paths,number=4,
            time='2026-10-25T12:30:00Z',observed='2026-10-25T12:35:00Z',
            evaluation='2026-10-25T12:39:00Z',expires='2026-10-25T13:10:00Z',
            challenge='79'*32)
        cls.base={'schema':r.MANIFEST_SCHEMA,'context':cls.policy,
                  'history':cls.hist,'hops':[cls.first,cls.h3,cls.h4],
                  'forks':[]}

    @classmethod
    def make_epoch(cls,*,parent,old_keys,number,time,observed,evaluation,
                   expires,challenge, suffix=''):
        name=f'ec341-{number}{suffix}'
        keys=[Ed25519PrivateKey.generate() for _ in r.one.ROLES]
        keypaths=[];issuers=[]
        for i,role in enumerate(one.ROLES):
            path=cls.w/f'{name}-{role}.key'
            old_tests.private(path,keys[i])
            keypaths.append(str(path))
            issuers.append({'role':role,'issuer_id':f'issuer_{name}_{role}',
                            'issuer_public_hex':old_tests.pub(keys[i]),
                            'subject_organization_id':f'org_{role}'})
        cfg=cls.w/f'{name}-config.json';cfg_sha=canonical(cfg,{'issuers':issuers})
        candidate=str(cls.w/f'{name}-roster.json')
        pair={'predecessor_roster_file':parent['successor_roster_file'],
              'expected_predecessor_roster_sha256':
                      parent['expected_successor_roster_sha256']}
        res=r.create_roster(out=candidate,**cls.pconf,**pair,
            issuer_config_file=str(cfg),expected_issuer_config_sha256=cfg_sha,
            rotation_id=f'rotation_{number}{suffix}',
            rotation_nonce_sha256=(f'{number+10+(10 if suffix else 0):02x}'*32),
            effective_utc=time)
        assert res['exit_code']==2
        nxt={'successor_roster_file':candidate,
             'expected_successor_roster_sha256':file_sha(candidate)}
        sig_files={};sig_shas={}
        for side,role in one.EDGE_KEYS:
            i=one.ROLES.index(role)
            path=str(cls.w/f'{name}-{side}-{role}-edge.json')
            result=r.sign_edge(out=path,private_key_file=(
                  old_keys[i] if side=='old' else keypaths[i]),
                  side=side,role=role,**cls.pconf,**pair,**nxt)
            assert result['exit_code']==2
            sig_files[(side,role)]=path
            sig_shas[(side,role)]=file_sha(path)
        witness=Ed25519PrivateKey.generate()
        witness_key=cls.w/f'{name}-observer.key'
        old_tests.private(witness_key,witness)
        obs_roster=cls.w/f'{name}-observer-root.json'
        obs_roster_sha=canonical(obs_roster,{
             'schema':one.OBSERVER_ROOT_SCHEMA,
             'transfer_id':'ec339_transfer_001',
             'policy_original_raw_sha256':cls.policy['expected_policy_sha256'],
             'observer_id':f'obs_{name}',
             'observer_organization_id':f'org_obs_{name}',
             'observer_public_hex':old_tests.pub(witness),
             'independent_out_of_band_approval_required':True})
        obspath=cls.w/f'{name}-observation.json'
        signed=r.issue_observation(out=str(obspath),
            private_key_file=str(witness_key),**cls.pconf,**pair,**nxt,
            observer_roster_file=str(obs_roster),
            expected_observer_roster_sha256=obs_roster_sha,
            edge_files=sig_files,edge_shas=sig_shas,
            verifier_challenge_sha256=challenge,
            observed_utc=observed,expires_utc=expires)
        assert signed['exit_code']==2
        hop={'epoch':number,**nxt,
             'observer_roster_file':str(obs_roster),
             'expected_observer_roster_sha256':obs_roster_sha,
             'root_observation_file':str(obspath),
             'expected_root_observation_sha256':file_sha(obspath),
             'edge_signatures':[{'side':side,'role':role,
                'file':sig_files[(side,role)],'sha256':sig_shas[(side,role)]}
                for side,role in one.EDGE_KEYS],
             'evaluation_utc':evaluation,
             'verifier_challenge_sha256':challenge}
        return keys,keypaths,hop

    @classmethod
    def tearDownClass(cls):
        old_tests.IssuerRootRotationTests.tearDownClass()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=str(self.w))
        self.addCleanup(self.temp.cleanup)
        self.tmp=Path(self.temp.name)

    def options(self,manifest=None,**mods):
        data=copy.deepcopy(manifest if manifest is not None else self.base)
        path=self.tmp/(f'plan-{len(list(self.tmp.iterdir()))}.json')
        sha=canonical(path,data)
        return {'manifest_file':str(path),'expected_manifest_sha256':sha,
                'expected_current_root_sha256':
                    data['hops'][-1]['expected_successor_roster_sha256'],
                'expected_current_root_epoch':len(data['hops'])+1,
                'minimum_acceptable_epoch':3,
                'current_root_evaluation_utc':data['hops'][-1]['evaluation_utc'],
                **mods}

    def test_a_genuine_epoch2_to_3_to_4_with_unmodified_ec340_to_ec337_replay(self):
        result=r.verify_lineage(**self.options())
        self.assertEqual(result['exit_code'],2)
        self.assertEqual(result['status'],'lineage_locally_verified_unresolved')
        self.assertEqual([x['epoch'] for x in result['verified_lineage']],[2,3,4])
        self.assertEqual(result['real_role_signature_count'],24)
        self.assertEqual(result['real_observer_signature_count'],3)
        self.assertTrue(result['historical_ec340_to_ec337_real_original_replay_verified'])
        self.assertTrue(all(result[f] is False for f in r.NEGATIVES))

    def test_b_epoch_floor_and_exact_current_pin_fail_closed(self):
        for change in ({'expected_current_root_epoch':3},
                       {'expected_current_root_sha256':'ba'*32},
                       {'minimum_acceptable_epoch':5},
                       {'current_root_evaluation_utc':'2026-10-25T12:38:00Z'}):
            with self.subTest(change=change):
                with self.assertRaises(anchor.AnchorError):
                    r.verify_lineage(**self.options(**change))

    def test_c_nonadjacent_key_aba_and_reused_nonce_rejected(self):
        doc=copy.deepcopy(self.base)
        root=json.loads(Path(self.h4['successor_roster_file']).read_text())
        root['issuers'][0]['issuer_public_hex']=self.old.new_keys[0].public_key().public_bytes(
            old_tests.serialization.Encoding.Raw,
            old_tests.serialization.PublicFormat.Raw).hex()
        tmp=self.tmp/'aba.json';sha=canonical(tmp,root)
        doc['hops'][2]['successor_roster_file']=str(tmp)
        doc['hops'][2]['expected_successor_roster_sha256']=sha
        with self.assertRaisesRegex(anchor.AnchorError,'ABA'):
            r.verify_lineage(**self.options(doc))
        ids=r._identities({'issuers':json.loads(Path(self.policy['authority_roster_file']).read_text())['issuers']},
                json.loads(Path(self.policy['policy_file']).read_text()))
        r._extend(ids,json.loads(Path(self.h3['successor_roster_file']).read_text()),
                  json.loads(Path(self.h3['observer_roster_file']).read_text()))
        bad=json.loads(Path(self.h4['successor_roster_file']).read_text())
        bad['rotation_nonce_sha256']=json.loads(Path(self.h3['successor_roster_file']).read_text())['rotation_nonce_sha256']
        with self.assertRaises(anchor.AnchorError):r._extend(ids,bad,{
            'observer_id':'unique_obs','observer_public_hex':'ad'*32,
            'observer_organization_id':'unique_org'})

    def test_d_missing_intermediate_and_out_of_order_manifest(self):
        broken=copy.deepcopy(self.base)
        broken['hops'].pop(1)
        with self.assertRaises(anchor.AnchorError):r.verify_lineage(**self.options(broken))
        broken=copy.deepcopy(self.base)
        broken['hops'][1],broken['hops'][2]=broken['hops'][2],broken['hops'][1]
        with self.assertRaises(anchor.AnchorError):r.verify_lineage(**self.options(broken))

    def test_e_unanchored_manifest_and_modified_signed_edge_denied(self):
        opts=self.options()
        opts['expected_manifest_sha256']='ce'*32
        with self.assertRaises(anchor.AnchorError):r.verify_lineage(**opts)
        broken=copy.deepcopy(self.base)
        original=Path(self.h3['edge_signatures'][0]['file'])
        tampered=json.loads(original.read_text())
        tampered['signature_ed25519']='ff'*64
        path=self.tmp/'tampered-edge.json';sha=canonical(path,tampered)
        broken['hops'][1]['edge_signatures'][0]['file']=str(path)
        broken['hops'][1]['edge_signatures'][0]['sha256']=sha
        with self.assertRaises(anchor.AnchorError):r.verify_lineage(**self.options(broken))

    def test_f_witness_stale_external_observer_time_rejected(self):
        broken=copy.deepcopy(self.base)
        broken['hops'][1]['evaluation_utc']='2026-10-25T12:40:00Z'
        with self.assertRaises(anchor.AnchorError):r.verify_lineage(**self.options(broken))

    def test_g_no_overwrite_signer_owner_private_candidate(self):
        old=self.h3
        outfile=self.tmp/'test-sign.json'
        args=dict(out=str(outfile),private_key_file=self.k3paths[0],side='new',
            role='sender',**self.pconf,
            predecessor_roster_file=self.first['successor_roster_file'],
            expected_predecessor_roster_sha256=self.first['expected_successor_roster_sha256'],
            successor_roster_file=old['successor_roster_file'],
            expected_successor_roster_sha256=old['expected_successor_roster_sha256'])
        self.assertEqual(r.sign_edge(**args)['exit_code'],2)
        self.assertEqual(outfile.stat().st_mode & 0o777,0o600)
        with self.assertRaises(Exception):r.sign_edge(**args)

    def test_h_actual_signed_sibling_fork_is_conflict_unresolved_no_winner(self):
        keys,paths,alternative=self.make_epoch(
            parent=self.first,old_keys=self.keys2paths,number=3,
            time='2026-10-25T12:02:00Z',observed='2026-10-25T12:07:00Z',
            evaluation='2026-10-25T12:22:00Z',expires='2026-10-25T12:45:00Z',
            challenge='81'*32,suffix='_fork')
        manifest=copy.deepcopy(self.base)
        manifest['forks']=[{'parent_epoch':2,'hop':alternative}]
        result=r.verify_lineage(**self.options(manifest))
        self.assertEqual(result['status'],'conflict_unresolved')
        self.assertEqual(len(result['fork_conflicts']),1)
        self.assertEqual(result['fork_conflicts'][0]['parent_epoch'],2)
        self.assertEqual(result['real_role_signature_count'],32)
        self.assertEqual(result['real_observer_signature_count'],4)

    def test_i_fork_unsigned_spoof_and_same_successor_refused(self):
        bad=copy.deepcopy(self.base)
        bad['forks']=[{'parent_epoch':2,'hop':copy.deepcopy(self.h3)}]
        with self.assertRaises(anchor.AnchorError):r.verify_lineage(**self.options(bad))

    def test_j_v1_standalone_verifier_isolated_cli(self):
        args=self.options()
        cmd=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_cas_issuer_lineage.py'),
             'verify-lineage']
        for k in op.VERIFY_KEYS:cmd.extend(['--'+k.replace('_','-'),str(args[k])])
        run=subprocess.run(cmd,cwd=ROOT,stdin=subprocess.DEVNULL,
             capture_output=True,text=True,timeout=90)
        self.assertEqual(run.returncode,2,run.stderr+run.stdout)
        self.assertEqual(json.loads(run.stdout)['status'],
                         'lineage_locally_verified_unresolved')

    def test_m_unified_fixed_readonly_route_and_scoped_response(self):
        args=self.options()
        cmd=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_next.py'),
             'audit-issuer-root-lineage','DeliveryAudit',
             'VerifyBoundedIssuerRootLineage']
        for k in op.VERIFY_KEYS:
            cmd.extend(['--'+k.replace('_','-'),str(args[k])])
        run=subprocess.run(cmd,cwd=ROOT,stdin=subprocess.DEVNULL,
            capture_output=True,text=True,timeout=90)
        self.assertEqual(run.returncode,2,run.stderr+run.stdout)
        parsed=json.loads(run.stdout)
        self.assertEqual(parsed['real_role_signature_count'],24)
        self.assertTrue(all(parsed[k] is False for k in r.NEGATIVES))

    def test_n_unified_route_never_exposes_candidate_private_signers(self):
        args=self.options()
        cmd=[sys.executable,'-I','-B',str(ROOT/'scripts/ces_next.py'),
            'audit-issuer-root-lineage','DeliveryAudit',
            'create-roster']
        for k in op.VERIFY_KEYS:
            cmd.extend(['--'+k.replace('_','-'),str(args[k])])
        run=subprocess.run(cmd,cwd=ROOT,stdin=subprocess.DEVNULL,
            capture_output=True,text=True,timeout=20)
        self.assertNotEqual(run.returncode,2)
        self.assertIn('EC341_',run.stdout)

    def test_o_observer_signature_corruption_reanchored_still_refused(self):
        broken=copy.deepcopy(self.base)
        signed=json.loads(Path(self.h3['root_observation_file']).read_text())
        signed['signature_ed25519']='01'*64
        path=self.tmp/'spoofed-witness.json';sha=canonical(path,signed)
        broken['hops'][1]['root_observation_file']=str(path)
        broken['hops'][1]['expected_root_observation_sha256']=sha
        with self.assertRaises(anchor.AnchorError):r.verify_lineage(**self.options(broken))

    def test_p_duplicate_witness_across_nonadjacent_epochs_denied(self):
        # Even if a new signed observation were recreated, the repeated
        # witness public key/org/id is a forbidden cross-epoch identity.
        seen=r._identities(json.loads(Path(self.policy['authority_roster_file']).read_text()),
             json.loads(Path(self.policy['policy_file']).read_text()))
        witness=json.loads(Path(self.h3['observer_roster_file']).read_text())
        r._extend(seen,json.loads(Path(self.h3['successor_roster_file']).read_text()),witness)
        with self.assertRaises(anchor.AnchorError):
            r._check_witness(self.h3['observer_roster_file'],
              self.h3['expected_observer_roster_sha256'],
              json.loads(Path(self.policy['policy_file']).read_text()),
              self.policy['expected_policy_sha256'],
              json.loads(Path(self.first['successor_roster_file']).read_text()),
              json.loads(Path(self.h3['successor_roster_file']).read_text()),seen)

    def test_q_seven_real_hops_to_epoch8_maximum(self):
        # Never rely on a dummy success: generate four further real 8-way
        # Ed25519 ceremonies and inspect the entire six-generation future.
        parent=self.h4;keys=self.k4paths
        extensions=[]
        for epoch,effective,observed,evaluation,expiry in (
           (5,'12:45:00','12:46:00','12:48:00','12:53:00'),
           (6,'12:54:00','12:55:00','12:57:00','13:04:00'),
           (7,'13:05:00','13:06:00','13:08:00','13:13:00'),
           (8,'13:15:00','13:16:00','13:18:00','13:25:00')):
            stamp=lambda h: '2026-10-25T'+h+'Z'
            _,keys,child=self.make_epoch(
                parent=parent,old_keys=keys,number=epoch,
                time=stamp(effective),observed=stamp(observed),
                evaluation=stamp(evaluation),expires=stamp(expiry),
                challenge=f'{epoch+42:02x}'*32)
            extensions.append(child);parent=child
        doc=copy.deepcopy(self.base)
        doc['hops']+=extensions
        result=r.verify_lineage(**self.options(doc,minimum_acceptable_epoch=8))
        self.assertEqual(result['externally_pinned_current_root_epoch'],8)
        self.assertEqual(result['real_role_signature_count'],56)
        self.assertEqual(result['real_observer_signature_count'],7)
        self.assertEqual(len(result['verified_lineage']),7)

    def test_r_actual_epoch1_competing_ec340_successor_eight_signatures(self):
        # The first historic hop can be a signed fork as well, not just
        # the EC341 >=3 rotations. This does not choose a legal winner.
        name='ec341-alternative-epoch2'
        keys=[Ed25519PrivateKey.generate() for _ in one.ROLES]
        paths=[];issuers=[]
        for key,role in zip(keys,one.ROLES,strict=True):
            priv=self.w/f'{name}-{role}.key';old_tests.private(priv,key)
            paths.append(str(priv))
            issuers.append({'role':role,'issuer_id':f'other_root_{role}',
                'issuer_public_hex':old_tests.pub(key),
                'subject_organization_id':f'org_{role}'})
        config=self.w/f'{name}-config.json';pin=canonical(config,{'issuers':issuers})
        altroot=str(self.w/f'{name}-roster.json')
        one.create_successor_roster(out=altroot,**self.policy,
            issuer_config_file=str(config),expected_issuer_config_sha256=pin,
            rotation_id='rotation_alt_epoch2',rotation_nonce_sha256='ca'*32,
            effective_utc='2026-10-25T11:01:00Z')
        altsha=file_sha(altroot)
        edges={};edgepins={}
        for side,role in one.EDGE_KEYS:
            i=one.ROLES.index(role)
            path=str(self.w/f'{name}-{side}-{role}.json')
            one.sign_edge(out=path,private_key_file=(
                self.old.parent.issuer_key_files[i] if side=='old' else paths[i]),
                side=side,role=role,**self.policy,
                successor_roster_file=altroot,
                expected_successor_roster_sha256=altsha)
            edges[(side,role)]=path;edgepins[(side,role)]=file_sha(path)
        witness=Ed25519PrivateKey.generate()
        keyfile=self.w/f'{name}-observer.key';old_tests.private(keyfile,witness)
        obs=self.w/f'{name}-observer.json'
        obs_pin=canonical(obs,{'schema':one.OBSERVER_ROOT_SCHEMA,
            'transfer_id':'ec339_transfer_001',
            'policy_original_raw_sha256':self.policy['expected_policy_sha256'],
            'observer_id':'obs_alt_epoch2',
            'observer_organization_id':'org_obs_alt_epoch2',
            'observer_public_hex':old_tests.pub(witness),
            'independent_out_of_band_approval_required':True})
        observed=str(self.w/f'{name}-signed-observation.json')
        one.issue_observation(out=observed,private_key_file=str(keyfile),
            **self.policy,successor_roster_file=altroot,
            expected_successor_roster_sha256=altsha,
            observer_roster_file=str(obs),
            expected_observer_roster_sha256=obs_pin,
            edge_files=edges,edge_shas=edgepins,
            verifier_challenge_sha256='cb'*32,
            observed_utc='2026-10-25T11:25:00Z',
            expires_utc='2026-10-25T11:55:00Z')
        hop={'epoch':2,'successor_roster_file':altroot,
            'expected_successor_roster_sha256':altsha,
            'observer_roster_file':str(obs),
            'expected_observer_roster_sha256':obs_pin,
            'root_observation_file':observed,
            'expected_root_observation_sha256':file_sha(observed),
            'edge_signatures':[{'side':side,'role':role,
                'file':edges[(side,role)],'sha256':edgepins[(side,role)]}
                for side,role in one.EDGE_KEYS],
            'evaluation_utc':'2026-10-25T11:42:00Z',
            'verifier_challenge_sha256':'cb'*32}
        manifest=copy.deepcopy(self.base)
        manifest['forks']=[{'parent_epoch':1,'hop':hop}]
        result=r.verify_lineage(**self.options(manifest))
        self.assertEqual(result['status'],'conflict_unresolved')
        self.assertEqual(result['fork_conflicts'][0]['parent_epoch'],1)
        self.assertEqual(result['real_role_signature_count'],32)

    def test_k_inherited_old_one_hop_signature_domains_not_changed(self):
        self.assertEqual(one.ROOT_SCHEMA,'ces.ec340.issuer_successor_epoch_roster.v1')
        self.assertNotEqual(r.EDGE_SCHEMA,one.EDGE_SCHEMA)
        self.assertNotEqual(r._domain('old','sender'),one._domain('old','sender'))

    def test_l_truncated_or_extra_manifest_fields_denied(self):
        doc=copy.deepcopy(self.base);doc['unknown']=True
        with self.assertRaises(anchor.AnchorError):r.verify_lineage(**self.options(doc))
        doc=copy.deepcopy(self.base);doc['hops']=[self.first]*8
        with self.assertRaises(anchor.AnchorError):r.verify_lineage(**self.options(doc))

if __name__=='__main__':
    unittest.main()
