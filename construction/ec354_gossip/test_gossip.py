#!/usr/bin/env python3
"""EC354 local *synthetic* genuine Ed25519 gossip against genuine EC353 replay."""
from __future__ import annotations

from datetime import timedelta
import json
from pathlib import Path
import subprocess
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519
from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec353_transparency import test_transparency as fx
from . import gossip as core

ROOT=Path(__file__).resolve().parents[2]


class GossipTests(fx.TransparencyTests):
    # Inherit full genuine RSA DER/OCSP/CRL fixture, not old test cases.
    for _name in dir(fx.TransparencyTests):
        if _name.startswith('test_'):locals()[_name]=None

    def setUp(self):
        super().setUp()
        self.actors={};self.exchanges=[];self.sequence=0

    def start(self,two_channels=True):
        self.baseline(two_channels=two_channels)
        self.make_log('log_a');self.make_log('log_b',reverse=True)
        self.parentvals=self.values()
        self.make_actor('auditor_a');self.make_actor('auditor_b')

    def make_actor(self,id='auditor_a',organization=None,key=None):
        key=key or ed25519.Ed25519PrivateKey.generate()
        kp=self.write353(id+'-gossip-key.bin',fx.pub(key))
        body={'schema':core.AUDITOR_SCHEMA,'auditor_id':id,
              'auditor_public_key_original_sha256':kp['sha256'],
              'claimed_auditor_organization':organization or f'SYNTHETIC {id} observer',
              'claimed_auditor_directory_uri':'https://invalid.example.test/auditors',
              'valid_from_utc':fx.ut(self.now-timedelta(days=2)),
              'valid_until_utc':fx.ut(self.now+timedelta(days=20))}
        ref=self.signed(id+'-gossip-ref',body,key,core.AUDITOR_DOMAIN)
        self.actors[id]={'private':key,'public':kp,'reference':ref,
                         'manifest':{'auditor_id':id,'auditor_reference':ref,
                                     'auditor_public_key':kp}}
        return self.actors[id]

    def gossip_challenge(self,log_id='log_a',challenger='auditor_a',responder='auditor_b',
                  previous=core.GENESIS,checkpoint=None,nonce=None,do_reply=True):
        self.sequence+=1
        cp=checkpoint or self.logs[log_id]['headers'][0]
        origin=self.actors[challenger];target=self.actors[responder]
        body={'schema':core.CHALLENGE_SCHEMA,
              'challenge_id':f'gossip_{self.sequence}',
              'challenger_auditor_id':challenger,'responder_auditor_id':responder,
              'challenger_reference_original_sha256':origin['reference']['sha256'],
              'responder_reference_original_sha256':target['reference']['sha256'],
              'parent_publication_bundle_original_sha256':self.parentvals['expected_publication_bundle_sha256'],
              'log_id':log_id,
              'log_reference_original_sha256':self.logs[log_id]['log_ref']['sha256'],
              'checkpoint_original_sha256':cp['file']['sha256'],
              'tree_size':cp['body']['tree_size'],
              'root_hash_sha256':cp['body']['root_hash_sha256'],
              'previous_challenge_original_sha256':previous,
              'nonce_hex':nonce or f'{self.sequence:032x}',
              'issued_utc':fx.ut(self.now+timedelta(minutes=8)),}
        pin=self.signed('challenge',body,origin['private'],core.CHALLENGE_DOMAIN)
        item={'challenge':pin,'replies':[]}
        self.exchanges.append(item)
        if do_reply:self.gossip_reply(item,log_id,responder,checkpoint=cp)
        return item

    def gossip_reply(self,item,log_id='log_a',responder='auditor_b',*,checkpoint=None,
              kind='checkpoint_view',unknown=False,root_override=None):
        cp=checkpoint or self.logs[log_id]['headers'][0]
        actor=self.actors[responder]
        rawsha=('a'*64 if unknown else cp['file']['sha256'])
        body={'schema':core.REPLY_SCHEMA,
              'challenge_original_sha256':item['challenge']['sha256'],
              'responder_auditor_id':responder,
              'responder_reference_original_sha256':actor['reference']['sha256'],
              'log_id':log_id,'response_kind':kind,
              'checkpoint_original_sha256':rawsha if kind=='checkpoint_view' else None,
              'tree_size':cp['body']['tree_size'] if kind=='checkpoint_view' else None,
              'root_hash_sha256':(root_override or cp['body']['root_hash_sha256'])
                    if kind=='checkpoint_view' else None,
              'responded_utc':fx.ut(self.now+timedelta(minutes=9))}
        pin=self.signed('reply',body,actor['private'],core.REPLY_DOMAIN)
        item['replies'].append(pin)
        return pin

    def full_views(self):
        self.gossip_challenge('log_a','auditor_a','auditor_b')
        self.gossip_challenge('log_b','auditor_b','auditor_a')

    def args354(self,**changes):
        auditor_items=[self.actors[k]['manifest'] for k in sorted(self.actors)]
        b=self.write353('gossip-bundle.json',{
            'schema':core.BUNDLE_SCHEMA,'auditors':auditor_items,'exchanges':self.exchanges})
        return {**self.parentvals,'gossip_evaluation_utc':fx.ut(self.now+timedelta(hours=1)),
                'gossip_bundle_file':b['path'],
                'expected_gossip_bundle_sha256':b['sha256'],**changes}

    def result(self,**changes):return core.audit(**self.args354(**changes))

    def deny(self,code,**changes):
        with self.assertRaises(errors.AnchorError) as caught:
            self.result(**changes)
        self.assertIn(code,caught.exception.code)

    def test_01_full_signed_two_log_views_remain_unresolved(self):
        self.start();self.full_views();res=self.result()
        self.assertEqual([r['outcome'] for r in res['channel_evidence']],
                         [core.OUTCOMES[-1],core.OUTCOMES[-1]])
        self.assertEqual(res['signed_challenge_count'],2)
        self.assertEqual(res['signed_reply_count'],2)
        self.assertEqual(res['covered_log_ids_with_two_signed_actors'],['log_a','log_b'])
        self.assertTrue(res['actual_ec353_through_ec337_original_signatures_replayed'])
        self.assertEqual(res['exit_code'],2)
        self.assertTrue(res['real_auditor_identity_physical_independence_utc_and_global_heads_unproven'])
        self.assertFalse(res['signed_gossip_proves_global_log_head_or_hidden_fork_absence'])

    def test_02_empty_auditors_and_challenges_is_not_a_pass(self):
        self.start();self.actors={}
        r=self.result();self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[1])

    def test_03_only_one_auditor_not_enough(self):
        self.start();self.actors.pop('auditor_b')
        self.assertEqual(self.result()['channel_evidence'][0]['outcome'],core.OUTCOMES[1])

    def test_04_one_log_challenge_missing(self):
        self.start();self.gossip_challenge()
        self.assertEqual(self.result()['channel_evidence'][0]['outcome'],core.OUTCOMES[2])

    def test_05_no_reply_is_visible(self):
        self.start();self.gossip_challenge(do_reply=False)
        self.gossip_challenge('log_b','auditor_b','auditor_a')
        r=self.result()
        self.assertEqual(r['gossip_exchanges'][0]['replies'],[])
        self.assertTrue(r['missing_unavailable_or_unfurnished_replies_visible'])

    def test_06_signed_unavailable_and_unfurnished_not_verified(self):
        self.start();a=self.gossip_challenge(do_reply=False)
        self.gossip_reply(a,kind='unavailable_claim')
        b=self.gossip_challenge('log_b','auditor_b','auditor_a',do_reply=False)
        self.gossip_reply(b,log_id='log_b',responder='auditor_a',unknown=True)
        r=self.result()
        self.assertEqual(r['gossip_exchanges'][0]['replies'][0]['view_state'],'signed_unavailable_claim')
        self.assertEqual(r['gossip_exchanges'][1]['replies'][0]['view_state'],
                         'signed_unfurnished_checkpoint_claim')
        self.assertTrue(r['missing_unavailable_or_unfurnished_replies_visible'])
        self.assertEqual(r['covered_log_ids_with_two_signed_actors'],[])

    def test_07_forged_challenge_signature_denied(self):
        self.start();self.full_views()
        p=self.exchanges[0]['challenge'];doc=json.loads(Path(p['path']).read_text())
        doc['signature_ed25519_hex']='a'*128
        replacement=self.write353('forged-challenge',doc)
        self.exchanges[0]['challenge']=replacement
        self.deny('CHALLENGE_SIGNATURE_INVALID')

    def test_08_forged_reply_signature_denied(self):
        self.start();self.full_views()
        p=self.exchanges[0]['replies'][0];doc=json.loads(Path(p['path']).read_text())
        doc['signature_ed25519_hex']='0'*128
        self.exchanges[0]['replies'][0]=self.write353('forged-reply',doc)
        self.deny('REPLY_SIGNATURE_INVALID')

    def test_09_wrong_checkpoint_parent_binding_denied(self):
        self.start();self.full_views()
        p=self.exchanges[0]['challenge'];d=json.loads(Path(p['path']).read_bytes())
        d['checkpoint_original_sha256']='b'*64
        self.exchanges[0]['challenge']=self.signed('wrong-cp',
            {k:v for k,v in d.items() if k!='signature_ed25519_hex'},
            self.actors['auditor_a']['private'],core.CHALLENGE_DOMAIN)
        self.deny('CHALLENGE_MUST_BIND_WITNESSED')

    def test_10_wrong_signature_actor_denied(self):
        self.start();self.full_views()
        p=self.exchanges[0]['replies'][0];d=json.loads(Path(p['path']).read_bytes())
        d['responder_auditor_id']='auditor_a'
        self.exchanges[0]['replies'][0]=self.signed('wrong-actor',
            {k:v for k,v in d.items() if k!='signature_ed25519_hex'},
            self.actors['auditor_a']['private'],core.REPLY_DOMAIN)
        self.deny('REPLY_CHALLENGE_OR_ACTOR_BINDING_INVALID')

    def test_11_key_reuse_with_log_role_forbidden(self):
        self.start();self.full_views()
        log=self.logs['log_a']
        self.make_actor('auditor_a',key=log['private'])
        self.deny('AUDITOR_KEY_ROLE_REUSE')

    def test_12_unique_nonce_across_challengers_enforced(self):
        self.start();self.gossip_challenge(nonce='1'*32)
        self.gossip_challenge('log_b','auditor_b','auditor_a',nonce='1'*32)
        self.deny('CHALLENGE_ID_OR_NONCE_REPLAY')

    def test_13_fabricated_predecessor_denied(self):
        self.start();self.gossip_challenge(previous='f'*64)
        self.deny('CHALLENGE_PREDECESSOR_SHA_PAIR_OR_TIME_INVALID')

    def test_14_chain_with_valid_sha_and_two_replies_is_auditable(self):
        self.start();self.full_views()
        first=self.exchanges[0]['challenge']['sha256']
        self.gossip_challenge(previous=first)
        r=self.result()
        self.assertEqual(r['signed_challenge_count'],3)
        self.assertFalse(r['signed_challenge_fork_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[-1])

    def test_15_same_parent_signed_challenge_forks_retained(self):
        self.start();self.full_views()
        root=self.exchanges[0]['challenge']['sha256']
        self.gossip_challenge(previous=root)
        self.gossip_challenge(previous=root)
        r=self.result()
        self.assertTrue(r['signed_challenge_fork_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[3])

    def test_16_two_signed_incompatible_responses_are_not_winner_elected(self):
        self.start();self.full_views()
        self.gossip_reply(self.exchanges[0],unknown=True)
        r=self.result()
        self.assertTrue(r['signed_responder_equivocation_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[3])
        self.assertEqual(len(r['gossip_exchanges'][0]['replies']),2)

    def test_17_same_checkpoint_wrong_root_from_reply_denied(self):
        self.start();a=self.gossip_challenge(do_reply=False)
        self.gossip_reply(a,root_override='2'*64)
        self.deny('REPLY_FURNISHED_CHECKPOINT_METADATA_MISMATCH')

    def test_18_claimed_auditor_name_cannot_certify_independence(self):
        self.start()
        self.make_actor('auditor_b',organization='SYNTHETIC auditor_a observer')
        self.full_views()
        r=self.result()
        self.assertFalse(r['claimed_auditor_organization_names_distinct'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[6])

    def test_19_gossip_does_not_repair_parent_incomplete_merkle_coverage(self):
        self.start();self.full_views()
        self.logs['log_b']['bundle']['inclusions'].pop()
        self.parentvals=self.values()
        # Signed challenges still bind old bundle SHA; re-sign with updated binding
        # would not cure the parent result either. Show parent condition separately.
        self.exchanges=[]
        r=self.result()
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[0])

    def test_20_bundle_path_alias_with_parent_denied(self):
        self.start();self.full_views()
        self.deny('GOSSIP_BUNDLE_PATH_ALIASES_ANCESTOR',
                  gossip_bundle_file=self.parentvals['publication_bundle_file'],
                  expected_gossip_bundle_sha256=self.parentvals['expected_publication_bundle_sha256'])

    def test_21_noncanonical_signed_json_denied(self):
        self.start();self.full_views()
        p=self.exchanges[0]['challenge'];raw=Path(p['path']).read_bytes()+b'\n'
        self.exchanges[0]['challenge']=self.write353('noncanonical',raw)
        self.deny('CANONICAL_JSON_REQUIRED')

    def test_22_derive_handoff_real_checkpoint_inventory(self):
        self.start();h=core.checklist(**self.parentvals)
        self.assertEqual(h['exit_code'],2)
        self.assertEqual(len(h['verified_witnessed_checkpoint_inventory']),2)
        self.assertTrue(h['actual_ec353_through_ec337_original_signatures_replayed'])

    def test_23_standalone_executable_and_unified_readonly(self):
        self.start();self.full_views();args=self.args354()
        from scripts import ces_next
        parts=[]
        for k in ces_next.EC354_KEYS:parts.extend(['--'+k.replace('_','-'),str(args[k])])
        for k,flag in ces_next.EC354_REPEATS:
            for value in args[k]:parts.extend([flag,str(value)])
        script=ROOT/'scripts'/'ces_cas_cross_log_gossip.py'
        run=subprocess.run([sys.executable,'-I','-B',str(script),'audit-cross-log-gossip',*parts],
                           capture_output=True,text=True,timeout=180)
        self.assertEqual(run.returncode,2,run.stdout+run.stderr)
        self.assertEqual(json.loads(run.stdout)['schema'],core.RESULT_SCHEMA)
        router=ROOT/'scripts'/'ces_next.py'
        r=subprocess.run([sys.executable,'-B',str(router),'audit-cross-log-gossip',
                          'DeliveryAudit','AuditSignedCrossLogGossip',*parts],
                         capture_output=True,text=True,timeout=180)
        self.assertEqual(r.returncode,2,r.stdout+r.stderr)
        self.assertEqual(json.loads(r.stdout)['schema'],core.RESULT_SCHEMA)
        blocked=subprocess.run([sys.executable,'-B',str(router),'audit-cross-log-gossip',
                                'DangerousAction','SignGossip',*parts],
                               capture_output=True,text=True,timeout=180)
        self.assertNotEqual(blocked.returncode,2)
        self.assertNotEqual(json.loads(blocked.stdout).get('schema'),core.RESULT_SCHEMA)

    def test_24_independent_signed_same_size_different_roots_compared_without_head_election(self):
        self.start()
        # Genuine log + independent witness sign a competing GENESIS original;
        # the EC353 parent itself must remain unresolved about this split.
        altered=self.logs['log_a']['leaves'][:-1]+[b'conflicting-original']
        fork=self.add_checkpoint('log_a',previous=None,leaves=altered)
        self.parentvals=self.values()
        self.gossip_challenge('log_a','auditor_a','auditor_b')
        self.gossip_challenge('log_a','auditor_b','auditor_a',checkpoint=fork)
        self.gossip_challenge('log_b','auditor_a','auditor_b')
        r=self.result()
        comparisons=[c for c in r['same_log_same_size_verified_root_comparisons']
                     if c['log_id']=='log_a']
        self.assertTrue(r['verified_same_log_branch_conflict_visible'])
        self.assertEqual(comparisons[0]['comparison'],'conflicting_verified_roots')
        self.assertEqual(len(comparisons[0]['verified_root_hashes_sha256']),2)
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[0])

    def test_25_real_append_only_different_size_is_not_a_same_size_conflict(self):
        self.start()
        later=self.add_checkpoint('log_a',leaves=self.logs['log_a']['leaves']+[b'late-original'])
        self.parentvals=self.values()
        item=self.gossip_challenge('log_a','auditor_a','auditor_b',do_reply=False)
        self.gossip_reply(item,'log_a','auditor_b',checkpoint=later)
        self.gossip_challenge('log_b','auditor_b','auditor_a')
        r=self.result()
        self.assertEqual(r['gossip_exchanges'][0]['replies'][0]['relationship'],
                         'verified_signed_ancestor_descendant_view')
        self.assertFalse(r['verified_same_log_branch_conflict_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[-1])

    def test_26_duplicate_signed_reply_path_not_reinterpreted_as_two_originals(self):
        self.start()
        item=self.gossip_challenge()
        item['replies'].append(item['replies'][0])
        self.deny('DUPLICATE_GOSSIP_ORIGINAL_PATH')



if __name__=='__main__':unittest.main()
