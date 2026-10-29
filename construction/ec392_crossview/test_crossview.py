#!/usr/bin/env python3
"""EC392 focused real Ed25519/CMS fixtures; inherited EC390->EC369 parent MOCKED.

Keys, local TSA certificates and tokens are newly generated for test purposes;
they are not evidence of true independent operators, trusted time or retention.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec389_external_revocation.test_witness_custody import ref
from ec391_prior_time import prior_time as previous
from ec391_prior_time.test_prior_time import PriorTimeTests as Inherited
from . import crossview as core


class CrossviewTests(Inherited):
    def setUp(self):
        super().setUp()
        self.cid=self.channel['tsa_channel_id']
        self.view={'id':'ObserverNorth','keys':self.roster_keys,'authorities':{}}
        self.own={'head_sha':self.current_entry['signed_prior_offsite_head_original']['sha256'],
          'pairs':copy.deepcopy(self.signed_source),
          'source_sha':core.sha(canonical.canonical(self.signed_source)),
          'signer':'PriorKeeper1','tsa_gen':None,'token_sha':None}
        self.peer={'head_sha':'81'*32,'pairs':copy.deepcopy(self.signed_source),
          'source_sha':self.own['source_sha'],'tsa_gen':None,'token_sha':None}
        self.claim={'schema':core.CLAIM_SCHEMA,
          'directory_lineage_id':'Lineage388',
          'observer_id':'ObserverNorth','peer_observer_id':'ObserverSouth',
          'tsa_channel_id':self.cid,'epoch_index':0,'checkpoint_sequence':1,
          'offsite_keeper_id':'PriorKeeper1',
          'own_prior_signed_head_original_sha256':self.own['head_sha'],
          'observed_peer_prior_signed_head_original_sha256':self.peer['head_sha'],
          'own_signed_source_snapshot_sha256':self.own['source_sha'],
          'previous_signed_crossview_checkpoint_original_sha256':core.ZERO,
          'claimed_observed_utc':'2026-10-25T11:40:00Z'}
        self.entry_cp=self.sign_checkpoint()

    def sign_checkpoint(self,claim=None,*,tag=None,key=None):
        claim=copy.deepcopy(self.claim if claim is None else claim)
        signed={'schema':core.CHECKPOINT_SCHEMA,'claim':claim,
          'signature_ed25519':(key or self.keeper_priv).sign(
                core.DOMAIN+canonical.canonical(claim)).hex()}
        return self._archive('ec392-checkpoint-'+(tag or self._testMethodName)+'.json',signed)

    def check_cp(self,href=None,*,token=None,aid=None,alt=None,previous_checkpoint=None,
                 own=None,peer=None,observer=None):
        flags={k:False for k in core.FLAGS}
        result,prev=core._verify_checkpoint(href if href is not None else self.entry_cp,
           'ObserverNorth',observer or 'ObserverSouth',self.view,own or self.own,
           peer or self.peer,self.cid,0,previous_checkpoint,self.read,'Lineage388',
           datetime.now(timezone.utc)+timedelta(minutes=3),token,aid,alt,flags)
        return result,prev,flags

    def deny_cp(self,**kwargs):
        with self.assertRaises(errors.AnchorError):self.check_cp(**kwargs)

    def test_ec392_01_domain_separated_signed_crossview_checkpoint(self):
        state,prev,flags=self.check_cp()
        self.assertEqual(state['checkpoint_sha256'],self.entry_cp['sha256'])
        self.assertTrue(state['claims_match_reopened_heads'])
        self.assertFalse(flags[core.FLAGS[5]])
        self.assertTrue(flags[core.FLAGS[2]])  # Real timestamp absent.
        self.assertEqual(prev['sha'],self.entry_cp['sha256'])

    def test_ec392_02_wrong_ed25519_signing_key_rejected(self):
        self.deny_cp(href=self.sign_checkpoint(key=Ed25519PrivateKey.generate(),
                      tag='invalid-signature'))

    def test_ec392_03_unrecognized_peer_observer_rejected(self):
        self.deny_cp(observer='OtherFakeObserver')

    def test_ec392_04_valid_but_wrong_peer_sha_is_adverse_not_erased(self):
        claim=copy.deepcopy(self.claim)
        claim['observed_peer_prior_signed_head_original_sha256']='bb'*32
        s,_,f=self.check_cp(href=self.sign_checkpoint(claim,tag='wrong-peer'))
        self.assertFalse(s['claims_match_reopened_heads'])
        self.assertTrue(f[core.FLAGS[5]])

    def test_ec392_05_wrong_own_signed_source_sha_is_adverse(self):
        claim=copy.deepcopy(self.claim);claim['own_signed_source_snapshot_sha256']='a7'*32
        self.assertTrue(self.check_cp(href=self.sign_checkpoint(claim,tag='wrong-pairs'))[2][core.FLAGS[5]])

    def test_ec392_06_signed_wrong_predecessor_reported_without_winner(self):
        claim=copy.deepcopy(self.claim)
        claim['previous_signed_crossview_checkpoint_original_sha256']='9d'*32
        self.assertTrue(self.check_cp(href=self.sign_checkpoint(claim,tag='bad-prev'))[2][core.FLAGS[7]])

    def test_ec392_07_signed_self_equivocation_keeps_both_sha_originals(self):
        claim=copy.deepcopy(self.claim);claim['observed_peer_prior_signed_head_original_sha256']='bb'*32
        alt=self.sign_checkpoint(claim,tag='same-keeper-equivocation')
        state,_,flags=self.check_cp(alt=alt)
        self.assertEqual(state['alternate_sha256'],alt['sha256'])
        self.assertTrue(flags[core.FLAGS[6]])
        self.assertNotEqual(state['checkpoint_sha256'],state['alternate_sha256'])

    def test_ec392_08_invalid_alternate_signature_denied(self):
        claim=copy.deepcopy(self.claim);claim['observed_peer_prior_signed_head_original_sha256']='bb'*32
        self.deny_cp(alt=self.sign_checkpoint(claim,tag='forged-alt',
                                               key=Ed25519PrivateKey.generate()))

    def test_ec392_09_duplicate_signed_alternate_denied(self):
        self.deny_cp(alt=self.entry_cp)

    def test_ec392_10_orphan_timestamp_without_checkpoint_denied(self):
        flags={k:False for k in core.FLAGS}
        with self.assertRaises(errors.AnchorError):core._verify_checkpoint(
          None,'ObserverNorth','ObserverSouth',self.view,self.own,self.peer,self.cid,0,
          None,self.read,'Lineage388',datetime.now(timezone.utc),
          {'path':'/not-an-original','sha256':'a4'*32},'TSA1',None,flags)

    def test_ec392_11_missing_checkpoint_preserved_as_not_proven(self):
        flags={k:False for k in core.FLAGS}
        state,previous=core._verify_checkpoint(None,'ObserverNorth','ObserverSouth',
          self.view,self.own,self.peer,self.cid,0,None,self.read,'Lineage388',
          datetime.now(timezone.utc),None,None,None,flags)
        self.assertIsNone(state['checkpoint_sha256'])
        self.assertIsNone(previous)
        self.assertFalse(state['timestamp_authenticated'])

    def test_ec392_12_timestamp_requires_real_registered_tsa(self):
        self.deny_cp(token={'path':'/fake','sha256':'a4'*32},aid='NotRegistered')

    def test_ec392_13_real_cms_checkpoint_original_imprint_and_crl(self):
        if not hasattr(self,'real_token'):self.skipTest('fixture not available')
        # Reuses EC391 local OpenSSL token generator on *checkpoint original*.
        mock_entry={'signed_prior_offsite_head_original':self.entry_cp}
        entry,_,_=self.real_token(entry=mock_entry)
        self.view['authorities']=self.authorities
        out,_,flags=self.check_cp(token=entry['rfc3161_timestamp_original'],
                                  aid='PriorTSA1')
        self.assertTrue(out['timestamp_authenticated'])
        self.assertTrue(out['bounded_crl_current'])
        self.assertEqual(out['token_sha256'],entry['rfc3161_timestamp_original']['sha256'])
        self.assertFalse(flags[core.FLAGS[8]])

    def test_ec392_14_real_cms_imprint_of_different_bytes_rejected(self):
        entry,_,_=self.real_token(entry={'signed_prior_offsite_head_original':self.entry_cp},
                                    wrong_source=True)
        self.view['authorities']=self.authorities
        self.deny_cp(token=entry['rfc3161_timestamp_original'],aid='PriorTSA1')

    def test_ec392_15_missing_crl_is_adverse_not_an_accepted_tsa(self):
        entry,_,_=self.real_token(entry={'signed_prior_offsite_head_original':self.entry_cp},
                                    with_crl=False)
        self.view['authorities']=self.authorities
        out,_,flags=self.check_cp(token=entry['rfc3161_timestamp_original'],aid='PriorTSA1')
        self.assertTrue(out['timestamp_authenticated'])
        self.assertFalse(out['bounded_crl_current'])
        self.assertTrue(flags[core.FLAGS[8]])

    def test_ec392_16_crossview_timestamp_claim_order_adverse(self):
        claim=copy.deepcopy(self.claim);claim['claimed_observed_utc']='2028-01-01T00:00:00Z'
        checkpoint=self.sign_checkpoint(claim,tag='future-signed-claim')
        entry,_,_=self.real_token(entry={'signed_prior_offsite_head_original':checkpoint})
        self.view['authorities']=self.authorities
        self.assertTrue(self.check_cp(href=checkpoint,
          token=entry['rfc3161_timestamp_original'],aid='PriorTSA1')[2][core.FLAGS[8]])

    def test_ec392_17_parent_result_cannot_be_a_caller_claim_of_pass(self):
        with self.assertRaises(errors.AnchorError):core._parent_report(
            {'schema':previous.RESULT_SCHEMA,'exit_code':0},
            {'historical_directory_root_shas':['bb'*32]},'ab'*32)

    def test_ec392_18_outside_observer_ids_cannot_repeat(self):
        with patch.object(core.parent,'_inputs',return_value=(None,None)),\
             patch.object(core.io.authority,'outer_pin'):
            opts={key:('ab'*32 if key.endswith('_sha256') else '/tmp/x') for key
                  in (*core.PARENT_SCALARS,*core.NEW_SCALARS)}
            opts['historical_directory_root_shas']=['ab'*32]
            opts['expected_outside_retained_ec392_primary_observer_id']='Same'
            opts['expected_outside_retained_ec392_secondary_observer_id']='Same'
            for key in core.PARENT_REPEATS:opts[key]=[]
            for key in core.REPEAT_NAMES:
                opts[key]=[0] if key.startswith('minimum_') else ['ab'*32]
            with self.assertRaises(errors.AnchorError):core._inputs(opts,True)

    def test_ec392_19_parent_secondary_swaps_only_separately_pinned_view(self):
        primary={key:'parent-'+key for key in (*previous.PARENT_SCALARS,
                    *previous.NEW_SCALARS,*previous.AUDIT_ONLY,
                    *previous.PARENT_REPEATS,*previous.REPEAT_NAMES)}
        add={key:'new-'+key for key in core.NEW_SCALARS}
        add.update({key:['sha-new'] for key in core.REPEAT_NAMES})
        new=core._secondary_opts(primary,add)
        for key in previous.PARENT_SCALARS: self.assertEqual(new[key],primary[key])
        self.assertEqual(new[previous.NEW_SCALARS[0]],add[core.NEW_SCALARS[2]])
        self.assertEqual(new[previous.AUDIT_ONLY[0]],add[core.NEW_SCALARS[6]])
        self.assertEqual(primary[previous.NEW_SCALARS[0]],'parent-'+previous.NEW_SCALARS[0])

    def test_ec392_20_two_observer_independence_denies_reused_keys(self):
        one={'id':'One','ref':{'path':'/a','sha256':'a1'*32},'keys':{'K':'f1'*32},
             'authorities':{'a':{'root_sha':'dd'*32}},
             'bundle':{'offsite_log_keeper_roster_original':{'path':'/ra'},
                        'tsa_trust_registry_original':{'path':'/ta'},'epochs':[]},
             'roster':{'log_keepers':[]},'trust':{'authorities':[]}}
        two=copy.deepcopy(one);two['id']='Two';two['ref']={'path':'/b','sha256':'b1'*32}
        two['bundle']['offsite_log_keeper_roster_original']={'path':'/rb'}
        two['bundle']['tsa_trust_registry_original']={'path':'/tb'}
        with self.assertRaises(errors.AnchorError):core._disjoint(one,two,{'path':'/cross'},set(),{'epochs':[]})

    def test_ec392_21_read_only_unified_and_standalone_help(self):
        root=Path(__file__).resolve().parents[2]
        for name in ('ces_cas_historical_ec339_crossview.py','ces_next.py'):
            cmd=['audit-historical-ec339-crossview']
            result=subprocess.run([sys.executable,'-I','-B',str(root/'scripts'/name),
                                   *cmd,'--help'],capture_output=True,text=True,timeout=35)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('--historical-ec339-crossview-rfc3161-token-inventory-sha256',result.stdout)
            self.assertNotIn('--private-key',result.stdout)

    @contextmanager
    def mocked_parent(self,real390):
        a,b,c=self._outer_context(real390)
        with a,b,c:yield

    def _outer_ec392(self,*,split_sources=False,timestamp_checkpoints=False):
        """Two *actual* EC391 audits over real original local cryptography;
        only outer EC390->EC369 chain is patched as in the inherited fixture.
        Crossview checkpoint signatures are genuine; token absence is explicit.
        """
        real390,primary_opts=self._outer_ec391()
        with self.mocked_parent(real390):
            pderived=previous.derive_inventory(**primary_opts)
        ep=pderived['historical_prior_offsite_time_epoch_reviews'][0]
        primary_opts[previous.NEW_REPEATS[0][0]]=[ep['prior_offsite_signed_head_inventory_sha256']]
        primary_opts[previous.NEW_REPEATS[1][0]]=[ep['prior_rfc3161_token_inventory_sha256']]
        primary_opts[previous.AUDIT_ONLY[0]]=pderived['receiver_verified_prior_offsite_time_inventory_sha256']
        skey=Ed25519PrivateKey.generate()
        pub=skey.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        path=self.root/('ec392-second-keeper-'+self._testMethodName+'.raw');path.write_bytes(pub)
        sroster={'schema':previous.ROSTER_SCHEMA,'claimed_directory_lineage_id':'Lineage388',
          'log_keepers':[{'signer_id':'SecondKeeper','public_hex':pub.hex(),
                          'public_key_original':ref(path)}]}
        srosterref=self._archive('ec392-second-roster-'+self._testMethodName+'.json',sroster)
        claim=copy.deepcopy(self.prior_claim);claim['offsite_keeper_id']='SecondKeeper'
        if split_sources:
            claim['ec389_signed_source_pairs'][0][
              'ec339_revoked_status_original_sha256']='ee'*32
        signed2=self.sign_prior(claim,priv=skey,name='ec392-second-head-'+self._testMethodName+'.json')
        entry2,strust,strustref=self.real_token(entry=signed2)
        original=json.loads(Path(primary_opts[previous.NEW_SCALARS[0]]).read_text())
        original['offsite_log_keeper_roster_original']=srosterref
        original['tsa_trust_registry_original']=strustref
        original['epochs'][0]['channels']=[entry2]
        secref=self._archive('ec392-second-ec391-bundle-'+self._testMethodName+'.json',original)
        secondary_opts=copy.deepcopy(primary_opts)
        secondary_opts[previous.NEW_SCALARS[0]]=secref['path']
        secondary_opts[previous.NEW_SCALARS[1]]=secref['sha256']
        secondary_opts[previous.NEW_SCALARS[2]]=srosterref['sha256']
        secondary_opts[previous.NEW_SCALARS[3]]=strustref['sha256']
        with self.mocked_parent(real390):
            sd=previous.derive_inventory(**secondary_opts)
        se=sd['historical_prior_offsite_time_epoch_reviews'][0]
        secondary_opts[previous.NEW_REPEATS[0][0]]=[se['prior_offsite_signed_head_inventory_sha256']]
        secondary_opts[previous.NEW_REPEATS[1][0]]=[se['prior_rfc3161_token_inventory_sha256']]
        secondary_opts[previous.AUDIT_ONLY[0]]=sd['receiver_verified_prior_offsite_time_inventory_sha256']
        cpclaim=copy.deepcopy(self.claim)
        cpclaim['observed_peer_prior_signed_head_original_sha256']=entry2['signed_prior_offsite_head_original']['sha256']
        cp1=self.sign_checkpoint(cpclaim,tag='primary-real-'+self._testMethodName)
        cpclaim['observer_id']='ObserverSouth';cpclaim['peer_observer_id']='ObserverNorth'
        cpclaim['offsite_keeper_id']='SecondKeeper'
        cpclaim['own_signed_source_snapshot_sha256']=core.sha(
            canonical.canonical(claim['ec389_signed_source_pairs']))
        cpclaim['own_prior_signed_head_original_sha256']=entry2['signed_prior_offsite_head_original']['sha256']
        cpclaim['observed_peer_prior_signed_head_original_sha256']=self.own['head_sha']
        cs={'schema':core.CHECKPOINT_SCHEMA,'claim':cpclaim,
            'signature_ed25519':skey.sign(core.DOMAIN+canonical.canonical(cpclaim)).hex()}
        cp2=self._archive('ec392-secondary-cp-'+self._testMethodName+'.json',cs)
        def cp_record(cp):return {'signed_crossview_checkpoint_original':cp,
          'rfc3161_crossview_checkpoint_token_original':None,
          'tsa_authority_id':None,
          'alternate_signed_crossview_checkpoint_original':None}
        primary_cp=cp_record(cp1)
        secondary_cp=cp_record(cp2)
        if timestamp_checkpoints:
            for record,cp,serial,role in (
               (primary_cp,cp1,1,'primary'),(secondary_cp,cp2,2,'secondary')):
                query=self.root/('ec392-'+role+'-'+self._testMethodName+'.tsq')
                token=self.root/('ec392-'+role+'-'+self._testMethodName+'.der')
                conf=self.root/('ec391-tsa-'+str(serial)+'.conf')
                for argv in (
                  ['openssl','ts','-query','-data',cp['path'],'-sha256','-cert',
                   '-out',str(query)],
                  ['openssl','ts','-reply','-queryfile',str(query),
                   '-config',str(conf),'-section','tsa_config','-token_out',
                   '-out',str(token)]):
                    result=subprocess.run(argv,capture_output=True,text=True,timeout=20)
                    if result.returncode:raise AssertionError(result.stderr)
                record['rfc3161_crossview_checkpoint_token_original']=ref(token)
                record['tsa_authority_id']='PriorTSA1'
        cross={'schema':core.BUNDLE_SCHEMA,'claimed_directory_lineage_id':'Lineage388',
          'primary_observer_id':'ObserverNorth','secondary_observer_id':'ObserverSouth',
          'primary_ec391_offsite_bundle_original':{
             'path':primary_opts[previous.NEW_SCALARS[0]],
             'sha256':primary_opts[previous.NEW_SCALARS[1]]},
          'secondary_ec391_offsite_bundle_original':secref,
          'epochs':[{'epoch_index':0,'channels':[{'tsa_channel_id':self.cid,
                     'primary':primary_cp,'secondary':secondary_cp}]}]}
        crossref=self._archive('ec392-crossview-'+self._testMethodName+'.json',cross)
        options=dict(primary_opts)
        options.update({core.NEW_SCALARS[0]:crossref['path'],
          core.NEW_SCALARS[1]:crossref['sha256'],
          core.NEW_SCALARS[2]:secref['path'],
          core.NEW_SCALARS[3]:secref['sha256'],
          core.NEW_SCALARS[4]:srosterref['sha256'],
          core.NEW_SCALARS[5]:strustref['sha256'],
          core.NEW_SCALARS[6]:secondary_opts[previous.AUDIT_ONLY[0]],
          core.NEW_SCALARS[7]:'ObserverNorth',core.NEW_SCALARS[8]:'ObserverSouth',
          core.NEW_REPEATS[0][0]:secondary_opts[previous.NEW_REPEATS[0][0]],
          core.NEW_REPEATS[1][0]:secondary_opts[previous.NEW_REPEATS[1][0]],
          core.NEW_REPEATS[2][0]:[1],
          core.NEW_REPEATS[3][0]:['a1'*32],
          core.NEW_REPEATS[4][0]:['a2'*32],
          core.NEW_REPEATS[5][0]:[0]})
        expected=set((*core.PARENT_SCALARS,*core.PARENT_REPEATS,*core.NEW_SCALARS,*core.REPEAT_NAMES))
        # Historical fixtures intentionally omit hundreds of deep ancestor CLI
        # values. Populate dummy *unused* keys only in this MOCKED test harness.
        # Production calls never manufacture any old pin, path or signature.
        for name in expected-set(options):
            if name in core.PARENT_REPEATS:
                options[name]=['a9'*32]
            elif name.endswith('_file'):
                options[name]='/tmp/ec392-test-ancestor-not-present'
            elif name.endswith('_utc'):
                options[name]='2026-10-26T00:00:00Z'
            elif name.endswith('_sha256'):
                options[name]='a9'*32
            elif name.startswith('minimum_'):
                options[name]=0
            else:
                options[name]='TestUnverifiedAncestor'
        assert set(options)==expected
        return real390,options,cross

    def test_ec392_22_two_actual_ec391_audits_and_signed_crossview_outer(self):
        real390,opts,_=self._outer_ec392()
        with self.mocked_parent(real390):res=core.derive_inventory(**opts)
        self.assertEqual(res['exit_code'],2)
        self.assertFalse(res[core.FLAGS[3]])
        self.assertTrue(res[core.FLAGS[2]])
        self.assertEqual(res['cryptographically_timestamped_crossview_checkpoint_count'],0)
        self.assertTrue(res['verified_primary_ec391_report_sha256']!=
                        res['verified_secondary_ec391_report_sha256'])
        self.assertEqual(res['historical_crossview_epoch_reviews'][0]['signed_snapshot_disagreements'],0)

    def test_ec392_23_second_audit_outside_integrity_missing_denied(self):
        real390,opts,_=self._outer_ec392()
        opts[core.NEW_SCALARS[5]]='f4'*32
        with self.mocked_parent(real390):
            with self.assertRaises(errors.AnchorError):core.derive_inventory(**opts)

    def test_ec392_24_signed_primary_crossview_conflict_retained(self):
        real390,opts,bundle=self._outer_ec392()
        wrong=copy.deepcopy(self.claim)
        wrong['observed_peer_prior_signed_head_original_sha256']='aa'*32
        wrong_cp=self.sign_checkpoint(wrong,tag='signed-disputed-crossview')
        bundle['epochs'][0]['channels'][0]['primary']['signed_crossview_checkpoint_original']=wrong_cp
        rr=self._archive('ec392-revised-crossview-'+self._testMethodName+'.json',bundle)
        opts[core.NEW_SCALARS[0]]=rr['path'];opts[core.NEW_SCALARS[1]]=rr['sha256']
        with self.mocked_parent(real390):derived=core.derive_inventory(**opts)
        self.assertTrue(derived[core.FLAGS[5]])
        self.assertEqual(len(derived['visible_crossview_conflict_cases']),1)

    def test_ec392_26_real_cms_on_both_crossview_checkpoints_e2e(self):
        real390,opts,_=self._outer_ec392(timestamp_checkpoints=True)
        with self.mocked_parent(real390):result=core.derive_inventory(**opts)
        self.assertEqual(result['cryptographically_timestamped_crossview_checkpoint_count'],2)
        self.assertEqual(result['historical_crossview_epoch_reviews'][0][
             'timestamp_authenticated_crossview_count'],2)
        self.assertFalse(result[core.FLAGS[2]])
        self.assertFalse(result[core.FLAGS[5]])
        self.assertTrue(result[core.FLAGS[1]])  # Outside digest was intentionally wrong.

    def test_ec392_27_two_differently_signed_ec391_source_views_are_not_merged(self):
        real390,opts,_=self._outer_ec392(split_sources=True)
        with self.mocked_parent(real390):result=core.derive_inventory(**opts)
        self.assertTrue(result[core.FLAGS[3]])
        self.assertTrue(result[core.FLAGS[4]])
        self.assertEqual(result['historical_crossview_epoch_reviews'][0][
                         'nonprefix_signed_split_views'],1)
        self.assertEqual(len(result['visible_crossview_conflict_cases']),1)
        case=result['visible_crossview_conflict_cases'][0]
        self.assertNotEqual(case['primary_source_snapshot_sha256'],
                            case['secondary_source_snapshot_sha256'])

    def test_ec392_28_authentic_same_keeper_double_signed_observation_retained(self):
        real390,opts,bundle=self._outer_ec392()
        alternate=copy.deepcopy(self.claim)
        alternate['observed_peer_prior_signed_head_original_sha256']='fa'*32
        altref=self.sign_checkpoint(alternate,tag='genuine-sibling-cp')
        bundle['epochs'][0]['channels'][0]['primary'][
            'alternate_signed_crossview_checkpoint_original']=altref
        bref=self._archive('ec392-signed-sibling-bundle.json',bundle)
        opts[core.NEW_SCALARS[0]]=bref['path'];opts[core.NEW_SCALARS[1]]=bref['sha256']
        with self.mocked_parent(real390):result=core.derive_inventory(**opts)
        self.assertTrue(result[core.FLAGS[6]])
        self.assertEqual(result['valid_distinct_same_keeper_signed_equivocation_count'],1)
        self.assertEqual(result['visible_crossview_conflict_cases'][0][
                         'primary_alternate_checkpoint_sha256'],altref['sha256'])

    def test_ec392_29_checkpoint_original_tamper_denied(self):
        real390,opts,bundle=self._outer_ec392()
        checkpath=bundle['epochs'][0]['channels'][0]['primary'][
                        'signed_crossview_checkpoint_original']['path']
        Path(checkpath).write_bytes(Path(checkpath).read_bytes()+b' ')
        with self.mocked_parent(real390):
            with self.assertRaises(errors.AnchorError):core.derive_inventory(**opts)

    def test_ec392_25_complete_inventory_pins_still_exit_2_unresolved(self):
        real390,opts,_=self._outer_ec392()
        with self.mocked_parent(real390):derived=core.derive_inventory(**opts)
        epoch=derived['historical_crossview_epoch_reviews'][0]
        opts[core.NEW_REPEATS[3][0]]=[epoch['crossview_signed_checkpoint_inventory_sha256']]
        opts[core.NEW_REPEATS[4][0]]=[epoch['crossview_rfc3161_token_inventory_sha256']]
        opts[core.AUDIT_ONLY[0]]=derived['receiver_verified_crossview_inventory_sha256']
        with self.mocked_parent(real390):result=core.audit(**opts)
        self.assertEqual(result['exit_code'],2)
        self.assertFalse(result[core.FLAGS[1]])
        self.assertTrue(result[core.FLAGS[-1]])
        self.assertNotIn('unsigned_crossview_inventory',result)


def load_tests(loader,tests,pattern):
    return unittest.TestSuite(CrossviewTests(k) for k in sorted(
      x for x in dir(CrossviewTests) if x.startswith('test_ec392_')))

if __name__=='__main__':
    unittest.TextTestRunner(verbosity=2).run(load_tests(None,None,None))
