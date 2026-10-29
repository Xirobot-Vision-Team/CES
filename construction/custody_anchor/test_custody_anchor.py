#!/usr/bin/env python3
"""EC393 bounded real Ed25519/OpenSSL CMS fixtures; outer EC390->EC369 MOCKED.

Synthetic local keys, timestamps, declared cutoff and log roots do not prove
pre-dispute external custody, a qualified TSA, WORM or independent legal sites.
"""
from __future__ import annotations

import copy
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import subprocess
import sys
import unittest

from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as tsa
from tsa_timestamp.test_timestamp import local_test_certs
from transparency import transparency as tr
from transparency.test_transparency import root,inclusion,consistency
from external_revocation.test_witness_custody import ref
from crossview import crossview as parent
from crossview.test_crossview import CrossviewTests
from . import custody_anchor as core

POLICY='1.2.3.4.5.393'


def utc(s):return datetime.strptime(s,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


class CustodyTests(CrossviewTests):
    def setUp(self):
        super().setUp()
        self.partykeys={}
        self.parties=[]
        for who in ('ObserverNorth','ObserverSouth'):
            for role in ('sender','receiver'):
                key=Ed25519PrivateKey.generate()
                self.partykeys[(who,role)]=key
                pub=key.public_key().public_bytes(
                    serialization.Encoding.Raw,serialization.PublicFormat.Raw)
                path=self.root/f'ec393-{who}-{role}-{self._testMethodName}.raw'
                path.write_bytes(pub)
                self.parties.append({'observer_id':who,'party_id':who+'_'+role,
                  'site_id':who+'_'+role+'_Site','role':role,
                  'public_hex':pub.hex(),'public_key_original':ref(path)})
        self.logpriv=Ed25519PrivateKey.generate()
        logpub=self.logpriv.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        path=self.root/f'ec393-log-key-{self._testMethodName}.raw'
        path.write_bytes(logpub)
        self.roster={'schema':core.ROSTER_SCHEMA,'claimed_directory_lineage_id':'Lineage388',
           'log_id':'IndependentCustodyLog1','log_operator_id':'LogKeeper3',
           'log_public_hex':logpub.hex(),'log_public_key_original':ref(path),
           'custody_parties':self.parties}
        self.rosterref=self._archive('ec393-custody-roster-'+self._testMethodName+'.json',
                                    self.roster)
        self.cutoff=(datetime.now(timezone.utc)+timedelta(days=1)).strftime(
             '%Y-%m-%dT%H:%M:%SZ')

    def sign_handoff(self,claim,name,*,sender_key=None,receiver_key=None):
        sender=sender_key or self.partykeys[(claim['observer_id'],'sender')]
        receiver=receiver_key or self.partykeys[(claim['observer_id'],'receiver')]
        return self._archive(name,{'schema':core.RECEIPT_SCHEMA,'claim':claim,
            'sender_signature_ed25519':sender.sign(
              core.SENDER_DOMAIN+canonical.canonical(claim)).hex(),
            'receiver_signature_ed25519':receiver.sign(
              core.RECEIVER_DOMAIN+canonical.canonical(claim)).hex()})

    def signed_head(self,tree_size,hash_value,sequence,prior_sha,name,**overrides):
        claim={'schema':core.HEAD_CLAIM_SCHEMA,'directory_lineage_id':'Lineage388',
          'log_id':'IndependentCustodyLog1','log_sequence':sequence,
          'tree_size':tree_size,'merkle_root_sha256':hash_value.hex(),
          'previous_signed_log_head_original_sha256':prior_sha,
          'claimed_integrated_utc':'2026-10-25T13:00:00Z' if sequence==1 else
                                    '2026-10-25T13:20:00Z'}
        claim.update(overrides)
        return self._archive(name,{'schema':core.HEAD_SCHEMA,'claim':claim,
          'signature_ed25519':self.logpriv.sign(
             core.LOG_DOMAIN+canonical.canonical(claim)).hex()})

    def stamp_heads(self,head0,head1,*,with_crl=True):
        base=Path(self.root);rootpath,cert,private,crl=local_test_certs(
            base,393,stale=not with_crl)
        conf=base/'ec393-signature-tsa.conf';serial=base/'ec393-tsa-serial.txt'
        serial.write_text('01\n',encoding='ascii')
        conf.write_text('[tsa_config]\nserial = '+str(serial)+'\nsigner_cert = '+str(cert)+
            '\nsigner_key = '+str(private)+'\ncerts = '+str(rootpath)+
            '\nsigner_digest = sha256\ndefault_policy = '+POLICY+
            '\ndigests = sha256, sha384, sha512\naccuracy = secs:1\nordering = yes\n'+
            'tsa_name = yes\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n',
            encoding='ascii')
        tokens=[]
        for n,h in enumerate((head0,head1)):
            q=base/f'ec393-{n}-{self._testMethodName}.tsq'
            out=base/f'ec393-{n}-{self._testMethodName}.der'
            for command in (
              ['openssl','ts','-query','-data',h['path'],'-sha256','-cert','-out',str(q)],
              ['openssl','ts','-reply','-queryfile',str(q),'-config',str(conf),
               '-section','tsa_config','-token_out','-out',str(out)]):
                p=subprocess.run(command,capture_output=True,text=True,timeout=25)
                if p.returncode:raise AssertionError(p.stderr)
            tokens.append(ref(out))
        registry={'schema':core.prior.TRUST_SCHEMA,
          'claimed_directory_lineage_id':'Lineage388',
          'authorities':[{'authority_id':'IndependentTSA3',
             'root_certificate_original':ref(rootpath),
             'root_certificate_der_sha256':tsa._certificate(rootpath.read_bytes()).fingerprint(
                 hashes.SHA256()).hex(),'expected_tsa_policy_oid':POLICY,
             'crl_originals':[ref(crl)] if with_crl else []}]}
        return tokens,self._archive('ec393-registry-'+self._testMethodName+'.json',registry)

    def build_outer(self,*,timestamp_checkpoints=True,include_receipts=True,
                    forged_claim=False,alternate=False,corrupt_proof=False,
                    include_log=True,with_crl=True):
        real390,opts,cross=self._outer_ec392(
            timestamp_checkpoints=timestamp_checkpoints)
        with self.mocked_parent(real390):
            report=parent.derive_inventory(**opts)
        p_review=report['historical_crossview_epoch_reviews'][0]
        opts[parent.NEW_REPEATS[3][0]]=[p_review['crossview_signed_checkpoint_inventory_sha256']]
        opts[parent.NEW_REPEATS[4][0]]=[p_review['crossview_rfc3161_token_inventory_sha256']]
        opts[parent.AUDIT_ONLY[0]]=report['receiver_verified_crossview_inventory_sha256']
        receipts=[];rows={};leaves=[]
        for side,observer,peer in (
          ('primary','ObserverNorth','ObserverSouth'),
          ('secondary','ObserverSouth','ObserverNorth')):
            source=cross['epochs'][0]['channels'][0][side]
            cp=source['signed_crossview_checkpoint_original']
            tok=source['rfc3161_crossview_checkpoint_token_original']
            claim={'schema':core.RECEIPT_CLAIM_SCHEMA,
              'directory_lineage_id':'Lineage388','log_id':'IndependentCustodyLog1',
              'observer_id':observer,'peer_observer_id':peer,
              'tsa_channel_id':self.cid,'epoch_index':0,'handoff_sequence':1,
              'sender_party_id':observer+'_sender',
              'receiver_party_id':observer+'_receiver',
              'sender_site_id':observer+'_sender_Site',
              'receiver_site_id':observer+'_receiver_Site',
              'crossview_bundle_original_sha256':opts[parent.NEW_SCALARS[1]],
              'signed_crossview_checkpoint_original_sha256':cp['sha256'],
              'crossview_rfc3161_token_original_sha256':tok['sha256'] if tok else None,
              'previous_signed_custody_handoff_original_sha256':core.ZERO,
              'claimed_handoff_utc':'2026-10-25T12:00:00Z'}
            if forged_claim and side=='primary':
                claim['signed_crossview_checkpoint_original_sha256']='f5'*32
            original=self.sign_handoff(claim,
                f'ec393-{side}-handoff-'+self._testMethodName+'.json')
            receipts.append(original)
            leaves.append(Path(original['path']).read_bytes())
            rows[side]={'signed_custody_handoff_original':original,
               'rfc6962_leaf_index':len(leaves)-1,
               'rfc6962_inclusion_path_sha256':None,
               'alternate_signed_custody_handoff_original':None,
               'alternate_rfc6962_leaf_index':None,
               'alternate_rfc6962_inclusion_path_sha256':None}
        log_leaves=leaves+[b'append-only-after-signed-anchor']
        first=self.signed_head(2,root(leaves),1,core.ZERO,
              'ec393-earlier-head-'+self._testMethodName+'.json')
        second=self.signed_head(3,root(log_leaves),2,first['sha256'],
              'ec393-newer-head-'+self._testMethodName+'.json')
        tokens,trustref=self.stamp_heads(first,second,with_crl=with_crl)
        for i,side in enumerate(('primary','secondary')):
            rows[side]['rfc6962_inclusion_path_sha256']=[
                p.hex() for p in inclusion(leaves,i)]
        if corrupt_proof:
            rows['primary']['rfc6962_inclusion_path_sha256']=['a0'*32]
        if alternate:
            conflicting=copy.deepcopy(claim)
            # The secondary observer signs two incompatible statements.
            conflicting['crossview_rfc3161_token_original_sha256']='55'*32
            cp_alt=self.sign_handoff(conflicting,
                     'ec393-alt-'+self._testMethodName+'.json')
            rows['secondary']['alternate_signed_custody_handoff_original']=cp_alt
        if not include_receipts:
            rows['primary']={key:None for key in core.ROW_FIELDS}
        if not include_log:
            first=None;second=None;tokens=[None,None]
        bundle={'schema':core.BUNDLE_SCHEMA,
          'claimed_directory_lineage_id':'Lineage388',
          'parent_ec392_crossview_bundle_original':{
              'path':opts[parent.NEW_SCALARS[0]],'sha256':opts[parent.NEW_SCALARS[1]]},
          'custody_log_roster_original':self.rosterref,
          'tsa_trust_registry_original':trustref,
          'prior_signed_log_head_original':first,
          'prior_log_head_rfc3161_token_original':tokens[0],
          'current_signed_log_head_original':second,
          'current_log_head_rfc3161_token_original':tokens[1],
          'log_tsa_authority_id':'IndependentTSA3' if include_log else None,
          'log_consistency_path_sha256':[x.hex() for x in consistency(log_leaves,2)],
          'epochs':[{'epoch_index':0,'channels':[
             {'tsa_channel_id':self.cid,**rows}]}]}
        bref=self._archive('ec393-archive-'+self._testMethodName+'.json',bundle)
        opts.update({core.NEW_SCALARS[0]:bref['path'],
          core.NEW_SCALARS[1]:bref['sha256'],
          core.NEW_SCALARS[2]:self.rosterref['sha256'],
          core.NEW_SCALARS[3]:trustref['sha256'],
          core.NEW_SCALARS[4]:first['sha256'] if first else '44'*32,
          core.NEW_SCALARS[5]:self.cutoff,
          core.NEW_REPEATS[0][0]:['33'*32],
          core.NEW_REPEATS[1][0]:['aa'*32],
          core.NEW_REPEATS[2][0]:[0]})
        return real390,opts,bundle,receipts

    def deny(self,real390,opts):
        with self.mocked_parent(real390):
            with self.assertRaises(errors.AnchorError):core.derive_inventory(**opts)

    def test_ec393_01_existing_rfc6962_algorithms_exhaustive_small_trees(self):
        for n in range(2,17):
            leaves=[f'original-{i}'.encode() for i in range(n)]
            for i in range(n):
                self.assertTrue(tr.verify_inclusion(tr.leaf_hash(leaves[i]),i,n,
                    root(leaves),inclusion(leaves,i)))
            for old in range(1,n):
                self.assertTrue(tr.verify_consistency(old,n,root(leaves[:old]),
                    root(leaves),consistency(leaves,old)))

    def test_ec393_02_real_sender_and_receiver_signature_domains(self):
        who='ObserverNorth'
        claim=self._claim_for_standalone(who)
        signed=self.sign_handoff(claim,'ec393-correct-'+self._testMethodName+'.json')
        parties={(p['observer_id'],p['role']):p for p in self.parties}
        result=core._receipt(signed,who,'ObserverSouth',self.cid,0,
           parties,'IndependentCustodyLog1',self.read,'Lineage388')
        self.assertEqual(result['sha256'],signed['sha256'])

    def _claim_for_standalone(self,who):
        peer='ObserverSouth' if who=='ObserverNorth' else 'ObserverNorth'
        return {'schema':core.RECEIPT_CLAIM_SCHEMA,
           'directory_lineage_id':'Lineage388','log_id':'IndependentCustodyLog1',
           'observer_id':who,'peer_observer_id':peer,'tsa_channel_id':self.cid,
           'epoch_index':0,'handoff_sequence':1,
           'sender_party_id':who+'_sender','receiver_party_id':who+'_receiver',
           'sender_site_id':who+'_sender_Site','receiver_site_id':who+'_receiver_Site',
           'crossview_bundle_original_sha256':'a1'*32,
           'signed_crossview_checkpoint_original_sha256':'b2'*32,
           'crossview_rfc3161_token_original_sha256':'c3'*32,
           'previous_signed_custody_handoff_original_sha256':core.ZERO,
           'claimed_handoff_utc':'2026-10-25T12:00:00Z'}

    def test_ec393_03_forged_sender_signature_rejected(self):
        claim=self._claim_for_standalone('ObserverNorth')
        receipt=self.sign_handoff(claim,'ec393-fake-sender.json',
             sender_key=Ed25519PrivateKey.generate())
        with self.assertRaises(errors.AnchorError):core._receipt(receipt,'ObserverNorth',
           'ObserverSouth',self.cid,0,
           {(p['observer_id'],p['role']):p for p in self.parties},
           'IndependentCustodyLog1',self.read,'Lineage388')

    def test_ec393_04_forged_receiver_signature_rejected(self):
        claim=self._claim_for_standalone('ObserverNorth')
        receipt=self.sign_handoff(claim,'ec393-fake-receiver.json',
             receiver_key=Ed25519PrivateKey.generate())
        with self.assertRaises(errors.AnchorError):core._receipt(receipt,'ObserverNorth',
            'ObserverSouth',self.cid,0,
            {(p['observer_id'],p['role']):p for p in self.parties},
            'IndependentCustodyLog1',self.read,'Lineage388')

    def test_ec393_05_wrong_site_id_cannot_reuse_two_signatures(self):
        claim=self._claim_for_standalone('ObserverNorth');claim['sender_site_id']='NotOwned'
        receipt=self.sign_handoff(claim,'ec393-fake-site.json')
        with self.assertRaises(errors.AnchorError):core._receipt(receipt,'ObserverNorth',
          'ObserverSouth',self.cid,0,
          {(p['observer_id'],p['role']):p for p in self.parties},
          'IndependentCustodyLog1',self.read,'Lineage388')

    def test_ec393_06_exact_keys_deny_missing_bundle_field(self):
        with self.assertRaises(errors.AnchorError):core.exact(
           {'schema':core.BUNDLE_SCHEMA},core.BUNDLE_FIELDS,'CUSTODY_BUNDLE')

    def test_ec393_07_public_key_reuse_cannot_simulate_independence(self):
        d=copy.deepcopy(self.roster)
        d['custody_parties'][1]['public_hex']=d['custody_parties'][0]['public_hex']
        with self.assertRaises(errors.AnchorError):core._roster(d,self.rosterref,
           self.rosterref['sha256'],'Lineage388',self.read,
           ('ObserverNorth','ObserverSouth'),set())

    def test_ec393_08_signed_log_head_forged_private_key_rejected(self):
        claim={'schema':core.HEAD_CLAIM_SCHEMA,'directory_lineage_id':'Lineage388',
          'log_id':'IndependentCustodyLog1','log_sequence':1,'tree_size':1,
          'merkle_root_sha256':'ab'*32,
          'previous_signed_log_head_original_sha256':core.ZERO,
          'claimed_integrated_utc':'2026-10-25T13:00:00Z'}
        bad=self._archive('ec393-forged-log.json',{'schema':core.HEAD_SCHEMA,
          'claim':claim,'signature_ed25519':Ed25519PrivateKey.generate().sign(
                   core.LOG_DOMAIN+canonical.canonical(claim)).hex()})
        log={'log_id':'IndependentCustodyLog1','log_key':self.roster['log_public_hex']}
        with self.assertRaises(errors.AnchorError):core._log_head(
              bad,self.read,log,'Lineage388',1)

    def test_ec393_09_true_dual_signatures_wrong_ec392_sha_not_silently_promoted(self):
        real390,opts,_,_=self.build_outer(forged_claim=True)
        with self.mocked_parent(real390):result=core.derive_inventory(**opts)
        self.assertTrue(result[core.FLAGS[3]])
        self.assertEqual(result['cryptographically_bounded_pre_cutoff_handoff_count'],1)

    def test_ec393_10_missing_handoff_is_visible_not_accepted(self):
        real390,opts,_,_=self.build_outer(include_receipts=False)
        with self.mocked_parent(real390):result=core.derive_inventory(**opts)
        self.assertTrue(result[core.FLAGS[2]])
        self.assertEqual(result['cryptographically_bounded_pre_cutoff_handoff_count'],1)

    def test_ec393_11_bad_merkle_path_keeps_valid_signed_claim_adverse(self):
        real390,opts,_,_=self.build_outer(corrupt_proof=True)
        with self.mocked_parent(real390):result=core.derive_inventory(**opts)
        self.assertTrue(result[core.FLAGS[5]])
        self.assertEqual(result['cryptographically_bounded_pre_cutoff_handoff_count'],1)

    def test_ec393_12_parent_crossview_is_real_audited_not_caller_supplied(self):
        with self.assertRaises(errors.AnchorError):core._parent_report(
          {'schema':parent.RESULT_SCHEMA,'exit_code':0},
          {'historical_directory_root_shas':['55'*32]})

    def test_ec393_13_signed_conflicting_double_handoff_keeps_both_shas(self):
        real390,opts,_,_=self.build_outer(alternate=True)
        with self.mocked_parent(real390):result=core.derive_inventory(**opts)
        self.assertTrue(result[core.FLAGS[4]])
        self.assertEqual(result['valid_distinct_dual_countersigned_conflict_count'],1)
        self.assertEqual(len(result['visible_custody_conflict_cases']),1)
        self.assertNotEqual(result['visible_custody_conflict_cases'][0][
          'primary_countersigned_receipt_original_sha256'],
          result['visible_custody_conflict_cases'][0][
          'alternate_countersigned_receipt_original_sha256'])

    def test_ec393_14_all_real_signatures_rfc3161_and_merkle_inclusion(self):
        real390,opts,_,_=self.build_outer()
        with self.mocked_parent(real390):result=core.derive_inventory(**opts)
        self.assertTrue(result['signed_rfc6962_append_only_extension_verified'])
        self.assertEqual(result['cryptographically_bounded_pre_cutoff_handoff_count'],2)
        self.assertFalse(result[core.FLAGS[3]])
        self.assertFalse(result[core.FLAGS[5]])
        self.assertFalse(result[core.FLAGS[6]])
        self.assertFalse(result[core.FLAGS[7]])
        self.assertTrue(result[core.FLAGS[-1]])

    def test_ec393_15_correct_inventory_pins_audit_exit2_never_publish(self):
        real390,opts,_,_=self.build_outer()
        with self.mocked_parent(real390):derived=core.derive_inventory(**opts)
        ep=derived['custody_anchor_epoch_reviews'][0]
        opts[core.NEW_REPEATS[0][0]]=[ep['countersigned_receipt_inventory_sha256']]
        opts[core.NEW_REPEATS[1][0]]=[ep['rfc6962_inclusion_inventory_sha256']]
        opts[core.NEW_REPEATS[2][0]]=[2]
        opts[core.AUDIT_ONLY[0]]=derived['receiver_verified_custody_anchor_inventory_sha256']
        with self.mocked_parent(real390):actual=core.audit(**opts)
        self.assertFalse(actual[core.FLAGS[1]])
        self.assertEqual(actual['exit_code'],2)
        self.assertFalse(actual['sender_origin_path_required_or_read'])
        self.assertNotIn('unsigned_custody_anchor_inventory',actual)
        self.assertTrue(all(actual[x] is False for x in core.NEGATIVES))

    def test_ec393_16_outside_prior_head_sha_mismatch_adverse(self):
        real390,opts,_,_=self.build_outer()
        opts[core.NEW_SCALARS[4]]='99'*32
        with self.mocked_parent(real390):result=core.derive_inventory(**opts)
        self.assertTrue(result[core.FLAGS[1]])

    def test_ec393_17_externally_asserted_cutoff_before_cms_time_adverse(self):
        real390,opts,_,_=self.build_outer()
        opts[core.NEW_SCALARS[5]]='2026-10-25T13:02:00Z'
        with self.mocked_parent(real390):result=core.derive_inventory(**opts)
        self.assertTrue(result[core.FLAGS[6]])
        self.assertEqual(result['cryptographically_bounded_pre_cutoff_handoff_count'],0)

    def test_ec393_18_missing_signed_log_not_pre_dispute_proof(self):
        real390,opts,_,_=self.build_outer(include_log=False)
        with self.mocked_parent(real390):result=core.derive_inventory(**opts)
        self.assertFalse(result['signed_rfc6962_append_only_extension_verified'])
        self.assertTrue(result[core.FLAGS[2]])
        self.assertEqual(result['cryptographically_bounded_pre_cutoff_handoff_count'],0)

    def test_ec393_19_stale_offline_crl_not_current_clean_proof(self):
        real390,opts,_,_=self.build_outer(with_crl=False)
        with self.mocked_parent(real390):result=core.derive_inventory(**opts)
        self.assertTrue(result[core.FLAGS[7]])
        self.assertEqual(result['cryptographically_bounded_pre_cutoff_handoff_count'],0)

    def test_ec393_20_tampered_original_denied_not_reclassed_as_dispute(self):
        real390,opts,bundle,_=self.build_outer()
        old=bundle['epochs'][0]['channels'][0]['primary']['signed_custody_handoff_original']
        Path(old['path']).write_bytes(Path(old['path']).read_bytes()+b' ')
        self.deny(real390,opts)

    def test_ec393_21_incorrect_outside_roster_sha_denied(self):
        real390,opts,_,_=self.build_outer()
        opts[core.NEW_SCALARS[2]]='cc'*32
        self.deny(real390,opts)

    def test_ec393_22_signed_log_merkle_extension_can_be_disputed_without_auto_repair(self):
        real390,opts,bundle,_=self.build_outer()
        bundle['log_consistency_path_sha256']=['77'*32]
        b=self._archive('ec393-wrong-consistency-'+self._testMethodName+'.json',bundle)
        opts[core.NEW_SCALARS[0]]=b['path'];opts[core.NEW_SCALARS[1]]=b['sha256']
        with self.mocked_parent(real390):result=core.derive_inventory(**opts)
        self.assertFalse(result['signed_rfc6962_append_only_extension_verified'])
        self.assertTrue(result[core.FLAGS[5]])

    def test_ec393_23_fixed_standalone_readonly_help(self):
        rootdir=Path(__file__).resolve().parents[2]
        for name in ('ces_cas_historical_custody_anchor.py','ces_next.py'):
            cmd=[sys.executable,'-I','-B',str(rootdir/'scripts'/name),
                 'audit-historical-ec339-custody-anchor','--help']
            p=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn('--historical-ec339-custody-log-inclusion-inventory-sha256',p.stdout)
            self.assertNotIn('--private-key',p.stdout)



    def test_ec393_24_valid_signed_but_wrong_log_predecessor_not_counted(self):
        real390,opts,bundle,_=self.build_outer()
        current=bundle['current_signed_log_head_original']
        original=json.loads(Path(current['path']).read_text())
        replacement=self.signed_head(3,
            bytes.fromhex(original['claim']['merkle_root_sha256']),2,
            'aa'*32,'ec393-broken-signed-log-predecessor-'+self._testMethodName+'.json')
        newtokens,newtrust=self.stamp_heads(
            bundle['prior_signed_log_head_original'],replacement)
        bundle['current_signed_log_head_original']=replacement
        bundle['prior_log_head_rfc3161_token_original']=newtokens[0]
        bundle['current_log_head_rfc3161_token_original']=newtokens[1]
        bundle['tsa_trust_registry_original']=newtrust
        changed=self._archive('ec393-broken-log-chain-'+self._testMethodName+'.json',bundle)
        opts[core.NEW_SCALARS[0]]=changed['path']
        opts[core.NEW_SCALARS[1]]=changed['sha256']
        opts[core.NEW_SCALARS[3]]=newtrust['sha256']
        with self.mocked_parent(real390):result=core.derive_inventory(**opts)
        self.assertTrue(result[core.FLAGS[5]])
        self.assertFalse(result['signed_rfc6962_append_only_extension_verified'])
        self.assertEqual(result['cryptographically_bounded_pre_cutoff_handoff_count'],0)

    def test_ec393_25_missing_current_genuine_tsa_token_blocks_count(self):
        real390,opts,bundle,_=self.build_outer()
        bundle['current_log_head_rfc3161_token_original']=None
        changed=self._archive('ec393-no-current-token-'+self._testMethodName+'.json',bundle)
        opts[core.NEW_SCALARS[0]]=changed['path']
        opts[core.NEW_SCALARS[1]]=changed['sha256']
        with self.mocked_parent(real390):result=core.derive_inventory(**opts)
        self.assertTrue(result[core.FLAGS[2]])
        self.assertEqual(result['cryptographically_bounded_pre_cutoff_handoff_count'],0)

    def test_ec393_26_signed_merkle_prefix_with_wrong_outside_head_pin_blocks_count(self):
        real390,opts,_,_=self.build_outer()
        opts[core.NEW_SCALARS[4]]='9a'*32
        with self.mocked_parent(real390):result=core.derive_inventory(**opts)
        self.assertTrue(result[core.FLAGS[1]])
        self.assertFalse(result['signed_rfc6962_append_only_extension_verified'])
        self.assertEqual(result['cryptographically_bounded_pre_cutoff_handoff_count'],0)

def load_tests(loader,tests,pattern):
    return unittest.TestSuite(CustodyTests(name) for name in sorted(
        key for key in dir(CustodyTests) if key.startswith('test_ec393_')))

if __name__=='__main__':
    unittest.TextTestRunner(verbosity=2).run(load_tests(None,None,None))
