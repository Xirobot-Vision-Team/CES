#!/usr/bin/env python3
"""EC394 focused offline cryptographic development fixtures only.

Real local Ed25519, OpenSSL DER/CMS, X509 and CRLs. ONLY outer
EC390->EC369 and old EC317/318 are mocked in inherited test setup.
These new test-time originals do not prove outside institutions or pre-dispute
physical storage. Do not run inherited EC390-393 tests as EC394 coverage.
"""
from __future__ import annotations

import copy
from datetime import datetime,timedelta,timezone
from pathlib import Path
import shutil
import subprocess
import unittest

from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from tsa_timestamp import timestamp as tsa
from tsa_timestamp.test_timestamp import local_test_certs
from external_revocation.test_witness_custody import ref
from custody_anchor.test_custody_anchor import CustodyTests
from custody_anchor import custody_anchor as parent
from . import registered_witness as core

POLICY='1.2.3.4.5.394'


class RegisteredWitnessTests(CustodyTests):
    def setUp(self):
        super().setUp()
        self.parties394={}
        for name in ('registrar','dispute_authority','witness_a','witness_b'):
            priv=Ed25519PrivateKey.generate()
            self.parties394[name]=priv
        def role(name):
            pub=self.parties394[name].public_key().public_bytes(
                serialization.Encoding.Raw,serialization.PublicFormat.Raw)
            path=self.root/f'ec394-role-{name}-{self._testMethodName}.raw'
            path.write_bytes(pub)
            return {'role_id':name+'394','site_id':name+'Site394',
                    'public_hex':pub.hex(),'public_key_original':ref(path)}
        self.roles394={name:role(name) for name in self.parties394}
        self.trustroster={'schema':core.ROSTER_SCHEMA,
          'claimed_directory_lineage_id':'Lineage388',
          'registrar':self.roles394['registrar'],
          'dispute_authority':self.roles394['dispute_authority'],
          'witnesses':[self.roles394['witness_a'],self.roles394['witness_b']]}
        self.trustref=self._archive('ec394-roles-'+self._testMethodName+'.json',
                                    self.trustroster)

    def registration(self,party,rostersha,*,name=None,public_hex=None,
                     previous=None,seq=1,old_priv=None,new_priv=None,override=None):
        key=public_hex or party['public_hex']
        claim={'schema':core.REGISTRATION_CLAIM_SCHEMA,
          'directory_lineage_id':'Lineage388',
          'parent_ec393_roster_original_sha256':rostersha,
          'registrar_id':self.roles394['registrar']['role_id'],
          'observer_id':party['observer_id'],'role':party['role'],
          'party_id':party['party_id'],'site_id':party['site_id'],
          'site_registry_reference_sha256':'9a'*32,
          'registration_sequence':seq,'registered_public_hex':key,
          'previous_registration_original_sha256':previous['sha256'] if previous else core.ZERO,
          'claimed_registered_utc':'2026-10-25T10:00:00Z',
          'effective_from_utc':'2026-10-25T10:15:00Z',
          'effective_until_utc':'2026-10-30T10:15:00Z'}
        if override:claim.update(override)
        signed={'schema':core.REGISTRATION_SCHEMA,'claim':claim,
          'registrar_signature_ed25519':self.parties394['registrar'].sign(
            core.REGISTRAR_DOMAIN+canonical.canonical(claim)).hex(),
          'previous_key_signature_ed25519':old_priv.sign(
            core.OLD_KEY_DOMAIN+canonical.canonical(claim)).hex() if old_priv else None,
          'new_key_signature_ed25519':new_priv.sign(
            core.NEW_KEY_DOMAIN+canonical.canonical(claim)).hex() if new_priv else None}
        return self._archive(name or 'ec394-registration-'+party['party_id']+'-'+
                             self._testMethodName+'.json',signed)

    def notice(self,ec393sha,case_sha,*,cutoff=None,private=None,name='ec394-notice'):
        claim={'schema':core.NOTICE_CLAIM_SCHEMA,
          'directory_lineage_id':'Lineage388',
          'authority_id':self.roles394['dispute_authority']['role_id'],
          'parent_ec393_custody_bundle_original_sha256':ec393sha,
          'external_dispute_case_file_original_sha256':case_sha,
          'declared_dispute_cutoff_utc':cutoff or self.cutoff,
          'claimed_notice_issued_utc':'2026-10-25T13:30:00Z'}
        return self._archive(name+'-'+self._testMethodName+'.json',
          {'schema':core.NOTICE_SCHEMA,'claim':claim,
           'authority_signature_ed25519':(private or self.parties394['dispute_authority']).sign(
             core.NOTICE_DOMAIN+canonical.canonical(claim)).hex()})

    def witness(self,name,head,notice_sha,rostersha,*,index=0,
                private=None,observed='2026-10-25T13:05:00Z'):
        signed_head=core.tr.strict_json(Path(head['path']).read_bytes(),'EC394_TEST_LOG_HEAD')
        claim={'schema':core.WITNESS_CLAIM_SCHEMA,
          'directory_lineage_id':'Lineage388','witness_id':self.roles394[name]['role_id'],
          'witness_site_id':self.roles394[name]['site_id'],
          'parent_ec393_roster_original_sha256':rostersha,
          'signed_dispute_notice_original_sha256':notice_sha,'epoch_index':index,
          'observed_log_id':signed_head['claim']['log_id'],
          'observed_signed_log_head_original_sha256':head['sha256'],
          'observed_log_tree_size':signed_head['claim']['tree_size'],
          'observed_log_merkle_root_sha256':signed_head['claim']['merkle_root_sha256'],
          'claimed_observed_utc':observed}
        return self._archive('ec394-witness-'+name+'-'+self._testMethodName+'.json',
          {'schema':core.WITNESS_SCHEMA,'claim':claim,
           'witness_signature_ed25519':(private or self.parties394[name]).sign(
             core.WITNESS_DOMAIN+canonical.canonical(claim)).hex()})

    def stamp_all(self,files):
        if not shutil.which('openssl'):self.skipTest('OpenSSL executable unavailable')
        base=Path(self.root);rootpath,cert,private,crl=local_test_certs(base,394)
        serial=base/'ec394-serial.txt';serial.write_text('01\n',encoding='ascii')
        cfg=base/'ec394-stamp.conf'
        cfg.write_text('[tsa_config]\nserial = '+str(serial)+'\nsigner_cert = '+str(cert)+
            '\nsigner_key = '+str(private)+'\ncerts = '+str(rootpath)+
            '\nsigner_digest = sha256\ndefault_policy = '+POLICY+
            '\ndigests = sha256, sha384, sha512\naccuracy = secs:1\nordering = yes\n'+
            'tsa_name = yes\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n',
            encoding='ascii')
        refs=[]
        for n,source in enumerate(files):
            query=base/f'ec394-query-{n}.tsq'
            token=base/f'ec394-token-{n}.der'
            for cmd in (
              ['openssl','ts','-query','-data',source['path'],'-sha256','-cert','-out',str(query)],
              ['openssl','ts','-reply','-queryfile',str(query),'-config',str(cfg),
               '-section','tsa_config','-token_out','-out',str(token)]):
                got=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
                if got.returncode:raise AssertionError(got.stderr)
            refs.append(ref(token))
        trust={'schema':parent.prior.TRUST_SCHEMA,
          'claimed_directory_lineage_id':'Lineage388','authorities':[
            {'authority_id':'EC394IndependentTSA',
             'root_certificate_original':ref(rootpath),
             'root_certificate_der_sha256':tsa._certificate(rootpath.read_bytes())
               .fingerprint(hashes.SHA256()).hex(),
             'expected_tsa_policy_oid':POLICY,'crl_originals':[ref(crl)]}]}
        return refs,self._archive('ec394-tsa-trust-'+self._testMethodName+'.json',trust)

    def status_snapshot(self,roster_sha,parent_roster_sha,notice_sha,histories,*,revoke=None):
        subjects={self.roles394[k]['role_id']:self.roles394[k]['public_hex']
                  for k in ('registrar','dispute_authority','witness_a','witness_b')}
        for history in histories:
            for seq,gen in enumerate(history['generations'],1):
                claim=core.tr.strict_json(
                   Path(gen['signed_site_key_registration_original']['path']).read_bytes(),
                   'EC394_TEST_SIGNED_REGISTRATION')['claim']
                subjects[history['party_id']+':'+str(seq)]=claim['registered_public_hex']
        claim={'schema':core.KEY_STATUS_CLAIM_SCHEMA,
          'directory_lineage_id':'Lineage388',
          'authority_id':self.roles394['dispute_authority']['role_id'],
          'external_trust_roster_original_sha256':roster_sha,
          'ec393_custody_roster_original_sha256':parent_roster_sha,
          'signed_dispute_notice_original_sha256':notice_sha,
          'declared_status_utc':'2026-10-25T14:00:00Z',
          'key_statuses':[{'subject_id':k,'public_hex':v,
             'status':'revoked' if k==revoke else 'active',
             'claimed_change_utc':'2026-10-25T13:40:00Z'}
             for k,v in sorted(subjects.items())]}
        return self._archive('ec394-original-key-status-'+self._testMethodName+'.json',
          {'schema':core.KEY_STATUS_SCHEMA,'claim':claim,
           'authority_signature_ed25519':self.parties394['dispute_authority'].sign(
              core.KEY_STATUS_DOMAIN+canonical.canonical(claim)).hex()})

    def build_ec394(self,*,fork=False,wrong_claim=False,forged_witness=False,
                    revoke=None):
        real390,opts,ec393bundle,_=self.build_outer()
        with self.mocked_parent(real390):
            derived=parent.derive_inventory(**opts)
        for index,review in enumerate(derived['custody_anchor_epoch_reviews']):
            opts[parent.NEW_REPEATS[0][0]][index]=review['countersigned_receipt_inventory_sha256']
            opts[parent.NEW_REPEATS[1][0]][index]=review['rfc6962_inclusion_inventory_sha256']
        opts[parent.AUDIT_ONLY[0]]=derived['receiver_verified_custody_anchor_inventory_sha256']
        rosterref=ec393bundle['custody_log_roster_original']
        histories=[];registrations=[]
        for party in self.parties:
            sitepath=self.root/('ec394-site-registration-'+party['party_id']+'-'+
                               self._testMethodName+'.txt')
            sitepath.write_bytes(b'SYNTHETIC REGISTERED SITE IDENTITY: '+
                                 party['site_id'].encode('ascii'))
            siteref=ref(sitepath)
            source=self.registration(party,rosterref['sha256'],
               override={'site_registry_reference_sha256':siteref['sha256']})
            public_copy=self.root/('ec394-generation-'+party['party_id']+'-'+self._testMethodName+'.raw')
            public_copy.write_bytes(bytes.fromhex(party['public_hex']))
            histories.append({'observer_id':party['observer_id'],'role':party['role'],
              'party_id':party['party_id'],'site_id':party['site_id'],
              'registered_site_identity_original':siteref,
              'generations':[{'signed_site_key_registration_original':source,
                 'registered_public_key_original':ref(public_copy),
                 'rfc3161_registration_token_original':None}]})
            registrations.append(source)
        casepath=self.root/('ec394-opaque-case-'+self._testMethodName+'.bin')
        casepath.write_bytes(b'SYNTHETIC TEST CASE ONLY - no legal authority')
        caseref=ref(casepath)
        noticeref=self.notice(opts[parent.NEW_SCALARS[1]],caseref['sha256'],
                              cutoff='2026-10-25T01:00:00Z' if wrong_claim else None)
        oldhead=ec393bundle['prior_signed_log_head_original']
        oldraw=core.tr.strict_json(Path(oldhead['path']).read_bytes(),'TEST_HEAD')
        alt=None
        if fork:
            alt=self.signed_head(oldraw['claim']['tree_size'],bytes.fromhex('71'*32),1,
                  core.ZERO,'ec394-authentic-operator-signed-fork-'+self._testMethodName+'.json')
        statusref=self.status_snapshot(self.trustref['sha256'],
                   rosterref['sha256'],noticeref['sha256'],histories,revoke=revoke)
        refs=[];witnesses=[]
        for i,name in enumerate(('witness_a','witness_b')):
            head=alt if fork and i==1 else oldhead
            wref=self.witness(name,head,noticeref['sha256'],rosterref['sha256'],
                  private=Ed25519PrivateKey.generate() if forged_witness and i==1 else None)
            witnesses.append({'witness_id':self.roles394[name]['role_id'],
              'observations':[{'signed_witness_observation_original':wref,
                'rfc3161_witness_token_original':None,
                'observed_signed_log_head_original':head}]})
            refs.append(wref)
        tokens,trustref=self.stamp_all(registrations+[noticeref,statusref]+refs)
        for hist,stamp in zip(histories,tokens[:4],strict=True):
            hist['generations'][0]['rfc3161_registration_token_original']=stamp
        for group,stamp in zip(witnesses,tokens[6:],strict=True):
            group['observations'][0]['rfc3161_witness_token_original']=stamp
        bundle={'schema':core.BUNDLE_SCHEMA,
          'claimed_directory_lineage_id':'Lineage388',
          'parent_ec393_custody_bundle_original':{'path':opts[parent.NEW_SCALARS[0]],
                                                  'sha256':opts[parent.NEW_SCALARS[1]]},
          'external_trust_roster_original':self.trustref,
          'witness_tsa_registry_original':trustref,
          'original_dispute_case_file':caseref,
          'signed_dispute_notice_original':noticeref,
          'dispute_notice_rfc3161_token_original':tokens[4],
          'key_status_snapshot_original':statusref,
          'key_status_snapshot_rfc3161_token_original':tokens[5],
          'witness_tsa_authority_id':'EC394IndependentTSA',
          'site_key_histories':histories,
          'epochs':[{'epoch_index':0,'witnesses':witnesses}]}
        bref=self._archive('ec394-bundle-'+self._testMethodName+'.json',bundle)
        opts.update({core.NEW_SCALARS[0]:bref['path'],core.NEW_SCALARS[1]:bref['sha256'],
           core.NEW_SCALARS[2]:self.trustref['sha256'],
           core.NEW_SCALARS[3]:trustref['sha256'],
           core.NEW_SCALARS[4]:witnesses[0]['observations'][0]['signed_witness_observation_original']['sha256'],
           core.NEW_SCALARS[5]:noticeref['sha256'],
           core.NEW_SCALARS[6]:self.roles394['registrar']['public_hex'],
           core.NEW_SCALARS[7]:self.roles394['dispute_authority']['public_hex'],
           core.NEW_REPEATS[0][0]:['41'*32],core.NEW_REPEATS[1][0]:['51'*32],
           core.NEW_REPEATS[2][0]:[0],core.NEW_REPEATS[3][0]:[0]})
        return real390,opts,bundle

    def test_ec394_01_external_roster_four_distinct_crypto_roles(self):
        result=core._roster(self.trustroster,self.trustref,{core.NEW_SCALARS[2]:self.trustref['sha256'],
           core.NEW_SCALARS[6]:self.roles394['registrar']['public_hex'],
           core.NEW_SCALARS[7]:self.roles394['dispute_authority']['public_hex']},
           'Lineage388',self.read,set())
        self.assertEqual(len(result['witnesses']),2)

    def test_ec394_02_reused_registrar_witness_key_is_denied(self):
        wrong=copy.deepcopy(self.trustroster)
        wrong['registrar']['public_hex']=wrong['witnesses'][0]['public_hex']
        with self.assertRaises(errors.AnchorError):
            core._roster(wrong,self.trustref,{core.NEW_SCALARS[2]:self.trustref['sha256'],
               core.NEW_SCALARS[6]:self.roles394['registrar']['public_hex'],
               core.NEW_SCALARS[7]:self.roles394['dispute_authority']['public_hex']},
               'Lineage388',self.read,set())

    def test_ec394_03_genesis_registrar_signature_exact_original(self):
        party=self.parties[0];source=self.registration(party,'11'*32)
        pubpath=self.root/'ec394-genesis-raw.pub'
        pubpath.write_bytes(bytes.fromhex(party['public_hex']))
        actual=core._registration(source,ref(pubpath),self.roles394['registrar'],
             self.read,'Lineage388','11'*32,party,1,None)
        self.assertEqual(actual['key'],party['public_hex'])

    def test_ec394_04_forged_registrar_signature_is_rejected(self):
        party=self.parties[0];source=self.registration(party,'11'*32)
        tampered=copy.deepcopy(canonical.strict_json(Path(source['path']).read_bytes())) if hasattr(canonical,'strict_json') else None
        if tampered is None:
            import json
            tampered=json.loads(Path(source['path']).read_bytes())
        tampered['registrar_signature_ed25519']='00'*64
        forged=self._archive('ec394-forged-reg-original.json',tampered)
        pubpath=self.root/'ec394-forged-reg-key.raw';pubpath.write_bytes(bytes.fromhex(party['public_hex']))
        with self.assertRaises(errors.AnchorError):
            core._registration(forged,ref(pubpath),self.roles394['registrar'],
                self.read,'Lineage388','11'*32,party,1,None)

    def test_ec394_05_rotation_old_and_new_keys_must_genuinely_consent(self):
        party=self.parties[0]
        oldkey=Ed25519PrivateKey.generate();newkey=self.partykeys[(party['observer_id'],party['role'])]
        oldhex=oldkey.public_key().public_bytes(
             serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
        first=self.registration(party,'11'*32,public_hex=oldhex,name='ec394-rotation-old.json',
             override={'effective_until_utc':'2026-10-26T00:00:00Z'})
        prev={'sha256':first['sha256'],'key':oldhex,
              'registered':core._utc('2026-10-25T10:00:00Z'),
              'start':core._utc('2026-10-25T10:15:00Z'),
              'end':core._utc('2026-10-26T00:00:00Z')}
        nextreg=self.registration(party,'11'*32,previous=first,seq=2,
              old_priv=oldkey,new_priv=newkey,name='ec394-rotation-new.json',
              override={'claimed_registered_utc':'2026-10-25T13:00:00Z',
                        'effective_from_utc':'2026-10-26T00:00:00Z'})
        pubpath=self.root/'ec394-rotated-key.raw';pubpath.write_bytes(bytes.fromhex(party['public_hex']))
        self.assertEqual(core._registration(nextreg,ref(pubpath),self.roles394['registrar'],
            self.read,'Lineage388','11'*32,party,2,prev)['key'],party['public_hex'])
        fake=self.registration(party,'11'*32,previous=first,seq=2,
              old_priv=Ed25519PrivateKey.generate(),new_priv=newkey,
              name='ec394-rotation-forged-old.json',
              override={'claimed_registered_utc':'2026-10-25T13:00:00Z',
                        'effective_from_utc':'2026-10-26T00:00:00Z'})
        with self.assertRaises(errors.AnchorError):
            core._registration(fake,ref(pubpath),self.roles394['registrar'],
                self.read,'Lineage388','11'*32,party,2,prev)

    def test_ec394_06_complete_real_ec393_392_391_chain_and_ec394_der_timestamps(self):
        actual,opts,_=self.build_ec394()
        with self.mocked_parent(actual):result=core.derive_inventory(**opts)
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result[core.FLAGS[3]])  # Genuine TSA issued after old CLAIMED handoff.
        self.assertEqual(result['cryptographically_timestamped_pre_handoff_registered_site_role_count'],0)
        self.assertEqual(result['cryptographically_timestamped_pre_cutoff_independent_witness_count'],2)
        self.assertFalse(result[core.FLAGS[6]])
        self.assertTrue(result['sender_origin_path_required_or_read'] is False)
        opts[core.NEW_REPEATS[0][0]]=[result['registered_witness_epoch_reviews'][0][
          'site_key_registration_inventory_sha256']]
        opts[core.NEW_REPEATS[1][0]]=[result['registered_witness_epoch_reviews'][0][
          'third_party_witness_inventory_sha256']]
        opts[core.AUDIT_ONLY[0]]=result['receiver_verified_registered_witness_inventory_sha256']
        with self.mocked_parent(actual):audited=core.audit(**opts)
        self.assertFalse(audited[core.FLAGS[1]])
        self.assertEqual(audited['receiver_verified_registered_witness_inventory_sha256'],
                         opts[core.AUDIT_ONLY[0]])
        self.assertNotIn('unsigned_registered_witness_inventory',audited)

    def test_ec394_07_genuinely_log_operator_signed_third_party_fork_is_visible(self):
        actual,opts,_=self.build_ec394(fork=True)
        with self.mocked_parent(actual):report=core.derive_inventory(**opts)
        self.assertTrue(report[core.FLAGS[4]])
        self.assertEqual(report['visible_genuine_signed_log_fork_count'],1)
        self.assertEqual(len(report['visible_signed_log_fork_cases'][0][
           'valid_log_operator_signed_conflicting_head_original_shas']),2)
        self.assertEqual(report['cryptographically_timestamped_pre_cutoff_independent_witness_count'],1)

    def test_ec394_08_forged_witness_ed25519_original_is_denied(self):
        actual,opts,_=self.build_ec394(forged_witness=True)
        with self.mocked_parent(actual):
            with self.assertRaises(errors.AnchorError):core.derive_inventory(**opts)

    def test_ec394_09_signed_notice_for_wrong_real_parent_cutoff_denied(self):
        actual,opts,_=self.build_ec394(wrong_claim=True)
        with self.mocked_parent(actual):
            with self.assertRaises(errors.AnchorError):core.derive_inventory(**opts)

    def test_ec394_10_signed_revoked_independent_witness_status_blocks_count(self):
        actual,opts,_=self.build_ec394(revoke=self.roles394['witness_b']['role_id'])
        with self.mocked_parent(actual):report=core.derive_inventory(**opts)
        self.assertTrue(report[core.FLAGS[6]])
        self.assertEqual(report['furnished_signed_key_revocation_count'],1)
        self.assertEqual(report['cryptographically_timestamped_pre_cutoff_independent_witness_count'],0)
        self.assertEqual(report['exit_code'],2)

    def test_ec394_11_source_input_exactness_and_no_forged_completion(self):
        with self.assertRaises(errors.AnchorError):core._inputs({},True)
        self.assertTrue(all(type(x) is str for x in core.NEGATIVES))



class StatusContractUnitTests(unittest.TestCase):
    """Fast, isolated role/status signature tests (timestamp is a stub here)."""
    def setUp(self):
        import tempfile
        self.tmp=tempfile.TemporaryDirectory(prefix='ec394-status-unit-')
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)
        self.keys={name:Ed25519PrivateKey.generate() for name in
           ('registrar','dispute_authority','a','b')}
        def pub(name):return self.keys[name].public_key().public_bytes(
           serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
        self.roles={'registrar':{'role_id':'Registrar','public_hex':pub('registrar')},
          'dispute_authority':{'role_id':'Dispute','public_hex':pub('dispute_authority')},
          'witnesses':{'WitnessA':{'role_id':'WitnessA','public_hex':pub('a')},
                       'WitnessB':{'role_id':'WitnessB','public_hex':pub('b')}}}
        self.history={}
        for i in range(4):
            key=Ed25519PrivateKey.generate()
            hx=key.public_key().public_bytes(
                serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
            self.history[('Observer'+str(i), 'sender')]=[
               {'key':hx,'claim':{'party_id':'Party'+str(i)}}]
        self.cutoff=core._utc('2026-10-27T18:00:00Z')
        self.evaluation=core._utc('2026-10-28T18:00:00Z')

    def build(self,revoked=None,forged=False):
        pairs={r['role_id']:r['public_hex'] for r in (
             self.roles['registrar'],self.roles['dispute_authority'],
             *self.roles['witnesses'].values())}
        for records in self.history.values():
            for seq,item in enumerate(records,1):
                pairs[item['claim']['party_id']+':'+str(seq)]=item['key']
        claim={'schema':core.KEY_STATUS_CLAIM_SCHEMA,
         'directory_lineage_id':'Lineage388','authority_id':'Dispute',
         'external_trust_roster_original_sha256':'11'*32,
         'ec393_custody_roster_original_sha256':'22'*32,
         'signed_dispute_notice_original_sha256':'33'*32,
         'declared_status_utc':'2026-10-25T14:00:00Z',
         'key_statuses':[{'subject_id':name,'public_hex':hexkey,
             'status':'revoked' if name==revoked else 'active',
             'claimed_change_utc':'2026-10-25T13:00:00Z'}
             for name,hexkey in pairs.items()]}
        key=Ed25519PrivateKey.generate() if forged else self.keys['dispute_authority']
        blob=canonical.canonical({'schema':core.KEY_STATUS_SCHEMA,'claim':claim,
           'authority_signature_ed25519':key.sign(
               core.KEY_STATUS_DOMAIN+canonical.canonical(claim)).hex()})
        source=self.path/'status.json';source.write_bytes(blob)
        return {'key_status_snapshot_original':ref(source),
                'key_status_snapshot_rfc3161_token_original':{
                    'path':str(self.path/'token.der'),'sha256':'44'*32}}

    def run_case(self,bundle):
        from unittest.mock import patch
        def read(r,role,cap):
            data=Path(r['path']).read_bytes()
            self.assertEqual(ref(Path(r['path']))['sha256'],r['sha256'])
            return data
        flags={k:False for k in core.FLAGS}
        with patch.object(core,'_timestamp',return_value={
              'sha256':'44'*32,'gen':core._utc('2026-10-26T12:00:00Z'),
              'clean':True}):
            result=core._key_status(bundle,self.roles,read,'Lineage388',{},
               'SomeTSA',self.evaluation,self.cutoff,
               '11'*32,'22'*32,'33'*32,self.history,flags)
        return result,flags

    def test_ec394_status_01_genuine_signed_full_active_roster(self):
        out,flags=self.run_case(self.build())
        self.assertTrue(out['clean'])
        self.assertFalse(flags[core.FLAGS[6]])

    def test_ec394_status_02_forged_authority_denied(self):
        with self.assertRaises(errors.AnchorError):self.run_case(self.build(forged=True))

    def test_ec394_status_03_signed_revocation_remains_adverse(self):
        result,flags=self.run_case(self.build(revoked='WitnessA'))
        self.assertFalse(result['clean'])
        self.assertEqual(result['revoked_subject_ids'],['WitnessA'])
        self.assertTrue(flags[core.FLAGS[6]])

    def test_ec394_status_04_missing_snapshot_is_unresolved(self):
        result,flags=self.run_case({
          'key_status_snapshot_original':None,
          'key_status_snapshot_rfc3161_token_original':None})
        self.assertIsNone(result['sha256'])
        self.assertTrue(flags[core.FLAGS[6]])


if __name__=='__main__':
    suite=unittest.TestSuite(
      RegisteredWitnessTests(name) for name in sorted(
         n for n in dir(RegisteredWitnessTests) if n.startswith('test_ec394_')))
    unittest.TextTestRunner(verbosity=2).run(suite)
