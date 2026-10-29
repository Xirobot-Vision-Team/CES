#!/usr/bin/env python3
"""EC382 focused genuine signed EC348 keeper originals and EC347 bindings.

The inherited EC347->EC337 fixture in old EC348 tests is MOCKED. We call the
REAL legacy EC348/EC349 replay routines on locally issued actual Ed25519
keeper receipts; never claim remote originals, physical sites or issuer proof.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ec295_delivery_anchor import anchor as errors
from ec348_external_custody import custody as old348
from ec348_external_custody import test_custody as _fixture
from ec349_dual_channel_anchor import anchor as old349
from ec350_tsa_timestamp import timestamp as old350
from ec381_historical_channel import channel_archive as p381
from . import keeper_archive as core


def digest(raw):return hashlib.sha256(raw).hexdigest()
def ref(path,sha):return {'path':str(path),'sha256':sha}

class GenuineOldKeeperOriginals(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _fixture.ExternalKeeperImportTests.setUpClass()
        cls.f=_fixture.ExternalKeeperImportTests.f;cls.root=_fixture.ExternalKeeperImportTests.root

    @classmethod
    def tearDownClass(cls):_fixture.ExternalKeeperImportTests.tearDownClass()

    def setUp(self):
        _fixture.ExternalKeeperImportTests.setUp(self)
        self.role_paths={}
        self.evaluation=old350._utc('2026-10-25T14:30:00Z')

    def build(self,mode='normal',present=True):
        first=self.record(0,expires='2026-10-25T14:20:00Z' if mode=='expired' else
                                     '2026-10-25T14:50:00Z',
                          pinned=mode!='unpinned')
        self.record(1)
        if mode=='fork':
            self.record(0,kind=old348.RENEW,seq=2,prev=first)
            self.record(0,kind=old348.REVOKE,seq=2,prev=first)
        if mode=='revoke':self.record(0,kind=old348.REVOKE,seq=2,prev=first)
        options=self.options(presented=[self.present(first)] if present and mode not in
             ('fork','revoke') else [])
        ctx=old349._replay(options)  # real EC348->347 original validation
        self.ctx=ctx;self.source=options
        raw=self.root_key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        keyfile=self.w/f'keeper-independent-public-{self.serial}.bin';self.serial+=1
        keyfile.write_bytes(raw)
        latest=[]
        for path,sha in zip(options['readback_response_files'],
                            options['readback_response_shas'],strict=True):
            claim=json.loads(Path(path).read_bytes())['claim']
            if claim['round_number']==len(options['readback_challenge_files']):
                latest.append(ref(path,sha))
        ledger_refs=[ref(p,s) for p,s in zip(options['presented_ledger_files'],
                         options['presented_ledger_shas'],strict=True)]
        bykeeper={row['custodian_id']:row for row in ctx['report']['keeper_outcomes']}
        retests=[bykeeper[k]['local_explicit_retest'] for k in options['presented_keeper_ids']]
        self.row={
          'keeper_root_public_key_original':ref(keyfile,digest(raw)),
          'keeper_signed_directory_original':ref(options['keeper_directory_file'],
                                                 options['expected_keeper_directory_sha256']),
          'keeper_signed_receipt_originals':[ref(p,s) for p,s in zip(
                        options['keeper_receipt_files'],options['keeper_receipt_shas'],strict=True)
                        if s!=old348.UNPINNED],
          'keeper_signed_ledger_originals':ledger_refs,
          'ec347_latest_signed_challenge_original':ref(
              options['readback_challenge_files'][-1],options['readback_challenge_shas'][-1]),
          'ec347_latest_signed_response_originals':latest,
          'retested_snapshot_originals':[ref(p,r['actual_copy_snapshot_original_raw_sha256'])
              for p,r in zip(options['presented_copy_snapshot_files'],retests,strict=True)],
          'retested_ack_set_originals':[ref(p,r['actual_copy_ack_set_original_raw_sha256'])
              for p,r in zip(options['presented_copy_ack_set_files'],retests,strict=True)],
        }
        return self.row

    def read_original(self,document,role,cap):
        raw=Path(document['path']).read_bytes()
        if len(raw)>cap or digest(raw)!=document['sha256']:
            raise errors.AnchorError('EC382_TEST_REAL_WHOLE_ORIGINAL_SHA_DENIED',
                                     'permission_denied')
        old=self.role_paths.get(document['path'])
        if old is not None and old!=role:
            raise errors.AnchorError('EC382_TEST_ROLE_ALIAS_DENIED','permission_denied')
        self.role_paths[document['path']]=role
        return raw

    def graph(self):
        return core._keeper_graph(self.row,self.source,self.ctx,
                                  self.read_original,self.evaluation)

    def denied(self):
        with self.assertRaises(errors.AnchorError):self.graph()

    def test_01_real_signed_keeper_root_directory_receipts_and_byte_retest(self):
        self.build()
        result=self.graph()
        self.assertEqual(result['signed_keeper_receipt_count'],2)
        self.assertEqual(result['true_original_ledger_and_copy_pair_retests'],1)
        self.assertEqual(result['ec347']['latest_signed_response_count'],2)
        self.assertEqual(result['ec347']['actual_latest_round_measured_receiver_count'],2)
        self.assertFalse(result['visible_signed_fork'])
        self.assertFalse(result['signed_keeper_expired_revoked_or_source_drift'])

    def test_02_wrong_independent_keeper_root_sha_denied(self):
        self.build();self.row['keeper_root_public_key_original']['sha256']='ab'*32
        self.denied()

    def test_03_wrong_root_original_public_key_with_correct_sha_denied(self):
        self.build()
        root=self.row['keeper_root_public_key_original']
        raw=b'Q'*32;path=self.w/'unrelated-keeper-root.bin';path.write_bytes(raw)
        self.row['keeper_root_public_key_original']=ref(path,digest(raw))
        self.denied()

    def test_04_substitute_keeper_directory_digest_denied(self):
        self.build();self.row['keeper_signed_directory_original']['sha256']='ca'*32
        self.denied()

    def test_05_original_receipt_sha_substitution_denied(self):
        self.build();self.row['keeper_signed_receipt_originals'][0]['sha256']='cc'*32
        self.denied()

    def test_06_missing_old_signed_keeper_receipt_denied(self):
        self.build();self.row['keeper_signed_receipt_originals'].pop()
        self.denied()

    def test_07_old_keeper_receipt_order_not_changeable(self):
        self.build();self.row['keeper_signed_receipt_originals'].reverse()
        self.denied()

    def test_08_original_ec347_last_signed_challenge_must_match(self):
        self.build();self.row['ec347_latest_signed_challenge_original']['sha256']='db'*32
        self.denied()

    def test_09_last_signed_ec347_reply_census_cannot_be_truncated(self):
        self.build();self.row['ec347_latest_signed_response_originals'].pop()
        self.denied()

    def test_10_old_ec347_last_challenge_path_cannot_be_replaced(self):
        self.build();self.row['ec347_latest_signed_challenge_original']['path']=str(self.w/'decoy.json')
        self.denied()

    def test_11_old_ec348_retested_ledger_sha_not_replaced(self):
        self.build();self.row['keeper_signed_ledger_originals'][0]['sha256']='ac'*32
        self.denied()

    def test_12_retested_copy_original_mutation_detected(self):
        self.build()
        path=Path(self.row['retested_snapshot_originals'][0]['path'])
        path.write_bytes(b'changed after signed keeper ledger and auditor copy retest')
        self.denied()

    def test_13_retested_ack_set_byte_drift_detected(self):
        self.build();path=Path(self.row['retested_ack_set_originals'][0]['path'])
        path.write_bytes(b'late bytes changed')
        self.denied()

    def test_14_real_signed_keeper_fork_remains_adverse(self):
        self.build(mode='fork',present=False)
        result=self.graph()
        self.assertTrue(result['visible_signed_fork'])
        self.assertEqual(len(result['keepers'][0]['visible_head_original_shas']),2)
        self.assertTrue(result['signed_keeper_expired_revoked_or_source_drift'])

    def test_15_real_signed_keeper_revocation_remains_adverse(self):
        self.build(mode='revoke',present=False)
        result=self.graph()
        self.assertFalse(result['visible_signed_fork'])
        self.assertTrue(result['keepers'][0]['latest_signed_head_revoked_or_expired'])

    def test_16_real_old_keeper_receipt_expiry_remains_adverse(self):
        self.build(mode='expired',present=False)
        self.assertTrue(self.graph()['signed_keeper_expired_revoked_or_source_drift'])

    def test_17_externally_unpinned_real_signed_keeper_receipt_denied(self):
        self.build(mode='unpinned',present=False)
        self.denied()

    def test_18_source_report_substitution_must_not_change_signed_directory(self):
        self.build()
        self.ctx=copy.deepcopy(self.ctx)
        self.ctx['report']['ec347_audit_inputs_canonical_sha256']='ae'*32
        self.denied()

    def test_19_role_alias_cannot_use_root_for_signed_directory(self):
        self.build()
        self.row['keeper_signed_directory_original']=copy.deepcopy(
            self.row['keeper_root_public_key_original'])
        self.denied()

    def test_20_noncanonical_original_ec347_json_retained_and_valid(self):
        # Original EC347 signed JSON in the inherited fixture is formatted,
        # rather than equal to JSON canonical claim serialization. The audit
        # must accept its unchanged raw SHA with real legacy signature replay.
        self.build()
        path=self.row['ec347_latest_signed_challenge_original']['path']
        raw=Path(path).read_bytes()
        self.assertNotEqual(raw,core.canonical.canonical(json.loads(raw)))
        self.assertEqual(self.graph()['ec347']['latest_signed_response_count'],2)

    def test_21_missing_full_source_cannot_claim_signature_verification(self):
        row={k:None for k in core.CHANNEL_FIELDS}
        row['tsa_channel_id']='HistoricalKeeperChannelA'
        for k in ('keeper_signed_receipt_originals','keeper_signed_ledger_originals',
                  'ec347_latest_signed_response_originals','retested_snapshot_originals',
                  'retested_ack_set_originals'):row[k]=[]
        parent={'tsa_channel_id':row['tsa_channel_id']}
        token={'tsa_channel_id':row['tsa_channel_id']}
        result=core._channel(row,parent,token,self.read_original,self.evaluation,set())
        self.assertFalse(result['true_ec348_old_ec347_full_original_replay_performed'])
        self.assertFalse(result['full_signed_ec349_keeper_source_and_target_binding_matches'])

    def test_22_no_original_source_but_extra_signed_root_denied(self):
        self.build()
        row={k:None for k in core.CHANNEL_FIELDS}
        row['tsa_channel_id']='HistoricalKeeperChannelA'
        for k in ('keeper_signed_receipt_originals','keeper_signed_ledger_originals',
                  'ec347_latest_signed_response_originals','retested_snapshot_originals',
                  'retested_ack_set_originals'):row[k]=[]
        row['keeper_root_public_key_original']=self.row['keeper_root_public_key_original']
        with self.assertRaises(errors.AnchorError):
            core._channel(row,{'tsa_channel_id':row['tsa_channel_id']},
                          {'tsa_channel_id':row['tsa_channel_id']},
                          self.read_original,self.evaluation,set())

    def test_23_true_source_replay_not_forged_signed_ec349_digest(self):
        self.build()
        src=self.w/'full-ec348-inputs.json';src.write_bytes(core.canonical.canonical(self.source))
        row={'tsa_channel_id':'HistoricalTsaA','ec348_full_replay_inputs_original':
                 ref(src,digest(src.read_bytes())),**copy.deepcopy(self.row)}
        parent={'tsa_channel_id':'HistoricalTsaA',
                'signed_channel_directory_original':ref(src,digest(src.read_bytes())),
                'ec348_replay_inputs_original':None}
        token={'tsa_channel_id':'HistoricalTsaA','ec349_receipt_original':ref(src,digest(src.read_bytes()))}
        oldclaim={'case_id':self.ctx['report']['case_id'],
                  'ec348_inputs_canonical_sha256':'77'*32,
                  'ec348_verified_result_canonical_sha256':self.ctx['result_sha'],
                  'ec348_keeper_directory_original_raw_sha256':self.source['expected_keeper_directory_sha256']}
        with (patch.object(p381,'_ec348_original',return_value=self.ctx),
              patch.object(p381,'_directory',return_value=(oldclaim,b'G'*32)),
              patch.object(p381,'_receipt',return_value={'claim':{
                  'keeper_visible_heads':self.ctx['keepers'],
                  'keeper_signed_originals':self.ctx['originals']}})):
            with self.assertRaises(errors.AnchorError):
                core._channel(row,parent,token,self.read_original,self.evaluation,set())

    def test_24_old_ec349_actor_collides_with_true_ec348_keeper_role_denied(self):
        self.build()
        src=self.w/'full-ec348-inputs.json';src.write_bytes(core.canonical.canonical(self.source))
        row={'tsa_channel_id':'HistoricalTsaA','ec348_full_replay_inputs_original':
                 ref(src,digest(src.read_bytes())),**copy.deepcopy(self.row)}
        parent={'tsa_channel_id':'HistoricalTsaA',
                'signed_channel_directory_original':ref(src,digest(src.read_bytes())),
                'ec348_replay_inputs_original':None}
        token={'tsa_channel_id':'HistoricalTsaA','ec349_receipt_original':ref(src,digest(src.read_bytes()))}
        oldclaim={'case_id':self.ctx['report']['case_id'],
                  'ec348_inputs_canonical_sha256':self.ctx['source_sha'],
                  'ec348_verified_result_canonical_sha256':self.ctx['result_sha'],
                  'ec348_keeper_directory_original_raw_sha256':self.source['expected_keeper_directory_sha256'],
                  'root_authority':self.ctx['old_actors'][0],
                  'receipt_actor':{'public_hex':'90'*32,'signer_id':'newreceipt','organization_id':'neworg'},
                  'time_actor':{'public_hex':'91'*32,'signer_id':'newtime','organization_id':'newtimeorg'}}
        with (patch.object(p381,'_ec348_original',return_value=self.ctx),
              patch.object(p381,'_directory',return_value=(oldclaim,b'G'*32)),
              patch.object(p381,'_receipt',return_value={'claim':{
                  'keeper_visible_heads':self.ctx['keepers'],
                  'keeper_signed_originals':self.ctx['originals']}})):
            with self.assertRaises(errors.AnchorError):
                core._channel(row,parent,token,self.read_original,self.evaluation,set())

    def test_25_receipt_duplicate_signed_path_denied(self):
        self.build()
        self.row['keeper_signed_receipt_originals'][1]=copy.deepcopy(
            self.row['keeper_signed_receipt_originals'][0])
        self.denied()

    def make_ec349(self,*,reuse_old_root=False,alter_signed_keeper_heads=False):
        """Make REAL locally Ed25519 signed EC349 originals over REAL EC348.

        Older EC347->337 original fixture remains MOCKED; there is no TSA/CMS
        signing or external original provider in this specific local test.
        """
        src=self.w/f'ec382-actual-full-ec348-source-{self.serial}.json'
        self.serial+=1
        src.write_bytes(core.canonical.canonical(self.source))
        source_ref=ref(src,digest(src.read_bytes()))
        self.signed349_keys={name:(self.root_key if reuse_old_root and name=='root'
            else Ed25519PrivateKey.generate()) for name in ('root','receipt','time')}
        def pub(name):return self.signed349_keys[name].public_key().public_bytes(
                  Encoding.Raw,PublicFormat.Raw)
        def actor(name):
            return {'signer_id':'historical_ec349_'+name,
                'public_hex':pub(name).hex(),
                'organization_id':'historic_ec349_'+name+'_organization'}
        def save(name,doc):
            path=self.w/f'ec382-{self.serial}-{name}.json';self.serial+=1
            path.write_bytes(core.canonical.canonical(doc))
            return ref(path,digest(path.read_bytes()))
        def signed(schema,claim,domain,who):
            return {'schema':schema,'claim':claim,'signature_ed25519':
               self.signed349_keys[who].sign(domain+core.canonical.canonical(claim)).hex()}
        rootfile=self.w/f'ec382-{self.serial}-ec349-root.bin';self.serial+=1
        rootbytes=pub('root');rootfile.write_bytes(rootbytes)
        rootref=ref(rootfile,digest(rootbytes))
        claim={'schema':old349.DIRECTORY_CLAIM,
           'case_id':self.ctx['report']['case_id'],
           'ec348_inputs_canonical_sha256':self.ctx['source_sha'],
           'ec348_verified_result_canonical_sha256':self.ctx['result_sha'],
           'ec348_keeper_directory_original_raw_sha256':self.source['expected_keeper_directory_sha256'],
           'channel_id':'HistoricTsaA',
           'channel_role':'independent_out_of_band_sha_anchor_claim',
           'root_authority':actor('root'),'receipt_actor':actor('receipt'),
           'time_actor':actor('time'),
           'valid_from_utc':'2026-10-25T14:00:00Z',
           'valid_until_utc':'2026-10-25T15:30:00Z',
           'scope':'bounded_offline_sha_anchor_and_time_witness_only',
           'no_independence_or_trusted_clock_authority':True}
        signed_directory=save('old349-signed-directory',
                   signed(old349.DIRECTORY_SCHEMA,claim,old349.D_DIRECTORY,'root'))
        heads=copy.deepcopy(self.ctx['keepers'])
        if alter_signed_keeper_heads:heads[0]['signed_receipt_count']+=1
        rc={'schema':old349.RECEIPT_CLAIM,'case_id':self.ctx['report']['case_id'],
            'ec348_inputs_canonical_sha256':self.ctx['source_sha'],
            'ec348_verified_result_canonical_sha256':self.ctx['result_sha'],
            'channel_id':'HistoricTsaA',
            'channel_directory_original_raw_sha256':signed_directory['sha256'],
            'receipt_signer_id':actor('receipt')['signer_id'],
            'receipt_signer_public_hex':actor('receipt')['public_hex'],
            'receipt_signer_organization_id':actor('receipt')['organization_id'],
            'keeper_visible_heads':heads,
            'keeper_signed_originals':self.ctx['originals'],
            'statement_kind':old349.KINDS[0],'sequence':1,
            'previous_statement_file':None,
            'previous_statement_original_raw_sha256':None,
            'statement_nonce_sha256':digest(b'ec382 real signed ec349 nonce'),
            'claimed_received_utc':'2026-10-25T14:20:00Z',
            'expires_utc':'2026-10-25T14:55:00Z',
            'scope':'signed_out_of_band_keeper_heads_claim_only',
            'no_remote_custody_or_external_time_authority':True}
        signed_receipt=save('old349-signed-receipt',
                    signed(old349.RECEIPT_SCHEMA,rc,old349.D_RECEIPT,'receipt'))
        self.row['tsa_channel_id']='HistoricTsaA'
        self.row['ec348_full_replay_inputs_original']=source_ref
        parent={'tsa_channel_id':'HistoricTsaA',
                'channel_root_public_key_original':rootref,
                'signed_channel_directory_original':signed_directory,
                'ec348_replay_inputs_original':None}
        token={'tsa_channel_id':'HistoricTsaA','ec349_receipt_original':signed_receipt}
        return parent,token

    def test_27_true_signed_ec349_parent_and_old_ec348_old_ec347_local_replay(self):
        self.build()
        parent,token=self.make_ec349()
        self.role_paths={}
        result=core._channel(self.row,parent,token,self.read_original,
                             self.evaluation,set())
        self.assertTrue(result['true_ec348_old_ec347_full_original_replay_performed'])
        self.assertTrue(result['full_signed_ec349_keeper_source_and_target_binding_matches'])
        self.assertEqual(result['ec348_signed_keeper_receipt_count'],2)
        self.assertEqual(result['ec348_genuine_retested_ledger_count'],1)

    def test_28_true_signed_ec349_receipt_with_forged_keeper_head_denied(self):
        self.build();parent,token=self.make_ec349(alter_signed_keeper_heads=True)
        self.role_paths={}
        with self.assertRaises(errors.AnchorError):
            core._channel(self.row,parent,token,self.read_original,self.evaluation,set())

    def test_29_real_ec349_signed_root_reused_from_ec348_does_not_escape(self):
        self.build();parent,token=self.make_ec349(reuse_old_root=True)
        self.role_paths={}
        with self.assertRaises(errors.AnchorError):
            core._channel(self.row,parent,token,self.read_original,self.evaluation,set())

    def test_30_existing_ec381_parent_true_source_cannot_be_swapped(self):
        self.build();parent,token=self.make_ec349()
        parent['ec348_replay_inputs_original']={'path':self.row['ec348_full_replay_inputs_original']['path'],
                                                 'sha256':'12'*32}
        self.role_paths={}
        with self.assertRaises(errors.AnchorError):
            core._channel(self.row,parent,token,self.read_original,self.evaluation,set())

    def test_26_caller_generated_sha_does_not_earn_acceptance(self):
        self.build()
        x=self.graph()
        self.assertIn('live_old_ec348_keeper_outcome',x['keepers'][0])
        self.assertNotIn('independent_physical_site_verified',x)
        self.assertFalse(core.NEGATIVES==())

# Borrow the test fixture's original signed-input producer without inheriting
# all its unrelated old regression test_* methods a second time.
for _method in ('configure','sign','parameters','audit','copies','observation',
 'arguments','show','challenge','response','kw','nonce_sha','issue','reply',
 'params','write','sign_document','make_directory','record','options','present'):
    setattr(GenuineOldKeeperOriginals,_method,getattr(_fixture.ExternalKeeperImportTests,_method))

if __name__=='__main__':unittest.main()
