#!/usr/bin/env python3
"""EC381 focused Ed25519 originals. Historic EC380->EC369 parent is MOCKED
only in receiver-engine cases; no deep issuer/keeper fixture is claimed real.
"""
from __future__ import annotations
import copy
from datetime import datetime,timedelta,timezone
import hashlib
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from dual_channel_anchor import anchor as old349
from external_custody import custody as old348
from historical_timestamp import timestamp_archive as p380
from historical_source import source_archive as p379
from historical_transparency import transparency_archive as p377
from . import channel_archive as core

UTC=timezone.utc

def stamp(t):return t.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')
def digest(raw):return hashlib.sha256(raw).hexdigest()

class GenuineEc349Bytes(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='ec381-ed25519-original-')
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.serial=0
        self.now=datetime(2026,10,26,9,0,0,tzinfo=UTC)
        self.evaluation=self.now+timedelta(minutes=10)
        self.channel='HistoricalTsaA'
        self.keys={k:ed25519.Ed25519PrivateKey.generate() for k in ('root','receipt','time')}
        self.rootref=self.write('root-public.bin',self.pub('root'))
        self.directory=self.directory_signed()
        self.heads=[{'custodian_id':'KeeperA','subject_receiver_id':'ReceiverA',
           'signed_receipt_count':1,
           'signed_head_original_raw_sha256s':['31'*32],
           'multiple_signed_heads_are_unresolved_forks':False,
           'latest_single_head_kind':'store_claim',
           'latest_head_entire_history_caller_sha_pins_present':True,
           'signed_keeper_ancestry_has_self_reported_expiry_gap':False,
           'latest_single_head_ledger_original_raw_sha256':'32'*32,
           'outcome':old349.inherited.OUTCOMES[7]}]
        self.originals=[{'whole_original_raw_sha256':'34'*32,
                         'independently_furnished_sha_pin_present':True}]
        self.receipt=self.receipt_signed()
        self.witness=self.witness_signed(self.receipt)
        self.row={'tsa_channel_id':self.channel,
          'channel_root_public_key_original':self.rootref,
          'signed_channel_directory_original':self.directory,
          'signed_receipt_predecessor_originals':[],
          'signed_receipt_sibling_originals':[],
          'signed_time_witness_originals':[self.witness],
          'ec348_replay_inputs_original':None}
        self.token={'tsa_channel_id':self.channel,
            'ec349_receipt_original':self.receipt,
            'rfc3161_timestamp_original':self.write('tsa-token.der',b'original-test-token')}

    def pub(self,role):
        return self.keys[role].public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)

    def actor(self,role):
        return {'signer_id':f'ec381_{role}_signer',
                'public_hex':self.pub(role).hex(),
                'organization_id':f'ec381_{role}_org'}

    def write(self,name,contents):
        self.serial+=1
        path=self.root/f'{self.serial:03d}-{name}'
        raw=contents if type(contents) is bytes else canonical.canonical(contents)
        path.write_bytes(raw)
        return {'path':str(path),'sha256':digest(raw)}

    def signed(self,schema,claim,domain,role):
        return {'schema':schema,'claim':claim,'signature_ed25519':
                self.keys[role].sign(domain+canonical.canonical(claim)).hex()}

    def directory_signed(self,overrides=None,role='root'):
        c={'schema':old349.DIRECTORY_CLAIM,
            'case_id':'EC381CaseA','ec348_inputs_canonical_sha256':'41'*32,
            'ec348_verified_result_canonical_sha256':'42'*32,
            'ec348_keeper_directory_original_raw_sha256':'43'*32,
            'channel_id':self.channel,
            'channel_role':'independent_out_of_band_sha_anchor_claim',
            'root_authority':self.actor('root'),
            'receipt_actor':self.actor('receipt'),
            'time_actor':self.actor('time'),
            'valid_from_utc':stamp(self.now-timedelta(hours=1)),
            'valid_until_utc':stamp(self.now+timedelta(days=2)),
            'scope':'bounded_offline_sha_anchor_and_time_witness_only',
            'no_independence_or_trusted_clock_authority':True}
        c.update(overrides or {})
        return self.write('signed-directory.json',self.signed(old349.DIRECTORY_SCHEMA,c,
                                                              old349.D_DIRECTORY,role))

    def receipt_signed(self,seq=1,prev=None,kind=None,overrides=None,role='receipt',minutes=0):
        c={'schema':old349.RECEIPT_CLAIM,'case_id':'EC381CaseA',
            'ec348_inputs_canonical_sha256':'41'*32,
            'ec348_verified_result_canonical_sha256':'42'*32,
            'channel_id':self.channel,
            'channel_directory_original_raw_sha256':self.directory['sha256'],
            'receipt_signer_id':self.actor('receipt')['signer_id'],
            'receipt_signer_public_hex':self.actor('receipt')['public_hex'],
            'receipt_signer_organization_id':self.actor('receipt')['organization_id'],
            'keeper_visible_heads':self.heads,'keeper_signed_originals':self.originals,
            'statement_kind':kind or (old349.KINDS[0] if seq==1 else old349.KINDS[1]),
            'sequence':seq,
            'previous_statement_file':None if prev is None else prev['path'],
            'previous_statement_original_raw_sha256':None if prev is None else prev['sha256'],
            'statement_nonce_sha256':digest((str(self.serial)+'nonce').encode()),
            'claimed_received_utc':stamp(self.now+timedelta(minutes=minutes)),
            'expires_utc':stamp(self.now+timedelta(days=1)),
            'scope':'signed_out_of_band_keeper_heads_claim_only',
            'no_remote_custody_or_external_time_authority':True}
        c.update(overrides or {})
        return self.write('signed-ec349-receipt.json',self.signed(old349.RECEIPT_SCHEMA,c,
                                                                  old349.D_RECEIPT,role))

    def witness_signed(self,ref,overrides=None,role='time'):
        rc=self.doc(ref)['claim']
        c={'schema':old349.TIME_CLAIM,'case_id':'EC381CaseA',
            'channel_id':self.channel,
            'channel_directory_original_raw_sha256':self.directory['sha256'],
            'receipt_original_raw_sha256':ref['sha256'],
            'receipt_sequence':rc['sequence'],
            'time_actor_id':self.actor('time')['signer_id'],
            'time_actor_public_hex':self.actor('time')['public_hex'],
            'time_actor_organization_id':self.actor('time')['organization_id'],
            'time_provenance_kind':'separately_signed_local_clock_claim',
            'claimed_observed_utc':stamp(self.now),
            'uncertainty_seconds':60,
            'time_nonce_sha256':digest((str(self.serial)+'witness').encode()),
            'scope':'receipt_sha_time_provenance_claim_only',
            'not_a_trusted_utc_or_legal_timestamp':True}
        c.update(overrides or {})
        return self.write('signed-ec349-witness.json',self.signed(old349.TIME_SCHEMA,c,
                                                                  old349.D_TIME,role))

    def doc(self,ref):
        import json
        return json.loads(Path(ref['path']).read_bytes())

    def read(self,ref,role,cap):
        data=Path(ref['path']).read_bytes()
        if digest(data)!=ref['sha256'] or len(data)>cap:
            raise errors.AnchorError('EC381_PIN_MISMATCH','permission_denied')
        return data

    def run_channel(self):
        return core._channel(self.row,self.token,self.now,self.read,self.evaluation,set())

    def denied(self):
        with self.assertRaises(errors.AnchorError):self.run_channel()

    def test_01_real_old_directory_receipt_time_signature(self):
        result=self.run_channel()
        self.assertTrue(result['actual_root_signed_directory_receipt_actor_authorization_verified'])
        self.assertEqual(result['visible_signed_receipt_count'],1)
        self.assertEqual(result['real_signed_time_witness_count'],1)
        self.assertFalse(result['signed_time_witness_missing_or_disagrees'])
        self.assertFalse(result['real_ec348_full_keeper_original_replay_performed'])

    def test_02_root_original_sha_forgery(self):
        self.row['channel_root_public_key_original']['sha256']='09'*32;self.denied()

    def test_03_wrong_directory_signature_private_key(self):
        self.row['signed_channel_directory_original']=self.directory_signed(role='receipt');self.denied()

    def test_04_directory_advertises_other_authority_root(self):
        self.row['signed_channel_directory_original']=self.directory_signed(
            {'root_authority':self.actor('time')});self.denied()

    def test_05_receipt_uses_self_claimed_other_signer_key(self):
        self.token['ec349_receipt_original']=self.receipt_signed(overrides={
            'receipt_signer_public_hex':self.actor('root')['public_hex']});self.denied()

    def test_06_receipt_signed_by_unapproved_private_key(self):
        self.token['ec349_receipt_original']=self.receipt_signed(role='time');self.denied()

    def test_07_directory_ref_original_digest_mutation(self):
        self.row['signed_channel_directory_original']['sha256']='19'*32;self.denied()

    def test_08_target_receipt_different_directory_ref(self):
        self.token['ec349_receipt_original']=self.receipt_signed(overrides={
            'channel_directory_original_raw_sha256':'12'*32});self.denied()

    def test_09_renewal_authentic_precursor_chain(self):
        later=self.receipt_signed(seq=2,prev=self.receipt,minutes=2)
        self.row['signed_receipt_predecessor_originals']=[self.receipt]
        self.token['ec349_receipt_original']=later
        self.row['signed_time_witness_originals']=[self.witness_signed(later)]
        result=self.run_channel()
        self.assertTrue(result['target_is_only_visible_signed_head'])
        self.assertEqual(result['target_signed_receipt_sequence'],2)

    def test_10_later_receipt_missing_predecessor_denied(self):
        self.token['ec349_receipt_original']=self.receipt_signed(seq=2,prev=self.receipt)
        self.denied()

    def test_11_later_receipt_wrong_previous_sha_denied(self):
        later=self.receipt_signed(seq=2,prev=self.receipt,overrides={
            'previous_statement_original_raw_sha256':'88'*32})
        self.token['ec349_receipt_original']=later
        self.row['signed_receipt_predecessor_originals']=[self.receipt]
        self.denied()

    def test_12_signed_two_sibling_heads_visible_and_adverse(self):
        sibling=self.receipt_signed(seq=1,overrides={'statement_nonce_sha256':'91'*32})
        self.row['signed_receipt_sibling_originals']=[sibling]
        result=self.run_channel()
        self.assertTrue(result['visible_signed_fork_or_nonhead'])
        self.assertEqual(len(result['visible_signed_receipt_head_shas']),2)

    def test_13_revocation_signed_is_not_erasure(self):
        later=self.receipt_signed(seq=2,prev=self.receipt,kind=old349.KINDS[2])
        self.row['signed_receipt_predecessor_originals']=[self.receipt]
        self.token['ec349_receipt_original']=later
        self.row['signed_time_witness_originals']=[self.witness_signed(later)]
        self.assertTrue(self.run_channel()['signed_revocation_at_target'])

    def test_14_wrong_receipt_witness_claim_even_with_true_signature(self):
        self.row['signed_time_witness_originals']=[self.witness_signed(self.receipt,
            {'time_actor_public_hex':self.actor('receipt')['public_hex']})]
        self.denied()

    def test_15_wrong_witness_signature_under_receipt_key(self):
        self.row['signed_time_witness_originals']=[self.witness_signed(self.receipt,
            role='receipt')]
        self.denied()

    def test_16_time_witness_missing_stays_unresolved_not_fake_verified(self):
        self.row['signed_time_witness_originals']=[]
        self.assertTrue(self.run_channel()['signed_time_witness_missing_or_disagrees'])

    def test_17_signed_witness_large_clock_difference_adverse(self):
        self.row['signed_time_witness_originals']=[self.witness_signed(self.receipt,{
            'claimed_observed_utc':stamp(self.now+timedelta(minutes=8))})]
        self.assertTrue(self.run_channel()['signed_time_witness_missing_or_disagrees'])

    def test_18_no_unpinned_keeper_head_inventory_claim_without_sources(self):
        bad=copy.deepcopy(self.heads)
        bad[0]['signed_receipt_count']=True
        self.token['ec349_receipt_original']=self.receipt_signed(
            overrides={'keeper_visible_heads':bad})
        self.denied()

    def test_19_root_receipt_time_actor_organization_reuse_denied(self):
        rc=self.actor('receipt');rc['organization_id']=self.actor('root')['organization_id']
        self.row['signed_channel_directory_original']=self.directory_signed({'receipt_actor':rc})
        self.denied()

    def test_20_unsigned_target_missing_ec348_replay_not_claimed_complete(self):
        checked=self.run_channel()
        self.assertFalse(checked['real_ec348_full_keeper_original_binding_matches'])
        self.assertEqual(checked['claimed_ec348_source_digest_sha256'],'41'*32)

    def test_20b_real_ec348_keeper_fork_receipt_count_up_to_six(self):
        # EC348 permits two signed siblings for each of three versions.
        heads=copy.deepcopy(self.heads)
        heads[0]['signed_receipt_count']=old348.MAX_VERSIONS*2
        heads[0]['multiple_signed_heads_are_unresolved_forks']=True
        self.token['ec349_receipt_original']=self.receipt_signed(overrides={
            'keeper_visible_heads':heads})
        self.row['signed_time_witness_originals']=[self.witness_signed(self.token['ec349_receipt_original'])]
        reviewed=self.run_channel()
        self.assertTrue(reviewed['actual_root_signed_directory_receipt_actor_authorization_verified'])
        self.assertFalse(reviewed['real_ec348_full_keeper_original_replay_performed'])

    def test_21_real_source_guard_does_not_follow_unpinned_sender_label(self):
        # EC348 full source must contain exact keys and safe receiver paths.
        ref=self.write('fake-ec348-parent-report.json',{'status':'success'})
        with self.assertRaises(errors.AnchorError):
            core._ec348_original(ref,self.read,set())

    def test_22_hidden_parent_injected_report_not_a_valid_receipt(self):
        self.token['ec349_receipt_original']=self.write('old-audit-report.json',
            {'schema':'ces.ec349.dual_channel_sha_time_audit_unresolved.v1'})
        self.denied()

    def test_23_no_parent_bundle_with_fake_success(self):
        with self.assertRaises(errors.AnchorError):
            core._parent({'schema':p380.RESULT_SCHEMA,'exit_code':0},1)

    def test_24_reject_receipt_on_wrong_channel(self):
        self.token['ec349_receipt_original']=self.receipt_signed(
            overrides={'channel_id':'OtherTsaChannel'})
        self.denied()

    def test_25_wrong_keeper_digest_in_signed_successor_rejected(self):
        later=self.receipt_signed(seq=2,prev=self.receipt,overrides={
          'keeper_signed_originals':[{'whole_original_raw_sha256':'99'*32,
                                      'independently_furnished_sha_pin_present':True}]})
        self.row['signed_receipt_predecessor_originals']=[self.receipt]
        self.token['ec349_receipt_original']=later
        self.denied()

    def test_26_time_witness_forged_as_arbitrary_extra_receipt(self):
        bad=self.witness_signed(self.receipt,{
            'receipt_original_raw_sha256':'81'*32})
        self.row['signed_time_witness_originals']=[bad]
        self.denied()


class MockedHistoricParentReceiver(GenuineEc349Bytes):
    """Actual EC349 signed originals, MOCK EC380 parent/source + CMS output.
    The production callsites remain real, are verified in isolated child only.
    """
    def _case(self):
        parent={'schema':p380.RESULT_SCHEMA,'exit_code':2,
                'sender_origin_path_required_or_read':False,
                'ec349_through_ec337_full_historical_parent_replay_performed':False,
                'local_signed_timestamp_and_revocation_inputs_consistent':True,
                'historical_timestamp_epoch_reviews':[{
                  'epoch_index':0,
                  'real_signed_rfc3161_token_and_ec349_receipt_imprint_count':1}]}
        lineage='HistoricLineageA'
        ec380=self.write('ec380-bundle.json',{
            'schema':p380.BUNDLE_SCHEMA,'claimed_directory_lineage_id':lineage,
            'parent_ec379_canonical_result_sha256':'41'*32,
            'ec379_historical_source_archive_original_sha256':'42'*32,
            'epochs':[{'epoch_index':0,'timestamps':[self.token]}]})
        source_root=self.write('source-root.cert',b'old-X509-test-placeholder')
        ec379=self.write('ec379-bundle.json',{
            'schema':p379.BUNDLE_SCHEMA,'claimed_directory_lineage_id':lineage,
            'parent_ec378_canonical_result_sha256':'43'*32,
            'ec378_historical_registry_archive_original_sha256':'44'*32,
            'epochs':[{'epoch_index':0,'sources':[{
              'tsa_channel_id':self.channel,
              'attester_public_key_original':{'path':'/fake-no-read-key','sha256':'51'*32},
              'tsa_root_certificate_original':source_root}]}]})
        sender=self.write('sender-labels.json',{'labels':[]})
        ec377=self.write('ec377-bundle.json',{
            'schema':p377.BUNDLE_SCHEMA,
            'claimed_directory_lineage_id':lineage,
            'parent_ec376_canonical_result_sha256':'62'*32,
            'ec376_historical_disclosure_archive_original_sha256':'63'*32,
            'epochs':[{'ec353_publication_bundle_original':sender,'logs':[]}]})
        ec381=self.write('ec381-receiver.json',{
            'schema':core.BUNDLE_SCHEMA,
            'parent_ec380_canonical_result_sha256':digest(canonical.canonical(parent)),
            'ec380_historical_timestamp_archive_original_sha256':ec380['sha256'],
            'claimed_directory_lineage_id':lineage,
            'epochs':[{'epoch_index':0,'channels':[self.row]}]})
        o={'historical_directory_root_shas':['61'*32],
           'institution_root_public_key_shas':['65'*32],
           'witness_public_key_shas':['66'*32],
           'expected_sender_public_key_sha256':'67'*32,
           'expected_receiver_public_key_sha256':'68'*32,
           'expected_publisher_public_key_sha256':'69'*32,
           'expected_publication_observer_public_key_sha256':'6a'*32,
           'detached_evaluation_utc':stamp(self.evaluation),
           'historical_timestamp_archive_bundle_file':ec380['path'],
           'expected_historical_timestamp_archive_bundle_sha256':ec380['sha256'],
           'historical_source_archive_bundle_file':ec379['path'],
           'expected_historical_source_archive_bundle_sha256':ec379['sha256'],
           'historical_transparency_archive_bundle_file':ec377['path'],
           'expected_historical_transparency_archive_bundle_sha256':ec377['sha256'],
           'historical_ec349_channel_archive_bundle_file':ec381['path'],
           'expected_historical_ec349_channel_archive_bundle_sha256':ec381['sha256'],
           'historical_ec349_authority_inventory_shas':['71'*32],
           'historical_ec349_witness_inventory_shas':['72'*32],
           'minimum_historical_ec349_signed_receipt_counts':[0],
           'minimum_historical_ec349_signed_witness_counts':[0],
           'expected_retained_historical_ec349_channel_inventory_sha256':'73'*32}
        return parent,o

    def _engine(self,derive=True,mutate=None):
        parent,opts=self._case()
        if mutate:mutate(parent,opts)
        with (patch.object(core,'_inputs',return_value={}),
              patch.object(p380,'audit',return_value=parent),
              patch.object(p379,'_source',return_value={'channel':self.channel,
                'binding':{'tsa_policy_oid':'1.2.3.4'},'attester_sha':'51'*32}),
              patch.object(core.old350,'_certificate',return_value=object()),
              patch.object(core.old350,'_tsa_token',return_value={'token_gen_time':self.now})):
            return core._engine(derive,**opts)

    def test_27_derive_real_directory_and_witness_under_mocked_parent(self):
        r=self._engine()
        self.assertEqual(r['exit_code'],2)
        self.assertEqual(r['real_signed_ec349_receipt_original_count'],1)
        self.assertEqual(r['real_signed_ec349_time_witness_original_count'],1)
        self.assertTrue(r[core.FLAGS[5]]) # lack of old EC348 originals remains unresolved
        self.assertFalse(r['local_root_authorized_receipt_witness_and_keeper_binding_consistent'])

    def test_28_unsigned_inventory_is_not_an_independent_pin(self):
        r=self._engine()
        self.assertFalse(r['caller_external_inventory_pin_created_or_certified'])
        self.assertEqual(r['schema'],core.DERIVE_SCHEMA)

    def test_29_missing_ec349_channel_is_observable(self):
        self.row={}  # a new signed EC381 archive with no channels
        def modify(parent,opts):
            # tamper the receiver archive as the hypothetical missing-source case
            from json import loads
            data=loads(Path(opts['historical_ec349_channel_archive_bundle_file']).read_bytes())
            data['epochs'][0]['channels']=[]
            ref=self.write('missing-receiver.json',data)
            opts['historical_ec349_channel_archive_bundle_file']=ref['path']
            opts['expected_historical_ec349_channel_archive_bundle_sha256']=ref['sha256']
        r=self._engine(mutate=modify)
        self.assertEqual(r['missing_ec349_channel_directory_count'],1)
        self.assertTrue(r[core.FLAGS[2]])

    def test_30_wrong_old_ec380_parent_digest_rejected(self):
        def modify(parent,opts):
            parent['exit_code']=0
        with self.assertRaises(errors.AnchorError):self._engine(mutate=modify)

    def test_31_retained_floor_disagreement_stays_adverse(self):
        r=self._engine()
        self.assertTrue(r[core.FLAGS[1]])

    def test_32_derived_inventory_sha_is_deterministic_for_pinned_originals(self):
        parent,opts=self._case()
        with (patch.object(core,'_inputs',return_value={}),
              patch.object(p380,'audit',return_value=parent),
              patch.object(p379,'_source',return_value={'channel':self.channel,
                'binding':{'tsa_policy_oid':'1.2.3.4'},'attester_sha':'51'*32}),
              patch.object(core.old350,'_certificate',return_value=object()),
              patch.object(core.old350,'_tsa_token',return_value={'token_gen_time':self.now})):
            first=core._engine(True,**opts)
            second=core._engine(True,**opts)
        self.assertEqual(first['receiver_verified_historical_ec349_channel_inventory_sha256'],
                         second['receiver_verified_historical_ec349_channel_inventory_sha256'])


    def _two_epoch_case(self,swap_history=False,replay_old=False):
        """Two actual EC349 signed original receipt chains; old audit/CMS mocked."""
        import json
        parent,opts=self._case()
        if swap_history:
            source=self.receipt_signed(seq=1,minutes=1)
        else:
            source=self.receipt
        second=source if replay_old else self.receipt_signed(seq=2,prev=source,minutes=2)
        earlier_witness=self.witness
        later_witness=self.witness_signed(second,{
            'claimed_observed_utc':stamp(self.now+timedelta(minutes=2))})
        newrow=copy.deepcopy(self.row)
        newrow['signed_receipt_predecessor_originals']=[] if replay_old else [source]
        newrow['signed_time_witness_originals']=[later_witness]
        newtoken=copy.deepcopy(self.token)
        newtoken['ec349_receipt_original']=second
        replacements=(
          ('historical_timestamp_archive_bundle_file',
           'expected_historical_timestamp_archive_bundle_sha256',
           lambda d:d['epochs'].append({'epoch_index':1,'timestamps':[newtoken]})),
          ('historical_source_archive_bundle_file',
           'expected_historical_source_archive_bundle_sha256',
           lambda d:d['epochs'].append(dict(d['epochs'][0],epoch_index=1))),
          ('historical_transparency_archive_bundle_file',
           'expected_historical_transparency_archive_bundle_sha256',
           lambda d:d['epochs'].append(copy.deepcopy(d['epochs'][0]))),
        )
        for pathkey,shakey,mutation in replacements:
            d=json.loads(Path(opts[pathkey]).read_bytes())
            mutation(d)
            ref=self.write('two-epoch-updated-original.json',d)
            opts[pathkey]=ref['path'];opts[shakey]=ref['sha256']
        parent['historical_timestamp_epoch_reviews'].append({
            'epoch_index':1,
            'real_signed_rfc3161_token_and_ec349_receipt_imprint_count':1})
        pathkey='historical_ec349_channel_archive_bundle_file'
        shakey='expected_historical_ec349_channel_archive_bundle_sha256'
        d=json.loads(Path(opts[pathkey]).read_bytes())
        d['epochs'].append({'epoch_index':1,'channels':[newrow]})
        d['parent_ec380_canonical_result_sha256']=digest(canonical.canonical(parent))
        d['ec380_historical_timestamp_archive_original_sha256']=opts[
            'expected_historical_timestamp_archive_bundle_sha256']
        ref=self.write('two-epoch-ec381-receiver-archive.json',d)
        opts[pathkey]=ref['path'];opts[shakey]=ref['sha256']
        opts['historical_directory_root_shas'].append('62'*32)
        for key in ('historical_ec349_authority_inventory_shas',
                    'historical_ec349_witness_inventory_shas',
                    'minimum_historical_ec349_signed_receipt_counts',
                    'minimum_historical_ec349_signed_witness_counts'):
            opts[key].append(opts[key][0])
        return parent,opts

    def _engine_two_epochs(self,swap_history=False,replay_old=False):
        parent,opts=self._two_epoch_case(swap_history,replay_old)
        with (patch.object(core,'_inputs',return_value={}),
              patch.object(p380,'audit',return_value=parent),
              patch.object(p379,'_source',return_value={'channel':self.channel,
                'binding':{'tsa_policy_oid':'1.2.3.4'},'attester_sha':'51'*32}),
              patch.object(core.old350,'_certificate',return_value=object()),
              patch.object(core.old350,'_tsa_token',return_value={'token_gen_time':self.now})):
            return core._engine(True,**opts)

    def test_33_two_real_signed_epoch_receipts_have_real_continuity(self):
        result=self._engine_two_epochs()
        self.assertEqual(len(result['historical_ec349_channel_epoch_reviews']),2)
        self.assertEqual(result['real_signed_ec349_receipt_original_count'],3)
        self.assertFalse(result[core.FLAGS[6]])

    def test_34_two_epoch_alternate_branch_does_not_satisfy_prior_epoch(self):
        result=self._engine_two_epochs(swap_history=True)
        self.assertTrue(result[core.FLAGS[6]])
        self.assertEqual(result['real_signed_ec349_receipt_original_count'],3)

    def test_35_two_epoch_same_old_original_is_not_false_new_epoch(self):
        result=self._engine_two_epochs(replay_old=True)
        self.assertTrue(result[core.FLAGS[6]])

if __name__=='__main__':unittest.main()
