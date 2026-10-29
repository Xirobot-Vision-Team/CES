#!/usr/bin/env python3
"""EC357 local signed source-review functional cases (synthetic signers only).

Each exercised audit genuinely replays EC356 through EC337. No external
institution, physical site, authoritative UTC, or native PS result is implied.
"""
from __future__ import annotations
from datetime import timedelta
from pathlib import Path
import unittest
import os
import json
import subprocess
import sys
from cryptography.hazmat.primitives.asymmetric import ed25519
from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec353_transparency import test_transparency as tr
from ec356_custody import custody as parent
from ec356_custody import test_custody as old
from . import provenance as core

class ProvenanceTests(old.CustodyTests):
    for _name in dir(old.CustodyTests):
        if _name.startswith('test_'):locals()[_name]=None

    def setUp(self):
        super().setUp()
        self.source_reviews={}

    def setup357(self):
        self.prepare356()
        self.custody_args=self.args356()
        self.verified356=parent.audit(**self.custody_args)
        self.assertTrue(self.verified356['two_channel_cross_role_exact_original_quorum_for_all_claims'])
        for slot in ('a','b'):self.add_source(slot)

    def add_source(self,slot,*,private=None,body_override=None):
        private=private or ed25519.Ed25519PrivateKey.generate()
        pub=self.write353('ec357-source-'+slot+'-pub',tr.pub(private))
        channels={x['slot']:x for x in self.verified356['channel_establishments']}
        roots=[{'slot':s,'institution_id':r['institution_id'],
                'claimed_legal_entity_id':'legal_'+s,
                'root_public_key_original_sha256':r['root_public_key_original_sha256'],
                'root_state':'active','replacement_root_public_key_sha256':None,
                'root_state_effective_utc':None,
                'declared_physical_site_id':r['claimed_physical_site_id']}
               for s,r in sorted(channels.items())]
        inventory=[];copies=[]
        for channel_slot in ('a','b'):
            for ack in self.custody_channels[channel_slot]['manifest']['acknowledgements']:
                receipt_sha=self._receipt_of_ack(ack)
                cp=ack['checkpoint_original'];wit=ack['witness_original']
                invoice={'slot':channel_slot,'ec355_receipt_original_sha256':receipt_sha,
                         'checkpoint_original_sha256':cp['sha256'],
                         'checkpoint_length':len(Path(cp['path']).read_bytes()),
                         'witness_original_sha256':wit['sha256'],
                         'witness_length':len(Path(wit['path']).read_bytes()),
                         'declared_site_id':channels[channel_slot]['claimed_physical_site_id'],
                         'availability':'present'}
                inventory.append(invoice)
                copies.append({'slot':channel_slot,
                               'ec355_receipt_original_sha256':receipt_sha,
                               'checkpoint_original':self.write353('ec357-copy-'+slot+'-cp',
                                                      Path(cp['path']).read_bytes()),
                               'witness_original':self.write353('ec357-copy-'+slot+'-wit',
                                                      Path(wit['path']).read_bytes())})
        body={'schema':core.SOURCE_SCHEMA,'source_id':'external_review_'+slot,
              'source_authority_public_key_original_sha256':pub['sha256'],
              'ec356_custody_bundle_original_sha256':self.custody_args[
                   'expected_custody_bundle_sha256'],
              'parent_ec356_canonical_result_sha256':core.sha(
                   canonical.canonical(self.verified356)),
              'issued_utc':tr.ut(self.now+timedelta(hours=3,minutes=5)),
              'expires_utc':tr.ut(self.now+timedelta(days=2)),
              'root_records':roots,'inventory_records':inventory}
        if body_override:body.update(body_override)
        record={'private':private,'pub':pub,'body':body,'copies':copies}
        self.source_reviews[slot]=record
        self.resign(slot)
        return record

    def _receipt_of_ack(self,ack):
        import json
        data=json.loads(Path(ack['acknowledgement']['path']).read_text())
        return data['ec355_receipt_original_sha256']

    def resign(self,slot):
        record=self.source_reviews[slot]
        record['signed']=self.signed('ec357-source-review-'+slot,record['body'],
                                      record['private'],core.SOURCE_DOMAIN)

    def args357(self,**changes):
        sources=[{'slot':slot,'source_authority_public_key':review['pub'],
                  'signed_source_review':review['signed'],
                  'inventory_copies':review['copies']}
                 for slot,review in sorted(self.source_reviews.items())]
        bundle=self.write353('ec357-imported-source-bundle',{
            'schema':core.BUNDLE_SCHEMA,'sources':sources})
        a=self.source_reviews.get('a');b=self.source_reviews.get('b')
        return {**self.custody_args,
                'provenance_review_evaluation_utc':tr.ut(self.now+timedelta(hours=4)),
                'provenance_review_bundle_file':bundle['path'],
                'expected_provenance_review_bundle_sha256':bundle['sha256'],
                'source_a_authority_public_key_file':a['pub']['path'] if a else None,
                'expected_source_a_authority_public_key_sha256':a['pub']['sha256'] if a else None,
                'source_b_authority_public_key_file':b['pub']['path'] if b else None,
                'expected_source_b_authority_public_key_sha256':b['pub']['sha256'] if b else None,
                **changes}

    def result357(self,**changes):return core.audit(**self.args357(**changes))

    def denied(self,code,**changes):
        with self.assertRaises(errors.AnchorError) as caught:
            self.result357(**changes)
        self.assertIn(code,caught.exception.code)

    def test_01_two_real_signed_source_inventory_copies_not_external_identity_proof(self):
        self.setup357();r=self.result357()
        self.assertEqual(r['exit_code'],2)
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[-1])
        self.assertEqual(r['source_review_count'],2)
        self.assertEqual(r['verified_ec356_custody_original_count'],2)
        self.assertTrue(r['both_source_copies_match_ec356_parent_for_all_signed_eligible_receipts'])
        self.assertTrue(r['externally_authenticated_source_identity_and_physical_custody_unproven'])
        self.assertFalse(r['two_signed_source_reviews_prove_independent_legal_institutions'])

    def test_02_missing_independent_second_source_visible(self):
        self.setup357();self.source_reviews.pop('b')
        r=self.result357()
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[1])
        self.assertTrue(r['missing_source_root_record_or_original_copy_visible'])

    def test_03_no_source_bundle_is_unresolved_not_automatic_approval(self):
        self.setup357()
        r=self.result357(provenance_review_bundle_file=None,
                         expected_provenance_review_bundle_sha256=None)
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[1])

    def test_04_genuinely_signed_revocation_visible(self):
        self.setup357()
        row=self.source_reviews['b']['body']['root_records'][0]
        row.update(root_state='revoked',root_state_effective_utc=tr.ut(self.now),
                   replacement_root_public_key_sha256=None)
        self.resign('b')
        r=self.result357()
        self.assertTrue(r['signed_revocation_or_rotation_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[2])

    def test_05_genuinely_signed_root_rotation_visible(self):
        self.setup357()
        row=self.source_reviews['a']['body']['root_records'][1]
        row.update(root_state='rotated',root_state_effective_utc=tr.ut(self.now),
                   replacement_root_public_key_sha256='8'*64)
        self.resign('a')
        self.assertEqual(self.result357()['channel_evidence'][0]['outcome'],core.OUTCOMES[2])

    def test_06_cross_source_signed_institution_mapping_conflict_visible(self):
        self.setup357()
        self.source_reviews['b']['body']['root_records'][0]['claimed_legal_entity_id']='different_legal_a'
        self.resign('b')
        self.assertEqual(self.result357()['channel_evidence'][0]['outcome'],core.OUTCOMES[3])

    def test_07_two_roots_alleged_same_legal_entity_cannot_prove_two_independents(self):
        self.setup357()
        for slot in ('a','b'):
            self.source_reviews[slot]['body']['root_records'][1]['claimed_legal_entity_id']='legal_a'
            self.resign(slot)
        r=self.result357()
        self.assertTrue(r['signed_root_identity_or_source_collision_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[3])

    def test_08_wrong_but_genuinely_signed_inventory_bytes_visible_as_conflict(self):
        self.setup357()
        rec=self.source_reviews['a']
        cp=rec['copies'][0]['checkpoint_original']
        altered=self.write353('ec357-wrong-original',b'SIGNED-BUT-WRONG-CHECKPOINT')
        rec['copies'][0]['checkpoint_original']=altered
        inventory=rec['body']['inventory_records'][0]
        inventory['checkpoint_original_sha256']=altered['sha256']
        inventory['checkpoint_length']=len(Path(altered['path']).read_bytes())
        self.resign('a')
        r=self.result357()
        self.assertTrue(r['signed_inventory_conflicts_with_ec356_or_other_source_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[4])

    def test_09_signed_unavailable_inventory_not_present_original(self):
        self.setup357()
        rec=self.source_reviews['b'];rec['body']['inventory_records'][0]['availability']='unavailable'
        rec['copies'].pop(0)
        self.resign('b')
        r=self.result357()
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[4])
        self.assertFalse(r['both_source_copies_match_ec356_parent_for_all_signed_eligible_receipts'])

    def test_10_signed_present_without_actual_copy_not_promotion(self):
        self.setup357();self.source_reviews['b']['copies'].pop(1)
        r=self.result357()
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[5])

    def test_11_source_signer_mismatch_denied(self):
        self.setup357()
        self.source_reviews['b']['private']=self.source_reviews['a']['private']
        self.resign('b')
        self.denied('REAL_SIGNATURE_INVALID')

    def test_12_source_key_reusing_ec356_channel_signer_denied(self):
        self.setup357()
        rec=self.source_reviews['b'];rec['private']=self.custody_channels['b']['private']
        rec['pub']=self.write353('ec357-channel-reused',tr.pub(rec['private']))
        rec['body']['source_authority_public_key_original_sha256']=rec['pub']['sha256']
        self.resign('b')
        self.denied('SOURCE_SIGNER_KEY_REUSES_PARENT')

    def test_13_source_parent_binding_is_genuinely_signed_and_must_match_replayed(self):
        self.setup357()
        self.source_reviews['a']['body']['parent_ec356_canonical_result_sha256']='1'*64
        self.resign('a')
        self.denied('SIGNATURE_MUST_BIND_ACTUAL_EC356_REPLAY')

    def test_14_modified_custodian_copied_byte_must_be_denied(self):
        self.setup357()
        cp=self.source_reviews['a']['copies'][0]['checkpoint_original']
        Path(cp['path']).write_bytes(b'BYTES-CHANGED-AFTER-PIN')
        self.denied('WHOLE_ORIGINAL_SHA_MISMATCH')

    def test_15_duplicate_signed_inventory_roles_denied(self):
        self.setup357()
        rec=self.source_reviews['b']
        rec['body']['inventory_records'].append(dict(rec['body']['inventory_records'][0]))
        self.resign('b')
        self.denied('SIGNED_INVENTORY_ROLE_DUPLICATE')

    def test_16_signed_stale_time_is_not_trusted_utc_or_silent_success(self):
        self.setup357()
        self.source_reviews['a']['body']['expires_utc']=tr.ut(self.now+timedelta(hours=3,minutes=30))
        self.resign('a')
        r=self.result357()
        self.assertTrue(r['stale_or_future_self_claimed_source_utc_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[6])

    def test_17_source_claimed_site_collides_with_other_signer(self):
        self.setup357()
        self.source_reviews['b']['body']['root_records'][0]['declared_physical_site_id']='bad_site'
        self.resign('b')
        self.assertEqual(self.result357()['channel_evidence'][0]['outcome'],core.OUTCOMES[3])

    def test_18_missing_signed_root_coverage_visible(self):
        self.setup357();self.source_reviews['a']['body']['root_records'].pop()
        self.resign('a')
        r=self.result357()
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[5])

    def test_19_old_ec356_original_path_cannot_masquerade_as_external_copy(self):
        self.setup357()
        self.source_reviews['a']['copies'][0]['checkpoint_original']=(
            self.custody_channels['a']['manifest']['acknowledgements'][0]['checkpoint_original'])
        self.denied('NEW_ROLE_OR_PARENT_ORIGINAL_PATH_ALIAS')

    def test_20_single_root_reused_as_both_source_pins_denied(self):
        self.setup357()
        self.denied('SOURCES_REQUIRE_TWO_DIFFERENT_CALLER_PINS',
                    source_b_authority_public_key_file=self.source_reviews['a']['pub']['path'],
                    expected_source_b_authority_public_key_sha256=self.source_reviews['a']['pub']['sha256'])

    def test_21_nested_ec355_historical_checkpoint_path_cannot_masquerade_as_external_copy(self):
        self.setup357()
        self.source_reviews['a']['copies'][0]['checkpoint_original']=(
            self.requests[0]['responses'][0]['checkpoint'])
        self.denied('NEW_ROLE_OR_PARENT_ORIGINAL_PATH_ALIAS')

    def test_22_parent_auditor_public_key_cannot_be_external_authority(self):
        self.setup357()
        rec=self.source_reviews['a'];rec['private']=self.actors['auditor_a']['private']
        rec['pub']=self.write353('ec357-old-auditor-reused',tr.pub(rec['private']))
        rec['body']['source_authority_public_key_original_sha256']=rec['pub']['sha256']
        self.resign('a')
        self.denied('SOURCE_SIGNER_KEY_REUSES_PARENT')

    def test_23_hardlinked_old_custody_inode_not_independent_external_copy(self):
        self.setup357()
        oldfile=self.custody_channels['a']['manifest']['acknowledgements'][0]['checkpoint_original']
        alias=Path(self.w)/'ec357-hardlinked-original'
        os.link(oldfile['path'],alias)
        self.source_reviews['a']['copies'][0]['checkpoint_original']={'path':str(alias),'sha256':oldfile['sha256']}
        self.denied('HARDLINK_ORIGINAL_INODE_ALIAS')

    def test_24_parent_ec356_missing_genuine_byte_custody_never_repaired_by_missing_reviews(self):
        self.prepare356()
        self.custody_channels['b']['manifest']['acknowledgements']=[]
        self.add_ack('b',1,kind='sha_claim_only')
        inputs=self.args356()
        r=core.audit(**inputs,provenance_review_evaluation_utc=tr.ut(self.now+timedelta(hours=4)))
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[0])
        self.assertFalse(r['both_source_copies_match_ec356_parent_for_all_signed_eligible_receipts'])

    def test_25_unified_fixed_readonly_route_real_subprocess(self):
        self.setup357();inputs=self.args357()
        sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
        import ces_next as router
        repeat_flags=dict(router.EC357_REPEATS)
        # Exercise the production router, NOT a mocked adapter or cached result.
        cmd=[sys.executable,'-B',str(Path(__file__).resolve().parents[2]/'scripts'/'ces_next.py'),
             'audit-institution-provenance','DeliveryAudit','AuditInstitutionProvenance']
        for key,value in inputs.items():
            flag=repeat_flags.get(key,'--'+key.replace('_','-'))
            if type(value) is list:
                for item in value:cmd.extend([flag,str(item)])
            elif value is not None:cmd.extend([flag,str(value)])
        proc=subprocess.run(cmd,capture_output=True,text=True,timeout=50)
        self.assertEqual(proc.returncode,2,proc.stderr+' '+proc.stdout[-500:])
        self.assertTrue(proc.stdout,proc.stderr[:1000])
        doc=json.loads(proc.stdout)
        self.assertEqual(doc['schema'],core.RESULT_SCHEMA)
        self.assertEqual(doc['channel_evidence'][0]['outcome'],core.OUTCOMES[-1])

    def test_26_signed_review_without_exact_bundle_original_sha_denied(self):
        self.setup357()
        self.source_reviews['b']['body']['ec356_custody_bundle_original_sha256']='a'*64
        self.resign('b')
        self.denied('SIGNATURE_MUST_BIND_ACTUAL_EC356_REPLAY')

if __name__=='__main__':unittest.main()
