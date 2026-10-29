#!/usr/bin/env python3
"""EC374 focused true EC357 + EC358 Ed25519 original signature checks.

Parent EC373->EC369 is genuinely replayed by the real child-process cases.
The *inherited deeper* EC366->EC337 predecessor in the EC367 test fixture
is deliberately MOCKED: these tests do not prove full historical parent replay.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ed25519
from delivery_anchor import anchor as errors
from offline_transfer_registry import registry as canonical
from provenance import provenance as ec357
from reviewer_epochs import epochs as ec358
from authority_directory import authority as ec360
from witness_distribution import test_distribution as util
from historical_inclusion import test_inclusion_archive as t373
from . import owner_archive as core

ROOT=Path(__file__).resolve().parents[2]


class ReceiverHistoricalRealOwnerAndReviewerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        t373.ReceiverHistoricalRealInclusionAndIssuerTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        t373.ReceiverHistoricalRealInclusionAndIssuerTests.tearDownClass()

    def setUp(self):
        self.ec373=t373.ReceiverHistoricalRealInclusionAndIssuerTests(
                     'test_01_genuine_ec360_merkle_and_ec359_signatures')
        old_construct=self.ec373.construct_ec359_and_resign_root_authority
        def build_preceding_real_ec358():
            self.prepare_genuine_ec357_and_ec358_originals()
            keys=iter(self.owners[slot] for slot in ('a','b'))
            with patch.object(ed25519.Ed25519PrivateKey,'generate',
                              side_effect=lambda:next(keys)):
                old_construct()
        self.ec373.construct_ec359_and_resign_root_authority=build_preceding_real_ec358
        self.ec373.setUp()
        self.addCleanup(self.ec373.doCleanups)
        self.old=self.ec373.old
        self.parent=self.ec373.audit()  # real EC373 signatures, deeper parent fixture mock
        self.make_bundle()

    def store(self,name,doc):return self.ec373.stored(name,doc)

    def prepare_genuine_ec357_and_ec358_originals(self):
        self.old=self.ec373.old
        self.owners={};self.reviewers={};self.reviewrefs={};self.events={}
        for slot in ('a','b'):
            owner=ed25519.Ed25519PrivateKey.generate()
            reviewer=ed25519.Ed25519PrivateKey.generate()
            self.owners[slot]=owner;self.reviewers[slot]=reviewer
            keyref=self.store('ec374_genuine_old_reviewer_'+slot,util.pub(reviewer))
            oldmanifest=json.loads(Path(self.old.rows[0][
                'source_'+slot+'_manifest_original']['path']).read_text())
            self.sourceid=oldmanifest['claimed_source_id']
            source_id=oldmanifest['claimed_source_id']
            body={'schema':ec357.SOURCE_SCHEMA,'source_id':source_id,
                  'source_authority_public_key_original_sha256':keyref['sha256'],
                  'ec356_custody_bundle_original_sha256':'d'*64,
                  'parent_ec356_canonical_result_sha256':'c'*64,
                  'issued_utc':util.UTC,'expires_utc':util.EXP,
                  'root_records':[],'inventory_records':[]}
            if getattr(self,'revoked_source',None)==slot:
                body['root_records']=[{
                   'slot':slot,'institution_id':'HistoricInstitute'+slot.upper(),
                   'claimed_legal_entity_id':'HistoricLegal'+slot.upper(),
                   'declared_physical_site_id':'HistoricSite'+slot.upper(),
                   'root_public_key_original_sha256':self.ec373.base.roles[
                       slot]['root_ref']['sha256'],
                   'root_state':'revoked',
                   'replacement_root_public_key_sha256':None,
                   'root_state_effective_utc':util.UTC}]
            review=self.ec373.signed('ec374_real_source_review_'+slot,body,
                reviewer,ec357.SOURCE_DOMAIN,'signature_ed25519_hex')
            self.reviewrefs[slot]={'key':keyref,'signed':review,'source_id':source_id}
            event_body={'schema':ec358.EVENT_SCHEMA,'slot':slot,
                  'source_id':source_id,
                  'claimed_owner_id':'HistoricOwner'+slot.upper(),
                  'owner_public_key_original_sha256':core.sha(util.pub(owner)),
                  'parent_ec357_canonical_result_sha256':'e'*64,
                  'parent_source_review_original_sha256':review['sha256'],
                  'epoch':0,'previous_event_original_sha256':None,
                  'operation':'issue',
                  'previous_reviewer_public_key_original_sha256':None,
                  'current_reviewer_public_key_original_sha256':keyref['sha256'],
                  'issued_utc':util.UTC,'expires_utc':util.EXP}
            signed=self.make_event_signatures(event_body,owner,None,reviewer)
            eref=self.store('ec374_real_owner_issued_'+slot,signed)
            self.events[slot]={'issue':eref,
                'pin':{'event_original':eref,'previous_reviewer_public_key_original':None,
                       'current_reviewer_public_key_original':keyref}}
            # EC373 itself genuinely rebuilds/signs EC359, EC360 delegation,
            # origin, root revocation, EC362 manifest and EC365 handoffs.
            # Give it the real signed EC358 event SHA before those signatures.
            role=self.ec373.base.roles[slot]
            old=json.loads(Path(role['delegation']['path']).read_text())
            old.pop('signature_root_ed25519_hex')
            old['parent_owner_head_event_sha256']=eref['sha256']
            role['delegation']=self.ec373.signed(
              'ec374_pre_ec359_real_ec358_head_'+slot,old,role['root'],
               ec360.DELEGATION_DOMAIN,'signature_root_ed25519_hex')

    def make_event_signatures(self,body,owner,previous,current):
        payload=canonical.canonical(body)
        return {**body,
          'signature_owner_ed25519_hex':owner.sign(
                 ec358.DOMAINS['owner']+payload).hex(),
          'signature_previous_reviewer_ed25519_hex':(
                previous.sign(ec358.DOMAINS['previous']+payload).hex()
                if previous is not None else None),
          'signature_current_reviewer_ed25519_hex':(
                current.sign(ec358.DOMAINS['current']+payload).hex()
                if current is not None else None)}

    def make_bundle(self):
        self.rows=[]
        for i in range(2):
            epoch={'epoch_index':i,
                   'signed_parent_ec357_canonical_result_sha256':'e'*64}
            for slot in ('a','b'):
                review=self.reviewrefs[slot]
                epoch['source_'+slot]={
                  'owner_public_key_original':self.ec373.distribution[slot]['owner'],
                  'claimed_owner_id':'HistoricOwner'+slot.upper(),
                  'claimed_source_id':review['source_id'],
                  'source_review_public_key_original':review['key'],
                  'source_review_signed_original':review['signed'],
                  'signed_parent_ec356_canonical_result_sha256':'c'*64,
                  'signed_ec356_custody_bundle_original_sha256':'d'*64,
                  'reviewer_epoch_events':[self.events[slot]['pin']],
                  'selected_owner_epoch_head_sha256':self.events[slot]['issue']['sha256']}
            self.rows.append(epoch)
        self.rebuild()

    def rebuild(self):
        self.bundle=self.store('ec374_receiver_real_owner_archive',{
          'schema':core.BUNDLE_SCHEMA,
          'parent_ec373_canonical_result_sha256':core.sha(canonical.canonical(self.parent)),
          'ec373_historical_inclusion_bundle_original_sha256':self.ec373.bundle['sha256'],
          'claimed_directory_lineage_id':self.old.lineage,
          'epochs':self.rows})

    def options(self,**kw):
        p=self.ec373.options()
        p['expected_retained_historical_inclusion_inventory_sha256']=self.ec373.derive()[
                    'receiver_verified_historical_inclusion_inventory_sha256']
        p.update(historical_owner_epoch_bundle_file=self.bundle['path'],
              expected_historical_owner_epoch_bundle_sha256=self.bundle['sha256'],
              historical_owner_a_head_shas=[self.events['a']['issue']['sha256']]*2,
              historical_owner_b_head_shas=[self.events['b']['issue']['sha256']]*2,
              minimum_historical_owner_a_epochs=[0,0],
              minimum_historical_owner_b_epochs=[0,0],
              historical_reviewer_a_key_shas=[self.reviewrefs['a']['key']['sha256']]*2,
              historical_reviewer_b_key_shas=[self.reviewrefs['b']['key']['sha256']]*2)
        return {**p,**kw}

    def derive(self,**kw):
        with patch.object(core.prior,'audit',return_value=self.parent):
            return core.derive_inventory(**self.options(**kw))

    def audit(self,**kw):
        p=self.options(expected_retained_historical_owner_inventory_sha256=self.derive()[
                            'receiver_verified_historical_owner_inventory_sha256'])
        p.update(kw)
        with patch.object(core.prior,'audit',return_value=self.parent):
            return core.audit(**p)

    def extra_event(self,slot,operation='revoke',new_reviewer=None):
        signed=json.loads(Path(self.events[slot]['issue']['path']).read_text())
        for k in ec358.SIGNATURE_FIELDS.values():signed.pop(k)
        reviewer_ref=self.reviewrefs[slot]['key']
        if operation=='rotate':
            new_reviewer=new_reviewer or ed25519.Ed25519PrivateKey.generate()
            fresh=self.store('ec374_new_reviewer_'+slot,util.pub(new_reviewer))
        else:fresh=None
        signed.update(epoch=1,operation=operation,
             previous_event_original_sha256=self.events[slot]['issue']['sha256'],
             previous_reviewer_public_key_original_sha256=reviewer_ref['sha256'],
             current_reviewer_public_key_original_sha256=(
                    fresh['sha256'] if fresh is not None else None))
        ref=self.store('ec374_real_'+operation+'_extra_'+slot,
             self.make_event_signatures(signed,self.owners[slot],
                                self.reviewers[slot],new_reviewer))
        return {'event_original':ref,
              'previous_reviewer_public_key_original':reviewer_ref,
              'current_reviewer_public_key_original':fresh}

    def test_01_original_ec357_and_ec358_signatures_and_parent_link(self):
        d=self.audit()
        self.assertTrue(d['local_pinned_historical_owner_reviewer_slice_consistent'])
        self.assertEqual(d['verified_real_ec357_source_review_signature_count'],4)
        self.assertEqual(d['verified_real_ec358_owner_epoch_event_count'],4)
        self.assertEqual(d['exit_code'],2)
        self.assertTrue(d[core.FLAGS[-1]])
        self.assertFalse(d['actual_ec357_or_ec358_canonical_result_recomputed_from_old_original_inputs'])

    def test_02_true_owner_signed_bytes_tampered_denied(self):
        Path(self.events['a']['issue']['path']).write_bytes(b'TAMPERED_OLD_EC358')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_03_invalid_owner_signature_denied(self):
        row=self.rows[0]['source_a'];ref=self.events['a']['issue']
        data=json.loads(Path(ref['path']).read_text())
        data['signature_owner_ed25519_hex']='f'*128
        row['reviewer_epoch_events'][0]['event_original']=self.store('invalid_owner_sig',data)
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_04_invalid_current_reviewer_signature_denied(self):
        data=json.loads(Path(self.events['a']['issue']['path']).read_text())
        data['signature_current_reviewer_ed25519_hex']='f'*128
        self.rows[0]['source_a']['reviewer_epoch_events'][0]['event_original']=self.store(
             'invalid_current_sig',data)
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_05_genuine_ec357_source_review_sig_tamper_denied(self):
        Path(self.reviewrefs['b']['signed']['path']).write_bytes(b'ALTERED_SOURCE_REVIEW')
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_06_genuine_ec357_false_signer_denied(self):
        row=self.rows[0]['source_a'];orig=self.reviewrefs['a']['signed']
        bad=json.loads(Path(orig['path']).read_text())
        bad['signature_ed25519_hex']='a'*128
        row['source_review_signed_original']=self.store('forged_ec357_review',bad)
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_07_missing_signed_genesis_denied(self):
        revoke=self.extra_event('a')
        self.rows[0]['source_a']['reviewer_epoch_events']=[revoke]
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_08_duplicate_signed_original_denied(self):
        row=self.rows[0]['source_b'];row['reviewer_epoch_events'].append(copy.deepcopy(
                            row['reviewer_epoch_events'][0]))
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_09_valid_real_revoke_visible_not_clean(self):
        row=self.rows[0]['source_a'];row['reviewer_epoch_events'].append(
                                    self.extra_event('a'))
        self.rebuild()
        self.assertTrue(self.audit()[core.FLAGS[2]])

    def test_10_valid_real_reviewer_rotation_visible_not_overridden(self):
        row=self.rows[0]['source_b'];row['reviewer_epoch_events'].append(
                                    self.extra_event('b','rotate'))
        self.rebuild()
        self.assertTrue(self.audit()[core.FLAGS[2]] or self.audit()[core.FLAGS[3]])

    def test_11_wrong_real_ec359_signed_owner_head_denied(self):
        self.rows[0]['source_a']['selected_owner_epoch_head_sha256']='f'*64
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_12_old_owner_public_key_not_ec373_issuer_owner_denied(self):
        self.rows[0]['source_a']['owner_public_key_original']=self.reviewrefs['a']['key']
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_13_changed_signed_ec357_parent_claim_denied(self):
        self.rows[0]['signed_parent_ec357_canonical_result_sha256']='b'*64
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_14_reviewed_source_id_mismatch_denied(self):
        self.rows[1]['source_b']['claimed_source_id']='IMPOSTOR'
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_15_valid_external_head_rollback_visible(self):
        self.assertTrue(self.audit(historical_owner_a_head_shas=['f'*64]*2)[core.FLAGS[1]])

    def test_16_independent_epoch_floor_not_met_visible(self):
        self.assertTrue(self.audit(minimum_historical_owner_b_epochs=[1,1])[core.FLAGS[1]])

    def test_17_reviewer_independent_key_pin_disagrees_visible(self):
        self.assertTrue(self.audit(historical_reviewer_a_key_shas=['f'*64]*2)[core.FLAGS[1]])

    def test_18_external_inventory_sha_mismatch_visible(self):
        self.assertTrue(self.audit(expected_retained_historical_owner_inventory_sha256=
                                   'f'*64)[core.FLAGS[1]])

    def test_19_signed_old_ec357_revocation_visible(self):
        row=self.rows[0]['source_a']
        ref=row['source_review_signed_original']
        data=json.loads(Path(ref['path']).read_text())
        data.pop('signature_ed25519_hex')
        data['root_records']=[{'slot':'a','institution_id':'LegacyInstitutionA',
           'claimed_legal_entity_id':'LegacyLegalA','declared_physical_site_id':'SiteA',
           'root_public_key_original_sha256':self.ec373.base.roles['a']['root_ref']['sha256'],
           'root_state':'revoked','replacement_root_public_key_sha256':None,
           'root_state_effective_utc':util.UTC}]
        row['source_review_signed_original']=self.ec373.signed(
            'ec374_root_review_revoked',data,self.reviewers['a'],
            ec357.SOURCE_DOMAIN,'signature_ed25519_hex')
        # The true EC358 event SHA-binding still points to original review;
        # replacing one reference is not enough and must be denied.
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_19b_genuinely_signed_old_ec357_root_revoke_stays_adverse(self):
        # Establish an entirely new fixture whose EC357 revocation is signed
        # BEFORE every EC358 owner event and EC359/EC360/EC365 descendant is
        # re-signed. This is not an unsigned edit to an old SHA claim.
        self.ec373.doCleanups()
        self.revoked_source='a'
        self.ec373.setUp()
        self.old=self.ec373.old
        self.parent=self.ec373.audit()
        self.make_bundle()
        result=self.audit()
        self.assertTrue(result[core.FLAGS[4]])
        self.assertFalse(result['local_pinned_historical_owner_reviewer_slice_consistent'])

    def test_19c_reviewer_must_not_reuse_old_issuer_signer_role(self):
        self.rows[0]['source_a']['source_review_public_key_original']=self.ec373.base.roles[
             'a']['issuer_ref']
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_20_old_unopened_source_copy_role_is_never_opened(self):
        label=json.loads(Path(self.old.rows[0]['source_a_manifest_original'][
                      'path']).read_text())['copies']['checkpoint']['path']
        self.rows[0]['source_a']['source_review_public_key_original']={
                 'path':label,'sha256':self.reviewrefs['a']['key']['sha256']}
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()
        self.assertFalse(Path(label).exists())

    def test_21_invalid_exact_bundle_schema_denied(self):
        self.rows[0]['source_a']['extra_unsafe_field']='untrusted'
        self.rebuild()
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_22_unsigned_inventory_digest_is_canonical(self):
        doc=self.derive()
        self.assertFalse(doc['caller_external_inventory_pin_created_or_certified'])
        self.assertEqual(doc['receiver_verified_historical_owner_inventory_sha256'],
            core.sha(canonical.canonical(doc['unsigned_verified_historical_owner_inventory'])))

    def test_23_false_parent_live_sha_denied(self):
        document=json.loads(Path(self.bundle['path']).read_text())
        document['parent_ec373_canonical_result_sha256']='f'*64
        self.bundle=self.store('false_ec373_live_sha',document)
        with self.assertRaises(errors.AnchorError):self.derive()

    def test_24_current_receiver_never_reads_signed_sender_labels(self):
        for epoch in self.old.rows:
            for slot in ('a','b'):
                m=json.loads(Path(epoch['source_'+slot+'_manifest_original']['path']).read_text())
                for ref in m['copies'].values():self.assertFalse(Path(ref['path']).exists())
        self.assertFalse(self.audit()['sender_origin_path_required_or_read'])

    def argv(self,unified=False,derive=False):
        from publication_accountability import accountability as p370
        from historical_archive import archive as p371
        from historical_authority import authority_archive as p372
        from historical_inclusion import inclusion_archive as p373
        opts=self.options()
        opts['expected_retained_historical_owner_inventory_sha256']=self.derive()[
                       'receiver_verified_historical_owner_inventory_sha256']
        mode='derive-historical-owner-inventory' if derive else 'audit-historical-owner-archive'
        argv=[sys.executable,'-I','-B',str(ROOT/'scripts'/(
                 'ces_next.py' if unified else 'ces_cas_historical_owner_archive.py')),mode]
        if unified:argv+=['DeliveryAudit','AuditHistoricalOwnerArchive']
        scalars=(*p370.prior.SCALARS,*p370.NEW_SCALARS,*p371.NEW_SCALARS,
                 *p371.AUDIT_ONLY,*p372.NEW_SCALARS,*p372.AUDIT_ONLY,
                 *p373.NEW_SCALARS,*p373.AUDIT_ONLY,*core.NEW_SCALARS)
        if not derive:scalars+=core.AUDIT_ONLY
        for key in scalars:argv.extend(['--'+key.replace('_','-'),str(opts[key])])
        for key,flag in (*p370.prior.REPEATS,*p370.NEW_REPEATS,
                         *p371.NEW_REPEATS,*p372.NEW_REPEATS,
                         *p373.NEW_REPEATS,*core.NEW_REPEATS):
            for value in opts[key]:argv.extend([flag,'none' if value is None else str(value)])
        return argv

    def test_25_actual_isolated_unified_live_ec373_through_ec369(self):
        proc=subprocess.run(self.argv(unified=True),capture_output=True,text=True,timeout=180)
        self.assertEqual(proc.returncode,2,proc.stderr+' '+proc.stdout[:1200])
        self.assertTrue(json.loads(proc.stdout)[
                         'local_pinned_historical_owner_reviewer_slice_consistent'])

    def test_26_actual_isolated_standalone_derive_unsigned_inventory(self):
        proc=subprocess.run(self.argv(derive=True),capture_output=True,text=True,timeout=180)
        self.assertEqual(proc.returncode,2,proc.stderr+' '+proc.stdout[:1200])
        self.assertEqual(json.loads(proc.stdout)['schema'],core.DERIVE_SCHEMA)

    def test_27_actual_isolated_unified_signed_owner_tamper_denial(self):
        argv=self.argv(unified=True)
        Path(self.events['a']['issue']['path']).write_bytes(b'altered')
        proc=subprocess.run(argv,capture_output=True,text=True,timeout=180)
        self.assertIn(proc.returncode,(3,4,5),proc.stderr+' '+proc.stdout[:1200])
        doc=json.loads(proc.stdout)
        self.assertEqual(doc['schema'],core.DENIAL_SCHEMA)
        self.assertFalse(doc['sender_origin_path_required_or_read'])

if __name__=='__main__':unittest.main()
