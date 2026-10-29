#!/usr/bin/env python3
"""EC358 genuine local Ed25519 synthetic signers and actual EC357->EC337 replay.

No fixture certifies external legal identity, chronological truth, trust-root
provenance, physical custody, native PowerShell or final acceptance.
"""
from __future__ import annotations
from datetime import timedelta
from pathlib import Path
import json
import os
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519
from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec353_transparency import test_transparency as tr
from ec357_provenance import provenance as prior
from ec357_provenance import test_provenance as parent_cases
from . import epochs as core


class EpochTests(parent_cases.ProvenanceTests):
    for _method in dir(parent_cases.ProvenanceTests):
        if _method.startswith('test_'):locals()[_method]=None

    def setUp(self):
        super().setUp()
        self.owners={};self.events={'a':[],'b':[]}
        self.my_heads={};self.floors={'a':0,'b':0}

    def setup358(self):
        self.setup357()
        self.provenance_inputs=self.args357()
        self.actual357=prior.audit(**self.provenance_inputs)
        self.assertTrue(self.actual357['both_source_copies_match_ec356_parent_for_all_signed_eligible_receipts'])
        self.actual357_sha=core._sha(canonical.canonical(self.actual357))
        for slot in ('a','b'):
            key=ed25519.Ed25519PrivateKey.generate()
            pub=self.write353('ec358-owner-'+slot,tr.pub(key))
            self.owners[slot]={'private':key,'pub':pub}
            self.event(slot,'issue',0,current=self.source_reviews[slot],
                       previous=None,prev_digest=None)

    def new_reviewer(self,name):
        priv=ed25519.Ed25519PrivateKey.generate()
        return {'private':priv,'pub':self.write353('ec358-reviewer-'+name,tr.pub(priv))}

    def event(self,slot,op,epoch,*,current=None,previous=None,prev_digest=None,
              changes=None,wrong_signature=None,issued_offset=timedelta(hours=4,minutes=10)):
        ow=self.owners[slot]
        source=self.source_reviews[slot]
        oldpin=previous['pub'] if previous else None
        newpin=current['pub'] if current else None
        body={'schema':core.EVENT_SCHEMA,'slot':slot,
              'source_id':'external_review_'+slot,
              'claimed_owner_id':'claimed_owner_'+slot,
              'owner_public_key_original_sha256':ow['pub']['sha256'],
              'parent_ec357_canonical_result_sha256':self.actual357_sha,
              'parent_source_review_original_sha256':source['signed']['sha256'],
              'epoch':epoch,'previous_event_original_sha256':prev_digest,
              'operation':op,
              'previous_reviewer_public_key_original_sha256':oldpin['sha256'] if oldpin else None,
              'current_reviewer_public_key_original_sha256':newpin['sha256'] if newpin else None,
              'issued_utc':tr.ut(self.now+issued_offset),
              'expires_utc':tr.ut(self.now+timedelta(days=2))}
        if changes:body.update(changes)
        payload=canonical.canonical(body)
        owner_sig=ow['private'].sign(core.DOMAINS['owner']+payload).hex()
        old_sig=previous['private'].sign(core.DOMAINS['previous']+payload).hex() if previous else None
        new_sig=current['private'].sign(core.DOMAINS['current']+payload).hex() if current else None
        if wrong_signature=='owner':owner_sig=source['private'].sign(core.DOMAINS['owner']+payload).hex()
        if wrong_signature=='old':old_sig=source['private'].sign(core.DOMAINS['previous']+payload).hex()
        if wrong_signature=='new':new_sig=ow['private'].sign(core.DOMAINS['current']+payload).hex()
        doc={**body,'signature_owner_ed25519_hex':owner_sig,
             'signature_previous_reviewer_ed25519_hex':old_sig,
             'signature_current_reviewer_ed25519_hex':new_sig}
        pin=self.write353('ec358-event-'+slot+'-'+str(len(self.events[slot])),doc)
        bundle_row={'event_original':pin,
                    'previous_reviewer_public_key':oldpin,
                    'current_reviewer_public_key':newpin}
        self.events[slot].append(bundle_row)
        self.my_heads[slot]=pin['sha256']
        return pin

    def args358(self,**changes):
        sources=[{'slot':slot,'owner_public_key':self.owners[slot]['pub'],
                  'events':self.events[slot]} for slot in ('a','b')
                 if slot in self.owners]
        bundle=self.write353('ec358-epoch-manifest',{
            'schema':core.BUNDLE_SCHEMA,'sources':sources})
        a=self.owners.get('a');b=self.owners.get('b')
        return {**self.provenance_inputs,
           'reviewer_epoch_evaluation_utc':tr.ut(self.now+timedelta(hours=5)),
           'reviewer_epoch_bundle_file':bundle['path'],
           'expected_reviewer_epoch_bundle_sha256':bundle['sha256'],
           'owner_a_public_key_file':a['pub']['path'] if a else None,
           'expected_owner_a_public_key_sha256':a['pub']['sha256'] if a else None,
           'owner_b_public_key_file':b['pub']['path'] if b else None,
           'expected_owner_b_public_key_sha256':b['pub']['sha256'] if b else None,
           'minimum_a_epoch':self.floors['a'],
           'minimum_b_epoch':self.floors['b'],
           'expected_a_head_event_sha256':self.my_heads.get('a'),
           'expected_b_head_event_sha256':self.my_heads.get('b'),**changes}

    def run358(self,**changes):return core.audit(**self.args358(**changes))

    def deny358(self,part,**changes):
        with self.assertRaises(errors.AnchorError) as caught:
            self.run358(**changes)
        self.assertIn(part,caught.exception.code)

    def rotate_a(self):
        old=self.new_reviewer('old-a')
        self.events['a']=[]
        genesis=self.event('a','issue',0,current=old,previous=None,prev_digest=None)
        rotation=self.event('a','rotate',1,previous=old,
                            current=self.source_reviews['a'],prev_digest=genesis['sha256'],
                            issued_offset=timedelta(hours=4,minutes=20))
        self.floors['a']=1
        return old,genesis,rotation

    def test_01_genuine_two_owner_co_signed_issues_remain_external_unproven(self):
        self.setup358();r=self.run358()
        self.assertEqual(r['exit_code'],2)
        self.assertTrue(r['actual_ec357_through_ec337_signed_originals_replayed'])
        self.assertTrue(r['two_signed_owner_histories_locally_continuous_and_match_ec357_review'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[-1])
        self.assertTrue(r['independent_official_owner_identity_physical_custody_trusted_utc_and_global_head_unproven'])
        self.assertFalse(r['caller_pinned_owner_sha_proves_official_owner_identity'])

    def test_02_actual_three_party_previous_current_owner_rotation(self):
        self.setup358();self.rotate_a()
        r=self.run358()
        self.assertEqual(r['owner_establishments'][0]['selected_head_epoch'],1)
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[-1])

    def test_03_owner_signed_terminal_revoke_cannot_approve_reviewer(self):
        self.setup358();root=self.events['a'][0]['event_original']
        self.event('a','revoke',1,previous=self.source_reviews['a'],
                   current=None,prev_digest=root['sha256'])
        r=self.run358();self.assertTrue(r['signed_reviewer_revocation_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[3])

    def test_04_signed_sibling_rotations_are_visible_even_if_head_pinned(self):
        self.setup358();old,genesis,head=self.rotate_a()
        alternate=self.new_reviewer('alternate')
        self.event('a','rotate',1,current=alternate,previous=old,
                   prev_digest=genesis['sha256'])
        self.my_heads['a']=head['sha256']
        r=self.run358()
        self.assertTrue(r['signed_branch_or_owner_identity_collision_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[2])

    def test_05_external_minimum_epoch_detects_rollback(self):
        self.setup358();old,genesis,head=self.rotate_a()
        self.my_heads['a']=genesis['sha256']
        r=self.run358()
        self.assertTrue(r['pinned_rollback_or_review_signer_mismatch_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[4])

    def test_06_absent_new_owner_signed_evidence_never_approves(self):
        self.setup358();r=self.run358(reviewer_epoch_bundle_file=None,
                              expected_reviewer_epoch_bundle_sha256=None)
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[1])

    def test_07_wrong_owner_signature_is_denied_not_classed_missing(self):
        self.setup358();self.events['a']=[]
        self.event('a','issue',0,current=self.source_reviews['a'],
                   previous=None,prev_digest=None,wrong_signature='owner')
        self.deny358('OWNER_REAL_SIGNATURE_INVALID')

    def test_08_new_signer_false_rotation_signer_denied(self):
        self.setup358();old,genesis,head=self.rotate_a()
        self.events['a'].pop()
        self.event('a','rotate',1,current=self.source_reviews['a'],
                   previous=old,prev_digest=genesis['sha256'],wrong_signature='old')
        self.deny358('PREVIOUS_REVIEWER_REAL_SIGNATURE_INVALID')

    def test_09_forged_missing_predecessor_denied(self):
        self.setup358();self.events['a']=[]
        self.event('a','rotate',1,current=self.source_reviews['a'],
                   previous=self.new_reviewer('old-missing'),prev_digest='e'*64)
        self.deny358('MISSING_SIGNED_PREDECESSOR')

    def test_10_owner_key_old_parent_source_key_alias_denied(self):
        self.setup358();bad=self.source_reviews['a']['pub']
        self.deny358('OWNER_KEY_MUST_EQUAL_SEPARATE_CALLER_SHA_PIN',
                     owner_a_public_key_file=bad['path'],
                     expected_owner_a_public_key_sha256=bad['sha256'])

    def test_11_self_claimed_future_event_visible_not_trusted_utc(self):
        self.setup358();self.events['a']=[]
        self.event('a','issue',0,current=self.source_reviews['a'],
                   previous=None,prev_digest=None,
                   issued_offset=timedelta(hours=5,minutes=30))
        r=self.run358()
        self.assertTrue(r['stale_future_or_reordered_self_claimed_epoch_time_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[5])

    def test_12_claimed_owner_same_legal_label_is_not_independence(self):
        self.setup358();self.events['b']=[]
        self.event('b','issue',0,current=self.source_reviews['b'],
                   previous=None,prev_digest=None,changes={'claimed_owner_id':'claimed_owner_a'})
        r=self.run358();self.assertTrue(r['signed_branch_or_owner_identity_collision_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[2])

    def test_13_actual_signed_parent_ec357_result_sha_bound(self):
        self.setup358();self.events['a']=[]
        self.event('a','issue',0,current=self.source_reviews['a'],
                   previous=None,prev_digest=None,
                   changes={'parent_ec357_canonical_result_sha256':'f'*64})
        self.deny358('EVENT_MUST_BIND_ACTUAL_REPLAY')

    def test_14_hardlinked_owner_key_as_old_parent_key_is_denied(self):
        self.setup358();key=self.owners['a']['pub']
        oldpath=self.source_reviews['a']['pub']['path']
        Path(key['path']).unlink()
        os.link(oldpath,key['path'])
        self.deny358('WHOLE_ORIGINAL_SHA_MISMATCH')

    def test_15_revoked_parent_ec357_not_repaired_by_good_epoch_history(self):
        self.setup358()
        self.source_reviews['b']['body']['root_records'][0].update(
            root_state='revoked',root_state_effective_utc=tr.ut(self.now),
            replacement_root_public_key_sha256=None)
        self.resign('b')
        # Rebind the *new* EC358 original signatures to the genuinely changed
        # parent EC357 canonical result; EC358 never repairs the revoked root.
        self.provenance_inputs=self.args357()
        self.actual357=prior.audit(**self.provenance_inputs)
        self.actual357_sha=core._sha(canonical.canonical(self.actual357))
        for slot in ('a','b'):
            self.events[slot]=[]
            self.event(slot,'issue',0,current=self.source_reviews[slot],
                       previous=None,prev_digest=None)
        r=self.run358()
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[0])

    def test_16_fixed_isolated_unified_route_return_contract(self):
        self.setup358();inp=self.args358()
        root=Path(__file__).resolve().parents[2]
        sys.path.insert(0,str(root/'scripts'))
        import ces_next as con
        argv=[sys.executable,'-I','-B',str(root/'scripts'/'ces_next.py'),
              'audit-reviewer-epochs','DeliveryAudit','AuditReviewerEpochContinuity']
        for key in con.EC358_REQUIRED:
            argv.extend(['--'+key.replace('_','-'),str(inp[key])])
        for key in con.EC358_OPTIONAL:
            if inp[key] is not None:
                argv.extend(['--'+key.replace('_','-'),str(inp[key])])
        for key,flag in con.EC358_REPEATS:
            for val in inp[key]:argv.extend([flag,str(val)])
        proc=subprocess.run(argv,capture_output=True,text=True,timeout=7200)
        self.assertEqual(proc.returncode,2,proc.stderr+' '+proc.stdout[-1200:])
        doc=json.loads(proc.stdout)
        self.assertEqual(doc['schema'],core.RESULT_SCHEMA)
        self.assertEqual(doc['channel_evidence'][0]['outcome'],core.OUTCOMES[-1])

    def test_17_cannot_continue_from_genuinely_signed_revocation(self):
        self.setup358();root=self.events['a'][0]['event_original']
        revoked=self.event('a','revoke',1,previous=self.source_reviews['a'],
                           current=None,prev_digest=root['sha256'])
        new=self.new_reviewer('after-revocation')
        self.event('a','rotate',2,previous=self.source_reviews['a'],
                   current=new,prev_digest=revoked['sha256'])
        self.deny358('EPOCH_LINK_OR_REVOKED_PREDECESSOR_INVALID')

    def test_18_owner_from_other_slot_cannot_become_a_reviewer_by_copy(self):
        self.setup358();self.events['b']=[]
        owner_a=self.owners['a']
        bad={'private':owner_a['private'],
             'pub':self.write353('ec358-owner-as-reviewer',tr.pub(owner_a['private']))}
        self.event('b','issue',0,current=bad,previous=None,prev_digest=None)
        self.deny358('REVIEWER_KEY_REUSES_OLD_OR_OWNER_ROLE')

    def test_19_current_reviewer_signature_mismatch_is_denied(self):
        self.setup358();self.events['b']=[]
        self.event('b','issue',0,current=self.source_reviews['b'],
                   previous=None,prev_digest=None,wrong_signature='new')
        self.deny358('CURRENT_REVIEWER_REAL_SIGNATURE_INVALID')

    def test_20_expired_signed_epoch_review_is_visible_not_proof_of_valid_utc(self):
        self.setup358();self.events['a']=[]
        self.event('a','issue',0,current=self.source_reviews['a'],previous=None,
                   prev_digest=None,changes={'expires_utc':tr.ut(
                       self.now+timedelta(hours=4,minutes=50))})
        r=self.run358()
        self.assertTrue(r['stale_future_or_reordered_self_claimed_epoch_time_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[5])
