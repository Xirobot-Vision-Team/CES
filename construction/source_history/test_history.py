#!/usr/bin/env python3
"""EC363 focused real Ed25519 disclosure scenarios over real EC362..EC337 replay.

All signer keys and 'source identities' are synthetic and locally generated.
"""
from __future__ import annotations

from datetime import timedelta
import json
from pathlib import Path
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519
from delivery_anchor import anchor as errors
from transparency import test_transparency as util
from publication_custody import test_custody as fixtures
from . import history as core


class HistoryTests(fixtures.PublicationCustodyTests):
    for _name in dir(fixtures.PublicationCustodyTests):
        if _name.startswith('test_'):locals()[_name]=None

    def setUp(self):
        super().setUp()
        self.histories={};self.challengers={};self.bundles={}
        self.disclosure_requests={};self.disclosure_responses={}

    def setup363(self):
        self.setup362()
        self.parent_inputs=self.args362()
        self.history_now=util.ut(self.now+timedelta(hours=7,minutes=40))
        for slot in core.SLOTS:
            latest=self.publications[slot]
            older=self.make_publication(slot,sequence=2)
            self.publications[slot]=latest
            challenger=ed25519.Ed25519PrivateKey.generate()
            pub=self.write353('ec363-challenger-'+slot,util.pub(challenger))
            self.challengers[slot]={'private':challenger,'public':pub}
            self.histories[slot]=[older]
            self.disclosure_requests[slot]=[];self.disclosure_responses[slot]=[]
            for n,role in enumerate(core.ROLES):
                req=self.make_challenge(slot,older,role,n)
                self.make_response(slot,req)
            self.rebundle(slot)

    def make_challenge(self,slot,manifest,role,n=0,**changes):
        doc=json.loads(Path(manifest['path']).read_bytes())
        body={'schema':core.CHALLENGE_SCHEMA,'source_slot':slot,
          'claimed_source_id':doc['claimed_source_id'],
          'challenger_public_key_original_sha256':
              self.challengers[slot]['public']['sha256'],
          'custodian_public_key_original_sha256':
              self.sources[slot]['public']['sha256'],
          'parent_ec362_canonical_result_sha256':self.actual_parent_sha(),
          'parent_ec361_canonical_result_sha256':self.ec361_sha,
          'target_manifest_original_sha256':manifest['sha256'],
          'target_publication_sequence':doc['publication_sequence'],
          'requested_copy_role':role,
          'requested_copy_sha256':doc['copies'][role]['sha256'],
          'nonce_hex':format(self.file_no+n+1,'064x'),
          'issued_utc':util.ut(self.now+timedelta(hours=7,minutes=26)),
          'expires_utc':util.ut(self.now+timedelta(days=1))}
        body.update(changes)
        ref=self.signed360('ec363-challenge-'+slot+'-'+str(self.file_no),body,
            self.challengers[slot]['private'],core.CHALLENGE_DOMAIN,
            'signature_challenger_ed25519_hex')
        self.disclosure_requests[slot].append(ref)
        return ref

    def make_response(self,slot,request,*,kind='disclosed',copy=None,**changes):
        req=json.loads(Path(request['path']).read_bytes())
        if kind=='disclosed' and copy is None:
            original=self.sources[slot]['copies'][req['requested_copy_role']]
            copy=self.write353('ec363-disclosure-'+slot+'-'+str(self.file_no),
                               Path(original['path']).read_bytes())
        body={'schema':core.RESPONSE_SCHEMA,'source_slot':slot,
          'claimed_source_id':req['claimed_source_id'],
          'custodian_public_key_original_sha256':
             self.sources[slot]['public']['sha256'],
          'parent_ec362_canonical_result_sha256':self.actual_parent_sha(),
          'challenge_original_sha256':request['sha256'],
          'target_manifest_original_sha256':req['target_manifest_original_sha256'],
          'requested_copy_role':req['requested_copy_role'],
          'requested_copy_sha256':req['requested_copy_sha256'],
          'response_kind':kind,'disclosed_copy':copy if kind=='disclosed' else None,
          'responded_utc':util.ut(self.now+timedelta(hours=7,minutes=32)),
          'expires_utc':util.ut(self.now+timedelta(days=1))}
        body.update(changes)
        ref=self.signed360('ec363-response-'+slot+'-'+str(self.file_no),body,
            self.sources[slot]['private'],core.RESPONSE_DOMAIN,
            'signature_custodian_ed25519_hex')
        self.disclosure_responses[slot].append(ref)
        return ref

    def actual_parent_sha(self):
        if not hasattr(self,'_parent_hash'):
            from offline_transfer_registry import registry as canonical
            from publication_custody import custody as parent
            self._parent_hash=core.sha(canonical.canonical(
                parent.audit(**self.parent_inputs)))
        return self._parent_hash

    def rebundle(self,slot):
        obj={'schema':core.BUNDLE_SCHEMA,'source_slot':slot,
          'parent_ec362_canonical_result_sha256':self.actual_parent_sha(),
          'custodian_public_key_original_sha256':self.sources[slot]['public']['sha256'],
          'challenger_public_key_original_sha256':self.challengers[slot]['public']['sha256'],
          'historical_manifest_originals':self.histories[slot],
          'signed_challenge_originals':self.disclosure_requests[slot],
          'signed_disclosure_response_originals':self.disclosure_responses[slot]}
        self.bundles[slot]=self.write353('ec363-history-bundle-'+slot+'-'+str(self.file_no),obj)
        return self.bundles[slot]

    def args363(self,**updates):
        values={**self.parent_inputs,'history_evaluation_utc':self.history_now}
        for slot in core.SLOTS:
            values.update({
              f'source_{slot}_history_bundle_file':self.bundles[slot]['path'],
              f'expected_source_{slot}_history_bundle_sha256':self.bundles[slot]['sha256'],
              f'source_{slot}_challenger_public_key_file':self.challengers[slot]['public']['path'],
              f'expected_source_{slot}_challenger_public_key_sha256':
                  self.challengers[slot]['public']['sha256'],
              f'minimum_source_{slot}_retained_publication_sequence':2,
              f'expected_source_{slot}_retained_manifest_sha256':self.histories[slot][0]['sha256'],
              f'minimum_source_{slot}_retained_directory_tree_size':5,
              f'source_{slot}_historical_manifest_shas':
                  [x['sha256'] for x in self.histories[slot]],
              f'source_{slot}_challenge_shas':
                  [x['sha256'] for x in self.disclosure_requests[slot]],
              f'source_{slot}_response_shas':
                  [x['sha256'] for x in self.disclosure_responses[slot]],
            })
        return {**values,**updates}

    def test_01_real_signed_history_challenges_and_all_eight_raw_copies(self):
        self.setup363()
        result=core.audit(**self.args363())
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['actual_ec362_through_ec337_signed_originals_replayed'])
        self.assertTrue(result['bounded_signed_history_and_disclosures_locally_coherent'])
        self.assertEqual([r['historical_originals_disclosed_and_rechecked'] for r in
                          result['source_history_reviews']],[4,4])
        self.assertFalse(result['self_signed_source_history_proves_official_public_archive'])

    def test_02_signed_same_sequence_ambiguous_history_is_never_elected(self):
        self.setup363()
        other=self.make_publication('a',sequence=2,changes={
            'issued_utc':util.ut(self.now+timedelta(hours=7,minutes=21))})
        self.histories['a'].append(other)
        self.rebundle('a')
        result=core.audit(**self.args363())
        self.assertTrue(result['genuinely_signed_same_sequence_or_challenge_equivocation'])
        self.assertFalse(result['bounded_signed_history_and_disclosures_locally_coherent'])

    def test_03_caller_saved_head_or_sequence_rollback(self):
        self.setup363()
        result=core.audit(**self.args363(minimum_source_a_retained_publication_sequence=4))
        self.assertTrue(result['caller_retained_source_sequence_or_head_regression'])

    def test_04_original_absent_even_with_source_claimed_available(self):
        self.setup363()
        self.disclosure_responses['b'].pop()
        self.rebundle('b')
        result=core.audit(**self.args363())
        self.assertTrue(result['signed_disclosure_missing_or_explicitly_unavailable'])
        self.assertFalse(result['bounded_signed_history_and_disclosures_locally_coherent'])

    def test_05_signed_retroactive_withdrawal_not_erased(self):
        self.setup363()
        self.disclosure_responses['a'].pop()
        self.make_response('a',self.disclosure_requests['a'][-1],kind='withdrawn')
        self.rebundle('a')
        result=core.audit(**self.args363())
        self.assertTrue(result['signed_retroactive_withdrawal_visible'])
        self.assertFalse(result['signed_withdrawal_erases_past_publication_or_revocation_obligations'])

    def test_06_disclosed_wrong_raw_sha_is_a_visible_mismatch(self):
        self.setup363()
        self.disclosure_responses['a'].pop()
        replacement=self.write353('ec363-wrong-original',b'EC363_NOT_THE_ADVERTISED_COPY')
        self.make_response('a',self.disclosure_requests['a'][-1],copy=replacement)
        self.rebundle('a')
        result=core.audit(**self.args363())
        self.assertTrue(result['disclosed_original_does_not_match_challenged_sha'])
        self.assertFalse(result['bounded_signed_history_and_disclosures_locally_coherent'])

    def test_07_separate_caller_sha_pin_mismatch_does_not_pass(self):
        self.setup363()
        original=self.args363()
        original['source_a_historical_manifest_shas']=['aa'*32]
        result=core.audit(**original)
        self.assertTrue(result['disclosed_original_does_not_match_challenged_sha'])
        self.assertFalse(result['bounded_signed_history_and_disclosures_locally_coherent'])

    def test_08_signed_unavailable_response_does_not_count_as_copy(self):
        self.setup363()
        self.disclosure_responses['a'].pop()
        self.make_response('a',self.disclosure_requests['a'][-1],kind='unavailable')
        self.rebundle('a')
        result=core.audit(**self.args363())
        self.assertTrue(result['signed_disclosure_missing_or_explicitly_unavailable'])
        self.assertFalse(result['bounded_signed_history_and_disclosures_locally_coherent'])

    def test_09_unauthorized_challenge_signature_denied(self):
        self.setup363()
        req=self.disclosure_requests['a'].pop()
        payload=json.loads(Path(req['path']).read_bytes())
        payload.pop('signature_challenger_ed25519_hex')
        wrong=self.signed360('ec363-bad-challenge',payload,
             self.sources['b']['private'],core.CHALLENGE_DOMAIN,
             'signature_challenger_ed25519_hex')
        self.disclosure_requests['a'].append(wrong)
        self.rebundle('a')
        with self.assertRaises(errors.AnchorError) as err:
            core.audit(**self.args363())
        self.assertEqual(err.exception.status,'permission_denied')

    def test_10_genuine_unified_isolated_python_I_B_entry(self):
        self.setup363()
        inputs=self.args363()
        root=Path(__file__).resolve().parents[2]
        sys.path.insert(0,str(root/'scripts'))
        import ces_next as router
        argv=[sys.executable,'-I','-B',str(root/'scripts'/'ces_next.py'),
              'audit-publication-history','DeliveryAudit','AuditPublicationHistory']
        for key in router.EC363_REQUIRED:
            argv.extend(['--'+key.replace('_','-'),str(inputs[key])])
        for key in router.EC363_OPTIONAL:
            if inputs[key] is not None:
                argv.extend(['--'+key.replace('_','-'),str(inputs[key])])
        for key,flag in router.EC363_REPEATS:
            for val in inputs[key]:argv.extend([flag,str(val)])
        p=subprocess.run(argv,capture_output=True,text=True,timeout=1800)
        self.assertEqual(p.returncode,2,p.stderr+' '+p.stdout[-1800:])
        doc=json.loads(p.stdout)
        self.assertEqual(doc['schema'],core.RESULT_SCHEMA)
        self.assertTrue(doc['bounded_signed_history_and_disclosures_locally_coherent'])

    def test_11_challenger_cannot_reuse_ec362_source_signer_key(self):
        self.setup363()
        self.challengers['b']['public']=self.sources['b']['public']
        self.rebundle('b')
        with self.assertRaises(errors.AnchorError) as err:
            core.audit(**self.args363())
        self.assertEqual(err.exception.status,'permission_denied')

    def test_12_historical_signed_utc_future_not_trusted(self):
        self.setup363()
        newer=self.make_publication('a',sequence=2,changes={
            'issued_utc':util.ut(self.now+timedelta(days=1)),
            'expires_utc':util.ut(self.now+timedelta(days=2))})
        self.histories['a']=[newer]
        self.disclosure_requests['a']=[];self.disclosure_responses['a']=[]
        for n,role in enumerate(core.ROLES):
            req=self.make_challenge('a',newer,role,n)
            self.make_response('a',req)
        self.rebundle('a')
        result=core.audit(**self.args363())
        self.assertTrue(result['signed_historical_claimed_clock_anomaly'])
        self.assertFalse(result['bounded_signed_history_and_disclosures_locally_coherent'])

    def test_13_disclosed_true_directory_signed_same_size_root_fork(self):
        self.setup363()
        original_publication=self.publications['a']
        current_cp=self.sources['a']['copies']['checkpoint']
        alternative=self.add_evolved_checkpoint(
            leaves=[*self.leaves[:-1],b'EC363_ALTERNATE_SIGNED_HEAD_LEAF'])
        old_copy=self.write353('ec363-old-truly-signed-checkpoint',
                               Path(alternative['path']).read_bytes())
        self.sources['a']['copies']['checkpoint']=old_copy
        old_manifest=self.make_publication('a',sequence=2)
        self.sources['a']['copies']['checkpoint']=current_cp
        self.publications['a']=original_publication
        self.histories['a']=[old_manifest]
        self.disclosure_requests['a']=[];self.disclosure_responses['a']=[]
        req=self.make_challenge('a',old_manifest,'checkpoint')
        disclosed=self.write353('ec363-alternate-head-disclosed',
                                Path(old_copy['path']).read_bytes())
        self.make_response('a',req,copy=disclosed)
        self.rebundle('a')
        result=core.audit(**self.args363())
        self.assertTrue(result['independently_verified_directory_signed_history_fork'])
        self.assertFalse(result['bounded_signed_history_and_disclosures_locally_coherent'])

    def test_14_two_genuine_signed_replies_to_same_challenge_never_choose_winner(self):
        self.setup363()
        self.make_response('a',self.disclosure_requests['a'][-1],kind='withdrawn')
        self.rebundle('a')
        result=core.audit(**self.args363())
        self.assertTrue(result['genuinely_signed_same_sequence_or_challenge_equivocation'])
        self.assertFalse(result['bounded_signed_history_and_disclosures_locally_coherent'])
