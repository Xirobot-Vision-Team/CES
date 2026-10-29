#!/usr/bin/env python3
"""EC355 genuine LOCAL/SYNTHETIC signatures, Merkle and byte handoff tests.

Parent EC354->EC337 is actually replayed on every new test. Old EC317/318
fixture remains a historical MOCK and none of the actors are outside entities.
"""
from __future__ import annotations

from datetime import timedelta
import json
from pathlib import Path
import subprocess
import sys
import unittest

from ec295_delivery_anchor import anchor as errors
from ec319_offline_transfer_registry import registry as canonical
from ec353_transparency import test_transparency as tr
from ec354_gossip import test_gossip as old
from . import disclosure as core

ROOT=Path(__file__).resolve().parents[2]


class DisclosureTests(old.GossipTests):
    for _name in dir(old.GossipTests):
        if _name.startswith('test_'):locals()[_name]=None

    def setUp(self):
        super().setUp()
        self.requests=[];self.counter=0

    def setup_claim(self, *,size='larger', log='log_a', witnessed=True):
        self.start(two_channels=True)
        self.make_actor('auditor_c')
        info=self.logs[log]
        prior=info['headers'][0]
        leaves=(info['leaves']+[b'SYNTHETIC post-gossip record'] if size=='larger'
                else [*info['leaves']])
        if size=='conflict':leaves[-1]=b'SYNTHETIC mutually incompatible last leaf'
        body={'schema':tr.core.CHECKPOINT_SCHEMA,'log_id':log,
              'log_reference_original_sha256':info['log_ref']['sha256'],
              'previous_checkpoint_original_sha256':prior['file']['sha256'],
              'tree_size':len(leaves),'root_hash_sha256':tr.root(leaves).hex(),
              'issued_utc':tr.ut(self.now+timedelta(minutes=6))}
        signed=self.signed('later-hidden-checkpoint',body,info['private'],
                           tr.core.CHECKPOINT_DOMAIN,'log_signature_ed25519_hex')
        witness_body={'schema':tr.core.WITNESS_SCHEMA,'log_id':log,
              'checkpoint_original_sha256':signed['sha256'],
              'witness_reference_original_sha256':info['witness_ref']['sha256'],
              'tree_size':len(leaves),'root_hash_sha256':body['root_hash_sha256'],
              'witnessed_utc':tr.ut(self.now+timedelta(minutes=7))}
        witness=self.signed('later-hidden-witness',witness_body,info['w_private'],
                            tr.core.WITNESS_DOMAIN,'witness_signature_ed25519_hex')
        consistency=None
        if size=='larger':
            proof={'schema':tr.core.CONSISTENCY_SCHEMA,'log_id':log,
                   'previous_checkpoint_original_sha256':prior['file']['sha256'],
                   'next_checkpoint_original_sha256':signed['sha256'],
                   'previous_tree_size':len(prior['leaves']),
                   'next_tree_size':len(leaves),
                   'audit_path_sha256_hex':[v.hex() for v in tr.consistency(
                       leaves,len(prior['leaves']))]}
            consistency=self.write353('later-hidden-consistency',proof)
        self.hidden={'file':signed,'witness':witness,'proof':consistency,
                     'body':body,'leaves':leaves}
        self.orig_ch=self.gossip_challenge(log,do_reply=False)
        self.orig_reply=self.gossip_reply(self.orig_ch,log_id=log,
                checkpoint={'file':signed,'body':body})
        self.gossip_challenge('log_b','auditor_b','auditor_a')
        return self.hidden

    def add_request(self,target='auditor_b',kind='furnished_originals',*,previous=core.GENESIS,
                    claim=None,custom=None,with_consistency=True,issue_delta=10):
        self.counter+=1
        reply=claim or self.orig_reply
        requestor=self.actors['auditor_a'];targetactor=self.actors[target]
        role=('original_responder' if target=='auditor_b' else 'independent_peer')
        source=self.hidden['body']
        original=custom or self.hidden
        args=self.args354()
        body={'schema':core.REQUEST_SCHEMA,'request_id':f'disclosure_{self.counter}',
              'parent_gossip_bundle_original_sha256':args['expected_gossip_bundle_sha256'],
              'gossip_challenge_original_sha256':self.orig_ch['challenge']['sha256'],
              'gossip_reply_original_sha256':reply['sha256'],
              'log_id':'log_a',
              'claimed_checkpoint_original_sha256':self.hidden['file']['sha256'],
              'claimed_tree_size':source['tree_size'],
              'claimed_root_hash_sha256':source['root_hash_sha256'],
              'requester_auditor_id':'auditor_a',
              'requester_reference_original_sha256':requestor['reference']['sha256'],
              'requested_auditor_id':target,
              'requested_reference_original_sha256':targetactor['reference']['sha256'],
              'requested_role':role,'previous_request_original_sha256':previous,
              'nonce_hex':f'{self.counter:032x}',
              'issued_utc':tr.ut(self.now+timedelta(minutes=issue_delta))}
        req=self.signed('signed-disclosure-request',body,requestor['private'],
                        core.REQUEST_DOMAIN)
        entry={'request':req,'responses':[]}
        self.requests.append(entry)
        if kind is not None:self.add_receipt(entry,kind=kind,target=target,
                           original=original,with_consistency=with_consistency)
        return entry

    def add_receipt(self,entry,kind='furnished_originals',target='auditor_b',*,
                    original=None,with_consistency=True,wrong=None):
        self.counter+=1
        actor=self.actors[target]; original=original or self.hidden
        cp=original['file'];w=original['witness']
        body={'schema':core.RECEIPT_SCHEMA,
              'request_original_sha256':entry['request']['sha256'],
              'gossip_reply_original_sha256':self.orig_reply['sha256'],
              'respondent_auditor_id':target,
              'respondent_reference_original_sha256':actor['reference']['sha256'],
              'log_id':'log_a','response_kind':kind,
              'checkpoint_original_sha256':self.hidden['file']['sha256'],
              'witness_original_sha256':w['sha256'] if kind=='furnished_originals' else None,
              'claimed_checkpoint_length':len(Path(cp['path']).read_bytes())
                     if kind=='furnished_originals' else None,
              'claimed_witness_length':len(Path(w['path']).read_bytes())
                     if kind=='furnished_originals' else None,
              'responded_utc':tr.ut(self.now+timedelta(minutes=12))}
        if wrong:body.update(wrong)
        signed=self.signed('signed-disclosure-receipt',body,actor['private'],
                           core.RECEIPT_DOMAIN)
        row={'receipt':signed,'checkpoint':cp if kind=='furnished_originals' else None,
             'witness_statement':w if kind=='furnished_originals' else None,
             'consistency_proof':original['proof'] if kind=='furnished_originals'
                    and with_consistency else None}
        entry['responses'].append(row)
        return row

    def copy_hidden(self):
        d=self.hidden
        return {'file':self.write353('different-receiver-cp-copy',
                   Path(d['file']['path']).read_bytes()),
                'witness':self.write353('different-receiver-witness-copy',
                   Path(d['witness']['path']).read_bytes()),
                'proof':(self.write353('different-receiver-proof-copy',
                    Path(d['proof']['path']).read_bytes()) if d['proof'] else None)}

    def args355(self,**changes):
        a=self.args354()
        manifest=self.write353('ec355-disclosure-bundle',{
            'schema':core.BUNDLE_SCHEMA,'requests':self.requests})
        return {**a,
            'checkpoint_disclosure_evaluation_utc':tr.ut(self.now+timedelta(hours=2)),
            'checkpoint_disclosure_bundle_file':manifest['path'],
            'expected_checkpoint_disclosure_bundle_sha256':manifest['sha256'],
            **changes}

    def result355(self,**changes):return core.audit(**self.args355(**changes))

    def denied(self,code,**changes):
        with self.assertRaises(errors.AnchorError) as caught:
            self.result355(**changes)
        self.assertIn(code,caught.exception.code)

    def test_01_real_two_recipient_original_byte_handoff_append_only(self):
        self.setup_claim()
        self.add_request();self.add_request('auditor_c',custom=self.copy_hidden())
        result=self.result355()
        self.assertEqual(result['exit_code'],2)
        self.assertEqual(result['channel_evidence'][0]['outcome'],core.OUTCOMES[-1])
        self.assertEqual((result['signed_request_count'],result['signed_receipt_count']), (2,2))
        claim=result['disclosure_claim_evidence'][0]
        self.assertTrue(claim['same_original_observed_by_both_signed_roles'])
        self.assertEqual(claim['disclosure_requests'][0]['signed_responses'][0][
            'verified_furnished_original']['relation_to_verified_ec353_challenge'],
            'verified_rfc6962_append_only_relative_to_challenged_parent')
        self.assertFalse(result['disclosure_claimed_copies_prove_physical_separate_custody'])
        self.assertTrue(result['actual_ec354_through_ec337_original_signatures_replayed'])

    def test_02_no_requests_keeps_missing_two_targets_visible(self):
        self.setup_claim()
        res=self.result355()
        self.assertEqual(res['channel_evidence'][0]['outcome'],core.OUTCOMES[2])
        self.assertTrue(res['any_two_target_requests_missing'])

    def test_03_only_original_responder_is_not_two_roles(self):
        self.setup_claim();self.add_request()
        self.assertEqual(self.result355()['channel_evidence'][0]['outcome'],core.OUTCOMES[2])

    def test_04_signed_offer_only_never_proves_original_byte(self):
        self.setup_claim()
        self.add_request(kind='offer_only')
        self.add_request('auditor_c',kind='offer_only')
        r=self.result355()
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[4])
        self.assertFalse(r['any_genuine_new_signed_log_and_witness_pair_verified'])

    def test_05_signed_unavailable_is_only_a_claim(self):
        self.setup_claim()
        self.add_request(kind='unavailable_claim')
        self.add_request('auditor_c',kind='unavailable_claim')
        self.assertTrue(self.result355()['any_signed_offer_unavailable_or_no_response'])

    def test_06_unanswered_original_request_preserved(self):
        self.setup_claim()
        self.add_request(kind=None)
        self.add_request('auditor_c',kind='offer_only')
        r=self.result355()
        self.assertTrue(r['any_signed_offer_unavailable_or_no_response'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[4])

    def test_07_one_actual_byte_cannot_prove_two_actor_handoff(self):
        self.setup_claim()
        self.add_request();self.add_request('auditor_c',kind='offer_only')
        self.assertEqual(self.result355()['channel_evidence'][0]['outcome'],core.OUTCOMES[6])

    def test_08_unverified_different_size_ancestry_downgraded(self):
        self.setup_claim()
        self.add_request(with_consistency=False)
        self.add_request('auditor_c',custom=self.copy_hidden(),with_consistency=False)
        r=self.result355()
        self.assertTrue(r['verified_same_log_conflict_or_unproved_ancestry_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[5])

    def test_09_same_log_same_size_signed_conflict_visible(self):
        self.setup_claim(size='conflict')
        self.add_request(with_consistency=False)
        self.add_request('auditor_c',custom=self.copy_hidden(),with_consistency=False)
        r=self.result355()
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[5])
        a=r['disclosure_claim_evidence'][0]['disclosure_requests'][0]['signed_responses'][0]
        self.assertEqual(a['verified_furnished_original']['relation_to_verified_ec353_challenge'],
                         'verified_same_log_same_size_conflicting_roots')

    def test_10_request_signature_tampered_rejected(self):
        self.setup_claim();entry=self.add_request(kind=None)
        p=entry['request'];body=json.loads(Path(p['path']).read_bytes())
        body['signature_ed25519_hex']='0'*128
        entry['request']=self.write353('tampered-signed-request',body)
        self.denied('REQUEST_SIGNATURE_INVALID')

    def test_11_response_signature_tampered_rejected(self):
        self.setup_claim();entry=self.add_request()
        p=entry['responses'][0]['receipt'];body=json.loads(Path(p['path']).read_bytes())
        body['signature_ed25519_hex']='0'*128
        entry['responses'][0]['receipt']=self.write353('tampered-signed-receipt',body)
        self.denied('RECEIPT_SIGNATURE_INVALID')

    def test_12_signature_domain_not_reusable(self):
        self.setup_claim();entry=self.add_request(kind=None)
        p=entry['request'];body=json.loads(Path(p['path']).read_bytes())
        body['signature_ed25519_hex']=self.actors['auditor_a']['private'].sign(
            core.RECEIPT_DOMAIN+canonical.canonical({k:v for k,v in body.items()
                                                    if k!='signature_ed25519_hex'})).hex()
        entry['request']=self.write353('wrong-domain-request',body)
        self.denied('REQUEST_SIGNATURE_INVALID')

    def test_13_mismatched_gossip_reply_sha_denied(self):
        self.setup_claim();entry=self.add_request(kind=None)
        p=entry['request'];body=json.loads(Path(p['path']).read_bytes())
        body['gossip_reply_original_sha256']='b'*64
        entry['request']=self.signed('wrong-claim-request',
            {k:v for k,v in body.items() if k!='signature_ed25519_hex'},
            self.actors['auditor_a']['private'],core.REQUEST_DOMAIN)
        self.denied('REQUEST_MUST_SELECT_SIGNED_UNFURNISHED')

    def test_14_original_target_cannot_be_peer_or_requester(self):
        self.setup_claim();entry=self.add_request('auditor_c',kind=None)
        p=entry['request'];body=json.loads(Path(p['path']).read_bytes())
        body['requested_role']='original_responder'
        entry['request']=self.signed('wrong-role-request',
            {k:v for k,v in body.items() if k!='signature_ed25519_hex'},
            self.actors['auditor_a']['private'],core.REQUEST_DOMAIN)
        self.denied('REQUEST_SIGNED_PARENT_CLAIM')

    def test_15_request_nonce_replay_denied(self):
        self.setup_claim();one=self.add_request(kind=None);two=self.add_request('auditor_c',kind=None)
        a=json.loads(Path(one['request']['path']).read_bytes())
        b=json.loads(Path(two['request']['path']).read_bytes())
        b['nonce_hex']=a['nonce_hex']
        two['request']=self.signed('replayed-nonce',
           {k:v for k,v in b.items() if k!='signature_ed25519_hex'},
           self.actors['auditor_a']['private'],core.REQUEST_DOMAIN)
        self.denied('REQUEST_ID_OR_NONCE_REPLAY')

    def test_16_full_checkpoint_sha_tamper_denied(self):
        self.setup_claim();entry=self.add_request()
        cp=entry['responses'][0]['checkpoint'];p=Path(cp['path'])
        p.write_bytes(p.read_bytes()+b'\n')
        self.denied('SHA')

    def test_17_actual_log_signature_tamper_denied(self):
        self.setup_claim()
        cpbody=json.loads(Path(self.hidden['file']['path']).read_bytes())
        cpbody['log_signature_ed25519_hex']='0'*128
        forged=self.write353('forged-signed-checkpoint',cpbody)
        self.hidden['file']=forged
        info=self.logs['log_a'];base=self.hidden['body']
        wbody={'schema':tr.core.WITNESS_SCHEMA,'log_id':'log_a',
            'checkpoint_original_sha256':forged['sha256'],
            'witness_reference_original_sha256':info['witness_ref']['sha256'],
            'tree_size':base['tree_size'],'root_hash_sha256':base['root_hash_sha256'],
            'witnessed_utc':tr.ut(self.now+timedelta(minutes=7))}
        self.hidden['witness']=self.signed('witness-for-forged-log-header',wbody,
                 info['w_private'],tr.core.WITNESS_DOMAIN,'witness_signature_ed25519_hex')
        self.orig_ch['replies']=[]
        self.orig_reply=self.gossip_reply(self.orig_ch,checkpoint={'file':forged,'body':base})
        self.add_request(with_consistency=False)
        self.denied('CHECKPOINT_LOG_SIGNATURE_INVALID')

    def test_18_actual_witness_signature_tamper_denied(self):
        self.setup_claim();entry=self.add_request()
        old=entry['responses'][0]['witness_statement']
        # In-place signature tamper changes the original SHA: late re-read must reject.
        p=Path(old['path']);body=json.loads(p.read_bytes())
        body['witness_signature_ed25519_hex']='0'*128
        p.write_bytes(canonical.canonical(body))
        self.denied('SHA')

    def test_19_signed_receipt_wrong_full_length_denied(self):
        self.setup_claim();entry=self.add_request()
        p=entry['responses'][0]['receipt'];body=json.loads(Path(p['path']).read_bytes())
        body['claimed_witness_length']+=1
        entry['responses'][0]['receipt']=self.signed('false-byte-length',
            {k:v for k,v in body.items() if k!='signature_ed25519_hex'},
            self.actors['auditor_b']['private'],core.RECEIPT_DOMAIN)
        self.denied('WHOLE_BYTE_SHA_OR_LENGTH')

    def test_20_signed_reply_cannot_swap_auditor(self):
        self.setup_claim();entry=self.add_request()
        p=entry['responses'][0]['receipt'];body=json.loads(Path(p['path']).read_bytes())
        body['respondent_auditor_id']='auditor_c'
        entry['responses'][0]['receipt']=self.signed('pretend-other-auditor',
            {k:v for k,v in body.items() if k!='signature_ed25519_hex'},
            self.actors['auditor_b']['private'],core.RECEIPT_DOMAIN)
        self.denied('RECEIPT_REQUEST_ROLE_OR_KIND')

    def test_21_broken_rfc6962_path_denied(self):
        self.setup_claim();entry=self.add_request()
        proof=entry['responses'][0]['consistency_proof'];doc=json.loads(Path(proof['path']).read_bytes())
        doc['audit_path_sha256_hex']=['f'*64]
        entry['responses'][0]['consistency_proof']=self.write353('bad-consistency',doc)
        self.denied('CONSISTENCY_PROOF_INVALID')

    def test_22_request_same_parent_fork_kept_not_elected(self):
        self.setup_claim();self.add_request(kind='offer_only')
        self.add_request(kind='offer_only');self.add_request('auditor_c',kind='offer_only')
        r=self.result355()
        self.assertTrue(r['request_sha_predecessor_forks_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[3])

    def test_23_request_history_wrong_predecessor_role_rejected(self):
        self.setup_claim();first=self.add_request(kind=None)
        self.add_request('auditor_c',kind=None,previous=first['request']['sha256'])
        self.denied('REQUEST_SHA_PREDECESSOR_CHAIN_INVALID')

    def test_24_two_incompatible_signed_receipts_visible(self):
        self.setup_claim();entry=self.add_request(kind='offer_only')
        self.add_receipt(entry,kind='unavailable_claim')
        self.add_request('auditor_c',kind='offer_only')
        r=self.result355()
        self.assertTrue(r['signed_receipt_equivocation_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[3])

    def test_25_no_unfurnished_view_is_not_reported_as_success(self):
        self.start(two_channels=True);self.make_actor('auditor_c');self.full_views()
        r=self.result355()
        self.assertEqual(r['signed_unfurnished_view_count'],0)
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[1])

    def test_26_derive_handoff_replays_real_parent(self):
        self.setup_claim()
        res=core.checklist(**self.args354())
        self.assertEqual(res['exit_code'],2)
        self.assertEqual(len(res['signed_unfurnished_view_inventory']),1)
        self.assertEqual(res['signed_unfurnished_view_inventory'][0][
            'claimed_checkpoint_original_sha256'],self.hidden['file']['sha256'])

    def test_27_corrupt_parent_gossip_challenge_cannot_be_repaired(self):
        self.setup_claim()
        p=self.orig_ch['challenge'];Path(p['path']).write_bytes(b'{}')
        self.denied('SHA')

    def test_29_fixed_unified_route_validates_readonly_child_result(self):
        import contextlib
        import io
        from scripts import ces_next as router
        self.setup_claim()
        self.add_request();self.add_request('auditor_c',custom=self.copy_hidden())
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            rc=router.audit_checkpoint_disclosures(
                'DeliveryAudit','AuditSignedCheckpointDisclosures',**self.args355())
        self.assertEqual(rc,2)
        response=json.loads(output.getvalue())
        self.assertEqual(response['schema'],core.RESULT_SCHEMA)
        self.assertEqual(response['signed_receipt_count'],2)
        self.assertFalse(response['checkpoint_and_witness_signatures_prove_global_head_or_all_hidden_forks'])

    def test_28_parser_and_unified_mode_refuse_privileged_action(self):
        script=ROOT/'scripts'/'ces_next.py'
        run=subprocess.run([sys.executable,'-B',str(script),
                'audit-checkpoint-disclosures','DeliverySend','AuditSignedCheckpointDisclosures'],
                capture_output=True,text=True)
        self.assertNotEqual(run.returncode,0)
        self.assertIn('error',run.stderr.lower())


if __name__=='__main__':unittest.main()
