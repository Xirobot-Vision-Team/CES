#!/usr/bin/env python3
"""EC356 LOCAL/SYNTHETIC real Ed25519 custody, full EC355->EC337 replay.

All institutions/roots/signatures are synthesized on *one machine*. The old
EC317/318 fixture remains a deep MOCK. These are developmental functional
checks, not proof of external institutional or physical custody.
"""
from __future__ import annotations

import contextlib
from datetime import timedelta
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519
from delivery_anchor import anchor as errors
from transparency import test_transparency as tr
from disclosure import test_disclosure as previous
from . import custody as core

ROOT=Path(__file__).resolve().parents[2]


class CustodyTests(previous.DisclosureTests):
    for _name in dir(previous.DisclosureTests):
        if _name.startswith('test_'):locals()[_name]=None

    def setUp(self):
        super().setUp()
        self.custody_channels={};self.counter356=0

    def prepare356(self):
        self.setup_claim()
        self.add_request()
        self.add_request('auditor_c',custom=self.copy_hidden())
        self.add_channel('a')
        self.add_channel('b')
        self.add_ack('a',0)
        self.add_ack('b',1)

    def add_channel(self,slot,*,institution=None,organization=None,site=None,
                    root_private=None,channel_private=None):
        root_private=root_private or ed25519.Ed25519PrivateKey.generate()
        channel_private=channel_private or ed25519.Ed25519PrivateKey.generate()
        institution=institution or 'institution_'+slot
        pub=self.write353('ec356-'+slot+'-root.bin',tr.pub(root_private))
        reference=self.signed('ec356-'+slot+'-rootref',{
            'schema':core.ROOT_SCHEMA,'institution_id':institution,
            'claimed_organization':organization or 'SYNTHETIC Org '+slot,
            'root_public_key_original_sha256':pub['sha256'],
            'valid_from_utc':tr.ut(self.now-timedelta(days=4)),
            'valid_until_utc':tr.ut(self.now+timedelta(days=32))},
            root_private,core.ROOT_DOMAIN)
        chan=self.write353('ec356-'+slot+'-channel.bin',tr.pub(channel_private))
        auth=self.signed('ec356-'+slot+'-auth',{
            'schema':core.AUTH_SCHEMA,'institution_id':institution,
            'channel_id':'channel_'+slot,
            'root_reference_original_sha256':reference['sha256'],
            'channel_public_key_original_sha256':chan['sha256'],
            'claimed_physical_site_id':site or 'site_'+slot,
            'valid_from_utc':tr.ut(self.now-timedelta(days=2)),
            'valid_until_utc':tr.ut(self.now+timedelta(days=20))},
            root_private,core.AUTH_DOMAIN)
        entry={'slot':slot,'institution_id':institution,'channel_id':'channel_'+slot,
               'claimed_organization':organization or 'SYNTHETIC Org '+slot,
               'root_public_key':pub,'root_reference':reference,
               'channel_public_key':chan,'channel_authorization':auth,
               'acknowledgements':[]}
        self.custody_channels[slot]={'root_private':root_private,'private':channel_private,
                             'manifest':entry,'root':pub,'auth':auth}
        return self.custody_channels[slot]

    def copy(self,pin,stem):
        return self.write353('ec356-copy-'+stem,Path(pin['path']).read_bytes())

    def add_ack(self,slot,request_index=0,*,kind='custodied_originals',previous_sha='GENESIS',
                delta=14,wrong=None,from_channel=None,copy_bytes=True):
        self.counter356+=1
        target=self.custody_channels[slot]
        req=self.requests[request_index]
        rece= req['responses'][0]
        source=self.hidden
        checkpoint=rece['checkpoint']
        witness=rece['witness_statement']
        actor=self.custody_channels[from_channel or slot]
        body={'schema':core.ACK_SCHEMA,
              'acknowledgement_id':f'ack_{self.counter356}',
              'parent_disclosure_bundle_original_sha256':self.args355()[
                   'expected_checkpoint_disclosure_bundle_sha256'],
              'gossip_reply_original_sha256':self.orig_reply['sha256'],
              'ec355_request_original_sha256':req['request']['sha256'],
              'ec355_receipt_original_sha256':rece['receipt']['sha256'],
              'ec355_requested_role':'original_responder' if request_index==0 else 'independent_peer',
              'log_id':'log_a','checkpoint_original_sha256':checkpoint['sha256'],
              'witness_original_sha256':witness['sha256'],
              'checkpoint_length':len(Path(checkpoint['path']).read_bytes()) if
                                   kind=='custodied_originals' else None,
              'witness_length':len(Path(witness['path']).read_bytes()) if
                                   kind=='custodied_originals' else None,
              'custody_status':kind,'institution_id':target['manifest']['institution_id'],
              'channel_id':target['manifest']['channel_id'],
              'channel_authorization_original_sha256':target['auth']['sha256'],
              'previous_ack_original_sha256':previous_sha,
              'nonce_hex':f'{self.counter356:032x}',
              'acknowledged_utc':tr.ut(self.now+timedelta(minutes=delta))}
        if wrong:body.update(wrong)
        signed=self.signed('ec356-ack',body,actor['private'],core.ACK_DOMAIN)
        presented={'acknowledgement':signed,
                   'checkpoint_original':self.copy(checkpoint,'checkpoint') if
                          kind=='custodied_originals' and copy_bytes else None,
                   'witness_original':self.copy(witness,'witness') if
                          kind=='custodied_originals' and copy_bytes else None}
        target['manifest']['acknowledgements'].append(presented)
        return presented

    def args356(self,**changes):
        parent=self.args355()
        bundle=self.write353('ec356-custody-bundle',{
            'schema':core.BUNDLE_SCHEMA,
            'channels':[self.custody_channels[s]['manifest'] for s in sorted(self.custody_channels)]})
        first=self.custody_channels['a']['root'];second=self.custody_channels['b']['root']
        return {**parent,'two_channel_custody_evaluation_utc':tr.ut(self.now+timedelta(hours=3)),
                'custody_bundle_file':bundle['path'],
                'expected_custody_bundle_sha256':bundle['sha256'],
                'root_a_public_key_file':first['path'],
                'expected_root_a_public_key_sha256':first['sha256'],
                'root_b_public_key_file':second['path'],
                'expected_root_b_public_key_sha256':second['sha256'],
                **changes}

    def result356(self,**changes):return core.audit(**self.args356(**changes))

    def reject(self,part,**changes):
        with self.assertRaises(errors.AnchorError) as exc:
            self.result356(**changes)
        self.assertIn(part,exc.exception.code)

    def test_01_two_distinct_root_authorized_original_sha_quorum(self):
        self.prepare356()
        r=self.result356()
        self.assertEqual(r['exit_code'],2)
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[-1])
        self.assertTrue(r['two_channel_cross_role_exact_original_quorum_for_all_claims'])
        self.assertEqual(r['signed_acknowledgement_count'],2)
        self.assertEqual(r['genuine_furnished_parent_receipt_count'],2)
        self.assertFalse(r['different_root_or_channel_signatures_prove_separate_legal_entities'])
        self.assertTrue(r['out_of_band_root_custody_source_and_real_external_independence_unproven'])

    def test_02_sha_claim_only_not_custodial_byte_proof(self):
        self.prepare356()
        self.custody_channels['b']['manifest']['acknowledgements']=[]
        self.add_ack('b',1,kind='sha_claim_only')
        r=self.result356()
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[3])
        self.assertFalse(r['two_channel_cross_role_exact_original_quorum_for_all_claims'])

    def test_03_unsigned_second_channel_missing_without_autoupgrade(self):
        self.prepare356();self.custody_channels['b']['manifest']['acknowledgements']=[]
        self.assertEqual(self.result356()['channel_evidence'][0]['outcome'],core.OUTCOMES[3])

    def test_04_wrong_external_root_pin_cannot_recover_with_self_signed_reference(self):
        self.prepare356()
        self.reject('ROOT_KEY_MUST_MATCH_SEPARATE_CALLER_PIN',
                    root_b_public_key_file=self.custody_channels['a']['root']['path'])

    def test_05_channel_uses_wrong_private_signer_denied(self):
        self.prepare356()
        self.custody_channels['b']['manifest']['acknowledgements']=[]
        self.add_ack('b',1,from_channel='a')
        self.reject('ACK_REAL_SIGNATURE_INVALID')

    def test_06_mutated_presented_exact_original_rejected(self):
        self.prepare356()
        p=self.custody_channels['b']['manifest']['acknowledgements'][0]['checkpoint_original']
        Path(p['path']).write_bytes(b'NOT THE RECEIVER-FURNISHED CHECKPOINT')
        self.reject('WHOLE_ORIGINAL_SHA_MISMATCH')

    def test_07_root_key_cannot_reuse_parent_auditor_key(self):
        self.prepare356()
        a=self.actors['auditor_a']
        self.custody_channels['b']['manifest']['acknowledgements']=[]
        self.custody_channels.pop('b')
        self.add_channel('b',root_private=a['private'])
        self.add_ack('b',1)
        self.reject('PARENT_SIGNATURE_ROLE_KEY_REUSED')

    def test_08_same_claimed_organization_is_explicit_conflict_not_two_real_institutions(self):
        self.prepare356()
        self.custody_channels.pop('b')
        self.add_channel('b',organization='synthetic org A')
        self.add_ack('b',1)
        r=self.result356()
        self.assertTrue(r['claimed_institution_or_site_identity_collision_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[5])

    def test_09_expired_self_claimed_receipt_visible_as_stale(self):
        self.prepare356()
        r=self.result356(two_channel_custody_evaluation_utc=tr.ut(self.now+timedelta(days=10)))
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[5])
        self.assertTrue(r['stale_custody_self_claimed_utc_visible'])

    def test_10_both_institutions_ack_one_ec355_role_not_a_quorum(self):
        self.prepare356()
        self.custody_channels['b']['manifest']['acknowledgements']=[]
        self.add_ack('b',0)
        r=self.result356()
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[6])

    def test_11_valid_two_signed_sibling_acks_are_not_elected_as_latest(self):
        self.prepare356()
        self.add_ack('a',0)
        r=self.result356()
        self.assertTrue(r['signed_ack_sha_predecessor_forks_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[4])

    def test_12_unknown_ack_sha_predecessor_cannot_be_skipped(self):
        self.prepare356()
        self.custody_channels['b']['manifest']['acknowledgements']=[]
        self.add_ack('b',1,previous_sha='a'*64)
        self.reject('ACK_SHA_PREDECESSOR_CYCLE_OR_CROSS_CHANNEL_LINK')

    def test_13_replayed_nonce_refused_even_different_channel_signature(self):
        self.prepare356()
        self.custody_channels['b']['manifest']['acknowledgements']=[]
        self.add_ack('b',1,wrong={'nonce_hex':'00000000000000000000000000000001'})
        self.reject('GLOBAL_ACK_ID_OR_NONCE_REPLAY')

    def test_14_mutated_parent_gossip_signature_cannot_be_repaired(self):
        self.prepare356()
        Path(self.orig_ch['challenge']['path']).write_bytes(b'{}')
        self.reject('SHA')

    def test_15_derive_handoff_only_lists_genuinely_furnished_parent_originals(self):
        self.prepare356()
        r=core.checklist(**self.args355())
        self.assertEqual(r['exit_code'],2)
        self.assertEqual(len(r['eligible_signed_furnished_receipts']),2)
        self.assertTrue(r['actual_ec355_through_ec337_signed_originals_replayed'])

    def test_16_unified_fixed_isolated_readonly_mode(self):
        from scripts import ces_next as router
        self.prepare356()
        out=io.StringIO()
        with contextlib.redirect_stdout(out):
            rc=router.audit_two_channel_custody('DeliveryAudit','AuditTwoChannelCustody',
                    **self.args356())
        self.assertEqual(rc,2)
        body=json.loads(out.getvalue())
        self.assertEqual(body['schema'],core.RESULT_SCHEMA)
        self.assertEqual(body['signed_acknowledgement_count'],2)
        self.assertEqual(body['channel_evidence'][0]['outcome'],core.OUTCOMES[-1])

    def test_18_symlinked_path_ancestor_cannot_masquerade_as_custody_copy(self):
        self.prepare356()
        item=self.custody_channels['b']['manifest']['acknowledgements'][0]
        real=Path(item['checkpoint_original']['path'])
        linked=Path(self.w)/'ec356-symlinked-parent'
        linked.symlink_to(Path(self.w),target_is_directory=True)
        item['checkpoint_original']={'path':str(linked/real.name),
                                    'sha256':item['checkpoint_original']['sha256']}
        self.reject('SYMLINKED_CUSTODY_PATH_ANCESTOR_DENIED')

    def test_19_hardlink_parent_original_cannot_count_as_new_custody_copy(self):
        self.prepare356()
        item=self.custody_channels['b']['manifest']['acknowledgements'][0]
        original=self.requests[1]['responses'][0]['checkpoint']
        linked=Path(self.w)/'ec356-hardlink-to-parent-checkpoint'
        os.link(original['path'],linked)
        item['checkpoint_original']={'path':str(linked),'sha256':original['sha256']}
        self.reject('HARDLINK_ORIGINAL_INODE_ALIAS')

    def test_20_missing_true_append_only_parent_proof_not_repaired_by_two_roots(self):
        self.prepare356()
        for entry in self.requests:
            entry['responses'][0]['consistency_proof']=None
        new_parent_sha=self.args355()['expected_checkpoint_disclosure_bundle_sha256']
        for channel in self.custody_channels.values():
            for item in channel['manifest']['acknowledgements']:
                previous=json.loads(Path(item['acknowledgement']['path']).read_bytes())
                previous.pop('signature_ed25519_hex')
                previous['parent_disclosure_bundle_original_sha256']=new_parent_sha
                item['acknowledgement']=self.signed('ec356-ack-parent-no-proof',
                        previous,channel['private'],core.ACK_DOMAIN)
        r=self.result356()
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[0])

    def test_21_one_channel_establishment_is_not_a_two_channel_quorum(self):
        self.prepare356()
        m=self.write353('ec356-one-channel-only',{
            'schema':core.BUNDLE_SCHEMA,
            'channels':[self.custody_channels['a']['manifest']]})
        r=self.result356(custody_bundle_file=m['path'],
                         expected_custody_bundle_sha256=m['sha256'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[2])

    def test_22_root_self_signature_forgery_denied(self):
        self.prepare356()
        channel=self.custody_channels['b']['manifest']
        old=channel['root_reference']
        ref=json.loads(Path(old['path']).read_bytes())
        ref['signature_ed25519_hex']='0'*128
        channel['root_reference']=self.write353('ec356-forged-rootref',ref)
        self.reject('ROOT_REF_REAL_SIGNATURE_INVALID')

    def test_23_different_genuine_witness_originals_cannot_form_same_byte_quorum(self):
        self.setup_claim()
        self.add_request()
        current=self.hidden['file'];doc=self.hidden['body']
        alternative=self.signed('ec356-second-true-witness',{
            'schema':tr.core.WITNESS_SCHEMA,'log_id':'log_a',
            'checkpoint_original_sha256':current['sha256'],
            'witness_reference_original_sha256':self.logs['log_a']['witness_ref']['sha256'],
            'tree_size':doc['tree_size'],'root_hash_sha256':doc['root_hash_sha256'],
            'witnessed_utc':tr.ut(self.now+timedelta(minutes=8))},
            self.logs['log_a']['w_private'],tr.core.WITNESS_DOMAIN,
            'witness_signature_ed25519_hex')
        self.add_request('auditor_c',custom={'file':self.copy(current,'alt-checkpoint'),
                    'witness':alternative,'proof':self.copy(self.hidden['proof'],
                                                          'alt-consistency')})
        self.add_channel('a');self.add_channel('b')
        self.add_ack('a',0);self.add_ack('b',1)
        r=self.result356()
        self.assertTrue(r['incompatible_signed_original_sha_pairs_visible'])
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[6])

    def test_24_no_ec355_receiver_originals_remains_unfurnished(self):
        self.setup_claim()
        self.add_channel('a');self.add_channel('b')
        r=self.result356()
        self.assertEqual(r['channel_evidence'][0]['outcome'],core.OUTCOMES[1])
        self.assertEqual(r['genuine_furnished_parent_receipt_count'],0)

    def test_25_wrong_ack_parent_request_sha_cannot_shift_to_other_receipt(self):
        self.prepare356()
        self.custody_channels['b']['manifest']['acknowledgements']=[]
        self.add_ack('b',1,wrong={'ec355_request_original_sha256':self.requests[0]['request']['sha256']})
        self.reject('ACK_SIGNED_PARENT_OR_CHANNEL_BINDING_INVALID')

    def test_26_channel_root_signed_authorization_signature_tamper(self):
        self.prepare356()
        entry=self.custody_channels['a']['manifest']
        ref=json.loads(Path(entry['channel_authorization']['path']).read_bytes())
        ref['signature_ed25519_hex']='0'*128
        entry['channel_authorization']=self.write353('ec356-forged-authorization',ref)
        self.reject('CHANNEL_AUTH_REAL_SIGNATURE_INVALID')

    def test_27_ack_claimed_before_ec355_receiver_receipt_rejected(self):
        self.prepare356()
        self.custody_channels['b']['manifest']['acknowledgements']=[]
        self.add_ack('b',1,delta=11)
        self.reject('ACK_TIME_OUTSIDE_PARENT_OR_SIGNER_VALIDITY')

    def test_28_unsigned_manifest_cannot_rewrite_root_signed_organization(self):
        self.prepare356()
        self.custody_channels['b']['manifest']['claimed_organization']='SYNTHETIC Org a'
        self.reject('ROOT_REFERENCE_SCOPE_OR_VALIDITY_INVALID')

    def test_17_fixed_cli_rejects_privileged_action(self):
        cmd=[sys.executable,'-B',str(ROOT/'scripts'/'ces_next.py'),
             'audit-two-channel-custody','DeliverySend','AuditTwoChannelCustody']
        p=subprocess.run(cmd,capture_output=True,text=True)
        self.assertNotEqual(p.returncode,0)
        self.assertIn('error',p.stderr.lower())

if __name__=='__main__':unittest.main()
