#!/usr/bin/env python3
"""EC414 real WARC original-byte + Ed25519 observation fixture and negatives.

Only the IMMEDIATE real EC413.audit call is patched inside this EC414 test
fixture. The parent EC413 report is derived from genuine locally signed
RSA2048/P256 EC413 original OCSP and signed EC412 CRL/XAdES bytes; the
historical deeper child ancestry has separate synthetic/mocked fixture links.
Production calls the unchanged EC413.audit, never this fixture.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import copy
from pathlib import Path
from uuid import uuid4
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from delivery_anchor import anchor as errors
from lotl_ocsp import test_protocol as ec413fixture
from . import operator, protocol as core


def core_stamp(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


class GenuineTwoWitnessOCSPWARC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ec413fixture.ActualSignedLotlIssuerOCSP.setUpClass()

    @classmethod
    def tearDownClass(cls):
        ec413fixture.ActualSignedLotlIssuerOCSP.tearDownClass()

    def setUp(self):
        self.f = ec413fixture.ActualSignedLotlIssuerOCSP(
            'test_01_four_true_issuer_signed_rsa_ocsp_historical_evaluation')
        self.f.setUp()
        self.parent_report = self.f.calibrate()
        self.assertTrue(self.parent_report[
            'bounded_original_issuer_ocsp_and_real_ec412_parent_consistency'])
        self.extra = dict(self.f.extra)
        self.lineage = self.f.f.b.f.lineage
        self.keys = {r: Ed25519PrivateKey.generate() for r in core.WITNESSES}
        self.ids = {'publisher': 'archive-publisher-A', 'observer': 'independent-observer-B'}
        self.roster = {
            'schema': core.ROSTER_SCHEMA,
            'claimed_directory_lineage_id': self.lineage,
            'https_origin': 'https://ocsp.example.org',
            **{who: {
                'witness_id': self.ids[who],
                'public_key_original': self.archive(
                    self.keys[who].public_key().public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                    who+'-key')}
               for who in core.WITNESSES},
        }
        self.roster_ref = self.archive(self.roster, 'roster')
        self.bundle = {
            'schema': core.BUNDLE_SCHEMA,
            'claimed_directory_lineage_id': self.lineage,
            'parent_ec413_original_lotl_ocsp_bundle_original': {
                'path': self.extra[core.parent.NEW_SCALARS[0]],
                'sha256': self.extra[core.parent.NEW_SCALARS[1]],
            },
            'outside_publication_witness_roster_original': self.roster_ref,
            'epochs': [{'epoch_index': 0, 'historical': None, 'evaluation': None}],
        }
        self.claims = {}
        self.previous = {'publisher': None, 'observer': None}
        self.make_window('historical', self.f.now+timedelta(minutes=1))
        self.make_window('evaluation', self.f.now+timedelta(minutes=2))
        self.refresh()

    def tearDown(self):
        self.f.tearDown()

    def archive(self, raw, label):
        return self.f.archive(raw, 'ec414-'+label+'-'+str(uuid4()))

    def urls(self):
        return {'root': 'https://ocsp.example.org/r/root-status',
                'intermediate': 'https://ocsp.example.org/r/lotl-status'}

    def warc_bytes(self, window, when, der_override=None):
        urls = self.urls()
        pieces = []
        for role in core.ROLES:
            der = der_override.get(role, self.f.raw[(window, role)]) if der_override else (
                self.f.raw[(window, role)])
            http = (b'HTTP/1.1 200 OK\r\n'
                    b'Content-Type: application/ocsp-response\r\n'
                    + ('Content-Length: '+str(len(der))+'\r\n').encode()
                    + ('Date: '+format_datetime(when, usegmt=True)+'\r\n\r\n').encode()
                    + der)
            header = ('WARC/1.1\r\n'
                      'WARC-Type: response\r\n'
                      'WARC-Target-URI: '+urls[role]+'\r\n'
                      'WARC-Date: '+when.strftime('%Y-%m-%dT%H:%M:%SZ')+'\r\n'
                      'WARC-Record-ID: <urn:uuid:'+str(uuid4())+'>\r\n'
                      'Content-Type: application/http; msgtype=response\r\n'
                      'Content-Length: '+str(len(http))+'\r\n'
                      'WARC-Block-Digest: '+core._b32(http)+'\r\n'
                      'WARC-Payload-Digest: '+core._b32(der)+'\r\n\r\n')
            pieces.append(header.encode()+http+b'\r\n\r\n')
        return b''.join(pieces)

    def signed(self, claim, who, label):
        return self.archive({
            'schema': core.RECEIPT_SCHEMA,
            'claim': claim,
            'signature_hex': self.keys[who].sign(
                core.DOMAIN + core.canonical(claim)).hex(),
        }, label)

    def make_window(self, window, when, der_override=None):
        utc = when.strftime('%Y-%m-%dT%H:%M:%SZ')
        src = self.f.bundle['epochs'][0]
        signed_lotl = self.f.f.b.f.bundle['epochs'][0][
            'original_'+window+'_signed_lotl_xml']
        warc = self.archive(self.warc_bytes(window, when, der_override),
                            window+'-two-warc-records')
        common = {
            'schema': core.CLAIM_SCHEMA,
            'directory_lineage_id': self.lineage,
            'epoch_index': 0,
            'window': window,
            'claimed_observation_utc': utc,
            'https_publication_urls': self.urls(),
            'original_lotl_ocsp_bundle_sha256':
                self.extra[core.parent.NEW_SCALARS[1]],
            'original_signed_lotl_xml_sha256': signed_lotl['sha256'],
            'original_two_ocsp_warc_sha256': warc['sha256'],
            'original_ocsp_der_sha256s': {
                role: src[window+'_'+role+'_ca_ocsp_original']['sha256']
                for role in core.ROLES},
        }
        refs = {}
        for who in core.WITNESSES:
            claim = {
                **copy.deepcopy(common),
                'witness_role': who,
                'witness_id': self.ids[who],
                'event_id': who+'-'+window+'-original-'+str(uuid4()),
                'previous_role_receipt_sha256': self.previous[who],
                'publisher_receipt_sha256': (
                    refs['publisher']['sha256'] if who == 'observer' else None),
            }
            self.claims[(window,who)] = claim
            refs[who] = self.signed(claim,who, window+'-'+who+'-receipt')
            self.previous[who] = refs[who]['sha256']
        self.bundle['epochs'][0][window] = {
            'original_two_ocsp_warc': warc,
            'publisher_signed_receipt_original': refs['publisher'],
            'observer_signed_receipt_original': refs['observer'],
        }

    def modify_observer(self, window, change):
        claim = copy.deepcopy(self.claims[(window,'observer')])
        change(claim)
        self.claims[(window,'observer')] = claim
        self.bundle['epochs'][0][window]['observer_signed_receipt_original'] = (
            self.signed(claim, 'observer', window+'-observer-modified'))
        # Mutating historical signed receipt requires a genuinely re-signed
        # later witness chain. Tests for window temporal inconsistencies use
        # evaluation to keep the previous SHA chain unmodified.
        self.refresh()

    def refresh(self, pins=True):
        bundleref = self.archive(self.bundle, 'publication-bundle')
        self.extra[core.NEW_SCALARS[0]] = bundleref['path']
        self.extra[core.NEW_SCALARS[1]] = bundleref['sha256']
        self.extra[core.NEW_SCALARS[2]] = self.roster_ref['sha256']
        for who, idx in (('publisher',3),('observer',4)):
            self.extra[core.NEW_SCALARS[idx]] = (
                self.roster[who]['public_key_original']['sha256'])
        if pins:
            for window, warc_idx, pub_idx, obs_idx in (
                ('historical',5,7,8),('evaluation',6,9,10)):
                row = self.bundle['epochs'][0][window]
                if row is not None:
                    for k, refkey in (
                        (warc_idx,'original_two_ocsp_warc'),
                        (pub_idx,'publisher_signed_receipt_original'),
                        (obs_idx,'observer_signed_receipt_original')):
                        self.extra[core.NEW_SCALARS[k]] = row[refkey]['sha256']
        self.extra[core.REPEAT_NAMES[0]] = ['f'*64]
        self.extra[core.REPEAT_NAMES[1]] = [0]

    def evaluate(self, deriving=True):
        # As in the EC413 child fixture, many earlier original parent flags
        # have only synthetic placeholders. Parent audit itself is mocked,
        # but the EC414 WARC/Ed25519 source verifier runs completely real.
        opts = {k: self.extra.get(k, 'unavailable-synthetic-ancestor-flag')
                for k in (*core.PARENT_SCALARS, *core.NEW_SCALARS)}
        opts.update({k: self.extra.get(k, [])
                     for k in (*core.PARENT_REPEATS, *core.REPEAT_NAMES)})
        if not deriving:
            opts[core.AUDIT_ONLY[0]] = self.extra.get(core.AUDIT_ONLY[0], 'f'*64)
        with patch.object(core.parent, 'audit', return_value=self.parent_report), \
             patch.object(core, '_inputs', return_value={}):
            return core.derive_inventory(**opts) if deriving else core.audit(**opts)

    def calibrate(self):
        derived = self.evaluate()
        self.extra[core.REPEAT_NAMES[0]] = [
            r['original_publication_epoch_inventory_sha256']
            for r in derived['ocsp_publication_epoch_reviews']]
        self.extra[core.REPEAT_NAMES[1]] = [2]
        derived = self.evaluate()
        self.extra[core.AUDIT_ONLY[0]] = (
            derived['receiver_verified_ocsp_publication_inventory_sha256'])
        return self.evaluate(False)

    def denied(self, fragment):
        with self.assertRaises(errors.AnchorError) as raised:
            self.evaluate()
        self.assertEqual(raised.exception.status, 'permission_denied')
        self.assertIn(fragment, raised.exception.code)

    def test_01_actual_http_warc_and_four_true_ed25519_signatures(self):
        r = self.calibrate()
        self.assertEqual(r['exit_code'],2)
        self.assertEqual(r['verified_joint_publication_and_real_ec413_publishers'],2)
        self.assertTrue(r['bounded_dual_witness_original_publication_and_real_ec413_parent_consistency'])
        self.assertFalse(any(r[k] for k in core.NEGATIVES))
        self.assertTrue(all(r[k] is True for k in core.FLAGS[-3:]))
        self.assertEqual(r['ocsp_publication_epoch_reviews'][0][
            'verified_http_200_original_ocsp_warc_response_count'],4)

    def test_02_bad_ed25519_signature_rejected(self):
        window='evaluation'
        row=self.bundle['epochs'][0][window]
        claim=self.claims[(window,'observer')]
        false_key=Ed25519PrivateKey.generate()
        row['observer_signed_receipt_original']=self.archive({
            'schema':core.RECEIPT_SCHEMA, 'claim':claim,
            'signature_hex':false_key.sign(core.DOMAIN+core.canonical(claim)).hex()},
            'forged-valid-shaped-ed25519')
        self.refresh()
        self.denied('TRUE_ED25519_OBSERVATION_SIGNATURE_INVALID')

    def test_03_true_signed_claim_substitutes_ocsp_sha_rejected(self):
        self.modify_observer('evaluation',lambda c:
            c['original_ocsp_der_sha256s'].__setitem__('root','a'*64))
        self.denied('CLAIM_REAL_WARC_OCSP_PARENT_OR_CHAIN_MISMATCH')

    def test_04_true_signed_claim_uses_wrong_parent_sha(self):
        self.modify_observer('evaluation',lambda c:
            c.__setitem__('original_lotl_ocsp_bundle_sha256','a'*64))
        self.denied('CLAIM_REAL_WARC_OCSP_PARENT_OR_CHAIN_MISMATCH')

    def test_05_true_signed_broken_publisher_cross_receipt_link(self):
        self.modify_observer('evaluation',lambda c:
            c.__setitem__('publisher_receipt_sha256','0'*64))
        self.denied('CLAIM_REAL_WARC_OCSP_PARENT_OR_CHAIN_MISMATCH')

    def test_06_true_signed_receipt_previous_epoch_chain_wrong(self):
        self.modify_observer('evaluation',lambda c:
            c.__setitem__('previous_role_receipt_sha256',None))
        self.denied('CLAIM_REAL_WARC_OCSP_PARENT_OR_CHAIN_MISMATCH')

    def test_07_actual_warc_different_der_denied_even_if_hashes_recomputed(self):
        # Signed receipts remain cryptographically genuine; WARC headers, block
        # and payload digests are all *internally* consistent, but actual OCSP
        # DER is substituted and must never be treated as the parent original.
        window='evaluation'; row=self.bundle['epochs'][0][window]
        bogus = { 'root': self.f.raw[(window,'intermediate')] }
        newwarc=self.archive(self.warc_bytes(window,
                            self.f.now+timedelta(minutes=2),bogus),
                            'internally-correct-warc-wrong-issuer-der')
        row['original_two_ocsp_warc']=newwarc
        for who in core.WITNESSES:
            claim=self.claims[(window,who)]
            claim['original_two_ocsp_warc_sha256']=newwarc['sha256']
            row[who+'_signed_receipt_original']=self.signed(
                claim,who,window+'-reissued-for-warc-test')
        # Rebind the observer to the new real publisher receipt signature.
        obs=self.claims[(window,'observer')]
        obs['publisher_receipt_sha256']=(
            row['publisher_signed_receipt_original']['sha256'])
        row['observer_signed_receipt_original']=self.signed(
            obs,'observer',window+'-reissued-crossbound')
        self.refresh()
        self.denied('WARC_HTTP_200_OCSP_EXACT_ORIGINAL_DER_REQUIRED')

    def test_08_warc_source_alias_parent_original_rejected(self):
        self.bundle['epochs'][0]['historical']['original_two_ocsp_warc']=(
            self.f.bundle['epochs'][0]['historical_root_ca_ocsp_original'])
        self.refresh()
        self.denied('ALIASES_ANY_PREVIOUS_ORIGINAL')

    def test_09_warc_cannot_replay_from_historic_to_evaluation(self):
        self.bundle['epochs'][0]['evaluation']['original_two_ocsp_warc']=(
            self.bundle['epochs'][0]['historical']['original_two_ocsp_warc'])
        self.refresh()
        self.denied('ALIASES_ANY_PREVIOUS_ORIGINAL')

    def test_10_original_warc_payload_hash_tampered_rejected(self):
        row=self.bundle['epochs'][0]['evaluation']
        old=Path(row['original_two_ocsp_warc']['path']).read_bytes()
        Path(row['original_two_ocsp_warc']['path']).write_bytes(old[:-1]+b'Z')
        with self.assertRaises(errors.AnchorError):
            self.evaluate()

    def test_11_external_roster_sha_substitution_rejected(self):
        self.extra[core.NEW_SCALARS[2]]='a'*64
        self.denied('ROSTER_NOT_OUTSIDE_PINNED')

    def test_12_duplicate_witness_key_denied(self):
        self.roster['observer']['public_key_original']=(
            self.roster['publisher']['public_key_original'])
        self.roster_ref=self.archive(self.roster,'duplicate-observer-key-roster')
        self.bundle['outside_publication_witness_roster_original']=self.roster_ref
        self.refresh()
        self.denied('NOT_DISTINCT_OUTSIDE_PINNED_OR_ALIASES_ANCESTOR')

    def test_13_valid_signed_observer_claim_after_ocsp_expiry_unresolved(self):
        self.modify_observer('evaluation',lambda c: c.__setitem__(
            'claimed_observation_utc', core_stamp(
                self.f.now+timedelta(days=3))))
        r=self.evaluate()
        self.assertTrue(r[core.FLAGS[3]])
        self.assertEqual(r['verified_joint_publication_and_real_ec413_publishers'],0)

    def test_14_valid_signed_observer_precedes_publisher_by_hours_unresolved(self):
        self.modify_observer('evaluation',lambda c:c.__setitem__(
            'claimed_observation_utc',core_stamp(
                self.f.now-timedelta(hours=5))))
        r=self.evaluate()
        self.assertTrue(r[core.FLAGS[3]])
        self.assertFalse(r['bounded_dual_witness_original_publication_and_real_ec413_parent_consistency'])

    def test_15_outside_first_warc_sha_mismatch_is_unresolved(self):
        self.calibrate()
        self.extra[core.NEW_SCALARS[5]]='a'*64
        r=self.evaluate(False)
        self.assertTrue(r[core.FLAGS[1]])
        self.assertEqual(r['exit_code'],2)

    def test_16_retained_inventory_pin_mismatch_is_unresolved(self):
        self.calibrate()
        self.extra[core.AUDIT_ONLY[0]]='a'*64
        r=self.evaluate(False)
        self.assertTrue(r[core.FLAGS[1]])

    def test_17_parent_signed_revoked_status_never_promoted(self):
        self.calibrate()
        p=dict(self.parent_report)
        p[core.parent.FLAGS[3]]=True
        p['bounded_original_issuer_ocsp_and_real_ec412_parent_consistency']=False
        p['status']=core.parent.OUTCOMES[3]+'_unresolved'
        self.parent_report=p
        r=self.evaluate()
        self.assertTrue(r[core.FLAGS[0]])
        self.assertEqual(r['verified_joint_publication_and_real_ec413_publishers'],0)

    def test_18_fake_success_parent_report_denied_unavailable(self):
        p=dict(self.parent_report)
        p['exit_code']=0
        self.parent_report=p
        with self.assertRaises(errors.AnchorError) as caught:
            self.evaluate()
        self.assertEqual(caught.exception.status,'unavailable')

    def test_19_signature_source_missing_first_window_denied(self):
        self.bundle['epochs'][0]['historical']=None
        self.refresh()
        self.denied('FIRST_EPOCH_ORIGINAL_PUBLICATION_WINDOW_MISSING')

    def test_20_real_parent_input_options_and_distinct_pin_policy(self):
        self.calibrate()
        opts = {k: self.extra.get(k, 'synthetic-ancestor-test')
                for k in (*core.PARENT_SCALARS, *core.NEW_SCALARS,
                          *core.AUDIT_ONLY)}
        opts.update({k: self.extra.get(k, [])
                     for k in (*core.PARENT_REPEATS, *core.REPEAT_NAMES)})
        with patch.object(core.parent, '_inputs', return_value={}):
            self.assertEqual(set(core._inputs(opts,False)),
                             set(core.PARENT_SCALARS)|set(core.PARENT_REPEATS))
            opts[core.NEW_SCALARS[4]]=opts[core.NEW_SCALARS[3]]
            with self.assertRaises(errors.AnchorError):
                core._inputs(opts,False)

    def test_21_exact_signed_unsupported_http_origin_denied(self):
        self.modify_observer('evaluation',lambda c:
            c['https_publication_urls'].__setitem__(
                'root','http://ocsp.example.org/insecure'))
        self.denied('CLAIM_REAL_WARC_OCSP_PARENT_OR_CHAIN_MISMATCH')

    def test_22_denial_contract_no_legal_pass(self):
        res=operator.denial('audit-historical-ec339-lotl-ocsp-publication',
                            errors.AnchorError('EC414_DENIED','permission_denied'))
        self.assertEqual(res['exit_code'],3)
        self.assertEqual(res['schema'],core.DENIAL_SCHEMA)
        self.assertFalse(any(res[k] for k in core.NEGATIVES))

    def test_23_standalone_derive_and_audit_cli_parse(self):
        choices=operator.parser()._subparsers._group_actions[0].choices
        self.assertIn('audit-historical-ec339-lotl-ocsp-publication',choices)
        self.assertIn('derive-historical-ec339-lotl-ocsp-publication-inventory',choices)


    def test_24_unified_fixed_route_accepts_real_focused_child_result(self):
        from scripts import ces_next
        result = self.calibrate()
        fields = {k:self.extra.get(k,'fixture-inherited-placeholder')
                  for k in ces_next.EC414_ALL_SCALARS}
        fields['historical_directory_root_shas'] = ['a'*64]
        fields.update({k:self.extra.get(k, ['f'*64])
                       for k, _ in ces_next.EC414_ALL_REPEATS})
        with patch.object(ces_next, '_command', return_value=(2,result)), \
             patch.object(ces_next, '_emit') as emitted:
            rc = ces_next.audit_historical_ec339_lotl_ocsp_publication(
                'DeliveryAudit','AuditHistoricalEC339LOTLOCSPPublication',**fields)
            self.assertEqual(rc,2)
            emitted.assert_called_once()

    def test_25_unified_rejects_fake_parent_success_and_wrong_mode(self):
        from scripts import ces_next
        with self.assertRaises(Exception):
            ces_next.audit_historical_ec339_lotl_ocsp_publication(
                'DeliveryAudit','AuditHistoricalEC339LOTLIssuerOCSP')
        result=self.calibrate()
        fake=dict(result)
        fake['exit_code']=0
        fields={k:self.extra.get(k,'fixture-inherited-placeholder')
                for k in ces_next.EC414_ALL_SCALARS}
        fields['historical_directory_root_shas']=['a'*64]
        fields.update({k:self.extra.get(k,['f'*64])
                       for k,_ in ces_next.EC414_ALL_REPEATS})
        with patch.object(ces_next,'_command',return_value=(2,fake)), \
             patch.object(ces_next,'_emit'):
            with self.assertRaises(Exception):
                ces_next.audit_historical_ec339_lotl_ocsp_publication(
                    'DeliveryAudit','AuditHistoricalEC339LOTLOCSPPublication',**fields)

    def test_26_two_signed_receipts_cannot_reuse_same_event_id(self):
        prior=self.claims[('evaluation','publisher')]['event_id']
        self.modify_observer('evaluation',lambda c:c.__setitem__('event_id',prior))
        self.denied('WITNESS_SIGNED_EVENT_ID_REPLAYED')

    def test_27_signed_observer_window_regression_adverse(self):
        self.modify_observer('evaluation',lambda c:c.__setitem__(
            'claimed_observation_utc', core_stamp(
                self.f.now+timedelta(seconds=30))))
        result=self.evaluate()
        self.assertTrue(result[core.FLAGS[3]])
        self.assertEqual(result['verified_joint_publication_and_real_ec413_publishers'],0)

    def test_28_unified_parser_registers_production_route(self):
        from scripts import ces_next
        sub=ces_next.build_parser()._subparsers._group_actions[0].choices
        self.assertIn('audit-historical-ec339-lotl-ocsp-publication',sub)


if __name__ == '__main__':
    unittest.main()
