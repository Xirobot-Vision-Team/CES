#!/usr/bin/env python3
"""EC404 genuine local Ed25519 capture receipts and exact HTTP byte tests.

Only EC403.audit and child _inputs are substituted in these synthetic tests.
The supplied EC403 report is itself computed from actual local XMLDSig/PDF
signatures and contains mocked deeper synthetic ancestor audits. This is NOT
an independent public archive, legal official record or real network replay.
"""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from delivery_anchor import anchor as errors
from signed_xml import test_protocol as ec403_fixture
from . import protocol as core
from . import operator


def http(body, kind, **kwargs):
    status = kwargs.get('status', 'HTTP/1.1 200 OK')
    ctype = kwargs.get('content_type', core.TYPES[kind])
    length = kwargs.get('length', len(body))
    extras = kwargs.get('extras', b'')
    head = f'{status}\r\nContent-Type: {ctype}\r\nContent-Length: {length}\r\n'.encode()
    return head + extras + b'\r\n' + body


class SignedPublicAccessCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = ec403_fixture.GenuineOriginalXMLDSigTests(
            'test_01_real_two_different_x509_xml_signatures')
        p.setUp()
        try:
            p.calibrate()
            cls.parent_report = p.evaluate(False)  # genuine signed local XML/PDF
            assert cls.parent_report['verified_joint_parent_pdf_and_xmlsig_publishers'] == 2
        except Exception:
            p.doCleanups()
            raise
        cls.parent_fixture = p

    @classmethod
    def tearDownClass(cls):
        cls.parent_fixture.doCleanups()

    def setUp(self):
        p = self.parent_fixture
        self.report = copy.deepcopy(self.parent_report)
        self.p = p
        self.fixture = p.fixture
        self.opts = dict(p.opts)
        self.lineage = p.lineage
        self.keys = {role: ed25519.Ed25519PrivateKey.generate() for role in ('A', 'B')}
        self.claims = {}
        self.roster = {'schema': core.ROSTER_SCHEMA,
                       'claimed_directory_lineage_id': self.lineage, 'archives': []}
        self.bundle = {'schema': core.BUNDLE_SCHEMA,
                       'claimed_directory_lineage_id': self.lineage,
                       'parent_ec403_original_xmldsig_bundle_original': {
                           'path': p.opts[core.parent.NEW_SCALARS[0]],
                           'sha256': p.opts[core.parent.NEW_SCALARS[1]]},
                       'outside_archive_roster_original': None,
                       'epochs': [{'epoch_index': 0, 'publishers': []}]}
        for letter in ('A', 'B'):
            key = self.keys[letter].public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            keyref = self.fixture.archive(key, 'ec404-external-key-' + letter)
            self.opts[core.NEW_SCALARS[3 if letter == 'A' else 4]] = keyref['sha256']
            self.roster['archives'].append({
                'publisher_id': 'Publisher'+letter,
                'archive_id': 'IndependentLocalTestArchive'+letter,
                'archive_public_key_original': keyref,
                'allowed_public_origin': 'https://public-'+letter.lower()+'.example.org'})
            self.bundle['epochs'][0]['publishers'].append({
                'publisher_id': 'Publisher'+letter,
                'signed_archive_receipt_original': None,
                'captures': []})
        self.rosterref = self.fixture.archive(self.roster, 'ec404-roster')
        self.bundle['outside_archive_roster_original'] = self.rosterref
        self.opts[core.NEW_SCALARS[2]] = self.rosterref['sha256']
        self.opts[core.NEW_SCALARS[7]] = '2026-10-26T00:00:00Z'
        self.opts[core.REPEAT_NAMES[0]] = ['a'*64]
        self.opts[core.REPEAT_NAMES[1]] = [0]
        for letter in ('A', 'B'):
            self._reset_role(letter)
        self._save_bundle()
        self._reanchor_first()

    def role(self, letter):
        return self.bundle['epochs'][0]['publishers'][0 if letter == 'A' else 1]

    def pdf(self, letter):
        return Path(self.p.old.pdfref(letter)['path']).read_bytes()

    def xml(self, letter):
        return Path(self.p.xmlref(letter)['path']).read_bytes()

    def body(self, kind, letter):
        return {'gazette': self.p.source, 'signed_pdf': self.pdf(letter),
                'signed_xml': self.xml(letter)}[kind]

    def _capture(self, kind, letter, raw=None):
        original = http(self.body(kind, letter), kind) if raw is None else raw
        return self.fixture.archive(original, 'ec404-captured-original-'+letter+'-'+kind)

    def _make_signed(self, claim, letter, *, wrong_key=False, wrong_signature=False):
        wire = core.DOMAIN + json.dumps(claim, sort_keys=True,
                    separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
        key = self.keys['B' if letter == 'A' and wrong_key else letter]
        signature = key.sign(wire).hex()
        if wrong_signature:
            signature = ('0' if signature[0] != '0' else '1') + signature[1:]
        return self.fixture.archive({'schema': core.RECEIPT_SCHEMA,
                                     'claim': claim, 'signature_hex': signature},
                                     'ec404-original-receipt-'+letter)

    def _reset_role(self, letter):
        row = self.role(letter)
        captures = [self._capture(kind, letter) for kind in core.CAPTURES]
        row['captures'] = [{'kind': kind, 'http_response_original': value}
                           for kind, value in zip(core.CAPTURES, captures)]
        self.claims[letter] = {
            'schema': core.CLAIM_SCHEMA, 'directory_lineage_id': self.lineage,
            'publisher_id': 'Publisher'+letter,
            'archive_id': 'IndependentLocalTestArchive'+letter,
            'epoch_index': 0, 'sequence': 1,
            'previous_receipt_sha256': None,
            'claimed_capture_utc': '2026-10-25T14:45:00Z',
            'source_original_sha256': core.sha(self.p.source),
            'signed_pdf_original_sha256': self.p.old.pdfref(letter)['sha256'],
            'signed_xml_original_sha256': self.p.xmlref(letter)['sha256'],
            'captures': [
                {'kind': kind, 'public_url': 'https://public-'+letter.lower()+
                 '.example.org/archives/'+kind+'.bin',
                 'http_response_sha256': cref['sha256']}
                for kind, cref in zip(core.CAPTURES, captures)]}
        row['signed_archive_receipt_original'] = self._make_signed(self.claims[letter], letter)

    def _save_bundle(self):
        ref = self.fixture.archive(self.bundle, 'ec404-original-bundle')
        self.opts[core.NEW_SCALARS[0]] = ref['path']
        self.opts[core.NEW_SCALARS[1]] = ref['sha256']

    def _reanchor_first(self):
        self.opts[core.NEW_SCALARS[5]] = self.role('A')[
            'signed_archive_receipt_original']['sha256']
        self.opts[core.NEW_SCALARS[6]] = self.role('B')[
            'signed_archive_receipt_original']['sha256']

    def replace_receipt(self, letter, *, resign=True, **changes):
        claim = copy.deepcopy(self.claims[letter])
        claim.update(changes)
        self.claims[letter] = claim
        self.role(letter)['signed_archive_receipt_original'] = self._make_signed(
            claim, letter, wrong_signature=not resign)
        self._save_bundle()
        self._reanchor_first()

    def replace_response(self, letter, kind, raw, *, update_signed_hash=True):
        ref = self.fixture.archive(raw, 'ec404-modified-original-'+kind+'-'+letter)
        self.role(letter)['captures'][core.CAPTURES.index(kind)][
            'http_response_original'] = ref
        if update_signed_hash:
            cap = copy.deepcopy(self.claims[letter]['captures'])
            cap[core.CAPTURES.index(kind)]['http_response_sha256'] = ref['sha256']
            self.replace_receipt(letter, captures=cap)
        else:
            self._save_bundle()

    def evaluate(self, derive=True):
        # Mandatory parent function itself is not rewritten. The patch is
        # strictly confined to this synthetic EC404 child fixture.
        with patch.object(core, '_inputs', return_value={}), \
             patch.object(core.parent, 'audit', return_value=self.report):
            return core.derive_inventory(**self.opts) if derive else core.audit(**self.opts)

    def calibrate(self):
        initial = self.evaluate()
        self.opts[core.REPEAT_NAMES[0]] = [initial['public_access_epoch_reviews'][0][
            'public_access_epoch_inventory_sha256']]
        self.opts[core.REPEAT_NAMES[1]] = [2]
        final = self.evaluate()
        self.opts[core.AUDIT_ONLY[0]] = final[
            'receiver_verified_public_access_inventory_sha256']
        return final

    def denied(self, expected=None):
        with self.assertRaises(errors.AnchorError) as got:
            self.evaluate()
        if expected:
            self.assertIn(expected, got.exception.code)

    def test_01_real_two_separate_archive_ed25519_receipts_three_http_originals(self):
        result = self.calibrate()
        self.assertTrue(result['bounded_local_public_access_and_real_ec403_parent_consistency'])
        self.assertEqual(result['verified_joint_archive_and_real_parent_publishers'], 2)
        self.assertTrue(all(result[k] for k in core.FLAGS[-3:]))
        self.assertEqual(result['exit_code'], 2)
        self.assertEqual([r['actual_verified_archive_receipt_count'] for r in
                          result['public_access_epoch_reviews']], [2])
        originals = result['unsigned_public_access_evidence_inventory']['epochs'][0]['publishers']
        self.assertEqual(len(originals[0]['verified_three_original_http_captures']), 3)

    def test_02_audit_real_original_sha_count_and_exit2(self):
        self.calibrate()
        result = self.evaluate(False)
        self.assertEqual(result['schema'], core.RESULT_SCHEMA)
        self.assertNotIn('unsigned_public_access_evidence_inventory', result)
        self.assertTrue(result['bounded_local_public_access_and_real_ec403_parent_consistency'])
        self.assertTrue(all(result[k] is False for k in core.NEGATIVES))

    def test_03_crypto_signature_flip_denied(self):
        self.replace_receipt('A', resign=False)
        self.denied('SIGNATURE')

    def test_04_signed_pdf_reference_forged_denied(self):
        self.replace_receipt('A', signed_pdf_original_sha256='f'*64)
        self.denied('PARENT_SHA')

    def test_05_signed_xml_reference_forged_denied(self):
        self.replace_receipt('B', signed_xml_original_sha256='e'*64)
        self.denied('PARENT_SHA')

    def test_06_signed_gazette_reference_forged_denied(self):
        self.replace_receipt('A', source_original_sha256='d'*64)
        self.denied('PARENT_SHA')

    def test_07_capture_body_original_tampering_denied(self):
        self.replace_response('A', 'gazette', http(self.p.source+b'FORGERY', 'gazette'))
        self.denied('HTTP_CAPTURE_BODY')

    def test_08_wrong_real_signed_pdf_bytes_denied(self):
        self.replace_response('B', 'signed_pdf', http(self.pdf('A'), 'signed_pdf'))
        self.denied('HTTP_CAPTURE_BODY')

    def test_09_wrong_xml_original_bytes_denied(self):
        self.replace_response('A', 'signed_xml', http(self.xml('B'), 'signed_xml'))
        self.denied('HTTP_CAPTURE_BODY')

    def test_10_signed_capture_hash_mismatch_denied(self):
        self.replace_response('A', 'gazette', http(self.p.source, 'gazette',
                              extras=b'Date: Sun, 25 Oct 2026 14:45:00 GMT\r\n'),
                              update_signed_hash=False)
        self.denied('PUBLIC_URL_OR_TRUE_HTTP_SHA')

    def test_11_http_content_length_wrong_denied(self):
        self.replace_response('A', 'gazette', http(self.p.source, 'gazette', length=1234))
        self.denied('HTTP_CAPTURE_BODY')

    def test_12_http_chunked_transfer_denied(self):
        self.replace_response('A', 'gazette', http(self.p.source, 'gazette',
                              extras=b'Transfer-Encoding: chunked\r\n'))
        self.denied('HTTP_DUPLICATE_UNKNOWN')

    def test_13_http_duplicate_content_length_denied(self):
        self.replace_response('A', 'gazette', http(self.p.source, 'gazette',
                              extras=b'Content-Length: 5\r\n'))
        self.denied('HTTP_DUPLICATE_UNKNOWN')

    def test_14_http_wrong_status_denied(self):
        self.replace_response('A', 'gazette', http(self.p.source, 'gazette',
                              status='HTTP/1.1 302 Found'))
        self.denied('HTTP_RESPONSE_200')

    def test_15_http_wrong_content_type_denied(self):
        self.replace_response('A', 'signed_pdf', http(self.pdf('A'), 'signed_pdf',
                              content_type='text/html'))
        self.denied('HTTP_CAPTURE_BODY')

    def test_16_signed_url_not_pinned_origin_denied(self):
        cap = copy.deepcopy(self.claims['A']['captures'])
        cap[0]['public_url'] = 'https://attacker.example.org/forged.bin'
        self.replace_receipt('A', captures=cap)
        self.denied('PUBLIC_URL')

    def test_17_signed_url_query_or_port_denied(self):
        cap = copy.deepcopy(self.claims['A']['captures'])
        cap[0]['public_url'] += '?inject=1'
        self.replace_receipt('A', captures=cap)
        self.denied('RESTRICTED_CANONICAL')

    def test_18_archive_key_mismatch_denied(self):
        self.opts[core.NEW_SCALARS[3]] = 'f'*64
        self.denied('EXTERNALLY_PINNED_ARCHIVE_KEY')

    def test_19_archive_key_same_as_other_archive_denied(self):
        self.roster['archives'][1]['archive_public_key_original'] = \
            self.roster['archives'][0]['archive_public_key_original']
        self.rosterref = self.fixture.archive(self.roster, 'ec404-changed-roster')
        self.bundle['outside_archive_roster_original'] = self.rosterref
        self.opts[core.NEW_SCALARS[2]] = self.rosterref['sha256']
        self.opts[core.NEW_SCALARS[4]] = self.opts[core.NEW_SCALARS[3]]
        self._save_bundle()
        self.denied('EXTERNALLY_PINNED_ARCHIVE_KEY')

    def test_20_duplicate_original_response_path_denied(self):
        self.role('B')['captures'][0]['http_response_original'] = \
            self.role('A')['captures'][0]['http_response_original']
        self._save_bundle()
        self.denied('ALIASES')

    def test_21_original_aliases_parent_source_denied(self):
        self.role('A')['captures'][0]['http_response_original'] = self.p.xmlref('A')
        self._save_bundle()
        self.denied('ALIASES')

    def test_22_capture_after_dispute_cutoff_unresolved_no_credit(self):
        self.replace_receipt('A', claimed_capture_utc='2026-10-26T01:00:00Z')
        result = self.evaluate()
        self.assertTrue(result[core.FLAGS[3]])
        self.assertEqual(result['verified_joint_archive_and_real_parent_publishers'], 1)
        self.assertEqual(result['exit_code'], 2)

    def test_23_capture_before_actual_parent_publication_denied(self):
        self.replace_receipt('B', claimed_capture_utc='2026-10-25T13:30:00Z')
        self.denied('CHRONOLOGY')

    def test_24_noncanonical_claimed_utc_denied(self):
        self.replace_receipt('A', claimed_capture_utc='2026-10-25T14:45:00+00:00')
        self.denied('CANONICAL_UTC_REQUIRED')

    def test_25_cross_role_receipt_transplant_denied(self):
        self.role('A')['signed_archive_receipt_original'] = \
            self.role('B')['signed_archive_receipt_original']
        self._save_bundle()
        self._reanchor_first()
        self.denied('ARCHIVE_SIGNED_ORIGINAL_CLAIM')

    def test_26_fake_parent_success_denied(self):
        forged = copy.deepcopy(self.report)
        forged['status'] = 'success'
        self.report = forged
        self.denied('UNCHANGED_REAL_EC403_PARENT')

    def test_27_adverse_real_parent_joint_zero_never_repaired(self):
        bad = copy.deepcopy(self.report)
        bad[core.parent.FLAGS[0]] = True
        bad['bounded_local_original_xmldsig_and_real_ec402_parent_consistency'] = False
        bad['original_xmldsig_epoch_reviews'][0]['joint_verified_xmlsig_and_parent_pdf_count'] = 0
        bad['verified_joint_parent_pdf_and_xmlsig_publishers'] = 0
        bad['status'] = core.parent.OUTCOMES[0]+'_unresolved'
        self.report = bad
        result = self.evaluate()
        self.assertEqual(result['verified_joint_archive_and_real_parent_publishers'], 0)
        self.assertTrue(result[core.FLAGS[0]])

    def test_28_first_receipt_pin_mismatch_only_unresolved(self):
        result = self.calibrate()
        self.opts[core.NEW_SCALARS[5]] = 'f'*64
        result = self.evaluate(False)
        self.assertTrue(result[core.FLAGS[1]])
        self.assertEqual(result['exit_code'], 2)

    def test_29_epoch_inventory_and_joint_floor_mismatch_unresolved(self):
        self.calibrate()
        self.opts[core.REPEAT_NAMES[0]] = ['a'*64]
        result = self.evaluate(False)
        self.assertTrue(result[core.FLAGS[1]])

    def test_30_whole_inventory_mismatch_unresolved(self):
        self.calibrate()
        self.opts[core.AUDIT_ONLY[0]] = 'a'*64
        result = self.evaluate(False)
        self.assertTrue(result[core.FLAGS[1]])

    def test_31_first_receipt_missing_must_deny(self):
        self.role('A')['signed_archive_receipt_original'] = None
        self.role('A')['captures'] = []
        self._save_bundle()
        self.denied('FIRST_ORIGINAL')

    def test_32_true_original_capture_bound_to_signed_sha(self):
        self.replace_response('B', 'signed_xml', http(self.xml('B'), 'signed_xml',
                              extras=b'Date: Sun, 25 Oct 2026 14:45:00 GMT\r\n'))
        result = self.calibrate()
        self.assertEqual(result['verified_joint_archive_and_real_parent_publishers'], 2)

    def test_33_invalid_parent_argument_tuple_denied(self):
        # Direct validation, instead of suppressing via synthetic test setup.
        bad = dict(self.opts)
        bad.pop('expected_outside_retained_ec404_first_a_receipt_sha256')
        with self.assertRaises(errors.AnchorError):
            core._inputs(bad, True)

    def test_34_invalid_parent_report_shape_denied(self):
        forged = copy.deepcopy(self.report)
        forged['extra_untrusted_success'] = True
        self.report = forged
        self.denied('UNCHANGED_REAL_EC403_PARENT')

    def test_35_child_denial_contract_is_fail_closed(self):
        result = operator.denial('audit-historical-ec339-public-access',
                                 errors.AnchorError('EC404_FORGED', 'permission_denied'))
        self.assertEqual(result['exit_code'], 3)
        self.assertEqual(result['status'], 'permission_denied')
        self.assertTrue(all(result[k] is False for k in core.NEGATIVES))


    def test_36_console_entry_validates_child_contract_not_just_exit_code(self):
        from scripts import ces_next as console
        self.calibrate()
        authenticated_local_result = self.evaluate(False)
        # Only the wrapper's contract is exercised: inherited CLI inputs are
        # placeholders; the isolated production child is NOT invoked here.
        full_opts = {k: self.opts.get(k, 'SYNTHETIC_PARENT_PLACEHOLDER')
                     for k in console.EC404_ALL_SCALARS}
        full_opts.update({k: self.opts.get(k, []) for k, _ in console.EC404_ALL_REPEATS})
        with patch.object(console, '_command', return_value=(2, authenticated_local_result)) as command, \
             patch.object(console, '_emit') as emitted:
            actual = console.audit_historical_ec339_public_access(
                'DeliveryAudit', 'AuditHistoricalEC339PublicAccess', **full_opts)
        self.assertEqual(actual, 2)
        self.assertEqual(command.call_args.args[0][4],
                         'audit-historical-ec339-public-access')
        self.assertIn('--expected-outside-ec404-dispute-cutoff-utc',
                      command.call_args.args[0])
        emitted.assert_called_once()

    def test_37_console_refuses_forged_success_json(self):
        from scripts import ces_next as console
        self.calibrate()
        fabricated = self.evaluate(False)
        fabricated['status'] = 'success'
        full_opts = {k: self.opts.get(k, 'SYNTHETIC_PARENT_PLACEHOLDER')
                     for k in console.EC404_ALL_SCALARS}
        full_opts.update({k: self.opts.get(k, []) for k, _ in console.EC404_ALL_REPEATS})
        with patch.object(console, '_command', return_value=(2, fabricated)), \
             patch.object(console, '_emit'):
            with self.assertRaises(console.ConsoleError):
                console.audit_historical_ec339_public_access(
                    'DeliveryAudit', 'AuditHistoricalEC339PublicAccess', **full_opts)

    def test_38_duplicate_json_keys_not_an_original_receipt(self):
        role = 'A'
        signed = Path(self.role(role)['signed_archive_receipt_original']['path']).read_bytes()
        injected = signed.replace(b'"schema":', b'"schema":"forged", "schema":', 1)
        self.role(role)['signed_archive_receipt_original'] = self.fixture.archive(
            injected, 'ec404-duplicate-key-original')
        self._save_bundle()
        self._reanchor_first()
        self.denied()

    def test_39_reject_unknown_receipt_claim_fields_even_with_real_signature(self):
        self.replace_receipt('A', fake_legal_authority=True)
        self.denied('EXACT_FIELDS_REQUIRED')

    def test_40_bare_publication_url_is_not_a_download_capture(self):
        new = copy.deepcopy(self.claims['A']['captures'])
        new[0]['public_url'] = 'https://public-a.example.org'
        self.replace_receipt('A', captures=new)
        self.denied('RESTRICTED_CANONICAL_CAPTURE_URL')

    def test_41_archive_key_cannot_reuse_real_parent_ed25519_signer_key(self):
        leaf = self.p.certificates['A']['leafcert'].public_key()
        raw = leaf.public_bytes(serialization.Encoding.Raw,
                                serialization.PublicFormat.Raw)
        keyref = self.fixture.archive(raw, 'ec404-alias-real-parent-leaf')
        self.roster['archives'][0]['archive_public_key_original'] = keyref
        self.rosterref = self.fixture.archive(self.roster, 'ec404-key-alias-roster')
        self.bundle['outside_archive_roster_original'] = self.rosterref
        self.opts[core.NEW_SCALARS[2]] = self.rosterref['sha256']
        self.opts[core.NEW_SCALARS[3]] = keyref['sha256']
        self._save_bundle()
        self.denied('ARCHIVE_KEY_MUST_DIFFER')


if __name__ == '__main__':
    unittest.main()
