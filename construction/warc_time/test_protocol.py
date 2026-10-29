#!/usr/bin/env python3
"""EC405 tests with genuine locally issued RFC3161/CMS and real WARC bytes.

The parent EC404.audit result is substituted **only in this child fixture**.
That result is produced from actual Ed25519 and PDF/XML signatures under the
older deliberately mocked ancestry.  Synthetic TSA roots/times are untrusted.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import shutil
import subprocess
import unittest
from unittest.mock import patch
from uuid import uuid4

from cryptography.hazmat.primitives import hashes
from delivery_anchor import anchor as errors
from tsa_timestamp import timestamp as tsa
from tsa_timestamp.test_timestamp import local_test_certs
from public_access import test_protocol as ec404_fixture
from . import protocol as core
from . import operator

POLICY = '1.2.3.4.5.405'


def warc_record(raw, url, stamp, *, record_id=None, **changes):
    head_end = raw.index(b'\r\n\r\n')
    fields = {
        'WARC-Type': 'response', 'WARC-Target-URI': url,
        'WARC-Date': stamp, 'WARC-Record-ID': '<urn:uuid:'+str(record_id or uuid4())+'>',
        'WARC-Block-Digest': core._b32(raw),
        'WARC-Payload-Digest': core._b32(raw[head_end+4:]),
        'Content-Type': 'application/http; msgtype=response',
        'Content-Length': str(len(raw)),
    }
    fields.update(changes)
    return (b'WARC/1.1\r\n' + b''.join(
        k.encode('ascii')+b': '+v.encode('ascii')+b'\r\n' for k, v in fields.items()) +
        b'\r\n'+raw+b'\r\n\r\n')


class GenuineWarcTimestampTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('openssl'):
            raise unittest.SkipTest('OpenSSL required to issue local genuine test RFC3161 tokens')
        ec404_fixture.SignedPublicAccessCaptureTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        ec404_fixture.SignedPublicAccessCaptureTests.tearDownClass()

    def setUp(self):
        self.f = ec404_fixture.SignedPublicAccessCaptureTests(
            'test_01_real_two_separate_archive_ed25519_receipts_three_http_originals')
        self.f.setUp()
        self.f.opts[core.parent.NEW_SCALARS[7]] = '2030-01-01T00:00:00Z'
        self.f.calibrate()
        self.parent_report = self.f.evaluate(False)
        self.stamp = self.f.claims['A']['claimed_capture_utc']
        self.extra = dict(self.f.opts)  # synthetic child fixture has intentionally abbreviated ancestor args
        self.extra.update({core.NEW_SCALARS[9]:
            (datetime.now(timezone.utc)+timedelta(minutes=2)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            core.REPEAT_NAMES[0]: ['a'*64], core.REPEAT_NAMES[1]: [0]})
        self.roster = {'schema':core.TRUST_SCHEMA,
                       'claimed_directory_lineage_id':self.f.lineage,
                       'authorities':[]}
        self.bundle = {'schema':core.BUNDLE_SCHEMA,
            'claimed_directory_lineage_id':self.f.lineage,
            'parent_ec404_original_public_access_bundle_original': {
                'path': self.f.opts[core.parent.NEW_SCALARS[0]],
                'sha256': self.f.opts[core.parent.NEW_SCALARS[1]]},
            'outside_tsa_roster_original':None,
            'epochs':[{'epoch_index':0,'publishers':[]}]}
        self.data = {}
        self._warc_override = {}
        self.serial = 0
        for letter in ('A','B'):
            self._new_tsa(letter)
            self._renew_warc(letter)
            self._renew_token(letter)
        self._save_roster()
        self._save_bundle()
        self._anchor_first()

    def archive(self, raw, tag):
        self.serial += 1
        return self.f.fixture.archive(raw, 'ec405-'+tag+'-'+str(self.serial))

    def role(self, letter):
        return self.bundle['epochs'][0]['publishers'][0 if letter == 'A' else 1]

    def _new_tsa(self, letter, *, stale=False, revoked=False):
        self.serial += 1
        rootdir = Path(self.f.p.fixture.root)
        root, cert, priv, crl = local_test_certs(
            rootdir, 1000 + self.serial, stale=stale, revoked=revoked)
        rootbytes = root.read_bytes()
        rootref = self.archive(rootbytes, 'tsa-root-'+letter)
        crlref = self.archive(crl.read_bytes(), 'tsa-crl-'+letter)
        root_sha = tsa._certificate(rootbytes).fingerprint(hashes.SHA256()).hex()
        self.extra[core.NEW_SCALARS[3 if letter=='A' else 4]] = root_sha
        aid = 'LocalTestTSA'+letter
        self.data[letter] = {'cert':cert, 'priv':priv, 'root':root, 'crlref':crlref}
        self.roster['authorities'].append({
            'publisher_id':'Publisher'+letter, 'tsa_authority_id':aid,
            'root_certificate_original':rootref,
            'root_certificate_der_sha256':root_sha,
            'expected_tsa_policy_oid':POLICY,
            'crl_originals':[crlref]})
        self.bundle['epochs'][0]['publishers'].append({
            'publisher_id':'Publisher'+letter, 'warc_original':None,
            'rfc3161_original':None, 'tsa_authority_id':aid})

    def _warc(self, letter):
        f = self.f
        records = []
        for kind in core.parent.CAPTURES:
            c = f.claims[letter]['captures'][core.parent.CAPTURES.index(kind)]
            raw = Path(f.role(letter)['captures'][core.parent.CAPTURES.index(kind)][
                'http_response_original']['path']).read_bytes()
            records.append(warc_record(raw, c['public_url'], f.claims[letter][
                'claimed_capture_utc']))
        return b''.join(records)

    def _renew_warc(self, letter, data=None):
        raw = self._warc(letter) if data is None else data
        ref = self.archive(raw, 'three-original-response-warc-'+letter)
        self.role(letter)['warc_original'] = ref
        self.data[letter]['warc_bytes'] = raw
        return ref

    def _issue_token(self, letter, source):
        self.serial += 1
        d = self.data[letter]
        rootdir = Path(self.f.p.fixture.root)
        serial = rootdir/('ec405-serial-'+letter+'-'+str(self.serial)+'.txt')
        serial.write_text('01\n',encoding='ascii')
        conf = rootdir/('ec405-tsa-'+letter+'-'+str(self.serial)+'.cnf')
        conf.write_text('[tsa_config]\nserial = '+str(serial)+'\nsigner_cert = '+str(d['cert'])+
             '\nsigner_key = '+str(d['priv'])+'\ncerts = '+str(d['root'])+
             '\nsigner_digest = sha256\ndefault_policy = '+POLICY+
             '\ndigests = sha256, sha384, sha512\naccuracy = secs:1\nordering = yes\n'+
             'tsa_name = yes\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n',
             encoding='ascii')
        query = rootdir/('ec405-'+letter+'-'+str(self.serial)+'.tsq')
        token = rootdir/('ec405-'+letter+'-'+str(self.serial)+'.tsr')
        cmds = [['openssl','ts','-query','-data',str(source),'-sha256','-cert',
                 '-out',str(query)],
                ['openssl','ts','-reply','-queryfile',str(query),'-config',str(conf),
                 '-section','tsa_config','-token_out','-out',str(token)]]
        for cmd in cmds:
            p = subprocess.run(cmd, text=True,capture_output=True,timeout=20)
            if p.returncode:
                raise AssertionError('OpenSSL local test token signing failed: '+p.stderr)
        return self.archive(token.read_bytes(), 'actual-rfc3161-token-'+letter)

    def _renew_token(self, letter, source=None):
        ref = self._issue_token(letter, source or self.role(letter)['warc_original']['path'])
        self.role(letter)['rfc3161_original'] = ref
        return ref

    def _save_roster(self):
        rr = self.archive(self.roster,'two-tsa-roster')
        self.bundle['outside_tsa_roster_original'] = rr
        self.extra[core.NEW_SCALARS[2]] = rr['sha256']

    def _save_bundle(self):
        ref = self.archive(self.bundle, 'original-ec405-bundle')
        self.extra[core.NEW_SCALARS[0]] = ref['path']
        self.extra[core.NEW_SCALARS[1]] = ref['sha256']

    def _anchor_first(self):
        self.extra[core.NEW_SCALARS[5]] = self.role('A')['warc_original']['sha256']
        self.extra[core.NEW_SCALARS[6]] = self.role('B')['warc_original']['sha256']
        self.extra[core.NEW_SCALARS[7]] = self.role('A')['rfc3161_original']['sha256']
        self.extra[core.NEW_SCALARS[8]] = self.role('B')['rfc3161_original']['sha256']

    def refresh(self, *, anchor=True, roster=False):
        if roster:
            self._save_roster()
        self._save_bundle()
        if anchor:
            self._anchor_first()

    def evaluate(self, derive=True):
        opts = dict(self.extra)
        if derive:
            opts.pop(core.AUDIT_ONLY[0],None)
        with patch.object(core, '_inputs', return_value={}), \
             patch.object(core.parent, 'audit', return_value=self.parent_report):
            return core.derive_inventory(**opts) if derive else core.audit(**opts)

    def calibrate(self):
        result = self.evaluate()
        self.extra[core.REPEAT_NAMES[0]] = [
            result['warc_timestamp_epoch_reviews'][0][
                'warc_timestamp_epoch_inventory_sha256']]
        self.extra[core.REPEAT_NAMES[1]] = [2]
        result = self.evaluate()
        self.extra[core.AUDIT_ONLY[0]] = result[
            'receiver_verified_warc_timestamp_inventory_sha256']
        return self.evaluate(False)

    def denied(self, expected=None):
        with self.assertRaises(errors.AnchorError) as caught:
            self.evaluate()
        if expected:
            self.assertIn(expected, caught.exception.code)

    def test_01_real_warc_11_three_http_bytes_and_two_genuine_signed_timestamps(self):
        result = self.calibrate()
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['bounded_local_warc_timestamp_and_real_ec404_parent_consistency'])
        self.assertEqual(result['verified_joint_warc_timestamp_and_real_parent_publishers'],2)
        self.assertEqual(result['warc_timestamp_epoch_reviews'][0]['actual_verified_rfc3161_count'],2)
        self.assertTrue(all(result[name] is False for name in core.NEGATIVES))

    def test_02_derive_is_unsigned_and_audit_requires_retained_sha(self):
        result = self.evaluate()
        self.assertEqual(result['schema'],core.DERIVE_SCHEMA)
        self.assertEqual(len(result['unsigned_warc_timestamp_evidence_inventory']['epochs'][0]['publishers']),2)
        self.calibrate()
        out = self.evaluate(False)
        self.assertNotIn('unsigned_warc_timestamp_evidence_inventory',out)

    def test_03_tampered_warc_content_denied(self):
        self._renew_warc('A',self.data['A']['warc_bytes'].replace(b'WARC/1.1',b'WARC/1.0',1))
        self.refresh()
        self.denied('WARC_1_1')

    def test_04_warc_body_altered_even_with_new_sha_denied(self):
        raw=self.data['A']['warc_bytes']
        self._renew_warc('A',raw.replace(b'HTTP/1.1 200 OK',b'HTTP/1.1 404 OK',1))
        self.refresh()
        self.denied('HTTP_ORIGINAL_BLOCK')

    def test_05_warc_sha256_block_digest_changed_denied(self):
        raw=self.data['B']['warc_bytes']
        self._renew_warc('B',raw.replace(b'sha256:',b'sha256:'+(b'A'*52),1))
        self.refresh()
        self.denied('WARC_')

    def test_06_wrong_signed_capture_target_uri_denied(self):
        raw=self.data['A']['warc_bytes'].replace(b'/archives/gazette.bin',
                                                 b'/archives/altered.bin',1)
        self._renew_warc('A',raw)
        self.refresh()
        self.denied('TARGET')

    def test_07_wrong_warc_claimed_date_denied(self):
        self._renew_warc('A',self.data['A']['warc_bytes'].replace(
            self.stamp.encode(),b'2026-10-20T00:00:00Z',1))
        self.refresh()
        self.denied('DATE')

    def test_08_two_duplicate_record_ids_denied(self):
        w=self._warc('A')
        # Use one of the record IDs from the WARC and overwrite the second.
        ids=list(re_match.group(1) for re_match in re.finditer(
            rb'WARC-Record-ID: <urn:uuid:([0-9a-f-]{36})>',w))
        w=w.replace(ids[1],ids[0],1)
        self._renew_warc('A',w)
        self.refresh()
        self.denied('DUPLICATE')

    def test_09_trailing_record_or_padding_denied(self):
        self._renew_warc('A',self.data['A']['warc_bytes']+b'\r\n\r\n')
        self.refresh()
        self.denied('EXTRA_TRAILING')

    def test_10_rfc3161_token_imprint_of_other_bytes_is_rejected(self):
        fake=self.archive(b'forged-other-warc-input','wrong-timestamp-imprint')
        self._renew_token('B',source=fake['path'])
        self.refresh()
        self.denied('IMPRINT')

    def test_11_wrong_tsa_policy_token_denied(self):
        self.roster['authorities'][0]['expected_tsa_policy_oid']='1.2.3.4.5.406'
        self.refresh(roster=True)
        self.denied('POLICY')

    def test_12_wrong_external_root_sha_rejected(self):
        self.extra[core.NEW_SCALARS[3]]='f'*64
        self.denied('EXTERNALLY_PINNED')

    def test_13_no_tsa_crl_has_no_verified_joint_timestamp_credit(self):
        self.roster['authorities'][0]['crl_originals']=[]
        self.refresh(roster=True)
        result=self.evaluate()
        self.assertTrue(result[core.FLAGS[4]])
        self.assertEqual(result['verified_joint_warc_timestamp_and_real_parent_publishers'],1)

    def test_14_missing_first_original_token_denied(self):
        self.role('A')['rfc3161_original']=None
        self.refresh(anchor=False)
        self.denied('FIRST_WARC_RFC3161_TOKEN')

    def test_15_parent_cryptographic_chain_must_be_real_and_bounded(self):
        self.parent_report['exit_code']=0
        self.denied('PARENT_REPORT_CONTRACT')

    def test_16_tsa_evaluation_utc_earlier_than_actual_signed_time_no_credit(self):
        self.extra[core.NEW_SCALARS[9]]='2020-01-01T00:00:00Z'
        out=self.evaluate()
        self.assertTrue(out[core.FLAGS[3]])
        self.assertEqual(out['verified_joint_warc_timestamp_and_real_parent_publishers'],0)

    def test_17_new_original_must_not_alias_parent_http_source_path(self):
        ref=self.f.role('A')['captures'][0]['http_response_original']
        self.role('A')['warc_original']=ref
        self.refresh()
        self.denied('ALIASES_REAL_PARENT')

    def test_18_new_original_must_not_alias_other_role_warc(self):
        self.role('A')['warc_original']=self.role('B')['warc_original']
        self.refresh(anchor=False)
        self.denied('ALIASES_REAL_PARENT')

    def test_19_invalid_json_parent_report_and_extra_properties_denied(self):
        self.parent_report['unexpected_verification_claim']=True
        self.denied('PARENT_REPORT_CONTRACT')

    def test_20_missing_first_warc_is_denied(self):
        self.role('B')['warc_original']=None
        self.role('B')['rfc3161_original']=None
        self.refresh(anchor=False)
        self.denied('FIRST_ORIGINAL_WARC')

    def test_21_real_token_same_original_cannot_satisfy_two_independent_roles(self):
        self.role('B')['rfc3161_original']=self.role('A')['rfc3161_original']
        self.refresh(anchor=False)
        self.denied('ALIASES_REAL_PARENT')

    def test_22_child_denials_never_report_success(self):
        result=operator.denial('audit-historical-ec339-warc-timestamp',
                               errors.AnchorError('EC405_FAKE_RECORD','permission_denied'))
        self.assertEqual(result['exit_code'],3)
        self.assertEqual(result['schema'],core.DENIAL_SCHEMA)
        self.assertTrue(all(result[k] is False for k in core.NEGATIVES))


if __name__ == '__main__':
    unittest.main()
