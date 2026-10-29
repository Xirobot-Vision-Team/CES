#!/usr/bin/env python3
"""EC-158 limited offline development fixtures (NOT native CES acceptance)."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import schema_compat as sc

FIX = Path(__file__).resolve().parent / 'fixtures' / 'ec158'


def document(raw: bytes) -> dict:
    return json.loads(raw.decode('utf-8'))


def record_bytes(obj: dict) -> bytes:
    return json.dumps(obj, separators=(',', ':')).encode('utf-8')


class CompatibilityCases(unittest.TestCase):
    def setUp(self) -> None:
        self.record = (FIX / 'ci-example.json').read_bytes()

    def test_identify_saved_without_rewrite(self) -> None:
        result = sc.inspect_bytes(self.record, path=str(FIX / 'ci-example.json'))
        self.assertTrue(result['compatible_for_offline_read'])
        self.assertEqual(result['family'], 'code_insight_saved')
        self.assertEqual(result['content_sha256'], hashlib.sha256(self.record).hexdigest())
        self.assertFalse(result['identity']['record_id_bound'])
        self.assertFalse(result['input_was_rewritten'])

    def test_valid_content_named_record(self) -> None:
        rid = 'ci-' + hashlib.sha256(self.record).hexdigest()
        report = sc.inspect_bytes(self.record, path='/test/' + rid + '.json', record_id=rid)
        self.assertTrue(report['compatible_for_offline_read'])
        self.assertTrue(report['identity']['record_id_bound'])

    def test_file_name_mismatch_rejected(self) -> None:
        report = sc.inspect_bytes(self.record, path='/test/ci-' + 'a'*64 + '.json')
        self.assertEqual(report['disposition'], 'REJECT_INVALID_V1')
        self.assertTrue(any(x['code'] == 'FILENAME_HASH_MISMATCH' for x in report['issues']))

    def test_supplied_expected_record_id_mismatch_rejected(self) -> None:
        report = sc.inspect_bytes(self.record, record_id='ci-'+'b'*64)
        self.assertFalse(report['compatible_for_offline_read'])

    def test_missing_and_future_tags_both_rejected(self) -> None:
        for value in ({'task_kind':'code_analysis'}, document((FIX/'future-version.json').read_bytes())):
            report = sc.inspect_bytes(record_bytes(value))
            self.assertEqual(report['disposition'], 'REJECT_UNVERSIONED_OR_UNKNOWN')

    def test_v1_unknown_and_missing_keys_rejected(self) -> None:
        for field in ('missing', 'unknown'):
            v = document(self.record)
            if field == 'missing':
                del v['model_origin_authenticated']
            else:
                v['custom_legacy_flag'] = False
            report = sc.inspect_bytes(record_bytes(v))
            self.assertFalse(report['compatible_for_offline_read'])

    def test_provenance_claim_not_trusted(self) -> None:
        obj = document(self.record)
        obj['semantic_claims_verified'] = True
        report = sc.inspect_bytes(record_bytes(obj))
        self.assertTrue(any(x['code'] == 'UNSUPPORTED_PROOF_CLAIM' for x in report['issues']))

    def test_duplicate_and_case_colliding_keys_rejected(self) -> None:
        for raw in (b'{"schema_version":"ces.cli.v1","schema_version":"x"}',
                    b'{"schema_version":"ces.cli.v1","Schema_Version":"x"}'):
            with self.assertRaises(sc.SchemaInputError):
                sc.inspect_bytes(raw)

    def test_nested_finding_invalid_layers_and_claims(self) -> None:
        record = document(self.record)
        record['finding_count'] = 1
        record['checked_findings'] = [{
            'id':'F01','title':'A code issue','severity':'high','confidence':'high',
            'layer':'changes','path':'foo.py','path_endpoint':'path',
            'line_start_claimed':None,'line_end_claimed':None,'line_numbers_verified':False,
            'quote_sha256':'0'*64,'quote_presence':'pathspec_scoped_tracked_diff_literal',
            'reasoning':'Potential error in path','impact':'Could alter runtime',
            'recommendation':'Review code carefully',
        }]
        report = sc.inspect_bytes(record_bytes(record))
        self.assertTrue(any(x['code'] == 'INVALID_LAYER_FOR_MODE' for x in report['issues']))
        self.assertEqual(report['identity']['finding_count'], 1)

    def test_cli_v1_response_and_unknown_coverage(self) -> None:
        obj = document((FIX.parent/'ec156'/'success.json').read_bytes())
        obj['coverage']['new_untrusted_future_flag'] = True
        report = sc.inspect_bytes(record_bytes(obj))
        self.assertTrue(report['compatible_for_offline_read'])
        self.assertEqual(report['family'], 'cli_response')
        self.assertTrue(report['advisories'])

    def test_inline_checked_schema_unknown_rejected(self) -> None:
        obj = document((FIX.parent/'ec156'/'success.json').read_bytes())
        obj['action'] = 'CodeValidate'
        obj['data'] = {'validated':True,'output_schema':'ces.code_insight_checked.v2'}
        report = sc.inspect_bytes(record_bytes(obj))
        self.assertTrue(any(x['code'] == 'UNSUPPORTED_EMBEDDED_VERSION' for x in report['issues']))

    def test_inline_codeprepare_packet_tag_and_codesave_identity(self) -> None:
        obj = document((FIX.parent/'ec156'/'success.json').read_bytes())
        obj['action'] = 'CodePrepare'
        obj['data'] = {'prepared':True,'review_packet':{'schema_version':'ces.code_packet.v2'}}
        report = sc.inspect_bytes(record_bytes(obj))
        self.assertFalse(report['compatible_for_offline_read'])
        obj['action'] = 'CodeSave'
        obj['read_only'] = False
        obj['coverage']['code_result_persisted'] = True
        obj['data'] = {'persisted':True,'record_schema':'ces.code_insight_saved.v1',
                       'record_id':'ci-'+'a'*64, 'record_sha256':'b'*64}
        report = sc.inspect_bytes(record_bytes(obj))
        self.assertTrue(any(x['code'] == 'SAVE_IDENTITY_INCONSISTENT' for x in report['issues']))

    def test_collect_is_wire_v1_not_invented_collect_schema(self) -> None:
        report = sc.inspect_file(str(FIX/'collect.v1.json'), 'auto')
        self.assertEqual(report['family'], 'collect_snapshot')
        self.assertTrue(report['compatible_for_offline_read'])
        self.assertFalse(report['runtime_or_source_provenance_verified'])

    def test_collect_can_be_read_as_generic_cli_response(self) -> None:
        report = sc.inspect_file(str(FIX/'collect.v1.json'), 'cli_response')
        self.assertTrue(report['compatible_for_offline_read'])
        self.assertEqual(report['family'], 'cli_response')

    def test_numeric_overflow_rejected(self) -> None:
        with self.assertRaises(sc.SchemaInputError):
            sc.inspect_bytes(b'{"schema_version":"ces.cli.v1","fake":1e999}')

    def test_draft_optional_line_pair_and_bom(self) -> None:
        obj = dict(schema_version='ces.code_insight_draft.v1',task_kind='code_analysis',
                   packet_sha256='a'*64,saved_collect_sha256='b'*64,
                   summary='Synthetic text',findings=[],limitations=[])
        report = sc.inspect_bytes(b'\xef\xbb\xbf' + record_bytes(obj))
        self.assertTrue(report['compatible_for_offline_read'])
        self.assertEqual(report['family'], 'code_insight_draft')
        obj['findings'] = [dict(id='F1',title='Known title',severity='info',confidence='low',
                                layer='changes',path='some/file',evidence_quote='abcdefgh',
                                reasoning='A reason to check',impact='Possible impact',
                                recommendation='Investigate it',line_start=1)]
        report = sc.inspect_bytes(record_bytes(obj))
        self.assertFalse(report['compatible_for_offline_read'])

    def test_owner_exact_bytes_only(self) -> None:
        report = sc.inspect_file(str(FIX/'owner.json'), 'auto')
        self.assertTrue(report['compatible_for_offline_read'])
        pretty = json.dumps(document((FIX/'owner.json').read_bytes()),indent=2).encode()
        self.assertFalse(sc.inspect_bytes(pretty)['compatible_for_offline_read'])

    def test_preview_only_identity_noop_new_version_blocked(self) -> None:
        source = sc.inspect_bytes(self.record)
        noop = sc.preview_upgrade(source,'ces.code_insight_saved.v1')
        blocked = sc.preview_upgrade(source,'ces.code_insight_saved.v2')
        self.assertEqual(noop['disposition'], 'NOOP_KEEP_ORIGINAL_BYTES')
        self.assertEqual(blocked['disposition'], 'BLOCKED_NO_AUTHORIZED_MIGRATION')
        self.assertFalse(noop['upgrade_executed'] or blocked['upgrade_executed'])

    def test_reject_nonregular_paths_and_large_saved_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'x.json'
            path.write_bytes(self.record)
            report = sc.inspect_file(str(path),'auto')
            self.assertTrue(report['compatible_for_offline_read'])
            self.assertEqual(path.read_bytes(), self.record)
            oversized = self.record + b' ' * (sc.LIMITS['code_insight_saved'] - len(self.record) + 1)
            with self.assertRaises(sc.SchemaInputError):
                # Explicit kind enforces read limit before parsing.
                sc._file_bytes(str(Path(tmp)), 1)
            path.write_bytes(oversized)
            report = sc.inspect_file(str(path),'auto')
            self.assertEqual(report['disposition'],'REJECT_INVALID_V1')
            self.assertEqual(path.read_bytes(), oversized)


if __name__ == '__main__':
    unittest.main(verbosity=2)
