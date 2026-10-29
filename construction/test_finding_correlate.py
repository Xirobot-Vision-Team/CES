#!/usr/bin/env python3
"""EC180 scoped correlation synthetic development cases, NOT final acceptance."""
from __future__ import annotations

import copy
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import unittest

import finding_correlate as correlate
import finding_save as save
import finding_schema as fs
import test_finding_show as earlier

FIX = Path(__file__).resolve().parent / 'fixtures' / 'ec158' / 'ci-example.json'


class FindingCorrelationCases(unittest.TestCase):
    setUp = earlier.FindingShowCases.setUp
    begin = earlier.FindingShowCases.begin
    start_finding = earlier.FindingShowCases.start_finding
    setup_projection = earlier.FindingShowCases.setup_projection
    setup_input = earlier.FindingShowCases.setup_input
    act = earlier.FindingShowCases.act
    callback = earlier.FindingShowCases.callback
    setup_save_store = earlier.FindingShowCases.setup_save_store
    project = earlier.FindingShowCases.project
    prepare = earlier.FindingShowCases.prepare
    validate = earlier.FindingShowCases.validate
    review = earlier.FindingShowCases.review
    with_review = earlier.FindingShowCases.with_review
    candidate = earlier.FindingShowCases.candidate
    dispatch = earlier.FindingShowCases.dispatch
    review_key = staticmethod(earlier.FindingShowCases.review_key)
    start = earlier.FindingShowCases.start
    save = earlier.FindingShowCases.save
    setup_historical = earlier.FindingShowCases.setup_historical
    commit = earlier.FindingShowCases.commit
    files = earlier.FindingShowCases.files
    second_batch = earlier.FindingShowCases.second_batch
    make_legacy_v1_record = earlier.FindingShowCases.make_legacy_v1_record

    def make(self, *, signed=('confirm',), historical=False, ttl_seconds=300):
        self.begin(signed=signed, historical=historical, ttl_seconds=ttl_seconds)
        self.configure(historical=historical)

    def make_multi(self, *, count=3, commits=3):
        # EC179's batch builder expects an initialized *empty* store.
        self.start_finding()
        self.second_batch(count=count, commits=commits)
        self.configure()

    def configure(self, *, historical=False):
        self.correlator = correlate.FindingCorrelator(
            str(self.root), str(self.repo), str(self.ledger_root), clock=self.clock)
        self.scope = {
            'authorized_source_binding': dict(self.preview['source_binding']),
            'query_content_for': self.prepared['source_mode'],
            'authorize_store_read': True,
            'authorize_query': True,
            'authorize_scope_correlation': True,
            'authorize_digest_details': True,
            'acknowledge_historical_proposal_metadata': historical,
        }
        self.arguments = {
            'expected_finding_store_pin': self.ledger_pin,
            'authorize_correlation': True,
            'scopes': [self.scope],
            'authorize_path_correlation': True,
        }

    def compare(self, **kw):
        params = dict(self.arguments)
        params.update(kw)
        return self.correlator.correlate(**params)

    def deny(self, result, code=None):
        self.assertIn(result['status'], ('invalid_input', 'unavailable'), result)
        self.assertEqual(result['nodes'], [], result)
        self.assertEqual(result['edges'], [], result)
        self.assertIsNone(result['next_cursor'], result)
        if code:
            self.assertEqual(result['reason_code'], code, result)

    def fixture_ci(self, *, findings=True, root=None, mode='working_tree_diff',
                   quote=None, path='read-only.py'):
        data = json.loads(FIX.read_text())
        data['source_root'] = str(self.repo) if root is None else root
        data['source_mode'] = mode
        if findings:
            data['finding_count'] = 1
            data['checked_findings'] = [{
                'id': 'F1', 'title': 'Synthetic candidate only',
                'severity': 'medium', 'confidence': 'low',
                'layer': 'unstaged' if mode == 'working_tree_diff' else 'changes',
                'path': path, 'path_endpoint': 'path',
                'line_start_claimed': None, 'line_end_claimed': None,
                'line_numbers_verified': False,
                'quote_sha256': quote if quote else 'a' * 64,
                'quote_presence': 'pathspec_scoped_tracked_diff_literal',
                'reasoning': 'Not objective', 'impact': 'Unknown impact',
                'recommendation': 'Check locally',
            }]
        raw = json.dumps(data, separators=(',', ':')).encode('utf-8')
        return {'record_id': 'ci-' + hashlib.sha256(raw).hexdigest(), 'raw_bytes': raw}

    def with_ci(self, entries, **kw):
        return self.compare(
            codeinsight_records=entries,
            authorize_cross_source_correlation=True,
            authorize_codeinsight_byte_inspection=True,
            authorize_codeinsight_correlation=True,
            **kw,
        )

    def test_one_real_hmac_record_graph_no_negative_or_ci_claim(self):
        self.make()
        before = {str(p): p.read_bytes() for p in self.files()}
        result = self.compare()
        self.assertEqual((result['status'], result['exit_code']), ('partial', 2), result)
        self.assertEqual(result['node_count'], 1)
        self.assertEqual(result['edge_count'], 0)
        self.assertEqual(result['candidate_edge_count'], 0)
        self.assertEqual(result['nodes'][0]['path_index_state'], 'PARTIAL_OR_UNPATHED')
        self.assertFalse(result['effects']['business_repository_written'])
        self.assertFalse(result['effects']['ci_or_actual_test_verified'])
        self.assertTrue(result['limitations']['no_edge_does_not_prove_different_or_fixed'])
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.files()})
        plain = json.dumps(result)
        for forbidden in ('read-only.py', 'diff --git', 'Synthetic patch line',
                          'synthetic-reviewer', 'Independent synthetic review'):
            self.assertNotIn(forbidden, plain)

    def test_scope_and_digest_grants_not_inferred_from_old_finding_show(self):
        self.make()
        for attr in ('authorize_store_read', 'authorize_query',
                     'authorize_scope_correlation', 'authorize_digest_details'):
            scope = dict(self.scope, **{attr: False})
            self.deny(self.compare(scopes=[scope]),
                      'FINDINGCORRELATE_EACH_SCOPE_NEEDS_FRESH_INDEPENDENT_GRANTS')
        self.deny(self.compare(authorize_correlation=False),
                  'FINDINGCORRELATE_INDEPENDENT_CORRELATION_GRANT_REQUIRED')
        self.deny(self.compare(expected_finding_store_pin='0' * 64),
                  'FINDINGCORRELATE_STORE_PIN_CHANGED')

    def test_strict_full_source_scope_does_not_broaden_without_data(self):
        self.make()
        mutated = dict(self.scope)
        mutated['authorized_source_binding'] = dict(self.scope['authorized_source_binding'])
        mutated['authorized_source_binding']['material_sha256'] = 'a' * 64
        empty = self.compare(scopes=[mutated])
        self.assertEqual(empty['node_count'], 0, empty)
        self.assertEqual(empty['status'], 'partial')
        mutated['authorized_source_binding'] = {'source_mode': 'WorkingTree'}
        self.deny(self.compare(scopes=[mutated]),
                  'FINDINGSHOW_EXACT_SOURCE_BINDING_SCOPE_REQUIRED')

    def test_source_duplicate_and_cross_partition_require_new_grant(self):
        self.make()
        self.deny(self.compare(scopes=[self.scope, self.scope],
                               authorize_cross_source_correlation=True),
                  'FINDINGCORRELATE_DUPLICATE_SOURCE_SCOPE')
        other = copy.deepcopy(self.scope)
        other['authorized_source_binding']['material_sha256'] = 'f' * 64
        self.deny(self.compare(scopes=[self.scope, other]),
                  'FINDINGCORRELATE_CROSS_SOURCE_NEEDS_NEW_GRANT')
        r = self.compare(scopes=[self.scope, other],
                         authorize_cross_source_correlation=True)
        self.assertEqual([x['selected_findings'] for x in r['scope_coverage']], [1, 0])

    def test_two_saved_same_anchor_are_only_similarity_not_duplicate(self):
        self.make_multi(count=2, commits=2)
        result = self.compare()
        self.assertEqual(result['node_count'], 2, result)
        self.assertEqual(result['candidate_edge_count'], 1, result)
        edge = result['edges'][0]
        self.assertEqual(edge['relation_state'], 'CANDIDATE_SIMILARITY')
        self.assertIn('SHARED_SEALED_ANCHOR_DIGEST', edge['signals'])
        self.assertFalse(edge['same_real_defect_proven'])
        self.assertFalse(edge['fixed_or_regressed_proven'])

    def test_pair_matching_requires_paired_path_quote_not_independent_overlap(self):
        a = {
            'kind': 'FINDING_HMAC', 'finding_id': 'a'*64,
            'source_binding': {'scope': 'same'}, 'source_mode': 'WorkingTree',
            'anchors': [('a'*64, 'b'*64, '1'*64), ('c'*64, 'd'*64, '2'*64)],
            'original_sha256': '1'*64, 'expired': False, 'historical': False,
            'assessment_state': 'REVIEWED', 'path_state': 'COMPLETE',
            'coverage_complete': True, 'counter_count': 0, 'node_id': 'a'*64,
        }
        b = dict(a, finding_id='b'*64, original_sha256='3'*64,
                 node_id='b'*64, anchors=[('a'*64, 'd'*64, '3'*64),
                                          ('c'*64, 'b'*64, '4'*64)])
        edge = correlate._compare(a, b, allow_path=True)
        self.assertEqual(edge['relation_state'], 'UNKNOWN')
        self.assertNotIn('SHARED_PATH_AND_QUOTE_DIGEST_SAME_ANCHOR', edge['signals'])
        b['anchors'] = [('a'*64, 'b'*64, '5'*64)]
        self.assertEqual(correlate._compare(a, b, allow_path=True)['relation_state'],
                         'CANDIDATE_SIMILARITY')
        self.assertEqual(correlate._compare(a, b, allow_path=False)['relation_state'],
                         'UNKNOWN')

    def test_rejected_remains_ineligible_even_with_shared_anchor(self):
        self.make_multi(count=2, commits=2)
        self.assertEqual(self.compare()['edges'][0]['relation_state'],
                         'CANDIDATE_SIMILARITY')
        # Evaluating the same signed anchor claims with a local REJECTED state
        # must never classify it as an eligible duplicate, even in isolation.
        common = {
            'kind': 'FINDING_HMAC', 'finding_id': 'a'*64,
            'source_binding': dict(self.scope['authorized_source_binding']),
            'source_mode': 'WorkingTree',
            'anchors': [(None, 'b'*64, 'c'*64)], 'original_sha256': 'd'*64,
            'expired': False, 'historical': False,
            'assessment_state': 'REVIEWED', 'path_state': 'PARTIAL_OR_UNPATHED',
            'coverage_complete': True, 'counter_count': 0, 'node_id': '1'*64,
        }
        rejected = dict(common, node_id='2'*64, finding_id='e'*64,
                        assessment_state='REJECTED')
        edge = correlate._compare(common, rejected, allow_path=True)
        self.assertEqual(edge['relation_state'], 'INELIGIBLE')
        self.assertIn('REJECTED_LOCAL_CLAIM', edge['basis'])

    def test_existing_v1_legacy_finding_never_infers_path(self):
        self.make(historical=True)
        self.make_legacy_v1_record()
        r = self.compare()
        self.assertEqual(r['status'], 'partial', r)
        self.assertEqual(r['scope_coverage'][0]['legacy_v1_unindexed'], 1)
        self.assertEqual(r['nodes'][0]['path_index_state'], 'LEGACY_V1_UNAVAILABLE')

    def test_historical_metadata_requires_explicit_ack(self):
        self.make(historical=True)
        bad = dict(self.scope, acknowledge_historical_proposal_metadata=False)
        self.deny(self.compare(scopes=[bad]),
                  'FINDINGCORRELATE_HISTORICAL_REQUIRES_SEPARATE_ACK')
        self.assertTrue(self.compare()['nodes'][0]['historical_proposal_only'])

    def test_expired_is_hidden_then_available_only_for_audit(self):
        self.make(ttl_seconds=60)
        self.clock.value += timedelta(seconds=61)
        fresh = self.compare()
        self.assertEqual(fresh['node_count'], 0)
        self.deny(self.compare(include_expired=True),
                  'FINDINGCORRELATE_EXPIRED_NEEDS_SEPARATE_AUDIT_GRANT')
        expired = self.compare(include_expired=True, authorize_expired_audit=True)
        self.assertEqual(expired['node_count'], 1)
        self.assertTrue(expired['nodes'][0]['expired_at_query_time'])
        self.assertFalse(expired['effects']['fix_verified'])

    def test_cursor_sorts_bound_and_does_not_renew(self):
        self.make_multi(count=4, commits=3)
        params = {'page_size': 1}
        a = self.compare(**params)
        self.assertEqual(a['edge_count'], 3, a)
        self.assertIsNotNone(a['next_cursor'])
        b = self.compare(cursor=a['next_cursor'], **params)
        self.assertEqual(b['status'], 'partial', b)
        self.assertNotEqual(a['edges'][0], b['edges'][0])
        self.assertEqual(a['cursor_expires_at_utc'], b['cursor_expires_at_utc'])
        c = self.compare(cursor=b['next_cursor'], **params)
        self.assertEqual(c['status'], 'partial', c)
        self.assertIsNone(c['next_cursor'])
        self.assertEqual(len({str(x['edges'][0]) for x in (a, b, c)}), 3)

    def test_cursor_disallows_grant_loss_query_change_and_tampering(self):
        self.make_multi(count=3, commits=3)
        first = self.compare(page_size=1)
        token = first['next_cursor']
        self.assertIsNotNone(token)
        self.deny(self.compare(cursor=token, page_size=2),
                  'FINDINGCORRELATE_CURSOR_QUERY_OR_GRAPH_DRIFT')
        self.deny(self.compare(cursor=token, page_size=1, authorize_path_correlation=False),
                  'FINDINGCORRELATE_CURSOR_QUERY_OR_GRAPH_DRIFT')
        self.deny(self.compare(cursor=token, page_size=1, authorize_correlation=False))
        tampered = token[:-1] + ('0' if token[-1] != '0' else '1')
        self.deny(self.compare(cursor=tampered, page_size=1),
                  'FINDINGCORRELATE_CURSOR_SIGNATURE_INVALID')

    def test_cursor_expiry_denies_without_partial_edges(self):
        self.make_multi(count=3, commits=3)
        first = self.compare(page_size=1)
        self.clock.value += timedelta(seconds=181)
        denied = self.compare(cursor=first['next_cursor'], page_size=1)
        self.deny(denied)

    def test_cursor_invalid_after_new_sealed_batch(self):
        self.make_multi(count=4, commits=3)
        first = self.compare(page_size=1)
        self.assertIsNotNone(first['next_cursor'])
        ids = sorted(f['finding_id'] for f in self.preview['findings'])
        saved = self.commit(finding_save_operation_key='correlation-later-batch-001',
                            authorized_finding_ids=[ids[3]])
        self.assertEqual(saved['status'], 'partial', saved)
        self.deny(self.compare(cursor=first['next_cursor'], page_size=1),
                  'FINDINGCORRELATE_CURSOR_QUERY_OR_GRAPH_DRIFT')

    def test_fail_closed_if_any_private_hmac_record_corrupted(self):
        self.make()
        target = self.files()[0]
        target.write_bytes(target.read_bytes() + b' ')  # strict record bytes
        self.deny(self.compare())

    def test_codeinsight_requires_independent_permissions_and_content_id(self):
        self.make()
        ci = self.fixture_ci()
        self.deny(self.compare(codeinsight_records=[ci]),
                  'FINDINGCORRELATE_CROSS_SOURCE_NEEDS_NEW_GRANT')
        self.deny(self.compare(codeinsight_records=[ci],
                               authorize_cross_source_correlation=True),
                  'FINDINGCORRELATE_CODEINSIGHT_NEEDS_SEPARATE_GRANTS')
        altered = dict(ci, record_id='ci-' + '0'*64)
        self.deny(self.with_ci([altered]),
                  'FINDINGCORRELATE_CODEINSIGHT_OFFLINE_SCHEMA_OR_HASH_INVALID')

    def test_real_strict_offline_codeinsight_join_never_claims_native_or_ci(self):
        self.make()
        digest = self.preview['findings'][0]['evidence']['positive_anchors'][0]['quote_sha256']
        sample = self.fixture_ci(quote=digest)
        result = self.with_ci([sample], include_unknown_pairs=True)
        self.assertEqual(result['status'], 'partial', result)
        self.assertEqual(result['node_count'], 2)
        self.assertEqual(result['edge_count'], 1)
        self.assertEqual(result['edges'][0]['relation_state'], 'UNKNOWN')
        self.assertIn('SHARED_QUOTE_DIGEST', result['edges'][0]['signals'])
        self.assertFalse(result['codeinsight_coverage']['native_store_or_git_authenticated'])
        self.assertFalse(result['codeinsight_coverage']['ci_test_observations_available'])
        self.assertFalse(result['effects']['ci_or_actual_test_verified'])
        literal = json.dumps(result)
        for sensitive in ('Synthetic candidate only', 'read-only.py', 'Check locally',
                          'Not objective', 'raw_bytes'):
            self.assertNotIn(sensitive, literal)

    def test_codeinsight_wrong_root_mode_or_duplicate_input_deny_all(self):
        self.make()
        self.deny(self.with_ci([self.fixture_ci(root='/elsewhere')]),
                  'FINDINGCORRELATE_CODEINSIGHT_ROOT_OR_MODE_NOT_EXACTLY_AUTHORIZED')
        entry = self.fixture_ci()
        self.deny(self.with_ci([entry, entry]),
                  'FINDINGCORRELATE_DUPLICATE_CODEINSIGHT_RECORD')
        poisoned = dict(entry, raw_bytes=entry['raw_bytes'] + b'{}')
        self.deny(self.with_ci([poisoned]))
        self.deny(self.with_ci([dict(entry, raw_bytes=entry['raw_bytes'].replace(
            b'"ci_verified":false', b'"ci_verified":true'))]))

    def test_no_silent_large_graph_truncation_or_type_coercion(self):
        self.make()
        for page_size in (0, 26, True, 5.0):
            self.deny(self.compare(page_size=page_size),
                      'FINDINGCORRELATE_PAGE_SIZE_BOUND')
        self.deny(self.compare(scopes=[]),
                  'FINDINGCORRELATE_SOURCE_SCOPE_BOUND')
        self.deny(self.compare(scopes=[self.scope] * 5),
                  'FINDINGCORRELATE_SOURCE_SCOPE_BOUND')
        self.deny(self.compare(include_expired='yes'),
                  'FINDINGCORRELATE_GRANT_FLAG_NOT_BOOLEAN')

    def test_exact_finding_allowlist_refines_large_or_scoped_graph_without_guessing(self):
        self.make_multi(count=4, commits=4)
        ids = sorted(f['finding_id'] for f in self.preview['findings'])
        selected = dict(self.scope, finding_id_allowlist=ids[:2])
        result = self.compare(scopes=[selected])
        self.assertEqual(result['node_count'], 2)
        self.assertEqual(result['scope_coverage'][0][
            'excluded_by_explicit_finding_id_allowlist'], 2)
        self.assertEqual(result['candidate_edge_count'], 1)
        self.assertFalse(result['scope_coverage'][0][
            'whole_source_defect_absence_proven'])
        for invalid in ([], [ids[0], ids[0]], [ids[1], ids[0]],
                        ['*'], ['0'*63], ['A'*64], True):
            scoped = dict(self.scope, finding_id_allowlist=invalid)
            self.deny(self.compare(scopes=[scoped]),
                      'FINDINGCORRELATE_FINDING_ALLOWLIST_MUST_BE_SORTED_UNIQUE_DIGESTS')

    def test_real_response_schema_accepts_success_and_denial_but_no_proof_escalation(self):
        import jsonschema
        path = Path(__file__).resolve().parent.parent / 'references' / \
            'finding-correlation-result.v1.schema.json'
        schema = json.loads(path.read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        self.make()
        success = self.compare()
        denied = self.compare(authorize_correlation=False)
        jsonschema.validate(success, schema)
        jsonschema.validate(denied, schema)
        injected = copy.deepcopy(success)
        injected['effects']['ci_or_actual_test_verified'] = True
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(injected, schema)
        injected = copy.deepcopy(success)
        injected['nodes'][0]['raw_model_reasoning'] = 'secret'
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(injected, schema)
        injected = copy.deepcopy(denied)
        injected['node_count'] = 1
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(injected, schema)

    def test_local_claim_equivalence_distinct_from_semantic_duplicate(self):
        a = {
            'kind': 'FINDING_HMAC', 'finding_id': 'f'*64,
            'source_binding': {'source_mode': 'WorkingTree'}, 'source_mode': 'WorkingTree',
            'anchors': [(None, 'a'*64, 'b'*64)], 'original_sha256': 'c'*64,
            'historical': False, 'expired': False, 'assessment_state': 'REVIEWED',
            'path_state': 'PARTIAL_OR_UNPATHED', 'coverage_complete': True,
            'counter_count': 0, 'node_id': '1'*64,
        }
        b = dict(a, node_id='2'*64)
        edge = correlate._compare(a, b, allow_path=False)
        self.assertEqual(edge['relation_state'], 'EQUIVALENT_DECLARATION')
        self.assertFalse(edge['same_real_defect_proven'])
        self.assertFalse(edge['duplicate_bug_proven'])
        b['expired'] = True
        self.assertEqual(correlate._compare(a, b, allow_path=True)['relation_state'],
                         'INELIGIBLE')


if __name__ == '__main__':
    unittest.main()
