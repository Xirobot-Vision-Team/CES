"""EC202 bounded real local file reads (synthetic temp source fixtures only)."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from knowledge_bootstrap import (KnowledgeBootstrap, MANIFEST_NAME, MANIFEST_SCHEMA,
                                 REQUEST_SCHEMA, POLICY_SCHEMA)
from knowledge_boundary import canonical

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

H = 'a' * 64
REV = {'algorithm': 'sha1', 'oid': '2' * 40}
ROOT = Path(__file__).resolve().parent.parent


def h(data):
    return hashlib.sha256(data).hexdigest()


def source(name, kind, path, content=None):
    return {'source_key': name, 'kind': kind, 'relative_path': path,
            'expected_sha256': h(content) if content is not None else None,
            'coverage': 'partial_declared'}


def request(*rows, target=REV, expected_manifest=None):
    return {'schema': REQUEST_SCHEMA, 'operation': 'knowledge.bootstrap.read',
            'scope': {
                'repository_ref': 'cesrepo1:' + '1' * 64,
                'knowledge_space_key': 'architecture',
                'period': {'period_id': 'oct-2026',
                           'start_utc': '2026-10-01T00:00:00Z',
                           'end_utc': '2026-11-01T00:00:00Z'},
                'target': {'mode': 'DeliveredTarget', 'revision': target,
                           'source_receipt_sha256': None},
                'source_policy_revision': 'policy-v1',
            }, 'expected_manifest_sha256': expected_manifest,
            'sources': list(rows)}


def policy(api, req, *, knowledge=True, manifest=True, repository=True,
           provenance=False, content=False):
    preview = api.binding_preview(request_json=canonical(req))
    assert preview['status'] == 'partial', preview
    pins = preview['subject']
    return {'schema': POLICY_SCHEMA, 'purpose': 'knowledge_bootstrap_local_read_only',
            'repository_ref': req['scope']['repository_ref'],
            'knowledge_space_key': req['scope']['knowledge_space_key'],
            'period_id': req['scope']['period']['period_id'],
            'source_policy_revision': req['scope']['source_policy_revision'],
            'request_binding_sha256': pins['request_binding_sha256'],
            'scope_binding_sha256': pins['scope_binding_sha256'],
            'repository_root_binding_sha256': pins['repository_root_binding_sha256'],
            'knowledge_root_binding_sha256': pins['knowledge_root_binding_sha256'],
            'permit_bootstrap_read': True,
            'permit_repository_read': repository,
            'permit_knowledge_read': knowledge,
            'permit_manifest_read': manifest,
            'permit_provenance_projection': provenance,
            'permit_content_projection': content,
            'permit_knowledge_write': False, 'permit_repository_write': False,
            'permit_business_source_write': False, 'permit_issue_write': False,
            'permit_publish': False, 'read_receipt_sha256': H,
            'source_grants': [{'source_key': p['source_key'],
                               'source_binding_sha256': p['source_binding_sha256'],
                               'permit_source_read': True,
                               'permit_content_projection': content,
                               'read_receipt_sha256': H}
                              for p in pins['source_bindings']]}


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ces-ec202-')
        self.addCleanup(self.tmp.cleanup)
        parent = Path(self.tmp.name)
        self.repo = parent / 'repo'
        self.repo.mkdir()
        self.knowledge = parent / 'ces-knowledge'
        self.api = KnowledgeBootstrap(repository_root=str(self.repo),
                                      knowledge_root=str(self.knowledge))

    def write(self, root, path, content):
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def make_manifest(self, docs=(), *, coverage='partial_declared',
                      stamp='2026-10-10T12:00:00Z'):
        self.knowledge.mkdir(exist_ok=True)
        entries = []
        for path, content in docs:
            self.write(self.knowledge, path, content)
            entries.append({'relative_path': path, 'sha256': h(content),
                            'size_bytes': len(content)})
        manifest = {'schema': MANIFEST_SCHEMA,
                    'repository_ref': request()['scope']['repository_ref'],
                    'knowledge_space_key': 'architecture',
                    'source_policy_revision': 'policy-v1',
                    'snapshot_version': 'snapshot-0001',
                    'captured_at_utc': stamp, 'coverage': coverage,
                    'entries': sorted(entries, key=lambda x: x['relative_path'])}
        raw = canonical(manifest).encode('utf-8')
        self.write(self.knowledge, MANIFEST_NAME, raw)
        return h(raw)

    def go(self, req, p=None):
        if p is None:
            p = policy(self.api, req)
        return self.api.read(request_json=canonical(req),
                             read_policy_json=canonical(p))

    def success(self, req, p=None):
        result = self.go(req, p)
        self.assertEqual((result['status'], result['exit_code']), ('partial', 2), result)
        self.assertEqual(json.loads(result['canonical_json']), result['subject'])
        self.assertEqual(result['subject']['verified_delivered_facts'], [])
        self.assertEqual(result['subject']['summary']['authenticated_delivered_facts'], 0)
        self.assertTrue(result['subject']['no_write_actions_performed'])
        self.assertFalse(any(result['limitations'].values()))
        return result['subject']

    def refusal(self, req, p, code, status='unavailable'):
        result = self.go(req, p)
        self.assertEqual((result['status'],result['reason_code']),
                         (status, 'KNOWLEDGE_BOOTSTRAP_' + code), result)
        self.assertIsNone(result['subject'])
        self.assertIsNone(result['canonical_json'])

    def test_actual_repository_and_knowledge_bytes_no_promotion(self):
        code = b'class Cache: pass\n'
        doc = b'# Architecture\nThis is a stored claim.\n'
        self.write(self.repo, 'src/cache.py', code)
        mh = self.make_manifest([('sections/cache.md', doc)])
        req = request(source('code', 'repository', 'src/cache.py', code),
                      source('knowledge', 'ces_knowledge', 'sections/cache.md', doc),
                      expected_manifest=mh)
        p = policy(self.api, req, provenance=True, content=True)
        result = self.success(req, p)
        self.assertEqual([s['state'] for s in result['sources']],
                         ['READ_UNVERIFIED', 'READ_UNVERIFIED'])
        self.assertEqual(result['summary']['selected_source_bytes_read'], len(code)+len(doc))
        self.assertEqual(result['knowledge_manifest']['snapshot_version'], 'snapshot-0001')
        self.assertEqual(result['knowledge_manifest']['period_relation'],
                         'WITHIN_DECLARED_PERIOD')
        self.assertEqual(result['sources'][0]['observed_sha256'], h(code))
        self.assertEqual(result['sources'][1]['manifest_entry_match'], True)
        self.assertEqual(base64.b64decode(result['sources'][1]['content_base64']), doc)
        self.assertEqual(result['current_architecture_state'], 'UNKNOWN_NOT_AUTHENTICATED')
        self.assertFalse(result['sources'][0]['source_classification'].endswith('VERIFIED'))
        self.assertEqual(result['coverage_gaps'], [])

    def test_empty_missing_knowledge_root_proposes_no_write_initialization(self):
        req = request()
        result = self.success(req)
        manifest = result['knowledge_manifest']
        self.assertEqual(manifest['state'], 'STORE_MISSING_UNINITIALIZED')
        self.assertEqual(manifest['empty_initialization_proposal']['entries'], [])
        self.assertEqual(manifest['empty_initialization_proposal']['coverage'], 'unknown')
        self.assertFalse(self.knowledge.exists())
        self.assertTrue(any(g['gap_code'] == 'STORE_MISSING_UNINITIALIZED'
                            for g in result['coverage_gaps']))

    def test_empty_existing_knowledge_dir_remains_uninitialized(self):
        self.knowledge.mkdir()
        result = self.success(request())
        self.assertEqual(result['knowledge_manifest']['state'],
                         'EMPTY_DIRECTORY_UNINITIALIZED')
        self.assertEqual(list(self.knowledge.iterdir()), [])

    def test_real_empty_manifest_is_declared_only(self):
        mh = self.make_manifest([], coverage='complete_declared')
        result = self.success(request(expected_manifest=mh))
        self.assertEqual(result['knowledge_manifest']['state'],
                         'EMPTY_MANIFEST_DECLARED_UNVERIFIED')
        self.assertIsNone(result['knowledge_manifest']['empty_initialization_proposal'])
        self.assertEqual(result['knowledge_manifest']['declared_entries'], 0)
        self.assertEqual(result['verified_delivered_facts'], [])

    def test_nonempty_unindexed_directory_has_coverage_gap(self):
        self.write(self.knowledge, 'unknown.md', b'unknown')
        r = self.success(request(source('x', 'ces_knowledge', 'unknown.md')))
        self.assertEqual(r['sources'][0]['state'], 'SNAPSHOT_NOT_AVAILABLE')
        self.assertEqual(r['knowledge_manifest']['state'], 'UNINDEXED_NONEMPTY_DIRECTORY')

    def test_unauthorized_manifest_and_selected_sources_not_inspected(self):
        self.make_manifest([('private.md', b'secret')])
        req = request(source('k', 'ces_knowledge', 'private.md'))
        p = policy(self.api, req, knowledge=False, manifest=False)
        result = self.success(req, p)
        self.assertEqual(result['knowledge_manifest']['state'], 'DENIED_NOT_INSPECTED')
        self.assertEqual(result['sources'][0]['state'], 'DENIED_NOT_INSPECTED')
        self.assertNotIn('secret', canonical(result))
        self.assertIsNone(result['knowledge_manifest']['declared_entries'])

    def test_per_source_denial_does_not_access_or_leak(self):
        self.write(self.repo, 'do-not-read.txt', b'private')
        req = request(source('r', 'repository', 'do-not-read.txt'))
        p = policy(self.api, req, provenance=True, content=True)
        p['source_grants'][0]['permit_source_read'] = False
        p['source_grants'][0]['permit_content_projection'] = False
        p['source_grants'][0]['read_receipt_sha256'] = None
        s = self.success(req, p)['sources'][0]
        self.assertEqual(s['state'], 'DENIED_NOT_INSPECTED')
        self.assertIsNone(s['size_bytes'])
        self.assertIsNone(s['observed_sha256'])

    def test_provenance_and_raw_bytes_two_separate_optins(self):
        self.write(self.repo, 'src.txt', b'raw material')
        req = request(source('x', 'repository', 'src.txt'))
        hidden = self.success(req)
        self.assertIsNone(hidden['sources'][0]['observed_sha256'])
        self.assertIsNone(hidden['sources'][0]['content_base64'])
        p = policy(self.api, req, provenance=True, content=False)
        shown = self.success(req, p)
        self.assertEqual(shown['sources'][0]['observed_sha256'], h(b'raw material'))
        self.assertIsNone(shown['sources'][0]['content_base64'])
        self.assertEqual(hidden['sources'][0]['source_ref'], shown['sources'][0]['source_ref'])

    def test_knowledge_source_ref_stable_across_provenance_permissions(self):
        self.make_manifest([('one.md', b'first')])
        req = request(source('k', 'ces_knowledge', 'one.md'))
        a = self.success(req)
        b = self.success(req, policy(self.api, req, provenance=True))
        self.assertEqual(a['sources'][0]['source_ref'], b['sources'][0]['source_ref'])

    def test_stale_local_repository_root_binding_denied(self):
        req = request()
        p = policy(self.api, req)
        self.repo.rename(self.repo.parent / 'moved')
        self.repo.mkdir()
        self.refusal(req, p, 'POLICY_BINDING_MISMATCH')

    def test_changed_source_with_expected_digest_is_not_selected(self):
        self.write(self.repo, 'cache.txt', b'new bytes')
        req = request(source('a', 'repository', 'cache.txt', b'old bytes'))
        r = self.success(req)
        self.assertEqual(r['sources'][0]['state'], 'EXPECTED_SHA_MISMATCH')
        self.assertEqual(r['summary']['repository_sources_read'], 0)

    def test_knowledge_manifest_entry_hash_mismatch_blocks_projection(self):
        self.make_manifest([('one.md', b'expected')])
        self.write(self.knowledge, 'one.md', b'altered')
        req = request(source('a', 'ces_knowledge', 'one.md'))
        p = policy(self.api, req, provenance=True, content=True)
        r = self.success(req, p)
        self.assertEqual(r['sources'][0]['state'], 'MANIFEST_ENTRY_MISMATCH')
        self.assertFalse(r['sources'][0]['manifest_entry_match'])
        self.assertIsNone(r['sources'][0]['content_base64'])

    def test_wrong_manifest_digest_disables_knowledge_reads(self):
        self.make_manifest([('one.md', b'one')])
        req = request(source('a', 'ces_knowledge', 'one.md'),
                      expected_manifest='f'*64)
        r = self.success(req)
        self.assertEqual(r['knowledge_manifest']['state'], 'MANIFEST_DIGEST_MISMATCH')
        self.assertEqual(r['sources'][0]['state'], 'SNAPSHOT_NOT_AVAILABLE')

    def test_manifest_wrong_scope_is_unavailable_not_trusted(self):
        self.make_manifest([('one.md', b'one')])
        path = self.knowledge / MANIFEST_NAME
        doc = json.loads(path.read_text())
        doc['repository_ref'] = 'cesrepo1:' + 'f'*64
        path.write_text(canonical(doc))
        r = self.success(request(source('a', 'ces_knowledge', 'one.md')))
        self.assertEqual(r['knowledge_manifest']['state'], 'MANIFEST_INVALID_OR_SCOPE_MISMATCH')
        self.assertEqual(r['sources'][0]['state'], 'SNAPSHOT_NOT_AVAILABLE')

    def test_unselected_manifest_entries_are_explicit_gaps(self):
        self.make_manifest([('a.md', b'a'), ('b.md', b'b')])
        r = self.success(request(source('a', 'ces_knowledge', 'a.md')))
        self.assertEqual(r['knowledge_manifest']['unselected_entries'], 1)
        self.assertIn('MANIFEST_ENTRIES_NOT_SELECTED',
                      [g['gap_code'] for g in r['coverage_gaps']])

    def test_unlisted_entry_is_never_read_as_snapshot_evidence(self):
        self.make_manifest([('a.md', b'a')])
        self.write(self.knowledge, 'other.md', b'not indexed')
        r = self.success(request(source('k', 'ces_knowledge', 'other.md')))
        self.assertEqual(r['sources'][0]['state'], 'NOT_IN_SNAPSHOT_MANIFEST')

    def test_unknown_period_and_out_of_period_are_not_coverage_proof(self):
        self.make_manifest([('a.md', b'a')], stamp='2026-11-01T00:00:00Z')
        r = self.success(request(source('k', 'ces_knowledge', 'a.md')))
        self.assertEqual(r['knowledge_manifest']['period_relation'], 'AFTER_PERIOD')
        self.assertIn('SNAPSHOT_PERIOD_NOT_ESTABLISHED',
                      [g['gap_code'] for g in r['coverage_gaps']])
        req = request()
        req['scope']['period'].update(start_utc=None, end_utc=None)
        r2 = self.success(req)
        self.assertEqual(r2['knowledge_manifest']['period_relation'], 'UNKNOWN')

    def test_missing_repo_file_is_gap_not_empty(self):
        r = self.success(request(source('x', 'repository', 'not-there.py')))
        self.assertEqual(r['sources'][0]['state'], 'MISSING')
        self.assertIsNone(r['sources'][0]['observed_sha256'])

    def test_bounded_large_regular_file(self):
        self.write(self.repo, 'big.txt', b'z' * 16400)
        r = self.success(request(source('x', 'repository', 'big.txt')))
        self.assertEqual(r['sources'][0]['state'], 'OVERSIZED')
        self.assertEqual(r['summary']['selected_source_bytes_read'], 0)

    @unittest.skipUnless(hasattr(os, 'symlink'), 'symlink unavailable')
    def test_symlinked_file_and_directory_never_followed(self):
        outside = self.repo.parent / 'outside.txt'
        outside.write_bytes(b'private bytes')
        os.symlink(outside, self.repo / 'secret.txt')
        folder = self.repo.parent / 'outside-dir'
        folder.mkdir()
        (folder / 'file.md').write_bytes(b'another secret')
        os.symlink(folder, self.repo / 'link')
        req = request(source('a', 'repository', 'link/file.md'),
                      source('b', 'repository', 'secret.txt'))
        p = policy(self.api, req, content=True)
        r = self.success(req, p)
        self.assertEqual([x['state'] for x in r['sources']],
                         ['UNAVAILABLE', 'UNAVAILABLE'])
        self.assertNotIn('secret', canonical([x['content_base64'] for x in r['sources']]))

    def test_write_intents_and_policy_mismatch_refuse_entire_request(self):
        req = request()
        p = policy(self.api, req)
        for action in ('permit_knowledge_write', 'permit_repository_write',
                       'permit_business_source_write', 'permit_issue_write',
                       'permit_publish'):
            q = dict(p)
            q[action] = True
            with self.subTest(action=action):
                self.refusal(req, q, 'POLICY_WRITE_INTENT_FORBIDDEN')
        p['request_binding_sha256'] = 'e'*64
        self.refusal(req, p, 'POLICY_BINDING_MISMATCH')

    def test_content_grant_escalation_denied(self):
        req = request(source('x', 'repository', 'doc.txt'))
        p = policy(self.api, req, content=False)
        p['source_grants'][0]['permit_content_projection'] = True
        self.refusal(req, p, 'POLICY_CONTENT_ESCALATION')

    def test_malformed_noncanonical_and_path_traversal_rejected(self):
        req = request(source('x', 'repository', 'file.txt'))
        p = policy(self.api, req)
        bad = json.loads(canonical(req))
        bad['sources'][0]['relative_path'] = '../secret'
        out = self.api.read(request_json=canonical(bad),
                            read_policy_json=canonical(p))
        self.assertEqual(out['reason_code'], 'KNOWLEDGE_BOOTSTRAP_SOURCE_PATH_INVALID')
        self.assertEqual(out['status'], 'invalid_input')
        out = self.api.binding_preview(request_json=json.dumps(req, indent=2))
        self.assertEqual(out['reason_code'], 'KNOWLEDGE_BOOTSTRAP_JSON_NONCANONICAL')

    @unittest.skipIf(Draft202012Validator is None, 'jsonschema not installed')
    def test_strict_four_draft2020_12_schemas(self):
        names = ('knowledge-bootstrap-request.v1.schema.json',
                 'knowledge-bootstrap-read-policy.v1.schema.json',
                 'knowledge-snapshot-manifest.v1.schema.json',
                 'knowledge-bootstrap-result.v1.schema.json')
        schemas = []
        for name in names:
            schema = json.loads((ROOT / 'references' / name).read_text())
            Draft202012Validator.check_schema(schema)
            schemas.append(Draft202012Validator(schema))
        req = request(source('x', 'repository', 'a.txt'))
        self.write(self.repo, 'a.txt', b'a')
        mh = self.make_manifest([('arch.md', b'old')])
        req['expected_manifest_sha256'] = mh
        p = policy(self.api, req)
        for idx, value in ((0, req), (1, p), (2, json.loads(
                (self.knowledge / MANIFEST_NAME).read_text()))):
            schemas[idx].validate(value)
        schemas[3].validate(self.go(req, p))
        schemas[3].validate(self.api.binding_preview(request_json=canonical(req)))
        p['permit_bootstrap_read'] = False
        schemas[3].validate(self.go(req, p))


if __name__ == '__main__':
    unittest.main()
