#!/usr/bin/env python3
"""EC203 real local Git/temp-key development checks, never org certification."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

from knowledge_boundary import canonical
from knowledge_bootstrap import MANIFEST_SCHEMA
from knowledge_target_binding import (KnowledgeTargetBinding, SIGNED_DOMAIN,
                                      POLICY_SCHEMA, STATEMENT_SCHEMA)
from test_knowledge_bootstrap import request, policy as bootstrap_policy, source

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    Ed25519PrivateKey = None
try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

HERE = Path(__file__).resolve().parent
SCHEMAS = HERE.parent / 'references'


def h(data):
    return hashlib.sha256(data).hexdigest()


@unittest.skipIf(Ed25519PrivateKey is None, 'cryptography missing (no signature verification)')
class TargetBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ces-ec203-')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'source'
        self.repo.mkdir()
        self.knowledge = Path(self.temp.name) / 'knowledge'
        self.cmd('init', '-q', '-b', 'main')
        self.private = Ed25519PrivateKey.generate()
        self.pub = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        self.api = self.factory()
        self.content = b'# Actual committed architecture\nA safe Git source.\n'
        self.put(self.repo, 'src/component.md', self.content)
        self.commit('init')

    def cmd(self, *args):
        cp = subprocess.run(['git', '-C', str(self.repo), *args],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=5)
        if cp.returncode:
            raise AssertionError(cp.stderr.decode(errors='replace'))
        return cp.stdout.decode('ascii').strip()

    def commit(self, msg):
        self.cmd('add', '.')
        self.cmd('-c', 'user.email=development@example.test',
                 '-c', 'user.name=Development', 'commit', '-q', '-m', msg)
        self.oid = self.cmd('rev-parse', 'HEAD')

    def put(self, root, name, data):
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def factory(self, *, keys=None, target_ref='refs/heads/main'):
        return KnowledgeTargetBinding(repository_root=str(self.repo),
            knowledge_root=str(self.knowledge),
            repository_ref='cesrepo1:'+'1'*64, target_ref=target_ref,
            trusted_ed25519_keys={'production': self.pub} if keys is None else keys)

    def binding(self, *, original=None, expected=True):
        r = request(source('r1', 'repository', 'src/component.md',
                           self.content if expected else None),
                    target={'algorithm': 'sha1', 'oid': self.oid})
        if original is not None:
            r = original
        bp = bootstrap_policy(self.api.bootstrap, r, provenance=True)
        pins = self.api.binding_preview(request_json=canonical(r))
        self.assertEqual(pins['status'], 'partial', pins)
        target = {'schema': POLICY_SCHEMA,
          'purpose': 'knowledge_target_git_read_only',
          'repository_ref': r['scope']['repository_ref'],
          'knowledge_space_key': r['scope']['knowledge_space_key'],
          'period_id': r['scope']['period']['period_id'],
          'source_policy_revision': r['scope']['source_policy_revision'],
          'request_binding_sha256': pins['subject']['request_binding_sha256'],
          'scope_binding_sha256': pins['subject']['scope_binding_sha256'],
          'repository_root_binding_sha256': pins['subject']['repository_root_binding_sha256'],
          'knowledge_root_binding_sha256': pins['subject']['knowledge_root_binding_sha256'],
          'git_root_binding_sha256': pins['subject']['git_root_binding_sha256'],
          'target_config_binding_sha256': pins['subject']['target_config_binding_sha256'],
          'issuer_registry_binding_sha256': pins['subject']['issuer_registry_binding_sha256'],
          'bootstrap_read_policy_binding_sha256': h(b'bad'),
          'permit_target_read': True,
          'permit_delivery_signature_verification': True,
          'permit_git_object_read': True,
          'permit_source_blob_compare': True,
          'permit_knowledge_manifest_bind': False,
          'permit_target_oid_projection': False,
          'permit_source_digest_projection': False,
          'permit_repository_write': False, 'permit_knowledge_write': False,
          'permit_business_source_write': False, 'permit_issue_write': False,
          'permit_publish': False,
          'read_receipt_sha256': 'a'*64,
          'source_grants': [
            {'source_key': p['source_key'],
             'source_binding_sha256': p['source_binding_sha256'],
             'permit_git_blob_compare': s['kind'] == 'repository',
             'read_receipt_sha256': 'b'*64 if s['kind'] == 'repository' else None}
            for s, p in zip(r['sources'], pins['subject']['source_bindings'])]
        }
        from knowledge_boundary import digest
        target['bootstrap_read_policy_binding_sha256'] = digest(
             'CES-EC202-READ-POLICY-v1', bp)
        doc = {'schema': STATEMENT_SCHEMA, 'purpose': 'knowledge_delivered_target_commit',
             'signer_key_id': 'production',
             'repository_ref': r['scope']['repository_ref'],
             'knowledge_space_key': r['scope']['knowledge_space_key'],
             'source_policy_revision': r['scope']['source_policy_revision'],
             'period_id': r['scope']['period']['period_id'],
             'request_binding_sha256': pins['subject']['request_binding_sha256'],
             'scope_binding_sha256': pins['subject']['scope_binding_sha256'],
             'target_ref': 'refs/heads/main',
             'target_revision': r['scope']['target']['revision'],
             'delivered_at_utc': '2026-10-12T12:00:00Z',
             'knowledge_manifest_sha256': None}
        return r, bp, target, doc

    def sign(self, doc):
        return base64.b64encode(self.private.sign(SIGNED_DOMAIN +
                   canonical(doc).encode('ascii'))).decode('ascii')

    def go(self, r, bp, target, doc=None, sig='AUTO'):
        if sig == 'AUTO' and doc is not None:
            sig = self.sign(doc)
        elif sig == 'AUTO':
            sig = None
        return self.api.verify(request_json=canonical(r),
            bootstrap_read_policy_json=canonical(bp),
            target_read_policy_json=canonical(target),
            delivery_statement_json=canonical(doc) if doc is not None else None,
            delivery_signature_base64=sig)

    def ok(self, output):
        self.assertEqual((output['status'], output['exit_code']), ('partial',2),output)
        self.assertEqual(json.loads(output['canonical_json']), output['subject'])
        self.assertFalse(any(output['limitations'].values()))
        self.assertEqual(output['subject']['verified_delivered_facts'], [])
        self.assertTrue(output['subject']['no_write_actions_performed'])
        return output['subject']

    def assert_rejected(self, output, code, status='unavailable'):
        self.assertEqual(output['status'], status, output)
        self.assertEqual(output['reason_code'], 'KNOWLEDGE_TARGET_'+code, output)
        self.assertIsNone(output['subject'])

    def test_signed_real_commit_and_actual_bytes(self):
        r,bp,t,doc = self.binding()
        out = self.ok(self.go(r,bp,t,doc))
        self.assertEqual(out['signature_state'], 'SIGNATURE_VERIFIED_CONFIGURED_KEY')
        self.assertEqual(out['git_object_state'], 'GIT_COMMIT_OBJECT_VERIFIED_REF_MATCH')
        self.assertEqual(out['delivery_state'], 'SIGNED_DELIVERED_TARGET_OBSERVED_AT_REF')
        self.assertTrue(out['summary']['eligible_for_ec204_source_diff'])
        self.assertEqual(out['sources'][0]['target_blob_state'], 'SIGNED_DELIVERY_TARGET_BLOB_MATCH')
        self.assertEqual(out['verified_target_source_bindings'], ['r1'])
        self.assertIsNone(out['sources'][0]['source_sha256'])
        self.assertIsNone(out['target_revision'])
        self.assertNotIn(self.oid, canonical(out))
        self.assertEqual(self.cmd('status', '--porcelain'), '')

    def test_no_attestation_is_never_delivered(self):
        r,bp,t,doc = self.binding()
        o = self.ok(self.go(r,bp,t))
        self.assertEqual(o['signature_state'], 'ATTESTATION_MISSING')
        self.assertEqual(o['sources'][0]['target_blob_state'],
                         'LOCAL_GIT_BLOB_MATCH_DELIVERY_UNVERIFIED')
        self.assertFalse(o['summary']['eligible_for_ec204_source_diff'])

    def test_unknown_public_key_is_not_authority(self):
        self.api = self.factory(keys={})
        r,bp,t,doc = self.binding()
        o = self.ok(self.go(r,bp,t,doc))
        self.assertEqual(o['signature_state'], 'UNKNOWN_SIGNER_UNVERIFIED')
        self.assertEqual(o['delivery_state'], 'TARGET_DELIVERY_UNKNOWN')

    def test_invalid_signature_does_not_bind(self):
        r,bp,t,doc = self.binding()
        o = self.ok(self.go(r,bp,t,doc,sig=base64.b64encode(b'0'*64).decode()))
        self.assertEqual(o['signature_state'], 'SIGNATURE_INVALID')

    def test_request_source_substitution_rejects_prior_signature(self):
        r,bp,t,doc = self.binding()
        valid_sig = self.sign(doc)
        r['sources'][0]['expected_sha256'] = 'f'*64
        # New complete policy, but no reissuance of the signed statement.
        bp = bootstrap_policy(self.api.bootstrap, r, provenance=True)
        pins = self.api.binding_preview(request_json=canonical(r))['subject']
        t['request_binding_sha256'] = pins['request_binding_sha256']
        t['scope_binding_sha256'] = pins['scope_binding_sha256']
        t['source_grants'][0]['source_binding_sha256'] = pins['source_bindings'][0]['source_binding_sha256']
        from knowledge_boundary import digest
        t['bootstrap_read_policy_binding_sha256'] = digest('CES-EC202-READ-POLICY-v1', bp)
        o = self.ok(self.go(r,bp,t,doc,sig=valid_sig))
        self.assertEqual(o['signature_state'], 'SIGNED_STATEMENT_SCOPE_OR_PERIOD_MISMATCH')
        self.assertFalse(o['summary']['eligible_for_ec204_source_diff'])

    def test_worktree_modified_vs_signed_commit(self):
        r,bp,t,doc = self.binding()
        self.put(self.repo,'src/component.md',b'unsaved local edit\n')
        r['sources'][0]['expected_sha256'] = None
        bp = bootstrap_policy(self.api.bootstrap, r, provenance=True)
        pins = self.api.binding_preview(request_json=canonical(r))['subject']
        from knowledge_boundary import digest
        t['request_binding_sha256'] = pins['request_binding_sha256']
        t['source_grants'][0]['source_binding_sha256'] = pins['source_bindings'][0]['source_binding_sha256']
        t['bootstrap_read_policy_binding_sha256'] = digest('CES-EC202-READ-POLICY-v1', bp)
        doc['request_binding_sha256'] = pins['request_binding_sha256']
        o = self.ok(self.go(r,bp,t,doc))
        self.assertEqual(o['delivery_state'],'SIGNED_DELIVERED_TARGET_OBSERVED_AT_REF')
        self.assertEqual(o['sources'][0]['target_blob_state'], 'WORKTREE_DIFFERS_FROM_TARGET_BLOB')
        self.assertFalse(o['summary']['eligible_for_ec204_source_diff'])

    def test_branch_advanced_after_signed_delivery(self):
        r,bp,t,doc = self.binding()
        self.put(self.repo, 'other.md', b'new commit')
        self.commit('move branch')
        o = self.ok(self.go(r,bp,t,doc))
        self.assertEqual(o['git_object_state'], 'GIT_COMMIT_VERIFIED_REF_DIFFERENT')
        self.assertEqual(o['delivery_state'], 'TARGET_DELIVERY_UNKNOWN')
        self.assertEqual(o['git_ref_relation'], 'NOT_ESTABLISHED_OR_DIVERGED')

    def test_caller_supplied_pr_head_oid_rejected_as_delivery(self):
        r,bp,t,doc = self.binding()
        r['scope']['target']['revision']['oid'] = '1'*40
        bp = bootstrap_policy(self.api.bootstrap,r,provenance=True)
        pins = self.api.binding_preview(request_json=canonical(r))['subject']
        t['request_binding_sha256'] = pins['request_binding_sha256']
        t['scope_binding_sha256'] = pins['scope_binding_sha256']
        from knowledge_boundary import digest
        t['bootstrap_read_policy_binding_sha256'] = digest('CES-EC202-READ-POLICY-v1', bp)
        doc['request_binding_sha256'] = pins['request_binding_sha256']
        doc['scope_binding_sha256'] = pins['scope_binding_sha256']
        doc['target_revision'] = r['scope']['target']['revision']
        o = self.ok(self.go(r,bp,t,doc))
        self.assertNotEqual(o['delivery_state'],'SIGNED_DELIVERED_TARGET_OBSERVED_AT_REF')

    def test_signature_period_outside_requested_window(self):
        r,bp,t,doc = self.binding()
        doc['delivered_at_utc'] = '2025-10-12T12:00:00Z'
        o = self.ok(self.go(r,bp,t,doc))
        self.assertEqual(o['signature_state'], 'SIGNED_STATEMENT_SCOPE_OR_PERIOD_MISMATCH')

    def test_signature_target_ref_not_host_config(self):
        r,bp,t,doc = self.binding()
        doc['target_ref'] = 'refs/heads/not-main'
        o = self.ok(self.go(r,bp,t,doc))
        self.assertEqual(o['signature_state'], 'SIGNED_STATEMENT_SCOPE_OR_PERIOD_MISMATCH')

    def test_read_policy_exact_issuer_binding_required(self):
        r,bp,t,doc = self.binding()
        t['issuer_registry_binding_sha256'] = 'e'*64
        self.assert_rejected(self.go(r,bp,t,doc), 'TARGET_POLICY_BINDING_MISMATCH')

    def test_ec202_policy_change_invalidates_ec203_policy(self):
        r,bp,t,doc = self.binding()
        bp['permit_content_projection'] = True
        self.assert_rejected(self.go(r,bp,t,doc), 'TARGET_POLICY_BOOTSTRAP_MISMATCH')

    def test_blob_authorization_denied_never_reads(self):
        r,bp,t,doc = self.binding()
        t['source_grants'][0]['permit_git_blob_compare'] = False
        o = self.ok(self.go(r,bp,t,doc))
        self.assertEqual(o['sources'][0]['target_blob_state'], 'DENIED_NOT_INSPECTED')
        self.assertFalse(o['summary']['eligible_for_ec204_source_diff'])

    def test_git_read_denied_does_not_establish_commit(self):
        r,bp,t,doc = self.binding()
        t['permit_git_object_read'] = False
        t['permit_source_blob_compare'] = False
        t['source_grants'][0]['permit_git_blob_compare'] = False
        o = self.ok(self.go(r,bp,t,doc))
        self.assertEqual(o['git_object_state'], 'GIT_READ_DENIED_NOT_INSPECTED')
        self.assertEqual(o['delivery_state'], 'TARGET_DELIVERY_UNKNOWN')

    def test_bootstrap_source_denied_no_commit_blob_escalation(self):
        r,bp,t,doc = self.binding()
        bp['source_grants'][0]['permit_source_read'] = False
        bp['source_grants'][0]['read_receipt_sha256'] = None
        from knowledge_boundary import digest
        t['bootstrap_read_policy_binding_sha256'] = digest('CES-EC202-READ-POLICY-v1', bp)
        o = self.ok(self.go(r,bp,t,doc))
        self.assertEqual(o['sources'][0]['target_blob_state'], 'BOOTSTRAP_SOURCE_NOT_READ')

    def test_git_symlink_blob_not_regular_file(self):
        link = self.repo / 'src' / 'component.md'
        link.unlink()
        link.symlink_to('other.md')
        self.commit('symlink target')
        r,bp,t,doc = self.binding(expected=False)
        o = self.ok(self.go(r,bp,t,doc))
        self.assertEqual(o['sources'][0]['target_blob_state'], 'BOOTSTRAP_SOURCE_NOT_READ')

    def test_missing_git_tree_path_returns_gap(self):
        r,bp,t,doc = self.binding()
        self.put(self.repo,'new/untracked.md',b'no git object')
        r['sources'][0]['relative_path'] = 'new/untracked.md'
        r['sources'][0]['expected_sha256'] = None
        bp = bootstrap_policy(self.api.bootstrap,r,provenance=True)
        pins = self.api.binding_preview(request_json=canonical(r))['subject']
        from knowledge_boundary import digest
        t['request_binding_sha256'] = pins['request_binding_sha256']
        t['source_grants'][0]['source_binding_sha256'] = pins['source_bindings'][0]['source_binding_sha256']
        t['bootstrap_read_policy_binding_sha256'] = digest('CES-EC202-READ-POLICY-v1', bp)
        doc['request_binding_sha256'] = pins['request_binding_sha256']
        o = self.ok(self.go(r,bp,t,doc))
        self.assertEqual(o['sources'][0]['target_blob_state'], 'PATH_NOT_IN_TARGET_TREE')

    def test_manifest_signature_binding_is_not_semantic_currentness(self):
        data = b'{"topic":"architecture"}'
        self.put(self.knowledge, 'docs/item.json', data)
        r,bp,t,doc = self.binding()
        r['sources'].append(source('s2', 'ces_knowledge', 'docs/item.json', data))
        manifest = {'schema': MANIFEST_SCHEMA,
          'repository_ref': r['scope']['repository_ref'],
          'knowledge_space_key': 'architecture',
          'source_policy_revision': 'policy-v1',
          'snapshot_version': 'v1', 'captured_at_utc': '2026-10-12T11:00:00Z',
          'coverage': 'partial_declared',
          'entries': [{'relative_path': 'docs/item.json',
                       'sha256': h(data), 'size_bytes': len(data)}]}
        raw = canonical(manifest).encode('ascii')
        self.put(self.knowledge,'ces-snapshot.v1.json',raw)
        r['expected_manifest_sha256'] = h(raw)
        bp = bootstrap_policy(self.api.bootstrap,r,provenance=True,knowledge=True,manifest=True)
        pins = self.api.binding_preview(request_json=canonical(r))['subject']
        from knowledge_boundary import digest
        for name in ('request_binding_sha256', 'scope_binding_sha256',
                     'repository_root_binding_sha256', 'knowledge_root_binding_sha256',
                     'git_root_binding_sha256', 'target_config_binding_sha256',
                     'issuer_registry_binding_sha256'):
            t[name] = pins[name]
        t['source_grants'] = [
            {'source_key': pin['source_key'],
             'source_binding_sha256': pin['source_binding_sha256'],
             'permit_git_blob_compare': row['kind'] == 'repository',
             'read_receipt_sha256': 'b'*64 if row['kind'] == 'repository' else None}
            for pin,row in zip(pins['source_bindings'],r['sources'])]
        t['bootstrap_read_policy_binding_sha256'] = digest('CES-EC202-READ-POLICY-v1',bp)
        t['permit_knowledge_manifest_bind'] = True
        doc['request_binding_sha256'] = pins['request_binding_sha256']
        doc['knowledge_manifest_sha256'] = h(raw)
        o = self.ok(self.go(r,bp,t,doc))
        self.assertEqual(o['knowledge_manifest_state'], 'SIGNED_MANIFEST_DIGEST_MATCH')
        self.assertEqual(o['current_architecture_state'],'UNKNOWN_NOT_SEMANTICALLY_VERIFIED')
        self.assertFalse(o['sources'][1]['matched_verified_delivery'])
        self.assertTrue(o['summary']['eligible_for_ec204_source_diff'])

    def test_git_alternate_objects_forbidden(self):
        alt = self.repo/'.git'/'objects'/'info'/'alternates'
        alt.write_text('/tmp/untrusted\n')
        out = self.api.binding_preview(request_json=canonical(request()))
        self.assert_rejected(out,'GIT_INDIRECT_OBJECTS_FORBIDDEN')

    def test_gitdir_symlink_rejected(self):
        parent = Path(self.temp.name)
        moved = parent/'actual-git'
        (self.repo/'.git').rename(moved)
        (self.repo/'.git').symlink_to(moved)
        out = self.api.binding_preview(request_json=canonical(request()))
        self.assertNotEqual(out['status'], 'partial',out)

    def test_unspecified_target_oid_stays_unknown(self):
        r,bp,t,doc = self.binding(original=request(
                    source('r1','repository','src/component.md',self.content),target=None))
        o = self.ok(self.go(r,bp,t))
        self.assertEqual(o['git_object_state'], 'TARGET_REVISION_UNKNOWN')
        self.assertEqual(o['git_ref_relation'], 'NOT_ESTABLISHED_OR_DIVERGED')

    def test_host_repository_identity_cannot_be_supplied_by_request(self):
        r = request(source('r1','repository','src/component.md',self.content),
                    target={'algorithm':'sha1','oid':self.oid})
        r['scope']['repository_ref'] = 'cesrepo1:'+'f'*64
        preview = self.api.binding_preview(request_json=canonical(r))
        self.assert_rejected(preview,'HOST_REPOSITORY_SCOPE_MISMATCH')

    def test_original_bootstrap_provenance_denial_blocks_digest_match(self):
        r,bp,t,doc = self.binding()
        bp['permit_provenance_projection'] = False
        from knowledge_boundary import digest
        t['bootstrap_read_policy_binding_sha256'] = digest('CES-EC202-READ-POLICY-v1',bp)
        o = self.ok(self.go(r,bp,t,doc))
        self.assertEqual(o['sources'][0]['target_blob_state'],
                         'BOOTSTRAP_PROVENANCE_NOT_GRANTED')
        self.assertFalse(o['summary']['eligible_for_ec204_source_diff'])

    def test_write_intent_denied_before_git_reads(self):
        r,bp,t,doc = self.binding()
        t['permit_repository_write'] = True
        self.assert_rejected(self.go(r,bp,t,doc),'TARGET_POLICY_WRITE_FORBIDDEN')

    def test_unbounded_period_cannot_verify_signed_delivery(self):
        r = request(source('r1','repository','src/component.md',self.content),
            target={'algorithm':'sha1','oid':self.oid})
        r['scope']['period']['start_utc'] = None
        r['scope']['period']['end_utc'] = None
        r,bp,t,doc = self.binding(original=r)
        o = self.ok(self.go(r,bp,t,doc))
        self.assertEqual(o['signature_state'],'SIGNED_STATEMENT_SCOPE_OR_PERIOD_MISMATCH')

    def test_sha256_native_git_object_format_when_supported(self):
        shutil.rmtree(self.repo/'.git')
        try:
            self.cmd('init','-q','-b','main','--object-format=sha256')
        except AssertionError:
            self.skipTest('local git lacks SHA-256 object-format support')
        self.commit('sha256 commit')
        self.assertEqual(len(self.oid), 64)
        r,bp,t,doc = self.binding(original=request(
            source('r1','repository','src/component.md',self.content),
            target={'algorithm':'sha256','oid':self.oid}))
        o = self.ok(self.go(r,bp,t,doc))
        self.assertTrue(o['summary']['eligible_for_ec204_source_diff'])
        self.assertEqual(o['git_object_state'],'GIT_COMMIT_OBJECT_VERIFIED_REF_MATCH')

    def test_lack_of_source_selection_is_not_impact_eligibility(self):
        r,bp,t,doc = self.binding(original=request(target={
              'algorithm':'sha1','oid':self.oid}))
        o = self.ok(self.go(r,bp,t,doc))
        self.assertEqual(o['delivery_state'],'SIGNED_DELIVERED_TARGET_OBSERVED_AT_REF')
        self.assertFalse(o['summary']['eligible_for_ec204_source_diff'])
        self.assertEqual(o['verified_target_source_bindings'],[])

    def test_bad_parent_policy_is_rejected_with_structured_reason(self):
        r,bp,t,doc = self.binding()
        del bp['permit_manifest_read']
        o = self.go(r,bp,t,doc)
        self.assertEqual(o['status'], 'invalid_input', o)
        self.assertEqual(o['reason_code'], 'KNOWLEDGE_TARGET_POLICY_FIELDS_INVALID')
        self.assertIsNone(o['subject'])

    def test_manifest_unselected_gap_survives_ec203(self):
        docs = [ ('docs/a.json', b'{"a":1}'), ('docs/z.json', b'{"z":1}') ]
        for path,data in docs:
            self.put(self.knowledge,path,data)
        r = request(source('r1','repository','src/component.md',self.content),
                    source('s2','ces_knowledge','docs/a.json',docs[0][1]),
                    target={'algorithm':'sha1','oid':self.oid})
        manifest={'schema':MANIFEST_SCHEMA,'repository_ref':r['scope']['repository_ref'],
           'knowledge_space_key':'architecture','source_policy_revision':'policy-v1',
           'snapshot_version':'v2','captured_at_utc':'2026-10-12T11:00:00Z',
           'coverage':'partial_declared',
           'entries':[{'relative_path':p,'sha256':h(d),'size_bytes':len(d)}
                      for p,d in docs]}
        raw=canonical(manifest).encode('ascii')
        self.put(self.knowledge,'ces-snapshot.v1.json',raw)
        r['expected_manifest_sha256']=h(raw)
        r,bp,t,doc=self.binding(original=r)
        t['permit_knowledge_manifest_bind']=True
        doc['knowledge_manifest_sha256']=h(raw)
        o=self.ok(self.go(r,bp,t,doc))
        self.assertEqual(o['knowledge_manifest_state'],'SIGNED_MANIFEST_DIGEST_MATCH')
        self.assertTrue(any(g['gap_code']=='MANIFEST_ENTRIES_NOT_SELECTED'
                            for g in o['bootstrap_coverage_gaps']))
        self.assertFalse(o['sources'][1]['matched_verified_delivery'])

    def test_schema_validates_output_and_policy(self):
        if Draft202012Validator is None:
            self.skipTest('jsonschema optional')
        r,bp,t,doc = self.binding()
        result = self.go(r,bp,t,doc)
        for kind,obj in [('knowledge-target-read-policy.v1.schema.json',t),
                         ('knowledge-target-delivery-statement.v1.schema.json',doc),
                         ('knowledge-target-binding-result.v1.schema.json',result)]:
            schema = json.loads((SCHEMAS/kind).read_text())
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(obj)
        # Strict unknown properties are rejected by each published contract.
        for name,obj in [('knowledge-target-read-policy.v1.schema.json',t),
                         ('knowledge-target-delivery-statement.v1.schema.json',doc),
                         ('knowledge-target-binding-result.v1.schema.json',result)]:
            altered = copy.deepcopy(obj)
            altered['unlisted'] = 'unsafe'
            validator = Draft202012Validator(json.loads((SCHEMAS/name).read_text()))
            self.assertFalse(validator.is_valid(altered))


if __name__ == '__main__':
    unittest.main()
