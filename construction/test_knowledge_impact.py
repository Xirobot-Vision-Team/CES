#!/usr/bin/env python3
"""EC204 synthetic local real Git+ephemeral Ed25519 development cases."""
from __future__ import annotations

import base64
import copy
import json
import os
import unittest
from pathlib import Path

from knowledge_boundary import canonical, digest
from knowledge_impact import KnowledgeImpact, BASELINE_DOMAIN, BASELINE_SCHEMA, POLICY_SCHEMA
import test_knowledge_target_binding as target_tests
from test_knowledge_target_binding import Ed25519PrivateKey
from test_knowledge_bootstrap import request, source, policy as bootstrap_policy

try:
    from cryptography.hazmat.primitives import serialization
except ImportError:
    serialization = None
try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

SCHEMAS = Path(__file__).resolve().parent.parent/'references'
H = 'd'*64


@unittest.skipIf(Ed25519PrivateKey is None, 'cryptography required for real signatures')
class ImpactTests(unittest.TestCase):
    def setUp(self):
        self.fx = target_tests.TargetBindingTests('test_signed_real_commit_and_actual_bytes')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.base_oid = self.fx.oid
        self.fx.content = b'# Replaced component\nversion two\n'
        self.fx.put(self.fx.repo, 'src/component.md', self.fx.content)
        self.fx.commit('change component')
        self.baseline_key = Ed25519PrivateKey.generate()
        self.baseline_public = self.baseline_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        self.api = self.factory()
        self.r, self.bp, self.tp, self.target_doc = self.fx.binding()
        self.ip = self.impact_policy()
        self.baseline_doc = self.baseline_statement()

    def factory(self, targetkeys=None, basekeys=None):
        return KnowledgeImpact(repository_root=str(self.fx.repo),
            knowledge_root=str(self.fx.knowledge),
            repository_ref='cesrepo1:'+'1'*64,
            target_ref='refs/heads/main',
            trusted_target_keys={'production': self.fx.pub} if targetkeys is None else targetkeys,
            trusted_baseline_keys={'baseline-authority': self.baseline_public}
                if basekeys is None else basekeys)

    def impact_policy(self):
        pin_result = self.api.binding_preview(request_json=canonical(self.r))
        self.assertEqual(pin_result['status'], 'partial',pin_result)
        pins = pin_result['subject']
        return {
            'schema': POLICY_SCHEMA,'purpose':'knowledge_impact_read_only',
            'repository_ref': self.r['scope']['repository_ref'],
            'knowledge_space_key': self.r['scope']['knowledge_space_key'],
            'period_id': self.r['scope']['period']['period_id'],
            'source_policy_revision': self.r['scope']['source_policy_revision'],
            **{k:pins[k] for k in (
                'request_binding_sha256','scope_binding_sha256',
                'repository_root_binding_sha256','knowledge_root_binding_sha256',
                'git_root_binding_sha256','target_config_binding_sha256',
                'issuer_registry_binding_sha256','baseline_issuer_registry_binding_sha256')},
            'bootstrap_read_policy_binding_sha256': digest('CES-EC202-READ-POLICY-v1', self.bp),
            'target_read_policy_binding_sha256': digest('CES-EC203-TARGET-POLICY-v1', self.tp),
            'target_statement_binding_sha256': digest('CES-EC204-TARGET-STATEMENT-v1', self.target_doc),
            'read_receipt_sha256': H,
            'permit_impact_read':True,
            'permit_baseline_signature_verification': True,
            'permit_baseline_git_read':True,
            'permit_selected_path_compare':True,
            'permit_change_digest_projection':False,
            'permit_repository_write':False,'permit_knowledge_write':False,
            'permit_business_source_write':False,'permit_issue_write':False,
            'permit_publish':False,
            'source_grants': [{
                'source_key': bind['source_key'],
                'source_binding_sha256': bind['source_binding_sha256'],
                'permit_baseline_path_compare':row['kind']=='repository',
                'read_receipt_sha256':H if row['kind']=='repository' else None}
                for row,bind in zip(self.r['sources'], pins['source_bindings'])]}

    def baseline_statement(self):
        pins = self.api.binding_preview(request_json=canonical(self.r))['subject']
        return {'schema':BASELINE_SCHEMA,
                'purpose':'knowledge_preceding_delivered_commit',
                'signer_key_id':'baseline-authority',
                'repository_ref':self.r['scope']['repository_ref'],
                'knowledge_space_key':self.r['scope']['knowledge_space_key'],
                'source_policy_revision':self.r['scope']['source_policy_revision'],
                'period_id':self.r['scope']['period']['period_id'],
                'request_binding_sha256':pins['request_binding_sha256'],
                'scope_binding_sha256':pins['scope_binding_sha256'],
                'target_statement_binding_sha256':digest('CES-EC204-TARGET-STATEMENT-v1',self.target_doc),
                'target_ref':'refs/heads/main',
                'baseline_revision':{'algorithm':'sha1','oid':self.base_oid},
                'target_revision':self.r['scope']['target']['revision'],
                'baseline_recorded_at_utc':'2026-10-10T12:00:00Z'}

    def sign_base(self):
        return base64.b64encode(self.baseline_key.sign(
            BASELINE_DOMAIN+canonical(self.baseline_doc).encode('ascii'))).decode('ascii')

    def call(self, *, target_sig='AUTO', base_sig='AUTO', baseline=True):
        if target_sig == 'AUTO': target_sig = self.fx.sign(self.target_doc)
        if base_sig == 'AUTO': base_sig = self.sign_base()
        return self.api.analyze(request_json=canonical(self.r),
            bootstrap_read_policy_json=canonical(self.bp),
            target_read_policy_json=canonical(self.tp),
            impact_read_policy_json=canonical(self.ip),
            target_statement_json=canonical(self.target_doc),
            target_signature_base64=target_sig,
            baseline_statement_json=canonical(self.baseline_doc) if baseline else None,
            baseline_signature_base64=base_sig if baseline else None)

    def ok(self, result):
        self.assertEqual((result['status'],result['exit_code']),('partial',2),result)
        self.assertEqual(result['subject'], json.loads(result['canonical_json']))
        self.assertFalse(any(result['limitations'].values()))
        self.assertEqual(result['subject']['verified_delivered_facts'],[])
        self.assertEqual(result['subject']['knowledge_sections_to_update'],[])
        self.assertTrue(result['subject']['no_write_actions_performed'])
        return result['subject']

    def test_real_git_modified_selected_file_and_no_section_claim(self):
        s=self.ok(self.call())
        self.assertEqual(s['selected_change_set_state'],'SELECTED_REPOSITORY_PATHS_COMPARED')
        self.assertEqual(s['source_changes'][0]['change_kind'],'MODIFIED')
        self.assertEqual(s['source_changes'][0]['comparison_state'],'GIT_SELECTED_PATH_BYTES_VERIFIED')
        self.assertEqual(s['summary']['changed_selected_paths'],1)
        self.assertFalse(s['summary']['whole_repository_change_set_complete'])
        self.assertEqual(s['knowledge_impact_state'],
                         'UNKNOWN_REQUIRES_EC205_SECTION_MAPPING_AND_REVIEW')
        self.assertIsNone(s['source_changes'][0]['target_sha256'])
        self.assertIsNone(s['target_revision'])
        self.assertNotIn(self.fx.oid,canonical(s))
        self.assertEqual(self.fx.cmd('status','--porcelain'),'')

    def test_identical_baseline_and_target_only_selected_unchanged(self):
        self.baseline_doc['baseline_revision']=self.r['scope']['target']['revision']
        s=self.ok(self.call())
        self.assertEqual(s['source_changes'][0]['change_kind'],'UNCHANGED')
        self.assertEqual(s['summary']['changed_selected_paths'],0)
        self.assertFalse(s['summary']['whole_repository_change_set_complete'])

    def test_added_path_at_target_detected_from_real_git(self):
        # Create a predecessor commit with no selected file, followed by add.
        (self.fx.repo/'src/component.md').unlink()
        self.fx.commit('predecessor file absent')
        self.base_oid=self.fx.oid
        self.fx.put(self.fx.repo,'src/component.md',self.fx.content)
        self.fx.commit('add component')
        self.rebind()
        s=self.ok(self.call())
        self.assertEqual(s['source_changes'][0]['change_kind'],'ADDED')

    def test_mode_only_change_on_selected_file(self):
        self.fx.cmd('config','core.filemode','true')
        p=self.fx.repo/'src/component.md'
        p.chmod(0o755)
        self.fx.commit('executable-only')
        self.rebind()
        s=self.ok(self.call())
        # Initial content and change are different, so compare to the last
        # content-modification commit to isolate a pure mode change.
        self.assertEqual(s['source_changes'][0]['change_kind'],'MODIFIED')
        self.base_oid=self.fx.cmd('rev-parse','HEAD^')
        self.baseline_doc=self.baseline_statement()
        s=self.ok(self.call())
        self.assertEqual(s['source_changes'][0]['change_kind'],'MODE_ONLY')

    def test_private_digest_projection_only_with_double_grant(self):
        self.tp['permit_source_digest_projection']=True
        self.ip=self.impact_policy()
        self.ip['permit_change_digest_projection']=True
        s=self.ok(self.call())
        row=s['source_changes'][0]
        self.assertEqual(len(row['baseline_sha256']),64)
        self.assertEqual(len(row['target_sha256']),64)
        self.assertNotEqual(row['baseline_sha256'],row['target_sha256'])
        self.assertEqual(row['baseline_mode'],'100644')

    def test_digest_projection_without_upstream_permission_is_blocked(self):
        self.ip['permit_change_digest_projection']=True
        self.assertEqual(self.call()['reason_code'],'KNOWLEDGE_IMPACT_IMPACT_DIGEST_PERMISSION_ESCALATION')

    def test_unsigned_target_does_not_read_or_promote_baseline(self):
        s=self.ok(self.call(target_sig=None))
        self.assertEqual(s['baseline_binding_state'],'NOT_INSPECTED_TARGET_NOT_ELIGIBLE')
        self.assertEqual(s['source_changes'][0]['change_kind'],'UNKNOWN')

    def test_forged_target_attestation_never_analyzed(self):
        s=self.ok(self.call(target_sig=base64.b64encode(b'0'*64).decode()))
        self.assertEqual(s['selected_change_set_state'],'UNKNOWN_TARGET_NOT_ELIGIBLE')

    def test_missing_baseline_attestation_is_unknown(self):
        s=self.ok(self.call(baseline=False))
        self.assertEqual(s['baseline_binding_state'],'BASELINE_STATEMENT_NOT_PROVIDED')
        self.assertEqual(s['source_changes'][0]['change_kind'],'UNKNOWN')

    def test_wrong_baseline_signature_is_unknown(self):
        s=self.ok(self.call(base_sig=base64.b64encode(b'0'*64).decode()))
        self.assertEqual(s['baseline_binding_state'],'BASELINE_SIGNATURE_INVALID')
        self.assertEqual(s['summary']['changed_selected_paths'],0)

    def test_unknown_baseline_signer_key_is_unknown(self):
        self.api=self.factory(basekeys={})
        self.ip=self.impact_policy()
        s=self.ok(self.call())
        self.assertEqual(s['baseline_binding_state'],'UNKNOWN_BASELINE_SIGNER')

    def test_base_signature_no_permission_not_even_inspected(self):
        self.ip['permit_baseline_signature_verification']=False
        s=self.ok(self.call())
        self.assertEqual(s['baseline_binding_state'],
                         'BASELINE_SIGNATURE_CHECK_DENIED_NOT_INSPECTED')

    def test_baseline_git_permission_absent_not_inspected(self):
        self.ip['permit_baseline_git_read']=False
        self.ip['permit_selected_path_compare']=False
        self.ip['source_grants'][0]['permit_baseline_path_compare']=False
        s=self.ok(self.call())
        self.assertEqual(s['baseline_binding_state'],'BASELINE_GIT_READ_DENIED_NOT_INSPECTED')

    def test_selected_path_permission_missing_reports_unknown(self):
        self.ip['source_grants'][0]['permit_baseline_path_compare']=False
        s=self.ok(self.call())
        self.assertEqual(s['source_changes'][0]['comparison_state'],'DENIED_NOT_INSPECTED')
        self.assertFalse(s['summary']['selected_source_comparison_complete'])

    def test_baseline_signature_scope_replay_blocked(self):
        self.baseline_doc['repository_ref']='cesrepo1:'+'f'*64
        s=self.ok(self.call())
        self.assertEqual(s['baseline_binding_state'],'BASELINE_SIGNED_SCOPE_OR_TIME_MISMATCH')

    def test_baseline_signed_timestamp_after_target_unknown(self):
        self.baseline_doc['baseline_recorded_at_utc']='2026-10-15T12:00:00Z'
        s=self.ok(self.call())
        self.assertEqual(s['baseline_binding_state'],'BASELINE_SIGNED_SCOPE_OR_TIME_MISMATCH')

    def test_baseline_not_ancestor_rejected(self):
        # A real but divergent commit is not previous delivered state.
        self.fx.cmd('checkout','-q','-b','unrelated-branch',self.base_oid)
        self.fx.put(self.fx.repo,'only-other-branch.md',b'other\n')
        self.fx.commit('diverged')
        self.baseline_doc['baseline_revision']['oid']=self.fx.oid
        self.fx.cmd('checkout','-q','main')
        s=self.ok(self.call())
        self.assertEqual(s['baseline_binding_state'],'BASELINE_NOT_CONFIRMED_ANCESTOR')

    def test_missing_baseline_commit_report_unknown(self):
        self.baseline_doc['baseline_revision']['oid']='f'*40
        s=self.ok(self.call())
        self.assertEqual(s['baseline_binding_state'],'BASELINE_COMMIT_UNAVAILABLE')

    def test_ref_moved_after_signed_source_binding_has_unknown_result(self):
        self.fx.put(self.fx.repo,'readme.md',b'new commit')
        self.fx.commit('moved head')
        s=self.ok(self.call())
        self.assertEqual(s['selected_change_set_state'],'UNKNOWN_TARGET_NOT_ELIGIBLE')
        self.assertEqual(s['source_changes'][0]['change_kind'],'UNKNOWN')

    def test_worktree_dirty_not_signed_source(self):
        self.fx.put(self.fx.repo,'src/component.md',b'uncommitted mutation')
        s=self.ok(self.call())
        self.assertEqual(s['selected_change_set_state'],'UNKNOWN_TARGET_NOT_ELIGIBLE')

    def test_invalid_policy_receipt_cannot_be_used(self):
        self.ip['read_receipt_sha256']=None
        self.assertEqual(self.call()['reason_code'],'KNOWLEDGE_IMPACT_IMPACT_READ_DENIED')

    def test_policy_cannot_turn_on_writes(self):
        self.ip['permit_knowledge_write']=True
        self.assertEqual(self.call()['reason_code'],'KNOWLEDGE_IMPACT_IMPACT_WRITE_INTENT_FORBIDDEN')

    def test_policy_fails_when_target_grant_changed(self):
        self.tp['source_grants'][0]['permit_git_blob_compare']=False
        self.assertEqual(self.call()['reason_code'],'KNOWLEDGE_IMPACT_IMPACT_POLICY_DEPENDENCY_MISMATCH')

    def test_policy_cannot_replace_baseline_registry(self):
        self.api=self.factory(basekeys={})
        self.assertEqual(self.call()['reason_code'],'KNOWLEDGE_IMPACT_IMPACT_POLICY_DEPENDENCY_MISMATCH')

    def test_baseline_cannot_escape_by_giving_wrong_repo_git_path(self):
        self.baseline_doc['baseline_revision']['oid']='../../../../etc/passwd'
        self.assertEqual(self.call()['status'],'invalid_input')

    def test_sha256_git_object_format_selected_change(self):
        import shutil
        # EC203 already supports SHA-256, EC204 must compare its real blobs
        # and verify the baseline commit with the matching algorithm too.
        shutil.rmtree(self.fx.repo/'.git')
        self.fx.cmd('init','-q','-b','main','--object-format=sha256')
        self.fx.content=b'old sha256 content\n'
        self.fx.put(self.fx.repo,'src/component.md',self.fx.content)
        self.fx.commit('sha256 base')
        self.base_oid=self.fx.oid
        self.fx.content=b'new sha256 content\n'
        self.fx.put(self.fx.repo,'src/component.md',self.fx.content)
        self.fx.commit('sha256 target')
        self.api=self.factory()
        r=request(source('r1','repository','src/component.md',self.fx.content),
            target={'algorithm':'sha256','oid':self.fx.oid})
        self.r,self.bp,self.tp,self.target_doc=self.fx.binding(original=r)
        self.ip=self.impact_policy()
        self.baseline_doc=self.baseline_statement()
        self.baseline_doc['baseline_revision']={'algorithm':'sha256','oid':self.base_oid}
        s=self.ok(self.call())
        self.assertEqual(s['source_changes'][0]['change_kind'],'MODIFIED')
        self.assertEqual(s['selected_change_set_state'],'SELECTED_REPOSITORY_PATHS_COMPARED')

    def test_unsafe_baseline_git_symlink_is_unknown_not_removed(self):
        selected=self.fx.repo/'src/component.md'
        selected.unlink()
        selected.symlink_to('../unrelated.md')
        self.fx.commit('baseline unsafe symlink')
        self.base_oid=self.fx.oid
        selected.unlink()
        self.fx.put(self.fx.repo,'src/component.md',self.fx.content)
        self.fx.commit('repaired target')
        self.rebind()
        s=self.ok(self.call())
        self.assertEqual(s['source_changes'][0]['change_kind'],'UNKNOWN')
        self.assertEqual(s['source_changes'][0]['baseline_blob_state'],'UNSUPPORTED_TREE_ENTRY')

    def test_removed_target_path_does_not_sneak_past_ec203_gate(self):
        (self.fx.repo/'src/component.md').unlink()
        self.fx.commit('deleted target')
        self.rebind()
        s=self.ok(self.call())
        self.assertEqual(s['source_changes'][0]['change_kind'],'UNKNOWN')
        self.assertEqual(s['baseline_binding_state'],'NOT_INSPECTED_TARGET_NOT_ELIGIBLE')

    def test_knowledge_manifest_gap_survives_git_verified_diff(self):
        s=self.ok(self.call())
        self.assertTrue(s['bootstrap_coverage_gaps'])
        self.assertTrue(any('KNOWLEDGE' in x for x in s['uncertainty_reasons']))

    def test_invalid_source_scope_denied_before_analysis(self):
        self.r['sources'][0]['relative_path']='../root-secret'
        self.assertEqual(self.call()['status'],'invalid_input')

    def rebind(self):
        self.r, self.bp, self.tp, self.target_doc = self.fx.binding()
        self.ip = self.impact_policy()
        self.baseline_doc = self.baseline_statement()

    @unittest.skipIf(Draft202012Validator is None, 'jsonschema not installed')
    def test_all_three_draft202012_contracts_and_live_results(self):
        for name in ('knowledge-impact-read-policy.v1.schema.json',
            'knowledge-impact-baseline-statement.v1.schema.json',
            'knowledge-impact-result.v1.schema.json'):
            document=json.loads((SCHEMAS/name).read_text())
            Draft202012Validator.check_schema(document)
        validator=lambda name:Draft202012Validator(json.loads((SCHEMAS/name).read_text()),
            format_checker=__import__('jsonschema').FormatChecker())
        validator('knowledge-impact-read-policy.v1.schema.json').validate(self.ip)
        validator('knowledge-impact-baseline-statement.v1.schema.json').validate(self.baseline_doc)
        result=self.call()
        validator('knowledge-impact-result.v1.schema.json').validate(result)
        validator('knowledge-impact-result.v1.schema.json').validate(
            self.api.binding_preview(request_json=canonical(self.r)))
        result=self.call(target_sig=None)
        validator('knowledge-impact-result.v1.schema.json').validate(result)
        result=self.call(baseline=False)
        validator('knowledge-impact-result.v1.schema.json').validate(result)
        result=self.call(base_sig=base64.b64encode(b'0'*64).decode())
        validator('knowledge-impact-result.v1.schema.json').validate(result)


if __name__=='__main__':
    unittest.main()
