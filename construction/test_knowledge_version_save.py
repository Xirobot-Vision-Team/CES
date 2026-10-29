#!/usr/bin/env python3
"""EC208 real local bytes/private journal/Ed25519 tests, not organizational acceptance."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from knowledge_boundary import canonical, digest as source_digest
from knowledge_chapters import _sections
from knowledge_version_save import (KnowledgeVersionSave, SCHEMA, SIGNED_DOMAIN, ROLES,
                                   digest as save_digest, _mac)
import test_knowledge_update_handoff as handoff_fixture

H = 'a'*64


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode('ascii')


def stamp(t: datetime) -> str:
    return t.strftime('%Y-%m-%dT%H:%M:%SZ')


class VersionSaveTests(unittest.TestCase):
    def setUp(self):
        self.hfx = handoff_fixture.KnowledgeUpdateHandoffTests('test_single_manual_local_draft_without_side_effects')
        self.hfx.setUp()
        self.addCleanup(self.hfx.doCleanups)
        self.src = self.hfx.fx.knowledge/'knowledge.md'
        self.before = (b'# Architecture\nOriginal background.\n\n'
                       b'## API\nOld API behavior with evidence.\n')
        self.src.write_bytes(self.before)
        self.manifest_file = self.hfx.fx.knowledge/'ces-snapshot.v1.json'
        self.manifest = {
            'schema': 'ces.knowledge_snapshot_manifest.v1',
            'repository_ref': handoff_fixture.REPO, 'knowledge_space_key': 'architecture',
            'source_policy_revision': 'policy-v1', 'snapshot_version': 'snapshot1',
            'captured_at_utc': '2026-10-24T00:00:00Z', 'coverage': 'complete_declared',
            'entries': [{'relative_path': 'knowledge.md', 'sha256': digest(self.before),
                         'size_bytes': len(self.before)}],
        }
        self.manifest_file.write_text(canonical(self.manifest), encoding='ascii')
        self.section_ref = 'cesksection1:' + source_digest('CES-EC205-SECTION-v1', {
            'scope_binding_sha256': H, 'source_binding_sha256': H,
            'ordinal': 1, 'bytes_sha256': _sections(self.before)[1]['sha256'],
        })
        upstream = self.hfx.fx.upstream
        def bound_upstream(origin, **changes):
            result = json.loads(upstream(origin, **changes))
            if origin == 'ec205_chapter_mapping':
                result['subject']['chapter_documents'][0]['sections'][0]['section_ref'] = self.section_ref
                result['canonical_json'] = canonical(result['subject'])
            return canonical(result)
        self.hfx.fx.upstream = bound_upstream
        self.hfx.add(key='candidate_one', origin='ec205_chapter_mapping',
                     section_ref=self.section_ref)

        base = Path(self.hfx.fx.tmp.name)
        self.root = base/'version_metadata'
        self.root.mkdir(mode=0o700)
        self.priv = {role: Ed25519PrivateKey.generate() for role in ROLES}
        self.trust = {('reviewer01' if role == 'independent_reviewer' else 'owner01'): {
            'role': role, 'public_key': key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)}
            for role, key in self.priv.items()}
        self.params = dict(root=str(self.root), store_id='knowledge_versions',
                           candidate_store=self.hfx.fx.api, chapter_path='knowledge.md',
                           trusted_approvers=self.trust)
        self.api = KnowledgeVersionSave(**self.params)
        self.assertEqual(self.api.initialize(allow_initialize=True)['status'], 'partial')
        self.hreq = self.hfx.request(['candidate_one'])
        pv = self.hfx.preview(['candidate_one'])
        self.hpolicy = self.hfx.policy(pv)
        self.reads = self.hfx.reads(pv)
        self.handoff = self.hfx.handoff.prepare(
            request_json=self.hreq, handoff_policy_json=self.hpolicy,
            candidate_read_policies_json=self.reads)
        self.assertEqual(self.handoff['status'], 'partial', self.handoff)
        self.draft = self.handoff['subject']
        self.original_section = _sections(self.before)[1]
        self.first_section = b'## API\nImproved behavior, reviewed by humans.\n'
        self.req = self.request()
        self.args = {'handoff_request_json': self.hreq,
                     'handoff_policy_json': self.hpolicy,
                     'candidate_read_policies_json': self.reads}

    def request(self, **overrides):
        old_section = self.original_section
        replacement = self.first_section
        current = self.before
        after = current[:old_section['start']] + replacement + current[old_section['end']:]
        doc = {'schema': 'ces.knowledge_save_request.v1',
            'operation': 'knowledge.save.metadata_version', 'save_key': 'version_one',
            'repository_ref': handoff_fixture.REPO, 'knowledge_space_key': 'architecture',
            'period_id': 'period01', 'source_policy_revision': 'policy-v1',
            'chapter_path': 'knowledge.md', 'expected_snapshot_version': 'snapshot1',
            'expected_manifest_sha256': digest(self.manifest_file.read_bytes()),
            'expected_baseline_chapter_sha256': digest(self.before),
            'expected_parent_version_id': None,
            'expected_parent_content_sha256': digest(current),
            'section_index': 1, 'expected_section_sha256': old_section['sha256'],
            'section_ref': self.section_ref,
            'ec202_knowledge_source_binding_sha256': H,
            'save_permission_receipt_sha256': H,
            'replacement_section_base64': b64(replacement),
            'replacement_section_sha256': digest(replacement),
            'expected_new_chapter_sha256': digest(after),
            'selection_binding_sha256': self.draft['selection_binding_sha256'],
            'ai_input_sha256': self.draft['ai_input_sha256'],
            'candidate_keys': ['candidate_one'],
            'candidate_record_ids': [self.draft['ai_input']['candidate_evidence'][0]['record_id']],
            'review_summary': 'Independent human-reviewed correction for a locally pinned API section.'}
        doc.update(overrides)
        return canonical(doc)

    def preview(self, request=None, **arguments):
        kw = dict(self.args)
        kw.update(arguments)
        return self.api.preview(request_json=request or self.req, **kw)

    def policy(self, preview, **overrides):
        doc = {'schema': 'ces.knowledge_save_policy.v1',
               'purpose': 'append_immutable_local_ces_knowledge_metadata_only',
               'store_instance_id': preview['store_instance_id'],
               'store_scope_binding_sha256': preview['store_scope_binding_sha256'],
               'authorization_scope_sha256': preview['authorization_scope_sha256'],
               'permission_receipt_sha256': H,
               'permit_local_version_append': True,
               'permit_reviewed_text_local_persistence': True,
               'permit_restricted_local_persistence': False,
               'permit_source_knowledge_overwrite': False,
               'permit_business_repository_write': False,
               'permit_issue_or_provider_write': False,
               'permit_publish': False}
        doc.update(overrides)
        return canonical(doc)

    def approvals(self, binding, **changes):
        when = datetime.now(timezone.utc).replace(microsecond=0)
        statements = []
        for role in ROLES:
            key_id = 'reviewer01' if role == 'independent_reviewer' else 'owner01'
            stmt = {'schema': 'ces.knowledge_save_approval_statement.v1',
                    'purpose': 'approve_exact_local_ces_knowledge_metadata_version',
                    'signer_key_id': key_id, 'role': role,
                    'authorization_scope_sha256': binding,
                    'review_state': 'REVIEWED_APPROVED_FOR_THIS_VERSION_ONLY',
                    'issued_at_utc': stamp(when),
                    'expires_at_utc': stamp(when + timedelta(minutes=30))}
            stmt.update(changes.get(role, {}))
            sig = self.priv[role].sign(SIGNED_DOMAIN+canonical(stmt).encode('ascii'))
            statements.append({'statement': stmt, 'signature_base64': b64(sig)})
        return canonical({'schema': 'ces.knowledge_save_approvals.v1',
                          'statements': statements})

    def save(self, request=None, policy=None, approvals=None, **other):
        req = request or self.req
        pv = self.preview(req)
        self.assertEqual(pv['status'], 'partial', pv)
        pin = pv['subject']
        return self.api.save(request_json=req, **self.args,
            save_policy_json=policy or self.policy(pin),
            approvals_json=approvals or self.approvals(pin['authorization_scope_sha256']),
            **other)

    def _sign(self, request, *, policy_changes=None, approval_changes=None):
        pv = self.preview(request)
        self.assertEqual(pv['status'], 'partial', pv)
        pin = pv['subject']
        return {'request_json': request, **self.args,
                'save_policy_json': self.policy(pin, **(policy_changes or {})),
                'approvals_json': self.approvals(pin['authorization_scope_sha256'],
                                                 **(approval_changes or {}))}

    def test_initialized_only_explicitly_and_no_source_modification(self):
        self.assertEqual(self.api.initialize(allow_initialize=True)['status'], 'unavailable')
        self.assertEqual(self.api.initialize(allow_initialize=False)['status'], 'unavailable')
        original_code = (self.hfx.fx.repo/'source.txt').read_bytes()
        preview = self.preview()
        self.assertEqual(preview['status'], 'partial', preview)
        self.assertFalse(preview['subject']['write_authorized'])
        self.assertNotIn('Improved behavior', json.dumps(preview))
        self.assertEqual(list((self.root/'versions').iterdir()), [])
        saved = self.save()
        self.assertEqual(saved['status'], 'partial', saved)
        self.assertTrue(saved['local_version_metadata_written'])
        self.assertFalse(saved['source_knowledge_file_written'])
        self.assertTrue(saved['subject']['reviewer_and_owner_signatures_locally_verified'])
        self.assertEqual(self.src.read_bytes(), self.before)
        self.assertEqual((self.hfx.fx.repo/'source.txt').read_bytes(), original_code)
        self.assertEqual(len(list((self.root/'versions').iterdir())), 1)
        inspected = self.api.inspect()
        self.assertEqual(inspected['status'], 'partial', inspected)
        self.assertEqual(inspected['subject']['head_version_id'], saved['subject']['version_id'])
        self.assertEqual(inspected['subject']['head_content_sha256'],
                         saved['subject']['chapter_content_sha256'])

    def test_duplicate_attempt_same_approvals_is_no_op(self):
        kwargs = self._sign(self.req)
        first = self.api.save(**kwargs)
        second = self.api.save(**kwargs)
        self.assertEqual(first['status'], 'partial', first)
        self.assertEqual(second['reason_code'], 'KNOWLEDGE_SAVE_ALREADY_SAVED_IDEMPOTENT_NO_WRITE')
        self.assertFalse(second['local_version_metadata_written'])
        self.assertEqual(first['subject']['version_id'], second['subject']['version_id'])
        self.assertEqual(len(list((self.root/'versions').iterdir())), 1)

    def test_second_version_chains_locally_without_touching_baseline(self):
        first = self.save()
        self.assertEqual(first['status'], 'partial', first)
        updated = self.before[:self.original_section['start']] + self.first_section
        section = _sections(updated)[1]
        replacement2 = b'## API\nRevised a second time after independent review.\n'
        result2 = updated[:section['start']] + replacement2
        req2 = self.request(save_key='version_two',
            expected_parent_version_id= first['subject']['version_id'],
            expected_parent_content_sha256= digest(updated),
            expected_section_sha256= section['sha256'],
            replacement_section_base64= b64(replacement2),
            replacement_section_sha256= digest(replacement2),
            expected_new_chapter_sha256= digest(result2))
        second = self.save(req2)
        self.assertEqual(second['status'], 'partial', second)
        info = self.api.inspect()['subject']
        self.assertEqual(info['version_count'], 2)
        self.assertEqual(info['head_version_id'], second['subject']['version_id'])
        self.assertEqual(info['version_receipts'][1]['parent_version_id'], first['subject']['version_id'])
        self.assertEqual(self.src.read_bytes(), self.before)

    def test_stale_parent_fails_closed_without_retry(self):
        first = self.save()
        stale = self.request(save_key='another_save')
        denied = self.preview(stale)
        self.assertEqual(denied['status'], 'unavailable')
        self.assertIn('OPTIMISTIC_PARENT_VERSION_CONFLICT', denied['reason_code'])
        self.assertEqual(len(list((self.root/'versions').iterdir())), 1)

    def test_section_fingerprint_and_scope_edits_are_denied(self):
        bad = self.request(expected_section_sha256=H)
        self.assertIn('SECTION_FINGERPRINT_CONFLICT', self.preview(bad)['reason_code'])
        bad2 = self.request(expected_new_chapter_sha256=H)
        self.assertIn('NEW_CHAPTER_DIGEST', self.preview(bad2)['reason_code'])
        bad3 = self.request(section_ref='cesksection1:'+'c'*64)
        self.assertIn('EC205_SECTION_REFERENCE_MISMATCH', self.preview(bad3)['reason_code'])
        bad4 = self.request(candidate_record_ids=[H])
        self.assertIn('CANDIDATE_RECORD_SELECTION_MISMATCH', self.preview(bad4)['reason_code'])
        bad5 = self.request(ai_input_sha256=H)
        self.assertIn('EC207_DRAFT_OR_SELECTION_PIN_MISMATCH', self.preview(bad5)['reason_code'])
        self.assertEqual(list((self.root/'versions').iterdir()), [])

    def test_independent_signatures_required_and_exact_approval_scope(self):
        base = self._sign(self.req)
        one = json.loads(base['approvals_json'])
        one['statements'].pop()
        denied = self.api.save(**{**base,'approvals_json':canonical(one)})
        self.assertIn('TWO_INDEPENDENT_APPROVALS_REQUIRED', denied['reason_code'])
        wrong = json.loads(base['approvals_json'])
        wrong['statements'][1]['signature_base64'] = wrong['statements'][0]['signature_base64']
        denied = self.api.save(**{**base,'approvals_json':canonical(wrong)})
        self.assertIn('SIGNATURE_INVALID', denied['reason_code'])
        wrong2 = json.loads(base['approvals_json'])
        wrong2['statements'][0]['statement']['authorization_scope_sha256'] = H
        denied = self.api.save(**{**base,'approvals_json':canonical(wrong2)})
        self.assertIn('APPROVAL_SCOPE_ROLE_OR_DECISION_INVALID', denied['reason_code'])
        self.assertFalse(list((self.root/'versions').iterdir()))

    def test_expiry_revocation_and_registry_drift_not_claimed_authoritative(self):
        base = self._sign(self.req)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        expired = self.approvals(self.preview()['subject']['authorization_scope_sha256'],
            independent_reviewer={'issued_at_utc':stamp(now - timedelta(days=2)),
                                  'expires_at_utc':stamp(now - timedelta(days=1))})
        self.assertIn('APPROVAL_EXPIRED', self.api.save(**{**base,
            'approvals_json':expired})['reason_code'])
        # Caller cannot silently change configured trust after store init.
        different = dict(self.params)
        different['revoked_approvers'] = {'reviewer01'}
        with self.assertRaises(ValueError):
            # No remaining active reviewer at all: construction fails closed.
            KnowledgeVersionSave(**different)
        extra = {**self.trust, 'reviewer02': self.trust['reviewer01']}
        other = KnowledgeVersionSave(**{**self.params, 'trusted_approvers': extra})
        self.assertIn('APPROVER_REGISTRY_OR_REVOCATION_DRIFT', other.inspect()['reason_code'])

    def test_restricted_requires_additional_local_grant(self):
        self.hfx.add(key='candidate_two', sensitivity='RESTRICTED', origin='manual_proposal')
        pv = self.hfx.preview(['candidate_one','candidate_two'])
        req_h = self.hfx.request(['candidate_one','candidate_two'])
        hp = self.hfx.policy(pv, permit_multi_candidate_draft=True,
                              permit_restricted_local_draft=True)
        reads = self.hfx.reads(pv)
        out = self.hfx.handoff.prepare(request_json=req_h,
                    handoff_policy_json=hp, candidate_read_policies_json=reads)
        self.assertEqual(out['status'], 'partial', out)
        ai = out['subject']
        req = self.request(selection_binding_sha256=ai['selection_binding_sha256'],
            ai_input_sha256=ai['ai_input_sha256'], candidate_keys=['candidate_one','candidate_two'],
            candidate_record_ids=[e['record_id'] for e in ai['ai_input']['candidate_evidence']])
        args = {'request_json':req, 'handoff_request_json':req_h,
                'handoff_policy_json':hp, 'candidate_read_policies_json':reads}
        preview = self.api.preview(**args)
        self.assertEqual(preview['status'],'partial', preview)
        pin=preview['subject']
        self.assertTrue(pin['restricted_content'])
        denied = self.api.save(**args, save_policy_json=self.policy(pin),
            approvals_json=self.approvals(pin['authorization_scope_sha256']))
        self.assertIn('POLICY_PERMISSION_DENIED', denied['reason_code'])
        result = self.api.save(**args,
            save_policy_json=self.policy(pin,permit_restricted_local_persistence=True),
            approvals_json=self.approvals(pin['authorization_scope_sha256']))
        self.assertEqual(result['status'],'partial', result)

    def test_handoff_grants_reapplied_on_save_and_no_auto_promotion(self):
        base = self._sign(self.req)
        altered = self.hfx.policy(self.hfx.preview(['candidate_one']),
                                   permit_knowledge_save=True)
        denied = self.api.save(**{**base,'handoff_policy_json':altered})
        self.assertIn('EC207_HANDOFF_NOT_AUTHORIZED', denied['reason_code'])
        self.assertFalse(list((self.root/'versions').iterdir()))
        denied2 = self.api.save(**{**base,'save_policy_json':self.policy(
            self.preview()['subject'],permit_publish=True)})
        self.assertIn('POLICY_PERMISSION_DENIED', denied2['reason_code'])
        self.assertFalse(list((self.root/'versions').iterdir()))

    def test_source_snapshot_file_or_manifest_drift_denied(self):
        self.src.write_bytes(self.before + b'\nexternal-drift\n')
        self.assertEqual(self.preview()['status'], 'unavailable')
        self.src.write_bytes(self.before)
        data = json.loads(self.manifest_file.read_text())
        data['snapshot_version']='snapshot2'
        self.manifest_file.write_text(canonical(data),encoding='ascii')
        self.assertIn('AUTHORITATIVE_KNOWLEDGE_BASELINE_DRIFT',
                      self.preview()['reason_code'])
        self.assertFalse(list((self.root/'versions').iterdir()))

    def test_tampered_record_and_unsafe_symlink_fail_closed(self):
        saved = self.save()
        self.assertEqual(saved['status'], 'partial', saved)
        path = self.root/'versions'/'00000001.json'
        record = json.loads(path.read_text('ascii'))
        record['body']['review_summary']='tampered'
        # Simulate an attacker who can read the LOCAL MAC key; cryptographic
        # reviewer/owner signatures must still pin the original review request.
        record['version_id'] = save_digest('IMMUTABLE-VERSION', {
            'sequence':record['sequence'], 'body':record['body']})
        manifest = json.loads((self.root/'manifest.json').read_text())
        unsigned = {k:record[k] for k in ('schema','sequence','version_id','body')}
        record['local_mac_sha256'] = _mac(manifest, unsigned)
        path.write_text(canonical(record)+'\n', encoding='ascii')
        self.assertIn('RECORD_SIGNED_REQUEST_OR_AUTHORIZATION_UNBOUND',
                      self.api.inspect()['reason_code'])
        path.unlink()
        path.symlink_to(self.src)
        self.assertEqual(self.api.inspect()['status'],'unavailable')
        self.assertEqual(self.src.read_bytes(), self.before)

    def test_malformed_input_and_unsafe_selection_no_write(self):
        no = self.preview(request=self.req+'\n')
        self.assertEqual(no['status'],'invalid_input')
        bad = self.request(replacement_section_base64='!!!')
        self.assertEqual(self.preview(bad)['status'],'invalid_input')
        bad = self.request(replacement_section_base64=b64(b'## Different heading\nText\n'),
            replacement_section_sha256=digest(b'## Different heading\nText\n'),
            expected_new_chapter_sha256=digest(self.before[:self.original_section['start']]+b'## Different heading\nText\n'))
        self.assertIn('SECTION_SCOPE_OR_FINGERPRINT_CONFLICT',self.preview(bad)['reason_code'])
        self.assertFalse(list((self.root/'versions').iterdir()))

    def test_idempotent_key_conflict_and_local_scope_confusion(self):
        kwargs=self._sign(self.req)
        saved=self.api.save(**kwargs)
        self.assertEqual(saved['status'],'partial',saved)
        conflict=self.request(review_summary='Different review for same save key')
        denied=self.preview(conflict)
        self.assertIn('SAVE_KEY_ALREADY_USED',denied['reason_code'])
        self.assertEqual(self.api.inspect()['subject']['version_count'],1)


if __name__ == '__main__':
    unittest.main()
