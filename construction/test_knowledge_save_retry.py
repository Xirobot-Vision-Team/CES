#!/usr/bin/env python3
"""EC209 POSIX local conflict/retry integration, not organizational acceptance."""
from __future__ import annotations

import json
import unittest

from knowledge_boundary import canonical
from knowledge_chapters import _sections
from knowledge_save_retry import KnowledgeSaveRetry, SCHEMA, PURPOSE, ACKNOWLEDGEMENT
import test_knowledge_version_save as save_fixture

digest, b64, H = save_fixture.digest, save_fixture.b64, save_fixture.H


class KnowledgeSaveRetryTests(unittest.TestCase):
    def setUp(self):
        self.fx = save_fixture.VersionSaveTests('test_initialized_only_explicitly_and_no_source_modification')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.retry = KnowledgeSaveRetry(self.fx.api)
        self.original = self.fx.request(save_key='pending_api_review')
        self.args = {'request_json': self.original, **self.fx.args}

    def _other_section_write(self, key='peer_intro'):
        """Append a properly approved version touching only section zero."""
        self.fx.hfx.add(key='manual_intro', origin='manual_proposal')
        hreq = self.fx.hfx.request(['manual_intro'])
        pv = self.fx.hfx.preview(['manual_intro'])
        hp = self.fx.hfx.policy(pv)
        reads = self.fx.hfx.reads(pv)
        draft = self.fx.hfx.handoff.prepare(
            request_json=hreq, handoff_policy_json=hp,
            candidate_read_policies_json=reads)['subject']
        original_section = _sections(self.fx.before)[0]
        replacement = b'# Architecture\nRevised introductory context.\n\n'
        new_content = (self.fx.before[:original_section['start']] + replacement +
                       self.fx.before[original_section['end']:])
        data = json.loads(self.fx.req)
        data.update(save_key=key, section_index=0, section_ref=None,
            ec202_knowledge_source_binding_sha256=None,
            expected_section_sha256=original_section['sha256'],
            expected_parent_version_id=None,
            expected_parent_content_sha256=digest(self.fx.before),
            replacement_section_base64=b64(replacement),
            replacement_section_sha256=digest(replacement),
            expected_new_chapter_sha256=digest(new_content),
            candidate_keys=['manual_intro'],
            candidate_record_ids=[draft['ai_input']['candidate_evidence'][0]['record_id']],
            selection_binding_sha256=draft['selection_binding_sha256'],
            ai_input_sha256=draft['ai_input_sha256'])
        args = {'request_json':canonical(data), 'handoff_request_json':hreq,
                'handoff_policy_json':hp, 'candidate_read_policies_json':reads}
        preview = self.fx.api.preview(**args)
        self.assertEqual(preview['status'], 'partial', preview)
        subject = preview['subject']
        result = self.fx.api.save(**args,
            save_policy_json=self.fx.policy(subject),
            approvals_json=self.fx.approvals(subject['authorization_scope_sha256']))
        self.assertEqual(result['status'], 'partial', result)
        self.assertTrue(result['local_version_metadata_written'])
        return result

    def assess(self, **updates):
        return self.retry.assess(**{**self.args, **updates})

    def _intent(self, observed, **changes):
        doc = {'schema': 'ces.knowledge_save_retry_intent.v1',
               'purpose': PURPOSE,
               'original_request_binding_sha256': observed['original_request_binding_sha256'],
               'observed_head_version_id': observed['observed_head_version_id'],
               'observed_head_content_sha256': observed['observed_head_content_sha256'],
               'observed_target_section_sha256': observed['observed_target_section_sha256'],
               'observed_intervening_version_ids': [
                   row['version_id'] for row in observed['intervening_version_receipts']],
               'new_save_key': 'retry_api_review',
               'new_save_permission_receipt_sha256': 'b'*64,
               'new_review_summary': 'Manually re-reviewed the intervening introduction edits; submit API replacement for fresh approvals.',
               'review_acknowledgement': ACKNOWLEDGEMENT}
        doc.update(changes)
        return canonical(doc)

    def _policy(self, preview, **changes):
        s = preview['subject']
        doc = {'schema': 'ces.knowledge_save_retry_policy.v1',
               'purpose': PURPOSE,
               'store_instance_id': s['store_instance_id'],
               'store_scope_binding_sha256': s['store_scope_binding_sha256'],
               'retry_authorization_scope_sha256': s['retry_authorization_scope_sha256'],
               'retry_permission_receipt_sha256': 'c'*64,
               'permit_disjoint_retry_request_prepare': True,
               'permit_retry_proposed_text_return': True,
               'permit_restricted_retry_proposed_text_return': False,
               'permit_automatic_target_content_merge': False,
               'permit_automatic_version_append': False,
               'permit_source_knowledge_overwrite': False,
               'permit_business_repository_write': False,
               'permit_issue_or_provider_write': False,
               'permit_publish': False}
        doc.update(changes)
        return canonical(doc)

    def _prepare(self, **changes):
        evaluated = self.assess()
        self.assertEqual(evaluated['reason_code'],
                         'KNOWLEDGE_RETRY_DISJOINT_PARENT_MOVED_RE_REVIEW_REQUIRED', evaluated)
        intent = self._intent(evaluated['subject'])
        preview = self.retry.preview_retry(**self.args, retry_intent_json=intent)
        self.assertEqual(preview['status'], 'partial', preview)
        return self.retry.prepare_retry(**self.args,
            retry_intent_json=changes.pop('intent', intent),
            retry_policy_json=changes.pop('policy', self._policy(preview)), **changes)

    def test_unmodified_head_requires_no_retry(self):
        result = self.assess()
        self.assertEqual(result['status'], 'partial', result)
        self.assertEqual(result['subject']['state'], 'CURRENT_PARENT_VALID_NO_RETRY_NEEDED')
        self.assertFalse(result['retry_request_prepared'])
        self.assertFalse(result['local_version_metadata_written'])
        self.assertNotIn('Improved behavior', json.dumps(result))

    def test_disjoint_concurrent_change_prepares_new_exact_request_then_fresh_human_save(self):
        first = self._other_section_write()
        denied = self.fx.api.preview(**self.args)
        self.assertIn('OPTIMISTIC_PARENT_VERSION_CONFLICT', denied['reason_code'])
        analyzed = self.assess()
        self.assertEqual(analyzed['status'], 'partial', analyzed)
        self.assertEqual(analyzed['subject']['observed_head_version_id'],
                         first['subject']['version_id'])
        self.assertTrue(analyzed['subject']['retry_eligible_after_independent_permission'])
        prepared = self._prepare()
        self.assertEqual(prepared['status'], 'partial', prepared)
        self.assertEqual(prepared['schema'], SCHEMA)
        self.assertTrue(prepared['retry_request_prepared'])
        self.assertFalse(prepared['local_version_metadata_written'])
        self.assertFalse(prepared['old_approvals_reused'])
        generated = json.loads(prepared['subject']['rebased_request_json'])
        original = json.loads(self.original)
        self.assertEqual(generated['replacement_section_base64'], original['replacement_section_base64'])
        self.assertEqual(generated['candidate_record_ids'], original['candidate_record_ids'])
        self.assertEqual(generated['expected_parent_version_id'], first['subject']['version_id'])
        self.assertNotEqual(generated['expected_new_chapter_sha256'],
                            original['expected_new_chapter_sha256'])
        self.assertEqual(generated['save_permission_receipt_sha256'], 'b'*64)
        self.assertEqual(self.fx.api.inspect()['subject']['version_count'], 1)
        # EC209 does not sign, grant or append. New EC208 scope must be
        # independently previewed, granted and signed after review.
        new_req = canonical(generated)
        pv = self.fx.api.preview(request_json=new_req, **self.fx.args)
        self.assertEqual(pv['status'], 'partial', pv)
        pin = pv['subject']
        self.assertEqual(pin['authorization_scope_sha256'],
                         prepared['subject']['rebased_ec208_authorization_scope_sha256'])
        new_policy = self.fx.policy(pin, permission_receipt_sha256='b'*64)
        new_approvals = self.fx.approvals(pin['authorization_scope_sha256'])
        result = self.fx.api.save(request_json=new_req, **self.fx.args,
            save_policy_json=new_policy, approvals_json=new_approvals)
        self.assertEqual(result['status'], 'partial', result)
        self.assertTrue(result['local_version_metadata_written'])
        self.assertEqual(self.fx.api.inspect()['subject']['version_count'], 2)
        self.assertEqual(self.fx.src.read_bytes(), self.fx.before)

    def test_same_target_change_forces_manual_merge(self):
        self.fx.save()
        found = self.assess()
        self.assertEqual(found['status'], 'unavailable')
        self.assertIn('TARGET_SHA_CHANGED', found['reason_code'])
        self.assertFalse(found['subject']['retry_eligible_after_independent_permission'])
        attempt = self.retry.preview_retry(**self.args,
            retry_intent_json=self._intent(found['subject']))
        self.assertIn('CONFLICT_RETRY_NOT_ELIGIBLE', attempt['reason_code'])
        self.assertEqual(self.fx.api.inspect()['subject']['version_count'], 1)

    def test_target_aba_revert_still_denies_automatic_retry(self):
        first = self.fx.save()
        updated = self.fx.before[:self.fx.original_section['start']] + self.fx.first_section
        new_section = _sections(updated)[1]
        reverted = updated[:new_section['start']] + self.fx.before[
            self.fx.original_section['start']:self.fx.original_section['end']]
        revert = self.fx.request(save_key='revert_api',
            expected_parent_version_id=first['subject']['version_id'],
            expected_parent_content_sha256=digest(updated),
            expected_section_sha256=new_section['sha256'],
            replacement_section_base64=b64(self.fx.before[
                self.fx.original_section['start']:self.fx.original_section['end']]),
            replacement_section_sha256=self.fx.original_section['sha256'],
            expected_new_chapter_sha256=digest(reverted))
        second = self.fx.save(revert)
        self.assertTrue(second['local_version_metadata_written'])
        result = self.assess()
        self.assertIn('TARGET_ABA_TOUCHED', result['reason_code'])
        self.assertEqual(len(result['subject']['intervening_version_receipts']), 2)
        self.assertFalse(result['subject']['retry_eligible_after_independent_permission'])

    def test_conflicting_save_key_or_succeeded_unknown_avoids_blind_retry(self):
        self.fx.save()
        used = self.fx.request(save_key='version_one')
        out = self.assess(request_json=used)
        self.assertEqual(out['subject']['state'], 'ALREADY_RECORDED_NO_RETRY')
        tampered = self.fx.request(save_key='version_one',
                                 review_summary='Changed signed review contents')
        denied = self.assess(request_json=tampered)
        self.assertIn('CONFLICT_SAVE_KEY_REUSED', denied['reason_code'])
        self.assertIsNone(denied['subject'])
        self.assertEqual(self.fx.api.inspect()['subject']['version_count'], 1)

    def test_stale_original_target_sha_and_unobserved_parent_are_refused(self):
        self._other_section_write()
        stale = self.fx.request(save_key='pending_api_review', expected_section_sha256=H)
        denied = self.assess(request_json=stale)
        self.assertIn('OPTIMISTIC_SECTION_FINGERPRINT_CONFLICT', denied['reason_code'])
        phantom = self.fx.request(save_key='pending_api_review',
                                  expected_parent_version_id='d'*64)
        denied2 = self.assess(request_json=phantom)
        self.assertIn('PARENT_NOT_AN_IMMUTABLE_ANCESTOR', denied2['reason_code'])

    def test_replay_invalid_original_expected_chapter_sha_refuses_rebase(self):
        self._other_section_write()
        altered = self.fx.request(save_key='pending_api_review',
                                  expected_new_chapter_sha256='e'*64)
        self.assertIn('NEW_CHAPTER_DIGEST',
                      self.assess(request_json=altered)['reason_code'])

    def test_intent_pins_head_history_and_explicit_new_key(self):
        self._other_section_write()
        view = self.assess()['subject']
        for changes in ({'observed_head_content_sha256': H},
                        {'observed_intervening_version_ids': []},
                        {'new_save_key': 'pending_api_review'},
                        {'new_save_permission_receipt_sha256': H},
                        {'new_review_summary':json.loads(self.original)['review_summary']},
                        {'review_acknowledgement':'AUTOMATIC_MERGE'}):
            denied = self.retry.preview_retry(**self.args,
                retry_intent_json=self._intent(view, **changes))
            self.assertNotEqual(denied['status'], 'partial', denied)
        self.assertEqual(self.fx.api.inspect()['subject']['version_count'], 1)

    def test_independent_retry_policy_exact_scope_and_denies_any_escalation(self):
        self._other_section_write()
        view = self.assess()['subject']
        intent = self._intent(view)
        preview = self.retry.preview_retry(**self.args, retry_intent_json=intent)
        self.assertEqual(preview['status'], 'partial', preview)
        for changes in ({'retry_authorization_scope_sha256': H},
                        {'retry_permission_receipt_sha256': H},
                        {'permit_automatic_version_append': True},
                        {'permit_automatic_target_content_merge': True},
                        {'permit_publish': True},
                        {'permit_source_knowledge_overwrite': True},
                        {'permit_retry_proposed_text_return': False},
                        {'permit_disjoint_retry_request_prepare': 1}):
            denied = self.retry.prepare_retry(**self.args,
                retry_intent_json=intent,
                retry_policy_json=self._policy(preview, **changes))
            self.assertNotEqual(denied['status'], 'partial', denied)
            self.assertNotIn('rebased_request_json', json.dumps(denied))
        self.assertEqual(self.fx.api.inspect()['subject']['version_count'], 1)

    def test_observation_drift_between_preview_and_prepare_requires_restart(self):
        self._other_section_write()
        view = self.assess()['subject']
        intent = self._intent(view)
        pv = self.retry.preview_retry(**self.args, retry_intent_json=intent)
        policy = self._policy(pv)
        # Another independently authorized local version changes this target.
        first_head = self.fx.api.inspect()['subject']
        current = self.fx.before[:_sections(self.fx.before)[0]['start']] + b'# Architecture\nRevised introductory context.\n\n' + self.fx.before[_sections(self.fx.before)[0]['end']:]
        section = _sections(current)[1]
        changed_section = b'## API\nAnother reviewer changed the API.\n'
        req = self.fx.request(save_key='competing_target',
            expected_parent_version_id=first_head['head_version_id'],
            expected_parent_content_sha256=digest(current),
            expected_section_sha256=section['sha256'],
            replacement_section_base64=b64(changed_section),
            replacement_section_sha256=digest(changed_section),
            expected_new_chapter_sha256=digest(current[:section['start']]+changed_section))
        self.assertTrue(self.fx.save(req)['local_version_metadata_written'])
        denied = self.retry.prepare_retry(**self.args, retry_intent_json=intent,
                                         retry_policy_json=policy)
        self.assertIn('CONFLICT_RETRY_NOT_ELIGIBLE', denied['reason_code'])
        self.assertEqual(self.fx.api.inspect()['subject']['version_count'], 2)

    def test_ec208_cas_blocks_late_concurrent_write_after_preparation(self):
        self._other_section_write()
        prepared = self._prepare()
        req = prepared['subject']['rebased_request_json']
        preview = self.fx.api.preview(request_json=req, **self.fx.args)
        pin = preview['subject']
        policy = self.fx.policy(pin, permission_receipt_sha256='b'*64)
        approvals = self.fx.approvals(pin['authorization_scope_sha256'])
        # Another writer now obtains the lock first and moves the head.
        head = self.fx.api.inspect()['subject']
        original = self.fx.before
        change = b'## API\nUpdated by another independently approved writer.\n'
        other_parent = original[:_sections(original)[0]['start']] + b'# Architecture\nRevised introductory context.\n\n' + original[_sections(original)[0]['end']:]
        sec = _sections(other_parent)[1]
        competing = self.fx.request(save_key='competing_target',
            expected_parent_version_id=head['head_version_id'],
            expected_parent_content_sha256=digest(other_parent),
            expected_section_sha256=sec['sha256'],
            replacement_section_base64=b64(change),
            replacement_section_sha256=digest(change),
            expected_new_chapter_sha256=digest(other_parent[:sec['start']]+change))
        self.assertTrue(self.fx.save(competing)['local_version_metadata_written'])
        denied = self.fx.api.save(request_json=req, **self.fx.args,
            save_policy_json=policy, approvals_json=approvals)
        self.assertIn('OPTIMISTIC_PARENT_VERSION_CONFLICT', denied['reason_code'])
        self.assertFalse(denied['local_version_metadata_written'])
        self.assertEqual(self.fx.api.inspect()['subject']['version_count'], 2)

    def test_snapshot_and_ec207_content_permission_changes_stop_retry(self):
        self._other_section_write()
        bad_policy = json.loads(self.fx.hpolicy)
        bad_policy['permit_selected_candidate_text_read'] = False
        denied = self.assess(handoff_policy_json=canonical(bad_policy))
        self.assertIn('EC207_HANDOFF_NOT_AUTHORIZED', denied['reason_code'])
        self.fx.src.write_bytes(self.fx.before+b'\nexternal drift')
        snapshot = self.assess()
        self.assertIn('KNOWLEDGE_SNAPSHOT_FILE_MISMATCH', snapshot['reason_code'])
        self.assertFalse(snapshot['local_version_metadata_written'])

    def test_restricted_selection_needs_new_explicit_text_return_permission(self):
        # Replace original handoff with a restricted-but-authorized candidate.
        self.fx.hfx.add(key='restricted_api', origin='manual_proposal', sensitivity='RESTRICTED')
        pv = self.fx.hfx.preview(['restricted_api'])
        hreq = self.fx.hfx.request(['restricted_api'])
        hpolicy = self.fx.hfx.policy(pv, permit_restricted_local_draft=True)
        reads = self.fx.hfx.reads(pv)
        draft = self.fx.hfx.handoff.prepare(
            request_json=hreq, handoff_policy_json=hpolicy,
            candidate_read_policies_json=reads)['subject']
        self.args = {'request_json':self.fx.request(save_key='pending_restricted',
            section_ref=None, ec202_knowledge_source_binding_sha256=None,
            selection_binding_sha256=draft['selection_binding_sha256'],
            ai_input_sha256=draft['ai_input_sha256'], candidate_keys=['restricted_api'],
            candidate_record_ids=[draft['ai_input']['candidate_evidence'][0]['record_id']]),
            'handoff_request_json':hreq, 'handoff_policy_json':hpolicy,
            'candidate_read_policies_json':reads}
        self._other_section_write()
        view=self.assess()['subject']
        intent=self._intent(view)
        pv=self.retry.preview_retry(**self.args,retry_intent_json=intent)
        self.assertTrue(pv['subject']['restricted_candidate_selection'])
        denied=self.retry.prepare_retry(**self.args, retry_intent_json=intent,
                retry_policy_json=self._policy(pv))
        self.assertIn('POLICY_PERMISSION_DENIED',denied['reason_code'])
        permitted=self.retry.prepare_retry(**self.args, retry_intent_json=intent,
            retry_policy_json=self._policy(pv,
                permit_restricted_retry_proposed_text_return=True))
        self.assertTrue(permitted['retry_request_prepared'], permitted)
        self.assertFalse(permitted['local_version_metadata_written'])


if __name__ == '__main__':
    unittest.main()
