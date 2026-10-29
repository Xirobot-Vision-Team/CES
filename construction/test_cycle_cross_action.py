#!/usr/bin/env python3
"""EC238 local development cases: genuine EC231+EC172, synthetic family outputs.

No enterprise/source/actor/real producer/OS crash or native acceptance claim.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import cycle_cross_action as cc
import cycle_run_metadata as md
import handoff_lifecycle as lc
import task_staging as st
from test_handoff_lifecycle import context


FAMILIES = {
    'Code': 'ces.code_prepare_multisource.v1',
    'Finding': 'ces.finding_save_result.v1',
    'Quality': 'ces.quality_show.v1',
    'Report': 'ces.report_prepare.v1',
    'Knowledge': 'ces.knowledge_update_handoff.v1',
    'Delivery': 'ces.delivery_preview.v1',
}


class CrossActionCases(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix='ces-ec238-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cycles = self.root / 'cycles'
        self.stage = self.root / 'stage'
        self.repo = self.root / 'business'
        self.stage.mkdir(mode=0o700)
        self.repo.mkdir(mode=0o700)
        (self.repo / 'business.txt').write_bytes(b'UNTOUCHED_BUSINESS_DATA')
        self.stager = st.TaskStaging(str(self.stage), str(self.repo))
        self.pin = self.stager.initialize(approve_init=True)['parent_pin']
        self.session = lc.Lifecycle.create(context(), 'ec238-created-0001')
        snap = self.session.snapshot()
        for target, key in [('READY', 'ec238-ready-0001'), ('ACTIVE', 'ec238-active-0001')]:
            snap = self.session.advance_run(target, expected_revision=snap['revision'],
                        context_sha256=snap['source']['context_sha256'], operation_key=key)
        snap = self.session.create_handoff(expected_revision=snap['revision'],
                    context_sha256=snap['source']['context_sha256'], operation_key='ec238-handoff-0001')
        self.handoff = snap['handoffs'][0]['handoff_id']
        self.staged = self.stager.stage_live(
            self.session, expected_parent_pin=self.pin,
            expected_revision=snap['revision'], context_sha256=snap['source']['context_sha256'],
            operation_key='ec238-created-0001', authorize_stage=True)
        self.stage_run = self.staged['run_id']
        self.snapshot = md.canonical({
            'schema': cc.CONTEXT_SNAPSHOT_SCHEMA, 'stage_run_id': self.stage_run,
            'handoff_id': self.handoff,
            'source_context_sha256': self.staged['source_context_sha256'],
            'source_identity_sha256': self.staged['source_identity_sha256'],
        })
        self.source_ref = 'host:ces-ec238-real-input'
        self.actions = [{'step_id': 'step_' + f.lower(), 'action': f + 'Show',
                         'mode': None, 'depends_on': []} for f in FAMILIES]
        self.store = md.CycleMetadataStore(self.cycles)
        self.run = self._cycle()['run_id']
        self.ledger = cc.CycleCrossActionLedger(self.cycles, self.stage, self.repo)
        self.repo_before = (self.repo / 'business.txt').read_bytes()

    def _cycle(self):
        return self.store.create(snapshot_bytes=self.snapshot, source_ref=self.source_ref,
            actor_origin='human', actor_subject='operator', actions=self.actions)

    def link(self, run=None, handoff=None, **changes):
        params = dict(snapshot_bytes=self.snapshot, source_ref=self.source_ref,
                      expected_stage_parent_pin=self.pin)
        params.update(changes)
        return self.ledger.link(run or self.run, handoff or self.handoff, **params)

    def artifact(self, family, **overrides):
        # Synthetic records have real allowed producer schema labels, not claims
        # of executing corresponding original native or business modules.
        o = {'schema': FAMILIES[family], 'status': 'partial',
             'reason_code': 'SYNTHETIC_UNVERIFIED_RESULT',
             'metadata': {'handoff_id': self.handoff,
                          'run_id': self.stage_run,
                          'source_context_sha256': self.staged['source_context_sha256'],
                          'source_identity_sha256': self.staged['source_identity_sha256']},
             'declared_result': family}
        o.update(overrides)
        return md.canonical(o)

    def attach(self, family, raw=None, *, run=None, handoff=None):
        return self.ledger.attach(run or self.run, handoff or self.handoff,
                                  expected_stage_parent_pin=self.pin,
                                  family=family, step_id='step_' + family.lower(),
                                  artifact_bytes=self.artifact(family) if raw is None else raw)

    def check(self, candidates):
        return self.ledger.check(self.run, self.handoff,
            expected_stage_parent_pin=self.pin, candidates=candidates)

    def err(self, expected, fn):
        with self.assertRaises((cc.CrossActionError, md.CycleMetadataError, st.StageError)) as context:
            fn()
        self.assertEqual(context.exception.code, expected)

    def test_old_plain_cycle_snapshot_cannot_be_backfilled_to_existing_handoff(self):
        old = md.canonical({'input': 'an original cycle created without a stage anchor'})
        old_run = self.store.create(snapshot_bytes=old, source_ref=self.source_ref,
            actor_origin='human', actor_subject='operator', actions=self.actions)['run_id']
        self.err('CROSS_SNAPSHOT_NOT_SAME_STAGED_HANDOFF', lambda:
            self.ledger.link(old_run, self.handoff, snapshot_bytes=old,
                source_ref=self.source_ref, expected_stage_parent_pin=self.pin))
        self.assertFalse((self.cycles / (self.handoff + cc.OWNER_FILE)).exists())

    def test_genuine_finding_show_schema_and_zero_claim_count_are_explicit(self):
        self.link()
        raw = md.canonical({'schema': 'ces.finding_show_result.v1', 'status': 'partial',
                            'reason_code': 'FINDINGSHOW_DECLARATION_ONLY',
                            'scope': {'finding_count': 0}})
        result = self.attach('Finding', raw)
        self.assertEqual(result['artifacts'][0]['producer_schema'],
                         'ces.finding_show_result.v1')
        self.assertEqual(result['artifacts'][0]['identity_fields_checked'], 0)
        self.assertFalse(result['producer_authenticated'])
        self.assertFalse(result['business_steps_executed_proven'])
        self.assertTrue(self.check([{'family': 'Finding', 'step_id': 'step_finding',
                                    'artifact_bytes': raw}])['local_identity_consistent'])
        bad = md.canonical({'schema': 'ces.finding_show.v1', 'status': 'partial',
                            'reason_code': 'OLD_INACCURATE_LABEL', 'scope': {}})
        self.err('CROSS_PRODUCER_SCHEMA_FAMILY_MISMATCH',
                 lambda: self.attach('Finding', bad))

    def test_output_and_snapshot_draft2020_12_contracts(self):
        import jsonschema
        root = Path(__file__).resolve().parent.parent
        with open(root / 'references/cycle-cross-action-result.v1.schema.json',
                  encoding='utf-8') as f:
            result_schema = json.load(f)
        with open(root / 'references/cycle-cross-action-snapshot.v1.schema.json',
                  encoding='utf-8') as f:
            snapshot_schema = json.load(f)
        jsonschema.Draft202012Validator.check_schema(result_schema)
        jsonschema.Draft202012Validator.check_schema(snapshot_schema)
        validate_result = jsonschema.Draft202012Validator(result_schema).validate
        jsonschema.Draft202012Validator(snapshot_schema).validate(json.loads(self.snapshot))
        validate_result(self.link())
        validate_result(self.attach('Code'))
        validate_result(self.check([{'family': 'Code', 'step_id': 'step_code',
                                    'artifact_bytes': self.artifact('Code')}]))
        denied = self.check([{'family': 'Code', 'step_id': 'step_code',
                             'artifact_bytes': self.artifact('Code', extra='other')}])
        self.assertEqual(denied['status'], 'BLOCKED_MIXED_CONTEXT')
        validate_result(denied)
        owner = self.cycles / (self.handoff + cc.OWNER_FILE)
        owner.write_bytes(b'corrupted\n')
        validate_result(self.check([{'family': 'Code', 'step_id': 'step_code',
                                    'artifact_bytes': self.artifact('Code')}]))

    def test_valid_real_persisted_run_and_handoff_link(self):
        r = self.link()
        self.assertEqual(r['status'], 'LINKED_LOCAL_ONLY')
        self.assertEqual(r['stage_run_id'], self.stage_run)
        self.assertNotEqual(r['run_id'], self.stage_run)
        self.assertFalse(r['source_authenticated'])
        self.assertFalse(r['permission_granted'])
        self.assertEqual((self.repo / 'business.txt').read_bytes(), self.repo_before)
        name = self.cycles / (self.handoff + cc.OWNER_FILE)
        self.assertEqual(name.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.link()['reason_code'], 'CROSS_LINK_REPLAY')

    def test_all_six_real_local_bindings_and_recheck(self):
        self.link()
        candidates = []
        for family in FAMILIES:
            raw = self.artifact(family)
            result = self.attach(family, raw)
            self.assertEqual(result['status'], 'ATTACHED_LOCAL_ONLY')
            self.assertEqual(result['artifacts'][0]['identity_fields_checked'], 4)
            candidates.append({'family': family, 'step_id': 'step_' + family.lower(),
                               'artifact_bytes': raw})
        result = self.check(candidates)
        self.assertEqual(result['status'], 'CONSISTENT_LOCAL_ONLY')
        self.assertTrue(result['all_six_present'])
        self.assertEqual(len(result['artifacts']), 6)
        self.assertTrue(result['local_identity_consistent'])
        self.assertFalse(result['business_steps_executed_proven'])
        self.assertFalse(result['producer_authenticated'])
        self.assertEqual((self.repo / 'business.txt').read_bytes(), self.repo_before)

    def test_per_family_partial_allowed_but_not_global_completion(self):
        self.link()
        self.attach('Code')
        r = self.check([{'family': 'Code', 'step_id': 'step_code',
                         'artifact_bytes': self.artifact('Code')}])
        self.assertEqual(r['families'], ['Code'])
        self.assertFalse(r['all_six_present'])
        self.assertFalse(r['business_steps_executed_proven'])
        self.assertEqual(self.attach('Code')['reason_code'], 'CROSS_ARTIFACT_REPLAY')

    def test_no_link_no_artifact_admission(self):
        self.err('CROSS_BINDING_NOT_FOUND', lambda: self.attach('Code'))
        self.assertEqual(self.check([{'family': 'Code', 'step_id': 'step_code',
                'artifact_bytes': self.artifact('Code')}])['status'], 'UNKNOWN_BLOCKED')

    def test_bad_fresh_bytes_and_source_never_create_owner(self):
        self.err('CROSS_FRESH_INPUT_NOT_SAME_RUN', lambda: self.link(snapshot_bytes=b'not same'))
        self.err('CROSS_FRESH_INPUT_NOT_SAME_RUN', lambda: self.link(source_ref='host:wrong'))
        self.assertFalse((self.cycles / (self.handoff + cc.OWNER_FILE)).exists())

    def test_exact_original_snapshot_anchor_rejects_other_staged_run(self):
        self.err('CROSS_FRESH_INPUT_NOT_SAME_RUN', lambda: self.link(
            snapshot_bytes=md.canonical({
                'schema': cc.CONTEXT_SNAPSHOT_SCHEMA, 'stage_run_id': 'run_v1_' + 'e' * 48,
                'handoff_id': self.handoff,
                'source_context_sha256': self.staged['source_context_sha256'],
                'source_identity_sha256': self.staged['source_identity_sha256']})))

    def test_unknown_handoff_is_not_fabricated_from_syntax(self):
        fake = 'handoff_v1_' + 'f' * 48
        self.err('CROSS_HANDOFF_NOT_UNIQUELY_STAGED', lambda: self.link(handoff=fake))
        self.assertFalse((self.cycles / (fake + cc.OWNER_FILE)).exists())

    def test_same_handoff_cannot_be_owned_by_another_cycle_run(self):
        self.link()
        different = self._cycle()['run_id']
        self.err('CROSS_IMMUTABLE_OWNER_OR_ARTIFACT_CONFLICT',
                 lambda: self.link(run=different))
        self.assertEqual(self.check([{'family': 'Code', 'step_id': 'step_code',
                'artifact_bytes': self.artifact('Code')}])['status'], 'BLOCKED_MIXED_CONTEXT')

    def test_same_artifact_bytes_cannot_be_inserted_in_other_cycle(self):
        self.link()
        # This producer has NO IDs in it: global exact-bytes ownership matters.
        raw = md.canonical({'schema': FAMILIES['Code'], 'status': 'partial',
                            'reason_code': 'NO_EMBEDDED_IDENTITY', 'result': 'shared'})
        self.attach('Code', raw)
        second = lc.Lifecycle.create(context(), 'second-run-0001')
        state = second.snapshot()
        for target, key in [('READY', 'second-ready-0001'), ('ACTIVE', 'second-active-0001')]:
            state = second.advance_run(target, expected_revision=state['revision'],
                context_sha256=state['source']['context_sha256'], operation_key=key)
        state = second.create_handoff(expected_revision=state['revision'],
             context_sha256=state['source']['context_sha256'], operation_key='second-handoff-0001')
        other_handoff = state['handoffs'][0]['handoff_id']
        other_stage = self.stager.stage_live(second, expected_parent_pin=self.pin,
             expected_revision=state['revision'], context_sha256=state['source']['context_sha256'],
             operation_key='second-run-0001', authorize_stage=True)
        other_snapshot = md.canonical({
            'schema': cc.CONTEXT_SNAPSHOT_SCHEMA, 'stage_run_id': other_stage['run_id'],
            'handoff_id': other_handoff,
            'source_context_sha256': other_stage['source_context_sha256'],
            'source_identity_sha256': other_stage['source_identity_sha256']})
        foreign = self.store.create(snapshot_bytes=other_snapshot, source_ref=self.source_ref,
            actor_origin='human', actor_subject='operator', actions=self.actions)['run_id']
        self.ledger.link(foreign, other_handoff, snapshot_bytes=other_snapshot,
            source_ref=self.source_ref, expected_stage_parent_pin=self.pin)
        self.err('CROSS_IMMUTABLE_OWNER_OR_ARTIFACT_CONFLICT',
                 lambda: self.ledger.attach(foreign, other_handoff,
                      expected_stage_parent_pin=self.pin, family='Code',
                      step_id='step_code', artifact_bytes=raw))

    def test_wrong_family_step_rejected_even_if_json_schema_matches(self):
        self.link()
        self.err('CROSS_STEP_ACTION_FAMILY_MISMATCH',
                 lambda: self.ledger.attach(self.run, self.handoff,
                    expected_stage_parent_pin=self.pin, family='Finding',
                    step_id='step_code', artifact_bytes=self.artifact('Finding')))
        self.err('CROSS_PRODUCER_SCHEMA_FAMILY_MISMATCH',
                 lambda: self.attach('Finding', self.artifact('Code')))

    def test_foreign_handoff_and_run_ids_inside_actual_bytes_rejected(self):
        self.link()
        for change, code in [({'metadata': {'handoff_id': 'handoff_v1_' + 'c' * 48}},
                              'CROSS_FOREIGN_HANDOFF_REF'),
                             ({'metadata': {'run_id': 'run_v1_' + 'd' * 48}},
                              'CROSS_FOREIGN_RUN_REF'),
                             ({'cycle_run_id': 'run_v1_' + 'd' * 48},
                              'CROSS_FOREIGN_CYCLE_RUN'),
                             ({'stage_run_id': self.run}, 'CROSS_FOREIGN_STAGE_RUN'),
                             ({'source_context_sha256': 'f' * 64},
                              'CROSS_FOREIGN_SOURCE_CONTEXT'),
                             ({'source_identity_sha256': '0' * 64},
                              'CROSS_FOREIGN_SOURCE_IDENTITY')]:
            with self.subTest(code=code):
                self.err(code, lambda ch=change: self.attach('Finding', self.artifact('Finding', **ch)))
        self.assertEqual(list(self.cycles.glob('artifact_*')), [])

    def test_known_keys_nested_list_mismatch_and_ci_numeric_run_id(self):
        self.link()
        raw = self.artifact('Quality', detail=[{'ci': {'run_id': 123}},
                                               {'nested': {'handoff_ids': [self.handoff]}}])
        self.assertEqual(self.attach('Quality', raw)['artifacts'][0]['identity_fields_checked'], 5)
        bad = self.artifact('Quality', detail=[{'handoff_ids': [self.handoff, 'handoff_v1_'+'a'*48]}])
        self.err('CROSS_FOREIGN_HANDOFF_REF', lambda: self.attach('Quality', bad))

    def test_invalid_producer_json_duplicate_keys_bom_null_identity(self):
        self.link()
        self.err('CROSS_PRODUCER_JSON_INVALID', lambda: self.attach('Code',
             b'{"schema":"ces.code_prepare_multisource.v1","Schema":42,"status":"partial","reason_code":"x","other":1}'))
        self.err('CROSS_PRODUCER_JSON_INVALID', lambda: self.attach('Code',
             b'\xef\xbb\xbf'+self.artifact('Code')))
        self.err('CROSS_PRODUCER_ENVELOPE_REQUIRED', lambda: self.attach('Code',
             md.canonical({'schema': FAMILIES['Code']})))
        self.err('CROSS_PRODUCER_SCHEMA_FAMILY_MISMATCH', lambda: self.attach('Code',
             self.artifact('Code', schema='ces.unrecognized.v1')))

    def test_modified_artifact_bytes_not_replayed_as_original(self):
        self.link()
        original = self.artifact('Report')
        self.attach('Report', original)
        changed = self.artifact('Report', extra='changed-bytes')
        r = self.check([{'family': 'Report', 'step_id': 'step_report', 'artifact_bytes': changed}])
        self.assertEqual(r['status'], 'BLOCKED_MIXED_CONTEXT')
        self.assertEqual(r['reason_code'], 'CROSS_ARTIFACT_NOT_REGISTERED')
        self.assertEqual(r['artifacts'], [])
        self.assertIsNone(r['cycle_record_sha256'])

    def test_corrupt_local_owner_returns_unknown_without_stale_data(self):
        self.link()
        self.attach('Finding')
        name = self.cycles / (self.handoff + cc.OWNER_FILE)
        obj = json.loads(name.read_bytes())
        obj['source_ref'] = 'host:other'
        name.write_bytes(md.canonical(obj) + b'\n')
        r = self.check([{'family': 'Finding', 'step_id': 'step_finding',
                         'artifact_bytes': self.artifact('Finding')}])
        self.assertEqual(r['status'], 'UNKNOWN_BLOCKED')
        self.assertEqual(r['artifacts'], [])
        self.assertFalse(r['local_identity_consistent'])

    def test_corrupt_or_symlinked_receipt_fails_closed(self):
        self.link()
        self.attach('Code')
        raw = self.artifact('Code')
        name = self.cycles / cc._artifact_name(hashlib.sha256(raw).hexdigest())
        backup = name.read_bytes()
        name.write_bytes(backup.replace(b'"business_result_proven":false',
                                        b'"business_result_proven":true'))
        self.assertEqual(self.check([{'family':'Code','step_id':'step_code',
                'artifact_bytes':raw}])['status'], 'UNKNOWN_BLOCKED')
        name.unlink()
        name.symlink_to(self.repo / 'business.txt')
        self.assertEqual(self.check([{'family':'Code','step_id':'step_code',
                'artifact_bytes':raw}])['status'], 'UNKNOWN_BLOCKED')

    def test_staged_handoff_expired_or_tampered_blocks_check(self):
        self.link()
        self.attach('Knowledge')
        raw = self.artifact('Knowledge')
        with patch.object(cc.st, '_check_expiry', side_effect=st.StageError('STAGING_EXPIRED_NO_REENTRY')):
            r = self.check([{'family': 'Knowledge', 'step_id': 'step_knowledge',
                            'artifact_bytes': raw}])
        self.assertEqual(r['status'], 'UNKNOWN_BLOCKED')
        staged_name = self.stage / (self.stage_run + '.stage.json')
        doc = json.loads(staged_name.read_bytes())
        doc['operation_key'] = 'wrong-operation-0001'
        staged_name.write_bytes(st._canonical(doc) + b'\n')
        r = self.check([{'family': 'Knowledge', 'step_id': 'step_knowledge',
                        'artifact_bytes': raw}])
        self.assertEqual(r['status'], 'UNKNOWN_BLOCKED')

    def test_check_batch_no_silent_partial_success_when_one_invalid(self):
        self.link()
        self.attach('Code')
        self.attach('Finding')
        batch = [{'family': 'Code', 'step_id': 'step_code', 'artifact_bytes': self.artifact('Code')},
                 {'family': 'Finding', 'step_id': 'step_finding',
                  'artifact_bytes': self.artifact('Finding', changed=True)}]
        r = self.check(batch)
        self.assertEqual(r['status'], 'BLOCKED_MIXED_CONTEXT')
        self.assertEqual(r['artifacts'], [])
        self.assertEqual(r['families'], [])

    def test_empty_and_duplicate_batch_not_success(self):
        self.link()
        self.assertEqual(self.check([])['status'], 'BLOCKED_MIXED_CONTEXT')
        self.attach('Code')
        entry = {'family': 'Code', 'step_id': 'step_code', 'artifact_bytes': self.artifact('Code')}
        self.assertEqual(self.check([entry, entry])['reason_code'], 'CROSS_DUPLICATE_ARTIFACT_IN_BATCH')

    def test_readonly_business_source_and_inherited_native_sources(self):
        self.link()
        self.attach('Delivery')
        self.assertEqual((self.repo / 'business.txt').read_bytes(), self.repo_before)
        self.assertEqual(list(self.repo.iterdir()), [self.repo / 'business.txt'])

    def test_cli_end_to_end_three_commands_no_business_success_exit_zero(self):
        file_snapshot = self.root / 'snapshot.bin'
        file_artifact = self.root / 'code.json'
        file_candidates = self.root / 'candidates.json'
        file_snapshot.write_bytes(self.snapshot)
        file_artifact.write_bytes(self.artifact('Code'))
        file_candidates.write_bytes(md.canonical([{'family':'Code','step_id':'step_code',
                                  'artifact_file':str(file_artifact)}]))
        base = [sys.executable, str(Path(cc.__file__)),
                '--cycle-store', str(self.cycles), '--stage-store', str(self.stage),
                '--business-repo', str(self.repo), '--run-id', self.run,
                '--handoff-id', self.handoff, '--stage-parent-pin', self.pin]
        def command(mode, *extra):
            args = [sys.executable, str(Path(cc.__file__)), mode] + base[2:] + list(extra)
            p = subprocess.run(args, capture_output=True, text=True, timeout=20)
            return p.returncode, json.loads(p.stdout)
        code, data = command('link', '--snapshot-file', str(file_snapshot), '--source-ref', self.source_ref)
        self.assertEqual((code, data['status']), (2, 'LINKED_LOCAL_ONLY'), data)
        code, data = command('attach', '--family','Code', '--step-id','step_code',
                             '--artifact-file', str(file_artifact))
        self.assertEqual((code, data['status']), (2, 'ATTACHED_LOCAL_ONLY'), data)
        code, data = command('check', '--candidates-json', str(file_candidates))
        self.assertEqual((code, data['status']), (2, 'CONSISTENT_LOCAL_ONLY'), data)
        # Known wrong original JSON bytes must produce exit 3, not generic 5.
        wrong = self.root / 'other-code.json'
        wrong.write_bytes(self.artifact('Code', extra='different-byte-hash'))
        file_candidates.write_bytes(md.canonical([{
            'family':'Code', 'step_id':'step_code', 'artifact_file':str(wrong)}]))
        code, data = command('check', '--candidates-json', str(file_candidates))
        self.assertEqual((code, data['status']), (3, 'BLOCKED_MIXED_CONTEXT'), data)
        self.assertEqual(data['artifacts'], [])
        # Unknown missing stage authentication is different from known misuse.
        file_candidates.write_bytes(md.canonical([{
            'family':'Code', 'step_id':'step_code', 'artifact_file':str(file_artifact)}]))
        (self.stage / (self.stage_run + '.stage.json')).unlink()
        code, data = command('check', '--candidates-json', str(file_candidates))
        self.assertEqual((code, data['status']), (5, 'UNKNOWN_BLOCKED'), data)
        self.assertEqual(data['artifacts'], [])


if __name__ == '__main__':
    unittest.main()
