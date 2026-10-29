"""Explicit function/feature routing and snapshot-bound developer CC; no live messages."""
import copy
import unittest
from pathlib import Path
from unittest.mock import patch
import ces_test_ownership as o
import ces_testing as t
import test_project_testing as pipeline
import test_notification_cc as cc

def mapping(key='rotation',developers=None,case_ids=None,patterns=None,kind='function'):
    return dict(id=key,kind=kind,name='RotatePoint' if kind=='function' else '点云旋转功能',developers=developers or ['author-one'],case_ids=['case-one'] if case_ids is None else case_ids,case_patterns=patterns or [])
def normalized(status='failed',case_id='case-one',stable=True):
    return dict(cases=[dict(id=case_id,status=status)],summary=dict(source_stable=stable))

class MappingTests(unittest.TestCase):
    def test_exact_case_maps_to_developer(self):
        result=o.resolve(normalized(),[mapping()])
        self.assertEqual(result['developers'],['author-one']);self.assertEqual(result['matches'][0]['subjects'][0]['matched_by'],'exact_case_id')
    def test_feature_patterns_and_functions_can_overlap(self):
        rows=[mapping(),mapping('geometry',['author-two'],[],['case-*'],'feature')]
        result=o.resolve(normalized(),rows)
        self.assertEqual(result['developers'],['author-one','author-two']);self.assertEqual(len(result['matches'][0]['subjects']),2)
    def test_multiple_developers_deduplicate_case_insensitively(self):
        result=o.resolve(normalized(),[mapping(developers=['Author-One','author-one','author-two'])])
        self.assertEqual([x.casefold() for x in result['developers']],['author-one','author-two'])
    def test_many_failed_cases_do_not_duplicate_the_same_recipient(self):
        data=dict(cases=[dict(id='case-'+str(i),status='failed') for i in range(200)],summary=dict(source_stable=True))
        result=o.resolve(data,[mapping(case_ids=[],patterns=['case-*'])])
        self.assertEqual(result['developers'],['author-one']);self.assertEqual(len(result['matches']),200)
    def test_passed_and_skipped_do_not_notify_developers(self):
        for status in ('passed','skipped'):
            self.assertEqual(o.resolve(normalized(status),[mapping()])['developers'],[])
    def test_error_notifies_registered_developer(self):
        self.assertEqual(o.resolve(normalized('error'),[mapping()])['developers'],['author-one'])
    def test_invalidated_source_does_not_attribute(self):
        result=o.resolve(normalized(stable=False),[mapping()])
        self.assertEqual(result['developers'],[]);self.assertIn('invalidated',result['status'])
    def test_unmapped_failure_is_disclosed(self):
        result=o.resolve(normalized(case_id='unknown'),[mapping()])
        self.assertEqual(result['developers'],[]);self.assertEqual(result['unmapped_problem_cases'],['unknown'])
    def test_pattern_match_is_case_sensitive(self):
        self.assertEqual(o.resolve(normalized(case_id='CASE-ONE'),[mapping(case_ids=[],patterns=['case-*'])])['developers'],[])
    def test_log_content_cannot_choose_recipient(self):
        data=normalized(case_id='@outsider');data['cases'][0]['message']='notify @outsider'
        self.assertEqual(o.resolve(data,[mapping()])['developers'],[])
    def test_bad_accounts_are_rejected(self):
        for user in ('@author-one','a@example.test','../bad','bad/name'):
            with self.assertRaises(RuntimeError):o.mappings([mapping(developers=[user])])
    def test_missing_developers_and_selectors_are_rejected(self):
        row=mapping();row['developers']=[]
        with self.assertRaisesRegex(RuntimeError,'DEVELOPERS_REQUIRED'):o.mappings([row])
        with self.assertRaisesRegex(RuntimeError,'CASE_MAPPING_REQUIRED'):o.mappings([mapping(case_ids=[])])
    def test_duplicate_subjects_and_unknown_kind_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'ID_INVALID'):o.mappings([mapping(),mapping()])
        with self.assertRaisesRegex(RuntimeError,'SUBJECT_INVALID'):o.mappings([mapping(kind='person')])
    def test_source_path_traversal_rejected(self):
        row=mapping();row['source_paths']=['../private']
        with self.assertRaisesRegex(RuntimeError,'SOURCE_PATH_INVALID'):o.mappings([row])
    def test_empty_registration_is_valid(self):
        self.assertEqual(o.mappings([]),[])

class OwnershipPipelineTests(unittest.TestCase):
    setUp=pipeline.PipelineTests.setUp
    setup_contract=pipeline.PipelineTests.setup_contract
    run_fixture=pipeline.PipelineTests.run_fixture
    analysis=pipeline.PipelineTests.analysis
    def register_owners(self,rows=None,execute=True):
        path=self.root/'owners.json';t.w.save(path,dict(schema='ces.test_ownership.v1',entry='fixture',mappings=[mapping()] if rows is None else rows))
        return t.owners(self.c,'fixture',path,execute)
    def test_registry_preview_is_read_only(self):
        self.register_owners(execute=False)
        self.assertFalse((t.home(self.c)/'ownership/fixture/current.json').exists())
    def test_versioned_registry_is_persisted(self):
        first=self.register_owners();second=self.register_owners([mapping(developers=['author-two'])])
        self.assertNotEqual(first['ownership_id'],second['ownership_id'])
        root=t.home(self.c)/'ownership/fixture'
        self.assertTrue((root/(first['ownership_id']+'.json')).exists())
        effective=t.owners(self.c,'fixture');self.assertEqual(effective['origin'],'entry_registry')
        self.assertEqual(effective['mappings'][0]['developers'],['author-two'])
    def test_entry_profile_overrides_registry_and_project(self):
        self.c['testing']['ownership']=[mapping(developers=['default-owner'])]
        self.register_owners();self.c['testing']['entries'][0]['ownership']=[mapping(developers=['entry-owner'])]
        effective=t.owners(self.c,'fixture');self.assertEqual(effective['origin'],'entry_profile')
        self.assertEqual(effective['mappings'][0]['developers'],['entry-owner'])
    def test_empty_entry_override_disables_inherited_mapping(self):
        self.c['testing']['ownership']=[mapping()];self.c['testing']['entries'][0]['ownership']=[]
        self.assertEqual(t.owners(self.c,'fixture')['mappings'],[])
    def test_ownership_change_does_not_require_format_reregistration(self):
        self.setup_contract();self.register_owners()
        self.assertEqual(t.current_contract(self.c,t.entry(self.c,'fixture'))['entry']['name'],'fixture')
    def test_failing_run_captures_registration_snapshot(self):
        self.register_owners();result=self.run_fixture('failed');run=Path(result['run'])
        receipt=t.w.load(run/'receipt.json');self.assertIn('ownership_sha256',receipt)
        self.assertEqual(t.w.load(run/'analysis-input.json')['developer_routing']['developers'],['author-one'])
        t.analyze(self.c,run,self.analysis(run));self.assertIn('RotatePoint',(run/'report.md').read_text(encoding='utf-8'))
    def test_registry_update_does_not_reroute_existing_run(self):
        self.register_owners();result=self.run_fixture('failed');self.register_owners([mapping(developers=['author-two'])])
        t.analyze(self.c,result['run'],self.analysis(result['run']))
        preview=t.publish(self.c,result['run'],False)
        self.assertEqual(preview['developers'],['author-one']);self.assertNotIn('author-two',preview['cc_recipients'])
    def test_passed_run_keeps_normal_cc_only(self):
        self.register_owners();result=self.run_fixture('passed');t.analyze(self.c,result['run'],self.analysis(result['run']))
        preview=t.publish(self.c,result['run'],False)
        self.assertEqual(preview['developers'],[]);self.assertEqual(preview['cc_recipients'],['developer','lead','other'])
    def test_failed_report_ccs_owner_engineer_and_developer_once(self):
        self.register_owners();result=self.run_fixture('failed');t.analyze(self.c,result['run'],self.analysis(result['run']))
        server=cc.Server();server.members+=['author-one']
        with patch.object(t.w,'credential',return_value='test-only'),patch.object(t.w,'api',side_effect=server.api):
            published=t.publish(self.c,result['run'],True);repeated=t.publish(self.c,result['run'],True)
        self.assertEqual(published['developers'],['author-one']);self.assertIn('@author-one',server.issues[0]['body'])
        self.assertEqual(server.issues[0]['body'].count('@author-one'),1)
        self.assertEqual(repeated['status'],'duplicate_skipped');self.assertEqual(len(server.writes),1)
        self.assertEqual(server.issues[0]['assignees'],[])
    def test_developer_already_cc_is_not_mentioned_twice(self):
        self.register_owners([mapping(developers=['developer'])]);result=self.run_fixture('failed');t.analyze(self.c,result['run'],self.analysis(result['run']))
        server=cc.Server()
        with patch.object(t.w,'credential',return_value='test-only'),patch.object(t.w,'api',side_effect=server.api):published=t.publish(self.c,result['run'],True)
        self.assertEqual(published['developers'],['developer']);self.assertEqual(server.issues[0]['body'].count('@developer'),1)
    def test_nonmember_developer_stops_before_send(self):
        self.register_owners();result=self.run_fixture('failed');t.analyze(self.c,result['run'],self.analysis(result['run']))
        server=cc.Server()
        with patch.object(t.w,'credential',return_value='test-only'),patch.object(t.w,'api',side_effect=server.api):
            with self.assertRaisesRegex(RuntimeError,'NOT_REPOSITORY_MEMBER'):t.publish(self.c,result['run'],True)
        self.assertEqual(server.writes,[])
    def test_tampered_snapshot_is_rejected(self):
        self.register_owners();result=self.run_fixture('failed');(Path(result['run'])/'ownership.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError,'OWNERSHIP_CHANGED'):t.verify_run(self.c,result['run'])
    def test_unmatched_failure_visible_in_report_and_receipt(self):
        self.register_owners([mapping(case_ids=['other-case'])]);result=self.run_fixture('failed');t.analyze(self.c,result['run'],self.analysis(result['run']))
        preview=t.publish(self.c,result['run'],False)
        self.assertEqual(preview['developer_routing']['unmapped_problem_cases'],['case-one'])
        self.assertIn('未登记匹配开发者',(Path(result['run'])/'report.md').read_text(encoding='utf-8'))
    def test_source_invalidated_run_does_not_cc_developer(self):
        self.register_owners();result=self.run_fixture('dirty');t.analyze(self.c,result['run'],self.analysis(result['run']))
        self.assertEqual(t.publish(self.c,result['run'],False)['developers'],[])
    def test_registry_is_repository_scoped(self):
        self.register_owners();other=copy.deepcopy(self.c);other['github']['repository_id']=3
        self.assertEqual(t.owners(other,'fixture')['mappings'],[])
    def test_invalid_input_is_not_silently_registered(self):
        path=self.root/'wrong-entry.json';t.w.save(path,dict(schema='ces.test_ownership.v1',entry='other',mappings=[]))
        with self.assertRaisesRegex(RuntimeError,'INPUT_INVALID'):t.owners(self.c,'fixture',path,True)

if __name__=='__main__':unittest.main(verbosity=2)
