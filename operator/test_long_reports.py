"""Long reports retain every byte, one thread, CC and uncertain-POST semantics."""
import unittest
from unittest.mock import patch
import ces_long_reports as long
import ces_reports as reports
import ces_workflow as w
from test_notification_cc import CCTests
from test_code_review import FunctionalDailyTests

class LongReportTests(CCTests):
    def body(self):return ('算法分析：输入、输出、候选筛选与复杂度。\n\n')*2500
    def test_multibyte_content_lossless_and_all_parts_one_thread(self):
        body=self.body();chunks=long.split_body(body)
        self.assertEqual(''.join(chunks),body);self.assertGreater(len(chunks),1)
        self.assertTrue(all(len(x.encode())<=40000 for x in chunks))
        result=self.client().publish('daily:2','snapshot','Detailed report',body,['developer'])
        self.assertEqual(len(self.server.issues),1);self.assertEqual(len(self.server.comments),len(chunks)-1)
        self.assertTrue(result['all_parts_readback_verified']);self.assertEqual(result['body_sha256'],w.sha(body))
        for chunk,(_,payload,_) in zip(chunks,self.server.writes):
            self.assertIn(chunk,payload['body']);self.assertIn('@lead',payload['body'])
            self.assertLess(len(payload['body'].encode()),60000)
        repeat=self.client().publish('daily:2','snapshot','Detailed report',body,['developer'])
        self.assertEqual(repeat['status'],'duplicate_skipped');self.assertEqual(len(self.server.writes),len(chunks))
    def test_interrupted_later_post_reconciles_and_finishes_without_duplicate(self):
        client=self.client();original=self.server.api;count=0
        def interrupted(token,path,payload=None,method=None):
            nonlocal count
            if method=='POST':
                count+=1
                result=original(token,path,payload,method)
                if count==2:raise RuntimeError('second POST response lost')
                return result
            return original(token,path,payload,method)
        with patch.object(w,'api',side_effect=interrupted):
            with self.assertRaisesRegex(RuntimeError,'response lost'):client.publish('daily:2','s','Title',self.body(),['developer'])
        before=len(self.server.writes)
        result=client.publish('daily:2','s','Title',self.body(),['developer'])
        self.assertEqual(len(self.server.issues),1)
        self.assertEqual(len(self.server.writes),result['part_count'])
        self.assertGreaterEqual(before,2)
    def test_total_limit_rejected_before_any_post_and_short_path_unchanged(self):
        with self.assertRaisesRegex(RuntimeError,'TOTAL_LIMIT'):self.client().publish('daily:2','s','T','x'*(long.MAX_REPORT_BYTES+1),['developer'])
        self.assertFalse(self.server.writes)
        result=self.client().publish('daily:2','s','T','Short body',['developer'])
        self.assertNotIn('multipart',result);self.assertEqual(len(self.server.writes),1)
    def test_no_newline_long_paragraph_and_empty_input_preserve_content(self):
        for body in ['', '中'*30000, 'line\n'*30000]:
            self.assertEqual(''.join(long.split_body(body)),body)

class ExtendedAnalysisTests(FunctionalDailyTests):
    def test_extended_sections_render_and_affect_snapshot_without_truncation(self):
        plan,draft=self.add_functional();first=self.reports()[0]['core']['id']
        record=w.load(self.run/'functional-review.json')
        import ces_code_review as review
        detail={key:('Detailed evidence, concrete example and engineering tradeoff.\n\n'*400) for key in review.DETAIL_FIELDS}
        record['draft']['features'][0]['details']=detail
        self.c['review']['report_detail']=dict(require_extended_analysis=True,target_chars=20000)
        from test_code_review import fake_git
        with patch.object(w,'git',fake_git),patch.object(review,'read_blob',return_value=b'int match() { return 1; }\n'):
            record['receipt']=review.validate(self.c,record['plan'],record['draft'])
        w.save(self.run/'functional-review.json',record)
        core=self.reports()[0]['core'];self.assertNotEqual(first,core['id'])
        for text in detail.values():self.assertIn(text,core['markdown'])
        self.assertGreater(len(core['markdown'].encode()),60000)
    def test_strict_detail_policy_rejects_missing_sections_and_bad_shapes(self):
        plan,draft=self.add_functional();import ces_code_review as review
        from test_code_review import fake_git
        self.c['review']['report_detail']=dict(require_extended_analysis=True)
        with patch.object(w,'git',fake_git),patch.object(review,'read_blob',return_value=b'int match() { return 1; }\n'):
            with self.assertRaisesRegex(RuntimeError,'EXTENDED_FUNCTIONAL'):review.validate(self.c,plan,draft)
            draft['features'][0]['details']={'imagined_field':'x'*30}
            with self.assertRaisesRegex(RuntimeError,'DETAILS_INVALID'):review.validate(self.c,plan,draft)

if __name__=='__main__':unittest.main()
