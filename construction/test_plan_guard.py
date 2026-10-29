"""Development-only deterministic static checks; no native CES runtime executed."""
import unittest
import copy
from pathlib import Path
import plan_guard

ROOT=Path(__file__).resolve().parent.parent

class ConstructionPlanGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan=plan_guard.jread(ROOT/'construction/LEGACY_PLAN.json')
        cls.progress=plan_guard.jread(ROOT/'construction/LEGACY_PROJECT_STATE.json')
        cls.active=plan_guard.jread(ROOT/'BUILD_STATE.json')

    def test_actual_plan_is_consistent(self):
        self.assertEqual([],plan_guard.check_plan(self.plan,self.progress,self.active))
        self.assertEqual([],plan_guard.check_history(ROOT))
        self.assertEqual([],plan_guard.check_structure(ROOT))

    def test_round_gap_is_rejected(self):
        p=copy.deepcopy(self.plan)
        p['rounds'][15]['round']=200
        self.assertTrue(any('bad round sequence' in e for e in plan_guard.check_plan(p,self.progress,self.active)))

    def test_missing_dependencies_rejected(self):
        p=copy.deepcopy(self.plan)
        p['rounds'][1]['depends_on']=[]
        self.assertTrue(any('missing' in e for e in plan_guard.check_plan(p,self.progress,self.active)))

    def test_fabricated_completion_rejected(self):
        p=copy.deepcopy(self.plan)
        p['rounds'][1]['status']='IMPLEMENTED_PENDING_FINAL_ACCEPTANCE'
        self.assertTrue(any('future EC-152' in e for e in plan_guard.check_plan(p,self.progress,self.active)))

    def test_future_progress_is_supported(self):
        p=copy.deepcopy(self.plan)
        s=copy.deepcopy(self.progress)
        a=copy.deepcopy(self.active)
        p['rounds'][0]['status']='IMPLEMENTED_PENDING_FINAL_ACCEPTANCE'
        s['last_completed_ec']='EC-151'
        s['next_ec']='EC-152'
        s['completed_replan_rounds']=1
        a['build']='R151'
        a['version']='V4.61'
        a['completed_ec']='EC-151'
        a['next_ec']='EC-152'
        self.assertEqual([],plan_guard.check_plan(p,s,a))

if __name__=='__main__': unittest.main()
