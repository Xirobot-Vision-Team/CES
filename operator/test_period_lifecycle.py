"""Continuation checks for a source-bound summary; no real build, Git repo or network."""
import tempfile,unittest
from pathlib import Path
from datetime import datetime,timezone,timedelta
from unittest.mock import patch
import ces_lifecycle as l
import ces_product as product

class PeriodLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.c=dict(repository_path=self.tmp.name,state_root=self.tmp.name,cache_root=self.tmp.name,
                    repository_sync=dict(branch="main"),execution_policy=dict(build_before_analysis=True,run_runtime_tests=False),
                    build_validation=dict(enabled=True,configuration="Release",platform="x64",steps=[dict(name="solution",kind="build",argv=["builder"],cwd="{repository}")]))
        log=Path(self.tmp.name)/"build.log";log.write_text("Build complete",encoding="utf-8")
        self.receipt=dict(status="ready",completed_at=datetime.now(timezone.utc).isoformat(),
                          build=dict(head="a"*40,source_stable=True,configuration="Release",platform="x64",runtime_tests_executed=False,application_launched=False,
                                     steps=[dict(name="solution",argv=["builder"],cwd=str(Path(self.tmp.name).resolve()),build_log=str(log),build_log_sha256=l.w.sha(log.read_bytes()))]))
        l.w.save(l.home(self.c)/"last-preflight.json",self.receipt)
    def resume(self):
        def git(c,*args,**kwargs):return "a"*40 if args[0]=="rev-parse" else "a"*40+"\trefs/heads/main"
        with patch.object(l,"run",side_effect=git),patch.object(l,"branch",return_value="main"),patch.object(l,"business_changes",return_value=""):
            return l.resume_preflight(self.c)
    def test_resume_reuses_exact_receipt(self):
        self.assertEqual(self.resume(),self.receipt)
    def test_expired_receipt_stops(self):
        self.receipt["completed_at"]=(datetime.now(timezone.utc)-timedelta(days=2)).isoformat();l.w.save(l.home(self.c)/"last-preflight.json",self.receipt)
        with self.assertRaisesRegex(RuntimeError,"EXPIRED"):self.resume()
    def test_changed_build_command_stops(self):
        self.c["build_validation"]["steps"][0]["argv"]=["different-builder"]
        with self.assertRaisesRegex(RuntimeError,"CONFIGURATION_CHANGED"):self.resume()
    def test_changed_log_stops(self):
        Path(self.receipt["build"]["steps"][0]["build_log"]).write_text("changed",encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError,"LOG_CHANGED"):self.resume()
    def test_remote_advance_stops(self):
        with patch.object(l,"run",side_effect=["a"*40,"b"*40+"\trefs/heads/main"]),patch.object(l,"branch",return_value="main"),patch.object(l,"business_changes",return_value=""):
            with self.assertRaisesRegex(RuntimeError,"REMOTE_ADVANCED"):l.resume_preflight(self.c)
    def test_build_failure_can_continue_as_failure(self):
        self.receipt["status"]="build_failed";self.receipt["build"]["status"]="failed";l.w.save(l.home(self.c)/"last-preflight.json",self.receipt)
        self.assertEqual(self.resume()["build"]["status"],"failed")
    def test_product_summary_completion_does_not_build_again(self):
        with patch.object(product.w,"config",return_value=self.c),patch.object(l,"resume_preflight") as resume,patch.object(l,"preflight") as start,patch.object(product.periods,"main"):
            product.main(["report","weekly","--config","profile","--analysis","synthesis.json","--execute"])
        resume.assert_called_once_with(self.c);start.assert_not_called()
    def test_product_summary_start_runs_actual_preflight(self):
        with patch.object(product.w,"config",return_value=self.c),patch.object(l,"resume_preflight") as resume,patch.object(l,"preflight") as start,patch.object(product.periods,"main"):
            product.main(["report","weekly","--config","profile"])
        start.assert_called_once_with(self.c);resume.assert_not_called()

if __name__=="__main__":unittest.main(verbosity=2)
