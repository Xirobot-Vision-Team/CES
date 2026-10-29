#!/usr/bin/env python3
"""EC278 focused tests: actual EC243 routing and strict native delegation shape.

These tests do NOT execute PowerShell 7, business writes, provider calls, or
enterprise host-authorized routes; the original acceptance suite remains due.
"""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ENTRY = Path(__file__).resolve().parents[2] / 'scripts' / 'ces_next.py'
sys.path.insert(0, str(ENTRY.parent))
import ces_next as console  # noqa: E402


class OperatorConsoleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ec278-console-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def call(self, *argv):
        p = subprocess.run([sys.executable, '-I', '-B', str(ENTRY), *argv],
                           stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=30, check=False)
        self.assertEqual(p.stderr, '', p.stderr)
        obj = json.loads(p.stdout)
        self.assertIn(obj['schema'], (console.SCHEMA, 'ces.unified_action_router.v2'))
        return p.returncode, obj

    def write_request(self, action, mode, **extras):
        p = self.root / 'request.json'
        p.write_text(json.dumps({'schema': console.REQUEST_SCHEMA,
                                  'action':action,'mode':mode,**extras}),encoding='utf8')
        return p

    def test_01_routes_show_frozen_74_original_routes_no_privileged_upgrade(self):
        rc, doc = self.call('routes')
        self.assertEqual(rc,0)
        self.assertEqual(doc['route_count'],74)
        host=[r for r in doc['routes'] if r['route_kind']=='HOST_REQUIRED']
        self.assertEqual(len(host),11)
        self.assertTrue(all(r['requires_independent_host'] and
                            r['entry_mode']=='blocked_by_router' for r in host))
        self.assertTrue(doc['host_restrictions_not_bypassed'])
        self.assertFalse(doc['business_effect_verified'])

    def test_02_explain_and_template_prevent_implicit_authority(self):
        rc, info=self.call('describe','Due','Evaluate')
        self.assertEqual(rc,0)
        self.assertEqual(info['fixed_handler'],'due_calendar:DueCalendar.evaluate')
        self.assertFalse(info['requires_independent_host'])
        self.assertNotIn('acknowledge_private_ces_write',info['request_template'])
        rc, tpl = subprocess_template('Due','Evaluate')
        self.assertEqual(rc,0)
        self.assertEqual(tpl['parameters'],{})
        self.assertEqual(tpl['schema'],console.REQUEST_SCHEMA)

    def test_03_due_evaluate_routes_through_actual_ec241_ec243_not_success(self):
        p=self.write_request('Due','Evaluate',parameters={
            'project_timezone':'UTC','cadence':'day',
            'observed_at':'2026-10-24T12:00:00Z','never_processed':True})
        rc,doc=self.call('run','Due','Evaluate','--request-file',str(p))
        self.assertEqual(rc,2)
        self.assertTrue(doc['handler_invoked'])
        self.assertEqual(doc['handler_result']['decision']['state'],'DUE')
        self.assertFalse(doc['permissions_granted_by_router'])
        self.assertFalse(doc['business_effect_verified'])

    def test_04_local_write_still_needs_explicit_private_write_opt_in(self):
        p=self.write_request('Cycle','Create',argv=[])
        rc,doc=self.call('run','Cycle','Create','--request-file',str(p))
        self.assertEqual(rc,3)
        self.assertEqual(doc['reason_code'],'ROUTER_PRIVATE_WRITE_EXPLICIT_OPT_IN_REQUIRED')
        self.assertFalse(doc['handler_invoked'])

    def test_05_untrusted_host_cannot_be_called_via_new_console(self):
        p=self.write_request('IssueCreate','Create')
        # New CLI intentionally stops ahead of existing router, regardless of
        # arbitrary caller-supplied fake credential fields in request JSON.
        rc,doc=self.call('run','IssueCreate','Create','--request-file',str(p))
        self.assertEqual(rc,3)
        self.assertEqual(doc['reason_code'],'EC278_INDEPENDENT_HOST_BRIDGE_REQUIRED')
        self.assertFalse(doc['handler_invoked'])
        rc,doc=self.call('template','IssueCreate','Create')
        self.assertEqual(rc,3)
        self.assertEqual(doc['reason_code'],
                         'EC278_TEMPLATE_UNAVAILABLE_FOR_PRIVILEGED_OR_LEGACY_ROUTE')

    def test_06_legacy_and_modern_namespace_do_not_cross(self):
        p=self.write_request('CodeShow','List')
        rc,doc=self.call('run','CodeShow','List','--request-file',str(p))
        self.assertEqual(rc,3)
        self.assertEqual(doc['reason_code'],'EC278_NATIVE_ROUTE_USE_LEGACY_ENTRY')
        rc,doc=self.call('legacy','--','-Action','QualityRun','-Mode','Execute')
        self.assertEqual(rc,3)
        self.assertEqual(doc['reason_code'],'EC278_LEGACY_ACTION_NOT_OWNED_BY_ORIGINAL_CLI')

    def test_07_native_missing_runtime_is_truthful(self):
        with mock.patch.object(console.shutil,'which',return_value=None):
            with self.assertRaises(console.ConsoleError) as cm:
                console.legacy(['-Action','Inspect','-Json'])
        self.assertEqual(cm.exception.code,'EC278_POWERSHELL7_NOT_INSTALLED')
        rc,doc=self.call('doctor')
        self.assertEqual(rc,0)
        self.assertFalse(doc['native_smoke_15_executed'])
        self.assertFalse(doc['final_acceptance_proven'])

    def test_08_legacy_original_cli_receives_exact_arguments_without_shell(self):
        arguments=['-Action','CodeSave','-Mode','Snapshot','-RepoPath',str(self.root)]
        fake=subprocess.CompletedProcess(args=[],returncode=4)
        with mock.patch.object(console,'_inventory',return_value=console._inventory()), \
             mock.patch.object(console.shutil,'which',return_value='/fake/pwsh'), \
             mock.patch.object(console.subprocess,'run',return_value=fake) as call:
            rc=console.legacy(arguments)
        self.assertEqual(rc,4)
        cmd=call.call_args.args[0]
        self.assertEqual(cmd[:5],['/fake/pwsh','-NoLogo','-NoProfile','-NonInteractive','-File'])
        self.assertEqual(cmd[5],str(console.LEGACY))
        self.assertEqual(cmd[6:],arguments)
        self.assertNotIn('-ApprovePersist',cmd)
        self.assertFalse(call.call_args.kwargs['check'])
        self.assertNotIn('shell',call.call_args.kwargs)

    def test_09_forged_or_invalid_router_response_is_never_relayed(self):
        fake={'schema':'ces.unified_action_router.v2','action':'Due','mode':'Evaluate',
              'route_kind':'API','normalized_exit_code':0,
              'permissions_granted_by_router':False,'business_effect_verified':False}
        with mock.patch.object(console,'_router',side_effect=[(0,console._inventory()),(2,fake)]):
            with self.assertRaises(console.ConsoleError) as cm:
                console.run('Due','Evaluate','/tmp/unknown')
        self.assertEqual(cm.exception.code,'EC278_UNEXPECTED_ROUTER_RESULT_OR_EXIT')

    def test_10_invalid_request_schema_remains_router_rejection(self):
        p=self.write_request('Due','Evaluate',parameters={})
        p.write_text('{"schema":"wrong","action":"Due","mode":"Evaluate"}',encoding='utf8')
        rc,doc=self.call('run','Due','Evaluate','--request-file',str(p))
        self.assertEqual(rc,4)
        self.assertEqual(doc['reason_code'],'ROUTER_REQUEST_SCHEMA_INVALID')
        self.assertFalse(doc['handler_invoked'])

    def test_11_legacy_selector_duplicate_and_abbreviated_forms_denied(self):
        for argv in (["-Action","Inspect","-Action","CodeSave"],
                     ["-Action","Inspect","-Action:CodeSave"],
                     ["-Action","QualityRun"]):
            with self.subTest(argv=argv),self.assertRaises(console.ConsoleError):
                console.legacy(argv)

    def test_12_pythonpath_poison_does_not_replace_fixed_router(self):
        poison=self.root/'unified_action_router.py'
        poison.write_text('raise AssertionError("PYTHONPATH injected")')
        p=self.write_request('Due','Evaluate',parameters={
            'project_timezone':'UTC','cadence':'day',
            'observed_at':'2026-10-24T12:00:00Z','never_processed':True})
        with mock.patch.dict('os.environ',{'PYTHONPATH':str(self.root)}):
            rc,doc=self.call('run','Due','Evaluate','--request-file',str(p))
        self.assertEqual(rc,2)
        self.assertEqual(doc['handler_result']['decision']['state'],'DUE')


def subprocess_template(action,mode):
    p=subprocess.run([sys.executable,'-I','-B',str(ENTRY),
                      'template',action,mode],capture_output=True,text=True,timeout=15)
    return p.returncode, json.loads(p.stdout)


if __name__=='__main__':
    unittest.main(verbosity=2)
