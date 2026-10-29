#!/usr/bin/env python3
"""EC244: focused offline safety boundary and tamper-regression cases.

Tests use a private copy of pinned source text; they NEVER run CES business
handlers, Git publication, provider HTTP or enterprise authorization.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import security_permission_audit as security


class StaticReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix='ec244-source-review-')
        cls.root = Path(cls._tmp.name)
        cls.lock = security.generate_lock(security.ROOT)
        files = set(cls.lock['source_sha256']) | {security.LOCK}
        for relative in sorted(files):
            src = security.ROOT / relative
            dst = cls.root / relative
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _mutate(self, relative: str, needle: str, replacement: str):
        target = self.root / relative
        original = target.read_bytes()
        try:
            old = original.decode('utf-8')
            self.assertIn(needle, old)
            target.write_text(old.replace(needle, replacement, 1), encoding='utf-8')
            return security.audit(self.root)
        finally:
            target.write_bytes(original)

    def test_complete_and_source_pinned(self):
        r = security.audit(self.root)
        self.assertEqual(r['status'], 'PASS_STATIC_SOURCE_ONLY', r.get('violations'))
        self.assertEqual(r['route_count'], 74)
        self.assertEqual(r['native_route_count'], 16)
        self.assertEqual(r['new_route_count'], 58)
        self.assertEqual(r['host_denied_routes'], 11)
        self.assertEqual(r['route_kinds'], {'API': 7, 'CLI': 39, 'HOST_REQUIRED': 11,
                                            'LEGACY_NATIVE_ONLY': 16, 'PREVIEW': 1})
        self.assertEqual(r['source_pin_count'], r['source_pin_matched'])
        self.assertEqual(r['pass_static_gates'], r['gate_count'])
        self.assertGreaterEqual(r['source_pin_count'], 150)
        self.assertGreaterEqual(r['gate_count'], 35)
        self.assertTrue(r['router_does_not_govern_direct_entrypoints'])
        self.assertGreaterEqual(r['direct_python_entrypoint_count'], 100)
        for key in ('actor_authenticated', 'permission_granted',
                    'existing_issue_live_nonmutation_proven',
                    'business_repository_mutation_absence_proven',
                    'docs_publication_live_isolation_proven',
                    'real_network_and_native_runtime_tested'):
            self.assertIs(r[key], False, key)

    def test_74_endpoints_and_business_boundary_are_traced(self):
        r = security.audit(self.root)
        routes = r['routes']
        self.assertEqual(len(routes), 74)
        self.assertEqual(len({(x['action'].casefold(), str(x['mode']).casefold())
                              for x in routes}), len(routes))
        self.assertTrue(all(x['source_sha256'] and x['entry_chain'] and x['boundary']
                            for x in routes))
        self.assertTrue(all(x['source'] == 'scripts/ces.ps1'
                            for x in routes if x['kind'] == 'LEGACY_NATIVE_ONLY'))
        self.assertTrue(all(x['source'].startswith('construction/')
                            for x in routes if x['kind'] != 'LEGACY_NATIVE_ONLY'))
        self.assertTrue(all(x['entry_line'] and x['entry_line'] > 0
                            for x in routes if x['kind'] != 'LEGACY_NATIVE_ONLY'))
        self.assertIn('scripts/ces_router.py', routes[-1]['entry_chain'])
        self.assertEqual(len([x for x in routes if x['action'] == 'IssueCreate'
                              and x['mode'] == 'Create' and x['kind'] == 'HOST_REQUIRED']), 1)
        self.assertEqual(len([x for x in routes if x['action'] == 'DocsOnlyPublish'
                              and x['kind'] == 'HOST_REQUIRED']), 1)
        self.assertFalse(any(x['action'] == 'IssueCreate' and x['mode'] == 'EditExisting'
                             for x in routes))

    def test_source_gates_cover_all_security_domains(self):
        r = security.audit(self.root)
        checked = {x['id']: x['status'] for x in r['checks']}
        for key in ('ROUTER_HOST_DENIED_FIRST',
                    'ROUTER_LOCAL_WRITE_EXPLICIT', 'RESULT_NEVER_GRANTS_BUSINESS_AUTHORITY',
                    'LEGACY_NATIVE_CODE_SAVE_OPTIN', 'V5_POWERSHELL_PYTHON_BRIDGE',
                    'ISSUE_GET_ONLY_SELECTED', 'ISSUE_NEW_COLLECTION_ONLY',
                    'ISSUE_CREATE_ONCE_LEDGER_BEFORE_POST',
                    'ISSUE_NONMUTATING_MODULE_ISSUE_SHOW',
                    'DOCS_FOUR_SEPARATE_SIGNERS', 'DOCS_DISJOINT_ROOTS',
                    'DOCS_ONLY_ONE_PRIVATE_PUSH_SITE',
                    'QUALITY_RUN_HOST_POLICY', 'QUALITY_RUN_BROKER',
                    'KNOWLEDGE_SAVE_INDEPENDENT_APPROVAL',
                    'DELIVERY_INDEPENDENT_GRANT',
                    'REPORT_PUBLISH_INDEPENDENT_GRANT'):
            self.assertEqual(checked[key], 'PASS_STATIC', key)

    def test_hash_lock_detects_even_comment_change(self):
        out = self._mutate('construction/due_calendar.py', '#!/usr/bin/env python3',
                           '#!/usr/bin/env python3\n# local unaudited drift')
        self.assertEqual(out['status'], 'BLOCKED_STATIC_REVIEW')
        self.assertIn('SOURCE_HASH_DRIFT:construction/due_calendar.py', out['violations'])

    def test_modified_legacy_code_save_gate_is_blocked(self):
        out = self._mutate('scripts/ces.ps1',
                           "if ($Action -ieq 'CodeSave' -and -not $ApprovePersist.IsPresent)",
                           "if ($Action -ieq 'CodeSave' -and $ApprovePersist.IsPresent)")
        self.assertEqual(out['status'], 'BLOCKED_STATIC_REVIEW')
        self.assertIn('LEGACY_NATIVE_CODE_SAVE_OPTIN', out['violations'])
        self.assertIn('SOURCE_HASH_DRIFT:scripts/ces.ps1', out['violations'])

    def test_unapproved_host_route_promotion_is_blocked(self):
        out = self._mutate('construction/unified_action_router.py',
                           "H('DocsOnlyPublish', 'LocalSandbox'",
                           "C('DocsOnlyPublish', 'LocalSandbox'")
        self.assertEqual(out['status'], 'BLOCKED_STATIC_REVIEW')
        self.assertTrue(any('ROUTER_' in x or 'ROUTE_' in x for x in out['violations']))

    def test_changing_router_truth_flags_is_blocked(self):
        out = self._mutate('construction/unified_action_router.py',
                           "'permissions_granted_by_router': False",
                           "'permissions_granted_by_router': True")
        self.assertIn('RESULT_NEVER_GRANTS_BUSINESS_AUTHORITY', out['violations'])

    def test_new_existing_issue_http_write_method_is_blocked(self):
        target = self.root / 'construction/issue_show.py'
        previous = target.read_bytes()
        try:
            with target.open('a', encoding='utf-8') as out:
                out.write("\ndef _unsafe_existing_issue_edit(session, url):\n"
                          "    return session.patch(url, data={'state':'closed'})\n")
            r = security.audit(self.root)
            self.assertIn('ISSUE_NONMUTATING_MODULE_ISSUE_SHOW', r['violations'])
            self.assertIn('SOURCE_HASH_DRIFT:construction/issue_show.py', r['violations'])
        finally:
            target.write_bytes(previous)

    def test_docs_push_outside_reviewed_function_is_blocked(self):
        target = self.root / 'construction/docs_only_publish.py'
        previous = target.read_bytes()
        try:
            with target.open('a', encoding='utf-8') as out:
                out.write("\ndef _unsafe_push(obj):\n"
                          "    return obj.git.run(obj.repo, 'push', '--', 'origin', 'main')\n")
            r = security.audit(self.root)
            self.assertIn('DOCS_ONLY_ONE_PRIVATE_PUSH_SITE', r['violations'])
            self.assertIn('SOURCE_HASH_DRIFT:construction/docs_only_publish.py', r['violations'])
        finally:
            target.write_bytes(previous)

    def test_new_direct_script_is_review_required_not_silent(self):
        new_script = self.root / 'construction' / 'unreviewed_new_entrypoint.py'
        try:
            new_script.write_text("if __name__ == '__main__':\n    print('unsafe')\n",
                                  encoding='utf-8')
            r = security.audit(self.root)
            self.assertEqual(r['status'], 'BLOCKED_STATIC_REVIEW')
            self.assertIn('SOURCE_HASH_DRIFT:' + security.LOCK, r['violations'])
        finally:
            new_script.unlink(missing_ok=True)

    @unittest.skipUnless(os.name == 'posix', 'symlink guard requires POSIX source')
    def test_symlink_source_blocked(self):
        f = self.root / 'construction/due_calendar.py'
        original = f.read_bytes()
        backing = self.root / 'exfil_dummy.py'
        try:
            f.unlink()
            backing.write_bytes(original)
            f.symlink_to(backing)
            r = security.audit(self.root)
            self.assertEqual(r['status'], 'BLOCKED_STATIC_REVIEW')
            self.assertIn('SOURCE_SYMLINK_NOT_ADMITTED:construction/due_calendar.py',
                          r['violations'])
        finally:
            f.unlink(missing_ok=True)
            f.write_bytes(original)
            backing.unlink(missing_ok=True)

    def test_lock_duplicate_keys_rejected(self):
        path = self.root / security.LOCK
        original = path.read_bytes()
        try:
            text = original.decode('utf-8')
            path.write_text(text.replace('"schema":', '"schema": "fake", "schema":', 1),
                            encoding='utf-8')
            r = security.audit(self.root)
            self.assertEqual(r['status'], 'BLOCKED_STATIC_REVIEW')
            self.assertTrue(any('SOURCE_HASH_DRIFT:' + security.LOCK == s
                                for s in r['violations']))
        finally:
            path.write_bytes(original)

    def test_cli_summary_and_exact_route_query(self):
        cli = security.ROOT / 'construction/security_permission_audit.py'
        proc = subprocess.run([sys.executable, '-I', str(cli), '--route',
                               'IssueCreate:Create'], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=20, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode()[:500])
        output = json.loads(proc.stdout)
        self.assertEqual(output['status'], 'PASS_STATIC_SOURCE_ONLY')
        self.assertEqual(len(output['routes']), 1)
        self.assertEqual(output['routes'][0]['kind'], 'HOST_REQUIRED')
        self.assertFalse(output['permission_granted'])
        proc = subprocess.run([sys.executable, '-I', str(cli), '--summary'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=20, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode()[:500])
        summary = json.loads(proc.stdout)
        self.assertNotIn('routes', summary)
        self.assertEqual(summary['route_count'], 74)
        self.assertEqual(summary['gate_count'], summary['pass_static_gates'])

    def test_unprivileged_router_cannot_publish_or_edit_existing_issue(self):
        from unified_action_router import dispatch, REQUEST_SCHEMA
        for action, mode in [('DocsOnlyPublish', 'LocalSandbox'),
                             ('IssueCreate', 'Create'),
                             ('DeliverySend', 'Send')]:
            request = {'schema': REQUEST_SCHEMA, 'action': action, 'mode': mode}
            out, rc = dispatch(action, mode, request)
            self.assertEqual(rc, 3)
            self.assertEqual(out['reason_code'],
                             'ROUTER_INDEPENDENT_HOST_AUTHORITY_REQUIRED')
            self.assertFalse(out['handler_attempted'])
            self.assertFalse(out['permissions_granted_by_router'])
        out, rc = dispatch('IssueCreate', 'EditExisting', {
            'schema': REQUEST_SCHEMA, 'action': 'IssueCreate', 'mode': 'EditExisting'})
        self.assertEqual(rc, 3)
        self.assertEqual(out['reason_code'], 'ROUTER_ACTION_OR_MODE_UNREGISTERED')


if __name__ == '__main__':
    unittest.main(verbosity=2)
