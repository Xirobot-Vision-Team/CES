#!/usr/bin/env python3
"""EC164 strictly synthetic, offline patch-disclosure focused tests."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch as mock_patch

import proposed_pr_patch as patch
import proposed_pr_paths as paths
import proposed_pr_source as source
import test_proposed_pr_paths as earlier

HERE = Path(__file__).resolve().parent


def rows(provider: str) -> list[dict]:
    return json.loads((HERE / 'fixtures' / 'ec164' /
                       f'{provider}.synthetic.patches.json').read_text('utf-8'))


def run(provider='github', *, paths_selected=('src/service.py',), file_rows=None,
        count=None, after=None, before=None, pin=None, include=True, acknowledge=True,
        allow_network=True, max_patch=4096, max_total=8192, pages=None,
        per_page=100, max_pages=30, token_supplier=None):
    if provider == 'gitlab' and paths_selected == ('src/service.py',):
        paths_selected = ('lib/new.py',)
    if count is None:
        count = 3 if provider == 'github' else '2'
    meta_before = earlier.metadata(provider, count) if before is None else before
    meta_after = earlier.metadata(provider, count) if after is None else after
    tx = earlier.Transport([meta_before, meta_after], pages if pages is not None else
                           [earlier.page(file_rows if file_rows is not None else rows(provider),
                                         provider=provider)])
    key = source.RequestKey(provider,
        'example/repo' if provider == 'github' else 'my-group/sub-group/repo', 8)
    p = pin if pin is not None else earlier.prior(provider, count)
    out = patch.collect_proposed_pr_patch(
        key, expected_pin=p, allow_network=allow_network,
        include_patch_content=include, acknowledge_provider_permission=acknowledge,
        policy=patch.ContentPolicy(tuple(paths_selected), max_patch, max_total) if include else None,
        transport=tx, token_supplier=token_supplier or (lambda: 'SYNTHETIC-NOT-REAL'),
        per_page=per_page, max_pages=max_pages,
    )
    return out, tx


class Ec164Tests(unittest.TestCase):
    def test_default_is_metadata_only_and_does_not_inspect_patch(self):
        out, tx = run(include=False)
        self.assertFalse(out['patch_content_collected'])
        self.assertFalse(out['patch_content_requested'])
        self.assertEqual(out['patches'], [])
        self.assertEqual(out['path_evidence']['coverage']['state'], 'COMPLETE')
        self.assertNotIn('old = 1', json.dumps(out))
        self.assertEqual(tx.calls, ['META', 'PAGE:1', 'META'])

    def test_no_network_by_default_stops_before_credential(self):
        out, tx = run(include=False, allow_network=False,
                      token_supplier=lambda: self.fail('token used'))
        self.assertEqual(out['reason_code'], 'NETWORK_NOT_AUTHORIZED')
        self.assertEqual(tx.calls, [])

    def test_missing_explicit_permission_ack_refuses_before_requests(self):
        out, tx = run(acknowledge=False, token_supplier=lambda: self.fail('token used'))
        self.assertEqual((out['status'], out['reason_code']),
                         ('invalid_input', 'PATCH_PERMISSION_ACK_REQUIRED'))
        self.assertEqual(tx.calls, [])

    def test_explicit_content_requires_network_too(self):
        out, tx = run(allow_network=False, token_supplier=lambda: self.fail('token used'))
        self.assertEqual((out['status'], out['reason_code']), ('unavailable', 'NETWORK_NOT_AUTHORIZED'))
        self.assertEqual(tx.calls, [])

    def test_requires_exact_selection_and_rejects_bad_counts(self):
        for selection in ((), tuple(f'src/{i}.py' for i in range(6)),
                          ('src/a.py', 'SRC/A.PY')):
            with self.subTest(selection=selection):
                out, tx = run(paths_selected=selection,
                              token_supplier=lambda: self.fail('token used'))
                self.assertEqual(out['status'], 'invalid_input')
                self.assertEqual(tx.calls, [])

    def test_rejects_unsafe_patterns_and_wildcard_paths(self):
        for bad in ('../repo', '/var/secret', 'src/../x', 'src/*.py', '.env',
                    'secrets/new.py', '.ssh/config', 'auth.key'):
            with self.subTest(path=bad):
                out, tx = run(paths_selected=(bad,),
                              token_supplier=lambda: self.fail('token used'))
                self.assertEqual(out['status'], 'invalid_input')
                self.assertEqual(tx.calls, [])

    def test_budget_gates_precede_token_and_network(self):
        for one, total in ((0, 8192), (8193, 8192), (4096, 32769),
                           (True, 20), (4096, -1)):
            with self.subTest(budget=(one,total)):
                out, tx = run(max_patch=one, max_total=total,
                              token_supplier=lambda: self.fail('token used'))
                self.assertEqual((out['status'], out['reason_code']),
                                 ('invalid_input', 'PATCH_BUDGET_INVALID'))
                self.assertEqual(tx.calls, [])

    def test_github_explicit_selected_release_synthetic_partial(self):
        out, tx = run()
        self.assertEqual(out['reason_code'], 'SYNTHETIC_PATCH_CONTENT_ONLY')
        self.assertEqual(out['status'], 'partial')
        self.assertEqual(out['patches'][0]['availability'], 'AVAILABLE')
        self.assertIn('+new = 2', out['patches'][0]['patch_text'])
        self.assertTrue(out['patch_content_collected'])
        self.assertFalse(out['diff_snapshot_proven'])
        self.assertFalse(out['write_authorized'])
        self.assertFalse(out['content_policy']['provider_permission_independently_verified'])
        self.assertEqual(tx.calls, ['META', 'PAGE:1', 'META'])

    def test_mocked_live_shaped_status_branch_is_not_real_provider_proof(self):
        # Offline mock of the network branch; no GitHub.com request occurs.
        prior = earlier.prior('github', 3)
        prior['synthetic'] = False
        # Live-shaped responses must not carry the synthetic fixture marker.
        first_meta = earlier.metadata('github', 3)
        last_meta = earlier.metadata('github', 3)
        first_meta.pop('_ces_fixture', None)
        last_meta.pop('_ces_fixture', None)
        tx = earlier.Transport([first_meta, last_meta],
                               [earlier.page(rows('github'))])
        key = source.RequestKey('github', 'example/repo', 8)
        with (mock_patch.object(paths, 'StrictPathsTransport', return_value=tx),
              mock_patch.object(source, 'StrictHttpsTransport', return_value=tx)):
            out = patch.collect_proposed_pr_patch(
                key, expected_pin=prior, allow_network=True,
                include_patch_content=True, acknowledge_provider_permission=True,
                policy=patch.ContentPolicy(('src/service.py',)),
                token_supplier=lambda: 'MOCK-TOKEN-NO-NETWORK',
            )
        self.assertEqual((out['status'], out['reason_code']),
                         ('success', 'BOUNDED_PATCH_CONTENT_RELEASED'))
        self.assertFalse(out['synthetic'])  # mocked live-shaped branch ONLY
        self.assertFalse(out['content_policy']['provider_permission_independently_verified'])
        self.assertFalse(out['diff_snapshot_proven'])
        self.assertEqual(tx.calls, ['META', 'PAGE:1', 'META'])

    def test_gitlab_explicit_release(self):
        out, tx = run('gitlab')
        self.assertEqual(out['status'], 'partial')
        self.assertEqual(out['patches'][0]['availability'], 'AVAILABLE')
        self.assertIn('+c', out['patches'][0]['patch_text'])
        self.assertEqual(tx.calls, ['META', 'PAGE:1', 'META'])

    def test_ordered_multiple_paths_without_cross_file_splicing(self):
        out, _ = run(paths_selected=('src/renamed.py', 'src/service.py'))
        self.assertEqual([x['path'] for x in out['patches']], ['src/renamed.py','src/service.py'])
        self.assertIn('after', out['patches'][0]['patch_text'])
        self.assertNotIn('after', out['patches'][1]['patch_text'])

    def test_missing_patch_is_indeterminate_not_faked_binary(self):
        out, _ = run(paths_selected=('docs/start.md',))
        self.assertEqual(out['patches'][0]['availability'], 'MISSING_OR_BINARY_UNKNOWN')
        self.assertIsNone(out['patches'][0]['patch_text'])
        self.assertFalse(out['patch_content_collected'])

    def test_collapse_too_large_binary_are_distinct(self):
        for mark, expected in ((('collapsed', True), 'PROVIDER_COLLAPSED'),
                               (('too_large', True), 'PROVIDER_TOO_LARGE')):
            with self.subTest(mark=mark):
                content = rows('gitlab')
                content[0][mark[0]] = mark[1]
                out, _ = run('gitlab', file_rows=content)
                self.assertEqual(out['patches'][0]['availability'], expected)
                self.assertIsNone(out['patches'][0]['patch_text'])
        out, _ = run('gitlab', paths_selected=('images/logo.png',))
        self.assertEqual(out['patches'][0]['availability'], 'BINARY_OR_BINARY_SUSPECTED')

    def test_binary_content_marker_detected(self):
        content = rows('github')
        content[0]['patch'] = 'GIT binary patch\nliteral 3\nabc\n'
        out, _ = run(file_rows=content)
        self.assertEqual(out['patches'][0]['availability'], 'BINARY')

    def test_empty_string_is_not_missing(self):
        content = rows('github')
        content[0]['patch'] = ''
        out, _ = run(file_rows=content)
        self.assertEqual(out['patches'][0]['availability'], 'EMPTY')

    def test_per_file_over_budget_is_not_truncated_prefix(self):
        content = rows('github')
        content[0]['patch'] = '@@ -1 +1 @@\n-' + 'a'*512 + '\n+' + 'b'*512
        out, _ = run(file_rows=content, max_patch=100)
        self.assertEqual(out['patches'][0]['availability'], 'TOO_LARGE')
        self.assertIsNone(out['patches'][0]['patch_text'])
        self.assertNotIn('a'*128, json.dumps(out))

    def test_total_budget_does_not_release_later_file(self):
        out, _ = run(paths_selected=('src/service.py', 'src/renamed.py'), max_total=35)
        self.assertEqual([x['availability'] for x in out['patches']],
                         ['AVAILABLE', 'TOTAL_BUDGET_EXHAUSTED'])
        self.assertEqual(out['content_policy']['emitted_utf8_bytes'],
                         out['patches'][0]['utf8_bytes'])
        self.assertFalse('after' in json.dumps(out))

    def test_secret_literals_are_blocked_even_when_explicitly_requested(self):
        secret_cases = [
            '@@ -1 +1 @@\n-x\n+password = "hunter2"\n',
            '@@ -1 +1 @@\n-a\n+AKIAABCDEFGHIJKLMNOP\n',
            '@@ -1 +1 @@\n-a\n+ghp_abcdefghijklmno123\n',
            '@@ -1 +1 @@\n-a\n+-----BEGIN PRIVATE KEY-----\n',
        ]
        for content_text in secret_cases:
            with self.subTest(example=content_text[:15]):
                data = rows('github')
                data[0]['patch'] = content_text
                out, _ = run(file_rows=data)
                self.assertEqual(out['patches'][0]['availability'], 'SENSITIVE_CONTENT_BLOCKED')
                self.assertNotIn(content_text, json.dumps(out))

    def test_control_and_bidi_content_refused(self):
        for part in ('\x1b[31m', '\u202e', '\x00'):
            with self.subTest(content=repr(part)):
                data = rows('github')
                data[0]['patch'] = '@@ -1 +1 @@\n-a\n+' + part + 'b\n'
                out, _ = run(file_rows=data)
                self.assertEqual(out['patches'][0]['availability'], 'UNSAFE_TEXT_BLOCKED')

    def test_declared_hunk_incomplete_classifies_truncated(self):
        data = rows('github')
        data[0]['patch'] = '@@ -1,3 +1,3 @@\n a\n-b\n+c\n'
        out, _ = run(file_rows=data)
        self.assertEqual(out['patches'][0]['availability'], 'TRUNCATED')
        self.assertIsNone(out['patches'][0]['patch_text'])

    def test_unknown_diff_format_is_never_released(self):
        data = rows('github')
        data[0]['patch'] = 'A FILE\n+word\n'
        out, _ = run(file_rows=data)
        self.assertEqual(out['patches'][0]['availability'], 'UNVERIFIED_FORMAT')

    def test_invalid_provider_payload_or_path_suppresses_all_text(self):
        data = rows('github')
        data[1]['filename'] = '../escape'
        out, _ = run(file_rows=data)
        self.assertEqual(out['status'], 'unavailable')
        self.assertEqual(out['patches'], [])
        self.assertFalse(out['patch_content_collected'])
        self.assertNotIn('new = 2', json.dumps(out))

    def test_pin_drift_after_page_destroys_buffered_content(self):
        changed = earlier.metadata('github', 3)
        changed['head']['sha'] = 'd'*40
        out, tx = run(after=changed)
        self.assertEqual(out['reason_code'], 'PIN_DRIFT_HEAD_SHA_CHANGED')
        self.assertEqual(out['patches'], [])
        self.assertNotIn('old = 1', json.dumps(out))
        self.assertEqual(tx.calls, ['META','PAGE:1','META'])

    def test_provider_count_drift_destroys_buffered_content(self):
        out, _ = run(after=earlier.metadata('github', 4))
        self.assertEqual(out['reason_code'], 'FILE_COUNT_OR_PIN_DRIFT')
        self.assertEqual(out['patches'], [])

    def test_incomplete_path_coverage_withholds_all_patches(self):
        content = rows('github')
        out, tx = run(pages=[earlier.page(content[:1], link=earlier.gh_link(2,1))],
                      per_page=1, max_pages=1)
        self.assertEqual(out['reason_code'], 'PATCH_WITHHELD_INCOMPLETE_COVERAGE')
        self.assertEqual(out['patches'][0]['availability'], 'COVERAGE_INCOMPLETE')
        self.assertIsNone(out['patches'][0]['patch_text'])
        self.assertEqual(tx.calls, ['META','PAGE:1','META'])

    def test_unknown_count_coverage_withholds_patches(self):
        out, _ = run(count=3000)
        self.assertEqual(out['reason_code'], 'PATCH_WITHHELD_INCOMPLETE_COVERAGE')
        self.assertFalse(out['patch_content_collected'])

    def test_unknown_selected_path_suppresses_other_selected_content(self):
        out, _ = run(paths_selected=('src/service.py', 'not/here.py'))
        self.assertEqual((out['status'], out['reason_code']),
                         ('invalid_input', 'PATCH_PATH_NOT_IN_COMPLETE_LIST'))
        self.assertEqual(out['patches'], [])
        self.assertNotIn('new = 2', json.dumps(out))

    def test_rename_old_path_is_not_silent_alias_of_new_path(self):
        out, _ = run(paths_selected=('src/old.py',))
        self.assertEqual(out['reason_code'], 'PATCH_PATH_NOT_IN_COMPLETE_LIST')

    def test_invalid_prior_pin_blocks_before_tokens(self):
        p = earlier.prior('github', 3)
        p['pin_fingerprint'] = 'sha256:' + '0'*64
        out, tx = run(pin=p, token_supplier=lambda: self.fail('token used'))
        self.assertEqual(out['reason_code'], 'INVALID_EXPECTED_PIN')
        self.assertEqual(tx.calls, [])

    def test_token_is_never_in_output_or_exception(self):
        out, _ = run(token_supplier=lambda: 'SYNTHETIC-TOP-SECRET-CREDENTIAL')
        self.assertNotIn('SYNTHETIC-TOP-SECRET-CREDENTIAL', json.dumps(out))
        self.assertNotIn('https://provider.example/secret', json.dumps(out))
        self.assertNotIn('raw_url', json.dumps(out))

    def test_metadata_before_drift_not_fetch_page(self):
        changed = earlier.metadata('github', 3)
        changed['base']['sha'] = 'c'*40
        out, tx = run(before=changed)
        self.assertEqual(out['status'], 'unavailable')
        self.assertEqual(tx.calls, ['META'])

    def test_false_flags_type_refused(self):
        key = source.RequestKey('github','example/repo',8)
        out = patch.collect_proposed_pr_patch(
            key, expected_pin=earlier.prior('github',3), allow_network=True,
            include_patch_content=1, acknowledge_provider_permission=True)
        self.assertEqual(out['reason_code'],'PATCH_AUTHORIZATION_INVALID')

    def test_diff_parser_hunk_count_valid_and_invalid(self):
        self.assertEqual(patch._diff_format('@@ -1,2 +1,2 @@\n a\n-b\n+c\n'), 'AVAILABLE')
        self.assertEqual(patch._diff_format('@@ -1,2 +1,2 @@\n a\n-b\n'), 'TRUNCATED')
        self.assertEqual(patch._diff_format('@@ -1 +1 @@\n-a\n+b\n'), 'AVAILABLE')
        self.assertEqual(patch._diff_format('@@ -1 +1 @@\n-a\n+b\n EXTRA\n'), 'UNVERIFIED_FORMAT')


if __name__ == '__main__':
    unittest.main(verbosity=2)
