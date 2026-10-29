#!/usr/bin/env python3
"""EC165 focused offline *development* tests; not live provider acceptance."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import proposed_pr_snapshot as snapshot
import proposed_pr_patch as patch
import proposed_pr_paths as paths
import proposed_pr_source as source
import test_proposed_pr_paths as ec163
import test_proposed_pr_patch as ec164


def create(provider='github', *, selected=(), include=False, recheck=False,
           ack=True, allow_network=True, repo=None, count=None,
           metadata_reads=None, page_reads=None, content_policy=None,
           token_supplier=None, local_git=None, per_page=100, max_pages=30,
           prior=None):
    if count is None:
        count = 3 if provider == 'github' else '2'
    key = source.RequestKey(provider, 'example/repo' if provider == 'github' else
                            'my-group/sub-group/repo', 8)
    metas = metadata_reads if metadata_reads is not None else [
        ec163.metadata(provider, count) for _ in range(4 if recheck else 2)]
    items = ec164.rows(provider)
    pages_ = page_reads if page_reads is not None else [
        ec163.page(items, provider=provider) for _ in range(2 if recheck else 1)]
    tx = ec163.Transport(metas, pages_)
    earlier = prior or ec163.prior(provider, count)
    if include:
        if content_policy is None:
            content_policy = patch.ContentPolicy(tuple(selected), 4096, 8192)
    output = snapshot.collect_proposed_pr_snapshot(
        key, expected_pin=earlier, allow_network=allow_network,
        include_patch_content=include,
        acknowledge_provider_permission=ack, content_policy=content_policy,
        selection=snapshot.SnapshotSelection(tuple(selected)),
        recheck_pages=recheck, transport=tx, local_git=local_git,
        token_supplier=token_supplier or (lambda: 'SYNTHETIC-NOT-REAL'),
        per_page=per_page, max_pages=max_pages,
    )
    return output, tx


def tagged(items, provider='github', tag='"v-a"', raw=None, nextlink=''):
    page = ec163.page(items, provider=provider)
    page.headers['etag'] = tag
    if nextlink:
        page.headers['link'] = nextlink
    if raw is not None:
        page = paths.FilePage(page.items, page.headers, page.byte_count, raw)
    return page


class SnapshotTests(unittest.TestCase):
    def test_default_is_private_nonatomic_and_recomputable(self):
        out, tx = create()
        self.assertEqual(out['status'], 'partial')
        self.assertEqual(out['exit_code'], 2)
        self.assertEqual(out['reason_code'], 'OBSERVATION_BOUND_NONATOMIC')
        self.assertFalse(out['diff_snapshot_proven'])
        self.assertFalse(out['version_consistency']['provider_atomic_snapshot'])
        self.assertIsNone(out['version_consistency']['provider_immutable_diff_version_id'])
        self.assertFalse(out['patch_evidence']['patch_content_collected'])
        self.assertEqual(out['patch_evidence']['patches'], [])
        self.assertNotIn('old = 1', json.dumps(out))
        self.assertEqual(out['observation_ref'], snapshot.fingerprint(out['evidence_material']))
        self.assertEqual(snapshot.verify_receipt(out)['status'], 'INTERNALLY_CONSISTENT_ONLY')
        self.assertEqual(tx.calls, ['META', 'PAGE:1', 'META'])

    def test_no_permission_no_network_no_token(self):
        out, tx = create(allow_network=False, token_supplier=lambda: self.fail('token read'))
        self.assertEqual(out['reason_code'], 'NETWORK_NOT_AUTHORIZED')
        self.assertIsNone(out['observation_ref'])
        self.assertEqual(tx.calls, [])

    def test_bad_path_and_no_ack_stop_before_token(self):
        for path in ('../bad', 'src/*.py', '.env', 'Private/client.txt',
                     'src/A.py', 'src/a.PY'):
            if path in ('src/A.py', 'src/a.PY'):
                sel = ('src/a.py', path)
            else:
                sel = (path,)
            with self.subTest(sel=sel):
                out, tx = create(selected=sel, token_supplier=lambda: self.fail('token'))
                self.assertEqual(out['status'], 'invalid_input')
                self.assertEqual(tx.calls, [])
        out, tx = create(include=True, selected=('src/service.py',), ack=False,
                         token_supplier=lambda: self.fail('token'))
        self.assertEqual(out['reason_code'], 'PATCH_PERMISSION_ACK_REQUIRED')
        self.assertEqual(tx.calls, [])

    def test_no_content_selection_can_bind_versions_without_patch_disclosure(self):
        items = ec164.rows('github')
        items[0]['sha'] = 'a'*40
        out, _ = create(selected=('src/service.py',), page_reads=[ec163.page(items)])
        versions = out['evidence_material']['selected_file_versions']
        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0]['status'], 'PROVIDER_BLOB_CLAIM_ONLY')
        self.assertEqual(versions[0]['provider_declared_blob_oid'], 'a'*40)
        self.assertFalse(versions[0]['provider_blob_membership_independently_verified'])
        self.assertFalse(out['patch_evidence']['patch_content_requested'])
        self.assertTrue('PROVIDER_IMMUTABLE_DIFF_VERSION_OR_ATOMIC_SNAPSHOT_TOKEN' in
                        out['version_consistency']['missing_independent_proofs'])

    def test_selected_blob_claim_wrong_format_withholds_receipt(self):
        items = ec164.rows('github')
        items[0]['sha'] = 'bad-sha'
        out, _ = create(selected=('src/service.py',), page_reads=[ec163.page(items)])
        self.assertEqual(out['reason_code'], 'PROVIDER_BLOB_CLAIM_INVALID')
        self.assertIsNone(out['patch_evidence'])

    def test_unselected_bad_blob_claim_does_not_inspect_private_field(self):
        items = ec164.rows('github')
        items[1]['sha'] = 'malformed-claim'
        out, _ = create(selected=('src/service.py',), page_reads=[ec163.page(items)])
        self.assertEqual(out['status'], 'partial')
        self.assertIsNotNone(out['observation_ref'])

    def test_strong_etag_claim_single_page_does_not_prove_snapshot(self):
        out, _ = create(page_reads=[tagged(ec164.rows('github'))])
        info = out['version_consistency']['provider_page_validators']
        self.assertEqual(info['strong_etags'], 1)
        self.assertEqual(info['missing_etags'], 0)
        self.assertFalse(out['diff_snapshot_proven'])

    def test_weak_or_missing_etag_is_unknown(self):
        for value in ('W/"abc"', None):
            with self.subTest(value=value):
                pg = tagged(ec164.rows('github'), tag=value or '"x"')
                if value is None:
                    pg.headers.pop('etag')
                out, _ = create(page_reads=[pg])
                info = out['version_consistency']['provider_page_validators']
                self.assertEqual(info['weak_etags'] if value else info['missing_etags'], 1)
                self.assertEqual(out['version_consistency']['state'],
                                 'OBSERVATION_ONLY_PROVIDER_VERSION_UNKNOWN')

    def test_malformed_etag_or_date_fails_closed(self):
        for headers in ({'etag': 'abc'}, {'etag': '\n"abc"'},
                        {'last-modified': 'not-a-date'},
                        {'last-modified': 'Thu, 22 Oct 2026 00:00:00'}):
            with self.subTest(headers=headers):
                pg = ec163.page(ec164.rows('github'))
                pg.headers.update(headers)
                out, _ = create(page_reads=[pg])
                self.assertEqual(out['reason_code'], 'PROVIDER_VERSION_HEADER_INVALID')
                self.assertIsNone(out['observation_ref'])

    def test_gitlab_metadata_and_patch_explicit_release(self):
        out, _ = create('gitlab', selected=('lib/new.py',), include=True)
        self.assertEqual(out['status'], 'partial')
        self.assertTrue(out['patch_evidence']['patch_content_collected'])
        self.assertIn('+c', out['patch_evidence']['patches'][0]['patch_text'])
        receipt = out['evidence_material']['patch_disclosure']
        self.assertEqual(receipt['selected_paths'], ['lib/new.py'])
        self.assertNotIn('patch_text', json.dumps(receipt))
        self.assertEqual(snapshot.verify_receipt(out)['status'], 'INTERNALLY_CONSISTENT_ONLY')

    def test_gh_explicit_patch_hash_matches_released_text(self):
        out, _ = create(selected=('src/service.py',), include=True)
        entry = out['patch_evidence']['patches'][0]
        claim = out['evidence_material']['patch_disclosure']['selected_patch_outcomes'][0]
        self.assertEqual(claim['released_patch_digest'], snapshot._bytes_hash(
            snapshot.PATCH_DOMAIN, entry['patch_text'].encode('utf-8')))
        self.assertEqual(claim['emitted_utf8_bytes'], entry['utf8_bytes'])
        self.assertFalse(out['version_consistency']['provider_atomic_snapshot'])

    def test_incomplete_pagination_receipt_never_assumes_no_other_changes(self):
        items = ec164.rows('github')
        first = tagged(items[:1], raw='a'*64, nextlink=ec163.gh_link(2, 1))
        out, tx = create(page_reads=[first], per_page=1, max_pages=1)
        self.assertEqual(out['reason_code'], 'INCOMPLETE_PATH_COVERAGE_RECEIPT')
        self.assertEqual(out['evidence_material']['path_coverage']['state'], 'INCOMPLETE')
        self.assertEqual(out['evidence_material']['path_coverage']['listed_files'], 1)
        self.assertFalse(out['diff_snapshot_proven'])
        self.assertIn('COMPLETE_CHANGED_FILE_PAGINATION',
                      out['version_consistency']['missing_independent_proofs'])
        self.assertEqual(snapshot.verify_receipt(out)['status'], 'INTERNALLY_CONSISTENT_ONLY')
        self.assertEqual(tx.calls, ['META', 'PAGE:1', 'META'])

    def test_incomplete_with_patch_suppresses_every_selected_patch(self):
        first = tagged(ec164.rows('github')[:1], nextlink=ec163.gh_link(2, 1))
        out, _ = create(selected=('src/service.py',), include=True,
                        page_reads=[first], per_page=1, max_pages=1)
        self.assertFalse(out['patch_evidence']['patch_content_collected'])
        self.assertEqual(out['patch_evidence']['patches'][0]['availability'], 'COVERAGE_INCOMPLETE')
        self.assertNotIn('+new = 2', json.dumps(out))

    def test_complete_two_page_receipt_in_order(self):
        items = ec164.rows('github')
        pages_ = [tagged(items[:2], raw='a'*64, nextlink=ec163.gh_link(2, 2)),
                  tagged(items[2:], raw='b'*64, tag='"v-b"')]
        out, _ = create(page_reads=pages_, per_page=2)
        self.assertEqual(out['evidence_material']['path_coverage']['state'], 'COMPLETE')
        self.assertEqual([p['entries'] for p in out['evidence_material']['ordered_pages']], [2, 1])
        self.assertEqual(snapshot.verify_receipt(out)['status'], 'INTERNALLY_CONSISTENT_ONLY')

    def test_recheck_matches_strong_etag_and_raw_but_never_atomic(self):
        pg = tagged(ec164.rows('github'), raw='a'*64)
        out, tx = create(recheck=True, page_reads=[pg, copy.deepcopy(pg)])
        v = out['version_consistency']
        self.assertEqual(out['reason_code'], 'NONATOMIC_RECHECKED_OBSERVATIONS')
        self.assertEqual(v['state'], 'OBSERVATIONS_RECHECKED_NOT_ATOMIC')
        self.assertEqual(v['replay']['matching_raw_responses'], 1)
        self.assertTrue(v['replay']['performed'])
        self.assertFalse(v['provider_atomic_snapshot'])
        self.assertEqual(tx.calls, ['META', 'PAGE:1', 'META', 'META', 'PAGE:1', 'META'])
        self.assertEqual(snapshot.verify_receipt(out)['status'], 'INTERNALLY_CONSISTENT_ONLY')

    def test_recheck_mock_lacks_raw_proof(self):
        out, _ = create(recheck=True)
        self.assertEqual(out['version_consistency']['replay']['matching_raw_responses'], 0)
        self.assertEqual(out['version_consistency']['replay']['raw_response_comparison_unavailable'], 1)

    def test_recheck_detects_etag_changing(self):
        rows = ec164.rows('github')
        out, _ = create(recheck=True, page_reads=[tagged(rows, tag='"one"'),
                                                    tagged(rows, tag='"two"')])
        self.assertEqual(out['reason_code'], 'SNAPSHOT_RECHECK_DRIFT_OR_UNAVAILABLE')
        self.assertIsNone(out['patch_evidence'])
        self.assertIsNone(out['observation_ref'])

    def test_recheck_detects_private_raw_change_even_if_paths_unchanged(self):
        rows = ec164.rows('github')
        out, _ = create(recheck=True, page_reads=[tagged(rows, raw='a'*64),
                                                    tagged(rows, raw='b'*64)])
        self.assertEqual(out['reason_code'], 'SNAPSHOT_RAW_PAGE_CHANGED')
        self.assertIsNone(out['evidence_material'])

    def test_recheck_detects_path_reorder_and_drops_released_patch(self):
        rows = ec164.rows('github')
        out, _ = create(selected=('src/service.py',), include=True, recheck=True,
                        page_reads=[tagged(rows), tagged(list(reversed(rows)))])
        self.assertEqual(out['reason_code'], 'SNAPSHOT_RECHECK_DRIFT_OR_UNAVAILABLE')
        self.assertIsNone(out['patch_evidence'])
        self.assertNotIn('+new = 2', json.dumps(out))

    def test_recheck_detects_patch_text_change_with_same_paths_and_no_raw_hash(self):
        rows = ec164.rows('github')
        altered = copy.deepcopy(rows)
        altered[0]['patch'] = '@@ -1 +1 @@\n-old = 1\n+new = 3\n'
        out, _ = create(selected=('src/service.py',), include=True, recheck=True,
                        page_reads=[ec163.page(rows), ec163.page(altered)])
        self.assertEqual(out['reason_code'], 'SNAPSHOT_RECHECK_DRIFT_OR_UNAVAILABLE')
        self.assertNotIn('+new = 2', json.dumps(out))
        self.assertNotIn('+new = 3', json.dumps(out))

    def test_recheck_does_not_inspect_unselected_patch_when_disabled(self):
        first = ec164.rows('github')
        changed = copy.deepcopy(first)
        changed[0]['patch'] = 'private-but-unselected-variation'
        out, _ = create(recheck=True,
                        page_reads=[ec163.page(first), ec163.page(changed)])
        self.assertEqual(out['status'], 'partial')
        self.assertFalse(out['patch_evidence']['patch_content_requested'])
        self.assertNotIn('private-but-unselected', json.dumps(out))
        self.assertEqual(out['version_consistency']['replay']['raw_response_comparison_unavailable'], 1)

    def test_recheck_detects_metadata_change_in_second_pass(self):
        metas = [ec163.metadata('github', 3) for _ in range(4)]
        metas[3]['head']['sha'] = 'e'*40
        out, _ = create(recheck=True, metadata_reads=metas)
        self.assertEqual(out['reason_code'], 'SNAPSHOT_RECHECK_DRIFT_OR_UNAVAILABLE')
        self.assertIsNone(out['observation_ref'])

    def test_count_mismatch_withholds_all_observed_metadata(self):
        metas = [ec163.metadata('github', 3), ec163.metadata('github', 2)]
        out, _ = create(metadata_reads=metas)
        self.assertEqual(out['reason_code'], 'FILE_COUNT_OR_PIN_DRIFT')
        self.assertIsNone(out['patch_evidence'])

    def test_github_provider_cap_cannot_be_complete(self):
        out, _ = create(count=3000)
        self.assertEqual(out['reason_code'], 'INCOMPLETE_PATH_COVERAGE_RECEIPT')
        self.assertEqual(out['evidence_material']['path_coverage']['state'], 'INCOMPLETE')

    def test_gitlab_1000_plus_is_unknown_total(self):
        out, _ = create('gitlab', count='1000+')
        self.assertEqual(out['evidence_material']['path_coverage']['state'], 'INCOMPLETE')
        self.assertNotEqual(out['version_consistency']['state'], 'OBSERVATIONS_RECHECKED_NOT_ATOMIC')

    def test_optional_local_git_commit_tree_binding_and_blob_conflict(self):
        with tempfile.TemporaryDirectory(prefix='ces-ec165-local-') as temp:
            repo = Path(temp)
            subprocess.run(['git', 'init', '-q', str(repo)], check=True, capture_output=True)
            (repo / 'src').mkdir()
            (repo / 'src' / 'service.py').write_text('x = 9\n', encoding='utf-8')
            subprocess.run(['git', '-C', str(repo), 'add', 'src/service.py'],
                           check=True, capture_output=True)
            subprocess.run(['git', '-C', str(repo), '-c', 'user.name=CES Fixture',
                            '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'test'],
                           check=True, capture_output=True)
            head = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
            blob = subprocess.check_output(['git', '-C', str(repo),
                                            'rev-parse', 'HEAD:src/service.py'], text=True).strip()
            meta = ec163.metadata('github', 3)
            meta['head']['sha'] = head
            earlier = ec163.prior('github', 3, target=meta)
            items = ec164.rows('github')
            items[0]['sha'] = blob
            out, _ = create(selected=('src/service.py',), local_git=str(repo),
                            prior=earlier, metadata_reads=[meta, meta],
                            page_reads=[ec163.page(items)])
            entry = out['evidence_material']['selected_file_versions'][0]
            self.assertEqual(entry['status'], 'LOCAL_HEAD_COMMIT_TREE_BOUND')
            self.assertEqual(entry['local_blob_oid'], blob)
            self.assertFalse(entry['provider_blob_membership_independently_verified'])
            self.assertEqual(snapshot.verify_receipt(out)['status'], 'INTERNALLY_CONSISTENT_ONLY')
            items[0]['sha'] = 'a'*40 if blob != 'a'*40 else 'b'*40
            out, _ = create(selected=('src/service.py',), local_git=str(repo),
                            prior=earlier, metadata_reads=[meta, meta],
                            page_reads=[ec163.page(items)])
            self.assertEqual(out['reason_code'], 'SNAPSHOT_LOCAL_PROVIDER_BLOB_CONFLICT')
            self.assertIsNone(out['patch_evidence'])

    def test_local_missing_repo_is_not_falsely_successful_version(self):
        out, _ = create(selected=('src/service.py',), local_git='/not/existing/repository')
        self.assertEqual(out['status'], 'partial')
        self.assertNotEqual(out['evidence_material']['selected_file_versions'][0]['status'],
                            'LOCAL_HEAD_COMMIT_TREE_BOUND')

    def test_local_selected_path_absent_is_invalid_and_does_not_bind_other(self):
        out, _ = create(selected=('src/service.py', 'src/unknown.py'))
        self.assertEqual(out['reason_code'], 'SNAPSHOT_PATH_NOT_IN_COMPLETE_LIST')
        self.assertIsNone(out['observation_ref'])

    def test_verifier_rejects_tampered_pin_and_path_and_patch_bytes(self):
        out, _ = create(selected=('src/service.py',), include=True)
        for change in ('path', 'pin', 'patch'):
            with self.subTest(change=change):
                altered = copy.deepcopy(out)
                if change == 'path':
                    altered['patch_evidence']['path_evidence']['files'][0]['new_path'] = 'src/wrong.py'
                elif change == 'pin':
                    altered['patch_evidence']['path_evidence']['pin']['head_sha'] = 'f'*40
                else:
                    altered['patch_evidence']['patches'][0]['patch_text'] = 'forged'
                self.assertEqual(snapshot.verify_receipt(altered)['status'], 'INVALID')

    def test_verifier_rejects_modified_material_digest_and_fake_atomic_claim(self):
        out, _ = create()
        changed = copy.deepcopy(out)
        changed['evidence_material']['request_budgets']['per_page'] = 999
        self.assertEqual(snapshot.verify_receipt(changed)['status'], 'INVALID')
        changed = copy.deepcopy(out)
        changed['diff_snapshot_proven'] = True
        self.assertEqual(snapshot.verify_receipt(changed)['status'], 'INVALID')

    def test_offline_verification_is_not_authentication(self):
        out, _ = create()
        verification = snapshot.verify_receipt(out)
        self.assertEqual(verification['status'], 'INTERNALLY_CONSISTENT_ONLY')
        self.assertFalse(verification['provider_authenticity_verified'])
        self.assertFalse(verification['cross_page_atomicity_verified'])
        self.assertFalse(verification['remote_source_rechecked_by_verifier'])

    def test_receipt_never_exposes_page_raw_body_hash(self):
        pg = tagged(ec164.rows('github'), raw='e'*64)
        out, _ = create(page_reads=[pg])
        self.assertNotIn('e'*64, json.dumps(out))
        self.assertFalse(out['evidence_material']['ordered_pages'][0]['raw_response_digest_disclosed'])

    def test_recheck_is_skipped_when_incomplete(self):
        first = tagged(ec164.rows('github')[:1], nextlink=ec163.gh_link(2, 1))
        out, tx = create(recheck=True, per_page=1, max_pages=1,
                         page_reads=[first])
        self.assertEqual(out['reason_code'], 'INCOMPLETE_PATH_COVERAGE_RECEIPT')
        self.assertFalse(out['version_consistency']['replay']['performed'])
        self.assertEqual(tx.calls, ['META', 'PAGE:1', 'META'])


if __name__ == '__main__':
    unittest.main()
