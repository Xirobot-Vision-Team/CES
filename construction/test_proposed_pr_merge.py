#!/usr/bin/env python3
"""EC167 functional offline scenarios against synthetic GH/GL and disposable Git."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import proposed_pr_identity as identity
import proposed_pr_merge as merge
import proposed_pr_reconcile as reconcile
import proposed_pr_source as source
import test_proposed_pr_paths as ec163


class Transport:
    def __init__(self, raw):
        self.raw = copy.deepcopy(raw)
        self.urls = []

    def get_object(self, url, headers, timeout):
        self.urls.append(url)
        return copy.deepcopy(self.raw)

    def get_page(self, *args):
        raise AssertionError('no file-page requests permitted')


class GitRepo:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ces-ec167-')
        self.root = Path(self.tmp.name) / 'target'
        self.root.mkdir()
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.email', 'fixture@example.test')
        self.git('config', 'user.name', 'CES Fixture')
        self.git('config', 'commit.gpgsign', 'false')
        self.commit('base.txt', 'base')
        self.base = self.sha()
        self.git('checkout', '-q', '-b', 'feature')
        self.commit('feature.txt', 'feature')
        self.head = self.sha()
        self.git('checkout', '-q', 'main')
        self.commit('target.txt', 'target')
        self.target = self.sha()
        self.git('merge', '-q', '--no-ff', 'feature', '-m', 'merge')
        self.merged = self.sha()
        self.tree = self.git('rev-parse', self.merged + '^{tree}').strip()

    def git(self, *args):
        cp = subprocess.run(['git', '-C', str(self.root), *args],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=7)
        if cp.returncode:
            raise AssertionError('temp git failed: ' + cp.stderr)
        return cp.stdout

    def commit(self, name, data):
        (self.root / name).write_text(data)
        self.git('add', '.')
        self.git('commit', '-q', '-m', name)

    def sha(self):
        return self.git('rev-parse', 'HEAD').strip()

    def close(self):
        self.tmp.cleanup()


def key(provider='github'):
    return source.RequestKey(provider, 'example/repo' if provider == 'github'
                             else 'my-group/sub-group/repo', 8)


def payload(git, provider='github', postmerge=False):
    raw = ec163.metadata(provider, 3 if provider == 'github' else '2')
    if provider == 'github':
        raw['state'], raw['merged'] = 'closed', True
        raw['base']['sha'] = git.merged if postmerge else git.target
        raw['head']['sha'] = git.head
    else:
        raw['state'] = 'merged'
        raw['diff_refs'].update(base_sha=git.base, start_sha=git.target, head_sha=git.head)
        raw['sha'] = git.head
    raw['merge_commit_sha'] = git.merged
    raw['title'] = 'PRIVATE_PROVIDER_TEXT_NOT_TO_RETURN'
    return raw


def chain(raw, provider='github'):
    first = identity.confirm_proposed_pr_identity(
        key(provider), allow_network=True, transport=Transport(raw),
        token_supplier=lambda: 'FIXTURE-TOKEN')
    assert first['status'] == 'partial', first
    second = reconcile.reconcile_proposed_pr(
        key(provider), expected_pin=first, allow_network=True,
        transport=Transport(raw), token_supplier=lambda: 'FIXTURE-TOKEN')
    assert second['reconciliation_state'] == 'FRESH_OBSERVATION', second
    return first, second


class Ec167MergeTests(unittest.TestCase):
    def setUp(self):
        self.g = GitRepo()
        self.addCleanup(self.g.close)

    def call(self, raw=None, *, prior=None, recent=None, provider='github',
             allow_network=True, allow_local_git=True, local_repo=None):
        raw = raw if raw is not None else payload(self.g, provider)
        if prior is None and recent is None:
            prior, recent = chain(raw, provider)
        tx = Transport(raw)
        out = merge.associate_merge_commit(
            key(provider), expected_pin=prior, ec166_reconciliation=recent,
            local_git_repository=str(self.g.root) if local_repo is None else local_repo,
            allow_network=allow_network, allow_local_git=allow_local_git,
            transport=tx, token_supplier=lambda: 'PRIVATE-TOKEN-DO-NOT-RETURN')
        return out, tx

    def test_github_local_merge_tree_parent_chain(self):
        out, tx = self.call()
        self.assertEqual((out['status'], out['exit_code'], out['association_state']),
                         ('partial', 2, 'LOCAL_MERGE_GRAPH_VERIFIED'))
        self.assertEqual(out['local_git']['merge_parent_oids'], [self.g.target, self.g.head])
        self.assertEqual(out['local_git']['merge_tree_oid'], self.g.tree)
        self.assertEqual(out['local_git']['target_lineage_relation'],
                         'TARGET_TIP_ANCESTOR_OF_FIRST_PARENT')
        self.assertEqual(len(tx.urls), 1)
        self.assertFalse(out['delivery_or_merge_proven'])
        self.assertFalse(out['target_repository_membership_authenticated'])
        self.assertFalse(out['write_authorized'])
        self.assertTrue(out['synthetic'])
        self.assertNotIn('PRIVATE-', json.dumps(out))

    def test_github_postmerge_target_branch(self):
        out, _ = self.call(payload(self.g, postmerge=True))
        self.assertEqual(out['association_state'], 'LOCAL_MERGE_GRAPH_VERIFIED')
        self.assertEqual(out['local_git']['target_lineage_relation'],
                         'MERGE_ANCESTOR_OF_OBSERVED_GITHUB_TARGET_TIP')

    def test_gitlab_target_start_is_not_merge_base(self):
        out, tx = self.call(provider='gitlab')
        self.assertEqual(out['association_state'], 'LOCAL_MERGE_GRAPH_VERIFIED')
        self.assertEqual(out['local_git']['target_tip_oid'], self.g.target)
        self.assertIn('/merge_requests/8', tx.urls[0])

    def test_both_read_permissions_required_before_token_or_request(self):
        for permit_network, permit_git, expected in ((False, True, 'NETWORK_NOT_AUTHORIZED'),
                                                      (True, False, 'LOCAL_GIT_NOT_AUTHORIZED')):
            with self.subTest(expected=expected):
                out, tx = self.call(allow_network=permit_network, allow_local_git=permit_git)
                self.assertEqual(out['reason_code'], expected)
                self.assertEqual(tx.urls, [])

    def test_missing_baselines_refused_before_provider(self):
        raw = payload(self.g)
        prior, recent = chain(raw)
        for p, r in ((None, recent), (prior, None)):
            with self.subTest(part='pin' if p is None else 'reconcile'):
                out, tx = self.call(raw, prior=p, recent=r)
                self.assertEqual(out['reason_code'], 'EC162_AND_EC166_REQUIRED')
                self.assertEqual(tx.urls, [])

    def test_stale_ec166_refused(self):
        raw = payload(self.g)
        pin, fresh = chain(raw)
        stale = copy.deepcopy(fresh)
        stale['reconciliation_state'] = 'STALE_BY_DRIFT'
        out, tx = self.call(raw, prior=pin, recent=stale)
        self.assertEqual(out['reason_code'], 'EC166_NOT_FRESH')
        self.assertEqual(tx.urls, [])

    def test_expired_ec166_refused(self):
        raw = payload(self.g)
        pin, fresh = chain(raw)
        expired = copy.deepcopy(fresh)
        expired['current_observation']['observed_at_utc'] = (
            datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        out, tx = self.call(raw, prior=pin, recent=expired)
        self.assertEqual(out['reason_code'], 'EC166_OBSERVATION_EXPIRED')
        self.assertEqual(tx.urls, [])

    def test_tampered_fresh_chain_rejected(self):
        raw = payload(self.g)
        pin, fresh = chain(raw)
        tampered = copy.deepcopy(fresh)
        tampered['current_observation']['pin']['head_sha'] = 'd' * 40
        out, tx = self.call(raw, prior=pin, recent=tampered)
        self.assertEqual(out['reason_code'], 'EC166_CHAIN_INVALID')
        self.assertEqual(tx.urls, [])

    def test_provider_head_drift_refused(self):
        raw = payload(self.g)
        pin, fresh = chain(raw)
        later = copy.deepcopy(raw)
        later['head']['sha'] = 'd' * 40
        out, tx = self.call(later, prior=pin, recent=fresh)
        self.assertEqual(out['reason_code'], 'CURRENT_PROVIDER_IDENTITY_DRIFT_HEAD_SHA_CHANGED')
        self.assertEqual(len(tx.urls), 1)

    def test_provider_count_drift_refused(self):
        raw = payload(self.g)
        pin, fresh = chain(raw)
        later = copy.deepcopy(raw)
        later['changed_files'] = 8
        out, _ = self.call(later, prior=pin, recent=fresh)
        self.assertEqual(out['reason_code'], 'CURRENT_PROVIDER_FILE_COUNT_DRIFT')

    def test_open_pr_status_cannot_prove_merge(self):
        raw = payload(self.g)
        raw['state'], raw['merged'] = 'open', False
        pin, recent = chain(raw)
        out, tx = self.call(raw, prior=pin, recent=recent)
        self.assertEqual(out['reason_code'], 'EC162_PROVIDER_NOT_MERGED')
        self.assertEqual(tx.urls, [])

    def test_missing_merge_sha_does_not_use_squash(self):
        for provider in ('github', 'gitlab'):
            with self.subTest(provider=provider):
                raw = payload(self.g, provider)
                raw['merge_commit_sha'] = None
                raw['squash_commit_sha'] = self.g.head
                out, _ = self.call(raw, provider=provider)
                self.assertEqual(out['reason_code'], 'MERGE_COMMIT_SHA_NOT_REPORTED')

    def test_invalid_merge_sha_does_not_enter_git(self):
        raw = payload(self.g)
        raw['merge_commit_sha'] = 'bad-oid'
        out, _ = self.call(raw)
        self.assertEqual(out['reason_code'], 'PROVIDER_MERGE_SHA_INVALID')

    def test_fast_forward_one_parent_defers_ec168(self):
        raw = payload(self.g)
        raw['merge_commit_sha'] = self.g.head
        out, _ = self.call(raw)
        self.assertEqual(out['reason_code'], 'TWO_PARENT_MERGE_NOT_PROVEN_EC168_DEFERRED')

    def test_second_parent_must_equal_pinned_head(self):
        raw = payload(self.g)
        raw['head']['sha'] = self.g.target
        out, _ = self.call(raw)
        self.assertEqual(out['reason_code'], 'MERGE_HEAD_PARENT_MISMATCH')

    def test_target_lineage_does_not_follow_head(self):
        raw = payload(self.g)
        raw['base']['sha'] = self.g.head
        out, _ = self.call(raw)
        self.assertEqual(out['reason_code'], 'TARGET_HISTORY_ASSOCIATION_UNPROVEN')

    def test_missing_target_tree_fails_closed(self):
        raw = payload(self.g)
        obj = self.g.root / '.git' / 'objects' / self.g.tree[:2] / self.g.tree[2:]
        self.assertTrue(obj.is_file())
        obj.unlink()  # ephemeral test clone only
        out, _ = self.call(raw)
        self.assertEqual(out['reason_code'], 'MERGE_TARGET_TREE_UNAVAILABLE')

    def test_missing_merge_commit_fails_closed(self):
        raw = payload(self.g)
        raw['merge_commit_sha'] = 'f' * 40
        out, _ = self.call(raw)
        self.assertEqual(out['reason_code'], 'LOCAL_COMMIT_UNAVAILABLE')

    def test_default_source_v1_does_not_return_merge_sha(self):
        raw = payload(self.g)
        normal = source.fetch_proposed_pr(
            key(), allow_network=True, transport=Transport(raw),
            token_supplier=lambda: 'SYNTHETIC')
        self.assertNotIn('provider_merge_commit_sha', normal['source'])
        extended = source.fetch_proposed_pr(
            key(), allow_network=True, transport=Transport(raw),
            token_supplier=lambda: 'SYNTHETIC', include_merge_commit_claim=True)
        self.assertEqual(extended['source']['provider_merge_commit_sha'], self.g.merged)


if __name__ == '__main__':
    unittest.main()
