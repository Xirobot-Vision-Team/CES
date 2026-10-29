#!/usr/bin/env python3
"""EC168: disposable real Git DAG/tree fixtures and synthetic GH/GL claims.

No remote provider network, user repository, checkout of real worktrees,
credential, or persisted CES state is touched by these tests.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import proposed_pr_identity as identity
import proposed_pr_linear as linear
import proposed_pr_merge as merge
import proposed_pr_reconcile as reconcile
import proposed_pr_source as source
import test_proposed_pr_paths as ec163


class Transport:
    def __init__(self, payload):
        self.payload = copy.deepcopy(payload)
        self.urls: list[str] = []

    def get_object(self, url, headers, timeout):
        self.urls.append(url)
        return copy.deepcopy(self.payload)

    def get_page(self, *args):
        raise AssertionError('EC168 must not request file pages')


class Repo:
    def __init__(self, scenario='squash', *, squash_base='target'):
        self.tmp = tempfile.TemporaryDirectory(prefix='ces-ec168-')
        self.root = Path(self.tmp.name) / 'target'
        self.root.mkdir()
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.name', 'CES Temporary Fixture')
        self.git('config', 'user.email', 'test@example.test')
        self.git('config', 'commit.gpgsign', 'false')
        self.commit('base.txt', 'base')
        self.base = self.sha()
        self.git('checkout', '-q', '-b', 'feature')
        self.commit('feature-one.txt', 'first feature')
        self.first = self.sha()
        self.commit('feature-two.txt', 'second feature')
        self.head = self.sha()
        self.git('checkout', '-q', 'main')
        self.commit('target.txt', 'target')
        self.target = self.sha()
        self.squash = None
        self.merged = None
        if scenario in ('squash', 'separate'):
            self.git('checkout', '-q', '-b', 'squashed', self.target if squash_base == 'target' else self.base)
            self.git('merge', '--squash', 'feature')
            self.git('commit', '-q', '-m', 'squash')
            self.squash = self.sha()
            self.git('checkout', '-q', 'main')
            if scenario == 'separate':
                self.git('merge', '-q', '--no-ff', 'squashed', '-m', 'merge squash')
                self.merged = self.sha()
            else:
                # Main is pre-merge target; the synthetic metadata can
                # report a provider-claimed squashed commit without refs.
                self.merged = self.squash
        elif scenario == 'two-parent':
            self.git('merge', '-q', '--no-ff', 'feature', '-m', 'merge feature')
            self.merged = self.sha()
        elif scenario == 'rebase':
            self.git('cherry-pick', '--no-edit', self.first)
            self.rebased_first = self.sha()
            self.git('cherry-pick', '--no-edit', self.head)
            self.merged = self.sha()
        elif scenario == 'fast-forward':
            # Main must be an ancestor of feature, use base as pre-merge tip.
            self.merged = self.head
        else:
            raise ValueError(scenario)

    def git(self, *args):
        cp = subprocess.run(['git', '-C', str(self.root), *args], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=7)
        if cp.returncode:
            raise AssertionError(f'temporary Git {args[0]} failed: {cp.stderr}')
        return cp.stdout.strip()

    def sha(self):
        return self.git('rev-parse', 'HEAD')

    def commit(self, name, content):
        (self.root / name).write_text(content, encoding='utf-8')
        self.git('add', '.')
        self.git('commit', '-q', '-m', name)

    def close(self):
        self.tmp.cleanup()


def key(provider='gitlab'):
    return source.RequestKey(provider, 'my-group/sub-group/repo' if provider == 'gitlab'
                             else 'example/repo', 8)


def metadata(g: Repo, provider='gitlab', *, kind='squash', postmerge=False):
    raw = ec163.metadata(provider, '2' if provider == 'gitlab' else 2)
    if provider == 'gitlab':
        raw['state'] = 'merged'
        raw['diff_refs'].update(base_sha=g.base, head_sha=g.head,
                                start_sha=g.base if kind == 'fast-forward' else g.target)
        raw['sha'] = g.head
        raw['squash_on_merge'] = kind == 'squash'
        raw['squash_commit_sha'] = g.squash if kind == 'squash' else None
    else:
        raw['state'], raw['merged'] = 'closed', True
        raw['base']['sha'] = g.base if kind == 'fast-forward' else (
            g.merged if postmerge else g.target)
        raw['head']['sha'] = g.head
    raw['merge_commit_sha'] = g.merged
    raw['title'] = 'SECRET-PRIVATE-BODY-NOT-FOR-RESULT'
    return raw


def chain(raw, provider):
    pin = identity.confirm_proposed_pr_identity(
        key(provider), allow_network=True, token_supplier=lambda: 'TEST_TOKEN',
        transport=Transport(raw))
    assert pin['status'] == 'partial', pin
    recent = reconcile.reconcile_proposed_pr(
        key(provider), expected_pin=pin, allow_network=True,
        token_supplier=lambda: 'TEST_TOKEN', transport=Transport(raw))
    assert recent['reconciliation_state'] == 'FRESH_OBSERVATION', recent
    return pin, recent


class Ec168Tests(unittest.TestCase):
    def setUp(self):
        self.repos = []

    def repo(self, scenario='squash', **kwargs):
        g = Repo(scenario, **kwargs)
        self.repos.append(g)
        self.addCleanup(g.close)
        return g

    def call(self, g, raw, *, provider='gitlab', prior=None, recent=None,
             network=True, local=True, repository=None):
        if prior is None and recent is None:
            prior, recent = chain(raw, provider)
        tx = Transport(raw)
        out = linear.associate_linear_change(
            key(provider), expected_pin=prior, ec166_reconciliation=recent,
            local_git_repository=str(g.root) if repository is None else repository,
            allow_network=network, allow_local_git=local,
            token_supplier=lambda: 'SECRET-TOKEN-MUST-BE-SUPPRESSED',
            transport=tx)
        self.assertNotIn('SECRET-', json.dumps(out))
        return out, tx

    def test_gitlab_explicit_squash_succeeds_with_exact_net_tree(self):
        g = self.repo()
        out, tx = self.call(g, metadata(g))
        self.assertEqual((out['status'], out['exit_code'], out['association_state']),
                         ('partial', 2, 'LOCAL_GITLAB_SQUASH_TREE_VERIFIED'))
        self.assertEqual(out['candidate_kind'], 'GITLAB_EXPLICIT_SQUASH_CLAIM')
        self.assertEqual(out['local_git']['squash_commit_oid'], g.squash)
        self.assertTrue(out['local_git']['net_result_mode_and_blob_oids_exactly_equal'])
        self.assertEqual(out['local_git']['source_net_changed_paths'], 2)
        self.assertEqual(len(tx.urls), 1)
        self.assertFalse(out['delivery_or_merge_proven'])
        self.assertFalse(out['target_repository_membership_authenticated'])
        self.assertFalse(out['evidence_policy']['squash_historical_method_authenticated'])
        self.assertFalse(out['write_authorized'])

    def test_gitlab_separate_two_parent_squash_merge_witness(self):
        g = self.repo('separate', squash_base='base')
        out, _ = self.call(g, metadata(g))
        self.assertEqual(out['association_state'], 'LOCAL_GITLAB_SQUASH_TREE_VERIFIED')
        self.assertEqual(out['local_git']['merge_parent_oids'][1], g.squash)
        self.assertIn('TWO_PARENT_SECOND_IS_SQUASH', out['local_git']['merge_witness'])

    def test_github_one_parent_net_tree_positive_but_method_stays_unknown(self):
        g = self.repo()
        out, tx = self.call(g, metadata(g, 'github'), provider='github')
        self.assertEqual(out['association_state'], 'LOCAL_SINGLE_COMMIT_NET_TREE_VERIFIED_METHOD_UNKNOWN')
        self.assertEqual(out['local_git']['historical_merge_method'], 'UNKNOWN')
        self.assertEqual(out['local_git']['rebase_commit_map'], 'NOT_ATTESTED')
        self.assertFalse(out['evidence_policy']['rebase_commit_mapping_complete'])
        self.assertEqual(len(tx.urls), 1)

    def test_github_postmerge_target_tip_still_works(self):
        g = self.repo()
        out, _ = self.call(g, metadata(g, 'github', postmerge=True), provider='github')
        self.assertEqual(out['association_state'], 'LOCAL_SINGLE_COMMIT_NET_TREE_VERIFIED_METHOD_UNKNOWN')
        self.assertEqual(out['local_git']['target_lineage_relation'],
                         'CANDIDATE_ANCESTOR_OF_OBSERVED_LATER_GITHUB_TARGET_TIP')

    def test_github_multi_commit_rebase_last_oid_not_a_mapping(self):
        g = self.repo('rebase')
        out, _ = self.call(g, metadata(g, 'github'), provider='github')
        self.assertEqual(out['association_state'], 'UNAVAILABLE_UNKNOWN')
        self.assertEqual(out['reason_code'], 'SOURCE_TO_TARGET_NET_BLOB_DELTA_MISMATCH')
        self.assertFalse(out['local_association_verified'])

    def test_gitlab_non_squash_one_parent_rebased_candidate_unknown(self):
        g = self.repo('rebase')
        out, _ = self.call(g, metadata(g, kind='rebase'))
        self.assertEqual(out['reason_code'], 'GITLAB_REBASE_OR_FAST_FORWARD_MAPPING_NOT_ATTESTED')
        self.assertEqual(out['association_state'], 'UNAVAILABLE_UNKNOWN')

    def test_gitlab_exact_head_linear_graph_is_not_rebase_equivalence(self):
        g = self.repo('fast-forward')
        out, _ = self.call(g, metadata(g, kind='fast-forward'))
        self.assertEqual(out['association_state'], 'LOCAL_EXACT_HEAD_GRAPH_VERIFIED_METHOD_UNKNOWN')
        self.assertFalse(out['local_git']['all_rebase_replacement_commits_mapped'])
        self.assertFalse(out['delivery_or_merge_proven'])

    def test_github_exact_head_requires_ancestry(self):
        g = self.repo('fast-forward')
        raw = metadata(g, 'github', kind='fast-forward')
        out, _ = self.call(g, raw, provider='github')
        self.assertEqual(out['association_state'], 'LOCAL_EXACT_HEAD_GRAPH_VERIFIED_METHOD_UNKNOWN')
        bad = copy.deepcopy(raw)
        bad['base']['sha'] = g.target  # diverged from feature
        out2, _ = self.call(g, bad, provider='github')
        self.assertEqual(out2['reason_code'], 'EXACT_HEAD_TARGET_ANCESTRY_UNPROVEN')

    def test_ec167_two_parent_route_stays_positive(self):
        g = self.repo('two-parent')
        for provider in ('github', 'gitlab'):
            with self.subTest(provider=provider):
                raw = metadata(g, provider, kind='merge')
                out, _ = self.call(g, raw, provider=provider)
                self.assertEqual(out['association_state'], 'LOCAL_MERGE_GRAPH_VERIFIED')
                self.assertEqual(out['local_git']['merge_parent_oids'][1], g.head)

    def test_squash_flag_without_real_sha_is_unknown(self):
        g = self.repo()
        raw = metadata(g)
        raw['squash_commit_sha'] = None
        out, _ = self.call(g, raw)
        self.assertEqual(out['reason_code'], 'GITLAB_SQUASH_COMMIT_CLAIM_MISSING')

    def test_squash_sha_without_effective_policy_is_unknown(self):
        g = self.repo()
        raw = metadata(g)
        raw['squash_on_merge'] = False
        out, _ = self.call(g, raw)
        self.assertEqual(out['reason_code'], 'GITLAB_SQUASH_POLICY_AND_SHA_INCONSISTENT')

    def test_legacy_gitlab_squash_flag_cannot_override_missing_effective(self):
        g = self.repo()
        raw = metadata(g)
        raw['squash'] = True
        del raw['squash_on_merge']
        out, _ = self.call(g, raw)
        self.assertEqual(out['reason_code'], 'GITLAB_SQUASH_POLICY_AND_SHA_INCONSISTENT')

    def test_invalid_squash_oid_rejected_before_git(self):
        g = self.repo()
        raw = metadata(g)
        raw['squash_commit_sha'] = 'badsha'
        out, tx = self.call(g, raw)
        self.assertEqual(out['reason_code'], 'PROVIDER_SQUASH_SHA_INVALID')
        self.assertEqual(len(tx.urls), 1)

    def test_wrong_gitlab_base_refuses_squash_association(self):
        g = self.repo()
        raw = metadata(g)
        raw['diff_refs']['base_sha'] = g.first
        out, _ = self.call(g, raw)
        self.assertEqual(out['reason_code'], 'GITLAB_PINNED_DIFF_BASE_MISMATCH')

    def test_mutated_git_squash_tree_mismatch_is_unknown(self):
        g = self.repo()
        raw = metadata(g)
        # Wrong provider squash SHA points to an existing but unrelated
        # one-parent target commit with a different delta.
        raw['squash_commit_sha'] = g.target
        raw['merge_commit_sha'] = g.target
        out, _ = self.call(g, raw)
        self.assertEqual(out['association_state'], 'UNAVAILABLE_UNKNOWN')
        self.assertIn(out['reason_code'], ('SOURCE_TO_TARGET_NET_BLOB_DELTA_MISMATCH',
                                           'GITLAB_PINNED_DIFF_BASE_MISMATCH'))

    def test_separate_merge_sha_must_actually_link_squash(self):
        g = self.repo('separate', squash_base='base')
        raw = metadata(g)
        raw['merge_commit_sha'] = g.target  # existing but not a merge of S
        out, _ = self.call(g, raw)
        self.assertEqual(out['reason_code'], 'SEPARATE_MERGE_DOES_NOT_NAME_SQUASH_PARENT')

    def test_permissions_denied_before_token_network_and_git(self):
        g = self.repo()
        raw = metadata(g)
        for a,b,reason in ((False, True, 'NETWORK_NOT_AUTHORIZED'),
                           (True, False, 'LOCAL_GIT_NOT_AUTHORIZED')):
            with self.subTest(reason=reason):
                out, tx = self.call(g, raw, network=a, local=b)
                self.assertEqual(out['reason_code'], reason)
                self.assertEqual(tx.urls, [])

    def test_pin_head_drift_refused_without_local_mapping(self):
        g = self.repo()
        raw = metadata(g)
        pin, recent = chain(raw, 'gitlab')
        changed = copy.deepcopy(raw)
        changed['sha'] = g.first
        changed['diff_refs']['head_sha'] = g.first
        out, tx = self.call(g, changed, prior=pin, recent=recent)
        self.assertIn('CURRENT_PROVIDER_IDENTITY_DRIFT_', out['reason_code'])
        self.assertEqual(len(tx.urls), 1)

    def test_file_count_drift_refused(self):
        g = self.repo()
        raw = metadata(g)
        pin, recent = chain(raw, 'gitlab')
        changed = copy.deepcopy(raw)
        changed['changes_count'] = '4'
        out, _ = self.call(g, changed, prior=pin, recent=recent)
        self.assertEqual(out['reason_code'], 'CURRENT_PROVIDER_FILE_COUNT_DRIFT')

    def test_stale_ec166_evidence_denied_before_network(self):
        g = self.repo()
        raw = metadata(g)
        pin, recent = chain(raw, 'gitlab')
        expired = copy.deepcopy(recent)
        expired['current_observation']['observed_at_utc'] = (
            datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        out, tx = self.call(g, raw, prior=pin, recent=expired)
        self.assertEqual(out['reason_code'], 'EC166_OBSERVATION_EXPIRED')
        self.assertEqual(tx.urls, [])

    def test_local_git_must_be_selected_root(self):
        g = self.repo()
        child = g.root / 'child'
        child.mkdir()
        out, _ = self.call(g, metadata(g), repository=str(child))
        self.assertEqual(out['reason_code'], 'LOCAL_GIT_REPOSITORY_SCOPE_MISMATCH')

    def test_same_paths_but_different_blob_content_is_unknown(self):
        g = self.repo()
        g.git('checkout', '-q', '-b', 'altered', g.target)
        (g.root / 'feature-one.txt').write_text('AN UNRELATED VERSION', encoding='utf-8')
        (g.root / 'feature-two.txt').write_text('second feature', encoding='utf-8')
        g.git('add', '.')
        g.git('commit', '-q', '-m', 'unrelated same-path edit')
        altered = g.sha()
        raw = metadata(g)
        raw['squash_commit_sha'] = altered
        raw['merge_commit_sha'] = altered
        out, _ = self.call(g, raw)
        self.assertEqual(out['reason_code'], 'SOURCE_TO_TARGET_NET_BLOB_DELTA_MISMATCH')

    def test_missing_changed_blob_never_yields_positive(self):
        g = self.repo()
        blob = g.git('rev-parse', g.head + ':feature-one.txt')
        loose = g.root / '.git' / 'objects' / blob[:2] / blob[2:]
        self.assertTrue(loose.exists())
        loose.unlink()   # disposable fixture only, simulates incomplete clone
        out, _ = self.call(g, metadata(g))
        self.assertIn(out['reason_code'],
                      ('LOCAL_CHANGE_BLOBS_UNAVAILABLE', 'LOCAL_TREE_DELTA_UNAVAILABLE_OR_TOO_LARGE'))
        self.assertEqual(out['association_state'], 'UNAVAILABLE_UNKNOWN')

    def test_gitlab_start_sha_cannot_change_diff_version_scope(self):
        g = self.repo()
        raw = metadata(g)
        raw['diff_refs']['start_sha'] = g.first   # base between head/start is now first
        out, _ = self.call(g, raw)
        self.assertEqual(out['reason_code'], 'GITLAB_PINNED_DIFF_BASE_MISMATCH')

    def test_submodule_pointer_is_not_accepted_as_blob_equivalence(self):
        g = self.repo()
        g.git('checkout', '-q', '-b', 'gitlink-test', g.base)
        g.git('update-index', '--add', '--cacheinfo', f'160000,{g.first},submodule')
        g.git('commit', '-q', '-m', 'submodule reference')
        src_tree = g.git('rev-parse', g.base + '^{tree}')
        dst_tree = g.git('rev-parse', 'HEAD^{tree}')
        with self.assertRaises(linear.Unknown) as error:
            linear._raw_delta(g.root, src_tree, dst_tree, 40)
        self.assertEqual(error.exception.reason, 'SUBMODULE_CONTENT_EQUIVALENCE_UNPROVEN')

    def test_no_merge_sha_and_non_squash_cannot_imply_delivery(self):
        g = self.repo('fast-forward')
        raw = metadata(g, kind='fast-forward')
        raw['merge_commit_sha'] = None
        out, _ = self.call(g, raw)
        self.assertEqual(out['reason_code'], 'MERGE_COMMIT_SHA_NOT_REPORTED')
        self.assertFalse(out['local_association_verified'])

    def test_unmerged_github_test_merge_sha_not_used(self):
        g = self.repo()
        raw = metadata(g, 'github')
        raw['state'], raw['merged'] = 'open', False
        out, tx = self.call(g, raw, provider='github')
        self.assertEqual(out['reason_code'], 'EC162_PROVIDER_NOT_MERGED')
        self.assertEqual(tx.urls, [])

    def test_inherited_adapter_default_and_ec167_opt_in_unchanged(self):
        g = self.repo()
        raw = metadata(g)
        raw_result = source.fetch_proposed_pr(
            key(), allow_network=True, transport=Transport(raw),
            token_supplier=lambda: 'TOKEN')
        prior_result = source.fetch_proposed_pr(
            key(), allow_network=True, transport=Transport(raw),
            token_supplier=lambda: 'TOKEN', include_merge_commit_claim=True)
        latest = source.fetch_proposed_pr(
            key(), allow_network=True, transport=Transport(raw),
            token_supplier=lambda: 'TOKEN', include_merge_commit_claim=True,
            include_squash_claim=True)
        self.assertNotIn('provider_squash_commit_sha', raw_result['source'])
        self.assertNotIn('provider_squash_commit_sha', prior_result['source'])
        self.assertEqual(prior_result['source']['provider_merge_commit_sha'], g.squash)
        self.assertEqual(latest['source']['provider_squash_commit_sha'], g.squash)
        self.assertTrue(latest['source']['provider_squash_on_merge'])


if __name__ == '__main__':
    unittest.main()
