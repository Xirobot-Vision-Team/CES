#!/usr/bin/env python3
"""EC229 focused disposable *real local Git* behavior with synthetic keys.

No real organization PKI, customer repository, remote account, network push,
human privacy approval or platform acceptance is implied by these tests.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

import delivery_authorization as da
import delivery_preview as dp
import docs_only_publish as pub

BASE = Path(__file__).resolve().parent.parent
RESULT_SCHEMA = json.loads(
    (BASE / "references" / "docs-only-publish-result.v1.schema.json").read_text())
Draft202012Validator.check_schema(RESULT_SCHEMA)
VALIDATOR = Draft202012Validator(RESULT_SCHEMA)


def public_key(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def signed(key, domain, doc):
    return da.SignedAuthorizationStatement(
        copy.deepcopy(doc), key.sign(domain + dp.canonical(doc)).hex())


def cmd(*argv, cwd=None):
    p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False,
                       env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1",
                            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"})
    if p.returncode:
        raise RuntimeError((argv, p.returncode, p.stderr[:1000]))
    return p.stdout.strip()


class DocsOnlyGitCases(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ces-ec229-local-git-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.repo = root / "repo"
        self.work = root / "worktrees"
        self.journal = root / "journal"
        self.bare = root / "bare-sandbox.git"
        for d in (self.repo, self.work, self.journal, self.bare):
            d.mkdir(mode=0o700)
        cmd("git", "init", "-q", str(self.repo))
        cmd("git", "init", "--bare", "-q", str(self.bare))
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "guide.md").write_text("# Existing guide\n")
        (self.repo / "source").mkdir()
        (self.repo / "source" / "service.py").write_text("print('unchanged')\n")
        (self.repo / ".github" / "workflows").mkdir(parents=True)
        (self.repo / ".github" / "workflows" / "ci.yml").write_text("name: CI\n")
        (self.repo / "schemas").mkdir()
        (self.repo / "schemas" / "record.json").write_text('{"unchanged":true}\n')
        cmd("git", "add", "--all", cwd=self.repo)
        cmd("git", "-c", "user.name=Test Fixture", "-c",
            "user.email=test@invalid.example", "commit", "-qm", "approved baseline",
            cwd=self.repo)
        self.head = cmd("git", "rev-parse", "HEAD", cwd=self.repo)
        self.keys = [Ed25519PrivateKey.generate() for _ in range(4)]
        self.roots = pub.DocsTrustRoots(
            "docs_issuer_229", "docs_operator_229", "proj_docs_test_229",
            "repo_docs_test_229", *(public_key(k) for k in self.keys),
            minimum_policy_epoch=7)
        self.paths = ("docs/releases/notice.md", "docs/releases/summary.md")
        self.access = pub.HostDocsScope(
            self.roots, str(self.repo), self.head, self.paths,
            str(self.work), str(self.journal), str(self.bare),
            "/usr/bin/git", True)
        # In this image the system git may live outside /usr/bin.
        actual_git = cmd("which", "git")
        self.access = replace(self.access, git_executable=actual_git)
        self.publisher = pub.DocsOnlyPublisher(self.access)
        self.now = int(time.time())
        self.raw = b"# Safe private release notes\n\nThis is a new documentation file.\n"
        self.doc = pub.ReviewedDocument(
            self.paths[0], base64.b64encode(self.raw).decode("ascii"),
            hashlib.sha256(self.raw).hexdigest())
        self.request = self.make_request()

    def make_request(self, *, doc=None, nonce="a" * 32, epoch=7,
                     signer_keys=None, policy_changes=None,
                     review_changes=None, revoke_changes=None, grant_changes=None):
        doc = doc or self.doc
        keys = signer_keys or self.keys
        m = [{"relative_path": doc.relative_path, "sha256": doc.content_sha256,
              "size_bytes": len(base64.b64decode(doc.content_b64))}]
        mhash = dp.sha(pub.MANIFEST_DOMAIN, m)
        t = self.now
        policy = {
            "schema": pub.POLICY_SCHEMA, "issuer_id": self.roots.issuer_id,
            "project_id": self.roots.project_id, "repository_id": self.roots.repository_id,
            "base_commit": self.head,
            "repo_binding_sha256": self.publisher._repo_binding,
            "target_binding_sha256": self.publisher._target_binding,
            "allowlist_sha256": self.publisher._allowlist,
            "policy_epoch": epoch, "privacy": pub.PRIVACY,
            "issued_at": t - 2, "expires_at": t + 70,
        }
        review = {
            "schema": pub.REVIEW_SCHEMA, "project_id": self.roots.project_id,
            "repository_id": self.roots.repository_id, "base_commit": self.head,
            "manifest_sha256": mhash, "reviewer_id": "private_reviewer_229",
            "review_state": "HUMAN_REVIEWED_EXACT_NEW_DOCS_BYTES",
            "privacy": pub.PRIVACY, "issued_at": t - 2, "expires_at": t + 70,
        }
        revoke = {
            "schema": pub.REVOKE_SCHEMA, "project_id": self.roots.project_id,
            "repository_id": self.roots.repository_id, "grant_nonce": nonce,
            "policy_epoch": epoch, "state": "ACTIVE",
            "issued_at": t - 1, "expires_at": t + 14,
        }
        policy.update(policy_changes or {})
        review.update(review_changes or {})
        revoke.update(revoke_changes or {})
        grant = {
            "schema": pub.GRANT_SCHEMA, "issuer_id": self.roots.issuer_id,
            "operator_id": self.roots.operator_id,
            "project_id": self.roots.project_id,
            "repository_id": self.roots.repository_id,
            "base_commit": self.head, "manifest_sha256": mhash,
            "repo_binding_sha256": self.publisher._repo_binding,
            "target_binding_sha256": self.publisher._target_binding,
            "allowlist_sha256": self.publisher._allowlist,
            "repository_policy_sha256": hashlib.sha256(dp.canonical(policy)).hexdigest(),
            "content_review_sha256": hashlib.sha256(dp.canonical(review)).hexdigest(),
            "revocation_sha256": hashlib.sha256(dp.canonical(revoke)).hexdigest(),
            "trust_roots_sha256": self.publisher._roots,
            "code_revision_sha256": pub.ACTIVE_CODE_SHA256,
            "grant_nonce": nonce, "policy_epoch": epoch, "action": pub.ACTION,
            "issued_at": t - 2, "expires_at": t + 25,
        }
        grant.update(grant_changes or {})
        return pub.DocsOnlyPublishRequest(
            (doc,), signed(keys[0], pub.POLICY_DOMAIN, policy),
            signed(keys[1], pub.REVIEW_DOMAIN, review),
            signed(keys[2], pub.REVOKE_DOMAIN, revoke),
            signed(keys[3], pub.GRANT_DOMAIN, grant), True)

    def result(self, req=None):
        value = self.publisher.publish_once(req or self.request)
        self.assertEqual(list(VALIDATOR.iter_errors(value)), [])
        return value

    def assert_refusal_without_side_effect(self, result):
        self.assertNotEqual(result["status"], "partial")
        self.assertFalse(result["claim_committed"])
        self.assertFalse(result["private_push_attempted"])
        self.assertEqual(list(self.journal.iterdir()), [])
        self.assertEqual(list(self.work.iterdir()), [])

    def test_real_git_docs_only_private_new_branch_and_source_unchanged(self):
        result = self.result()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["local_candidate_state"], "PRIVATE_LOCAL_REF_OBSERVED_ONCE")
        self.assertFalse(result["published"])
        self.assertFalse(result["production_or_public_published"])
        self.assertTrue(result["original_repository_intact_verified"])
        self.assertEqual(cmd("git", "rev-parse", "HEAD", cwd=self.repo), self.head)
        self.assertEqual(cmd("git", "status", "--porcelain", cwd=self.repo), "")
        self.assertEqual((self.repo / "docs" / "guide.md").read_text(), "# Existing guide\n")
        self.assertFalse((self.repo / self.doc.relative_path).exists())
        ref = result["private_sandbox_ref"]
        candidate = result["local_candidate_commit_sha"]
        self.assertEqual(cmd("git", "rev-parse", ref, cwd=self.bare), candidate)
        self.assertEqual(cmd("git", "show", candidate + ":" + self.doc.relative_path,
                             cwd=self.bare), self.raw.decode().strip())
        self.assertEqual(cmd("git", "diff", "--name-status", self.head, candidate,
                             cwd=self.bare), "A\tdocs/releases/notice.md")
        self.assertEqual(cmd("git", "rev-list", "--parents", "-n", "1", candidate,
                             cwd=self.bare), candidate + " " + self.head)
        self.assertEqual(len(list(self.journal.iterdir())), 1)
        markers = sorted(p.name for p in next(self.journal.iterdir()).iterdir())
        self.assertEqual(len(markers), 8)
        self.assertEqual(len(list(self.work.iterdir())), 1)

    def test_original_operation_replay_forbidden_after_success(self):
        self.assertEqual(self.result()["status"], "partial")
        later = self.result()
        self.assertEqual(later["reason_code"],
                         "DOCS_ONLY_SANDBOX_REF_ALREADY_EXISTS_NO_OVERWRITE")
        self.assertEqual(len(list(self.work.iterdir())), 1)

    def test_new_signed_nonce_same_exact_operation_no_republish(self):
        self.assertEqual(self.result()["status"], "partial")
        later = self.result(self.make_request(nonce="b" * 32))
        self.assertEqual(later["reason_code"],
                         "DOCS_ONLY_SANDBOX_REF_ALREADY_EXISTS_NO_OVERWRITE")
        self.assertEqual(len(list(self.work.iterdir())), 1)

    def test_consent_denied(self):
        self.assert_refusal_without_side_effect(
            self.result(replace(self.request,
                                explicitly_approve_exact_docs_only_local_publish=False)))

    def test_host_publication_flag_denied(self):
        host = replace(self.access, enable_private_local_sandbox_publish=False)
        self.publisher = pub.DocsOnlyPublisher(host)
        self.assert_refusal_without_side_effect(self.result())

    def test_mutated_reviewer_signature_denied(self):
        bad = copy.deepcopy(self.request.content_review.statement)
        bad["review_state"] = "AUTOMATED_NOT_REVIEWED"
        self.assert_refusal_without_side_effect(
            self.result(replace(self.request,
                                content_review=da.SignedAuthorizationStatement(
                                    bad, self.request.content_review.signature_hex))))

    def test_missing_distinct_signer_denied_at_configuration(self):
        keys = self.keys
        roots = replace(self.roots,
                        revocation_public_key=public_key(keys[1]))
        with self.assertRaises(pub.DocsDenied):
            pub.DocsOnlyPublisher(replace(self.access, roots=roots))

    def test_report_publish_grant_cannot_be_reused(self):
        self.assert_refusal_without_side_effect(
            self.result(self.make_request(grant_changes={"action": "PUBLISH_REPORT"})))

    def test_stale_revocation_denied(self):
        self.assert_refusal_without_side_effect(
            self.result(self.make_request(revoke_changes={
                "issued_at": self.now - 200, "expires_at": self.now - 100})))

    def test_revoked_grant_denied(self):
        self.assert_refusal_without_side_effect(
            self.result(self.make_request(revoke_changes={"state": "REVOKED"})))

    def test_policy_epoch_drift_denied(self):
        self.assert_refusal_without_side_effect(
            self.result(self.make_request(policy_changes={"policy_epoch": 8})))

    def test_changed_content_with_old_review_denied(self):
        other = replace(self.doc, content_b64=base64.b64encode(b"# Changed\n").decode())
        self.assert_refusal_without_side_effect(
            self.result(replace(self.request, documents=(other,))))

    def test_hash_mismatch_rejected(self):
        doc = replace(self.doc, content_sha256="0" * 64)
        self.assert_refusal_without_side_effect(
            self.result(self.make_request(doc=doc)))

    def test_not_allowlisted_source_code_rejected(self):
        doc = replace(self.doc, relative_path="source/service.py")
        self.assert_refusal_without_side_effect(
            self.result(self.make_request(doc=doc)))

    def test_ci_schema_and_traversal_paths_rejected(self):
        for path in (".github/workflows/push.md", "schemas/thing.md",
                     "docs/../source/escape.md", "docs\\evil.md",
                     "docs//release.md", "docs/releases/.hidden.md"):
            with self.subTest(path=path):
                doc = replace(self.doc, relative_path=path)
                self.assert_refusal_without_side_effect(
                    self.result(self.make_request(doc=doc)))

    def test_existing_file_overwrite_refused_before_claim(self):
        path = "docs/guide.md"
        self.publisher = pub.DocsOnlyPublisher(replace(
            self.access, allowed_exact_paths=(path,)))
        doc = replace(self.doc, relative_path=path)
        result = self.result(self.make_request(doc=doc))
        self.assertEqual(result["reason_code"], "DOCS_ONLY_DOC_PATH_EXISTS_OR_OVERWRITES_TREE")
        self.assert_refusal_without_side_effect(result)

    def test_dirty_worktree_denied(self):
        (self.repo / "source" / "service.py").write_text("changed!\n")
        self.assert_refusal_without_side_effect(self.result())

    def test_untracked_original_file_denied(self):
        (self.repo / "new_script.sh").write_text("#!/bin/sh\n")
        self.assert_refusal_without_side_effect(self.result())

    def test_approved_head_moved_denied(self):
        (self.repo / "CHANGELOG.md").write_text("New baseline\n")
        cmd("git", "add", "CHANGELOG.md", cwd=self.repo)
        cmd("git", "-c", "user.name=Test Fixture", "-c",
            "user.email=test@invalid.example", "commit", "-qm", "moved",
            cwd=self.repo)
        self.assert_refusal_without_side_effect(self.result())

    def test_path_symlink_in_original_base_denied(self):
        (self.repo / "source" / "payload").symlink_to("/etc/passwd")
        cmd("git", "add", "--all", cwd=self.repo)
        cmd("git", "-c", "user.name=Test Fixture", "-c",
            "user.email=test@invalid.example", "commit", "-qm", "unsafe",
            cwd=self.repo)
        head = cmd("git", "rev-parse", "HEAD", cwd=self.repo)
        self.access = replace(self.access, approved_base_commit=head)
        self.publisher = pub.DocsOnlyPublisher(self.access)
        self.head = head
        self.assert_refusal_without_side_effect(self.result(self.make_request()))

    def test_dangerous_git_filter_config_refused(self):
        cmd("git", "config", "--local", "filter.evil.clean", "sh -c 'echo hi'",
            cwd=self.repo)
        self.assert_refusal_without_side_effect(self.result())

    def test_sandbox_hook_disallowed(self):
        hook = self.bare / "hooks" / "pre-receive"
        hook.write_text("#!/bin/sh\nexit 0\n")
        hook.chmod(0o700)
        self.assert_refusal_without_side_effect(self.result())

    def test_source_change_during_worktree_preparation_fails_closed(self):
        real = self.publisher._source_ready
        n = [0]
        def drift(docs):
            n[0] += 1
            if n[0] == 2:
                (self.repo / "source" / "service.py").write_text("raced\n")
            return real(docs)
        with patch.object(self.publisher, "_source_ready", side_effect=drift):
            result = self.result()
        self.assertFalse(result["private_push_attempted"])
        self.assertTrue(result["claim_committed"])
        self.assertFalse(result["private_sandbox_ref_observed"])
        self.assertEqual(len(list(self.journal.iterdir())), 1)

    def test_failed_push_unknown_no_retry_and_original_is_clean(self):
        runner = self.publisher.git.run
        def failing_push(cwd, *args, **kw):
            if args and args[0] == "push":
                raise pub.DocsDenied("SYNTHETIC_PRIVATE_PUSH_UNKNOWN", "unavailable")
            return runner(cwd, *args, **kw)
        with patch.object(self.publisher.git, "run", side_effect=failing_push):
            result = self.result()
        self.assertEqual(result["local_candidate_state"], "UNKNOWN_AFTER_EFFECT")
        self.assertTrue(result["claim_committed"])
        self.assertTrue(result["local_commit_created"])
        self.assertTrue(result["private_push_attempted"])
        self.assertFalse(result["private_sandbox_ref_observed"])
        self.assertEqual(cmd("git", "status", "--porcelain", cwd=self.repo), "")
        self.assertFalse(self.result()["private_push_attempted"])

    def test_private_journal_replay_no_new_remote_even_when_ref_missing(self):
        runner = self.publisher.git.run
        with patch.object(self.publisher.git, "run", side_effect=lambda cwd, *args, **kw:
                          (_ for _ in ()).throw(
                              pub.DocsDenied("SYNTHETIC_TIMEOUT", "unavailable"))
                          if args and args[0] == "push" else runner(cwd, *args, **kw)):
            first = self.result()
        self.assertTrue(first["private_push_attempted"])
        second = self.result()
        self.assertIn("ALREADY_CLAIMED", second["reason_code"])
        self.assertFalse(second["private_push_attempted"])

    def test_permission_code_drift_fails_before_effect(self):
        with patch.object(pub, "_code_sha", return_value="1" * 64):
            self.assert_refusal_without_side_effect(self.result())


    def test_normal_origin_remote_config_not_used_or_pushed(self):
        cmd("git", "remote", "add", "origin",
            "https://production.example.invalid/no-network.git", cwd=self.repo)
        result = self.result()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["effects"]["production_network_or_remote_requested"], False)
        self.assertEqual(cmd("git", "remote", "-v", cwd=self.repo).splitlines()[0].split()[0],
                         "origin")

    def test_new_private_ref_cannot_overwrite_any_existing_ref(self):
        contents, checked = self.publisher._verify(self.request, int(time.time()))
        operation = dp.sha(pub.OP_DOMAIN, {
            "repository_id": self.roots.repository_id,
            "project_id": self.roots.project_id,
            "base_commit": self.head,
            "manifest_sha256": checked["manifest_sha256"],
            "private_target_sha256": self.publisher._target_binding,
        })
        ref = pub.REF_NAMESPACE + operation
        cmd("git", "fetch", "-q", str(self.repo), self.head, cwd=self.bare)
        cmd("git", "update-ref", ref, self.head, cwd=self.bare)
        result = self.result()
        self.assertEqual(result["reason_code"],
                         "DOCS_ONLY_SANDBOX_REF_ALREADY_EXISTS_NO_OVERWRITE")
        self.assertEqual(cmd("git", "rev-parse", ref, cwd=self.bare), self.head)
        self.assert_refusal_without_side_effect(result)

    def test_obvious_secret_content_fail_closed_before_checkout(self):
        raw = b"api_key = supersecretcredentialvalue0123456789\n"
        doc = pub.ReviewedDocument(self.paths[0],
                                   base64.b64encode(raw).decode("ascii"),
                                   hashlib.sha256(raw).hexdigest())
        self.assert_refusal_without_side_effect(
            self.result(self.make_request(doc=doc)))

    def test_private_sandbox_must_live_outside_original_repository(self):
        nested = self.repo / "private-target"
        nested.mkdir(mode=0o700)
        with self.assertRaises(pub.DocsDenied):
            pub.DocsOnlyPublisher(replace(self.access, sandbox_bare_root=str(nested)))


if __name__ == "__main__":
    unittest.main()
