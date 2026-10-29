#!/usr/bin/env python3
"""EC229: independently authorized DocsOnlyPublish into a private local Git sandbox.

The original Git worktree/index/branch and all production remotes are read-only.
Only signed, *new* exact-allowlisted Markdown paths enter a detached, private
linked worktree. An explicitly separate local bare sandbox receives one new
operation-namespaced ref using an absent-ref lease; never an existing ref.

This is not a public release, remote receipt, merge, source edit, or native
PowerShell action. Crash/UNKNOWN claims are never retried or auto-cleaned.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from typing import Any

try:
    from . import delivery_authorization as da, delivery_preview as dp
except ImportError:
    import delivery_authorization as da
    import delivery_preview as dp

SCHEMA = "ces.docs_only_publish.v1"
POLICY_SCHEMA = "ces.docs_only_publish.repository_policy.v1"
REVIEW_SCHEMA = "ces.docs_only_publish.content_review.v1"
REVOKE_SCHEMA = "ces.docs_only_publish.current_revocation.v1"
GRANT_SCHEMA = "ces.docs_only_publish.one_use_grant.v1"

POLICY_DOMAIN = b"CES-EC229-DOCS-ONLY-REPOSITORY-POLICY-v1\0"
REVIEW_DOMAIN = b"CES-EC229-DOCS-ONLY-INDEPENDENT-REVIEW-v1\0"
REVOKE_DOMAIN = b"CES-EC229-DOCS-ONLY-CURRENT-REVOCATION-v1\0"
GRANT_DOMAIN = b"CES-EC229-DOCS-ONLY-ONE-USE-GRANT-v1\0"
ROOT_DOMAIN = b"CES-EC229-FOUR-INDEPENDENT-HOST-KEYS-v1\0"
REPO_DOMAIN = b"CES-EC229-EXACT-LOCAL-REPOSITORY-v1\0"
TARGET_DOMAIN = b"CES-EC229-PRIVATE-OFFLINE-SANDBOX-TARGET-v1\0"
MANIFEST_DOMAIN = b"CES-EC229-REVIEWED-DOC-PATH-CONTENT-v1\0"
OP_DOMAIN = b"CES-EC229-ONE-REPO-COMMIT-AND-CONTENT-OPERATION-v1\0"
CODE_DOMAIN = b"CES-EC229-CODE-AND-SIGNATURE-HELPERS-v1\0"
PRIVACY = "INTERNAL_PRIVATE_LOCAL_SANDBOX"
ACTION = "CREATE_DOCS_ONLY_ISOLATED_COMMIT_AND_PRIVATE_NEW_REF_ONCE"
REF_NAMESPACE = "refs/heads/ces-docs-private/"

MAX_FILES = 8
MAX_FILE_BYTES = 65536
MAX_DOC_BYTES = 262144
MAX_TREE_FILES = 8000
MAX_TREE_BYTES = 128 * 1024 * 1024
MAX_GIT_OUTPUT = 3 * 1024 * 1024
MAX_SOURCE_INDEX_BYTES = 16 * 1024 * 1024
MAX_GIT_SECONDS = 18
MAX_SKEW = 5
MAX_GRANT_AGE = 45
MAX_REVOKE_AGE = 30

SHA256 = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
GIT_SHA = re.compile(r"[a-f0-9]{40}\Z", re.ASCII)
NONCE = re.compile(r"[a-f0-9]{32}\Z", re.ASCII)
IDENT = re.compile(r"[a-z][a-z0-9_-]{7,63}\Z", re.ASCII)
REPO_ID = re.compile(r"repo_[a-z0-9_-]{8,63}\Z", re.ASCII)
PROJECT = re.compile(r"proj_[a-z0-9_-]{8,63}\Z", re.ASCII)
DOC_PATH = re.compile(r"docs/(?:[a-z0-9_-]+/)*[a-z0-9_-]+\.md\Z", re.ASCII)
TREE_ITEM = re.compile(rb"(100644|100755|120000|160000) (blob|commit) ([a-f0-9]{40}) +([0-9]+|-)\t(.+)\Z")
CREDENTIAL = (
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I),
    re.compile(rb"(?i)authorization\s*:\s*bearer\s+\S+"),
    re.compile(rb"(?i)(?:api[_-]?key|secret[_-]?token)\s*[:=]\s*[\w-]{16,}"),
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_sha(value: Any) -> str:
    return _sha(dp.canonical(value))


def _is_sha(value: Any) -> bool:
    return type(value) is str and SHA256.fullmatch(value) is not None


def _code_sha() -> str | None:
    try:
        here = Path(__file__).resolve().parent
        hashes = {n: _sha((here / n).read_bytes())
                  for n in ("docs_only_publish.py", "delivery_authorization.py",
                            "delivery_preview.py")}
        return dp.sha(CODE_DOMAIN, hashes)
    except (OSError, ValueError, TypeError):
        return None


# The signer must pin the actual running code, not an arbitrary claimed version.
ACTIVE_CODE_SHA256 = _code_sha()


class DocsDenied(ValueError):
    def __init__(self, code: str, status: str = "blocked"):
        super().__init__(code)
        self.code, self.status = code, status


def need(condition: bool, code: str, status: str = "blocked") -> None:
    if not condition:
        raise DocsDenied(code, status)


def _current_time() -> int:
    now = time.time()
    need(type(now) in (float, int) and math.isfinite(now) and
         946684800 <= now <= 4102444800,
         "TRUSTED_CLOCK_UNAVAILABLE", "unavailable")
    return int(now)


def _window(doc: dict[str, Any], now: int, maximum: int, name: str) -> None:
    start, end = doc.get("issued_at"), doc.get("expires_at")
    need(type(start) is int and type(end) is int and
         946684800 <= start < end <= 4102444800 and
         end - start <= maximum and
         now - maximum <= start <= now + MAX_SKEW and now < end,
         name + "_EXPIRED_OR_NOT_CURRENT")


def _signed(item: Any, key: bytes, domain: bytes,
            fields: set[str], name: str) -> dict[str, Any]:
    try:
        doc, sig = da._snapshot_signed(item, name)
        da.exact(doc, fields, name + "_FIELDS_INVALID")
        da._verify_signature(key, domain, doc, sig, name)
        return doc
    except da.AuthorizationDenied as exc:
        raise DocsDenied(exc.code, exc.status) from None


def _safe_path(value: Any) -> bool:
    return type(value) is str and len(value) <= 180 and DOC_PATH.fullmatch(value) is not None \
        and all(s not in {"con", "prn", "aux", "nul", "com1", "lpt1"}
                for s in value.removesuffix(".md").split("/"))


def _safe_directory(path: Any, *, private: bool = True) -> tuple[str, tuple[int, int]]:
    """Existing, real, owner-controlled directory, without symlink ancestors."""
    need(type(path) is str and path.startswith("/") and len(path) < 2048 and
         os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
         "PINNED_POSIX_ABSOLUTE_DIRECTORY_REQUIRED", "unavailable")
    p = Path(path)
    try:
        need(not any(x.is_symlink() for x in (p, *p.parents)),
             "SYMLINK_DIRECTORY_ANCESTOR", "unavailable")
        st = os.lstat(path)
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
             (not private or stat.S_IMODE(st.st_mode) & 0o077 == 0),
             "OWNER_PRIVATE_DIRECTORY_REQUIRED", "unavailable")
        return str(p.resolve(strict=True)), (st.st_dev, st.st_ino)
    except (OSError, ValueError, TypeError, RuntimeError):
        raise DocsDenied("HOST_DIRECTORY_NOT_VERIFIABLE", "unavailable") from None


def _file_identity(path: str) -> tuple[int, int, str]:
    try:
        st = os.lstat(path)
        need(stat.S_ISREG(st.st_mode) and not os.path.islink(path),
             "PINNED_GIT_EXECUTABLE_INVALID", "unavailable")
        return st.st_dev, st.st_ino, _sha(Path(path).read_bytes())
    except (OSError, ValueError):
        raise DocsDenied("PINNED_GIT_EXECUTABLE_UNAVAILABLE", "unavailable") from None


@dataclass(frozen=True)
class DocsTrustRoots:
    issuer_id: str
    operator_id: str
    project_id: str
    repository_id: str
    policy_public_key: bytes
    reviewer_public_key: bytes
    revocation_public_key: bytes
    side_effect_public_key: bytes
    minimum_policy_epoch: int


@dataclass(frozen=True)
class HostDocsScope:
    roots: DocsTrustRoots
    repository_root: str
    approved_base_commit: str
    allowed_exact_paths: tuple[str, ...]
    worktree_root: str
    journal_root: str
    sandbox_bare_root: str
    git_executable: str
    enable_private_local_sandbox_publish: bool


@dataclass(frozen=True)
class ReviewedDocument:
    relative_path: str
    content_b64: str
    content_sha256: str


@dataclass(frozen=True)
class DocsOnlyPublishRequest:
    documents: tuple[ReviewedDocument, ...]
    repository_policy: da.SignedAuthorizationStatement
    content_review: da.SignedAuthorizationStatement
    current_revocation: da.SignedAuthorizationStatement
    one_use_grant: da.SignedAuthorizationStatement
    explicitly_approve_exact_docs_only_local_publish: bool


def _refused(code: str, status: str, *, operation: str | None = None,
             claimed: bool = False, worktree: bool = False, committed: bool = False,
             pushed: bool = False) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "status": status,
        "exit_code": {"blocked": 4, "invalid_input": 4,
                      "unavailable": 5, "partial": 2}.get(status, 5),
        "reason_code": "DOCS_ONLY_" + code, "operation_id": operation,
        "local_candidate_commit_sha": None, "private_sandbox_ref": None,
        "local_candidate_state": "UNKNOWN_AFTER_EFFECT" if claimed else "NOT_STARTED",
        "claim_committed": claimed, "isolated_worktree_created": worktree,
        "local_commit_created": committed, "private_push_attempted": pushed,
        "private_sandbox_ref_observed": False,
        "original_repository_intact_verified": False,
        "published": False, "production_or_public_published": False,
        "external_publication_confirmed": False, "native_action_registered": False,
        "effects": {
            "original_worktree_or_index_edited": False,
            "business_ci_schema_path_staged": False,
            "existing_ref_overwritten": False,
            "production_network_or_remote_requested": False,
            "private_local_sandbox_ref_write_attempted": pushed,
            "automatic_cleanup_or_retry": False,
        },
    }


class OnceOnlyDocsJournal:
    """Crash-conservative local operation slot; NO deletion, reset, or retry.

    root is pre-existing owner-0700 POSIX local filesystem. Same-UID/NFS/power
    failure or directory snapshot rollback cannot be trusted without host control.
    """
    def __init__(self, root: str):
        self.root = root
        self.parent: int | None = None
        self.slot: int | None = None

    def __enter__(self) -> "OnceOnlyDocsJournal":
        try:
            _safe_directory(self.root)
            self.parent = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            return self
        except (OSError, DocsDenied):
            self.__exit__(None, None, None)
            raise DocsDenied("DOCS_JOURNAL_UNAVAILABLE", "unavailable") from None

    def claim(self, operation: str) -> None:
        need(_is_sha(operation) and self.parent is not None,
             "OPERATION_ID_INVALID", "invalid_input")
        try:
            os.mkdir("ec229-" + operation, 0o700, dir_fd=self.parent)
        except FileExistsError:
            raise DocsDenied("SAME_DOCS_OPERATION_ALREADY_CLAIMED_NO_RETRY") from None
        except OSError:
            raise DocsDenied("DOCS_JOURNAL_CLAIM_FAILED", "unavailable") from None
        try:
            self.slot = os.open("ec229-" + operation,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=self.parent)
            os.fsync(self.slot)
            os.fsync(self.parent)
            self.mark("00_CLAIM_DURABLE")
        except (OSError, DocsDenied):
            raise DocsDenied("DOCS_JOURNAL_CLAIM_DURABILITY_UNKNOWN", "unavailable") from None

    def mark(self, event: str, payload: bytes = b"") -> None:
        need(self.slot is not None and event in {
            "00_CLAIM_DURABLE", "01_WORKTREE_ATTEMPTED", "02_WORKTREE_READY",
            "03_DOCS_WRITTEN", "04_COMMIT_ATTEMPTED", "05_COMMIT_CREATED",
            "06_PUSH_ATTEMPTED", "07_SANDBOX_REF_OBSERVED",
        } and type(payload) is bytes and len(payload) <= 1024,
             "DOCS_JOURNAL_MARKER_INVALID", "unavailable")
        try:
            fd = os.open(event, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self.slot)
            try:
                if payload:
                    need(os.write(fd, payload) == len(payload),
                         "DOCS_JOURNAL_MARKER_PARTIAL", "unavailable")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(self.slot)
        except (OSError, DocsDenied):
            raise DocsDenied("DOCS_JOURNAL_WRITE_DURABILITY_UNKNOWN", "unavailable") from None

    def __exit__(self, *_: Any) -> None:
        for fd in (self.slot, self.parent):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self.slot = self.parent = None


class RestrictedGit:
    """Only local Git builtins, clean configuration and bounded subprocesses.

    No Git environment inheritance, shell, optional locking, host/network
    protocol, branch checkout, hooks, pager, git aliases, arbitrary refspec.
    """
    def __init__(self, executable: str, private_home: str):
        self.executable, self.home = executable, private_home
        self.identity = _file_identity(executable)

    def run(self, cwd: str, *arguments: str, ok: tuple[int, ...] = (0,),
            limit: int = MAX_GIT_OUTPUT) -> tuple[int, bytes]:
        cmd = [self.executable,
               "-c", "core.hooksPath=/dev/null",
               "-c", "core.fsmonitor=false",
               "-c", "core.untrackedCache=false",
               "-c", "core.autocrlf=false",
               "-c", "core.protectNTFS=true",
               "-c", "core.protectHFS=true",
               "-c", "maintenance.auto=false",
               "-c", "gc.auto=0",
               "-c", "protocol.allow=never",
               "-c", "protocol.file.allow=always",
               "-C", cwd, *arguments]
        env = {
            "HOME": self.home, "PATH": "/usr/bin:/bin", "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_PAGER": "cat", "GIT_AUTHOR_NAME": "CES Docs Sandbox",
            "GIT_AUTHOR_EMAIL": "docs-sandbox@invalid.example",
            "GIT_COMMITTER_NAME": "CES Docs Sandbox",
            "GIT_COMMITTER_EMAIL": "docs-sandbox@invalid.example",
        }
        try:
            output = subprocess.run(
                cmd, input=b"", capture_output=True, timeout=MAX_GIT_SECONDS,
                check=False, env=env, cwd="/")
        except (OSError, subprocess.TimeoutExpired, ValueError):
            raise DocsDenied("GIT_PROCESS_UNAVAILABLE_OR_TIMEOUT", "unavailable") from None
        need(len(output.stdout) <= limit and len(output.stderr) <= 4096,
             "GIT_OUTPUT_LIMIT", "unavailable")
        if output.returncode not in ok:
            raise DocsDenied("GIT_COMMAND_REFUSED", "unavailable")
        return output.returncode, output.stdout

    def text(self, cwd: str, *args: str, ok: tuple[int, ...] = (0,)) -> str:
        return self.run(cwd, *args, ok=ok)[1].decode("ascii", "strict").strip()

    def safe_config(self, path: str) -> None:
        """Reject dynamic Git behavior, including include/rewrites/filters/hooks."""
        _, data = self.run(path, "config", "--local", "--no-includes",
                           "--null", "--list", limit=131072)
        for item in data.split(b"\0"):
            if not item:
                continue
            name = item.split(b"\n", 1)[0].decode("ascii", "strict").lower()
            need(not (
                name.startswith(("include.", "includeif.", "url.", "filter.",
                                 "credential.", "submodule.", "alias.", "push."))
                or (name.startswith("remote.") and
                    name.endswith((".promisor", ".partialclonefilter", ".vcs",
                                   ".uploadpack", ".receivepack"))) or
                name in {"extensions.partialclone", "core.hookspath", "core.fsmonitor", "core.worktree",
                            "core.attributesfile", "core.excludesfile",
                            "core.sshcommand", "core.pager", "diff.external",
                            "extensions.worktreeconfig", "core.alternateobjectdirectories"}
            ), "UNSAFE_GIT_REPOSITORY_CONFIGURATION", "unavailable")



class DocsOnlyPublisher:
    """Execute exactly one signed private, offline docs-only publication."""

    def __init__(self, access: HostDocsScope):
        need(type(access) is HostDocsScope and
             type(access.roots) is DocsTrustRoots,
             "EXACT_PINNED_HOST_CONFIGURATION_REQUIRED", "invalid_input")
        self.access = access
        r = access.roots
        keys = (r.policy_public_key, r.reviewer_public_key,
                r.revocation_public_key, r.side_effect_public_key)
        need(all(type(k) is bytes and len(k) == 32 and k != bytes(32)
                 for k in keys) and len(set(keys)) == 4 and
             all(type(x) is str and IDENT.fullmatch(x) is not None
                 for x in (r.issuer_id, r.operator_id)) and
             type(r.project_id) is str and PROJECT.fullmatch(r.project_id) is not None and
             type(r.repository_id) is str and REPO_ID.fullmatch(r.repository_id) is not None and
             type(r.minimum_policy_epoch) is int and
             1 <= r.minimum_policy_epoch < 2**63 and
             type(access.enable_private_local_sandbox_publish) is bool,
             "INDEPENDENT_DOCS_TRUST_ROOTS_REQUIRED", "invalid_input")
        need(type(access.approved_base_commit) is str and
             GIT_SHA.fullmatch(access.approved_base_commit) is not None,
             "PINNED_GIT_COMMIT_REQUIRED", "invalid_input")
        need(type(access.allowed_exact_paths) is tuple and
             1 <= len(access.allowed_exact_paths) <= MAX_FILES and
             all(_safe_path(p) for p in access.allowed_exact_paths) and
             tuple(sorted(set(access.allowed_exact_paths))) == access.allowed_exact_paths,
             "HOST_EXACT_DOCS_ALLOWLIST_REQUIRED", "invalid_input")
        self.repo, self.repo_inode = _safe_directory(access.repository_root,
                                                       private=False)
        self.gitdir, self.gitdir_inode = _safe_directory(
            str(Path(self.repo) / ".git"), private=False)
        self.workroot, self.work_inode = _safe_directory(access.worktree_root)
        self.journalroot, self.journal_inode = _safe_directory(access.journal_root)
        self.bare, self.bare_inode = _safe_directory(access.sandbox_bare_root)
        roots = (self.repo, self.gitdir, self.workroot, self.journalroot, self.bare)
        need(len(set(roots)) == 5 and all(
            not (p == self.repo or p.startswith(self.repo + "/"))
            for p in (self.workroot, self.journalroot, self.bare)) and
            all(not (a.startswith(b + "/") or b.startswith(a + "/"))
                for i, a in enumerate((self.workroot, self.journalroot, self.bare))
                for b in (self.workroot, self.journalroot, self.bare)[i + 1:]),
            "GIT_PUBLICATION_SANDBOX_NOT_ISOLATED", "unavailable")
        need(type(access.git_executable) is str and
             os.path.isabs(access.git_executable),
             "PINNED_GIT_EXECUTABLE_REQUIRED", "unavailable")
        self.git = RestrictedGit(access.git_executable, self.journalroot)
        self._original_baseline: tuple[str, str] | None = None
        self._roots = dp.sha(ROOT_DOMAIN, {
            "issuer_id": r.issuer_id, "operator_id": r.operator_id,
            "repository_id": r.repository_id, "project_id": r.project_id,
            "minimum_policy_epoch": r.minimum_policy_epoch,
            "key_sha256s": [_sha(k) for k in keys],
        })
        self._repo_binding = dp.sha(REPO_DOMAIN, {
            "repository_id": r.repository_id, "project_id": r.project_id,
            "root_path_sha256": _sha(self.repo.encode()),
            "gitdir_path_sha256": _sha(self.gitdir.encode()),
            "root_identity": list(self.repo_inode),
            "gitdir_identity": list(self.gitdir_inode),
            "base_commit": access.approved_base_commit,
        })
        self._target_binding = dp.sha(TARGET_DOMAIN, {
            "worktree_root_sha256": _sha(self.workroot.encode()),
            "journal_root_sha256": _sha(self.journalroot.encode()),
            "bare_root_sha256": _sha(self.bare.encode()),
            "private_inode_pins": [
                list(self.work_inode), list(self.journal_inode), list(self.bare_inode)
            ],
            "new_ref_only": True, "ref_namespace": REF_NAMESPACE,
            "offline_file_protocol_only": True, "production": False,
        })
        self._allowlist = dp.sha(MANIFEST_DOMAIN, {
            "allowed_exact_paths": list(access.allowed_exact_paths),
            "new_files_only": True, "extension": ".md",
        })

    def _host_still_pinned(self) -> None:
        for path, expected, private in (
            (self.repo, self.repo_inode, False),
            (self.gitdir, self.gitdir_inode, False),
            (self.workroot, self.work_inode, True),
            (self.journalroot, self.journal_inode, True),
            (self.bare, self.bare_inode, True),
        ):
            actual, inode = _safe_directory(path, private=private)
            need(actual == path and inode == expected,
                 "PINNED_HOST_DIRECTORY_IDENTITY_DRIFT", "unavailable")
        need(_file_identity(self.git.executable) == self.git.identity,
             "PINNED_GIT_EXECUTABLE_CHANGED", "unavailable")

    def _documents(self, request: DocsOnlyPublishRequest
                   ) -> tuple[dict[str, bytes], list[dict[str, Any]], str]:
        docs = request.documents
        need(type(docs) is tuple and 1 <= len(docs) <= MAX_FILES and
             all(type(d) is ReviewedDocument for d in docs),
             "REVIEWED_DOC_INPUT_REQUIRED", "invalid_input")
        paths = tuple(d.relative_path for d in docs)
        need(tuple(sorted(set(paths))) == paths and
             set(paths).issubset(set(self.access.allowed_exact_paths)) and
             all(_safe_path(p) for p in paths),
             "DOCS_PATH_NOT_EXACTLY_ALLOWLISTED", "invalid_input")
        output: dict[str, bytes] = {}
        manifest: list[dict[str, Any]] = []
        total = 0
        for d in docs:
            need(_is_sha(d.content_sha256) and type(d.content_b64) is str and
                 4 <= len(d.content_b64) <= 4 * ((MAX_FILE_BYTES + 2) // 3),
                 "REVIEWED_DOC_HASH_OR_SIZE_INVALID", "invalid_input")
            try:
                content = base64.b64decode(d.content_b64, validate=True)
                decoded = content.decode("utf-8", "strict")
            except (binascii.Error, UnicodeError, ValueError):
                raise DocsDenied("DOCS_MUST_BE_EXACT_UTF8_BASE64", "invalid_input") from None
            need(0 < len(content) <= MAX_FILE_BYTES and
                 base64.b64encode(content).decode("ascii") == d.content_b64 and
                 _sha(content) == d.content_sha256 and
                 "\x00" not in decoded and "\r" not in decoded and
                 all((ord(ch) >= 32 or ch in "\n\t") and ord(ch) != 127
                     for ch in decoded) and
                 not any(rx.search(content) for rx in CREDENTIAL),
                 "DOCS_CONTENT_PRIVATE_REVIEW_LIMIT_VIOLATION", "invalid_input")
            total += len(content)
            need(total <= MAX_DOC_BYTES, "DOCS_TOTAL_BYTES_LIMIT", "invalid_input")
            output[d.relative_path] = content
            manifest.append({"relative_path": d.relative_path,
                             "sha256": d.content_sha256, "size_bytes": len(content)})
        return output, manifest, dp.sha(MANIFEST_DOMAIN, manifest)

    def _verify(self, request: DocsOnlyPublishRequest,
                now: int) -> tuple[dict[str, bytes], dict[str, Any]]:
        need(type(request) is DocsOnlyPublishRequest and
             request.explicitly_approve_exact_docs_only_local_publish is True and
             self.access.enable_private_local_sandbox_publish is True,
             "EXPLICIT_PRIVATE_DOCS_ONLY_CONSENT_REQUIRED", "unavailable")
        contents, manifest, manifest_sha = self._documents(request)
        r, a = self.access.roots, self.access
        policy = _signed(request.repository_policy, r.policy_public_key,
                         POLICY_DOMAIN, {
            "schema", "issuer_id", "project_id", "repository_id", "base_commit",
            "repo_binding_sha256", "target_binding_sha256",
            "allowlist_sha256", "policy_epoch", "privacy",
            "issued_at", "expires_at"}, "REPOSITORY_POLICY")
        review = _signed(request.content_review, r.reviewer_public_key,
                         REVIEW_DOMAIN, {
            "schema", "project_id", "repository_id", "base_commit",
            "manifest_sha256", "reviewer_id", "review_state", "privacy",
            "issued_at", "expires_at"}, "DOCS_CONTENT_REVIEW")
        revoke = _signed(request.current_revocation, r.revocation_public_key,
                         REVOKE_DOMAIN, {
            "schema", "project_id", "repository_id", "grant_nonce",
            "policy_epoch", "state", "issued_at", "expires_at"},
                         "DOCS_CURRENT_REVOCATION")
        grant = _signed(request.one_use_grant, r.side_effect_public_key,
                        GRANT_DOMAIN, {
            "schema", "issuer_id", "operator_id", "project_id", "repository_id",
            "base_commit", "manifest_sha256", "repo_binding_sha256",
            "target_binding_sha256", "allowlist_sha256",
            "repository_policy_sha256", "content_review_sha256",
            "revocation_sha256", "trust_roots_sha256", "code_revision_sha256",
            "grant_nonce", "policy_epoch", "action", "issued_at", "expires_at"},
                        "DOCS_ONE_USE_GRANT")
        for name, doc, expiry in (
            ("REPOSITORY_POLICY", policy, 120),
            ("DOCS_CONTENT_REVIEW", review, 120),
            ("DOCS_CURRENT_REVOCATION", revoke, MAX_REVOKE_AGE),
            ("DOCS_ONE_USE_GRANT", grant, MAX_GRANT_AGE),
        ):
            _window(doc, now, expiry, name)
        need(policy["schema"] == POLICY_SCHEMA and
             policy["issuer_id"] == r.issuer_id and
             policy["project_id"] == r.project_id and
             policy["repository_id"] == r.repository_id and
             policy["base_commit"] == a.approved_base_commit and
             policy["repo_binding_sha256"] == self._repo_binding and
             policy["target_binding_sha256"] == self._target_binding and
             policy["allowlist_sha256"] == self._allowlist and
             type(policy["policy_epoch"]) is int and
             policy["policy_epoch"] >= r.minimum_policy_epoch and
             policy["privacy"] == PRIVACY,
             "HOST_REPOSITORY_DOCS_POLICY_MISMATCH")
        need(review["schema"] == REVIEW_SCHEMA and
             review["project_id"] == r.project_id and
             review["repository_id"] == r.repository_id and
             review["base_commit"] == a.approved_base_commit and
             review["manifest_sha256"] == manifest_sha and
             type(review["reviewer_id"]) is str and
             IDENT.fullmatch(review["reviewer_id"]) is not None and
             review["review_state"] == "HUMAN_REVIEWED_EXACT_NEW_DOCS_BYTES" and
             review["privacy"] == PRIVACY,
             "INDEPENDENT_EXACT_DOCS_REVIEW_REQUIRED")
        need(grant["schema"] == GRANT_SCHEMA and
             grant["issuer_id"] == r.issuer_id and
             grant["operator_id"] == r.operator_id and
             grant["project_id"] == r.project_id and
             grant["repository_id"] == r.repository_id and
             grant["base_commit"] == a.approved_base_commit and
             grant["manifest_sha256"] == manifest_sha and
             grant["repo_binding_sha256"] == self._repo_binding and
             grant["target_binding_sha256"] == self._target_binding and
             grant["allowlist_sha256"] == self._allowlist and
             grant["repository_policy_sha256"] == _canonical_sha(policy) and
             grant["content_review_sha256"] == _canonical_sha(review) and
             grant["revocation_sha256"] == _canonical_sha(revoke) and
             grant["trust_roots_sha256"] == self._roots and
             _is_sha(ACTIVE_CODE_SHA256) and
             grant["code_revision_sha256"] == ACTIVE_CODE_SHA256 == _code_sha() and
             type(grant["grant_nonce"]) is str and
             NONCE.fullmatch(grant["grant_nonce"]) is not None and
             grant["policy_epoch"] == policy["policy_epoch"] and
             grant["action"] == ACTION,
             "DOCS_GRANT_NOT_EXACT_OR_RUNNING_CODE_DRIFT")
        need(revoke["schema"] == REVOKE_SCHEMA and
             revoke["project_id"] == r.project_id and
             revoke["repository_id"] == r.repository_id and
             revoke["grant_nonce"] == grant["grant_nonce"] and
             revoke["policy_epoch"] == policy["policy_epoch"] and
             revoke["state"] == "ACTIVE",
             "CURRENT_INDEPENDENT_DOCS_REVOCATION_DENIED")
        result = {
            "manifest": manifest, "manifest_sha256": manifest_sha,
            "policy": policy, "review": review, "revoke": revoke, "grant": grant,
            "statement_sha256s": tuple(_canonical_sha(doc) for doc in
                                      (policy, review, revoke, grant)),
        }
        return contents, result

    def _original_source_fingerprint(self) -> tuple[str, str]:
        """No original index or HEAD-file edits hidden behind a clean status."""
        try:
            index = Path(self.gitdir, "index")
            raw = index.read_bytes()
            head_raw = Path(self.gitdir, "HEAD").read_bytes()
            need(0 < len(raw) <= MAX_SOURCE_INDEX_BYTES and
                 0 < len(head_raw) <= 4096,
                 "SOURCE_GIT_METADATA_SIZE_INVALID", "unavailable")
            return _sha(raw), _sha(head_raw)
        except OSError:
            raise DocsDenied("SOURCE_GIT_METADATA_UNAVAILABLE", "unavailable") from None

    def _git_storage_safe(self) -> None:
        for root in (Path(self.gitdir), Path(self.bare)):
            for name in ("config", "objects", "refs", "info", "HEAD",
                         "objects/info", "objects/pack", "refs/heads"):
                path = root / name
                need(path.exists() and not path.is_symlink(),
                     "GIT_STORAGE_PATH_SYMLINK_OR_MISSING", "unavailable")
            need((root / "config").is_file() and (root / "HEAD").is_file() and
                 (root / "objects/info").is_dir() and
                 (root / "objects/pack").is_dir(),
                 "GIT_STORAGE_FILE_TYPE_UNSAFE", "unavailable")
            objects = root / "objects"
            need(not (objects / "info" / "alternates").exists(),
                 "GIT_OBJECT_ALTERNATES_DISALLOWED", "unavailable")
        need(not (Path(self.gitdir) / "index").is_symlink() and
             (Path(self.gitdir) / "index").is_file(),
             "ORIGINAL_GIT_INDEX_NOT_REGULAR", "unavailable")

    def _source_ready(self, files: dict[str, bytes]) -> None:
        """Recheck approved exact HEAD, clean original index/tree, safe base tree."""
        self._host_still_pinned()
        repo, bare, head = self.repo, self.bare, self.access.approved_base_commit
        g = self.git
        need(g.text(repo, "rev-parse", "--is-inside-work-tree") == "true" and
             g.text(repo, "rev-parse", "--show-toplevel") == repo and
             g.text(repo, "rev-parse", "--absolute-git-dir") == self.gitdir and
             g.text(repo, "rev-parse", "--verify", "HEAD^{commit}") == head and
             g.text(bare, "rev-parse", "--is-bare-repository") == "true" and
             g.text(bare, "rev-parse", "--absolute-git-dir") == bare,
             "GIT_REPOSITORY_OR_APPROVED_HEAD_DRIFT", "unavailable")
        g.safe_config(repo)
        g.safe_config(bare)
        self._git_storage_safe()
        self._sandbox_hooks_off()
        need(g.run(repo, "status", "--porcelain=v1", "-z",
                   "--untracked-files=all", "--ignore-submodules=none")[1] == b"",
             "ORIGINAL_REPOSITORY_NOT_CLEAN", "unavailable")
        need(g.text(repo, "cat-file", "-t", head) == "commit",
             "APPROVED_HEAD_OBJECT_UNAVAILABLE", "unavailable")
        tree = g.run(repo, "ls-tree", "-r", "-l", "-z", head)[1].split(b"\0")
        tracked: set[bytes] = set()
        sum_bytes = 0
        for item in tree:
            if not item:
                continue
            match = TREE_ITEM.fullmatch(item)
            need(match is not None, "BASE_TREE_METADATA_UNSAFE", "unavailable")
            mode, obj_type, _, size, path = match.groups()
            need(mode in (b"100644", b"100755") and obj_type == b"blob" and
                 size.isdigit() and path not in tracked and
                 b"\n" not in path and b"\r" not in path and
                 b"\\" not in path,
                 "BASE_TREE_SYMLINK_SUBMODULE_OR_AMBIGUOUS_PATH", "unavailable")
            tracked.add(path)
            sum_bytes += int(size)
            need(len(tracked) <= MAX_TREE_FILES and
                 sum_bytes <= MAX_TREE_BYTES,
                 "BASE_TREE_RESOURCE_BUDGET_EXCEEDED", "unavailable")
            need(not any(p in (b".gitattributes", b".gitmodules", b".lfsconfig")
                         for p in path.split(b"/")),
                 "GIT_ATTRIBUTES_SUBMODULE_OR_LFS_CONFIG_FORBIDDEN", "unavailable")
        lower = {p.lower() for p in tracked}
        need(len(lower) == len(tracked),
             "BASE_TREE_CASE_COLLISION_UNSAFE", "unavailable")
        baseline = self._original_source_fingerprint()
        if self._original_baseline is None:
            self._original_baseline = baseline
        need(self._original_baseline == baseline,
             "ORIGINAL_GIT_INDEX_OR_HEAD_FILE_CHANGED", "unavailable")
        for name in files:
            encoded = name.encode("ascii")
            ancestors = [b"/".join(encoded.split(b"/")[:i])
                         for i in range(1, len(encoded.split(b"/")))]
            need(encoded not in tracked and encoded.lower() not in lower and
                 not any(a in tracked or a.lower() in lower for a in ancestors),
                 "DOC_PATH_EXISTS_OR_OVERWRITES_TREE", "blocked")

    def _sandbox_hooks_off(self) -> None:
        hooks = Path(self.bare) / "hooks"
        need(hooks.is_dir() and not hooks.is_symlink(),
             "SANDBOX_GIT_HOOKS_DIRECTORY_UNSAFE", "unavailable")
        for p in hooks.iterdir():
            need(not p.is_symlink() and
                 (p.name.endswith(".sample") and p.is_file()),
                 "ACTIVE_SANDBOX_GIT_HOOKS_NOT_ALLOWED", "unavailable")

    def _reference_absent(self, ref: str) -> bool:
        result, _ = self.git.run(self.bare, "show-ref", "--verify",
                                 "--quiet", ref, ok=(0, 1))
        return result == 1

    @staticmethod
    def _write_private_docs(worktree: str, contents: dict[str, bytes]) -> None:
        """Dirfd O_NOFOLLOW and O_EXCL: never follow or overwrite tracked files."""
        base = os.open(worktree, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for name, content in contents.items():
                fd = os.dup(base)
                try:
                    pieces = name.split("/")
                    for segment in pieces[:-1]:
                        try:
                            os.mkdir(segment, 0o700, dir_fd=fd)
                        except FileExistsError:
                            pass
                        following = os.open(segment, os.O_RDONLY | os.O_DIRECTORY |
                                            os.O_NOFOLLOW, dir_fd=fd)
                        os.close(fd)
                        fd = following
                    filefd = os.open(pieces[-1], os.O_WRONLY | os.O_CREAT |
                                     os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                    try:
                        offset = 0
                        while offset < len(content):
                            written = os.write(filefd, content[offset:])
                            need(written > 0, "DOC_FILE_PARTIAL_WRITE", "unavailable")
                            offset += written
                        os.fsync(filefd)
                    finally:
                        os.close(filefd)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            os.fsync(base)
        finally:
            os.close(base)

    def _verify_isolated_commit(self, worktree: str, commit: str,
                                contents: dict[str, bytes]) -> None:
        g, base = self.git, self.access.approved_base_commit
        need(GIT_SHA.fullmatch(commit) is not None and commit != base and
             g.text(worktree, "rev-list", "--parents", "-n", "1", commit) ==
             commit + " " + base and
             g.text(worktree, "rev-parse", "--verify", "HEAD^{commit}") == commit,
             "ISOLATED_COMMIT_PARENT_OR_HEAD_INVALID", "unavailable")
        _, changed = g.run(worktree, "diff-tree", "--no-commit-id",
                           "--name-status", "-r", "-z", base, commit)
        expected = b"".join(b"A\0" + p.encode("ascii") + b"\0"
                            for p in sorted(contents))
        need(changed == expected,
             "NON_DOC_CHANGE_OR_EXISTING_FILE_OVERWRITE_DETECTED", "unavailable")
        for path, raw in contents.items():
            actual = g.run(worktree, "show", commit + ":" + path,
                           limit=MAX_FILE_BYTES + 1)[1]
            need(actual == raw, "COMMITTED_DOC_BYTES_DRIFT", "unavailable")
        need(g.run(worktree, "status", "--porcelain=v1", "-z",
                   "--untracked-files=all")[1] == b"",
             "ISOLATED_WORKTREE_NOT_CLEAN", "unavailable")

    def publish_once(self, request: DocsOnlyPublishRequest) -> dict[str, Any]:
        operation: str | None = None
        claimed = worktree_created = commit_created = pushed = False
        try:
            start = _current_time()
            contents, checked = self._verify(request, start)
            self._source_ready(contents)
            operation = dp.sha(OP_DOMAIN, {
                "repository_id": self.access.roots.repository_id,
                "project_id": self.access.roots.project_id,
                "base_commit": self.access.approved_base_commit,
                "manifest_sha256": checked["manifest_sha256"],
                "private_target_sha256": self._target_binding,
            })
            ref = REF_NAMESPACE + operation
            need(self._reference_absent(ref),
                 "SANDBOX_REF_ALREADY_EXISTS_NO_OVERWRITE")
            with OnceOnlyDocsJournal(self.journalroot) as journal:
                journal.claim(operation)
                claimed = True
                journal.mark("01_WORKTREE_ATTEMPTED")
                directory = self.workroot + "/ec229-" + operation
                # Must not reuse a pre-existing path even if it looks empty.
                os.mkdir(directory, 0o700)
                wtfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(wtfd)
                finally:
                    os.close(wtfd)
                dirfd = os.open(self.workroot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(dirfd)
                finally:
                    os.close(dirfd)
                self.git.run(self.repo, "worktree", "add", "--detach",
                             directory, self.access.approved_base_commit)
                worktree_created = True
                journal.mark("02_WORKTREE_READY")
                need(self.git.text(directory, "rev-parse", "--verify", "HEAD^{commit}") ==
                     self.access.approved_base_commit and
                     self.git.run(directory, "status", "--porcelain=v1", "-z",
                                  "--untracked-files=all")[1] == b"",
                     "ISOLATED_BASE_CHECKOUT_UNSAFE", "unavailable")
                self._write_private_docs(directory, contents)
                journal.mark("03_DOCS_WRITTEN")
                self._source_ready(contents)
                again, reviewed = self._verify(request, _current_time())
                need(again == contents and
                     reviewed["statement_sha256s"] == checked["statement_sha256s"],
                     "SIGNATURE_OR_REVIEW_CHANGED_BEFORE_COMMIT", "unavailable")
                self.git.run(directory, "add", "--", *sorted(contents))
                _, staged = self.git.run(directory, "diff", "--cached", "--name-status",
                                         "-z", "--no-renames", "HEAD")
                expected = b"".join(b"A\0" + p.encode("ascii") + b"\0"
                                    for p in sorted(contents))
                need(staged == expected, "NON_DOC_PATH_STAGED", "unavailable")
                journal.mark("04_COMMIT_ATTEMPTED")
                self.git.run(directory, "commit", "--no-gpg-sign", "--no-verify",
                             "-m", "CES private docs-only candidate " + operation[:16])
                commit = self.git.text(directory, "rev-parse", "--verify", "HEAD^{commit}")
                commit_created = True
                journal.mark("05_COMMIT_CREATED", commit.encode("ascii"))
                self._verify_isolated_commit(directory, commit, contents)
                self._source_ready(contents)
                need(self._reference_absent(ref), "PRIVATE_REF_RACE_OR_OVERWRITE_REFUSED")
                now = _current_time()
                expiry = min(x["expires_at"] for x in
                             (checked["policy"], checked["review"],
                              checked["revoke"], checked["grant"]))
                need(now >= start and now < expiry and
                     self._verify(request, now)[1]["statement_sha256s"] ==
                     checked["statement_sha256s"] and
                     _code_sha() == ACTIVE_CODE_SHA256,
                     "PRIVATE_GIT_PUSH_EDGE_PERMISSION_EXPIRED", "unavailable")
                journal.mark("06_PUSH_ATTEMPTED")  # durable before Git receive-pack
                edge = _current_time()
                need(edge >= now and edge < expiry and
                     _code_sha() == ACTIVE_CODE_SHA256,
                     "DURABLE_PRIVATE_PUSH_EDGE_EXPIRED_NO_RETRY", "unavailable")
                pushed = True
                # One exact ref, absent-ref lease, FILE transport only. No
                # branch mutation on source or network/production remote.
                self.git.run(directory, "push", "--porcelain",
                             "--force-with-lease=" + ref + ":",
                             "--", self.bare, commit + ":" + ref, limit=8192)
                need(self.git.text(self.bare, "rev-parse", "--verify", ref + "^{commit}")
                     == commit, "PRIVATE_SANDBOX_REF_NOT_OBSERVED", "unavailable")
                self._verify_isolated_commit(directory, commit, contents)
                self._source_ready(contents)
                journal.mark("07_SANDBOX_REF_OBSERVED", commit.encode("ascii"))
                return {
                    "schema": SCHEMA, "status": "partial", "exit_code": 2,
                    "reason_code": "DOCS_ONLY_PRIVATE_LOCAL_SANDBOX_REF_OBSERVED",
                    "operation_id": operation, "local_candidate_commit_sha": commit,
                    "private_sandbox_ref": ref,
                    "local_candidate_state": "PRIVATE_LOCAL_REF_OBSERVED_ONCE",
                    "claim_committed": True, "isolated_worktree_created": True,
                    "local_commit_created": True, "private_push_attempted": True,
                    "private_sandbox_ref_observed": True,
                    "original_repository_intact_verified": True,
                    "published": False, "production_or_public_published": False,
                    "external_publication_confirmed": False,
                    "native_action_registered": False,
                    "effects": {
                        "original_worktree_or_index_edited": False,
                        "business_ci_schema_path_staged": False,
                        "existing_ref_overwritten": False,
                        "production_network_or_remote_requested": False,
                        "private_local_sandbox_ref_write_attempted": True,
                        "automatic_cleanup_or_retry": False,
                    },
                }
        except DocsDenied as exc:
            return _refused(exc.code, exc.status, operation=operation,
                            claimed=claimed, worktree=worktree_created,
                            committed=commit_created, pushed=pushed)
        except (OSError, ValueError, TypeError, KeyError, UnicodeError,
                RecursionError):
            return _refused("GIT_LOCAL_EFFECT_OR_HOST_STATE_UNKNOWN_NO_RETRY",
                            "unavailable", operation=operation,
                            claimed=claimed, worktree=worktree_created,
                            committed=commit_created, pushed=pushed)
