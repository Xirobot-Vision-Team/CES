#!/usr/bin/env python3
"""EC-161 focused offline synthetic tests. No network, Git or PowerShell."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import proposed_pr_source as src

HERE = Path(__file__).resolve().parent


def fixture(provider: str) -> dict:
    return json.loads((HERE / "fixtures" / "ec161" / f"{provider}.synthetic.json").read_text("utf-8"))


class FakeTransport:
    def __init__(self, value: dict | Exception) -> None:
        self.value = value
        self.calls = []

    def get_object(self, url, headers, timeout):
        self.calls.append((url, headers, timeout))
        if isinstance(self.value, Exception):
            raise self.value
        return copy.deepcopy(self.value)


def read(provider="github", repo="example/repo", number=8, *, data=None,
         token="SYNTHETIC-TOKEN-NOT-OUTPUT"):
    transport = FakeTransport(fixture(provider) if data is None else data)
    result = src.fetch_proposed_pr(src.RequestKey(provider, repo, number),
                                   allow_network=True, token_supplier=lambda: token,
                                   transport=transport)
    return result, transport


class ProposedPrSourceTests(unittest.TestCase):
    def test_network_opt_in_is_default_deny(self):
        def must_not_read_token():
            raise AssertionError("offline path touched credentials")
        out = src.fetch_proposed_pr(src.RequestKey("github", "example/repo", 8),
                                     token_supplier=must_not_read_token)
        self.assertEqual((out["status"], out["reason_code"], out["exit_code"]),
                         ("unavailable", "NETWORK_NOT_AUTHORIZED", 5))
        self.assertIsNone(out["source"])

    def test_no_credential_fails_closed_without_fetch(self):
        transport = FakeTransport(fixture("github"))
        out = src.fetch_proposed_pr(src.RequestKey("github", "example/repo", 8),
                                     allow_network=True, token_supplier=lambda: None,
                                     transport=transport)
        self.assertEqual(out["reason_code"], "CREDENTIALS_UNAVAILABLE")
        self.assertEqual(transport.calls, [])

    def test_bad_supplier_sanitized(self):
        def fail():
            raise RuntimeError("secret-is-in-exception")
        out = src.fetch_proposed_pr(src.RequestKey("github", "example/repo", 8),
                                     allow_network=True, token_supplier=fail)
        self.assertNotIn("secret-is-in-exception", json.dumps(out))
        self.assertEqual(out["status"], "unavailable")

    def test_bad_token_rejected_before_transport(self):
        out, transport = read(token="abc\r\nINJECT: yes")
        self.assertEqual(out["reason_code"], "CREDENTIALS_UNAVAILABLE")
        self.assertEqual(transport.calls, [])

    def test_invalid_repositories_never_trigger_credentials(self):
        invalid = ("https://example/repo", "example", "example/../evil",
                   "example/%2f", "example/repo?token=x", "localhost/repo/extra",
                   "example//repo", "./repo", "example/.git/../repo", "example/repo\nX")
        for repo in invalid:
            with self.subTest(repository=repo):
                out = src.fetch_proposed_pr(src.RequestKey("github", repo, 8),
                                             allow_network=True,
                                             token_supplier=lambda: self.fail("read credential"))
                self.assertEqual(out["status"], "invalid_input")
                self.assertEqual(out["exit_code"], 4)

    def test_other_invalid_fields(self):
        for key in (src.RequestKey("gitea", "org/repo", 8),
                    src.RequestKey("github", "org/repo", True),
                    src.RequestKey("github", "org/repo", 0),
                    src.RequestKey("gitlab", "g/r", -1)):
            with self.subTest(key=key):
                out = src.fetch_proposed_pr(key, allow_network=True)
                self.assertEqual(out["status"], "invalid_input")

    def test_bad_timeout_rejected(self):
        out = src.fetch_proposed_pr(src.RequestKey("github", "example/repo", 8),
                                     allow_network=True, timeout=float("nan"))
        self.assertEqual(out["reason_code"], "INVALID_TIMEOUT")

    def test_github_candidate_not_diff_or_actor_proof(self):
        out, transport = read()
        self.assertEqual((out["status"], out["exit_code"], out["synthetic"]), ("success", 0, True))
        self.assertTrue(out["source"]["origin"] == "synthetic_fixture")
        self.assertEqual(out["source"]["base"]["sha"], "a" * 40)
        self.assertEqual(out["source"]["head"]["sha"], "b" * 40)
        self.assertFalse(out["source"]["file_paths_collected"])
        self.assertFalse(out["source"]["patch_content_collected"])
        self.assertFalse(out["source"]["delivery_or_merge_proven"])
        self.assertFalse(out["write_authorized"])
        self.assertFalse(out["native_cli_action_registered"])
        self.assertEqual(transport.calls[0][0], "https://api.github.com/repos/example/repo/pulls/8")
        self.assertEqual(transport.calls[0][1]["Authorization"], "Bearer SYNTHETIC-TOKEN-NOT-OUTPUT")
        self.assertNotIn("SYNTHETIC-TOKEN-NOT-OUTPUT", json.dumps(out))
        self.assertNotIn("SYNTHETIC: must not be emitted", json.dumps(out))

    def test_gitlab_subgroup_encoded_and_diff_base_semantic(self):
        out, transport = read("gitlab", "my-group/sub-group/repo")
        self.assertEqual(out["status"], "success")
        self.assertEqual(transport.calls[0][0], "https://gitlab.com/api/v4/projects/my-group%2Fsub-group%2Frepo/merge_requests/8")
        self.assertEqual(transport.calls[0][1]["PRIVATE-TOKEN"], "SYNTHETIC-TOKEN-NOT-OUTPUT")
        self.assertEqual(out["source"]["base"]["meaning"], "gitlab_diff_refs_merge_base_not_target_branch_tip")
        self.assertEqual(out["source"]["identity_binding"], "NOT_VERIFIED_EC162")

    def test_github_request_number_mismatch(self):
        data = fixture("github")
        data["number"] = 9
        out, _ = read(data=data)
        self.assertEqual(out["reason_code"], "PROVIDER_SOURCE_MISMATCH")
        self.assertIsNone(out["source"])

    def test_github_repository_mismatch(self):
        data = fixture("github")
        data["base"]["repo"]["full_name"] = "other/repo"
        out, _ = read(data=data)
        self.assertEqual(out["reason_code"], "PROVIDER_SOURCE_MISMATCH")

    def test_missing_sha_not_constructed_from_branch(self):
        data = fixture("github")
        data["head"].pop("sha")
        data["head"]["ref"] = "feature-not-sha"
        out, _ = read(data=data)
        self.assertEqual(out["reason_code"], "PROVIDER_METADATA_INCOMPLETE")
        self.assertIsNone(out["source"])

    def test_sha_formats_and_mismatch_rejected(self):
        for bad in ("abc", "0" * 40, "f" * 64):
            data = fixture("github")
            data["head"]["sha"] = bad
            out, _ = read(data=data)
            self.assertEqual(out["status"], "unavailable")

    def test_gitlab_inconsistent_head_is_unavailable(self):
        data = fixture("gitlab")
        data["sha"] = "c" * 40
        out, _ = read("gitlab", data=data)
        self.assertEqual(out["reason_code"], "PROVIDER_METADATA_INCONSISTENT")

    def test_gitlab_missing_diff_refs_is_unavailable(self):
        data = fixture("gitlab")
        data["diff_refs"] = None
        out, _ = read("gitlab", data=data)
        self.assertEqual(out["reason_code"], "PROVIDER_METADATA_INCOMPLETE")

    def test_gitlab_invalid_iid_and_id_not_accepted(self):
        for changes in ({"iid": 12}, {"id": True}, {"target_project_id": 0}):
            data = fixture("gitlab")
            data.update(changes)
            out, _ = read("gitlab", data=data)
            self.assertEqual(out["status"], "unavailable")

    def test_opaque_transport_exception_never_leaks(self):
        transport = FakeTransport(RuntimeError("PR secret TOKEN=shhh"))
        out = src.fetch_proposed_pr(src.RequestKey("github", "example/repo", 8),
                                     allow_network=True, token_supplier=lambda: "token",
                                     transport=transport)
        self.assertEqual(out["reason_code"], "PROVIDER_READ_FAILED")
        self.assertNotIn("shhh", json.dumps(out))

    def test_json_parser_rejects_duplicate_root_nested_and_nan(self):
        for raw in (b'{"id":1,"id":2}', b'{"a":{"a":1,"a":2}}',
                    b'{"id":NaN}', b'[1,2]', b'not_json', b'\xff'):
            with self.subTest(payload=raw):
                with self.assertRaises(src.SourceFailure):
                    src._decode_object(raw)

    def test_fixture_masquerading_as_live_refused(self):
        with patch.object(src, "StrictHttpsTransport", autospec=True) as mocked:
            mocked.return_value.get_object.return_value = fixture("github")
            out = src.fetch_proposed_pr(src.RequestKey("github", "example/repo", 8),
                                         allow_network=True, token_supplier=lambda: "secret")
            self.assertEqual(out["reason_code"], "PROVIDER_PAYLOAD_INVALID")

    def test_https_transport_whitelists_endpoint_before_open(self):
        transport = src.StrictHttpsTransport()
        with self.assertRaises(src.SourceFailure) as ctx:
            transport.get_object("https://127.0.0.1/private", {}, 1)
        self.assertEqual(ctx.exception.reason, "PROVIDER_ENDPOINT_REJECTED")

    def test_readonly_transport_configuration_and_no_proxy(self):
        outer = self
        class FakeResponse:
            status = 200
            headers = {"Content-Type": "application/json"}
            def geturl(self):
                return "https://api.github.com/repos/example/repo/pulls/8"
            def read(self, maximum):
                outer.assertEqual(maximum, src.MAX_BODY_BYTES + 1)
                return b'{"synthetic":true}'
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return None
        class FakeOpener:
            def open(self, request, timeout):
                outer.assertEqual(request.get_method(), "GET")
                outer.assertEqual(timeout, 1)
                return FakeResponse()
        # Verify the real transport's opener arguments and read bound without
        # touching a socket. The Open() response itself is synthetic.
        with patch.object(src, "build_opener") as op:
            op.return_value = FakeOpener()
            out = src.StrictHttpsTransport().get_object(
                "https://api.github.com/repos/example/repo/pulls/8", {}, 1)
            self.assertTrue(out["synthetic"])
            args = op.call_args.args
            self.assertTrue(any(type(x) is src.ProxyHandler and x.proxies == {} for x in args))
            self.assertTrue(any(type(x) is src._DenyRedirect for x in args))

    def test_cli_default_offline_machine_exit5(self):
        process = subprocess.run(
            [sys.executable, str(HERE / "proposed_pr_source.py"),
             "--provider", "github", "--repository", "example/repo", "--number", "8", "--json"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(process.returncode, 5)
        out = json.loads(process.stdout)
        self.assertEqual(out["reason_code"], "NETWORK_NOT_AUTHORIZED")
        self.assertEqual(process.stderr, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
