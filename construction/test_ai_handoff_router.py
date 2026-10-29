#!/usr/bin/env python3
"""EC174 focused synthetic local route/candidate behavior; NOT external AI acceptance."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import ai_handoff_router as route
import codeprepare_multisource as ec170
import handoff_input as hi
import handoff_lifecycle as lc
import task_staging as st
from test_handoff_input import Clock, refreshed
from test_handoff_lifecycle import context, ready_active, add_handoff, step_handoff
import test_codeprepare_multisource as fx


class RouteCases(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ces-ec174-")
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.root = base / "private_parent" / "ces"
        self.root.parent.mkdir(mode=0o700)
        self.root.mkdir(mode=0o700)
        self.repo = base / "business"
        self.repo.mkdir(mode=0o700)
        (self.repo / "read-only.py").write_bytes(b"synthetic original business code\n")
        self.clock = Clock()
        self.stage = st.TaskStaging(str(self.root), str(self.repo), clock=self.clock)
        self.pin = self.stage.initialize(approve_init=True)["parent_pin"]
        self.input = hi.HandoffInput(str(self.root), str(self.repo), clock=self.clock)
        self.router = route.HandoffRouter(str(self.root), str(self.repo), clock=self.clock)
        self.prepared = refreshed(context(), self.clock.value)
        self.opts = {}

    def setup_input(self, prepared=None, *, historical=False, input_ttl=300):
        self.prepared = prepared or self.prepared
        session = lc.Lifecycle.create(self.prepared, "create-run-0001")
        ready_active(session)
        add_handoff(session)
        step_handoff(session, "READY", "handoff-ready-0001",
                     acknowledge_partial=self.prepared["status"] == "partial")
        snap = session.snapshot()
        self.stage.stage_live(session, expected_parent_pin=self.pin,
                              expected_revision=snap["revision"],
                              context_sha256=self.prepared["context_sha256"],
                              operation_key="create-run-0001", authorize_stage=True,
                              ttl_seconds=900)
        self.opts = dict(
            expected_parent_pin=self.pin, run_id=snap["run"]["run_id"],
            handoff_id=snap["handoffs"][0]["handoff_id"],
            expected_revision=snap["revision"],
            expected_event_sha256=snap["last_event_sha256"],
            operation_key="input-write-0001", allow_historical_proposal=historical,
            max_source_age_seconds=600,
        )
        created = self.input.create(
            self.prepared, authorize_input=True,
            allow_content_for=self.prepared["source_mode"],
            ttl_seconds=input_ttl, **self.opts,
        )
        self.assertTrue(created["input_committed"])
        self.route_opts = dict(
            requested_task_kind="code_analysis", authorize_route=True,
            authorize_read=True, read_content_for=self.prepared["source_mode"],
            **self.opts,
        )
        self.input_path = Path(created["input_path"])
        return created

    def act(self, **changes):
        kw = dict(self.route_opts)
        kw.update(changes)
        return self.router.route(self.prepared, **kw)

    def candidate(self, request: dict, *, anchors=None):
        if anchors is None:
            anchors = [{"segment_index": 0, "item_index": None,
                        "line_number": 4, "quote": "+new"}]
        return {
            "schema": route.CANDIDATE_SCHEMA,
            "task_kind": request["task_kind"], "route_id": request["route_id"],
            "source_binding": request["source_binding"],
            "coverage_assessment": request["coverage_assessment"],
            "summary": "Provisional analysis of authorized synthetic source.",
            "actor_claim": "synthetic-test-actor",
            "findings": [{
                "title": "Synthetic patch line requires review", "severity": "medium",
                "confidence": "low", "analysis": "The added line may need inspection.",
                "suggested_action": "Review the change manually.", "anchors": anchors,
            }],
        }

    def callback(self, request_bytes: bytes, provider: str, timeout: int) -> bytes:
        request = json.loads(request_bytes)
        self.assertEqual(request["task_kind"], "code_analysis")
        self.assertEqual(request["route_id"], route.ROUTE_ID)
        self.assertEqual(provider, "synthetic_provider")
        self.assertEqual(timeout, 15)
        self.assertIn("+new", json.dumps(request["source_material"]))
        return json.dumps(self.candidate(request)).encode()

    def dispatch(self, *, adapter=None, **changes):
        kw = dict(
            action="dispatch", approve_external_transfer=True,
            transfer_content_for=self.prepared["source_mode"],
            provider_claim="synthetic_provider", bridge_id=route.BRIDGE_ID,
            adapter=self.callback if adapter is None else adapter,
            timeout_seconds=15,
        )
        kw.update(changes)
        return self.act(**kw)

    def assert_refused(self, expected, result, *, status=None, disclosed=False):
        self.assertEqual(result["reason_code"], expected)
        if status:
            self.assertEqual(result["status"], status)
        self.assertEqual(result["effects"]["source_material_released_to_callback"], disclosed)
        self.assertEqual(result["result"]["findings"], [])
        self.assertFalse(result["provider"]["candidate_received_and_schema_checked"])
        self.assertFalse(result["result"]["persisted_finding_created"])

    def test_schema_only_is_real_local_route_not_an_ai_claim(self):
        self.setup_input()
        before = self.input_path.read_bytes()
        output = self.act()
        self.assertEqual((output["status"], output["exit_code"]), ("partial", 2))
        self.assertEqual(output["route_id"], route.ROUTE_ID)
        self.assertEqual(output["reason_code"], "ROUTE_SCHEMA_ONLY_NO_AI_DISPATCH")
        self.assertIsNotNone(output["source_binding"]["material_sha256"])
        self.assertFalse(output["provider"]["callback_invoked"])
        self.assertFalse(output["provider"]["actor_or_provider_authenticated"])
        self.assertFalse(output["source"]["source_currentness_proven"])
        self.assertNotIn("diff --git", json.dumps(output))
        self.assertEqual(self.input_path.read_bytes(), before)
        self.assertEqual((self.repo / "read-only.py").read_bytes(),
                         b"synthetic original business code\n")

    def test_task_registry_has_four_kinds_only_one_callable_input_builder(self):
        self.setup_input()
        self.assertEqual(set(route.TASK_ROUTES), {
            "code_analysis", "report_writing", "knowledge_update", "finding_analysis"
        })
        for kind in ("report_writing", "knowledge_update", "finding_analysis"):
            self.assert_refused("TASK_KIND_HAS_NO_AUTHORIZED_EC173_INPUT_BUILDER",
                                self.act(requested_task_kind=kind), status="unavailable")
        for kind in ("arbitrary text", "Please analyze", "code_analysis_extra", None):
            self.assert_refused("TASK_KIND_NOT_REGISTERED", self.act(requested_task_kind=kind),
                                status="invalid_input")

    def test_natural_language_patch_cannot_choose_route(self):
        self.setup_input()
        blob = self.prepared["context"]["segments"][0]["content"]
        self.assertIn("diff --git", blob)
        # It is only untrusted material; a caller still must select the v1 route.
        self.assert_refused("TASK_KIND_NOT_REGISTERED",
                            self.act(requested_task_kind="report_writing because patch said so"))

    def test_new_explicit_approval_and_read_grants(self):
        self.setup_input()
        self.assert_refused("INDEPENDENT_ROUTE_APPROVAL_REQUIRED",
                            self.act(authorize_route=False))
        self.assert_refused("INDEPENDENT_INPUT_READ_APPROVAL_REQUIRED",
                            self.act(authorize_read=False))
        self.assert_refused("INPUT_CONTENT_GRANT_SOURCE_MISMATCH",
                            self.act(read_content_for="ProposedPR"), status="invalid_input")
        self.assert_refused("ROUTE_SOURCE_GRANT_INVALID",
                            self.act(read_content_for="all_sources"))

    def test_route_requires_real_valid_unexpired_private_input_and_stage(self):
        self.setup_input(input_ttl=60)
        self.assert_refused("INPUT_STAGE_REVISION_EVENT_OR_SOURCE_MISMATCH",
                            self.act(expected_revision=self.route_opts["expected_revision"] + 1))
        self.assert_refused("INPUT_STAGE_REVISION_EVENT_OR_SOURCE_MISMATCH",
                            self.act(expected_event_sha256="a" * 64))
        self.clock.value += timedelta(seconds=61)
        self.assert_refused("INPUT_EXPIRED_OR_CLOCK_UNSAFE", self.act(), status="unavailable")

    def test_wrong_parent_run_handoff_and_operation_fail_before_any_transfer(self):
        self.setup_input()
        self.assert_refused("STAGING_PARENT_PIN_MISMATCH",
                            self.act(expected_parent_pin="a" * 64), status="unavailable")
        self.assert_refused("INPUT_COMMITTED_RUN_STAGE_NOT_FOUND",
                            self.act(run_id="run_v1_" + "f" * 48), status="unavailable")
        self.assert_refused("INPUT_COMMITTED_HANDOFF_NOT_FOUND",
                            self.act(handoff_id="handoff_v1_" + "f" * 48), status="unavailable")
        self.assert_refused("INPUT_OPERATION_REPLAY_OR_CONFLICT",
                            self.act(operation_key="unrelated-0001"), status="invalid_input")

    def test_wrong_source_or_tampered_seal_cannot_route(self):
        self.setup_input()
        changed = copy.deepcopy(self.prepared)
        changed["permission"]["content_granted"] = False
        self.assert_refused("EC170_CONTENT_RELEASE_NOT_AUTHORIZED_FOR_SOURCE",
                            self.router.route(changed, **self.route_opts), status="invalid_input")
        record = json.loads(self.input_path.read_bytes())
        record["material"]["source_mode"] = "DeliveredTarget"
        self.input_path.write_text(json.dumps(record), encoding="utf-8")
        self.assert_refused("STORED_JSON_INVALID", self.act(), status="unavailable")

    def test_schema_only_cannot_bring_a_hidden_provider(self):
        self.setup_input()
        self.assert_refused("SCHEMA_ONLY_MUST_NOT_SPECIFY_EXTERNAL_TRANSFER",
                            self.act(provider_claim="synthetic_provider"))
        self.assert_refused("SCHEMA_ONLY_MUST_NOT_SPECIFY_EXTERNAL_TRANSFER",
                            self.act(approve_external_transfer=True))
        self.assert_refused("SCHEMA_ONLY_MUST_NOT_SPECIFY_EXTERNAL_TRANSFER",
                            self.act(adapter=self.callback))

    def test_external_dispatch_defaults_closed_without_explicit_scoped_grant(self):
        self.setup_input()
        for changes in (
            {"approve_external_transfer": False},
            {"transfer_content_for": "DeliveredTarget"},
            {"transfer_content_for": None},
        ):
            self.assert_refused("EXPLICIT_SOURCE_SCOPED_EXTERNAL_TRANSFER_APPROVAL_REQUIRED",
                                self.dispatch(**changes))
        self.assert_refused("EXTERNAL_BRIDGE_NOT_REGISTERED",
                            self.dispatch(bridge_id="openai_http_automagic"))
        self.assert_refused("PROVIDER_CLAIM_REQUIRED_NOT_AUTHENTICATED",
                            self.dispatch(provider_claim=""))
        self.assert_refused("EXTERNAL_BRIDGE_UNAVAILABLE_NO_CALLBACK",
                            self.dispatch(adapter=False), status="unavailable")

    def test_bounded_candidate_has_locally_matched_anchors_never_verified_finding(self):
        self.setup_input()
        orig_names = set(os.listdir(self.root))
        output = self.dispatch()
        self.assertEqual(output["reason_code"], "AI_CANDIDATE_RECEIVED_UNVERIFIED")
        self.assertEqual((output["status"], output["exit_code"]), ("partial", 2))
        self.assertTrue(output["provider"]["callback_invoked"])
        self.assertTrue(output["effects"]["source_material_released_to_callback"])
        self.assertFalse(output["provider"]["external_model_execution_verified"])
        self.assertFalse(output["provider"]["actor_or_provider_authenticated"])
        self.assertFalse(output["result"]["persisted_finding_created"])
        self.assertEqual(len(output["result"]["findings"]), 1)
        f = output["result"]["findings"][0]
        self.assertEqual(f["verification"], "UNVERIFIED_AI_ASSERTION_NOT_PERSISTED_FINDING")
        self.assertEqual(f["anchors"][0]["quote"], "+new")
        self.assertIsNone(f["anchors"][0]["source_path"])
        self.assertFalse(f["anchors"][0]["line_number_is_git_file_line"])
        self.assertEqual(len(output["result"]["candidate_sha256"]), 64)
        self.assertEqual(set(os.listdir(self.root)), orig_names)
        self.assertEqual((self.repo / "read-only.py").read_bytes(),
                         b"synthetic original business code\n")

    def test_delivered_target_source_is_not_working_tree(self):
        source = ec170.prepare_context(
            "DeliveredTarget", local_codeprepare=fx.local_result("DeliveredTarget"),
            content_permission="DeliveredTarget",
        )
        self.setup_input(refreshed(source, self.clock.value))
        self.assertEqual(self.act()["source"]["mode"], "DeliveredTarget")
        self.assert_refused("INPUT_CONTENT_GRANT_SOURCE_MISMATCH",
                            self.act(read_content_for="WorkingTree"), status="invalid_input")
        output = self.dispatch()
        self.assertEqual((output["status"], output["exit_code"]), ("partial", 2))
        self.assertEqual(output["source_binding"]["source_mode"], "DeliveredTarget")

    def test_historical_proposal_candidate_anchor_uses_selected_item_path_only(self):
        snap, _ = fx.ec165.create(selected=("src/service.py",), include=True)
        source = ec170.prepare_context("ProposedPR", proposed_snapshot=snap,
                                      content_permission="ProposedPR")
        self.setup_input(refreshed(source, self.clock.value), historical=True)
        def cb(raw, provider, timeout):
            candidate = self.candidate(json.loads(raw), anchors=[{
                "segment_index": 0, "item_index": 0, "line_number": 3,
                "quote": "+new = 2",
            }])
            return json.dumps(candidate).encode()
        output = self.dispatch(adapter=cb)
        self.assertEqual((output["status"], output["exit_code"]), ("partial", 2))
        self.assertTrue(output["source"]["historical_proposal_only"])
        self.assertFalse(output["coverage"]["complete_for_selected_source"])
        self.assertEqual(output["result"]["findings"][0]["anchors"][0]["source_path"],
                         "src/service.py")
        self.assertFalse(output["provider"]["external_model_execution_verified"])

    def test_file_content_anchor_keeps_exact_path(self):
        self.setup_input()
        def cb(raw, provider, timeout):
            request = json.loads(raw)
            selected = self.candidate(request, anchors=[
                {"segment_index": 2, "item_index": 0, "line_number": 1, "quote": "hello"},
            ])
            return json.dumps(selected).encode()
        output = self.dispatch(adapter=cb)
        self.assertEqual(output["status"], "partial")
        anchor = output["result"]["findings"][0]["anchors"][0]
        self.assertEqual(anchor["source_path"], "notes.txt")
        self.assertEqual(anchor["segment_label"], "untracked")

    def test_mixed_source_file_and_patch_anchor_substitution_fails(self):
        self.setup_input()
        def cb(raw, provider, timeout):
            request = json.loads(raw)
            candidate = self.candidate(request, anchors=[
                {"segment_index": 0, "item_index": 0, "line_number": 4, "quote": "+new"}
            ])
            return json.dumps(candidate).encode()
        self.assert_refused("CANDIDATE_PATCH_ANCHOR_MUST_BE_SEGMENT_SCOPED",
                            self.dispatch(adapter=cb), status="unavailable", disclosed=True)

    def test_candidate_cannot_echo_wrong_run_revision_or_evidence(self):
        self.setup_input()
        for field, replacement in (("run_id", "run_v1_" + "a" * 48),
                                   ("handoff_id", "handoff_v1_" + "b" * 48),
                                   ("stage_revision", 55),
                                   ("stage_event_sha256", "f" * 64),
                                   ("evidence_hash", "f" * 64),
                                   ("material_sha256", "f" * 64),
                                   ("source_mode", "ProposedPR")):
            def cb(raw, provider, timeout):
                request = json.loads(raw)
                candidate = self.candidate(request)
                candidate["source_binding"][field] = replacement
                return json.dumps(candidate).encode()
            self.assert_refused("CANDIDATE_RUN_HANDOFF_REVISION_OR_SOURCE_BINDING_MISMATCH",
                                self.dispatch(adapter=cb), status="unavailable", disclosed=True)

    def test_json_type_masquerading_is_not_a_valid_source_echo(self):
        self.setup_input()
        for field, replacement in (("stage_revision", True),
                                   ("stage_revision", float(self.route_opts["expected_revision"]))):
            def cb(raw, provider, timeout):
                candidate = self.candidate(json.loads(raw))
                candidate["source_binding"][field] = replacement
                return json.dumps(candidate).encode()
            self.assert_refused("CANDIDATE_RUN_HANDOFF_REVISION_OR_SOURCE_BINDING_MISMATCH",
                                self.dispatch(adapter=cb), status="unavailable", disclosed=True)
        def cb(raw, provider, timeout):
            candidate = self.candidate(json.loads(raw))
            candidate["coverage_assessment"]["complete_for_selected_source"] = 1
            return json.dumps(candidate).encode()
        self.assert_refused("CANDIDATE_COVERAGE_ECHO_MISMATCH",
                            self.dispatch(adapter=cb), status="unavailable", disclosed=True)

    def test_candidate_model_text_secret_tripwire(self):
        self.setup_input()
        def cb(raw, provider, timeout):
            candidate = self.candidate(json.loads(raw))
            candidate["summary"] = "-----BEGIN RSA PRIVATE KEY----- example"
            return json.dumps(candidate).encode()
        self.assert_refused("CANDIDATE_TEXT_UNSAFE_OR_SECRET",
                            self.dispatch(adapter=cb), status="unavailable", disclosed=True)

    def test_bad_coverage_does_not_upgrade_partial_or_source_quality(self):
        partial = copy.deepcopy(self.prepared)
        cov = partial["context"]["coverage"]
        cov["content_complete_for_selected_source"] = False
        cov["missing_requirements"] = ["SYNTHETIC_MISSING_COVERAGE"]
        partial["coverage"] = copy.deepcopy(cov)
        partial["status"], partial["exit_code"] = "partial", 2
        partial["context_sha256"] = lc._hash(lc.DOMAIN_CONTEXT, partial["context"])
        self.setup_input(partial)
        self.assertEqual(self.act()["coverage"]["source_quality"], "partial")
        def cb(raw, provider, timeout):
            request = json.loads(raw)
            candidate = self.candidate(request)
            candidate["coverage_assessment"]["source_quality"] = "success"
            return json.dumps(candidate).encode()
        self.assert_refused("CANDIDATE_COVERAGE_ECHO_MISMATCH",
                            self.dispatch(adapter=cb), status="unavailable", disclosed=True)

    def test_valid_historical_proposal_must_remain_partial(self):
        snap, _ = fx.ec165.create(selected=("src/service.py",), include=True)
        p = ec170.prepare_context("ProposedPR", proposed_snapshot=snap,
                                  content_permission="ProposedPR")
        self.setup_input(refreshed(p, self.clock.value), historical=True)
        r = self.act()
        self.assertEqual((r["status"], r["exit_code"]), ("partial", 2))
        self.assertTrue(r["source"]["historical_proposal_only"])
        self.assertFalse(r["coverage"]["complete_for_selected_source"])
        self.assert_refused("HISTORICAL_PROPOSAL_NEEDS_EXPLICIT_LIMITED_CONSENT",
                            self.act(allow_historical_proposal=False), status="invalid_input")

    def test_unknown_response_schema_and_status_injection_rejected(self):
        self.setup_input()
        for alter in (lambda c: c.update(schema="fake.model.v9"),
                      lambda c: c.update(status="success", exit_code=0),
                      lambda c: c.update(route_id="ces.route.report_writing.v1"),
                      lambda c: c.update(extra="ignored")):
            def cb(raw, provider, timeout):
                candidate = self.candidate(json.loads(raw))
                alter(candidate)
                return json.dumps(candidate).encode()
            self.assert_refused("CANDIDATE_SCHEMA_OR_ROUTE_INVALID",
                                self.dispatch(adapter=cb), status="unavailable", disclosed=True)

    def test_duplicate_case_colliding_json_keys_or_invalid_utf8_rejected(self):
        self.setup_input()
        self.assert_refused("CANDIDATE_JSON_INVALID",
                            self.dispatch(adapter=lambda *args: b'{"a":1,"A":2}'),
                            status="unavailable", disclosed=True)
        self.assert_refused("CANDIDATE_JSON_INVALID",
                            self.dispatch(adapter=lambda *args: b'\xff\xfe'),
                            status="unavailable", disclosed=True)

    def test_wrong_quoted_evidence_line_is_rejected(self):
        self.setup_input()
        for anchor in (
            {"segment_index": 0, "item_index": None, "line_number": 4, "quote": "+forged"},
            {"segment_index": 0, "item_index": None, "line_number": 400, "quote": "+new"},
            {"segment_index": 5, "item_index": None, "line_number": 4, "quote": "+new"},
        ):
            def cb(raw, provider, timeout):
                return json.dumps(self.candidate(json.loads(raw), anchors=[anchor])).encode()
            result = self.dispatch(adapter=cb)
            self.assertEqual(result["status"], "unavailable")
            self.assertTrue(result["effects"]["source_material_released_to_callback"])

    def test_invalid_findings_and_missing_anchor_rejected(self):
        self.setup_input()
        for alters in (
            {"anchors": []}, {"severity": "done"},
            {"confidence": ["high"]},
            {"title": "X" * 121}, {"suggested_action": "p" * 1601},
        ):
            def cb(raw, provider, timeout):
                candidate = self.candidate(json.loads(raw))
                candidate["findings"][0].update(alters)
                return json.dumps(candidate).encode()
            output = self.dispatch(adapter=cb)
            self.assertEqual(output["status"], "unavailable")
            self.assertEqual(output["result"]["findings"], [])

    def test_malformed_or_excessive_callback_response_fails_closed(self):
        self.setup_input()
        for payload in ("{}", "[]", "A" * (route.MAX_RESPONSE_BYTES + 1), 42):
            output = self.dispatch(adapter=lambda *args: payload)
            self.assertEqual(output["status"], "unavailable")
            self.assertFalse(output["provider"]["candidate_received_and_schema_checked"])

    def test_callback_failure_does_not_log_source_or_forge_no_disclosure(self):
        self.setup_input()
        def cb(*args):
            raise RuntimeError("SUPER-SECRET-FROM-BRIDGE " + self.prepared["context"]["segments"][0]["content"])
        output = self.dispatch(adapter=cb)
        self.assert_refused("EXTERNAL_BRIDGE_FAILED_OR_TIMED_OUT", output,
                            status="unavailable", disclosed=True)
        self.assertNotIn("SUPER-SECRET", json.dumps(output))
        self.assertNotIn("diff --git", json.dumps(output))

    def test_expiry_during_callback_rejects_result_without_claiming_disclosure_undone(self):
        self.setup_input(input_ttl=60)
        def cb(raw, provider, timeout):
            result = json.dumps(self.candidate(json.loads(raw))).encode()
            self.clock.value += timedelta(seconds=61)
            return result
        self.assert_refused("INPUT_EXPIRED_OR_CLOCK_UNSAFE",
                            self.dispatch(adapter=cb), status="unavailable", disclosed=True)

    def test_bridge_mutation_of_source_context_rejected_on_postflight(self):
        self.setup_input()
        def cb(raw, provider, timeout):
            result = json.dumps(self.candidate(json.loads(raw))).encode()
            self.prepared["permission"]["content_granted"] = False
            return result
        self.assert_refused("EC170_CONTENT_RELEASE_NOT_AUTHORIZED_FOR_SOURCE",
                            self.dispatch(adapter=cb), status="invalid_input", disclosed=True)

    def test_cli_exposes_schema_only_and_never_source_or_adapter(self):
        self.setup_input()
        path = self.root.parent / "synthetic_ec170.json"
        path.write_text(json.dumps(self.prepared), encoding="utf-8")
        cmd = [sys.executable, str(Path(route.__file__)), "--schema-only", str(path),
               "--root", str(self.root), "--business-repo-root", str(self.repo),
               "--parent-pin", self.pin,
               "--run-id", self.route_opts["run_id"],
               "--handoff-id", self.route_opts["handoff_id"],
               "--expected-revision", str(self.route_opts["expected_revision"]),
               "--expected-event-sha256", self.route_opts["expected_event_sha256"],
               "--operation-key", self.route_opts["operation_key"],
               "--task-kind", "code_analysis", "--allow-content-for", "WorkingTree",
               "--approve-route", "--approve-read"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["status"], "partial")
        self.assertNotIn("diff --git", result.stdout)
        self.assertNotIn("+new", result.stdout)
        denied = subprocess.run(cmd[:-2], capture_output=True, text=True, check=False)
        self.assertEqual(denied.returncode, 4)
        self.assertEqual(json.loads(denied.stdout)["reason_code"],
                         "INDEPENDENT_ROUTE_APPROVAL_REQUIRED")
        self.assertNotIn("--dispatch", subprocess.run([sys.executable, str(Path(route.__file__)),
                                                        "--help"], capture_output=True,
                                                       text=True).stdout)


if __name__ == "__main__":
    unittest.main()
