#!/usr/bin/env python3
"""EC231 focused metadata-only developer tests; no native or enterprise run."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import cycle_run_metadata as cm

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

BASE = Path(__file__).resolve().parent.parent


def tasks() -> list[dict]:
    return [{"step_id": "step_code", "action": "CodePrepare", "mode": "WorkingTree", "depends_on": []},
            {"step_id": "step_quality", "action": "QualityRun", "mode": None,
             "depends_on": ["step_code"]},
            {"step_id": "step_report", "action": "ReportPrepare", "mode": "Snapshot",
             "depends_on": ["step_quality"]}]


@unittest.skipUnless(os.name == "posix", "private storage intentionally POSIX-only")
class CycleMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ces-ec231-")
        self.addCleanup(self.tmp.cleanup)
        self.private = Path(self.tmp.name) / "runs"
        self.store = cm.CycleMetadataStore(self.private)
        self.snapshot = b'{"source":"repo","version":1}\n'
        self.kw = dict(snapshot_bytes=self.snapshot, source_ref="git:repo/test/snapshot-1",
                       actor_origin="human", actor_subject="operator-0001", actions=tasks())

    def new(self, **changes) -> dict:
        return self.store.create(**{**self.kw, **changes})

    def record_path(self, record: dict) -> Path:
        return self.private / (record["run_id"] + ".cycle.json")

    def reject(self, record: dict, expected: str) -> None:
        with self.assertRaises(cm.CycleMetadataError) as error:
            cm.validate_record(record)
        self.assertEqual(error.exception.code, expected)

    def reseal(self, record: dict) -> dict:
        record["record_sha256"] = cm.digest(cm.DOMAIN_RECORD, cm._without_digest(record))
        return record

    def test_create_is_durable_real_run_id_and_exact_bytes_bound(self) -> None:
        record = self.new()
        self.assertRegex(record["run_id"], r"^run_v1_[0-9a-f]{48}$")
        self.assertEqual(record["input"]["sha256"], hashlib.sha256(self.snapshot).hexdigest())
        self.assertEqual(record["input"]["byte_length"], len(self.snapshot))
        self.assertEqual(record["action_set_sha256"], cm.digest(cm.DOMAIN_ACTIONS, tasks()))
        self.assertEqual(record["run_state"], "NOT_STARTED")
        self.assertEqual([s["state"] for s in record["steps"]], ["NOT_STARTED"] * 3)
        self.assertTrue(self.private.is_dir())
        self.assertEqual(stat.S_IMODE(self.private.stat().st_mode), 0o700)
        file = self.record_path(record)
        self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
        self.assertEqual(cm.validate_record(json.loads(file.read_text())), record)
        self.assertEqual(self.store.load(record["run_id"]), record)
        self.assertEqual(self.store.inspect(record["run_id"])["record"], record)
        self.assertFalse(self.store.inspect(record["run_id"])["execution_proven"])
        self.assertFalse(self.store.inspect(record["run_id"])["can_resume"])

    def test_no_full_snapshot_or_credentials_persisted(self) -> None:
        marker = b'SENSITIVE_TOKEN_231_77'
        record = self.new(snapshot_bytes=self.snapshot + marker)
        raw = self.record_path(record).read_bytes()
        self.assertNotIn(marker, raw)
        self.assertEqual(record["input"]["provenance"], "CALLER_SUPPLIED_BYTES")
        self.assertFalse(record["input"]["authenticated"])
        self.assertFalse(record["actor"]["verified"])
        self.assertFalse(record["actor"]["permissions_granted"])
        self.assertEqual(set(record["effects"].values()), {False})

    def test_new_ids_never_reuse_and_existing_not_overwritten(self) -> None:
        a = self.new()
        before = self.record_path(a).read_bytes()
        b = self.new()
        self.assertNotEqual(a["run_id"], b["run_id"])
        self.assertEqual(self.record_path(a).read_bytes(), before)

    def test_collision_gets_new_fresh_run_id_without_clobber(self) -> None:
        original = self.new()
        existing = original["run_id"].removeprefix("run_v1_")
        random_value = b'\x31' * 24
        self.assertNotEqual(random_value.hex(), existing)
        with mock.patch.object(cm.secrets, "token_bytes", side_effect=[bytes.fromhex(existing), random_value]):
            next_record = self.new()
        self.assertEqual(next_record["run_id"], "run_v1_" + random_value.hex())
        self.assertEqual(self.store.load(original["run_id"]), original)

    def test_input_is_bytes_not_opaque_hash_and_bounded(self) -> None:
        for bad in (None, "not-bytes", b"", b"A" * (cm.MAX_SNAPSHOT_BYTES + 1)):
            with self.subTest(type=type(bad).__name__):
                with self.assertRaises(cm.CycleMetadataError):
                    self.new(snapshot_bytes=bad)
        self.assertFalse(self.private.exists(), "No RunId minted for invalid input")

    def test_invalid_actor_and_proof_escalation(self) -> None:
        for change in ({"actor_origin":"root"},{"actor_subject":"../escape"},
                       {"actor_subject":"secret=1"}, {"input_completeness":"COMPLETE_VERIFIED"}):
            with self.subTest(change=change), self.assertRaises(cm.CycleMetadataError):
                self.new(**change)
        rec = self.new()
        for key in ("verified", "permissions_granted"):
            modified = copy.deepcopy(rec)
            modified["actor"][key] = True
            self.reject(self.reseal(modified), "CYCLE_ACTOR_AUTHORITY_FORBIDDEN")

    def test_unhashable_attacker_values_fail_closed_not_traceback(self) -> None:
        with self.assertRaises(cm.CycleMetadataError):
            self.new(actor_origin=[])
        with self.assertRaises(cm.CycleMetadataError):
            self.new(input_completeness=[])
        rec = self.new()
        for field, val in (("actor", []), ("input", []), ("steps", [])):
            altered = copy.deepcopy(rec)
            if field == "actor":
                altered["actor"]["origin"] = val
            elif field == "input":
                altered["input"]["completeness"] = val
            else:
                altered["steps"][0]["state"] = val
            with self.subTest(field=field), self.assertRaises(cm.CycleMetadataError):
                cm.validate_record(self.reseal(altered))

    def test_input_coverage_is_declared_not_verified(self) -> None:
        rec = self.new(input_completeness="DECLARED_PARTIAL")
        self.assertEqual(rec["run_state"], "NOT_STARTED")
        self.assertEqual(rec["input"]["completeness"], "DECLARED_PARTIAL")
        rec2 = self.new(input_completeness="DECLARED_COMPLETE")
        self.assertEqual(rec2["run_state"], "NOT_STARTED")
        self.assertEqual(rec2["input"]["authenticated"], False)

    def test_budget_fields_bounded_capture_enforced_not_run_budget(self) -> None:
        rec = self.new()
        self.assertEqual(rec["budget"]["usage"]["input_bytes"], len(self.snapshot))
        self.assertEqual(rec["budget"]["enforcement"], "CAPTURE_ONLY_NO_RUN_ENFORCEMENT")
        self.assertEqual(rec["budget"]["usage"]["steps"], 0)
        for change in ({"max_steps":2}, {"input_bytes":len(self.snapshot)-1},
                       {"wall_ms":0}, {"wall_ms":86_400_001}, {"max_steps":True}):
            bad = copy.deepcopy(rec["budget"]["limits"])
            bad.update(change)
            with self.subTest(change=change), self.assertRaises(cm.CycleMetadataError):
                self.new(limits=bad)

    def test_reference_integrity_bounds_and_duplicates(self) -> None:
        for mutate in (
            lambda t: t[1]["depends_on"].append("step_unknown"),
            lambda t: t[1]["depends_on"].append("step_code"),
            lambda t: t[1]["depends_on"].append("step_quality"),
            lambda t: t[1].update(step_id="step_code"),
            lambda t: t[1].update(action="Delete/Source"),
            lambda t: t[1].update(mode="snapshot"),
            lambda t: t[1].update(extra=True),
        ):
            data = tasks()
            mutate(data)
            with self.subTest(data=data), self.assertRaises(cm.CycleMetadataError):
                self.new(actions=data)

    def test_dependency_cycle_is_only_placeholder_for_ec232(self) -> None:
        data = tasks()
        data[0]["depends_on"] = ["step_report"]
        rec = self.new(actions=data)
        self.assertEqual(rec["dependency_resolution"], "NOT_EVALUATED_EC232")
        self.assertEqual(rec["run_state"], "NOT_STARTED")

    def test_all_unstarted_remains_not_started_and_no_claim(self) -> None:
        rec = self.new()
        for key in ("executed", "write_authorized", "external_delivery_proven", "resume_authorized"):
            tampered = copy.deepcopy(rec)
            tampered["effects"][key] = True
            self.reject(self.reseal(tampered), "CYCLE_EFFECT_CLAIM_FORBIDDEN")
        dirty = copy.deepcopy(rec)
        dirty["steps"][0]["evidence_sha256"] = "a" * 64
        self.reject(self.reseal(dirty), "CYCLE_NOT_STARTED_DIRTY")

    def test_partial_historical_declaration_is_not_execution_proof(self) -> None:
        rec = self.new()
        changed = copy.deepcopy(rec)
        changed["steps"][0].update(state="DECLARED_PARTIAL", observed_at_utc=rec["created_at_utc"],
                                   evidence_sha256="a" * 64, reason_code="CALLER_DECLARED_PARTIAL")
        changed["run_state"] = "PARTIAL"
        changed["budget"]["usage"]["steps"] = 1
        validated = cm.validate_record(self.reseal(changed))
        self.assertEqual(validated["run_state"], "PARTIAL")
        self.assertFalse(validated["effects"]["executed"])
        changed["steps"][0]["observed_at_utc"] = "2010-10-01T00:00:00.000000Z"
        self.reject(self.reseal(changed), "CYCLE_TIMESTAMP_OUT_OF_RANGE")

    def test_unknown_takes_precedence_over_partial_not_complete(self) -> None:
        rec = self.new()
        updated = copy.deepcopy(rec)
        updated["steps"][0].update(state="DECLARED_PARTIAL", observed_at_utc=rec["created_at_utc"],
                                   evidence_sha256="f" * 64, reason_code="CALLER_DECLARED_PARTIAL")
        updated["steps"][1].update(state="UNKNOWN", reason_code="CRASH_UNCERTAIN")
        updated["run_state"] = "UNKNOWN"
        validated = cm.validate_record(self.reseal(updated))
        self.assertEqual(validated["run_state"], "UNKNOWN")
        updated["run_state"] = "PARTIAL"
        self.reject(self.reseal(updated), "CYCLE_RUN_STATE_INCONSISTENT")
        updated["run_state"] = "UNKNOWN"
        updated["steps"][1]["evidence_sha256"] = "a" * 64
        self.reject(self.reseal(updated), "CYCLE_UNKNOWN_EVIDENCE_FORBIDDEN")

    def test_false_success_and_dag_claim_rejected(self) -> None:
        rec = self.new()
        for key, val, code in (("run_state", "COMPLETED", "CYCLE_RUN_STATE_INCONSISTENT"),
                                ("dependency_resolution", "EVALUATED", "CYCLE_DAG_CLAIM_FORBIDDEN")):
            tampered = copy.deepcopy(rec)
            tampered[key] = val
            self.reject(self.reseal(tampered), code)
        tampered = copy.deepcopy(rec)
        tampered["steps"][0]["state"] = "COMPLETED"
        self.reject(self.reseal(tampered), "CYCLE_STEP_STATE_INVALID")

    def test_action_set_input_record_hashes_integrity(self) -> None:
        rec = self.new()
        for mutate, code in (
            (lambda r: r["action_set"][0].update(action="QualityRun"), "CYCLE_ACTION_SET_HASH_MISMATCH"),
            (lambda r: r["steps"].reverse(), "CYCLE_STEP_ORDER_MISMATCH"),
            (lambda r: r["input"].update(sha256="a"*64), "CYCLE_RECORD_HASH_MISMATCH"),
            (lambda r: r.update(record_sha256="a"*64), "CYCLE_RECORD_HASH_MISMATCH"),
        ):
            tampered = copy.deepcopy(rec)
            mutate(tampered)
            if code != "CYCLE_RECORD_HASH_MISMATCH":
                self.reseal(tampered)
            self.reject(tampered, code)

    def test_timestamp_and_runid_semantics(self) -> None:
        rec = self.new()
        changed = copy.deepcopy(rec)
        changed["updated_at_utc"] = (datetime.strptime(rec["created_at_utc"], "%Y-%m-%dT%H:%M:%S.%fZ")+
                                      timedelta(days=31)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        self.reject(self.reseal(changed), "CYCLE_TIMESTAMP_ORDER_INVALID")
        changed = copy.deepcopy(rec)
        changed["updated_at_utc"] = "2026-01-01T00:00:00Z"
        self.reject(self.reseal(changed), "CYCLE_TIMESTAMP_INVALID")
        changed = copy.deepcopy(rec)
        changed["run_id"] = "run_v1_"+"g"*48
        self.reject(self.reseal(changed), "CYCLE_RUN_ID_INVALID")
        with self.assertRaises(cm.CycleMetadataError):
            self.store.load("../../root")

    def test_missing_is_unknown_and_never_not_started(self) -> None:
        missing = "run_v1_" + "a"*48
        result = self.store.inspect(missing)
        self.assertEqual(result["run_state"], "UNKNOWN")
        self.assertEqual(result["reason_code"], "CYCLE_STORE_UNAVAILABLE")
        _ = self.new()
        result = self.store.inspect(missing)
        self.assertEqual(result["reason_code"], "CYCLE_RUN_NOT_FOUND")
        self.assertFalse(result["metadata_valid"])

    def test_corrupt_saved_record_returns_unknown_not_success(self) -> None:
        rec = self.new()
        self.record_path(rec).write_bytes(b'{"schema": "spoof"}')
        result = self.store.inspect(rec["run_id"])
        self.assertEqual(result["run_state"], "UNKNOWN")
        self.assertEqual(result["reason_code"], "CYCLE_RECORD_SHAPE_INVALID")

    def test_duplicate_and_case_colliding_json_rejected(self) -> None:
        for raw in (b'{"a":1,"a":2}', b'{"a":1,"A":2}', b'\xef\xbb\xbf{}', b'{"a":NaN}',b'[]garbage'):
            with self.subTest(raw=raw), self.assertRaises(cm.CycleMetadataError):
                cm.strict_json(raw, 2048)

    def test_unprivileged_store_and_symlink_or_hardlink_records_denied(self) -> None:
        rec = self.new()
        target = self.record_path(rec)
        other = target.parent / "backup.json"
        os.link(target, other)
        self.assertEqual(self.store.inspect(rec["run_id"])["run_state"], "UNKNOWN")
        other.unlink()
        target.unlink()
        os.symlink(Path(self.tmp.name)/"elsewhere", target)
        self.assertEqual(self.store.inspect(rec["run_id"])["run_state"], "UNKNOWN")
        target.unlink()
        self.private.chmod(0o755)
        self.assertEqual(self.store.inspect(rec["run_id"])["reason_code"], "CYCLE_STORE_NOT_PRIVATE")

    def test_non_private_record_permissions_denied(self) -> None:
        rec = self.new()
        self.record_path(rec).chmod(0o644)
        self.assertEqual(self.store.inspect(rec["run_id"])["reason_code"], "CYCLE_RECORD_NOT_PRIVATE")

    def test_cli_create_and_inspect_real_files_no_native_action(self) -> None:
        snapshot = Path(self.tmp.name) / "snap.bin"
        tasks_file = Path(self.tmp.name) / "actions.json"
        snapshot.write_bytes(self.snapshot)
        tasks_file.write_text(json.dumps(tasks()), encoding="utf-8")
        proc = subprocess.run([sys.executable, str(BASE / "construction/cycle_run_metadata.py"),
                               "create", "--store", str(self.private), "--snapshot-file", str(snapshot),
                               "--source-ref", self.kw["source_ref"], "--actor-origin", "human",
                               "--actor-subject", "operator-0001", "--actions-json", str(tasks_file)],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        created = json.loads(proc.stdout)
        self.assertEqual(created["status"], "metadata_created_not_started")
        self.assertFalse(created["native_cycle_action_registered"])
        proc = subprocess.run([sys.executable, str(BASE / "construction/cycle_run_metadata.py"),
                               "inspect", "--store", str(self.private), "--run-id", created["run_id"]],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["record"]["run_id"], created["run_id"])
        self.assertEqual(json.loads(proc.stdout)["run_state"], "NOT_STARTED")

    def test_cli_does_not_mint_for_invalid_actions(self) -> None:
        snap = Path(self.tmp.name) / "snap.bin"
        tasks_file = Path(self.tmp.name) / "tasks.json"
        snap.write_bytes(self.snapshot)
        tasks_file.write_text('[{"step_id":"step_a","action":"DoIt","mode":null,"depends_on":["step_b"]}]')
        proc = subprocess.run([sys.executable, str(BASE / "construction/cycle_run_metadata.py"),
                               "create", "--store", str(self.private), "--snapshot-file", str(snap),
                               "--source-ref", "test", "--actor-origin", "human",
                               "--actor-subject", "operator-0001", "--actions-json", str(tasks_file)],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 4, proc.stderr)
        self.assertIsNone(json.loads(proc.stdout)["run_id"])
        self.assertFalse(self.private.exists())

    @unittest.skipIf(Draft202012Validator is None, "jsonschema not installed")
    def test_json_schema_roundtrip_and_reject_extra_properties(self) -> None:
        schema = json.loads((BASE/"references/cycle-run-metadata.v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        record = self.new()
        Draft202012Validator(schema).validate(record)
        extra = copy.deepcopy(record)
        extra["unknown_field"] = "unallowed"
        self.assertFalse(Draft202012Validator(schema).is_valid(extra))
        self.reject(self.reseal(extra), "CYCLE_RECORD_SHAPE_INVALID")


if __name__ == "__main__":
    unittest.main(verbosity=2)
