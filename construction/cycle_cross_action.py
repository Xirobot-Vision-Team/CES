#!/usr/bin/env python3
"""EC238: conservative cross-action Cycle/EC172 handoff identity binding.

Links one genuine owner-private EC231 Cycle run to one *different* genuine
HMAC-checked EC172 staged AI run/handoff. Associates exact bytes of six
already-produced action-family records using immutable, globally keyed local
receipts. This prevents accidental cross-Run insertion *within this private
store*, not forged producer attestations, same-UID attacks or unauthorized
business execution. No payload, credential, approval or business files saved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

if __package__:
    from . import cycle_run_metadata as md
    from . import task_staging as st
else:
    import cycle_run_metadata as md
    import task_staging as st

SCHEMA = 'ces.cycle_cross_action.v1'
OWNER_SCHEMA = 'ces.cycle_cross_action_owner.v1'
ARTIFACT_SCHEMA = 'ces.cycle_cross_action_artifact.v1'
DOMAIN_OWNER = b'CES-EC238-CYCLE-CROSS-ACTION-OWNER-v1\x00'
DOMAIN_STAGE_OWNER = b'CES-EC238-CYCLE-STAGE-RUN-OWNER-v1\x00'
DOMAIN_ARTIFACT = b'CES-EC238-CYCLE-CROSS-ACTION-ARTIFACT-v1\x00'
MAX_ARTIFACT_BYTES = 524_288
MAX_CANDIDATES = 32
MAX_RECEIPT_BYTES = 8192
MAX_OUTPUT_BYTES = 65_536
CONTEXT_SNAPSHOT_SCHEMA = 'ces.cycle_cross_action_snapshot.v1'
CONTEXT_SNAPSHOT_FIELDS = frozenset(('schema', 'stage_run_id', 'handoff_id',
                                    'source_context_sha256', 'source_identity_sha256'))
FAMILY_SCHEMAS = {
    'Code': frozenset(('ces.code_prepare_multisource.v1', 'ces.ai_code_context.v1')),
    'Finding': frozenset(('ces.finding_show_result.v1', 'ces.finding_save_result.v1')),
    'Quality': frozenset(('ces.quality_show.v1', 'ces.quality_finding_link.v1')),
    'Report': frozenset(('ces.report_prepare.v1', 'ces.report_writing_handoff.v1')),
    'Knowledge': frozenset(('ces.knowledge_update_handoff.v1', 'ces.knowledge_impact.v1')),
    'Delivery': frozenset(('ces.delivery_preview.v1', 'ces.delivery_redaction.v1')),
}
OWNER_FIELDS = frozenset((
    'schema', 'run_id', 'handoff_id', 'record_sha256', 'action_set_sha256',
    'input_sha256', 'source_ref', 'stage_parent_pin', 'stage_run_id',
    'stage_checkpoint_sha256', 'stage_record_sha256', 'stage_revision',
    'stage_event_sha256', 'source_context_sha256', 'source_identity_sha256',
    'authority', 'binding_sha256',
))
STAGE_OWNER_SCHEMA = 'ces.cycle_cross_action_stage_owner.v1'
STAGE_OWNER_FIELDS = frozenset((
    'schema', 'run_id', 'stage_run_id', 'record_sha256',
    'source_context_sha256', 'source_identity_sha256', 'authority', 'binding_sha256',
))
ARTIFACT_FIELDS = frozenset((
    'schema', 'run_id', 'handoff_id', 'family', 'step_id', 'producer_schema',
    'artifact_sha256', 'artifact_bytes', 'owner_binding_sha256',
    'identity_fields_checked', 'artifact_producer_authenticated',
    'business_result_proven', 'authority', 'binding_sha256',
))
OWNER_AUTHORITY = 'LOCAL_EC231_EC172_CONSISTENCY_ONLY_NOT_SOURCE_OR_ACTOR_ATTESTATION'
ARTIFACT_AUTHORITY = 'ORIGINAL_BYTES_HASH_LOCALLY_BOUND_NOT_PRODUCER_ATTESTED'
OWNER_FILE = '.cross-owner.json'
ARTIFACT_FILE = '.cross-artifact.json'
STAGE_OWNER_FILE = '.cross-stage-owner.json'
SHA = re.compile(r'[0-9a-f]{64}\Z')


class CrossActionError(ValueError):
    def __init__(self, code: str, *, unknown: bool = False):
        super().__init__(code)
        self.code, self.unknown = code, unknown


def need(ok: bool, code: str, *, unknown: bool = False) -> None:
    if not ok:
        raise CrossActionError(code, unknown=unknown)


def digest(domain: bytes, obj: dict[str, Any]) -> str:
    return md.digest(domain, obj)


def _owner_name(handoff_id: str) -> str:
    md.token(handoff_id, md.HANDOFF_RE, 'CROSS_HANDOFF_ID_INVALID')
    return handoff_id + OWNER_FILE


def _stage_owner_name(stage_run_id: str) -> str:
    md.token(stage_run_id, md.RUN_RE, 'CROSS_STAGE_RUN_INVALID')
    return stage_run_id + STAGE_OWNER_FILE


def _artifact_name(raw_sha: str) -> str:
    md.token(raw_sha, md.SHA_RE, 'CROSS_ARTIFACT_DIGEST_INVALID')
    return 'artifact_' + raw_sha + ARTIFACT_FILE


def _read(fd: int, name: str) -> dict[str, Any]:
    # No-follow, owner-private, non-hardlinked leaf, exact bounded strict JSON.
    try:
        opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0), dir_fd=fd)
    except FileNotFoundError as exc:
        raise CrossActionError('CROSS_BINDING_NOT_FOUND', unknown=True) from exc
    except OSError as exc:
        raise CrossActionError('CROSS_BINDING_UNAVAILABLE', unknown=True) from exc
    try:
        f = os.fstat(opened)
        need(stat.S_ISREG(f.st_mode) and f.st_uid == os.geteuid() and
             stat.S_IMODE(f.st_mode) == 0o600 and f.st_nlink == 1 and
             0 < f.st_size <= MAX_RECEIPT_BYTES,
             'CROSS_BINDING_NOT_PRIVATE', unknown=True)
        raw = os.read(opened, MAX_RECEIPT_BYTES + 1)
        need(len(raw) == f.st_size, 'CROSS_BINDING_READ_CHANGED', unknown=True)
    except OSError as exc:
        raise CrossActionError('CROSS_BINDING_UNAVAILABLE', unknown=True) from exc
    finally:
        os.close(opened)
    try:
        value = md.strict_json(raw, MAX_RECEIPT_BYTES)
    except md.CycleMetadataError as exc:
        raise CrossActionError('CROSS_BINDING_JSON_INVALID', unknown=True) from exc
    need(type(value) is dict, 'CROSS_BINDING_SHAPE_INVALID', unknown=True)
    return value


def _write_once(fd: int, name: str, record: dict[str, Any]) -> bool:
    """Return False on byte-identical replay. Existing conflict NEVER overwritten.

    If crash/fsync/readback is uncertain, leave the file for manual inspection.
    No idempotent success is claimed after an uncertain write.
    """
    raw = md.canonical(record) + b'\n'
    need(len(raw) <= MAX_RECEIPT_BYTES, 'CROSS_RECEIPT_TOO_LARGE')
    try:
        created = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                          getattr(os, 'O_CLOEXEC', 0), 0o600, dir_fd=fd)
    except FileExistsError:
        existing = _read(fd, name)
        need(md.canonical(existing) == md.canonical(record), 'CROSS_IMMUTABLE_OWNER_OR_ARTIFACT_CONFLICT')
        return False
    except OSError as exc:
        raise CrossActionError('CROSS_CREATE_UNAVAILABLE', unknown=True) from exc
    try:
        try:
            os.fchmod(created, 0o600)
            md._write_all(created, raw)
            os.fsync(created)
        except (OSError, md.CycleMetadataError) as exc:
            raise CrossActionError('CROSS_COMMIT_UNCERTAIN', unknown=True) from exc
    finally:
        os.close(created)
    try:
        os.fsync(fd)
        need(md.canonical(_read(fd, name)) == md.canonical(record),
             'CROSS_COMMIT_READBACK_CHANGED', unknown=True)
    except (OSError, CrossActionError) as exc:
        raise CrossActionError('CROSS_COMMIT_UNCERTAIN', unknown=True) from exc
    return True


def _validate_owner(record: Any, *, run_id: str, handoff_id: str) -> dict[str, Any]:
    need(type(record) is dict and set(record) == OWNER_FIELDS and
         record['schema'] == OWNER_SCHEMA and record['run_id'] == run_id and
         record['handoff_id'] == handoff_id and record['authority'] == OWNER_AUTHORITY,
         'CROSS_OWNER_RECORD_INVALID', unknown=True)
    for key in ('record_sha256', 'action_set_sha256', 'input_sha256', 'stage_parent_pin',
                'stage_checkpoint_sha256', 'stage_record_sha256', 'stage_event_sha256',
                'source_context_sha256', 'source_identity_sha256', 'binding_sha256'):
        need(type(record[key]) is str and SHA.fullmatch(record[key]) is not None,
             'CROSS_OWNER_HASH_INVALID', unknown=True)
    md.token(record['stage_run_id'], md.RUN_RE, 'CROSS_STAGE_RUN_INVALID')
    md.token(record['source_ref'], md.SOURCE_RE, 'CROSS_SOURCE_REF_INVALID')
    need(type(record['stage_revision']) is int and 1 <= record['stage_revision'] <= 256,
         'CROSS_STAGE_REVISION_INVALID', unknown=True)
    need(digest(DOMAIN_OWNER, {k: v for k, v in record.items() if k != 'binding_sha256'}) ==
         record['binding_sha256'], 'CROSS_OWNER_HASH_DRIFT', unknown=True)
    return record


def _validate_stage_owner(record: Any, *, stage_run_id: str) -> dict[str, Any]:
    need(type(record) is dict and set(record) == STAGE_OWNER_FIELDS and
         record['schema'] == STAGE_OWNER_SCHEMA and
         record['stage_run_id'] == stage_run_id and
         record['authority'] == OWNER_AUTHORITY,
         'CROSS_STAGE_OWNER_INVALID', unknown=True)
    md.token(record['run_id'], md.RUN_RE, 'CROSS_STAGE_OWNER_RUN_INVALID')
    for key in ('record_sha256', 'source_context_sha256', 'source_identity_sha256',
                'binding_sha256'):
        md.token(record[key], md.SHA_RE, 'CROSS_STAGE_OWNER_HASH_INVALID')
    need(digest(DOMAIN_STAGE_OWNER, {k: v for k, v in record.items()
                                     if k != 'binding_sha256'}) == record['binding_sha256'],
         'CROSS_STAGE_OWNER_HASH_DRIFT', unknown=True)
    return record


def _validate_artifact(record: Any, *, sha: str) -> dict[str, Any]:
    need(type(record) is dict and set(record) == ARTIFACT_FIELDS and
         record['schema'] == ARTIFACT_SCHEMA and record['artifact_sha256'] == sha and
         record['authority'] == ARTIFACT_AUTHORITY and
         record['artifact_producer_authenticated'] is False and
         record['business_result_proven'] is False,
         'CROSS_ARTIFACT_RECEIPT_INVALID', unknown=True)
    md.token(record['run_id'], md.RUN_RE, 'CROSS_ARTIFACT_RUN_INVALID')
    md.token(record['handoff_id'], md.HANDOFF_RE, 'CROSS_ARTIFACT_HANDOFF_INVALID')
    md.token(record['step_id'], md.STEP_RE, 'CROSS_ARTIFACT_STEP_INVALID')
    need(record['family'] in FAMILY_SCHEMAS and
         record['producer_schema'] in FAMILY_SCHEMAS[record['family']] and
         type(record['artifact_bytes']) is int and 1 <= record['artifact_bytes'] <= MAX_ARTIFACT_BYTES and
         type(record['identity_fields_checked']) is int and 0 <= record['identity_fields_checked'] <= 10000,
         'CROSS_ARTIFACT_FIELDS_INVALID', unknown=True)
    for k in ('owner_binding_sha256', 'binding_sha256'):
        md.token(record[k], md.SHA_RE, 'CROSS_ARTIFACT_HASH_INVALID')
    need(digest(DOMAIN_ARTIFACT, {k: v for k, v in record.items() if k != 'binding_sha256'}) ==
         record['binding_sha256'], 'CROSS_ARTIFACT_HASH_DRIFT', unknown=True)
    return record


def _embedded_claims(doc: Any, *, cycle_run: str, staged_run: str,
                     handoff_id: str, context: str, identity: str) -> int:
    """Reject *known identity keys* in a producer's actual JSON if conflicting.

    CI numeric run IDs are distinct from CES 192-bit RunIds. This intentionally
    does not certify that an arbitrary producer was honestly authored.
    """
    seen = 0
    pending = [(doc, 0)]
    nodes = 0
    while pending:
        obj, depth = pending.pop()
        nodes += 1
        need(nodes <= 16000 and depth <= 20, 'CROSS_ARTIFACT_NESTING_LIMIT')
        if type(obj) is list:
            pending.extend((v, depth + 1) for v in obj)
        elif type(obj) is dict:
            for k, v in obj.items():
                if k in ('handoff_id', 'origin_handoff_id') and v is not None:
                    seen += 1
                    need(type(v) is str and v == handoff_id, 'CROSS_FOREIGN_HANDOFF_REF')
                elif k in ('handoff_ids',) and v is not None:
                    seen += 1
                    need(type(v) is list and all(type(i) is str and i == handoff_id for i in v),
                         'CROSS_FOREIGN_HANDOFF_REF')
                elif k in ('run_id', 'origin_run_id', 'stage_run_id', 'cycle_run_id') and v is not None:
                    if k == 'cycle_run_id':
                        seen += 1
                        need(type(v) is str and v == cycle_run, 'CROSS_FOREIGN_CYCLE_RUN')
                    elif k == 'stage_run_id':
                        seen += 1
                        need(type(v) is str and v == staged_run, 'CROSS_FOREIGN_STAGE_RUN')
                    elif type(v) is str and v.startswith('run_v1_'):
                        seen += 1
                        need(v in (cycle_run, staged_run), 'CROSS_FOREIGN_RUN_REF')
                elif k == 'source_context_sha256' and v is not None:
                    seen += 1
                    need(type(v) is str and v == context, 'CROSS_FOREIGN_SOURCE_CONTEXT')
                elif k == 'source_identity_sha256' and v is not None:
                    seen += 1
                    need(type(v) is str and v == identity, 'CROSS_FOREIGN_SOURCE_IDENTITY')
                pending.append((v, depth + 1))
    return seen


def _producer(raw: bytes, family: str, *, cycle_run: str, staged_run: str,
              handoff: str, context: str, identity: str) -> tuple[str, int, str]:
    need(type(family) is str and family in FAMILY_SCHEMAS, 'CROSS_FAMILY_INVALID')
    try:
        doc = md.strict_json(raw, MAX_ARTIFACT_BYTES)
    except md.CycleMetadataError as exc:
        raise CrossActionError('CROSS_PRODUCER_JSON_INVALID') from exc
    need(type(doc) is dict and type(doc.get('schema')) is str and
         doc['schema'] in FAMILY_SCHEMAS[family], 'CROSS_PRODUCER_SCHEMA_FAMILY_MISMATCH')
    # Require a real producer envelope, not a single marker pretending to be a record.
    need(len(doc) >= 4 and type(doc.get('status')) is str and
         doc['status'] in ('success', 'partial', 'unavailable', 'invalid_input', 'blocked'),
         'CROSS_PRODUCER_ENVELOPE_REQUIRED')
    checked = _embedded_claims(doc, cycle_run=cycle_run, staged_run=staged_run,
                               handoff_id=handoff, context=context, identity=identity)
    return doc['schema'], checked, hashlib.sha256(raw).hexdigest()


class CycleCrossActionLedger:
    """Append-only local references. Never executes/accepts a producer action."""

    def __init__(self, cycle_store: str | Path, stage_store: str | Path,
                 business_repo_root: str | Path) -> None:
        self.store = md.CycleMetadataStore(cycle_store)
        self.path = Path(cycle_store)
        self.stage = st.TaskStaging(str(stage_store), str(business_repo_root))
        # The other store has a different local authentication and namespace.
        a, b = self.path.resolve(strict=False), Path(stage_store).resolve(strict=False)
        c = Path(business_repo_root).resolve(strict=False)
        need(not any(x == y or x in y.parents or y in x.parents
                     for x, y in ((a, b), (a, c))),
             'CROSS_PRIVATE_STORE_MUST_NOT_OVERLAP_STAGE_OR_BUSINESS')

    def _stage(self, handoff_id: str, parent_pin: str) -> dict[str, Any]:
        md.token(parent_pin, md.SHA_RE, 'CROSS_PARENT_PIN_INVALID')
        with self.stage._locked() as (fd, manifest, key):
            need(manifest is not None and key is not None, 'CROSS_STAGE_NOT_INITIALIZED', unknown=True)
            self.stage._expect_pin(parent_pin, manifest)
            records = self.stage._all(fd, key, manifest)
            matches = [r for r in records if any(
                h['handoff_id'] == handoff_id for h in r['checkpoint']['handoffs'])]
            need(len(matches) == 1, 'CROSS_HANDOFF_NOT_UNIQUELY_STAGED', unknown=True)
            r = matches[0]
            st._check_expiry(r, st._now(self.stage.clock))
            matching = [h for h in r['checkpoint']['handoffs'] if h['handoff_id'] == handoff_id]
            need(len(matching) == 1 and matching[0]['run_id'] == r['run_id'] and
                 r['source']['task_kind'] == 'code_analysis',
                 'CROSS_STAGE_HANDOFF_RELATION_INVALID', unknown=True)
            return {
                'stage_parent_pin': r['parent_pin'], 'stage_run_id': r['run_id'],
                'stage_checkpoint_sha256': r['checkpoint_sha256'],
                'stage_record_sha256': hashlib.sha256(md.canonical(r)).hexdigest(),
                'stage_revision': r['revision'], 'stage_event_sha256': r['last_event_sha256'],
                'source_context_sha256': r['source']['context_sha256'],
                'source_identity_sha256': r['source']['identity_sha256'],
            }

    @staticmethod
    def _original(record: dict[str, Any]) -> dict[str, Any]:
        need(record['run_state'] == 'NOT_STARTED' and
             any(a['action'].startswith('Code') or a['action'] == 'AIHandoff'
                 for a in record['action_set']),
             'CROSS_CYCLE_NOT_PRISTINE_OR_NO_CODE_ORIGIN')
        return record

    def _live_owner(self, run_id: str, handoff_id: str, parent_pin: str) -> dict[str, Any]:
        fd = md._safe_dir(self.path, create=False)
        try:
            owner = _validate_owner(_read(fd, _owner_name(handoff_id)),
                                    run_id=run_id, handoff_id=handoff_id)
            stage_owner = _validate_stage_owner(
                _read(fd, _stage_owner_name(owner['stage_run_id'])),
                stage_run_id=owner['stage_run_id'])
        finally:
            os.close(fd)
        need((stage_owner['run_id'], stage_owner['record_sha256'],
              stage_owner['source_context_sha256'], stage_owner['source_identity_sha256']) ==
             (run_id, owner['record_sha256'], owner['source_context_sha256'],
              owner['source_identity_sha256']),
             'CROSS_STAGE_OWNER_OTHER_RUN_OR_DRIFT', unknown=True)
        need(owner['stage_parent_pin'] == parent_pin, 'CROSS_STAGE_PIN_MISMATCH')
        original = self._original(self.store.load(run_id))
        need((owner['record_sha256'], owner['action_set_sha256'], owner['input_sha256'],
              owner['source_ref']) ==
             (original['record_sha256'], original['action_set_sha256'],
              original['input']['sha256'], original['input']['source_ref']),
             'CROSS_CYCLE_ORIGINAL_DRIFT', unknown=True)
        now = self._stage(handoff_id, parent_pin)
        need(all(owner[k] == v for k, v in now.items()),
             'CROSS_STAGED_HANDOFF_DRIFT', unknown=True)
        return owner

    @staticmethod
    def _snapshot_anchor(raw: bytes, handoff_id: str, staged: dict[str, Any]) -> None:
        # EC231 stored only the hash of caller bytes, not an independent stage
        # provenance. Require an EXACT explicit original Cycle snapshot anchor.
        # Ordinary older EC231 snapshots are deliberately not auto-upgraded.
        try:
            obj = md.strict_json(raw, md.MAX_SNAPSHOT_BYTES)
        except md.CycleMetadataError as exc:
            raise CrossActionError('CROSS_SNAPSHOT_ANCHOR_NOT_VALID') from exc
        need(type(obj) is dict and set(obj) == CONTEXT_SNAPSHOT_FIELDS and
             obj['schema'] == CONTEXT_SNAPSHOT_SCHEMA and
             obj['stage_run_id'] == staged['stage_run_id'] and
             obj['handoff_id'] == handoff_id and
             obj['source_context_sha256'] == staged['source_context_sha256'] and
             obj['source_identity_sha256'] == staged['source_identity_sha256'],
             'CROSS_SNAPSHOT_NOT_SAME_STAGED_HANDOFF')

    def link(self, run_id: str, handoff_id: str, *, snapshot_bytes: bytes,
             source_ref: str, expected_stage_parent_pin: str) -> dict[str, Any]:
        """Bind actual saved Run+staged handoff, requiring fresh EC231 snapshot bytes.

        Original EC171 staged run has its OWN RunId; it is never re-labelled as
        the Cycle RunId. This is a local explicit association, not authorization.
        """
        md.token(run_id, md.RUN_RE, 'CROSS_RUN_ID_INVALID')
        md.token(handoff_id, md.HANDOFF_RE, 'CROSS_HANDOFF_ID_INVALID')
        need(type(snapshot_bytes) is bytes and 1 <= len(snapshot_bytes) <= md.MAX_SNAPSHOT_BYTES,
             'CROSS_FRESH_SNAPSHOT_REQUIRED')
        md.token(source_ref, md.SOURCE_RE, 'CROSS_SOURCE_REF_INVALID')
        original = self._original(self.store.load(run_id))
        need(original['input']['sha256'] == hashlib.sha256(snapshot_bytes).hexdigest() and
             original['input']['byte_length'] == len(snapshot_bytes) and
             original['input']['source_ref'] == source_ref,
             'CROSS_FRESH_INPUT_NOT_SAME_RUN')
        staged = self._stage(handoff_id, expected_stage_parent_pin)
        self._snapshot_anchor(snapshot_bytes, handoff_id, staged)
        owner = {
            'schema': OWNER_SCHEMA, 'run_id': run_id, 'handoff_id': handoff_id,
            'record_sha256': original['record_sha256'],
            'action_set_sha256': original['action_set_sha256'],
            'input_sha256': original['input']['sha256'], 'source_ref': source_ref,
            **staged, 'authority': OWNER_AUTHORITY,
        }
        owner['binding_sha256'] = digest(DOMAIN_OWNER, owner)
        stage_owner = {
            'schema': STAGE_OWNER_SCHEMA, 'run_id': run_id,
            'stage_run_id': staged['stage_run_id'],
            'record_sha256': original['record_sha256'],
            'source_context_sha256': staged['source_context_sha256'],
            'source_identity_sha256': staged['source_identity_sha256'],
            'authority': OWNER_AUTHORITY,
        }
        stage_owner['binding_sha256'] = digest(DOMAIN_STAGE_OWNER, stage_owner)
        fd = md._safe_dir(self.path, create=False)
        try:
            # Stage RunId has only ONE Cycle owner, even when EC171 staged
            # multiple genuine handoffs. Exclusive create is the collision gate.
            # The two receipts are not an atomic multi-file transaction; crash
            # ambiguity is fail-closed and deferred to EC240/host acceptance.
            _write_once(fd, _stage_owner_name(staged['stage_run_id']), stage_owner)
            created = _write_once(fd, _owner_name(handoff_id), owner)
        finally:
            os.close(fd)
        live = self._live_owner(run_id, handoff_id, expected_stage_parent_pin)
        need(md.canonical(live) == md.canonical(owner),
             'CROSS_OWNER_CHANGED_DURING_LINK', unknown=True)
        need(self.store.load(run_id) == original,
             'CROSS_CYCLE_CHANGED_DURING_LINK', unknown=True)
        return self._result('LINKED_LOCAL_ONLY', 'CROSS_LINK_CREATED' if created else 'CROSS_LINK_REPLAY',
                            run_id, handoff_id, owner, [])

    def _step(self, run_id: str, family: str, step_id: str) -> None:
        original = self._original(self.store.load(run_id))
        md.token(step_id, md.STEP_RE, 'CROSS_STEP_ID_INVALID')
        need(any(a['step_id'] == step_id and a['action'].startswith(family)
                 for a in original['action_set']), 'CROSS_STEP_ACTION_FAMILY_MISMATCH')

    def attach(self, run_id: str, handoff_id: str, *, expected_stage_parent_pin: str,
               family: str, step_id: str, artifact_bytes: bytes) -> dict[str, Any]:
        owner = self._live_owner(run_id, handoff_id, expected_stage_parent_pin)
        self._step(run_id, family, step_id)
        producer_schema, checked, raw_sha = _producer(
            artifact_bytes, family, cycle_run=run_id,
            staged_run=owner['stage_run_id'], handoff=handoff_id,
            context=owner['source_context_sha256'], identity=owner['source_identity_sha256'])
        entry = {
            'schema': ARTIFACT_SCHEMA, 'run_id': run_id, 'handoff_id': handoff_id,
            'family': family, 'step_id': step_id, 'producer_schema': producer_schema,
            'artifact_sha256': raw_sha, 'artifact_bytes': len(artifact_bytes),
            'owner_binding_sha256': owner['binding_sha256'],
            'identity_fields_checked': checked,
            'artifact_producer_authenticated': False, 'business_result_proven': False,
            'authority': ARTIFACT_AUTHORITY,
        }
        entry['binding_sha256'] = digest(DOMAIN_ARTIFACT, entry)
        fd = md._safe_dir(self.path, create=False)
        try:
            created = _write_once(fd, _artifact_name(raw_sha), entry)
        finally:
            os.close(fd)
        self._live_owner(run_id, handoff_id, expected_stage_parent_pin)
        need(self.store.load(run_id)['record_sha256'] == owner['record_sha256'],
             'CROSS_CYCLE_CHANGED_DURING_ATTACH', unknown=True)
        return self._result('ATTACHED_LOCAL_ONLY',
                            'CROSS_ARTIFACT_ATTACHED' if created else 'CROSS_ARTIFACT_REPLAY',
                            run_id, handoff_id, owner, [entry])

    @staticmethod
    def _result(status: str, reason: str, run_id: str | None, handoff: str | None,
                owner: dict[str, Any] | None, entries: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            'schema': SCHEMA, 'status': status, 'reason_code': reason,
            'run_id': run_id, 'handoff_id': handoff,
            'cycle_record_sha256': owner['record_sha256'] if owner else None,
            'owner_binding_sha256': owner['binding_sha256'] if owner else None,
            'stage_run_id': owner['stage_run_id'] if owner else None,
            'stage_context_sha256': owner['source_context_sha256'] if owner else None,
            'families': sorted({e['family'] for e in entries}),
            'artifacts': [{k: e[k] for k in ('family', 'step_id', 'producer_schema',
                                              'artifact_sha256', 'artifact_bytes',
                                              'identity_fields_checked')} for e in entries],
            'all_six_present': len({e['family'] for e in entries}) == 6,
            'local_identity_consistent': status in ('LINKED_LOCAL_ONLY', 'ATTACHED_LOCAL_ONLY',
                                                   'CONSISTENT_LOCAL_ONLY'),
            'producer_authenticated': False, 'actor_authenticated': False,
            'source_authenticated': False, 'business_steps_executed_proven': False,
            'permission_granted': False, 'business_write_performed': False,
            'native_cycle_action_registered': False,
        }

    def check(self, run_id: str, handoff_id: str, *, expected_stage_parent_pin: str,
              candidates: list[dict[str, Any]]) -> dict[str, Any]:
        """Read fresh artifact bytes and verify each exact previously saved receipt.

        No candidates yields an empty diagnostic, not an implicit success. A
        missing binding is BLOCKED, corrupt/drifting sources are UNKNOWN.
        """
        display_run = run_id if type(run_id) is str and md.RUN_RE.fullmatch(run_id) else None
        display_handoff = (handoff_id if type(handoff_id) is str and
                           md.HANDOFF_RE.fullmatch(handoff_id) else None)
        try:
            md.token(run_id, md.RUN_RE, 'CROSS_RUN_ID_INVALID')
            md.token(handoff_id, md.HANDOFF_RE, 'CROSS_HANDOFF_ID_INVALID')
            need(type(candidates) is list and 1 <= len(candidates) <= MAX_CANDIDATES,
                 'CROSS_CANDIDATE_COUNT_INVALID')
            owner = self._live_owner(run_id, handoff_id, expected_stage_parent_pin)
            entries = []
            seen = set()
            fd = md._safe_dir(self.path, create=False)
            try:
                for obj in candidates:
                    need(type(obj) is dict and set(obj) == {'family', 'step_id', 'artifact_bytes'},
                         'CROSS_CANDIDATE_SHAPE_INVALID')
                    family, step_id, raw = (obj[k] for k in ('family', 'step_id', 'artifact_bytes'))
                    self._step(run_id, family, step_id)
                    schema, checked, sha = _producer(
                        raw, family, cycle_run=run_id, staged_run=owner['stage_run_id'],
                        handoff=handoff_id, context=owner['source_context_sha256'],
                        identity=owner['source_identity_sha256'])
                    need(sha not in seen, 'CROSS_DUPLICATE_ARTIFACT_IN_BATCH')
                    seen.add(sha)
                    try:
                        entry = _validate_artifact(_read(fd, _artifact_name(sha)), sha=sha)
                    except CrossActionError as exc:
                        if exc.code == 'CROSS_BINDING_NOT_FOUND':
                            raise CrossActionError('CROSS_ARTIFACT_NOT_REGISTERED') from exc
                        raise
                    need(entry['run_id'] == run_id and entry['handoff_id'] == handoff_id and
                         entry['owner_binding_sha256'] == owner['binding_sha256'] and
                         entry['family'] == family and entry['step_id'] == step_id and
                         entry['artifact_bytes'] == len(raw) and
                         entry['producer_schema'] == schema and
                         entry['identity_fields_checked'] == checked,
                         'CROSS_OTHER_RUN_OR_STEP_ARTIFACT')
                    entries.append(entry)
            finally:
                os.close(fd)
            # Exact same real sources, re-checked after reading all producer bytes.
            again = self._live_owner(run_id, handoff_id, expected_stage_parent_pin)
            need(md.canonical(again) == md.canonical(owner),
                 'CROSS_SOURCE_CHANGED_DURING_CHECK', unknown=True)
            result = self._result('CONSISTENT_LOCAL_ONLY', 'CROSS_LOCAL_IDS_AND_BYTES_CONSISTENT',
                                  run_id, handoff_id, owner, entries)
        except (CrossActionError, md.CycleMetadataError, st.StageError, OSError) as exc:
            unknown = (not isinstance(exc, CrossActionError) or exc.unknown)
            reason = exc.code if hasattr(exc, 'code') else 'CROSS_IO_UNAVAILABLE'
            result = self._result('UNKNOWN_BLOCKED' if unknown else 'BLOCKED_MIXED_CONTEXT',
                                  reason, display_run, display_handoff, None, [])
        need(len(md.canonical(result)) <= MAX_OUTPUT_BYTES, 'CROSS_RESULT_TOO_LARGE', unknown=True)
        return result


def _file(path: str, maximum: int) -> bytes:
    # Reuse the exact existing no-follow regular input file boundary, keeping
    # file paths out of saved metadata and JSON responses.
    return md._read_input_file(Path(path), maximum)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='EC238 cross-action immutable local identity check')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('link', 'attach', 'check'):
        c = commands.add_parser(name)
        for flag in ('cycle-store', 'stage-store', 'business-repo', 'run-id',
                     'handoff-id', 'stage-parent-pin'):
            c.add_argument('--' + flag, required=True)
        if name == 'link':
            c.add_argument('--snapshot-file', required=True)
            c.add_argument('--source-ref', required=True)
        elif name == 'attach':
            c.add_argument('--family', required=True, choices=sorted(FAMILY_SCHEMAS))
            c.add_argument('--step-id', required=True)
            c.add_argument('--artifact-file', required=True)
        else:
            c.add_argument('--candidates-json', required=True,
                           help='local list of {family,step_id,artifact_file} entries')
    args = parser.parse_args(argv)
    try:
        ledger = CycleCrossActionLedger(args.cycle_store, args.stage_store, args.business_repo)
        shared = dict(run_id=args.run_id, handoff_id=args.handoff_id,
                      expected_stage_parent_pin=args.stage_parent_pin)
        if args.command == 'link':
            response = ledger.link(**shared, snapshot_bytes=_file(args.snapshot_file, md.MAX_SNAPSHOT_BYTES),
                                   source_ref=args.source_ref)
        elif args.command == 'attach':
            response = ledger.attach(**shared, family=args.family, step_id=args.step_id,
                                     artifact_bytes=_file(args.artifact_file, MAX_ARTIFACT_BYTES))
        else:
            rows = md.strict_json(_file(args.candidates_json, 65_536), 65_536)
            need(type(rows) is list and 1 <= len(rows) <= MAX_CANDIDATES,
                 'CROSS_CANDIDATES_JSON_INVALID')
            candidates = []
            for row in rows:
                need(type(row) is dict and set(row) == {'family', 'step_id', 'artifact_file'},
                     'CROSS_CANDIDATE_ROW_INVALID')
                candidates.append({'family': row['family'], 'step_id': row['step_id'],
                                   'artifact_bytes': _file(row['artifact_file'], MAX_ARTIFACT_BYTES)})
            response = ledger.check(**shared, candidates=candidates)
        exit_code = {'LINKED_LOCAL_ONLY': 2, 'ATTACHED_LOCAL_ONLY': 2,
                     'CONSISTENT_LOCAL_ONLY': 2, 'BLOCKED_MIXED_CONTEXT': 3,
                     'UNKNOWN_BLOCKED': 5}[response['status']]
    except (CrossActionError, md.CycleMetadataError, st.StageError, OSError) as exc:
        code = exc.code if hasattr(exc, 'code') else 'CROSS_IO_UNAVAILABLE'
        blocked = isinstance(exc, CrossActionError) and not exc.unknown
        response = CycleCrossActionLedger._result(
            'BLOCKED_MIXED_CONTEXT' if blocked else 'UNKNOWN_BLOCKED',
            code, None, None, None, [])
        exit_code = 3 if blocked else 5
    print(json.dumps(response, sort_keys=True, separators=(',', ':'), ensure_ascii=True))
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
