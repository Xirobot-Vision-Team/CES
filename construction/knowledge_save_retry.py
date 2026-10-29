#!/usr/bin/env python3
"""EC209: evidence-bound, no-write conflict assessment and explicit CES retry proposal.

Only an EC208 *local metadata* chain is rebased, never the original chapter.
The original request must have been valid at an immutable ancestor, and every
intervening version must have edited another section. Returning a new proposed
request REQUIRES a separately pinned EC209 grant; saving it still requires
an independent EC208 write grant and fresh reviewer/owner Ed25519 approvals.

Nothing here automatically merges, signs, writes, retries unknown I/O results,
or asserts live Git/provider knowledge target freshness. All source and EC206/
EC207 read permissions are replayed; POSIX version locking is inherited.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any

try:
    from . import knowledge_version_save as vs
    from . import knowledge_candidate_store as kc
    from . import knowledge_update_handoff as kh
    from . import knowledge_boundary as kb
except ImportError:
    import knowledge_version_save as vs
    import knowledge_candidate_store as kc
    import knowledge_update_handoff as kh
    import knowledge_boundary as kb

SCHEMA = 'ces.knowledge_save_retry.v1'
INTENT_SCHEMA = 'ces.knowledge_save_retry_intent.v1'
POLICY_SCHEMA = 'ces.knowledge_save_retry_policy.v1'
PURPOSE = 'prepare_reviewed_disjoint_metadata_retry_request_only'
ACKNOWLEDGEMENT = 'I_REVIEWED_INTERVENING_VERSION_RECEIPTS_AND_REQUIRE_NEW_APPROVALS'
MAX_INTENT = 8192
MAX_POLICY = 8192


class RetryError(ValueError):
    def __init__(self, reason: str, status: str = 'unavailable') -> None:
        super().__init__(reason)
        self.reason, self.status = reason, status


def require(value: bool, reason: str, status: str = 'unavailable') -> None:
    if not value:
        raise RetryError(reason, status)


def _response(status: str, reason: str, *, subject: dict[str, Any] | None = None,
              prepared: bool = False) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'status': status,
        'exit_code': {'partial': 2, 'invalid_input': 4, 'unavailable': 5}[status],
        'reason_code': 'KNOWLEDGE_RETRY_' + reason,
        'subject': subject,
        'retry_request_prepared': prepared,
        'local_version_metadata_written': False,
        'source_knowledge_file_written': False,
        'business_repository_written': False,
        'existing_version_overwritten': False,
        'issue_or_provider_written': False,
        'published': False,
        'old_approvals_reused': False,
        'new_approvals_created_or_verified': False,
        'new_write_permission_granted': False,
        'auto_merge_or_auto_retry_performed': False,
        'organizational_signer_identity_authenticated': False,
        'current_architecture_or_delivery_verified': False,
        'native_knowledge_route_registered': False,
    }


def _receipt(row: dict[str, Any]) -> dict[str, Any]:
    return {'sequence': row['sequence'], 'version_id': row['version_id'],
            'parent_version_id': row['body']['parent_version_id'],
            'content_sha256': row['body']['content_sha256'],
            'modified_section_index': row['body']['section_index']}


def _summary_ok(value: Any) -> bool:
    return (type(value) is str and value.strip() and
            len(value.encode('utf-8', 'strict')) <= vs.MAX_SUMMARY_BYTES and
            not kh._restricted_text(value) and
            not any((ord(ch) < 32 and ch not in ('\t', '\n')) or
                    ord(ch) == 127 or 0xd800 <= ord(ch) <= 0xdfff
                    for ch in value))


def _intent(text: str, request: dict[str, Any], observation: dict[str, Any],
            already_used: set[str]) -> dict[str, Any]:
    try:
        value = vs.exact(vs.decode_json(text, MAX_INTENT), {
            'schema', 'purpose', 'original_request_binding_sha256',
            'observed_head_version_id', 'observed_head_content_sha256',
            'observed_target_section_sha256', 'observed_intervening_version_ids',
            'new_save_key', 'new_save_permission_receipt_sha256',
            'new_review_summary', 'review_acknowledgement'}, 'RETRY_INTENT_FIELDS_INVALID')
    except vs.SaveError as exc:
        raise RetryError('INTENT_' + exc.reason, exc.status) from exc
    require(value['schema'] == INTENT_SCHEMA and value['purpose'] == PURPOSE,
            'INTENT_SCHEMA_OR_PURPOSE_INVALID', 'invalid_input')
    require(value['original_request_binding_sha256'] == vs.digest('EXACT-SAVE-REQUEST', request) and
            value['observed_head_version_id'] == observation['head_id'] and
            value['observed_head_content_sha256'] == observation['head_sha'] and
            value['observed_target_section_sha256'] == observation['target_sha'] and
            value['observed_intervening_version_ids'] ==
                [r['version_id'] for r in observation['intervening']],
            'INTENT_HEAD_TARGET_OR_HISTORY_STALE')
    key = value['new_save_key']
    require(type(key) is str and kc.CANDIDATE_KEY.fullmatch(key) is not None and
            key != request['save_key'] and key not in already_used,
            'RETRY_SAVE_KEY_MUST_BE_NEW_AND_UNUSED')
    grant = value['new_save_permission_receipt_sha256']
    require(kb.sha(grant) and grant != request['save_permission_receipt_sha256'],
            'RETRY_REQUIRES_NEW_EC208_PERMISSION_RECEIPT')
    summary = value['new_review_summary']
    require(_summary_ok(summary) and summary != request['review_summary'],
            'RETRY_REQUIRES_DISTINCT_REVIEW_SUMMARY', 'invalid_input')
    require(value['review_acknowledgement'] == ACKNOWLEDGEMENT,
            'EXPLICIT_HUMAN_RE_REVIEW_ACKNOWLEDGEMENT_REQUIRED')
    return value


def _proposal(api: vs.KnowledgeVersionSave, manifest: dict[str, Any],
              req: dict[str, Any], replacement: bytes, observation: dict[str, Any],
              intent: dict[str, Any]) -> tuple[dict[str, Any], str, str]:
    parent = observation['head_bytes']
    section = vs._parts(parent)[req['section_index']]
    new_body = parent[:section['start']] + replacement + parent[section['end']:]
    # Refuse to create a proposal if even the new one-section transformation
    # violates EC208 structure/capacity constraints.
    require(len(new_body) <= vs.MAX_MARKDOWN, 'REBASING_WOULD_EXCEED_CHAPTER_LIMIT')
    vs._check_replacement(parent, new_body, req['section_index'],
                          section['sha256'], req['replacement_section_sha256'])
    proposed = dict(req)
    proposed.update({
        'save_key': intent['new_save_key'],
        'save_permission_receipt_sha256': intent['new_save_permission_receipt_sha256'],
        'review_summary': intent['new_review_summary'],
        'expected_parent_version_id': observation['head_id'],
        'expected_parent_content_sha256': observation['head_sha'],
        'expected_section_sha256': section['sha256'],
        'expected_new_chapter_sha256': vs.raw_sha(new_body),
    })
    text = vs.canonical(proposed)
    # Reparse using the actual EC208 writer's request parser, and reapply
    # its exact current-head CAS and single-section derivation.
    checked, checked_replacement = vs._request(text, api)
    require(checked == proposed and vs._compose_checked(
        checked, checked_replacement, parent, observation['head_id']) == new_body,
        'PREPARED_EC208_REQUEST_DID_NOT_REPLAY')
    rebased_sha = vs.digest('EXACT-SAVE-REQUEST', proposed)
    receipts = observation['intervening']
    retry_binding = vs.digest('RETRY-PREPARE-AUTHORIZATION', {
        'purpose': PURPOSE,
        'store_instance_id': manifest['instance_id'],
        'store_scope_binding_sha256': manifest['store_scope_binding_sha256'],
        'original_request_binding_sha256': vs.digest('EXACT-SAVE-REQUEST', req),
        'retry_intent_binding_sha256': vs.digest('RETRY-INTENT', intent),
        'intervening_history_binding_sha256': vs.digest('RETRY-HISTORY', receipts),
        'rebased_request_binding_sha256': rebased_sha,
        'rebased_ec208_authorization_scope_sha256': vs._auth_scope(manifest, proposed),
    })
    return proposed, text, retry_binding


def _policy(text: str, manifest: dict[str, Any], binding: str,
            restricted: bool, old_receipt: str, new_receipt: str) -> dict[str, Any]:
    try:
        policy = vs.exact(vs.decode_json(text, MAX_POLICY), {
            'schema', 'purpose', 'store_instance_id', 'store_scope_binding_sha256',
            'retry_authorization_scope_sha256', 'retry_permission_receipt_sha256',
            'permit_disjoint_retry_request_prepare', 'permit_retry_proposed_text_return',
            'permit_restricted_retry_proposed_text_return',
            'permit_automatic_target_content_merge', 'permit_automatic_version_append',
            'permit_source_knowledge_overwrite', 'permit_business_repository_write',
            'permit_issue_or_provider_write', 'permit_publish'}, 'RETRY_POLICY_FIELDS_INVALID')
    except vs.SaveError as exc:
        raise RetryError('POLICY_' + exc.reason, exc.status) from exc
    require(policy['schema'] == POLICY_SCHEMA and policy['purpose'] == PURPOSE and
            policy['store_instance_id'] == manifest['instance_id'] and
            policy['store_scope_binding_sha256'] == manifest['store_scope_binding_sha256'] and
            policy['retry_authorization_scope_sha256'] == binding and
            kb.sha(policy['retry_permission_receipt_sha256']) and
            policy['retry_permission_receipt_sha256'] not in (old_receipt, new_receipt),
            'POLICY_SCOPE_OR_SEPARATE_RECEIPT_MISMATCH')
    flags = [name for name in policy if name.startswith('permit_')]
    require(all(type(policy[name]) is bool for name in flags),
            'POLICY_PERMISSION_FLAG_TYPE_INVALID', 'invalid_input')
    require(policy['permit_disjoint_retry_request_prepare'] and
            policy['permit_retry_proposed_text_return'] and
            (not restricted or policy['permit_restricted_retry_proposed_text_return']) and
            not any(policy[name] for name in (
                'permit_automatic_target_content_merge', 'permit_automatic_version_append',
                'permit_source_knowledge_overwrite', 'permit_business_repository_write',
                'permit_issue_or_provider_write', 'permit_publish')),
            'POLICY_PERMISSION_DENIED_OR_ESCALATION')
    return policy


class KnowledgeSaveRetry:
    """Read-only EC208 conflict/rebase coordinator; no implicit write operation."""

    def __init__(self, save_api: vs.KnowledgeVersionSave) -> None:
        require(isinstance(save_api, vs.KnowledgeVersionSave),
                'EXISTING_EC208_SAVE_ADAPTER_REQUIRED', 'invalid_input')
        self.api = save_api

    @contextmanager
    def _read(self, *, request_json: str, handoff_request_json: str,
              handoff_policy_json: str, candidate_read_policies_json: str):
        req, replacement = vs._request(request_json, self.api)
        with self.api._open() as (manifest, version_fd, root_fd):
            snapshot = vs._snapshot(self.api)
            versions = vs._load_versions(self.api, version_fd, manifest, snapshot['content'])
            handoff = self.api._handoff(handoff_request_json, handoff_policy_json,
                                        candidate_read_policies_json)
            head, head_id, restricted = self.api._context(
                req, manifest, snapshot, versions, handoff)
            used_keys = {row['body']['save_key'] for row in versions}
            already = next((r for r in versions if r['body']['save_key'] == req['save_key']), None)
            # Full-chain recovery must be unambiguous. In particular, an unknown
            # append outcome with an extant save_key NEVER becomes a new retry.
            if already is not None:
                require(already['body']['request_binding_sha256'] ==
                        vs.digest('EXACT-SAVE-REQUEST', req),
                        'CONFLICT_SAVE_KEY_REUSED_FOR_DIFFERENT_CONTENT')
                state = 'ALREADY_RECORDED_NO_RETRY'
            else:
                state = ''
            historical = [(None, snapshot['content'])] + [
                (row['version_id'], vs.decode_b64(row['body']['content_base64'],
                    vs.MAX_MARKDOWN, 'HISTORICAL_CONTENT_INVALID')) for row in versions]
            matching = [(idx, body) for idx, (ver, body) in enumerate(historical)
                        if ver == req['expected_parent_version_id']]
            require(len(matching) == 1,
                    'CONFLICT_PARENT_NOT_AN_IMMUTABLE_ANCESTOR')
            ancestor_seq, anchor = matching[0]
            # Reject phantom, corrupted or already stale original review
            # requests. A retry can only update a request originally valid
            # on a real exact historical parent.
            vs._compose_checked(req, replacement, anchor, req['expected_parent_version_id'])
            anchor_sha = vs.raw_sha(anchor)
            require(anchor_sha == req['expected_parent_content_sha256'],
                    'CONFLICT_HISTORICAL_PARENT_SHA_MISMATCH')
            current_sections = vs._parts(head)
            require(req['section_index'] < len(current_sections),
                    'CONFLICT_TARGET_SECTION_ORDINAL_GONE')
            target_sha = current_sections[req['section_index']]['sha256']
            intervening = [_receipt(row) for row in versions[ancestor_seq:]]
            # All prior metadata is replay-verified and each record only
            # changes one structural section; any same-target edit blocks
            # rebase, including an ABA change that returned to the old SHA.
            target_touched = any(r['modified_section_index'] == req['section_index']
                                 for r in intervening)
            head_sha = vs.raw_sha(head)
            if state == 'ALREADY_RECORDED_NO_RETRY':
                pass
            elif head_id == req['expected_parent_version_id']:
                # _compose_checked above already proved exact current head.
                state = 'CURRENT_PARENT_VALID_NO_RETRY_NEEDED'
            elif target_sha != req['expected_section_sha256']:
                state = 'CONFLICT_TARGET_SHA_CHANGED_REQUIRES_MANUAL_MERGE'
            elif target_touched:
                state = 'CONFLICT_TARGET_ABA_TOUCHED_REQUIRES_MANUAL_MERGE'
            else:
                state = 'DISJOINT_PARENT_MOVED_RE_REVIEW_REQUIRED'
            observed = {
                'store_instance_id': manifest['instance_id'],
                'store_scope_binding_sha256': manifest['store_scope_binding_sha256'],
                'original_request_binding_sha256': vs.digest('EXACT-SAVE-REQUEST', req),
                'save_key': req['save_key'],
                'expected_parent_version_id': req['expected_parent_version_id'],
                'expected_parent_content_sha256': req['expected_parent_content_sha256'],
                'observed_head_version_id': head_id,
                'observed_head_content_sha256': head_sha,
                'target_section_index': req['section_index'],
                'expected_target_section_sha256': req['expected_section_sha256'],
                'observed_target_section_sha256': target_sha,
                'intervening_version_receipts': intervening,
                'retry_eligible_after_independent_permission':
                    state == 'DISJOINT_PARENT_MOVED_RE_REVIEW_REQUIRED',
                'old_review_and_signature_valid_for_new_parent': False,
                'new_ec208_scope_and_two_new_signatures_required': True,
                'result_is_local_metadata_not_live_source_truth': True,
                'state': state,
            }
            # Execute intent+policy in this single consistent shared-lock
            # snapshot, eliminating inspect/prepare intra-call TOCTOU.
            yield_data = (req, replacement, manifest, restricted,
                          {'head_id': head_id, 'head_sha': head_sha,
                           'head_bytes': head, 'target_sha': target_sha,
                           'intervening': intervening, 'state': state,
                           'source_snapshot_pin': (snapshot['snapshot_version'],
                               snapshot['manifest_sha256'], snapshot['content_sha256']),
                           'root_fd': root_fd},
                          observed, used_keys)
            yield yield_data

    def _final_source_pin(self, observation: dict[str, Any],
                          manifest: dict[str, Any]) -> None:
        latest = vs._snapshot(self.api)
        require((latest['snapshot_version'], latest['manifest_sha256'],
                 latest['content_sha256']) == observation['source_snapshot_pin'] and
                vs.fs._root_pinned(self.api.root, observation['root_fd']) and
                vs._root_id(self.api.store.repository_root) ==
                    manifest['repository_root_identity'],
                'CONFLICT_SOURCE_SNAPSHOT_OR_METADATA_ROOT_CHANGED_DURING_RETRY')

    def _run(self, *, request_json: str, handoff_request_json: str,
             handoff_policy_json: str, candidate_read_policies_json: str,
             retry_intent_json: str | None = None,
             retry_policy_json: str | None = None) -> dict[str, Any]:
        # Keep the EC208 shared lock across classification, policy and request
        # construction to avoid an intra-call head-change race.
        with self._read(
                request_json=request_json, handoff_request_json=handoff_request_json,
                handoff_policy_json=handoff_policy_json,
                candidate_read_policies_json=candidate_read_policies_json) as (
                    req, replacement, manifest, restricted, observation, public, used_keys):
            state = observation['state']
            if retry_intent_json is None:
                self._final_source_pin(observation, manifest)
                return _response('unavailable' if state.startswith('CONFLICT_') else 'partial',
                                 state, subject=public)
            require(state == 'DISJOINT_PARENT_MOVED_RE_REVIEW_REQUIRED',
                    'CONFLICT_RETRY_NOT_ELIGIBLE_' + state)
            intent = _intent(retry_intent_json, req, observation, used_keys)
            proposed, text, binding = _proposal(self.api, manifest, req,
                                                 replacement, observation, intent)
            outcome = {**public,
                'retry_authorization_scope_sha256': binding,
                'new_save_key': proposed['save_key'],
                'rebased_request_binding_sha256': vs.digest('EXACT-SAVE-REQUEST', proposed),
                'rebased_ec208_authorization_scope_sha256': vs._auth_scope(manifest, proposed),
                'rebased_new_chapter_sha256': proposed['expected_new_chapter_sha256'],
                'rebased_request_bytes_disclosed': False,
                'fresh_ec208_permission_receipt_required': True,
                'fresh_two_independent_ed25519_signatures_required': True,
                'restricted_candidate_selection': restricted,
            }
            if retry_policy_json is None:
                self._final_source_pin(observation, manifest)
                return _response('partial', 'RETRY_SCOPE_PREVIEW_NO_WRITE', subject=outcome)
            _policy(retry_policy_json, manifest, binding, restricted,
                    req['save_permission_receipt_sha256'],
                    intent['new_save_permission_receipt_sha256'])
            self._final_source_pin(observation, manifest)
            return _response('partial', 'RE_REVIEWED_RETRY_REQUEST_PREPARED_NO_WRITE',
                subject={**outcome, 'rebased_request_bytes_disclosed': True,
                         'rebased_request_json': text}, prepared=True)

    def assess(self, *, request_json: str, handoff_request_json: str,
               handoff_policy_json: str, candidate_read_policies_json: str) -> dict[str, Any]:
        """Classify source/head/target conflicts. Never disclose reviewed text."""
        return self._safe_run(request_json=request_json,
                              handoff_request_json=handoff_request_json,
                              handoff_policy_json=handoff_policy_json,
                              candidate_read_policies_json=candidate_read_policies_json)

    def preview_retry(self, *, request_json: str, handoff_request_json: str,
                      handoff_policy_json: str, candidate_read_policies_json: str,
                      retry_intent_json: str) -> dict[str, Any]:
        """Bind a proposed new request to an exact observed immutable head."""
        return self._safe_run(request_json=request_json,
                              handoff_request_json=handoff_request_json,
                              handoff_policy_json=handoff_policy_json,
                              candidate_read_policies_json=candidate_read_policies_json,
                              retry_intent_json=retry_intent_json)

    def prepare_retry(self, *, request_json: str, handoff_request_json: str,
                      handoff_policy_json: str, candidate_read_policies_json: str,
                      retry_intent_json: str, retry_policy_json: str) -> dict[str, Any]:
        """Return *unapproved* new EC208 request; NEVER append or sign it."""
        return self._safe_run(request_json=request_json,
                              handoff_request_json=handoff_request_json,
                              handoff_policy_json=handoff_policy_json,
                              candidate_read_policies_json=candidate_read_policies_json,
                              retry_intent_json=retry_intent_json,
                              retry_policy_json=retry_policy_json)

    def _safe_run(self, **kwargs: Any) -> dict[str, Any]:
        try:
            return self._run(**kwargs)
        except (RetryError, vs.SaveError, kc.CandidateError) as exc:
            return _response(exc.status, exc.reason)
        except (UnicodeError, ValueError, TypeError, OverflowError):
            return _response('invalid_input', 'INVALID_RETRY_INPUT')
