#!/usr/bin/env python3
"""EC210: bounded, permission-separated local CES Knowledge lifecycle.

A host-configured facade joins actual EC202/205/206/207/208/209 APIs.
It never resolves organizational signer identity, publishes, calls a provider,
modifies source Markdown or business Git, or registers a PowerShell route.

Queries replay the immutable EC208 journal; text disclosure requires *both*
a fresh exact EC210 projection grant AND the original EC202 source-content
read grant. Private-version text additionally requires a fresh EC207 whole
selection and EC206 per-candidate grants for every selected-section writer.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any

try:
    from . import knowledge_boundary as kb
    from . import knowledge_bootstrap as boot
    from . import knowledge_candidate_store as kc
    from . import knowledge_chapters as chapters
    from . import knowledge_save_retry as retry
    from . import knowledge_update_handoff as handoff
    from . import knowledge_version_save as vs
except ImportError:
    import knowledge_boundary as kb
    import knowledge_bootstrap as boot
    import knowledge_candidate_store as kc
    import knowledge_chapters as chapters
    import knowledge_save_retry as retry
    import knowledge_update_handoff as handoff
    import knowledge_version_save as vs

SCHEMA = 'ces.knowledge_lifecycle.v1'
QUERY_SCHEMA = 'ces.knowledge_lifecycle_query_request.v1'
QUERY_POLICY_SCHEMA = 'ces.knowledge_lifecycle_query_policy.v1'
EVIDENCE_SCHEMA = 'ces.knowledge_lifecycle_version_evidence.v1'
ADMISSION_SCHEMA = 'ces.knowledge_lifecycle_save_admission.v1'
QUERY_PURPOSE = 'knowledge_lifecycle_exact_local_read'
ADMISSION_PURPOSE = 'knowledge_lifecycle_independently_authorized_local_save_dispatch'
MAX_QUERY_JSON = 12288
MAX_POLICY_JSON = 6144
MAX_EVIDENCE_JSON = 262144
MAX_SECTIONS = 8
MAX_TERMS = 4
MAX_TERM_CHARS = 72
MAX_SNIPPET_CHARS = 200
MAX_MATCHES = 16

CHAPTER_INPUTS = frozenset((
    'request_json', 'bootstrap_read_policy_json', 'target_read_policy_json',
    'impact_read_policy_json', 'chapter_read_policy_json',
    'target_statement_json', 'target_signature_base64',
    'baseline_statement_json', 'baseline_signature_base64'))
HANDOFF_INPUTS = frozenset((
    'handoff_request_json', 'handoff_policy_json', 'candidate_read_policies_json'))
SAVE_DENIED = (
    'permit_source_knowledge_overwrite', 'permit_business_repository_write',
    'permit_issue_or_provider_write', 'permit_docs_only_publish', 'permit_publish')
QUERY_DENIED = (
    'permit_source_knowledge_write', 'permit_local_metadata_append',
    'permit_business_repository_write', 'permit_issue_or_provider_write',
    'permit_docs_only_publish', 'permit_publish')


class LifecycleError(Exception):
    def __init__(self, code: str, status: str = 'unavailable'):
        self.code, self.status = code, status
        super().__init__(code)


def require(condition: bool, code: str, status: str = 'unavailable') -> None:
    if not condition:
        raise LifecycleError(code, status)


def exact(value: Any, keys: set[str] | frozenset[str], code: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == set(keys), code, 'invalid_input')
    return value


def json_obj(raw: str, limit: int) -> dict[str, Any]:
    try:
        return kb._json(raw, limit)
    except kb.KnowledgeBoundaryError as exc:
        raise LifecycleError('JSON_' + exc.reason, 'invalid_input') from exc


def sha(value: Any) -> bool:
    return kb.sha(value)


def binding(domain: str, doc: Any) -> str:
    return kb.digest('CES-EC210-' + domain + '-v1', doc)


def result(status: str, reason: str, *, subject: dict[str, Any] | None = None,
           candidate_written: bool = False, version_written: bool = False,
           write_outcome_unknown: bool = False) -> dict[str, Any]:
    return {'schema': SCHEMA, 'status': status,
            'exit_code': {'partial': 2, 'invalid_input': 4, 'unavailable': 5}[status],
            'reason_code': 'KNOWLEDGE_LIFECYCLE_' + reason, 'subject': subject,
            'candidate_metadata_written': candidate_written,
            'local_version_metadata_written': version_written,
            'local_write_outcome_unknown': write_outcome_unknown,
            'source_knowledge_file_written': False,
            'business_repository_written': False,
            'issue_or_provider_written': False, 'docs_only_publish_invoked': False,
            'published': False, 'candidate_promoted_to_verified_fact': False,
            'organizational_authority_authenticated': False,
            'live_git_delivery_currentness_proven': False,
            'native_knowledge_route_registered': False}


def _query_request(raw: str, api: vs.KnowledgeVersionSave) -> dict[str, Any]:
    req = exact(json_obj(raw, MAX_QUERY_JSON), {
        'schema', 'operation', 'view', 'selected_version_id',
        'expected_head_version_id', 'expected_chapter_sha256',
        'section_indices', 'projection', 'search_terms'}, 'QUERY_REQUEST_FIELDS_INVALID')
    require(req['schema'] == QUERY_SCHEMA and req['operation'] == 'knowledge.lifecycle.query',
            'QUERY_SCHEMA_OR_OPERATION_INVALID', 'invalid_input')
    require(req['view'] in ('source_snapshot', 'local_metadata_version') and
            type(req['view']) is str, 'QUERY_VIEW_INVALID', 'invalid_input')
    require(req['selected_version_id'] is None or sha(req['selected_version_id']),
            'QUERY_VERSION_ID_INVALID', 'invalid_input')
    require(req['view'] == 'local_metadata_version' and req['selected_version_id'] is not None
            or req['view'] == 'source_snapshot' and req['selected_version_id'] is None,
            'QUERY_VERSION_VIEW_INCONSISTENT', 'invalid_input')
    require(req['expected_head_version_id'] is None or sha(req['expected_head_version_id']),
            'QUERY_HEAD_PIN_INVALID', 'invalid_input')
    require(sha(req['expected_chapter_sha256']),
            'QUERY_CHAPTER_PIN_INVALID', 'invalid_input')
    indices = req['section_indices']
    require(type(indices) is list and 1 <= len(indices) <= MAX_SECTIONS and
            all(type(i) is int and 0 <= i < chapters.MAX_SECTIONS for i in indices) and
            indices == sorted(set(indices)), 'QUERY_SECTION_SELECTION_INVALID', 'invalid_input')
    require(type(req['projection']) is str and req['projection'] in
            ('hashes_only', 'match_snippets', 'full_sections'),
            'QUERY_PROJECTION_INVALID', 'invalid_input')
    terms = req['search_terms']
    require(type(terms) is list and len(terms) <= MAX_TERMS and
            all(type(t) is str and t == t.strip() and
                1 <= len(t) <= MAX_TERM_CHARS and
                not any(ord(c) < 32 or ord(c) == 127 for c in t)
                for t in terms) and
            terms == sorted(set(terms), key=lambda t: (t.casefold(), t)),
            'QUERY_TERMS_INVALID', 'invalid_input')
    require(bool(terms) == (req['projection'] == 'match_snippets'),
            'QUERY_SEARCH_TERMS_ONLY_FOR_SNIPPET_PROJECTION', 'invalid_input')
    return req


def _query_policy(raw: str, ctx: dict[str, Any], req: dict[str, Any]) -> dict[str, Any]:
    doc = exact(json_obj(raw, MAX_POLICY_JSON), {
        'schema', 'purpose', 'store_instance_id', 'store_scope_binding_sha256',
        'query_authorization_scope_sha256', 'permission_receipt_sha256',
        'permit_query_metadata', 'permit_source_snapshot_text',
        'permit_private_version_text', 'permit_restricted_private_version_text',
        'permit_term_search', 'permit_full_section_return', *QUERY_DENIED},
        'QUERY_POLICY_FIELDS_INVALID')
    require(doc['schema'] == QUERY_POLICY_SCHEMA and doc['purpose'] == QUERY_PURPOSE and
            doc['store_instance_id'] == ctx['store_instance_id'] and
            doc['store_scope_binding_sha256'] == ctx['store_scope_binding_sha256'] and
            doc['query_authorization_scope_sha256'] == ctx['query_authorization_scope_sha256'] and
            sha(doc['permission_receipt_sha256']), 'QUERY_POLICY_SCOPE_MISMATCH')
    bools = ('permit_query_metadata', 'permit_source_snapshot_text',
             'permit_private_version_text', 'permit_restricted_private_version_text',
             'permit_term_search', 'permit_full_section_return', *QUERY_DENIED)
    require(all(type(doc[k]) is bool for k in bools),
            'QUERY_POLICY_PERMISSION_TYPE_INVALID', 'invalid_input')
    require(doc['permit_query_metadata'] and not any(doc[k] for k in QUERY_DENIED),
            'QUERY_METADATA_GRANT_MISSING_OR_WRITE_ESCALATION')
    if req['projection'] != 'hashes_only':
        require(doc['permit_source_snapshot_text'], 'EC202_SOURCE_TEXT_GRANT_REQUIRED')
        if req['view'] == 'local_metadata_version':
            require(doc['permit_private_version_text'] and
                    doc['permit_restricted_private_version_text'],
                    'PRIVATE_METADATA_TEXT_AND_RESTRICTED_GRANTS_REQUIRED')
        if req['projection'] == 'match_snippets':
            require(doc['permit_term_search'], 'TERM_SEARCH_NOT_GRANTED')
        if req['projection'] == 'full_sections':
            require(doc['permit_full_section_return'], 'FULL_SECTION_NOT_GRANTED')
    return doc


def _evidence_bundle(raw: str | None, versions: list[dict[str, Any]]
                     ) -> dict[str, dict[str, str]]:
    required = {v['version_id'] for v in versions}
    if not required:
        require(raw is None, 'UNEXPECTED_VERSION_EVIDENCE_BUNDLE', 'invalid_input')
        return {}
    require(type(raw) is str, 'VERSION_EVIDENCE_BUNDLE_REQUIRED')
    obj = exact(json_obj(raw, MAX_EVIDENCE_JSON), {'schema', 'versions'},
                'VERSION_EVIDENCE_FIELDS_INVALID')
    require(obj['schema'] == EVIDENCE_SCHEMA and type(obj['versions']) is list and
            len(obj['versions']) == len(required),
            'VERSION_EVIDENCE_SELECTION_INCOMPLETE')
    found: dict[str, dict[str, str]] = {}
    for item in obj['versions']:
        row = exact(item, {'version_id', *HANDOFF_INPUTS}, 'VERSION_EVIDENCE_ITEM_INVALID')
        require(sha(row['version_id']) and row['version_id'] in required and
                row['version_id'] not in found and
                all(type(row[k]) is str for k in HANDOFF_INPUTS),
                'VERSION_EVIDENCE_VERSION_OR_INPUT_INVALID')
        found[row['version_id']] = row
    require(set(found) == required, 'VERSION_EVIDENCE_VERSION_SET_MISMATCH')
    return found


def _source_content(api: vs.KnowledgeVersionSave, snap: dict[str, Any],
                    bootstrap_request_json: str | None,
                    bootstrap_read_policy_json: str | None) -> None:
    """Require a real EC202 byte projection, not just a caller's grant assertion."""
    require(type(bootstrap_request_json) is str and
            type(bootstrap_read_policy_json) is str,
            'SOURCE_EC202_CONTENT_PERMISSION_REQUIRED')
    req = boot._request(json_obj(bootstrap_request_json, boot.MAX_REQUEST))
    require(len(req['sources']) == 1 and
            req['sources'][0]['kind'] == 'ces_knowledge' and
            req['sources'][0]['relative_path'] == api.chapter_path and
            req['sources'][0]['expected_sha256'] == snap['content_sha256'] and
            req['expected_manifest_sha256'] == snap['manifest_sha256'],
            'EC202_QUERY_NOT_EXACTLY_BOUND_TO_CHAPTER')
    scope = req['scope']
    require(scope['repository_ref'] == api.store.repository_ref and
            scope['knowledge_space_key'] == api.store.knowledge_space_key and
            scope['period']['period_id'] == api.store.period_id and
            scope['source_policy_revision'] == api.store.source_policy_revision,
            'EC202_SOURCE_SCOPE_MISMATCH')
    read = boot.KnowledgeBootstrap(
        repository_root=api.store.repository_root,
        knowledge_root=api.store.knowledge_root).read(
        request_json=bootstrap_request_json,
        read_policy_json=bootstrap_read_policy_json)
    require(read['status'] == 'partial' and read['subject'] is not None and
            len(read['subject']['sources']) == 1,
            'EC202_READ_DENIED_OR_UNAVAILABLE')
    entry = read['subject']['sources'][0]
    require(entry['state'] == 'READ_UNVERIFIED' and
            entry['manifest_entry_match'] is True and
            entry['content_base64'] is not None and
            base64.b64decode(entry['content_base64'], validate=True) == snap['content'],
            'EC202_CONTENT_NOT_AUTHORIZED_OR_SNAPSHOT_DRIFT')


def _line_hits(section: bytes, terms: list[str]) -> list[dict[str, Any]]:
    """Bounded exact-section excerpts; no surrounding/unauthorized section bleed."""
    lines = section.decode('utf-8', 'strict').splitlines()
    hits = []
    folded = [t.casefold() for t in terms]
    for number, line in enumerate(lines, 1):
        if not any(t in line.casefold() for t in folded):
            continue
        # Retain a bounded fragment near the earliest match, not unbounded lines.
        positions = [line.casefold().find(t) for t in folded if t in line.casefold()]
        start = max(0, min(positions) - 48)
        end = min(len(line), start + MAX_SNIPPET_CHARS)
        hits.append({'line_number_in_section': number, 'excerpt': line[start:end],
                     'excerpt_truncated_left': start > 0,
                     'excerpt_truncated_right': end < len(line)})
        if len(hits) == MAX_MATCHES:
            break
    return hits


class KnowledgeLifecycle:
    """An explicit orchestration surface, not a new organizational authority.

    The mapper is optional for read-only query deployments. Actual candidate
    intake and reviewed save dispatch require a host-injected EC205 mapper.
    """

    def __init__(self, version_store: vs.KnowledgeVersionSave,
                 chapter_mapper: chapters.KnowledgeChapters | None = None) -> None:
        require(isinstance(version_store, vs.KnowledgeVersionSave),
                'HOST_EC208_VERSION_STORE_REQUIRED', 'invalid_input')
        if chapter_mapper is not None:
            require(isinstance(chapter_mapper, chapters.KnowledgeChapters),
                    'HOST_EC205_MAPPER_INVALID', 'invalid_input')
            bound = chapter_mapper.impact.target
            require(bound.bootstrap.repository_root == version_store.store.repository_root and
                    bound.bootstrap.knowledge_root == version_store.store.knowledge_root and
                    bound.repository_ref == version_store.store.repository_ref,
                    'HOST_MAPPER_SOURCE_SCOPE_DIFFERS_FROM_STORE', 'invalid_input')
        self.save_api = version_store
        self.mapper = chapter_mapper
        self.retry_api = retry.KnowledgeSaveRetry(version_store)

    def _view(self, req: dict[str, Any], manifest: dict[str, Any],
              snap: dict[str, Any], versions: list[dict[str, Any]]
              ) -> tuple[dict[str, Any], bytes, list[dict[str, Any]]]:
        require(snap['snapshot_version'] == manifest['baseline_snapshot_version'] and
                snap['manifest_sha256'] == manifest['baseline_manifest_sha256'] and
                snap['content_sha256'] == manifest['baseline_chapter_sha256'],
                'SNAPSHOT_MANIFEST_OR_CHAPTER_DRIFT')
        latest = versions[-1] if versions else None
        head_id = latest['version_id'] if latest else None
        require(req['expected_head_version_id'] == head_id,
                'QUERY_HEAD_CHANGED_RESTART_PREVIEW')
        chosen = None
        prior = []
        if req['view'] == 'source_snapshot':
            body = snap['content']
            selected_id = None
        else:
            for i, version in enumerate(versions):
                if version['version_id'] == req['selected_version_id']:
                    chosen, prior = version, versions[:i+1]
                    break
            require(chosen is not None, 'REQUESTED_IMMUTABLE_VERSION_NOT_FOUND')
            body = vs.decode_b64(chosen['body']['content_base64'],
                                 vs.MAX_MARKDOWN, 'QUERY_VERSION_BODY_INVALID')
            selected_id = chosen['version_id']
        require(vs.raw_sha(body) == req['expected_chapter_sha256'],
                'QUERY_CHAPTER_CONTENT_PIN_CHANGED')
        sections = vs._parts(body)
        require(all(i < len(sections) for i in req['section_indices']),
                'QUERY_SECTION_INDEX_NOT_PRESENT')
        selected = [{'ordinal': i, 'sha256': sections[i]['sha256'],
                     'length_bytes': sections[i]['end']-sections[i]['start']}
                    for i in req['section_indices']]
        writers = [row for row in prior
                   if row['body']['section_index'] in req['section_indices']]
        commitment = {'request': req, 'store_instance_id': manifest['instance_id'],
            'store_scope_binding_sha256': manifest['store_scope_binding_sha256'],
            'snapshot_version': snap['snapshot_version'],
            'snapshot_manifest_sha256': snap['manifest_sha256'],
            'baseline_chapter_sha256': snap['content_sha256'],
            'observed_head_version_id': head_id,
            'queried_version_id': selected_id,
            'queried_chapter_sha256': req['expected_chapter_sha256'],
            'selected_sections': selected,
            'contributing_version_ids': [r['version_id'] for r in writers]}
        ctx = {
            'store_instance_id': manifest['instance_id'],
            'store_scope_binding_sha256': manifest['store_scope_binding_sha256'],
            'query_authorization_scope_sha256': binding('QUERY-SCOPE', commitment),
            'view': req['view'], 'queried_version_id': selected_id,
            'observed_head_version_id': head_id,
            'queried_chapter_sha256': req['expected_chapter_sha256'],
            'baseline_chapter_sha256': snap['content_sha256'],
            'section_fingerprints': selected,
            'contributing_version_ids': commitment['contributing_version_ids'],
            'source_or_local_version_content_authenticated_as_org_truth': False,
            'metadata_only_without_query_grants': True}
        return ctx, body, writers

    def query_binding_preview(self, *, query_request_json: str) -> dict[str, Any]:
        """Observe exact immutable IDs/SHA only; no text or search side channels."""
        try:
            req = _query_request(query_request_json, self.save_api)
            with self.save_api._open() as (manifest, fd, _):
                snap = vs._snapshot(self.save_api)
                versions = vs._load_versions(self.save_api, fd, manifest, snap['content'])
                ctx, _, _ = self._view(req, manifest, snap, versions)
                return result('partial', 'QUERY_BINDING_PREVIEW_NO_CONTENT',
                              subject=ctx)
        except (LifecycleError, vs.SaveError, kc.CandidateError, boot.BootstrapError) as exc:
            return result(getattr(exc, 'status', 'unavailable'),
                          getattr(exc, 'code', getattr(exc, 'reason', 'SOURCE_UNAVAILABLE')))
        except (TypeError, ValueError, UnicodeError, OverflowError):
            return result('invalid_input', 'QUERY_PREVIEW_INPUT_INVALID')

    def query(self, *, query_request_json: str, query_policy_json: str,
              bootstrap_request_json: str | None = None,
              bootstrap_read_policy_json: str | None = None,
              version_evidence_json: str | None = None) -> dict[str, Any]:
        """Bounded section text/search with independent source and candidate rights.

        Every private section writer is reauthorized, even when its text was
        subsequently replaced. Query never writes or calls DocsOnlyPublish.
        """
        try:
            req = _query_request(query_request_json, self.save_api)
            with self.save_api._open() as (manifest, fd, root_fd):
                snap = vs._snapshot(self.save_api)
                versions = vs._load_versions(self.save_api, fd, manifest, snap['content'])
                ctx, body, contributing = self._view(req, manifest, snap, versions)
                _query_policy(query_policy_json, ctx, req)
                if req['projection'] != 'hashes_only':
                    _source_content(self.save_api, snap, bootstrap_request_json,
                                    bootstrap_read_policy_json)
                    evidence = _evidence_bundle(
                        version_evidence_json, contributing)
                    for version in contributing:
                        access = evidence[version['version_id']]
                        read = self.save_api._handoff(
                            access['handoff_request_json'], access['handoff_policy_json'],
                            access['candidate_read_policies_json'])
                        b = version['body']
                        actual = read['ai_input']['candidate_evidence']
                        require(read['selection_binding_sha256'] == b['ec207_selection_binding_sha256'] and
                                read['ai_input_sha256'] == b['ec207_ai_input_sha256'] and
                                [r['candidate_key'] for r in actual] == b['candidate_keys'] and
                                [r['record_id'] for r in actual] == b['candidate_record_ids'],
                                'PRIVATE_VERSION_EC206_EC207_PROVENANCE_MISMATCH')
                else:
                    require(bootstrap_request_json is None and
                            bootstrap_read_policy_json is None and
                            version_evidence_json is None,
                            'HASH_QUERY_MUST_NOT_ACCEPT_CONTENT_BUNDLES',
                            'invalid_input')

                spans = vs._parts(body)
                projected = []
                for i in req['section_indices']:
                    section = spans[i]
                    item = {'ordinal': i, 'section_sha256': section['sha256']}
                    if req['projection'] == 'full_sections':
                        item['section_content_base64'] = base64.b64encode(
                            body[section['start']:section['end']]).decode('ascii')
                    elif req['projection'] == 'match_snippets':
                        item['matching_lines'] = _line_hits(
                            body[section['start']:section['end']], req['search_terms'])
                    projected.append(item)
                current = vs._snapshot(self.save_api)
                require(current['snapshot_version'] == snap['snapshot_version'] and
                        current['manifest_sha256'] == snap['manifest_sha256'] and
                        current['content_sha256'] == snap['content_sha256'] and
                        vs.fs._root_pinned(self.save_api.root, root_fd),
                        'SOURCE_OR_METADATA_ROOT_CHANGED_DURING_QUERY')
                return result('partial', 'EXACT_LOCAL_KNOWLEDGE_QUERY_NOT_PUBLISHED',
                    subject={**ctx, 'metadata_only_without_query_grants': False,
                    'projection': req['projection'],
                    'read_permission_receipt_sha256':
                        json_obj(query_policy_json, MAX_POLICY_JSON)['permission_receipt_sha256'],
                    'selected_sections': projected,
                    'source_snapshot_is_not_verified_current_architecture': True,
                    'private_versions_not_authoritative_or_published': True,
                    'external_or_native_actions_performed': False})
        except (LifecycleError, vs.SaveError, kc.CandidateError, boot.BootstrapError,
                kb.KnowledgeBoundaryError, handoff.HandoffError) as exc:
            return result(getattr(exc, 'status', 'unavailable'),
                          getattr(exc, 'code', getattr(exc, 'reason', 'SOURCE_UNAVAILABLE')))
        except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
            return result('invalid_input', 'QUERY_INPUT_INVALID')

    def _map(self, source_inputs: dict[str, str | None]) -> dict[str, Any]:
        require(self.mapper is not None, 'EC205_MAPPER_NOT_CONFIGURED')
        exact(source_inputs, CHAPTER_INPUTS, 'EC205_INPUT_SET_INVALID')
        require(all(value is None or type(value) is str for value in source_inputs.values()),
                'EC205_INPUT_TYPES_INVALID', 'invalid_input')
        mapped = self.mapper.map_chapters(**source_inputs)
        require(mapped['status'] == 'partial' and mapped.get('subject') is not None and
                mapped.get('canonical_json') == kb.canonical(mapped['subject']) and
                mapped.get('limitations') is not None and
                not any(mapped['limitations'].values()),
                'EC205_RECHECK_DENIED_OR_UNAVAILABLE')
        subject = mapped['subject']
        require(subject['knowledge_snapshot_stable_across_read'] is True and
                subject['target_delivery_state'] == 'SIGNED_DELIVERED_TARGET_OBSERVED_AT_REF' and
                subject['selected_change_set_state'] == 'SELECTED_REPOSITORY_PATHS_COMPARED',
                'EC205_SOURCE_MAPPING_OR_GIT_RECHECK_INCOMPLETE')
        store = self.save_api.store
        require(subject['repository_ref'] == store.repository_ref and
                subject['knowledge_space_key'] == store.knowledge_space_key and
                subject['period_id'] == store.period_id,
                'EC205_RESULT_STORE_SCOPE_MISMATCH')
        return mapped

    def preview_candidate_intake(self, *, source_inputs: dict[str, str | None],
                                 proposal_json: str) -> dict[str, Any]:
        """Recompute the EC205 map; don't accept a caller-supplied EC205 result."""
        try:
            mapped = self._map(source_inputs)
            proposal = json_obj(proposal_json, kc.MAX_PROPOSAL_BYTES)
            require(proposal.get('origin') == 'ec205_chapter_mapping',
                    'EC210_INTAKE_ONLY_EXPLICIT_EC205_MAPPING')
            pv = self.save_api.store.preview(
                proposal_json=proposal_json, source_result_json=kb.canonical(mapped))
            require(pv['status'] == 'partial', 'EC206_INTAKE_PREVIEW_DENIED')
            return result('partial', 'FRESH_EC205_CANDIDATE_PREVIEW_NO_WRITE',
                subject={**pv['subject'],
                         'source_mapping_binding_sha256': binding('EC205-MAPPING', mapped['subject']),
                         'append_authorized': False})
        except (LifecycleError, vs.SaveError, kc.CandidateError,
                kb.KnowledgeBoundaryError) as exc:
            return result(getattr(exc, 'status', 'unavailable'),
                          getattr(exc, 'code', getattr(exc, 'reason', 'SOURCE_UNAVAILABLE')))
        except (TypeError, ValueError, UnicodeError, OverflowError):
            return result('invalid_input', 'CANDIDATE_PREVIEW_INPUT_INVALID')

    def append_candidate(self, *, source_inputs: dict[str, str | None],
                         proposal_json: str, append_policy_json: str) -> dict[str, Any]:
        """Only the independently granted EC206 quarantine append, not a save."""
        try:
            mapped = self._map(source_inputs)
            proposal = json_obj(proposal_json, kc.MAX_PROPOSAL_BYTES)
            require(proposal.get('origin') == 'ec205_chapter_mapping',
                    'EC210_INTAKE_ONLY_EXPLICIT_EC205_MAPPING')
            out = self.save_api.store.append(
                proposal_json=proposal_json,
                append_policy_json=append_policy_json,
                source_result_json=kb.canonical(mapped))
            require(out['status'] == 'partial',
                    'EC206_CANDIDATE_APPEND_DENIED_' + out['reason_code'])
            return result('partial', 'EC206_PRIVATE_CANDIDATE_INTAKE_ONLY',
                subject={'candidate_receipt': out['subject'],
                         'source_mapping_binding_sha256': binding('EC205-MAPPING', mapped['subject']),
                         'save_authorized': False},
                candidate_written=out['local_candidate_write_performed'])
        except (LifecycleError, vs.SaveError, kc.CandidateError,
                kb.KnowledgeBoundaryError) as exc:
            return result(getattr(exc, 'status', 'unavailable'),
                          getattr(exc, 'code', getattr(exc, 'reason', 'SOURCE_UNAVAILABLE')))
        except (TypeError, ValueError, UnicodeError, OverflowError):
            return result('invalid_input', 'CANDIDATE_APPEND_INPUT_INVALID')

    def _update_plan(self, *, source_inputs: dict[str, str | None],
                     handoff_inputs: dict[str, str],
                     save_request_json: str) -> dict[str, Any]:
        exact(handoff_inputs, HANDOFF_INPUTS, 'HANDOFF_INPUT_SET_INVALID')
        require(all(type(s) is str for s in handoff_inputs.values()),
                'HANDOFF_INPUT_TYPES_INVALID', 'invalid_input')
        mapped = self._map(source_inputs)
        source_request = boot._request(json_obj(
            source_inputs['request_json'], boot.MAX_REQUEST))
        save_req, _ = vs._request(save_request_json, self.save_api)
        scope = source_request['scope']
        store = self.save_api.store
        require(scope['repository_ref'] == store.repository_ref and
                scope['knowledge_space_key'] == store.knowledge_space_key and
                scope['period']['period_id'] == store.period_id and
                scope['source_policy_revision'] == store.source_policy_revision,
                'EC202_MAPPING_STORE_SCOPE_MISMATCH')
        matches = [row for row in source_request['sources']
                   if row['kind'] == 'ces_knowledge' and
                   row['relative_path'] == self.save_api.chapter_path]
        require(len(matches) == 1, 'EC205_REQUIRED_SOURCE_CHAPTER_NOT_SELECTED')
        source_binding = kb.digest('CES-EC202-SOURCE-v1', matches[0])
        require(save_req['section_ref'] is not None and
                save_req['ec202_knowledge_source_binding_sha256'] == source_binding,
                'EC205_EXPLICIT_SECTION_SOURCE_WITNESS_REQUIRED')
        subject = mapped['subject']
        docs = [d for d in subject['chapter_documents']
                if d['relative_path'] == self.save_api.chapter_path and
                d['source_key'] == matches[0]['source_key'] and
                d['mapping_state'] == 'SELECTED_SNAPSHOT_CHAPTERS_SCANNED']
        require(len(docs) == 1, 'EC205_CHAPTER_MAPPING_NOT_AVAILABLE')
        visible = [s for s in docs[0]['sections']
                   if s['ordinal'] == save_req['section_index'] and
                   s['section_ref'] == save_req['section_ref'] and
                   s['manual_review_candidate'] is True and
                   any(a['selected_git_comparison_state'] == 'GIT_SELECTED_PATH_BYTES_VERIFIED'
                       and a['manual_review_candidate'] is True
                       for a in s['associations'])]
        require(len(visible) == 1, 'EC205_SECTION_NOT_SELECTED_FOR_EVIDENCE_REVIEW')
        require(save_req['expected_manifest_sha256'] ==
                subject['knowledge_manifest']['manifest_sha256'],
                'EC205_MANIFEST_DIGEST_NOT_SAME_AS_EC208_REQUEST')
        pv = self.save_api.preview(request_json=save_request_json, **handoff_inputs)
        require(pv['status'] == 'partial' and pv['subject'] is not None,
                'EC208_SAVE_PREVIEW_DENIED_' + pv['reason_code'])
        pin = pv['subject']
        # The EC208 preview recomputes EC207 selection+content grants, section
        # witness and EC202 snapshot. EC205 was independently re-derived above.
        statement = {'mapping_subject_sha256': binding('EC205-MAPPING', subject),
            'ec205_request_binding_sha256': subject['request_binding_sha256'],
            'ec205_section_ref': save_req['section_ref'],
            'ec205_section_index': save_req['section_index'],
            'ec205_source_binding_sha256': source_binding,
            'ec208_store_scope_binding_sha256': pin['store_scope_binding_sha256'],
            'ec208_store_instance_id': pin['store_instance_id'],
            'ec208_request_binding_sha256': vs.digest('EXACT-SAVE-REQUEST', save_req),
            'ec208_authorization_scope_sha256': pin['authorization_scope_sha256'],
            'ec207_selection_binding_sha256': save_req['selection_binding_sha256'],
            'ec207_ai_input_sha256': save_req['ai_input_sha256']}
        return {**statement, 'workflow_authorization_scope_sha256':
                binding('REVIEWED-SAVE-DISPATCH', statement),
                'save_key': save_req['save_key'], 'save_state': pin['state'],
                'write_granted_by_preview': False, 'review_and_owner_signatures_supplied': False,
                'real_organizational_source_currentness_verified': False,
                'knowledge_source_write_authorized': False}

    def prepare_update(self, *, source_inputs: dict[str, str | None],
                       handoff_inputs: dict[str, str],
                       save_request_json: str) -> dict[str, Any]:
        """EC205 -> EC206/207 -> EC208 exact no-write admission preview."""
        try:
            return result('partial', 'EVIDENCE_BOUND_REVIEWED_SAVE_PREVIEW_NO_WRITE',
                subject=self._update_plan(source_inputs=source_inputs,
                    handoff_inputs=handoff_inputs, save_request_json=save_request_json))
        except (LifecycleError, vs.SaveError, kc.CandidateError,
                kb.KnowledgeBoundaryError, boot.BootstrapError) as exc:
            return result(getattr(exc, 'status', 'unavailable'),
                          getattr(exc, 'code', getattr(exc, 'reason', 'SOURCE_UNAVAILABLE')))
        except (TypeError, ValueError, UnicodeError, OverflowError):
            return result('invalid_input', 'UPDATE_PREVIEW_INPUT_INVALID')

    @staticmethod
    def _save_admission(raw: str, pin: dict[str, Any]) -> None:
        doc = exact(json_obj(raw, MAX_POLICY_JSON),
            {'schema', 'purpose', 'store_instance_id', 'store_scope_binding_sha256',
             'workflow_authorization_scope_sha256', 'permission_receipt_sha256',
             'permit_evidence_bound_save_dispatch', 'permit_local_metadata_append_dispatch',
             'permit_candidate_store_write', *SAVE_DENIED},
            'SAVE_ADMISSION_FIELDS_INVALID')
        require(doc['schema'] == ADMISSION_SCHEMA and doc['purpose'] == ADMISSION_PURPOSE and
                doc['store_instance_id'] == pin['ec208_store_instance_id'] and
                doc['store_scope_binding_sha256'] == pin['ec208_store_scope_binding_sha256'] and
                doc['workflow_authorization_scope_sha256'] ==
                    pin['workflow_authorization_scope_sha256'] and
                sha(doc['permission_receipt_sha256']),
                'SAVE_ADMISSION_SCOPE_MISMATCH')
        flags = ('permit_evidence_bound_save_dispatch',
                 'permit_local_metadata_append_dispatch',
                 'permit_candidate_store_write', *SAVE_DENIED)
        require(all(type(doc[k]) is bool for k in flags),
                'SAVE_ADMISSION_PERMISSION_TYPES_INVALID', 'invalid_input')
        require(doc['permit_evidence_bound_save_dispatch'] and
                doc['permit_local_metadata_append_dispatch'] and
                not doc['permit_candidate_store_write'] and
                not any(doc[k] for k in SAVE_DENIED),
                'SAVE_ADMISSION_NOT_GRANTED_OR_FORBIDDEN_ESCALATION')

    def save_reviewed(self, *, source_inputs: dict[str, str | None],
                      handoff_inputs: dict[str, str], save_request_json: str,
                      lifecycle_save_admission_json: str, ec208_save_policy_json: str,
                      ec208_approvals_json: str) -> dict[str, Any]:
        """Dispatch exactly ONE EC208 CAS save; no retry, publish or signers created."""
        try:
            pin = self._update_plan(source_inputs=source_inputs,
                                    handoff_inputs=handoff_inputs,
                                    save_request_json=save_request_json)
            self._save_admission(lifecycle_save_admission_json, pin)
            out = self.save_api.save(request_json=save_request_json, **handoff_inputs,
                                     save_policy_json=ec208_save_policy_json,
                                     approvals_json=ec208_approvals_json)
            require(out['status'] == 'partial',
                    'EC208_SAVE_DENIED_' + out['reason_code'])
            return result('partial', 'SIGNED_LOCAL_METADATA_SAVE_DISPATCHED_NO_PUBLISH',
                subject={'workflow_authorization_scope_sha256':
                         pin['workflow_authorization_scope_sha256'],
                         'ec208_version_receipt': out['subject'],
                         'ec208_idempotent_no_write': not out['local_version_metadata_written'],
                         'source_and_external_systems_untouched': True},
                version_written=out['local_version_metadata_written'])
        except (LifecycleError, vs.SaveError, kc.CandidateError,
                kb.KnowledgeBoundaryError, boot.BootstrapError) as exc:
            code = getattr(exc, 'code', getattr(exc, 'reason', 'SOURCE_UNAVAILABLE'))
            # An EC208 append exception is not automatically a safe retry.
            return result(getattr(exc, 'status', 'unavailable'), code,
                          write_outcome_unknown='APPEND_OUTCOME_UNKNOWN' in code)
        except (TypeError, ValueError, UnicodeError, OverflowError):
            return result('invalid_input', 'SAVE_DISPATCH_INPUT_INVALID')

    def assess_conflict(self, *, save_request_json: str,
                        handoff_inputs: dict[str, str]) -> dict[str, Any]:
        """Delegates to EC209 historical replay; never retries automatically."""
        try:
            exact(handoff_inputs, HANDOFF_INPUTS, 'HANDOFF_INPUT_SET_INVALID')
            out = self.retry_api.assess(request_json=save_request_json, **handoff_inputs)
            return result(out['status'], 'EC209_' + out['reason_code'], subject=out['subject'])
        except (LifecycleError, TypeError, ValueError):
            return result('invalid_input', 'CONFLICT_INPUT_INVALID')

    def prepare_retry(self, *, save_request_json: str, handoff_inputs: dict[str, str],
                      ec209_retry_intent_json: str,
                      ec209_retry_policy_json: str) -> dict[str, Any]:
        """Explicit EC209 no-write proposal only; new EC208 grant/signatures remain."""
        try:
            exact(handoff_inputs, HANDOFF_INPUTS, 'HANDOFF_INPUT_SET_INVALID')
            out = self.retry_api.prepare_retry(
                request_json=save_request_json, **handoff_inputs,
                retry_intent_json=ec209_retry_intent_json,
                retry_policy_json=ec209_retry_policy_json)
            return result(out['status'], 'EC209_' + out['reason_code'], subject=out['subject'])
        except (LifecycleError, TypeError, ValueError):
            return result('invalid_input', 'RETRY_INPUT_INVALID')
