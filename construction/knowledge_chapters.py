#!/usr/bin/env python3
"""EC205: map existing Markdown chapters to separately verified selected Git deltas.

All observed bytes and policy bindings are recomputed from EC202/203/204. The
only recognized source associations are exact existing CES-SOURCE annotations
or literal Markdown links to *selected* repository paths. No fuzzy matching,
AI-derived linkage, semantic validation, repository write or knowledge edit.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import re
from typing import Any

try:
    from . import knowledge_boundary as boundary
    from . import knowledge_bootstrap as bootstrap
    from . import knowledge_impact as impact
    from . import knowledge_target_binding as target
except ImportError:
    import knowledge_boundary as boundary
    import knowledge_bootstrap as bootstrap
    import knowledge_impact as impact
    import knowledge_target_binding as target

SCHEMA = 'ces.knowledge_chapters.v1'
POLICY_SCHEMA = 'ces.knowledge_chapter_read_policy.v1'
PURPOSE = 'knowledge_existing_chapters_read_only'
MAX_POLICY = 65536
MAX_SECTIONS = 64
MAX_ANCHORS = 128
MAX_HEADING_LENGTH = 160
FENCE = re.compile(r'^ {0,3}(`{3,}|~{3,})(.*)$')
HEADING = re.compile(r'^ {0,3}(#{1,6})[ \t]+(.+?)\s*$')
ANNOTATION = re.compile(
    r'^ {0,3}<!-- CES-SOURCE source_key=([A-Za-z][A-Za-z0-9._-]{0,63})'
    r'(?: source_sha256=([0-9a-f]{64}))? -->[ \t]*$')
LINK = re.compile(r'\[[^\]\r\n]{1,96}\]\(([A-Za-z0-9_][A-Za-z0-9._/-]{0,255})\)')
INLINE_CODE = re.compile(r'`[^`\r\n]*`')
INLINE_HTML_COMMENT = re.compile(r'<!--.*?-->')
LIMITATIONS = {
    'organizational_identity_grants_or_signer_revocation_verified': False,
    'repository_delivery_or_deployment_authoritatively_verified': False,
    'snapshot_claims_semantically_authenticated': False,
    'unselected_knowledge_documents_or_source_paths_scanned': False,
    'markdown_links_prove_architectural_dependency': False,
    'chapter_semantic_staleness_or_conflict_proven': False,
    'historical_knowledge_versions_or_text_diffs_verified': False,
    'automatic_sections_to_rewrite_identified': False,
    'candidate_store_save_publication_or_ai_dispatch_performed': False,
    'business_source_repository_issue_or_knowledge_write_performed': False,
    'native_powershell_knowledge_route_registered': False,
}


class ChapterError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def require(condition: bool, code: str, status: str = 'invalid_input') -> None:
    if not condition:
        raise ChapterError(code, status)


def digest(domain: str, doc: Any) -> str:
    return boundary.digest(domain, doc)


def _base() -> dict[str, Any]:
    return {'schema': SCHEMA, 'status': 'invalid_input', 'exit_code': 4,
        'reason_code': 'KNOWLEDGE_CHAPTERS_INVALID_INPUT', 'subject': None,
        'canonical_json': None, 'limitations': dict(LIMITATIONS)}


def _dependencies(api: impact.KnowledgeImpact, request: dict[str, Any],
                  bp: dict[str, Any], tp: dict[str, Any], ip: dict[str, Any],
                  target_doc: dict[str, Any], baseline_doc: dict[str, Any] | None) -> dict[str, Any]:
    pins = api.target._preview(request)
    bootstrap._policy(bp, request, pins)
    target._policy(tp, request, pins, bp)
    impact._read_policy(ip, request, pins, bp, tp, api.registry_pin, target_doc)
    if baseline_doc is not None:
        impact._baseline_statement(baseline_doc)
    return {
        **pins,
        'baseline_issuer_registry_binding_sha256': api.registry_pin,
        'bootstrap_read_policy_binding_sha256': digest('CES-EC202-READ-POLICY-v1', bp),
        'target_read_policy_binding_sha256': digest('CES-EC203-TARGET-POLICY-v1', tp),
        'impact_read_policy_binding_sha256': digest('CES-EC204-IMPACT-POLICY-v1', ip),
        'target_statement_binding_sha256': digest('CES-EC204-TARGET-STATEMENT-v1', target_doc),
        'baseline_statement_binding_sha256': digest('CES-EC205-BASELINE-DOCUMENT-v1', baseline_doc),
    }


def _policy(obj: Any, req: dict[str, Any], pins: dict[str, Any],
            bp: dict[str, Any], tp: dict[str, Any], ip: dict[str, Any]) -> dict[str, Any]:
    bootstrap.fields(obj, {
        'schema', 'purpose', 'repository_ref', 'knowledge_space_key',
        'source_policy_revision', 'period_id', 'request_binding_sha256',
        'scope_binding_sha256', 'repository_root_binding_sha256',
        'knowledge_root_binding_sha256', 'git_root_binding_sha256',
        'target_config_binding_sha256', 'issuer_registry_binding_sha256',
        'baseline_issuer_registry_binding_sha256',
        'bootstrap_read_policy_binding_sha256', 'target_read_policy_binding_sha256',
        'impact_read_policy_binding_sha256', 'target_statement_binding_sha256',
        'baseline_statement_binding_sha256', 'read_receipt_sha256',
        'permit_chapter_mapping', 'permit_section_title_projection',
        'permit_section_digest_projection', 'permit_reference_digest_comparison',
        'permit_repository_write', 'permit_knowledge_write',
        'permit_business_source_write', 'permit_issue_write', 'permit_publish',
        'source_grants',
    }, 'CHAPTER_POLICY_FIELDS_INVALID')
    require(obj['schema'] == POLICY_SCHEMA and obj['purpose'] == PURPOSE,
            'CHAPTER_POLICY_PURPOSE_INVALID', 'unavailable')
    s = req['scope']
    require(all(obj[k] == s[k] for k in ('repository_ref', 'knowledge_space_key',
                'source_policy_revision')) and obj['period_id'] == s['period']['period_id'],
            'CHAPTER_POLICY_SCOPE_MISMATCH', 'unavailable')
    for key in ('request_binding_sha256', 'scope_binding_sha256',
            'repository_root_binding_sha256', 'knowledge_root_binding_sha256',
            'git_root_binding_sha256', 'target_config_binding_sha256',
            'issuer_registry_binding_sha256', 'baseline_issuer_registry_binding_sha256',
            'bootstrap_read_policy_binding_sha256', 'target_read_policy_binding_sha256',
            'impact_read_policy_binding_sha256', 'target_statement_binding_sha256',
            'baseline_statement_binding_sha256'):
        require(obj[key] == pins[key], 'CHAPTER_POLICY_BINDING_MISMATCH', 'unavailable')
    flags = ('permit_chapter_mapping', 'permit_section_title_projection',
             'permit_section_digest_projection', 'permit_reference_digest_comparison',
             'permit_repository_write', 'permit_knowledge_write',
             'permit_business_source_write', 'permit_issue_write', 'permit_publish')
    require(all(type(obj[k]) is bool for k in flags), 'CHAPTER_POLICY_FLAG_TYPE_INVALID')
    require(obj['permit_chapter_mapping'] and boundary.sha(obj['read_receipt_sha256']),
            'CHAPTER_MAPPING_DENIED', 'unavailable')
    require(not any(obj[k] for k in ('permit_repository_write', 'permit_knowledge_write',
            'permit_business_source_write', 'permit_issue_write', 'permit_publish')),
            'CHAPTER_WRITE_INTENT_FORBIDDEN', 'unavailable')
    require(not obj['permit_section_digest_projection'] or bp['permit_provenance_projection'],
            'CHAPTER_DIGEST_PROJECTION_ESCALATION', 'unavailable')
    require(not obj['permit_reference_digest_comparison'] or
            (ip['permit_change_digest_projection'] and
             tp['permit_source_digest_projection']),
            'CHAPTER_FINGERPRINT_COMPARISON_ESCALATION', 'unavailable')
    require(not obj['permit_section_title_projection'] or bp['permit_content_projection'],
            'CHAPTER_TITLE_PROJECTION_ESCALATION', 'unavailable')
    grants = obj['source_grants']
    require(type(grants) is list and len(grants) == len(req['sources']),
            'CHAPTER_GRANTS_INCOMPLETE', 'unavailable')
    for row, pin, grant, prior in zip(req['sources'], pins['source_bindings'], grants,
                                      bp['source_grants']):
        bootstrap.fields(grant, {'source_key', 'source_binding_sha256',
            'permit_section_mapping', 'permit_repository_association',
            'read_receipt_sha256'}, 'CHAPTER_GRANT_FIELDS_INVALID')
        require(grant['source_key'] == pin['source_key'] and
                grant['source_binding_sha256'] == pin['source_binding_sha256'],
                'CHAPTER_GRANT_BINDING_MISMATCH', 'unavailable')
        require(type(grant['permit_section_mapping']) is bool and
                type(grant['permit_repository_association']) is bool and
                (grant['read_receipt_sha256'] is None or
                 boundary.sha(grant['read_receipt_sha256'])),
                'CHAPTER_GRANT_INVALID')
        if grant['permit_section_mapping']:
            require(row['kind'] == 'ces_knowledge' and
                    bp['permit_knowledge_read'] and bp['permit_manifest_read'] and
                    bp['permit_content_projection'] and
                    prior['permit_source_read'] and prior['permit_content_projection'] and
                    boundary.sha(grant['read_receipt_sha256']),
                    'CHAPTER_SECTION_PERMISSION_ESCALATION', 'unavailable')
        if grant['permit_repository_association']:
            require(row['kind'] == 'repository' and
                    boundary.sha(grant['read_receipt_sha256']),
                    'CHAPTER_REPOSITORY_ASSOCIATION_ESCALATION', 'unavailable')
        require(not (grant['permit_section_mapping'] and
                     grant['permit_repository_association']),
                'CHAPTER_GRANT_KIND_CONFLICT', 'unavailable')
    return obj


def _manifest_snapshot(a: dict[str, Any]) -> dict[str, Any]:
    display = a['knowledge_manifest']
    return {'state': display['state'],
            'manifest_sha256': display['manifest_sha256'],
            'snapshot_version': display['snapshot_version'],
            'captured_at_utc': display['captured_at_utc'],
            'declared_coverage': display['declared_coverage'],
            'period_relation': display['period_relation'],
            'declared_entries': display['declared_entries'],
            'unselected_entries': display['unselected_entries']}


def _stable_knowledge(first: dict[str, Any], second: dict[str, Any]) -> bool:
    """Byte-backed source refs include non-projected manifest SHA; no blind text trust."""
    if _manifest_snapshot(first) != _manifest_snapshot(second):
        return False
    for a, b in zip(first['sources'], second['sources']):
        if a['source_key'] != b['source_key'] or a['kind'] != b['kind']:
            return False
        if a['kind'] == 'ces_knowledge':
            for key in ('state', 'source_ref', 'manifest_entry_match', 'content_base64'):
                if a[key] != b[key]:
                    return False
    return True


def _remove_html_comments(line: str, inside: bool) -> tuple[str, bool]:
    """Omit multiline/inline HTML comments; do not infer links from examples."""
    kept = []
    i = 0
    while i < len(line):
        if inside:
            finish = line.find('-->', i)
            if finish < 0:
                break
            i = finish + 3
            inside = False
        else:
            begin = line.find('<!--', i)
            if begin < 0:
                kept.append(line[i:])
                break
            kept.append(line[i:begin])
            i = begin + 4
            inside = True
    return ''.join(kept), inside


def _sections(raw: bytes) -> list[dict[str, Any]]:
    """Parse byte-exact bounded ATX sections and very narrow authored links.

    Never infer associations from fenced examples, inline code, HTML comments,
    similar basenames, arbitrary URL strings or unselected source paths.
    """
    try:
        text = raw.decode('utf-8', 'strict')
    except UnicodeError as exc:
        raise ChapterError('CHAPTER_NON_UTF8', 'unavailable') from exc
    if '\x00' in text:
        raise ChapterError('CHAPTER_NUL_BYTE', 'unavailable')
    lines = raw.splitlines(keepends=True)
    spans: list[dict[str, Any]] = []
    active: dict[str, Any] = {'start': 0, 'heading': None, 'level': 0,
                              'refs': [], 'paths': []}
    offset = 0
    fence: tuple[str, int] | None = None
    html_comment = False
    anchors = 0
    for piece in lines:
        line = piece.decode('utf-8', 'strict').rstrip('\r\n')
        if fence is not None:
            fence_match = FENCE.match(line)
            if fence_match and fence_match.group(1)[0] == fence[0] and \
                    len(fence_match.group(1)) >= fence[1] and not fence_match.group(2).strip():
                fence = None
            offset += len(piece)
            continue
        marker = ANNOTATION.fullmatch(line) if not html_comment else None
        if marker is not None:
            anchors += 1
            active['refs'].append((marker.group(1), marker.group(2)))
        else:
            content, html_comment = _remove_html_comments(line, html_comment)
            fence_match = FENCE.match(content)
            if fence_match:
                fence = (fence_match.group(1)[0], len(fence_match.group(1)))
            else:
                heading = HEADING.match(content)
                if heading is not None:
                    name = heading.group(2).strip()
                    if len(name) > MAX_HEADING_LENGTH or any(ord(ch) < 32 for ch in name):
                        raise ChapterError('CHAPTER_HEADING_INVALID', 'unavailable')
                    if offset > active['start']:
                        active['end'] = offset
                        spans.append(active)
                    active = {'start': offset, 'heading': name,
                              'level': len(heading.group(1)), 'refs': [], 'paths': []}
                if line.lstrip().startswith('<!-- CES-SOURCE'):
                    anchors += 1
                    active['refs'].append((None, None))  # malformed, no inferred link
                else:
                    no_code = INLINE_CODE.sub('', content)
                    matches = [m.group(1) for m in LINK.finditer(no_code)]
                    active['paths'].extend(matches)
                    anchors += len(matches)
        if anchors > MAX_ANCHORS or len(spans) >= MAX_SECTIONS:
            raise ChapterError('CHAPTER_REFERENCE_OR_SECTION_LIMIT', 'unavailable')
        offset += len(piece)
    if offset > active['start'] or not spans:
        active['end'] = len(raw)
        spans.append(active)
    if len(spans) > MAX_SECTIONS:
        raise ChapterError('CHAPTER_REFERENCE_OR_SECTION_LIMIT', 'unavailable')
    for span in spans:
        span['sha256'] = hashlib.sha256(raw[span['start']:span['end']]).hexdigest()
    return spans


def _association(row: dict[str, Any], asserted: set[str | None],
                 methods: set[str], compare_allowed: bool) -> dict[str, Any]:
    change = row['change_kind'] if row['comparison_state'] == \
        'GIT_SELECTED_PATH_BYTES_VERIFIED' else 'UNKNOWN'
    recorded = {x for x in asserted if x is not None}
    if len(recorded) > 1:
        difference = 'CONFLICTING_DOCUMENTED_FINGERPRINTS'
    elif not recorded:
        difference = 'LINK_ONLY_NO_DOCUMENTED_FINGERPRINT'
    elif not compare_allowed:
        difference = 'FINGERPRINT_COMPARISON_NOT_AUTHORIZED'
    elif change == 'UNKNOWN' or row['target_sha256'] is None:
        difference = 'TARGET_DIGEST_NOT_VERIFIED_OR_NOT_PROJECTED'
    elif next(iter(recorded)) == row['target_sha256']:
        difference = 'DOCUMENTED_FINGERPRINT_MATCHES_TARGET'
    else:
        difference = 'DOCUMENTED_FINGERPRINT_DIFFERS_FROM_TARGET'

    if change == 'UNKNOWN':
        review = 'UNKNOWN_SELECTED_SOURCE_EVIDENCE'
    elif difference == 'CONFLICTING_DOCUMENTED_FINGERPRINTS':
        review = 'REVIEW_CONFLICTING_DOCUMENTED_FINGERPRINTS'
    elif difference == 'DOCUMENTED_FINGERPRINT_DIFFERS_FROM_TARGET':
        review = 'REVIEW_DOCUMENTED_FINGERPRINT_DIFFERS'
    elif difference == 'DOCUMENTED_FINGERPRINT_MATCHES_TARGET':
        review = 'NO_FINGERPRINT_MISMATCH_SEMANTICS_UNKNOWN'
    elif change in ('ADDED', 'MODIFIED'):
        review = 'REVIEW_CHANGED_SELECTED_SOURCE'
    elif change == 'MODE_ONLY':
        review = 'REVIEW_MODE_ONLY_NOT_CONTENT_STALENESS'
    else:
        review = 'NO_SELECTED_CHANGE_SIGNAL_NOT_FRESHNESS_PROOF'
    signals = {
        'UNKNOWN_SELECTED_SOURCE_EVIDENCE': 'UNKNOWN_STALENESS_NOT_ESTABLISHED',
        'REVIEW_CONFLICTING_DOCUMENTED_FINGERPRINTS': 'CONFLICTING_DOCUMENTED_SOURCE_FINGERPRINTS',
        'REVIEW_DOCUMENTED_FINGERPRINT_DIFFERS': 'DOCUMENTED_FINGERPRINT_MISMATCH_CANDIDATE',
        'NO_FINGERPRINT_MISMATCH_SEMANTICS_UNKNOWN': 'DOCUMENTED_FINGERPRINT_MATCH_NOT_SEMANTIC_PROOF',
        'REVIEW_CHANGED_SELECTED_SOURCE': 'POTENTIALLY_STALE_SELECTED_GIT_CONTENT_CHANGED',
        'REVIEW_MODE_ONLY_NOT_CONTENT_STALENESS': 'MODE_ONLY_NO_CONTENT_STALENESS_PROOF',
        'NO_SELECTED_CHANGE_SIGNAL_NOT_FRESHNESS_PROOF': 'NO_SELECTED_CHANGE_NOT_KNOWLEDGE_FRESHNESS_PROOF',
    }
    return {'source_key': row['source_key'], 'association_methods': sorted(methods),
            'staleness_signal': signals[review],
            'selected_git_change_kind': change,
            'selected_git_comparison_state': row['comparison_state'],
            'documented_fingerprint_state': difference,
            'review_state': review,
            'manual_review_candidate': review.startswith('REVIEW_') or
                review == 'UNKNOWN_SELECTED_SOURCE_EVIDENCE',
            'semantic_dependency_or_staleness_verified': False}


class KnowledgeChapters:
    """Existing-knowledge mapping; host config matches EC204 exactly."""

    def __init__(self, *, repository_root: str, knowledge_root: str,
                 repository_ref: str, target_ref: str,
                 trusted_target_keys: dict[str, bytes],
                 trusted_baseline_keys: dict[str, bytes],
                 git_executable: str | None = None) -> None:
        self.impact = impact.KnowledgeImpact(
            repository_root=repository_root, knowledge_root=knowledge_root,
            repository_ref=repository_ref, target_ref=target_ref,
            trusted_target_keys=trusted_target_keys,
            trusted_baseline_keys=trusted_baseline_keys,
            git_executable=git_executable)

    def _load(self, *, request_json: str, bootstrap_read_policy_json: str,
              target_read_policy_json: str, impact_read_policy_json: str,
              target_statement_json: str,
              baseline_statement_json: str | None) -> tuple[dict[str, Any], ...]:
        req = bootstrap._request(boundary._json(request_json, bootstrap.MAX_REQUEST))
        bp = boundary._json(bootstrap_read_policy_json, bootstrap.MAX_POLICY)
        tp = boundary._json(target_read_policy_json, target.MAX_POLICY)
        ip = boundary._json(impact_read_policy_json, impact.MAX_POLICY)
        td = target._statement(boundary._json(target_statement_json, target.MAX_STATEMENT))
        bd = (impact._baseline_statement(boundary._json(
            baseline_statement_json, impact.MAX_BASELINE)) if
            baseline_statement_json is not None else None)
        pins = _dependencies(self.impact, req, bp, tp, ip, td, bd)
        return req, bp, tp, ip, td, bd, pins

    @staticmethod
    def _local_read_policy(bp: dict[str, Any], req: dict[str, Any],
                           cp: dict[str, Any]) -> dict[str, Any]:
        """Read selected chapter bytes only, not repository bytes/denied chapters.

        EC204 still independently replays the original, exact upstream policy;
        this narrower *additional* local read policy cannot enlarge that grant.
        """
        narrowed = copy.deepcopy(bp)
        for row, grant, original in zip(req['sources'], cp['source_grants'],
                                        narrowed['source_grants']):
            if row['kind'] != 'ces_knowledge' or not grant['permit_section_mapping']:
                original['permit_source_read'] = False
                original['permit_content_projection'] = False
                original['read_receipt_sha256'] = None
        return narrowed

    def binding_preview(self, *, request_json: str, bootstrap_read_policy_json: str,
                        target_read_policy_json: str, impact_read_policy_json: str,
                        target_statement_json: str,
                        baseline_statement_json: str | None = None) -> dict[str, Any]:
        out = _base()
        try:
            *_, pins = self._load(
                request_json=request_json,
                bootstrap_read_policy_json=bootstrap_read_policy_json,
                target_read_policy_json=target_read_policy_json,
                impact_read_policy_json=impact_read_policy_json,
                target_statement_json=target_statement_json,
                baseline_statement_json=baseline_statement_json)
            out.update(status='partial', exit_code=2,
                       reason_code='KNOWLEDGE_CHAPTERS_BINDINGS_ONLY',
                       subject=pins, canonical_json=boundary.canonical(pins))
        except (ChapterError, impact.ImpactError, target.TargetError,
                bootstrap.BootstrapError, boundary.KnowledgeBoundaryError) as exc:
            status = getattr(exc, 'status', 'unavailable')
            out.update(status=status, exit_code=5 if status == 'unavailable' else 4,
                       reason_code='KNOWLEDGE_CHAPTERS_' + getattr(exc, 'code',
                           getattr(exc, 'reason', 'SOURCE_UNAVAILABLE')))
        except (OSError, UnicodeError, ValueError, OverflowError, RecursionError):
            out.update(status='unavailable', exit_code=5,
                       reason_code='KNOWLEDGE_CHAPTERS_SOURCE_UNAVAILABLE')
        return out

    def map_chapters(self, *, request_json: str, bootstrap_read_policy_json: str,
                     target_read_policy_json: str, impact_read_policy_json: str,
                     chapter_read_policy_json: str,
                     target_statement_json: str, target_signature_base64: str | None,
                     baseline_statement_json: str | None = None,
                     baseline_signature_base64: str | None = None) -> dict[str, Any]:
        out = _base()
        try:
            req, bp, tp, ip, td, bd, pins = self._load(
                request_json=request_json,
                bootstrap_read_policy_json=bootstrap_read_policy_json,
                target_read_policy_json=target_read_policy_json,
                impact_read_policy_json=impact_read_policy_json,
                target_statement_json=target_statement_json,
                baseline_statement_json=baseline_statement_json)
            cp = _policy(boundary._json(chapter_read_policy_json, MAX_POLICY),
                         req, pins, bp, tp, ip)
            canonical_req = boundary.canonical(req)
            canonical_bp = boundary.canonical(bp)
            mapped_bp = self._local_read_policy(bp, req, cp)
            canonical_mapped_bp = boundary.canonical(mapped_bp)
            # The upstream EC204 proof uses the original policy unchanged.
            # EC205's extra local reads do not fetch unselected/denied sources.
            first = self.impact.target.bootstrap.read(
                request_json=canonical_req, read_policy_json=canonical_mapped_bp)
            require(first['status'] == 'partial', 'EC202_FIRST_READ_UNAVAILABLE', 'unavailable')
            upstream = self.impact.analyze(
                request_json=canonical_req,
                bootstrap_read_policy_json=canonical_bp,
                target_read_policy_json=boundary.canonical(tp),
                impact_read_policy_json=boundary.canonical(ip),
                target_statement_json=boundary.canonical(td),
                target_signature_base64=target_signature_base64,
                baseline_statement_json=boundary.canonical(bd) if bd is not None else None,
                baseline_signature_base64=baseline_signature_base64)
            require(upstream['status'] == 'partial',
                    'EC204_ATTESTED_CHANGE_RECHECK_UNAVAILABLE', 'unavailable')
            last = self.impact.target.bootstrap.read(
                request_json=canonical_req, read_policy_json=canonical_mapped_bp)
            require(last['status'] == 'partial', 'EC202_FINAL_READ_UNAVAILABLE', 'unavailable')
            stable = _stable_knowledge(first['subject'], last['subject'])
            upstream_subject = upstream['subject']
            change_rows = {r['source_key']: dict(r)
                           for r in upstream_subject['source_changes']
                           if r['kind'] == 'repository'}
            # EC204 itself rechecks the ref, but a separate knowledge read
            # follows. Recheck the exact Git target/root before reporting an
            # EC204 confirmed change as a current mapping observation.
            post_ref_state = 'NO_VERIFIED_SELECTED_SOURCE_CHANGE_TO_RECHECK'
            if any(r['comparison_state'] == 'GIT_SELECTED_PATH_BYTES_VERIFIED'
                   for r in change_rows.values()):
                post_ref_state = 'UNKNOWN_POST_READ_REF_OR_ROOT_DRIFT'
                try:
                    fresh = self.impact.target._preview(req)
                    checks = ('repository_root_binding_sha256',
                        'knowledge_root_binding_sha256', 'git_root_binding_sha256',
                        'target_config_binding_sha256', 'issuer_registry_binding_sha256')
                    if all(fresh[k] == pins[k] for k in checks):
                        target._git_sandbox(self.impact.target.bootstrap.repository_root)
                        git = target._GitReader(
                            self.impact.target.bootstrap.repository_root + '/.git',
                            self.impact.target.git_executable)
                        actual = git.target_commit(req['scope']['target']['revision'],
                            self.impact.target.target_ref)
                        if actual['ref_before'] == req['scope']['target']['revision']['oid'] and \
                                git.ref_after(self.impact.target.target_ref) == actual['ref_before']:
                            post_ref_state = 'SIGNED_TARGET_REF_RECHECKED_AFTER_CHAPTER_READ'
                except (target.TargetError, bootstrap.BootstrapError,
                        OSError, ValueError, UnicodeError):
                    pass
                if post_ref_state != 'SIGNED_TARGET_REF_RECHECKED_AFTER_CHAPTER_READ':
                    for row in change_rows.values():
                        row.update(change_kind='UNKNOWN', target_sha256=None,
                            comparison_state='UNKNOWN_POST_READ_REF_OR_ROOT_DRIFT')
            repo_paths = {r['relative_path']: r['source_key'] for r, grant in
                zip(req['sources'], cp['source_grants'])
                if r['kind'] == 'repository' and grant['permit_repository_association']}
            permitted_repos = set(repo_paths.values())
            known_repos = {r['source_key'] for r in req['sources']
                           if r['kind'] == 'repository'}
            docs = []
            mapped_sources: set[str] = set()
            observed_sections = 0
            mapped_count = 0
            unresolved_count = 0
            review_count = 0
            unknown_documents = 0
            evidence_gap_codes: list[str] = []
            for requested, grant, observed in zip(req['sources'], cp['source_grants'],
                                                   first['subject']['sources']):
                if requested['kind'] != 'ces_knowledge':
                    continue
                record = {'source_key': requested['source_key'],
                    'relative_path': requested['relative_path'],
                    'local_snapshot_state': observed['state'],
                    'mapping_state': 'DENIED_NOT_MAPPED', 'section_count': None,
                    'unrelated_sections_not_projected': None,
                    'unresolved_explicit_references': None, 'sections': []}
                if not grant['permit_section_mapping']:
                    unknown_documents += 1
                    docs.append(record)
                    continue
                if not stable:
                    record['mapping_state'] = 'UNKNOWN_SNAPSHOT_CHANGED_DURING_ANALYSIS'
                elif not requested['relative_path'].lower().endswith(('.md', '.markdown')):
                    record['mapping_state'] = 'UNKNOWN_UNSUPPORTED_CHAPTER_FORMAT'
                elif observed['state'] != 'READ_UNVERIFIED' or \
                        observed['manifest_entry_match'] is not True or \
                        observed['content_base64'] is None:
                    record['mapping_state'] = 'UNKNOWN_MANIFEST_OR_KNOWLEDGE_BYTES'
                else:
                    try:
                        content = base64.b64decode(observed['content_base64'], validate=True)
                        if base64.b64encode(content).decode('ascii') != observed['content_base64']:
                            raise ValueError('noncanonical base64')
                        pieces = _sections(content)
                    except (ChapterError, ValueError, UnicodeError):
                        record['mapping_state'] = 'UNKNOWN_UNPARSABLE_OR_UNBOUNDED_MARKDOWN'
                    else:
                        record['mapping_state'] = 'SELECTED_SNAPSHOT_CHAPTERS_SCANNED'
                        record['section_count'] = len(pieces)
                        unresolved = 0
                        for ordinal, item in enumerate(pieces):
                            associations: dict[str, dict[str, Any]] = {}
                            for key, sha in item['refs']:
                                if key in permitted_repos:
                                    link = associations.setdefault(key, {'sha': set(), 'methods': set()})
                                    link['sha'].add(sha)
                                    link['methods'].add('EXPLICIT_CES_SOURCE_ANNOTATION')
                                else:
                                    unresolved += 1
                            for path in item['paths']:
                                key = repo_paths.get(path)
                                if key is not None:
                                    link = associations.setdefault(key, {'sha': set(), 'methods': set()})
                                    link['methods'].add('EXACT_MARKDOWN_LINK')
                                # Generic unrelated Markdown links are not claimed to be source refs.
                            if not associations:
                                continue
                            linked = []
                            for key in sorted(associations):
                                if key not in known_repos or key not in change_rows:
                                    unresolved += 1
                                    continue
                                evidence = _association(change_rows[key],
                                    associations[key]['sha'], associations[key]['methods'],
                                    cp['permit_reference_digest_comparison'])
                                linked.append(evidence)
                                mapped_sources.add(key)
                            if not linked:
                                continue
                            section_ref = 'cesksection1:' + digest('CES-EC205-SECTION-v1', {
                                'scope_binding_sha256': pins['scope_binding_sha256'],
                                'source_binding_sha256': next(b['source_binding_sha256']
                                    for b in pins['source_bindings']
                                    if b['source_key'] == requested['source_key']),
                                'ordinal': ordinal, 'bytes_sha256': item['sha256'],
                            })
                            candidate = any(e['manual_review_candidate'] for e in linked)
                            record['sections'].append({
                                'section_ref': section_ref,
                                'ordinal': ordinal, 'heading_level': item['level'],
                                'heading': (item['heading'] if
                                    cp['permit_section_title_projection'] else None),
                                'section_sha256': (item['sha256'] if
                                    cp['permit_section_digest_projection'] else None),
                                'associations': linked,
                                'manual_review_candidate': candidate,
                                'semantic_diff_verified': False,
                            })
                            review_count += int(candidate)
                        record['unrelated_sections_not_projected'] = (
                            len(pieces) - len(record['sections']))
                        record['unresolved_explicit_references'] = unresolved
                        unresolved_count += unresolved
                        mapped_count += len(record['sections'])
                        observed_sections += len(pieces)
                if record['mapping_state'] != 'SELECTED_SNAPSHOT_CHAPTERS_SCANNED':
                    unknown_documents += 1
                    evidence_gap_codes.append(record['mapping_state'])
                docs.append(record)
            if not stable:
                evidence_gap_codes.append('SNAPSHOT_OR_KNOWLEDGE_BYTES_CHANGED_BETWEEN_READS')
            if post_ref_state == 'UNKNOWN_POST_READ_REF_OR_ROOT_DRIFT':
                evidence_gap_codes.append(post_ref_state)
            change_subject = list(change_rows.values())
            changed_known = {s['source_key'] for s in change_subject
                if s['kind'] == 'repository' and s['comparison_state'] ==
                'GIT_SELECTED_PATH_BYTES_VERIFIED' and
                s['change_kind'] in ('ADDED', 'MODIFIED', 'MODE_ONLY') and
                s['source_key'] in permitted_repos}
            unmapped_changed = sorted(changed_known - mapped_sources)
            manifest = _manifest_snapshot(first['subject'])
            snapshot_recency = 'UNKNOWN_UNVERIFIED_SNAPSHOT_OR_TARGET_TIME'
            if (manifest['captured_at_utc'] is not None and
                    upstream_subject['target_delivery_state'] ==
                    'SIGNED_DELIVERED_TARGET_OBSERVED_AT_REF'):
                if boundary._time(manifest['captured_at_utc']) < boundary._time(td['delivered_at_utc']):
                    snapshot_recency = 'DECLARED_SNAPSHOT_PREDATES_SIGNED_TARGET_UNVERIFIED_TIME'
                else:
                    snapshot_recency = 'DECLARED_SNAPSHOT_NOT_EARLIER_UNVERIFIED_TIME'
            if manifest['declared_coverage'] != 'complete_declared' or \
                    manifest['unselected_entries'] or \
                    manifest['period_relation'] != 'WITHIN_DECLARED_PERIOD':
                evidence_gap_codes.append('KNOWLEDGE_SNAPSHOT_COVERAGE_NOT_COMPLETE_PROOF')
            if unresolved_count:
                evidence_gap_codes.append('UNRESOLVED_OR_UNAUTHORIZED_EXPLICIT_MARKERS')
            if unmapped_changed:
                evidence_gap_codes.append('CHANGED_SELECTED_SOURCE_HAS_NO_AUTHORIZED_CHAPTER_LINK')
            subject = {
                'model_revision': 'EC205_EXPLICIT_EXISTING_CHAPTER_LINKS_ONLY',
                'repository_ref': req['scope']['repository_ref'],
                'knowledge_space_key': req['scope']['knowledge_space_key'],
                'period_id': req['scope']['period']['period_id'],
                'request_binding_sha256': pins['request_binding_sha256'],
                'scope_binding_sha256': pins['scope_binding_sha256'],
                'bootstrap_policy_binding_sha256': pins['bootstrap_read_policy_binding_sha256'],
                'target_policy_binding_sha256': pins['target_read_policy_binding_sha256'],
                'impact_policy_binding_sha256': pins['impact_read_policy_binding_sha256'],
                'chapter_policy_binding_sha256': digest('CES-EC205-CHAPTER-POLICY-v1', cp),
                'baseline_statement_binding_sha256': pins['baseline_statement_binding_sha256'],
                'target_delivery_state': upstream_subject['target_delivery_state'],
                'selected_change_set_state': (upstream_subject['selected_change_set_state'] if
                    post_ref_state != 'UNKNOWN_POST_READ_REF_OR_ROOT_DRIFT' else
                    'UNKNOWN_POST_READ_REF_OR_ROOT_DRIFT'),
                'target_ref_post_chapter_read_state': post_ref_state,
                'knowledge_snapshot_stable_across_read': stable,
                'knowledge_manifest': manifest,
                'snapshot_recency_signal': snapshot_recency,
                'chapter_documents': docs,
                'summary': {
                    'selected_knowledge_documents': len(docs),
                    'knowledge_documents_mapped': len(docs) - unknown_documents,
                    'knowledge_documents_unknown': unknown_documents,
                    'visible_selected_sections': observed_sections,
                    'sections_with_explicit_selected_source_links': mapped_count,
                    'manual_review_candidate_sections': review_count,
                    'unrelated_sections_not_projected': observed_sections - mapped_count,
                    'unresolved_explicit_refs': unresolved_count,
                    'changed_selected_sources_without_visible_link': len(unmapped_changed),
                    'whole_knowledge_space_linkage_complete': False,
                    'semantic_chapter_differences_verified': False,
                    'knowledge_update_authorized': False,
                },
                'unmapped_changed_selected_source_keys': unmapped_changed,
                'uncertainty_reasons': sorted(set(
                    upstream_subject['uncertainty_reasons'] + evidence_gap_codes + [
                        'CES_SNAPSHOT_LINKS_ARE_AUTHOR_ASSERTIONS_NOT_SEMANTIC_PROOF',
                        'ONLY_EXPLICIT_LINKS_IN_SELECTED_AUTHORIZED_MARKDOWN_EXAMINED',
                        'NO_PRIOR_KNOWLEDGE_VERSION_FOR_TEXTUAL_CHAPTER_DIFF',
                        'NO_AUTOMATIC_KNOWLEDGE_REWRITE_AUTHORITY',
                    ])),
                'knowledge_sections_to_update': [],
                'verified_delivered_facts': [],
                'no_write_actions_performed': True,
                'next_unimplemented': ['EC206_KNOWLEDGE_CANDIDATE_ISOLATION',
                    'EC207_KNOWLEDGE_UPDATE_HANDOFF', 'EC208_KNOWLEDGE_SAVE',
                    'NATIVE_POWERSHELL_KNOWLEDGE_ROUTE'],
            }
            out.update(status='partial', exit_code=2,
                reason_code=('KNOWLEDGE_CHAPTERS_EXPLICIT_LINKS_PARTIAL' if stable
                    else 'KNOWLEDGE_CHAPTERS_SNAPSHOT_DRIFT_UNKNOWN'),
                subject=subject, canonical_json=boundary.canonical(subject))
        except (ChapterError, impact.ImpactError, target.TargetError,
                bootstrap.BootstrapError, boundary.KnowledgeBoundaryError) as exc:
            status = getattr(exc, 'status', 'unavailable')
            out.update(status=status, exit_code=5 if status == 'unavailable' else 4,
                       reason_code='KNOWLEDGE_CHAPTERS_' + getattr(exc, 'code',
                           getattr(exc, 'reason', 'SOURCE_UNAVAILABLE')))
        except (OSError, UnicodeError, ValueError, OverflowError, RecursionError):
            out.update(status='unavailable', exit_code=5,
                       reason_code='KNOWLEDGE_CHAPTERS_SOURCE_UNAVAILABLE')
        return out
