#!/usr/bin/env python3
"""EC204: bounded selected-path Git changes between independently attested revisions.

No changes are written. An EC203 target receipt is freshly recomputed with
actual source/Git bytes, not accepted as caller-supplied JSON. A separate,
previously authorized baseline signer and exact read grant are mandatory.
Only selected repository paths are compared; *semantic* knowledge impact stays
UNKNOWN, including when every selected Git path can be compared exactly.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
from typing import Any

try:
    from . import knowledge_boundary as boundary
    from . import knowledge_bootstrap as bootstrap
    from . import knowledge_target_binding as target
except ImportError:
    import knowledge_boundary as boundary
    import knowledge_bootstrap as bootstrap
    import knowledge_target_binding as target

SCHEMA = 'ces.knowledge_impact.v1'
POLICY_SCHEMA = 'ces.knowledge_impact_read_policy.v1'
BASELINE_SCHEMA = 'ces.knowledge_impact_baseline_statement.v1'
PURPOSE = 'knowledge_impact_read_only'
BASELINE_PURPOSE = 'knowledge_preceding_delivered_commit'
BASELINE_DOMAIN = b'CES-EC204-BASELINE-ATTESTATION-v1\0'
MAX_POLICY = 65536
MAX_BASELINE = 8192
LIMITATIONS = {
    'organization_baseline_signer_authorization_or_revocation_verified': False,
    'repository_delivery_event_authoritatively_verified': False,
    'unselected_repository_paths_examined': False,
    'git_ref_future_stability_guaranteed': False,
    'knowledge_snapshot_completeness_or_semantics_verified': False,
    'knowledge_section_mapping_or_content_semantically_verified': False,
    'knowledge_save_candidate_store_or_publication_performed': False,
    'business_git_issue_provider_or_file_write_performed': False,
    'native_powershell_knowledge_route_registered': False,
}


class ImpactError(ValueError):
    def __init__(self, code: str, status: str = 'invalid_input') -> None:
        super().__init__(code)
        self.code, self.status = code, status


def require(predicate: bool, code: str, status: str = 'invalid_input') -> None:
    if not predicate:
        raise ImpactError(code, status)


def _digest(domain: str, value: Any) -> str:
    return boundary.digest(domain, value)


def _base() -> dict[str, Any]:
    return {'schema': SCHEMA, 'status': 'invalid_input', 'exit_code': 4,
            'reason_code': 'KNOWLEDGE_IMPACT_INVALID_INPUT', 'subject': None,
            'canonical_json': None, 'limitations': dict(LIMITATIONS)}


def _baseline_statement(obj: Any) -> dict[str, Any]:
    bootstrap.fields(obj, {'schema', 'purpose', 'signer_key_id', 'repository_ref',
        'knowledge_space_key', 'source_policy_revision', 'period_id',
        'request_binding_sha256', 'scope_binding_sha256',
        'target_statement_binding_sha256', 'target_ref', 'baseline_revision',
        'target_revision', 'baseline_recorded_at_utc'}, 'BASELINE_FIELDS_INVALID')
    require(obj['schema'] == BASELINE_SCHEMA and obj['purpose'] == BASELINE_PURPOSE,
            'BASELINE_TYPE_INVALID')
    require(boundary.key(obj['signer_key_id']) and
            type(obj['repository_ref']) is str and
            boundary.REPO.fullmatch(obj['repository_ref']) is not None and
            all(boundary.key(obj[k]) for k in ('knowledge_space_key',
                 'source_policy_revision', 'period_id')),
            'BASELINE_IDENTITY_INVALID')
    require(all(boundary.sha(obj[k]) for k in ('request_binding_sha256',
        'scope_binding_sha256', 'target_statement_binding_sha256')),
        'BASELINE_DIGEST_INVALID')
    target._ref(obj['target_ref'])
    try:
        boundary._revision(obj['baseline_revision'])
        boundary._revision(obj['target_revision'])
        boundary._time(obj['baseline_recorded_at_utc'])
    except boundary.KnowledgeBoundaryError as exc:
        raise ImpactError('BASELINE_' + exc.reason) from exc
    require(obj['baseline_revision'] is not None and
            obj['target_revision'] is not None and
            obj['baseline_revision']['algorithm'] == obj['target_revision']['algorithm'],
            'BASELINE_REVISION_INVALID')
    return obj


def _verify_baseline(doc: dict[str, Any], signature: Any,
                     keys: dict[str, bytes]) -> str:
    public_key = keys.get(doc['signer_key_id'])
    if public_key is None:
        return 'UNKNOWN_BASELINE_SIGNER'
    if type(signature) is not str or len(signature) != 88:
        return 'BASELINE_SIGNATURE_MISSING_OR_MALFORMED'
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
        if len(signature_bytes) != 64 or base64.b64encode(signature_bytes).decode('ascii') != signature:
            return 'BASELINE_SIGNATURE_MISSING_OR_MALFORMED'
    except (ValueError, binascii.Error):
        return 'BASELINE_SIGNATURE_MISSING_OR_MALFORMED'
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return 'BASELINE_VERIFIER_DEPENDENCY_UNAVAILABLE'
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature_bytes, BASELINE_DOMAIN + boundary.canonical(doc).encode('ascii'))
    except (ValueError, TypeError, InvalidSignature):
        return 'BASELINE_SIGNATURE_INVALID'
    return 'BASELINE_SIGNATURE_VERIFIED_CONFIGURED_KEY'


def _statement_matches(doc: dict[str, Any], req: dict[str, Any],
                       pins: dict[str, Any], delivery: dict[str, Any],
                       host_ref: str) -> bool:
    scope = req['scope']
    return (doc['repository_ref'] == scope['repository_ref'] and
        doc['knowledge_space_key'] == scope['knowledge_space_key'] and
        doc['source_policy_revision'] == scope['source_policy_revision'] and
        doc['period_id'] == scope['period']['period_id'] and
        doc['request_binding_sha256'] == pins['request_binding_sha256'] and
        doc['scope_binding_sha256'] == pins['scope_binding_sha256'] and
        doc['target_statement_binding_sha256'] == _digest(
            'CES-EC204-TARGET-STATEMENT-v1', delivery) and
        doc['target_ref'] == host_ref and
        doc['target_revision'] == scope['target']['revision'] and
        boundary._time(doc['baseline_recorded_at_utc']) <
            boundary._time(delivery['delivered_at_utc']))


def _read_policy(obj: Any, req: dict[str, Any], pins: dict[str, Any],
                 bp: dict[str, Any], tp: dict[str, Any],
                 base_registry_digest: str, target_statement: dict[str, Any]) -> dict[str, Any]:
    bootstrap.fields(obj, {'schema', 'purpose', 'repository_ref', 'knowledge_space_key',
        'period_id', 'source_policy_revision', 'request_binding_sha256',
        'scope_binding_sha256', 'repository_root_binding_sha256',
        'knowledge_root_binding_sha256', 'git_root_binding_sha256',
        'target_config_binding_sha256', 'issuer_registry_binding_sha256',
        'baseline_issuer_registry_binding_sha256',
        'bootstrap_read_policy_binding_sha256', 'target_read_policy_binding_sha256',
        'target_statement_binding_sha256', 'read_receipt_sha256',
        'permit_impact_read', 'permit_baseline_signature_verification',
        'permit_baseline_git_read', 'permit_selected_path_compare',
        'permit_change_digest_projection', 'permit_repository_write',
        'permit_knowledge_write', 'permit_business_source_write',
        'permit_issue_write', 'permit_publish', 'source_grants'},
        'IMPACT_POLICY_FIELDS_INVALID')
    require(obj['schema'] == POLICY_SCHEMA and obj['purpose'] == PURPOSE,
            'IMPACT_POLICY_PURPOSE_INVALID', 'unavailable')
    scope = req['scope']
    require(all(obj[k] == scope[k] for k in ('repository_ref',
        'knowledge_space_key', 'source_policy_revision')) and
        obj['period_id'] == scope['period']['period_id'],
        'IMPACT_POLICY_SCOPE_MISMATCH', 'unavailable')
    for key in ('request_binding_sha256', 'scope_binding_sha256',
                'repository_root_binding_sha256', 'knowledge_root_binding_sha256',
                'git_root_binding_sha256', 'target_config_binding_sha256',
                'issuer_registry_binding_sha256'):
        require(obj[key] == pins[key], 'IMPACT_POLICY_PIN_MISMATCH', 'unavailable')
    require(obj['baseline_issuer_registry_binding_sha256'] == base_registry_digest and
        obj['bootstrap_read_policy_binding_sha256'] == _digest(
             'CES-EC202-READ-POLICY-v1', bp) and
        obj['target_read_policy_binding_sha256'] == _digest(
             'CES-EC203-TARGET-POLICY-v1', tp) and
        obj['target_statement_binding_sha256'] == _digest(
             'CES-EC204-TARGET-STATEMENT-v1', target_statement),
        'IMPACT_POLICY_DEPENDENCY_MISMATCH', 'unavailable')
    bools = ('permit_impact_read', 'permit_baseline_signature_verification',
             'permit_baseline_git_read', 'permit_selected_path_compare',
             'permit_change_digest_projection', 'permit_repository_write',
             'permit_knowledge_write', 'permit_business_source_write',
             'permit_issue_write', 'permit_publish')
    require(all(type(obj[k]) is bool for k in bools), 'IMPACT_POLICY_FLAGS_INVALID')
    require(obj['permit_impact_read'] and boundary.sha(obj['read_receipt_sha256']),
            'IMPACT_READ_DENIED', 'unavailable')
    require(not any(obj[k] for k in ('permit_repository_write',
        'permit_knowledge_write', 'permit_business_source_write',
        'permit_issue_write', 'permit_publish')),
        'IMPACT_WRITE_INTENT_FORBIDDEN', 'unavailable')
    require(not obj['permit_selected_path_compare'] or obj['permit_baseline_git_read'],
            'IMPACT_PATH_PERMISSION_ESCALATION', 'unavailable')
    require(not obj['permit_change_digest_projection'] or
            (obj['permit_selected_path_compare'] and tp['permit_source_digest_projection']),
            'IMPACT_DIGEST_PERMISSION_ESCALATION', 'unavailable')
    grants = obj['source_grants']
    require(type(grants) is list and len(grants) == len(pins['source_bindings']),
            'IMPACT_GRANTS_INCOMPLETE', 'unavailable')
    for row, grant, bind, tgrant in zip(req['sources'], grants,
                                       pins['source_bindings'], tp['source_grants']):
        bootstrap.fields(grant, {'source_key', 'source_binding_sha256',
            'permit_baseline_path_compare', 'read_receipt_sha256'},
            'IMPACT_GRANT_FIELDS_INVALID')
        require(grant['source_key'] == bind['source_key'] and
                grant['source_binding_sha256'] == bind['source_binding_sha256'],
                'IMPACT_GRANT_BINDING_MISMATCH', 'unavailable')
        require(type(grant['permit_baseline_path_compare']) is bool and
                (grant['read_receipt_sha256'] is None or
                 boundary.sha(grant['read_receipt_sha256'])),
                'IMPACT_GRANT_INVALID')
        require(not grant['permit_baseline_path_compare'] or
                (row['kind'] == 'repository' and
                 obj['permit_selected_path_compare'] and
                 tgrant['permit_git_blob_compare'] and
                 boundary.sha(grant['read_receipt_sha256'])),
                'IMPACT_GRANT_ESCALATION', 'unavailable')
    return obj


def _commit_object(reader: target._GitReader, oid: str, algorithm: str) -> str:
    """Read and hash base commit bytes; Git's own exit code is not enough."""
    try:
        kind = reader._run(['cat-file', '-t', oid]).decode('ascii').strip()
        if kind != 'commit':
            return 'BASELINE_NOT_COMMIT'
        size_text = reader._run(['cat-file', '-s', oid]).decode('ascii').strip()
        if not size_text.isascii() or not size_text.isdecimal() or int(size_text) > target.MAX_COMMIT:
            return 'BASELINE_COMMIT_OVERSIZED_OR_INVALID'
        payload = reader._run(['cat-file', 'commit', oid], target.MAX_COMMIT)
        if len(payload) != int(size_text) or target._git_oid(payload, 'commit', algorithm) != oid:
            return 'BASELINE_COMMIT_OBJECT_HASH_MISMATCH'
    except (target.TargetError, UnicodeError):
        return 'BASELINE_COMMIT_UNAVAILABLE'
    return 'BASELINE_COMMIT_OBJECT_VERIFIED'


def _ancestor(reader: target._GitReader, baseline: str, destination: str) -> bool:
    """Exact merge-base result, not a similarity guess or PR metadata."""
    try:
        merged = reader._run(['merge-base', baseline, destination]).decode('ascii').strip()
        return merged == baseline
    except (target.TargetError, UnicodeError):
        return False


def _tree_entry(reader: target._GitReader, commit: str, path: str,
                algorithm: str) -> tuple[str, dict[str, str] | None]:
    """Inspect one literal bounded path; verify actual blob bytes independently."""
    try:
        raw = reader._run(['ls-tree', '-rz', '--full-tree', commit,
                           '--', ':(literal)' + path], 4096)
        if not raw:
            return 'PATH_ABSENT', None
        rows = raw.rstrip(b'\0').split(b'\0')
        if len(rows) != 1 or b'\t' not in rows[0]:
            return 'TREE_ENTRY_AMBIGUOUS', None
        meta, entry_path = rows[0].split(b'\t', 1)
        if entry_path != path.encode('ascii'):
            return 'TREE_ENTRY_AMBIGUOUS', None
        fields = meta.split(b' ')
        if len(fields) != 3 or fields[0] not in (b'100644', b'100755') or fields[1] != b'blob':
            return 'UNSUPPORTED_TREE_ENTRY', None
        oid = fields[2].decode('ascii')
        if target.GIT_OID.fullmatch(oid) is None or len(oid) != (40 if algorithm == 'sha1' else 64):
            return 'TREE_OBJECT_ID_INVALID', None
        size_text = reader._run(['cat-file', '-s', oid]).decode('ascii').strip()
        if not size_text.isascii() or not size_text.isdecimal() or int(size_text) > bootstrap.MAX_FILE:
            return 'TREE_BLOB_OVERSIZED_OR_INVALID', None
        blob = reader._run(['cat-file', 'blob', oid], bootstrap.MAX_FILE)
        if len(blob) != int(size_text) or target._git_oid(blob, 'blob', algorithm) != oid:
            return 'TREE_BLOB_HASH_MISMATCH', None
        return 'VERIFIED_GIT_BLOB', {'mode': fields[0].decode('ascii'),
             'sha256': hashlib.sha256(blob).hexdigest()}
    except (target.TargetError, UnicodeError, ValueError):
        return 'GIT_BLOB_UNAVAILABLE', None


class KnowledgeImpact:
    """Host-only configuration. Requests cannot provide their own trusted keys."""

    def __init__(self, *, repository_root: str, knowledge_root: str,
                 repository_ref: str, target_ref: str,
                 trusted_target_keys: dict[str, bytes],
                 trusted_baseline_keys: dict[str, bytes],
                 git_executable: str | None = None) -> None:
        self.target = target.KnowledgeTargetBinding(
            repository_root=repository_root, knowledge_root=knowledge_root,
            repository_ref=repository_ref, target_ref=target_ref,
            trusted_ed25519_keys=trusted_target_keys,
            git_executable=git_executable)
        require(type(trusted_baseline_keys) is dict and
                len(trusted_baseline_keys) <= 16, 'HOST_BASELINE_SIGNERS_INVALID')
        self.baseline_keys = {}
        for key, pub in trusted_baseline_keys.items():
            require(boundary.key(key) and type(pub) is bytes and len(pub) == 32,
                    'HOST_BASELINE_SIGNER_INVALID')
            self.baseline_keys[key] = pub
        self.registry_pin = _digest('CES-EC204-BASELINE-ISSUERS-v1', [
            {'key_id': k, 'public_key_sha256': hashlib.sha256(v).hexdigest()}
            for k, v in sorted(self.baseline_keys.items())])

    def binding_preview(self, *, request_json: str) -> dict[str, Any]:
        out = _base()
        try:
            request = bootstrap._request(boundary._json(request_json, bootstrap.MAX_REQUEST))
            preview = self.target._preview(request)
            pins = {**preview,
                    'baseline_issuer_registry_binding_sha256': self.registry_pin}
            out.update(status='partial', exit_code=2,
                       reason_code='KNOWLEDGE_IMPACT_BINDINGS_ONLY', subject=pins,
                       canonical_json=boundary.canonical(pins))
        except (ImpactError, target.TargetError, bootstrap.BootstrapError,
                boundary.KnowledgeBoundaryError) as exc:
            status = getattr(exc, 'status', 'unavailable')
            out.update(status=status, exit_code=5 if status == 'unavailable' else 4,
                reason_code='KNOWLEDGE_IMPACT_' + getattr(exc, 'code',
                  getattr(exc, 'reason', 'SOURCE_UNAVAILABLE')))
        except (OSError, UnicodeError, ValueError):
            out.update(status='unavailable', exit_code=5,
                       reason_code='KNOWLEDGE_IMPACT_SOURCE_UNAVAILABLE')
        return out

    def analyze(self, *, request_json: str, bootstrap_read_policy_json: str,
                target_read_policy_json: str, impact_read_policy_json: str,
                target_statement_json: str, target_signature_base64: str | None,
                baseline_statement_json: str | None = None,
                baseline_signature_base64: str | None = None) -> dict[str, Any]:
        out = _base()
        try:
            request = bootstrap._request(boundary._json(request_json, bootstrap.MAX_REQUEST))
            pins = self.target._preview(request)
            bp = boundary._json(bootstrap_read_policy_json, bootstrap.MAX_POLICY)
            tp = boundary._json(target_read_policy_json, target.MAX_POLICY)
            bootstrap._policy(bp, request, pins)
            target._policy(tp, request, pins, bp)
            signed_target = target._statement(boundary._json(
                target_statement_json, target.MAX_STATEMENT))
            ip = _read_policy(boundary._json(impact_read_policy_json, MAX_POLICY),
                request, pins, bp, tp, self.registry_pin, signed_target)
            # Run the EC203 entire verification again. Never trust a supplied
            # success flag or a stored/signature-less earlier result.
            verified = self.target.verify(
                request_json=boundary.canonical(request),
                bootstrap_read_policy_json=boundary.canonical(bp),
                target_read_policy_json=boundary.canonical(tp),
                delivery_statement_json=boundary.canonical(signed_target),
                delivery_signature_base64=target_signature_base64)
            if verified['status'] != 'partial':
                raise ImpactError('TARGET_EC203_RECHECK_UNAVAILABLE', 'unavailable')
            ts = verified['subject']
            repo_rows = [r for r in request['sources'] if r['kind'] == 'repository']
            matching = (ts['delivery_state'] ==
                'SIGNED_DELIVERED_TARGET_OBSERVED_AT_REF' and
                ts['summary']['eligible_for_ec204_source_diff'] and bool(repo_rows))
            baseline_state = 'NOT_INSPECTED_TARGET_NOT_ELIGIBLE'
            comparison_state = 'UNKNOWN_TARGET_NOT_ELIGIBLE'
            base_oid: str | None = None
            source_results: list[dict[str, Any]] = []
            reasons: list[str] = []
            baseline_doc = None
            if not matching:
                reasons.append('TARGET_EC203_SIGNED_SOURCE_GATE_NOT_MET')
            elif not ip['permit_baseline_signature_verification']:
                baseline_state = 'BASELINE_SIGNATURE_CHECK_DENIED_NOT_INSPECTED'
                reasons.append(baseline_state)
            elif baseline_statement_json is None:
                baseline_state = 'BASELINE_STATEMENT_NOT_PROVIDED'
                reasons.append(baseline_state)
            else:
                baseline_doc = _baseline_statement(boundary._json(
                    baseline_statement_json, MAX_BASELINE))
                baseline_state = _verify_baseline(baseline_doc,
                    baseline_signature_base64, self.baseline_keys)
                if baseline_state == 'BASELINE_SIGNATURE_VERIFIED_CONFIGURED_KEY' and not _statement_matches(
                        baseline_doc, request, pins, signed_target, self.target.target_ref):
                    baseline_state = 'BASELINE_SIGNED_SCOPE_OR_TIME_MISMATCH'
                if baseline_state != 'BASELINE_SIGNATURE_VERIFIED_CONFIGURED_KEY':
                    reasons.append(baseline_state)
                elif not ip['permit_baseline_git_read']:
                    baseline_state = 'BASELINE_GIT_READ_DENIED_NOT_INSPECTED'
                    reasons.append(baseline_state)
                else:
                    revision = request['scope']['target']['revision']
                    base_oid = baseline_doc['baseline_revision']['oid']
                    reader = target._GitReader(self.target.bootstrap.repository_root + '/.git',
                                               self.target.git_executable)
                    try:
                        target._git_sandbox(self.target.bootstrap.repository_root)
                        latest = reader.target_commit(revision, self.target.target_ref)
                        require(latest['ref_before'] == revision['oid'],
                                'REF_NO_LONGER_MATCHES_TARGET', 'unavailable')
                        baseline_state = _commit_object(reader, base_oid, revision['algorithm'])
                        if baseline_state == 'BASELINE_COMMIT_OBJECT_VERIFIED':
                            if not _ancestor(reader, base_oid, revision['oid']):
                                baseline_state = 'BASELINE_NOT_CONFIRMED_ANCESTOR'
                        if baseline_state != 'BASELINE_COMMIT_OBJECT_VERIFIED':
                            reasons.append(baseline_state)
                        else:
                            comparison_state = 'SELECTED_PATHS_PARTIALLY_COMPARED'
                            for original, observed, grant in zip(request['sources'],
                                                                 ts['sources'], ip['source_grants']):
                                result = {'source_key': original['source_key'],
                                    'kind': original['kind'],
                                    'relative_path': original['relative_path'],
                                    'target_source_state': observed['target_blob_state'],
                                    'baseline_blob_state': 'NOT_INSPECTED',
                                    'target_blob_state': 'NOT_INSPECTED',
                                    'change_kind': 'UNKNOWN', 'comparison_state': 'UNKNOWN',
                                    'baseline_sha256': None, 'target_sha256': None,
                                    'baseline_mode': None, 'target_mode': None,
                                    'knowledge_section_impact': 'UNKNOWN_NOT_MAPPED'}
                                if original['kind'] != 'repository':
                                    result['comparison_state'] = 'KNOWLEDGE_SOURCE_NOT_MAPPED_EC205'
                                elif not grant['permit_baseline_path_compare']:
                                    result['comparison_state'] = 'DENIED_NOT_INSPECTED'
                                elif not observed['matched_verified_delivery']:
                                    result['comparison_state'] = 'EC203_SOURCE_NOT_VERIFIED'
                                else:
                                    left_state, left = _tree_entry(reader, base_oid,
                                        original['relative_path'], revision['algorithm'])
                                    right_state, right = _tree_entry(reader, revision['oid'],
                                        original['relative_path'], revision['algorithm'])
                                    result['baseline_blob_state'] = left_state
                                    result['target_blob_state'] = right_state
                                    if left_state in ('VERIFIED_GIT_BLOB', 'PATH_ABSENT') and \
                                       right_state == 'VERIFIED_GIT_BLOB' and \
                                       left_state == 'PATH_ABSENT':
                                        kind = 'ADDED'
                                    elif left_state == 'VERIFIED_GIT_BLOB' and right_state == 'PATH_ABSENT':
                                        kind = 'REMOVED'
                                    elif left_state == right_state == 'VERIFIED_GIT_BLOB':
                                        if left['sha256'] != right['sha256']:
                                            kind = 'MODIFIED'
                                        elif left['mode'] != right['mode']:
                                            kind = 'MODE_ONLY'
                                        else:
                                            kind = 'UNCHANGED'
                                    elif left_state == 'PATH_ABSENT' and right_state == 'PATH_ABSENT':
                                        # An EC203-verified target file cannot be absent.
                                        kind = 'UNKNOWN'
                                    else:
                                        kind = 'UNKNOWN'
                                    if kind != 'UNKNOWN':
                                        result['change_kind'] = kind
                                        result['comparison_state'] = 'GIT_SELECTED_PATH_BYTES_VERIFIED'
                                        if ip['permit_change_digest_projection']:
                                            result['baseline_sha256'] = (left or {}).get('sha256')
                                            result['target_sha256'] = (right or {}).get('sha256')
                                            result['baseline_mode'] = (left or {}).get('mode')
                                            result['target_mode'] = (right or {}).get('mode')
                                source_results.append(result)
                            # All normal comparisons are scoped, never global.
                            complete = all(r['comparison_state'] ==
                                'GIT_SELECTED_PATH_BYTES_VERIFIED' for r in source_results
                                if r['kind'] == 'repository')
                            comparison_state = ('SELECTED_REPOSITORY_PATHS_COMPARED' if complete
                                else 'SELECTED_PATHS_PARTIALLY_COMPARED')
                        after = reader.ref_after(self.target.target_ref)
                        post = self.target._preview(request)
                        if (after != latest['ref_before'] or after != revision['oid'] or
                            any(post[field] != pins[field] for field in
                                ('repository_root_binding_sha256', 'knowledge_root_binding_sha256',
                                 'git_root_binding_sha256', 'target_config_binding_sha256',
                                 'issuer_registry_binding_sha256'))):
                            comparison_state = 'UNKNOWN_REF_OR_ROOT_CHANGED_DURING_ANALYSIS'
                            reasons.append('REF_OR_ROOT_CHANGED_DURING_ANALYSIS')
                            for r in source_results:
                                r.update(change_kind='UNKNOWN', comparison_state='UNKNOWN_REF_DRIFT',
                                         baseline_sha256=None, target_sha256=None,
                                         baseline_mode=None, target_mode=None)
                    except (target.TargetError, bootstrap.BootstrapError,
                            ImpactError, OSError, ValueError, UnicodeError):
                        comparison_state = 'UNKNOWN_GIT_RECHECK_UNAVAILABLE'
                        reasons.append('GIT_RECHECK_UNAVAILABLE')
                        for r in source_results:
                            r.update(change_kind='UNKNOWN', comparison_state='UNKNOWN_GIT_RECHECK',
                                     baseline_sha256=None, target_sha256=None,
                                     baseline_mode=None, target_mode=None)
            if not source_results:
                for r, observed in zip(request['sources'], ts['sources']):
                    source_results.append({'source_key': r['source_key'], 'kind': r['kind'],
                       'relative_path': r['relative_path'],
                       'target_source_state': observed['target_blob_state'],
                       'baseline_blob_state': 'NOT_INSPECTED',
                       'target_blob_state': 'NOT_INSPECTED', 'change_kind': 'UNKNOWN',
                       'comparison_state': 'UNKNOWN_UNVERIFIED_BASELINE_OR_TARGET',
                       'baseline_sha256': None, 'target_sha256': None,
                       'baseline_mode': None, 'target_mode': None,
                       'knowledge_section_impact': 'UNKNOWN_NOT_MAPPED'})
            verified_rows = [r for r in source_results if r['kind'] == 'repository' and
                             r['comparison_state'] == 'GIT_SELECTED_PATH_BYTES_VERIFIED']
            delta_rows = [r for r in verified_rows if r['change_kind'] not in ('UNCHANGED', 'UNKNOWN')]
            incomplete_sources = [r['source_key'] for r in source_results
                if r['kind'] == 'repository' and
                r['comparison_state'] != 'GIT_SELECTED_PATH_BYTES_VERIFIED']
            knowledge_gaps = ts['bootstrap_coverage_gaps']
            if knowledge_gaps:
                reasons.append('EC202_KNOWLEDGE_COVERAGE_GAPS_RETAINED')
            if incomplete_sources:
                reasons.append('SELECTED_REPOSITORY_PATHS_NOT_FULLY_COMPARABLE')
            subject = {'model_revision': 'EC204_ATTESTED_SELECTED_GIT_CHANGE_SET_ONLY',
                'repository_ref': request['scope']['repository_ref'],
                'knowledge_space_key': request['scope']['knowledge_space_key'],
                'period_id': request['scope']['period']['period_id'],
                'scope_binding_sha256': pins['scope_binding_sha256'],
                'request_binding_sha256': pins['request_binding_sha256'],
                'bootstrap_policy_binding_sha256': _digest('CES-EC202-READ-POLICY-v1', bp),
                'target_policy_binding_sha256': _digest('CES-EC203-TARGET-POLICY-v1', tp),
                'impact_policy_binding_sha256': _digest('CES-EC204-IMPACT-POLICY-v1', ip),
                'baseline_issuer_registry_binding_sha256': self.registry_pin,
                'target_delivery_state': ts['delivery_state'],
                'baseline_binding_state': baseline_state,
                'selected_change_set_state': comparison_state,
                'target_revision': request['scope']['target']['revision']
                    if tp['permit_target_oid_projection'] else None,
                'baseline_revision': baseline_doc['baseline_revision']
                    if (baseline_doc is not None and baseline_state ==
                        'BASELINE_COMMIT_OBJECT_VERIFIED' and
                        tp['permit_target_oid_projection']) else None,
                'source_changes': source_results,
                'summary': {'selected_repository_paths': len(repo_rows),
                    'source_paths_compared': len(verified_rows),
                    'changed_selected_paths': len(delta_rows),
                    'unknown_selected_paths': len(incomplete_sources),
                    'selected_source_comparison_complete': comparison_state ==
                        'SELECTED_REPOSITORY_PATHS_COMPARED',
                    'whole_repository_change_set_complete': False,
                    'knowledge_chapter_impact_verified': False},
                'knowledge_impact_state': 'UNKNOWN_REQUIRES_EC205_SECTION_MAPPING_AND_REVIEW',
                'knowledge_sections_to_update': [],
                'bootstrap_coverage_gaps': knowledge_gaps,
                'target_binding_coverage_gaps': ts['coverage_gaps'],
                'uncertainty_reasons': sorted(set(reasons + [
                    'UNSELECTED_REPOSITORY_PATHS_NOT_AUTHORIZED_OR_COMPARED',
                    'KNOWLEDGE_SEMANTIC_IMPACT_NOT_VERIFIED'])),
                'verified_delivered_facts': [], 'no_write_actions_performed': True,
                'next_unimplemented': ['EC205_KNOWLEDGE_SECTION_ASSOCIATION',
                    'EC206_CANDIDATE_KNOWLEDGE_STORE', 'EC208_KNOWLEDGE_SAVE',
                    'NATIVE_POWERSHELL_KNOWLEDGE_ROUTE']}
            out.update(status='partial', exit_code=2,
                reason_code=('KNOWLEDGE_IMPACT_SELECTED_GIT_CHANGES_PARTIAL' if
                    comparison_state == 'SELECTED_REPOSITORY_PATHS_COMPARED'
                    else 'KNOWLEDGE_IMPACT_EVIDENCE_INCOMPLETE'),
                subject=subject, canonical_json=boundary.canonical(subject))
        except (ImpactError, target.TargetError, bootstrap.BootstrapError,
                boundary.KnowledgeBoundaryError) as exc:
            status = getattr(exc, 'status', 'unavailable')
            out.update(status=status, exit_code=5 if status == 'unavailable' else 4,
                reason_code='KNOWLEDGE_IMPACT_' + getattr(exc, 'code',
                    getattr(exc, 'reason', 'SOURCE_UNAVAILABLE')))
        except (OSError, UnicodeError, ValueError, OverflowError, RecursionError):
            out.update(status='unavailable', exit_code=5,
                reason_code='KNOWLEDGE_IMPACT_SOURCE_UNAVAILABLE')
        return out
