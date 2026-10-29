#!/usr/bin/env python3
"""EC242: pinned, offline CES cross-domain JSON schema admission and migration plan.

This is a READ-ONLY compatibility inspector over exact source bytes. It uses
only locally pinned schemas, never fetches $refs, never alters saved evidence,
and never converts schema validity into source authenticity or business approval.

Eight application domains are supported. The R158 CodeInsight reader remains
its own governing legacy byte/ID inspector; other contracts are admitted only
via a pinned literal path and its exact root discriminator or an explicitly
named historical unversioned request contract.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = ROOT / 'construction' / 'SCHEMA_CATALOG.json'
SCHEMA = 'ces.schema_migration_review.v1'
VERSION = 'V5.52'
BUILD = 'R242'
DOMAINS = ('CodeInsight', 'Finding', 'Quality', 'Report', 'Knowledge',
           'Issue', 'Delivery', 'Cycle', 'Infrastructure')
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_CATALOG_BYTES = 256 * 1024
MAX_SCHEMA_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 256 * 1024
MAX_DEPTH = 48
MAX_DIAGNOSTICS = 12
SHA256_RE = re.compile(r'[0-9a-f]{64}\Z')
CONTRACT_RE = re.compile(r'[a-z][a-z0-9-]*\.v[0-9]+\Z')
TRUST = ('OFFLINE_LOCAL_SCHEMA_AND_EXACT_BYTES_ONLY; NO_ORIGIN_ACTOR_SIGNATURE_'
         'HMAC_SOURCE_CURRENTNESS_SEMANTIC_CI_APPROVAL_OR_BUSINESS_AUTHORITY')


class ReviewError(Exception):
    def __init__(self, code: str, exit_code: int = 4):
        super().__init__(code)
        self.code, self.exit_code = code, exit_code


def require(ok: bool, code: str, exit_code: int = 4) -> None:
    if not ok:
        raise ReviewError(code, exit_code)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    seen: set[str] = set()
    for key, value in items:
        folded = key.casefold()
        require(folded not in seen, 'DUPLICATE_OR_CASE_COLLIDING_JSON_PROPERTY')
        seen.add(folded)
        d[key] = value
    return d


def _finite(token: str) -> float:
    v = float(token)
    require(math.isfinite(v), 'NONFINITE_JSON_NUMBER')
    return v


def _reject_constant(_: str) -> None:
    raise ReviewError('NON_JSON_CONSTANT')


def strict_decode(raw: bytes, *, root_object: bool = True) -> Any:
    require(not raw.startswith(b'\xef\xbb\xbf'), 'UTF8_BOM_NOT_ALLOWED')
    try:
        obj = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=_pairs,
                         parse_float=_finite, parse_constant=_reject_constant)
    except ReviewError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise ReviewError('NOT_ONE_STRICT_UTF8_JSON_VALUE') from exc
    if root_object:
        require(type(obj) is dict, 'JSON_ROOT_OBJECT_REQUIRED')
    # Iterative depth walk prevents recursion overflow and unpaired surrogate
    # escapes that would otherwise be accepted by Python's JSON decoder.
    stack = [(obj, 1)]
    while stack:
        value, depth = stack.pop()
        require(depth <= MAX_DEPTH, 'JSON_DEPTH_LIMIT')
        if type(value) is dict:
            for k, v in value.items():
                require(not any(0xD800 <= ord(ch) <= 0xDFFF for ch in k),
                        'UNPAIRED_SURROGATE_IN_JSON_KEY')
                if type(v) in (dict, list): stack.append((v, depth + 1))
                if type(v) is str:
                    require(not any(0xD800 <= ord(ch) <= 0xDFFF for ch in v),
                            'UNPAIRED_SURROGATE_IN_JSON_STRING')
        elif type(value) is list:
            for v in value:
                if type(v) in (dict, list): stack.append((v, depth + 1))
                if type(v) is str:
                    require(not any(0xD800 <= ord(ch) <= 0xDFFF for ch in v),
                            'UNPAIRED_SURROGATE_IN_JSON_STRING')
        elif type(value) is str:
            require(not any(0xD800 <= ord(ch) <= 0xDFFF for ch in value),
                    'UNPAIRED_SURROGATE_IN_JSON_STRING')
    return obj


def read_regular(path: str | Path, budget: int, *, input_stdin: bool = False) -> bytes:
    require(0 < budget <= MAX_INPUT_BYTES or (not input_stdin and budget <= MAX_CATALOG_BYTES),
            'INVALID_BYTE_BUDGET')
    if input_stdin and str(path) == '-':
        raw = sys.stdin.buffer.read(budget + 1)
        require(0 < len(raw) <= budget, 'INPUT_TOO_LARGE_OR_EMPTY')
        return raw
    name = str(path)
    try:
        prior = os.lstat(name)
        require(stat.S_ISREG(prior.st_mode), 'NON_REGULAR_OR_SYMLINK_INPUT', 5)
        require(0 < prior.st_size <= budget, 'FILE_TOO_LARGE_OR_EMPTY', 5)
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
        fd = os.open(name, flags)
        try:
            stat0 = os.fstat(fd)
            require(stat.S_ISREG(stat0.st_mode) and
                    (stat0.st_dev, stat0.st_ino) == (prior.st_dev, prior.st_ino),
                    'FILE_CHANGED_BEFORE_READ', 5)
            raw = os.read(fd, budget + 1)
            stat1 = os.fstat(fd)
            require(len(raw) == stat0.st_size == stat1.st_size and
                    stat1.st_mtime_ns == stat0.st_mtime_ns and
                    stat1.st_ctime_ns == stat0.st_ctime_ns and
                    stat1.st_ino == stat0.st_ino, 'FILE_CHANGED_DURING_READ', 5)
            return raw
        finally:
            os.close(fd)
    except ReviewError:
        raise
    except OSError as exc:
        raise ReviewError('FILE_READ_UNAVAILABLE', 5) from exc


def _validate_root_markers(doc: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    def direct(d: dict[str, Any]) -> list[tuple[str, str]]:
        props = d.get('properties')
        if type(props) is not dict: return []
        return [(name, props[name]['const']) for name in ('schema', 'schema_version')
                if type(props.get(name)) is dict and type(props[name].get('const')) is str]
    values = direct(doc)
    if not values:
        for branch in doc.get('oneOf', []):
            if type(branch) is dict: values += direct(branch)
    return tuple(sorted(set(values)))


def catalog() -> dict[str, Any]:
    reg = strict_decode(read_regular(CATALOG_PATH, MAX_CATALOG_BYTES))
    require(reg.get('schema') == 'ces.ec242.schema_catalog.v1', 'CATALOG_SCHEMA_UNRECOGNIZED', 5)
    entries = reg.get('contracts')
    require(type(entries) is list and len(entries) >= 100, 'CATALOG_INCOMPLETE', 5)
    used: set[tuple[str, str]] = set()
    paths: set[str] = set()
    for e in entries:
        require(type(e) is dict and set(e) == {
            'domain', 'contract', 'path', 'sha256', 'markers', 'declared_id', 'draft'
        }, 'CATALOG_ENTRY_INVALID', 5)
        require(e['domain'] in DOMAINS[1:], 'CATALOG_DOMAIN_INVALID', 5)
        contract = e['contract']
        require(type(contract) is str and CONTRACT_RE.fullmatch(contract) is not None,
                'CATALOG_CONTRACT_INVALID', 5)
        require(e['path'] == 'references/' + contract + '.schema.json' and
                (e['domain'], contract) not in used and e['path'] not in paths,
                'CATALOG_DUPLICATE_OR_UNSAFE_PATH', 5)
        require(type(e['sha256']) is str and SHA256_RE.fullmatch(e['sha256']) is not None,
                'CATALOG_DIGEST_INVALID', 5)
        require(type(e['markers']) is list and all(
            type(x) is dict and set(x) == {'field', 'value'} and
            x['field'] in ('schema', 'schema_version') and
            type(x['value']) is str and x['value'].startswith('ces.')
            for x in e['markers']), 'CATALOG_MARKER_INVALID', 5)
        used.add((e['domain'], contract))
        paths.add(e['path'])
    legacy = reg.get('legacy_codeinsight')
    require(type(legacy) is dict and legacy.get('kinds') == [
        'cli_response', 'collect_snapshot', 'code_packet', 'code_insight_draft',
        'code_insight_saved', 'local_store_owner'
    ], 'CATALOG_CODEINSIGHT_READER_UNAVAILABLE', 5)
    return reg


def _check_local_refs(schema: Any) -> None:
    stack = [schema]
    while stack:
        item = stack.pop()
        if type(item) is dict:
            for key, value in item.items():
                if key in ('$ref', '$dynamicRef'):
                    require(type(value) is str and value.startswith('#/') and
                            len(value) <= 256, 'REMOTE_OR_UNSAFE_SCHEMA_REF', 5)
                stack.append(value)
        elif type(item) is list:
            stack.extend(item)


def local_contract(entry: dict[str, Any]) -> dict[str, Any]:
    path = ROOT / entry['path']
    data = read_regular(path, MAX_SCHEMA_BYTES)
    require(sha(data) == entry['sha256'], 'PINNED_SCHEMA_BYTES_DRIFT', 5)
    source = strict_decode(data)
    require(source.get('$schema') == 'https://json-schema.org/draft/2020-12/schema',
            'UNSUPPORTED_SCHEMA_DIALECT', 5)
    require(source.get('$id') == entry['declared_id'] and
            _validate_root_markers(source) == tuple(sorted({(x['field'], x['value']) for x in entry['markers']})),
            'CATALOG_DECLARATION_SOURCE_DRIFT', 5)
    _check_local_refs(source)
    return source


def _validator(schema: dict[str, Any]):
    # This optional developer dependency is required for positive JSON Schema
    # claims. Unavailability is NOT a pass or a permissive fallback.
    try:
        from jsonschema import Draft202012Validator, FormatChecker
        Draft202012Validator.check_schema(schema)
        return Draft202012Validator(schema, format_checker=FormatChecker())
    except ImportError as exc:
        raise ReviewError('JSONSCHEMA_RUNTIME_UNAVAILABLE', 5) from exc
    except Exception as exc:
        raise ReviewError('SCHEMA_INVALID_FOR_DRAFT202012', 5) from exc


def _diag(validator: Any, value: dict[str, Any]) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    # Never return error.message or instance values: these can contain
    # unpublished drafts, passwords or private repository content.
    try:
        for error in validator.iter_errors(value):
            if len(messages) >= MAX_DIAGNOSTICS: break
            parts = [str(x)[:80] for x in list(error.absolute_path)[:10]]
            messages.append({
                'keyword': str(error.validator or 'schema')[:48],
                'instance_path': '/' + '/'.join(parts),
                'schema_path': '/' + '/'.join(str(x)[:60] for x in list(error.absolute_schema_path)[:10]),
            })
    except Exception as exc:
        raise ReviewError('SCHEMA_EVALUATION_UNAVAILABLE', 5) from exc
    return messages


def _base(mode: str, domain: str | None = None) -> dict[str, Any]:
    return {
        'schema': SCHEMA, 'version': VERSION, 'build': BUILD,
        'mode': mode, 'domain': domain, 'status': 'unavailable',
        'reason_code': 'NOT_EVALUATED', 'exit_code': 5,
        'disposition': 'UNKNOWN', 'source_contract': None,
        'source_schema_marker': None, 'observed_content_sha256': None,
        'structural_validation': False, 'schema_pin_checked': False,
        'source_authority_verified': False, 'business_authorization_verified': False,
        'identity_or_record_authentication_verified': False,
        'original_bytes_rewritten': False, 'migration_executed': False,
        'external_network_used': False, 'data': None,
        'limitations': TRUST,
    }


def _out(out: dict[str, Any], *, status: str, reason: str, code: int,
         disposition: str, data: Any = None) -> dict[str, Any]:
    out.update(status=status, reason_code=reason, exit_code=code,
               disposition=disposition, data=data)
    return out


def _codeinsight(raw: bytes, path: str, kind: str, expected_id: str | None,
                 registry: dict[str, Any], out: dict[str, Any]) -> dict[str, Any]:
    legacy = registry['legacy_codeinsight']
    for path_field, sha_field in (('policy_path', 'policy_sha256'),
                                   ('reader_path', 'reader_sha256')):
        rel = legacy[path_field]
        require(rel in ('references/schema-compatibility.v1.json',
                        'construction/schema_compat.py') and
                sha(read_regular(ROOT / rel, MAX_INPUT_BYTES)) == legacy[sha_field],
                'LEGACY_READER_OR_POLICY_PIN_DRIFT', 5)
    # The governing original EC158 reader is used, not a reimplementation.
    construction = str(ROOT / 'construction')
    if construction not in sys.path: sys.path.insert(0, construction)
    try:
        import schema_compat as legacy_reader
        report = legacy_reader.inspect_bytes(raw, kind=kind, path=path,
                                             record_id=expected_id)
    except Exception as exc:
        raise ReviewError('LEGACY_CODEINSIGHT_INPUT_OR_READER_ERROR', 4) from exc
    out['schema_pin_checked'] = True
    out['source_schema_marker'] = report.get('schema_version')
    out['source_contract'] = report.get('family')
    valid = report.get('compatible_for_offline_read') is True
    out['structural_validation'] = valid
    safe = {
        'legacy_disposition': report.get('disposition'),
        'legacy_identity': report.get('identity'),
        'legacy_issue_codes': [x.get('code') for x in report.get('issues', [])][:MAX_DIAGNOSTICS],
        'legacy_notes': report.get('advisories', [])[:MAX_DIAGNOSTICS],
        'record_origin_and_native_codeshow_not_verified': True,
    }
    # The old reader emits no source content in these metadata-only fields,
    # but record/identity structures may evolve: keep only scalar identifiers.
    ident = safe.pop('legacy_identity')
    if type(ident) is dict:
        safe['legacy_identity'] = {k: v for k, v in ident.items()
                                   if k in ('record_id_from_exact_bytes', 'filename_sha256_matches_content',
                                            'record_id_matches_content', 'content_sha256', 'record_id')
                                   and type(v) in (str, bool, type(None))}
    else:
        safe['legacy_identity'] = None
    return _out(out, status='readable' if valid else 'rejected',
                reason='CODEINSIGHT_LEGACY_READ_SHAPE_ONLY' if valid else 'CODEINSIGHT_LEGACY_REJECTED',
                code=0 if valid else 2,
                disposition='READ_SAME_VERSION_AS_ORIGINAL_BYTES' if valid else 'REJECT_INVALID_OR_FUTURE_LEGACY',
                data=safe)


def _choose(domain: str, obj: dict[str, Any], preferred: str | None,
            registry: dict[str, Any]) -> dict[str, Any]:
    entries = [e for e in registry['contracts'] if e['domain'] == domain]
    if preferred is not None:
        eligible = [e for e in entries if e['contract'] == preferred]
        require(len(eligible) == 1, 'UNREGISTERED_CONTRACT_OR_WRONG_DOMAIN')
        return eligible[0]
    observed = [(k, obj[k]) for k in ('schema', 'schema_version')
                if k in obj and type(obj[k]) is str]
    require(len(observed) == 1, 'UNVERSIONED_OR_AMBIGUOUS_ROOT_MARKER')
    candidates = [e for e in entries if any(
        (x['field'], x['value']) == observed[0] for x in e['markers'])]
    require(candidates, 'FUTURE_OR_UNREGISTERED_ROOT_VERSION')
    require(len(candidates) == 1, 'AMBIGUOUS_ROOT_VERSION_REQUIRES_EXPLICIT_CONTRACT')
    return candidates[0]


def inspect(raw: bytes, *, domain: str, registry: dict[str, Any], path: str = '-',
            contract: str | None = None, expect_sha256: str | None = None,
            record_id: str | None = None) -> dict[str, Any]:
    out = _base('inspect', domain)
    out['observed_content_sha256'] = sha(raw)
    if expect_sha256 is not None:
        require(type(expect_sha256) is str and SHA256_RE.fullmatch(expect_sha256),
                'EXPECTED_SHA256_FORMAT_INVALID')
        if expect_sha256 != out['observed_content_sha256']:
            return _out(out, status='rejected', reason='INPUT_RAW_BYTES_CHANGED',
                        code=3, disposition='REJECT_SOURCE_SHA_DRIFT')
    require(len(raw) <= MAX_INPUT_BYTES, 'RECORD_MAXIMUM_BYTES_EXCEEDED')
    if domain == 'CodeInsight':
        require(contract is None or contract in registry['legacy_codeinsight']['kinds'],
                'CODEINSIGHT_KIND_UNREGISTERED')
        return _codeinsight(raw, path, contract or 'auto', record_id, registry, out)
    require(record_id is None, 'RECORD_ID_ONLY_FOR_CODEINSIGHT_SAVED')
    obj = strict_decode(raw)
    entry = _choose(domain, obj, contract, registry)
    out['source_contract'] = entry['contract']
    observed = [(x['field'], x['value']) for x in entry['markers']]
    if observed:
        require(len(observed) == 1, 'CONTRACT_MULTI_VERSION_MARKER_AMBIGUITY', 5)
        field, value = observed[0]
        out['source_schema_marker'] = value
        if obj.get(field) != value:
            return _out(out, status='rejected', reason='WRONG_CONTRACT_VERSION_OR_FAMILY',
                        code=3, disposition='REJECT_NO_VERSION_DOWNGRADE')
    else:
        # Some historical Issue request/grant records are unversioned.
        # Only an explicitly selected *pinned* contract may inspect the shape;
        # this does not authorize versioned migration or proof of origin.
        require(contract is not None, 'UNVERSIONED_CONTRACT_REQUIRES_EXPLICIT_SELECTION')
        if 'schema' in obj or 'schema_version' in obj:
            return _out(out, status='rejected', reason='UNEXPECTED_VERSION_FIELD_IN_UNVERSIONED_CONTRACT',
                        code=3, disposition='REJECT_CONTRACT_CONFUSION')
    source = local_contract(entry)
    validator = _validator(source)
    out['schema_pin_checked'] = True
    issues = _diag(validator, obj)
    if issues:
        return _out(out, status='rejected', reason='JSON_SCHEMA_INSTANCE_REJECTED',
                    code=3, disposition='REJECT_INVALID_KNOWN_CONTRACT',
                    data={'diagnostics': issues, 'values_disclosed': False})
    out['structural_validation'] = True
    if not observed:
        return _out(out, status='review_required', reason='HISTORICAL_UNVERSIONED_SHAPE_ONLY',
                    code=2, disposition='EXPLICIT_CONTRACT_SHAPE_ONLY_NO_VERSION_MIGRATION',
                    data={'historical_unversioned_contract': True})
    return _out(out, status='readable', reason='KNOWN_VERSION_PINNED_SCHEMA_SHAPE',
                code=0, disposition='READ_SAME_VERSION_AS_ORIGINAL_BYTES',
                data={'historical_unversioned_contract': False})


def plan(source: dict[str, Any], *, target: str | None, registry: dict[str, Any]) -> dict[str, Any]:
    out = {**source, 'mode': 'plan', 'migration_executed': False,
           'original_bytes_rewritten': False}
    origin = source.get('source_contract')
    domain = source['domain']
    if target is None:
        return _out(out, status='rejected', reason='TARGET_CONTRACT_REQUIRED',
                    code=4, disposition='NO_MIGRATION_WITHOUT_TARGET')
    if domain == 'CodeInsight':
        eligible = set(registry['legacy_codeinsight']['kinds'])
        target_valid = target in eligible
    else:
        target_valid = any(e['domain'] == domain and e['contract'] == target
                           for e in registry['contracts'])
    if not target_valid:
        return _out(out, status='rejected', reason='UNKNOWN_OR_CROSS_DOMAIN_TARGET',
                    code=3, disposition='REJECT_TARGET_UNKNOWN_OR_DIFFERENT_DOMAIN')
    if source['status'] == 'readable' and source['structural_validation'] and origin == target:
        return _out(out, status='readable', reason='NOOP_ORIGINAL_BYTES_ALREADY_READABLE',
                    code=0, disposition='NOOP_KEEP_EXACT_ORIGINAL_BYTES',
                    data={'write_permitted': False, 'new_record_needed': False,
                          'preserve_original_sha256': source['observed_content_sha256']})
    if source['status'] != 'readable':
        return _out(out, status='rejected', reason='SOURCE_NOT_ADMITTED_FOR_MIGRATION',
                    code=3, disposition='QUARANTINE_NO_TRANSFORM',
                    data={'raw_bytes_must_be_preserved': True, 'migration_available': False})
    # No generic transcode exists: a new version must be independently
    # produced, re-identified, and reviewed by the original owner/producer.
    # Even Finding v1->v2 has HMAC/hash-chain identities, so copying keys or
    # retagging the record would be a dangerous false migration.
    special = domain == 'Finding' and origin == 'finding-save-batch.v1' and target == 'finding-save-batch.v2'
    return _out(out, status='review_required',
                reason='FINDING_V1_V2_REISSUE_REQUIRED' if special else 'NO_REVIEWED_CROSS_CONTRACT_MIGRATOR',
                code=2, disposition='BLOCKED_NEW_IMMUTABLE_RECORD_REQUIRED',
                data={
                    'migration_available': False,
                    'raw_bytes_must_be_preserved': True,
                    'write_permitted': False,
                    'requires': ['independent producer reissue under target contract',
                                 'exact input SHA and original immutable record retention',
                                 'new record identity and independent permission/review',
                                 'revalidation of source, actor, MAC/signature and dependency pins',
                                 'separate reviewed rollback/selection procedure'],
                    'historical_schema_id_collision': special,
                    'old_contract': origin, 'target_contract': target,
                })


def inventory(registry: dict[str, Any]) -> dict[str, Any]:
    out = _base('inventory')
    summary = Counter(e['domain'] for e in registry['contracts'])
    summary['CodeInsight'] = len(registry['legacy_codeinsight']['kinds'])
    data = {
        'domain_counts': {x: summary[x] for x in DOMAINS},
        'registered_json_schema_contracts': len(registry['contracts']),
        'codeinsight_original_reader_kinds': registry['legacy_codeinsight']['kinds'],
        'contracts': [
            {'domain': e['domain'], 'contract': e['contract'], 'sha256': e['sha256'],
             'root_markers': e['markers'], 'has_declared_id': e['declared_id'] is not None}
            for e in registry['contracts']
        ],
        'contract_selectors_do_not_prove_source_provenance': True,
    }
    return _out(out, status='inventory_only', reason='REGISTERED_CONTRACTS_NOT_READ_ACCEPTANCE',
                code=0, disposition='CATALOG_INFORMATION_ONLY', data=data)


def audit(registry: dict[str, Any]) -> dict[str, Any]:
    out = _base('audit')
    colliding = defaultdict(list)
    no_id: list[str] = []
    no_marker: list[str] = []
    drift: list[dict[str, str]] = []
    for entry in registry['contracts']:
        try:
            d = local_contract(entry)
            _validator(d)
            if entry['declared_id'] is None:
                no_id.append(entry['contract'])
            else:
                colliding[entry['declared_id']].append(entry['contract'])
            if not entry['markers']:
                no_marker.append(entry['contract'])
        except ReviewError as exc:
            drift.append({'contract': entry['contract'], 'reason_code': exc.code})
    extras = sorted(p.name for p in (ROOT / 'references').glob('*.schema.json')
                    if 'references/' + p.name not in {e['path'] for e in registry['contracts']})
    collisions = [{'declared_id': k, 'contracts': sorted(names)}
                  for k, names in sorted(colliding.items()) if len(names) > 1]
    data = {
        'domains': {name: sum(e['domain'] == name for e in registry['contracts'])
                    for name in DOMAINS[1:]},
        'pinned_contract_count': len(registry['contracts']),
        'drift_or_unusable': drift[:MAX_DIAGNOSTICS],
        'drift_count': len(drift),
        'missing_declared_schema_id': no_id,
        'no_version_marker_requires_explicit_contract': no_marker,
        'colliding_declared_schema_ids': collisions,
        'unregistered_schema_files': extras,
        'remote_ref_resolution_attempted': False,
        'finding_v1_v2_same_id_must_not_be_used_for_automatic_resolution': True,
    }
    if drift or extras:
        return _out(out, status='unavailable', reason='SCHEMA_DRIFT_OR_UNREGISTERED_FILE',
                    code=5, disposition='STOP_UNREVIEWED_SCHEMA_CORPUS', data=data)
    return _out(out, status='review_required' if (no_id or no_marker or collisions) else 'audited',
                reason='KNOWN_LEGACY_SCHEMA_DEBT' if (no_id or no_marker or collisions) else 'CATALOG_PINNED',
                code=2 if (no_id or no_marker or collisions) else 0,
                disposition='REVIEW_KNOWN_LEGACY_SCHEMA_ANOMALIES' if (no_id or no_marker or collisions)
                            else 'CATALOG_OBSERVED_NO_BUSINESS_PROOF', data=data)


def _serialize(out: dict[str, Any]) -> bytes:
    raw = json.dumps(out, ensure_ascii=True, separators=(',', ':'),
                     sort_keys=True, allow_nan=False).encode('ascii')
    require(len(raw) <= MAX_OUTPUT_BYTES, 'INSPECTOR_OUTPUT_LIMIT', 5)
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('inventory', help='Show reviewed pinned local catalog (never input data).')
    sub.add_parser('audit', help='Inspect whole schema catalog, report legacy debt; no writes.')
    for name in ('inspect', 'plan'):
        p = sub.add_parser(name, help='Read one exact bounded local JSON record.')
        p.add_argument('--input', required=True, help='Local file path or - for bounded stdin.')
        p.add_argument('--domain', required=True, choices=DOMAINS)
        p.add_argument('--contract', help='Pinned contract name, or legacy CodeInsight kind.')
        p.add_argument('--expect-sha256', help='Expected original raw SHA-256 (exact bytes).')
        p.add_argument('--record-id', help='Legacy CodeInsight saved ci-<SHA256> only.')
        if name == 'plan': p.add_argument('--target-contract', required=True)
    try:
        args = parser.parse_args(argv)
        registry = catalog()
        if args.command == 'inventory':
            out = inventory(registry)
        elif args.command == 'audit':
            out = audit(registry)
        else:
            raw = read_regular(args.input, MAX_INPUT_BYTES, input_stdin=True)
            out = inspect(raw, domain=args.domain, registry=registry,
                          path=args.input, contract=args.contract,
                          expect_sha256=args.expect_sha256, record_id=args.record_id)
            if args.command == 'plan': out = plan(out, target=args.target_contract,
                                                  registry=registry)
    except ReviewError as exc:
        out = _out(_base(argv[0] if argv else 'unknown'), status='unavailable' if exc.exit_code == 5 else 'rejected',
                   reason=exc.code, code=exc.exit_code, disposition='FAIL_CLOSED_NO_ARTIFACTS_CHANGED')
    except Exception:
        out = _out(_base(argv[0] if argv else 'unknown'), status='unavailable',
                   reason='UNEXPECTED_OFFLINE_READER_ERROR', code=5,
                   disposition='FAIL_CLOSED_NO_ARTIFACTS_CHANGED')
    try:
        sys.stdout.buffer.write(_serialize(out) + b'\n')
    except ReviewError:
        return 5
    return out['exit_code']


if __name__ == '__main__':
    sys.exit(main())
