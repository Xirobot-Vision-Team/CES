#!/usr/bin/env python3
"""EC186 QualityRun safety configuration gate -- plans only, never launches.

Trust anchors are two *host-owned, separate* HMAC verification keys. A project,
EC181 profile hint, EC185 observation, signature copied from another source,
or a boolean "sandboxed" flag grants no authority. Approval and broker lease
must bind the same exact WorkingTree observation and immutable built-in profile.
The host must enforce key custody, broker provenance, isolation and lease
reservation; this library cannot prove that a kernel sandbox actually exists.
EC187 must independently reauthorize, revalidate and atomically consume a lease
before any execution. No shell, subprocess, import of project code, network,
write or arbitrary argument is performed by this module.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
from typing import Any, Callable

import quality_detect as detect
import quality_observation as observation_module

SCHEMA = 'ces.quality_run_guard.v1'
APPROVAL_SCHEMA = 'ces.qualityrun.profile_approval.v1'
LEASE_SCHEMA = 'ces.qualityrun.isolation_lease.v1'
DOMAIN_PROFILE = b'CES-EC186-STATIC-PROFILE-v1\x00'
DOMAIN_CATALOG = b'CES-EC186-STATIC-CATALOG-v1\x00'
DOMAIN_APPROVAL = b'CES-EC186-PROFILE-APPROVAL-v1\x00'
DOMAIN_LEASE = b'CES-EC186-ISOLATION-LEASE-v1\x00'
DOMAIN_RECEIPT = b'CES-EC186-RECEIPT-BINDING-v1\x00'
DOMAIN_PLAN = b'CES-EC186-QUALITY-RUN-PLAN-v1\x00'
REASON = 'QUALITYRUNGUARD_'
EXIT = {'partial': 2, 'invalid_input': 4, 'unavailable': 5}
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{11,63}\Z', re.ASCII)
MAX_TICKET_BYTES = 8 * 1024
MAX_OBSERVATION_BYTES = 192 * 1024
MAX_RESULT_BYTES = 32 * 1024
MAX_APPROVAL_AGE = 300
MAX_APPROVAL_LIFETIME = 600
MAX_LEASE_AGE = 60
MAX_LEASE_LIFETIME = 120
CLOCK_SKEW = 30

# These are code-owned recipes, NOT caller arguments and NOT commands executed
# here. EC187 must resolve the image-owned runtime, never PATH/project binaries.
# Both may execute untrusted repository material and REQUIRE actual isolation.
BUILTIN_PROFILES: dict[str, dict[str, Any]] = {
    'python.pytest': {
        'profile_id': 'python.pytest', 'revision': 1,
        'runtime': 'TRUSTED_PINNED_PYTHON_IMAGE',
        'entrypoint_kind': 'PYTHON_MODULE', 'module': 'pytest',
        'fixed_arguments': ['-q', '-p', 'no:cacheprovider'],
        'purpose': 'TEST', 'project_code_may_execute': True,
        'allow_user_arguments': False, 'allow_project_entrypoint': False,
        'allow_shell': False,
    },
    'python.ruff': {
        'profile_id': 'python.ruff', 'revision': 1,
        'runtime': 'TRUSTED_PINNED_PYTHON_IMAGE',
        'entrypoint_kind': 'PYTHON_MODULE', 'module': 'ruff',
        'fixed_arguments': ['check', '.', '--no-cache'],
        'purpose': 'LINT', 'project_code_may_execute': False,
        'allow_user_arguments': False, 'allow_project_entrypoint': False,
        'allow_shell': False,
    },
}

# Exact attested broker contract. A checked HMAC is only a checked statement
# *from the configured host trust domain*: no kernel/container probe runs here.
REQUIRED_CONTROLS: dict[str, Any] = {
    'lease_state': 'RESERVED_NOT_STARTED',
    'source_mount': 'READ_ONLY',
    'scratch_mount': 'PRIVATE_EPHEMERAL',
    'network_access': 'DENIED',
    'executor': 'PINNED_IMAGE_FIXED_PROFILE_ONLY',
    'non_root_user': True,
    'user_namespace_isolated': True,
    'mount_namespace_isolated': True,
    'pid_namespace_isolated': True,
    'no_new_privileges': True,
    'capabilities_dropped': True,
    'seccomp_enforced': True,
    'cgroup_bounds_present': True,
    'host_secrets_mounted': False,
    'host_home_mounted': False,
    'host_sockets_mounted': False,
    'host_docker_socket_mounted': False,
    'host_network_shared': False,
    'host_pid_shared': False,
    'unapproved_bind_mounts': False,
}


class GateError(ValueError):
    def __init__(self, code: str, status: str = 'unavailable') -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def _require(valid: Any, code: str, status: str = 'invalid_input') -> None:
    if valid is not True:
        raise GateError(code, status)


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _digest(domain: bytes, obj: Any) -> str:
    return hashlib.sha256(domain + _canonical(obj)).hexdigest()


def _stamp(dt: datetime) -> str:
    return dt.isoformat(timespec='seconds').replace('+00:00', 'Z')


def _now(clock: Callable[[], datetime] | None) -> datetime:
    try:
        current = clock() if clock is not None else datetime.now(timezone.utc)
        _require(type(current) is datetime and current.tzinfo is not None and
                 current.utcoffset() is not None, 'CLOCK_INVALID', 'unavailable')
        current = current.astimezone(timezone.utc).replace(microsecond=0)
        _require(2000 <= current.year <= 9998, 'CLOCK_INVALID', 'unavailable')
        return current
    except GateError:
        raise
    except Exception:
        raise GateError('CLOCK_UNAVAILABLE') from None


def _time(value: Any) -> datetime:
    _require(type(value) is str and re.fullmatch(
        r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value) is not None,
        'TICKET_TIMESTAMP_INVALID')
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        raise GateError('TICKET_TIMESTAMP_INVALID', 'invalid_input') from None


def _fresh_ticket(ticket: dict[str, Any], now: datetime, *,
                  max_age: int, max_lifetime: int) -> None:
    issued = _time(ticket['issued_at_utc'])
    expiry = _time(ticket['expires_at_utc'])
    _require(-CLOCK_SKEW <= (now - issued).total_seconds() <= max_age and
             issued < expiry and (expiry - issued).total_seconds() <= max_lifetime and
             now < expiry, 'TICKET_EXPIRED_OR_NOT_YET_VALID', 'unavailable')


def _fresh_source_pin(source_pin: Any, repo_root: Any, now: datetime) -> dict[str, Any]:
    _require(type(repo_root) is str, 'WORKINGTREE_ROOT_INVALID')
    detect._root_parts(repo_root)  # strictly POSIX absolute, normalized, no dot traversals
    _require(type(source_pin) is dict and set(source_pin) == {
        'schema', 'source_mode', 'repo_root', 'root_identity', 'observed_at_utc'
    } and source_pin['schema'] == detect.PIN_SCHEMA and
        source_pin['source_mode'] == 'WorkingTree' and
        source_pin['repo_root'] == repo_root, 'SOURCE_PIN_EXACT_SCOPE_REQUIRED')
    identity = source_pin['root_identity']
    _require(type(identity) is dict and set(identity) == {
        'device', 'inode', 'mtime_ns', 'ctime_ns'} and
        all(type(v) is int and 0 <= v <= (2**64-1) for v in identity.values()),
        'SOURCE_PIN_IDENTITY_INVALID')
    observed = _time(source_pin['observed_at_utc'])
    _require(-CLOCK_SKEW <= (now - observed).total_seconds() <= detect.MAX_PIN_AGE,
             'SOURCE_PIN_STALE', 'unavailable')
    _require(len(_canonical(source_pin)) <= 4096, 'SOURCE_PIN_OVERSIZED')
    return source_pin


def catalog_entry(profile_id: str) -> dict[str, Any] | None:
    """Return an informational copy of an immutable code-owned recipe.

    It is not an approval, executable argv, installer hint or trusted-runner proof.
    """
    spec = BUILTIN_PROFILES.get(profile_id) if type(profile_id) is str else None
    if spec is None:
        return None
    return {'profile': json.loads(_canonical(spec)),
            'profile_sha256': _digest(DOMAIN_PROFILE, spec),
            'catalog_sha256': _digest(DOMAIN_CATALOG, BUILTIN_PROFILES)}


def _safe_copy(obj: Any, code: str, limit: int) -> dict[str, Any]:
    _require(type(obj) is dict, code)
    try:
        encoded = _canonical(obj)
        _require(len(encoded) <= limit, code)
        copy = json.loads(encoded.decode('ascii'))
        _require(type(copy) is dict, code)
        return copy
    except GateError:
        raise
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        raise GateError(code, 'invalid_input') from None


def _verify_ticket(raw: Any, *, schema: str, fields: set[str], key: bytes,
                   domain: bytes, now: datetime, max_age: int,
                   max_lifetime: int) -> dict[str, Any]:
    obj = _safe_copy(raw, 'TICKET_STRUCTURE_INVALID', MAX_TICKET_BYTES)
    _require(set(obj) == fields | {'mac_sha256'} and obj.get('schema') == schema,
             'TICKET_STRUCTURE_INVALID')
    _require(type(obj['mac_sha256']) is str and HEX.fullmatch(obj['mac_sha256']) is not None,
             'TICKET_MAC_FORMAT_INVALID')
    _require(type(obj.get('ticket_id')) is str and
             IDENTIFIER.fullmatch(obj['ticket_id']) is not None,
             'TICKET_ID_INVALID')
    _fresh_ticket(obj, now, max_age=max_age, max_lifetime=max_lifetime)
    unsigned = {name: value for name, value in obj.items() if name != 'mac_sha256'}
    expected = hmac.new(key, domain + _canonical(unsigned), hashlib.sha256).hexdigest()
    _require(hmac.compare_digest(obj['mac_sha256'], expected),
             'TICKET_NOT_AUTHENTICATED_BY_HOST_KEY', 'unavailable')
    return obj


def _host_grant(authorize: Callable[[dict[str, Any]], bool] | None, *,
                stage: str, scope: dict[str, Any], effects: dict[str, Any]) -> None:
    _require(callable(authorize), 'HOST_AUTHORIZER_REQUIRED', 'unavailable')
    effects['authorization_calls'] += 1
    try:
        allowed = authorize({'operation': 'QUALITYRUN_CONFIGURE', 'stage': stage,
                             'schema': SCHEMA, **scope})
    except Exception:
        raise GateError('HOST_AUTHORIZATION_UNAVAILABLE') from None
    _require(allowed is True, 'HOST_AUTHORIZATION_DENIED', 'unavailable')


def _checked_root(repo_root: str, source_pin: dict[str, Any],
                  authorize_root: Callable[[dict[str, Any]], bool] | None,
                  clock: Callable[[], datetime] | None,
                  effects: dict[str, Any]) -> None:
    _require(callable(authorize_root), 'ROOT_AUTHORIZER_REQUIRED', 'unavailable')
    effects['root_observations'] += 1
    seen = detect.QualityDetector.observe_root(
        repo_root, authorize_observation=authorize_root, clock=clock)
    _require(seen['root_identity'] == source_pin['root_identity'],
             'WORKINGTREE_IDENTITY_DRIFT', 'unavailable')
    # An observed directory does not prove the Git SHA, its children's bytes,
    # its mount is read-only, or that EC187 will see this exact content.


def _context_view(receipt: Any, pin_digest: str, profile_id: str,
                  now: datetime) -> dict[str, Any]:
    if receipt is None:
        return {'ec185_supplied': False, 'profile_hint_present': None,
                'observation_digest_checked_not_authenticating': False}
    d = _safe_copy(receipt, 'EC185_OBSERVATION_INVALID', MAX_OBSERVATION_BYTES)
    _require(d.get('schema') == observation_module.SCHEMA and
             d.get('status') == 'partial' and d.get('exit_code') == 2 and
             type(d.get('observation_sha256')) is str and
             HEX.fullmatch(d['observation_sha256']) is not None and
             type(d.get('source')) is dict and type(d.get('observations')) is dict,
             'EC185_OBSERVATION_INVALID')
    try:
        payload = {name: d[name] for name in (
            'observed_at_utc', 'source', 'observations', 'evidence_refs',
            'execution_environment', 'grants', 'proof')}
        _require(observation_module._hash(payload) == d['observation_sha256'],
                 'EC185_OBSERVATION_HASH_CHANGED', 'unavailable')
        local = d['source']['local']
        cfg = d['observations']['local_config']
        _require(type(local) is dict and type(cfg) is dict and
                 local.get('source_mode') == 'WorkingTree' and
                 local.get('pin_digest') == pin_digest and
                 cfg.get('pin_digest') == pin_digest and
                 type(cfg.get('profile_hints')) is list and
                 len(cfg['profile_hints']) <= 32 and
                 not d['source'].get('same_revision_proven', True),
                 'EC185_SOURCE_NOT_THIS_WORKINGTREE', 'unavailable')
        observed = _time(d['observed_at_utc'])
        _require(-CLOCK_SKEW <= (now - observed).total_seconds() <= MAX_APPROVAL_AGE,
                 'EC185_OBSERVATION_STALE', 'unavailable')
        hints = cfg['profile_hints']
        match = any(type(h) is dict and h.get('profile_id') == profile_id for h in hints)
    except GateError:
        raise
    except (TypeError, ValueError, KeyError, AttributeError):
        raise GateError('EC185_OBSERVATION_INVALID', 'invalid_input') from None
    return {'ec185_supplied': True, 'profile_hint_present': match,
            'observation_digest_checked_not_authenticating': True}


def _effects() -> dict[str, Any]:
    return {'root_observations': 0, 'authorization_calls': 0,
            'commands_executed': False, 'tests_executed': False,
            'network_access': False, 'writes_performed': False,
            'lease_consumed': False}


def _denied(reason: str, status: str, effects: dict[str, Any]) -> dict[str, Any]:
    return {'schema': SCHEMA, 'status': status, 'exit_code': EXIT[status],
            'reason_code': REASON + reason, 'prepared_at_utc': None,
            'profile': None, 'source': None, 'authorization': None,
            'isolation': None, 'context': None, 'plan': None,
            'proof': None, 'plan_sha256': None, 'effects': effects,
            'trust_boundary': 'FAIL_CLOSED_NO_PLAN_NO_EXECUTION'}


class QualityRunSafetyGate:
    """A local, strict pre-execution authorization gate (not a runner).

    The host, *not a repository*, provisions unrelated policy and broker keys.
    HMAC verifies a short-lived scoped authorization statement; the HMAC does
    not verify kernel enforcement of sandbox controls, issuer personhood or
    the contents of a future checkout. EC187 must re-check and consume.
    """

    def __init__(self, *, policy_verification_key: bytes,
                 broker_verification_key: bytes,
                 clock: Callable[[], datetime] | None = None) -> None:
        if not (type(policy_verification_key) is bytes and
                type(broker_verification_key) is bytes and
                32 <= len(policy_verification_key) <= 4096 and
                32 <= len(broker_verification_key) <= 4096 and
                not hmac.compare_digest(policy_verification_key,
                                        broker_verification_key)):
            raise ValueError('Two distinct host-controlled verification keys are required')
        if clock is not None and not callable(clock):
            raise ValueError('Invalid trusted clock callback')
        self._policy_key = policy_verification_key
        self._broker_key = broker_verification_key
        self.clock = clock

    def prepare(self, *, repo_root: str, source_pin: dict[str, Any],
                profile_id: str, policy_ticket: dict[str, Any],
                isolation_ticket: dict[str, Any],
                allow_prepare: bool = False,
                allow_profile_approval: bool = False,
                allow_isolation_lease: bool = False,
                authorize_root: Callable[[dict[str, Any]], bool] | None = None,
                authorize_gate: Callable[[dict[str, Any]], bool] | None = None,
                ec185_observation: dict[str, Any] | None = None) -> dict[str, Any]:
        effects = _effects()
        try:
            _require(type(allow_prepare) is bool and allow_prepare and
                     type(allow_profile_approval) is bool and allow_profile_approval and
                     type(allow_isolation_lease) is bool and allow_isolation_lease,
                     'SEPARATE_OPTINS_REQUIRED', 'unavailable')
            _require(type(profile_id) is str and profile_id in BUILTIN_PROFILES,
                     'PROFILE_NOT_IN_BUILTIN_CATALOG')
            now = _now(self.clock)
            pin = _safe_copy(source_pin, 'SOURCE_PIN_INVALID', 4096)
            _fresh_source_pin(pin, repo_root, now)
            pin_digest = detect._sha(detect.DOMAIN_PIN, pin)
            profile = catalog_entry(profile_id)
            _require(profile is not None, 'PROFILE_NOT_IN_BUILTIN_CATALOG')
            profile_digest = profile['profile_sha256']
            selection = {'source_mode': 'WorkingTree', 'repo_root': repo_root,
                         'source_pin_sha256': pin_digest,
                         'profile_id': profile_id,
                         'profile_sha256': profile_digest}
            _host_grant(authorize_gate, stage='BEFORE_PROFILE',
                        scope=selection, effects=effects)
            _checked_root(repo_root, pin, authorize_root, self.clock, effects)
            approval = _verify_ticket(policy_ticket, schema=APPROVAL_SCHEMA,
                fields={'schema', 'ticket_id', 'profile_id', 'profile_sha256',
                        'source_pin_sha256', 'issued_at_utc', 'expires_at_utc',
                        'approved_purpose'},
                key=self._policy_key, domain=DOMAIN_APPROVAL, now=_now(self.clock),
                max_age=MAX_APPROVAL_AGE, max_lifetime=MAX_APPROVAL_LIFETIME)
            _require(approval['profile_id'] == profile_id and
                     approval['profile_sha256'] == profile_digest and
                     approval['source_pin_sha256'] == pin_digest and
                     approval['approved_purpose'] == profile['profile']['purpose'],
                     'PROFILE_NOT_EXPLICITLY_APPROVED', 'unavailable')
            approve_receipt_sha = _digest(DOMAIN_RECEIPT, approval)
            _host_grant(authorize_gate, stage='APPROVED_PROFILE',
                        scope={**selection, 'approval_ticket_id': approval['ticket_id']},
                        effects=effects)
            lease = _verify_ticket(isolation_ticket, schema=LEASE_SCHEMA,
                fields={'schema', 'ticket_id', 'source_pin_sha256',
                        'profile_sha256', 'approval_receipt_sha256',
                        'image_sha256', 'controls', 'issued_at_utc',
                        'expires_at_utc'},
                key=self._broker_key, domain=DOMAIN_LEASE, now=_now(self.clock),
                max_age=MAX_LEASE_AGE, max_lifetime=MAX_LEASE_LIFETIME)
            _require(lease['source_pin_sha256'] == pin_digest and
                     lease['profile_sha256'] == profile_digest and
                     lease['approval_receipt_sha256'] == approve_receipt_sha and
                     type(lease['image_sha256']) is str and
                     HEX.fullmatch(lease['image_sha256']) is not None,
                     'LEASE_NOT_BOUND_TO_APPROVED_SOURCE_PROFILE', 'unavailable')
            _require(type(lease['controls']) is dict and
                     set(lease['controls']) == set(REQUIRED_CONTROLS) and
                     all(type(lease['controls'][k]) is type(expected) and
                         lease['controls'][k] == expected
                         for k, expected in REQUIRED_CONTROLS.items()),
                     'ISOLATION_REQUIREMENTS_NOT_ATTESTED', 'unavailable')
            _require(_time(lease['expires_at_utc']) <=
                     _time(approval['expires_at_utc']),
                     'LEASE_OUTLASTS_PROFILE_APPROVAL', 'unavailable')
            _host_grant(authorize_gate, stage='ISOLATION_RESERVED',
                        scope={**selection, 'approval_ticket_id': approval['ticket_id'],
                               'lease_ticket_id': lease['ticket_id']},
                        effects=effects)
            context = _context_view(ec185_observation, pin_digest, profile_id,
                                    _now(self.clock))
            # Recheck after the final host authorization, because the host
            # callback itself may mutate the source or consume time. Neither
            # the callback nor this probe seals all file content for EC187.
            _host_grant(authorize_gate, stage='FINALIZE',
                        scope={**selection, 'approval_ticket_id': approval['ticket_id'],
                               'lease_ticket_id': lease['ticket_id']},
                        effects=effects)
            _checked_root(repo_root, pin, authorize_root, self.clock, effects)
            finalized = _now(self.clock)
            _fresh_source_pin(pin, repo_root, finalized)
            _fresh_ticket(approval, finalized, max_age=MAX_APPROVAL_AGE,
                          max_lifetime=MAX_APPROVAL_LIFETIME)
            _fresh_ticket(lease, finalized, max_age=MAX_LEASE_AGE,
                          max_lifetime=MAX_LEASE_LIFETIME)
            # The authorization callback may revoke at finalization. No plan
            # leaves this function before that point. No executable argv is
            # returned: the next EC must bind a trusted runtime and seal it.
            output_profile = {'id': profile_id,
                              'catalog_sha256': profile['catalog_sha256'],
                              'spec_sha256': profile_digest,
                              'kind': profile['profile']['purpose'],
                              'recipe_code_owned': True,
                              'caller_supplied_arguments_allowed': False,
                              'project_material_untrusted': True}
            source = {'mode': 'WorkingTree', 'root_path_redacted': True,
                      'source_pin_sha256': pin_digest,
                      'root_identity_rechecked': True,
                      'git_object_bytes_verified': False,
                      'source_contents_sealed': False}
            authorization = {'policy_ticket_id': approval['ticket_id'],
                             'policy_mac_verified': True,
                             'broker_lease_id': lease['ticket_id'],
                             'broker_mac_verified': True,
                             'separate_host_keys_required': True,
                             'host_grants_checked_at_finalization': True,
                             'host_key_custody_externally_assumed': True}
            isolation = {'lease_ticket_sha256': _digest(DOMAIN_RECEIPT, lease),
                         'pinned_image_sha256': lease['image_sha256'],
                         'lease_expires_at_utc': lease['expires_at_utc'],
                         'required_controls': json.loads(_canonical(REQUIRED_CONTROLS)),
                         'broker_controls_mac_verified': True,
                         'actual_kernel_isolation_probed_by_ces': False,
                         'lease_consumed': False,
                         'lease_state': 'RESERVED_NOT_STARTED'}
            plan = {'state': 'PREPARED_ONLY_NOT_EXECUTABLE',
                    'profile_id': profile_id, 'source_pin_sha256': pin_digest,
                    'profile_sha256': profile_digest,
                    'approval_receipt_sha256': approve_receipt_sha,
                    'lease_receipt_sha256': isolation['lease_ticket_sha256'],
                    'requires_ec187_fresh_reauthorization': True,
                    'requires_atomic_lease_consumption_before_run': True,
                    'has_executable_command': False}
            proof = {'profile_built_in': True,
                     'approved_profile_mac_verified': True,
                     'isolation_broker_lease_mac_verified': True,
                     'host_policy_grants_complete': True,
                     'trusted_future_runner_instantiated': False,
                     'actual_isolation_verified_by_ces': False,
                     'source_git_bytes_verified': False,
                     'test_execution_verified': False,
                     'overall_quality_pass_verified': False}
            body = {'prepared_at_utc': _stamp(finalized),
                    'profile': output_profile, 'source': source,
                    'authorization': authorization, 'isolation': isolation,
                    'context': context, 'plan': plan, 'proof': proof}
            out = {'schema': SCHEMA, 'status': 'partial', 'exit_code': 2,
                   'reason_code': REASON + 'CONFIGURATION_GATED_PLAN_ONLY',
                   **body, 'plan_sha256': _digest(DOMAIN_PLAN, body),
                   'effects': effects,
                   'trust_boundary': 'HOST_SIGNED_ASSERTIONS_ONLY_NO_ACTUAL_EXECUTION'}
            _require(len(_canonical(out)) <= MAX_RESULT_BYTES,
                     'PLAN_OUTPUT_TOO_LARGE', 'unavailable')
            return out
        except GateError as exc:
            return _denied(exc.code, exc.status, effects)
        except (detect.QualityError, ValueError, TypeError, KeyError,
                AttributeError, OverflowError, RecursionError, UnicodeError,
                OSError, MemoryError):
            return _denied('UNSAFE_OR_UNAVAILABLE_INPUT', 'unavailable', effects)
