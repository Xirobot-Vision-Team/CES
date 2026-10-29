#!/usr/bin/env python3
"""EC255: operator-only Podman container identity and recovery barrier.

Bind a one-use EC253 lease to a container label, and a successful create to
its *full* ID. Recovery discovers the label across renamed containers rather
than trusting an old name; only the exact verified ID is removed. Missing,
malformed, duplicate or inconsistent engine evidence blocks cleanup instead
of allowing another container to be removed. Podman is a host assertion,
not independently authenticated kernel/cgroup evidence.
"""
from __future__ import annotations

import re
from typing import Any

from ec252_quality_run_host import broker as runner

LABEL_KEY = 'io.ces.lease.sha256'
INSPECT_FORMAT = ('{{.ID}}|{{.Name}}|'
                  '{{index .Config.Labels "io.ces.lease.sha256"}}|{{.Image}}')
FULL_ID = re.compile(r'[a-f0-9]{64}\Z')
NAME = re.compile(r'ces-ec252-[0-9a-f]{24}\Z')
PODMAN_NAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z')


def _require(ok: bool, code: str) -> None:
    if not ok:
        raise runner.HostRunError('OCI_IDENTITY_' + code)


def _hex(value: Any) -> bool:
    return type(value) is str and FULL_ID.fullmatch(value) is not None


def _execute(pol: dict[str, Any], args: list[str], *, max_output: int = 4096
             ) -> runner.CommandResult:
    return runner._run_command(pol, args, timeout=runner.MAX_CLEANUP_SECONDS,
                               limit=max_output)


def _labels(pol: dict[str, Any], label_sha256: str) -> list[str]:
    """Discover *all* containers with this signed-lease marker, even renamed.

    A missing or inaccessible Podman store is not evidence of absence: exit
    status must be zero. Multiple IDs or truncated output fail closed.
    """
    _require(_hex(label_sha256), 'LABEL_INVALID')
    result = _execute(pol, ['ps', '--all', '--no-trunc', '--filter',
                            'label=' + LABEL_KEY + '=' + label_sha256,
                            '--format', '{{.ID}}'], max_output=4096)
    _require(result.exit_code == 0 and len(result.stdout) <= 4096,
             'DISCOVERY_UNAVAILABLE')
    try:
        rows = result.stdout.decode('ascii').splitlines()
    except UnicodeError as exc:
        raise runner.HostRunError('OCI_IDENTITY_DISCOVERY_INVALID') from exc
    values = [row.strip() for row in rows]
    _require(len(values) <= 1 and all(_hex(v) for v in values),
             'DISCOVERY_AMBIGUOUS')
    return values


def verify(pol: dict[str, Any], container_id: str, label_sha256: str,
           *, expected_name: str | None = None) -> None:
    """Require exact ID, signed lease label and pinned image on one inspect.

    Verify an immutable full ID before any start or destructive cleanup.
    Checking the label and image does not make Podman an independent trust
    anchor; it prevents a stale name from silently targeting another object.
    """
    _require(_hex(container_id) and _hex(label_sha256), 'BINDING_INVALID')
    result = _execute(pol, ['container', 'inspect', '--format', INSPECT_FORMAT,
                            container_id], max_output=2048)
    _require(result.exit_code == 0 and len(result.stdout) <= 1024,
             'INSPECT_UNAVAILABLE')
    try:
        parts = result.stdout.decode('ascii').strip().split('|')
    except UnicodeError as exc:
        raise runner.HostRunError('OCI_IDENTITY_INSPECT_INVALID') from exc
    _require(len(parts) == 4 and parts[0] == container_id and
             PODMAN_NAME.fullmatch(parts[1]) is not None and
             parts[2] == label_sha256 and
             parts[3] in (pol['image_id'], pol['image_id'][7:]),
             'INSPECT_MISMATCH')
    if expected_name is not None:
        _require(parts[1] == expected_name, 'NAME_MISMATCH')


def _absent(pol: dict[str, Any], identity: str) -> bool:
    """Only exit=1 is the documented Podman 'not present' state."""
    result = _execute(pol, ['container', 'exists', identity], max_output=256)
    _require(result.exit_code in (0, 1), 'EXISTS_UNAVAILABLE')
    return result.exit_code == 1


def verified_cleanup(pol: dict[str, Any], label_sha256: str,
                     name: str, container_id: str | None = None) -> bool:
    """Remove only a verified lease-bound full ID; true means absence proven.

    The label was passed to `podman create` atomically. This handles a crash
    after create but before the created-ID journal append. An unknown/renamed
    ID, failed discovery, or nonmatching image can never authorize removal.
    """
    try:
        _require(_hex(label_sha256) and type(name) is str and
                 NAME.fullmatch(name) is not None and
                 (container_id is None or _hex(container_id)),
                 'CLEANUP_REQUEST_INVALID')
        found = _labels(pol, label_sha256)
        if not found:
            # An unbound create that never succeeded has nothing to remove.
            # If an ID was journaled, prove that exact ID is also absent;
            # the engine must not be allowed to hide a relabeled container.
            return _absent(pol, name if container_id is None else container_id)
        identity = found[0]
        _require(container_id is None or identity == container_id,
                 'RECOVERY_ID_CHANGED')
        # Without a durable created ID, only the original name is admitted.
        # With a durable ID we can safely remove a renamed container by ID.
        verify(pol, identity, label_sha256,
               expected_name=name if container_id is None else None)
        _execute(pol, ['rm', '--force', '--time', '0', identity], max_output=2048)
        return _absent(pol, identity)
    except (runner.HostRunError, OSError, ValueError, TypeError):
        return False


def before_start(pol: dict[str, Any], label_sha256: str,
                 name: str, created_id: str) -> None:
    """Ensure that create returned exactly the unique labeled OCI object."""
    _require(_hex(created_id), 'CREATE_ID_INVALID')
    ids = _labels(pol, label_sha256)
    _require(ids == [created_id], 'CREATE_ID_NOT_UNIQUE')
    verify(pol, created_id, label_sha256, expected_name=name)
