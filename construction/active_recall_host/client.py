#!/usr/bin/env python3
"""EC260 original EC187 callback transport with bounded slow-custody patience.

This adapter does NOT supply grants, choose profiles, bypass source gates or
change ANY wire fields. Real Git revalidation takes longer than the original
EC254 2s response-read timeout on larger repositories. A signed EC187
controller can opt into this subclass rather than prematurely treating a
valid-but-slow proof as a failed host.
"""
from __future__ import annotations

from pathlib import Path
import sys
import time
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from session_host import broker as session
from quality_run_host import broker as runner


class ActiveRecallBroker(session.TrustedBroker):
    """Original begin/poll/stop semantics, extended local read timeout ONLY."""

    def begin(self, request: dict[str, Any]) -> session.Session:
        session.need(type(request) is dict and
                     type(request.get('deadline_monotonic_ns')) is int and
                     request['deadline_monotonic_ns'] > time.monotonic_ns(),
                     'EC260_CLIENT_DEADLINE_INVALID', 'invalid_input')
        # Keep original wire, validation and signed binding unmodified.
        remote = super().begin(request)
        remaining = max(0.0, (request['deadline_monotonic_ns'] -
                              time.monotonic_ns()) / 1e9)
        # A slow real-Git check can validly exceed EC254's previous 2s receive
        # timeout. Bound waiting to the approved session wall time plus host
        # cleanup allowance; never increase server/OCI resource ceilings.
        timeout = max(2.0, min(runner.WALL_SECONDS + runner.MAX_CLEANUP_SECONDS + 3,
                               remaining + runner.MAX_CLEANUP_SECONDS + 3))
        remote.conn.settimeout(timeout)
        return remote
