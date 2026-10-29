#!/usr/bin/env python3
"""Offline, SHA-pinned EC350 RFC3161/CMS token, certificate and CRL verifier."""
from __future__ import annotations
import sys
from pathlib import Path

root=str(Path(__file__).resolve().parents[1]/'construction')
sys.path.insert(0,root)
from tsa_timestamp.operator import main

if __name__=='__main__':
    raise SystemExit(main())
