#!/usr/bin/env python3
"""EC352 offline self-signed registry root + genuine signer rotation verifier."""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from ec352_key_registry.operator import main

if __name__=='__main__':
    raise SystemExit(main())
