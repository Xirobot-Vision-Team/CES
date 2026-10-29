#!/usr/bin/env python3
"""EC353 fixed offline signed checkpoint/witness/Merkle verifier (READ ONLY)."""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from transparency.operator import main

if __name__=='__main__':raise SystemExit(main())
