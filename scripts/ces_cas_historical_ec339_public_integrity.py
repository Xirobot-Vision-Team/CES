#!/usr/bin/env python3
"""EC396 isolated read-only public registry, signed log, device recovery verifier."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'construction'))
from ec396_public_integrity.operator import main
if __name__=='__main__':raise SystemExit(main())
