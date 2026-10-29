#!/usr/bin/env python3
"""EC397 isolated original-bytes dual-channel publication witness verifier."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'construction'))
from publication_witness.operator import main
if __name__=='__main__':raise SystemExit(main())
