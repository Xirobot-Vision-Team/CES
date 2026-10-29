#!/usr/bin/env python3
"""EC391 fixed isolated read-only prior offsite log and RFC3161 receiver."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'construction'))
from prior_time.operator import main
if __name__=='__main__':raise SystemExit(main())
