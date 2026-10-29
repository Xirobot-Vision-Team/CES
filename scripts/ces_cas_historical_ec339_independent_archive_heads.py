#!/usr/bin/env python3
"""EC390 fixed isolated offline signed head and independent receipt receiver."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'construction'))
from ec390_independent_archive.operator import main
if __name__=='__main__':raise SystemExit(main())
