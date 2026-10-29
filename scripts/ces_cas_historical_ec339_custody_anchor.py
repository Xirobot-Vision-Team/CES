#!/usr/bin/env python3
"""EC393 isolated, receiver-only historical original custody and log anchor."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'construction'))
from ec393_custody_anchor.operator import main
if __name__=='__main__':raise SystemExit(main())
