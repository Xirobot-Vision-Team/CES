#!/usr/bin/env python3
"""EC389 fixed isolated offline signed historical EC339 external witness receiver."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'construction'))
from ec389_external_revocation.operator import main
if __name__=='__main__':raise SystemExit(main())
