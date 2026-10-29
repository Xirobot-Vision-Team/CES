#!/usr/bin/env python3
"""EC398 offline external registry-notice and two-custodian original verifier."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'construction'))
from official_notice.operator import main
if __name__=='__main__':raise SystemExit(main())
