#!/usr/bin/env python3
"""EC394 isolated external registrar/key-history and log-witness receiver."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'construction'))
from ec394_registered_witness.operator import main
if __name__=='__main__':raise SystemExit(main())
