#!/usr/bin/env python3
"""EC377 fixed receiver-held old EC353 real signature/Merkle read-only CLI."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'construction'))
from historical_transparency.operator import main
if __name__=='__main__':raise SystemExit(main())
