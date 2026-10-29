#!/usr/bin/env python3
"""EC374 fixed read-only historical owner/reviewer original signature CLI."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'construction'))
from historical_owner.operator import main
if __name__=='__main__':raise SystemExit(main())
